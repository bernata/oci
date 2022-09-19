package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/sigstore/cosign/pkg/oci/static"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/pkg/oci"
	ocimutate "github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/walk"
	"github.com/sigstore/sigstore/pkg/signature"
	sigopts "github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

type Sign struct {
	SourceImage string `required:""`
	DestImage   string `required:""`
}

func (s *Sign) Run() error {
	b, _ := pem.Decode([]byte(testKey))

	privateKey, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return err
	}
	rsaPrivateKey := privateKey.(*rsa.PrivateKey)
	verifier, err := signature.LoadSignerVerifier(rsaPrivateKey, crypto.SHA256)
	if err != nil {
		return err
	}
	//dd := cosremote.NewDupeDetector(verifier)

	srcRef, err := parseOCIReference(s.SourceImage)
	if err != nil {
		return fmt.Errorf("parsing source reference %q: %w", s.SourceImage, err)
	}

	dstRef, err := parseOCIReference(s.DestImage)
	if err != nil {
		return fmt.Errorf("parsing destination reference %q: %w", s.DestImage, err)
	}

	var srcDesc *remote.Descriptor
	if srcDesc, err = remote.Get(srcRef, remote.WithAuth(&awsAuthenticator{})); err != nil {
		return fmt.Errorf("fetching %q: %w", s.SourceImage, err)
	}

	srcImg, err := srcDesc.Image()
	if err != nil {
		return fmt.Errorf("pulling linux/amd64 manifest: %w", err)
	}

	cfg, err := srcImg.ConfigFile()
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	// Copy the existing config, merging the annotations with any existing
	// legacy Docker labels and overwriting where needed.
	cfg = cfg.DeepCopy()

	annotations := map[string]string{
		"test": "me",
	}
	if cfg.Config.Labels == nil {
		cfg.Config.Labels = make(map[string]string, len(annotations))
	}

	for k, v := range annotations {
		cfg.Config.Labels[k] = v
	}

	srcImg, err = mutate.Config(srcImg, cfg.Config)
	if err != nil {
		return fmt.Errorf("mutating config: %w", err)
	}

	srcImg = mutate.Annotations(srcImg, annotations).(v1.Image)

	if err = remote.Write(dstRef, srcImg, remote.WithAuth(&awsAuthenticator{})); err != nil {
		return fmt.Errorf("writing destination image %q: %w", dstRef.Name(), err)
	}

	se, err := ociremote.SignedEntity(
		dstRef,
		ociremote.WithRemoteOptions(remote.WithAuth(&awsAuthenticator{})),
	)
	if err != nil {
		return fmt.Errorf("discovering existing signed entities: %w", err)
	}

	if err := walk.SignedEntity(context.Background(), se, func(ctx context.Context, se oci.SignedEntity) error {
		d, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
		if err != nil {
			return err
		}

		downscaledAnnotations := map[string]interface{}{
			"test": "me",
		}
		digest := dstRef.Context().Digest(d.String())
		data, err := (&payload.Cosign{
			Image:       digest,
			Annotations: downscaledAnnotations,
		}).MarshalJSON()
		if err != nil {
			return err
		}

		signed, err := verifier.SignMessage(bytes.NewReader(data), sigopts.WithContext(ctx))
		if err != nil {
			return err
		}

		b64sig := base64.StdEncoding.EncodeToString(signed)

		sig, err := static.NewSignature(data, b64sig)
		if err != nil {
			return err
		}

		newSE, err := ocimutate.AttachSignatureToEntity(se, sig) //, ocimutate.WithDupeDetector(dd))
		if err != nil {
			return err
		}

		return ociremote.WriteSignatures(
			digest.Repository,
			newSE,
			ociremote.WithRemoteOptions(remote.WithAuth(&awsAuthenticator{})),
		)
	}); err != nil {
		return err
	}

	fmt.Printf("%T\n", se != nil)
	return nil
}

func parseOCIReference(ref string) (name.Reference, error) {
	ociReferenceRegex := regexp.MustCompile(
		// NOTE: Sourced from https://git.io/JuM43.
		`^([A-Za-z0-9]+(([-._:@+]|--)[A-Za-z0-9]+)*)(/([A-Za-z0-9]+(([-._:@+]|--)[A-Za-z0-9]+)*))*$`,
	)
	errInvalidOCIRefName := errors.New("invalid OCI reference name")

	if !ociReferenceRegex.MatchString(ref) {
		return nil, errInvalidOCIRefName
	}

	return name.ParseReference(ref)
}

type awsAuthenticator struct{}

func (aa *awsAuthenticator) Authorization() (*authn.AuthConfig, error) {
	cred, err := retrieveCredential(context.Background(), "xxx")
	if err != nil {
		return nil, err
	}
	return &authn.AuthConfig{
		Username: cred.Username,
		Password: cred.Password,
	}, nil
}

const testKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCi6FwueyFr9TKR
/DMz6XnjKu9cvW2ixSu/ZtVq8hZRMj6hQVKo/r59nExBV78nfhL2dhuM1ro4C2yz
DLVwAQazDCN23TTPoQAdkaW5iGiCrk8vvmgdTgbRqtDPvurG1rZp6dAtPH1uNshk
g87fzUezwYJSXOhTWRNYr3vlc1sJO4YM4ojrVEjCHkVmZ7u4JnxwSQn48E1NEIPB
oeqi2TD1kyp1xO0EQVzPKIVr6xejUxRkoaByBm8BH8z7KBn3KV+Esht+rYA+NUL6
sY2Kv8bzgihoe/XA8mzBXpODSL95O1NH3PIW8LcUOOWEuCRvcGWmM4IsquqHEPpc
D8j/9ecNAgMBAAECggEAM9/0AqUY5mzE9rGtiFlPg+QXJpv3fn50yNUxHoYKTz7F
rMnFTaUY+Zy8t43+g8/kr/C6IyX5VIFm0rk4SXs6K+ewn1gfSgKFq+TGNgdW6E4j
Txu9wZ8oErnnFlBAKKMUoTNgJBeABYmSVFeYl7GhpH75Rcrp/CiAPZxbwpvyIET+
/8Jt6pnfIy1E78HivirxvI81mRIhiSuPT+zMTPUFUhBX7VLjTHOnNz3L14B5h0hz
U54Daab3yf/T4f6+CuEmyoDpEkRAbtJ8UDVfUBkhfXev8yxnWu7WNUWE191pPXi/
tniPZAyvMYErBHLKYuSZe+1kxAcIj44Ua+br/ptqIQKBgQDJoTDkxfMuuViOrImA
m02Ch1CybZJlMQIrOBy9xGgHiIlr+C15hCKkDaWIlQNGW8VA6p45IVE/nbMFiiYz
MM7EtcDmJIiTDTZo+o6gDku244CqoWWFGysByMlZL8jJq5RFYkaitUN5ArQd4XtE
TLeDlnfFni6vfOjFvr/8LEsn6QKBgQDO1iEgriJohJclmEiBjJRIPayj8Jjwt6Mg
WS/X37a/xOxHZPY0w0twYcSBMl1JMUC7l4kpncn1wifHVU0GK7OU0GS1GTYHyQvE
XYRFrhrQKAjiGVI/V6XqOkBjSxG9adLoEzFH4QHbc6NReW8o9NgDFwvFLNSFca7D
NNE0uMjzhQKBgQDJi+z54b0ySWdyRpm0ComyHlzV3p1ltVV7qj1gm8F5NkxXtt6O
Bz0xS8rZ+kopvHYya9P5O4qh0psuwGdq6DDnhN7rrj0u8RggW8TRzTh1+neVGHwI
T53vzKsoEZHdtTsjGBePcS2e+srcy5WSMjWGvZO/4Fy+YlezwvbZtdTycQKBgDgQ
SoJ1MNZruhxynpSe6kJ6lSUKvinhXNIT2qgE96AbXIAtmZ7LoNMhbQYoBKkmNImk
lYU2Q9vdeLLLKEmX5uFbazC7WK3bjNj5EDVi79mkQGQowOZyd4J5r6I6YuCYopZN
PXpiPwKg4Y/f/oV3eGW+BW64rBJPsjMvSdWkkLORAoGAEhur+cHxlkcJosvhPYoW
muiVGHJH08V/4deeXt2nlLE1fysd5KXr85JuIK6e+rQbzS4FiWwkY9nr/u3My8gT
4mkpX68E7ZAiweQjqGrlJJjqXJj3MoWgb7GYronUPe5lHJv+VWSfpULcABOobcqX
UZpTsPJ7FvI/rbtLluvu3io=
-----END RSA PRIVATE KEY-----`
