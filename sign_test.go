package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/mutate"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	cosremote "github.com/sigstore/cosign/pkg/cosign/remote"
	"github.com/sigstore/cosign/pkg/oci"
	ocimutate "github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/oci/walk"
	"github.com/sigstore/sigstore/pkg/signature"
	sigopts "github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	"github.com/stretchr/testify/require"
)

func TestReadDescriptor(t *testing.T) {
	sourceImage := "492618166700.dkr.ecr.us-west-2.amazonaws.com/demosign:sha256-d03c89a41b64a3f286c6e71eced57df7c3bd01cf7109335737329dd71bdec547.sig"
	srcRef, err := parseOCIReference(sourceImage)
	require.NoError(t, err)
	srcDesc, err := remote.Get(srcRef, remote.WithAuth(&awsAuthenticator{}))
	require.NoError(t, err)
	fmt.Printf("%s\n", srcDesc.Manifest)

	sourceImage = "492618166700.dkr.ecr.us-west-2.amazonaws.com/demosign:v1"
	srcRef, err = parseOCIReference(sourceImage)
	require.NoError(t, err)
	srcDesc, err = remote.Get(srcRef, remote.WithAuth(&awsAuthenticator{}))
	require.NoError(t, err)
	fmt.Printf("%s\n", srcDesc.Manifest)

	sourceImage = "492618166700.dkr.ecr.us-west-2.amazonaws.com/demosign:v2"
	srcRef, err = parseOCIReference(sourceImage)
	require.NoError(t, err)
	srcDesc, err = remote.Get(srcRef, remote.WithAuth(&awsAuthenticator{}))
	require.NoError(t, err)
	fmt.Printf("%s\n", srcDesc.Manifest)
}

func TestReadDescriptor2(t *testing.T) {
	sourceImage := "492618166700.dkr.ecr.us-west-2.amazonaws.com/demosign:annotatedv1"
	srcRef, err := parseOCIReference(sourceImage)
	require.NoError(t, err)
	srcDesc, err := remote.Get(srcRef, remote.WithAuth(&awsAuthenticator{}))
	require.NoError(t, err)
	fmt.Printf("%s\n", srcDesc.Manifest)
}

func TestCopy(t *testing.T) {
	sourceImage := "492618166700.dkr.ecr.us-west-2.amazonaws.com/demosign:v1"
	srcRef, err := parseOCIReference(sourceImage)
	require.NoError(t, err)
	srcDesc, err := remote.Get(srcRef, remote.WithAuth(&awsAuthenticator{}))
	require.NoError(t, err)

	dstRef, err := parseOCIReference("492618166700.dkr.ecr.us-west-2.amazonaws.com/demosign:copyv1")
	require.NoError(t, err)

	img, err := srcDesc.Image()
	require.NoError(t, err)
	err = remote.Write(dstRef, img, remote.WithAuth(&awsAuthenticator{}))
	require.NoError(t, err)
}

func TestCopyAndAnnotate(t *testing.T) {
	sourceImage := "492618166700.dkr.ecr.us-west-2.amazonaws.com/demosign:v1"
	srcRef, err := parseOCIReference(sourceImage)
	require.NoError(t, err)
	srcDesc, err := remote.Get(srcRef, remote.WithAuth(&awsAuthenticator{}))
	require.NoError(t, err)

	dstRef, err := parseOCIReference("492618166700.dkr.ecr.us-west-2.amazonaws.com/demosign:annotatedv1")
	require.NoError(t, err)

	img, err := srcDesc.Image()
	require.NoError(t, err)

	newImg := mutate.Annotations(img, map[string]string{"foo": "bar"}).(v1.Image)

	err = remote.Write(dstRef, newImg, remote.WithAuth(&awsAuthenticator{}))
	require.NoError(t, err)
}

func TestCopyAndSign(t *testing.T) {
	sourceImage := "492618166700.dkr.ecr.us-west-2.amazonaws.com/demosign:v1"
	srcRef, err := parseOCIReference(sourceImage)
	require.NoError(t, err)
	srcDesc, err := remote.Get(srcRef, remote.WithAuth(&awsAuthenticator{}))
	require.NoError(t, err)

	dstRef, err := parseOCIReference("492618166700.dkr.ecr.us-west-2.amazonaws.com/demosign:annotatedv1")
	require.NoError(t, err)

	img, err := srcDesc.Image()
	require.NoError(t, err)

	newImg := mutate.Annotations(img, map[string]string{"foo": "bar"}).(v1.Image)

	err = remote.Write(dstRef, newImg, remote.WithAuth(&awsAuthenticator{}))
	require.NoError(t, err)
}

func TestSign(t *testing.T) {
	b, _ := pem.Decode([]byte(testKey))

	privateKey, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	require.NoError(t, err)
	rsaPrivateKey := privateKey.(*rsa.PrivateKey)
	verifier, err := signature.LoadSignerVerifier(rsaPrivateKey, crypto.SHA256)
	require.NoError(t, err)

	dd := cosremote.NewDupeDetector(verifier)
	sourceImage := "492618166700.dkr.ecr.us-west-2.amazonaws.com/demosign:v1"
	srcRef, err := parseOCIReference(sourceImage)
	require.NoError(t, err)

	srcDesc, err := remote.Get(srcRef, remote.WithAuth(&awsAuthenticator{}))
	require.NoError(t, err)
	fmt.Printf("%s\n", srcDesc.Digest.String())

	se, err := ociremote.SignedEntity(
		srcRef,
		ociremote.WithRemoteOptions(remote.WithAuth(&awsAuthenticator{})),
	)
	require.NoError(t, err)

	err = walk.SignedEntity(context.Background(), se, func(ctx context.Context, se oci.SignedEntity) error {
		d, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
		if err != nil {
			return err
		}

		downscaledAnnotations := map[string]interface{}{
			"test": "me",
		}
		digest := srcRef.Context().Digest(d.String())
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

		newSE, err := ocimutate.AttachSignatureToEntity(se, sig, ocimutate.WithDupeDetector(dd))
		if err != nil {
			return err
		}

		return ociremote.WriteSignatures(
			digest.Repository,
			newSE,
			ociremote.WithRemoteOptions(remote.WithAuth(&awsAuthenticator{})),
		)
	})
	require.NoError(t, err)

}
