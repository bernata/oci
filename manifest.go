package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

type Manifest struct {
	Retrieve ManifestRetrieve `cmd:"" help:"retrieve manifest"`
}

type ManifestRetrieve struct {
	Image string `required:""`
}

func (m *ManifestRetrieve) Run() error {
	repo, err := newRepository(m.Image)
	if err != nil {
		return err
	}

	desc, err := oras.Resolve(context.Background(), repo, m.Image, oras.ResolveOptions{})
	if err != nil {
		return err
	}

	data, err := json.Marshal(ocispec.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	})
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", string(data))
	return nil
}

func newRepository(image string) (*remote.Repository, error) {
	repo, err := remote.NewRepository(image)
	if err != nil {
		return nil, err
	}
	if repo.Client, err = authClient(); err != nil {
		return nil, err
	}
	return repo, nil
}

// authClient assembles a oras auth client.
func authClient() (client *auth.Client, err error) {
	client = &auth.Client{
		Client: &http.Client{
			// default value are derived from http.DefaultTransport
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig:       &tls.Config{},
			},
		},
		Cache: auth.NewCache(),
	}
	client.SetUserAgent("oci/1.0")

	client.Credential = retrieveCredential

	return
}

func retrieveCredential(ctx context.Context, _ string) (auth.Credential, error) {
	c, err := awsconfig.LoadDefaultConfig(
		ctx,
		awsconfig.WithRegion("us-west-2"),
		awsconfig.WithSharedConfigProfile("abernat"))
	if err != nil {
		return auth.Credential{}, err
	}
	ecrClient := ecr.NewFromConfig(c)
	authTokenOutput, err := ecrClient.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return auth.Credential{}, err
	}

	password, err := normalizeToken(*authTokenOutput.AuthorizationData[0].AuthorizationToken)
	if err != nil {
		return auth.Credential{}, err
	}
	return auth.Credential{
		Username: "AWS",
		Password: password,
	}, nil
}

func normalizeToken(token string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(string(decoded), "AWS:"), nil
}
