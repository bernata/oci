package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateKey(t *testing.T) {
	const bits2048 = 2048

	key, err := rsa.GenerateKey(rand.Reader, bits2048)
	require.NoError(t, err)

	marshalled, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: marshalled,
		},
	)

	fmt.Printf("%s\n", pemData)
}
