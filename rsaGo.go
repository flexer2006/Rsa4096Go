package rsa4096andrew

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

const rsaBits = 4096

var (
	errDecodePrivateKey      = errors.New("failed to decode private key PEM")
	errUnsupportedPrivateKey = errors.New("unsupported private key format")
	errInvalidKeySize        = errors.New("invalid RSA key size: expected 4096 bits")
)

func Encrypt(plainText []byte) ([]byte, []byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	publicKey := &privateKey.PublicKey

	maxPlaintextLen := publicKey.Size() - 2*sha256.Size - 2
	if len(plainText) > maxPlaintextLen {
		return nil, nil, nil, fmt.Errorf("plaintext too large for RSA-OAEP SHA-256: got %d, max %d", len(plainText), maxPlaintextLen)
	}

	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plainText, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return cipherText, privateKeyPEM, publicKeyPEM, nil
}

func Decrypt(cipherText []byte, privateKeyPEM []byte) ([]byte, error) {
	privateKey, err := parseRSAPrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	if privateKey.N.BitLen() != rsaBits {
		return nil, errInvalidKeySize
	}

	plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plainText, nil
}

func parseRSAPrivateKeyPEM(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errDecodePrivateKey
	}

	if keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if key, ok := keyAny.(*rsa.PrivateKey); ok {
			return key, nil
		}
		return nil, errUnsupportedPrivateKey
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return key, nil
}
