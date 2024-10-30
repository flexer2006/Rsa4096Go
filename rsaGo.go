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

// Encrypt шифрует текст с помощью RSA 4096 и возвращает зашифрованный текст, приватный и публичный ключи в формате PEM.
func Encrypt(plainText []byte) ([]byte, []byte, []byte, error) {
	// Генерация ключей RSA 4096
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Получение публичного ключа
	publicKey := &privateKey.PublicKey

	// Шифрование текста с помощью публичного ключа
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plainText, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Преобразование приватного ключа в формат PEM
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Преобразование публичного ключа в формат PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Возвращение зашифрованного текста и ключей в формате PEM
	return cipherText, privateKeyPEM, publicKeyPEM, nil
}

// Decrypt дешифрует текст с помощью RSA 4096 и приватного ключа в формате PEM.
func Decrypt(cipherText []byte, privateKeyPEM []byte) ([]byte, error) {
	// Декодирование приватного ключа из формата PEM
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}

	// Преобразование приватного ключа в структуру rsa.PrivateKey
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Дешифрование текста с помощью приватного ключа
	plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Возвращение расшифрованного текста
	return plainText, nil
}
