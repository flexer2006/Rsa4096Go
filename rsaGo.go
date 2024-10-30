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

// Encrypt encrypts the given plaintext using RSA 4096 and returns the ciphertext, private key, and public key in PEM format.
// Encrypt шифрует текст с помощью RSA 4096 и возвращает зашифрованный текст, приватный и публичный ключи в формате PEM.
func Encrypt(plainText []byte) ([]byte, []byte, []byte, error) {
    // Generate RSA 4096 keys
    // Генерация ключей RSA 4096
    privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
    if err != nil {
        return nil, nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
    }

    // Get the public key
    // Получение публичного ключа
    publicKey := &privateKey.PublicKey

    // Encrypt the plaintext using the public key
    // Шифрование текста с помощью публичного ключа
    cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plainText, nil)
    if err != nil {
        return nil, nil, nil, fmt.Errorf("failed to encrypt data: %w", err)
    }

    // Convert the private key to PEM format
    // Преобразование приватного ключа в формат PEM
    privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    })

    // Convert the public key to PEM format
    // Преобразование публичного ключа в формат PEM
    publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {
        return nil, nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
    }

    publicKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: publicKeyBytes,
    })

    // Return the ciphertext and keys in PEM format
    // Возвращение зашифрованного текста и ключей в формате PEM
    return cipherText, privateKeyPEM, publicKeyPEM, nil
}

// Decrypt decrypts the given ciphertext using RSA 4096 and the private key in PEM format.
// Decrypt дешифрует текст с помощью RSA 4096 и приватного ключа в формате PEM.
func Decrypt(cipherText []byte, privateKeyPEM []byte) ([]byte, error) {
    // Decode the private key from PEM format
    // Декодирование приватного ключа из формата PEM
    block, _ := pem.Decode(privateKeyPEM)
    if block == nil {
        return nil, errors.New("failed to decode private key")
    }

    // Convert the private key to rsa.PrivateKey structure
    // Преобразование приватного ключа в структуру rsa.PrivateKey
    privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse private key: %w", err)
    }

    // Decrypt the ciphertext using the private key
    // Дешифрование текста с помощью приватного ключа
    plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cipherText, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt data: %w", err)
    }

    // Return the decrypted plaintext
    // Возвращение расшифрованного текста
    return plainText, nil
}
