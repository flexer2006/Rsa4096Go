                                                                                                            RSA 4096 Encryption and Decryption in Go
  This package implements encryption and decryption of text using RSA 4096-bit keys in Go.
The code includes functions to generate RSA keys, encrypt text using the public key, and decrypt text using the private key. The keys are returned in PEM format for easy storage and transfer.

  Functions:
1)Encrypt: Encrypts the given plaintext using RSA 4096 and returns the ciphertext, private key, and public key in PEM format.
2)Decrypt: Decrypts the given ciphertext using RSA 4096 and the private key in PEM format.

  Variables:
errCiphertextTooShort: Error that occurs if the ciphertext is too short.

  Encryption:
To encrypt text, use the Encrypt function. It takes a byte slice of plaintext and returns the encrypted ciphertext, private key, and public key in PEM format.

  Decryption:
To decrypt text, use the Decrypt function. It takes the encrypted ciphertext and the private key in PEM format, and returns the decrypted plaintext.

