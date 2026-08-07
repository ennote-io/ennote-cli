package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

func EncryptOnetime(plaintext, password string) (encryptedBlob, passwordHash, saltBase64, keyBase64 string, err error) {
	key := make([]byte, AesKeyLength)
	iv := make([]byte, IvLength)

	if _, err := rand.Read(key); err != nil {
		return "", "", "", "", fmt.Errorf("rng failure (key): %w", err)
	}
	if _, err := rand.Read(iv); err != nil {
		return "", "", "", "", fmt.Errorf("rng failure (iv): %w", err)
	}
	defer ZeroMemory(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", "", "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", "", "", err
	}

	// Seal appends the authentication tag to the ciphertext automatically, matching JS
	ciphertext := aesgcm.Seal(nil, iv, []byte(plaintext), nil)

	// Blob format: concatBytes(iv, ciphertext)
	blob := make([]byte, 0, len(iv)+len(ciphertext))
	blob = append(blob, iv...)
	blob = append(blob, ciphertext...)

	encryptedBlob = base64.StdEncoding.EncodeToString(blob)
	keyBase64 = base64.StdEncoding.EncodeToString(key)

	if password != "" {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return "", "", "", "", fmt.Errorf("rng failure (salt): %w", err)
		}

		derivedKey := pbkdf2.Key([]byte(password), salt, Pbkdf2Iterations, Pbkdf2KeyLength, sha256.New)
		passwordHash = base64.StdEncoding.EncodeToString(derivedKey)
		saltBase64 = base64.StdEncoding.EncodeToString(salt)

		defer ZeroMemory(derivedKey)
	}

	return encryptedBlob, passwordHash, saltBase64, keyBase64, nil
}

func DerivePasswordHash(password, saltBase64 string) (string, error) {
	salt, err := base64.StdEncoding.DecodeString(saltBase64)
	if err != nil {
		return "", fmt.Errorf("invalid salt format: %w", err)
	}

	derivedKey := pbkdf2.Key([]byte(password), salt, Pbkdf2Iterations, Pbkdf2KeyLength, sha256.New)
	defer ZeroMemory(derivedKey)

	return base64.StdEncoding.EncodeToString(derivedKey), nil
}

func DecryptOnetime(encryptedBlobBase64, keyBase64 string) (string, error) {
	blob, err := base64.StdEncoding.DecodeString(encryptedBlobBase64)
	if err != nil {
		return "", fmt.Errorf("invalid encrypted blob format: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", fmt.Errorf("invalid key format: %w", err)
	}
	defer ZeroMemory(key)

	if len(blob) < IvLength {
		return "", errors.New("encrypted blob too short")
	}

	iv := blob[:IvLength]
	ciphertext := blob[IvLength:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", errors.New("decryption failed: incorrect key, password, or corrupted data")
	}
	defer ZeroMemory(plaintext)

	return string(plaintext), nil
}
