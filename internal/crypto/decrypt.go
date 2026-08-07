package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func DecapsulatePayload(clientPrivateKey, reWrappedKeyBlob, encryptedBlob []byte) ([]byte, error) {
	if len(reWrappedKeyBlob) < 4 {
		return nil, errors.New("wrapped key blob too small for header")
	}
	ephPubLen := binary.BigEndian.Uint32(reWrappedKeyBlob[0:4])
	if ephPubLen == 0 || ephPubLen > MaxSpkiHeaderSize {
		return nil, errors.New("invalid SPKI header size")
	}

	kOff := uint32(4)
	if uint32(len(reWrappedKeyBlob)) < kOff+ephPubLen+IvLength {
		return nil, errors.New("wrapped key blob too small for parameters")
	}

	serverEphPubSPKI := reWrappedKeyBlob[kOff : kOff+ephPubLen]
	kOff += ephPubLen

	sessionIv := reWrappedKeyBlob[kOff : kOff+IvLength]
	kOff += IvLength

	encryptedDek := reWrappedKeyBlob[kOff:]

	if len(serverEphPubSPKI) < 32 {
		return nil, errors.New("handshake failed: invalid public key length")
	}
	serverEphPubRaw := serverEphPubSPKI[len(serverEphPubSPKI)-32:]

	sharedSecret, err := curve25519.X25519(clientPrivateKey, serverEphPubRaw)
	if err != nil {
		return nil, fmt.Errorf("x25519 derivation failed: %w", err)
	}
	defer ZeroMemory(sharedSecret)

	salt := make([]byte, 32)
	info := []byte(SessionIdentity)
	derivedKey := make([]byte, 32)

	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, info)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("hkdf failed: %w", err)
	}
	defer ZeroMemory(derivedKey)

	dek, err := gcmDecrypt(derivedKey, sessionIv, encryptedDek, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap DEK: %w", err)
	}
	defer ZeroMemory(dek)

	if len(encryptedBlob) < 5 {
		return nil, errors.New("encrypted blob too small")
	}
	algoId := encryptedBlob[0]

	var wrappedKeySize uint32
	if algoId == AlgorithmIDMlKem1024 {
		wrappedKeySize = EncapsulationSizeKyber
	} else if algoId == AlgorithmIDRsaOaep256 {
		wrappedKeySize = EncapsulationSizeRsa
	} else {
		return nil, errors.New("unknown cryptographic algorithm")
	}

	verLen := binary.BigEndian.Uint32(encryptedBlob[1:5])
	if verLen > MaxVersionLength {
		return nil, errors.New("invalid version length")
	}

	bOff := uint32(5)
	if uint32(len(encryptedBlob)) < bOff+verLen+IvLength+wrappedKeySize {
		return nil, errors.New("encrypted blob too small for payload boundaries")
	}

	verBytes := encryptedBlob[bOff : bOff+verLen]
	bOff += verLen

	aad := make([]byte, 0, 1+len(verBytes))
	aad = append(aad, algoId)
	aad = append(aad, verBytes...)

	dataIv := encryptedBlob[bOff : bOff+IvLength]
	bOff += IvLength

	bOff += wrappedKeySize

	dataCiphertext := encryptedBlob[bOff:]

	plaintextBytes, err := gcmDecrypt(dek, dataIv, dataCiphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret payload: %w", err)
	}

	return plaintextBytes, nil
}

func gcmDecrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, nonce, ciphertext, aad)
}
