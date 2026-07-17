package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	clipb "github.com/ennote-io/ennote-cli/internal/grpc/pb"
)

func EncryptSecretPayload(plaintext []byte, config *clipb.GetCliCryptoConfigResponse) (string, error) {
	if config == nil || config.Algorithm == "" || len(config.PublicKey) == 0 {
		return "", errors.New("invalid crypto config received from backend")
	}

	keyVersion := config.KeyVersion
	if keyVersion == "" {
		keyVersion = "latest"
	}
	verBytes := []byte(keyVersion)
	verLen := uint32(len(verBytes))

	var algoIdByte byte
	var wrappedDek []byte
	var rawDek []byte

	algoUpper := strings.ToUpper(config.Algorithm)
	isKyber := strings.Contains(algoUpper, "KYBER") || strings.Contains(algoUpper, "ML-KEM")

	if isKyber {
		algoIdByte = AlgorithmIDMlKem1024

		pubKeyBytes := config.PublicKey
		if len(pubKeyBytes) > mlkem1024.PublicKeySize {
			pubKeyBytes = pubKeyBytes[len(pubKeyBytes)-mlkem1024.PublicKeySize:]
		}

		pk, err := mlkem1024.Scheme().UnmarshalBinaryPublicKey(pubKeyBytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse ML-KEM public key: %w", err)
		}

		ct, ss, err := mlkem1024.Scheme().Encapsulate(pk)
		if err != nil {
			return "", fmt.Errorf("ML-KEM encapsulation failed: %w", err)
		}
		wrappedDek = ct
		rawDek = ss
	} else {
		algoIdByte = AlgorithmIDRsaOaep256

		block, _ := pem.Decode(config.PublicKey)
		var keyToParse []byte
		if block != nil {
			keyToParse = block.Bytes
		} else {
			keyToParse = config.PublicKey
		}

		pub, err := x509.ParsePKIXPublicKey(keyToParse)
		if err != nil {
			return "", fmt.Errorf("failed to parse PKIX public key: %w", err)
		}

		rsaPubKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return "", errors.New("public key is not an RSA key")
		}

		rawDek = make([]byte, AesKeyLength)
		if _, err := rand.Read(rawDek); err != nil {
			return "", fmt.Errorf("rng failure (aes key): %w", err)
		}

		wrappedDek, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, rawDek, nil)
		if err != nil {
			return "", fmt.Errorf("rsa encapsulation failed: %w", err)
		}
	}

	defer ZeroMemory(rawDek)

	iv := make([]byte, IvLength)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("rng failure (iv): %w", err)
	}

	aad := append([]byte{algoIdByte}, verBytes...)

	block, err := aes.NewCipher(rawDek)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nil, iv, plaintext, aad)

	verLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(verLenBytes, verLen)

	var blob []byte
	blob = append(blob, algoIdByte)
	blob = append(blob, verLenBytes...)
	blob = append(blob, verBytes...)
	blob = append(blob, iv...)
	blob = append(blob, wrappedDek...)
	blob = append(blob, ciphertext...)

	return base64.StdEncoding.EncodeToString(blob), nil
}
