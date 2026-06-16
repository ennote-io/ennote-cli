package secrets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/ennote-io/ennote-cli/internal/crypto"
	clipb "github.com/ennote-io/ennote-cli/internal/grpc/pb"
	"golang.org/x/crypto/curve25519"
)

func FetchAndDecapsulate(
	ctx context.Context,
	client clipb.CliServiceClient,
	orgID string,
	workspaceID string,
	secretName string,
	version *int32,
) ([]byte, error) {
	var privateKey, publicKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("rng failure: %w", err)
	}

	defer crypto.ZeroMemory(privateKey[:])

	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	spkiPrefix := []byte{
		0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
	}

	spkiBytes := make([]byte, 0, len(spkiPrefix)+len(publicKey))
	spkiBytes = append(spkiBytes, spkiPrefix...)
	spkiBytes = append(spkiBytes, publicKey[:]...)

	pubKeyBase64 := base64.StdEncoding.EncodeToString(spkiBytes)

	req := &clipb.GetCliSecretRequest{
		SessionPublicKey: pubKeyBase64,
		SecretName:       secretName,
		OrganizationId:   orgID,
		WorkspaceId:      workspaceID,
	}

	if version != nil {
		req.SecretVersionNumber = version
	}

	resp, err := client.GetSecretVersionData(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("backend secret fetch failed: %w", err)
	}

	return crypto.DecapsulatePayload(privateKey[:], resp.SessionWrappedKey, resp.EncryptedBlob)
}
