package grpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/ennote-io/ennote-cli/internal/config"
	"github.com/zalando/go-keyring"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type TokenAuth struct {
	Keyring    config.SecureStorage
	Version    string
	RequireTLS bool
	EnvToken   string
}

func (t TokenAuth) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	var token string
	var err error

	if t.EnvToken != "" {
		token = t.EnvToken
	} else {
		token, err = t.Keyring.RetrieveCredential("ennote", "session")
		if err != nil {
			if errors.Is(err, keyring.ErrNotFound) {
				return nil, fmt.Errorf("unauthorized: no active session found. Please set the ENNOTE_TOKEN environment variable or run 'ennote auth login'")
			}
			return nil, fmt.Errorf("failed to access secure keyring: %w", err)
		}
	}

	ua := fmt.Sprintf("ennote-cli/%s (%s/%s)", t.Version, runtime.GOOS, runtime.GOARCH)

	return map[string]string{
		"authorization":      "Bearer " + token,
		"ennote-client-type": "cli",
		"user-agent":         ua,
	}, nil
}

func (t TokenAuth) RequireTransportSecurity() bool {
	return t.RequireTLS
}

func NewSecureClient(target string, keyring config.SecureStorage, version string, envToken string) (*grpc.ClientConn, error) {
	isLocalhost := target == "localhost" || target == "127.0.0.1" || strings.HasPrefix(target, "localhost:") || strings.HasPrefix(target, "127.0.0.1:")

	var transportCreds credentials.TransportCredentials
	if isLocalhost {
		transportCreds = insecure.NewCredentials()
	} else {
		transportCreds = credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13,
		})
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithPerRPCCredentials(TokenAuth{
			Keyring:    keyring,
			Version:    version,
			RequireTLS: !isLocalhost,
			EnvToken:   envToken,
		}),
	}

	return grpc.NewClient(target, opts...)
}
