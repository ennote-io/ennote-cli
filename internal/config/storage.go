package config

import (
	"errors"

	"github.com/zalando/go-keyring"
)

var ErrStorageUnavailable = errors.New("secure storage is unavailable on this system")

type SecureStorage interface {
	StoreCredential(service string, account string, token string) error
	RetrieveCredential(service string, account string) (string, error)
	DeleteCredential(service string, account string) error
}

type OSKeyring struct{}

func NewOSKeyring() *OSKeyring {
	return &OSKeyring{}
}

func (k *OSKeyring) StoreCredential(service string, account string, token string) error {
	err := keyring.Set(service, account, token)
	if err != nil {
		return ErrStorageUnavailable
	}
	return nil
}

func (k *OSKeyring) RetrieveCredential(service string, account string) (string, error) {
	token, err := keyring.Get(service, account)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (k *OSKeyring) DeleteCredential(service string, account string) error {
	return keyring.Delete(service, account)
}
