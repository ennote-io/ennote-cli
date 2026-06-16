.PHONY: build snapshot release clean generate

export PATH := $(shell go env GOPATH)/bin:$(PATH)

ifneq (,$(wildcard ./.env))
    include .env
    export
endif

BINARY_NAME=ennote
PACKAGE=github.com/ennote-io/ennote-cli/internal/config

build: generate
	go build -ldflags="\
		-s -w \
		-X '$(PACKAGE).BackendURL=$(BACKEND_URL)' \
		-X '$(PACKAGE).RedirectURI=http://127.0.0.1:8888/callback'" \
		-o bin/$(BINARY_NAME) cmd/ennote/main.go

snapshot: generate
	goreleaser release --snapshot --clean --skip=sign

release:
	goreleaser release --clean

clean:
	rm -rf bin/ dist/

generate:
	protoc --go_out=. \
	       --go_opt=module=github.com/ennote-io/ennote-cli \
	       --go-grpc_out=. --go-grpc_opt=module=github.com/ennote-io/ennote-cli \
	       api/proto/cli/v1/cli.proto