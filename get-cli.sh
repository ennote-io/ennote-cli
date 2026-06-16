#!/bin/sh
set -e

PROJECT="ennote"
BASE_URL="https://github.com/ennote-io/ennote-cli/releases/latest/download"

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
    Linux)
        OS_NAME="linux"
        ;;
    Darwin)
        OS_NAME="darwin"
        ;;
    FreeBSD)
        OS_NAME="freebsd"
        ;;
    NetBSD)
        OS_NAME="netbsd"
        ;;
    OpenBSD)
        OS_NAME="openbsd"
        ;;
    *)
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64)
        ARCH_NAME="amd64"
        ;;
    aarch64|arm64)
        ARCH_NAME="arm64"
        ;;
    i386|i686)
        ARCH_NAME="386"
        ;;
    armv7l|armv7)
        ARCH_NAME="armv7"
        ;;
    armv6l|armv6)
        ARCH_NAME="armv6"
        ;;
    *)
        exit 1
        ;;
esac

TARBALL_SUFFIX="${OS_NAME}_${ARCH_NAME}"
if [ "$ARCH_NAME" = "armv7" ]; then
    TARBALL_SUFFIX="${OS_NAME}_armv7"
elif [ "$ARCH_NAME" = "armv6" ]; then
    TARBALL_SUFFIX="${OS_NAME}_armv6"
fi

TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

curl -sSfL -O "$BASE_URL/checksums.txt"

VERSION_TAG=$(awk -v suffix="${TARBALL_SUFFIX}.tar.gz" '
    $2 ~ "^" "ennote_" "[0-9]+\\.[0-9]+\\.[0-9]+" "_" suffix "$" {
        split($2, parts, "_")
        print parts[2]
        exit
    }
' checksums.txt)

if [ -z "$VERSION_TAG" ]; then
    exit 1
fi

TARBALL="${PROJECT}_${VERSION_TAG}_${TARBALL_SUFFIX}.tar.gz"

curl -sSfL -O "$BASE_URL/$TARBALL"

awk -v target="$TARBALL" '$2 == target {print $0}' checksums.txt > target_checksum.txt

if [ ! -s target_checksum.txt ]; then
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c target_checksum.txt
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c target_checksum.txt
else
    exit 1
fi

tar -xzf "$TARBALL" "$PROJECT"

INSTALL_DIR="/usr/local/bin"
if [ -w "$INSTALL_DIR" ]; then
    mv "$PROJECT" "$INSTALL_DIR/$PROJECT"
else
    sudo mv "$PROJECT" "$INSTALL_DIR/$PROJECT"
fi

cd - >/dev/null
rm -rf "$TMP_DIR"