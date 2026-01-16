#!/bin/bash
set -euo pipefail

if git describe --tags >/dev/null 2>&1; then
    VERSION="$(git describe --tags --dirty)"
else
    VERSION="0.0.0-dev"
fi

OS=$(uname -s | tr 'A-Z' 'a-z')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) echo "Unsupported arch: $ARCH" && exit 1 ;;
esac

PLATFORM="${OS}_${ARCH}"


PLUGIN_DIR="$HOME/.terraform.d/plugins/registry.terraform.io/linero/redis/${VERSION}/${PLATFORM}"
mkdir -p "$PLUGIN_DIR"

OUT="${PLUGIN_DIR}/terraform-provider-redis_v${VERSION}"

echo "Building plugin:"
echo "  Version:  $VERSION"
echo "  Platform: $PLATFORM"
echo "  Output:   $OUT"

go mod vendor
go build -o "$OUT"

echo "Plugin succesfully installed"