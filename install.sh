#!/bin/sh

set -eu

OWNER=${OWNER:-nagi1}
REPO=${REPO:-larainspect}
BIN_NAME=${BIN_NAME:-larainspect}
INSTALL_DIR=${INSTALL_DIR:-/usr/local/bin}
VERSION=${VERSION:-latest}
BASE_URL="https://github.com/$OWNER/$REPO/releases"

usage() {
  cat <<'EOF'
Usage:
  sh install.sh

Environment overrides:
  VERSION=latest            Install the latest release (default)
  VERSION=v0.1.0            Install a specific release tag
  INSTALL_DIR=/custom/bin   Change the install destination

Examples:
  curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | sh
  curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | VERSION=v0.1.0 sh
  curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | INSTALL_DIR="$HOME/.local/bin" sh
EOF
}

print_banner() {
  cat <<'EOF'
▄▄     ▄▄▄  ▄▄▄▄   ▄▄▄  ▄▄ ▄▄  ▄▄  ▄▄▄▄ ▄▄▄▄  ▄▄▄▄▄  ▄▄▄▄ ▄▄▄▄▄▄
██    ██▀██ ██▄█▄ ██▀██ ██ ███▄██ ███▄▄ ██▄█▀ ██▄▄  ██▀▀▀   ██
██▄▄▄ ██▀██ ██ ██ ██▀██ ██ ██ ▀██ ▄▄██▀ ██    ██▄▄▄ ▀████   ██
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing required command: $1" >&2
    exit 1
  fi
}

detect_platform() {
  os=$(uname -s)
  arch=$(uname -m)

  case "$os" in
    Darwin)
      platform_os="macOS"
      ;;
    Linux)
      platform_os="Linux"
      ;;
    *)
      echo "error: unsupported operating system: $os" >&2
      exit 1
      ;;
  esac

  case "$arch" in
    x86_64|amd64)
      platform_arch="x86_64"
      ;;
    arm64|aarch64)
      platform_arch="arm64"
      ;;
    armv7l|armv7)
      platform_arch="armv7"
      ;;
    *)
      echo "error: unsupported architecture: $arch" >&2
      exit 1
      ;;
  esac

  ASSET_NAME="${BIN_NAME}_${platform_os}_${platform_arch}.tar.gz"
}

download_file() {
  url=$1
  output=$2

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$output"
    return
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO "$output" "$url"
    return
  fi

  echo "error: curl or wget is required" >&2
  exit 1
}

checksum_file() {
  file=$1

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return
  fi

  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return
  fi

  echo "error: sha256sum or shasum is required" >&2
  exit 1
}

pick_release_base() {
  if [ "$VERSION" = "latest" ]; then
    RELEASE_BASE="$BASE_URL/latest/download"
    return
  fi

  case "$VERSION" in
    v*)
      RELEASE_BASE="$BASE_URL/download/$VERSION"
      ;;
    *)
      echo "error: VERSION must be 'latest' or start with v (example: v0.1.0)" >&2
      exit 1
      ;;
  esac
}

install_binary() {
  source_binary=$1
  target_binary="$INSTALL_DIR/$BIN_NAME"
  install_parent=$(dirname "$INSTALL_DIR")

  if [ -w "$INSTALL_DIR" ] || { [ ! -e "$INSTALL_DIR" ] && [ -w "$install_parent" ]; }; then
    install -d "$INSTALL_DIR"
    install -m 0755 "$source_binary" "$target_binary"
    return
  fi

  require_command sudo
  sudo install -d "$INSTALL_DIR"
  sudo install -m 0755 "$source_binary" "$target_binary"
}

require_command tar
require_command install
require_command uname
require_command mktemp

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
esac

detect_platform
pick_release_base

TMP_DIR=$(mktemp -d)
ARCHIVE_PATH="$TMP_DIR/$ASSET_NAME"
CHECKSUM_PATH="$TMP_DIR/checksums.txt"

cleanup() {
  rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

print_banner
echo

echo ">>> downloading $ASSET_NAME"
download_file "$RELEASE_BASE/$ASSET_NAME" "$ARCHIVE_PATH"

echo ">>> downloading checksums.txt"
download_file "$RELEASE_BASE/checksums.txt" "$CHECKSUM_PATH"

EXPECTED_SUM=$(awk -v asset="$ASSET_NAME" '$2 == asset { print $1; exit }' "$CHECKSUM_PATH")
if [ -z "$EXPECTED_SUM" ]; then
  echo "error: could not find checksum for $ASSET_NAME" >&2
  exit 1
fi

ACTUAL_SUM=$(checksum_file "$ARCHIVE_PATH")
if [ "$EXPECTED_SUM" != "$ACTUAL_SUM" ]; then
  echo "error: checksum mismatch for $ASSET_NAME" >&2
  exit 1
fi

echo ">>> extracting archive"
tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"

if [ ! -f "$TMP_DIR/$BIN_NAME" ]; then
  echo "error: archive did not contain $BIN_NAME" >&2
  exit 1
fi

echo ">>> installing to $INSTALL_DIR/$BIN_NAME"
install_binary "$TMP_DIR/$BIN_NAME"

cat <<EOF

$BIN_NAME is ready.

$BIN_NAME installed successfully.

Run:
  $BIN_NAME version
EOF
