#!/bin/sh
# vault-cli installer
# Usage: curl -fsSL https://blindkeep.com/install.sh | sh
#    or: curl -fsSL https://blindkeep.com/install.sh | sh -s -- --to /usr/local/bin
set -eu

REPO="blindkeep-vault/vault-cli"
BINARY="vault-cli"
INSTALL_DIR="${HOME}/.local/bin"

# Parse arguments
while [ $# -gt 0 ]; do
  case "$1" in
    --to)   INSTALL_DIR="$2"; shift 2 ;;
    --help) usage; exit 0 ;;
    *)      echo "Unknown option: $1"; exit 1 ;;
  esac
done

usage() {
  echo "Install vault-cli"
  echo ""
  echo "Usage: curl -fsSL https://blindkeep.com/install.sh | sh"
  echo "       curl -fsSL https://blindkeep.com/install.sh | sh -s -- --to /usr/local/bin"
  echo ""
  echo "Options:"
  echo "  --to DIR    Install to DIR (default: ~/.local/bin)"
}

detect_platform() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "$OS" in
    Linux)  OS="unknown-linux-gnu" ;;
    Darwin) OS="apple-darwin" ;;
    *)      echo "Unsupported OS: $OS"; exit 1 ;;
  esac

  case "$ARCH" in
    x86_64|amd64)  ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *)             echo "Unsupported architecture: $ARCH"; exit 1 ;;
  esac

  TARGET="${ARCH}-${OS}"
}

get_latest_version() {
  if command -v curl >/dev/null 2>&1; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
  elif command -v wget >/dev/null 2>&1; then
    VERSION=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
  else
    echo "Error: curl or wget required"
    exit 1
  fi

  if [ -z "$VERSION" ]; then
    echo "Error: could not determine latest version"
    exit 1
  fi
}

download() {
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}-${TARGET}"
  TMPFILE=$(mktemp)
  trap 'rm -f "$TMPFILE"' EXIT

  echo "Downloading vault-cli ${VERSION} for ${TARGET}..."

  if command -v curl >/dev/null 2>&1; then
    curl -fSL --progress-bar -o "$TMPFILE" "$URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --show-progress -O "$TMPFILE" "$URL"
  fi

  if [ ! -s "$TMPFILE" ]; then
    echo "Error: download failed"
    exit 1
  fi

  chmod +x "$TMPFILE"

  # Verify it's a real binary (not an HTML error page)
  if ! file "$TMPFILE" | grep -qiE 'executable|Mach-O|ELF'; then
    echo "Error: downloaded file is not a valid binary"
    echo "Check https://github.com/${REPO}/releases for available assets"
    exit 1
  fi

  mkdir -p "$INSTALL_DIR"
  mv "$TMPFILE" "${INSTALL_DIR}/${BINARY}"
  trap - EXIT

  echo ""
  echo "Installed vault-cli ${VERSION} to ${INSTALL_DIR}/${BINARY}"
}

check_path() {
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      echo ""
      echo "Add ${INSTALL_DIR} to your PATH:"
      case "$(basename "${SHELL:-sh}")" in
        zsh)  echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.zshrc && source ~/.zshrc" ;;
        fish) echo "  fish_add_path ${INSTALL_DIR}" ;;
        *)    echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.bashrc && source ~/.bashrc" ;;
      esac
      ;;
  esac
}

detect_platform
get_latest_version
download
check_path
