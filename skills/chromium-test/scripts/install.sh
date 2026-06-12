#!/usr/bin/env bash
set -euo pipefail

if command -v certutil >/dev/null 2>&1; then
  echo "certutil already installed: $(command -v certutil)"
  exit 0
fi

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y libnss3-tools
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y nss-tools
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y nss-tools
elif command -v pacman >/dev/null 2>&1; then
  sudo pacman -Sy --needed nss
elif command -v brew >/dev/null 2>&1; then
  brew install nss
else
  echo "No supported package manager found. Install certutil/libnss3-tools manually." >&2
  exit 1
fi

command -v certutil >/dev/null 2>&1
echo "certutil installed: $(command -v certutil)"
