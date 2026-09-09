#!/usr/bin/env bash
# Install the age CLI used by the interop tests.
#
# Ubuntu packages age 1.1.x, which predates native post-quantum support
# (1.3.0), so the release tarball is used instead. The download is verified
# against a pinned sha256: this binary decrypts test material, so an
# unverified swap would be executing attacker code.
#
# Used by CI and by developers who want to run the #[ignore]d interop tests:
#
#   ./scripts/install-age.sh                     # -> /usr/local/bin (may need sudo)
#   ./scripts/install-age.sh ~/.local/bin        # -> somewhere on your PATH
#   cargo test --workspace -- --include-ignored
set -euo pipefail

AGE_VERSION="${AGE_VERSION:-v1.3.2}"
AGE_SHA256="${AGE_SHA256:-cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10}"
DEST="${1:-/usr/local/bin}"

case "$(uname -s)" in
  Linux)  PLATFORM="linux" ;;
  Darwin) PLATFORM="darwin" ;;
  *) echo "unsupported platform $(uname -s); install age >= 1.3 manually" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "unsupported arch $(uname -m); install age >= 1.3 manually" >&2; exit 1 ;;
esac

# The pinned checksum is for linux/amd64 only. On anything else, verifying
# against it would fail confusingly, so require an explicit override.
if [ "${PLATFORM}/${ARCH}" != "linux/amd64" ] && [ -z "${AGE_SHA256_OVERRIDE:-}" ]; then
  echo "No pinned checksum for ${PLATFORM}/${ARCH}." >&2
  echo "Set AGE_SHA256 and AGE_SHA256_OVERRIDE=1 for your platform's release." >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

URL="https://github.com/FiloSottile/age/releases/download/${AGE_VERSION}/age-${AGE_VERSION}-${PLATFORM}-${ARCH}.tar.gz"
echo "downloading ${URL}"
curl -sSLf -o "$TMP/age.tar.gz" "$URL"
echo "${AGE_SHA256}  $TMP/age.tar.gz" | sha256sum -c -
tar -xzf "$TMP/age.tar.gz" -C "$TMP"

install -d "$DEST"
install -m 0755 "$TMP/age/age" "$DEST/age"
install -m 0755 "$TMP/age/age-keygen" "$DEST/age-keygen"
"$DEST/age" --version
