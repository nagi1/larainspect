#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

SKIP_TESTS=0
SKIP_CHECK=0
SNAPSHOT=0
YES=0
VERSION=

usage() {
  cat <<'EOF'
Usage:
  ./scripts/release.sh v0.1.0
  ./scripts/release.sh --snapshot

Options:
  --snapshot               Build a local snapshot release with GoReleaser and exit.
  --skip-tests             Skip go test ./...
  --skip-goreleaser-check  Skip goreleaser check
  --yes                    Skip the confirmation prompt for official releases.
  -h, --help               Show this help.

Examples:
  ./scripts/release.sh v0.1.0
  ./scripts/release.sh v0.2.0-rc.1 --yes
  ./scripts/release.sh --snapshot
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing required command: $1" >&2
    exit 1
  fi
}

confirm() {
  if [ "$YES" -eq 1 ]; then
    return 0
  fi

  printf '%s' "Create and push tag $VERSION from $(git rev-parse --short HEAD)? [y/N] " >&2
  read -r answer
  case "$answer" in
    y|Y|yes|YES)
      ;;
    *)
      echo "aborted" >&2
      exit 1
      ;;
  esac
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --snapshot)
      SNAPSHOT=1
      ;;
    --skip-tests)
      SKIP_TESTS=1
      ;;
    --skip-goreleaser-check)
      SKIP_CHECK=1
      ;;
    --yes)
      YES=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -* )
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      if [ -n "$VERSION" ]; then
        echo "error: only one version argument is allowed" >&2
        usage >&2
        exit 1
      fi
      VERSION=$1
      ;;
  esac
  shift
done

require_command git
require_command go

cd "$REPO_ROOT"

if [ ! -d .git ]; then
  echo "error: scripts/release.sh must run from the larainspect repository" >&2
  exit 1
fi

if [ "$SNAPSHOT" -eq 1 ] && [ -n "$VERSION" ]; then
  echo "error: --snapshot does not accept a version argument" >&2
  exit 1
fi

if [ "$SNAPSHOT" -eq 0 ] && [ -z "$VERSION" ]; then
  echo "error: missing release version (expected something like v0.1.0)" >&2
  usage >&2
  exit 1
fi

if [ "$SNAPSHOT" -eq 0 ]; then
  case "$VERSION" in
    v[0-9]*.[0-9]*.[0-9]*|v[0-9]*.[0-9]*.[0-9]*-*)
      ;;
    *)
      echo "error: version must look like vMAJOR.MINOR.PATCH or include a prerelease suffix" >&2
      exit 1
      ;;
  esac
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "error: worktree is dirty; commit or stash changes first" >&2
  exit 1
fi

if [ "$SKIP_TESTS" -eq 0 ]; then
  echo ">>> go test ./..."
  go test ./...
fi

if [ "$SKIP_CHECK" -eq 0 ]; then
  echo ">>> goreleaser check"
  go run github.com/goreleaser/goreleaser/v2@latest check
fi

if [ "$SNAPSHOT" -eq 1 ]; then
  echo ">>> goreleaser snapshot"
  go run github.com/goreleaser/goreleaser/v2@latest release --clean --snapshot
  echo
  echo "Snapshot build complete. Inspect dist/ locally."
  exit 0
fi

if git rev-parse "$VERSION" >/dev/null 2>&1; then
  echo "error: tag $VERSION already exists locally" >&2
  exit 1
fi

if git ls-remote --exit-code --tags origin "$VERSION" >/dev/null 2>&1; then
  echo "error: tag $VERSION already exists on origin" >&2
  exit 1
fi

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "Preparing release"
echo "  version: $VERSION"
echo "  branch:  $CURRENT_BRANCH"
echo "  commit:  $(git rev-parse --short HEAD)"

confirm

echo ">>> git tag -a $VERSION"
git tag -a "$VERSION" -m "Release $VERSION"

echo ">>> git push origin $VERSION"
git push origin "$VERSION"

cat <<EOF

Release tag pushed.

Next:
  1. Watch the GitHub Release workflow for tag $VERSION.
  2. Verify the published archives and checksums.
  3. Smoke-test the installer:
     curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | sh
EOF
