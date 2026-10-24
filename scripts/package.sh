#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-v1.0.0}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${PROJECT_ROOT}/dist"

TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
)

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

echo "=========================================="
echo "Packaging Raven Production Release ${VERSION}"
echo "=========================================="

for target in "${TARGETS[@]}"; do
  GOOS="${target%%/*}"
  GOARCH="${target##*/}"
  RELEASE_NAME="raven-${VERSION}-${GOOS}-${GOARCH}"
  STAGE_DIR="${DIST_DIR}/${RELEASE_NAME}"

  echo "🔨 Compiling for ${GOOS}/${GOARCH}..."
  mkdir -p "${STAGE_DIR}/bin" "${STAGE_DIR}/configs" "${STAGE_DIR}/scripts" "${STAGE_DIR}/migrations"

  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" go build -ldflags="-w -s" -o "${STAGE_DIR}/bin/raven" "${PROJECT_ROOT}/cmd/raven"

  cp -r "${PROJECT_ROOT}/scripts/"*.py "${STAGE_DIR}/scripts/"
  cp "${PROJECT_ROOT}/scripts/requirements.txt" "${STAGE_DIR}/scripts/"
  cp -r "${PROJECT_ROOT}/migrations/"*.sql "${STAGE_DIR}/migrations/"
  cp "${PROJECT_ROOT}/configs/config.yaml.example" "${STAGE_DIR}/configs/config.yaml"
  cp "${PROJECT_ROOT}/README.md" "${STAGE_DIR}/"

  chmod +x "${STAGE_DIR}/bin/raven" "${STAGE_DIR}/scripts/"*.py

  echo "📦 Creating archive ${RELEASE_NAME}.tar.gz..."
  tar -czf "${DIST_DIR}/${RELEASE_NAME}.tar.gz" -C "${DIST_DIR}" "${RELEASE_NAME}"
  rm -rf "${STAGE_DIR}"

  echo "✅ Packaged: ${DIST_DIR}/${RELEASE_NAME}.tar.gz"
done

echo ""
echo "🎉 All release bundles successfully generated in ${DIST_DIR}:"
ls -lh "${DIST_DIR}"/*.tar.gz
