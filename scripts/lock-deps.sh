#!/usr/bin/env bash
# Regenerate the hashed lockfile and CycloneDX SBOM from requirements.in
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v uv >/dev/null 2>&1; then
  echo "Compiling hashed lockfile with uv..."
  uv pip compile --generate-hashes -o requirements.txt requirements.in
  AUDIT=(uvx pip-audit)
else
  echo "Compiling hashed lockfile with pip-tools..."
  python3 -m pip install --quiet pip-tools
  pip-compile --generate-hashes -o requirements.txt requirements.in
  python3 -m pip install --quiet pip-audit
  AUDIT=(pip-audit)
fi

echo "Generating CycloneDX SBOM..."
mkdir -p sbom
"${AUDIT[@]}" -r requirements.txt --progress-spinner off --format cyclonedx-json -o sbom/cyclonedx.json

echo "Auditing locked dependencies..."
"${AUDIT[@]}" -r requirements.txt --progress-spinner off

echo "Done. Commit requirements.txt and sbom/cyclonedx.json together."
