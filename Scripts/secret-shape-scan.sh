#!/bin/sh
set -eu
root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"

if git grep -n -E '(BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{20,}|Bearer [A-Za-z0-9._~-]{20,}|AKIA[0-9A-Z]{16})' -- ':!Scripts/secret-shape-scan.sh'; then
  echo "credential-like material found" >&2
  exit 1
fi

echo "secret-shape scan passed"
