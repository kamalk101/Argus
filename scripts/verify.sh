#!/usr/bin/env bash
# Verify the cross-platform core: build, unit tests, replay assertions, selftest.
# Requires the .NET 8 SDK (user-local install in ~/.dotnet is fine).
set -euo pipefail

cd "$(dirname "$0")/.."

export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1

DOTNET="${DOTNET:-}"
if [[ -z "$DOTNET" ]]; then
  if [[ -x "$HOME/.dotnet/dotnet" ]]; then
    DOTNET="$HOME/.dotnet/dotnet"
  else
    DOTNET="dotnet"
  fi
fi

if ! "$DOTNET" --version >/dev/null 2>&1; then
  echo "error: .NET SDK not found. Install .NET 8 locally:" >&2
  echo "  curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh" >&2
  echo "  bash /tmp/dotnet-install.sh --channel 8.0 --install-dir \"\$HOME/.dotnet\" --no-path" >&2
  exit 1
fi

echo "== dotnet $("$DOTNET" --version) =="
"$DOTNET" build Argus.sln -v q --nologo
"$DOTNET" test Argus.sln --nologo -v q
"$DOTNET" run --project src/Argus.Cli -v q --no-build -- replay tests/fixtures/scenarios --assert
"$DOTNET" run --project src/Argus.Cli -v q --no-build -- selftest

echo
echo "verify.sh: all checks passed"
