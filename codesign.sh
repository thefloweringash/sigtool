#!/usr/bin/env bash

# Mimic a subset of the interface of codesign
# Requires mktemp from coreutils

set -euo pipefail

allocate=${CODESIGN_ALLOCATE-codesign_allocate}

while getopts "i:s:fv" opt; do
  case "$opt" in
    i)
      global_identifier=$OPTARG
      ;;
    s)
      # signing identity
      if [ "$OPTARG" != - ]; then
        echo "Only adhoc signatures supported" >&2
        exit 1
      fi
      ;;
    f)
      # force
      ;;
    v)
      # verbose
      verbose=1
      ;;
    ?)
      echo "Invalid options" >&2
      exit 1
      ;;
  esac
done

shift $((OPTIND-1))

signDarwinBinary() {
  local path="$1"
  local sigsize arch identifier tempfile

  # This only supports mktemp for coreutils
  tempfile=$(mktemp -p "$(dirname "$path")" "$(basename "$path").XXXXXX")
  identifier=${global_identifier-$(basename "$path")}

  arch=$(sigtool --file "$path" show-arch)

  sigsize=$(sigtool --file "$path" size)
  sigsize=$(( ((sigsize + 15) / 16) * 16 + 1024 ))

  "$allocate" -i "$path" -a "$arch" "$sigsize" -o "$tempfile"
  sigtool --identifier "$identifier" --file "$tempfile" inject
  mv -f "$tempfile" "$path"
}

if [ "${verbose-}" ]; then
  set -x
fi

for f in "$@"; do
  signDarwinBinary "$1"
done
