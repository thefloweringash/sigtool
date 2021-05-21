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
  local -a allocate_archs=()

  # This only supports mktemp for coreutils
  tempfile=$(mktemp -p "$(dirname "$path")" "$(basename "$path").XXXXXX")
  identifier=${global_identifier-$(basename "$path")}

  while read -r arch sigsize; do
    sigsize=$(( ((sigsize + 15) / 16) * 16 + 1024 ))
    allocate_archs+=(-a "$arch" "$sigsize")
  done < <(sigtool --file "$path" size)

  "$allocate" -i "$path" "${allocate_archs[@]}" -o "$tempfile"
  sigtool --identifier "$identifier" --file "$tempfile" inject
  mv -f "$tempfile" "$path"
}

if [ "${verbose-}" ]; then
  set -x
fi

for f in "$@"; do
  signDarwinBinary "$f"
done
