#!/usr/bin/env bash

set -euo pipefail

mkdir -p resigned tmp apple_signed

archs=(arm64-darwin x86_64-darwin)

# Thins
for arch in "${archs[@]}"; do
  out=tmp/test.$arch
  if ! [ -e "$out" ]; then
    cc -target "$arch" -o "$out" -DMESSAGE="\"$arch\"" main.c
  fi
  files+=("$out")
done

# Fat
lipo -create "${files[@]}" -output tmp/test
files+=(tmp/test)

failures=()

resign() {
  local input=$1

  local name
  name=$(basename "$input")
  local out=resigned/$name

  echo "Re-signing and checking: $name"

  allocate_archs=()
  while read -r arch sigsize; do
    sigsize=$(( ((sigsize + 15) / 16) * 16 + 1024 ))
    allocate_archs+=(-a "$arch" "$sigsize")
  done < <(sigtool --file "$input" size)

  codesign_allocate -i "$input" "${allocate_archs[@]}" -o "$out"
  sigtool --identifier "$name" --file "$out" inject

  # This must be actual codesign
  if codesign --verify -vvv "$out"; then
    echo "OK: $name"
  else
    echo "FAIL: $name"
    failures+=("$name")
  fi

  echo
}

for f in "${files[@]}"; do
  resign "$f"
done

if [ "${#failures[@]}" -eq 0 ]; then
  exit 0
else
  echo "Failed: ${failures[*]}"
  exit 1
fi
