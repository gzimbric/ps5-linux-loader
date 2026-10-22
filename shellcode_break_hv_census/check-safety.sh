#!/bin/sh
set -eu

dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

if grep -nE 'vmcb_write|write(32|64)' \
  "$dir/census.c"; then
  echo "census safety: a VMCB write path is present" >&2
  exit 1
fi

grep -q 'const volatile uint8_t \*p' "$dir/census.c"
grep -q 'const volatile void \*address' "$dir/census.c"

if [ "$#" -ge 2 ]; then
  nm=$1
  elf=$2
  if "$nm" "$elf" | grep -Eq 'vmcb_write|vmcb_disable|write(32|64)'; then
    echo "census safety: forbidden write helper linked" >&2
    exit 1
  fi
fi

echo "census safety: no HV write helper or mutable HV pointer"
