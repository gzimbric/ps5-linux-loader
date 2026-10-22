#!/bin/sh
set -eu

nm=$1
loader=$2
ap=$3
map=$4
object=$5
marker=$6

if "$nm" "$loader" | grep -Eq 'hv_defeat|fetch_linux|prepare_resume|vmcb_disable'; then
  echo "pro-census check: production loader path was linked" >&2
  exit 1
fi
if "$nm" "$ap" | grep -Eq 'vmcb_write|vmcb_disable|write(32|64)'; then
  echo "pro-census check: AP contains an HV write helper" >&2
  exit 1
fi
if grep -Eq 'source/(main|loader|prepare_resume|hv_defeat).*\.o' "$map"; then
  echo "pro-census check: production object present in link map" >&2
  exit 1
fi
grep -Fq "$object" "$map"
if ! strings "$loader" | grep -Fxq "$marker"; then
  echo "pro-census check: artifact marker '$marker' is missing" >&2
  exit 1
fi
echo "pro-census check: isolated $marker loader and read-only AP"
