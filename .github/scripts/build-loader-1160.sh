#!/usr/bin/env bash

set -euo pipefail

: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_REF_NAME:?GITHUB_REF_NAME is required}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"
: "${PS5_PAYLOAD_SDK_VERSION:?PS5_PAYLOAD_SDK_VERSION is required}"
: "${PS5_PAYLOAD_SDK_SHA256:?PS5_PAYLOAD_SDK_SHA256 is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

dist="$RUNNER_TEMP/loader-1160-dist"
targets="$RUNNER_TEMP/loader-1160-targets"
rm -rf "$dist"
mkdir -p "$dist/build-info" "$dist/targets"

# target|ELF|DMA E820|visible refusals|Wi-Fi firmware|bounded files|
# historical regular release|historical file SHA-256|historical code SHA-256
cat >"$targets" <<'TARGETS'
linux-1160|bin/ps5-linux-loader-1160.elf|0|0|0|0|Run 15|422b87ec39ca0edfce8dddd609c2eff1cc7adcb2732b7909b76fafbd60dd2336|f900298838f8a8b83954fdae5c5eb9ff6a9c628add6437bc10790e905aba8503
linux-1160-dma-e820|bin/ps5-linux-loader-1160-dma-e820.elf|1|0|0|0|Run 18 DMA E820|2e1758a2d013305bcb9faa0eb3adf18c34ed76ad85313dd945719c8bf2a0c9c0|6737e7352b3b6bdbad83c4e6b4980c07926f9624b3e4a3dfe52f2a5ea0f3038c
linux-1160-dma-e820-visible|bin/ps5-linux-loader-1160-dma-e820-visible.elf|1|1|0|0|||
linux-1160-dma-e820-wifi|bin/ps5-linux-loader-1160-dma-e820-wifi.elf|1|1|1|0|||
linux-1160-dma-e820-bounded|bin/ps5-linux-loader-1160-dma-e820-bounded.elf|1|1|0|1|Run 21 bounded tester prerelease (non-Wi-Fi, unbooted)|1c80b040c5a808b3f09418728424a875d5598fe6b2a5d68adeb4db5979a7541a|fdabc92c7f7373e2805c66e8614d36703d63e1df67c32b4230bf8f6168651724
linux-1160-dma-e820-bounded-wifi|bin/ps5-linux-loader-1160-dma-e820-bounded-wifi.elf|1|1|1|1|Run 21 bounded Wi-Fi tester prerelease|e9fe6469943e97a635eccd3f674e55876b56cd1bbd69023eee3af4acea3a1b5f|7b4588e3441fb83b3843196c6ebb20fb630dc737cdd7b9e0945dc7a86fdfbace
TARGETS

verdict() {
  if [ "$1" = "$2" ]; then
    printf '%s\n' same
  else
    printf '%s\n' different
  fi
}

check_direct_target() {
  target=$1
  elf=$2
  expected_dma_e820=$3
  plan="$RUNNER_TEMP/${target}-direct-target.plan"

  # The normal build runs first so generated headers exist. -B then prints
  # the complete recursive build plan without changing the completed ELF.
  make -B -n "$elf" >"$plan"
  grep -Fq -- \
    "-DPS5_1160_DMA_E820_SAFE=$expected_dma_e820" "$plan"

  opposite=$((1 - expected_dma_e820))
  if grep -Fq -- "-DPS5_1160_DMA_E820_SAFE=$opposite" "$plan"; then
    cat "$plan"
    return 1
  fi

  if [ "$target" = linux-1160-dma-e820 ]; then
    reject_mixed "$elf" bin/ps5-linux-loader-1160.elf
    reject_mixed bin/ps5-linux-loader-1160.elf "$elf"
  fi
}

reject_mixed() {
  log="$RUNNER_TEMP/mixed-goals.log"
  if make -n "$@" >"$log" 2>&1; then
    cat "$log"
    return 1
  fi
  grep -Fq 'in a separate make invocation' "$log"
}

write_build_info() {
  target=$1
  elf=$2
  release=$3
  release_sha256=$4
  code_sha256=$5
  target_dist=$6
  name=$(basename "$elf")

  llvm-objcopy --remove-section=.comment \
    --remove-section=.note.gnu.build-id "$elf" "$RUNNER_TEMP/${target}-code.elf"
  file_sha=$(shasum -a 256 "$elf" | cut -d' ' -f1)
  code_sha=$(shasum -a 256 "$RUNNER_TEMP/${target}-code.elf" | cut -d' ' -f1)

  if [ -n "$release_sha256" ]; then
    file_match=$(verdict "$file_sha" "$release_sha256")
    code_match=$(verdict "$code_sha" "$code_sha256")
  else
    file_match=unpinned
    code_match=unpinned
  fi

  {
    echo "commit: $GITHUB_SHA"
    echo "ref: $GITHUB_REF_NAME"
    echo "target: $target"
    echo "runner: macOS $(sw_vers -productVersion) $(uname -m)"
    echo "llvm: $("$LLVM_CONFIG" --version)"
    echo "lld: $("$(brew --prefix lld)/bin/ld.lld" --version)"
    echo "gcc: $(x86_64-elf-gcc --version | head -n1)"
    echo "binutils: $(x86_64-elf-ld --version | head -n1)"
    echo "ps5-payload-sdk: $PS5_PAYLOAD_SDK_VERSION ($PS5_PAYLOAD_SDK_SHA256)"
    echo
    echo "sha256: $file_sha"
    echo "sha256 without .comment and build ID: $code_sha"
    if [ "$file_match" = unpinned ]; then
      echo "not pinned: no pinned release file to compare with"
    else
      echo "historical $release file: $release_sha256 ($file_match)"
      echo "historical $release code: $code_sha256 ($code_match)"
    fi
  } >"$target_dist/build-info.txt"

  cp "$target_dist/build-info.txt" "$dist/build-info/${name%.elf}.txt"
  cat "$target_dist/build-info.txt"

  {
    echo "### $name"
    echo
    echo '```'
    cat "$target_dist/build-info.txt"
    echo '```'
  } >>"$GITHUB_STEP_SUMMARY"

  if [ "$code_match" = unpinned ]; then
    echo "::notice title=$target::sha256 $file_sha (not pinned)"
  elif [ "$code_match" = same ]; then
    echo "::notice title=$target::code matches historical $release (file hash $file_match)"
  else
    echo "::notice title=$target::code differs from historical $release (expected for the universal regular/Pro loader)"
  fi
}

built=0

# Exercise the public wake-argument ABI and reject mixed or off-by-one regular
# and Pro HV address pairs. The startup-AP synthetic-DMAP test runs through
# every target's break-hv-1160-check dependency.
mkdir -p build/tests
cc -std=c11 -O2 -Wall -Wextra -Werror tests/test_shellcode_kernel_args.c \
  -o build/tests/test_shellcode_kernel_args
build/tests/test_shellcode_kernel_args

while IFS='|' read -r target elf dma_e820 visible_refusals wifi_fw \
  bounded_boot_files release release_sha256 code_sha256; do
  if ! grep -Eq "^${target}([[:space:]]|:)" Makefile; then
    echo "::notice title=$target::not in this branch's Makefile, skipped"
    continue
  fi

  # Every target starts with an empty build tree. This prevents the nested HV
  # and wake blobs, which share filenames, from leaking between configurations.
  make clean
  make "$target"
  check_direct_target "$target" "$elf" "$dma_e820"

  PS5_1160_DIAGNOSTIC=1 \
  PS5_1160_ELF="$elf" \
  PS5_1160_DMA_E820_SAFE="$dma_e820" \
  PS5_1160_VISIBLE_REFUSALS="$visible_refusals" \
  PS5_1160_WIFI_FW="$wifi_fw" \
  PS5_1160_BOUNDED_BOOT_FILES="$bounded_boot_files" \
    python3 tests/audit_1160_port.py

  if [ "$bounded_boot_files" = 1 ]; then
    mkdir -p build/tests
    cc -std=c11 -Wall -Wextra -Werror tests/test_boot_files_1160.c \
      -o build/tests/test_boot_files_1160
    build/tests/test_boot_files_1160
  fi

  name=$(basename "$elf")
  target_dist="$dist/targets/$target"
  mkdir -p "$target_dist"
  cp "$elf" "$target_dist/$name"
  (cd "$target_dist" && shasum -a 256 "$name" >SHA256SUMS)
  cp "$elf" "$dist/$name"
  write_build_info "$target" "$elf" "$release" "$release_sha256" \
    "$code_sha256" "$target_dist"
  built=$((built + 1))
done <"$targets"

if [ "$built" -eq 0 ]; then
  echo 'No 11.60 loader targets were present in this revision.' >&2
  exit 1
fi

(cd "$dist" && shasum -a 256 ./*.elf >SHA256SUMS)
{
  echo
  echo '### Combined artifact'
  echo
  echo "Built $built target(s). The combined SHA256SUMS covers every ELF."
  echo
  echo '```'
  cat "$dist/SHA256SUMS"
  echo '```'
} >>"$GITHUB_STEP_SUMMARY"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "dist=$dist" >>"$GITHUB_OUTPUT"
  echo "artifact=ps5-linux-loader-1160-${GITHUB_SHA::7}" >>"$GITHUB_OUTPUT"
fi
