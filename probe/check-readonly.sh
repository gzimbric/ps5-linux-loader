#!/bin/sh
# Build gate for the read-only probe.
#   check-readonly.sh               check the probe sources
#   check-readonly.sh NM OBJ...     also check the objects' undefined symbols
# Fails on kernel write primitives, page-table edits, HV or rest-mode entry
# points, raw system calls, the SDK's socket primitives, inline asm, code
# loading, console identity APIs, sysctl writes, any ioctl other than
# PCIOCGETCONF, any device node other than /dev/pci, and any object import
# that is not on the list below.
set -eu
dir=$(cd "$(dirname "$0")" && pwd)
srcs="$dir/probe.c $dir/hash.c $dir/hash.h"
fail=0
what=sources

bad='kernel_copyin|kernel_set|kernel_proc_copyin|kernel_proc_set'
bad="$bad|kernel_mprotect|kernel_overlap_sockets|kernel_dynlib"
bad="$bad|kwrite|write_kernel|pte_store|install_page|page_chain_set_rw"
bad="$bad|page_remove_global|enter_rest_mode|SuspendStart|SetEventFlag"
bad="$bad|vmmcall|wrmsr|(^|[^A-Za-z_])(__)?asm([^A-Za-z_]|$)|PROT_EXEC"
bad="$bad|dlopen|dlsym|LoadStartModule|exec[lv]|/dev/mem|/dev/kmem|O_RDWR"
bad="$bad|SerialNumber|IdPs|PsId|Idps|Psid|MacAddr|AccountId|kenv"
bad="$bad|syscall|setsockopt|getsockopt|(^|[^A-Za-z_])socket\(|mmap|mprotect"
bad="$bad|ptrace|sysarch|payload_get_args|fcntl\("

if grep -nE "$bad" $srcs; then
  echo "check-readonly: forbidden call or API in the probe sources" >&2
  fail=1
fi
# Every sysctl call is a read: no new value.
if grep -nE '(^|[^A-Za-z_])sysctl(byname)?\(' $srcs | grep -v 'NULL, 0)'; then
  echo "check-readonly: sysctl call that may set a value" >&2
  fail=1
fi
if grep -nE '(^|[^A-Za-z_])ioctl\(' $srcs | grep -v 'PCIOCGETCONF'; then
  echo "check-readonly: ioctl other than PCIOCGETCONF" >&2
  fail=1
fi
if grep -nE '"/dev/' $srcs | grep -v '"/dev/pci", O_RDONLY)'; then
  echo "check-readonly: device node other than /dev/pci read-only" >&2
  fail=1
fi

# Objects may import exactly these symbols and nothing else. The sha256_*
# and fnv64_masked imports are defined in hash.o.
if [ $# -ge 2 ]; then
  nm=$1
  shift
  what="sources and objects"
  allow=" KERNEL_ADDRESS_ALLPROC KERNEL_ADDRESS_DATA_BASE"
  allow="$allow KERNEL_ADDRESS_DMAP_BASE KERNEL_ADDRESS_TEXT_BASE"
  allow="$allow KERNEL_OFFSET_PROC_P_PID KERNEL_OFFSET_PROC_P_VMSPACE"
  allow="$allow KERNEL_OFFSET_VMSPACE_VM_PMAP"
  allow="$allow kernel_copyout kernel_get_fw_version kernel_get_proc"
  allow="$allow sceKernelGetCurrentCpu sceKernelGetHwModelName"
  allow="$allow sceKernelGetMainSocId sceKernelSendNotificationRequest"
  allow="$allow sha256_final sha256_hex sha256_init sha256_update fnv64_masked"
  allow="$allow __error close cpuset_getaffinity cpuset_setaffinity fsync"
  allow="$allow getpid gmtime_r ioctl memcmp memcpy memset mkdir open poll"
  allow="$allow rename sched_yield signal snprintf stat statfs strchr strcmp"
  allow="$allow strcspn strftime strlen strrchr sysctl sysctlbyname"
  allow="$allow sysctlnametomib time unlink usleep vsnprintf write "
  for obj in "$@"; do
    for s in $("$nm" -u "$obj" | awk 'NF {print $NF}' | grep -v ':$'); do
      case "$allow" in
      *" $s "*) ;;
      *)
        echo "check-readonly: $obj imports $s, which is not on the list" >&2
        fail=1
        ;;
      esac
    done
  done
fi

[ $fail -eq 0 ] || exit 1
echo "check-readonly: ok ($what)"
