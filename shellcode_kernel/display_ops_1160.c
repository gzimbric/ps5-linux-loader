#include "display_ops_1160.h"
#include "shellcode_kernel_args.h"
#include "utils.h"
#include <stddef.h>

/*
 * Sonic's wake blob runs this ordered table after the VBIOS/DP/MP3 handoff
 * and Linux staging, but before the final SMP rendezvous.  Every target below
 * is the authenticated 11.60 structural homolog of Sonic's 13.60 target; no
 * 13.60 address is executed on the console.
 *
 * The record ABI deliberately matches Sonic's 0x18-byte table.  The original
 * dispatcher always loads EDI from arg1_edi, even when mode is zero.  Mode 2
 * additionally loads RSI from arg2_rsi.  Preserve that behavior: entries
 * 15--18 and 26 rely on non-default EDI values.
 */
_Static_assert(sizeof(ps5_display_op_1160) == 0x18,
               "Sonic display-op record ABI changed");

const ps5_display_op_1160 ps5_display_ops_1160[29] = {
    {0x00362730, 0, 0, 0},
    {0x00362980, 0, 0, 0},
    {0x00362AD0, 0, 0, 0},
    {0x00362C90, 0, 0, 0},
    {0x00C16F70, 0, 0, 0},
    {0x00333410, 0, 0, 0},
    {0x00751F20, 0, 0, 0},
    {0x00B01800, 0, 0, 0},
    {0x005381C0, 0, 0, 0},
    {0x005383B0, 0, 0, 0},
    {0x00362AA0, 0, 0, 0},
    {0x00B88B80, 0, 0, 0},
    {0x00B896F0, 0, 0, 0},
    {0x00B89900, 0, 0, 0},
    {0x00B89A40, 0, 0, 0},
    {0x00334460, 0, 0, 0},
    {0x00334460, 1, 0, 0},
    {0x00334460, 2, 0, 0},
    {0x00334460, 3, 0, 0},
    {0x00362CC0, 0, 0, 0},
    {0x00538580, 0, 0, 0},
    {0x00538700, 0, 0, 0},
    {0x00B88C70, 0, 0, 0},
    {0x007585F0, 0, 0, 0},
    {0x009DC910, 1, 2, 0x7F0},
    {0x0053D9F0, 0, 0, 0},
    {0x00539460, 1, 0, 0},
    {0x00538ED0, 0, 0, 0},
    {0x00538D70, 0, 0, 0},
};

_Static_assert(sizeof(ps5_display_ops_1160) == 29 * 0x18,
               "Sonic display-op table size changed");

#if SHELLCODE_1160_DIAGNOSTIC
#ifndef PS5_1160_DIAG_OP_LIMIT
#define PS5_1160_DIAG_OP_LIMIT 29
#endif
_Static_assert(PS5_1160_DIAG_OP_LIMIT >= 0 && PS5_1160_DIAG_OP_LIMIT <= 29,
               "11.60 diagnostic display-op limit is out of range");
volatile const uint32_t ps5_diag_display_op_limit_1160 =
    PS5_1160_DIAG_OP_LIMIT;
#endif

typedef uint64_t (*display_op1_fn)(uint32_t);
typedef uint64_t (*display_op2_fn)(uint32_t, uint64_t);

/*
 * Keep Sonic's two-layer call shape: the outer loop CALLs this leaf, then the
 * leaf tail-JMPs to the selected kernel target.  The target's RET therefore
 * returns directly to the outer loop's post-operation checkpoint.
 */
__attribute__((noinline)) static uint64_t
dispatch_ps5_display_op_1160(uint32_t index) {
  if (index >= 29)
    return 0;

  const ps5_display_op_1160 *op = &ps5_display_ops_1160[index];
  const uintptr_t target = args.ktext + op->ktext_offset;

  if (op->mode == 2)
    return ((display_op2_fn)target)(op->arg1_edi, op->arg2_rsi);
  return ((display_op1_fn)target)(op->arg1_edi);
}

void run_ps5_display_ops_1160(void) {
  uint32_t completed = 0;

  for (;;) {
#if SHELLCODE_1160_DIAGNOSTIC
    const uint32_t limit = ps5_diag_display_op_limit_1160;
#else
    const uint32_t limit = 29;
#endif

    if (completed >= limit)
      break;

    const uint32_t index = completed++;
    printf("11.60 display op %u starting\n", index + 1);
    dispatch_ps5_display_op_1160(index);
    printf("11.60 display op %u returned\n", index + 1);
  }
}
