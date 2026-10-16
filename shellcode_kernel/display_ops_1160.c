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

typedef uint64_t (*display_op1_fn)(uint32_t);
typedef uint64_t (*display_op2_fn)(uint32_t, uint64_t);

void run_ps5_display_ops_1160(void) {
  for (uint32_t i = 0; i < 29; i++) {
    const ps5_display_op_1160 *op = &ps5_display_ops_1160[i];
    const uintptr_t target = args.ktext + op->ktext_offset;

    printf("11.60 display op %u starting\n", i + 1);
    if (op->mode == 2)
      ((display_op2_fn)target)(op->arg1_edi, op->arg2_rsi);
    else
      ((display_op1_fn)target)(op->arg1_edi);
    printf("11.60 display op %u returned\n", i + 1);
  }
}
