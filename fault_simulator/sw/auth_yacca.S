/* auth_yacca.S – Secure boot authorization WITH YACCA_CMP protection
 *
 * Reference: Vankeirsbilck PhD Thesis §2.3.2 YACCA, KU Leuven 2020.
 *            Goloubeva et al., "Software-Implemented Hardware Fault Tolerance"
 * Target   : biRISC-V (RV32I) via biRISC-V TCM testbench
 *
 * ─── YACCA_CMP MECHANISM ─────────────────────────────────────────────────
 * Each basic block is assigned a unique compile-time signature B_X.
 * A run-time register (t5 = "code") tracks the last-executed block.
 *
 *   END   of block X:   xori t5, t5, M2_X    →  t5 becomes B_X
 *   START of block Y:   addi t4, x0, B_pred_Y
 *                       bne  t5, t4, error_handler   (CFE check)
 *
 * where M2_X = B_pred_X XOR B_X.
 *
 * In error-free execution B_X is always the last predecessor's identity.
 * A fault that causes an invalid CFG edge results in t5 ≠ B_pred_Y → error.
 *
 * ─── COMPILE-TIME CONSTANTS ──────────────────────────────────────────────
 *
 *   CODE_INIT = 1          (initial code value – no predecessor)
 *   B_A = 5, B_B = 7, B_C = 11, B_D = 13
 *
 *   M2_A = CODE_INIT XOR B_A = 1  XOR 5  = 4
 *   M2_B = B_A       XOR B_B = 5  XOR 7  = 2
 *   M2_C = B_B       XOR B_C = 7  XOR 11 = 12
 *   M2_D = B_B       XOR B_D = 7  XOR 13 = 10
 *
 * ─── FAULT ATTACK & DETECTION ────────────────────────────────────────────
 *
 *  Fault: "j block_b" at Block A end → "j block_c" (skips Block B)
 *
 *  After fault:
 *    t5 = B_A = 5   (set at end of Block A)
 *    Block C checks: t4 = B_B = 7;  bne t5(5), t4(7) → TAKEN → error!
 *
 *  Error handler: a0 = -1, store to RESULT_ADDR, ebreak.
 *
 * ─── REGISTER ALLOCATION ─────────────────────────────────────────────────
 *   t0 (x5)  = user_token
 *   t1 (x6)  = secret_key
 *   t2 (x7)  = result value
 *   t3 (x28) = base address for result store
 *   t4 (x29) = YACCA temp (expected predecessor signature)
 *   t5 (x30) = YACCA code register (run-time CFG signature)
 * ─────────────────────────────────────────────────────────────────────────
 */

    .section .text
    .global  main
    .type    main, @function

/* Output address and result codes */
.equ RESULT_ADDR,  0x80010000
.equ RESULT_GRANT, 1
.equ RESULT_DENY,  0
.equ RESULT_ERROR, -1       /* fits in 12-bit ADDI as -1 */

/* YACCA compile-time signatures */
.equ CODE_INIT,  1
.equ B_A,        5
.equ B_B,        7
.equ B_C,        11
.equ B_D,        13
.equ M2_A,       4   /* CODE_INIT XOR B_A */
.equ M2_B,       2   /* B_A XOR B_B */
.equ M2_C,       12  /* B_B XOR B_C */
.equ M2_D,       10  /* B_B XOR B_D */

main:
/* ═══════════════════════════════════════════════════════
 * BLOCK A – Entry / Initialization (no predecessor check)
 * ═══════════════════════════════════════════════════════ */
block_a:
    li    t5, CODE_INIT         /* YACCA: init code = 1 */
    li    t0, 0                 /* user_token = 0 (unauthorized) */
    li    t1, 0x50              /* secret_key = 80 */
    xori  t5, t5, M2_A         /* YACCA: code = 1 XOR 4 = 5 = B_A */
    j     block_b               /* ← FAULT POINT: replace with j block_c */

/* ═══════════════════════════════════════════════════════
 * BLOCK B – Authorization check
 * Predecessor: Block A  →  code must be B_A = 5
 * ═══════════════════════════════════════════════════════ */
block_b:
    /* YACCA: verify predecessor */
    li    t4, B_A               /* expected predecessor = 5 */
    bne   t5, t4, error_handler /* code ≠ B_A → CFE detected! */

    /* YACCA: update code BEFORE the branch (both successors see B_B) */
    xori  t5, t5, M2_B         /* code = 5 XOR 2 = 7 = B_B */

    /* Application: compare token */
    bne   t0, t1, block_d       /* if token ≠ key → deny */
    j     block_c               /* token matched → grant */

/* ═══════════════════════════════════════════════════════
 * BLOCK C – GRANT ACCESS  ← ATTACK TARGET
 * Predecessor: Block B  →  code must be B_B = 7
 *
 * FAULT DETECTION: fault delivers code = B_A = 5 ≠ 7 → error!
 * ═══════════════════════════════════════════════════════ */
block_c:
    /* YACCA: verify predecessor */
    li    t4, B_B               /* expected predecessor = 7 */
    bne   t5, t4, error_handler /* code ≠ B_B → ATTACK DETECTED! */

    /* Application: grant access */
    li    t2, RESULT_GRANT
    lui   t3, %hi(RESULT_ADDR)
    sw    t2, %lo(RESULT_ADDR)(t3)
    xori  t5, t5, M2_C         /* YACCA: code = B_C = 11 */
    ebreak

/* ═══════════════════════════════════════════════════════
 * BLOCK D – DENY ACCESS
 * Predecessor: Block B  →  code must be B_B = 7
 * ═══════════════════════════════════════════════════════ */
block_d:
    /* YACCA: verify predecessor */
    li    t4, B_B               /* expected predecessor = 7 */
    bne   t5, t4, error_handler /* code ≠ B_B → CFE detected! */

    /* Application: deny access */
    li    t2, RESULT_DENY
    lui   t3, %hi(RESULT_ADDR)
    sw    t2, %lo(RESULT_ADDR)(t3)
    xori  t5, t5, M2_D         /* YACCA: code = B_D = 13 */
    ebreak

/* ═══════════════════════════════════════════════════════
 * ERROR HANDLER – CFE detected by YACCA
 * Reached when code register doesn't match expected predecessor.
 * ═══════════════════════════════════════════════════════ */
error_handler:
    li    t2, RESULT_ERROR      /* -1 = CFE detected */
    lui   t3, %hi(RESULT_ADDR)
    sw    t2, %lo(RESULT_ADDR)(t3)
    ebreak                      /* signal to testbench: attack stopped */

error_loop:
    j     error_loop            /* safety halt */

    .size main, . - main
