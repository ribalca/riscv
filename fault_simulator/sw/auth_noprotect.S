/* auth_noprotect.S – Secure boot authorization WITHOUT YACCA protection
 *
 * Reference: Vankeirsbilck PhD Thesis §2.3.2 YACCA, KU Leuven 2020.
 * Target   : biRISC-V (RV32I) via biRISC-V TCM testbench
 *
 * ─── SCENARIO ────────────────────────────────────────────────────────────
 * A device checks an authorization token before granting boot access.
 *   user_token  = 0x00  (attacker: unauthorized)
 *   secret_key  = 0x50  (the correct token)
 *
 * Expected behavior (no fault):  user gets ACCESS DENIED  (result = 0)
 * After fault attack:            user gets ACCESS GRANTED (result = 1) !!
 *
 * ─── CFG ─────────────────────────────────────────────────────────────────
 *
 *   block_a ──j──► block_b
 *                     │ bne (token≠key)          ← FAULT skips block_b
 *              block_c◄┴──► block_d              ← fault lands here
 *              (GRANT)       (DENY)
 *
 * Fault: replace "j block_b" with "j block_c" at 0x80000008.
 *        Processor jumps directly to block_c, bypassing the check.
 *
 * ─── RESULT OUTPUT ───────────────────────────────────────────────────────
 * Result is stored to RESULT_ADDR = 0x80010000 and signalled via EBREAK.
 * The testbench monitors data writes to 0x80010000.
 *
 * ─── REGISTER ALLOCATION ─────────────────────────────────────────────────
 *   t0 (x5)  = user_token
 *   t1 (x6)  = secret_key
 *   t2 (x7)  = result value
 *   t3 (x28) = base address for result store
 * ─────────────────────────────────────────────────────────────────────────
 */

    .section .text
    .global  main
    .type    main, @function

/* Output address and result codes */
.equ RESULT_ADDR,  0x80010000
.equ RESULT_GRANT, 1
.equ RESULT_DENY,  0

main:
/* ═══════════════════════════════════════════════════════
 * BLOCK A – Entry / Initialization
 * No predecessor (program entry).
 * ═══════════════════════════════════════════════════════ */
block_a:
    li    t0, 0             /* t0 = user_token = 0 (unauthorized) */
    li    t1, 0x50          /* t1 = secret_key = 80 */
    j     block_b           /* ← FAULT POINT: replace with j block_c */

/* ═══════════════════════════════════════════════════════
 * BLOCK B – Authorization check
 * Valid predecessors: ONLY Block A.
 * ═══════════════════════════════════════════════════════ */
block_b:
    bne   t0, t1, block_d   /* if token ≠ key → deny */
    j     block_c           /* token matches → grant */

/* ═══════════════════════════════════════════════════════
 * BLOCK C – GRANT ACCESS  ← ATTACK TARGET
 * Valid predecessors: ONLY Block B (fall-through when token matches).
 * With fault: reached directly from Block A → SECURITY BREACH!
 * ═══════════════════════════════════════════════════════ */
block_c:
    li    t2, RESULT_GRANT
    lui   t3, %hi(RESULT_ADDR)
    sw    t2, %lo(RESULT_ADDR)(t3)
    ebreak                  /* signal result to testbench */

/* ═══════════════════════════════════════════════════════
 * BLOCK D – DENY ACCESS
 * Valid predecessors: ONLY Block B (branch when token mismatches).
 * ═══════════════════════════════════════════════════════ */
block_d:
    li    t2, RESULT_DENY
    lui   t3, %hi(RESULT_ADDR)
    sw    t2, %lo(RESULT_ADDR)(t3)
    ebreak                  /* signal result to testbench */

    .size main, . - main
