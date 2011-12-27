/*-
 * Copyright (c) 2011 Alexander Nasonov.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "bpfjit.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/types.h>

#if defined(SLJIT_VERBOSE) && SLJIT_VERBOSE
#include <stdio.h> /* for stderr */
#endif

/*
 * Generate code for BPF_LD+BPF_B+BPF_ABS    A <- P[k:1].
 */
static int
emit_ld_b_abs(struct sljit_compiler* compiler, struct bpf_insn *pc)
{

	return sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_A, 0,
	    SLJIT_MEM1(BPFJIT_BUF), pc->k);
}

/*
 * Generate code for BPF_LD+BPF_H+BPF_ABS    A <- P[k:2].
 */
static int
emit_ld_h_abs(struct sljit_compiler* compiler, struct bpf_insn *pc)
{
	int status;

	/* tmp1 = buf[pc->k]; */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_TMP1, 0,
	    SLJIT_MEM1(BPFJIT_BUF), pc->k);
	if (status != SLJIT_SUCCESS)
		return status;

	/* tmp2 = buf[pc->k+1]; */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_TMP2, 0,
	    SLJIT_MEM1(BPFJIT_BUF), pc->k+1);
	if (status != SLJIT_SUCCESS)
		return status;

	/* tmp1 = tmp1 << 8; */
	status = sljit_emit_op2(compiler,
	    SLJIT_SHL,
	    BPFJIT_TMP1, 0,
	    BPFJIT_TMP1, 0,
	    SLJIT_IMM, 8);
	if (status != SLJIT_SUCCESS)
		return status;

	/* A = tmp1 + tmp2; */
	status = sljit_emit_op2(compiler,
	    SLJIT_ADD,
	    BPFJIT_A, 0,
	    BPFJIT_TMP1, 0,
	    BPFJIT_TMP2, 0);
	return status;
}

/*
 * Generate code for BPF_LD+BPF_W+BPF_ABS    A <- P[k:4].
 */
static int
emit_ld_w_abs(struct sljit_compiler* compiler, struct bpf_insn *pc)
{
	int status;

	/* tmp1 = buf[pc->k]; */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_TMP1, 0,
	    SLJIT_MEM1(BPFJIT_BUF), pc->k);
	if (status != SLJIT_SUCCESS)
		return status;

	/* tmp2 = buf[pc->k+1]; */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_TMP2, 0,
	    SLJIT_MEM1(BPFJIT_BUF), pc->k+1);
	if (status != SLJIT_SUCCESS)
		return status;

	/* A = buf[pc->k+3]; */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_A, 0,
	    SLJIT_MEM1(BPFJIT_BUF), pc->k+3);
	if (status != SLJIT_SUCCESS)
		return status;

	/* tmp1 = tmp1 << 24; */
	status = sljit_emit_op2(compiler,
	    SLJIT_SHL,
	    BPFJIT_TMP1, 0,
	    BPFJIT_TMP1, 0,
	    SLJIT_IMM, 24);
	if (status != SLJIT_SUCCESS)
		return status;

	/* A = A + tmp1; */
	status = sljit_emit_op2(compiler,
	    SLJIT_ADD,
	    BPFJIT_A, 0,
	    BPFJIT_A, 0,
	    BPFJIT_TMP1, 0);
	if (status != SLJIT_SUCCESS)
		return status;

	/* tmp1 = buf[pc->k+2]; */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_TMP1, 0,
	    SLJIT_MEM1(BPFJIT_BUF), pc->k+2);
	if (status != SLJIT_SUCCESS)
		return status;

	/* tmp2 = tmp2 << 16; */
	status = sljit_emit_op2(compiler,
	    SLJIT_SHL,
	    BPFJIT_TMP2, 0,
	    BPFJIT_TMP2, 0,
	    SLJIT_IMM, 16);
	if (status != SLJIT_SUCCESS)
		return status;

	/* A = A + tmp2; */
	status = sljit_emit_op2(compiler,
	    SLJIT_ADD,
	    BPFJIT_A, 0,
	    BPFJIT_A, 0,
		BPFJIT_TMP2, 0);
	if (status != SLJIT_SUCCESS)
		return status;

	/* tmp1 = tmp1 << 8; */
	status = sljit_emit_op2(compiler,
	    SLJIT_SHL,
	    BPFJIT_TMP1, 0,
	    BPFJIT_TMP1, 0,
	    SLJIT_IMM, 8);
	if (status != SLJIT_SUCCESS)
		return status;

	/* A = A + tmp1; */
	status = sljit_emit_op2(compiler,
	    SLJIT_ADD,
	    BPFJIT_A, 0,
	    BPFJIT_A, 0,
		BPFJIT_TMP1, 0);
	return status;
}

/*
 * Count out-of-bounds jumps in BPF_LD and BPF_LDX instructions.
 */
static size_t
count_oob_jumps(struct bpf_insn *insns, size_t insn_count)
{
	size_t rv = 0;
	struct bpf_insn *pc;

	for (pc = insns; pc != insns + insn_count; pc++) {
		switch (BPF_CLASS(pc->code)) {
		case BPF_LD:
			switch (BPF_MODE(pc->code)) {
			case BPF_ABS: rv += 1; break;
			case BPF_IND: rv += 2; break;
			}
			break;
		case BPF_LDX:
			if (pc->code & BPF_MSH)
				rv++;
			break;
		}
	}

	return rv;
}

/*
 * Count BPF_RET instructions.
 */
static size_t
count_ret_insns(struct bpf_insn *insns, size_t insn_count)
{
	size_t rv = 0;
	struct bpf_insn *pc;

	for (pc = insns; pc != insns + insn_count; pc++) {
		if (BPF_CLASS(pc->code) == BPF_RET)
			rv++;
	}

	return rv;
}

#if 0
/*
 * Convert BPF_ALU operations except BPF_DIV.
 */
static int
bpf_alu_to_sljit(struct bpf_insn *pc)
{

	switch (BPF_OP(pc->code)) {
	case BPF_ADD: return SLJIT_ADD;
	case BPF_SUB: return SLJIT_SUB;
	case BPF_MUL: return SLJIT_MUL;
	case BPF_OR:  return SLJIT_OR;
	case BPF_AND: return SLJIT_AND;
	case BPF_LSH: return SLJIT_SHL;
	case BPF_RSH: return SLJIT_LSHR; /* XXX or SLJIT_ASHR? */
	default:
		assert(false);
	}
}
#endif

#if 0
/*
 * Convert BPF_JMP operations except BPF_JA and BPF_JSET.
 */
static int
bpf_jmp_to_sljit_cond(struct bpf_insn *pc)
{

	switch (BPF_OP(pc->code)) {
	case BPF_NEG: return SLJIT_NOT;
	case BPF_JEQ: return SLJIT_C_EQUAL;
	case BPF_JGT: return SLJIT_C_GREATER;
	case BPF_JGE: return SLJIT_C_GREATER_EQUAL;
	default:
		assert(false);
	}
}
#endif

/*
 * Convert BPF_JMP operations except BPF_JA and BPF_JSET.
 */
static int
bpf_jmp_to_sljit_cond_inverted(struct bpf_insn *pc)
{

	switch (BPF_OP(pc->code)) {
	case BPF_JGT: return SLJIT_C_LESS_EQUAL;
	case BPF_JGE: return SLJIT_C_LESS;
	case BPF_JEQ: return SLJIT_C_NOT_EQUAL;
	default:
		assert(false);
	}
}

static int
read_width(struct bpf_insn *pc)
{

	switch (BPF_SIZE(pc->code)) {
	case BPF_W:
		return 4;
	case BPF_H:
		return 2;
	case BPF_B:
		return 1;
	default:
		return -1;
	}
}

static bool
skip_A_init(struct bpf_insn *insns, size_t insn_count)
{

	/* XXX implement */
	return false;
}

static bool
skip_X_init(struct bpf_insn *insns, size_t insn_count)
{

	/* XXX implement */
	return false;
}


void *
bpfjit_generate_code(struct bpf_insn *insns, size_t insn_count)
{
	void *rv;
	size_t i;
	int status;
	int width;
	unsigned int rval, mode;
	int num_used_memwords;
	struct sljit_compiler* compiler;

	/* jumps[pc-insns] stores a list of jumps to instruction pc */
	SLIST_HEAD(, bpfjit_jump) *jumps;

	/* a list of jumps to a normal return from a generated function */
	struct sljit_jump **returns;
	size_t returns_size, returns_maxsize;

	/* a list of jumps to out-of-bound return from a generated function */
	struct sljit_jump **oob;
	size_t oob_size, oob_maxsize;

	/* for local use */
	struct sljit_label *label;
	struct sljit_jump *jump;
	struct bpfjit_jump *bjump;

	rv = NULL;
	compiler = NULL;
	jumps = NULL;
	returns = NULL;
	oob = NULL;

	num_used_memwords = 0; /* XXX implement */

	jumps = calloc(insn_count, sizeof(jumps[0]));
	if (jumps == NULL)
		goto fail;

	for (i = 0; i < insn_count; i++)
		SLIST_INIT(&jumps[i]);

	returns_size = 0;
	returns_maxsize = count_ret_insns(insns, insn_count);
	if (returns_maxsize > 0) {
		returns = calloc(returns_maxsize, sizeof(returns[0]));
		if (returns == NULL)
			goto fail;
	}

	oob_size = 0;
	oob_maxsize = count_oob_jumps(insns, insn_count);
	if (oob_maxsize > 0) {
		oob = calloc(oob_maxsize, sizeof(oob[0]));
		if (oob == NULL)
			goto fail;
	}

	compiler = sljit_create_compiler();
	if (compiler == NULL)
		goto fail;

#if defined(SLJIT_VERBOSE) && SLJIT_VERBOSE
	sljit_compiler_verbose(compiler, stderr);
#endif

	status = sljit_emit_enter(compiler, 3, 4, 3,
	    num_used_memwords * sizeof(uint32_t));
	if (status != SLJIT_SUCCESS)
		goto fail;

	if (!skip_A_init(insns, insn_count)) {
		/* A = 0; */
		status = sljit_emit_op1(compiler,
		    SLJIT_MOV,
		    BPFJIT_A, 0,
		    SLJIT_IMM, 0);
		if (status != SLJIT_SUCCESS)
			goto fail;
	}

	if (!skip_X_init(insns, insn_count)) {
		/* X = 0; */
		status = sljit_emit_op1(compiler,
		    SLJIT_MOV,
		    BPFJIT_X, 0,
		    SLJIT_IMM, 0);
		if (status != SLJIT_SUCCESS)
			goto fail;
	}

	for (i = 0; i < insn_count; i++) {
		struct bpf_insn *pc = &insns[i];

		/*
		 * Resolve jumps to pc and remove not anymore
		 * needed bpfjit_jump entries from the list.
		 */
		if (!SLIST_EMPTY(&jumps[i])) {
			label = sljit_emit_label(compiler);
			if (label == NULL)
				goto fail;
			while (!SLIST_EMPTY(&jumps[i])) {
				bjump = SLIST_FIRST(&jumps[i]);
				sljit_set_label(bjump->bj_jump, label);
				free(bjump);
				SLIST_REMOVE_HEAD(&jumps[i], bj_entries);
			}
		}

		/*
		 * Command dispatcher.
		 */
		switch (BPF_CLASS(pc->code)) {

		default:
			goto fail;

		case BPF_LD:
			mode = BPF_MODE(pc->code);
			width = read_width(pc);
			if (width == -1)
				goto fail;

			if (mode == BPF_IND) {
				/* if (X > buflen) return 0; */
				jump = sljit_emit_cmp(compiler,
				    SLJIT_C_GREATER,
				    BPFJIT_X, 0,
				    BPFJIT_BUFLEN, 0);
				if (jump == NULL)
					goto fail;
				oob[oob_size++] = jump;

				/* temporarily do buf += X; buflen -= X; */
				status = sljit_emit_op2(compiler,
				    SLJIT_ADD,
				    BPFJIT_BUF, 0,
				    BPFJIT_BUF, 0,
				    BPFJIT_X, 0);
				if (status != SLJIT_SUCCESS)
					goto fail;

				status = sljit_emit_op2(compiler,
				    SLJIT_SUB,
				    BPFJIT_BUFLEN, 0,
				    BPFJIT_BUFLEN, 0,
				    BPFJIT_X, 0);
				if (status != SLJIT_SUCCESS)
					goto fail;
			}

			/* if (pc->k + width > buflen) return 0; */
			if (mode == BPF_ABS || mode == BPF_IND) {
				/* overflow check for pc->k + width */
				if (pc->k > UINT32_MAX - width)
					goto fail;
				jump = sljit_emit_cmp(compiler,
				    SLJIT_C_GREATER,
				    SLJIT_IMM, pc->k + (uint32_t)width,
				    BPFJIT_BUFLEN, 0);
				if (jump == NULL)
					goto fail;
				oob[oob_size++] = jump;
			}

			if (mode == BPF_ABS || mode == BPF_IND) {
				switch (width) {
				case 4:
					status = emit_ld_w_abs(compiler, pc);
					break;
				case 2:
					status = emit_ld_h_abs(compiler, pc);
					break;
				case 1:
					status = emit_ld_b_abs(compiler, pc);
					break;
				}
				if (status != SLJIT_SUCCESS)
					goto fail;
			}

			/* restore buf and buflen values: buf -= X; buflen += X; */
			if (mode == BPF_IND) {
				status = sljit_emit_op2(compiler,
				    SLJIT_SUB,
				    BPFJIT_BUF, 0,
				    BPFJIT_BUF, 0,
				    BPFJIT_X, 0);
				if (status != SLJIT_SUCCESS)
					goto fail;

				status = sljit_emit_op2(compiler,
				    SLJIT_ADD,
				    BPFJIT_BUFLEN, 0,
				    BPFJIT_BUFLEN, 0,
				    BPFJIT_X, 0);
				if (status != SLJIT_SUCCESS)
					goto fail;
			}

			/*
			 * XXX implement
			 * BPF_LD+BPF_W+BPF_LEN    A <- len
			 * BPF_LD+BPF_IMM          A <- k
			 * BPF_LD+BPF_MEM          A <- M[k]
			 */

			continue;

		case BPF_LDX:
			mode = BPF_MODE(pc->code);

			/* BPF_LDX+BPF_W+BPF_IMM    X <- k */
			if (mode == BPF_IMM) {
				if (BPF_SIZE(pc->code) != BPF_W)
					goto fail;
				status = sljit_emit_op1(compiler,
				    SLJIT_MOV,
				    BPFJIT_X, 0,
				    SLJIT_IMM, pc->k);
				if (status != SLJIT_SUCCESS)
					goto fail;
			}

			/*
			 * XXX implement
			 * BPF_LDX+BPF_W+BPF_MEM    X <- M[k]
			 * BPF_LDX+BPF_W+BPF_LEN    X <- len
			 * BPF_LDX+BPF_B+BPF_MSH    X <- 4*(P[k:1]&0xf)
			 */

			continue;

		case BPF_RET:
			rval = BPF_RVAL(pc->code);
			if (rval == BPF_X)
				goto fail;

			/* BPF_RET+BPF_K    accept k bytes */
			if (rval == BPF_K) {
				status = sljit_emit_op1(compiler,
				    SLJIT_MOV,
				    BPFJIT_A, 0,
				    SLJIT_IMM, pc->k);
				if (status != SLJIT_SUCCESS)
					goto fail;
			}

			/* BPF_RET+BPF_A    accept A bytes */
			if (rval == BPF_A) {
#if BPFJIT_A != SLJIT_RETURN_REG
				status = sljit_emit_op1(compiler,
				    SLJIT_MOV,
				    SLJIT_RETURN_REG, 0,
				    BPFJIT_A, 0);
				if (status != SLJIT_SUCCESS)
					goto fail;
#endif
			}

			/*
			 * Save a jump to a normal return. If the program
			 * ends with BPF_RET, no jump is needed because
			 * the normal return is generated right after the
			 * last instruction.
			 */
			if (i != insn_count - 1) {
				jump = sljit_emit_jump(compiler, SLJIT_JUMP);
				if (jump == NULL)
					goto fail;
				returns[returns_size++] = jump;
			}

			continue;

		case BPF_JMP:
			if (BPF_SRC(pc->code) == BPF_K) {
				bjump = malloc(sizeof(struct bpfjit_jump));
				if (bjump == NULL)
					goto fail;

				if (pc->jt == 0) {
					bjump->bj_jump = sljit_emit_cmp(
					    compiler,
					    bpf_jmp_to_sljit_cond_inverted(pc),
					    SLJIT_IMM, pc->k,
					    BPFJIT_A, 0);
					SLIST_INSERT_HEAD(&jumps[i + 1 + pc->jf],
					    bjump, bj_entries);
					if (bjump->bj_jump == NULL)
						goto fail;
				}
			}

			continue;
		} /* switch */
	} /* main loop */

	assert(oob_size == oob_maxsize);
	assert(returns_maxsize - returns_size <= 1);

	if (returns_size > 0) {
		label = sljit_emit_label(compiler);
		if (label == NULL)
			goto fail;
		for (i = 0; i < returns_size; i++)
			sljit_set_label(returns[i], label);
	}

	status = sljit_emit_return(compiler, BPFJIT_A, 0);
	if (status != SLJIT_SUCCESS)
		goto fail;

	if (oob_size > 0) {
		label = sljit_emit_label(compiler);
		if (label == NULL)
			goto fail;

		for (i = 0; i < oob_size; i++)
			sljit_set_label(oob[i], label);

		status = sljit_emit_op1(compiler,
		    SLJIT_MOV,
		    SLJIT_RETURN_REG, 0,
		    SLJIT_IMM, 0);
		if (status != SLJIT_SUCCESS)
			goto fail;

		status = sljit_emit_return(compiler, SLJIT_RETURN_REG, 0);
		if (status != SLJIT_SUCCESS)
			goto fail;
	}

	rv = sljit_generate_code(compiler);

fail:
	sljit_free_compiler(compiler);

	if (jumps != NULL) {
		for (i = 0; i < insn_count; i++) {
			while (!SLIST_EMPTY(&jumps[i])) {
				struct bpfjit_jump *head;
				head = SLIST_FIRST(&jumps[i]);
				SLIST_REMOVE_HEAD(&jumps[i], bj_entries);
				free(head);
			}
		}
		free(jumps);
	}

	if (returns != NULL)
		free(returns);

	if (oob != NULL)
		free(oob);

	return rv;
}

unsigned int
bpfjit_execute_code(const uint8_t *p, unsigned int wirelen,
    unsigned int buflen, const void *code)
{
	union
	{
		const void* code;
		sljit_uw (SLJIT_CALL *func)(const uint8_t *p,
		    sljit_uw wirelen, sljit_uw buflen);
	} func = { code };

	return func.func(p, wirelen, buflen);
}

void
bpfjit_free_code(void *code)
{
	sljit_free_code((void *)code);
}
