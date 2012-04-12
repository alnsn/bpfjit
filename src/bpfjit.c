/*-
 * Copyright (c) 2011-2012 Alexander Nasonov.
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
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/types.h>

#if defined(SLJIT_VERBOSE) && SLJIT_VERBOSE
#include <stdio.h> /* for stderr */
#endif

#include <sljitLir.h>


#define BPFJIT_A	SLJIT_TEMPORARY_REG1
#define BPFJIT_X	SLJIT_TEMPORARY_EREG1
#define BPFJIT_TMP1	SLJIT_TEMPORARY_REG2
#define BPFJIT_TMP2	SLJIT_TEMPORARY_REG3
#define BPFJIT_BUF	SLJIT_SAVED_REG1
#define BPFJIT_WIRELEN	SLJIT_SAVED_REG2
#define BPFJIT_BUFLEN	SLJIT_SAVED_REG3

/* 
 * Flags for bpfjit_optimization_hints().
 */
#define BPFJIT_INIT_X 0x10000
#define BPFJIT_INIT_A 0x20000


struct bpfjit_jump
{
	struct sljit_jump *bj_jump;
	SLIST_ENTRY(bpfjit_jump) bj_entries;
};

struct bpfjit_insn_data
{
	uint32_t bj_length;
	bool bj_unreachable;

	/* List of jumps to this insn. */
	SLIST_HEAD(, bpfjit_jump) bj_jumps;

	/*
	 * These entries make up bj_jumps list.
	 * bj_jtf[0] - for jt
	 * bj_jtf[1] - for jf
	 */
	struct bpfjit_jump bj_jtf[2];
};

struct bpfjit_stack_entry
{
	struct bpf_insn *bj_insn;
	uint32_t bj_length;
};


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
		assert(false);
		return -1;
	}
}

/*
 * Generate code for BPF_LD+BPF_B+BPF_ABS    A <- P[k:1].
 */
static int
emit_read8(struct sljit_compiler* compiler, uint32_t k)
{

	return sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_A, 0,
	    SLJIT_MEM1(BPFJIT_BUF), k);
}

/*
 * Generate code for BPF_LD+BPF_H+BPF_ABS    A <- P[k:2].
 */
static int
emit_read16(struct sljit_compiler* compiler, uint32_t k)
{
	int status;

	/* tmp1 = buf[k]; */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_TMP1, 0,
	    SLJIT_MEM1(BPFJIT_BUF), k);
	if (status != SLJIT_SUCCESS)
		return status;

	/* A = buf[k+1]; */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_A, 0,
	    SLJIT_MEM1(BPFJIT_BUF), k+1);
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
 * Generate code for BPF_LD+BPF_W+BPF_ABS    A <- P[k:4].
 */
static int
emit_read32(struct sljit_compiler* compiler, uint32_t k)
{
	int status;

	/* tmp1 = buf[k]; */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_TMP1, 0,
	    SLJIT_MEM1(BPFJIT_BUF), k);
	if (status != SLJIT_SUCCESS)
		return status;

	/* tmp2 = buf[k+1]; */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_TMP2, 0,
	    SLJIT_MEM1(BPFJIT_BUF), k+1);
	if (status != SLJIT_SUCCESS)
		return status;

	/* A = buf[k+3]; */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_A, 0,
	    SLJIT_MEM1(BPFJIT_BUF), k+3);
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

	/* tmp1 = buf[k+2]; */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_TMP1, 0,
	    SLJIT_MEM1(BPFJIT_BUF), k+2);
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
 * Generate code for BPF_LDX+BPF_B+BPF_MSH    X <- 4*(P[k:1]&0xf).
 */
static int
emit_msh(struct sljit_compiler* compiler, uint32_t k)
{
	int status;

	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPFJIT_TMP1, 0,
	    SLJIT_MEM1(BPFJIT_BUF), k);
	if (status != SLJIT_SUCCESS)
		return status;

	status = sljit_emit_op2(compiler,
	    SLJIT_AND,
	    BPFJIT_TMP1, 0,
	    BPFJIT_TMP1, 0,
	    SLJIT_IMM, 0xf);
	if (status != SLJIT_SUCCESS)
		return status;

	return sljit_emit_op2(compiler,
	    SLJIT_SHL,
	    BPFJIT_X, 0,
	    BPFJIT_TMP1, 0,
	    SLJIT_IMM, 2);
}

static int
emit_pow2_division(struct sljit_compiler* compiler, uint32_t k)
{
	int shift = 0;
	int status = SLJIT_SUCCESS;

	while (k > 1) {
		k >>= 1;
		shift++;
	}

	assert(k == 1 && shift < 32);

	if (shift != 0) {
		status = sljit_emit_op2(compiler,
		    SLJIT_LSHR|SLJIT_INT_OP,
		    BPFJIT_A, 0,
		    BPFJIT_A, 0,
		    SLJIT_IMM, shift);
	}

	return status;
}

#if !defined(BPFJIT_USE_UDIV)
static sljit_uw
divide(sljit_uw x, sljit_uw y)
{

	return (uint32_t)x / (uint32_t)y;
}
#endif

/*
 * Generate A = A / div.
 * divt,divw are either SLJIT_IMM,pc->k or BPFJIT_X,0.
 */
static int
emit_division(struct sljit_compiler* compiler, int divt, sljit_w divw)
{
	int status;

#if BPFJIT_X == SLJIT_TEMPORARY_REG1 || \
    BPFJIT_X == SLJIT_RETURN_REG     || \
    BPFJIT_X == SLJIT_TEMPORARY_REG2 || \
    BPFJIT_A == SLJIT_TEMPORARY_REG2
#error "Not supported assignment of registers."
#endif

#if BPFJIT_A != SLJIT_TEMPORARY_REG1
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV,
	    SLJIT_TEMPORARY_REG1, 0,
	    BPFJIT_A, 0);
	if (status != SLJIT_SUCCESS)
		return status;
#endif

	status = sljit_emit_op1(compiler,
	    SLJIT_MOV,
	    SLJIT_TEMPORARY_REG2, 0,
	    divt, divw);
	if (status != SLJIT_SUCCESS)
		return status;

#if defined(BPFJIT_USE_UDIV)
	status = sljit_emit_op0(compiler, SLJIT_UDIV|SLJIT_INT_OP);

#if BPFJIT_A != SLJIT_TEMPORARY_REG1
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV,
	    BPFJIT_A, 0,
	    SLJIT_TEMPORARY_REG1, 0);
	if (status != SLJIT_SUCCESS)
		return status;
#endif
#else
	status = sljit_emit_ijump(compiler,
	    SLJIT_CALL2,
	    SLJIT_IMM, SLJIT_FUNC_OFFSET(divide));

#if BPFJIT_A != SLJIT_RETURN_REG
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV,
	    BPFJIT_A, 0,
	    SLJIT_RETURN_REG, 0);
	if (status != SLJIT_SUCCESS)
		return status;
#endif
#endif

	return status;
}

/*
 * Count the following:
 * returns  - BPF_RET instructions
 * branches - jumps with pc->jt != pc->jf
 */
static void
get_sizes(struct bpf_insn *insns, size_t insn_count,
    size_t *returns, size_t *branches)
{
	struct bpf_insn *pc;

	*returns = 0;
	*branches = 0;

	for (pc = insns; pc != insns + insn_count; pc++) {
		switch (BPF_CLASS(pc->code)) {
		case BPF_JMP:
			if (pc->code != (BPF_JMP|BPF_JA) && pc->jt != pc->jf)
				*branches += 1;
			continue;
		case BPF_RET:
			*returns += 1;
			continue;
		}
	}
}

/*
 * The first optimization pass divides instructions into linear blocks.
 * A block either don't have BPF_RET and BPF_JMP instructions or one
 * of these instructions is the last instruction in the block. Any jump
 * instruction always points to the first instruction of some block.
 * The function also sets initial values of bj_length fields to complete
 * an initialization of insn_dat elements.
 * XXX finish implementation
 */
static int
optimize_pass1(struct bpf_insn *insns,
    struct bpfjit_insn_data *insn_dat, size_t insn_count)
{
	size_t i;
	int unreachable;
	uint32_t jt, jf;
	struct bpf_insn *pc;
	struct bpfjit_insn_data *jdst;

	for (i = 0; i < insn_count; i++) {
		insn_dat[i].bj_length = UINT32_MAX;
		SLIST_INIT(&insn_dat[i].bj_jumps);
		insn_dat[i].bj_jtf[0].bj_jump = NULL;
		insn_dat[i].bj_jtf[1].bj_jump = NULL;
	}

	unreachable = 0;
	for (i = 0; i < insn_count; i++) {
		if (!SLIST_EMPTY(&insn_dat[i].bj_jumps))
			unreachable = 0;

		insn_dat[i].bj_unreachable = unreachable;

		if (unreachable)
			continue;
		
		pc = &insns[i];
		switch (BPF_CLASS(pc->code)) {
		case BPF_RET:
			unreachable = 1;
			continue;

		case BPF_JMP:
			if (pc->code == (BPF_JMP|BPF_JA)) {
				jt = jf = pc->k;
			} else {
				jt = pc->jt;
				jf = pc->jf;
			}

			if (jt >= insn_count - (i + 1) ||
			    jf >= insn_count - (i + 1)) {
				return -1;
			}

			if (jt > 0 && jf > 0)
				unreachable = 1;

			jdst = &insn_dat[i + 1 + jt];
			SLIST_INSERT_HEAD(&jdst->bj_jumps,
			    &insn_dat[i].bj_jtf[0], bj_entries);

			if (jf != jt) {
				jdst = &insn_dat[i + 1 + jf];
				SLIST_INSERT_HEAD(&jdst->bj_jumps,
				    &insn_dat[i].bj_jtf[1], bj_entries);
			}

			continue;
		}
	}

	return 0;
}

/*
 * Walk through all branches and calculate:
 *  (a) a guaranteed minimum length of a packet,
 *  (b) XXX loaded/unloaded flag of all M[k], A and X registers
 * at each intruction i.
 *
 * stack - an array with a size obtained from get_sizes() call.
 */
static int
optimize(struct bpf_insn *insns,
    struct bpfjit_insn_data *insn_dat, size_t insn_count,
    struct bpfjit_stack_entry stack[])
{
	size_t depth;
	uint32_t length;
	struct bpf_insn *pc;
	unsigned int mode;
	int width;

	if (optimize_pass1(insns, insn_dat, insn_count) != 0)
		return -1;

	depth = 0;
	length = 0;
	for (pc = insns; pc != insns + insn_count; pc++) {

		if (insn_dat[pc - insns].bj_length > length)
			insn_dat[pc - insns].bj_length = length;

		switch (BPF_CLASS(pc->code)) {
		default:
			continue;

		case BPF_LD:
			if (pc->code == (BPF_LD|BPF_IMM) ||
			    pc->code == (BPF_LD|BPF_MEM)) {
			    continue;
			}

			mode = BPF_MODE(pc->code);
			if (mode != BPF_ABS && mode != BPF_IND)
				continue;
			
			width = read_width(pc);
			if (pc->k > UINT32_MAX - width)
				length = UINT32_MAX;
			else if (length < pc->k + width)
				length = pc->k + width;

			continue;

		case BPF_LDX:
			if (pc->code != (BPF_LDX|BPF_B|BPF_MSH))
				continue;

			if (pc->k == UINT32_MAX)
				length = UINT32_MAX;
			else if (length < pc->k + 1)
				length = pc->k + 1;

			continue;

		case BPF_JMP:
			if (pc->code == (BPF_JMP|BPF_JA)) {
				pc += pc->k;
			} else if (pc->jt == pc->jf) {
				pc += pc->jt;
			} else {
				stack[depth].bj_insn = pc + pc->jf;
				stack[depth].bj_length = length;
				depth++;
				pc += pc->jt;
			}
			continue;

		case BPF_RET:
			if (depth == 0)
				break;
			depth--;
			pc     = stack[depth].bj_insn;
			length = stack[depth].bj_length;
			continue;
		}
	}

	assert(depth == 0); /* valid program should end with BPF_RET */

	return 0;
}

/*
 * Count out-of-bounds and division by zero jumps.
 *
 * insn_dat should be initialized by optimize().
 */
static size_t
get_ret0_size(struct bpf_insn *insns, size_t insn_count,
    struct bpfjit_insn_data *insn_dat)
{
	size_t rv = 0;
	struct bpf_insn *pc;

	for (pc = insns; pc != insns + insn_count; pc++) {
		switch (BPF_CLASS(pc->code)) {
		case BPF_LD:
			if (pc->code != (BPF_LD|BPF_IMM) &&
			    pc->code != (BPF_LD|BPF_MEM)) {
				switch (BPF_MODE(pc->code)) {
				case BPF_ABS: rv += 1; break;
				case BPF_IND: rv += 2; break;
				}
			}
			continue;
		case BPF_LDX:
			if (pc->code == (BPF_LDX|BPF_B|BPF_MSH))
				rv += 1;
			continue;
		case BPF_ALU:
			if (pc->code == (BPF_ALU|BPF_DIV|BPF_X))
				rv += 1;
			if (pc->code == (BPF_ALU|BPF_DIV|BPF_K) && pc->k == 0)
				rv += 1;
			continue;
		}
	}

	return rv;
}

/*
 * Convert BPF_ALU operations except BPF_NEG and BPF_DIV to sljit operation.
 */
static int
bpf_alu_to_sljit_op(struct bpf_insn *pc)
{

	/*
	 * Note: all supported 64bit arches have 32bit multiply
	 * instruction so SLJIT_INT_OP doesn't have any overhead.
	 */
	switch (BPF_OP(pc->code)) {
	case BPF_ADD: return SLJIT_ADD;
	case BPF_SUB: return SLJIT_SUB;
	case BPF_MUL: return SLJIT_MUL|SLJIT_INT_OP;
	case BPF_OR:  return SLJIT_OR;
	case BPF_AND: return SLJIT_AND;
	case BPF_LSH: return SLJIT_SHL;
	case BPF_RSH: return SLJIT_LSHR|SLJIT_INT_OP;
	default:
		assert(false);
	}
}

/*
 * Convert BPF_JMP operations except BPF_JA to sljit condition.
 */
static int
bpf_jmp_to_sljit_cond(struct bpf_insn *pc, bool negate)
{
	/*
	 * Note: all supported 64bit arches have 32bit comparison
	 * instructions so SLJIT_INT_OP doesn't have any overhead.
	 */
	int rv = SLJIT_INT_OP;

	switch (BPF_OP(pc->code)) {
	case BPF_JGT:
		rv |= negate ? SLJIT_C_LESS_EQUAL : SLJIT_C_GREATER;
		break;
	case BPF_JGE:
		rv |= negate ? SLJIT_C_LESS : SLJIT_C_GREATER_EQUAL;
		break;
	case BPF_JEQ:
		rv |= negate ? SLJIT_C_NOT_EQUAL : SLJIT_C_EQUAL;
		break;
	case BPF_JSET:
		rv |= negate ? SLJIT_C_EQUAL : SLJIT_C_NOT_EQUAL;
		break;
	default:
		assert(false);
	}

	return rv;
}

static unsigned int
bpfjit_optimization_hints(struct bpf_insn *insns, size_t insn_count)
{
	unsigned int rv = BPFJIT_INIT_A;
	struct bpf_insn *pc;
	int minm, maxm;

	assert(BPF_MEMWORDS - 1 <= 0xff);

	maxm = 0;
	minm = BPF_MEMWORDS - 1;

	for (pc = insns; pc != insns + insn_count; pc++) {
		switch (BPF_CLASS(pc->code)) {
		case BPF_LD:
			if (BPF_MODE(pc->code) == BPF_IND)
				rv |= BPFJIT_INIT_X;
			if (BPF_MODE(pc->code) == BPF_MEM &&
			    pc->k >= 0 && pc->k < BPF_MEMWORDS) {
				if (pc->k > maxm)
					maxm = pc->k;
				if (pc->k < minm)
					minm = pc->k;
			}
			continue;
		case BPF_LDX:
			rv |= BPFJIT_INIT_X;
			if (BPF_MODE(pc->code) == BPF_MEM &&
			    pc->k >= 0 && pc->k < BPF_MEMWORDS) {
				if (pc->k > maxm)
					maxm = pc->k;
				if (pc->k < minm)
					minm = pc->k;
			}
			continue;
		case BPF_ST:
			if (pc->k >= 0 && pc->k < BPF_MEMWORDS) {
				if (pc->k > maxm)
					maxm = pc->k;
				if (pc->k < minm)
					minm = pc->k;
			}
			continue;
		case BPF_STX:
			rv |= BPFJIT_INIT_X;
			if (pc->k >= 0 && pc->k < BPF_MEMWORDS) {
				if (pc->k > maxm)
					maxm = pc->k;
				if (pc->k < minm)
					minm = pc->k;
			}
			continue;
		case BPF_ALU:
			if (pc->code == (BPF_ALU|BPF_NEG))
				continue;
			if (BPF_SRC(pc->code) == BPF_X)
				rv |= BPFJIT_INIT_X;
			continue;
		case BPF_JMP:
			if (pc->code == (BPF_JMP|BPF_JA))
				continue;
			if (BPF_SRC(pc->code) == BPF_X)
				rv |= BPFJIT_INIT_X;
			continue;
		case BPF_RET:
			continue;
		case BPF_MISC:
			rv |= BPFJIT_INIT_X;
			continue;
		default:
			assert(false);
		}
	}

	return rv | (maxm << 8) | minm;
}

/*
 * Convert BPF_K and BPF_X to sljit register.
 */
static int
kx_to_reg(struct bpf_insn *pc)
{

	switch (BPF_SRC(pc->code)) {
	case BPF_K: return SLJIT_IMM;
	case BPF_X: return BPFJIT_X;
	default:
		assert(false);
	}
}

static sljit_w
kx_to_reg_arg(struct bpf_insn *pc)
{

	switch (BPF_SRC(pc->code)) {
	case BPF_K: return (uint32_t)pc->k; /* SLJIT_IMM, pc->k, */
	case BPF_X: return 0;               /* BPFJIT_X, 0,      */
	default:
		assert(false);
	}
}

bpfjit_function_t
bpfjit_generate_code(struct bpf_insn *insns, size_t insn_count)
{
	void *rv;
	size_t i;
	int status;
	int width;
	int jalways, negate;
	unsigned int rval, mode, src;
	size_t locals_size;
	int minm, maxm; /* min/max k for M[k] */
	unsigned int opts;
	struct bpf_insn *pc;
	struct sljit_compiler* compiler;

	/* a list of jumps to a normal return from a generated function */
	struct sljit_jump **returns;
	size_t returns_size, returns_maxsize;

	/* a list of jumps to out-of-bound return from a generated function */
	struct sljit_jump **ret0;
	size_t ret0_size, ret0_maxsize;

	/* stack for optimize() */
	struct bpfjit_stack_entry *stack;
	size_t stack_maxsize;

	/*
	 * minimal guaranteed lengths that don't need to be checked
	 * XXX
	 */
	struct bpfjit_insn_data *insn_dat;

	/* for local use */
	struct sljit_label *label;
	struct sljit_jump *jump;
	struct bpfjit_jump *bjump;

	uint32_t jt, jf;

	rv = NULL;
	compiler = NULL;
	insn_dat = NULL;
	returns = NULL;
	ret0 = NULL;
	stack = NULL;

	opts = bpfjit_optimization_hints(insns, insn_count);
	minm = opts & 0xff;
	maxm = (opts >> 8) & 0xff;
	locals_size = (minm <= maxm) ? (maxm - minm + 1) * sizeof(uint32_t) : 0;

	get_sizes(insns, insn_count, &returns_maxsize, &stack_maxsize);

	if (returns_maxsize  == 0)
		goto fail;

	insn_dat = calloc(insn_count, sizeof(insn_dat[0]));
	if (insn_dat == NULL)
		goto fail;

	if (stack_maxsize > 0) {
		stack = calloc(stack_maxsize, sizeof(struct bpfjit_stack_entry));
		if (stack == NULL)
			goto fail;
	}

	if (optimize(insns, insn_dat, insn_count, stack) < 0)
		goto fail;

	ret0_size = 0;
	ret0_maxsize = get_ret0_size(insns, insn_count, insn_dat);
	if (ret0_maxsize > 0) {
		ret0 = calloc(ret0_maxsize, sizeof(ret0[0]));
		if (ret0 == NULL)
			goto fail;
	}

	returns_size = 0;
	returns = calloc(returns_maxsize, sizeof(returns[0]));
	if (returns == NULL)
		goto fail;

	compiler = sljit_create_compiler();
	if (compiler == NULL)
		goto fail;

#if defined(SLJIT_VERBOSE) && SLJIT_VERBOSE
	sljit_compiler_verbose(compiler, stderr);
#endif

	status = sljit_emit_enter(compiler, 3, 4, 3, locals_size);
	if (status != SLJIT_SUCCESS)
		goto fail;

	for (i = 0; i < locals_size; i+= sizeof(uint32_t)) {
		status = sljit_emit_op1(compiler,
		    SLJIT_MOV_UI,
		    SLJIT_MEM1(SLJIT_LOCALS_REG), i,
		    SLJIT_IMM, 0);
		if (status != SLJIT_SUCCESS)
			goto fail;
	}

	if (opts & BPFJIT_INIT_A) {
		/* A = 0; */
		status = sljit_emit_op1(compiler,
		    SLJIT_MOV,
		    BPFJIT_A, 0,
		    SLJIT_IMM, 0);
		if (status != SLJIT_SUCCESS)
			goto fail;
	}

	if (opts & BPFJIT_INIT_X) {
		/* X = 0; */
		status = sljit_emit_op1(compiler,
		    SLJIT_MOV,
		    BPFJIT_X, 0,
		    SLJIT_IMM, 0);
		if (status != SLJIT_SUCCESS)
			goto fail;
	}

	for (i = 0; i < insn_count; i++) {
		if (insn_dat[i].bj_unreachable)
			continue;

		/*
		 * Resolve jumps to the current insn.
		 */
		label = NULL;
		SLIST_FOREACH(bjump, &insn_dat[i].bj_jumps, bj_entries) {
			if (bjump->bj_jump != NULL) {
				if (label == NULL)
					label = sljit_emit_label(compiler);
				if (label == NULL)
					goto fail;
				sljit_set_label(bjump->bj_jump, label);
			}
		}

		/*
		 * Command dispatcher.
		 */
		pc = &insns[i];
		switch (BPF_CLASS(pc->code)) {

		default:
			goto fail;

		case BPF_LD:
			/* BPF_LD+BPF_IMM          A <- k */
			if (pc->code == (BPF_LD|BPF_IMM)) {
				status = sljit_emit_op1(compiler,
				    SLJIT_MOV,
				    BPFJIT_A, 0,
				    SLJIT_IMM, (uint32_t)pc->k);
				if (status != SLJIT_SUCCESS)
					goto fail;

				continue;
			}

			/* BPF_LD+BPF_MEM          A <- M[k] */
			if (pc->code == (BPF_LD|BPF_MEM)) {
				if (pc->k < minm || pc->k > maxm)
					goto fail;
				status = sljit_emit_op1(compiler,
				    SLJIT_MOV_UI,
				    BPFJIT_A, 0,
				    SLJIT_MEM1(SLJIT_LOCALS_REG),
				    (pc->k - minm) * sizeof(uint32_t));
				if (status != SLJIT_SUCCESS)
					goto fail;

				continue;
			}

			/* BPF_LD+BPF_W+BPF_LEN    A <- len */
			if (pc->code == (BPF_LD|BPF_W|BPF_LEN)) {
				status = sljit_emit_op1(compiler,
				    SLJIT_MOV,
				    BPFJIT_A, 0,
				    BPFJIT_WIRELEN, 0);
				if (status != SLJIT_SUCCESS)
					goto fail;

				continue;
			}

			mode = BPF_MODE(pc->code);
			if (mode != BPF_ABS && mode != BPF_IND)
				goto fail;

			/*
			 * BPF_LD+BPF_W+BPF_ABS    A <- P[k:4]
			 * BPF_LD+BPF_H+BPF_ABS    A <- P[k:2]
			 * BPF_LD+BPF_B+BPF_ABS    A <- P[k:1]
			 * BPF_LD+BPF_W+BPF_IND    A <- P[X+k:4]
			 * BPF_LD+BPF_H+BPF_IND    A <- P[X+k:2]
			 * BPF_LD+BPF_B+BPF_IND    A <- P[X+k:1]
			 */

			if (mode == BPF_IND) {
				/* if (X > buflen) return 0; */
				jump = sljit_emit_cmp(compiler,
				    SLJIT_C_GREATER,
				    BPFJIT_X, 0,
				    BPFJIT_BUFLEN, 0);
				if (jump == NULL)
					goto fail;
				ret0[ret0_size++] = jump;

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

			width = read_width(pc);
			if (width == -1)
				goto fail;

			if (pc->k > UINT32_MAX - width) {
				/* return 0; */
				jump = sljit_emit_jump(compiler, SLJIT_JUMP);
				if (jump == NULL)
					goto fail;
				ret0[ret0_size++] = jump;
			} else if (mode == BPF_IND ||
			    pc->k + width > insn_dat[i].bj_length) {
				/* if (pc->k + width > buflen) return 0; */
				jump = sljit_emit_cmp(compiler,
				    SLJIT_C_GREATER,
				    SLJIT_IMM, (uint32_t)pc->k + width,
				    BPFJIT_BUFLEN, 0);
				if (jump == NULL)
					goto fail;
				ret0[ret0_size++] = jump;
			}

			switch (width) {
			case 4:
				status = emit_read32(compiler, (uint32_t)pc->k);
				break;
			case 2:
				status = emit_read16(compiler, (uint32_t)pc->k);
				break;
			case 1:
				status = emit_read8(compiler, (uint32_t)pc->k);
				break;
			}

			if (status != SLJIT_SUCCESS)
				goto fail;

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
				    SLJIT_IMM, (uint32_t)pc->k);
				if (status != SLJIT_SUCCESS)
					goto fail;

				continue;
			}

			/* BPF_LDX+BPF_W+BPF_LEN    X <- len */
			if (mode == BPF_LEN) {
				if (BPF_SIZE(pc->code) != BPF_W)
					goto fail;
				status = sljit_emit_op1(compiler,
				    SLJIT_MOV,
				    BPFJIT_X, 0,
				    BPFJIT_WIRELEN, 0);
				if (status != SLJIT_SUCCESS)
					goto fail;

				continue;
			}

			/* BPF_LDX+BPF_W+BPF_MEM    X <- M[k] */
			if (mode == BPF_MEM) {
				if (BPF_SIZE(pc->code) != BPF_W)
					goto fail;
				if (pc->k < minm || pc->k > maxm)
					goto fail;
				status = sljit_emit_op1(compiler,
				    SLJIT_MOV_UI,
				    BPFJIT_X, 0,
				    SLJIT_MEM1(SLJIT_LOCALS_REG),
				    (pc->k - minm) * sizeof(uint32_t));
				if (status != SLJIT_SUCCESS)
					goto fail;

				continue;
			}

			/* BPF_LDX+BPF_B+BPF_MSH    X <- 4*(P[k:1]&0xf) */
			if (mode == BPF_MSH) {
				if (BPF_SIZE(pc->code) != BPF_B)
					goto fail;

				if (pc->k == UINT32_MAX) {
					/* return 0; */
					jump = sljit_emit_jump(compiler,
					    SLJIT_JUMP);
					if (jump == NULL)
				  		goto fail;
				  	ret0[ret0_size++] = jump;
				} else if (pc->k + 1u > insn_dat[i].bj_length) {
					/* if (pc->k + 1 > buflen) return 0; */
					jump = sljit_emit_cmp(compiler,
					    SLJIT_C_GREATER,
					    SLJIT_IMM, (uint32_t)pc->k + 1,
					    BPFJIT_BUFLEN, 0);
					if (jump == NULL)
				  		goto fail;
				  	ret0[ret0_size++] = jump;
				}
			
				status = emit_msh(compiler, (uint32_t)pc->k);
				if (status != SLJIT_SUCCESS)
					goto fail;

				continue;
			}

			goto fail;

		case BPF_ST:
			if (pc->code != BPF_ST || pc->k < minm || pc->k > maxm)
				goto fail;

			status = sljit_emit_op1(compiler,
			    SLJIT_MOV_UI,
			    SLJIT_MEM1(SLJIT_LOCALS_REG),
			    (pc->k - minm) * sizeof(uint32_t),
			    BPFJIT_A, 0);
			if (status != SLJIT_SUCCESS)
				goto fail;

			continue;

		case BPF_STX:
			if (pc->code != BPF_STX || pc->k < minm || pc->k > maxm)
				goto fail;

			status = sljit_emit_op1(compiler,
			    SLJIT_MOV_UI,
			    SLJIT_MEM1(SLJIT_LOCALS_REG),
			    (pc->k - minm) * sizeof(uint32_t),
			    BPFJIT_X, 0);
			if (status != SLJIT_SUCCESS)
				goto fail;

			continue;

		case BPF_ALU:

			if (pc->code == (BPF_ALU|BPF_NEG)) {
				status = sljit_emit_op1(compiler,
				    SLJIT_NEG,
				    BPFJIT_A, 0,
				    BPFJIT_A, 0);
				if (status != SLJIT_SUCCESS)
					goto fail;

				continue;
			}

			if (BPF_OP(pc->code) != BPF_DIV) {
				status = sljit_emit_op2(compiler,
				    bpf_alu_to_sljit_op(pc),
				    BPFJIT_A, 0,
				    BPFJIT_A, 0,
				    kx_to_reg(pc), kx_to_reg_arg(pc));
				if (status != SLJIT_SUCCESS)
					goto fail;

				continue;
			}

			/* BPF_DIV */

			src = BPF_SRC(pc->code);
			if (src != BPF_X && src != BPF_K)
				goto fail;

			/* division by zero? */
			if (src == BPF_X) {
				jump = sljit_emit_cmp(compiler,
				    SLJIT_C_EQUAL|SLJIT_INT_OP,
				    BPFJIT_X, 0, 
				    SLJIT_IMM, 0);
				if (jump == NULL)
					goto fail;
				ret0[ret0_size++] = jump;
			} else if (pc->k == 0) {
				jump = sljit_emit_jump(compiler, SLJIT_JUMP);
				if (jump == NULL)
					goto fail;
				ret0[ret0_size++] = jump;
			}

			if (src == BPF_X) {
				status = emit_division(compiler, BPFJIT_X, 0);
				if (status != SLJIT_SUCCESS)
					goto fail;
			} else if (pc->k != 0) {
				if (pc->k & (pc->k - 1)) {
				    status = emit_division(compiler,
				        SLJIT_IMM, (uint32_t)pc->k);
				} else {
    				    status = emit_pow2_division(compiler,
				        (uint32_t)pc->k);
				}
				if (status != SLJIT_SUCCESS)
					goto fail;
			}

			continue;

		case BPF_JMP:

			if (pc->code == (BPF_JMP|BPF_JA)) {
				jt = jf = pc->k;
			} else {
				jt = pc->jt;
				jf = pc->jf;
			}

			negate = (jt == 0) ? 1 : 0;
			jalways = (jt == jf) ? 1 : 0;

			if (!jalways) {
				if (BPF_OP(pc->code) != BPF_JSET) {
					jump = sljit_emit_cmp(compiler,
					    bpf_jmp_to_sljit_cond(pc, negate),
					    BPFJIT_A, 0,
					    kx_to_reg(pc), kx_to_reg_arg(pc));
				} else {
					status = sljit_emit_op2(compiler,
					    SLJIT_AND,
					    BPFJIT_TMP1, 0,
					    BPFJIT_A, 0,
					    kx_to_reg(pc), kx_to_reg_arg(pc));
					if (status != SLJIT_SUCCESS)
						goto fail;

					jump = sljit_emit_cmp(compiler,
					    bpf_jmp_to_sljit_cond(pc, negate),
					    BPFJIT_TMP1, 0,
					    SLJIT_IMM, 0);
				}

				if (jump == NULL)
					goto fail;

				bjump = &insn_dat[i].bj_jtf[negate];
				assert(bjump->bj_jump == NULL);

				bjump->bj_jump = jump;
			}

			if (jalways || (jt != 0 && jf != 0)) {
				jump = sljit_emit_jump(compiler, SLJIT_JUMP);
				if (jump == NULL)
					goto fail;

				bjump = &insn_dat[i].bj_jtf[1 - jalways];
				assert(bjump->bj_jump == NULL);

				bjump->bj_jump = jump;

			}

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
				    SLJIT_IMM, (uint32_t)pc->k);
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

		case BPF_MISC:

			if (pc->code == (BPF_MISC|BPF_TAX)) {
				status = sljit_emit_op1(compiler,
				    SLJIT_MOV_UI,
				    BPFJIT_X, 0,
				    BPFJIT_A, 0);
				if (status != SLJIT_SUCCESS)
					goto fail;

				continue;
			}

			if (pc->code == (BPF_MISC|BPF_TXA)) {
				status = sljit_emit_op1(compiler,
				    SLJIT_MOV,
				    BPFJIT_A, 0,
				    BPFJIT_X, 0);
				if (status != SLJIT_SUCCESS)
					goto fail;

				continue;
			}

			goto fail;
		} /* switch */
	} /* main loop */

	assert(ret0_size <= ret0_maxsize); /* XXX make it == again */
	assert(returns_size <= returns_maxsize);

	if (returns_size > 0) {
		label = sljit_emit_label(compiler);
		if (label == NULL)
			goto fail;
		for (i = 0; i < returns_size; i++)
			sljit_set_label(returns[i], label);
	}

	status = sljit_emit_return(compiler,
	    SLJIT_MOV_UI,
	    BPFJIT_A, 0);
	if (status != SLJIT_SUCCESS)
		goto fail;

	if (ret0_size > 0) {
		label = sljit_emit_label(compiler);
		if (label == NULL)
			goto fail;

		for (i = 0; i < ret0_size; i++)
			sljit_set_label(ret0[i], label);

		status = sljit_emit_op1(compiler,
		    SLJIT_MOV,
		    SLJIT_RETURN_REG, 0,
		    SLJIT_IMM, 0);
		if (status != SLJIT_SUCCESS)
			goto fail;

		status = sljit_emit_return(compiler,
		    SLJIT_MOV_UI,
		    SLJIT_RETURN_REG, 0);
		if (status != SLJIT_SUCCESS)
			goto fail;
	}

	rv = sljit_generate_code(compiler);

fail:
	if (compiler != NULL)
		sljit_free_compiler(compiler);

	if (insn_dat != NULL)
		free(insn_dat);

	if (returns != NULL)
		free(returns);

	if (ret0 != NULL)
		free(ret0);

	if (stack != NULL)
		free(stack);

	return (bpfjit_function_t)rv;
}

void
bpfjit_free_code(bpfjit_function_t code)
{

	sljit_free_code((void *)code);
}
