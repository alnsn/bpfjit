#include "bpfjit.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/queue.h>

static int
emit_read8(struct sljit_compiler* compiler, struct bpf_insn *pc)
{

	return sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPF_SLJIT_A, 0,
	    SLJIT_MEM1(BPF_SLJIT_BUF), pc->k);
}

static int
emit_read16(struct sljit_compiler* compiler, struct bpf_insn *pc)
{
	int status;

	/* tmp1 = buf[pc->k] */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPF_SLJIT_TMP1, 0,
	    SLJIT_MEM1(BPF_SLJIT_BUF), pc->k);
	if (status != SLJIT_SUCCESS)
		return compiler->error;

	/* tmp2 = buf[pc->k+1] */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPF_SLJIT_TMP2, 0,
	    SLJIT_MEM1(BPF_SLJIT_BUF), pc->k+1);
	if (status != SLJIT_SUCCESS)
		return compiler->error;

	/* tmp1 <<= 8 */
	status = sljit_emit_op2(compiler,
	    SLJIT_SHL,
	    BPF_SLJIT_TMP1, 0,
	    BPF_SLJIT_TMP1, 0,
	    SLJIT_IMM, 8);
	if (status != SLJIT_SUCCESS)
		return compiler->error;

	/* A = tmp1 + tmp2 */
	status = sljit_emit_op2(compiler,
	    SLJIT_ADD,
	    BPF_SLJIT_A, 0,
	    BPF_SLJIT_TMP1, 0,
	    BPF_SLJIT_TMP2, 0);
	return status;
}

static int
emit_read32(struct sljit_compiler* compiler, struct bpf_insn *pc)
{
	int status;

	/* tmp1 = buf[pc->k] */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPF_SLJIT_TMP1, 0,
	    SLJIT_MEM1(BPF_SLJIT_BUF), pc->k);
	if (status != SLJIT_SUCCESS)
		return compiler->error;

	/* tmp2 = buf[pc->k+1] */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPF_SLJIT_TMP2, 0,
	    SLJIT_MEM1(BPF_SLJIT_BUF), pc->k+1);
	if (status != SLJIT_SUCCESS)
		return compiler->error;

	/* A = buf[pc->k+3] */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPF_SLJIT_A, 0,
	    SLJIT_MEM1(BPF_SLJIT_BUF), pc->k+3);
	if (status != SLJIT_SUCCESS)
		return compiler->error;

	/* tmp1 <<= 24 */
	status = sljit_emit_op2(compiler,
	    SLJIT_SHL,
	    BPF_SLJIT_TMP1, 0,
	    BPF_SLJIT_TMP1, 0,
	    SLJIT_IMM, 24);
	if (status != SLJIT_SUCCESS)
		return compiler->error;

	/* A = A + tmp1 */
	status = sljit_emit_op2(compiler,
	    SLJIT_ADD,
	    BPF_SLJIT_A, 0,
	    BPF_SLJIT_A, 0,
		BPF_SLJIT_TMP1, 0);
	if (status != SLJIT_SUCCESS)
		return compiler->error;

	/* tmp1 = buf[pc->k+2] */
	status = sljit_emit_op1(compiler,
	    SLJIT_MOV_UB,
	    BPF_SLJIT_TMP1, 0,
	    SLJIT_MEM1(BPF_SLJIT_BUF), pc->k+2);
	if (status != SLJIT_SUCCESS)
		return compiler->error;

	/* tmp2 <<= 16 */
	status = sljit_emit_op2(compiler,
	    SLJIT_SHL,
	    BPF_SLJIT_TMP2, 0,
	    BPF_SLJIT_TMP2, 0,
	    SLJIT_IMM, 16);
	if (status != SLJIT_SUCCESS)
		return compiler->error;

	/* A = A + tmp2 */
	status = sljit_emit_op2(compiler,
	    SLJIT_ADD,
	    BPF_SLJIT_A, 0,
	    BPF_SLJIT_A, 0,
		BPF_SLJIT_TMP2, 0);
	if (status != SLJIT_SUCCESS)
		return compiler->error;

	/* tmp1 <<= 8 */
	status = sljit_emit_op2(compiler,
	    SLJIT_SHL,
	    BPF_SLJIT_TMP1, 0,
	    BPF_SLJIT_TMP1, 0,
	    SLJIT_IMM, 8);
	if (status != SLJIT_SUCCESS)
		return compiler->error;

	/* A = A + tmp1 */
	status = sljit_emit_op2(compiler,
	    SLJIT_ADD,
	    BPF_SLJIT_A, 0,
	    BPF_SLJIT_A, 0,
		BPF_SLJIT_TMP1, 0);
	return status;
}

/*
 * Count BPF_LD and BPF_LDX instructions.
 */
static size_t
count_load_insns(struct bpf_insn *insns, size_t insn_count)
{
	size_t rv = 0;
	struct bpf_insn *pc;

	for (pc = insns; pc != insns + insn_count; pc++) {
		unsigned int class = BPF_CLASS(pc->code);
		if (class == BPF_LD || class == BPF_LDX)
			rv++;
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
 * Convert BPF_ALU perations except BPF_DIV.
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

const void *
bpfjit_generate_code(struct bpf_insn *insns, size_t insn_count)
{
	const void *rv;
	size_t i;
	size_t width;
	struct sljit_label *label;
	SLIST_HEAD(bpfjit_jump_head, bpfjit_jump) *jumps;
	struct sljit_jump **returns;
	struct sljit_jump **outofbounds;
	size_t returns_size, returns_capacity;
	size_t outofbounds_size, outofbounds_capacity;

	rv = NULL;
	jumps = NULL;
	returns = NULL;
	outofbounds = NULL;

	struct sljit_compiler* compiler = sljit_create_compiler();

	/* XXX check rv of other sljit calls */
	if (compiler == NULL)
		return NULL;

#if (defined SLJIT_VERBOSE && SLJIT_VERBOSE)
	sljit_compiler_verbose(compiler, stdout);
#endif

	jumps = calloc(insn_count, sizeof(jumps[0]));
	if (jumps == NULL)
		goto fail;

	for (i = 0; i < insn_count; i++)
		SLIST_INIT(&jumps[i]);

	returns_size = 0;
	returns_capacity = count_ret_insns(insns, insn_count);
	if (returns_capacity > 0) {
		returns = calloc(returns_capacity,
		    sizeof(returns[0]));
		if (returns == NULL)
			goto fail;
	}

	outofbounds_size = 0;
	outofbounds_capacity = count_load_insns(insns, insn_count);
	if (outofbounds_capacity > 0) {
		outofbounds = calloc(outofbounds_capacity,
		    sizeof(outofbounds[0]));
		if (outofbounds == NULL)
			goto fail;
	}

	sljit_emit_enter(compiler, 3, 3, 3, BPF_MEMWORDS * sizeof(uint32_t));
	sljit_emit_op1(compiler, SLJIT_MOV, BPF_SLJIT_A, 0, SLJIT_IMM, 0);

	for (i = 0; i < insn_count; i++) {
		struct bpf_insn *pc = &insns[i];

		if (!SLIST_EMPTY(&jumps[i])) {
			struct bpfjit_jump *jump;

			label = sljit_emit_label(compiler);
			if (label == NULL)
				goto fail;
			SLIST_FOREACH(jump, &jumps[i], bj_entries)
				sljit_set_label(jump->bj_jump, label);
		}

		switch (BPF_CLASS(pc->code)) {

		default:
			goto fail;

		case BPF_RET:
			if (BPF_RVAL(pc->code) == BPF_K) {
				sljit_emit_op1(compiler,
				    SLJIT_MOV,
				    BPF_SLJIT_A, 0,
				    SLJIT_IMM, pc->k);
			}

			/* XXX BPF_X is mentioned in bpf.h but not in man */

			if (pc != &insns[insn_count - 1]) {
				returns[returns_size++] = sljit_emit_jump(
				    compiler, SLJIT_JUMP);
			}

			continue;

		case BPF_LD:
			switch (BPF_SIZE(pc->code)) {
			case BPF_W: width = 4; break;
			case BPF_H: width = 2; break;
			case BPF_B: width = 1; break;
			default:
				goto fail;
			}

			if (BPF_MODE(pc->code) == BPF_ABS) {
				int status;

				outofbounds[outofbounds_size++] = sljit_emit_cmp(
				    compiler,
				    SLJIT_C_GREATER,
				    SLJIT_IMM, pc->k + width,
				    BPF_SLJIT_BUFLEN, 0);

				switch (width) {
				case 4:
					status = emit_read32(compiler, pc);
					break;
				case 2:
					status = emit_read16(compiler, pc);
					break;
				case 1:
					status = emit_read8(compiler, pc);
					break;
				}

				if (status != SLJIT_SUCCESS)
					goto fail;
			}

			continue;

		case BPF_JMP:
			if (BPF_SRC(pc->code) == BPF_K) {
				struct bpfjit_jump *jump;

				jump = malloc(sizeof(struct bpfjit_jump));
				if (jump == NULL)
					goto fail;

				if (pc->jt == 0) {
					jump->bj_jump = sljit_emit_cmp(
					    compiler,
					    bpf_jmp_to_sljit_cond_inverted(pc),
					    SLJIT_IMM, pc->k,
					    BPF_SLJIT_A, 0);

					SLIST_INSERT_HEAD(&jumps[i + 1 + pc->jf],
					    jump, bj_entries);
					if (jump->bj_jump == NULL)
						goto fail;
				}
			}

			continue;

		}
	}

	if (returns_size > 0) {
		label = sljit_emit_label(compiler);
		for (i = 0; i < returns_size; i++)
			sljit_set_label(returns[i], label);
	}

	sljit_emit_return(compiler, BPF_SLJIT_A, 0);

	if (outofbounds_size > 0) {
		label = sljit_emit_label(compiler);

		for (i = 0; i < outofbounds_size; i++)
			sljit_set_label(outofbounds[i], label);

		sljit_emit_op1(compiler, SLJIT_MOV,
		    SLJIT_RETURN_REG, 0, SLJIT_IMM, 0);
		sljit_emit_return(compiler, SLJIT_RETURN_REG, 0);
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

	if (outofbounds != NULL)
		free(outofbounds);

	return rv;
}
