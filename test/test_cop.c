/*-
 * Copyright (c) 2013 Alexander Nasonov.
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

#include <bpfjit.h>

#include <stdbool.h>
#include <stdint.h>

#include "util.h"
#include "tests.h"

static uint32_t
retA(bpf_ctx_t *bc, bpf_args_t *args, bpf_state_t *state)
{

	return state->regA;
}

static uint32_t
retM(bpf_ctx_t *bc, bpf_args_t *args, bpf_state_t *state)
{

	return state->mem[(uintptr_t)args->arg];
}

static uint32_t
retBL(bpf_ctx_t *bc, bpf_args_t *args, bpf_state_t *state)
{

	return args->buflen;
}

static uint32_t
retWL(bpf_ctx_t *bc, bpf_args_t *args, bpf_state_t *state)
{

	return args->wirelen;
}

static uint32_t
retNF(bpf_ctx_t *bc, bpf_args_t *args, bpf_state_t *state)
{

	return bc->nfuncs;
}

/*
 * COP function with a side effect.
 */
static uint32_t
setARG(bpf_ctx_t *bc, bpf_args_t *args, bpf_state_t *state)
{
	bool *arg = (bool *)args->arg;
	bool old = *arg;

	*arg = true;
	return old;
}

static const bpf_copfunc_t copfuncs[] = {
	&retA,
	&retM,
	&retBL,
	&retWL,
	&retNF,
	&setARG
};

static bpf_ctx_t ctx = { copfuncs, sizeof(copfuncs) / sizeof(copfuncs[0]) };

static void
test_cop_no_ctx(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_MISC+BPF_COP, 0),
		BPF_STMT(BPF_RET+BPF_K, 7)
	};

	bpfjit_function_t code;
	uint8_t pkt[1] = { 0 };
	bpf_args_t args = { pkt, sizeof(pkt), sizeof(pkt) };

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(NULL, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(NULL, &args) == 0);

	bpfjit_free_code(code);
}

static void
test_cop_ret_A(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 13),
		BPF_STMT(BPF_MISC+BPF_COP, 0), // retA
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	bpfjit_function_t code;
	uint8_t pkt[1] = { 0 };
	bpf_args_t args = { pkt, sizeof(pkt), sizeof(pkt) };

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(&ctx, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(&ctx, &args) == 13);

	bpfjit_free_code(code);
}

static void
test_cop_ret_mem(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 13),
		BPF_STMT(BPF_ST, 3),
		BPF_STMT(BPF_LD+BPF_IMM, 1),
		BPF_STMT(BPF_MISC+BPF_COP, 1), // retM
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	bpfjit_function_t code;
	uint8_t pkt[1] = { 0 };
	void *arg = (void*)(uintptr_t)3;
	bpf_args_t args = { pkt, sizeof(pkt), sizeof(pkt), arg };

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(&ctx, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(&ctx, &args) == 13);

	bpfjit_free_code(code);
}

static void
test_cop_ret_buflen(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 13),
		BPF_STMT(BPF_MISC+BPF_COP, 2), // retBL
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	bpfjit_function_t code;
	uint8_t pkt[1] = { 0 };
	bpf_args_t args = { pkt, sizeof(pkt), sizeof(pkt) };

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(&ctx, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(&ctx, &args) == sizeof(pkt));

	bpfjit_free_code(code);
}

static void
test_cop_ret_wirelen(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 13),
		BPF_STMT(BPF_MISC+BPF_COP, 3), // retWL
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	bpfjit_function_t code;
	uint8_t pkt[1] = { 0 };
	bpf_args_t args = { pkt, sizeof(pkt), sizeof(pkt) };

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(&ctx, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(&ctx, &args) == sizeof(pkt));

	bpfjit_free_code(code);
}

static void
test_cop_ret_nfuncs(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 13),
		BPF_STMT(BPF_MISC+BPF_COP, 4), // retNF
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	bpfjit_function_t code;
	uint8_t pkt[1] = { 0 };
	bpf_args_t args = { pkt, sizeof(pkt), sizeof(pkt) };

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(&ctx, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(&ctx, &args) == ctx.nfuncs);

	bpfjit_free_code(code);
}

/*
 * Check that safe_length optimization doesn't skip BPF_COP call.
 */
static void
test_cop_mixed_with_ld(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 13),
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 0),
		BPF_STMT(BPF_MISC+BPF_COP, 5), // setARG
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 99999),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	bpfjit_function_t code;
	bool arg = false;
	uint8_t pkt[1] = { 0 };
	bpf_args_t args = { pkt, sizeof(pkt), sizeof(pkt), &arg };

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(&ctx, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(&ctx, &args) == 0);
	CHECK(arg == true);

	bpfjit_free_code(code);
}

static void
test_cop_invalid_index(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 13),
		BPF_STMT(BPF_MISC+BPF_COP, 6), // invalid index
		BPF_STMT(BPF_RET+BPF_K, 27)
	};

	bpfjit_function_t code;
	uint8_t pkt[1] = { 0 };
	bpf_args_t args = { pkt, sizeof(pkt), sizeof(pkt) };

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(&ctx, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(&ctx, &args) == 0);

	bpfjit_free_code(code);
}

void
test_cop(void)
{

	test_cop_no_ctx();
	test_cop_ret_A();
	test_cop_ret_mem();
	test_cop_ret_buflen();
	test_cop_ret_wirelen();
	test_cop_ret_nfuncs();
	test_cop_mixed_with_ld();
	test_cop_invalid_index();
}
