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

#include <stdint.h>

#include "util.h"
#include "tests.h"

static uint32_t
retA(bpf_ctx_t *bc, bpf_args_t *args, bpf_state_t *state)
{

	return state->regA;
}

static uint32_t
retM3(bpf_ctx_t *bc, bpf_args_t *args, bpf_state_t *state)
{

	return state->mem[3];
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

const bpf_copfunc_t copfuncs[] = {
	&retA,
	&retM3,
	&retBL,
	&retWL,
	&retNF
};

bpf_ctx_t ctx = { copfuncs, sizeof(copfuncs) / sizeof(copfuncs[0]) };

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

	CHECK(!bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(NULL, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(NULL, &args) == 0);

	bpfjit_free_code(code);
}

static void
test_cop_retA(void)
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

	CHECK(!bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(&ctx, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(&ctx, &args) == 13);

	bpfjit_free_code(code);
}

static void
test_cop_retM3(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 13),
		BPF_STMT(BPF_ST, 3),
		BPF_STMT(BPF_LD+BPF_IMM, 1),
		BPF_STMT(BPF_MISC+BPF_COP, 1), // retM3
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	bpfjit_function_t code;
	uint8_t pkt[1] = { 0 };
	bpf_args_t args = { pkt, sizeof(pkt), sizeof(pkt) };

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(!bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(&ctx, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(&ctx, &args) == 13);

	bpfjit_free_code(code);
}

static void
test_cop_retBL(void)
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

	CHECK(!bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(&ctx, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(&ctx, &args) == sizeof(pkt));

	bpfjit_free_code(code);
}

static void
test_cop_retWL(void)
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

	CHECK(!bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(&ctx, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(&ctx, &args) == sizeof(pkt));

	bpfjit_free_code(code);
}

static void
test_cop_retNF(void)
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

	CHECK(!bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(&ctx, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(&ctx, &args) == ctx.nfuncs);

	bpfjit_free_code(code);
}

static void
test_cop_invalid_index(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 13),
		BPF_STMT(BPF_MISC+BPF_COP, 5), // invalid index
		BPF_STMT(BPF_RET+BPF_K, 27)
	};

	bpfjit_function_t code;
	uint8_t pkt[1] = { 0 };
	bpf_args_t args = { pkt, sizeof(pkt), sizeof(pkt) };

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(!bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(&ctx, insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(code(&ctx, &args) == 0);

	bpfjit_free_code(code);
}

void
test_cop(void)
{

	test_cop_no_ctx();
	test_cop_retA();
	test_cop_retM3();
	test_cop_retBL();
	test_cop_retWL();
	test_cop_retNF();
	test_cop_invalid_index();
}
