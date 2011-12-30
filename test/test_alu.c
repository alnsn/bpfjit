
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

#include <bpfjit.h>

#include <stdint.h>

#include "util.h"
#include "tests.h"

static void
test_alu_add_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 3),
		BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, 2),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 5);

	bpfjit_free_code(code);
}

static void
test_alu_sub_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 1),
		BPF_STMT(BPF_ALU+BPF_SUB+BPF_K, 2),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == UINT32_MAX);

	bpfjit_free_code(code);
}

static void
test_alu_mul_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, UINT32_MAX),
		BPF_STMT(BPF_ALU+BPF_MUL+BPF_K, 3),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == UINT32_MAX * UINT32_C(3));

	bpfjit_free_code(code);
}

static void
test_alu_and_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 0xdead),
		BPF_STMT(BPF_ALU+BPF_AND+BPF_K, 0xbeef),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 0x9ebd);

	bpfjit_free_code(code);
}

static void
test_alu_or_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 0xdead0000),
		BPF_STMT(BPF_ALU+BPF_OR+BPF_K, 0x0000beef),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 0xdeadbeef);

	bpfjit_free_code(code);
}

void test_alu(void)
{
	test_alu_add_k();
	test_alu_sub_k();
	test_alu_mul_k();
	test_alu_and_k();
	test_alu_or_k();
}