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
test_alu_div0_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 0);

	bpfjit_free_code(code);
}

static void
test_alu_div1_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 7),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, 1),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 7);

	bpfjit_free_code(code);
}

static void
test_alu_div2_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 7),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, 2),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 3);

	bpfjit_free_code(code);
}

static void
test_alu_div4_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, UINT32_MAX),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, 4),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == (UINT32_MAX/4u));

	bpfjit_free_code(code);
}

static void
test_alu_div10_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294843849)),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, 10),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == UINT32_C(429484384));

	bpfjit_free_code(code);
}

static void
test_alu_div10000_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294843849)),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, 10000),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == UINT32_C(429484));

	bpfjit_free_code(code);
}

static void
test_alu_div7609801_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294967295)),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, UINT32_C(7609801)),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 564);

	bpfjit_free_code(code);
}

static void
test_alu_div2147483648_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, UINT32_MAX - 33),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, UINT32_C(2147483648)),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 1);

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

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == (0xdead&0xbeef));

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

static void
test_alu_lsh_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 0xdeadbeef),
		BPF_STMT(BPF_ALU+BPF_LSH+BPF_K, 16),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 0xbeef0000);

	bpfjit_free_code(code);
}

static void
test_alu_rsh_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 0xdeadbeef),
		BPF_STMT(BPF_ALU+BPF_RSH+BPF_K, 16),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 0x0000dead);

	bpfjit_free_code(code);
}

static void
test_alu_add_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 3),
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 2),
		BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
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
test_alu_sub_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 1),
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 2),
		BPF_STMT(BPF_ALU+BPF_SUB+BPF_X, 0),
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
test_alu_mul_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, UINT32_MAX),
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 3),
		BPF_STMT(BPF_ALU+BPF_MUL+BPF_X, 0),
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
test_alu_div0_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 0),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 0);

	bpfjit_free_code(code);
}

static void
test_alu_div1_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 7),
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 1),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 7);

	bpfjit_free_code(code);
}

static void
test_alu_div2_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 7),
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 2),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 3);

	bpfjit_free_code(code);
}

static void
test_alu_div4_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, UINT32_MAX),
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 4),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == (UINT32_MAX/4u));

	bpfjit_free_code(code);
}

static void
test_alu_div10_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294843849)),
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 10),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == UINT32_C(429484384));

	bpfjit_free_code(code);
}

static void
test_alu_div10000_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294843849)),
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 10000),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == UINT32_C(429484));

	bpfjit_free_code(code);
}

static void
test_alu_div7609801_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294967295)),
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_C(7609801)),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 564);

	bpfjit_free_code(code);
}

static void
test_alu_div2147483648_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, UINT32_MAX - 33),
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_C(2147483648)),
		BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 1);

	bpfjit_free_code(code);
}

static void
test_alu_and_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 0xdead),
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 0xbeef),
		BPF_STMT(BPF_ALU+BPF_AND+BPF_X, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == (0xdead&0xbeef));

	bpfjit_free_code(code);
}

static void
test_alu_or_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 0xdead0000),
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 0x0000beef),
		BPF_STMT(BPF_ALU+BPF_OR+BPF_X, 0),
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

static void
test_alu_lsh_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 0xdeadbeef),
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 16),
		BPF_STMT(BPF_ALU+BPF_LSH+BPF_X, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 0xbeef0000);

	bpfjit_free_code(code);
}

static void
test_alu_rsh_x(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 0xdeadbeef),
		BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 16),
		BPF_STMT(BPF_ALU+BPF_RSH+BPF_X, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 0x0000dead);

	bpfjit_free_code(code);
}

static void
test_alu_neg(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM, 777),
		BPF_STMT(BPF_ALU+BPF_NEG, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	REQUIRE(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 0u-777u);

	bpfjit_free_code(code);
}

void
test_alu(void)
{

	test_alu_add_k();
	test_alu_sub_k();
	test_alu_mul_k();
	test_alu_div0_k();
	test_alu_div1_k();
	test_alu_div2_k();
	test_alu_div4_k();
	test_alu_div10_k();
	test_alu_div10000_k();
	test_alu_div7609801_k();
	test_alu_div2147483648_k();
	test_alu_and_k();
	test_alu_or_k();
	test_alu_lsh_k();
	test_alu_rsh_k();

	test_alu_add_x();
	test_alu_sub_x();
	test_alu_mul_x();
	test_alu_div0_x();
	test_alu_div1_x();
	test_alu_div2_x();
	test_alu_div4_x();
	test_alu_div10_x();
	test_alu_div10000_x();
	test_alu_div7609801_x();
	test_alu_div2147483648_x();
	test_alu_and_x();
	test_alu_or_x();
	test_alu_lsh_x();
	test_alu_rsh_x();

	test_alu_neg();
}
