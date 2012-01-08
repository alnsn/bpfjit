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
test_jmp_ja(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_JMP+BPF_JA, 1),
		BPF_STMT(BPF_RET+BPF_K, 0),
		BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
		BPF_STMT(BPF_RET+BPF_K, 1),
		BPF_STMT(BPF_RET+BPF_K, 2),
		BPF_STMT(BPF_RET+BPF_K, 3),
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == UINT32_MAX);

	bpfjit_free_code(code);
}

static void
test_jmp_gt_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
		BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 7, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, 0),
		BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 2, 2, 0),
		BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 9, 0, 0),
		BPF_STMT(BPF_RET+BPF_K, 1),
		BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 4, 1, 1),
		BPF_STMT(BPF_RET+BPF_K, 2),
		BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 6, 2, 3),
		BPF_STMT(BPF_RET+BPF_K, 3),
		BPF_STMT(BPF_RET+BPF_K, 4),
		BPF_STMT(BPF_RET+BPF_K, 5),
		BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 5, 3, 1),
		BPF_STMT(BPF_RET+BPF_K, 6),
		BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 0, 0, 0),
		BPF_STMT(BPF_RET+BPF_K, 7),
		BPF_STMT(BPF_RET+BPF_K, 8)
	};

	void *code;
	uint8_t pkt[8]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 1);
	CHECK(bpfjit_execute_code(pkt, 2, 2, code) == 1);
	CHECK(bpfjit_execute_code(pkt, 3, 3, code) == 7);
	CHECK(bpfjit_execute_code(pkt, 4, 4, code) == 7);
	CHECK(bpfjit_execute_code(pkt, 5, 5, code) == 7);
	CHECK(bpfjit_execute_code(pkt, 6, 6, code) == 8);
	CHECK(bpfjit_execute_code(pkt, 7, 7, code) == 5);
	CHECK(bpfjit_execute_code(pkt, 8, 8, code) == 0);

	bpfjit_free_code(code);
}

static void
test_jmp_ge_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 8, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, 0),
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 3, 2, 0),
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 9, 0, 0),
		BPF_STMT(BPF_RET+BPF_K, 1),
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 5, 1, 1),
		BPF_STMT(BPF_RET+BPF_K, 2),
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 7, 2, 3),
		BPF_STMT(BPF_RET+BPF_K, 3),
		BPF_STMT(BPF_RET+BPF_K, 4),
		BPF_STMT(BPF_RET+BPF_K, 5),
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 6, 3, 1),
		BPF_STMT(BPF_RET+BPF_K, 6),
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 1, 0, 0),
		BPF_STMT(BPF_RET+BPF_K, 7),
		BPF_STMT(BPF_RET+BPF_K, 8)
	};

	void *code;
	uint8_t pkt[8]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 1);
	CHECK(bpfjit_execute_code(pkt, 2, 2, code) == 1);
	CHECK(bpfjit_execute_code(pkt, 3, 3, code) == 7);
	CHECK(bpfjit_execute_code(pkt, 4, 4, code) == 7);
	CHECK(bpfjit_execute_code(pkt, 5, 5, code) == 7);
	CHECK(bpfjit_execute_code(pkt, 6, 6, code) == 8);
	CHECK(bpfjit_execute_code(pkt, 7, 7, code) == 5);
	CHECK(bpfjit_execute_code(pkt, 8, 8, code) == 0);

	bpfjit_free_code(code);
}

static void
test_jmp_eq_k(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 8, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 3, 1, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 9, 1, 1),
		BPF_STMT(BPF_RET+BPF_K, 1),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 5, 1, 1),
		BPF_STMT(BPF_RET+BPF_K, 2),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 7, 2, 3),
		BPF_STMT(BPF_RET+BPF_K, 3),
		BPF_STMT(BPF_RET+BPF_K, 4),
		BPF_STMT(BPF_RET+BPF_K, 5),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 6, 3, 1),
		BPF_STMT(BPF_RET+BPF_K, 6),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 1, 0, 0),
		BPF_STMT(BPF_RET+BPF_K, 7),
		BPF_STMT(BPF_RET+BPF_K, 8)
	};

	void *code;
	uint8_t pkt[8]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 7);
	CHECK(bpfjit_execute_code(pkt, 2, 2, code) == 7);
	CHECK(bpfjit_execute_code(pkt, 3, 3, code) == 1);
	CHECK(bpfjit_execute_code(pkt, 4, 4, code) == 7);
	CHECK(bpfjit_execute_code(pkt, 5, 5, code) == 7);
	CHECK(bpfjit_execute_code(pkt, 6, 6, code) == 8);
	CHECK(bpfjit_execute_code(pkt, 7, 7, code) == 5);
	CHECK(bpfjit_execute_code(pkt, 8, 8, code) == 0);

	bpfjit_free_code(code);
}

void
test_jmp(void)
{

	test_jmp_ja();
	test_jmp_gt_k();
	test_jmp_ge_k();
	test_jmp_eq_k();
	/* XXX add test_jmp_*_modulo_[kx] tests */
}
