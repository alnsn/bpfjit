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
		BPF_STMT(BPF_RET+BPF_A, 0),
		BPF_STMT(BPF_RET+BPF_A, UINT32_MAX),
		BPF_STMT(BPF_RET+BPF_A, 1),
		BPF_STMT(BPF_RET+BPF_A, 2),
		BPF_STMT(BPF_RET+BPF_A, 3),
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
		BPF_JUMP(BPF_JMP+BPF_JGT, 1, 0, 1),
		BPF_STMT(BPF_RET+BPF_A, 0),
		BPF_STMT(BPF_LD+BPF_IMM, 2),
		BPF_JUMP(BPF_JMP+BPF_JGT, 1, 1, 0),
		BPF_STMT(BPF_RET+BPF_A, 1),
		BPF_JUMP(BPF_JMP+BPF_JGT, 2, 1, 1),
		BPF_STMT(BPF_RET+BPF_A, 2),
		BPF_JUMP(BPF_JMP+BPF_JGT, UINT32_MAX, 2, 3),
		BPF_STMT(BPF_RET+BPF_A, 3),
		BPF_STMT(BPF_RET+BPF_A, 4),
		BPF_STMT(BPF_RET+BPF_A, 5),
		BPF_JUMP(BPF_JMP+BPF_JGT, 0, 3, 1),
		BPF_STMT(BPF_RET+BPF_A, 6),
		BPF_STMT(BPF_RET+BPF_A, UINT32_MAX),
		BPF_STMT(BPF_RET+BPF_A, 7),
		BPF_STMT(BPF_RET+BPF_A, 8)
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

void
test_jmp(void)
{

	test_jmp_ja();
	test_jmp_gt_k();
}
