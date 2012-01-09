/*-
 * Copyright (c) 2012 Alexander Nasonov.
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
#include <string.h>

#include "util.h"
#include "tests.h"

static void
test_stx1(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LDX+BPF_W+BPF_LEN, 0),
		BPF_STMT(BPF_STX, 0),
		BPF_STMT(BPF_LDX+BPF_W+BPF_MEM, 0),
		BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	size_t i;
	void *code;
	uint8_t pkt[16]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	for (i = 1; i <= sizeof(pkt); i++)
		CHECK(bpfjit_execute_code(pkt, i, sizeof(pkt), code) == i);

	bpfjit_free_code(code);
}

static void
test_stx2(void)
{
	static struct bpf_insn insns[] = {
		BPF_STMT(BPF_LDX+BPF_W+BPF_LEN, 0),
		BPF_STMT(BPF_STX, BPF_MEMWORDS-1),
		BPF_STMT(BPF_LDX+BPF_W+BPF_MEM, 0),
		BPF_STMT(BPF_MISC+BPF_TXA, 0),
		BPF_STMT(BPF_RET+BPF_A, 0)
	};

	void *code;
	uint8_t pkt[1]; /* the program doesn't read any data */

	size_t insn_count = sizeof(insns) / sizeof(insns[0]);

	CHECK(bpf_validate(insns, insn_count));

	code = bpfjit_generate_code(insns, insn_count);
	REQUIRE(code != NULL);

	CHECK(bpfjit_execute_code(pkt, 1, 1, code) == 0);

	bpfjit_free_code(code);
}

void
test_stx(void)
{

	test_stx1();
	test_stx2();
	/* XXX
	 * test_stx3();
	 * test_stx4();
	 * test_stx5();
	 */
}
