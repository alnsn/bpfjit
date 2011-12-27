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

#include "util.h"

static struct bpf_insn insns_abs[3][2] = {
	{
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 5),
		BPF_STMT(BPF_RET+BPF_A, 0)
	},
	{
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 5),
		BPF_STMT(BPF_RET+BPF_A, 0)
	},
	{
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 5),
		BPF_STMT(BPF_RET+BPF_A, 0)
	}
};

static void
test_ld_abs(void)
{
	int i, l;
	static uint8_t pkt[] = { 0, 0xf1, 2, 0xf3, 4, 0xde, 0xad, 0xbe, 0xef };
	static size_t lengths[3] = { 1, 2, 4 };
	static unsigned int expected[3] = { 0xde, 0xdead, 0xdeadbeef };
	size_t insn_count = sizeof(insns_abs[0]) / sizeof(insns_abs[0][0]);

	for (i = 0; i < 3; i++) {
		void *code;

		REQUIRE(bpf_validate(insns_abs[i], insn_count));

		code = bpfjit_generate_code(insns_abs[i], insn_count);
		REQUIRE(code != NULL);

		for (l = 0; l < 5 + lengths[i]; l++)
			CHECK(bpfjit_execute_code(pkt, l, l, code) == 0);

		l = 5 + lengths[i];
		CHECK(bpfjit_execute_code(pkt, l, l, code) == expected[i]);

		l = sizeof(pkt);
		CHECK(bpfjit_execute_code(pkt, l, l, code) == expected[i]);

		bpfjit_free_code(code);
	}
}

void test_ld(void)
{
	test_ld_abs();
}
