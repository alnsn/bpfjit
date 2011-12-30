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

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __linux
#include <net/ethernet.h>
#else
#include <net/ethertypes.h>
#endif

void usage(const char *prog);
void test_bpf_filter(size_t counter, size_t dummy);
void test_bpfjit(size_t counter, size_t dummy);

/*
 * From bpf(4): This filter accepts only IP packets between host
 * 128.3.112.15 and 128.3.112.35.
 */
static struct bpf_insn insns[] = {
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 0, 8),
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 26),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 2),
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 3, 4),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 0, 3),
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
	BPF_STMT(BPF_RET+BPF_K, 0),
};

/* XXX change to matching packet */
static uint8_t pkt[128] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
	14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
	0x80, 0x03, 0x70, 0x0f,
	0x80, 0x03, 0x70, 0x23
};

void
test_bpfjit(size_t counter, size_t dummy)
{
	size_t i;
	void *code;
	unsigned int ret = 0;

	code = bpfjit_generate_code(insns, sizeof(insns) / sizeof(insns[0]));

	for (i = 0; i < counter; i++)
		ret += bpfjit_execute_code(pkt, sizeof(pkt), sizeof(pkt), code);

	bpfjit_free_code(code);

	if (counter == dummy)
		printf("bpfjit_execute_code returned %u\n", ret);
}

void
test_bpf_filter(size_t counter, size_t dummy)
{
	size_t i;
	unsigned int ret = 0;

	for (i = 0; i < counter; i++)
		ret += bpf_filter(insns, pkt, sizeof(pkt), sizeof(pkt));

	if (counter == dummy)
		printf("bpf_filter returned %u\n", ret);
}

void usage(const char *prog)
{

	fprintf(stderr,
	    "USAGE: time %s [-]NNN\n"
	    "  NNN - number of iterations\n"
	    "        positive - run bpfjit_execute_code\n"
	    "        negative - rune bpf_filter\n", prog);
}

int main(int argc, char* argv[])
{
	int dummy;
	double counter;

	dummy = (argc == INT_MAX - 1) ? argv[argc-1][0] : 1;

	if (argc == 1 || (counter = strtod(argv[1], NULL)) == 0 ||
	    abs(counter) > SIZE_MAX) {
		usage(argv[0]);
		counter = 1;
	}

	if (!bpf_validate(insns, sizeof(insns) / sizeof(insns[0])))
		errx(EXIT_FAILURE, "Not valid bpf program");

	if (counter > 0)
		test_bpfjit(counter, dummy);
	else
		test_bpf_filter(-counter, dummy);

	return EXIT_SUCCESS;
}
