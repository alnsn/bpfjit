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

#ifndef _NET_BPFJIT_H_
#define _NET_BPFJIT_H_

#include <stddef.h>
#include <sys/queue.h>
#include <sys/types.h>

#ifdef __linux
#include <pcap-bpf.h>
#else
#include <net/bpf.h>
#endif

#include <sljitLir.h>


#define BPFJIT_A	SLJIT_RETURN_REG
#define BPFJIT_X	SLJIT_TEMPORARY_REG1
#define BPFJIT_TMP1	SLJIT_TEMPORARY_REG2
#define BPFJIT_TMP2	SLJIT_TEMPORARY_REG3
#define BPFJIT_BUF	SLJIT_GENERAL_REG1
#define BPFJIT_WIRELEN	SLJIT_GENERAL_REG2
#define BPFJIT_BUFLEN	SLJIT_GENERAL_REG3


struct bpfjit_jump
{
	struct sljit_jump *bj_jump;
	SLIST_ENTRY(bpfjit_jump) bj_entries;
};

void *bpfjit_generate_code(struct bpf_insn *insns, size_t insn_count);
void bpfjit_free_code(void *code);

#endif /* !_NET_BPFJIT_H_ */
