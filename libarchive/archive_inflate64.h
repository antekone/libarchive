/*-
 * Copyright (c) 2018 Grzegorz Antoniak (http://antoniak.org)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __ARCHIVE_INFLATE64_H_
#define __ARCHIVE_INFLATE64_H_

#include <stdint.h>
#include <stdlib.h>

struct inflate64internal;

enum INF64_RET {
    INF64_OK = 0, INF64_ALLOC = 1, INF64_ERROR = 2, INF64_ARG = 3, INF64_IO = 4,
    INF64_BADDATA = 5,
};

struct inflate64stream {
    /* API */
    ssize_t avail_in;
    ssize_t avail_out;
    ssize_t total_in;
    ssize_t total_out;
    const uint8_t* next_in;
    uint8_t* next_out;

    /* Not API */
    struct inflate64internal* inner;
    uint32_t initialized;
};

int inflate64init(struct inflate64stream* s);
int inflate64run(struct inflate64stream* s);
int inflate64finish(struct inflate64stream* s);

#endif
