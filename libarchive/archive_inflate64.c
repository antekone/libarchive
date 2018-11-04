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

#include "archive_inflate64.h"

#include <stdlib.h>
#include <string.h>

const uint32_t INIT_TAG = 0xa1a2a3a4;

struct inflate64internal {
    int dummy;
};

static
int valid_context(struct inflate64stream* s) {
    return s->initialized == INIT_TAG && s->inner;
}

int inflate64init(struct inflate64stream* s) {
    if(valid_context(s))
        return INF64_ARG;

    s->inner = (struct inflate64internal*) malloc(sizeof(struct inflate64internal));
    if(!s->inner)
        return INF64_ALLOC;

    memset(s->inner, 0, sizeof(struct inflate64internal));
    s->initialized = INIT_TAG;

    return valid_context(s) ? INF64_OK : INF64_ERROR;
}

int inflate64run(struct inflate64stream* s) {
    if(!valid_context(s))
        return INF64_ARG;

    return INF64_OK;
}

int inflate64finish(struct inflate64stream* s) {
    if(!valid_context(s))
        return INF64_ARG;

    free(s->inner);
    s->inner = NULL;
    s->initialized = 0;

    return INF64_OK;
}
