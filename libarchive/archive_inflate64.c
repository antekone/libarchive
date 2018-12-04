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

#include <stdio.h>
#define LOG(...) do { printf(__VA_ARGS__); puts(""); } while(0)
#define HEXDUMP(what, size) do {\
        size_t __i = 0;\
        uint8_t* __x = (uint8_t*) &what;\
        for(__i = 0; __i < (size_t) size; __i++) {\
            printf("%02x ", __x[__i]);\
        }\
        \
        printf("\n");\
    } while(0)
#define HEXDUMP_PTR(what, size) do {\
        size_t __i = 0;\
        const uint8_t* __x = (const uint8_t*) what;\
        for(__i = 0; __i < (size_t) size; __i++) {\
            printf("%02x ", __x[__i]);\
        }\
        \
        printf("\n");\
    } while(0)

const uint32_t INIT_TAG = 0xa1a2a3a4;

struct bit_reader {
    uint8_t pos;
    uint32_t cache;
    uint32_t value;
};

struct inflate64internal {
    struct bit_reader br;
};

static
void br_reset(struct inflate64stream* s) {
    s->inner->br.pos = 32;
}

static
int br_fill_raw(struct inflate64stream* s, uint8_t* pbyte) {
    uint8_t byte = 0;

    if(s->total_in >= s->avail_in)
        return INF64_IO;

    byte = s->next_in[s->total_in++];
    *pbyte = byte;
    return INF64_OK;
}

static
int br_fill(struct inflate64stream* s) {
    struct bit_reader* const br = &s->inner->br;

    while(br->pos >= 8) {
        uint8_t b = 0;
        int ret;

        ret = br_fill_raw(s, &b);
        if(ret != INF64_OK)
            return ret;

        br->cache |= ((uint32_t) b) << (32 - br->pos);
        br->pos -= 8;
    }

    return INF64_OK;
}

static inline
void br_skip(struct inflate64stream* s, int n) {
    struct bit_reader* const br = &s->inner->br;
    br->pos += n;
    br->cache >>= n;
}

// n is up to 32
static
int br_read_n(struct inflate64stream* s, int n, uint32_t* pvalue) {
    struct bit_reader* const br = &s->inner->br;

    if(INF64_OK != br_fill(s)) {
        LOG("br_fill error");
        return 1;
    }

    *pvalue = br->cache & ((1 << n) - 1);
    br_skip(s, n);
    return 0;
}

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
    br_reset(s);
    s->initialized = INIT_TAG;
    return INF64_OK;
}

#define INF64_TRY(x) do { int __ret; if(INF64_OK != (__ret = (x))) { return __ret; } } while(0)
#define INF64_TRY_OR(x, ref) do { int __ret; if(INF64_OK != (__ret = (x))) { return __ret; } else { ref = __ret; } } while(0)

static
int read_table_huff_dyn(struct inflate64stream* s) {
    uint32_t num_lit_len_levels = 0;
    uint32_t num_dist_levels = 0;
    uint32_t num_level_codes = 0;

    LOG("reading huffman dynamic table");

    INF64_TRY(br_read_n(s, 5, &num_lit_len_levels));
    INF64_TRY(br_read_n(s, 5, &num_dist_levels));
    INF64_TRY(br_read_n(s, 4, &num_level_codes));

    num_lit_len_levels += 257;
    num_dist_levels += 1;
    num_level_codes += 4;

    LOG("%d/%d/%d", num_lit_len_levels, num_dist_levels, num_level_codes);

    return INF64_OK;
}

int inflate64run(struct inflate64stream* s) {
    uint32_t final_block = 0;
    uint32_t block_type = 0;

    if(!valid_context(s))
        return INF64_ARG;

    INF64_TRY(br_read_n(s, 1, &final_block));
    INF64_TRY(br_read_n(s, 2, &block_type));

    enum {
        HUFFMAN_STORED = 0,
        HUFFMAN_STATIC = 1,
        HUFFMAN_DYNAMIC = 2,
    };

    LOG("bit: %d", final_block);

    switch(block_type) {
        case HUFFMAN_STORED:
            LOG("stored huffman tables are not supported yet");
            return INF64_BADDATA;
        case HUFFMAN_STATIC:
            LOG("static huffman tables are not supported yet");
            return INF64_BADDATA;
        case HUFFMAN_DYNAMIC:
            INF64_TRY(read_table_huff_dyn(s));
            break;
        default:
            LOG("got block_type=%d, which is not supported", block_type);
            return INF64_BADDATA;
    }

    LOG("ok");
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
