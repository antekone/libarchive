/*-
 * Copyright (c) 2018 Grzegorz Antoniak (http://antoniak.org)
 * All rights reserved.
 *
 * This zlib-free deflate64 decoder is based on 7-Zip's deflate64 
 * decoder by Igor Pavlov.
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
#define INF64_TRY(x) do { int __ret; if(INF64_OK != (__ret = (x))) { return __ret; } } while(0)
#define INF64_TRY_OR(x, ref) do { int __ret; if(INF64_OK != (__ret = (x))) { return __ret; } else { ref = __ret; } } while(0)
#define INF64_COUNT_OF(x) (sizeof(x) / sizeof(*x))

const uint32_t INIT_TAG = 0xa1a2a3a4;

#define CODE_LENGTH_TABLE_SIZE 19
#define END_OF_BLOCK_SYMBOL    0x100
#define MATCH_SYMBOL           (END_OF_BLOCK_SYMBOL + 1)
#define LEN_TABLE_SIZE         31
#define DIST_TABLE_SIZE        32
#define MAIN_TABLE_SIZE        (LEN_TABLE_SIZE + MATCH_SYMBOL)

struct bit_reader {
    uint8_t pos;
    uint32_t cache;
    uint32_t value;
    uint8_t invert_table[256];
};

struct huff_table {
    uint32_t ll;
    uint32_t dl;
    uint32_t lc;
    uint8_t levels[CODE_LENGTH_TABLE_SIZE];
    uint8_t lens[1 << 7];
};

const uint8_t code_len_pos[CODE_LENGTH_TABLE_SIZE] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

struct inflate64internal {
    struct bit_reader br;
    struct huff_table huff;
};

static
void br_reset(struct inflate64stream* s) {
    struct bit_reader* const br = &s->inner->br;
    int i;

    br->pos = 32;

    /* Bit reversal lookup table initialization. */
    for(i = 0; i < 256; i++) {
        uint32_t x = ((i & 0x55) << 1) | ((i & 0xAA) >> 1);
        x = ((x & 0x33) << 2) | ((x & 0xCC) >> 2);
        x = (uint8_t) (((x & 0x0F) << 4) | ((x & 0xF0) >> 4));
        br->invert_table[i] = x;
    }
}

/*static*/
/*int br_check_avail(struct inflate64stream* s, uint32_t how_many) {*/
    /*if(s->total_in >= s->avail_in)*/
        /*return INF64_NEEDMORE;*/

    /*if(s->avail_in - s->total_in < how_many)*/
        /*return INF64_NEEDMORE;*/

    /*return INF64_OK;*/
/*}*/

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

        INF64_TRY(br_fill_raw(s, &b));

        br->cache = br->cache | (((uint32_t) b) << (32 - br->pos));
        br->value = (br->value << 8) | br->invert_table[b];
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
// naming comes from [bitreader]_read_[n=multiple bytes]
static
int br_read_n(struct inflate64stream* s, int n, uint32_t* pvalue) {
    struct bit_reader* const br = &s->inner->br;

    INF64_TRY(br_fill(s));

    *pvalue = br->cache & ((1 << n) - 1);
    br_skip(s, n);
    return INF64_OK;
}

static
int br_readval_n(struct inflate64stream* s, int n, uint32_t* pvalue) {
    struct bit_reader* const br = &s->inner->br;
    const uint32_t mask = (1 << 24) - 1;

    INF64_TRY(br_fill(s));

    *pvalue = ((br->value >> (8 - br->pos)) & mask) >> (24 - n);
    return INF64_OK;
}

// n is up to 8
// convinience function that allows to read directly to uint8_t* without
// triggering any type errors
// naming comes from [bitreader]_read_[n=multiple bytes]_[uint8_t][pointer]
static inline
int br_read_n_u8p(struct inflate64stream* s, int n, uint8_t* pvalue) {
    uint32_t buf;
    INF64_TRY(br_read_n(s, n, &buf));
    *pvalue = (uint8_t) (buf & 255);
    return INF64_OK;
}

static
int valid_context(struct inflate64stream* s) {
    return s->initialized == INIT_TAG && s->inner ? INF64_OK : INF64_ARG;
}

int inflate64init(struct inflate64stream* s) {
    INF64_TRY(valid_context(s));

    s->inner = (struct inflate64internal*) malloc(sizeof(struct inflate64internal));
    if(!s->inner)
        return INF64_ALLOC;

    memset(s->inner, 0, sizeof(struct inflate64internal));
    br_reset(s);
    s->initialized = INIT_TAG;
    return INF64_OK;
}

static
int levels_load(struct inflate64stream* s) {
    size_t i;
    struct huff_table* huff = &s->inner->huff;

    LOG("reading huffman dynamic table");

    INF64_TRY(br_read_n(s, 5, &huff->ll));
    INF64_TRY(br_read_n(s, 5, &huff->dl));
    INF64_TRY(br_read_n(s, 4, &huff->lc));

    huff->ll += 257;
    huff->dl += 1;
    huff->lc += 4;

    LOG("%d/%d/%d", huff->ll, huff->dl, huff->lc);

    for(i = 0; i < INF64_COUNT_OF(huff->levels); ++i) {
        const size_t position = code_len_pos[i];
        if(i < huff->lc) {
            INF64_TRY(br_read_n_u8p(s, 3, &huff->levels[position]));
        } else {
            huff->levels[position] = 0;
        }
    }

    for(i = 0; i < INF64_COUNT_OF(huff->levels); ++i) {
        LOG("1 levels[%zu] = %02x", i, huff->levels[i]);
    }

    return INF64_OK;
}

static
int levels_init(struct inflate64stream* s) {
    size_t i;
    ssize_t k;
    struct huff_table* const huff = &s->inner->huff;
    
    uint32_t len_counts[8] = { 0 };
    uint32_t temp_poses[8] = { 0 };
    uint32_t poses[8] = { 0 };
    uint32_t limits[8] = { 0 };
    uint32_t sym = 0;
    uint32_t start_pos = 0;

    for(sym = 0; sym < INF64_COUNT_OF(huff->levels); ++sym) {
        const size_t position = huff->levels[sym];
        ++len_counts[position];
    }

    len_counts[0] = 0;
    poses[0] = 0;
    limits[0] = 0;

    for(i = 1; i < 8; ++i) {
        start_pos += len_counts[i] << (7 - i);
        if(start_pos > 128)
            return INF64_BADDATA;

        limits[i] = start_pos;
        poses[i] = poses[i - 1] + len_counts[i - 1];
        temp_poses[i] = poses[i];
    }

    for(sym = 0; sym < INF64_COUNT_OF(huff->levels); ++sym) {
        const uint8_t len = huff->levels[sym];
        uint32_t offset;
        uint8_t val;
        size_t index;

        if(len == 0)
            continue;

        /* 'len' will never be more than 7, because it's read from the
         * file by using only 3 bits. */

        offset = temp_poses[len];
        ++temp_poses[len];
        offset -= poses[len];

        val = (uint8_t) ((sym << 3) | len);
        index = limits[len - 1] + (offset << (7 - len));
        for(k = 0; k < (1 << (7 - len)); ++k) {
            if((index + k) > (ssize_t) INF64_COUNT_OF(huff->lens)) {
                LOG("fatal: index+k = %zu, should be max %zu", index + k, INF64_COUNT_OF(huff->lens));
                return INF64_BADDATA;
            }

            LOG("save val %02x to index+k=%zu", val, index+k);
            huff->lens[index + k] = val;
        }
    }

    for(k = 0; k < (128 - limits[7]); ++k) {
        if((limits[7] + k) > (ssize_t) INF64_COUNT_OF(huff->lens)) {
            LOG("fatal: limits[7]+k = %zu, should be max %zu", limits[7] + k, INF64_COUNT_OF(huff->lens));
            return INF64_BADDATA;
        }

        huff->lens[limits[7] + k] = 0x1F << 3;
    }

    for(i = 0; i < INF64_COUNT_OF(huff->lens); ++i) {
        LOG("2 lens[%zu] = %02x", i, huff->lens[i]);
    }

    return INF64_OK;
}

static
int levels_decode(struct inflate64stream* s, uint8_t* levels, int sym_count) {
    struct huff_table* const huff = &s->inner->huff;
    ssize_t i = 0;
    uint32_t num_bits = 0, num = 0, bit_data = 0;
    uint8_t symbol = 0;

    (void) s;
    (void) levels;
    (void) sym_count;

    uint32_t val, pair, len, sym;

    do {
        INF64_TRY(br_readval_n(s, 7, &val));
        pair = huff->lens[val];

        len = pair & 7;
        br_skip(s, len);
        sym = pair >> 3;

        LOG("sym=0x%08x", sym);

        if(sym < 16) {
            levels[i++] = (uint8_t) (sym & 255);
            continue;
        }

        if(sym >= CODE_LENGTH_TABLE_SIZE) {
            return INF64_BADDATA;
        }

        if(sym == 16) {
            if(i == 0) {
                return INF64_BADDATA;
            }

            num_bits = 2;
            num = 0;
            symbol = levels[i - 1];
        } else {
            sym = (sym - 17) << 2;
            num_bits = 3 + sym;
            num = (uint32_t) sym << 1;
            symbol = 0;
        }

        INF64_TRY(br_read_n(s, num_bits, &bit_data));

        num = num + 3 + i + bit_data;
        if(num > (uint32_t) sym_count) {
            return INF64_BADDATA;
        } 

        do {
            levels[i++] = symbol;
        } while(i < num);
    } while(i < sym_count);

    return INF64_OK;
}

static
int read_table_huff_dyn(struct inflate64stream* s) {
    uint8_t temp_levels[MAIN_TABLE_SIZE + DIST_TABLE_SIZE];

    INF64_TRY(levels_load(s));
    INF64_TRY(levels_init(s));
    INF64_TRY(levels_decode(s, 
                temp_levels, 
                s->inner->huff.ll + s->inner->huff.dl));

    return INF64_OK;
}

int inflate64run(struct inflate64stream* s) {
    uint32_t final_block = 0;
    uint32_t block_type = 0;

    INF64_TRY(valid_context(s));
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
    INF64_TRY(valid_context(s));

    free(s->inner);
    s->inner = NULL;
    s->initialized = 0;

    return INF64_OK;
}
