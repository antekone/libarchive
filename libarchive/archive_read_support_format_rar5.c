/*-
* Copyright (c) 2018 Grzegorz Antoniak
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

// TODO: test unpacking on a 100gb file

#include "archive_platform.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <time.h>
#ifdef HAVE_ZLIB_H
#include <zlib.h> /* crc32 */
#endif

#include "archive.h"
#ifndef HAVE_ZLIB_H
#include "archive_crc32.h"
#endif

#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_ppmd7_private.h"
#include "archive_entry_private.h"
#include "archive_blake2.h"

#if __GNUC__ > 4 && !defined __OpenBSD__
#define fallthrough __attribute__((fallthrough))
#define unused      __attribute__((unused))
#else
#define fallthrough
#define unused
#endif

#define DONT_FAIL_ON_CRC_ERROR

//#define SKIP_CRC_FAILURE

static int rar5_read_data_skip(struct archive_read *a);

struct file_header {
    uint32_t stored_crc32;
    uint32_t calculated_crc32;
    uint64_t unpacked_size;
    uint64_t packed_size;
    uint64_t bytes_remaining;
    uint64_t read_offset; // offset in the compressed stream
    uint64_t write_offset; // offset in the output stream
    uint64_t prev_read_bytes;

    // optional time fields
    uint64_t e_mtime;
    uint64_t e_ctime;
    uint64_t e_atime;
    uint32_t e_unix_ns;

    // optional hash fields
    uint8_t blake2sp[32];
    blake2sp_state b2state;
    char has_blake2;
};

enum FILTER_TYPE {
    FILTER_DELTA = 0, 
    FILTER_E8    = 1,   // 0xE8 jumps in x86 code
    FILTER_E8E9  = 2,   // 0xE8, 0xE9 jumps in x86 code
    FILTER_ARM   = 3,   // arm code
    FILTER_AUDIO = 4,
    FILTER_RGB   = 5,   // color palette
    FILTER_ITANIUM = 6, // intel's itanium
    FILTER_PPM   = 7,   // not used in RARv5
    FILTER_NONE  = 8,
};

#define HUFF_NC 306
#define HUFF_DC 64
#define HUFF_LDC 16
#define HUFF_RC 44
#define HUFF_BC 20
#define HUFF_TABLE_SIZE (HUFF_NC + HUFF_DC + HUFF_RC + HUFF_LDC)

static const int CIF_SOLID       = 0x00000001;
/*static const int CIF_TABLES_READ = 0x00000002;*/

#define MAX_QUICK_DECODE_BITS 10

struct decode_table {
    uint32_t size;
    int32_t decode_len[16];
    uint32_t decode_pos[16];
    uint32_t quick_bits;
    uint8_t quick_len[1 << MAX_QUICK_DECODE_BITS];
    uint16_t quick_num[1 << MAX_QUICK_DECODE_BITS];
    uint16_t decode_num[306];
};

struct filter_info {
    int type;
    int channels;
    int id;

    int next_window : 1;
    int pos_r : 2;

    // TODO: those types should be int64_t?
    uint32_t block_start;
    uint32_t block_length;
    uint16_t width;
    uint32_t orig_block_start;
};

struct data_ready {
    char used;
    const uint8_t* buf;
    size_t size;
    int64_t offset;
};

struct cdeque {
    uint16_t beg_pos;
    uint16_t end_pos;
    uint16_t cap_mask;
    uint16_t size;
    size_t* arr;
};

struct comp_state {
    int initialized : 1;

    int flags;
    int method;
    int version;
    size_t window_size;
    uint8_t* window_buf;
    uint8_t* filtered_buf;
    const uint8_t* block_buf;
    size_t window_mask;
    ssize_t write_ptr;
    ssize_t last_write_ptr;
    ssize_t solid_offset;
    ssize_t unpacked_bytes;
    ssize_t cur_block_size;
    int block_num;
    int computed_block_size;
    int last_len;
    int block_parsing_finished;
    int code_seq;
    int window_flip_count;
    int all_filters_applied;

    struct decode_table bd;
    struct decode_table ld;
    struct decode_table dd;
    struct decode_table ldd;
    struct decode_table rd;

    struct cdeque filters;
    int dist_cache[4];
    // TODO: convert this to cdeque
    struct data_ready dready[2];
    int filter_count;
};

struct bit_reader {
    int bit_addr;
    int in_addr;
};

struct compressed_block_header { 
    union {
        struct {
            uint8_t bit_size : 3;
            uint8_t byte_count : 3;
            uint8_t is_last_block : 1;
            uint8_t is_table_present : 1;
        } block_flags;
        uint8_t block_flags_u8;
    };

    uint8_t block_cksum;
};

struct main_header {
    uint8_t solid : 1;
    uint8_t volume : 1;
    uint8_t notused : 6;
};

struct rar5 {
    int header_initialized;
    int skipped_magic;
    int skip_mode;

    uint64_t qlist_offset;    // not used by this unpacker
    uint64_t rr_offset;       // not used by this unpacker

    struct main_header main;
    struct comp_state cstate;
    struct file_header file;
    struct bit_reader bits;
    struct compressed_block_header last_block_hdr;
};

#define rar5_min(a, b) (((a) > (b)) ? (b) : (a))
#define rar5_max(a, b) (((a) > (b)) ? (a) : (b))
#define rar5_countof(X) ((const ssize_t) (sizeof(X) / sizeof(*X)))

#define UNUSED(x) (void) (x)
#define LOG(...)  do { printf(__VA_ARGS__); puts(""); } while(0)

/* CDE_xxx = Circular Double Ended (Queue) xxx */
enum CDE_RETURN_VALUES {
    CDE_OK, CDE_ALLOC, CDE_PARAM, CDE_OUT_OF_BOUNDS,
};

struct cdeque_iter {
    int index;
};

static void cdeque_clear(struct cdeque* d) {
    d->size = 0;
    d->beg_pos = 0;
    d->end_pos = 0;
}

// capacity must be power of 2: 8, 16, 32, 64, 256, etc.
static int cdeque_init(struct cdeque* d, int max_capacity_power_of_2) {
    if(d == NULL || max_capacity_power_of_2 == 0) 
        return CDE_PARAM;

    d->cap_mask = max_capacity_power_of_2 - 1;
    d->arr = NULL;

    if((max_capacity_power_of_2 & d->cap_mask) > 0)
        return CDE_PARAM;

    cdeque_clear(d);
    d->arr = malloc(sizeof(void*) * max_capacity_power_of_2);

    return d->arr ? CDE_OK : CDE_ALLOC;
}

static size_t cdeque_size(struct cdeque* d) {
    return d->size;
}

static void cdeque_front_fast(struct cdeque* d, void** value) {
    *value = (void*) d->arr[d->beg_pos];
}

static int cdeque_front(struct cdeque* d, void** value) {
    if(d->size > 0) {
        cdeque_front_fast(d, value);
        return CDE_OK;
    } else
        return CDE_OUT_OF_BOUNDS;
}

static int cdeque_push_back(struct cdeque* d, void* item) {
    if(d == NULL) 
        return CDE_PARAM;

    if(d->size == d->cap_mask + 1)
        return CDE_OUT_OF_BOUNDS;

    d->arr[d->end_pos] = (size_t) item;
    d->end_pos = (d->end_pos + 1) & d->cap_mask;
    d->size++;

    return CDE_OK;
}

static void cdeque_pop_front_fast(struct cdeque* d, void** value) {
    *value = (void*) d->arr[d->beg_pos];
    d->beg_pos = (d->beg_pos + 1) & d->cap_mask;
    d->size--;
}

static int cdeque_pop_front(struct cdeque* d, void** value) {
    if(!d || !value) 
        return CDE_PARAM;

    if(d->size == 0)
        return CDE_OUT_OF_BOUNDS;

    cdeque_pop_front_fast(d, value);
    return CDE_OK;
}

static void** cdeque_filter_p(struct filter_info** f) {
    return (void**) (size_t) f;
}

static void* cdeque_filter(struct filter_info* f) {
    return (void**) (size_t) f;
}

static void cdeque_free(struct cdeque* d) {
    if(!d)
        return;

    if(!d->arr) 
        return;

    free(d->arr);

    d->arr = NULL;
    d->beg_pos = -1;
    d->end_pos = -1;
    d->cap_mask = 0;
}

// TODO: make sure these functions return a little endian number 

static uint32_t read_filter_data(struct rar5* rar, uint32_t offset) {
    uint32_t* dptr = (uint32_t*) &rar->cstate.window_buf[offset];
    // TODO: bswap if big endian
    return *dptr;
}

static void write_filter_data(struct rar5* rar, uint32_t offset, uint32_t value) {
    uint32_t* dptr = (uint32_t*) &rar->cstate.filtered_buf[offset];
    // TODO: bswap if big endian
    *dptr = value;
}

static void circular_memcpy(uint8_t* dst, uint8_t* window, const int mask, ssize_t start, ssize_t end) {
    if((start & mask) > (end & mask)) {
        LOG("todo: start=0x%zx end=0x%zx", start, end);
        exit(1);
    } else {
        memcpy(dst, &window[start & mask], (end - start) & mask);
    }
}

static struct filter_info* add_new_filter(struct rar5* rar) {
    struct filter_info* f = 
        (struct filter_info*) calloc(1, sizeof(struct filter_info));

    cdeque_push_back(&rar->cstate.filters, cdeque_filter(f));

    f->id = rar->cstate.filter_count;
    return f;
}

static void push_data_ready(struct rar5* rar, const uint8_t* buf, size_t size, int64_t offset);

static int run_delta_filter(struct rar5* rar, struct filter_info* flt) {
    int i;
    uint32_t dest_pos, src_pos = 0;

    /*LOG("run_delta_filter id=%d @ 0x%08x-0x%08x, channels=%d", flt->id, flt->block_start, flt->block_start + flt->block_length - 1, flt->channels);*/
    
    for(i = 0; i < flt->channels; i++) {
        uint8_t prev_byte = 0;
        for(dest_pos = i; dest_pos < flt->block_length; dest_pos += flt->channels) {
            uint8_t byte;

            byte = rar->cstate.window_buf[(rar->cstate.solid_offset + flt->block_start + src_pos) & rar->cstate.window_mask];
            prev_byte -= byte;

            rar->cstate.filtered_buf[dest_pos] = prev_byte;

            /*LOG("%02d %04d/%04d Data[%d]=%02x  -> DstData[%d]=%02x", i, dest_pos, flt->block_length,*/
                    /*rar->cstate.solid_offset + flt->block_start + src_pos,*/
                    /*rar->cstate.window_buf[(rar->cstate.solid_offset + flt->block_start + src_pos) & rar->cstate.window_mask],*/
                    /*dest_pos,*/
                    /*rar->cstate.filtered_buf[flt->block_start + dest_pos]);*/

            src_pos++;
        }
    }
    
    // TODO: move this outside of run_xxx_filter()? every filter does this, so
    // maybe move it to some common place so it's executed automatically?
    push_data_ready(rar, rar->cstate.filtered_buf, flt->block_length, rar->cstate.last_write_ptr);
    rar->cstate.last_write_ptr += flt->block_length;

    return ARCHIVE_OK;
}

static int run_e8e9_filter(struct rar5* rar, struct filter_info* flt, int extended) {
    const uint32_t file_size = 0x1000000;
    uint32_t i;

    /*LOG("run_e8e9_filter, from 0x%x to 0x%x", flt->block_start, flt->block_start + flt->block_length - 1);*/

    circular_memcpy(rar->cstate.filtered_buf, 
        rar->cstate.window_buf, 
        rar->cstate.window_mask, 
        rar->cstate.solid_offset + flt->block_start, 
        rar->cstate.solid_offset + flt->block_start + flt->block_length);

    for(i = 0; i < flt->block_length - 4;) {
        uint8_t b = rar->cstate.window_buf[(rar->cstate.solid_offset + flt->block_start + i++) & rar->cstate.window_mask];

        if(b == 0xE8 || (extended && b == 0xE9)) {
            // 0xE8 = x86's call <relative_addr_uint32> (function call)
            // 0xE9 = x86's jmp <relative_addr_uint32> (unconditional jump)
            
            uint32_t addr;
            uint32_t offset = (i + flt->block_start) % file_size;

            /*LOG("found 0xE8/0xE9 on pos 0x%x", flt->block_start + i);*/
            addr = read_filter_data(rar, (rar->cstate.solid_offset + flt->block_start + i) & rar->cstate.window_mask);
            /*LOG("addr=%08x", addr);*/

            if(addr & 0x80000000) {
                if(((addr + offset) & 0x80000000) == 0) {
                    write_filter_data(rar, i, addr + file_size);
                    /*LOG("#1: stored %08x", addr + file_size);*/
                } else {
                    /*LOG("skip #1");*/
                }
            } else {
                if((addr - file_size) & 0x80000000) {
                    uint32_t naddr = addr - offset;
                    /*LOG("writting %08x", naddr);*/
                    write_filter_data(rar, i, naddr);
                } else {
                    /*LOG("skip #2");*/
                }
            }

            i += 4;
        }
    }

    // TODO: move this outside of run_xxx_filter()? every filter does this, so
    // maybe move it to some common place so it's executed automatically?
    push_data_ready(rar, rar->cstate.filtered_buf, flt->block_length, rar->cstate.last_write_ptr);
    rar->cstate.last_write_ptr += flt->block_length;

    return ARCHIVE_OK;
}

static int run_arm_filter(struct rar5* rar, struct filter_info* flt) {
    uint32_t i = 0, offset;
    const int mask = rar->cstate.window_mask;

    circular_memcpy(rar->cstate.filtered_buf, 
        rar->cstate.window_buf, 
        rar->cstate.window_mask, 
        rar->cstate.solid_offset + flt->block_start, 
        rar->cstate.solid_offset + flt->block_start + flt->block_length);

    for(i = 0; i < flt->block_length - 3; i += 4) {
        uint8_t* b = &rar->cstate.window_buf[(rar->cstate.solid_offset + flt->block_start + i) & mask];
        if(b[3] == 0xEB) {
            // 0xEB = ARM's BL (branch + link) instruction
            offset = read_filter_data(rar, (rar->cstate.solid_offset + flt->block_start + i) & mask) & 0x00ffffff;
            offset -= (i + flt->block_start) / 4;
            offset = (offset & 0x00ffffff) | 0xeb000000;
            write_filter_data(rar, i, offset);
        }
    }

    // TODO: move this outside of run_xxx_filter()? every filter does this, so
    // maybe move it to some common place so it's executed automatically?
    push_data_ready(rar, rar->cstate.filtered_buf, flt->block_length, rar->cstate.last_write_ptr);
    rar->cstate.last_write_ptr += flt->block_length;

    return ARCHIVE_OK;
}

static int run_filter(struct rar5* rar, struct filter_info* flt) {
    int ret;
    if(rar->cstate.filtered_buf)
        free(rar->cstate.filtered_buf);

    rar->cstate.filtered_buf = malloc(flt->block_length);
    if(!rar->cstate.filtered_buf) {
        LOG("failed to allocate memory");
        return ARCHIVE_FATAL;
    }

    switch(flt->type) {
        case FILTER_DELTA:
            ret = run_delta_filter(rar, flt);
            break;

        case FILTER_E8:
            fallthrough;
        case FILTER_E8E9:
            ret = run_e8e9_filter(rar, flt, flt->type == FILTER_E8E9);
            break;

        case FILTER_ARM:
            ret = run_arm_filter(rar, flt);
            break;

        default:
            LOG("*** filter type not supported: %d", flt->type);
            return ARCHIVE_FATAL;
    }

    if(ret != ARCHIVE_OK) {
        LOG("filter failed");
        return ret;
    }

    return ARCHIVE_OK;
}

static void push_data(struct rar5* rar, const uint8_t* buf, ssize_t idx_begin, ssize_t idx_end) {
    const int mask = rar->cstate.window_mask;

    LOG("push_data: idx_begin=%x, idx_end=%x", idx_begin, idx_end);

    if((idx_begin & mask) > (idx_end & mask)) {
        ssize_t frag1_size = rar->cstate.window_size - (rar->cstate.solid_offset + rar->cstate.last_write_ptr & mask);
        ssize_t frag2_size = (idx_end - idx_begin) - frag1_size;

        LOG("idx_begin=0x%zx, idx_end=0x%zx", idx_begin, idx_end);
        LOG("frag1_size=0x%zx", frag1_size);
        LOG("frag2_size=0x%zx", frag2_size);

        push_data_ready(rar,
            buf + (rar->cstate.solid_offset + rar->cstate.last_write_ptr & mask),
            frag1_size,
            rar->cstate.last_write_ptr);

        push_data_ready(rar,
            buf + rar->cstate.solid_offset,
            frag2_size,
            rar->cstate.last_write_ptr + frag1_size);

        rar->cstate.last_write_ptr += frag1_size + frag2_size;
    } else {
        push_data_ready(rar,
            buf + (rar->cstate.solid_offset + rar->cstate.last_write_ptr & mask),
            idx_end - idx_begin,
            rar->cstate.last_write_ptr);

        rar->cstate.last_write_ptr += idx_end - idx_begin;
    }
}

static void push_window_data(struct rar5* rar, ssize_t idx_begin, ssize_t idx_end) {
    return push_data(rar, rar->cstate.window_buf, idx_begin, idx_end);
}

static int apply_filters(struct rar5* rar) {
    struct filter_info* flt;
    int ret;

    LOG("processing filters, last_write_ptr=0x%zx, write_ptr=0x%zx", rar->cstate.last_write_ptr, rar->cstate.write_ptr);

    rar->cstate.all_filters_applied = 0;
    while(CDE_OK == cdeque_front(&rar->cstate.filters, cdeque_filter_p(&flt))) {
        if(rar->cstate.write_ptr > flt->block_start && rar->cstate.write_ptr >= flt->block_start + flt->block_length) {
            if(rar->cstate.last_write_ptr == flt->block_start) {
                LOG("will process filter %d 0x%08x-0x%08x", flt->type, flt->block_start, flt->block_start + flt->block_length - 1);
                ret = run_filter(rar, flt);
                if(ret != ARCHIVE_OK) {
                    LOG("filter failure, returning error");
                    return ret;
                }

                /*LOG("filter executed, removing it from queue");*/
                (void) cdeque_pop_front(&rar->cstate.filters, cdeque_filter_p(&flt));
                return ARCHIVE_RETRY;
            } else {
                LOG("not yet, will dump memory right before the filter");
                push_window_data(rar, rar->cstate.last_write_ptr, flt->block_start);
                return ARCHIVE_RETRY;
            }
        } else {
            LOG("no, can't run this filter yet");
            break;
        }
    }

    rar->cstate.all_filters_applied = 1;
    return ARCHIVE_OK;
}

static void dist_cache_push(struct rar5* rar, int value) {
    int* q = rar->cstate.dist_cache;

    q[3] = q[2];
    q[2] = q[1];
    q[1] = q[0];
    q[0] = value;
}

static int dist_cache_touch(struct rar5* rar, int index) {
    int* q = rar->cstate.dist_cache;
    int i, dist = q[index];

    for(i = index; i > 0; i--)
        q[i] = q[i - 1];

    q[0] = dist;
    return dist;
}

static int rar5_init(struct rar5* rar) {
    memset(rar, 0, sizeof(struct rar5));

    if(CDE_OK != cdeque_init(&rar->cstate.filters, 8192))
        return ARCHIVE_FATAL;

    return ARCHIVE_OK;
}

static void reset_filters(struct rar5* rar);

static void reset_file_context(struct rar5* rar) {
    memset(&rar->file, 0, sizeof(rar->file));
    
    if(rar->main.solid) {
        rar->cstate.solid_offset = rar->cstate.write_ptr;
    } else {
        rar->cstate.solid_offset = 0;
    }

    rar->cstate.write_ptr = 0;
    rar->cstate.last_write_ptr = 0;
    reset_filters(rar);
}

static int is_solid(struct rar5* rar) {
    return (rar->cstate.flags & CIF_SOLID) > 0;
}

static void set_solid(struct rar5* rar, int flag) {
    rar->cstate.flags |= flag ? CIF_SOLID : 0;
}

const unsigned char rar5_signature[] = { 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00 };
const size_t rar5_signature_size = sizeof(rar5_signature);
const size_t g_unpack_buf_chunk_size = 1024;
const size_t g_unpack_window_size = 0x20000;

static inline int get_archive_read(struct archive* a, struct archive_read** ar) {
    *ar = (struct archive_read*) a;

    archive_check_magic(a, ARCHIVE_READ_MAGIC, ARCHIVE_STATE_NEW,
                        "archive_read_support_format_rar5");

    return ARCHIVE_OK;
}

static inline struct rar5* get_context(struct archive_read* a) {
    return (struct rar5*) a->format->data;
}

static int consume(struct archive_read* a, int64_t how_many) {
    /*LOG("consume: %ld bytes", how_many);*/
    return 
        how_many == __archive_read_consume(a, how_many)
        ? ARCHIVE_OK
        : ARCHIVE_FATAL;
}

static int read_ahead(struct archive_read* a, size_t how_many, const uint8_t** ptr) {
    if(!ptr)
        return 0;

    ssize_t avail = -1;
    *ptr = __archive_read_ahead(a, how_many, &avail);
    if(*ptr == NULL) {
        return 0;
    }

    return 1;
}

/**
 * Read a RAR5 variable sized numeric value. This value will be stored in
 * `pvalue`. The `pvalue_len` argument points to a variable that will receive
 * the byte count that was consumed in order to decode the `pvalue` value, plus
 * one.
 *
 * pvalue_len is optional and can be NULL. 
 *
 * NOTE: if `pvalue_len` is NOT NULL, the caller needs to manually consume 
 * the number of bytes that `pvalue_len` value contains. If the `pvalue_len`
 * is NULL, this consuming operation is done automatically.
 *
 * Returns 1 if *pvalue was successfully read.
 * Returns 0 if there was an error. In this case, *pvalue contains an
 *           invalid value.
 */

static int read_var(struct archive_read* a, uint64_t* pvalue, size_t* pvalue_len) {
    uint64_t result = 0;
    size_t shift, i;
    const uint8_t* p;
    uint8_t b;

    /* We will read maximum of 8 bytes. We don't have to handle the situation
     * to read the RAR5 variable-sized value stored at the end of the file,
     * because such situation will never happen. */
    if(!read_ahead(a, 8, &p))
        return 0;

    for(shift = 0, i = 0; i < 8; i++, shift += 7) {
        b = p[i];

        /* Strip the MSB from the input byte and add the resulting number
         * to the `result`. */
        result += (b & 0x7F) << shift;

        /* MSB set to 1 means we need to continue decoding process. MSB set
         * to 0 means we're done. 
         *
         * This conditional checks for the second case. */
        if((b & 0x80) == 0) {
            if(pvalue) {
                *pvalue = result;
            }

            /* If the caller has passed the `pvalue_len` pointer, store the
             * number of consumed bytes in it and do NOT consume those bytes,
             * since the caller has all the information it needs to perform
             * the consuming process itself. */
            if(pvalue_len) {
                *pvalue_len = 1 + i;
            } else {
                /* If the caller did not provide the `pvalue_len` pointer,
                 * it will not have the possibility to advance the file
                 * pointer, because it will not know how many bytes it needs
                 * to consume. This is why we handle such situation here 
                 * autmatically. */
                if(ARCHIVE_OK != consume(a, 1 + i)) {
                    LOG("error: archive_read_consume failed");
                    return 0;
                }
            }

            /* End of decoding process, return success. */
            return 1;
        }
    }

    /* The decoded value takes the maximum number of 8 bytes. It's a maximum
     * number of bytes, so end decoding process here even if the first bit
     * of last byte is 1. */
    if(pvalue) {
        *pvalue = result;
    }

    if(pvalue_len) {
        *pvalue_len = 9;
    } else {
        if(ARCHIVE_OK != consume(a, 9)) {
            LOG("error: archive_read_consume failed");
            return 0;
        }
    }

    return 1;
}

static int read_var_sized(struct archive_read* a, size_t* pvalue, size_t* pvalue_len) {
    uint64_t v;
    uint64_t max_value = (size_t) 0;
    int ret;

    // Intentional underflow.
    max_value--; 

    ret = read_var(a, &v, pvalue_len);
    if(v > max_value)
        return 0;
    else {
        *pvalue = (size_t) v;
        return ret;
    }
}

static int read_bits_16(struct rar5* rar, const uint8_t* p, uint16_t* value);
static void skip_bits(struct rar5* rar, int bits);

// n = up to 16
static int read_consume_bits(struct rar5* rar, const uint8_t* p, int n, int* value) {
    if(n > 16) {
        return ARCHIVE_FATAL;
    } else if(n == 16) {
        uint16_t v;

        int ret = read_bits_16(rar, p, &v);
        if(ret == ARCHIVE_OK) 
            skip_bits(rar, 16);

        *value = (int) v;
        return ret;
    } else {
        uint16_t v;

        int ret = read_bits_16(rar, p, &v);
        if(ret != ARCHIVE_OK)
            return ret;

        int num = (int) v;
        num >>= 16 - n;
        skip_bits(rar, n);
        *value = num;

        return ARCHIVE_OK;
    }
}

static int read_bits_32(struct rar5* rar, const uint8_t* p, uint32_t* value) {
    uint32_t bits = p[rar->bits.in_addr] << 24;
    bits |= p[rar->bits.in_addr + 1] << 16;
    bits |= p[rar->bits.in_addr + 2] << 8;
    bits |= p[rar->bits.in_addr + 3];
    bits <<= rar->bits.bit_addr;
    bits |= p[rar->bits.in_addr + 4] >> (8 - rar->bits.bit_addr);
    *value = bits;
    return ARCHIVE_OK;
}

static int read_bits_16(struct rar5* rar, const uint8_t* p, uint16_t* value) {
    /*LOG("in=%d bit=%d", rar->bits.in_addr, rar->bits.bit_addr);*/
    int bits = (int) p[rar->bits.in_addr] << 16;
    /*LOG("addr=%d, bit=%d, raw=0x%04x", 4 + rar->bits.in_addr, rar->bits.bit_addr, p[rar->bits.in_addr]);*/
    bits |= (int) p[rar->bits.in_addr + 1] << 8;
    bits |= (int) p[rar->bits.in_addr + 2];
    bits >>= (8 - rar->bits.bit_addr);
    *value = bits & 0xffff;
    return ARCHIVE_OK;
}

static void skip_bits(struct rar5* rar, int bits) {
    int new_bits = rar->bits.bit_addr + bits;
    rar->bits.in_addr += new_bits >> 3;
    rar->bits.bit_addr = new_bits & 7;
}

static int read_u32(struct archive_read* a, uint32_t* pvalue) {
    const uint8_t* p;

    if(!read_ahead(a, 4, &p))
        return 0;

    *pvalue = *(const uint32_t*)p;

    return ARCHIVE_OK == consume(a, 4) ? 1 : 0;
}

int read_u64(struct archive_read* a, uint64_t* pvalue);
int read_u64(struct archive_read* a, uint64_t* pvalue) {
    const uint8_t* p;

    if(!read_ahead(a, 8, &p))
        return 0;

    *pvalue = *(const uint64_t*)p;

    return ARCHIVE_OK == consume(a, 8) ? 1 : 0;
}

static int bid_standard(struct archive_read* a) {
    const uint8_t* p;

    if(!read_ahead(a, rar5_signature_size, &p))
        return -1;

    if(!memcmp(rar5_signature, p, rar5_signature_size))
        return 30;

    return -1;
}

static int
bid_sfx(struct archive_read* a) {
    UNUSED(a);

    // TODO implement this
    return -1;
}

static int
rar5_bid(struct archive_read* a, int best_bid) {
    int my_bid;

    LOG("rar5_bid");

    if(best_bid > 30)
        return -1;

    my_bid = bid_standard(a);
    if(my_bid > -1) {
        LOG("bid_standard");
        return my_bid;
    }

    my_bid = bid_sfx(a);
    if(my_bid > -1)
        return my_bid;

    LOG("bid failed");
    return -1;
}

static int
rar5_options(struct archive_read *a, const char *key, const char *val) {
    UNUSED(a);
    UNUSED(key);
    UNUSED(val);

    return ARCHIVE_FATAL;
}

static void
init_header(struct archive_read* a, struct rar5* rar) {
    UNUSED(rar);

    a->archive.archive_format = ARCHIVE_FORMAT_RAR_V5;
    a->archive.archive_format_name = "RAR";
}

enum HEADER_FLAGS {
    HFL_EXTRA_DATA = 0x0001, HFL_DATA = 0x0002, HFL_SKIP_IF_UNKNOWN = 0x0004,
    HFL_SPLIT_BEFORE = 0x0008, HFL_SPLIT_AFTER = 0x0010, HFL_CHILD = 0x0020,
    HFL_INHERITED = 0x0040
};

static int
process_main_locator_extra_block(struct archive_read* a, struct rar5* rar) {
    uint64_t locator_flags;

    if(!read_var(a, &locator_flags, NULL)) {
        LOG("bad locator_flags");
        return ARCHIVE_EOF;
    }

    enum LOCATOR_FLAGS {
        QLIST = 0x01, RECOVERY = 0x02,
    };

    if(locator_flags & QLIST) {
        if(!read_var(a, &rar->qlist_offset, NULL)) {
            LOG("bad qlist_offset");
            return ARCHIVE_EOF;
        }
        
        // TODO: use qlist?
    }

    if(locator_flags & RECOVERY) {
        if(!read_var(a, &rar->rr_offset, NULL)) {
            LOG("bad rr_offset");
            return ARCHIVE_EOF;
        }

        // TODO: use rr?
    }

    return ARCHIVE_OK;
}
                
static int parse_file_extra_hash(struct archive_read* a, struct rar5* rar, ssize_t* extra_data_size) {
    uint64_t hash_type;
    size_t value_len;

    if(!read_var(a, &hash_type, &value_len))
        return ARCHIVE_EOF;

    *extra_data_size -= value_len;
    if(ARCHIVE_OK != consume(a, value_len)) {
        LOG("consume fail");
        return ARCHIVE_FATAL;
    }

    enum HASH_TYPE {
        BLAKE2sp = 0x00
    };

    if(hash_type == BLAKE2sp) {
        const uint8_t* p;
        const int hash_size = sizeof(rar->file.blake2sp);

        rar->file.has_blake2 = 1;
        blake2sp_init(&rar->file.b2state, 32);

        if(!read_ahead(a, hash_size, &p))
            return ARCHIVE_EOF;

        memcpy(&rar->file.blake2sp, p, hash_size);

        if(ARCHIVE_OK != consume(a, hash_size)) {
            LOG("consume fail");
            return ARCHIVE_FATAL;
        }

        *extra_data_size -= hash_size;
    } else {
        LOG("*** error: unknown hash type: 0x%02x", (int) hash_type);
        // TODO: set last error for all ARCHIVE_FATAL error codes across this file.
        return ARCHIVE_FATAL;
    }

    return ARCHIVE_OK;
}

static int parse_htime_item(struct archive_read* a, char unix_time, uint64_t* where, ssize_t* extra_data_size) {
    if(unix_time) {
        uint32_t time_val;
        if(!read_u32(a, &time_val))
            return ARCHIVE_EOF;

        *extra_data_size -= 4;
        *where = (uint64_t) time_val;
    } else {
        if(!read_u64(a, where))
            return ARCHIVE_EOF;

        *extra_data_size -= 8;
    }

    return ARCHIVE_OK;
}

static int parse_file_extra_htime(struct archive_read* a, struct rar5* rar, ssize_t* extra_data_size) {
    char unix_time = 0;
    uint64_t flags;
    size_t value_len;

    enum HTIME_FLAGS {
        IS_UNIX       = 0x01,
        HAS_MTIME     = 0x02,
        HAS_CTIME     = 0x04,
        HAS_ATIME     = 0x08,
        HAS_UNIX_NS   = 0x10,
    };

    if(!read_var(a, &flags, &value_len))
        return ARCHIVE_EOF;

    *extra_data_size -= value_len;
    if(ARCHIVE_OK != consume(a, value_len)) {
        LOG("consume fail");
        return ARCHIVE_FATAL;
    }

    unix_time = flags & IS_UNIX;

    if(flags & HAS_MTIME)
        parse_htime_item(a, unix_time, &rar->file.e_mtime, extra_data_size);

    if(flags & HAS_CTIME)
        parse_htime_item(a, unix_time, &rar->file.e_ctime, extra_data_size);

    if(flags & HAS_ATIME)
        parse_htime_item(a, unix_time, &rar->file.e_atime, extra_data_size);

    if(flags & HAS_UNIX_NS) {
        if(!read_u32(a, &rar->file.e_unix_ns))
            return ARCHIVE_EOF;

        *extra_data_size -= 4;
    }


    /*LOG("mtime: %016lx", rar->file.e_mtime);*/
    /*LOG("ctime: %016lx", rar->file.e_ctime);*/
    /*LOG("atime: %016lx", rar->file.e_atime);*/
    return ARCHIVE_OK;
}

static int process_head_file_extra(struct archive_read* a, struct rar5* rar, ssize_t extra_data_size) {
    uint64_t extra_field_size;
    uint64_t extra_field_id;
    int ret = ARCHIVE_FATAL;
    size_t var_size;

    enum EXTRA {
        CRYPT = 0x01, HASH = 0x02, HTIME = 0x03, VERSION_ = 0x04, REDIR = 0x05, UOWNER = 0x06, SUBDATA = 0x07
    };

    /*LOG("extra_data_size before attr loop=%zi", extra_data_size);*/

    while(extra_data_size > 0) {
        if(!read_var(a, &extra_field_size, &var_size))
            return ARCHIVE_EOF;

        extra_data_size -= var_size;
        if(ARCHIVE_OK != consume(a, var_size)) {
            LOG("consume error");
            return ARCHIVE_FATAL;
        }

        if(!read_var(a, &extra_field_id, &var_size))
            return ARCHIVE_EOF;

        extra_data_size -= var_size;
        if(ARCHIVE_OK != consume(a, var_size)) {
            LOG("consume error");
            return ARCHIVE_FATAL;
        }

        /*LOG("extra_field_size=%ld", extra_field_size);*/
        /*LOG("extra_field_id=%ld", extra_field_id);*/
        /*LOG("extra_data_size after size/type fields=%zi", extra_data_size);*/

        switch(extra_field_id) {
            case CRYPT:
                LOG("CRYPT");
                break;
            case HASH:
                ret = parse_file_extra_hash(a, rar, &extra_data_size);
                break;
            case HTIME:
                ret = parse_file_extra_htime(a, rar, &extra_data_size);
                break;
            case VERSION_:
                LOG("VERSION");
                fallthrough;
            case REDIR:
                LOG("REDIR");
                fallthrough;
            case UOWNER:
                LOG("UOWNER");
                fallthrough;
            case SUBDATA:
                LOG("SUBDATA");
                fallthrough;
            default:
                LOG("*** fatal: unknown extra field in a file/service block: %lu", extra_field_id);
                return ARCHIVE_FATAL;
        }

        /*LOG("extra_data_size after parsing attr: %zi", extra_data_size);*/
    }

    if(ret != ARCHIVE_OK) {
        LOG("*** attribute parsing failed: attr not implemented maybe?");
        return ret;
    }

    return ARCHIVE_OK;
}

static int process_head_file(struct archive_read* a, struct rar5* rar, struct archive_entry* entry, size_t block_flags) {
    UNUSED(rar);

    ssize_t extra_data_size = 0;
    size_t data_size, file_flags, file_attr, compression_info, host_os, name_size;
    uint64_t unpacked_size;
    uint32_t mtime = 0, crc;
    int c_method = 0, c_version = 0, is_dir;
    char name_utf8_buf[2048 * 4];
    const uint8_t* p;

    UNUSED(c_method);
    UNUSED(c_version);

    reset_file_context(rar);

    /*LOG("processing file header");*/

    if(block_flags & HFL_EXTRA_DATA) {
        /*LOG("extra data is present here");*/

        size_t edata_size;
        if(!read_var_sized(a, &edata_size, NULL))
            return ARCHIVE_EOF;

        // intentional type cast from unsigned to signed
        extra_data_size = (ssize_t) edata_size;
    }

    if(block_flags & HFL_DATA) {
        if(!read_var_sized(a, &data_size, NULL))
            return ARCHIVE_EOF;

        rar->file.packed_size = data_size;
        rar->file.bytes_remaining = rar->file.packed_size;
        /*LOG("data size: 0x%08zx", data_size);*/
    } else {
        rar->file.packed_size = 0;
        rar->file.bytes_remaining = 0;

        LOG("*** FILE/SERVICE block without data, failing");
        return ARCHIVE_FATAL;
    }

    enum FILE_FLAGS {
        DIRECTORY = 0x0001, UTIME = 0x0002, CRC32 = 0x0004, UNKNOWN_UNPACKED_SIZE = 0x0008,
    };

    enum COMP_INFO_FLAGS {
        SOLID = 0x0040,
    };

    if(!read_var_sized(a, &file_flags, NULL))
        return ARCHIVE_EOF;

    if(!read_var(a, &unpacked_size, NULL))
        return ARCHIVE_EOF;

    if(file_flags & UNKNOWN_UNPACKED_SIZE) {
        unpacked_size = 0;
        LOG("*** unknown unpacked size, not handled!");
        return ARCHIVE_FAILED;
    }

    is_dir = (int) (file_flags & DIRECTORY);
    rar->file.unpacked_size = unpacked_size;

    if(!read_var_sized(a, &file_attr, NULL))
        return ARCHIVE_EOF;

    if(file_flags & UTIME) {
        if(!read_u32(a, &mtime))
            return ARCHIVE_EOF;
    } else {
        /*LOG("no UTIME");*/
    }

    if(file_flags & CRC32) {
        /*LOG("has CRC32");*/
        if(!read_u32(a, &crc))
            return ARCHIVE_EOF;
    } else {
        /*LOG("no CRC32");*/
    }

    if(!read_var_sized(a, &compression_info, NULL))
        return ARCHIVE_EOF;

    c_method = (int) (compression_info >> 7) & 0x7;
    c_version = (int) (compression_info & 0x3f);

    rar->cstate.window_size = is_dir ? 0 : g_unpack_window_size << ((compression_info >> 10) & 15);
    rar->cstate.method = c_method;
    rar->cstate.version = c_version + 50;

    /*LOG("window_size=%zu", rar->cstate.window_size);*/

    LOG("compression_info: %08x", compression_info);
    set_solid(rar, (int) (compression_info & SOLID));

    if(!read_var_sized(a, &host_os, NULL))
        return ARCHIVE_EOF;

    if(!read_var_sized(a, &name_size, NULL))
        return ARCHIVE_EOF;

    if(!read_ahead(a, name_size, &p))
        return ARCHIVE_EOF;

    if(name_size > 2047) {
        // TODO: name too long, failing
        LOG("*** name too long, fail");
        return ARCHIVE_FATAL;
    }

    if(name_size == 0) {
        // TODO: no name specifiec, failing
        return ARCHIVE_FATAL;
    }

    memcpy(name_utf8_buf, p, name_size);
    name_utf8_buf[name_size] = 0;
    if(ARCHIVE_OK != consume(a, name_size)) {
        LOG("consume fail");
        return ARCHIVE_FATAL;
    }

    /*LOG("name: %s, dir? %d", name_utf8_buf, is_dir);*/

    if(extra_data_size > 0) {
        int ret = process_head_file_extra(a, rar, extra_data_size);

        // sanity check
        if(extra_data_size < 0) {
            LOG("*** internal error, file extra data size is not zero, parse error?");
            return ARCHIVE_FATAL;
        }

        if(ret != ARCHIVE_OK)
            return ret;
    }

    memset(entry, 0, sizeof(struct archive_entry));

    if((file_flags & UNKNOWN_UNPACKED_SIZE) == 0) {
        archive_entry_set_size(entry, unpacked_size);
    }

    if(file_flags & UTIME)
        archive_entry_set_ctime(entry, (time_t) mtime, 0);

    if(file_flags & CRC32) {
        /*LOG("file has stored crc: 0x%08x", crc);*/
        rar->file.stored_crc32 = crc;
    }

    archive_entry_update_pathname_utf8(entry, name_utf8_buf);
    rar->cstate.block_parsing_finished = 1;
    rar->cstate.all_filters_applied = 1;
    rar->cstate.unpacked_bytes = 0;
    rar->cstate.initialized = 0;

    return ARCHIVE_OK;
}

static int process_head_service(struct archive_read* a, struct rar5* rar, struct archive_entry* entry, size_t block_flags) {
    // Process this SERVICE block the same way as FILE blocks
    int ret = process_head_file(a, rar, entry, block_flags);
    if(ret != ARCHIVE_OK)
        return ret;

    // But skip the data part automatically. It's no use for the user anyway.
    // It contains only service data needed to properly unpack the archive.
    ret = rar5_read_data_skip(a);
    if(ret != ARCHIVE_OK)
        return ret;

    // After skipping, try parsing another block automatically. 
    return ARCHIVE_RETRY;
}

static int process_head_main(struct archive_read* a, struct rar5* rar, struct archive_entry* entry, size_t block_flags) {
    UNUSED(entry);

    int ret;
    size_t extra_data_size,
        extra_field_size,
        extra_field_id,
        archive_flags;

    if(block_flags & HFL_EXTRA_DATA) {
        if(!read_var_sized(a, &extra_data_size, NULL))
            return ARCHIVE_EOF;

        LOG("process_head_main: has extra data, size: 0x%08zx bytes", extra_data_size);
    } else {
        extra_data_size = 0;
    }

    if(!read_var_sized(a, &archive_flags, NULL)) {
        LOG("bad archive_flags");
        return ARCHIVE_EOF;
    }

    enum MAIN_FLAGS {
        VOLUME = 0x0001, VOLUME_NUMBER = 0x0002, SOLID = 0x0004, PROTECT = 0x0008, LOCK = 0x0010,
    };

    LOG("archive flags: 0x%08zu", archive_flags);
    if(archive_flags & VOLUME) {
        rar->main.volume = 1;
        LOG("*** volume archives not supported yet"); // TODO implement this
        return ARCHIVE_FATAL;
    }

    if(archive_flags & SOLID) {
        rar->main.solid = 1;
    }

    if(extra_data_size == 0) {
        LOG("early return, because extra_data_size == 0");
        return ARCHIVE_OK;
    }

    if(!read_var_sized(a, &extra_field_size, NULL)) {
        LOG("bad extra_field_size");
        return ARCHIVE_EOF;
    }

    if(!read_var_sized(a, &extra_field_id, NULL)) {
        LOG("bad extra_field_id");
        return ARCHIVE_EOF;
    }

    // TODO: bounds check
    if(extra_field_size == 0) {
        LOG("invalid extra_field_size");
        // TODO: Invalid main/extra/field size
        return ARCHIVE_FATAL;
    }

    enum MAIN_EXTRA {
        // Just one attribute here.
        LOCATOR = 0x01,
    };

    switch(extra_field_id) {
        case LOCATOR:
            ret = process_main_locator_extra_block(a, rar);
            if(ret != ARCHIVE_OK) {
                LOG("error while parsing main locator extra block");
                return ret;
            }

            break;
        default:
            LOG("invalid extra field id");
            // TODO: Invalid extra field id
            return ARCHIVE_FATAL;
    }

    LOG("main header parsing ok");
    return ARCHIVE_OK;
}

static int process_base_block(struct archive_read* a, struct rar5* rar, struct archive_entry* entry) {
    uint32_t hdr_crc, computed_crc;
    size_t raw_hdr_size, hdr_size_len, hdr_size;
    size_t header_id, header_flags;
    const uint8_t* p;
    int ret;

    if(!read_u32(a, &hdr_crc)) {
        LOG("can't read crc");
        return ARCHIVE_EOF;
    }

    /*LOG("hdr_crc=%08x", hdr_crc);*/

    if(!read_var_sized(a, &raw_hdr_size, &hdr_size_len)) {
        LOG("can't read hdr_size");
        return ARCHIVE_EOF;
    }

    // Sanity check, maximum header size for RAR5 is 2MB.
    if(raw_hdr_size > (2 * 1024 * 1024)) {
        LOG("bad hdr_size");
        return ARCHIVE_FATAL;
    }

    hdr_size = raw_hdr_size + hdr_size_len;

    if(!read_ahead(a, hdr_size, &p)) {
        LOG("can't read hdr buf");
        return ARCHIVE_EOF;
    }

    computed_crc = (uint32_t) crc32(0, p, (int) hdr_size);
    if(computed_crc != hdr_crc) {
        LOG("Base Header Block CRC error: hdr=0x%08x, calc=0x%08x", hdr_crc, computed_crc);
        archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT, "Header CRC error");
        return ARCHIVE_FATAL;
    }

    if(ARCHIVE_OK != consume(a, hdr_size_len)) {
        LOG("consume fail");
        return ARCHIVE_FATAL;
    }

    if(!read_var_sized(a, &header_id, NULL))
        return ARCHIVE_EOF;

    if(!read_var_sized(a, &header_flags, NULL))
        return ARCHIVE_EOF;

    enum HEADER_TYPE {
        HEAD_MARK = 0x00, HEAD_MAIN = 0x01, HEAD_FILE = 0x02, HEAD_SERVICE = 0x03,
        HEAD_CRYPT = 0x04, HEAD_ENDARC = 0x05, HEAD_UNKNOWN = 0xff,
    };

    /*LOG("header_id=%02lx", header_id);*/
    switch(header_id) {
        case HEAD_MAIN:
            ret = process_head_main(a, rar, entry, header_flags);

            // Main header doesn't have any files in it, so it's pointless
            // to return to the caller. Retry to next header, which should be
            // HEAD_FILE/HEAD_SERVICE.
            if(ret == ARCHIVE_OK)
                return ARCHIVE_RETRY;
            break;
        case HEAD_SERVICE:
            ret = process_head_service(a, rar, entry, header_flags);
            return ret;
        case HEAD_FILE:
            ret = process_head_file(a, rar, entry, header_flags);
            // TODO if this block didn't have any data in it, retry
            // TODO to next block.
            return ret;
        case HEAD_CRYPT:
            return ARCHIVE_FATAL;
        case HEAD_ENDARC:
            return ARCHIVE_FATAL;
        default:
            if((header_flags & HFL_SKIP_IF_UNKNOWN) == 0) {
                archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT, "Header type error");
                return ARCHIVE_FATAL;
            } else {
                // If the block is marked as 'skip if unknown', do as the flag says:
                // skip the block instead on failing on it.
                return ARCHIVE_RETRY;
            }
    }

    // Not reached.
    archive_set_error(&a->archive, ARCHIVE_ERRNO_PROGRAMMER, "Internal unpacked error");
    return ARCHIVE_FATAL;
}

static int rar5_read_header(struct archive_read *a, struct archive_entry *entry) {
    struct rar5* rar = get_context(a);
    int ret;

    if(rar->header_initialized == 0) {
        init_header(a, rar);
        rar->header_initialized = 1;
    }

    if(rar->skipped_magic == 0) {
        if(ARCHIVE_OK != consume(a, rar5_signature_size)) {
            LOG("consume fail");
            return ARCHIVE_FATAL;
        }

        rar->skipped_magic = 1;
    }

    do {
        /*LOG("-> parsing base header block");*/
        ret = process_base_block(a, rar, entry);
    } while(ret == ARCHIVE_RETRY);

    return ret;
}

static void reset_filters(struct rar5* rar) {
    cdeque_clear(&rar->cstate.filters);
}

static void init_unpack(struct rar5* rar) {
    rar->file.calculated_crc32 = 0;
    rar->file.read_offset = 0;
    rar->cstate.window_mask = rar->cstate.window_size - 1;

    if(rar->cstate.window_buf)
        free(rar->cstate.window_buf);

    if(rar->cstate.filtered_buf)
        free(rar->cstate.filtered_buf);

    rar->cstate.window_buf = calloc(1, rar->cstate.window_size);
    rar->cstate.filtered_buf = calloc(1, rar->cstate.window_size);

    rar->cstate.write_ptr = 0;
    rar->cstate.last_write_ptr = 0;

    memset(&rar->cstate.bd, 0, sizeof(rar->cstate.bd));
    memset(&rar->cstate.ld, 0, sizeof(rar->cstate.ld));
    memset(&rar->cstate.dd, 0, sizeof(rar->cstate.dd));
    memset(&rar->cstate.ldd, 0, sizeof(rar->cstate.ldd));
    memset(&rar->cstate.rd, 0, sizeof(rar->cstate.rd));
}

static void update_crc(struct rar5* rar, const uint8_t* p, size_t to_read) {
    /* Don't update CRC32 if the file doesn't have the `stored_crc32` info
       filled in. */
    if(rar->file.stored_crc32 > 0) {
        rar->file.calculated_crc32 = crc32(rar->file.calculated_crc32, p, to_read);
    }

    /* Check if the file uses an optional BLAKE2sp checksum algorithm. */
    if(rar->file.has_blake2 > 0) {
        /* Return value of the `update` function is always 0, so we can explicitly
           ignore it here. */
        (void) blake2sp_update(&rar->file.b2state, p, to_read);
    }
}

static int create_decode_tables(uint8_t* bit_length, struct decode_table* table, int size) {
    int code, upper_limit = 0, i, lc[16];
    uint32_t decode_pos_clone[rar5_countof(table->decode_pos)];
    ssize_t cur_len, quick_data_size;

    memset(&lc, 0, sizeof(lc));
    memset(table->decode_num, 0, sizeof(table->decode_num));
    table->size = size;
    table->quick_bits = size == HUFF_NC ? 10 : 7;

    for(i = 0; i < size; i++) {
        lc[bit_length[i] & 15]++;
    }
    
    lc[0] = 0;
    table->decode_pos[0] = 0;
    table->decode_len[0] = 0;

    for(i = 1; i < 16; i++) {
        upper_limit += lc[i];

        table->decode_len[i] = upper_limit << (16 - i);
        table->decode_pos[i] = table->decode_pos[i - 1] + lc[i - 1];

        upper_limit <<= 1;
    }

    memcpy(decode_pos_clone, table->decode_pos, sizeof(decode_pos_clone));

    for(i = 0; i < size; i++) {
        uint8_t clen = bit_length[i] & 15;
        if(clen > 0) {
            int last_pos = decode_pos_clone[clen];
            table->decode_num[last_pos] = i;
            decode_pos_clone[clen]++;
        }
    }

    quick_data_size = 1 << table->quick_bits;
    cur_len = 1;
    for(code = 0; code < quick_data_size; code++) {
        int bit_field = code << (16 - table->quick_bits);
        int dist, pos;

        while(cur_len < rar5_countof(table->decode_len) && bit_field >= table->decode_len[cur_len])
            cur_len++;

        table->quick_len[code] = cur_len;

        dist = bit_field - table->decode_len[cur_len - 1];
        dist >>= (16 - cur_len);

        pos = table->decode_pos[cur_len] + dist;
        if(cur_len < rar5_countof(table->decode_pos) && pos < size) {
            table->quick_num[code] = table->decode_num[pos];
        } else {
            table->quick_num[code] = 0;
        }
    }

    return ARCHIVE_OK;
}

static int decode_number(struct archive_read* a, struct rar5* rar,
    struct decode_table* table, const uint8_t* p, uint16_t* num)
{
    int i, bits, dist;
    uint16_t bitfield;
    uint32_t pos;

    (void) a;

    if(ARCHIVE_OK != read_bits_16(rar, p, &bitfield)) {
        LOG("read_bits_16 fail");
        return ARCHIVE_EOF;
    }

    bitfield &= 0xfffe;
    /*LOG("bitfield=%04x", bitfield);*/
    
    if(bitfield < table->decode_len[table->quick_bits]) {
        //LOG("using cached value");
        int code = bitfield >> (16 - table->quick_bits);
        //LOG("move fwd by %d bits", table->quick_len[code]);
        skip_bits(rar, table->quick_len[code]);
        *num = table->quick_num[code];
        return ARCHIVE_OK;
    }

    bits = 15;

    for(i = table->quick_bits + 1; i < 15; i++) {
        if(bitfield < table->decode_len[i]) {
            bits = i;
            break;
        }
    }

    skip_bits(rar, bits);

    dist = bitfield - table->decode_len[bits - 1];
    dist >>= (16 - bits);
    pos = table->decode_pos[bits] + dist;

    if(pos >= table->size)
        pos = 0;

    *num = table->decode_num[pos];
    return ARCHIVE_OK;
}

static int parse_tables(struct archive_read* a, 
    struct rar5* rar,
    const struct compressed_block_header* hdr,
    const uint8_t* p)
{
    UNUSED(rar);
    UNUSED(hdr);

    int ret;
    uint8_t bit_length[HUFF_BC];
    uint8_t nibble_mask = 0xF0;
    uint8_t nibble_shift = 4;
    int value, i, w;

    enum {
        ESCAPE = 15
    };

    for(w = 0, i = 0; w < HUFF_BC;) {
        value = (p[i] & nibble_mask) >> nibble_shift;

        if(nibble_mask == 0x0F)
            ++i;

        nibble_mask ^= 0xFF;
        nibble_shift ^= 4;

        if(value == ESCAPE) {
            value = (p[i] & nibble_mask) >> nibble_shift;
            if(nibble_mask == 0x0F)
                ++i;
            nibble_mask ^= 0xFF;
            nibble_shift ^= 4;

            if(value == 0) {
                /*LOG("store %d %02x", w, ESCAPE);*/
                bit_length[w++] = ESCAPE;
            } else {
                int k;

                for(k = 0; k < value + 2; k++) {
                    /*LOG("store %d %02x", w, 0);*/
                    bit_length[w++] = 0;
                }
            }
        } else {
            /*LOG("store %d %02x", w, value);*/
            bit_length[w++] = value;
        }
    }

    rar->bits.in_addr = i;
    rar->bits.bit_addr = nibble_shift ^ 4;

    ret = create_decode_tables(bit_length, &rar->cstate.bd, HUFF_BC);
    if(ret != ARCHIVE_OK) {
        LOG("create_decode_tables #1 fail");
        return ARCHIVE_FATAL;
    }

    uint8_t table[HUFF_TABLE_SIZE];
    UNUSED(table);

    /*LOG("building table");*/
    for(i = 0; i < HUFF_TABLE_SIZE;) {
        uint16_t num;

        ret = decode_number(a, rar, &rar->cstate.bd, p, &num);
        if(ret != ARCHIVE_OK) {
            LOG("decode_number fail");
            return ARCHIVE_FATAL;
        }

        /*LOG("num=%d", num);*/

        if(num < 16) {
            // 0..15: store directly
            table[i] = num;
            i++;
            continue;
        }

        if(num < 18) {
            // 16..17: repeat previous code
            uint16_t n;
            if(ARCHIVE_OK != read_bits_16(rar, p, &n))
                return ARCHIVE_EOF;

            if(num == 16) {
                n >>= 13;
                n += 3;
                skip_bits(rar, 3);
            } else {
                n >>= 9;
                n += 11;
                skip_bits(rar, 7);
            }

            if(i > 0) {
                while(n-- > 0 && i < HUFF_TABLE_SIZE) {
                    table[i] = table[i - 1];
                    i++;
                }
            } else
                return ARCHIVE_FATAL;

            continue;
        }

        // other codes: fill with zeroes `n` times
        uint16_t n;
        if(ARCHIVE_OK != read_bits_16(rar, p, &n))
            return ARCHIVE_EOF;

        if(num == 18) {
            n >>= 13;
            n += 3;
            skip_bits(rar, 3);
        } else {
            n >>= 9;
            n += 11;
            skip_bits(rar, 7);
        }

        while(n-- > 0 && i < HUFF_TABLE_SIZE)
            table[i++] = 0;
    }

    /*LOG("done, table size: %d", HUFF_TABLE_SIZE + w);*/

    ret = create_decode_tables(&table[0], &rar->cstate.ld, HUFF_NC);
    if(ret != ARCHIVE_OK) {
        LOG("ld table creation fail");
        return ARCHIVE_FATAL;
    }

    ret = create_decode_tables(&table[HUFF_NC], &rar->cstate.dd, HUFF_DC);
    if(ret != ARCHIVE_OK) {
        LOG("dd table creation fail");
        return ARCHIVE_FATAL;
    }

    ret = create_decode_tables(&table[HUFF_NC + HUFF_DC], &rar->cstate.ldd, HUFF_LDC);
    if(ret != ARCHIVE_OK) {
        LOG("ldd table creation fail");
        return ARCHIVE_FATAL;
    }

    ret = create_decode_tables(&table[HUFF_NC + HUFF_DC + HUFF_LDC], &rar->cstate.rd, HUFF_RC);
    if(ret != ARCHIVE_OK) {
        LOG("rd table creation fail");
        return ARCHIVE_FATAL;
    }

    /*LOG("tables read OK, addr=%d, bit=%d", rar->bits.in_addr, rar->bits.bit_addr);*/
    return ARCHIVE_OK;
}

static int parse_block_header(const uint8_t* p, ssize_t* block_size, struct compressed_block_header* hdr) {
    memcpy(hdr, p, sizeof(struct compressed_block_header));
    LOG("parsing block header: ptr is %02x %02x %02x %02x", p[0], p[1], p[2], p[3]);
    if(hdr->block_flags.byte_count == 3) {
        LOG("error: block header byte_count is %d", hdr->block_flags.byte_count);
        return ARCHIVE_FATAL;
    }

    LOG("raw bytecount: %d", hdr->block_flags.byte_count);

    // This should probably use bit reader interface in order to be more
    // future-proof.
    *block_size = 0;
    switch(hdr->block_flags.byte_count) {
        // 1-byte block size
        case 0: 
            *block_size = *(const uint8_t*) &p[2]; 
            break;

        // 2-byte block size
        case 1: 
            *block_size = *(const uint16_t*) &p[2]; 
            break;

        // 3-byte block size
        case 2: 
            *block_size = *(const uint32_t*) &p[2]; 
            *block_size &= 0x00FFFFFF; 
            break;

        default:
            LOG("*** todo: unsupported block size: %d", hdr->block_flags.byte_count);
            return ARCHIVE_FATAL;
    }

    uint8_t calculated_cksum = 0x5A
                               ^ hdr->block_flags_u8
                               ^ *block_size
                               ^ (*block_size >> 8)
                               ^ (*block_size >> 16);

    if(calculated_cksum != hdr->block_cksum) {
        LOG("Checksum error in compressed data block header, file corrupted?");
        LOG("Checksum stored in file: %02x, checksum calculated: %02x",
            hdr->block_cksum, calculated_cksum);
        return ARCHIVE_FATAL;
    } else {
        /*LOG("Block header checksum ok");*/
    }

    LOG("hdr=%p, block header last? %d, tables? %d", hdr, hdr->block_flags.is_last_block, hdr->block_flags.is_table_present);
    return ARCHIVE_OK;
}

static int parse_filter_data(struct rar5* rar, const uint8_t* p, uint32_t* filter_data) {
    int i, bytes;
    uint32_t data = 0;

    if(ARCHIVE_OK != read_consume_bits(rar, p, 2, &bytes))
        return ARCHIVE_EOF;

    bytes++;

    for(i = 0; i < bytes; i++) {
        uint16_t byte;

        if(ARCHIVE_OK != read_bits_16(rar, p, &byte)) {
            LOG("read_bits_16 fail when reading filter data");
            return ARCHIVE_EOF;
        }

        /*printf("data=%04x ", byte);*/
        data += (byte >> 8) << (i * 8);
        skip_bits(rar, 8);
    }
    /*printf("\n");*/

    *filter_data = data;
    return ARCHIVE_OK;
}

static int parse_filter(struct rar5* rar, const uint8_t* p) {
    uint32_t block_start, block_length;
    uint16_t filter_type;

    if(ARCHIVE_OK != parse_filter_data(rar, p, &block_start))
        return ARCHIVE_EOF;

    if(ARCHIVE_OK != parse_filter_data(rar, p, &block_length))
        return ARCHIVE_EOF;

    if(ARCHIVE_OK != read_bits_16(rar, p, &filter_type))
        return ARCHIVE_EOF;

    filter_type >>= 13;
    skip_bits(rar, 3);

    struct filter_info* filt = add_new_filter(rar);
    filt->type = filter_type;
    filt->orig_block_start = block_start;
    filt->block_start = rar->cstate.write_ptr + block_start;
    filt->block_length = block_length;

    // TODO: sanity checks;
    // fail if block length will be smaller than 4,
    // fail if block length will be bigger than 0x400000
    // fail if filter type will be unknown
    // fail if block start/block length combination will be outside of current file
    //     (verify with current file's uncompressed size)

    LOG("[filter] id=%d,rng=0x%08x-0x%08x type=%d", filt->id, filt->block_start, filt->block_length + filt->block_start - 1, filt->type);

    // Only some filters will be processed here.
    switch(filter_type) {
        case FILTER_DELTA:
            fallthrough;
        case FILTER_AUDIO: {
            int channels;

            if(ARCHIVE_OK != read_consume_bits(rar, p, 5, &channels))
                return ARCHIVE_EOF;

            filt->channels = channels + 1;
            break;
        }

        case FILTER_RGB: {
            int width;
            int pos_r;

            filt->channels = 3;

            if(ARCHIVE_OK != read_consume_bits(rar, p, 16, &width))
                return ARCHIVE_EOF;

            if(ARCHIVE_OK != read_consume_bits(rar, p, 2, &pos_r))
                return ARCHIVE_EOF;

            filt->width = (uint16_t) width;
            filt->pos_r = pos_r;
            break;
        }
    }

    return ARCHIVE_OK;
}

static int decode_code_length(struct rar5* rar, const uint8_t* p, uint16_t code) {
    int lbits, length = 2;
    if(code < 8) {
        lbits = 0;
        length += code;
    } else {
        lbits = code / 4 - 1;
        length += (4 | (code & 3)) << lbits;
    }

    if(lbits > 0) {
        int add;

        // LOG("requested read lbits=%d", lbits);

        if(ARCHIVE_OK != read_consume_bits(rar, p, lbits, &add))
            return -1;
        
        length += add;
    }

    return length;
}

static int copy_string(struct rar5* rar, int len, int dist) {
    ssize_t write_ptr = rar->cstate.write_ptr + rar->cstate.solid_offset;
    int i;

    /*if(!rar->skip_mode)*/
        /*printf("copy_string (len=%d dist=%d, srcptr=%d): ", len, dist, (write_ptr - dist) & rar->cstate.window_mask);*/

    for(i = 0; i < len; i++) {
        uint8_t src_byte = 
            rar->cstate.window_buf[(write_ptr - dist + i) & rar->cstate.window_mask];

        /*if(!rar->skip_mode)*/
            /*printf("%02x ", src_byte);*/

        rar->cstate.window_buf[(write_ptr + i) & rar->cstate.window_mask] =
            src_byte;
    }

    /*if(!rar->skip_mode)*/
        /*printf("\n");*/

    rar->cstate.write_ptr += len;
    return ARCHIVE_OK;
}

static int do_uncompress_block(struct archive_read* a, 
        struct rar5* rar, 
        const uint8_t* p, 
        const struct compressed_block_header* hdr)
{
    uint16_t num;
    int ret;
    const uint8_t bit_size = 1 + hdr->block_flags.bit_size;

    rar->cstate.block_parsing_finished = 0;

    while(1) {
        if(rar->cstate.write_ptr - rar->cstate.last_write_ptr > (4 * 1024 * 1024)) {
            // Don't allow growing data by more than 1 MB at a time.
            break;
        }

        if(rar->bits.in_addr > rar->cstate.cur_block_size - 1) {
            /*LOG("natural break, because in_addr=%d < cur_block_size-1=%zu",*/
                    /*rar->bits.in_addr, rar->cstate.cur_block_size - 1);*/

            rar->cstate.block_parsing_finished = 1;
            break;
        }

        if(rar->bits.in_addr == rar->cstate.cur_block_size - 1) {
            if(rar->bits.bit_addr >= bit_size) {
                /*LOG("natural break, because in_addr=%d == cur_block_size-1=%zu and bit_addr=%d >= bit_size=%d",*/
                        /*rar->bits.in_addr, rar->cstate.cur_block_size - 1,*/
                        /*rar->bits.bit_addr, bit_size);*/

                rar->cstate.block_parsing_finished = 1;
                break;
            }
        }

        rar->cstate.code_seq++;

        /*LOG("(addr=%d, bit=%d, cbs=%d)", rar->bits.in_addr, rar->bits.bit_addr, rar->cstate.computed_block_size);*/
        if(ARCHIVE_OK != decode_number(a, rar, &rar->cstate.ld, p, &num)) {
            LOG("fail in decode_number");
            return ARCHIVE_EOF;
        }

        /*if(!rar->skip_mode)*/
        /*LOG("--> code=%03d (seq=%d)", num, rar->cstate.code_seq);*/

        // num = RARv5 command code. 
        //
        // - Lower than 256 are just bytes, those codes can be stored in the
        // output buffer directly. 
        //
        // - Code 256 defines a new filter, which will be used to transform the
        // data block when it'll be fully decoded.
        //
        // - Code bigger than 257 and smaller than 262 define a repetition
        // pattern that should be copied from an already uncompressed chunk
        // of data.
        if(num < 256) {
            // Store literal directly.
            /*if(!rar->skip_mode)*/
                /*LOG("write byte: 0x%02x", num);*/

            rar->cstate.window_buf[(rar->cstate.solid_offset + rar->cstate.write_ptr++) & rar->cstate.window_mask] = 
                (uint8_t) num;

            continue;
        } else if(num >= 262) {
            int len = decode_code_length(rar, p, num - 262);
            if(len == -1) {
                LOG("decode_code_length fail");
                return ARCHIVE_FATAL;
            }

            // LOG("repetition: len=%d", len);

            int dbits, dist = 1;
            uint16_t dist_slot;
            if(ARCHIVE_OK != decode_number(a, rar, &rar->cstate.dd, p, &dist_slot)) {
                LOG("fail when decode_number(dd)");
                return ARCHIVE_FATAL;
            }

            /*LOG("dist_slot=%d", dist_slot);*/

            if(dist_slot < 4) {
                dbits = 0;
                dist += dist_slot;
            } else {
                dbits = dist_slot / 2 - 1;
                dist += (2 | (dist_slot & 1)) << dbits;
            }

            /*LOG("dist=%d, dbits=%d", dist, dbits);*/

            if(dbits > 0) {
                if(dbits >= 4) {
                    uint32_t add = 0;
                    if(dbits > 4) {
                        if(ARCHIVE_OK != read_bits_32(rar, p, &add)) {
                            LOG("fatal error during reading add value");
                            return ARCHIVE_EOF;
                        }

                        //LOG("readbuf=%08x", add);
                        skip_bits(rar, dbits - 4);

                        //add=((bits>>(36-DBits))<<4);
                        add = (add >> (36 - dbits)) << 4;
                        //LOG("add=%08x", add);

                        dist += add;
                    }

                    uint16_t low_dist;
                    if(ARCHIVE_OK != decode_number(a, rar, &rar->cstate.ldd, p, &low_dist)) {
                        LOG("fail during decode_number(ldd)");
                        return ARCHIVE_FATAL;
                    }

                    dist += low_dist;
                    //LOG("add=%d, low_dist=%d", add, low_dist);
                } else {
                    // dbits == 4
                    int add;

                    if(ARCHIVE_OK != read_consume_bits(rar, p, dbits, &add)) {
                        LOG("fail during read_consume_bits #2");
                        return ARCHIVE_FATAL;
                    }

                    //LOG("add=%d", add);
                    dist += add;
                }
            }

            if(dist > 0x100) {
                len++;

                if(dist > 0x2000) {
                    len++;

                    if(dist > 0x40000) {
                        len++;
                    }
                }
            }

            //LOG("copy_string: len=%d, dist=%d", len, dist);
            dist_cache_push(rar, dist);
            rar->cstate.last_len = len;
            /*LOG("last_len <- %d", last_len);*/
            if(ARCHIVE_OK != copy_string(rar, len, dist))
                return ARCHIVE_FATAL;
            continue;
        } else if(num == 256) {
            // Create a filter
            int prev_addr = rar->bits.in_addr;
            ret = parse_filter(rar, p);
            if(ret != ARCHIVE_OK) {
                LOG("filter parsing fail");
                return ARCHIVE_EOF;
            }

            continue;
        } else if(num == 257) {
            if(rar->cstate.last_len != 0) {
                /*LOG("CopyString %d,%d", rar->cstate.last_len, rar->cstate.dist_cache[0]);*/
                if(ARCHIVE_OK != copy_string(rar, rar->cstate.last_len, rar->cstate.dist_cache[0]))
                    return ARCHIVE_FATAL;
            }

            continue;
        } else if(num < 262) {
            const int index = num - 258;
            const int dist = dist_cache_touch(rar, index);
            uint16_t len_slot;
            int len;

            if(ARCHIVE_OK != decode_number(a, rar, &rar->cstate.rd, p, &len_slot)) {
                LOG("fail during decode_number(rd)");
                return ARCHIVE_FATAL;
            }

            len = decode_code_length(rar, p, len_slot);
            rar->cstate.last_len = len;
            /*LOG("last_len <- %d (#2)", last_len);*/

            if(ARCHIVE_OK != copy_string(rar, len, dist))
                return ARCHIVE_FATAL;

            continue;
        }

        LOG("*** todo: unsupported block code: %d", num);
        return ARCHIVE_FATAL;
    }

    if(rar->cstate.block_parsing_finished) {
        /*LOG("natural end of block");*/
    }

    return ARCHIVE_OK;
}

enum PROCESS_BLOCK_RET {
    CONTINUE, LAST_BLOCK, ERROR_FATAL, ERROR_EOF
};

static int process_block(struct archive_read* a, struct rar5* rar) {
    const uint8_t* p;
    int ret;

    if(rar->cstate.block_parsing_finished) {
        if(!read_ahead(a, 6, &p)) {
            LOG("failed to prefetch data block header");
            return ERROR_EOF;
        }

        /*LOG("%02x %02x %02x %02x", p[0], p[1], p[2], p[3]);*/

        // Read block_size by parsing block header. Validate the header by
        // calculating CRC byte stored inside the header. Size of the header
        // is not constant (block size can be stored either in 1 or 2 bytes),
        // that's why block size is left out from the `compressed_block_header`
        // structure and returned by `parse_block_header` as the second
        // argument.
        ssize_t block_size;

        ret = parse_block_header(p, &block_size, &rar->last_block_hdr);
        if(ret != ARCHIVE_OK) {
            LOG("parse_block_header returned an error");
            return ERROR_FATAL;
        }

        // Skip block header. Next data is huffman tables, if present.
        //
        ssize_t to_skip = sizeof(struct compressed_block_header) + 
            rar->last_block_hdr.block_flags.byte_count + 1;

        rar->file.bytes_remaining -= to_skip;
        if(ARCHIVE_OK != consume(a, to_skip)) {
            LOG("consuming %zi bytes resulted in an error: %d", to_skip, ret);
            return ERROR_EOF;
        }

        // Read the whole block size into memory. This can take up to
        // 8 megabytes of memory in theoretical cases. Might be worth to
        // optimize this and use a standard chunk of 4kb's.
        if(!read_ahead(a, 4 + block_size, &p)) {
            LOG("failed to prefetch the whole block: %zi bytes", 4 + block_size);
            return ERROR_EOF;
        }

        rar->cstate.block_buf = p;
        rar->cstate.cur_block_size = block_size;
        rar->cstate.block_num++;
        //rar->cstate.code_seq = 0;
        rar->cstate.computed_block_size = to_skip;

        rar->bits.in_addr = 0;
        rar->bits.bit_addr = 0;

        if(rar->last_block_hdr.block_flags.is_table_present) {
            ret = parse_tables(a, rar, &rar->last_block_hdr, p);
            if(ret != ARCHIVE_OK) {
                LOG("parse_tables fail");
                return ret;
            }
        }
    } else {
        p = rar->cstate.block_buf;
    }

    ret = do_uncompress_block(a, rar, p, &rar->last_block_hdr);
    if(ret != ARCHIVE_OK) {
        LOG("uncompress_block fail");
        return ERROR_FATAL;
    }

    if(rar->cstate.block_parsing_finished) {
        if(rar->cstate.cur_block_size > 0) {
            rar->file.bytes_remaining -= rar->cstate.cur_block_size;
            if(ARCHIVE_OK != consume(a, rar->cstate.cur_block_size)) {
                LOG("fail when consuming");
                return ARCHIVE_FATAL;
            }
        }
    }

    if(rar->cstate.block_parsing_finished && rar->last_block_hdr.block_flags.is_last_block) {
        return LAST_BLOCK;
    } else
        return CONTINUE;
}

static int use_data(struct rar5* rar, const void** buf, size_t* size, int64_t* offset) {
    int i;

    for(i = 0; i < rar5_countof(rar->cstate.dready); i++) {
        struct data_ready *d = &rar->cstate.dready[i];
        if(d->used) {
            if(buf)    *buf = d->buf;
            if(size)   *size = d->size;
            if(offset) *offset = d->offset;

            d->used = 0;

            update_crc(rar, d->buf, d->size);

            LOG("using data: buf=%zx, size=%zx, offset=%lx", d->buf, d->size, d->offset);
            LOG("window_buf:     %zx", &rar->cstate.window_buf[0]);
            return ARCHIVE_OK;
        }
    }

    return ARCHIVE_RETRY;
}

static void push_data_ready(struct rar5* rar, const uint8_t* buf, size_t size, int64_t offset) {
    int i;

    /*unused ssize_t b = (ssize_t) buf - (ssize_t) rar->cstate.window_buf;*/
    /*LOG("pushing data ready: buf=%zx, size=%zx, offset=%lx", b, size, offset);*/

    for(i = 0; i < rar5_countof(rar->cstate.dready); i++) {
        struct data_ready* d = &rar->cstate.dready[i];
        if(!d->used) {
            d->used = 1;
            d->buf = buf;
            d->size = size;
            d->offset = offset;
            return;
        }
    }

    LOG("internal rar5 unpacker error: premature end of data_ready stack");
    exit(1);
}

static void dump_window_buf(struct rar5* rar) {
    int col = 0;

    LOG("dumping window.bin");
    FILE* fw = fopen("window.bin", "wb");
    fwrite(rar->cstate.window_buf, rar->cstate.window_mask + 1, 1, fw);
    fclose(fw);
}

static int do_uncompress_file(struct archive_read* a,
                           struct rar5* rar)
{
    const size_t mask = rar->cstate.window_mask;
    int ret;

    if(!rar->cstate.initialized) {
        if(!rar->main.solid || !rar->cstate.window_buf) {
            LOG("*** init_unpack");
            init_unpack(rar);
        } else if(rar->main.solid) {
            LOG("*** solid init");
            dump_window_buf(rar);
        }

        rar->cstate.code_seq = 0;
        rar->cstate.initialized = 1;
    }

    if(rar->cstate.all_filters_applied == 1) {
        // TODO: fatal fail when trying to be here if is_last_block=1
        //       this would be an internal unpacker error

        LOG("--- processing blocks..., last_block=%d", rar->last_block_hdr.block_flags.is_last_block);
        // This loop will iterate only when current block won't emit any data. If
        // the block has written any data at all, the loop will break.
        while(1) {
            ret = process_block(a, rar);
            switch(ret) {
                case ERROR_EOF:
                    LOG("process_block returned ERROR_EOF");
                    return ARCHIVE_EOF;

                case ERROR_FATAL:
                    LOG("process_block returned ERROR_FATAL");
                    return ARCHIVE_FATAL;

                // ignoring LAST_BLOCK and CONTINUE
            }

            if(rar->cstate.last_write_ptr == rar->cstate.write_ptr) {
                LOG("no data in this block, continuing");
                continue;
            }

            break;
        }

        // There shouldn't be a situation where 1 block will write more data than
        // the size of the window, because the `process_block` function limits the
        // data than can be generated. 
        if((rar->cstate.last_write_ptr & mask) > (rar->cstate.write_ptr & mask)) {
            rar->cstate.window_flip_count++;
        }
    }

    ret = apply_filters(rar);
    if(ret == ARCHIVE_RETRY)
        return ARCHIVE_OK;
    else if(ret == ARCHIVE_FATAL) {
        LOG("apply_filters returned an error");
        return ARCHIVE_FATAL;
    }

    // if ARCHIVE_OK, continue

    ssize_t max_end_pos;

    if(cdeque_size(&rar->cstate.filters) > 0) {
        /*LOG("checking if we can write something before hitting first filter...");*/
        struct filter_info* flt;
        if(CDE_OK != cdeque_front(&rar->cstate.filters, cdeque_filter_p(&flt))) {
            LOG("internal error, can't read first filter");
            return ARCHIVE_FATAL;
        }

        max_end_pos = rar5_min(flt->block_start, rar->cstate.write_ptr);
    } else {
        // no filters, we just dump the data and we're happy
        max_end_pos = rar->cstate.write_ptr;
    }

    if(max_end_pos == rar->cstate.last_write_ptr) {
        // can't write anything... ;(
        /*LOG("can't write anything, we have to loop, return 0 bytes or retry request");*/
        /*LOG("we're standing on 0x%08zx, last generated byte is 0x%08zx", rar->cstate.last_write_ptr,*/
                /*rar->cstate.write_ptr);*/
        return ARCHIVE_RETRY;
    } else {
        // can write something before hitting first filter. do it now.
        push_window_data(rar, rar->cstate.last_write_ptr, max_end_pos);
        rar->cstate.last_write_ptr = max_end_pos;
    }

    return ARCHIVE_OK;
}

static int uncompress_file(struct archive_read* a,
                           struct rar5* rar)
{
    int ret;

    while(1) {
        ret = do_uncompress_file(a, rar);
        if(ret != ARCHIVE_RETRY)
            return ret;
    }
}


static int do_unstore_file(struct archive_read* a, 
                           struct rar5* rar,
                           const void** buf,
                           size_t* size,
                           int64_t* offset) 
{
    const uint8_t* p;

    if(ARCHIVE_OK != consume(a, rar->file.prev_read_bytes)) {
        LOG("consume failed");
        return ARCHIVE_FATAL;
    }

    size_t to_read = rar5_min(rar->file.bytes_remaining, 64 * 1024);

    if(!read_ahead(a, to_read, &p)) {
        LOG("I/O error during do_unstore_file");
        archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT, "I/O error when unstoring file");
        return ARCHIVE_FATAL;
    }

    if(buf)    *buf = p;
    if(size)   *size = to_read;
    if(offset) *offset = rar->file.read_offset;

    rar->file.prev_read_bytes = to_read;
    rar->file.bytes_remaining -= to_read;
    rar->file.read_offset += to_read;
    update_crc(rar, p, to_read);
    return ARCHIVE_OK;
}

static int do_unpack(struct archive_read* a, 
                     struct rar5* rar, 
                     const void** buf, 
                     size_t* size, 
                     int64_t* offset) 
{
    enum COMPRESSION_METHOD {
        STORE = 0, FASTEST = 1, FAST = 2, NORMAL = 3, GOOD = 4, BEST = 5
    };

    switch(rar->cstate.method) {
        case STORE:
            return do_unstore_file(a, rar, buf, size, offset);
        case FASTEST: 
            fallthrough;
        case FAST:    
            fallthrough;
        case NORMAL:  
            fallthrough;
        case GOOD:    
            fallthrough;
        case BEST:
            return uncompress_file(a, rar);
        default:
            LOG("TODO: compression method not supported yet: %d", rar->cstate.method);
            return ARCHIVE_FATAL;
    }

    return ARCHIVE_OK;
}

static int finalize_file(struct archive_read* a, struct rar5* rar) {
    /* Sanity checks. */
    
    if(rar->file.read_offset > rar->file.packed_size) {
        LOG("something is wrong: offset is bigger than packed size");
        return ARCHIVE_FATAL;
    }

    /* During unpacking, on each unpacked block we're calling the update_crc()
     * function. Since we are here, the unpacking process is already over and
     * we can check if calculated checksum (CRC32 or BLAKE2sp) is the same as
     * what is stored in the archive
     */
    
    if(rar->file.stored_crc32 > 0) {
        /* Check CRC32 only when the file contains a CRC32 value for this 
         * file. */

        if(rar->file.calculated_crc32 != rar->file.stored_crc32) {
            /* Checksums do not match; the unpacked file is corrupted. */

            LOG("Checksum error: CRC32");
#ifndef DONT_FAIL_ON_CRC_ERROR
            archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
                              "Checksum error: CRC32");
            return ARCHIVE_FATAL;
#endif
        } else {
            LOG("Checksum OK: CRC32");
        }
    }

    if(rar->file.has_blake2 > 0) {
        /* BLAKE2sp is an optional checksum algorithm that is added to RARv5 
         * archives when using the `-htb` switch during creation of archive.
         *
         * We now finalize the hash calculation by calling the `final`
         * function. This will generate the final hash value we can use
         * to compare it with the BLAKE2sp checksum that is stored in the
         * archive. 
         *
         * The return value of this `final` function is not very helpful,
         * as it guards only against improper use. This is why we're
         * explicitly ignoring it. */

        uint8_t b2_buf[32];

        (void) blake2sp_final(&rar->file.b2state, b2_buf, 32);

        if(memcmp(&rar->file.blake2sp, b2_buf, 32) != 0) {
            LOG("Checksum error: BLAKE2sp");
#ifndef DONT_FAIL_ON_CRC_ERROR
            archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
                              "Checksum error: BLAKE2");

            return ARCHIVE_FATAL;
#endif
        } else {
            LOG("Checksum OK: BLAKE2sp");
        }
    }

    /* Finalization for this file has been successfully completed. */
    return ARCHIVE_OK;
}

static int rar5_read_data(struct archive_read *a, const void **buff,
                                  size_t *size, int64_t *offset) {
    int ret;
    struct rar5* rar = get_context(a);

    ret = use_data(rar, buff, size, offset);
    if(ret == ARCHIVE_OK)
        return ret;

    ret = do_unpack(a, rar, buff, size, offset);
    if(ret != ARCHIVE_OK) {
        LOG("do_unpack returned error: %d", ret);
        return ret;
    }

    (void) use_data(rar, buff, size, offset);

    if(rar->file.bytes_remaining == 0 && rar->cstate.last_write_ptr == rar->cstate.write_ptr) {
        /* If all bytes of current file were processed, run finalization.
         *
         * Finalization will check checksum against proper values. If
         * some of the checksums will not match, we'll return an error
         * value in the last `archive_read_data` call to signal an error
         * to the user. */

        return finalize_file(a, rar);
    }

    return ARCHIVE_OK;
}

static int rar5_read_data_skip(struct archive_read *a) {
    struct rar5* rar = get_context(a);

    if(rar->main.solid) {
        /* In solid archives, instead of skipping data, we need to extract 
         * it. */
        
        LOG("skipping solid: %ld bytes", rar->file.bytes_remaining);

        int ret;

        while(rar->file.bytes_remaining > 0) {
            rar->skip_mode = 1;
            LOG("enabling skip_mode");
            ret = rar5_read_data(a, NULL, NULL, NULL);
            LOG("disabling skip_mode");
            rar->skip_mode = 0;

            if(ret < 0) {
                return ret;
            }
        }

        return ARCHIVE_OK;
    } else {
        LOG("skipping non-solid: %ld bytes", rar->file.bytes_remaining);

        if(ARCHIVE_OK != consume(a, rar->file.bytes_remaining + rar->file.prev_read_bytes)) {
            LOG("consume failed");
            return ARCHIVE_FATAL;
        }

        rar->file.prev_read_bytes = 0;
        rar->file.bytes_remaining = 0;

        return ARCHIVE_OK;
    }
}

static int64_t rar5_seek_data(struct archive_read *a, int64_t offset,
                                  int whence) {
    UNUSED(a);
    UNUSED(offset);
    UNUSED(whence);
    return ARCHIVE_FATAL;
}

static int rar5_cleanup(struct archive_read *a)
{
    struct rar5* rar = get_context(a);

    free(rar->cstate.window_buf);
    free(rar->cstate.filtered_buf);
    reset_filters(rar);
    cdeque_free(&rar->cstate.filters);
    free(rar);
    a->format->data = NULL;

    return ARCHIVE_OK;
}

static int rar5_capabilities(struct archive_read * a)
{
    UNUSED(a);

    return (ARCHIVE_READ_FORMAT_CAPS_ENCRYPT_DATA
            | ARCHIVE_READ_FORMAT_CAPS_ENCRYPT_METADATA);
}

static int rar5_has_encrypted_entries(struct archive_read *_a)
{
    UNUSED(_a);
    return ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW;
}

int
archive_read_support_format_rar5(struct archive *_a) {
    struct archive_read* ar;
    int ret;
    struct rar5* rar;

    if(ARCHIVE_OK != (ret = get_archive_read(_a, &ar)))
        return ret;

    rar = malloc(sizeof(*rar));
    if(rar == NULL) {
        archive_set_error(&ar->archive, ENOMEM, "Can't allocate rar5 data");
        return ARCHIVE_FATAL;
    }

    if(ARCHIVE_OK != rar5_init(rar)) {
        archive_set_error(&ar->archive, ENOMEM, "Can't allocate rar5 filter buffer");
        return ARCHIVE_FATAL;
    }

    ret = __archive_read_register_format(ar,
                                         rar,
                                         "rar5",
                                         rar5_bid,
                                         rar5_options,
                                         rar5_read_header,
                                         rar5_read_data,
                                         rar5_read_data_skip,
                                         rar5_seek_data,
                                         rar5_cleanup,
                                         rar5_capabilities,
                                         rar5_has_encrypted_entries);

    if(ret != ARCHIVE_OK) {
        cdeque_free(&rar->cstate.filters);
        free(rar);
    }

    return ret;
}
