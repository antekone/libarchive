#include "archive_platform.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <time.h>
#include <limits.h>
#ifdef HAVE_ZLIB_H
#include <zlib.h> /* crc32 */
#endif

#include "archive.h"
#ifndef HAVE_ZLIB_H
#include "archive_crc32.h"
#endif
#include "archive_endian.h"
#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_ppmd7_private.h"
#include "archive_private.h"
#include "archive_read_private.h"
#include "archive_entry_private.h"

struct rar5 {
    int header_initialized;
    int skipped_magic;
    uint64_t qlist_offset;
    uint64_t rr_offset;
};

void rar5_init(struct rar5* rar) {
    rar->header_initialized = 0;
    rar->skipped_magic = 0;
    rar->qlist_offset = 0;
    rar->rr_offset = 0;
}

#define UNUSED(x) (void) (x)
#define LOG(...)  do { printf(__VA_ARGS__); puts(""); } while(0)

const unsigned char rar5_signature[] = { 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00 };
const size_t rar5_signature_size = sizeof(rar5_signature);

static inline
int __get_archive_read(struct archive* a, struct archive_read** ar) {
    *ar = (struct archive_read*) a;

    archive_check_magic(a, ARCHIVE_READ_MAGIC, ARCHIVE_STATE_NEW,
                        "archive_read_support_format_rar5");

    return ARCHIVE_OK;
}

static inline
struct rar5* __get_context(struct archive_read* a) {
    return (struct rar5*) a->format->data;
}

int __rar_read_ahead(struct archive_read* a, size_t how_many, const uint8_t** ptr) {
    if(!ptr)
        return 0;

    *ptr = __archive_read_ahead(a, how_many, NULL);
    if(*ptr == NULL)
        return 0;

    return 1;
}

int __rar_read_var(struct archive_read* a, uint64_t* pvalue, size_t* pvalue_len) {
    uint64_t result = 0;
    size_t shift, i;
    const uint8_t* p;
    uint8_t b;

    if(!__rar_read_ahead(a, 8, &p))
        return 0;

    for(shift = 0, i = 0; i < 8; i++, shift += 7) {
        b = p[i];

        result += (b & 0x7F) << shift;
        if((b & 0x80) == 0) {
            if(pvalue)
                *pvalue = result;

            if(pvalue_len)
                *pvalue_len = 1 + i;
            else {
                (void) __archive_read_consume(a, 1 + i);
            }

            return 1;
        }
    }

    // Bad encoding.
    return 0;
}

int __rar_read_u32(struct archive_read* a, uint32_t* pvalue) {
    const uint8_t* p;

    if(!__rar_read_ahead(a, 4, &p))
        return 0;

    *pvalue = *(const uint32_t*)p;

    (void) __archive_read_consume(a, 4);
    return 1;
}

static int
bid_standard(struct archive_read* a) {
    const uint8_t* p;

    if(!__rar_read_ahead(a, rar5_signature_size, &p))
        return -1;

    if(!memcmp(rar5_signature, p, rar5_signature_size))
        return 30;

    return -1;
}

static int
bid_sfx(struct archive_read* a) {
    // TODO implement this
    return -1;
}

static int
rar5_bid(struct archive_read* a, int best_bid) {
    struct rar5* ctx = __get_context(a);
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
    return ARCHIVE_FATAL;
}

static void
init_header(struct archive_read* a, struct rar5* rar) {
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
    size_t locator_flags;

    if(!__rar_read_var(a, &locator_flags, NULL))
        return ARCHIVE_EOF;

    enum LOCATOR_FLAGS {
        QLIST = 0x01, RECOVERY = 0x02,
    };

    if(locator_flags & QLIST) {
        if(!__rar_read_var(a, &rar->qlist_offset, NULL))
            return ARCHIVE_EOF;

        LOG("qlist offset=0x%08lx", rar->qlist_offset);
    }

    if(locator_flags & RECOVERY) {
        if(!__rar_read_var(a, &rar->rr_offset, NULL))
            return ARCHIVE_EOF;

        LOG("rr offset=0x%08lx", rar->rr_offset);
    }

    return ARCHIVE_OK;
}

static int
process_head_file(struct archive_read* a, struct rar5* rar, struct archive_entry* entry, size_t block_flags) {
    int ret;
    size_t extra_data_size, data_size, file_flags, unpacked_size,
        file_attr, compression_info, host_os, name_size;
    uint32_t mtime, crc;
    int c_method, c_version, is_dir;
    char name_utf8_buf[2048 * 4];
    const uint8_t* p;

    if(block_flags & HFL_EXTRA_DATA) {
        if(!__rar_read_var(a, &extra_data_size, NULL))
            return ARCHIVE_EOF;

        LOG("process_head_file: has extra data, size: 0x%08zx bytes", extra_data_size);
        LOG("*** not supported yet");
        return ARCHIVE_FATAL;
    }

    if(block_flags & HFL_DATA) {
        if(!__rar_read_var(a, &data_size, NULL))
            return ARCHIVE_EOF;
    }

    enum FILE_FLAGS {
        DIRECTORY = 0x0001, UTIME = 0x0002, CRC32 = 0x0004, UNKNOWN_UNPACKED_SIZE = 0x0008,
    };

    if(!__rar_read_var(a, &file_flags, NULL))
        return ARCHIVE_EOF;

    if(!__rar_read_var(a, &unpacked_size, NULL))
        return ARCHIVE_EOF;

    if(file_flags & UNKNOWN_UNPACKED_SIZE) {
        unpacked_size = 0;
        LOG("*** unknown unpacked size, not handled!");
        return ARCHIVE_FAILED;
    }

    is_dir = (int) (file_flags & DIRECTORY);

    if(!__rar_read_var(a, &file_attr, NULL))
        return ARCHIVE_EOF;

    if(file_flags & UTIME) {
        if(!__rar_read_u32(a, &mtime))
            return ARCHIVE_EOF;
    }

    if(file_flags & CRC32) {
        if(!__rar_read_u32(a, &crc))
            return ARCHIVE_EOF;
    }

    if(!__rar_read_var(a, &compression_info, NULL))
        return ARCHIVE_EOF;

    c_method = (int) (compression_info >> 7) & 0x7;
    c_version = (int) (compression_info & 0x3f);

    if(!__rar_read_var(a, &host_os, NULL))
        return ARCHIVE_EOF;

    if(!__rar_read_var(a, &name_size, NULL))
        return ARCHIVE_EOF;

    if(!__rar_read_ahead(a, name_size, &p))
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
    __archive_read_consume(a, name_size);

    LOG("name: %s, dir? %d", name_utf8_buf, is_dir);

    if(extra_data_size > 0) {
        size_t extra_field_size;
        size_t extra_field_id;

        enum EXTRA {
            CRYPT = 0x01, HASH = 0x02, HTIME = 0x03, VERSION_ = 0x04, REDIR = 0x05, UOWNER = 0x06, SUBDATA = 0x07
        };

        if(!__rar_read_var(a, &extra_field_size, NULL))
            return ARCHIVE_EOF;

        if(!__rar_read_var(a, &extra_field_id, NULL))
            return ARCHIVE_EOF;

        // ...
    }

    memset(entry, 0, sizeof(struct archive_entry));
    archive_entry_set_size(entry, unpacked_size);

    return ARCHIVE_FAILED;
}

static int
process_head_main(struct archive_read* a, struct rar5* rar, struct archive_entry* entry, size_t block_flags) {
    int ret;
    size_t extra_data_size,
        extra_field_size,
        extra_field_id,
        archive_flags;

    if(block_flags & HFL_EXTRA_DATA) {
        if(!__rar_read_var(a, &extra_data_size, NULL))
            return ARCHIVE_EOF;

        LOG("process_head_main: has extra data, size: 0x%08zx bytes", extra_data_size);
    } else {
        extra_data_size = 0;
    }

    if(!__rar_read_var(a, &archive_flags, NULL))
        return ARCHIVE_EOF;

    enum MAIN_FLAGS {
        VOLUME = 0x0001, VOLUME_NUMBER = 0x0002, SOLID = 0x0004, PROTECT = 0x0008, LOCK = 0x0010,
    };

    LOG("archive flags: 0x%08zu", archive_flags);
    if(archive_flags & VOLUME) {
        LOG("*** volume archives not supported yet"); // TODO implement this
        return ARCHIVE_FATAL;
    }

    if(extra_data_size == 0)
        return ARCHIVE_OK;

    if(!__rar_read_var(a, &extra_field_size, NULL))
        return ARCHIVE_EOF;

    if(!__rar_read_var(a, &extra_field_id, NULL))
        return ARCHIVE_EOF;

    // TODO: bounds check
    if(extra_field_size == 0) {
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
            if(ret != ARCHIVE_OK)
                return ret;

            break;
        default:
            // TODO: Invalid extra field id
            return ARCHIVE_FATAL;
    }

    LOG("main header parsing ok");
    return ARCHIVE_OK;
}

static int
process_base_block(struct archive_read* a, struct rar5* rar, struct archive_entry* entry) {
    uint32_t hdr_crc, computed_crc;
    size_t raw_hdr_size, hdr_size_len, hdr_size;
    size_t header_id, header_flags;
    const uint8_t* p;
    int ret;

    if(!__rar_read_u32(a, &hdr_crc)) {
        LOG("can't read crc");
        return ARCHIVE_EOF;
    }

    LOG("crc: 0x%08x", hdr_crc);

    if(!__rar_read_var(a, &raw_hdr_size, &hdr_size_len))
        return ARCHIVE_EOF;

    // Sanity check, maximum header size for RAR5 is 2MB.
    if(raw_hdr_size > (2 * 1024 * 1024))
        return ARCHIVE_FATAL;

    hdr_size = raw_hdr_size + hdr_size_len;

    if(!__rar_read_ahead(a, hdr_size, &p))
        return ARCHIVE_EOF;

    computed_crc = (uint32_t) crc32(0, p, (int) hdr_size);
    if(computed_crc != hdr_crc) {
        LOG("CRC error: hdr=0x%08x, calc=0x%08x", hdr_crc, computed_crc);
        archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT, "Header CRC error");
        return ARCHIVE_FATAL;
    }

    (void) __archive_read_consume(a, hdr_size_len);

    if(!__rar_read_var(a, &header_id, NULL))
        return ARCHIVE_EOF;

    if(!__rar_read_var(a, &header_flags, NULL))
        return ARCHIVE_EOF;

    enum HEADER_TYPE {
        HEAD_MARK = 0x00, HEAD_MAIN = 0x01, HEAD_FILE = 0x02, HEAD_SERVICE = 0x03,
        HEAD_CRYPT = 0x04, HEAD_ENDARC = 0x05, HEAD_UNKNOWN = 0xff,
    };

    switch(header_id) {
        case HEAD_MAIN:
            ret = process_head_main(a, rar, entry, header_flags);
            if(ret == ARCHIVE_OK)
                return ARCHIVE_RETRY;
            break;
        case HEAD_FILE:
        case HEAD_SERVICE:
            ret = process_head_file(a, rar, entry, header_flags);
            if(ret == ARCHIVE_OK)
                return ARCHIVE_RETRY;
            break;
            return ARCHIVE_FATAL;
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
}

static int
rar5_read_header(struct archive_read *a, struct archive_entry *entry)
{
    struct rar5* rar = __get_context(a);
    int ret;

    if(rar->header_initialized == 0) {
        init_header(a, rar);
        rar->header_initialized = 1;
    }

    if(rar->skipped_magic == 0) {
        __archive_read_consume(a, rar5_signature_size);
        rar->skipped_magic = 1;
    }

    do {
        LOG("-> parsing block");
        ret = process_base_block(a, rar, entry);
    } while(ret == ARCHIVE_RETRY);

    return ret;
}

static int
rar5_read_data(struct archive_read *a, const void **buff,
                                  size_t *size, int64_t *offset) {
    return ARCHIVE_FATAL;
}

static int
rar5_read_data_skip(struct archive_read *a) {
    return ARCHIVE_FATAL;
}

static int64_t
rar5_seek_data(struct archive_read *a, int64_t offset,
                                  int whence) {
    return ARCHIVE_FATAL;
}

static int
rar5_cleanup(struct archive_read *a)
{
    return ARCHIVE_FATAL;
}

static int
rar5_capabilities(struct archive_read * a)
{
    UNUSED(a);

    return (ARCHIVE_READ_FORMAT_CAPS_ENCRYPT_DATA
            | ARCHIVE_READ_FORMAT_CAPS_ENCRYPT_METADATA);
}

static int
rar5_has_encrypted_entries(struct archive_read *_a)
{
    return ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW;
}



int
archive_read_support_format_rar5(struct archive *_a) {
    struct archive_read* ar;
    int ret;
    struct rar5* rar;

    if(ARCHIVE_OK != (ret = __get_archive_read(_a, &ar)))
        return ret;

    rar = malloc(sizeof(*rar));
    if(rar == NULL) {
        archive_set_error(&ar->archive, ENOMEM, "Can't allocate rar5 data");
        return (ARCHIVE_FATAL);
    }

    rar5_init(rar);

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

    if(ret != ARCHIVE_OK)
        free(rar);

    return (ret);
}