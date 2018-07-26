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

struct file_header {
    uint32_t stored_crc32;
    uint32_t calculated_crc32;
    uint64_t unpacked_size;
    uint64_t packed_size;
    uint64_t bytes_remaining;
    uint64_t read_offset; // offset in the compressed stream
};

enum BLOCK_TYPE {
    BLOCK_UNSPECIFIED = 0, BLOCK_LZ = 1, BLOCK_PPM = 2,
};

#define HUFF_NC 306
#define HUFF_DC 64
#define HUFF_LDC 16
#define HUFF_RC 44
#define HUFF_BC 20
#define HUFF_TABLE_SIZE (HUFF_NC + HUFF_DC + HUFF_RC + HUFF_LDC)

static const int CIF_SOLID       = 0x00000001;
static const int CIF_TABLES_READ = 0x00000002;

struct comp_info {
    int flags;
    int method;
    int version;
    size_t window_size;
    uint8_t* window_buf;
    size_t window_offset;
    size_t window_mask;

    int tables_read;
    uint8_t huffman_table[HUFF_TABLE_SIZE];
    enum BLOCK_TYPE block_type;
};

static const int BIT_READER_MAX_BUF = 0x8000;

struct bit_reader {
    uint8_t* buf;
    int buf_size;
    int bit_addr;
    int in_addr;
};

struct rar5 {
    int header_initialized;
    int skipped_magic;

    uint64_t qlist_offset;    // not used by this unpacker
    uint64_t rr_offset;       // not used by this unpacker

    uint8_t* unpack_buf;

    struct comp_info compression;
    struct file_header file;
    struct bit_reader bits;
};

#define RAR5_MIN(a, b) (((a) > (b)) ? (b) : (a))

static void rar5_init(struct rar5* rar) {
    memset(rar, 0, sizeof(struct rar5));
}

static void set_solid(struct rar5* rar, int flag) {
    rar->compression.flags |= flag ? CIF_SOLID : 0;
}

static void set_tables_read(struct rar5* rar, int flag) {
    rar->compression.flags |= flag ? CIF_TABLES_READ : 0;
}

static int is_solid(struct rar5* rar) {
    return rar->compression.flags & CIF_SOLID;
}

static int is_tables_read(struct rar5* rar) {
    return rar->compression.flags & CIF_TABLES_READ;
}

#define UNUSED(x) (void) (x)
#define LOG(...)  do { printf(__VA_ARGS__); puts(""); } while(0)

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

static inline
struct rar5* get_context(struct archive_read* a) {
    return (struct rar5*) a->format->data;
}

static int read_ahead(struct archive_read* a, size_t how_many, const uint8_t** ptr) {
    if(!ptr)
        return 0;

    *ptr = __archive_read_ahead(a, how_many, NULL);
    if(*ptr == NULL)
        return 0;

    return 1;
}

static int read_var(struct archive_read* a, uint64_t* pvalue, size_t* pvalue_len) {
    uint64_t result = 0;
    size_t shift, i;
    const uint8_t* p;
    uint8_t b;

    if(!read_ahead(a, 8, &p))
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

int read_u32(struct archive_read* a, uint32_t* pvalue);
int read_u32(struct archive_read* a, uint32_t* pvalue) {
    const uint8_t* p;

    if(!read_ahead(a, 4, &p))
        return 0;

    *pvalue = *(const uint32_t*)p;

    (void) __archive_read_consume(a, 4);
    return 1;
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
    size_t locator_flags;

    if(!read_var(a, &locator_flags, NULL))
        return ARCHIVE_EOF;

    enum LOCATOR_FLAGS {
        QLIST = 0x01, RECOVERY = 0x02,
    };

    if(locator_flags & QLIST) {
        if(!read_var(a, &rar->qlist_offset, NULL))
            return ARCHIVE_EOF;

        LOG("qlist offset=0x%08lx", rar->qlist_offset);
    }

    if(locator_flags & RECOVERY) {
        if(!read_var(a, &rar->rr_offset, NULL))
            return ARCHIVE_EOF;

        LOG("rr offset=0x%08lx", rar->rr_offset);
    }

    return ARCHIVE_OK;
}

static int
process_head_file(struct archive_read* a, struct rar5* rar, struct archive_entry* entry, size_t block_flags) {
    UNUSED(rar);

    size_t extra_data_size = 0, data_size, file_flags, unpacked_size,
        file_attr, compression_info, host_os, name_size;
    uint32_t mtime = 0, crc;
    int c_method = 0, c_version = 0, is_dir;
    char name_utf8_buf[2048 * 4];
    const uint8_t* p;

    UNUSED(c_method);
    UNUSED(c_version);

    if(block_flags & HFL_EXTRA_DATA) {
        if(!read_var(a, &extra_data_size, NULL))
            return ARCHIVE_EOF;

        LOG("process_head_file: has extra data, size: 0x%08zx bytes", extra_data_size);
        LOG("*** not supported yet");
        return ARCHIVE_FATAL;
    }

    if(block_flags & HFL_DATA) {
        if(!read_var(a, &data_size, NULL))
            return ARCHIVE_EOF;

        rar->file.packed_size = data_size;
        rar->file.bytes_remaining = rar->file.packed_size;
        LOG("data size: 0x%08zx", data_size);
    } else {
        LOG("*** FILE/SERVICE block without data, failing");
        return ARCHIVE_FATAL;
    }

    enum FILE_FLAGS {
        DIRECTORY = 0x0001, UTIME = 0x0002, CRC32 = 0x0004, UNKNOWN_UNPACKED_SIZE = 0x0008,
    };

    enum COMP_INFO_FLAGS {
        SOLID = 0x0040,
    };

    if(!read_var(a, &file_flags, NULL))
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

    if(!read_var(a, &file_attr, NULL))
        return ARCHIVE_EOF;

    if(file_flags & UTIME) {
        if(!read_u32(a, &mtime))
            return ARCHIVE_EOF;
    }

    if(file_flags & CRC32) {
        if(!read_u32(a, &crc))
            return ARCHIVE_EOF;
    }

    if(!read_var(a, &compression_info, NULL))
        return ARCHIVE_EOF;

    c_method = (int) (compression_info >> 7) & 0x7;
    c_version = (int) (compression_info & 0x3f);

    rar->compression.window_size = is_dir ? 0 : g_unpack_window_size << ((compression_info >> 10) & 15);
    rar->compression.method = c_method;
    rar->compression.version = c_version;

    set_solid(rar, (int) (compression_info & SOLID));

    if(!read_var(a, &host_os, NULL))
        return ARCHIVE_EOF;

    if(!read_var(a, &name_size, NULL))
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
    (void) __archive_read_consume(a, name_size);

    LOG("name: %s, dir? %d", name_utf8_buf, is_dir);

    if(extra_data_size > 0) {
        size_t extra_field_size;
        size_t extra_field_id;

        enum EXTRA {
            CRYPT = 0x01, HASH = 0x02, HTIME = 0x03, VERSION_ = 0x04, REDIR = 0x05, UOWNER = 0x06, SUBDATA = 0x07
        };

        if(!read_var(a, &extra_field_size, NULL))
            return ARCHIVE_EOF;

        if(!read_var(a, &extra_field_id, NULL))
            return ARCHIVE_EOF;

        LOG("*** EXTRA in file/service block, not supported yet");
        return ARCHIVE_FAILED;
    }

    memset(entry, 0, sizeof(struct archive_entry));

    if((file_flags & UNKNOWN_UNPACKED_SIZE) == 0) {
        archive_entry_set_size(entry, unpacked_size);
    }

    if(file_flags & UTIME)
        archive_entry_set_ctime(entry, (time_t) mtime, 0);

    if(file_flags & CRC32) {
        if(!read_u32(a, &rar->file.stored_crc32))
            return ARCHIVE_EOF;

        LOG("stored CRC32 of this file: %x", rar->file.stored_crc32);
    }

    archive_entry_update_pathname_utf8(entry, name_utf8_buf);
    LOG("file pointer is positioned at a file record");
    return ARCHIVE_OK;
}

static int
process_head_main(struct archive_read* a, struct rar5* rar, struct archive_entry* entry, size_t block_flags) {
    UNUSED(entry);

    int ret;
    size_t extra_data_size,
        extra_field_size,
        extra_field_id,
        archive_flags;

    if(block_flags & HFL_EXTRA_DATA) {
        if(!read_var(a, &extra_data_size, NULL))
            return ARCHIVE_EOF;

        LOG("process_head_main: has extra data, size: 0x%08zx bytes", extra_data_size);
    } else {
        extra_data_size = 0;
    }

    if(!read_var(a, &archive_flags, NULL))
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

    if(!read_var(a, &extra_field_size, NULL))
        return ARCHIVE_EOF;

    if(!read_var(a, &extra_field_id, NULL))
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

    if(!read_u32(a, &hdr_crc)) {
        LOG("can't read crc");
        return ARCHIVE_EOF;
    }

    LOG("crc: 0x%08x", hdr_crc);

    if(!read_var(a, &raw_hdr_size, &hdr_size_len))
        return ARCHIVE_EOF;

    // Sanity check, maximum header size for RAR5 is 2MB.
    if(raw_hdr_size > (2 * 1024 * 1024))
        return ARCHIVE_FATAL;

    hdr_size = raw_hdr_size + hdr_size_len;

    if(!read_ahead(a, hdr_size, &p))
        return ARCHIVE_EOF;

    computed_crc = (uint32_t) crc32(0, p, (int) hdr_size);
    if(computed_crc != hdr_crc) {
        LOG("CRC error: hdr=0x%08x, calc=0x%08x", hdr_crc, computed_crc);
        archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT, "Header CRC error");
        return ARCHIVE_FATAL;
    }

    (void) __archive_read_consume(a, hdr_size_len);

    if(!read_var(a, &header_id, NULL))
        return ARCHIVE_EOF;

    if(!read_var(a, &header_flags, NULL))
        return ARCHIVE_EOF;

    enum HEADER_TYPE {
        HEAD_MARK = 0x00, HEAD_MAIN = 0x01, HEAD_FILE = 0x02, HEAD_SERVICE = 0x03,
        HEAD_CRYPT = 0x04, HEAD_ENDARC = 0x05, HEAD_UNKNOWN = 0xff,
    };

    switch(header_id) {
        case HEAD_MAIN:
            ret = process_head_main(a, rar, entry, header_flags);

            // Main header doesn't have any files in it, so it's pointless
            // to return to the caller. Retry to next header, which should be
            // HEAD_FILE/HEAD_SERVICE.
            if(ret == ARCHIVE_OK)
                return ARCHIVE_RETRY;
            break;
        case HEAD_FILE:
        case HEAD_SERVICE:
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

static int
rar5_read_header(struct archive_read *a, struct archive_entry *entry)
{
    struct rar5* rar = get_context(a);
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

static void bit_init(struct bit_reader* bits) {
    if(bits->buf)
        free(bits->buf);

    bits->buf = malloc(3 + BIT_READER_MAX_BUF); // TODO: verify null pointer
    memset(bits->buf, 0, 3 + BIT_READER_MAX_BUF);
    bits->bit_addr = 0;
    bits->in_addr = 0;
}

static void bit_fill(struct bit_reader* bits, struct archive_read* a, size_t size) {
    const uint8_t* buf;
    read_ahead(a, size, &buf); // TODO: check success
    memcpy(bits->buf, buf, size);
}

static void bit_skip(int n) {
    UNUSED(n);
}

static uint16_t bit_get16() {
    return 0;
}

static uint32_t bit_get32() {
    return 0;
}

static void init_unpack(struct rar5* rar) {
    rar->compression.block_type = BLOCK_LZ;
    rar->compression.window_mask = rar->compression.window_size - 1;
    memset(rar->compression.huffman_table, 0, HUFF_TABLE_SIZE);
    set_tables_read(rar, False);
    bit_init(&rar->bits);
}

static int do_unstore_file(struct archive_read* a, 
                           struct rar5* rar,
                           const void** buf,
                           size_t* size,
                           int64_t* offset) 
{
    const uint8_t* p;

    LOG("unstoring file, remaining bytes: %lx", rar->file.bytes_remaining);

    size_t to_read = RAR5_MIN(rar->file.bytes_remaining, a->archive.read_data_requested);
    if(!read_ahead(a, to_read, &p)) {
        LOG("I/O error during do_unstore_file");
        archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT, "I/O error when unstoring file");
        return ARCHIVE_FATAL;
    }

    *buf = p;
    *size = rar->file.bytes_remaining;
    *offset = rar->file.read_offset;

    // TODO: update crc of unpacked file

    rar->file.bytes_remaining -= to_read;
    rar->file.read_offset += to_read;
    rar->file.calculated_crc32 = crc32(rar->file.calculated_crc32, p, to_read);
    return ARCHIVE_OK;
}

static int do_unpack(struct archive_read* a, 
                     struct rar5* rar, 
                     const void** buf, 
                     size_t* size, 
                     int64_t* offset) 
{
    LOG("do_unpack, compression method: %d", rar->compression.method);

    if(is_solid(rar)) {
        LOG("TODO: solid archives are not supported yet");
        return ARCHIVE_FATAL;
    }

    if(rar->compression.method > 5) {
        LOG("do_unpack: Unknown compression method");
        archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT, "Unknown compression method");
        return ARCHIVE_FATAL;
    }

    enum COMPRESSION_METHOD {
        STORE = 0, FASTEST = 1, FAST = 2, NORMAL = 3, GOOD = 4, BEST = 5
    };

    switch(rar->compression.method) {
        case STORE:
            return do_unstore_file(a, rar, buf, size, offset);
        default:
            LOG("TODO: compression method not supported yet");
            return ARCHIVE_FATAL;
    }

    return ARCHIVE_OK;
}

static int rar5_read_data(struct archive_read *a, const void **buff,
                                  size_t *size, int64_t *offset) {
    UNUSED(a);
    UNUSED(buff);
    UNUSED(size);
    UNUSED(offset);

    size_t bytes_requested = a->archive.read_data_requested > g_unpack_buf_chunk_size ?
                             g_unpack_buf_chunk_size : a->archive.read_data_requested;

    struct rar5* rar = get_context(a);
    if(rar->unpack_buf == NULL) {
        init_unpack(rar);
        rar->unpack_buf = malloc(g_unpack_buf_chunk_size);
        LOG("allocated unpack_buf=%p", (void*) rar->unpack_buf);
        if(!rar->unpack_buf) {
            archive_set_error(&a->archive, ENOMEM, "Can't allocate decompression buffer");
            return ARCHIVE_FATAL;
        }
    }

    LOG("ask for data: %zu", a->archive.read_data_requested);

    int ret = do_unpack(a, rar, buff, size, offset);
    if(ret != ARCHIVE_OK) {
        LOG("do_unpack returned error: %d", ret);
        return ret;
    }

    if(rar->file.bytes_remaining == 0) {
        // Sanity check.
        if(rar->file.read_offset > rar->file.packed_size) {
            LOG("something is wrong: offset is bigger than packed size");
            return ARCHIVE_FATAL;
        }

        // Fully unpacked the file.

        LOG("got crc: %x, should be: %x", rar->file.calculated_crc32,
                                          rar->file.stored_crc32);
    }

    return ARCHIVE_OK;
}

static int
rar5_read_data_skip(struct archive_read *a) {
    UNUSED(a);
    return ARCHIVE_FATAL;
}

static int64_t
rar5_seek_data(struct archive_read *a, int64_t offset,
                                  int whence) {
    UNUSED(a);
    UNUSED(offset);
    UNUSED(whence);
    return ARCHIVE_FATAL;
}

static int
rar5_cleanup(struct archive_read *a)
{
    struct rar5* rar = get_context(a);

    if(rar->unpack_buf)
        free(rar->unpack_buf);

    free(rar);
    return ARCHIVE_OK;
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
