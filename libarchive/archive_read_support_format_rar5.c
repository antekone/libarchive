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

static int rar5_read_data_skip(struct archive_read *a);

// common with rar4
struct huffman_tree_node
{
  int branches[2];
};

struct huffman_table_entry
{
  unsigned int length;
  int value;
};

struct huffman_code
{
  struct huffman_tree_node *tree;
  int numentries;
  int numallocatedentries;
  int minlength;
  int maxlength;
  int tablesize;
  struct huffman_table_entry *table;
};
int create_code(struct archive_read *, struct huffman_code *, unsigned char *, int, char);
// end common with rar4

struct file_header {
    uint32_t stored_crc32;
    uint32_t calculated_crc32;
    uint64_t unpacked_size;
    uint64_t packed_size;
    uint64_t bytes_remaining;
    uint64_t read_offset; // offset in the compressed stream
    uint64_t prev_read_bytes;

    // optional time fields
    uint64_t e_mtime;
    uint64_t e_ctime;
    uint64_t e_atime;
    uint32_t e_unix_ns;

    // optional hash fields
    uint8_t blake2sp[32];
    char has_blake2;
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

struct comp_info {
    int flags;
    int method;
    int version;
    size_t window_size;
    uint8_t* window_buf;
    size_t window_offset;
    size_t window_mask;

    struct decode_table bd;
    struct decode_table ld;
    struct decode_table dd;
    struct decode_table ldd;
    struct decode_table rd;
};

/*static const int BIT_READER_MAX_BUF = 0x8000;*/

struct bit_reader {
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

struct compressed_block_header { 
    union {
        struct {
            uint8_t bit_size : 3;
            uint8_t byte_count : 2;
            uint8_t _ : 1;
            uint8_t is_last_block : 1;
            uint8_t is_table_present : 1;
        } block_flags;
        uint8_t block_flags_u8;
    };

    uint8_t block_cksum;
};

#define RAR5_MIN(a, b) (((a) > (b)) ? (b) : (a))

static void rar5_init(struct rar5* rar) {
    memset(rar, 0, sizeof(struct rar5));
}

static void reset_file_context(struct rar5* rar) {
    memset(&rar->file, 0, sizeof(rar->file));
}

static void set_solid(struct rar5* rar, int flag) {
    rar->compression.flags |= flag ? CIF_SOLID : 0;
}

/*static void set_tables_read(struct rar5* rar, int flag) {*/
    /*rar->compression.flags |= flag ? CIF_TABLES_READ : 0;*/
/*}*/

static int is_solid(struct rar5* rar) {
    return rar->compression.flags & CIF_SOLID;
}

/*static int is_tables_read(struct rar5* rar) {*/
    /*return rar->compression.flags & CIF_TABLES_READ;*/
/*}*/

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

/*static int read_u16(struct archive_read* a, uint16_t* pvalue) {*/
    /*const uint8_t* p;*/

    /*if(!read_ahead(a, 2, &p))*/
        /*return 0;*/

    /**pvalue = *(const uint16_t*)p;*/

    /*(void) __archive_read_consume(a, 2);*/
    /*return 1;*/
/*}*/

static int read_bits_16(struct rar5* rar, const uint8_t* p, uint16_t* value) {
    int bits = (int) p[rar->bits.in_addr] << 16;
    LOG("addr=%d, bit=%d", 4 + rar->bits.in_addr, rar->bits.bit_addr);
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

    (void) __archive_read_consume(a, 4);
    return 1;
}

int read_u64(struct archive_read* a, uint64_t* pvalue);
int read_u64(struct archive_read* a, uint64_t* pvalue) {
    const uint8_t* p;

    if(!read_ahead(a, 8, &p))
        return 0;

    *pvalue = *(const uint64_t*)p;

    (void) __archive_read_consume(a, 8);
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
                
static int parse_file_extra_hash(struct archive_read* a, struct rar5* rar, ssize_t* extra_data_size) {
    uint64_t hash_type;
    size_t value_len;

    if(!read_var(a, &hash_type, &value_len))
        return ARCHIVE_EOF;

    *extra_data_size -= value_len;
    (void) __archive_read_consume(a, value_len);

    enum HASH_TYPE {
        BLAKE2sp = 0x00
    };

    if(hash_type == BLAKE2sp) {
        const uint8_t* p;
        const int hash_size = sizeof(rar->file.blake2sp);

        rar->file.has_blake2 = 1;
        if(!read_ahead(a, hash_size, &p))
            return ARCHIVE_EOF;

        memcpy(&rar->file.blake2sp, p, hash_size);

        (void) __archive_read_consume(a, hash_size);
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
    (void) __archive_read_consume(a, value_len);

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


    LOG("mtime: %016lx", rar->file.e_mtime);
    LOG("ctime: %016lx", rar->file.e_ctime);
    LOG("atime: %016lx", rar->file.e_atime);
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

    LOG("extra_data_size before attr loop=%zi", extra_data_size);

    while(extra_data_size > 0) {
        if(!read_var(a, &extra_field_size, &var_size))
            return ARCHIVE_EOF;

        extra_data_size -= var_size;
        (void) __archive_read_consume(a, var_size);

        if(!read_var(a, &extra_field_id, &var_size))
            return ARCHIVE_EOF;

        extra_data_size -= var_size;
        (void) __archive_read_consume(a, var_size);

        LOG("extra_field_size=%ld", extra_field_size);
        LOG("extra_field_id=%ld", extra_field_id);
        LOG("extra_data_size after size/type fields=%zi", extra_data_size);

        switch(extra_field_id) {
            case CRYPT:
                LOG("CRYPT");
                break;
            case HASH:
                ret = parse_file_extra_hash(a, rar, &extra_data_size); break;
                break;
            case HTIME:
                ret = parse_file_extra_htime(a, rar, &extra_data_size); break;
                break;
            case VERSION_:
                LOG("VERSION");
                break;
            case REDIR:
                LOG("REDIR");
                break;
            case UOWNER:
                LOG("UOWNER");
                break;
            case SUBDATA:
                LOG("SUBDATA");
                break;
            default:
                LOG("*** fatal: unknown extra field in a file/service block: %ld", extra_field_id);
                return ARCHIVE_FATAL;
        }

        LOG("extra_data_size after parsing attr: %zi", extra_data_size);
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
    size_t data_size, file_flags, unpacked_size, file_attr, compression_info, host_os, name_size;
    uint32_t mtime = 0, crc;
    int c_method = 0, c_version = 0, is_dir;
    char name_utf8_buf[2048 * 4];
    const uint8_t* p;

    UNUSED(c_method);
    UNUSED(c_version);

    reset_file_context(rar);

    if(block_flags & HFL_EXTRA_DATA) {
        LOG("extra data is present here");

        size_t edata_size;
        if(!read_var(a, &edata_size, NULL))
            return ARCHIVE_EOF;

        // intentional type cast from unsigned to signed
        extra_data_size = (ssize_t) edata_size;
    }

    if(block_flags & HFL_DATA) {
        if(!read_var(a, &data_size, NULL))
            return ARCHIVE_EOF;

        rar->file.packed_size = data_size;
        rar->file.bytes_remaining = rar->file.packed_size;
        LOG("data size: 0x%08zx", data_size);
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
    rar->compression.version = c_version + 50;

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

    if(file_flags & CRC32)
        rar->file.stored_crc32 = crc;

    archive_entry_update_pathname_utf8(entry, name_utf8_buf);
    LOG("file pointer is positioned at a file record");
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

    LOG("hdr_crc=%08x", hdr_crc);

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

    LOG("header_id=%02lx", header_id);
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

static int
rar5_read_header(struct archive_read *a, struct archive_entry *entry)
{
    struct rar5* rar = get_context(a);
    int ret;

    const uint8_t* p = NULL;
    if(!read_ahead(a, 4, &p)) {
        LOG("read_ahead failed");
    } else {
        printf("ptr now is %02x %02x %02x %02x\n", p[0], p[1], p[2], p[3]);
    }

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

/*static void bit_init(struct bit_reader* bits) {*/
    /*if(bits->buf)*/
        /*free(bits->buf);*/

    /*bits->buf = malloc(3 + BIT_READER_MAX_BUF); // TODO: verify null pointer*/
    /*memset(bits->buf, 0, 3 + BIT_READER_MAX_BUF);*/
    /*bits->bit_addr = 0;*/
    /*bits->in_addr = 0;*/
/*}*/

/*static void bit_fill(struct bit_reader* bits, struct archive_read* a, size_t size) {*/
    /*const uint8_t* buf;*/
    /*read_ahead(a, size, &buf); // TODO: check success*/
    /*memcpy(bits->buf, buf, size);*/
/*}*/

static void init_unpack(struct rar5* rar) {
    rar->file.calculated_crc32 = 0;
    rar->file.read_offset = 0;
    rar->compression.window_mask = rar->compression.window_size - 1;
}

static void update_crc(struct rar5* rar, const uint8_t* p, size_t to_read) {
    rar->file.calculated_crc32 = crc32(rar->file.calculated_crc32, p, to_read);
}

#define countof(X) ((const ssize_t) (sizeof(X) / sizeof(*X)))

static void dump_decode_table(struct decode_table* t) {
    LOG("[decodetable] size: %d", t->size);

    LOG("[decodetable] decode_len: ");
    for(int i = 0; i < 16; i++) {
        printf("%04x, ", t->decode_len[i]);
    }
    printf("\n");

    LOG("[decodetable] decode_pos: ");
    for(int i = 0; i < 16; i++) {
        printf("%04x, ", t->decode_pos[i]);
    }
    printf("\n");

    LOG("[decodetable] quick_bits: %d", t->quick_bits);

    LOG("[decodetable] quick_len: ");
    for(int i = 0; i < (1 << 10); i++) {
        printf("%04x, ", t->quick_len[i]);
    }
    printf("\n");

    LOG("[decodetable] quick_num: ");
    for(int i = 0; i < (1 << 10); i++) {
        printf("%04x, ", t->quick_num[i]);
    }
    printf("\n");

    LOG("[decodetable] decode_num: ");
    for(int i = 0; i < 306; i++) {
        printf("%04x, ", t->decode_num[i]);
    }
    printf("\n");

}

static int create_decode_tables(uint8_t* bit_length, struct decode_table* table, int size) {
    int lc[16];
    uint32_t decode_pos_clone[countof(table->decode_pos)];
    int upper_limit = 0;

    memset(&lc, 0, sizeof(lc));
    memset(table->decode_num, 0, sizeof(table->decode_num));
    table->size = size;
    table->quick_bits = size == HUFF_NC ? 10 : 7;

    for(int i = 0; i < size; i++) {
        lc[bit_length[i] & 15]++;
    }
    
    lc[0] = 0;
    table->decode_pos[0] = 0;
    table->decode_len[0] = 0;

    for(int i = 1; i < 16; i++) {
        upper_limit += lc[i];

        table->decode_len[i] = upper_limit << (16 - i);
        table->decode_pos[i] = table->decode_pos[i - 1] + lc[i - 1];

        upper_limit <<= 1;
    }

    memcpy(decode_pos_clone, table->decode_pos, sizeof(decode_pos_clone));

    for(int i = 0; i < size; i++) {
        uint8_t cur_len = bit_length[i] & 15;
        if(cur_len > 0) {
            int last_pos = decode_pos_clone[cur_len];
            table->decode_num[last_pos] = i;
            decode_pos_clone[cur_len]++;
        }
    }

    ssize_t quick_data_size = 1 << table->quick_bits;
    ssize_t cur_len = 1;
    for(int code = 0; code < quick_data_size; code++) {
        int bit_field = code << (16 - table->quick_bits);
        int dist, pos;

        while(cur_len < countof(table->decode_len) && bit_field >= table->decode_len[cur_len])
            cur_len++;

        table->quick_len[code] = cur_len;

        dist = bit_field - table->decode_len[cur_len - 1];
        dist >>= (16 - cur_len);

        pos = table->decode_pos[cur_len] + dist;
        if(cur_len < countof(table->decode_pos) && pos < size) {
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
    UNUSED(a);

    uint16_t bitfield;
    if(ARCHIVE_OK != read_bits_16(rar, p, &bitfield)) {
        LOG("read_bits_16 fail");
        return ARCHIVE_EOF;
    }

    bitfield &= 0xfffe;
    LOG("bitfield: 0x%04x", bitfield);
    
    if(bitfield < table->decode_len[table->quick_bits]) {
        LOG("using cached value");
        int code = bitfield >> (16 - table->quick_bits);
        LOG("move fwd by %d bits", table->quick_len[code]);
        skip_bits(rar, table->quick_len[code]);
        *num = table->quick_num[code];
        return ARCHIVE_OK;
    }

    int bits = 15;
    UNUSED(bits);
    for(int i = table->quick_bits + 1; i < 15; i++) {
        if(bitfield < table->decode_len[i]) {
            bits = i;
            break;
        }
    }

    LOG("*** decode_number TODO");
    return ARCHIVE_FATAL;
}

static int parse_tables(struct archive_read* a, 
    struct rar5* rar,
    const struct compressed_block_header* hdr,
    ssize_t block_size)
{
    UNUSED(rar);
    UNUSED(hdr);

    int ret;
    const uint8_t* p;

    if(!read_ahead(a, block_size, &p))
        return ARCHIVE_EOF;

    uint8_t bit_length[HUFF_BC];
    uint8_t nibble_mask = 0xF0;
    uint8_t nibble_shift = 4;
    int value, i, w;

    for(w = 0, i = 0; w < HUFF_BC;) {
        value = (p[i] & nibble_mask) >> nibble_shift;

        if(nibble_mask == 0x0F)
            ++i;

        nibble_mask ^= 0xFF;
        nibble_shift ^= 4;

        if(value == 15) {
            value = (p[i] & nibble_mask) >> nibble_shift;
            if(nibble_mask == 0x0F)
                ++i;
            nibble_mask ^= 0xFF;
            nibble_shift ^= 4;

            if(value == 0) {
                LOG("store %d %02x", w, 15);
                bit_length[w++] = 15;
            } else {
                for(int k = 0; k < value + 2; k++) {
                    LOG("store %d %02x", w, 0);
                    bit_length[w++] = 0;
                }
            }
        } else {
            LOG("store %d %02x", w, value);
            bit_length[w++] = value;
        }
    }

    (void) __archive_read_consume(a, i);
    rar->bits.in_addr = i;

    ret = create_decode_tables(bit_length, &rar->compression.bd, HUFF_BC);
    if(ret != ARCHIVE_OK) {
        LOG("create_decode_tables #1 fail");
        return ARCHIVE_FATAL;
    }

    dump_decode_table(&rar->compression.bd);

    uint8_t table[HUFF_TABLE_SIZE];
    UNUSED(table);

    LOG("building table");
    for(i = 0; i < HUFF_TABLE_SIZE;) {
        uint16_t num;

        ret = decode_number(a, rar, &rar->compression.bd, p, &num);
        if(ret != ARCHIVE_OK) {
            LOG("decode_number fail");
            return ARCHIVE_FATAL;
        }

        LOG("num=%d", num);

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

    LOG("done, table size: %d", HUFF_TABLE_SIZE);

    ret = create_decode_tables(&table[0], &rar->compression.ld, HUFF_NC);
    if(ret != ARCHIVE_OK) {
        LOG("ld table creation fail");
        return ARCHIVE_FATAL;
    }

    ret = create_decode_tables(&table[HUFF_NC], &rar->compression.dd, HUFF_DC);
    if(ret != ARCHIVE_OK) {
        LOG("dd table creation fail");
        return ARCHIVE_FATAL;
    }

    ret = create_decode_tables(&table[HUFF_NC + HUFF_DC], &rar->compression.ldd, HUFF_LDC);
    if(ret != ARCHIVE_OK) {
        LOG("ldd table creation fail");
        return ARCHIVE_FATAL;
    }

    ret = create_decode_tables(&table[HUFF_NC + HUFF_DC + HUFF_LDC], &rar->compression.rd, HUFF_RC);
    if(ret != ARCHIVE_OK) {
        LOG("rd table creation fail");
        return ARCHIVE_FATAL;
    }

    return ARCHIVE_OK;
}

static const struct compressed_block_header* parse_block_header(const uint8_t* p, 
    ssize_t* block_size) 
{
    const struct compressed_block_header* hdr = (const struct compressed_block_header*) p;
    if(hdr->block_flags.byte_count == 3)
        return NULL;

    // This should probably use bit reader interface in order to be more
    // future-proof.
    *block_size = 0;
    switch(hdr->block_flags.byte_count) {
        // 2-byte block size
        case 1: *block_size = *(const uint16_t*) &p[2]; break;
        // 3-byte block size
        case 2: *block_size = *(const uint32_t*) &p[2]; *block_size &= 0x00FFFFFF; break;
        default:
            LOG("*** todo: unsupported block size: %d", hdr->block_flags.byte_count);
            return NULL;
    }

    uint8_t calculated_cksum = 0x5A
                               ^ hdr->block_flags_u8
                               ^ *block_size
                               ^ (*block_size >> 8)
                               ^ (*block_size >> 16);

    if(calculated_cksum != hdr->block_cksum) {
        LOG("Checksum error in compressed data block header, file corrupted?");
        return NULL;
    }

    return hdr;
}

static int do_uncompress_file(struct archive_read* a,
                           struct rar5* rar,
                           const void** buf,
                           size_t* size,
                           int64_t* offset) 
{
    UNUSED(buf);
    UNUSED(size);
    UNUSED(offset);

    const uint8_t* p;

    if(rar->compression.version != 50) {
        LOG("compression version not supported: %d", rar->compression.version);
        return ARCHIVE_FATAL;
    }

    if(is_solid(rar)) {
        LOG("*** TODO: solid archives are not supported yet");
        return ARCHIVE_FATAL;
    }

    if(rar->unpack_buf == NULL) {
        init_unpack(rar);
        rar->unpack_buf = malloc(g_unpack_buf_chunk_size);
        LOG("allocated unpack_buf=%p, size=%zi", (void*) rar->unpack_buf,
                                                g_unpack_buf_chunk_size);
        if(!rar->unpack_buf) {
            archive_set_error(&a->archive, ENOMEM, "Can't allocate decompression buffer");
            return ARCHIVE_FATAL;
        }
    }

    size_t to_read = RAR5_MIN(rar->file.bytes_remaining, a->archive.read_data_requested);
    if(!read_ahead(a, to_read, &p))
        return ARCHIVE_EOF;

    ssize_t block_size;
    const struct compressed_block_header* hdr = parse_block_header(p, &block_size);
    if(!hdr) {
        LOG("*** hdr == NULL");
        return ARCHIVE_FATAL;
    }

    (void) __archive_read_consume(a, hdr->block_flags.byte_count + 3);

    if(hdr->block_flags.is_table_present) {
        int ret = parse_tables(a, rar, hdr, block_size);
        if(ret != ARCHIVE_OK) {
            LOG("parse_tables fail");
            return ret;
        }
    }

    LOG("OK");
    return ARCHIVE_FATAL;
}

static int do_unstore_file(struct archive_read* a, 
                           struct rar5* rar,
                           const void** buf,
                           size_t* size,
                           int64_t* offset) 
{
    const uint8_t* p;

    (void) __archive_read_consume(a, rar->file.prev_read_bytes);
    size_t to_read = RAR5_MIN(rar->file.bytes_remaining, a->archive.read_data_requested);

    if(!read_ahead(a, to_read, &p)) {
        LOG("I/O error during do_unstore_file");
        archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT, "I/O error when unstoring file");
        return ARCHIVE_FATAL;
    }

    *buf = p;
    *size = to_read;
    *offset = rar->file.read_offset;

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
    if(is_solid(rar)) {
        LOG("TODO: *** solid archives are not supported yet");
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

    LOG("compression method.version: %d.%d", rar->compression.method,
                                             rar->compression.version);

    switch(rar->compression.method) {
        case STORE:
            return do_unstore_file(a, rar, buf, size, offset);
        case FASTEST:
            return do_uncompress_file(a, rar, buf, size, offset);
        case FAST:
        case NORMAL:
        case GOOD:
        case BEST:
        default:
            LOG("TODO: compression method not supported yet: %d", rar->compression.method);
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

    struct rar5* rar = get_context(a);

    int ret = do_unpack(a, rar, buff, size, offset);
    if(ret != ARCHIVE_OK) {
        LOG("do_unpack returned error: %d", ret);
        return ret;
    }

    // TODO: move this if into `finish_file` or something similar
    if(rar->file.bytes_remaining == 0) {
        // Fully unpacked the file.
        //
        // Sanity check.
        if(rar->file.read_offset > rar->file.packed_size) {
            LOG("something is wrong: offset is bigger than packed size");
            LOG("read_offset=0x%08lx", rar->file.read_offset);
            LOG("packed_size=0x%08lx", rar->file.packed_size);
            return ARCHIVE_FATAL;
        }

        // Some FILE entries in RARv5 are optional entries with extra data,
        // i.e. the "QO" section. Those sections doesn't have CRC info, so we
        // can't use standard file CRC entry to verify them.
        //
        // In cases where CRC isn't used, it's simply stored as 0.
        char check_crc = rar->file.stored_crc32 > 0;

        if(check_crc && (rar->file.calculated_crc32 != rar->file.stored_crc32)) {
            LOG("checksum error: calculated=%x, valid=%x",
                    rar->file.calculated_crc32,
                    rar->file.stored_crc32);

            archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
                              "File CRC error");
            return ARCHIVE_FATAL;
        } else if(!check_crc) {
            LOG("warning: this entry doesn't have CRC info");
        } else {
            LOG("file crc ok");
        }
    }

    return ARCHIVE_OK;
}

static int rar5_read_data_skip(struct archive_read *a) {
    struct rar5* rar = get_context(a);

    (void) __archive_read_consume(a, rar->file.bytes_remaining + rar->file.prev_read_bytes);

    rar->file.prev_read_bytes = 0;
    rar->file.bytes_remaining = 0;

    return ARCHIVE_OK;
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

    if(rar->unpack_buf)
        free(rar->unpack_buf);

    free(rar);
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
