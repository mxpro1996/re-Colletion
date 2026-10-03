/*
 * mbf_decryptor.c
 * GPT6-Luna templated
 * Exact C equivalent of the verified HTML/JS implementation.
 *
 * Core algorithm:
 *
 *   sub_43D004():
 *       newLo = low32(20021 * oldLo + 1)
 *       newHi = high32(20021 * oldLo)
 *             + 20021 * oldHi
 *             + 346 * oldLo
 *       return newHi & 0x7FFFFFFF
 *
 *   sub_417664():
 *       table[i] = sub_43D004() % 20, i = 0 .. 0x1FFF
 *
 *   sub_417628():
 *       key = table[keyOffset + (counter % 256)]
 *       counter++
 *
 * MBF:
 *   file[0..3]     : prefix DWORD, untouched
 *   file[4..0x17B] : encrypted 0x178-byte header
 *
 * Header / payload decryption:
 *   plaintext = ciphertext - key (mod 256)
 *
 *   The counter is reset once before the header and then is CONTINUOUSLY
 *   consumed by payload1 and payload2.
 *
 * Build:
 *   cc -O2 -std=c11 -Wall -Wextra -o mbf_decryptor mbf_decryptor.c
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define MBF_HEADER_SIZE 0x178u
#define MBF_HEADER_FILE_OFFSET 0x04u
#define KEY_TABLE_SIZE 0x2000u
#define KEY_WINDOW_SIZE 0x100u

typedef struct {
    uint32_t lo; /* state + 0x44 */
    uint32_t hi; /* state + 0x48 */
} PRNGState;

typedef struct {
    uint8_t  *data;
    size_t     size;
} Buffer;

typedef struct {
    uint32_t prefix;
    uint32_t a4;
    uint32_t key_offset;

    uint32_t payload1_start;
    uint32_t payload1_end;
    uint32_t payload1_checksum;

    uint32_t field_0xC8;
    uint32_t field_0xCC;
    uint32_t payload2_checksum;

    uint16_t magic;
    uint16_t magic2;
} MBFHeader;

/*
 * Equivalent to sub_43D004().
 *
 * Important:
 * Use uint64_t explicitly so the low/high 32-bit behavior is well-defined.
 */
static uint32_t sub_43D004(PRNGState *s)
{
    const uint32_t old_lo = s->lo;
    const uint32_t old_hi = s->hi;

    /*
     * v4 = 20021LL * old_lo
     */
    const uint64_t p = 20021ULL * (uint64_t)old_lo;

    /*
     * HIDWORD(v4) +=
     *      20021 * old_hi
     *    + 346   * old_lo
     */
    uint32_t new_hi =
        (uint32_t)(p >> 32)
        + (uint32_t)(20021ULL * (uint64_t)old_hi)
        + (uint32_t)(346ULL   * (uint64_t)old_lo);

    /*
     * v5 = v4 + 1
     *
     * Low DWORD gets +1.
     * If low DWORD overflows, carry into high DWORD.
     */
    uint32_t new_lo = (uint32_t)p;

    ++new_lo;
    if (new_lo == 0)
        ++new_hi;

    s->lo = new_lo;
    s->hi = new_hi;

    return new_hi & 0x7FFFFFFFu;
}

/*
 * Equivalent to:
 *
 *   sub_4176A0(20)
 *   {
 *       return sub_43D004() % 20;
 *   }
 */
static uint8_t sub_4176A0_20(PRNGState *s)
{
    return (uint8_t)(sub_43D004(s) % 20u);
}

/*
 * Equivalent to sub_417664().
 */
static int generate_key_table(PRNGState *state,
                              uint8_t table[KEY_TABLE_SIZE])
{
    for (uint32_t i = 0; i < KEY_TABLE_SIZE; ++i)
        table[i] = sub_4176A0_20(state);

    return 0;
}

typedef struct {
    const uint8_t *table;
    size_t table_size;
    uint32_t key_offset;
    uint32_t counter;
} KeyReader;

/*
 * Equivalent to sub_417628().
 *
 *   v1 = counter;
 *   counter++;
 *   return table[keyOffset + v1 % 256];
 */
static int key_next(KeyReader *kr, uint8_t *out_key)
{
    const uint32_t old_counter = kr->counter;
    const uint32_t index =
        kr->key_offset + (old_counter % KEY_WINDOW_SIZE);

    if (index >= kr->table_size)
        return -1;

    *out_key = kr->table[index];
    kr->counter = old_counter + 1u;
    return 0;
}

static uint16_t rd_u16_le(const uint8_t *p)
{
    return (uint16_t)p[0]
         | ((uint16_t)p[1] << 8);
}

static uint32_t rd_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static void wr_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t sum_decrypt_range(const uint8_t *src,
                                  uint8_t *dst,
                                  uint32_t start,
                                  uint32_t end,
                                  KeyReader *kr)
{
    uint32_t sum = 0;

    if (end < start)
        return UINT32_MAX;

    for (uint32_t off = start; off < end; ++off) {
        uint8_t key;

        if (key_next(kr, &key) != 0)
            return UINT32_MAX;

        dst[off] = (uint8_t)(src[off] - key);
        sum += dst[off];
    }

    return sum;
}

static void print_header_meta(const uint8_t *h)
{
    printf("Header meta:\n");
    printf("  0x000 u16 magic          = 0x%04" PRIX16 "\n", rd_u16_le(h + 0x000));
    printf("  0x004 u8                = 0x%02X\n", h[0x004]);
    printf("  0x006 u16              = 0x%04" PRIX16 "\n", rd_u16_le(h + 0x006));
    printf("  0x008 u8                = 0x%02X\n", h[0x008]);
    printf("  0x009 u8                = 0x%02X\n", h[0x009]);
    printf("  0x00A u8                = 0x%02X\n", h[0x00A]);
    printf("  0x00C u16              = 0x%04" PRIX16 "\n", rd_u16_le(h + 0x00C));
    printf("  0x00E u8                = 0x%02X\n", h[0x00E]);
    printf("  0x00F u8                = 0x%02X\n", h[0x00F]);
    printf("  0x011 u8                = 0x%02X\n", h[0x011]);

    for (unsigned off = 0x014; off <= 0x034; off += 4)
        printf("  0x%03X u32              = 0x%08" PRIX32 "\n",
               off, rd_u32_le(h + off));

    printf("  0x038 u32 count         = %" PRIu32 "\n",
           rd_u32_le(h + 0x038));

    for (unsigned off = 0x03C; off <= 0x0A8; off += 4)
        printf("  0x%03X entry            = 0x%08" PRIX32 "\n",
               off, rd_u32_le(h + off));

    for (unsigned off = 0x0AC; off <= 0x0D0; off += 4)
        printf("  0x%03X u32              = 0x%08" PRIX32 "\n",
               off, rd_u32_le(h + off));

    printf("  0x174 u16 magic2        = 0x%04" PRIX16 "\n",
           rd_u16_le(h + 0x174));
}

static int load_file(const char *path, Buffer *b)
{
    FILE *fp = fopen(path, "rb");
    long size;

    if (!fp) {
        perror(path);
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return -1;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    b->size = (size_t)size;
    b->data = (uint8_t *)malloc(b->size);

    if (!b->data) {
        fclose(fp);
        return -1;
    }

    if (b->size != 0 &&
        fread(b->data, 1, b->size, fp) != b->size) {
        free(b->data);
        b->data = NULL;
        b->size = 0;
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static int save_file(const char *path, const uint8_t *data, size_t size)
{
    FILE *fp = fopen(path, "wb");

    if (!fp) {
        perror(path);
        return -1;
    }

    if (size != 0 && fwrite(data, 1, size, fp) != size) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static void print_first_keys(const uint8_t table[KEY_TABLE_SIZE],
                             uint32_t key_offset)
{
    printf("\nFirst 32 key-table bytes at keyOffset=0x%08" PRIX32 ":\n",
           key_offset);

    for (unsigned i = 0; i < 32; ++i) {
        uint32_t idx = key_offset + i;

        if (idx >= KEY_TABLE_SIZE)
            break;

        printf("  [%02u] table[0x%03" PRIX32 "] = %u\n",
               i, idx, table[idx]);
    }
}

static int decrypt_mbf(const char *input_path,
                       const char *output_path,
                       uint32_t state_lo,
                       uint32_t state_hi,
                       uint32_t a4,
                       uint32_t expected_key_offset,
                       uint32_t payload2_multiplier)
{
    Buffer src = {0};
    uint8_t *dec = NULL;
    uint8_t table[KEY_TABLE_SIZE];

    if (load_file(input_path, &src) != 0) {
        fprintf(stderr, "failed to load input\n");
        return -1;
    }

    if (src.size < MBF_HEADER_FILE_OFFSET + MBF_HEADER_SIZE) {
        fprintf(stderr, "file too small\n");
        free(src.data);
        return -1;
    }

    const uint32_t prefix = rd_u32_le(src.data + 0);

    printf("File: %s\n", input_path);
    printf("Size: 0x%zX (%zu)\n", src.size, src.size);
    printf("Prefix DWORD: 0x%08" PRIX32 "\n", prefix);

    const uint32_t derived_key_offset = prefix + a4;
    const uint32_t key_offset =
        (expected_key_offset != UINT32_MAX)
            ? expected_key_offset
            : derived_key_offset;

    printf("a4: 0x%08" PRIX32 "\n", a4);
    printf("Derived keyOffset: 0x%08" PRIX32 "\n",
           derived_key_offset);
    printf("Using keyOffset: 0x%08" PRIX32 "\n",
           key_offset);

    if (key_offset + 255u >= KEY_TABLE_SIZE) {
        fprintf(stderr, "keyOffset outside 256-byte table window\n");
        free(src.data);
        return -1;
    }

    /*
     * Important:
     *
     * The supplied debugger sample is:
     *   36 4E 5A 01 00 00 00 00
     *
     * => LO=0x015A4E36, HI=0.
     *
     * This function intentionally does NOT force the state to 1/0.
     * Pass the verified state from the debugger.
     */
    PRNGState state = {
        .lo = state_lo,
        .hi = state_hi
    };

    if (generate_key_table(&state, table) != 0) {
        free(src.data);
        return -1;
    }

    print_first_keys(table, key_offset);

    dec = (uint8_t *)malloc(src.size);
    if (!dec) {
        free(src.data);
        return -1;
    }

    memcpy(dec, src.data, src.size);

    /*
     * sub_414C90 resets a1+9256 = 0 here.
     */
    KeyReader kr = {
        .table = table,
        .table_size = KEY_TABLE_SIZE,
        .key_offset = key_offset,
        .counter = 0
    };

    /*
     * 1) Header:
     *    file + 4 .. file + 4 + 0x178
     */
    if (sum_decrypt_range(src.data,
                          dec,
                          MBF_HEADER_FILE_OFFSET,
                          MBF_HEADER_FILE_OFFSET + MBF_HEADER_SIZE,
                          &kr) == UINT32_MAX) {
        fprintf(stderr, "header decrypt failed\n");
        free(dec);
        free(src.data);
        return -1;
    }

    const uint8_t *h = dec + MBF_HEADER_FILE_OFFSET;

    MBFHeader hdr = {
        .prefix = prefix,
        .a4 = a4,
        .key_offset = key_offset,

        .payload1_start = rd_u32_le(h + 0x0B4),
        .payload1_end = rd_u32_le(h + 0x0B8),
        .payload1_checksum = rd_u32_le(h + 0x0C4),

        .field_0xC8 = rd_u32_le(h + 0x0C8),
        .field_0xCC = rd_u32_le(h + 0x0CC),
        .payload2_checksum = rd_u32_le(h + 0x0D0),

        .magic = rd_u16_le(h + 0x000),
        .magic2 = rd_u16_le(h + 0x174)
    };

    print_header_meta(h);

    printf("\nHeader checks:\n");
    printf("  magic  = 0x%04" PRIX16 " (%s)\n",
           hdr.magic,
           hdr.magic == 0x4554 ? "OK" : "FAIL");

    printf("  magic2 = 0x%04" PRIX16 " (%s)\n",
           hdr.magic2,
           hdr.magic2 == 0x3579 ? "OK" : "FAIL");

    /*
     * 2) Payload 1.
     */
    if (hdr.payload1_end > src.size ||
        hdr.payload1_end < hdr.payload1_start) {
        fprintf(stderr, "invalid payload1 range\n");
        free(dec);
        free(src.data);
        return -1;
    }

    uint32_t sum1 =
        sum_decrypt_range(src.data,
                          dec,
                          hdr.payload1_start,
                          hdr.payload1_end,
                          &kr);

    if (sum1 == UINT32_MAX) {
        fprintf(stderr, "payload1 decrypt failed\n");
        free(dec);
        free(src.data);
        return -1;
    }

    printf("\nPayload1:\n");
    printf("  range    = 0x%08" PRIX32 " .. 0x%08" PRIX32 "\n",
           hdr.payload1_start, hdr.payload1_end);
    printf("  length   = 0x%08" PRIX32 "\n",
           hdr.payload1_end - hdr.payload1_start);
    printf("  checksum = %" PRIu32 " vs %" PRIu32 " (%s)\n",
           sum1,
           hdr.payload1_checksum,
           sum1 == hdr.payload1_checksum ? "OK" : "FAIL");

    /*
     * 3) Payload 2.
     *
     * The shown decompilation computes:
     *
     *   end = header[0xB8] + multiplier * header[0xC8]
     *
     * The a3-side multiplier is not initialized in the pasted function,
     * so this is supplied by the caller.
     */
    const uint64_t p2_end64 =
        (uint64_t)hdr.payload1_end
        + (uint64_t)payload2_multiplier * hdr.field_0xC8;

    if (p2_end64 > src.size ||
        p2_end64 > UINT32_MAX) {
        fprintf(stderr, "invalid payload2 end\n");
        free(dec);
        free(src.data);
        return -1;
    }

    const uint32_t p2_start = hdr.payload1_end;
    const uint32_t p2_end = (uint32_t)p2_end64;

    uint32_t sum2 =
        sum_decrypt_range(src.data,
                          dec,
                          p2_start,
                          p2_end,
                          &kr);

    if (sum2 == UINT32_MAX) {
        fprintf(stderr, "payload2 decrypt failed\n");
        free(dec);
        free(src.data);
        return -1;
    }

    printf("\nPayload2:\n");
    printf("  range    = 0x%08" PRIX32 " .. 0x%08" PRIX32 "\n",
           p2_start, p2_end);
    printf("  length   = 0x%08" PRIX32 "\n",
           p2_end - p2_start);
    printf("  multiplier = %" PRIu32 "\n", payload2_multiplier);
    printf("  header[0xC8] = %" PRIu32 "\n", hdr.field_0xC8);
    printf("  checksum = %" PRIu32 " vs %" PRIu32 " (%s)\n",
           sum2,
           hdr.payload2_checksum,
           sum2 == hdr.payload2_checksum ? "OK" : "FAIL");

    printf("\nCounter:\n");
    printf("  after header   = 0x%08" PRIX32 "\n", 0x178u);
    printf("  after payload1 = 0x%08" PRIX32 "\n",
           0x178u + (hdr.payload1_end - hdr.payload1_start));
    printf("  after payload2 = 0x%08" PRIX32 "\n", kr.counter);

    if (save_file(output_path, dec, src.size) != 0) {
        fprintf(stderr, "failed to save output\n");
        free(dec);
        free(src.data);
        return -1;
    }

    printf("\nDecrypted output: %s\n", output_path);

    free(dec);
    free(src.data);
    return 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s input.mbf output.mbf [state_lo] [state_hi] [a4] [multiplier]\n"
        "\n"
        "Example for the verified sample:\n"
        "  %s 040720_RA1.PAC_C042_CN0M0802_LPCL1201mf.mbf out.mbf \\\n"
        "      0x015A4E36 0x00000000 0x345 1\n"
        "\n"
        "The keyOffset is derived as prefix + a4.\n"
        "For the sample:\n"
        "  prefix = 0x4D5\n"
        "  a4     = 0x345 / 0x777\n"
        "  keyOff = 0x81A\n",
        argv0, argv0);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    uint32_t state_lo = 0x015A4E36u;
    uint32_t state_hi = 0x00000000u;
    uint32_t a4 = 0x00000345u;  // fixed for V1.0
    uint32_t multiplier = 4096u; // chunk2-4K unit

    if (argc >= 4)
        state_lo = (uint32_t)strtoul(argv[3], NULL, 0);

    if (argc >= 5)
        state_hi = (uint32_t)strtoul(argv[4], NULL, 0);

    if (argc >= 6)
        a4 = (uint32_t)strtoul(argv[5], NULL, 0);

    if (argc >= 7)
        multiplier = (uint32_t)strtoul(argv[6], NULL, 0);

    /*
     * UINT32_MAX means "derive from prefix + a4".
     */
    return decrypt_mbf(
        argv[1],
        argv[2],
        state_lo,
        state_hi,
        a4,
        UINT32_MAX,
        multiplier
    ) == 0 ? 0 : 1;
}
