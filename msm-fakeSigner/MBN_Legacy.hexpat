#pragma endian little

struct MbnHeader {
    u32 code_word;       // 0x00
    u32 magic;           // 0x04
    u32 image_type;      // 0x08
    u8  _pad[0x08];      // 0x0C - 0x13
    u32 header_size;     // 0x14
    u32 load_addr;       // 0x18
    u32 body_size;       // 0x1C
    u32 code_size;       // 0x20
    u32 sig_addr;        // 0x24
    u32 sig_len;         // 0x28
    u32 cert_addr;       // 0x2C
    u32 cert_len;        // 0x30
};

MbnHeader mbn @ 0x00;
