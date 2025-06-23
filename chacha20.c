#include <stdint.h>
#include <string.h>
#include <stdio.h>

/**
 * 实现了 32 位整数到 4 字节数组之间的小端序转换
 */
static inline void u32t8le(uint32_t v, uint8_t p[4]) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

/**
 * 实现了 4 字节数组 到 32 位整数之间的小端序转换
 */
static inline uint32_t u8t32le(const uint8_t p[4]) {
    uint32_t value = p[3];

    value = (value << 8) | p[2];
    value = (value << 8) | p[1];
    value = (value << 8) | p[0];

    return value;
}

/**
 * 循环移位操作
 */
static inline uint32_t rotl32(uint32_t x, int n) {
    return x << n | (x >> (-n & 31));
}

/**
 * 四分之一轮函数：通过加法和异或运算在 4 个状态变量之间传递数据，循环移位确保扩散性。
 */
static void chacha20_quarterround(uint32_t* x, int a, int b, int c, int d) {
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);
}


static void chacha20_serialize(uint32_t in[16], uint8_t output[64]) {
    int i;
    for (i = 0; i < 16; i++) {
        u32t8le(in[i], output + (i << 2));
    }
}

/**
 * 块加密函数
 */
static void chacha20_block(uint32_t in[16], uint8_t out[64], int num_rounds) {
    int i;
    uint32_t x[16];

    memcpy(x, in, sizeof(uint32_t) * 16);

    for (i = num_rounds; i > 0; i -= 2) {
        chacha20_quarterround(x, 0, 4, 8, 12);
        chacha20_quarterround(x, 1, 5, 9, 13);
        chacha20_quarterround(x, 2, 6, 10, 14);
        chacha20_quarterround(x, 3, 7, 11, 15);
        chacha20_quarterround(x, 0, 5, 10, 15);
        chacha20_quarterround(x, 1, 6, 11, 12);
        chacha20_quarterround(x, 2, 7, 8, 13);
        chacha20_quarterround(x, 3, 4, 9, 14);
    }

    for (i = 0; i < 16; i++) {
        x[i] += in[i];
    }

    chacha20_serialize(x, out);
}

/**
 * 状态初始化与块生成
 */
static void chacha20_init_state(uint32_t s[16], const uint8_t key[32], const uint32_t counter, const uint8_t nonce[12]) {
    int i;

    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;

    for (i = 0; i < 8; i++) {
        s[4 + i] = u8t32le(key + i * 4);
    }

    s[12] = counter;

    for (i = 0; i < 3; i++) {
        s[13 + i] = u8t32le(nonce + i * 4);
    }
}

/**
 * 加密 / 解密主函数
 */
void ChaCha20XOR(const uint8_t key[32], const uint32_t counter, const uint8_t nonce[12], const uint8_t* in, uint8_t* out, int inlen) {
    int i, j;

    uint32_t s[16];
    uint8_t block[64];

    chacha20_init_state(s, key, counter, nonce);

    for (i = 0; i < inlen; i += 64) {
        chacha20_block(s, block, 20);
        s[12]++;

        for (j = i; j < i + 64; j++) {
            if (j >= inlen) {
                break;
            }
            out[j] = in[j] ^ block[j - i];
        }
    }
}

// 安全检查辅助函数
int validate_params(const uint8_t* key, int key_len,
    const uint8_t* nonce, int nonce_len,
    const uint8_t* in, int in_len,
    uint8_t* out, int out_len)
{
    if (!key || key_len != 32) {
        fprintf(stderr, "Invalid key: must be 32 bytes\n");
        return 0;
    }
    if (!nonce || nonce_len != 12) {
        fprintf(stderr, "Invalid nonce: must be 12 bytes\n");
        return 0;
    }
    if (!in || !out) {
        fprintf(stderr, "Input or output buffer is NULL\n");
        return 0;
    }
    if (in_len != out_len) {
        fprintf(stderr, "Input and output lengths must match\n");
        return 0;
    }
    return 1;
}

/**
 * 加密函数
 */
void ChaCha20_encrypt(const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* nonce, size_t nonce_len,
    uint32_t counter,
    uint8_t* ciphertext, size_t ciphertext_len)
{
    if (!validate_params(key, key_len, nonce, nonce_len,
        plaintext, plaintext_len,
        ciphertext, ciphertext_len)) {
        return;
    }

    ChaCha20XOR(key, counter, nonce, plaintext, ciphertext, plaintext_len);
}

/**
 * 解密函数
 */
void ChaCha20_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* nonce, size_t nonce_len,
    uint32_t counter,
    uint8_t* plaintext, size_t plaintext_len)
{
    if (!validate_params(key, key_len, nonce, nonce_len,
        ciphertext, ciphertext_len,
        plaintext, plaintext_len)) {
        return;
    }

    ChaCha20XOR(key, counter, nonce, ciphertext, plaintext, ciphertext_len);
}