﻿#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/**
 * 类型重定义，提高代码可读性
 */
typedef unsigned short u16;
typedef unsigned int  u32;

/**
 * 16位无符号整数循环左、右移宏定义
 */
#define rotl16(x,n)   (((x) << ((u16)(n))) | ((x) >> (16 - (u16)(n))))
#define rotr16(x,n)   (((x) >> ((u16)(n))) | ((x) << (16 - (u16)(n))))

/**
 * 定义RFC 2268标准中规定的块大小为8字节
 */
#define RFC2268_BLOCKSIZE 8

/**
 * RC2算法上下文结构体，包含64个16位S盒元素
 */
typedef struct
{
    unsigned short S[64];
} RFC2268_context;

/**
 * RC2算法使用的S盒数据，用于混淆操作
 */
static const unsigned char rfc2268_sbox[] = {
  217, 120, 249, 196,  25, 221, 181, 237,
   40, 233, 253, 121,  74, 160, 216, 157,
  198, 126,  55, 131,  43, 118,  83, 142,
   98,  76, 100, 136,  68, 139, 251, 162,
   23, 154,  89, 245, 135, 179,  79,  19,
   97,  69, 109, 141,   9, 129, 125,  50,
  189, 143,  64, 235, 134, 183, 123,  11,
  240, 149,  33,  34,  92, 107,  78, 130,
   84, 214, 101, 147, 206,  96, 178,  28,
  115,  86, 192,  20, 167, 140, 241, 220,
   18, 117, 202,  31,  59, 190, 228, 209,
   66,  61, 212,  48, 163,  60, 182,  38,
  111, 191,  14, 218,  70, 105,   7,  87,
   39, 242,  29, 155, 188, 148,  67,   3,
  248,  17, 199, 246, 144, 239,  62, 231,
    6, 195, 213,  47, 200, 102,  30, 215,
    8, 232, 234, 222, 128,  82, 238, 247,
  132, 170, 114, 172,  53,  77, 106,  42,
  150,  26, 210, 113,  90,  21,  73, 116,
   75, 159, 208,  94,   4,  24, 164, 236,
  194, 224,  65, 110,  15,  81, 203, 204,
   36, 145, 175,  80, 161, 244, 112,  57,
  153, 124,  58, 133,  35, 184, 180, 122,
  252,   2,  54,  91,  37,  85, 151,  49,
   45,  93, 250, 152, 227, 138, 146, 174,
    5, 223,  41,  16, 103, 108, 186, 201,
  211,   0, 230, 207, 225, 158, 168,  44,
   99,  22,   1,  63,  88, 226, 137, 169,
   13,  56,  52,  27, 171,  51, 255, 176,
  187,  72,  12,  95, 185, 177, 205,  46,
  197, 243, 219,  71, 229, 165, 156, 119,
   10, 166,  32, 104, 254, 127, 193, 173
};

/**
 * RC2加密核心函数
 */
void do_encrypt(void* context, unsigned char* outbuf, const unsigned char* inbuf)
{
    RFC2268_context* ctx = context;
    register int i, j;
    u16 word0 = 0, word1 = 0, word2 = 0, word3 = 0;

    word0 = (word0 << 8) | inbuf[1];
    word0 = (word0 << 8) | inbuf[0];
    word1 = (word1 << 8) | inbuf[3];
    word1 = (word1 << 8) | inbuf[2];
    word2 = (word2 << 8) | inbuf[5];
    word2 = (word2 << 8) | inbuf[4];
    word3 = (word3 << 8) | inbuf[7];
    word3 = (word3 << 8) | inbuf[6];

    for (i = 0; i < 16; i++)
    {
        j = i * 4;
        /* For some reason I cannot combine those steps. */
        word0 += (word1 & ~word3) + (word2 & word3) + ctx->S[j];
        word0 = rotl16(word0, 1);

        word1 += (word2 & ~word0) + (word3 & word0) + ctx->S[j + 1];
        word1 = rotl16(word1, 2);

        word2 += (word3 & ~word1) + (word0 & word1) + ctx->S[j + 2];
        word2 = rotl16(word2, 3);

        word3 += (word0 & ~word2) + (word1 & word2) + ctx->S[j + 3];
        word3 = rotl16(word3, 5);

        if (i == 4 || i == 10)
        {
            word0 += ctx->S[word3 & 63];
            word1 += ctx->S[word0 & 63];
            word2 += ctx->S[word1 & 63];
            word3 += ctx->S[word2 & 63];
        }

    }

    outbuf[0] = word0 & 255;
    outbuf[1] = word0 >> 8;
    outbuf[2] = word1 & 255;
    outbuf[3] = word1 >> 8;
    outbuf[4] = word2 & 255;
    outbuf[5] = word2 >> 8;
    outbuf[6] = word3 & 255;
    outbuf[7] = word3 >> 8;
}

/**
 * RC2解密核心函数
 */
void do_decrypt(void* context, unsigned char* outbuf, const unsigned char* inbuf)
{
    RFC2268_context* ctx = context;
    register int i, j;
    u16 word0 = 0, word1 = 0, word2 = 0, word3 = 0;

    word0 = (word0 << 8) | inbuf[1];
    word0 = (word0 << 8) | inbuf[0];
    word1 = (word1 << 8) | inbuf[3];
    word1 = (word1 << 8) | inbuf[2];
    word2 = (word2 << 8) | inbuf[5];
    word2 = (word2 << 8) | inbuf[4];
    word3 = (word3 << 8) | inbuf[7];
    word3 = (word3 << 8) | inbuf[6];

    for (i = 15; i >= 0; i--)
    {
        j = i * 4;

        word3 = rotr16(word3, 5);
        word3 -= (word0 & ~word2) + (word1 & word2) + ctx->S[j + 3];

        word2 = rotr16(word2, 3);
        word2 -= (word3 & ~word1) + (word0 & word1) + ctx->S[j + 2];

        word1 = rotr16(word1, 2);
        word1 -= (word2 & ~word0) + (word3 & word0) + ctx->S[j + 1];

        word0 = rotr16(word0, 1);
        word0 -= (word1 & ~word3) + (word2 & word3) + ctx->S[j];

        if (i == 5 || i == 11)
        {
            word3 = word3 - ctx->S[word2 & 63];
            word2 = word2 - ctx->S[word1 & 63];
            word1 = word1 - ctx->S[word0 & 63];
            word0 = word0 - ctx->S[word3 & 63];
        }

    }

    outbuf[0] = word0 & 255;
    outbuf[1] = word0 >> 8;
    outbuf[2] = word1 & 255;
    outbuf[3] = word1 >> 8;
    outbuf[4] = word2 & 255;
    outbuf[5] = word2 >> 8;
    outbuf[6] = word3 & 255;
    outbuf[7] = word3 >> 8;
}

/**
 * RC2密钥设置核心函数
 */
int setkey_core(void* context, const unsigned char* key, unsigned int keylen, int with_phase2)
{
    static int initialized;
    static const char* selftest_failed;
    RFC2268_context* ctx = context;
    unsigned int i;
    unsigned char* S, x;
    int len;
    int bits = keylen * 8;

    if (keylen < 40 / 8)
    {
        /* We want at least 40 bits. */
        printf("aaa");
        return -1;
    }

    if (keylen > 128)
    {
        printf("bbb");
        return -1;
    }

    S = (unsigned char*)ctx->S;

    for (i = 0; i < keylen; i++)
        S[i] = key[i];

    for (i = keylen; i < 128; i++)
        S[i] = rfc2268_sbox[(S[i - keylen] + S[i - 1]) & 255];

    S[0] = rfc2268_sbox[S[0]];

    /* Phase 2 - reduce effective key size to "bits". This was not
     * discussed in Gutmann's paper. I've copied that from the public
     * domain code posted in sci.crypt. */
    if (with_phase2)
    {
        len = (bits + 7) >> 3;
        i = 128 - len;
        x = rfc2268_sbox[S[i] & (255 >> (7 & -bits))];
        S[i] = x;

        while (i--)
        {
            x = rfc2268_sbox[x ^ S[i + len]];
            S[i] = x;
        }
    }

    /* Make the expanded key, endian independent. */
    for (i = 0; i < 64; i++)
        ctx->S[i] = ((u16)S[i * 2] | (((u16)S[i * 2 + 1]) << 8));

    return 0;
}

/**
 * 加密函数
 */
void RC2_encrypt(const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    uint8_t* ciphertext, size_t ciphertext_len)
{
    RFC2268_context ctx;
    setkey_core(&ctx, key, key_len, 0);
    do_encrypt(&ctx, ciphertext, plaintext);
}

/**
 * 解密函数
 */
void RC2_decrypt(const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    uint8_t* ciphertext, size_t ciphertext_len)
{
    RFC2268_context ctx;
    setkey_core(&ctx, key, key_len, 0);
    do_decrypt(&ctx, ciphertext, plaintext);
}
