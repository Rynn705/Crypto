#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MD4_DIGEST_LENGTH      16   // MD4 每个消息分块的大小（单位：字节），即 1024 位
#define MD4_BLOCK_SIZES        16   // MD4 输出摘要长度（字节）
#define MD4_HASH_SIZES         4    // MD4 内部状态寄存器个数

/**
 * 循环左移宏
 */
#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

 /**
  * MD4 的布尔函数（逻辑运算）
  */
#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

  /**
   * 轮函数
   */
#define ROUND1(a, b, c, d, k, s) ((a) = rol((a) + F((b),(c),(d)) + (k), (s)))
#define ROUND2(a, b, c, d, k, s) ((a) = rol((a) + G((b),(c),(d)) + (k) + (uint32_t)0x5A827999, (s)))
#define ROUND3(a, b, c, d, k, s) ((a) = rol((a) + H((b),(c),(d)) + (k) + (uint32_t)0x6ED9EBA1, (s)))

   /**
    * MD4 上下文结构体，仅在本文件中使用
    */
typedef struct {
    uint32_t hash[MD4_HASH_SIZES];
    uint32_t block[MD4_BLOCK_SIZES];
    uint64_t byte_count;
} MD4_CTX;

/**
 * 初始化 MD4 上下文
 */
void MD4_Init(MD4_CTX* ctx) {
    ctx->hash[0] = 0x67452301;
    ctx->hash[1] = 0xefcdab89;
    ctx->hash[2] = 0x98badcfe;
    ctx->hash[3] = 0x10325476;
    ctx->byte_count = 0;
}

/**
 * 主压缩函数：对每个数据块执行哈希运算
 */
static void MD4_Transform(uint32_t* hash, uint32_t const* in) {
    uint32_t a, b, c, d;
    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    // Round 1
    ROUND1(a, b, c, d, in[0], 3);
    ROUND1(d, a, b, c, in[1], 7);
    ROUND1(c, d, a, b, in[2], 11);
    ROUND1(b, c, d, a, in[3], 19);
    ROUND1(a, b, c, d, in[4], 3);
    ROUND1(d, a, b, c, in[5], 7);
    ROUND1(c, d, a, b, in[6], 11);
    ROUND1(b, c, d, a, in[7], 19);
    ROUND1(a, b, c, d, in[8], 3);
    ROUND1(d, a, b, c, in[9], 7);
    ROUND1(c, d, a, b, in[10], 11);
    ROUND1(b, c, d, a, in[11], 19);
    ROUND1(a, b, c, d, in[12], 3);
    ROUND1(d, a, b, c, in[13], 7);
    ROUND1(c, d, a, b, in[14], 11);
    ROUND1(b, c, d, a, in[15], 19);
    // Round 2
    ROUND2(a, b, c, d, in[0], 3);
    ROUND2(d, a, b, c, in[4], 5);
    ROUND2(c, d, a, b, in[8], 9);
    ROUND2(b, c, d, a, in[12], 13);
    ROUND2(a, b, c, d, in[1], 3);
    ROUND2(d, a, b, c, in[5], 5);
    ROUND2(c, d, a, b, in[9], 9);
    ROUND2(b, c, d, a, in[13], 13);
    ROUND2(a, b, c, d, in[2], 3);
    ROUND2(d, a, b, c, in[6], 5);
    ROUND2(c, d, a, b, in[10], 9);
    ROUND2(b, c, d, a, in[14], 13);
    ROUND2(a, b, c, d, in[3], 3);
    ROUND2(d, a, b, c, in[7], 5);
    ROUND2(c, d, a, b, in[11], 9);
    ROUND2(b, c, d, a, in[15], 13);
    // Round 3
    ROUND3(a, b, c, d, in[0], 3);
    ROUND3(d, a, b, c, in[8], 9);
    ROUND3(c, d, a, b, in[4], 11);
    ROUND3(b, c, d, a, in[12], 15);
    ROUND3(a, b, c, d, in[2], 3);
    ROUND3(d, a, b, c, in[10], 9);
    ROUND3(c, d, a, b, in[6], 11);
    ROUND3(b, c, d, a, in[14], 15);
    ROUND3(a, b, c, d, in[1], 3);
    ROUND3(d, a, b, c, in[9], 9);
    ROUND3(c, d, a, b, in[5], 11);
    ROUND3(b, c, d, a, in[13], 15);
    ROUND3(a, b, c, d, in[3], 3);
    ROUND3(d, a, b, c, in[11], 9);
    ROUND3(c, d, a, b, in[7], 11);
    ROUND3(b, c, d, a, in[15], 15);
    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
}

/**
 * 处理输入数据（可以多次调用）
 */
void MD4_Update(MD4_CTX* ctx, const void* data, unsigned long len) {
    unsigned char* byte_data = (unsigned char*)data;
    unsigned char* byte_block = (unsigned char*)ctx->block;
    // block中空余的字节数
    const uint32_t avail = sizeof(ctx->block) - (ctx->byte_count & 0x3f);
    ctx->byte_count += len;
    // data不足以装满一个block则存入后直接返回
    if (avail > len) {
        memcpy(byte_block + (sizeof(ctx->block) - avail), byte_data, len);
        return;
    }
    // 装满一个block后更新状态寄存器
    memcpy(byte_block + (sizeof(ctx->block) - avail), byte_data, avail);
    // TODO
    MD4_Transform(ctx->hash, ctx->block);
    byte_data += avail;
    len -= avail;
    while (len >= sizeof(ctx->block)) {
        memcpy(ctx->block, byte_data, sizeof(ctx->block));
        // TODO
        MD4_Transform(ctx->hash, ctx->block);
        byte_data += sizeof(ctx->block);
        len -= sizeof(ctx->block);
    }
    // 剩余的不足一个block的部分暂存在block等下次更新
    memcpy(ctx->block, byte_data, len);
}

/**
 * 结束处理函数
 */
void MD4_Final(MD4_CTX* ctx, unsigned char* hash) {
    // block中剩余的字节数
    const unsigned int offset = ctx->byte_count & 0x3f;
    char* p = (char*)ctx->block + offset;
    int padding = 56 - ((int)offset + 1);
    *p++ = (char)0x80;
    if (padding < 0) {
        memset(p, 0, padding + sizeof(uint64_t));
        // TODO
        MD4_Transform(ctx->hash, ctx->block);
        p = (char*)ctx->block;
        padding = 56;
    }
    memset(p, 0, padding);
    ctx->block[14] = ctx->byte_count << 3;
    ctx->block[15] = ctx->byte_count >> 29;
    MD4_Transform(ctx->hash, ctx->block);
    memcpy(hash, ctx->hash, sizeof(ctx->hash));
    memset(ctx, 0, sizeof(MD4_CTX));
}

/**
 * MD4 封装接口（一次性完成所有步骤）
 */
void MD4(const unsigned char* message, size_t len, unsigned char* digest, size_t digest_len) {
    MD4_CTX ctx;
    MD4_Init(&ctx);
    MD4_Update(&ctx, message, len);
    MD4_Final(&ctx, digest);
}
