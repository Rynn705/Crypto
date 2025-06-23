#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * 类型别名定义，提高代码可读性
 */
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint64_t u64;
typedef int64_t s64;

/**
 * 无符号整数常量定义
 */
#define U8C(v) (v##U)
#define U16C(v) (v##U)
#define U32C(v) (v##U)
#define U64C(v) (v##U)

/**
 * 大小端转换宏定义
 */
#define U16TO16_LITTLE(v) (v)
#define U32TO32_LITTLE(v) (v)
#define U64TO64_LITTLE(v) (v)

#define U16TO16_BIG(v) SWAP16(v)
#define U32TO32_BIG(v) SWAP32(v)
#define U64TO64_BIG(v) SWAP64(v)

/**
 * 字节到整数的转换宏
 */
#define U8TO16_LITTLE(p) U16TO16_LITTLE(((u16*)(p))[0])
#define U8TO32_LITTLE(p) U32TO32_LITTLE(((u32*)(p))[0])
#define U8TO64_LITTLE(p) U64TO64_LITTLE(((u64*)(p))[0])

#define U8TO16_BIG(p) U16TO16_BIG(((u16*)(p))[0])
#define U8TO32_BIG(p) U32TO32_BIG(((u32*)(p))[0])
#define U8TO64_BIG(p) U64TO64_BIG(((u64*)(p))[0])

/**
 * 整数到字节的转换宏
 */
#define U16TO8_LITTLE(p, v) (((u16*)(p))[0] = U16TO16_LITTLE(v))
#define U32TO8_LITTLE(p, v) (((u32*)(p))[0] = U32TO32_LITTLE(v))
#define U64TO8_LITTLE(p, v) (((u64*)(p))[0] = U64TO64_LITTLE(v))

#define U16TO8_BIG(p, v) (((u16*)(p))[0] = U16TO16_BIG(v))
#define U32TO8_BIG(p, v) (((u32*)(p))[0] = U32TO32_BIG(v))
#define U64TO8_BIG(p, v) (((u64*)(p))[0] = U64TO64_BIG(v))

/**
 * 加密算法的最大密钥和IV大小定义
 */
#define ECRYPT_MAXKEYSIZE 2048
#define ECRYPT_KEYSIZE(i) (128 + (i)*128)

#define ECRYPT_MAXIVSIZE 2048
#define ECRYPT_IVSIZE(i) (128 + (i)*128)

/**
 * 加密块长度定义
 */
#define ECRYPT_BLOCKLENGTH (624 * 2)

/**
 * 加密上下文结构，存储加密过程中的状态信息
 */
typedef struct {
    u32 sfmt[156 + 2 + ((ECRYPT_MAXKEYSIZE + ECRYPT_MAXIVSIZE) * 3) / 128][4];
    u32 accum[4];
    u32 lung[4];
    u32* psfmt;
    u32 length;
    u32 key[ECRYPT_MAXKEYSIZE / 32];
    s32 keysize;
    s32 ivsize;
    s32 first;
} ECRYPT_ctx;

/**
 * SFMT算法参数
 */
#define N 156
#define POS1 108
#define SHIFT64 3
#define SR1 1
#define MSK1 U32C(0xffdfafdf)
#define MSK2 U32C(0xf5dabfff)
#define MSK3 U32C(0xffdbffff)
#define MSK4 U32C(0xef7bffff)
#define INIL U32C(0x4d734e48)

/**
 * SFMT状态结构
 */
struct SFMT_T {
    u32 sfmt[N][4];
};
typedef struct SFMT_T sfmt_t;

/**
 * 函数原型声明
 */
static int is_simd_cpu(void);
static inline void do_recursion(u32 a[4], const u32 b[4], const u32 c[4]);
static void genrand_bytes_first(ECRYPT_ctx* ctx, u8 cipher[], const u8 plain[],
    u32 len);
static void fast_genrand_bytes_first(ECRYPT_ctx* ctx, u8 cipher[],
    const u8 plain[], u32 len);
static void genrand_bytes(ECRYPT_ctx* ctx, u8 cipher[], const u8 plain[],
    u32 len);
static inline void fast_genrand_bytes(ECRYPT_ctx* ctx, u8 cipher[],
    const u8 plain[], u32 len);
static void genrand_block_first(ECRYPT_ctx* ctx, u8 cipher[],
    const u8 plain[]);
static void fast_genrand_block_first(ECRYPT_ctx* ctx, u8 cipher[],
    const u8 plain[]);
static inline void genrand_block(ECRYPT_ctx* ctx, u8 cipher[],
    const u8 plain[]);
static inline void fast_genrand_block(ECRYPT_ctx* ctx, u8 cipher[],
    const u8 plain[]);
static inline void boot_up(ECRYPT_ctx* ctx, s32 length);
static inline void fast_boot_up(ECRYPT_ctx* ctx, s32 length);
static void filter_16bytes(u32 sfmt[], u32 accum[4], u8 cipher[],
    const u8 plain[], s32 count);
static inline void filter_bytes(u32 sfmt[], u32 accum[4], u8 cipher[],
    const u8 plain[], s32 len);
static inline void booter_am(u32 acc[4], u32 pos1[][4], u32 pos2[][4],
    s32 count);

/**
 * 快速代码标志和CPU检测函数
 */
static int fast_code = 0;
static int is_simd_cpu(void) {
    return 0;
}

/**
 * 快速实现函数
 */
static void fast_genrand_bytes_first(ECRYPT_ctx* ctx, u8 cipher[],
    const u8 plain[], u32 len) {
    fprintf(stderr, "ERROR:fast_genrand_bytes_first not implemented\n");
    exit(1);
}

static inline void fast_genrand_bytes(ECRYPT_ctx* ctx, u8 cipher[],
    const u8 plain[], u32 len) {
    fprintf(stderr, "ERROR:fast_genrand_bytes not implemented\n");
    exit(1);
}

static void fast_genrand_block_first(ECRYPT_ctx* ctx, u8 cipher[],
    const u8 plain[]) {
    fprintf(stderr, "ERROR:fast_genrand_block_first not implemented\n");
    exit(1);
}

static inline void fast_genrand_block(ECRYPT_ctx* ctx, u8 cipher[],
    const u8 plain[]) {
    fprintf(stderr, "ERROR:fast_genrand_block not implemented\n");
    exit(1);
}

static inline void fast_boot_up(ECRYPT_ctx* ctx, s32 length) {
    fprintf(stderr, "ERROR:fast_boot_up not implemented\n");
    exit(1);
}


/**
 * 实现函数
 */
static void genrand_bytes_first(ECRYPT_ctx* ctx, u8 cipher[], const u8 plain[],
    u32 len)
{
    s32 i, p, count;
    sfmt_t* sp;

    count = (len + 7) / 8;
    sp = (sfmt_t*)ctx->psfmt;
    p = ctx->length - 2;
    booter_am(ctx->lung, &sp->sfmt[0], &sp->sfmt[p], count);
    filter_16bytes(sp->sfmt[0], ctx->accum, cipher, plain, len / 16);
    i = (len / 16) * 2;
    len = len % 16;
    if (len != 0) {
        filter_bytes(sp->sfmt[i], ctx->accum, &cipher[i * 8],
            &plain[i * 8], len);
    }
}

/**
 * SFMT算法的核心递归函数，生成下一组随机数
 */
static inline void do_recursion(u32 a[4], const u32 b[4], const u32 c[4]) {
    u64 t;
    u32 bb[4];
    u32 tmp;

    t = ((u64)b[1] << 32) | ((u64)b[0]);
    t = t >> SHIFT64;
    bb[0] = (u32)t;
    bb[1] = (u32)(t >> 32);
    t = ((u64)b[3] << 32) | ((u64)b[2]);
    t = t >> SHIFT64;
    bb[2] = (u32)t;
    bb[3] = (u32)(t >> 32);
    tmp = a[0];
    a[0] = a[1] ^ b[1] ^ bb[0] ^ (c[0] & MSK1);
    a[1] = a[2] ^ b[3] ^ bb[1] ^ (c[1] & MSK2);
    a[2] = a[3] ^ b[0] ^ bb[2] ^ (c[2] & MSK3);
    a[3] = tmp ^ b[2] ^ bb[3] ^ (c[3] & MSK4);
}

/**
 * 生成随机字节的函数
 */
static void genrand_bytes(ECRYPT_ctx* ctx, u8 cipher[], const u8 plain[],
    u32 len)
{
    u32* accum;
    sfmt_t* ps;
    int i;
    s32 count;
    accum = ctx->accum;
    ps = (sfmt_t*)ctx->psfmt;
    count = (len + 7) / 8;

    do_recursion(ps->sfmt[0], ps->sfmt[POS1], ps->sfmt[N - 1]);
    count--;
    for (i = 1; (count > 0) && (i < N - POS1); i++, count--) {
        do_recursion(ps->sfmt[i], ps->sfmt[i + POS1], ps->sfmt[i - 1]);
    }
    for (; (count > 0) && (i < N); i++, count--) {
        do_recursion(ps->sfmt[i], ps->sfmt[i + POS1 - N], ps->sfmt[i - 1]);
    }

    filter_16bytes(ps->sfmt[0], ctx->accum, cipher, plain, len / 16);
    i = (len / 16) * 2;
    len = len % 16;
    if (len != 0) {
        filter_bytes(ps->sfmt[i], ctx->accum, &cipher[i * 8],
            &plain[i * 8], len);
    }
}

/**
 * 首次生成随机块的函数
 */
static void genrand_block_first(ECRYPT_ctx* ctx, u8 cipher[], const u8 plain[])
{
    s32 p;
    sfmt_t* ps;
    int i;

    ps = (sfmt_t*)ctx->psfmt;
    p = ctx->length - 2;
    booter_am(ctx->lung, &ps->sfmt[0], &ps->sfmt[p], N);
    filter_16bytes(ps->sfmt[0], ctx->accum, cipher, plain, N / 2);
    ps->sfmt[0][3] = INIL;
    for (i = 0; i < 4; i++) {
        ps->sfmt[N - 1][i] = ps->sfmt[0][i];
    }
    do_recursion(ps->sfmt[N - 1], ps->sfmt[POS1], ps->sfmt[N - 1]);
    ctx->psfmt = ps->sfmt[1];
}

/**
 * 处理16字节块的函数，将随机数与明文异或生成密文
 */
static void filter_16bytes(u32 sfmt[], u32 accum[4], u8 cipher[],
    const u8 plain[], s32 count) {
    u32 t1, t2, t3, t4;
    u32 ac1, ac2, ac3, ac4;
    int i;

    ac1 = accum[0];
    ac2 = accum[1];
    ac3 = accum[2];
    ac4 = accum[3];

    for (i = 0; i < count; i++) {
        t1 = ac1;
        ac1 = ac1 ^ (ac2 >> 1);
        ac2 = ac2 ^ (ac3 >> 1);
        ac3 = ac3 ^ (ac4 >> 1);
        ac4 = ac4 ^ (t1 >> 1);
        ac1 = (2 * ac1 + 1) * sfmt[0] + ac1;
        ac2 = (2 * ac2 + 1) * sfmt[1] + ac2;
        ac3 = (2 * ac3 + 1) * sfmt[2] + ac3;
        ac4 = (2 * ac4 + 1) * sfmt[3] + ac4;
        t1 = (ac1 >> 16) ^ ac1;
        t2 = (ac2 >> 16) ^ ac2;
        t3 = (ac3 >> 16) ^ ac3;
        t4 = (ac4 >> 16) ^ ac4;
        cipher[0] = (u8)(plain[0] ^ (u8)(t1));
        cipher[1] = (u8)(plain[1] ^ (u8)(t1 >> 8));
        cipher[4] = (u8)(plain[4] ^ (u8)(t2));
        cipher[5] = (u8)(plain[5] ^ (u8)(t2 >> 8));
        cipher[8] = (u8)(plain[8] ^ (u8)(t3));
        cipher[9] = (u8)(plain[9] ^ (u8)(t3 >> 8));
        cipher[12] = (u8)(plain[12] ^ (u8)(t4));
        cipher[13] = (u8)(plain[13] ^ (u8)(t4 >> 8));

        t1 = ac1;
        ac1 = ac1 ^ (ac2 >> 1);
        ac2 = ac2 ^ (ac3 >> 1);
        ac3 = ac3 ^ (ac4 >> 1);
        ac4 = ac4 ^ (t1 >> 1);
        ac1 = (2 * ac1 + 1) * sfmt[4] + ac1;
        ac2 = (2 * ac2 + 1) * sfmt[5] + ac2;
        ac3 = (2 * ac3 + 1) * sfmt[6] + ac3;
        ac4 = (2 * ac4 + 1) * sfmt[7] + ac4;
        t1 = (ac1 >> 16) ^ ac1;
        t2 = (ac2 >> 16) ^ ac2;
        t3 = (ac3 >> 16) ^ ac3;
        t4 = (ac4 >> 16) ^ ac4;
        cipher[2] = (u8)(plain[2] ^ (u8)(t1));
        cipher[3] = (u8)(plain[3] ^ (u8)(t1 >> 8));
        cipher[6] = (u8)(plain[6] ^ (u8)(t2));
        cipher[7] = (u8)(plain[7] ^ (u8)(t2 >> 8));
        cipher[10] = (u8)(plain[10] ^ (u8)(t3));
        cipher[11] = (u8)(plain[11] ^ (u8)(t3 >> 8));
        cipher[14] = (u8)(plain[14] ^ (u8)(t4));
        cipher[15] = (u8)(plain[15] ^ (u8)(t4 >> 8));
        sfmt += 8;
        cipher += 16;
        plain += 16;
    }
    accum[0] = ac1;
    accum[1] = ac2;
    accum[2] = ac3;
    accum[3] = ac4;
}

/**
 * 处理任意长度字节的函数
 */
static inline void filter_bytes(u32 sfmt[], u32 accum[4], u8 cipher[],
    const u8 plain[], s32 len) {
    u32 t1, t2, t3, t4, t5, t6, t7, t8;

    t1 = accum[0];
    accum[0] = accum[0] ^ (accum[1] >> 1);
    accum[1] = accum[1] ^ (accum[2] >> 1);
    accum[2] = accum[2] ^ (accum[3] >> 1);
    accum[3] = accum[3] ^ (t1 >> 1);
    accum[0] = (2 * accum[0] + 1) * sfmt[0] + accum[0];
    accum[1] = (2 * accum[1] + 1) * sfmt[1] + accum[1];
    accum[2] = (2 * accum[2] + 1) * sfmt[2] + accum[2];
    accum[3] = (2 * accum[3] + 1) * sfmt[3] + accum[3];
    t1 = (accum[0] >> 16) ^ accum[0];
    t2 = (accum[1] >> 16) ^ accum[1];
    t3 = (accum[2] >> 16) ^ accum[2];
    t4 = (accum[3] >> 16) ^ accum[3];

    t5 = accum[0];
    accum[0] = accum[0] ^ (accum[1] >> 1);
    accum[1] = accum[1] ^ (accum[2] >> 1);
    accum[2] = accum[2] ^ (accum[3] >> 1);
    accum[3] = accum[3] ^ (t5 >> 1);
    accum[0] = (2 * accum[0] + 1) * sfmt[4] + accum[0];
    accum[1] = (2 * accum[1] + 1) * sfmt[5] + accum[1];
    accum[2] = (2 * accum[2] + 1) * sfmt[6] + accum[2];
    accum[3] = (2 * accum[3] + 1) * sfmt[7] + accum[3];
    t5 = (accum[0] >> 16) ^ accum[0];
    t6 = (accum[1] >> 16) ^ accum[1];
    t7 = (accum[2] >> 16) ^ accum[2];
    t8 = (accum[3] >> 16) ^ accum[3];

    cipher[0] = (u8)(plain[0] ^ (u8)(t1));
    if (--len == 0) return;
    cipher[1] = (u8)(plain[1] ^ (u8)(t1 >> 8));
    if (--len == 0) return;
    cipher[2] = (u8)(plain[2] ^ (u8)(t5));
    if (--len == 0) return;
    cipher[3] = (u8)(plain[3] ^ (u8)(t5 >> 8));
    if (--len == 0) return;
    cipher[4] = (u8)(plain[4] ^ (u8)(t2));
    if (--len == 0) return;
    cipher[5] = (u8)(plain[5] ^ (u8)(t2 >> 8));
    if (--len == 0) return;
    cipher[6] = (u8)(plain[6] ^ (u8)(t6));
    if (--len == 0) return;
    cipher[7] = (u8)(plain[7] ^ (u8)(t6 >> 8));
    if (--len == 0) return;
    cipher[8] = (u8)(plain[8] ^ (u8)(t3));
    if (--len == 0) return;
    cipher[9] = (u8)(plain[9] ^ (u8)(t3 >> 8));
    if (--len == 0) return;
    cipher[10] = (u8)(plain[10] ^ (u8)(t7));
    if (--len == 0) return;
    cipher[11] = (u8)(plain[11] ^ (u8)(t7 >> 8));
    if (--len == 0) return;
    cipher[12] = (u8)(plain[12] ^ (u8)(t4));
    if (--len == 0) return;
    cipher[13] = (u8)(plain[13] ^ (u8)(t4 >> 8));
    if (--len == 0) return;
    cipher[14] = (u8)(plain[14] ^ (u8)(t8));
    if (--len == 0) return;
    cipher[15] = (u8)(plain[15] ^ (u8)(t8 >> 8));
}

/**
 * 生成随机块的函数
 */
static inline void genrand_block(ECRYPT_ctx* ctx, u8 cipher[],
    const u8 plain[])
{
    int i;
    sfmt_t* ps;

    ps = (sfmt_t*)ctx->psfmt;
    do_recursion(ps->sfmt[0], ps->sfmt[POS1], ps->sfmt[N - 1]);
    for (i = 1; i < N - POS1; i++) {
        do_recursion(ps->sfmt[i], ps->sfmt[i + POS1], ps->sfmt[i - 1]);
    }
    for (; i < N; i++) {
        do_recursion(ps->sfmt[i], ps->sfmt[i + POS1 - N], ps->sfmt[i - 1]);
    }
    filter_16bytes(ps->sfmt[0], ctx->accum, cipher, plain, N / 2);
}

/**
 * SFMT算法结束
 * 启动函数，初始化SFMT状态
 */
static inline void booter_am(u32 acc[4], u32 pos1[][4], u32 pos2[][4],
    s32 count)
{
    u32 a[4], b[4];
    u32 tmp;
    int i, j;

    for (i = 0; i < count; i++) {
        for (j = 0; j < 4; j++) {
            pos1[i][j] = a[j] = pos1[i][j] + pos2[i][j];
        }
        tmp = a[0];
        a[0] = a[3] ^ (a[0] >> 13);
        a[3] = a[2] ^ (a[3] >> 13);
        a[2] = a[1] ^ (a[2] >> 13);
        a[1] = tmp ^ (a[1] >> 13);
        b[0] = pos2[i + 1][3] ^ (pos2[i + 1][0] >> 11);
        b[1] = pos2[i + 1][2] ^ (pos2[i + 1][1] >> 11);
        b[2] = pos2[i + 1][0] ^ (pos2[i + 1][2] >> 11);
        b[3] = pos2[i + 1][1] ^ (pos2[i + 1][3] >> 11);
        for (j = 0; j < 4; j++) {
            acc[j] = (2 * b[j] + 1) * acc[j] + b[j];
            pos2[i + 2][j] = a[j] - acc[j];
        }
    }
}

/**
 * 初始化加密上下文
 */
static void boot_up(ECRYPT_ctx* ctx, s32 length)
{
    s32 i, p;

    ctx->psfmt = ctx->sfmt[length + 2];
    p = ctx->ivsize / 4;
    for (i = 0; i < 4; i++) {
        ctx->lung[i] = ctx->sfmt[p * 4][i] | 1;
    }
    p = length - 2;
    booter_am(ctx->lung, &ctx->sfmt[0], &ctx->sfmt[p], length + 2);
    for (i = 0; i < 4; i++) {
        ctx->accum[i] = ctx->sfmt[2 * length + 1][i];
    }
}

/**
 * 加密API函数
 */
void ECRYPT_init(void)
{
    if (fast_code) {
        fast_code = is_simd_cpu();
    }
}

/**
 * 设置加密密钥
 */
void ECRYPT_keysetup(ECRYPT_ctx* ctx, const u8* key, u32 keysize,
    u32 ivsize)
{
    s32 i;

    memset(ctx, 0, sizeof(ctx));
    ctx->keysize = keysize / 128;
    ctx->ivsize = ivsize / 128;
    for (i = 0; i < keysize / 32; i++) {
        ctx->key[i] = U8TO32_LITTLE(key);
        key += 4;
    }
}

/**
 * 设置初始化向量
 */
void ECRYPT_ivsetup(ECRYPT_ctx* ctx, const u8* iv)
{
    s32 p, ivsize, keysize, i, j;
    u32 block_size;

    ivsize = ctx->ivsize;
    keysize = ctx->keysize;
    block_size = ivsize + keysize;
    for (i = 0; i < ivsize; i++) {
        for (j = 0; j < 4; j++) {
            ctx->sfmt[i][j] = U8TO32_LITTLE(iv);
            iv += 4;
        }
    }
    memcpy(ctx->sfmt[ivsize], ctx->key, keysize * 16);
    memcpy(ctx->sfmt[block_size], ctx->sfmt, block_size * 16);
    p = 2 * block_size - 1;
    ctx->sfmt[p][0] += 314159UL;
    ctx->sfmt[p][1] += 265358UL;
    ctx->sfmt[p][2] += 979323UL;
    ctx->sfmt[p][3] += 846264UL;
    ctx->length = block_size * 2;
    if (fast_code) {
        fast_boot_up(ctx, ctx->length);
    }
    else {
        boot_up(ctx, ctx->length);
    }
    ctx->first = 1;
}

/**
 * 按字节加密函数
 */
void ECRYPT_encrypt_bytes(ECRYPT_ctx* ctx,
    const u8* plaintext,
    u8* ciphertext, u32 msglen)
{
    if (fast_code) {
        if (ctx->first && (msglen > 0)) {
            if (msglen >= ECRYPT_BLOCKLENGTH) {
                fast_genrand_block_first(ctx, ciphertext, plaintext);
                ciphertext += ECRYPT_BLOCKLENGTH;
                plaintext += ECRYPT_BLOCKLENGTH;
                msglen -= ECRYPT_BLOCKLENGTH;
                ctx->first = 0;
            }
            else {
                fast_genrand_bytes_first(ctx, ciphertext, plaintext, msglen);
                return;
            }
        }
        while (msglen >= ECRYPT_BLOCKLENGTH) {
            fast_genrand_block(ctx, ciphertext, plaintext);
            ciphertext += ECRYPT_BLOCKLENGTH;
            plaintext += ECRYPT_BLOCKLENGTH;
            msglen -= ECRYPT_BLOCKLENGTH;
        }
        if (msglen != 0) {
            fast_genrand_bytes(ctx, ciphertext, plaintext, msglen);
        }
    }
    else {
        if (ctx->first && (msglen > 0)) {
            if (msglen >= ECRYPT_BLOCKLENGTH) {
                genrand_block_first(ctx, ciphertext, plaintext);
                ciphertext += ECRYPT_BLOCKLENGTH;
                plaintext += ECRYPT_BLOCKLENGTH;
                msglen -= ECRYPT_BLOCKLENGTH;
                ctx->first = 0;
            }
            else {
                genrand_bytes_first(ctx, ciphertext, plaintext, msglen);
                return;
            }
        }
        while (msglen >= ECRYPT_BLOCKLENGTH) {
            genrand_block(ctx, ciphertext, plaintext);
            ciphertext += ECRYPT_BLOCKLENGTH;
            plaintext += ECRYPT_BLOCKLENGTH;
            msglen -= ECRYPT_BLOCKLENGTH;
        }
        if (msglen != 0) {
            genrand_bytes(ctx, ciphertext, plaintext, msglen);
        }
    }
}

/**
 * 按字节解密函数（与加密相同，因为是异或操作）
 */
void ECRYPT_decrypt_bytes(ECRYPT_ctx* ctx,
    const u8* ciphertext,
    u8* plaintext, u32 msglen)
{
    ECRYPT_encrypt_bytes(ctx, ciphertext, plaintext, msglen);
}

/**
 * 按块加密函数
 */
void ECRYPT_encrypt_blocks(ECRYPT_ctx* ctx,
    const u8* plaintext,
    u8* ciphertext, u32 blocks)
{
    s32 i;

    if (fast_code) {
        if (ctx->first && (blocks > 0)) {
            fast_genrand_block_first(ctx, ciphertext, plaintext);
            ciphertext += ECRYPT_BLOCKLENGTH;
            plaintext += ECRYPT_BLOCKLENGTH;
            blocks--;
            ctx->first = 0;
        }
        for (i = 0; i < blocks; i++) {
            fast_genrand_block(ctx, ciphertext, plaintext);
            ciphertext += ECRYPT_BLOCKLENGTH;
            plaintext += ECRYPT_BLOCKLENGTH;
        }
    }
    else {
        if (ctx->first && (blocks > 0)) {
            genrand_block_first(ctx, ciphertext, plaintext);
            ciphertext += ECRYPT_BLOCKLENGTH;
            plaintext += ECRYPT_BLOCKLENGTH;
            blocks--;
            ctx->first = 0;
        }
        for (i = 0; i < blocks; i++) {
            genrand_block(ctx, ciphertext, plaintext);
            ciphertext += ECRYPT_BLOCKLENGTH;
            plaintext += ECRYPT_BLOCKLENGTH;
        }
    }
}

/**
 * 按块解密函数（与加密相同）
 */
void ECRYPT_decrypt_blocks(ECRYPT_ctx* ctx,
    const u8* ciphertext,
    u8* plaintext, u32 blocks)
{
    ECRYPT_encrypt_blocks(ctx, ciphertext, plaintext, blocks);
}

/**
 * 高级加密接口
 */
void Cryptmt_encrypt(const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* ciphertext, size_t ciphertext_len)
{
    int key_bits = key_len * 8;
    int iv_bits = iv_len * 8;

    ECRYPT_ctx ctx;

    // 限制 key/iv 长度在允许范围内
    if (key_bits > ECRYPT_MAXKEYSIZE || key_bits < 128 || key_bits % 128 != 0) {
        fprintf(stderr, "不支持的密钥大小: %d\n", key_bits);
        return;
    }

    if (iv_bits > ECRYPT_MAXIVSIZE || iv_bits < 128 || iv_bits % 128 != 0) {
        fprintf(stderr, "不支持的IV大小: %d\n", iv_bits);
        return;
    }

    ECRYPT_init();
    ECRYPT_keysetup(&ctx, key, key_bits, iv_bits);
    ECRYPT_ivsetup(&ctx, iv);
    ECRYPT_encrypt_bytes(&ctx, plaintext, ciphertext, plaintext_len);
}

/**
 * 高级解密接口
 */
void Cryptmt_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* plaintext, size_t plaintext_len)
{
    int key_bits = key_len * 8;
    int iv_bits = iv_len * 8;
    ECRYPT_ctx ctx;

    // 限制 key/iv 长度在允许范围内
    if (key_bits > ECRYPT_MAXKEYSIZE || key_bits < 128 || key_bits % 128 != 0) {
        fprintf(stderr, "不支持的密钥大小: %d\n", key_bits);
        return;
    }

    if (iv_bits > ECRYPT_MAXIVSIZE || iv_bits < 128 || iv_bits % 128 != 0) {
        fprintf(stderr, "不支持的IV大小: %d\n", iv_bits);
        return;
    }

    ECRYPT_init();
    ECRYPT_keysetup(&ctx, key, key_bits, iv_bits);
    ECRYPT_ivsetup(&ctx, iv);
    ECRYPT_decrypt_bytes(&ctx, ciphertext, plaintext, ciphertext_len);
}
