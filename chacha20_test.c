#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "chacha20.h"

/**
 * 测试向量1：选自 RFC-7539
 * 对应编号：Test Vector #1
 * 包含Key、Nonce、Counter和前64字节的密钥流。
 */
static const uint8_t CHACHA20_TEST_VECTOR_1_KEY[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t CHACHA20_TEST_VECTOR_1_NONCE[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

static const uint32_t CHACHA20_TEST_VECTOR_1_COUNTER = 0;

static const uint8_t CHACHA20_TEST_VECTOR_1_KEYSTREAM[64] = {
    0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
    0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
    0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
    0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
    0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
    0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
    0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
    0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86
};

/**
 * 测试向量2：选自 RFC-7539
 * 对应编号：Test Vector #2
 * 包含Key、Nonce、Counter和前375字节的密钥流。
 */
static const uint8_t CHACHA20_TEST_VECTOR_2_KEY[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static const uint8_t CHACHA20_TEST_VECTOR_2_NONCE[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02
};

static const uint32_t CHACHA20_TEST_VECTOR_2_COUNTER = 1;

static const uint8_t CHACHA20_TEST_VECTOR_2_KEYSTREAM[64] = {
    0xE2, 0x95, 0x89, 0x5D, 0x80, 0x8F, 0x4D, 0xB3,
    0x26, 0x44, 0x1F, 0xCB, 0x51, 0xEC, 0x53, 0x04,
    0x2E, 0x40, 0x29, 0xF7, 0x2A, 0x6F, 0x1E, 0xF8,
    0xD8, 0xB9, 0x0C, 0x74, 0x25, 0x0D, 0x30, 0x82,
    0x4E, 0xF2, 0xF0, 0xAB, 0xB1, 0x0B, 0x09, 0x61,
    0xA0, 0x96, 0xF3, 0x74, 0x98, 0xBD, 0x04, 0x77,
    0x67, 0xFC, 0xE3, 0xA2, 0x28, 0xC5, 0xE3, 0xF9,
    0x39, 0x92, 0x11, 0xBA, 0x2B, 0xD4, 0x49, 0x64
};

static const uint8_t TEST_INPUT[64] = "This is a test for chacha20 encryption symmetry check!";

//int main() {
//    uint8_t zero_input[64] = { 0 };
//    uint8_t ciphertext[64] = { 0 };
//    uint8_t decrypted[64] = { 0 };
//    uint8_t key_stream[64] = { 0 };
//
//    int all_passed = 1;
//
//    // 验证测试向量1的密钥流正确性以及加解密对称性
//    printf("Test 1:\n");
//    printf("== Vector 1 ==\n");
//
//    printf("Key:\n");
//    for (int i = 0; i < sizeof(CHACHA20_TEST_VECTOR_1_KEY); i++)
//        printf("%02X", CHACHA20_TEST_VECTOR_1_KEY[i]);
//    printf("\n");
//
//    printf("NONCE:\n");
//    for (int i = 0; i < sizeof(CHACHA20_TEST_VECTOR_1_NONCE); i++)
//        printf("%02X", CHACHA20_TEST_VECTOR_1_NONCE[i]);
//    printf("\n");
//
//    printf("COUNTER:\n%d\n", CHACHA20_TEST_VECTOR_1_COUNTER);
//
//    printf("Keystream:\n");
//    for (int i = 0; i < sizeof(CHACHA20_TEST_VECTOR_1_KEYSTREAM); ++i)
//        printf("%02X", CHACHA20_TEST_VECTOR_1_KEYSTREAM[i]);
//    printf("\n");
//
//    printf("== Official Keystream ==\n");
//
//    // 获取密钥流
//    ChaCha20_encrypt(zero_input, sizeof(zero_input),
//        CHACHA20_TEST_VECTOR_1_KEY, sizeof(CHACHA20_TEST_VECTOR_1_KEY),
//        CHACHA20_TEST_VECTOR_1_NONCE, sizeof(CHACHA20_TEST_VECTOR_1_NONCE),
//        CHACHA20_TEST_VECTOR_1_COUNTER,
//        ciphertext, sizeof(ciphertext));
//    
//    printf("Plaintext:\n");
//    for (int i = 0; i < sizeof(zero_input); i++)
//        printf("%02X", zero_input[i]);
//    printf("\n");
//
//    printf("Ciphertext:\n");
//    for (int i = 0; i < sizeof(ciphertext); i++)
//        printf("%02X", ciphertext[i]);
//    printf("\n");
//
//    if (memcmp(ciphertext, CHACHA20_TEST_VECTOR_1_KEYSTREAM, sizeof(ciphertext)) == 0)
//        printf("PASS!\n\n");
//    else {
//        printf("FAIL!\n\n");
//        all_passed = 0;
//    }
//
//    printf("== Encryption-Decryption Symmetry ==\n");
//
//    // 对实际明文加密，获得密文
//    ChaCha20_encrypt(TEST_INPUT, sizeof(TEST_INPUT),
//        CHACHA20_TEST_VECTOR_1_KEY, sizeof(CHACHA20_TEST_VECTOR_1_KEY),
//        CHACHA20_TEST_VECTOR_1_NONCE, sizeof(CHACHA20_TEST_VECTOR_1_NONCE),
//        CHACHA20_TEST_VECTOR_1_COUNTER,
//        ciphertext, sizeof(ciphertext));
//
//    // 对密文解密，获得解密后的明文
//    ChaCha20_decrypt(ciphertext, sizeof(ciphertext),
//        CHACHA20_TEST_VECTOR_1_KEY, sizeof(CHACHA20_TEST_VECTOR_1_KEY),
//        CHACHA20_TEST_VECTOR_1_NONCE, sizeof(CHACHA20_TEST_VECTOR_1_NONCE),
//        CHACHA20_TEST_VECTOR_1_COUNTER,
//        decrypted, sizeof(decrypted));
//   
//    // 对全0明文加密，获得与密文等长的密钥流（用于验证密钥流是否符合预期）
//    ChaCha20_encrypt(zero_input, sizeof(zero_input),
//        CHACHA20_TEST_VECTOR_1_KEY, sizeof(CHACHA20_TEST_VECTOR_1_KEY),
//        CHACHA20_TEST_VECTOR_1_NONCE, sizeof(CHACHA20_TEST_VECTOR_1_NONCE),
//        CHACHA20_TEST_VECTOR_1_COUNTER,
//        key_stream, sizeof(key_stream));
//
//    printf("Actual Keystream:\n");
//    for (int i = 0; i < sizeof(key_stream); i++)
//        printf("%02X", key_stream[i]);
//    printf("\n");
//
//    // 输出原始明文
//    printf("Plaintext(input to encryption):\n");
//    for (int i = 0; i < sizeof(TEST_INPUT); ++i) printf("%02X", TEST_INPUT[i]);
//    printf("\n");
//    
//    // 输出加密得到的密文
//    printf("Ciphertext(output of encryption):\n");
//    for (int i = 0; i < sizeof(ciphertext); ++i) printf("%02X", ciphertext[i]);
//    printf("\n");
//
//    // 输出解密输入（即密文）
//    printf("Ciphertext(input to decryption):\n");
//    for (int i = 0; i < sizeof(ciphertext); ++i) printf("%02X", ciphertext[i]);
//    printf("\n");
//
//    // 输出解密后明文
//    printf("Plaintext(output of decryption):\n");
//    for (int i = 0; i < sizeof(decrypted); ++i) printf("%02X", decrypted[i]);
//    printf("\n");
//
//    if (memcmp(TEST_INPUT, decrypted, sizeof(TEST_INPUT)) == 0)
//        printf("PASS!\n\n");
//    else {
//        printf("FAIL!\n\n");
//        all_passed = 0;
//    }
//
//    // 验证测试向量2的密钥流正确性以及加解密对称性
//    printf("Test 2:\n");
//    printf("== Vector 2 ==\n");
//
//    printf("Key:\n");
//    for (int i = 0; i < sizeof(CHACHA20_TEST_VECTOR_2_KEY); i++)
//        printf("%02X", CHACHA20_TEST_VECTOR_2_KEY[i]);
//    printf("\n");
//
//    printf("NONCE:\n");
//    for (int i = 0; i < sizeof(CHACHA20_TEST_VECTOR_2_NONCE); i++)
//        printf("%02X", CHACHA20_TEST_VECTOR_2_NONCE[i]);
//    printf("\n");
//
//    printf("COUNTER:\n%d\n", CHACHA20_TEST_VECTOR_2_COUNTER);
//
//    printf("Keystream:\n");
//    for (int i = 0; i < sizeof(CHACHA20_TEST_VECTOR_2_KEYSTREAM); ++i)
//        printf("%02X", CHACHA20_TEST_VECTOR_2_KEYSTREAM[i]);
//    printf("\n");
//
//    printf("== Official Keystream ==\n");
//
//    // 获取密钥流
//    ChaCha20_encrypt(zero_input, sizeof(zero_input),
//        CHACHA20_TEST_VECTOR_2_KEY, sizeof(CHACHA20_TEST_VECTOR_2_KEY),
//        CHACHA20_TEST_VECTOR_2_NONCE, sizeof(CHACHA20_TEST_VECTOR_2_NONCE),
//        CHACHA20_TEST_VECTOR_2_COUNTER,
//        ciphertext, sizeof(ciphertext));
//
//    printf("Plaintext:\n");
//    for (int i = 0; i < sizeof(zero_input); i++)
//        printf("%02X", zero_input[i]);
//    printf("\n");
//
//    printf("Ciphertext:\n");
//    for (int i = 0; i < sizeof(ciphertext); i++)
//        printf("%02X", ciphertext[i]);
//    printf("\n");
//
//    if (memcmp(ciphertext, CHACHA20_TEST_VECTOR_2_KEYSTREAM, sizeof(ciphertext)) == 0)
//        printf("PASS!\n\n");
//    else {
//        printf("FAIL!\n\n");
//        all_passed = 0;
//    }
//
//    // 对实际明文加密，获得密文
//    ChaCha20_encrypt(TEST_INPUT, sizeof(TEST_INPUT),
//        CHACHA20_TEST_VECTOR_2_KEY, sizeof(CHACHA20_TEST_VECTOR_2_KEY),
//        CHACHA20_TEST_VECTOR_2_NONCE, sizeof(CHACHA20_TEST_VECTOR_2_NONCE),
//        CHACHA20_TEST_VECTOR_2_COUNTER,
//        ciphertext, sizeof(ciphertext));
//
//    // 对密文解密，获得解密后的明文
//    ChaCha20_decrypt(ciphertext, sizeof(ciphertext),
//        CHACHA20_TEST_VECTOR_2_KEY, sizeof(CHACHA20_TEST_VECTOR_2_KEY),
//        CHACHA20_TEST_VECTOR_2_NONCE, sizeof(CHACHA20_TEST_VECTOR_2_NONCE),
//        CHACHA20_TEST_VECTOR_2_COUNTER,
//        decrypted, sizeof(decrypted));
//
//    // 对全0明文加密，获得与密文等长的密钥流（用于验证密钥流是否符合预期）
//    ChaCha20_encrypt(zero_input, sizeof(zero_input),
//        CHACHA20_TEST_VECTOR_2_KEY, sizeof(CHACHA20_TEST_VECTOR_2_KEY),
//        CHACHA20_TEST_VECTOR_2_NONCE, sizeof(CHACHA20_TEST_VECTOR_2_NONCE),
//        CHACHA20_TEST_VECTOR_2_COUNTER,
//        key_stream, sizeof(key_stream));
//
//    printf("Actual Keystream:\n");
//    for (int i = 0; i < sizeof(key_stream); i++)
//        printf("%02X", key_stream[i]);
//    printf("\n");
//
//    // 输出原始明文
//    printf("Plaintext(input to encryption):\n");
//    for (int i = 0; i < sizeof(TEST_INPUT); ++i) printf("%02X", TEST_INPUT[i]);
//    printf("\n");
//
//    // 输出加密得到的密文
//    printf("Ciphertext(output of encryption):\n");
//    for (int i = 0; i < sizeof(ciphertext); ++i) printf("%02X", ciphertext[i]);
//    printf("\n");
//
//    // 输出解密输入（即密文）
//    printf("Ciphertext(input to decryption):\n");
//    for (int i = 0; i < sizeof(ciphertext); ++i) printf("%02X", ciphertext[i]);
//    printf("\n");
//
//    // 输出解密后明文
//    printf("Plaintext(output of decryption):\n");
//    for (int i = 0; i < sizeof(decrypted); ++i) printf("%02X", decrypted[i]);
//    printf("\n");
//
//    if (memcmp(TEST_INPUT, decrypted, sizeof(TEST_INPUT)) == 0)
//        printf("PASS!\n\n");
//    else {
//        printf("FAIL!\n\n");
//        all_passed = 0;
//    }
//
//    // 汇总测试结果
//    if (all_passed) {
//        printf("All test vectors passed!\n");
//    }
//    else {
//        printf("Some test vectors failed.\n");
//    }
//
//    return all_passed ? 0 : 1;
//}
