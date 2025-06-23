#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "cryptmt.h"

 /**
  * 测试向量1：选自 ECrypt
  * 对应编号：Test Vector #1
  * 包含Key、IV和前64字节的密钥流。
  */
static const uint8_t CRYPTMT_TEST_VECTOR_1_KEY[16] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t CRYPTMT_TEST_VECTOR_1_IV[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t CRYPTMT_TEST_VECTOR_1_KEYSTREAM[64] = {
    0x92, 0x6C, 0x1C, 0xAF, 0x00, 0x3B, 0x5C, 0x7E,
    0x06, 0xD6, 0xA4, 0x7E, 0x89, 0x87, 0x74, 0x59,
    0x4B, 0x7D, 0x7C, 0x4F, 0xF8, 0xCF, 0x83, 0x10,
    0x5E, 0x8A, 0xF9, 0xF0, 0xC6, 0xA7, 0xF0, 0x7A,
    0x6D, 0x4B, 0xC7, 0x7A, 0xF6, 0x61, 0x8D, 0x2F,
    0x73, 0xAB, 0x7F, 0x05, 0xF5, 0x7C, 0xA7, 0xF4,
    0x3D, 0xC2, 0xBC, 0xB2, 0xF1, 0x9F, 0xBB, 0xBB,
    0xC0, 0xC1, 0xCD, 0x56, 0x28, 0x0B, 0xF4, 0x7C
};

/**
 * 测试向量2：选自 ECrypt
 * 对应编号：Test Vector #2
 * 包含Key、IV和前64字节的密钥流。
 */
static const uint8_t CRYPTMT_TEST_VECTOR_2_KEY[16] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t CRYPTMT_TEST_VECTOR_2_IV[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t CRYPTMT_TEST_VECTOR_2_KEYSTREAM[64] = {
    0xBD, 0x7F, 0x08, 0x7F, 0x14, 0x95, 0x9E, 0xE6,
    0x0B, 0xCE, 0xDE, 0x4F, 0x09, 0x9D, 0xA1, 0x37,
    0x12, 0x34, 0xA8, 0x8D, 0x58, 0x2D, 0x19, 0xD5,
    0x33, 0xD8, 0x0C, 0x1B, 0x96, 0x5A, 0x3C, 0x54,
    0x11, 0xE6, 0xD9, 0x62, 0x65, 0x92, 0x0C, 0x74,
    0x92, 0xFE, 0x25, 0xB9, 0x1B, 0x17, 0x8E, 0x8F,
    0x09, 0xF7, 0x14, 0x3B, 0x82, 0xCC, 0xC3, 0x08,
    0xBD, 0xA3, 0x3D, 0x79, 0xAC, 0xBC, 0x77, 0x69
};

/**
 * 测试向量3：选自 ECrypt
 * 对应编号：Test Vector #3
 * 包含Key、IV和前64字节的密钥流。
 */
static const uint8_t CRYPTMT_TEST_VECTOR_3_KEY[32] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t CRYPTMT_TEST_VECTOR_3_IV[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t CRYPTMT_TEST_VECTOR_3_KEYSTREAM[64] = {
    0x36, 0xD7, 0x41, 0x8E, 0xDE, 0xD0, 0xF4, 0x0C,
    0x78, 0x21, 0x74, 0xF4, 0x70, 0x42, 0xBE, 0x93,
    0x39, 0x1B, 0x48, 0xE1, 0x5D, 0xC9, 0x5F, 0x27,
    0x32, 0xEA, 0xE7, 0x79, 0x2E, 0x94, 0x0F, 0xFE,
    0xE2, 0x36, 0xFD, 0xD9, 0x6F, 0x3A, 0xD1, 0x1E,
    0x0F, 0xAA, 0x3E, 0x0E, 0xD9, 0x93, 0x35, 0x5B,
    0xBE, 0x92, 0xDC, 0x9F, 0x91, 0x58, 0x29, 0x75,
    0xBC, 0xFE, 0x26, 0xD9, 0xE6, 0xE5, 0x4B, 0xA2
};

/**
 * 测试向量4：选自 ECrypt
 * 对应编号：Test Vector #4
 * 包含Key、IV和前64字节的密钥流。
 */
static const uint8_t CRYPTMT_TEST_VECTOR_4_KEY[32] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t CRYPTMT_TEST_VECTOR_4_IV[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t CRYPTMT_TEST_VECTOR_4_KEYSTREAM[64] = {
    0x77, 0xEF, 0x71, 0xE3, 0xF8, 0x93, 0x69, 0x5B,
    0xEB, 0x74, 0x1B, 0x43, 0x29, 0x03, 0x0B, 0x66,
    0x6D, 0xE6, 0x6E, 0xB6, 0x15, 0x23, 0x21, 0x78,
    0x06, 0x21, 0x32, 0x76, 0xAA, 0x7A, 0x79, 0x70,
    0x10, 0x2D, 0xF1, 0x7D, 0xAC, 0x28, 0x1F, 0xFD,
    0x47, 0x0F, 0x1C, 0x49, 0x53, 0xFB, 0x15, 0x36,
    0x6B, 0x7F, 0x68, 0x30, 0xE0, 0x8D, 0x78, 0x04,
    0xFD, 0xDF, 0x54, 0x6F, 0xC9, 0x94, 0xCA, 0x6F
};

static const uint8_t TEST_INPUT[64] = "The quick brown fox jumps over the lazy dog.";

//int main() {
//    uint8_t zero_input[64] = { 0 };
//    uint8_t ciphertext[64];
//    uint8_t decrypted[64];
//    uint8_t keystream[64];
//
//    int all_passed = 1;
//
//    // 验证测试向量1的密钥流正确性以及加解密对称性
//    printf("Test 1:\n");
//    printf("== Vector 1 ==\n");
//
//    printf("Key:\n");
//    for (int i = 0; i < sizeof(CRYPTMT_TEST_VECTOR_1_KEY); i++)
//        printf("%02X", CRYPTMT_TEST_VECTOR_1_KEY[i]);
//    printf("\n");
//
//    printf("IV:\n");
//    for (int i = 0; i < sizeof(CRYPTMT_TEST_VECTOR_1_IV); i++)
//        printf("%02X", CRYPTMT_TEST_VECTOR_1_IV[i]);
//    printf("\n");
//
//    printf("Keystream:\n");
//    for (int i = 0; i < sizeof(CRYPTMT_TEST_VECTOR_1_KEYSTREAM); ++i)
//        printf("%02X", CRYPTMT_TEST_VECTOR_1_KEYSTREAM[i]);
//    printf("\n");
//
//    printf("== Official Keystream ==\n");
//
//    // 获取密钥流
//    Cryptmt_encrypt(zero_input, sizeof(zero_input),
//        CRYPTMT_TEST_VECTOR_1_KEY, sizeof(CRYPTMT_TEST_VECTOR_1_KEY),
//        CRYPTMT_TEST_VECTOR_1_IV, sizeof(CRYPTMT_TEST_VECTOR_1_IV),
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
//    if (memcmp(ciphertext, CRYPTMT_TEST_VECTOR_1_KEYSTREAM, sizeof(keystream)) == 0)
//        printf("PASS!\n");
//    else {
//        printf("FAIL!\n");
//        all_passed = 0;
//    }
//
//    printf("== Encryption-Decryption Symmetry ==\n");
//
//    // 对实际明文加密，获得密文
//    Cryptmt_encrypt(TEST_INPUT, sizeof(TEST_INPUT),
//        CRYPTMT_TEST_VECTOR_1_KEY, sizeof(CRYPTMT_TEST_VECTOR_1_KEY),
//        CRYPTMT_TEST_VECTOR_1_IV, sizeof(CRYPTMT_TEST_VECTOR_1_IV),
//        ciphertext, sizeof(ciphertext));
//
//    // 对密文解密，获得解密后的明文
//    Cryptmt_decrypt(ciphertext, sizeof(ciphertext),
//        CRYPTMT_TEST_VECTOR_1_KEY, sizeof(CRYPTMT_TEST_VECTOR_1_KEY),
//        CRYPTMT_TEST_VECTOR_1_IV, sizeof(CRYPTMT_TEST_VECTOR_1_IV),
//        decrypted, sizeof(decrypted));
//
//    // 对全0明文加密，获得与密文等长的密钥流（用于验证密钥流是否符合预期）
//    Cryptmt_encrypt(zero_input, sizeof(zero_input),
//        CRYPTMT_TEST_VECTOR_1_KEY, sizeof(CRYPTMT_TEST_VECTOR_1_KEY),
//        CRYPTMT_TEST_VECTOR_1_IV, sizeof(CRYPTMT_TEST_VECTOR_1_IV),
//        keystream, sizeof(keystream));
//
//    printf("Actual Keystream:\n");
//    for (int i = 0; i < sizeof(keystream); i++)
//        printf("%02X", keystream[i]);
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
//    for (int i = 0; i < sizeof(CRYPTMT_TEST_VECTOR_2_KEY); i++)
//        printf("%02X", CRYPTMT_TEST_VECTOR_2_KEY[i]);
//    printf("\n");
//
//    printf("IV:\n");
//    for (int i = 0; i < sizeof(CRYPTMT_TEST_VECTOR_2_IV); i++)
//        printf("%02X", CRYPTMT_TEST_VECTOR_2_IV[i]);
//    printf("\n");
//
//    printf("Keystream:\n");
//    for (int i = 0; i < sizeof(CRYPTMT_TEST_VECTOR_2_KEYSTREAM); ++i)
//        printf("%02X", CRYPTMT_TEST_VECTOR_2_KEYSTREAM[i]);
//    printf("\n");
//
//    printf("== Official Keystream ==\n");
//
//    // 获取密钥流
//    Cryptmt_encrypt(zero_input, sizeof(zero_input),
//        CRYPTMT_TEST_VECTOR_2_KEY, sizeof(CRYPTMT_TEST_VECTOR_2_KEY),
//        CRYPTMT_TEST_VECTOR_2_IV, sizeof(CRYPTMT_TEST_VECTOR_2_IV),
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
//    if (memcmp(ciphertext, CRYPTMT_TEST_VECTOR_2_KEYSTREAM, sizeof(keystream)) == 0)
//        printf("PASS!\n");
//    else {
//        printf("FAIL!\n");
//        all_passed = 0;
//    }
//
//    printf("== Encryption-Decryption Symmetry ==\n");
//
//    // 对实际明文加密，获得密文
//    Cryptmt_encrypt(TEST_INPUT, sizeof(TEST_INPUT),
//        CRYPTMT_TEST_VECTOR_2_KEY, sizeof(CRYPTMT_TEST_VECTOR_2_KEY),
//        CRYPTMT_TEST_VECTOR_2_IV, sizeof(CRYPTMT_TEST_VECTOR_2_IV),
//        ciphertext, sizeof(ciphertext));
//
//    // 对密文解密，获得解密后的明文
//    Cryptmt_decrypt(ciphertext, sizeof(ciphertext),
//        CRYPTMT_TEST_VECTOR_2_KEY, sizeof(CRYPTMT_TEST_VECTOR_2_KEY),
//        CRYPTMT_TEST_VECTOR_2_IV, sizeof(CRYPTMT_TEST_VECTOR_2_IV),
//        decrypted, sizeof(decrypted));
//
//    // 对全0明文加密，获得与密文等长的密钥流（用于验证密钥流是否符合预期）
//    Cryptmt_encrypt(zero_input, sizeof(zero_input),
//        CRYPTMT_TEST_VECTOR_2_KEY, sizeof(CRYPTMT_TEST_VECTOR_2_KEY),
//        CRYPTMT_TEST_VECTOR_2_IV, sizeof(CRYPTMT_TEST_VECTOR_2_IV),
//        keystream, sizeof(keystream));
//
//    printf("Actual Keystream:\n");
//    for (int i = 0; i < sizeof(keystream); i++)
//        printf("%02X", keystream[i]);
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
//    // 验证测试向量3的密钥流正确性以及加解密对称性
//    printf("Test 3:\n");
//    printf("== Vector 3 ==\n");
//
//    printf("Key:\n");
//    for (int i = 0; i < sizeof(CRYPTMT_TEST_VECTOR_3_KEY); i++)
//        printf("%02X", CRYPTMT_TEST_VECTOR_3_KEY[i]);
//    printf("\n");
//
//    printf("IV:\n");
//    for (int i = 0; i < sizeof(CRYPTMT_TEST_VECTOR_3_IV); i++)
//        printf("%02X", CRYPTMT_TEST_VECTOR_3_IV[i]);
//    printf("\n");
//
//    printf("Keystream:\n");
//    for (int i = 0; i < sizeof(CRYPTMT_TEST_VECTOR_3_KEYSTREAM); ++i)
//        printf("%02X", CRYPTMT_TEST_VECTOR_3_KEYSTREAM[i]);
//    printf("\n");
//
//    printf("== Official Keystream ==\n");
//
//    // 获取密钥流
//    Cryptmt_encrypt(zero_input, sizeof(zero_input),
//        CRYPTMT_TEST_VECTOR_3_KEY, sizeof(CRYPTMT_TEST_VECTOR_3_KEY),
//        CRYPTMT_TEST_VECTOR_3_IV, sizeof(CRYPTMT_TEST_VECTOR_3_IV),
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
//    if (memcmp(ciphertext, CRYPTMT_TEST_VECTOR_3_KEYSTREAM, sizeof(ciphertext)) == 0)
//        printf("PASS!\n");
//    else {
//        printf("FAIL!\n");
//        all_passed = 0;
//    }
//
//    printf("== Encryption-Decryption Symmetry ==\n");
//
//    // 对实际明文加密，获得密文
//    Cryptmt_encrypt(TEST_INPUT, sizeof(TEST_INPUT),
//        CRYPTMT_TEST_VECTOR_3_KEY, sizeof(CRYPTMT_TEST_VECTOR_3_KEY),
//        CRYPTMT_TEST_VECTOR_3_IV, sizeof(CRYPTMT_TEST_VECTOR_3_IV),
//        ciphertext, sizeof(ciphertext));
//
//    // 对密文解密，获得解密后的明文
//    Cryptmt_decrypt(ciphertext, sizeof(ciphertext),
//        CRYPTMT_TEST_VECTOR_3_KEY, sizeof(CRYPTMT_TEST_VECTOR_3_KEY),
//        CRYPTMT_TEST_VECTOR_3_IV, sizeof(CRYPTMT_TEST_VECTOR_3_IV),
//        decrypted, sizeof(decrypted));
//
//    // 对全0明文加密，获得与密文等长的密钥流（用于验证密钥流是否符合预期）
//    Cryptmt_encrypt(zero_input, sizeof(zero_input),
//        CRYPTMT_TEST_VECTOR_3_KEY, sizeof(CRYPTMT_TEST_VECTOR_3_KEY),
//        CRYPTMT_TEST_VECTOR_3_IV, sizeof(CRYPTMT_TEST_VECTOR_3_IV),
//        keystream, sizeof(keystream));
//
//    printf("Actual Keystream:\n");
//    for (int i = 0; i < sizeof(keystream); i++)
//        printf("%02X", keystream[i]);
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
//    // 验证测试向量4的密钥流正确性以及加解密对称性
//    printf("Test 4:\n");
//    printf("== Vector 4 ==\n");
//
//    printf("Key:\n");
//    for (int i = 0; i < sizeof(CRYPTMT_TEST_VECTOR_4_KEY); i++)
//        printf("%02X", CRYPTMT_TEST_VECTOR_4_KEY[i]);
//    printf("\n");
//
//    printf("IV:\n");
//    for (int i = 0; i < sizeof(CRYPTMT_TEST_VECTOR_4_IV); i++)
//        printf("%02X", CRYPTMT_TEST_VECTOR_4_IV[i]);
//    printf("\n");
//
//    printf("Keystream:\n");
//    for (int i = 0; i < sizeof(CRYPTMT_TEST_VECTOR_4_KEYSTREAM); ++i)
//        printf("%02X", CRYPTMT_TEST_VECTOR_4_KEYSTREAM[i]);
//    printf("\n");
//
//    printf("== Official Keystream ==\n");
//
//    // 获取密钥流
//    Cryptmt_encrypt(zero_input, sizeof(zero_input),
//        CRYPTMT_TEST_VECTOR_4_KEY, sizeof(CRYPTMT_TEST_VECTOR_4_KEY),
//        CRYPTMT_TEST_VECTOR_4_IV, sizeof(CRYPTMT_TEST_VECTOR_4_IV),
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
//    if (memcmp(ciphertext, CRYPTMT_TEST_VECTOR_4_KEYSTREAM, sizeof(ciphertext)) == 0)
//        printf("PASS!\n");
//    else {
//        printf("FAIL!\n");
//        all_passed = 0;
//    }
//
//    printf("== Encryption-Decryption Symmetry ==\n");
//
//    // 对实际明文加密，获得密文
//    Cryptmt_encrypt(TEST_INPUT, sizeof(TEST_INPUT),
//        CRYPTMT_TEST_VECTOR_4_KEY, sizeof(CRYPTMT_TEST_VECTOR_4_KEY),
//        CRYPTMT_TEST_VECTOR_4_IV, sizeof(CRYPTMT_TEST_VECTOR_4_IV),
//        ciphertext, sizeof(ciphertext));
//
//    // 对密文解密，获得解密后的明文
//    Cryptmt_decrypt(ciphertext, sizeof(ciphertext),
//        CRYPTMT_TEST_VECTOR_4_KEY, sizeof(CRYPTMT_TEST_VECTOR_4_KEY),
//        CRYPTMT_TEST_VECTOR_4_IV, sizeof(CRYPTMT_TEST_VECTOR_4_IV),
//        decrypted, sizeof(decrypted));
//
//    // 对全0明文加密，获得与密文等长的密钥流（用于验证密钥流是否符合预期）
//    Cryptmt_encrypt(zero_input, sizeof(zero_input),
//        CRYPTMT_TEST_VECTOR_4_KEY, sizeof(CRYPTMT_TEST_VECTOR_4_KEY),
//        CRYPTMT_TEST_VECTOR_4_IV, sizeof(CRYPTMT_TEST_VECTOR_4_IV),
//        keystream, sizeof(keystream));
//
//    printf("Actual Keystream:\n");
//    for (int i = 0; i < sizeof(keystream); i++)
//        printf("%02X", keystream[i]);
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
