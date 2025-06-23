#include <stdio.h>
#include <string.h>
#include "rc2.h"

/**
 * 测试向量1：选自 Ron Rivest's Cipher No.2
 * 对应编号：Test Vector #1
 * 包含Key、Plain和Cipher。
 */
static const uint8_t RC2_TEST_VECTOR_1_KEY[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t RC2_TEST_VECTOR_1_KEYSTREAM[8] = {
    0x1C, 0x19, 0x8A, 0x83, 0x8D, 0xF0, 0x28, 0xB7
};

/**
 * 测试向量1：选自 Ron Rivest's Cipher No.2
 * 对应编号：Test Vector #2
 * 包含Key、Plain和Cipher。
 */
static const uint8_t RC2_TEST_VECTOR_2_KEY[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static const uint8_t RC2_TEST_VECTOR_2_KEYSTREAM[8] = {
    0x21, 0x82, 0x9C, 0x78, 0xA9, 0xF9, 0xC0, 0x74
};

/**
 * 测试向量1：选自 Ron Rivest's Cipher No.2
 * 对应编号：Test Vector #3
 * 包含Key、Plain和Cipher。
 */
static const uint8_t RC2_TEST_VECTOR_3_KEY[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const uint8_t RC2_TEST_VECTOR_3_KEYSTREAM[8] = {
    0x50, 0xDC, 0x01, 0x62, 0xBD, 0x75, 0x7F, 0x31
};

static const uint8_t TEST_INPUT[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

//int main() {
//    uint8_t zero_input[8] = { 0 };
//    uint8_t ciphertext[8] = { 0 };
//    uint8_t decrypted[8] = { 0 };
//    uint8_t key_stream[8] = { 0 };
//
//    int all_passed = 1;
//
//    // 验证测试向量1的密钥流正确性以及加解密对称性
//    printf("Test 1:\n");
//    printf("== Vector 1 ==\n");
//
//    printf("Key:\n");
//    for (int i = 0; i < sizeof(RC2_TEST_VECTOR_1_KEY); i++)
//        printf("%02X", RC2_TEST_VECTOR_1_KEY[i]);
//    printf("\n");
//
//    printf("Keystream:\n");
//    for (int i = 0; i < sizeof(RC2_TEST_VECTOR_1_KEYSTREAM); ++i)
//        printf("%02X", RC2_TEST_VECTOR_1_KEYSTREAM[i]);
//    printf("\n");
//
//    printf("== Official Keystream ==\n");
//
//    // 获取密钥流
//    RC2_encrypt(zero_input, sizeof(zero_input),
//        RC2_TEST_VECTOR_1_KEY, sizeof(RC2_TEST_VECTOR_1_KEY),
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
//    if (memcmp(ciphertext, RC2_TEST_VECTOR_1_KEYSTREAM, sizeof(ciphertext)) == 0)
//        printf("PASS!\n\n");
//    else {
//        printf("FAIL!\n\n");
//        all_passed = 0;
//    }
//
//    printf("== Encryption-Decryption Symmetry ==\n");
//
//    // 对实际明文加密，获得密文
//    RC2_encrypt(TEST_INPUT, sizeof(TEST_INPUT),
//        RC2_TEST_VECTOR_1_KEY, sizeof(RC2_TEST_VECTOR_1_KEY),
//        ciphertext, sizeof(ciphertext));
//
//    // 对密文解密，获得解密后的明文
//    RC2_decrypt(ciphertext, sizeof(ciphertext),
//        RC2_TEST_VECTOR_1_KEY, sizeof(RC2_TEST_VECTOR_1_KEY),
//        decrypted, sizeof(decrypted));
//
//    // 对全0明文加密，获得与密文等长的密钥流（用于验证密钥流是否符合预期）
//    RC2_encrypt(zero_input, sizeof(zero_input),
//        RC2_TEST_VECTOR_1_KEY, sizeof(RC2_TEST_VECTOR_1_KEY),
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
//    for (int i = 0; i < sizeof(RC2_TEST_VECTOR_2_KEY); i++)
//        printf("%02X", RC2_TEST_VECTOR_2_KEY[i]);
//    printf("\n");
//
//    printf("Keystream:\n");
//    for (int i = 0; i < sizeof(RC2_TEST_VECTOR_2_KEYSTREAM); ++i)
//        printf("%02X", RC2_TEST_VECTOR_2_KEYSTREAM[i]);
//    printf("\n");
//
//    printf("== Official Keystream ==\n");
//
//    // 获取密钥流
//    RC2_encrypt(zero_input, sizeof(zero_input),
//        RC2_TEST_VECTOR_2_KEY, sizeof(RC2_TEST_VECTOR_2_KEY),
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
//    if (memcmp(ciphertext, RC2_TEST_VECTOR_2_KEYSTREAM, sizeof(ciphertext)) == 0)
//        printf("PASS!\n\n");
//    else {
//        printf("FAIL!\n\n");
//        all_passed = 0;
//    }
//
//    printf("== Encryption-Decryption Symmetry ==\n");
//
//    // 对实际明文加密，获得密文
//    RC2_encrypt(TEST_INPUT, sizeof(TEST_INPUT),
//        RC2_TEST_VECTOR_2_KEY, sizeof(RC2_TEST_VECTOR_2_KEY),
//        ciphertext, sizeof(ciphertext));
//
//    // 对密文解密，获得解密后的明文
//    RC2_decrypt(ciphertext, sizeof(ciphertext),
//        RC2_TEST_VECTOR_2_KEY, sizeof(RC2_TEST_VECTOR_2_KEY),
//        decrypted, sizeof(decrypted));
//
//    // 对全0明文加密，获得与密文等长的密钥流（用于验证密钥流是否符合预期）
//    RC2_encrypt(zero_input, sizeof(zero_input),
//        RC2_TEST_VECTOR_2_KEY, sizeof(RC2_TEST_VECTOR_2_KEY),
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
//    // 验证测试向量3的密钥流正确性以及加解密对称性
//    printf("Test 3:\n");
//    printf("== Vector 3 ==\n");
//
//    printf("Key:\n");
//    for (int i = 0; i < sizeof(RC2_TEST_VECTOR_3_KEY); i++)
//        printf("%02X", RC2_TEST_VECTOR_3_KEY[i]);
//    printf("\n");
//
//    printf("Keystream:\n");
//    for (int i = 0; i < sizeof(RC2_TEST_VECTOR_3_KEYSTREAM); ++i)
//        printf("%02X", RC2_TEST_VECTOR_3_KEYSTREAM[i]);
//    printf("\n");
//
//    printf("== Official Keystream ==\n");
//
//    // 获取密钥流
//    RC2_encrypt(zero_input, sizeof(zero_input),
//        RC2_TEST_VECTOR_3_KEY, sizeof(RC2_TEST_VECTOR_3_KEY),
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
//    if (memcmp(ciphertext, RC2_TEST_VECTOR_3_KEYSTREAM, sizeof(ciphertext)) == 0)
//        printf("PASS!\n\n");
//    else {
//        printf("FAIL!\n\n");
//        all_passed = 0;
//    }
//
//    printf("== Encryption-Decryption Symmetry ==\n");
//
//    // 对实际明文加密，获得密文
//    RC2_encrypt(TEST_INPUT, sizeof(TEST_INPUT),
//        RC2_TEST_VECTOR_3_KEY, sizeof(RC2_TEST_VECTOR_3_KEY),
//        ciphertext, sizeof(ciphertext));
//
//    // 对密文解密，获得解密后的明文
//    RC2_decrypt(ciphertext, sizeof(ciphertext),
//        RC2_TEST_VECTOR_3_KEY, sizeof(RC2_TEST_VECTOR_3_KEY),
//        decrypted, sizeof(decrypted));
//
//    // 对全0明文加密，获得与密文等长的密钥流（用于验证密钥流是否符合预期）
//    RC2_encrypt(zero_input, sizeof(zero_input),
//        RC2_TEST_VECTOR_3_KEY, sizeof(RC2_TEST_VECTOR_3_KEY),
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
