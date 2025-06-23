#include <stdio.h>
#include <string.h>
#include "sm3.h"

#define SM3_DIGEST_LENGTH 32  // SHA-512 输出摘要长度（字节）

/*
 * SM3 测试向量
 */
 // 测试向量1
#define SM3_TEST_VECTOR_INPUT1 ""
const unsigned char SM3_TEST_VECTOR_OUTPUT1[SM3_DIGEST_LENGTH] = {
    0x1a, 0xb2, 0x1d, 0x83, 0x55, 0xcf, 0xa1, 0x7f,
    0x8e, 0x61, 0x19, 0x48, 0x31, 0xe8, 0x1a, 0x8f,
    0x22, 0xbe, 0xc8, 0xc7, 0x28, 0xfe, 0xfb, 0x74,
    0x7e, 0xd0, 0x35, 0xeb, 0x50, 0x82, 0xaa, 0x2b
};
// 测试向量2
#define SM3_TEST_VECTOR_INPUT2 "abc"
const unsigned char SM3_TEST_VECTOR_OUTPUT2[SM3_DIGEST_LENGTH] = {
    0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
    0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
    0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
    0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
};
// 测试向量3
#define SM3_TEST_VECTOR_INPUT3 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn" \
                    "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
const unsigned char SM3_TEST_VECTOR_OUTPUT3[SM3_DIGEST_LENGTH] = {
    0x78, 0xbc, 0xfb, 0x58, 0x6a, 0xcd, 0x98, 0x3d,
    0x7f, 0xae, 0x8e, 0x69, 0x30, 0x15, 0x7f, 0x15,
    0x62, 0x01, 0x9e, 0x2c, 0xaf, 0x68, 0xf1, 0xc9,
    0x8a, 0x85, 0x5f, 0x1a, 0x95, 0xbb, 0x89, 0xbb
};

//int main() {
//    int all_passed = 1;
//    unsigned char digest[SM3_DIGEST_LENGTH];
//
//    // 向量1测试
//    memset(digest, 0, SM3_DIGEST_LENGTH);
//    SM3((const unsigned char *)SM3_TEST_VECTOR_INPUT1,
//            strlen(SM3_TEST_VECTOR_INPUT1),
//            digest,
//            SM3_DIGEST_LENGTH);
//
//    printf("Test Vector 1:\n");
//    printf("input: \"%s\"\n", SM3_TEST_VECTOR_INPUT1);
//    printf("output: ");
//    for (int i = 0; i < SM3_DIGEST_LENGTH; i++) {
//        printf("%02x", digest[i]);
//    }
//    printf("\n");
//
//    if (memcmp(digest, SM3_TEST_VECTOR_OUTPUT1, SM3_DIGEST_LENGTH) == 0) {
//        printf("PASS!\n\n");
//    } else {
//        printf("FAILED\n\n");
//        all_passed = 0;
//    }
//
//    // 向量2测试
//    memset(digest, 0, SM3_DIGEST_LENGTH);
//    SM3((const unsigned char *)SM3_TEST_VECTOR_INPUT2,
//            strlen(SM3_TEST_VECTOR_INPUT2),
//            digest,
//            SM3_DIGEST_LENGTH);
//
//    printf("Test Vector 2:\n");
//    printf("input: \"%s\"\n", SM3_TEST_VECTOR_INPUT2);
//    printf("output: ");
//    for (int i = 0; i < SM3_DIGEST_LENGTH; i++) {
//        printf("%02x", digest[i]);
//    }
//    printf("\n");
//
//    if (memcmp(digest, SM3_TEST_VECTOR_OUTPUT2, SM3_DIGEST_LENGTH) == 0) {
//        printf("PASS!\n\n");
//    } else {
//        printf("FAILED\n\n");
//        all_passed = 0;
//    }
//
//    // 向量3测试
//    memset(digest, 0, SM3_DIGEST_LENGTH);
//    SM3((const unsigned char *)SM3_TEST_VECTOR_INPUT3,
//            strlen(SM3_TEST_VECTOR_INPUT3),
//            digest,
//            SM3_DIGEST_LENGTH);
//
//    printf("Test Vector 3:\n");
//    printf("input: \"%s\"\n", SM3_TEST_VECTOR_INPUT3);
//    printf("output: ");
//    for (int i = 0; i < SM3_DIGEST_LENGTH; i++) {
//        printf("%02x", digest[i]);
//    }
//    printf("\n");
//
//    if (memcmp(digest, SM3_TEST_VECTOR_OUTPUT3, SM3_DIGEST_LENGTH) == 0) {
//        printf("PASS!\n\n");
//    } else {
//        printf("FAILED\n\n");
//        all_passed = 0;
//    }
//
//    // 测试结果汇总
//    if (all_passed) {
//        printf("All test vectors passed!\n");
//    } else {
//        printf("Some test vectors failed.\n");
//    }
//
//    return 0;
//}
