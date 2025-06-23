#include "md4.h"
#include <stdio.h>
#include <string.h>

#define MD4_DIGEST_LENGTH 16

/**
 * MD4 测试向量
 */
 // 测试向量1
#define MD4_TEST_VECTOR_INPUT1 ""
const unsigned char MD4_TEST_VECTOR_OUTPUT1[MD4_DIGEST_LENGTH] = {
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
    0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
};
// 测试向量2
#define MD4_TEST_VECTOR_INPUT2 "abc"
const unsigned char MD4_TEST_VECTOR_OUTPUT2[MD4_DIGEST_LENGTH] = {
    0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52,
    0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d
};
// 测试向量3
#define MD4_TEST_VECTOR_INPUT3 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn" \
                    "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
const unsigned char MD4_TEST_VECTOR_OUTPUT3[MD4_DIGEST_LENGTH] = {
    0x21, 0x02, 0xd1, 0xd9, 0x4b, 0xd5, 0x8e, 0xbf,
    0x5a, 0xa2, 0x5c, 0x30, 0x5b, 0xb7, 0x83, 0xad
};

//int main() {
//    int all_passed = 1;
//    unsigned char digest[MD4_DIGEST_LENGTH];
//
//    // 向量1测试
//    memset(digest, 0, MD4_DIGEST_LENGTH);
//    MD4((const unsigned char*)MD4_TEST_VECTOR_INPUT1,
//        strlen(MD4_TEST_VECTOR_INPUT1),
//        digest,
//        MD4_DIGEST_LENGTH);
//
//    printf("Test Vector 1:\n");
//    printf("input: \"%s\"\n", MD4_TEST_VECTOR_INPUT1);
//    printf("output: ");
//    for (int i = 0; i < MD4_DIGEST_LENGTH; i++) {
//        printf("%02x", digest[i]);
//    }
//    printf("\n");
//
//    if (memcmp(digest, MD4_TEST_VECTOR_OUTPUT1, MD4_DIGEST_LENGTH) == 0) {
//        printf("PASS!\n\n");
//    }
//    else {
//        printf("FAILED\n\n");
//        all_passed = 0;
//    }
//
//    // 向量2测试
//    memset(digest, 0, MD4_DIGEST_LENGTH);
//    MD4((const unsigned char*)MD4_TEST_VECTOR_INPUT2,
//        strlen(MD4_TEST_VECTOR_INPUT2),
//        digest,
//        MD4_DIGEST_LENGTH);
//
//    printf("Test Vector 2:\n");
//    printf("input: \"%s\"\n", MD4_TEST_VECTOR_INPUT2);
//    printf("output: ");
//    for (int i = 0; i < MD4_DIGEST_LENGTH; i++) {
//        printf("%02x", digest[i]);
//    }
//    printf("\n");
//
//    if (memcmp(digest, MD4_TEST_VECTOR_OUTPUT2, MD4_DIGEST_LENGTH) == 0) {
//        printf("PASS!\n\n");
//    }
//    else {
//        printf("FAILED\n\n");
//        all_passed = 0;
//    }
//
//    // 向量3测试
//    memset(digest, 0, MD4_DIGEST_LENGTH);
//    MD4((const unsigned char*)MD4_TEST_VECTOR_INPUT3,
//        strlen(MD4_TEST_VECTOR_INPUT3),
//        digest,
//        MD4_DIGEST_LENGTH);
//
//    printf("Test Vector 3:\n");
//    printf("input: \"%s\"\n", MD4_TEST_VECTOR_INPUT3);
//    printf("output: ");
//    for (int i = 0; i < MD4_DIGEST_LENGTH; i++) {
//        printf("%02x", digest[i]);
//    }
//    printf("\n");
//
//    if (memcmp(digest, MD4_TEST_VECTOR_OUTPUT3, MD4_DIGEST_LENGTH) == 0) {
//        printf("PASS!\n\n");
//    }
//    else {
//        printf("FAILED\n\n");
//        all_passed = 0;
//    }
//
//    // 测试结果汇总
//    if (all_passed) {
//        printf("All test vectors passed!\n");
//    }
//    else {
//        printf("Some test vectors failed.\n");
//    }
//
//    return 0;
//}
