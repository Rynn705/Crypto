#ifndef MD4_H
#define MD4_H

#include <stddef.h>  // 提供 size_t 类型定义

/**
 * 计算输入消息的 MD4 哈希值。
 *
 * @param message     输入消息指针
 * @param len         输入消息长度（单位：字节）
 * @param digest      输出缓冲区（应预留足够空间）
 * @param digest_len  输出摘要长度（单位：字节，为 16）
 */
void MD4(const unsigned char* message, size_t len, unsigned char* digest, size_t digest_len);

#endif //HASH_MD4_H
