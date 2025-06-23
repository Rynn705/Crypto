#ifndef SM3_H
#define SM3_H

#include <stdint.h>                     
#include <stddef.h>               

/**
 * 计算输入消息的 SM3 哈希值
 *
 * @param message     输入消息指针
 * @param len         输入消息长度（单位：字节）
 * @param digest      输出缓冲区（应预留足够空间）
 * @param digest_len  输出摘要长度（单位：字节，为 32）
 */
void SM3(const unsigned char* message, size_t len, unsigned char* digest, size_t digest_len);

#endif // SM3_H
