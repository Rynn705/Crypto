#ifndef CRYPTMT_H
#define CRYPTMT_H

#include <stdint.h>

/**
 * CryptMT 加密函数
 *
 * 生成密钥流并与明文异或生成密文。密钥长度应为 16 字节，IV 为 8 字节。
 *
 * @param plaintext       明文字节数组
 * @param plaintext_len   明文长度（字节）
 * @param key             密钥（最小 16 字节，最大 256 字节，其中初始为 16 字节，以 16 字节递增）
 * @param key_len         密钥长度（应为 16 + n * 16）
 * @param iv              初始向量（16 字节）
 * @param iv_len          初始向量长度（应为 16 + n * 16）
 * @param ciphertext      输出密文字节数组
 * @param ciphertext_len  密文长度（应与明文相同）
 */
void Cryptmt_encrypt(const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_bits,
    const uint8_t* iv, size_t iv_bits,
    uint8_t* ciphertext, size_t ciphertext_len
);

/**
 * CryptMT 解密函数
 *
 * 与加密过程相同。将密文与密钥流异或还原明文。
 *
 * @param ciphertext      密文字节数组
 * @param ciphertext_len  密文长度（字节）
 * @param key             密钥（最小 16 字节，最大 256 字节，其中初始为 16 字节，以 16 字节递增）
 * @param key_len         密钥长度（应为 16 + n * 16）
 * @param iv              初始向量（16 字节）
 * @param iv_len          初始向量长度（应为 16 + n * 16）
 * @param plaintext       输出明文字节数组
 * @param plaintext_len   明文长度（应与密文相同）
 */
void Cryptmt_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_bits,
    const uint8_t* iv, size_t iv_bits,
    uint8_t* plaintext, size_t plaintext_len
);

#endif // CRYPTMT_H
