#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>

/**
 * 使用 ChaCha20 算法对输入数据进行加密
 *
 * @param plaintext        明文数据指针
 * @param plaintext_len    明文长度（单位：字节）
 * @param key              密钥指针（32 字节）
 * @param key_len          密钥长度，应为 32
 * @param nonce            随机数指针（12 字节）
 * @param nonce_len        随机数长度，应为 12
 * @param counter          初始计数器 (32位整数)
 * @param ciphertext       密文输出缓冲区指针
 * @param ciphertext_len   密文缓冲区长度（应与明文长度一致）
 */
void ChaCha20_encrypt(const uint8_t* plaintext, size_t plaintext_len,
	const uint8_t* key, size_t key_len,
	const uint8_t* nonce, size_t nonce_len,
	uint32_t counter,
	uint8_t* ciphertext, size_t ciphertext_len);

/**
 * 使用 ChaCha20 算法对密文进行解密
 *
 * @param ciphertext       密文数据指针
 * @param ciphertext_len   密文长度（单位：字节）
 * @param key              密钥指针（32 字节）
 * @param key_len          密钥长度，应为 32
 * @param nonce            随机数指针（12 字节，应与加密时相同）
 * @param nonce_len        随机数长度，应为 12
 * @param counter          初始计数器
 * @param plaintext        明文输出缓冲区指针
 * @param plaintext_len    明文缓冲区长度（应与密文一致）
 */
void ChaCha20_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
	const uint8_t* key, size_t key_len,
	const uint8_t* nonce, size_t nonce_len,
	uint32_t counter,
	uint8_t* plaintext, size_t plaintext_len);

#endif // CHACHA20_H