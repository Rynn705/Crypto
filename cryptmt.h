#ifndef CRYPTMT_H
#define CRYPTMT_H

#include <stdint.h>

/**
 * CryptMT ���ܺ���
 *
 * ������Կ��������������������ġ���Կ����ӦΪ 16 �ֽڣ�IV Ϊ 8 �ֽڡ�
 *
 * @param plaintext       �����ֽ�����
 * @param plaintext_len   ���ĳ��ȣ��ֽڣ�
 * @param key             ��Կ����С 16 �ֽڣ���� 256 �ֽڣ����г�ʼΪ 16 �ֽڣ��� 16 �ֽڵ�����
 * @param key_len         ��Կ���ȣ�ӦΪ 16 + n * 16��
 * @param iv              ��ʼ������16 �ֽڣ�
 * @param iv_len          ��ʼ�������ȣ�ӦΪ 16 + n * 16��
 * @param ciphertext      ��������ֽ�����
 * @param ciphertext_len  ���ĳ��ȣ�Ӧ��������ͬ��
 */
void Cryptmt_encrypt(const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_bits,
    const uint8_t* iv, size_t iv_bits,
    uint8_t* ciphertext, size_t ciphertext_len
);

/**
 * CryptMT ���ܺ���
 *
 * ����ܹ�����ͬ������������Կ�����ԭ���ġ�
 *
 * @param ciphertext      �����ֽ�����
 * @param ciphertext_len  ���ĳ��ȣ��ֽڣ�
 * @param key             ��Կ����С 16 �ֽڣ���� 256 �ֽڣ����г�ʼΪ 16 �ֽڣ��� 16 �ֽڵ�����
 * @param key_len         ��Կ���ȣ�ӦΪ 16 + n * 16��
 * @param iv              ��ʼ������16 �ֽڣ�
 * @param iv_len          ��ʼ�������ȣ�ӦΪ 16 + n * 16��
 * @param plaintext       ��������ֽ�����
 * @param plaintext_len   ���ĳ��ȣ�Ӧ��������ͬ��
 */
void Cryptmt_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_bits,
    const uint8_t* iv, size_t iv_bits,
    uint8_t* plaintext, size_t plaintext_len
);

#endif // CRYPTMT_H
