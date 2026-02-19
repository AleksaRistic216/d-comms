#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE   32  /* AES-256 */
#define AES_IV_SIZE    16

typedef struct {
    uint32_t rk[60];  /* round keys: 4 * (Nr + 1) = 4 * 15 = 60 for AES-256 */
} aes256_ctx;

void aes256_init(aes256_ctx *ctx, const uint8_t key[AES_KEY_SIZE]);
void aes256_encrypt_block(const aes256_ctx *ctx, const uint8_t in[16], uint8_t out[16]);
void aes256_decrypt_block(const aes256_ctx *ctx, const uint8_t in[16], uint8_t out[16]);

/*
 * CBC mode with PKCS7 padding.
 *
 * aes_cbc_encrypt: Returns malloc'd buffer of (iv || ciphertext).
 *   *out_len = 16 (IV) + padded_len.
 *
 * aes_cbc_decrypt: Input is (iv || ciphertext). Returns malloc'd plaintext.
 *   *out_len = plaintext length after padding removal.
 *   Returns NULL on padding error.
 */
uint8_t *aes_cbc_encrypt(const uint8_t key[AES_KEY_SIZE],
                          const uint8_t *plain, size_t plain_len,
                          size_t *out_len);

uint8_t *aes_cbc_decrypt(const uint8_t key[AES_KEY_SIZE],
                          const uint8_t *data, size_t data_len,
                          size_t *out_len);

#endif
