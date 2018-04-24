/*
 * AES functions
 * Copyright (c) 2003-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#define AES_BLOCK_SIZE 16

int omac1_aes_vector(const u8 *key, size_t key_len, size_t num_elem,
                     const u8 *addr[], const size_t *len, u8 *mac);
int omac1_aes_128_vector(const u8 *key, size_t num_elem,
			 const u8 *addr[], const size_t *len, u8 *mac);
int omac1_aes_128(const u8 *key, const u8 *data, size_t data_len, u8 *mac);
int omac1_aes_256(const u8 *key, const u8 *data, size_t data_len, u8 *mac);
int aes_ctr_encrypt(const u8 *key, size_t key_len, const u8 *nonce,
		    u8 *data, size_t data_len);
void aes_encrypt(void *ctx, const u8 *plain, u8 *crypt);

