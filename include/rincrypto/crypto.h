/* SPDX-License-Identifier: MIT */
#ifndef RINCRYPTO_CRYPTO_H
#define RINCRYPTO_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIN_CRYPTO_SHA256_BYTES ((size_t)32u)
#define RIN_CRYPTO_SHA512_BYTES ((size_t)64u)
#define RIN_CRYPTO_HMAC_SHA256_BYTES ((size_t)32u)
#define RIN_CRYPTO_SHA256_CONTEXT_BYTES ((size_t)104u)
#define RIN_CRYPTO_SHA512_CONTEXT_BYTES ((size_t)208u)
#define RIN_CRYPTO_MAX_ONE_SHOT_BYTES ((size_t)16u * 1024u * 1024u)
#define RIN_CRYPTO_MAX_RANDOM_BYTES ((size_t)4096u)
#define RIN_CRYPTO_MAX_PBKDF2_BYTES ((size_t)1024u * 1024u)
#define RIN_CRYPTO_MAX_PBKDF2_ITERATIONS UINT32_C(10000000)
#define RIN_CRYPTO_MAX_HKDF_BYTES ((size_t)8160u)

typedef enum RinCryptoStatus {
    RIN_CRYPTO_OK = 0,
    RIN_CRYPTO_INVALID_ARGUMENT = -1,
    RIN_CRYPTO_LIMIT = -2,
    RIN_CRYPTO_BUFFER_TOO_SMALL = -3,
    RIN_CRYPTO_BACKEND_FAILURE = -4,
    RIN_CRYPTO_INVALID_STATE = -5
} RinCryptoStatus;

/* The storage is intentionally opaque to callers. Its size is fixed because
 * the Browser download resume wire contract carries a SHA-256 snapshot. */
typedef struct RinCryptoSha256Context {
    uint64_t storage[13];
} RinCryptoSha256Context;

typedef struct RinCryptoSha512Context {
    uint64_t storage[26];
} RinCryptoSha512Context;

int rin_crypto_sha256_init(RinCryptoSha256Context* context);
int rin_crypto_sha256_update(RinCryptoSha256Context* context,
                             const uint8_t* data, size_t data_size);
int rin_crypto_sha256_final(RinCryptoSha256Context* context,
                            uint8_t digest[RIN_CRYPTO_SHA256_BYTES]);
int rin_crypto_sha256(const uint8_t* data, size_t data_size,
                      uint8_t digest[RIN_CRYPTO_SHA256_BYTES]);

int rin_crypto_sha512_init(RinCryptoSha512Context* context);
int rin_crypto_sha512_update(RinCryptoSha512Context* context,
                             const uint8_t* data, size_t data_size);
int rin_crypto_sha512_final(RinCryptoSha512Context* context,
                            uint8_t digest[RIN_CRYPTO_SHA512_BYTES]);
int rin_crypto_sha512(const uint8_t* data, size_t data_size,
                      uint8_t digest[RIN_CRYPTO_SHA512_BYTES]);

int rin_crypto_hmac_sha256(const uint8_t* key, size_t key_size,
                           const uint8_t* data, size_t data_size,
                           uint8_t mac[RIN_CRYPTO_HMAC_SHA256_BYTES]);
int rin_crypto_hkdf_sha256(const uint8_t* salt, size_t salt_size,
                           const uint8_t* input_key_material,
                           size_t input_key_material_size,
                           const uint8_t* info, size_t info_size,
                           uint8_t* output, size_t output_size);
int rin_crypto_pbkdf2_sha256(const uint8_t* password, size_t password_size,
                             const uint8_t* salt, size_t salt_size,
                             uint32_t iterations, uint8_t* output,
                             size_t output_size);

int rin_crypto_random(void* output, size_t output_size);
int rin_crypto_hex_encode(const uint8_t* input, size_t input_size,
                          int uppercase, uint8_t* output,
                          size_t output_capacity, size_t* output_size);

#ifdef __cplusplus
}
#endif

#endif
