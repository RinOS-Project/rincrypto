/* SPDX-License-Identifier: MIT */
#include "include/rincrypto/crypto.h"

#include "../rinencoding/include/rinencoding/encoding.h"
#include "../rinsecure/include/rinsecure/memory.h"
#include "../rintls/crypto/hmac.h"
#include "../rintls/crypto/sha256.h"

#include <limits.h>

_Static_assert(sizeof(RinCryptoSha256Context) == sizeof(sha256_ctx),
               "RinCryptoSha256Context must fit the SHA-256 backend");
_Static_assert(sizeof(RinCryptoSha512Context) == sizeof(sha512_ctx),
               "RinCryptoSha512Context must fit the SHA-512 backend");

static int crypto_input_valid(const uint8_t* data, size_t size,
                              size_t limit)
{
    return (size == 0u || data != NULL) && size <= limit;
}

static rin_size_t crypto_chunk_size(size_t size)
{
    return size > (size_t)UINT32_MAX ? (rin_size_t)UINT32_MAX
                                      : (rin_size_t)size;
}

static int crypto_sha256_update_backend(sha256_ctx* context,
                                        const uint8_t* data, size_t size)
{
    while (size != 0u) {
        const rin_size_t chunk = crypto_chunk_size(size);
        sha256_update(context, data, chunk);
        data += chunk;
        size -= chunk;
    }
    return RIN_CRYPTO_OK;
}

static int crypto_sha512_update_backend(sha512_ctx* context,
                                        const uint8_t* data, size_t size)
{
    while (size != 0u) {
        const rin_size_t chunk = crypto_chunk_size(size);
        sha512_update(context, data, chunk);
        data += chunk;
        size -= chunk;
    }
    return RIN_CRYPTO_OK;
}

int rin_crypto_sha256_init(RinCryptoSha256Context* context)
{
    if (!context) return RIN_CRYPTO_INVALID_ARGUMENT;
    rin_secure_zero(context, sizeof(*context));
    sha256_init((sha256_ctx*)(void*)context->storage);
    return RIN_CRYPTO_OK;
}

int rin_crypto_sha256_update(RinCryptoSha256Context* context,
                             const uint8_t* data, size_t data_size)
{
    if (!context || !crypto_input_valid(data, data_size, SIZE_MAX))
        return RIN_CRYPTO_INVALID_ARGUMENT;
    return crypto_sha256_update_backend(
        (sha256_ctx*)(void*)context->storage, data, data_size);
}

int rin_crypto_sha256_final(RinCryptoSha256Context* context,
                            uint8_t digest[RIN_CRYPTO_SHA256_BYTES])
{
    if (!context || !digest) {
        if (digest != NULL) rin_secure_zero(digest, RIN_CRYPTO_SHA256_BYTES);
        return RIN_CRYPTO_INVALID_ARGUMENT;
    }
    sha256_final((sha256_ctx*)(void*)context->storage, digest);
    rin_secure_zero(context, sizeof(*context));
    return RIN_CRYPTO_OK;
}

int rin_crypto_sha256(const uint8_t* data, size_t data_size,
                      uint8_t digest[RIN_CRYPTO_SHA256_BYTES])
{
    RinCryptoSha256Context context;
    int status;
    if (digest != NULL) rin_secure_zero(digest, RIN_CRYPTO_SHA256_BYTES);
    if (!digest || !crypto_input_valid(data, data_size,
                                       RIN_CRYPTO_MAX_ONE_SHOT_BYTES))
        return digest ? RIN_CRYPTO_LIMIT : RIN_CRYPTO_INVALID_ARGUMENT;
    status = rin_crypto_sha256_init(&context);
    if (status == RIN_CRYPTO_OK)
        status = rin_crypto_sha256_update(&context, data, data_size);
    if (status == RIN_CRYPTO_OK) status = rin_crypto_sha256_final(&context, digest);
    rin_secure_zero(&context, sizeof(context));
    return status;
}

int rin_crypto_sha512_init(RinCryptoSha512Context* context)
{
    if (!context) return RIN_CRYPTO_INVALID_ARGUMENT;
    rin_secure_zero(context, sizeof(*context));
    sha512_init((sha512_ctx*)(void*)context->storage);
    return RIN_CRYPTO_OK;
}

int rin_crypto_sha512_update(RinCryptoSha512Context* context,
                             const uint8_t* data, size_t data_size)
{
    if (!context || !crypto_input_valid(data, data_size, SIZE_MAX))
        return RIN_CRYPTO_INVALID_ARGUMENT;
    return crypto_sha512_update_backend(
        (sha512_ctx*)(void*)context->storage, data, data_size);
}

int rin_crypto_sha512_final(RinCryptoSha512Context* context,
                            uint8_t digest[RIN_CRYPTO_SHA512_BYTES])
{
    if (!context || !digest) {
        if (digest != NULL) rin_secure_zero(digest, RIN_CRYPTO_SHA512_BYTES);
        return RIN_CRYPTO_INVALID_ARGUMENT;
    }
    sha512_final((sha512_ctx*)(void*)context->storage, digest);
    rin_secure_zero(context, sizeof(*context));
    return RIN_CRYPTO_OK;
}

int rin_crypto_sha512(const uint8_t* data, size_t data_size,
                      uint8_t digest[RIN_CRYPTO_SHA512_BYTES])
{
    RinCryptoSha512Context context;
    int status;
    if (digest != NULL) rin_secure_zero(digest, RIN_CRYPTO_SHA512_BYTES);
    if (!digest || !crypto_input_valid(data, data_size,
                                       RIN_CRYPTO_MAX_ONE_SHOT_BYTES))
        return digest ? RIN_CRYPTO_LIMIT : RIN_CRYPTO_INVALID_ARGUMENT;
    status = rin_crypto_sha512_init(&context);
    if (status == RIN_CRYPTO_OK)
        status = rin_crypto_sha512_update(&context, data, data_size);
    if (status == RIN_CRYPTO_OK) status = rin_crypto_sha512_final(&context, digest);
    rin_secure_zero(&context, sizeof(context));
    return status;
}

static int crypto_key_data_valid(const uint8_t* key, size_t key_size,
                                 const uint8_t* data, size_t data_size)
{
    return crypto_input_valid(key, key_size, RIN_CRYPTO_MAX_ONE_SHOT_BYTES) &&
           crypto_input_valid(data, data_size, RIN_CRYPTO_MAX_ONE_SHOT_BYTES);
}

int rin_crypto_hmac_sha256(const uint8_t* key, size_t key_size,
                           const uint8_t* data, size_t data_size,
                           uint8_t mac[RIN_CRYPTO_HMAC_SHA256_BYTES])
{
    if (mac != NULL) rin_secure_zero(mac, RIN_CRYPTO_HMAC_SHA256_BYTES);
    if (!mac || !crypto_key_data_valid(key, key_size, data, data_size))
        return mac ? RIN_CRYPTO_LIMIT : RIN_CRYPTO_INVALID_ARGUMENT;
    hmac_sha256((const u8*)key, (rin_size_t)key_size, (const u8*)data,
                (rin_size_t)data_size, (u8*)mac);
    return RIN_CRYPTO_OK;
}

int rin_crypto_hkdf_sha256(const uint8_t* salt, size_t salt_size,
                           const uint8_t* input_key_material,
                           size_t input_key_material_size,
                           const uint8_t* info, size_t info_size,
                           uint8_t* output, size_t output_size)
{
    if (output != NULL && output_size <= RIN_CRYPTO_MAX_HKDF_BYTES)
        rin_secure_zero(output, output_size);
    if (!crypto_input_valid(salt, salt_size, RIN_CRYPTO_MAX_ONE_SHOT_BYTES) ||
        !crypto_input_valid(input_key_material, input_key_material_size,
                            RIN_CRYPTO_MAX_ONE_SHOT_BYTES) ||
        !crypto_input_valid(info, info_size, 1024u) ||
        output_size > RIN_CRYPTO_MAX_HKDF_BYTES ||
        (output_size != 0u && !output))
        return RIN_CRYPTO_INVALID_ARGUMENT;
    hkdf_sha256((const u8*)salt, (rin_size_t)salt_size,
                (const u8*)input_key_material, (rin_size_t)input_key_material_size,
                (const u8*)info, (rin_size_t)info_size, (u8*)output,
                (rin_size_t)output_size);
    return RIN_CRYPTO_OK;
}

int rin_crypto_pbkdf2_sha256(const uint8_t* password, size_t password_size,
                             const uint8_t* salt, size_t salt_size,
                             uint32_t iterations, uint8_t* output,
                             size_t output_size)
{
    uint32_t block_index = 1u;
    size_t offset = 0u;
    uint8_t digest[RIN_CRYPTO_HMAC_SHA256_BYTES];
    uint8_t block[RIN_CRYPTO_HMAC_SHA256_BYTES];
    if (output != NULL && output_size <= RIN_CRYPTO_MAX_PBKDF2_BYTES)
        rin_secure_zero(output, output_size);
    if (!crypto_key_data_valid(password, password_size, salt, salt_size) ||
        iterations == 0u || iterations > RIN_CRYPTO_MAX_PBKDF2_ITERATIONS ||
        output_size > RIN_CRYPTO_MAX_PBKDF2_BYTES ||
        (output_size != 0u && !output))
        return RIN_CRYPTO_INVALID_ARGUMENT;
    rin_secure_zero(digest, sizeof(digest));
    rin_secure_zero(block, sizeof(block));
    while (offset < output_size) {
        hmac_sha256_ctx context;
        uint8_t counter[4];
        size_t index;
        counter[0] = (uint8_t)(block_index >> 24u);
        counter[1] = (uint8_t)(block_index >> 16u);
        counter[2] = (uint8_t)(block_index >> 8u);
        counter[3] = (uint8_t)block_index;
        hmac_sha256_init(&context, (const u8*)password, (rin_size_t)password_size);
        if (salt_size != 0u)
            hmac_sha256_update(&context, (const u8*)salt, (rin_size_t)salt_size);
        hmac_sha256_update(&context, counter, sizeof(counter));
        hmac_sha256_final(&context, block);
        for (uint32_t round = 1u; round < iterations; ++round) {
            hmac_sha256((const u8*)password, (rin_size_t)password_size,
                        block, sizeof(block), digest);
            for (index = 0u; index < sizeof(block); ++index)
                block[index] ^= digest[index];
        }
        {
            const size_t copy_size = output_size - offset < sizeof(block)
                ? output_size - offset : sizeof(block);
            for (index = 0u; index < copy_size; ++index)
                output[offset + index] = block[index];
        }
        offset += sizeof(block) < output_size - offset
            ? sizeof(block) : output_size - offset;
        ++block_index;
    }
    rin_secure_zero(digest, sizeof(digest));
    rin_secure_zero(block, sizeof(block));
    return RIN_CRYPTO_OK;
}

int rin_crypto_random(void* output, size_t output_size)
{
    if (output != NULL && output_size <= RIN_CRYPTO_MAX_RANDOM_BYTES)
        rin_secure_zero(output, output_size);
    if (output_size > RIN_CRYPTO_MAX_RANDOM_BYTES ||
        (output_size != 0u && !output)) return RIN_CRYPTO_INVALID_ARGUMENT;
    if (output_size == 0u) return RIN_CRYPTO_OK;
    if (rintls_get_random((u8*)output, (rin_size_t)output_size) != 0) {
        rin_secure_zero(output, output_size);
        return RIN_CRYPTO_BACKEND_FAILURE;
    }
    return RIN_CRYPTO_OK;
}

int rin_crypto_hex_encode(const uint8_t* input, size_t input_size,
                          int uppercase, uint8_t* output,
                          size_t output_capacity, size_t* output_size)
{
    int status;
    if (output_size != NULL) *output_size = 0u;
    if (output != NULL && output_capacity <=
        RIN_CRYPTO_MAX_ONE_SHOT_BYTES * 2u + 1u)
        rin_secure_zero(output, output_capacity);
    if (!output_size || !crypto_input_valid(input, input_size,
                                            RIN_CRYPTO_MAX_ONE_SHOT_BYTES))
        return RIN_CRYPTO_INVALID_ARGUMENT;
    status = rin_encoding_hex_encode(input, input_size, uppercase != 0,
                                     output, output_capacity, output_size);
    if (status == RIN_ENCODING_OK) return RIN_CRYPTO_OK;
    if (status == RIN_ENCODING_BUFFER_TOO_SMALL)
        return RIN_CRYPTO_BUFFER_TOO_SMALL;
    return RIN_CRYPTO_INVALID_ARGUMENT;
}
