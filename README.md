# RinCrypto

Bounded SHA-256/SHA-512, HMAC-SHA256, HKDF/PBKDF2, random-byte, and hex helpers.

## Public API contract

| Requirement | Contract |
| --- | --- |
| Purpose | Bounded SHA-256/SHA-512, HMAC-SHA256, HKDF/PBKDF2, random-byte, and hex helpers. |
| Supported API | include/rincrypto/crypto.h: digest, KDF, random, hex APIs. |
| Unsupported API | Not a key store, keyring, cipher suite, or policy engine; only declared algorithms are supported. |
| ownership | Caller owns all inputs/outputs and streaming contexts. |
| thread-safety | One-shot operations are stateless; do not share a mutable streaming context concurrently. |
| limits | One-shot input 16 MiB; random output 4096 bytes; PBKDF2 output 1 MiB and 10M iterations; HKDF 8160 bytes. |
| errors | RinCryptoStatus covers invalid arguments, limits, short buffers, backend failure, and state errors. |
| ABI stability | Source ABI; context size is checked against the RinTLS backend, no separate binary ABI version. |
| security | Random generation has no local PRNG fallback; this library does not retain keys or authorize their use. |
| build | No standalone build file; compile crypto.c with its declared RinTLS, RinEncoding, and RinSecure dependencies. |
| test | No standalone test target; parent consumer contracts are authoritative. No tests/builds run for this README update. |
