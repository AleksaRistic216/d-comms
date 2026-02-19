/*
 * test_crypto.c — unit tests for sha256.c and aes.c
 *
 * Known-answer tests use NIST / RFC vectors so failures indicate a real bug
 * in the primitive, not just a comparison typo.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha256.h"
#include "aes.h"

/* ---- minimal test framework ---- */

static int g_pass = 0, g_fail = 0, g_cur_failed = 0;

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "    FAIL  %s:%d  (%s)\n", __FILE__, __LINE__, #expr); \
        g_cur_failed = 1; \
    } \
} while (0)

static void run_test(const char *name, void (*fn)(void))
{
    g_cur_failed = 0;
    fn();
    if (g_cur_failed) { fprintf(stderr, "FAIL  %s\n", name); g_fail++; }
    else              { printf("pass  %s\n",  name); g_pass++; }
}

/* ---- helpers ---- */

static void bytes_to_hex(const uint8_t *b, int n, char *out)
{
    for (int i = 0; i < n; i++)
        sprintf(out + i * 2, "%02x", b[i]);
    out[n * 2] = '\0';
}

/* ---- SHA-256 tests ---- */

/* FIPS 180-4: SHA-256("") */
static void test_sha256_empty(void)
{
    uint8_t hash[32];
    sha256((const uint8_t *)"", 0, hash);
    char hex[65];
    bytes_to_hex(hash, 32, hex);
    CHECK(strcmp(hex,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
}

/* FIPS 180-4: SHA-256("abc") */
static void test_sha256_abc(void)
{
    uint8_t hash[32];
    sha256((const uint8_t *)"abc", 3, hash);
    char hex[65];
    bytes_to_hex(hash, 32, hex);
    CHECK(strcmp(hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
}

/* FIPS 180-4: 448-bit message spanning two compression blocks */
static void test_sha256_two_blocks(void)
{
    const char *msg =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t hash[32];
    sha256((const uint8_t *)msg, strlen(msg), hash);
    char hex[65];
    bytes_to_hex(hash, 32, hex);
    CHECK(strcmp(hex,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0);
}

/* Key-derivation pattern used by proto.c: SHA256("hmac:" || user_key).
   Verify incremental and one-shot APIs agree. */
static void test_sha256_incremental_vs_oneshot(void)
{
    const char *data = "hmac:deadbeefcafebabedeadbeefcafebabe";

    uint8_t h1[32];
    sha256((const uint8_t *)data, strlen(data), h1);

    uint8_t h2[32];
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)data, 5);   /* "hmac:" */
    sha256_update(&ctx, (const uint8_t *)data + 5, strlen(data) - 5);
    sha256_final(&ctx, h2);

    CHECK(memcmp(h1, h2, 32) == 0);
}

/* ---- HMAC-SHA256 tests (RFC 4231) ---- */

/* RFC 4231 Test Case 1: key = 20 × 0x0b, data = "Hi There" */
static void test_hmac_rfc4231_tc1(void)
{
    uint8_t key[20];
    memset(key, 0x0b, 20);
    uint8_t out[32];
    hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, out);
    char hex[65];
    bytes_to_hex(out, 32, hex);
    CHECK(strcmp(hex,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7") == 0);
}

/* RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?" */
static void test_hmac_rfc4231_tc2(void)
{
    const uint8_t *key  = (const uint8_t *)"Jefe";
    const uint8_t *data = (const uint8_t *)"what do ya want for nothing?";
    uint8_t out[32];
    hmac_sha256(key, 4, data, 28, out);
    char hex[65];
    bytes_to_hex(out, 32, hex);
    CHECK(strcmp(hex,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") == 0);
}

/* ---- AES-256 block-level tests ---- */

/* NIST FIPS 197, Appendix C.3: AES-256 ECB single block */
static void test_aes256_block_encrypt_nist(void)
{
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t plain[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    static const uint8_t expected[16] = {
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
        0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89
    };

    aes256_ctx ctx;
    aes256_init(&ctx, key);
    uint8_t out[16];
    aes256_encrypt_block(&ctx, plain, out);
    CHECK(memcmp(out, expected, 16) == 0);
}

/* Decrypt must invert encrypt for the same NIST vector */
static void test_aes256_block_decrypt_nist(void)
{
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t expected[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    static const uint8_t ct[16] = {
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
        0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89
    };

    aes256_ctx ctx;
    aes256_init(&ctx, key);
    uint8_t out[16];
    aes256_decrypt_block(&ctx, ct, out);
    CHECK(memcmp(out, expected, 16) == 0);
}

/* ---- AES-256-CBC round-trip tests ---- */

static void test_aes_cbc_roundtrip_short(void)
{
    static const uint8_t key[32] = {0};
    const char *plain = "Hello, world!";  /* 13 bytes — sub-block */

    size_t ct_len;
    uint8_t *ct = aes_cbc_encrypt(key, (const uint8_t *)plain, strlen(plain), &ct_len);
    CHECK(ct != NULL);
    CHECK(ct_len == 16 + 16); /* IV(16) + one padded block(16) */

    size_t pt_len;
    uint8_t *pt = aes_cbc_decrypt(key, ct, ct_len, &pt_len);
    CHECK(pt != NULL);
    CHECK(pt_len == strlen(plain));
    CHECK(memcmp(pt, plain, pt_len) == 0);

    free(ct);
    free(pt);
}

/* Exactly 16 bytes → PKCS7 appends a full 16-byte padding block */
static void test_aes_cbc_roundtrip_exact_block(void)
{
    static const uint8_t key[32] = {
        1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
        17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
    };
    const uint8_t plain[16] = "0123456789abcdef";

    size_t ct_len;
    uint8_t *ct = aes_cbc_encrypt(key, plain, 16, &ct_len);
    CHECK(ct != NULL);
    CHECK(ct_len == 16 + 32); /* IV + 2 blocks (data + PKCS7 full-block pad) */

    size_t pt_len;
    uint8_t *pt = aes_cbc_decrypt(key, ct, ct_len, &pt_len);
    CHECK(pt != NULL);
    CHECK(pt_len == 16);
    CHECK(memcmp(pt, plain, 16) == 0);

    free(ct);
    free(pt);
}

/* Multi-block plaintext */
static void test_aes_cbc_roundtrip_multiblock(void)
{
    static const uint8_t key[32] = {0xff};
    const char *plain =
        "The quick brown fox jumps over the lazy dog. "
        "Pack my box with five dozen liquor jugs.";

    size_t ct_len;
    uint8_t *ct = aes_cbc_encrypt(key, (const uint8_t *)plain, strlen(plain), &ct_len);
    CHECK(ct != NULL);

    size_t pt_len;
    uint8_t *pt = aes_cbc_decrypt(key, ct, ct_len, &pt_len);
    CHECK(pt != NULL);
    CHECK(pt_len == strlen(plain));
    CHECK(memcmp(pt, plain, pt_len) == 0);

    free(ct);
    free(pt);
}

/* Corrupt the last ciphertext byte (overlaps PKCS7 padding) → NULL return */
static void test_aes_cbc_corrupt_padding(void)
{
    static const uint8_t key[32] = {0};
    const char *plain = "test data";

    size_t ct_len;
    uint8_t *ct = aes_cbc_encrypt(key, (const uint8_t *)plain, strlen(plain), &ct_len);
    CHECK(ct != NULL);

    ct[ct_len - 1] ^= 0xff; /* flip last byte → bad PKCS7 pad */

    size_t pt_len;
    uint8_t *pt = aes_cbc_decrypt(key, ct, ct_len, &pt_len);
    CHECK(pt == NULL);

    free(ct);
    /* pt is NULL, nothing to free */
}

/* Wrong key → decrypt produces garbage that fails PKCS7 validation → NULL */
static void test_aes_cbc_wrong_key(void)
{
    static const uint8_t key_a[32] = {0xaa};
    static const uint8_t key_b[32] = {0xbb};
    const char *plain = "secret message";

    size_t ct_len;
    uint8_t *ct = aes_cbc_encrypt(key_a, (const uint8_t *)plain, strlen(plain), &ct_len);
    CHECK(ct != NULL);

    size_t pt_len;
    uint8_t *pt = aes_cbc_decrypt(key_b, ct, ct_len, &pt_len);
    /* Decryption with wrong key should fail (bad padding) or produce wrong output */
    if (pt != NULL) {
        /* If padding happens to look valid, content must differ */
        CHECK(pt_len != strlen(plain) || memcmp(pt, plain, pt_len) != 0);
        free(pt);
    }
    /* pt == NULL is also acceptable (padding check failed) */

    free(ct);
}

/* ---- main ---- */

int main(void)
{
    printf("=== crypto tests ===\n");

    run_test("sha256_empty",                 test_sha256_empty);
    run_test("sha256_abc",                   test_sha256_abc);
    run_test("sha256_two_blocks_nist",       test_sha256_two_blocks);
    run_test("sha256_incremental_vs_oneshot",test_sha256_incremental_vs_oneshot);
    run_test("hmac_sha256_rfc4231_tc1",      test_hmac_rfc4231_tc1);
    run_test("hmac_sha256_rfc4231_tc2",      test_hmac_rfc4231_tc2);
    run_test("aes256_block_encrypt_nist",    test_aes256_block_encrypt_nist);
    run_test("aes256_block_decrypt_nist",    test_aes256_block_decrypt_nist);
    run_test("aes_cbc_roundtrip_short",      test_aes_cbc_roundtrip_short);
    run_test("aes_cbc_roundtrip_exact_block",test_aes_cbc_roundtrip_exact_block);
    run_test("aes_cbc_roundtrip_multiblock", test_aes_cbc_roundtrip_multiblock);
    run_test("aes_cbc_corrupt_padding",      test_aes_cbc_corrupt_padding);
    run_test("aes_cbc_wrong_key",            test_aes_cbc_wrong_key);

    printf("---\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
