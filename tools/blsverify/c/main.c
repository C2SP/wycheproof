/*
 * BLS12-381 Wycheproof test vector verifier using blst.
 *
 * Verifies:
 *   - bls_sig_g2_basic_verify_test.json
 *   - bls_sig_g2_pop_verify_test.json
 *   - bls_sig_g2_aggregate_verify_test.json
 *   - bls_hash_to_g2_test.json
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "blst.h"
#include "cJSON.h"

/* ------------------------------------------------------------------ */
/* Hex decoding                                                       */
/* ------------------------------------------------------------------ */

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * Decode hex string into buf. Returns decoded length, or -1 on error.
 * buf must be at least strlen(hex)/2 bytes.
 */
static int hex_decode(const char *hex, uint8_t *buf, size_t buf_len)
{
    if (hex == NULL) return -1;
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return -1;
    size_t out_len = hlen / 2;
    if (out_len > buf_len) return -1;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_val(hex[2 * i]);
        int lo = hex_val(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)out_len;
}

/* ------------------------------------------------------------------ */
/* File reading                                                       */
/* ------------------------------------------------------------------ */

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len < 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)len, f);
    fclose(f);
    buf[rd] = '\0';
    return buf;
}

/* ------------------------------------------------------------------ */
/* DST lookup from ciphersuite string                                 */
/* ------------------------------------------------------------------ */

static const char *dst_from_ciphersuite(const char *cs)
{
    if (strcmp(cs,
        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_") == 0)
        return "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    if (strcmp(cs,
        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_") == 0)
        return "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Signature verification (single): basic and pop schemes             */
/* ------------------------------------------------------------------ */

typedef struct {
    int pass;
    int fail;
} results_t;

static void run_sig_verify(
    const char *path, results_t *res)
{
    char *data = read_file(path);
    if (!data) {
        fprintf(stderr, "Cannot open %s\n", path);
        res->fail++;
        return;
    }
    cJSON *root = cJSON_Parse(data);
    free(data);
    if (!root) {
        fprintf(stderr, "JSON parse error in %s\n", path);
        res->fail++;
        return;
    }

    cJSON *groups = cJSON_GetObjectItem(root, "testGroups");
    int ngroups = cJSON_GetArraySize(groups);

    for (int gi = 0; gi < ngroups; gi++) {
        cJSON *grp = cJSON_GetArrayItem(groups, gi);
        const char *cs =
            cJSON_GetObjectItem(grp, "ciphersuite")->valuestring;
        const char *dst = dst_from_ciphersuite(cs);
        if (!dst) {
            fprintf(stderr, "Unknown ciphersuite: %s\n", cs);
            res->fail++;
            continue;
        }
        size_t dst_len = strlen(dst);

        /* Parse the group public key */
        cJSON *pk_obj = cJSON_GetObjectItem(grp, "publicKey");
        const char *pk_hex =
            cJSON_GetObjectItem(pk_obj, "pk")->valuestring;
        uint8_t pk_bytes[48];
        int pk_len = hex_decode(pk_hex, pk_bytes, sizeof(pk_bytes));

        blst_p1_affine pk_aff;
        bool pk_ok = (pk_len == 48) &&
            (blst_p1_uncompress(&pk_aff, pk_bytes) == BLST_SUCCESS);

        cJSON *tests = cJSON_GetObjectItem(grp, "tests");
        int ntests = cJSON_GetArraySize(tests);

        for (int ti = 0; ti < ntests; ti++) {
            cJSON *tc = cJSON_GetArrayItem(tests, ti);
            int tcId = cJSON_GetObjectItem(tc, "tcId")->valueint;
            const char *result_str =
                cJSON_GetObjectItem(tc, "result")->valuestring;
            bool expect_valid = (strcmp(result_str, "valid") == 0);

            const char *msg_hex =
                cJSON_GetObjectItem(tc, "msg")->valuestring;
            const char *sig_hex =
                cJSON_GetObjectItem(tc, "sig")->valuestring;

            /* Decode message */
            size_t msg_hex_len = strlen(msg_hex);
            size_t msg_len = msg_hex_len / 2;
            uint8_t *msg = NULL;
            if (msg_len > 0) {
                msg = malloc(msg_len);
                if (hex_decode(msg_hex, msg, msg_len) < 0) {
                    /* Bad hex => treat as verify failure */
                    if (!expect_valid) { res->pass++; }
                    else {
                        fprintf(stderr,
                            "%s tcId=%d: bad msg hex\n",
                            path, tcId);
                        res->fail++;
                    }
                    free(msg);
                    continue;
                }
            }

            /* Decode signature */
            uint8_t sig_bytes[96];
            int sig_len =
                hex_decode(sig_hex, sig_bytes, sizeof(sig_bytes));

            bool verified = false;

            if (pk_ok && sig_len == 96) {
                blst_p2_affine sig_aff;
                if (blst_p2_uncompress(&sig_aff, sig_bytes)
                    == BLST_SUCCESS) {
                    /* Reject identity points */
                    if (!blst_p1_affine_is_inf(&pk_aff) &&
                        !blst_p2_affine_is_inf(&sig_aff)) {
                        BLST_ERROR err = blst_core_verify_pk_in_g1(
                            &pk_aff, &sig_aff,
                            true, /* hash */
                            msg, msg_len,
                            (const uint8_t *)dst, dst_len,
                            NULL, 0);
                        verified = (err == BLST_SUCCESS);
                    }
                }
            }

            if (verified == expect_valid) {
                res->pass++;
            } else {
                fprintf(stderr,
                    "%s tcId=%d: expected %s got %s\n",
                    path, tcId,
                    expect_valid ? "valid" : "invalid",
                    verified ? "valid" : "invalid");
                res->fail++;
            }
            free(msg);
        }
    }
    cJSON_Delete(root);
}

/* ------------------------------------------------------------------ */
/* Aggregate verification                                             */
/* ------------------------------------------------------------------ */

static void run_aggregate_verify(
    const char *path, results_t *res)
{
    char *data = read_file(path);
    if (!data) {
        fprintf(stderr, "Cannot open %s\n", path);
        res->fail++;
        return;
    }
    cJSON *root = cJSON_Parse(data);
    free(data);
    if (!root) {
        fprintf(stderr, "JSON parse error in %s\n", path);
        res->fail++;
        return;
    }

    cJSON *groups = cJSON_GetObjectItem(root, "testGroups");
    int ngroups = cJSON_GetArraySize(groups);

    for (int gi = 0; gi < ngroups; gi++) {
        cJSON *grp = cJSON_GetArrayItem(groups, gi);
        const char *cs =
            cJSON_GetObjectItem(grp, "ciphersuite")->valuestring;
        const char *dst = dst_from_ciphersuite(cs);
        if (!dst) {
            fprintf(stderr, "Unknown ciphersuite: %s\n", cs);
            res->fail++;
            continue;
        }
        size_t dst_len = strlen(dst);

        cJSON *tests = cJSON_GetObjectItem(grp, "tests");
        int ntests = cJSON_GetArraySize(tests);

        for (int ti = 0; ti < ntests; ti++) {
            cJSON *tc = cJSON_GetArrayItem(tests, ti);
            int tcId = cJSON_GetObjectItem(tc, "tcId")->valueint;
            const char *result_str =
                cJSON_GetObjectItem(tc, "result")->valuestring;
            bool expect_valid = (strcmp(result_str, "valid") == 0);

            cJSON *pubkeys_arr =
                cJSON_GetObjectItem(tc, "pubkeys");
            cJSON *messages_arr =
                cJSON_GetObjectItem(tc, "messages");
            const char *sig_hex =
                cJSON_GetObjectItem(tc, "sig")->valuestring;

            int n_pks = cJSON_GetArraySize(pubkeys_arr);
            int n_msgs = cJSON_GetArraySize(messages_arr);

            bool verified = false;

            /* n=0 or mismatched counts => invalid */
            if (n_pks == 0 || n_pks != n_msgs) {
                goto check_result;
            }

            /* Decode aggregate signature */
            uint8_t sig_bytes[96];
            if (hex_decode(sig_hex, sig_bytes, sizeof(sig_bytes))
                != 96) {
                goto check_result;
            }

            blst_p2_affine sig_aff;
            if (blst_p2_uncompress(&sig_aff, sig_bytes)
                != BLST_SUCCESS) {
                goto check_result;
            }
            if (blst_p2_affine_is_inf(&sig_aff)) {
                goto check_result;
            }

            /* Set up pairing context */
            size_t ctx_bytes = blst_pairing_sizeof();
            void *ctx = malloc(ctx_bytes);
            if (!ctx) {
                fprintf(stderr, "malloc failed\n");
                res->fail++;
                continue;
            }
            blst_pairing_init(
                (blst_pairing *)ctx, true,
                (const byte *)dst, dst_len);

            bool agg_ok = true;
            for (int i = 0; i < n_pks; i++) {
                const char *pk_hex =
                    cJSON_GetArrayItem(pubkeys_arr, i)
                        ->valuestring;
                const char *msg_hex =
                    cJSON_GetArrayItem(messages_arr, i)
                        ->valuestring;

                uint8_t pk_buf[48];
                if (hex_decode(pk_hex, pk_buf, sizeof(pk_buf))
                    != 48) {
                    agg_ok = false;
                    break;
                }
                blst_p1_affine pk_a;
                if (blst_p1_uncompress(&pk_a, pk_buf)
                    != BLST_SUCCESS) {
                    agg_ok = false;
                    break;
                }
                if (blst_p1_affine_is_inf(&pk_a)) {
                    agg_ok = false;
                    break;
                }

                size_t mhex_len = strlen(msg_hex);
                size_t mlen = mhex_len / 2;
                uint8_t *mbuf = NULL;
                if (mlen > 0) {
                    mbuf = malloc(mlen);
                    if (hex_decode(msg_hex, mbuf, mlen) < 0) {
                        free(mbuf);
                        agg_ok = false;
                        break;
                    }
                }

                /* Pass sig on first pair, NULL on rest */
                BLST_ERROR err =
                    blst_pairing_chk_n_aggr_pk_in_g1(
                        (blst_pairing *)ctx,
                        &pk_a, true,
                        (i == 0) ? &sig_aff : NULL, (i == 0),
                        mbuf, mlen,
                        NULL, 0);
                free(mbuf);
                if (err != BLST_SUCCESS) {
                    agg_ok = false;
                    break;
                }
            }

            if (agg_ok) {
                blst_pairing_commit((blst_pairing *)ctx);
                verified = blst_pairing_finalverify(
                    (blst_pairing *)ctx, NULL);
            }
            free(ctx);

check_result:
            if (verified == expect_valid) {
                res->pass++;
            } else {
                fprintf(stderr,
                    "%s tcId=%d: expected %s got %s\n",
                    path, tcId,
                    expect_valid ? "valid" : "invalid",
                    verified ? "valid" : "invalid");
                res->fail++;
            }
        }
    }
    cJSON_Delete(root);
}

/* ------------------------------------------------------------------ */
/* Hash-to-G2 test                                                    */
/* ------------------------------------------------------------------ */

static void run_hash_to_g2(
    const char *path, results_t *res)
{
    char *data = read_file(path);
    if (!data) {
        fprintf(stderr, "Cannot open %s\n", path);
        res->fail++;
        return;
    }
    cJSON *root = cJSON_Parse(data);
    free(data);
    if (!root) {
        fprintf(stderr, "JSON parse error in %s\n", path);
        res->fail++;
        return;
    }

    cJSON *groups = cJSON_GetObjectItem(root, "testGroups");
    int ngroups = cJSON_GetArraySize(groups);

    for (int gi = 0; gi < ngroups; gi++) {
        cJSON *grp = cJSON_GetArrayItem(groups, gi);
        const char *dst_str =
            cJSON_GetObjectItem(grp, "dst")->valuestring;
        size_t dst_len = strlen(dst_str);

        cJSON *tests = cJSON_GetObjectItem(grp, "tests");
        int ntests = cJSON_GetArraySize(tests);

        for (int ti = 0; ti < ntests; ti++) {
            cJSON *tc = cJSON_GetArrayItem(tests, ti);
            int tcId = cJSON_GetObjectItem(tc, "tcId")->valueint;

            const char *msg_hex =
                cJSON_GetObjectItem(tc, "msg")->valuestring;
            const char *exp_hex =
                cJSON_GetObjectItem(tc, "expected")->valuestring;

            size_t msg_len = strlen(msg_hex) / 2;
            uint8_t *msg = NULL;
            if (msg_len > 0) {
                msg = malloc(msg_len);
                if (hex_decode(msg_hex, msg, msg_len) < 0) {
                    fprintf(stderr,
                        "%s tcId=%d: bad msg hex\n",
                        path, tcId);
                    res->fail++;
                    free(msg);
                    continue;
                }
            }

            uint8_t expected[96];
            if (hex_decode(exp_hex, expected, sizeof(expected))
                != 96) {
                fprintf(stderr,
                    "%s tcId=%d: bad expected hex\n",
                    path, tcId);
                res->fail++;
                free(msg);
                continue;
            }

            /* Hash to G2 */
            blst_p2 p2;
            blst_hash_to_g2(
                &p2,
                msg, msg_len,
                (const uint8_t *)dst_str, dst_len,
                NULL, 0);

            /* Convert to affine and compress */
            blst_p2_affine p2_aff;
            blst_p2_to_affine(&p2_aff, &p2);
            uint8_t compressed[96];
            blst_p2_affine_compress(compressed, &p2_aff);

            if (memcmp(compressed, expected, 96) == 0) {
                res->pass++;
            } else {
                fprintf(stderr,
                    "%s tcId=%d: hash-to-G2 mismatch\n",
                    path, tcId);
                res->fail++;
            }
            free(msg);
        }
    }
    cJSON_Delete(root);
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr,
            "Usage: %s <testvectors_v1_dir>\n", argv[0]);
        return 1;
    }

    const char *dir = argv[1];
    results_t res = {0, 0};

    /* Build paths */
    char path[4096];

    snprintf(path, sizeof(path),
        "%s/bls_sig_g2_basic_verify_test.json", dir);
    printf("Testing %s ...\n", path);
    run_sig_verify(path, &res);

    snprintf(path, sizeof(path),
        "%s/bls_sig_g2_pop_verify_test.json", dir);
    printf("Testing %s ...\n", path);
    run_sig_verify(path, &res);

    snprintf(path, sizeof(path),
        "%s/bls_sig_g2_aggregate_verify_test.json", dir);
    printf("Testing %s ...\n", path);
    run_aggregate_verify(path, &res);

    snprintf(path, sizeof(path),
        "%s/bls_hash_to_g2_test.json", dir);
    printf("Testing %s ...\n", path);
    run_hash_to_g2(path, &res);

    printf("\nResults: %d passed, %d failed\n",
        res.pass, res.fail);

    if (res.fail > 0) {
        printf("FAIL\n");
        return 1;
    }
    printf("PASS\n");
    return 0;
}
