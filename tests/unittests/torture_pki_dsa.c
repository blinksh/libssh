#include "config.h"

#define LIBSSH_STATIC

#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "torture.h"
#include "torture_key.h"
#include "torture_pki.h"
#include "pki.c"

#define LIBSSH_DSA_TESTKEY "libssh_testkey.id_dsa"
#define LIBSSH_DSA_TESTKEY_PASSPHRASE "libssh_testkey_passphrase.id_dsa"

const unsigned char DSA_HASH[] = "12345678901234567890";

static int setup_dsa_key(void **state)
{
    (void) state; /* unused */

    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY_PASSPHRASE);
    unlink(LIBSSH_DSA_TESTKEY ".pub");
    unlink(LIBSSH_DSA_TESTKEY "-cert.pub");

    torture_write_file(LIBSSH_DSA_TESTKEY,
                       torture_get_testkey(SSH_KEYTYPE_DSS, 0, 0));
    torture_write_file(LIBSSH_DSA_TESTKEY_PASSPHRASE,
                       torture_get_testkey(SSH_KEYTYPE_DSS, 0, 1));
    torture_write_file(LIBSSH_DSA_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_DSS, 0));
    torture_write_file(LIBSSH_DSA_TESTKEY "-cert.pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_DSS_CERT01, 0));

    return 0;
}

static int setup_openssh_dsa_key(void **state)
{
    (void) state; /* unused */

    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY_PASSPHRASE);
    unlink(LIBSSH_DSA_TESTKEY ".pub");
    unlink(LIBSSH_DSA_TESTKEY "-cert.pub");

    torture_write_file(LIBSSH_DSA_TESTKEY,
                       torture_get_openssh_testkey(SSH_KEYTYPE_DSS, 0, 0));
    torture_write_file(LIBSSH_DSA_TESTKEY_PASSPHRASE,
                       torture_get_openssh_testkey(SSH_KEYTYPE_DSS, 0, 1));
    torture_write_file(LIBSSH_DSA_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_DSS, 0));
    torture_write_file(LIBSSH_DSA_TESTKEY "-cert.pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_DSS_CERT01, 0));

    return 0;
}

static int teardown_dsa_key(void **state)
{
    (void)state;

    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY_PASSPHRASE);
    unlink(LIBSSH_DSA_TESTKEY ".pub");
    unlink(LIBSSH_DSA_TESTKEY "-cert.pub");

    return 0;
}

static void torture_pki_dsa_import_pubkey_file(void **state)
{
    ssh_key pubkey = NULL;
    int rc;

    (void)state;

    /* The key doesn't have the hostname as comment after the key */
    rc = ssh_pki_import_pubkey_file(LIBSSH_DSA_TESTKEY ".pub", &pubkey);
    assert_return_code(rc, errno);
    assert_non_null(pubkey);

    ssh_key_free(pubkey);
}

static void torture_pki_dsa_import_pubkey_from_openssh_privkey(void **state)
{
    ssh_key pubkey = NULL;
    int rc;

    (void)state;

    /* The key doesn't have the hostname as comment after the key */
    rc = ssh_pki_import_pubkey_file(LIBSSH_DSA_TESTKEY_PASSPHRASE, &pubkey);
    assert_return_code(rc, errno);
    assert_non_null(pubkey);

    ssh_key_free(pubkey);
}

static void torture_pki_dsa_import_privkey_base64(void **state)
{
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0, 0),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);

    ssh_key_free(key);
}

#ifdef HAVE_LIBCRYPTO
static void torture_pki_dsa_write_privkey(void **state)
{
    ssh_key origkey = NULL;
    ssh_key privkey = NULL;
    int rc;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);

    unlink(LIBSSH_DSA_TESTKEY);

    rc = ssh_pki_export_privkey_file(origkey,
                                     NULL,
                                     NULL,
                                     NULL,
                                     LIBSSH_DSA_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(origkey);
    ssh_key_free(privkey);

    /* Test with passphrase */
    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY_PASSPHRASE,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);

    unlink(LIBSSH_DSA_TESTKEY_PASSPHRASE);
    rc = ssh_pki_export_privkey_file(origkey,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     LIBSSH_DSA_TESTKEY_PASSPHRASE);
    assert_true(rc == 0);

    /* Test with invalid passphrase */
    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY_PASSPHRASE,
                                     "invalid secret",
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == SSH_ERROR);

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY_PASSPHRASE,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(origkey);
    ssh_key_free(privkey);
}
#endif

static void torture_pki_dsa_import_privkey_base64_passphrase(void **state)
{
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0, 1),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_return_code(rc, errno);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    ssh_key_free(key);
    key = NULL;

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0, 1),
                                       "wrong passphrase !!",
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);

    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
#ifndef HAVE_LIBCRYPTO
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0, 1),
                                       NULL,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
#endif

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0, 1),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_return_code(rc, errno);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    ssh_key_free(key);
    key = NULL;

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0, 1),
                                       "wrong passphrase !!",
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);

#ifndef HAVE_LIBCRYPTO
    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0, 1),
                                       NULL,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
#endif /* HAVE_LIBCRYPTO */
}

static void
torture_pki_dsa_import_openssh_privkey_base64_passphrase(void **state)
{
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();
    const char *keystring = NULL;

    (void) state; /* unused */

    keystring = torture_get_openssh_testkey(SSH_KEYTYPE_DSS, 0, 1);
    assert_true(keystring != NULL);

    rc = ssh_pki_import_privkey_base64(keystring,
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_return_code(rc, errno);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    ssh_key_free(key);
    key = NULL;

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(keystring,
                                       "wrong passphrase !!",
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);

    /* test if it returns -1 if passphrase is NULL */
    rc = ssh_pki_import_privkey_base64(keystring,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);

    rc = ssh_pki_import_privkey_base64(keystring,
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_return_code(rc, errno);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    ssh_key_free(key);
    key = NULL;

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(keystring,
                                       "wrong passphrase !!",
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);

    /* test if it returns -1 if passphrase is NULL */
    rc = ssh_pki_import_privkey_base64(keystring,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
}


static void torture_pki_dsa_publickey_from_privatekey(void **state)
{
    int rc;
    ssh_key key = NULL;
    ssh_key pubkey = NULL;
    const char *passphrase = NULL;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0, 0),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);

    ssh_key_free(key);
    ssh_key_free(pubkey);
}

static void torture_pki_dsa_import_cert_file(void **state)
{
    int rc;
    ssh_key cert = NULL;
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    rc = ssh_pki_import_cert_file(LIBSSH_DSA_TESTKEY "-cert.pub", &cert);
    assert_true(rc == 0);

    type = ssh_key_type(cert);
    assert_true(type == SSH_KEYTYPE_DSS_CERT01);

    rc = ssh_key_is_public(cert);
    assert_true(rc == 1);

    ssh_key_free(cert);
}

static void torture_pki_dsa_publickey_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key = NULL, *key_buf = NULL, *p = NULL;
    const char *str = NULL;
    ssh_key key = NULL;
    size_t keylen;
    size_t i;
    int rc;

    (void) state; /* unused */

    key_buf = strdup(torture_get_testkey_pub(SSH_KEYTYPE_DSS, 0));
    assert_true(key_buf != NULL);

    keylen = strlen(key_buf);

    str = p = key_buf;
    for (i = 0; i < keylen; i++) {
        if (isspace((int)p[i])) {
            p[i] = '\0';
            break;
        }

    }

    type = ssh_key_type_from_name(str);
    assert_true(type == SSH_KEYTYPE_DSS);

    str = &p[i + 1];

    for (; i < keylen; i++) {
        if (isspace((int)p[i])) {
            p[i] = '\0';
            break;
        }
    }

    rc = ssh_pki_import_pubkey_base64(str, type, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    assert_true(rc == 0);

    assert_string_equal(str, b64_key);

    free(b64_key);
    free(key_buf);
    ssh_key_free(key);
}

static void torture_pki_dsa_generate_pubkey_from_privkey(void **state)
{
    char pubkey_generated[4096] = {0};
    ssh_key privkey = NULL;
    ssh_key pubkey = NULL;
    int len;
    int rc;

    (void) state; /* unused */

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_DSA_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_DSA_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);

    len = torture_pubkey_len(torture_get_testkey_pub(SSH_KEYTYPE_DSS, 0));
    assert_memory_equal(torture_get_testkey_pub(SSH_KEYTYPE_DSS, 0),
                        pubkey_generated,
                        len);

    ssh_key_free(privkey);
    ssh_key_free(pubkey);
}

static void torture_pki_dsa_duplicate_key(void **state)
{
    int rc;
    char *b64_key = NULL;
    char *b64_key_gen = NULL;
    ssh_key pubkey = NULL;
    ssh_key privkey = NULL;
    ssh_key privkey_dup = NULL;

    (void) state;

    rc = ssh_pki_import_pubkey_file(LIBSSH_DSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key);
    assert_true(rc == 0);
    ssh_key_free(pubkey);

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    privkey_dup = ssh_key_dup(privkey);
    assert_true(privkey_dup != NULL);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key_gen);
    assert_true(rc == 0);

    assert_string_equal(b64_key, b64_key_gen);

    rc = ssh_key_cmp(privkey, privkey_dup, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(pubkey);
    ssh_key_free(privkey);
    ssh_key_free(privkey_dup);
    ssh_string_free_char(b64_key);
    ssh_string_free_char(b64_key_gen);
}

static void torture_pki_dsa_generate_key(void **state)
{
    int rc;
    ssh_key key = NULL;
    ssh_signature sign = NULL;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 1024, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, DSA_HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,DSA_HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 2048, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, DSA_HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,DSA_HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 3072, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, DSA_HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,DSA_HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_pki_dsa_import_pubkey_file,
                                 setup_dsa_key,
                                 teardown_dsa_key),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_import_pubkey_from_openssh_privkey,
                                 setup_openssh_dsa_key,
                                 teardown_dsa_key),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_import_privkey_base64,
                                 setup_dsa_key,
                                 teardown_dsa_key),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_import_privkey_base64,
                                 setup_openssh_dsa_key,
                                 teardown_dsa_key),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_publickey_from_privatekey,
                                 setup_dsa_key,
                                 teardown_dsa_key),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_import_cert_file,
                                        setup_dsa_key,
                                        teardown_dsa_key),
#ifdef HAVE_LIBCRYPTO
        cmocka_unit_test_setup_teardown(torture_pki_dsa_write_privkey,
                                 setup_dsa_key,
                                 teardown_dsa_key),
#endif
        cmocka_unit_test(torture_pki_dsa_import_privkey_base64_passphrase),
        cmocka_unit_test(torture_pki_dsa_import_openssh_privkey_base64_passphrase),

        /* public key */
        cmocka_unit_test_setup_teardown(torture_pki_dsa_publickey_base64,
                                 setup_dsa_key,
                                 teardown_dsa_key),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_generate_pubkey_from_privkey,
                                 setup_dsa_key,
                                 teardown_dsa_key),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_duplicate_key,
                                 setup_dsa_key,
                                 teardown_dsa_key),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_duplicate_key,
                                 setup_dsa_key,
                                 teardown_dsa_key),
        cmocka_unit_test(torture_pki_dsa_generate_key),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
