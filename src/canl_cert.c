#include "canl_locl.h"
static int set_cert(glb_ctx *cc, X509 *cert);
static int set_key_file(glb_ctx *cc, char *key);
static int set_cert_file(glb_ctx *cc, char *cert);

//TODO just stub
int do_set_ctx_own_cert(glb_ctx *cc, canl_x509 cert, canl_stack_of_x509 chain, 
        canl_pkey key)
{
    int err = 0;
    X509 *l_cert = (X509 *) cert;
    STACK_OF(X509*) *l_chain = (STACK_OF(X509*)*) chain;
    EVP_PKEY *l_key = (EVP_PKEY *)key;

/*    if (cert)
        set_cert(l_cert);
        cert
    if (chain)
        is_chain = 1;
    if (key)
        is_key = 1;
    if (!cc->cert_key){
        cc->cert_key = (cert_key_store *) calloc(1, sizeof(*(cc->cert_key)));
        if (!cc->cert_key) {
            err = ENOMEM;
            goto end;
        }
    }

    if (!cc->cert_key->cert) {
    }
*/
    return 0;
}

static int set_cert(glb_ctx *cc, X509 *cert)
{
    int err = 0;
    CANL_ERROR_ORIGIN err_orig = 0;
    
    if (cc->cert_key->cert) {
        free(cc->cert_key->cert);
        cc->cert_key->cert = NULL;
    }
    cc->cert_key->cert = (X509 *) malloc (sizeof(X509));
    if (!cc->cert_key->cert) {
        err = ENOMEM;
        goto end;
    }

end:
    if (err)
        set_error(cc, err, err_orig, "cannot get certificate (set_cert)");
    return err;
}

//TODO cert
int do_set_ctx_own_cert_file(glb_ctx *cc, char *cert, char *key)
{
    int err = 0;
    /* otherwise the private key is in cert file*/
    if (key) {
        err = set_key_file(cc, key);
        if (err)
            return err;
    }

    if (cert) {
        err = set_cert_file(cc, cert);
        if (err)
            return err;
    }
    return 0;
}

static int set_key_file(glb_ctx *cc, char *key)
{
    unsigned long ssl_err = 0;
    int err = 0;
    FILE * key_file = NULL;

    if (!cc->cert_key){
        cc->cert_key = (cert_key_store *) calloc(1, sizeof(*(cc->cert_key)));
        if (!cc->cert_key) {
            err = ENOMEM;
            set_error(cc, err, posix_error, "not enought memory for the"
                    " certificate storage (set_key_file)");
            return ENOMEM;
        }
    }

    if (cc->cert_key->key) {
        EVP_PKEY_free(cc->cert_key->key);
        cc->cert_key->key = NULL;
    }
    key_file = fopen(key, "rb");
    if (!key_file) {
       err = errno;
        set_error(cc, err, posix_error, "cannot open file with key"
                " (set_key_file)");
        return err;
    }

    ERR_clear_error();

    /*TODO NULL NULL, callback and user data*/
    cc->cert_key->key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    if (!cc->cert_key->key) {
        ssl_err = ERR_peek_error();
        set_error(cc, ssl_err, ssl_error, "error while writing key to context"
                " (set_key_file)");
        goto end;
    }
    if (fclose(key_file)){
        err = errno;
        set_error(cc, err, posix_error, "cannot close file with key"
                " (set_key_file)");
        return errno;
    }
    return 0;

end:
    if (fclose(key_file)){
        err = errno;
        update_error(cc, "cannot close file with key"
                " (set_key_file)");
    }
    return 1;
}

static int set_cert_file(glb_ctx *cc, char *cert)
{
    unsigned long ssl_err = 0;
    int err = 0;
    FILE * cert_file = NULL;

    if (!cc->cert_key){
        cc->cert_key = (cert_key_store *) calloc(1, sizeof(*(cc->cert_key)));
        if (!cc->cert_key) {
            err = ENOMEM;
            set_error(cc, err, posix_error, "not enought memory for the"
                    " certificate storage (set_cert_file)");
            return ENOMEM;
        }
    }

    if (cc->cert_key->cert) {
        X509_free(cc->cert_key->cert);
        cc->cert_key->cert = NULL;
    }
    cert_file = fopen(cert, "rb");
    if (!cert_file) {
       err = errno;
        set_error(cc, err, posix_error, "cannot open file with cert"
                " (set_cert_file)");
        return err;
    }
    
    ERR_clear_error();
    /*TODO NULL NULL, callback and user data*/
    cc->cert_key->cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (!cc->cert_key->cert) {
        ssl_err = ERR_get_error();
        set_error(cc, ssl_err, ssl_error, "error while writing certificate"
                " to context (set_cert_file)");
        goto end;
    }

    if (fclose(cert_file)){
        err = errno;
        set_error(cc, err, posix_error, "cannot close file with certificate"
                " (set_cert_file)");
        return errno;
    }
    return 0;

end:
    if (fclose(cert_file)){
        err = errno;
        update_error(cc, "cannot close file with certificate"
                " (set_cert_file)");
    }
    return 1;
}
