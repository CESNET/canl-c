#include "canl_locl.h"

#if 0
static int set_cert(glb_ctx *cc, X509 *cert);
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
        set_error(cc, err, err_orig, "cannot get certificate");
    return err;
}
#endif

//TODO cert
int do_set_ctx_own_cert_file(glb_ctx *cc, char *cert, char *key)
{
    int err = 0;

    if (!cc->cert_key){
        cc->cert_key = (cert_key_store *) calloc(1, sizeof(*(cc->cert_key)));
        if (!cc->cert_key) {
            return set_error(cc, ENOMEM, POSIX_ERROR, "not enought memory"
                    " for the certificate storage"); 
        }
    }

    if (key) {
        err = set_key_file(cc, &cc->cert_key->key, key);
        if (err)
            return err;
    }

    if (cert) {
        err = set_cert_file(cc, &cc->cert_key->cert, cert);
        if (err)
            return err;
    }
    return 0;
}

int set_key_file(glb_ctx *cc, EVP_PKEY **to, const char *key)
{
    unsigned long ssl_err = 0;
    int err = 0;
    FILE * key_file = NULL;

    if (*to) {
        EVP_PKEY_free(*to);
        *to = NULL;
    }
    key_file = fopen(key, "rb");
    if (!key_file) {
        err = errno;
        set_error(cc, err, POSIX_ERROR, "cannot open file with key");
        return err;
    }

    ERR_clear_error();

    /*TODO NULL NULL, callback and user data*/
    *to = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    if (!(*to)) {
        ssl_err = ERR_peek_error();
        err = set_error(cc, ssl_err, SSL_ERROR, "error while writing key to context");
        goto end;
    }
    if (fclose(key_file)){
        err = errno;
        set_error(cc, err, POSIX_ERROR, "cannot close file with key");
        return errno;
    }
    return 0;

end:
    if (fclose(key_file)){
        err = errno;
        update_error(cc, errno, POSIX_ERROR, "cannot close file with key");
    }
    return err;
}

int set_cert_file(glb_ctx *cc, X509 **to, const char *cert)
{
    unsigned long ssl_err = 0;
    int err = 0;
    FILE * cert_file = NULL;


    if (*to) {
        X509_free(*to);
        *to = NULL;
    }
    cert_file = fopen(cert, "rb");
    if (!cert_file) {
       err = errno;
        set_error(cc, err, POSIX_ERROR, "cannot open file with cert");
        return err;
    }
    
    ERR_clear_error();
    /*TODO NULL NULL, callback and user data*/
    *to = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (!(*to)) {
        ssl_err = ERR_get_error();
        err = set_error(cc, ssl_err, SSL_ERROR, "error while writing certificate"
                " to context"); 
        goto end;
    }

    if (fclose(cert_file)){
        err = errno;
        set_error(cc, err, POSIX_ERROR, "cannot close file with certificate");
        return errno;
    }
    return 0;

end:
    if (fclose(cert_file)){
        err = errno;
        update_error(cc, errno, POSIX_ERROR, "cannot close file with certificate");
    }
    return err;
}

int set_cert_chain_file(glb_ctx *cc, STACK_OF(X509) **to, const char *file)
{
    unsigned long ssl_err = 0;
    FILE * cert_file = NULL;
    int count = 0;
    int ret = -1;
    X509 *x = NULL;

    if (file == NULL)
        return set_error(cc, EINVAL, POSIX_ERROR, "Cert. chain file"
                "does not exist");

    if (*to) {
        sk_X509_pop_free(*to, X509_free);
        *to = NULL;
    }

    cert_file = fopen(file, "rb");
    if (!cert_file)
        return set_error(cc, errno, POSIX_ERROR, "Cannot "
                "open file with cert. chain");

    for (;;)
    {
        /* TODO maybe callback can be specified*/
        x = PEM_read_X509(cert_file,NULL, NULL, NULL);
        if (x == NULL)
        {
            ssl_err = ERR_peek_error();
            if ((ERR_GET_REASON(ssl_err) ==
                        PEM_R_NO_START_LINE)) {
                /*everything OK*/
                if ((count > 0)) {
                    ERR_clear_error();
                    break;
                }
                else {
                    ret = set_error(cc, ssl_err, SSL_ERROR, "Cannot get"
                            "certificate out of file");
                    goto end;
                }
            }
        }

        (void)sk_X509_insert(*to, x, sk_X509_num(*to));
        x = NULL;
        count++;
    }
    return 0;

end:
    if (fclose(cert_file)){
        ret = errno;
        return update_error(cc, errno, POSIX_ERROR, "cannot close file with"
                " the certificate");
    }
    return ret;
}
