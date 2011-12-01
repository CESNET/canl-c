#include "canl_locl.h"
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
    CANL_ERROR_ORIGIN err_orig;
    
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

//int authn_set_ctx_own_cert_file(auth_ctx ac, char *cert, char *key, authn_password_callback cb, void *userdata);
