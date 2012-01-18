#include "canl_locl.h"
#include "canl_cred.h"

canl_err_code CANL_CALLCONV
canl_cred_new(canl_ctx ctx, canl_cred * cred)
{
    glb_ctx *cc = ctx;
    creds *crd = NULL;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, posix_error, "Cred. handler"
                " not initialized" );

    /*create new cred. handler*/
    crd = (creds *) calloc(1, sizeof(*crd));
    if (crd)
        return set_error(cc, ENOMEM, posix_error, "Not enough memory");

    return 0;
}

canl_err_code CANL_CALLCONV
canl_cred_free(canl_ctx ctx, canl_cred cred)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, posix_error, "Cred. handler"
                " not initialized" );

    /* Delete contents*/
    if (crd->c_key) {
        EVP_PKEY_free(crd->c_key);
        crd->c_key = NULL;
    }
    if (crd->c_cert) {
        X509_free(crd->c_cert);
        crd->c_cert = NULL;
    }
    if (crd->c_cert_ext) {
        X509_EXTENSION_free(crd->c_cert_ext);
        crd->c_cert_ext = NULL;
    }
    if (crd->c_cert_chain) {
        sk_X509_pop_free(crd->c_cert_chain, X509_free);
        crd->c_cert_chain = NULL;
    }
    if (crd->c_req) {
        X509_REQ_free(crd->c_req);
        crd->c_req = NULL;
    }

    free (crd);
    crd = NULL;

    return 0;
}

canl_err_code CANL_CALLCONV
canl_ctx_set_cred(canl_ctx ctx, canl_cred cred)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_cred_load_req(canl_ctx ctx, canl_cred cred, canl_x509_req req)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_cred_load_priv_key_file(canl_ctx ctx, canl_cred cred, const char * pkey_file,
			     canl_password_callback pass_clb, void * arg)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_cred_load_chain(canl_ctx ctx, canl_cred cred, STACK_OF(X509) *cert_stack)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_cred_load_chain_file(canl_ctx ctx, canl_cred cred, const char *chain_file)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_cred_load_cert(canl_ctx ctx, canl_cred cred, X509 *cert)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_cred_load_cert_file(canl_ctx ctx, canl_cred cred, const char * cert_file)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_cred_set_lifetime(canl_ctx ctx, canl_cred cred, long lifetime)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_cred_set_extension(canl_ctx ctx, canl_cred cred, X509_EXTENSION *cert_ext)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_cred_set_cert_type(canl_ctx ctx, canl_cred cred, enum canl_cert_type cert_type)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_cred_sign_proxy(canl_ctx ctx, canl_cred signer_cred, canl_cred proxy_cred)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_cred_save_proxyfile(canl_ctx ctx, canl_cred cred, const char *proxy_file)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_cred_save_cert(canl_ctx ctx, canl_cred cred, X509 ** cert)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_cred_save_chain(canl_ctx ctx, canl_cred cred, STACK_OF(X509) **cert_stack)
{
    return ENOSYS; 
}

/* handle requests*/
canl_err_code CANL_CALLCONV
canl_req_create(canl_ctx ctx, canl_x509_req *c_req)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_req_create_req(canl_ctx ctx, canl_x509_req *c_req, X509_REQ *req)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_req_free(canl_ctx ctx, canl_x509_req c_req)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_req_gen_key(canl_ctx ctx, canl_x509_req c_req, unsigned int bits)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_req_get_req(canl_ctx ctx, canl_x509_req c_req, X509_REQ ** req_stack)
{
    return ENOSYS; 
}

#if 0
canl_err_code CANL_CALLCONV
canl_req_get_pair(canl_ctx, canl_x509_req, EVP_PKEY **)
{
    return ENOSYS; 
}
#endif

