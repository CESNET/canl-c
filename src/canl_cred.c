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
    if (!crd)
        return set_error(cc, ENOMEM, posix_error, "Not enough memory");

    *cred = crd;
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
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;
    request *rqst = (request *) req;
    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, posix_error, "Cred. handler"
                " not initialized" );
    if (!rqst || rqst->c_req)
        return set_error(cc, EINVAL, posix_error, "Cred. handler"
                " not initialized" );

    if (crd->c_req) {
        X509_REQ_free(crd->c_req);
        crd->c_req = NULL;
    }

    crd->c_req = X509_REQ_dup(rqst->c_req);
    if (!crd->c_req)
        return set_error(cc, ENOMEM, posix_error, "Cannot copy"
                " X509 request handler" ); //TODO check ret val

    return 0;    
}

canl_err_code CANL_CALLCONV
canl_cred_load_priv_key_file(canl_ctx ctx, canl_cred cred, const char *pkey_file,
        canl_password_callback pass_clb, void *arg)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;
    int ret = 0;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, posix_error, "Cred. handler"
                " not initialized" );
    if (!pkey_file)
        return set_error(cc, EINVAL, posix_error, "Invalid filename");

    ret = set_key_file(cc, &crd->c_key, pkey_file);

    return ret;
}

canl_err_code CANL_CALLCONV
canl_cred_load_chain(canl_ctx ctx, canl_cred cred, STACK_OF(X509) *cert_stack)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;
    int count = 0;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, posix_error, "Cred. handler"
                " not initialized" );
  
    if (!cert_stack)
        return set_error(cc, EINVAL, posix_error, "Invalid stack value");

    count = sk_X509_num(cert_stack);
    if (!count)
        return 0; //TODO is empty cert_stack error?
    
    if (crd->c_cert_chain) {
        sk_X509_pop_free(crd->c_cert_chain, X509_free);
        crd->c_cert_chain = NULL;
    }
    crd->c_cert_chain = sk_X509_dup(cert_stack);
    if (crd->c_cert_chain)
        return set_error(cc, ENOMEM, posix_error, "Cannot copy"
                " certificate chain" ); //TODO check ret val
    return 0;
}

canl_err_code CANL_CALLCONV
canl_cred_load_chain_file(canl_ctx ctx, canl_cred cred, const char *chain_file)
{
    return ENOSYS; 
}

canl_err_code CANL_CALLCONV
canl_cred_load_cert(canl_ctx ctx, canl_cred cred, X509 *cert)
{ 
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, posix_error, "Cred. handler"
                " not initialized" );
  
    if (!cert)
        return set_error(cc, EINVAL, posix_error, "Invalid cert. file name");

    if (crd->c_cert) {
        X509_free(crd->c_cert);
        crd->c_cert = NULL;
    }

    crd->c_cert = X509_dup(cert);
    if (crd->c_cert)
        return set_error(cc, ENOMEM, posix_error, "Cannot copy"
                " certificate" ); //TODO check ret val
    return 0;
}

canl_err_code CANL_CALLCONV
canl_cred_load_cert_file(canl_ctx ctx, canl_cred cred, const char *cert_file)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;
    int ret = 0;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, posix_error, "Cred. handler"
                " not initialized" );
    if (!cert_file)
        return set_error(cc, EINVAL, posix_error, "Invalid filename");

    ret = set_cert_file(cc, &crd->c_cert, cert_file);

    return ret;
}

canl_err_code CANL_CALLCONV
canl_cred_set_lifetime(canl_ctx ctx, canl_cred cred, const long lifetime)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, posix_error, "Cred. handler"
                " not initialized" );
    crd->c_lifetime = lifetime;
    return 0;
}

/*TODO rather use STACK_OF(X509_EXTENSION) ???*/
canl_err_code CANL_CALLCONV
canl_cred_set_extension(canl_ctx ctx, canl_cred cred, X509_EXTENSION *cert_ext)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, posix_error, "Cred. handler"
                " not initialized" );
    
    if (crd->c_cert_ext) {
        X509_EXTENSION_free(crd->c_cert_ext);
        crd->c_cert_ext = NULL;
    }
    
    crd->c_cert_ext = X509_EXTENSION_dup(cert_ext);
    return 0;
}

canl_err_code CANL_CALLCONV
canl_cred_set_cert_type(canl_ctx ctx, canl_cred cred, 
        const enum canl_cert_type cert_type)
{    
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, posix_error, "Cred. handler"
                " not initialized" );
    crd->c_type = cert_type;
    return 0;
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
canl_req_create(canl_ctx ctx, canl_x509_req *ret_req, unsigned int bits)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    request *req = NULL;
    int ret = 0;

    if (!ctx)
        return EINVAL;

    if (!ret_req)
        return set_error(cc, EINVAL, posix_error, "Cred. handler"
                " not initialized" );

    /*create new cred. handler*/
    req = (request *) calloc(1, sizeof(*req));
    if (!req)
        return set_error(cc, ENOMEM, posix_error, "Not enough memory");

    /*TODO 1st NULL may invoke callback to ask user for new name*/
    ret = proxy_genreq(NULL,&req->c_req, &req->c_key, bits, NULL, NULL);
    if (ret)
        
    *ret_req = req;

    return 0;
}

canl_err_code CANL_CALLCONV
canl_req_free(canl_ctx ctx, canl_x509_req c_req)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    request *req = (request*) c_req;

    if (!ctx)
        return EINVAL;

    if (!c_req)
        return set_error(cc, EINVAL, posix_error, "Request handler"
                " not initialized" );

    /* Delete contents*/
    if (req->c_key) {
        EVP_PKEY_free(req->c_key);
        req->c_key = NULL;
    }
    if (req->c_req) {
        X509_REQ_free(req->c_req);
        req->c_req = NULL;
    }

    free (req);
    req = NULL;

    return 0;


}

canl_err_code CANL_CALLCONV
canl_req_get_req(canl_ctx ctx, canl_x509_req req_in, X509_REQ ** req_ret)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    request *req = (request*) req_in;

    if (!ctx)
        return EINVAL;
    if (!req || !req->c_req)
        return set_error(cc, EINVAL, posix_error, "Request handler"
                " not initialized" );
    if (!req_ret)
        return set_error(cc, EINVAL, posix_error, "Request handler"
                " not initialized" );
    
    *req_ret = X509_REQ_dup(req->c_req);
    if (*req_ret)
        return set_error(cc, ENOMEM, posix_error, "Cannot copy"
                " X509 request handler" ); //TODO check ret val
    return 0;
}

#if 0
canl_err_code CANL_CALLCONV
canl_req_get_pair(canl_ctx, canl_x509_req, EVP_PKEY **)
{
    return ENOSYS; 
}
#endif

