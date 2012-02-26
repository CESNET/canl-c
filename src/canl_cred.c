#include "canl_locl.h"
#include "canl_cred.h"

static int pkey_dup(glb_ctx *cc, EVP_PKEY **to, EVP_PKEY *from);

canl_err_code CANL_CALLCONV
canl_cred_new(canl_ctx ctx, canl_cred * cred)
{
    glb_ctx *cc = ctx;
    creds *crd = NULL;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );

    /*create new cred. handler*/
    crd = (creds *) calloc(1, sizeof(*crd));
    if (!crd)
        return set_error(cc, ENOMEM, POSIX_ERROR, "Not enough memory");

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
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
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
        sk_X509_EXTENSION_pop_free(crd->c_cert_ext, X509_EXTENSION_free);
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
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;
    int ret = 0;

    if (!ctx)
        return EINVAL;
    if (!crd || !cc->cert_key)
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
    
    if (!cc->cert_key){
        cc->cert_key = (cert_key_store *) calloc(1, sizeof(*(cc->cert_key)));
        if (!cc->cert_key) {
            return set_error(cc, ENOMEM, POSIX_ERROR, "not enought memory"
                    " for the certificate storage");
        }
    }

    if (crd->c_key) {
        if ((ret = pkey_dup(cc, &cc->cert_key->key, crd->c_key))) {
            return ret;
        }
    }

    if (crd->c_cert)
        cc->cert_key->cert = X509_dup(crd->c_cert);
    if (crd->c_cert_chain)
        cc->cert_key->chain = sk_X509_dup(crd->c_cert_chain);
    return 0;
}

static int pkey_dup(glb_ctx *cc, EVP_PKEY **to, EVP_PKEY *from)
{
    CRYPTO_add(&from->references,1,CRYPTO_LOCK_EVP_PKEY);
    *to = from;
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
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
    if (!pkey_file)
        return set_error(cc, EINVAL, POSIX_ERROR, "Invalid filename");

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
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
  
    if (!cert_stack)
        return set_error(cc, EINVAL, POSIX_ERROR, "Invalid stack value");

    count = sk_X509_num(cert_stack);
    if (!count)
        return 0; //TODO is empty cert_stack error?
    
    if (crd->c_cert_chain) {
        sk_X509_pop_free(crd->c_cert_chain, X509_free);
        crd->c_cert_chain = NULL;
    }
    crd->c_cert_chain = sk_X509_dup(cert_stack);
    if (crd->c_cert_chain)
        return set_error(cc, ENOMEM, POSIX_ERROR, "Cannot copy"
                " certificate chain" ); //TODO check ret val
    return 0;
}

canl_err_code CANL_CALLCONV
canl_cred_load_chain_file(canl_ctx ctx, canl_cred cred, const char *chain_file)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
  
    if (!chain_file)
        return set_error(cc, EINVAL, POSIX_ERROR, "Invalid chain filename");

    if (crd->c_cert_chain) {
        sk_X509_pop_free(crd->c_cert_chain, X509_free);
        crd->c_cert_chain = NULL;
    }
    else
        crd->c_cert_chain = sk_X509_new_null();

    return set_cert_chain_file(cc, &crd->c_cert_chain, chain_file);
}

    canl_err_code CANL_CALLCONV
canl_cred_load_cert(canl_ctx ctx, canl_cred cred, X509 *cert)
{ 
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
  
    if (!cert)
        return set_error(cc, EINVAL, POSIX_ERROR, "Invalid cert. file name");

    if (crd->c_cert) {
        X509_free(crd->c_cert);
        crd->c_cert = NULL;
    }

    crd->c_cert = X509_dup(cert);
    if (crd->c_cert)
        return set_error(cc, ENOMEM, POSIX_ERROR, "Cannot copy"
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
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
    if (!cert_file)
        return set_error(cc, EINVAL, POSIX_ERROR, "Invalid filename");

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
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
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
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" ); 

    if (!crd->c_cert_ext)
       crd->c_cert_ext = sk_X509_EXTENSION_new_null();
    sk_X509_EXTENSION_push(crd->c_cert_ext, cert_ext);
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
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
    crd->c_type = cert_type;
    return 0;
}

/*TODO use flags*/
canl_err_code CANL_CALLCONV
canl_cred_sign_proxy(canl_ctx ctx, canl_cred signer_cred, canl_cred proxy_cred)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *signer_crd = (creds*) signer_cred;
    creds *proxy_crd = (creds*) proxy_cred;
    int err = 0;

    if (!ctx)
        return EINVAL;

    if (!signer_crd)
        return set_error(cc, EINVAL, POSIX_ERROR, "Signer cred. handler"
                " not initialized" );
    if (!proxy_crd)
        return set_error(cc, EINVAL, POSIX_ERROR, "Proxy cred. handler"
                " not initialized" );
    /*TODO flags - limited,version*/
    err = proxy_sign(signer_crd->c_cert, signer_crd->c_key, proxy_crd->c_req,
            &proxy_crd->c_cert, proxy_crd->c_lifetime, 
            proxy_crd->c_cert_ext, 0, 2, NULL, NULL, 0, NULL, 0);
    if (err)
        return set_error(cc, CANL_ERR_unknown, CANL_ERROR, "");
        
    /*concatenate new chain*/
    if (signer_crd->c_cert_chain)
        proxy_crd->c_cert_chain = sk_X509_dup(signer_crd->c_cert_chain);
    if (!proxy_crd->c_cert_chain)
       proxy_crd->c_cert_chain = sk_X509_new_null();
    sk_X509_push(proxy_crd->c_cert_chain, signer_crd->c_cert);
    
    return 0;
       
}

canl_err_code CANL_CALLCONV
canl_cred_save_proxyfile(canl_ctx ctx, canl_cred cred, const char *proxy_file)
{ 
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;
    FILE *cert_file  = NULL;
    int ret = 0;
    unsigned long ssl_err = 0;
    X509 *cert_from_chain = NULL;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
    if (!proxy_file)
        return set_error(cc, EINVAL, POSIX_ERROR, "Invalid proxy file name");

    /*posix compliant*/
    ret = open(proxy_file, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if (ret == -1){
        ret = errno;
        set_error(cc, ret, POSIX_ERROR, "Cannot open file for writing");
        return ret;
    }
    close(ret);
    if (ret == -1){
        ret = errno;
        set_error(cc, ret, POSIX_ERROR, "Cannot open file for writing");
        return ret;
    }

    cert_file = fopen(proxy_file, "ab");
    if (!cert_file) {
        ret = errno;
        set_error(cc, ret, POSIX_ERROR, "cannot open file for writing");
        return ret;
    }
    
    ERR_clear_error();

    /*new cert + priv key + chain*/
    ret = PEM_write_X509(cert_file, crd->c_cert);
    if (!ret) {
        ssl_err = ERR_get_error();
        ret = set_error(cc, ssl_err, SSL_ERROR, "Error while writing"
               " the certificate to the file");
        goto end;
    }
    ret = PEM_write_PrivateKey(cert_file, crd->c_key, NULL, NULL, 0, 0, NULL);
    if (!ret) {
        ssl_err = ERR_get_error();
        ret = set_error(cc, ssl_err, SSL_ERROR, "Error while writing"
                " the key to the file");
        goto end;
    }

    while ((cert_from_chain = sk_X509_pop(crd->c_cert_chain)) != NULL) {
        ret = PEM_write_X509(cert_file, cert_from_chain);
        if (!ret) {
            ssl_err = ERR_get_error();
            ret = set_error(cc, ssl_err, SSL_ERROR, "Error while writing"
                    " the certificate to the file");
            goto end;
        }
    }


    if (fclose(cert_file)){
        ret = errno;
        set_error(cc, ret, POSIX_ERROR, "cannot close file with certificate");
        return errno;
    }

    return 0;

end:
    if (fclose(cert_file)){
        ret = errno;
        update_error(cc, ret, POSIX_ERROR, "cannot close file with certificate");
        return errno;
    }

    return ret;

}

canl_err_code CANL_CALLCONV
canl_cred_save_cert(canl_ctx ctx, canl_cred cred, X509 ** cert)
{ 
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
    if (!cert)
        return set_error(cc, EINVAL, POSIX_ERROR, "Invalid cert."
                " handler");
 
    if (*cert) {
        X509_free(*cert);
        *cert = NULL;
    }

    *cert = X509_dup(crd->c_cert);
    if (*cert)
        return set_error(cc, ENOMEM, POSIX_ERROR, "Cannot copy"
                " certificate" ); //TODO check ret val
 
    return 0; 
}

canl_err_code CANL_CALLCONV
canl_cred_save_chain(canl_ctx ctx, canl_cred cred, STACK_OF(X509) **cert_stack)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;
    int count = 0;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
  
    if (!cert_stack)
        return set_error(cc, EINVAL, POSIX_ERROR, "Invalid stack value");

    if (!crd->c_cert_chain)
        return 0; //TODO is empty cert_stack error?

    count = sk_X509_num(crd->c_cert_chain);
    if (!count)
        return 0; //TODO is empty cert_stack error?
    
    if (*cert_stack) {
        sk_X509_pop_free(*cert_stack, X509_free);
        *cert_stack = NULL;
    }
    *cert_stack = sk_X509_dup(crd->c_cert_chain);
    if (*cert_stack)
        return set_error(cc, ENOMEM, POSIX_ERROR, "Cannot copy"
                " certificate chain" ); //TODO check ret val
    return 0;
}

/* handle requests*/
canl_err_code CANL_CALLCONV
canl_cred_new_req(canl_ctx ctx, canl_cred ret_req, unsigned int bits)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd_req = (creds*) ret_req;
    int ret = 0;

    if (!ctx)
        return EINVAL;

    if (!ret_req)
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
    
    if (crd_req->c_req) {
        X509_REQ_free(crd_req->c_req);
        crd_req->c_req = NULL;
    }

    /*TODO 1st NULL may invoke callback to ask user for new name*/
    ret = proxy_genreq(NULL, &crd_req->c_req, &crd_req->c_key, bits, NULL, NULL);
    if (ret)
        return set_error(cc, CANL_ERR_unknown, CANL_ERROR, "Cannot make new"
                "proxy certificate");

    return 0;
}

canl_err_code CANL_CALLCONV
canl_req_get_req(canl_ctx ctx, canl_cred req_in, X509_REQ ** req_ret)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *req = (creds*) req_in;

    if (!ctx)
        return EINVAL;
    if (!req || !req->c_req)
        return set_error(cc, EINVAL, POSIX_ERROR, "Request handler"
                " not initialized" );
    if (!req_ret)
        return set_error(cc, EINVAL, POSIX_ERROR, "Request handler"
                " not initialized" );

    /*TODO free REQ if req_ret full*/
    *req_ret = X509_REQ_dup(req->c_req);
    if (*req_ret)
        return set_error(cc, ENOMEM, POSIX_ERROR, "Cannot copy"
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

