#include "canl_locl.h"
#include "canl_cred.h"
#include "canl_mech_ssl.h"
#include "scutils.h"

#define DEF_KEY_LEN 1024
#define DEF_KEY_LEN_LONGER 2048
#define LIFETIME_TRESHOLD 10*24*60*60 //10 days

static STACK_OF(X509)* my_sk_X509_dup(glb_ctx *cc, STACK_OF(X509) *stack);
extern int proxy_verify_cert_chain(X509 * ucert, STACK_OF(X509) * cert_chain, proxy_verify_desc * pvd);
extern proxy_verify_desc *pvd_setup_initializers(char *cadir, int flags);
extern void pvd_destroy_initializers(void *data);
extern canl_error map_verify_result(unsigned long ssl_err,
                const X509_STORE_CTX *store_ctx, SSL *ssl);

static STACK_OF(X509)* my_sk_X509_dup(glb_ctx *cc, STACK_OF(X509) *stack)
{
    int count = 0;
    X509 *cert_from_chain = NULL;
    STACK_OF(X509) *new_chain = NULL;
    int i = 0;
    
    if (!stack)
        return NULL;
    
    count = sk_X509_num(stack);
    if (!count)
        return NULL;

    new_chain = sk_X509_new_null();
    if (!new_chain)
        return NULL;

    for (i = 0; i < count; i++){
        cert_from_chain = sk_X509_value(stack, i);
        if (cert_from_chain) {
           sk_X509_push(new_chain, X509_dup(cert_from_chain));
        }
    }

    return new_chain;
}

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
    mech_glb_ctx *m_ctx = (mech_glb_ctx *)cc->mech_ctx;

    if (!ctx)
        return EINVAL;

    if (!m_ctx)
        return set_error(cc, EINVAL, POSIX_ERROR, "SSL context not"
                " initialized");

    if (!crd || !m_ctx->cert_key)
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
    
    if (!m_ctx->cert_key){
        m_ctx->cert_key = (cert_key_store *) calloc(1, 
                sizeof(*(m_ctx->cert_key)));
        if (!m_ctx->cert_key) {
            return set_error(cc, ENOMEM, POSIX_ERROR, "not enought memory"
                    " for the certificate storage");
        }
    }

    if (crd->c_key)
        pkey_dup(&m_ctx->cert_key->key, crd->c_key);

    if (crd->c_cert)
        m_ctx->cert_key->cert = X509_dup(crd->c_cert);
    if (crd->c_cert_chain)
        m_ctx->cert_key->chain = my_sk_X509_dup(cc, crd->c_cert_chain);
    return 0;
}

void pkey_dup(EVP_PKEY **to, EVP_PKEY *from)
{
    CRYPTO_add(&from->references,1,CRYPTO_LOCK_EVP_PKEY);
    *to = from;
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
canl_cred_save_priv_key(canl_ctx ctx, canl_cred cred, EVP_PKEY **pkey)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;
    int ret = 0;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
    if (!pkey)
        return set_error(cc, EINVAL, POSIX_ERROR, "Invalid private key"
                " parameter");
    pkey_dup(pkey, crd->c_key);

    return ret;
}

canl_err_code CANL_CALLCONV
canl_cred_load_priv_key(canl_ctx ctx, canl_cred cred, EVP_PKEY *pkey)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;
    int ret = 0;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
    if (!pkey)
        return set_error(cc, EINVAL, POSIX_ERROR, "Invalid private key"
                " parameter");
    pkey_dup(&crd->c_key, pkey);

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
    crd->c_cert_chain = my_sk_X509_dup(cc, cert_stack);
    if (!crd->c_cert_chain)
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
    if (!crd->c_cert)
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
    sk_X509_EXTENSION_push(crd->c_cert_ext, X509_EXTENSION_dup(cert_ext));
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
    int key_size = 0;

    if (!ctx)
        return EINVAL;

    if (!signer_crd)
        return set_error(cc, EINVAL, POSIX_ERROR, "Signer cred. handler"
                " not initialized" );
    if (!proxy_crd)
        return set_error(cc, EINVAL, POSIX_ERROR, "Proxy cred. handler"
                " not initialized" );

    if (proxy_crd->c_req) {
        EVP_PKEY *tmp_key = X509_REQ_get_pubkey(proxy_crd->c_req);
        if (!tmp_key)
            return set_error(cc, CANL_ERR_unknown, CANL_ERROR, "Cannot"
                    "extract key out of the certificate request" );
        key_size = EVP_PKEY_size(tmp_key);
        /*TODO free tmp_key? is it duplicate or poiter? */
        if ((proxy_crd->c_lifetime > LIFETIME_TRESHOLD) && 
                (key_size <= DEF_KEY_LEN_LONGER))
            return set_error(cc, CANL_ERR_unknown, CANL_ERROR, "Cannot" 
                    "sign cert. request -the key is too short with "
                   "respect to cert. lifetime");
    }

    /*TODO flags - limited,version*/
    err = proxy_sign(signer_crd->c_cert, signer_crd->c_key, proxy_crd->c_req,
            &proxy_crd->c_cert, proxy_crd->c_lifetime, 
            proxy_crd->c_cert_ext, 0, 2, NULL, NULL, 0, NULL, 0);
    if (err)
        return set_error(cc, CANL_ERR_unknown, CANL_ERROR, "");
        
    /*concatenate new chain*/
    if (signer_crd->c_cert_chain)
        proxy_crd->c_cert_chain = my_sk_X509_dup(cc, signer_crd->c_cert_chain);
    if (!proxy_crd->c_cert_chain)
       proxy_crd->c_cert_chain = sk_X509_new_null();
    sk_X509_push(proxy_crd->c_cert_chain, X509_dup(signer_crd->c_cert));
    
    return 0;
       
}

canl_err_code CANL_CALLCONV
canl_cred_save_proxyfile(canl_ctx ctx, canl_cred cred, const char *proxy_file)
{ 
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *crd = (creds*) cred;
    FILE *cert_file  = NULL;
    int ret = 0;
    int o_ret = 0;
    unsigned long ssl_err = 0;
    int n_certs = 0;
    int i = 0;
    X509 *cert_from_chain = NULL;
    int cert_in_chain = 0;

    if (!ctx)
        return EINVAL;

    if (!cred)
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
    if (!proxy_file)
        return set_error(cc, EINVAL, POSIX_ERROR, "Invalid proxy file name");

    /*posix compliant*/
    o_ret = open(proxy_file, O_CREAT | O_EXCL |O_WRONLY, S_IRUSR | S_IWUSR);
    if (o_ret == -1){
        ret = errno;
        set_error(cc, ret, POSIX_ERROR, "Cannot open file for writing");
    }
    else {
        ret = close(o_ret);
        if (ret == -1){
            ret = errno;
            set_error(cc, ret, POSIX_ERROR, "Cannot close file for writing");
            return ret;
        }
    }
    if (o_ret)
        cert_file = fopen(proxy_file, "wb");
    else
        cert_file = fopen(proxy_file, "ab");
    if (!cert_file) {
        ret = errno;
        set_error(cc, ret, POSIX_ERROR, "cannot open file for writing");
        return ret;
    }

    ERR_clear_error();

    /*new cert + priv key + chain
      if the new cert is empty, take it from the chain*/
    if (crd->c_cert){
        ret = PEM_write_X509(cert_file, crd->c_cert);
        if (!ret) {
            ssl_err = ERR_get_error();
            if (ssl_err)
                ret = set_error(cc, ssl_err, SSL_ERROR, "Error while writing"
                        " the certificate to the file");
            goto end;
        }
    }
    else if (crd->c_cert_chain){
        cert_from_chain = sk_X509_value(crd->c_cert_chain, 0);
        if (cert_from_chain) {
            ret = PEM_write_X509(cert_file, cert_from_chain);
            if (!ret) {
                ssl_err = ERR_get_error();
                if (ssl_err)
                    ret = set_error(cc, ssl_err, SSL_ERROR, "Error "
                            " while writing the certificate to the file");
                goto end;
            }
            cert_in_chain = 1;
        }
    }
    ret = PEM_write_PrivateKey(cert_file, crd->c_key, NULL, NULL, 0, 0, NULL);
    if (!ret) {
        ssl_err = ERR_get_error();
        ret = set_error(cc, ssl_err, SSL_ERROR, "Error while writing"
                " the key to the file");
        goto end;
    }

    n_certs = sk_X509_num(crd->c_cert_chain);
    for (i = cert_in_chain; i <  n_certs; i++){
        cert_from_chain = sk_X509_value(crd->c_cert_chain, i);
        if (cert_from_chain) {
            ret = PEM_write_X509(cert_file, cert_from_chain);
            if (!ret) {
                ssl_err = ERR_get_error();
                if (ssl_err)
                    ret = set_error(cc, ssl_err, SSL_ERROR, "Error "
                            " while writing the certificate to the file");
                goto end;
            }
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
        update_error(cc, ret, POSIX_ERROR, "cannot close file"
                " with certificate");
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
        *cert = NULL;
    }

    *cert = X509_dup(crd->c_cert);
    if (!(*cert))
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
    *cert_stack = my_sk_X509_dup(cc, crd->c_cert_chain);
    if (!(*cert_stack))
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
    int in_bits = DEF_KEY_LEN;

    if (!ctx)
        return EINVAL;   
    
    
    if (bits)
        in_bits = bits;
    /*set longer key if lifetime is long enough*/
    else if (crd_req->c_lifetime > LIFETIME_TRESHOLD)
        in_bits = DEF_KEY_LEN_LONGER;

    if (!ret_req)
        return set_error(cc, EINVAL, POSIX_ERROR, "Cred. handler"
                " not initialized" );
    
    if (crd_req->c_req) {
        X509_REQ_free(crd_req->c_req);
        crd_req->c_req = NULL;
    }

    /*TODO 1st NULL may invoke callback to ask user for new name*/
    ret = proxy_genreq(NULL, &crd_req->c_req, &crd_req->c_key, in_bits, 
            NULL, NULL);
    if (ret)
        return set_error(cc, CANL_ERR_unknown, CANL_ERROR, "Cannot make new"
                "proxy certificate");

    return 0;
}

canl_err_code CANL_CALLCONV
canl_cred_save_req(canl_ctx ctx, canl_cred req_in, X509_REQ ** req_ret)
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
    if (!(*req_ret))
        return set_error(cc, ENOMEM, POSIX_ERROR, "Cannot copy"
                " X509 request handler" ); //TODO check ret val
    return 0;
}

canl_err_code CANL_CALLCONV
canl_cred_load_req(canl_ctx ctx, canl_cred cred_out, const X509_REQ *req_in)
{
    glb_ctx *cc = (glb_ctx*) ctx;
    creds *req = (creds*) cred_out;

    if (!ctx)
        return EINVAL;
    if (!req)
        return set_error(cc, EINVAL, POSIX_ERROR, "Request handler"
                " not initialized" );
    if (!req_in)
        return set_error(cc, EINVAL, POSIX_ERROR, "Request handler"
                " not initialized" );
    if (req->c_req) {
        X509_REQ_free(req->c_req);
        req->c_req = NULL;
    }

    req->c_req = X509_REQ_dup(req_in);
    if (!req->c_req)
        return set_error(cc, ENOMEM, POSIX_ERROR, "Cannot copy"
                " X509 request handler" ); //TODO check ret val
    return 0;
}

canl_err_code CANL_CALLCONV
canl_verify_chain(canl_ctx ctx, X509 *ucert, STACK_OF(X509) *cert_chain,
        char *cadir)
{
    int ret = 0;
    proxy_verify_desc *pvd = NULL; /* verification context */

    pvd = pvd_setup_initializers(cadir, 0);
    ret = proxy_verify_cert_chain(ucert, cert_chain, pvd);
    pvd_destroy_initializers(pvd);
    if (ret)
        /* This will be ommited when proxy_verify_cert sets errors itself or
           propagate them out. */
        return set_error(ctx, CANL_ERR_unknown, CANL_ERROR, "Certificate chain"
                " validation failed"); // TODO error code check
    return 0;
}

canl_err_code CANL_CALLCONV
canl_verify_chain_wo_ossl(canl_ctx ctx, char *cadir,
	X509_STORE_CTX *store_ctx)
{
    int ret = 0, depth = 0, i = 0;
    STACK_OF(X509) *certstack;
    proxy_verify_desc *pvd = NULL; /* verification context */
    unsigned long ssl_err = 0;
    canl_error canl_err = 0;

    pvd = pvd_setup_initializers(cadir, 0);
    X509_STORE_CTX_set_ex_data(store_ctx, PVD_STORE_EX_DATA_IDX, (void *)pvd);
#ifdef X509_V_FLAG_ALLOW_PROXY_CERTS
    X509_STORE_CTX_set_flags(store_ctx, X509_V_FLAG_ALLOW_PROXY_CERTS);
#endif
    pvd_destroy_initializers(pvd);

    certstack = X509_STORE_CTX_get_chain(store_ctx);
    depth = sk_X509_num(certstack);
    /*TODO maybe free() certstack? is it refferenced? */

    ERR_clear_error();
    /* Go through the client cert chain and check it */
    for (i = depth - 1; i >= 0; i--){
        ret = proxy_verify_callback(1, store_ctx);
        if (!ret){
            /* Verification failed */
            ssl_err = ERR_get_error();
            canl_err = map_verify_result(ssl_err, store_ctx, NULL);
            if (canl_err)
                return set_error (ctx, canl_err, CANL_ERROR,
                        "Error during SSL handshake");
            else
                return set_error(ctx, ssl_err, SSL_ERROR,
                        "Error during SSL handshake");
        }
    }

    return 0;
}

proxy_verify_desc *pvd_setup_initializers(char *cadir, int pvxd_flags)
{
    proxy_verify_ctx_desc *pvxd = NULL;
    proxy_verify_desc *pvd = NULL;
    char *ca_cert_dirn = NULL;
    int err = 0;

    pvd  = (proxy_verify_desc*)     malloc(sizeof(proxy_verify_desc));
    pvxd = (proxy_verify_ctx_desc *)malloc(sizeof(proxy_verify_ctx_desc));
    pvd->cert_store = NULL;


    if (!pvd || !pvxd) {
        free(pvd);
        free(pvxd);
        return NULL;
    }

    proxy_verify_ctx_init(pvxd);
    proxy_verify_init(pvd, pvxd);

    /* If cadir is not specified, do the best as to get the 
       standard CA certificates directory name */
    if (!cadir){
        err = proxy_get_filenames(0, NULL, &ca_cert_dirn, NULL, NULL, NULL);
        if (!err){
            pvd->pvxd->certdir = ca_cert_dirn;
            return pvd;
        }
    }
    else
        pvd->pvxd->certdir = strdup(cadir);
    pvd->pvxd->flags |= pvxd_flags;
    return pvd;
}

void pvd_destroy_initializers(void *data)
{
    proxy_verify_desc *pvd = (proxy_verify_desc *)data;

    if (pvd) {
        if (pvd->pvxd)
            proxy_verify_ctx_release(pvd->pvxd);

        free(pvd->pvxd);
        pvd->pvxd = NULL;
        proxy_verify_release(pvd);

        /* X509_STORE_CTX_free segfaults if passed a NULL store_ctx */
        if (pvd->cert_store)
            X509_STORE_CTX_free(pvd->cert_store);
        pvd->cert_store = NULL;

        free(pvd);
    }
}

#if 0
canl_err_code CANL_CALLCONV
canl_req_get_pair(canl_ctx, canl_x509_req, EVP_PKEY **)
{
    return ENOSYS; 
}
#endif

canl_err_code CANL_CALLCONV
canl_cred_load_priv_key_pkcs11(canl_ctx ctx, canl_cred cred, const char *label,
			       canl_password_callback pass_clb, void *arg)
{
    int ret;
    creds *crd = (creds*) cred;
    unsigned long hSession;

    ret = sc_init(&hSession, NULL, NULL, NULL, CKU_USER, 0);
    if (ret)
	return set_error(ctx, EINVAL, POSIX_ERROR, "Failed to open session to smartcard");

    ret = sc_get_priv_key_obj_by_label(hSession, label, &crd->c_key);
    if (ret)
	return set_error(ctx, EINVAL, POSIX_ERROR, "Failed to locate private key for '%s' on smartcard",
			 label);

    return 0;
}

canl_err_code CANL_CALLCONV
canl_cred_load_cert_pkcs11(canl_ctx ctx, canl_cred cred, const char *label)
{
    int ret;
    creds *crd = (creds*) cred;
    unsigned long hSession;

    ret = sc_init(&hSession, NULL, NULL, NULL, CKU_USER, 0);
    if (ret)
	return set_error(ctx, EINVAL, POSIX_ERROR, "Failed to open session to smartcard");

    ret = sc_get_cert_obj_by_label(hSession, label, &crd->c_cert);
    if (ret)
	return set_error(ctx, EINVAL, POSIX_ERROR, "Failed to locate X.509 certificate for '%s' on smartcard",
			 label);

    return 0;
}
