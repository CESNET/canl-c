#include <canl.h>
#include <canl_cred.h>

int
main(int argc, char *argv[])
{
    canl_cred signer = NULL;
    canl_cred proxy = NULL;
    canl_cred proxy_cert = NULL;
    canl_x509_req proxy_req = NULL;
    X509_REQ *req = NULL;
    X509 *x509_cert = NULL;
    STACK_OF(X509) *x509_chain= NULL;
    canl_ctx ctx = NULL;
    canl_err_code ret;

    ctx = canl_create_ctx();

/* Bob - after Alice has asked to delegate her credentials */
    ret = canl_req_new(ctx, &proxy_req);
    ret = canl_req_gen_key(ctx, proxy_req, 1024);
    ret = canl_req_get_req(ctx, proxy_req, &req);

    /* serialize 'req' and send it to Alice */

/* Alice - after receiving the CSR from Bob. (The private key stays with Bob.) */
    {
	ret = canl_cred_new(ctx, &signer);
	ret = canl_cred_load_cert_file(ctx, signer, "$HOME/.globus/usercert.pem");
	ret = canl_cred_load_priv_key_file(ctx, signer, "$HOME/.globus/userkey.pem",
			  		   NULL, NULL);

	/* deserialize 'req' from Bob */
	ret = canl_cred_new(ctx, &proxy_cert);
	ret = canl_cred_load_req(ctx, proxy_cert, req);
	ret = canl_cred_set_lifetime(ctx, proxy_cert, 60*10);
	ret = canl_cred_set_cert_type(ctx, proxy_cert, CANL_RFC);
	ret = canl_cred_sign_proxy(ctx, signer, proxy_cert);

	ret = canl_cred_save_cert(ctx, proxy_cert, &x509_cert);
	ret = canl_cred_save_chain(ctx, proxy_cert, &x509_chain);
	/* serialize the new proxy cert and chain and send it back to Bob */
    }

/* Bob - on receiving the final certificate and chain */
    /* deserialize the new proxy cert and chain from Alice */

    ret = canl_cred_new(ctx, &proxy);
    ret = canl_cred_load_req(ctx, proxy, proxy_req);
    ret = canl_cred_load_cert(ctx, proxy, x509_cert);
    ret = canl_cred_load_chain(ctx, proxy, x509_chain);
    ret = canl_cred_save_proxyfile(ctx, proxy, "/tmp/x509up_u11930");

    ret = 0;

    if (signer)
	canl_cred_free(ctx, signer);
    if (proxy)
	canl_cred_free(ctx, proxy);
    if (proxy_cert)
	canl_cred_free(ctx, proxy_cert);
    if (proxy_req)
	canl_req_free(ctx, proxy_req);
    if (req)
	X509_REQ_free(req);
    if (ctx)
	canl_free_ctx(ctx);

    return ret;
}
