#include <canl.h>
#include <canl_cred.h>

#define BITS 1024
#define LIFETIME 600
#define USERCERT "$HOME/.globus/usercert.pem"
#define USERKEY "$HOME/.globus/userkey.pem"
int
main(int argc, char *argv[])
{
    canl_cred signer = NULL;
    canl_cred proxy = NULL;
    canl_ctx ctx = NULL;
    canl_err_code ret;

    ctx = canl_create_ctx();
    if (ctx == NULL) {
	fprintf(stderr, "Failed to create library context\n");
	return 1;
    }

/* First create a certificate request with a brand-new keypair */
    ret = canl_cred_new(ctx, &proxy);
    ret = canl_cred_new_req(ctx, proxy, BITS);
    if (ret) {
	fprintf(stderr, "Failed to create certificate request container: %s\n",
		canl_get_error_message(ctx));
	return 1;
    }

    /*Create key-pairs implicitly*/
    ret = canl_cred_set_lifetime(ctx, proxy, LIFETIME);
    ret = canl_cred_set_cert_type(ctx, proxy, CANL_RFC);

    /* Load the signing credentials */
    ret = canl_cred_new(ctx, &signer);
    ret = canl_cred_load_cert_file(ctx, signer, USERCERT);
    ret = canl_cred_load_priv_key_file(ctx, signer, USERKEY, NULL, NULL);
    /* export lookup routines ?? */

#ifdef VOMS
    GET_VOMS_EXTS(ctx, signer, STACK_OF(EXTS));
    foreach (EXTS)
	ret = canl_cred_set_ext(ctx, proxy, ext);
#endif

/* Create the proxy certificate */
    ret = canl_cred_sign_proxy(ctx, signer, proxy);

/* and store it in a file */
    ret = canl_cred_save_proxyfile(ctx, proxy, "/tmp/x509up_u11930");

    ret = 0;

end:
    if (signer)
	canl_cred_free(ctx, signer);
    if (proxy)
	canl_cred_free(ctx, proxy);
    if (ctx)
	canl_free_ctx(ctx);

    return ret;
}
