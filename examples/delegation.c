#include <stdio.h>
#include <unistd.h>
#include <canl.h>
#include <canl_cred.h>

#define BITS 1024
#define LIFETIME 43200 /*12 hours*/
#define OUTPUT "/tmp/x509_u99999"

int
main(int argc, char *argv[])
{
    canl_cred signer = NULL;
    canl_cred proxy = NULL;
    canl_cred proxy_cert = NULL;
    canl_cred proxy_bob = NULL;
    X509_REQ *req = NULL;
    X509 *x509_cert = NULL;
    STACK_OF(X509) *x509_chain= NULL;
    canl_ctx ctx = NULL;
    canl_err_code ret;

    char *user_cert = NULL;
    char *output = NULL;
    char *user_key = NULL;
    long int lifetime = 0;
    unsigned int bits = 0;
    int opt = 0;

    while ((opt = getopt(argc, argv, "hc:k:l:b:o:")) != -1) {
        switch (opt) {
            case 'h':
                fprintf(stderr, "Usage: %s [-c certificate]"
                        " [-k private key] [-h] [-l lifetime] [-b bits]"
                        " [-o output]"
                        "\n", argv[0]);
                exit(0);
            case 'c':
                user_cert = optarg;
                break;
            case 'k':
                user_key = optarg;
                break;
            case 'l':
                lifetime = atoi(optarg);
                break;
            case 'b':
                bits = atoi(optarg);
                break;
            case 'o':
                output = optarg;
                break;
            default: /* '?' */
                fprintf(stderr, "Usage: %s [-c certificate]"
                        " [-k private key] [-h] [-l lifetime] [-b bits]"
                        " [-o output]"
                        "\n", argv[0]);
                exit(-1);
        }
    }

    ctx = canl_create_ctx();
    if (ctx == NULL) {
        fprintf(stderr, "[DELEGATION] Failed to create library context\n");
        return 1;
    }

    /* Bob - after Alice has asked to delegate her credentials */
    ret = canl_cred_new(ctx, &proxy_bob);
    if (ret){
        fprintf(stderr, "[DELEGATION] Proxy context cannot be created"
                ": %s\n", canl_get_error_message(ctx));
        goto end;
    }
    
    if (!bits)
        bits = BITS;
    ret = canl_cred_new_req(ctx, proxy_bob, bits);
    if (ret) {
        fprintf(stderr, "[DELEGATION] Failed to create certificate "
                "request container: %s\n", canl_get_error_message(ctx));
        goto end;
    }
    ret = canl_cred_save_req(ctx, proxy_bob, &req);
    if (ret) {
        fprintf(stderr, "[DELEGATION] Failed to get certificate "
                "request container: %s\n", canl_get_error_message(ctx));
        goto end;
    }

    /* serialize 'req' and send it to Alice */

/* Alice - after receiving the CSR from Bob. (The private key stays with Bob.) */
    {
        ret = canl_cred_new(ctx, &signer);
        if (ret){
            fprintf(stderr, "[DELEGATION] Proxy context cannot be created"
                    ": %s\n", canl_get_error_message(ctx));
            goto end;
        }

        ret = canl_cred_load_cert_file(ctx, signer, user_cert);
        if (ret){
            fprintf(stderr, "[DELEGATION] Cannot load signer's certificate"
                    ": %s\n", canl_get_error_message(ctx));
            goto end;
        }
        ret = canl_cred_load_priv_key_file(ctx, signer, user_key, NULL, NULL);
        if (ret){
            fprintf(stderr, "[DELEGATION] Cannot access signer's key"
                    ": %s\n", canl_get_error_message(ctx));
            goto end;
        }

        /* deserialize 'req' from Bob */
        ret = canl_cred_new(ctx, &proxy_cert);
        if (ret){
            fprintf(stderr, "[DELEGATION] Proxy context cannot be created"
                    ": %s\n", canl_get_error_message(ctx));
            goto end;
        }
        ret = canl_cred_load_req(ctx, proxy_cert, req);
        if (ret) {
            fprintf(stderr, "[DELEGATION] Failed to load certificate "
                    "request container: %s\n", canl_get_error_message(ctx));
            goto end;
        }


        if (!lifetime)
                    lifetime = LIFETIME;
        ret = canl_cred_set_lifetime(ctx, proxy_cert, lifetime);
        if (ret)
            fprintf(stderr, "[DELEGATION] Failed set new cert lifetime"
                    ": %s\n", canl_get_error_message(ctx));

        ret = canl_cred_set_cert_type(ctx, proxy_cert, CANL_RFC);
        if (ret)
            fprintf(stderr, "[DELEGATION] Failed set new cert type"
                    ": %s\n", canl_get_error_message(ctx));

        ret = canl_cred_sign_proxy(ctx, signer, proxy_cert);
        if (ret){
            fprintf(stderr, "[DELEGATION] Cannot sign new proxy"
                    ": %s\n", canl_get_error_message(ctx));
            goto end;
        }

        ret = canl_cred_save_cert(ctx, proxy_cert, &x509_cert);
        if (ret){
            fprintf(stderr, "[DELEGATION] Cannot save new cert file"
                    ": %s\n", canl_get_error_message(ctx));
            goto end;
        }

	ret = canl_cred_save_chain(ctx, proxy_cert, &x509_chain);
        if (ret){
            fprintf(stderr, "[DELEGATION] Cannot save cert chain"
                    ": %s\n", canl_get_error_message(ctx));
            goto end;
        }
	/* serialize the new proxy cert and chain and send it back to Bob */
    }

/* Bob - on receiving the final certificate and chain */
    /* deserialize the new proxy cert and chain from Alice */

    ret = canl_cred_load_cert(ctx, proxy_bob, x509_cert);
    if (ret){
        fprintf(stderr, "[DELEGATION] Cannot load certificate"
                ": %s\n", canl_get_error_message(ctx));
        goto end;
    }
    
    ret = canl_cred_load_chain(ctx, proxy_bob, x509_chain);
    if (ret){
        fprintf(stderr, "[DELEGATION] Cannot load cert. chain"
                ": %s\n", canl_get_error_message(ctx));
        goto end;
    }
    
    if (!output)
        output = OUTPUT;
    ret = canl_cred_save_proxyfile(ctx, proxy_bob, output);
    if (ret){
        fprintf(stderr, "[PROXY-INIT] Cannot save new proxy"
                ": %s\n", canl_get_error_message(ctx));
        goto end;
    }
    
    ret = 0;
end:
    if (signer)
	canl_cred_free(ctx, signer);
    if (proxy)
	canl_cred_free(ctx, proxy);
    if (proxy_cert)
	canl_cred_free(ctx, proxy_cert);
    if (proxy_bob)
	canl_cred_free(ctx, proxy_bob);
    if (req)
	X509_REQ_free(req);
    if (x509_cert)
	X509_free(x509_cert);
/* TODO free stack    
 * if (x509_chain)
	X509_free(x509_cert);
*/    
    if (ctx)
	canl_free_ctx(ctx);

    return ret;
}
