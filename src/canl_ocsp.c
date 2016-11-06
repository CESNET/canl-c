#include "canl_ocsp.h"
#include "canl_mech_ssl.h"
#include <openssl/ocsp.h>

#define USENONCE 0

static X509_STORE * canl_create_x509store(canl_x509store_t *store);

static OCSP_RESPONSE *send_request(OCSP_REQUEST *req, char *host, char *path,
        int port, int ssl, int req_timeout);

static OCSP_RESPONSE *
query_responder(BIO *conn, char *path, OCSP_REQUEST *req, int req_timeout);

static char *get_ocsp_url_from_aia(X509 * cert, char** urls);

int ocsprequest_init(canl_ocsprequest_t **ocspreq)
{
    if (!ocspreq)
        return 1;
    *ocspreq = calloc(1, sizeof(**ocspreq));
    if (!(*ocspreq))
        return 1;

    return 0;
}

void ocsprequest_free(canl_ocsprequest_t *ocspreq)
{
    if (ocspreq)
        free(ocspreq);
}

int set_ocsp_url(canl_ocsprequest_t *ocspreq, char *url)
{
    int len = 0;
    if (!ocspreq)
        return 1;

    if (url) {
        if (!ocspreq->url) {
            free (ocspreq->url);
            ocspreq->url = NULL;
        }
        len = strlen(url);
        ocspreq->url = (char *) malloc((len +1) * sizeof (char));
        if (!ocspreq->url)
            return 1;
        strncpy(ocspreq->url, url, len + 1);
    }
    return 0;
}

int set_ocsp_sign_cert(canl_ocsprequest_t *ocspreq, X509 *sign_cert)
{
    if (!ocspreq)
        return 1;
    if (sign_cert) {
        if (!ocspreq->sign_cert) {
            X509_free (ocspreq->sign_cert);
            ocspreq->sign_cert = NULL;
        }
        ocspreq->sign_cert = X509_dup(sign_cert);
        if (!ocspreq->sign_cert)
            return 1;
    }
    return 0;
}

int set_ocsp_sign_key(canl_ocsprequest_t *ocspreq, EVP_PKEY *sign_key)
{
    if (!ocspreq)
        return 1;
    if (sign_key) {
        if (!ocspreq->sign_key) {
            EVP_PKEY_free (ocspreq->sign_key);
            ocspreq->sign_key = NULL;
        }
        pkey_dup(&ocspreq->sign_key, sign_key);
        if (!ocspreq->sign_key)
            return 1;
    }
    return 0;
}

static X509_STORE *
canl_create_x509store(canl_x509store_t *c_store)
{
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;

    if (!c_store)
        return NULL;
    if(!(store = X509_STORE_new()))
        goto end; 
    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL)
        goto end;
    if (c_store->ca_file) {
        if(!X509_LOOKUP_load_file(lookup, c_store->ca_file, X509_FILETYPE_PEM)) { 
            goto end; 
        } 
    }
    else X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT); 

    lookup=X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir()); 
    if (lookup == NULL)
        goto end; 
    if (c_store->ca_dir) {
        if(!X509_LOOKUP_add_dir(lookup, c_store->ca_dir, X509_FILETYPE_PEM)) { 
            goto end;
        }
    }
    else X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT); 

    ERR_clear_error(); 
    return store; 
end: 
    X509_STORE_free(store); 
    return NULL; 
}

/* Extract an url of given ocsp responder out of the AIA extension.
   
   Newer openssl libs support OPENSSL_STRING type and X509_get1_ocsp()
   funcion which can easily do that. We may use it in future.
   aia = X509_get1_ocsp(x);
   return sk_OPENSSL_STRING_value(aia, 0);

   Returns string of the form: URI:uri1 \0 URI:uri2 \0 ... URI:urin \0\0 
   (without spaces)
 */
static char *get_ocsp_url_from_aia(X509 * cert, char** urls)
{ 
    BIO* mem=NULL; 
    ACCESS_DESCRIPTION* ad=NULL;
    STACK_OF(ACCESS_DESCRIPTION)* ads=NULL;
    int adsnum;
    int crit = 0;
    int idx = 0;
    int i;

    if(!cert||!urls)
        return NULL;

    *urls=NULL;

    mem=BIO_new(BIO_s_mem());
    if(!mem)
        goto cleanup;

    ads=(STACK_OF(ACCESS_DESCRIPTION)*)X509_get_ext_d2i(cert,
            NID_info_access, &crit, &idx);
    if(!ads)
        goto cleanup;
    adsnum=sk_ACCESS_DESCRIPTION_num(ads);

    for(i=0; i<adsnum; i++){
        ad=sk_ACCESS_DESCRIPTION_value(ads, i);
        if(!ad)
            continue;
        if(OBJ_obj2nid(ad->method) == NID_ad_OCSP){
            if(GENERAL_NAME_print(mem, ad->location)<=0)
                goto cleanup;

            BIO_write(mem, "\0", 1);
        }
    }

    BIO_write(mem, "\0\0", 2);
    BIO_flush(mem);

    BIO_get_mem_data(mem, urls);
    BIO_set_close(mem, BIO_NOCLOSE);

cleanup:

    if(ads)
        sk_ACCESS_DESCRIPTION_free(ads);
    if(mem)
        BIO_free(mem);

    return *urls;
} 

/*TODO error codes in this function has to be passed to canl_ctx somehow*/
/*Timeout shoult be in data structure*/
int do_ocsp_verify (canl_ocsprequest_t *data)
{
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    OCSP_BASICRESP *basic = NULL;
    X509_STORE *store = NULL;
    int rc = 0, reason = 0, ssl = 0, status = 0;
    char *host = NULL, *path = NULL, *port = NULL;
    OCSP_CERTID *id = NULL;
    char *chosenurl = NULL;
    char *tr_chosenurl = NULL;
    canl_ocspresult_t result = 0;
    ASN1_GENERALIZEDTIME  *producedAt, *thisUpdate, *nextUpdate;
    int timeout = -1; // -1 means no timeout - use blocking I/O
    unsigned long verify_flags = 0;

    if (!data || !data->cert) { // TODO || !data->issuer ?
        result = EINVAL; //TODO error code
        return result;
    }

    /*get url from cert or use some implicit value*/
    /*TODO duplicate the value*/
    if (data->url)
        chosenurl = strdup(data->url);
    else
        if (!get_ocsp_url_from_aia(data->cert, &chosenurl)) {
            result = CANL_OCSPRESULT_ERROR_NOAIAOCSPURI;
            goto end;
        }
    /* It is necessary to truncate chosenurl for URI:*/
    tr_chosenurl = strstr(chosenurl, "URI:");
    if (tr_chosenurl)
        tr_chosenurl += 4;
    else
        tr_chosenurl = chosenurl;

    /*get connection parameters out of the tr_chosenurl.
      Determine whether to use encrypted (ssl) connection (based on the url
      format). Url is http[s]://host where host consists of 
      DN [:port] and [path]*/
    if (!OCSP_parse_url(tr_chosenurl, &host, &port, &path, &ssl)) {
        result = CANL_OCSPRESULT_ERROR_BADOCSPADDRESS;
        goto end;
    }
    /*Make new OCSP_REQUEST*/
    if (!(req = OCSP_REQUEST_new())) {
        result = CANL_OCSPRESULT_ERROR_OUTOFMEMORY;
        goto end;
    }

    /*map a cert and its issuer to an ID*/
    id = OCSP_cert_to_id(0, data->cert, data->issuer);

    /* Add an id and nonce to the request*/
    if (!id || !OCSP_request_add0_id(req, id))
        goto end;
    if (USENONCE)
        OCSP_request_add1_nonce(req, 0, -1);

    /* sign the request
       Default hash algorithm is sha1(), might be changed.
       Do not add additional certificates to request
       Do not use flags (e.g. like -no_certs for command line ) now */
    if (data->sign_cert && data->sign_key &&
            !OCSP_request_sign(req, data->sign_cert, data->sign_key, 
                EVP_sha1(), 0, 0)) {
        result = CANL_OCSPRESULT_ERROR_SIGNFAILURE;
        goto end;
    }


    /* establish a connection to the OCSP responder */
    if (!(resp = send_request(req, host, path, atoi(port), ssl, timeout))) {
        result = CANL_OCSPRESULT_ERROR_CONNECTFAILURE;
        goto end;
    }

    /* send the request and get a response */
    if ((rc = OCSP_response_status(resp)) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        switch (rc) {
            case OCSP_RESPONSE_STATUS_MALFORMEDREQUEST:
                result = CANL_OCSPRESULT_ERROR_MALFORMEDREQUEST; break;
            case OCSP_RESPONSE_STATUS_INTERNALERROR:
                result = CANL_OCSPRESULT_ERROR_INTERNALERROR;    break;
            case OCSP_RESPONSE_STATUS_TRYLATER:
                result = CANL_OCSPRESULT_ERROR_TRYLATER;         break;
            case OCSP_RESPONSE_STATUS_SIGREQUIRED:
                result = CANL_OCSPRESULT_ERROR_SIGREQUIRED;      break;
            case OCSP_RESPONSE_STATUS_UNAUTHORIZED:
                result = CANL_OCSPRESULT_ERROR_UNAUTHORIZED;     break;
        }
        goto end;
    }

    /* verify the response */
    result = CANL_OCSPRESULT_ERROR_INVALIDRESPONSE;
    if (!(basic = OCSP_response_get1_basic(resp))) 
        goto end;
    if (USENONCE && OCSP_check_nonce(req, basic) <= 0) 
        goto end;
    /* TODO is this compulsory? */
    store = canl_create_x509store(&data->store);
    if (!store)
        goto end;
    
    /* The last param. may be used when OCSP API is fully defined*/
    rc = OCSP_basic_verify(basic, data->cert_chain, store, verify_flags);
    if (rc < 0)
        rc = OCSP_basic_verify(basic, NULL, store, 0);
    if (rc <= 0) {
        /*response verify failure*/
        result = CANL_OCSPRESULT_ERROR_VERIFYRESPONSE;
        goto end;
    }

    if (!OCSP_resp_find_status(basic, id, &status, &reason, &producedAt,
                &thisUpdate, &nextUpdate)){
        result = CANL_OCSPRESULT_ERROR_NOSTATUS;
        goto end;
    }
    if (!OCSP_check_validity(thisUpdate, nextUpdate, 
                data->skew, data->maxage)) {
        result = CANL_OCSPRESULT_ERROR_INVTIME;
        goto end;
    }

    /* All done.  Set the return code based on the status from the response. */
    if (status == V_OCSP_CERTSTATUS_REVOKED) {
        result = CANL_OCSPRESULT_CERTIFICATE_REVOKED;
        /*TODO myproxy_log("OCSP status revoked!"); */
    } else {
        result = CANL_OCSPRESULT_CERTIFICATE_VALID;
        /*TODO myproxy_log("OCSP status valid"); */
    }
end:
    if (host)
        OPENSSL_free(host);
    if (port)
        OPENSSL_free(port);
    if (path)
        OPENSSL_free(path);
    if (req)
        OCSP_REQUEST_free(req);
    if (resp)
        OCSP_RESPONSE_free(resp);
    if (basic)
        OCSP_BASICRESP_free(basic);
    if (chosenurl)
        free(chosenurl);
    if (store)
        X509_STORE_free(store);

    return result;
}

static OCSP_RESPONSE *
send_request(OCSP_REQUEST *req, char *host, char *path,  int port, int ssl,
        int req_timeout) {
    BIO *conn;
    SSL_CTX *ctx_in = NULL;
    OCSP_RESPONSE *resp = NULL;

    if (!(conn = BIO_new_connect(host)))
        goto end;
    BIO_set_conn_port(conn, &port);

    if (ssl){
        BIO *sbio;
        ctx_in = SSL_CTX_new(TLS_client_method());
        if (ctx_in == NULL) {
            goto end;
        }
        //SSL_CTX_set_cert_store(ctx_in, store);
        /*TODO verify using OCSP? Infinite loop
           !!!!!!!!!!!!!!!!!!!!!!!§
           SSL_CTX_set_mode(ctx_in, SSL_MODE_AUTO_RETRY); ? - return only after
          the handshake and successful completion*/
        SSL_CTX_set_verify(ctx_in, SSL_VERIFY_PEER, NULL);

        sbio = BIO_new_ssl(ctx_in, 1);
        conn = BIO_push(sbio, conn);
        /*
           BIO_get_ssl(conn, &ssl_ptr);

           TODO figure out, how to check cert without canl_ctx

           if (!check_hostname_cert(SSL_get_peer_certificate(ssl_ptr), host))
           goto end;

           TODO verify certs in OCSP at this place? openssl CL tool does not do
           that.
           if (SSL_get_verify_result(ssl_ptr) != X509_V_OK)
           goto end;
         */
    }

    resp = query_responder(conn, path, req, req_timeout);

end:
    if (conn)
        BIO_free_all(conn);
    if (ctx_in)
        SSL_CTX_free(ctx_in);
    return resp;
}

#ifdef OPENSSL_SYSNAME_WIN32
#define openssl_fdset(a,b) FD_SET((unsigned int)a, b)
#else
#define openssl_fdset(a,b) FD_SET(a, b)
#endif

#if SSLEAY_VERSION_NUMBER >=  0x0090900fL
/*TODO the timeout variable should be modified if TO is reached.
  Somehow retur error codes! */
    static OCSP_RESPONSE *
query_responder(BIO *conn, char *path, OCSP_REQUEST *req, int req_timeout)
{
    OCSP_RESPONSE *rsp = NULL;
    int fd;
    int rv;
    OCSP_REQ_CTX *ctx = NULL;
    fd_set confds;
    struct timeval tv;
    
    /*If timeout is set, the nonblocking I/O flag is set*/
    if (req_timeout != -1)
        BIO_set_nbio(conn, 1);

    rv = BIO_do_connect(conn);
    if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(conn)))
    {
        /*connect failed*/
        return NULL;
    }

    if (BIO_get_fd(conn, &fd) <= 0)
    {
        /*Cannot get the socket*/
        goto err;
    }

    if (req_timeout != -1 && rv <= 0)
    {
        /*try connecting untill timeout is reached*/
        FD_ZERO(&confds);
        FD_SET(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
        if (rv == 0)
        {
            /*Timeout reached*/
            return NULL;
        }
    }


    /*Prepare OCSP_REQ_CTX*/
    ctx = OCSP_sendreq_new(conn, path, NULL, -1);
    if (!ctx)
        return NULL;
    if (!OCSP_REQ_CTX_set1_req(ctx, req))
        goto err;

    /*send the OCSP request and wait for the response*/
    for (;;)
    {
        rv = OCSP_sendreq_nbio(&rsp, ctx);
        if (rv != -1)
            break;

        /* Blocking I/O flag set
         TODO - might end in an infinite loop? - what about
         SSL_MODE_AUTO_RETRY ?? */
        if (req_timeout == -1) 
            continue;
        FD_ZERO(&confds);
        openssl_fdset(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        if (BIO_should_read(conn))
            rv = select(fd + 1, (void *)&confds, NULL, NULL, &tv);
        else if (BIO_should_write(conn))
            rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
        else
        {
            /* Unexpected retry condition */
            goto err;
        }
        if (rv == 0)
        {
            /*Timeout on request */
            break;
        }
        if (rv == -1)
        {
            /*Select error*/
            break;
        }

    }
err:
    if (ctx)
        OCSP_REQ_CTX_free(ctx);
    return rsp;
}
#endif

#if SSLEAY_VERSION_NUMBER < 0x0090900fL
/*TODO the timeout variable should be modified if TO is reached.
  Somehow retur error codes! */
    static OCSP_RESPONSE *
query_responder(BIO *conn, char *path, OCSP_REQUEST *req, int req_timeout)
{
    OCSP_RESPONSE *rsp = NULL;
    
/*openssl does support non blocking BIO for OCSP_send_request*/

    /*openssl does not support non blocking BIO for OCSP_send_request*/

    if (BIO_do_connect(conn) <= 0)
    {
        /*Error connecting BIO*/
        goto err;
    }

    rsp = OCSP_sendreq_bio(conn, path, req);
    if (!rsp) {
        /*no response from the server*/
        goto err;
    }

err:
    return rsp;
}
#endif
