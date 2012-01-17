#include "canl_locl.h"

static struct canl_mech *mechs[] = {
    &canl_mech_ssl,
};

static void io_destroy(glb_ctx *cc, io_handler *io);
static int init_io_content(glb_ctx *cc, io_handler *io);
static int try_connect(glb_ctx *glb_cc, io_handler *io_cc, char *addr,
        int addrtype, int port, struct timeval *timeout);

canl_ctx canl_create_ctx()
{
    glb_ctx *ctx = NULL;
    int  i;

    /*create context*/
    ctx = (glb_ctx *) calloc(1, sizeof(*ctx));
    if (!ctx) 
        return NULL;

    for (i = 0; i < sizeof(mechs)/sizeof(mechs[0]); i++)
	mechs[i]->initialize(&mechs[i]->global_context);

    return ctx;
}

void canl_free_ctx(canl_ctx cc)
{
    glb_ctx *ctx = (glb_ctx*) cc;

    if (!cc)
        return;

    /*delete content*/
    if (ctx->err_msg) {
        free(ctx->err_msg);
        ctx->err_msg = NULL;
    }

    free(ctx);
}

canl_err_code
canl_create_io_handler(canl_ctx cc, canl_io_handler *io)
{
    io_handler *new_io_h = NULL;
    glb_ctx *g_cc = cc;
    int err = 0;

    if (!g_cc || io == NULL)
        return EINVAL;

    /*create io handler*/
    new_io_h = (io_handler *) calloc(1, sizeof(*new_io_h));
    if (!new_io_h)
        return set_error(g_cc, ENOMEM, posix_error, "Not enough memory");

    /* allocate memory and initialize io content*/
    if ((err = init_io_content(g_cc ,new_io_h))){
	free(new_io_h);
	return err;
    }

    *io = new_io_h;
    return 0;
}

static int init_io_content(glb_ctx *cc, io_handler *io)
{
    io->s_ctx = (ossl_ctx *) calloc(1, sizeof(*(io->s_ctx)));
    if (!io->s_ctx)
        return set_error(cc, ENOMEM, posix_error, "Not enough memory");

    io->authn_mech.type = AUTH_UNDEF;
    io->sock = -1;
    return 0;
}

canl_err_code
canl_io_connect(canl_ctx cc, canl_io_handler io, const char *host, const char *service,
	int port, gss_OID_set auth_mechs,
        int flags, struct timeval *timeout)
{
    int err = 0;
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    struct _asyn_result ar;
    int i = 0;
    int addr_types[] = {AF_INET, AF_INET6}; //TODO ip versions policy?
    int ipver = AF_INET6;
    int j = 0;

    memset(&ar, 0, sizeof(ar));

    if (!glb_cc) {
        return EINVAL;
    }

    if (!io_cc)
        return set_error(glb_cc, EINVAL, posix_error, 
                "IO handler not initialized");

    err = ssl_client_init(glb_cc, (void **) &glb_cc->ssl_ctx);
    if (err)
	return err;

    for (j = 0; j< sizeof(addr_types)/sizeof(*addr_types); j++) {
        ipver = addr_types[j];
	if (ar.ent) {
	    free_hostent(ar.ent);
	    memset(&ar, 0, sizeof(ar));
	}

        ar.ent = (struct hostent *) calloc (1, sizeof(struct hostent));
        if (ar.ent == NULL)
            return set_error(cc, ENOMEM, posix_error, "Not enough memory");

        switch (err = asyn_getservbyname(ipver, &ar, host, NULL)) {
            case NETDB_SUCCESS:
                err = 0;
                break;
            case TRY_AGAIN:
                err = update_error(glb_cc, ETIMEDOUT, posix_error,
                        "Cannot resolve the server hostname (%s)", host);
		goto end;
            case NETDB_INTERNAL:
		err = update_error(glb_cc, errno, posix_error,
                        "Cannot resolve the server hostname (%s)", host);
                continue;
            default:
                err = update_error(glb_cc, err, netdb_error,
                        "Cannot resolve the server hostname (%s)", host);
                continue;
        }

	err = ECONNREFUSED;
	for (i = 0; ar.ent->h_addr_list[i]; i++) {
            err = try_connect(glb_cc, io_cc, ar.ent->h_addr_list[i], 
                    ar.ent->h_addrtype, port, timeout);//TODO timeout
	    if (err)
		continue;

	    err = ssl_connect(glb_cc, io_cc, timeout, host); //TODO timeout
	    if (err)
		continue;
        }

        free_hostent(ar.ent);
        ar.ent = NULL;
	if (!err)
	    break;
    }

    if (err)
	goto end;

    err = 0;

end:
    if (err) /* XXX: rather invent own error */
	err = update_error(glb_cc, ECONNREFUSED, posix_error,
		"Failed to make network connection to server %s", host);

    if (ar.ent != NULL)
        free_hostent(ar.ent);

    return err;
}
/* try to connect to addr with port (both ipv4 and 6)
 * return 0 when successful
 * errno otherwise*/
/* XXX use set_error on errors and return a CANL return code */
static int try_connect(glb_ctx *glb_cc, io_handler *io_cc, char *addr,
        int addrtype, int port, struct timeval *timeout)
{
    //struct timeval before,after,to;
    struct sockaddr_storage a;
    struct sockaddr_storage *p_a=&a;
    socklen_t a_len;
    //int  opt;
    int err = 0;

    struct sockaddr_in *p4 = (struct sockaddr_in *)p_a;
    struct sockaddr_in6 *p6 = (struct sockaddr_in6 *)p_a;

    memset(p_a, 0, sizeof *p_a);
    p_a->ss_family = addrtype;
    switch (addrtype) {
        case AF_INET:
            memcpy(&p4->sin_addr, addr, sizeof(struct in_addr));
            p4->sin_port = htons(port);
            a_len = sizeof (struct sockaddr_in);
            break;
        case AF_INET6:
            memcpy(&p6->sin6_addr, addr, sizeof(struct in6_addr));
            p6->sin6_port = htons(port);
            a_len = sizeof (struct sockaddr_in6);
            break;
        default:
            return EINVAL;
            break;
    }
    
    io_cc->sock = socket(a.ss_family, SOCK_STREAM, 0);
    if (io_cc->sock == -1)
        return errno;

    err = connect(io_cc->sock,(struct sockaddr *) &a, a_len);
    /* XXX timeouts missing */
    if (err) {
        close(io_cc->sock);
        io_cc->sock = -1;
        return errno;
    }

    return 0;
}

/*TODO select + timeout, EINTR!!! */ 
canl_err_code
canl_io_accept(canl_ctx cc, canl_io_handler io, int new_fd,
        struct sockaddr s_addr, int flags, canl_principal *peer,
        struct timeval *timeout)
{
   int err = 0;
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;

    if (!glb_cc) 
        return EINVAL; /* XXX Should rather be a CANL error */

    if (!io_cc)
        return set_error(cc, EINVAL, posix_error, "IO handler not initialized");

    io_cc->sock = new_fd;

    err = ssl_server_init(glb_cc, (void **) &glb_cc->ssl_ctx);
    if (err)
        goto end;

    err = ssl_accept(glb_cc, io_cc, timeout); 
    if (err)
	goto end;

    err = 0;

end:
    if (err)
        (io_cc)->sock = -1;

    return err;
}

/* close connection, preserve some info for the future reuse */
canl_err_code
canl_io_close(canl_ctx cc, canl_io_handler io)
{
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int err = 0;
    /*check cc and io*/
    if (!cc) {
        return EINVAL; /* XXX Should rather be a CANL error */
    }

    if (!io)
	return set_error(cc, EINVAL, posix_error, "IO handler not initialized");

    err = ssl_close(glb_cc, io_cc);
    if (err <= 0)
        return err;

    if (io_cc->sock != -1) {
        close (io_cc->sock);
        io_cc->sock = -1;
    }

    return err;
}

static void io_destroy(glb_ctx *cc, io_handler *io)
{
    io_handler *io_cc = (io_handler*) io;

    if (io_cc->s_ctx) {
	if (io_cc->s_ctx->ssl_io)
	    ssl_free(cc, io_cc->s_ctx->ssl_io);

	free (io_cc->s_ctx);
	io_cc->s_ctx = NULL;
    }

    return;
}


canl_err_code
canl_io_destroy(canl_ctx cc, canl_io_handler io)
{
    int err = 0;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    io_handler *io_cc = (io_handler*) io;
    /*check cc and io*/

    if (!glb_cc) {
        return EINVAL; /* XXX Should rather be a CANL error */
    }

    if (!io_cc)
	return set_error(glb_cc, EINVAL, posix_error,  "Invalid io handler");

    canl_io_close(cc, io);

    io_destroy(glb_cc, io_cc);
    free (io_cc);

    return err;
}

/* XXX: 0 returned returned by ssl_read() means error or EOF ? */
size_t canl_io_read(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout)
{
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int b_recvd = 0;
    
    if (!cc)
        return -1;

    if (!io) {
	 set_error(cc, EINVAL, posix_error, "IO handler not initialized");
	 return -1;
    }
    
    if (!buffer || !size) {
	set_error(cc, EINVAL, posix_error, "No memory to write into");
	return -1;
    }

    b_recvd = ssl_read(glb_cc, io_cc, buffer, size, timeout);

    return b_recvd;
}

size_t canl_io_write(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout)
{
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int b_written = 0;

    if (!cc)
        return -1;

    if (!io) {
	set_error(cc, EINVAL, posix_error, "IO handler not initialized");
	return -1;
    }

    if (!buffer || !size) {
	set_error(cc, EINVAL, posix_error, "No memory to read from");
	return -1;
    }

    b_written = ssl_write(glb_cc, io_cc, buffer, size, timeout);

    return b_written;
}

#if 0
int canl_set_ctx_own_cert(canl_ctx cc, canl_x509 cert, 
        canl_stack_of_x509 chain, canl_pkey key)
{
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int err = 0;

    if (!cc)
        return EINVAL;
    if(!cert)
        return set_error(glb_cc, EINVAL, posix_error, "invalid"
                "parameter value");

    err = do_set_ctx_own_cert(glb_cc, cert, chain, key);
    if(err) {
        update_error(glb_cc, "can't set cert or key to context");
    }
        return err;
}

//TODO callback and userdata process
int canl_set_ctx_own_cert_file(canl_ctx cc, char *cert, char *key,
        canl_password_callback cb, void *userdata)
{
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int err = 0;

    if (!cc)
        return EINVAL;
    if(!cert ) {
        set_error(glb_cc, EINVAL, posix_error, "invalid parameter value");
        return EINVAL;
    }

    err = do_set_ctx_own_cert_file(glb_cc, cert, key);
    if(err) {
        update_error(glb_cc, "can't set cert or key to context");
    }
        return err;
}
#endif
