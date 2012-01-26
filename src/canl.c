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
	mechs[i]->initialize(ctx, &mechs[i]->global_context);

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
    /*TODO delete ctx content for real*/

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
        return set_error(g_cc, ENOMEM, POSIX_ERROR, "Not enough memory");

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
    io->authn_mech.type = AUTH_UNDEF;
    io->authn_mech.oid = GSS_C_NO_OID;
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
    int i = 0, k;
    int addr_types[] = {AF_INET, AF_INET6}; //TODO ip versions policy?
    int ipver = AF_INET6;
    int j = 0, done;
    struct canl_mech *mech;
    gss_OID oid;

    memset(&ar, 0, sizeof(ar));

    if (!glb_cc) {
        return EINVAL;
    }

    if (!io_cc)
        return set_error(glb_cc, EINVAL, POSIX_ERROR, 
                "IO handler not initialized");

    done = 0;
    for (k = 0; k < sizeof(addr_types)/sizeof(*addr_types); k++) {
        ipver = addr_types[k];
	if (ar.ent) {
	    free_hostent(ar.ent);
	    memset(&ar, 0, sizeof(ar));
	}

        ar.ent = (struct hostent *) calloc (1, sizeof(struct hostent));
        if (ar.ent == NULL)
            return set_error(cc, ENOMEM, POSIX_ERROR, "Not enough memory");

        switch (err = asyn_getservbyname(ipver, &ar, host, NULL)) {
            case NETDB_SUCCESS:
                err = 0;
                break;
            case TRY_AGAIN:
                err = update_error(glb_cc, ETIMEDOUT, POSIX_ERROR,
                        "Cannot resolve the server hostname (%s)", host);
		goto end;
            case NETDB_INTERNAL:
		err = update_error(glb_cc, errno, POSIX_ERROR,
                        "Cannot resolve the server hostname (%s)", host);
                continue;
            default:
                err = update_error(glb_cc, err, NETDB_ERROR,
                        "Cannot resolve the server hostname (%s)", host);
                continue;
        }

	j = 0;
	do {
	    if (auth_mechs == GSS_C_NO_OID_SET || auth_mechs->count == 0)
		oid = GSS_C_NO_OID;
	    else
		oid = &auth_mechs->elements[j];

	    mech = find_mech(oid);

	    for (i = 0; ar.ent->h_addr_list[i]; i++) {
		void *ctx = NULL;

		err = try_connect(glb_cc, io_cc, ar.ent->h_addr_list[i], 
			ar.ent->h_addrtype, port, timeout);//TODO timeout
		if (err)
		    continue;

		err = mech->client_init(glb_cc, mech->global_context, &ctx);
		if (err) {
		    canl_io_close(glb_cc, io_cc);
		    continue;
		}

		err = mech->connect(glb_cc, io_cc, ctx, timeout, host); //TODO timeout
		if (err) {
		    canl_io_close(glb_cc, io_cc);
		    mech->free_ctx(glb_cc, ctx);
		    ctx = NULL;
		    continue;
		}
		io_cc->authn_mech.ctx = ctx;
		io_cc->authn_mech.type = mech->mech;
		done = 1;
		break;
	    }
	    j++;
	} while (auth_mechs != GSS_C_NO_OID_SET && j < auth_mechs->count && !done);

        free_hostent(ar.ent);
        ar.ent = NULL;
	if (done)
	    break;
    }

    if (!done) {
	err = ECONNREFUSED;
	goto end;
    }

    err = 0;

end:
    if (err) /* XXX: rather invent own error */
	err = update_error(glb_cc, ECONNREFUSED, POSIX_ERROR,
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
    int sock;
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
            return update_error(glb_cc, EINVAL, POSIX_ERROR,
			    "Unsupported address type (%d)", addrtype);
            break;
    }
    
    sock = socket(a.ss_family, SOCK_STREAM, 0);
    if (sock == -1)
        return update_error(glb_cc, errno, POSIX_ERROR,
			 "Failed to create network socket");

    err = connect(sock,(struct sockaddr *) &a, a_len);
    /* XXX timeouts missing */
    if (err) {
        return update_error(glb_cc, errno, POSIX_ERROR,
			 "Failed to open network connection");
    }

    io_cc->sock = sock;
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
    struct canl_mech *mech = find_mech(GSS_C_NO_OID);
    void *conn_ctx = NULL;

    if (!glb_cc) 
        return EINVAL; /* XXX Should rather be a CANL error */

    if (!io_cc)
        return set_error(cc, EINVAL, POSIX_ERROR, "IO handler not initialized");

    io_cc->sock = new_fd;

    err = mech->server_init(glb_cc, mech->global_context, &conn_ctx);
    if (err)
        goto end;

    err = mech->accept(glb_cc, io_cc, conn_ctx, timeout); 
    if (err)
	goto end;

    io_cc->authn_mech.ctx = conn_ctx;
    io_cc->authn_mech.type = mech->mech;
    io_cc->authn_mech.oid = GSS_C_NO_OID;

    err = 0;

end:
    if (err) {
        (io_cc)->sock = -1;
	mech->free_ctx(glb_cc, conn_ctx);
    }

    return err;
}

/* close connection, preserve some info for the future reuse */
canl_err_code
canl_io_close(canl_ctx cc, canl_io_handler io)
{
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int err = 0;
    canl_mech *mech;

    /*check cc and io*/
    if (!cc) {
        return EINVAL; /* XXX Should rather be a CANL error */
    }

    if (!io)
	return set_error(cc, EINVAL, POSIX_ERROR, "IO handler not initialized");

    if (io_cc->authn_mech.ctx) {
	mech = find_mech(io_cc->authn_mech.oid);
	mech->close(glb_cc, io, io_cc->authn_mech.ctx);
	/* XXX can it be safely reopened ?*/
    }

    if (io_cc->sock != -1) {
        close (io_cc->sock);
        io_cc->sock = -1;
    }

    return err;
}

static void io_destroy(glb_ctx *cc, io_handler *io)
{
    io_handler *io_cc = (io_handler*) io;
    canl_mech *mech;
    
    if (io == NULL)
	return;

    if (io_cc->authn_mech.ctx) {
	mech = find_mech(io->authn_mech.oid);
	mech->free_ctx(cc, io_cc->authn_mech.ctx);
	io_cc->authn_mech.ctx = NULL;
	io_cc->authn_mech.type = AUTH_UNDEF;
	io_cc->authn_mech.oid = GSS_C_NO_OID;
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
	return set_error(glb_cc, EINVAL, POSIX_ERROR,  "Invalid io handler");

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
    struct canl_mech *mech;
    
    if (!cc)
        return -1;

    if (!io) {
	 set_error(cc, EINVAL, POSIX_ERROR, "IO handler not initialized");
	 return -1;
    }

    if (io_cc->authn_mech.ctx == NULL)
	return set_error(cc, EINVAL, POSIX_ERROR, "Connection not secured");
    
    if (!buffer || !size) {
	set_error(cc, EINVAL, POSIX_ERROR, "No memory to write into");
	return -1;
    }

    mech = find_mech(io_cc->authn_mech.oid);

    b_recvd = mech->read(glb_cc, io_cc, io_cc->authn_mech.ctx,
		         buffer, size, timeout);

    return b_recvd;
}

size_t canl_io_write(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout)
{
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int b_written = 0;
    struct canl_mech *mech;

    if (!cc)
        return -1;

    if (!io) {
	set_error(cc, EINVAL, POSIX_ERROR, "IO handler not initialized");
	return -1;
    }

    if (io_cc->authn_mech.ctx == NULL)
	return set_error(cc, EINVAL, POSIX_ERROR, "Connection not secured");

    if (!buffer || !size) {
	set_error(cc, EINVAL, POSIX_ERROR, "No memory to read from");
	return -1;
    }

    mech = find_mech(io_cc->authn_mech.oid);

    b_written = mech->write(glb_cc, io_cc, io_cc->authn_mech.ctx,
			    buffer, size, timeout);

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
        return set_error(glb_cc, EINVAL, POSIX_ERROR, "invalid"
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
        set_error(glb_cc, EINVAL, POSIX_ERROR, "invalid parameter value");
        return EINVAL;
    }

    err = do_set_ctx_own_cert_file(glb_cc, cert, key);
    if(err) {
        update_error(glb_cc, "can't set cert or key to context");
    }
        return err;
}
#endif

struct canl_mech *
find_mech(gss_OID oid)
{
    /* XXX */
    return &canl_mech_ssl;
}
