#include "canl_locl.h"

#define ERR_CODE_LEN 512

static canl_err_code resolve_error_code(glb_ctx *cc, unsigned long err_code, 
        canl_err_origin err_orig);
static void get_error_string(glb_ctx *cc, char *code_str);
static canl_err_code update_error_msg(canl_ctx cc, const char *new_msg);
static char *canl_strerror(const canl_err_code c_code);
static canl_error canl_err_ssl_to_canl(const unsigned long ossl_lib,
        const unsigned long ossl_reason);

/* Save error message into err_msg
 * use NULL for empty err_format */
canl_err_code update_error (glb_ctx *cc, unsigned long err_code,
		  canl_err_origin err_orig,
		  const char *err_format, ...)
{
    int err_format_len = 0;
    va_list ap;
    char *new_msg = NULL;
    int ret = 0;

    if (!cc)
        return EINVAL;

    if (err_format == NULL || err_format[0] == '\0') {
        goto wo_msg;
    }

    va_start(ap, err_format);
    
    /*TODO if vasprintf not successful?*/
    err_format_len = vasprintf(&new_msg, err_format, ap);
    if (!err_format_len) {
        va_end(ap);
        return EINVAL;
    }
    va_end(ap);

wo_msg:
    ret = resolve_error_code(cc, err_code, err_orig);
    update_error_msg(cc, new_msg);
    if (new_msg)
        free(new_msg);

    return ret;
}

/* If there was some error message in ctx, delete it and make new */
canl_err_code set_error (glb_ctx *cc, unsigned long err_code,
	canl_err_origin err_orig, const char *err_format, ...)
{
    va_list ap;
    char *new_msg = NULL;
    int ret;
    int err_format_len = 0;
    
    if (!cc) 
        return 1;
    /* if message already exists, delete it */
    if (cc->err_msg)
        reset_error(cc, err_code);

    if (err_format == NULL || err_format[0] == '\0') {
        goto wo_msg;
    }

    /* make new message */
    va_start(ap, err_format);
    err_format_len = vasprintf(&new_msg, err_format, ap);
    if (!err_format_len) {
        va_end(ap);
        return EINVAL;
    }
    va_end(ap);

wo_msg:
    ret = resolve_error_code(cc, err_code, err_orig);
    update_error_msg(cc, new_msg);
    if (new_msg)
        free(new_msg);

    if (!err_code) //TODO ???
        return 0;
    return ret;
}

/* Delete error message in ctx, suppose msg is not empty.Set pointer to NULL*/
void reset_error (glb_ctx *cc, unsigned long err_code)
{
    /*check cc*/
    if (!cc )
        return;
    if (cc->err_msg)
        free(cc->err_msg);
    cc->err_msg = NULL;
    cc->err_code = 0;
    cc->err_orig = UNKNOWN_ERROR;
}

/* Provide human readable information about errors */
static canl_err_code
update_error_msg(canl_ctx cc, const char *new_msg)
{
    int error_length = 0;
    char *new_error = NULL;
    char code_str[ERR_CODE_LEN];
    int code_len = 0;
    char *separ = ": ";
    int separ_len = 0;
    int err_old_msg_len = 0;
    int err_new_msg_len = 0;
    glb_ctx *ctx = (glb_ctx*) cc;

    code_str[0] = '\0';

    /*check cc*/
    if (!ctx) {
        return EINVAL;
    }

    if (ctx->err_msg)
        err_old_msg_len = strlen(ctx->err_msg);
    
    if (new_msg)
        err_new_msg_len = strlen(new_msg);

    /* get human readable error code */
    get_error_string(cc, code_str);
    code_len = strlen(code_str);

    separ_len = strlen(separ);
    error_length = err_new_msg_len + err_old_msg_len + code_len + 
        (2*separ_len) + 1;
    new_error = (char *) malloc ((error_length) * sizeof (char));
    if (!new_error) {
        return set_error(ctx, ENOMEM, POSIX_ERROR, "cannot get error message");
    }
    
    new_error[0] = '\0';
    if (new_msg) {
        strncpy(new_error, new_msg, err_new_msg_len + 1);
        strncat(new_error, separ, separ_len + 1);
    }
    strncat(new_error, code_str, code_len + 1);
    strncat(new_error, separ, separ_len + 1);
    if (ctx->err_msg) {
        strncat(new_error, ctx->err_msg, err_old_msg_len + 1);
    }

    if (ctx->err_msg)
        free(ctx->err_msg);
    ctx->err_msg = new_error;
    return 0;
}

static void get_error_string(glb_ctx *cc, char *code_str)
{
    char *new_str = NULL;

    switch (cc->err_orig) {
        case SSL_ERROR:
            ERR_error_string_n(cc->err_code, code_str,
                    ERR_CODE_LEN);
            break;
        case POSIX_ERROR:
            new_str = strerror(cc->err_code);
            if (new_str) {
                strncpy(code_str, new_str,
                        ERR_CODE_LEN);
                code_str[ERR_CODE_LEN - 1] = '\0';
            }
            break;
        case NETDB_ERROR:
            new_str = (char *) hstrerror(cc->err_code);
            if (new_str) {
                strncpy(code_str, new_str,
                        ERR_CODE_LEN);
                code_str[ERR_CODE_LEN - 1] = '\0';
            }
            break;
        case CANL_ERROR:
            new_str = canl_strerror(cc->err_code);
            if (new_str) {
                strncpy(code_str, new_str,
                        ERR_CODE_LEN);
                code_str[ERR_CODE_LEN - 1] = '\0';
            }
            break;
        default:
	    snprintf(code_str, ERR_CODE_LEN,
		     "Unknown error origin (%u) of error %lu!",
		     cc->err_orig, cc->err_code);
            break;
    }
}

static char *
canl_strerror(const canl_err_code c_code)
{
    char *new_str = NULL;
    int k = 0;
    for (k = 0; k < canl_err_descs_num; k++) {
        if (canl_err_descs[k].code == c_code) {
            new_str = canl_err_descs[k].desc;
        }
    }
    return new_str;
}

/*return appropriate CANL_ERROR according to openssl error code or -1 if
no one found */
static canl_error
canl_err_ssl_to_canl(const unsigned long ossl_lib,
        const unsigned long ossl_reason)
{
    canl_error ret_err = -1;
    int k = 0;
    for (k = 0; k < canl_err_descs_num; k++) {
        if (canl_err_descs[k].openssl_lib == ossl_lib) {
            if (canl_err_descs[k].openssl_reason == ossl_reason)
                ret_err = canl_err_descs[k].code;
        }
    }
    return ret_err;
}

canl_err_code
canl_get_error_code(canl_ctx cc)
{
    glb_ctx *ctx = (glb_ctx*) cc;

    if (ctx == NULL)
	return -1;

    return ctx->err_code;
}

char * 
canl_get_error_message(canl_ctx cc)
{
    glb_ctx *ctx = (glb_ctx*) cc;

    if (ctx == NULL)
        return "Context is not initialized";

    return ctx->err_msg;
}

/*if the error code is known to canl, assign appropriate canl code
  TODO go through ssl errors and assign appr. canl code
  ?preserve original one? */
static canl_err_code resolve_error_code(glb_ctx *cc, unsigned long err_code, 
				   canl_err_origin err_orig)
{
    cc->original_err_code = err_code;
    cc->err_orig = err_orig;

    switch (err_orig) {
	case UNKNOWN_ERROR:
	    cc->err_code = (err_code) ? CANL_ERR_unknown : 0;
	    break;
	case POSIX_ERROR:
	    /* We don't use that many posix-like codes, perhaps we want to
	     * map them to CANL codes. */
	    cc->err_code = err_code;
	    break;
	case SSL_ERROR:
	    /* XXX Add mapping based on canl_err_desc.c */
	    /* TODO use err_code until mechanism mapping ssl_codes to 
             * canl_code is implemented 
             * cc->err_code = CANL_ERR_GeneralSSLError; */
            cc->err_code = err_code;
	    break;
	case CANL_ERROR:
	    cc->err_code = err_code;
	    break;
	case NETDB_ERROR:
	    switch (cc->err_code) {
		case HOST_NOT_FOUND:
		    cc->err_code = CANL_ERR_HostNotFound;
		    break;
		default:
		    cc->err_code = CANL_ERR_ResolverError;
		    break;
	    }
	    break;
	default:
	    cc->err_code = CANL_ERR_unknown;
    }

    return cc->err_code;
}
