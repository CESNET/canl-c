#include "canl_locl.h"

#define ERR_CODE_LEN 512

static CANL_ERROR resolve_error(glb_ctx *cc, unsigned long err_code, 
        CANL_ERROR_ORIGIN err_orig);
static void get_error_string(glb_ctx *cc, char *code_str);

/* Save error message into err_msg
 * use NULL for empty err_format */
void update_error (glb_ctx *cc,  const char *err_format, ...)
{
    unsigned int err_msg_len = 0;
    unsigned int err_msg_sum = 0; // sum of msg and format lengths
    int err_format_len = 0;
    int separator_len = 0;
    const char *separator = "; ";
    va_list ap;
    char *new_msg = NULL;
    char *old_msg = NULL;

    if (!cc)
        return;

    if (err_format == NULL) {
        return;
    }
    separator_len = strlen(separator);

    va_start(ap, err_format);

    if (!(cc->err_msg)) {
        vasprintf(&cc->err_msg, err_format, ap);
        va_end(ap);
        return;
    }
    err_format_len = vasprintf(&new_msg, err_format, ap);

    err_msg_len = strlen(cc->err_msg);
    old_msg = cc->err_msg;

    /* Add new error message to the older one */
    err_msg_sum = err_format_len + err_msg_len + separator_len + 1;
    cc->err_msg = (char *) malloc ((err_msg_sum)*sizeof(char));
    if (cc->err_msg == NULL)
        return;

    strncpy(cc->err_msg, new_msg, err_format_len + 1);
    strncat (cc->err_msg, separator, separator_len + 1);
    strncat (cc->err_msg, old_msg, err_msg_len + 1);

    free(new_msg);
    free(old_msg);
}

/* If there was some error message in ctx, delete it and make new */
int set_error (glb_ctx *cc, unsigned long err_code, CANL_ERROR_ORIGIN err_orig,
        const char *err_format, ...)
{
    va_list ap;
    /*check cc*/
    if (!cc) 
        return 1;
    /* if message already exists, delete it */
    if (cc->err_msg)
        reset_error(cc, err_code);

    /* make new message */
    va_start(ap, err_format);
    vasprintf(&cc->err_msg, err_format, ap);
    va_end(ap);

    //0 is not error
    if (!err_code)
	return 0;
    return resolve_error(cc, err_code, err_orig);
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
    cc->err_orig = unknown_error;
}

/* Provide human readable information about errors */
int canl_get_error(canl_ctx cc, char  **reason)
{
    int err = 0;
    int e_orig = unknown_error;
    int error_length = 0;
    char *new_error = NULL;
    char code_str[ERR_CODE_LEN];
    int code_len = 0;
    char *separ = ": ";
    int separ_len = 0;
    int err_msg_len = 0;
    glb_ctx *ctx = (glb_ctx*) cc;

    code_str[0] = '\0';

    /*check cc*/
    if (!ctx) {
        return EINVAL;
    }

    //TODO what to return
    if (!ctx->err_msg)
        goto end;

    /* get human readable error code*/
    get_error_string(cc, code_str);
    code_len = strlen(code_str);

    err_msg_len = strlen(ctx->err_msg);

    separ_len = strlen(separ);
    error_length = err_msg_len + code_len + separ_len + 1;
    new_error = (char *) malloc ((error_length) * sizeof (char));
    if (!new_error) {
        err = ENOMEM;
        e_orig = posix_error;
        goto end;
    }

    strncpy(new_error, ctx->err_msg, err_msg_len + 1);
    strncat(new_error, separ, separ_len + 1);
    strncat(new_error, code_str, code_len + 1);

end:
    *reason = new_error;
    if (err)
        set_error(ctx, err, e_orig, "cannot get error message");
    return err;
}

/*TODO ! map error codes to their human readable strings */
static void get_error_string(glb_ctx *cc, char *code_str)
{
    char *new_str = NULL;

    switch (cc->err_orig) {
        case ssl_error:
            ERR_error_string_n(cc->err_code, code_str,
                    ERR_CODE_LEN);
            break;
        case posix_error:
            new_str = strerror(cc->err_code);
            if (new_str) {
                strncpy(code_str, new_str,
                        ERR_CODE_LEN);
                code_str[ERR_CODE_LEN - 1] = '\0';
            }
        case netdb_error:
            new_str = hstrerror(cc->err_code);
            if (new_str) {
                strncpy(code_str, new_str,
                        ERR_CODE_LEN);
                code_str[ERR_CODE_LEN - 1] = '\0';
            }
            break;
        default:
            break;
    }
}

long
canl_get_error_code(canl_ctx cc)
{
    glb_ctx *ctx = (glb_ctx*) cc;

    if (ctx == NULL)
	return -1;

    return ctx->err_code;
}

/* TODO why canl_get_error, neuvolnila se pamet  ctx->err_msg ???*/
char * 
canl_get_error_message(canl_ctx cc)
{
    glb_ctx *ctx = (glb_ctx*) cc;
    int ret;
    char *msg = NULL;

    if (ctx == NULL)
	return "Context is not initialized";

    ret = canl_get_error(ctx, &msg);
    if (ret)
	return "No human-error available";

    ctx->err_msg = msg;
    return ctx->err_msg;
}

/*if the error code is known to canl, assign appropriate canl code
  TODO go through ssl errors and assign appr. canl code
  ?preserve original one? */
static CANL_ERROR resolve_error(glb_ctx *cc, unsigned long err_code, 
        CANL_ERROR_ORIGIN err_orig)
{
    if (err_orig == canl_error) {
        cc->err_code = err_code;
        cc->err_orig = canl_error;
        return (int)err_code;
    }
    if (err_orig == posix_error) {
        cc->err_code = err_code;
        cc->err_orig = posix_error;
        return (int)err_code;
    }
    if (err_orig == netdb_error) {
        cc->err_code = err_code;
        cc->err_orig = netdb_error;
        return (int)err_code;
    }

    switch (err_code) {
	/*TODO map ssl_errors on canl errors*/
        default:
            cc->err_code = err_code;
            cc->err_orig = err_orig;
            break;
    }

    return 1; //TODO return ssl generic error - add it to canl_error_codes,desc
}
