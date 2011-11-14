#define _GNU_SOURCE //vasprintf
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "canl.h"
#include "canl_locl.h"

/* Save error message into err_msg
 * use NULL for empty err_format */
void update_error (glb_ctx *cc, CANL_ERROR err_code, const char *err_format, ...)
{
    unsigned int err_msg_len = 0;
    unsigned int err_msg_sum = 0; // sum of msg and format lengths
    int err_format_len = 0;
    va_list ap;
    char *new_msg;

    if (!cc)
        return;

    if (err_format == NULL) {
        if (!err_code)
            return;
        else {
            cc->err_code = err_code;
            return;
        }
    }

    va_start(ap, err_format);

    if (!(cc->err_msg)) {
        vasprintf(&cc->err_msg, err_format, ap);
        va_end(ap);
        return;
    }
    err_format_len = vasprintf(&new_msg, err_format, ap);

    err_msg_len = strlen(cc->err_msg);

    /* Add new error message to older one */
    err_msg_sum = err_format_len + err_msg_len;
    /* separator ; and ending '\0' -> 2 bytes */
    cc->err_msg = (char *) realloc (cc->err_msg, (err_msg_sum + 2)*sizeof(char));
    if (cc->err_msg == NULL)
        return;

    strcat (cc->err_msg, ";");
    strcat (cc->err_msg, new_msg);

    cc->err_code = err_code;

    free(new_msg);
}

/* If there was some error message in ctx, delete it and make new */
void set_error (glb_ctx *cc, CANL_ERROR err_code, const char *err_format, ...)
{
    va_list ap;
    /*check cc*/
    if (!cc) 
        return;
    /* if message already exists, delete it */
    if (cc->err_msg)
        reset_error(cc, err_code);

    /* make new message */
    va_start(ap, err_format);
    vasprintf(&cc->err_msg, err_format, ap);
    va_end(ap);

    cc->err_code = err_code;
}

/* Delete error message in ctx, suppose msg is not empty.Set pointer to NULL*/
void reset_error (glb_ctx *cc, CANL_ERROR err_code)
{
    /*check cc*/
    if (!cc )
        return;
    if (cc->err_msg)
        free(cc->err_msg);
    cc->err_msg = NULL;
    cc->err_code = no_error;
}

/* Provide human readable information about errors */
int canl_get_error(canl_ctx cc, char  **reason)
{
    int err = 0;
    int error_length = 0;
    char *new_error = NULL;
    glb_ctx *ctx = (glb_ctx*) cc;

    /*check cc*/
    if (!ctx) {
        return EINVAL;
    }

    if (!ctx->err_msg)
        goto end;

    error_length = strlen(ctx->err_msg);
    new_error = (char *) malloc ((error_length + 1) * sizeof (char));
    if (!new_error) {
        err = ENOMEM;
        goto end;
    }

    strncpy(new_error, ctx->err_msg, error_length + 1);
    *reason = new_error;

end:
    if (err)
        update_error(ctx, err, "cannot get error message (canl_get_error)");
    return err;
}
