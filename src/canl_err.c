#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "canl_locl.h"

/* Save error message into err_msg
 * use NULL for empty err_format */
void make_err_msg (char **err_msg, const char *err_format, ...)
{
    unsigned int err_msg_len = 0;
    va_list ap;
    char *new_msg = NULL;
    int err_format_len = 0;
    unsigned int err_msg_sum = 0; // sum of msg and format lengths

    if (err_format == NULL)
        return;

    if (*err_msg != NULL)
        err_msg_len = strlen(*err_msg);

    /* make new error message */
    va_start(ap, err_format);
    err_format_len = vsnprintf(NULL, 0, err_format, ap );
    new_msg = (char*) malloc ( (err_format_len +1) * sizeof(char));
    vsprintf(new_msg, err_format, ap);
    if (err_format_len < 1)
        return;

    /* Add new error message to older one */
    err_msg_sum = err_format_len + err_msg_len;
    /* separator ; and ending '\0' -> 2 bytes */
    *err_msg = (char *) realloc (*err_msg, (err_msg_sum + 2)*sizeof(char));
    if (*err_msg == NULL)
    {
        free(new_msg);
        return;
    }
    if (err_msg_len == 0)
        (*err_msg)[0] = '\0';
    strcat (*err_msg, new_msg);
    strcat (*err_msg, ";");

    free(new_msg);
}
