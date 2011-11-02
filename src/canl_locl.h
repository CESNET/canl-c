#ifndef CANL_CBIND_H
#define CANL_CBIND_H
struct glb_ctx
{
    int opened_ios;
    struct io_handler * io_ctx;
    char * err_msg;
};
/*
   struct ossl_ctx
   {
   SSL_METHOD ssl_meth;
   SSL_CTX ssl_ctx;
   SSL ssl_conn_ctx;
   }
 */
struct io_handler
{
    int something;
};

struct asyn_result {
    struct hostent *ent;
    int err;
};

void make_err_msg (char **err_msg, const char *err_format, ...);

#endif
