#include "canl_locl.h"

static int decrement_timeout(struct timeval *timeout, struct timeval before, struct timeval after);

//#if ARES_VERSION >= 0x010500
static void callback_ares_gethostbyname(void *arg, int status, int timeouts, struct hostent *h)
//#else
//static void callback_ares_gethostbyname(void *arg, int status, struct hostent *h)
//#endif
{
    asyn_result *arp = (asyn_result *) arg;
    int n_addr = 0;
    int i = 0;

    switch (status) {
        case ARES_SUCCESS:
            if (h == NULL || h->h_addr_list[0] == NULL){
                arp->err = NO_DATA;
                break;
            }
            /*how many addresses are there in h->h_addr_list*/
            while (h->h_addr_list[n_addr])
                n_addr++;

            arp->ent->h_addr_list = (char **) calloc((n_addr+1), sizeof(char *));
            if (arp->ent->h_addr_list == NULL) {
                arp->err = NETDB_INTERNAL;
                break;
            }
            for (i = 0; i < n_addr; i++) {
                arp->ent->h_addr_list[i] = malloc(h->h_length);
                if (arp->ent->h_addr_list[i] == NULL) {
                    free_hostent (arp->ent);
                    arp->ent = NULL;
                    arp->err = NETDB_INTERNAL;
                    break;
                }
                memcpy(arp->ent->h_addr_list[i], h->h_addr_list[i],
                        h->h_length);
            }
            /* rest of h members might be assigned here(name,aliases), not necessery now */
            arp->ent->h_addr_list[n_addr] = NULL;
            arp->ent->h_addrtype = h->h_addrtype;
            arp->ent->h_length = h->h_length;
            arp->err = NETDB_SUCCESS;
            break;
        case ARES_EBADNAME:
        case ARES_ENOTFOUND:
        case ARES_ENODATA:
            arp->err = HOST_NOT_FOUND;
            break;
        case ARES_ENOTIMP:
            arp->err = NO_RECOVERY;
            break;
        case ARES_ENOMEM:
        case ARES_EDESTRUCTION:
        default:
            arp->err = NETDB_INTERNAL;
            break;
    }
}

static int decrement_timeout(struct timeval *timeout, struct timeval before, struct timeval after)
{
    (*timeout).tv_sec = (*timeout).tv_sec - (after.tv_sec - before.tv_sec);
    (*timeout).tv_usec = (*timeout).tv_usec - (after.tv_usec - before.tv_usec);
    while ( (*timeout).tv_usec < 0) {
        (*timeout).tv_sec--;
        (*timeout).tv_usec += 1000000;
    }
    if ( ((*timeout).tv_sec < 0) || (((*timeout).tv_sec == 0) && ((*timeout).tv_usec == 0)) ) return(1);
    else return(0);
}


void free_hostent(struct hostent *h)
{
    int i;

    if (h) {
        if (h->h_name) free(h->h_name);
        if (h->h_aliases) {
            for (i=0; h->h_aliases[i]; i++) free(h->h_aliases[i]);
            free(h->h_aliases);
        }
        if (h->h_addr_list) {
            for (i=0; h->h_addr_list[i]; i++) free(h->h_addr_list[i]);
            free(h->h_addr_list);
        }
        free(h);
    }
}

int asyn_getservbyname(int a_family, asyn_result *ares_result,char const *name, 
        struct timeval *timeout)
{
    int err;
    ares_channel channel;
    int nfds;
    fd_set readers, writers;
    struct timeval tv, *tvp;
    struct timeval start_time,check_time;

    /* start timer */
    gettimeofday(&start_time,0);

    /* ares init */
    if ( ares_init(&channel) != ARES_SUCCESS )
        return(NETDB_INTERNAL); //TODO return value...

    /* query DNS server asynchronously */
    ares_gethostbyname(channel, name, a_family, callback_ares_gethostbyname, 
            (void *) ares_result);

    /* wait for result */
    while (1) {
        FD_ZERO(&readers);
        FD_ZERO(&writers);
        nfds = ares_fds(channel, &readers, &writers);
        if (nfds == 0)
            break;

        gettimeofday(&check_time,0);
        if (timeout && decrement_timeout(timeout, start_time, check_time)) {
            ares_destroy(channel);
            return(TRY_AGAIN);
        }
        start_time = check_time;

        tvp = ares_timeout(channel, timeout, &tv);

        switch ( select(nfds, &readers, &writers, NULL, tvp) ) {
            case -1: if (errno != EINTR) {
                         ares_destroy(channel);
                         return NETDB_INTERNAL;
                     } else
                         continue;
            case 0:
                     FD_ZERO(&readers);
                     FD_ZERO(&writers);
                     /* fallthrough */
            default: ares_process(channel, &readers, &writers);
        }
    }
    err = ares_result->err;

    ares_destroy(channel);

    return err;
}
