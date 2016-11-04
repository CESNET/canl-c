/*********************************************************************
 *
 * Authors: Valerio Venturi - Valerio.Venturi@cnaf.infn.it
 *          Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it
 *
 * Copyright (c) 2002-2009 INFN-CNAF on behalf of the EU DataGrid
 * and EGEE I, II and III
 * For license conditions see LICENSE file or
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/
/**********************************************************************

sslutils.c

Description:
        Routines used internally to implement delegation and proxy 
        certificates for use with Globus The same file is also used
        for the non-exportable sslk5 which allows Kerberos V5 to
        accept SSLv3 with certificates as proof of identiy and
        issue a TGT. 

**********************************************************************/

/**********************************************************************
                             Include header files
**********************************************************************/
#define _GNU_SOURCE

//#include "config.h"
//#include "replace.h"
#include "myproxycertinfo.h"
#include "sslutils.h"
#include "parsertypes.h"
#include "doio.h"
//#include "data.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef DEFAULT_SECURE_TMP_DIR
#ifndef WIN32
#define DEFAULT_SECURE_TMP_DIR "/tmp"
#else
#define DEFAULT_SECURE_TMP_DIR "c:\\tmp"
#endif
#endif

#ifndef WIN32
#define FILE_SEPERATOR "/"
#else
#define FILE_SEPERATOR "\\"
#endif

#ifdef WIN32
#include "winglue.h"
#include <io.h>
#else
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <dirent.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>

#include "openssl/buffer.h"
#include "openssl/crypto.h"

#include "openssl/objects.h"
#include "openssl/asn1.h"
#include "openssl/evp.h"
#include "openssl/pkcs12.h"

#include "openssl/rsa.h"
#include "openssl/rand.h"
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
#include "openssl/x509v3.h"
#endif

#ifndef X509_V_ERR_INVALID_PURPOSE
#define X509_V_ERR_INVALID_PURPOSE X509_V_ERR_CERT_CHAIN_TOO_LONG
#endif 

#ifdef USE_PKCS11
#include "scutils.h"
#endif
/* Maximum leeway in validity period: default 5 minutes */
#define MAX_VALIDITY_PERIOD     (5 * 60)

static int fix_add_entry_asn1_set_param = 0;


#define V1_ROOT (EXFLAG_V1|EXFLAG_SS)
#define ku_reject(x, usage) \
	(((x)->ex_flags & EXFLAG_KUSAGE) && !((x)->ex_kusage & (usage)))
#define xku_reject(x, usage) \
	(((x)->ex_flags & EXFLAG_XKUSAGE) && !((x)->ex_xkusage & (usage)))
#define ns_reject(x, usage) \
	(((x)->ex_flags & EXFLAG_NSCERT) && !((x)->ex_nscert & (usage)))

static X509_NAME *make_DN(const char *dnstring);


extern int restriction_evaluate(STACK_OF(X509) *chain, struct policy **namespaces,
                                struct policy **signings);
extern void voms_free_policies(struct policy **policies);
extern int read_pathrestriction(STACK_OF(X509) *chain, char *path,
                                struct policy ***namespaces, 
                                struct policy ***signings);

static int check_critical_extensions(X509 *cert, int itsaproxy);
static int grid_verifyPathLenConstraints (STACK_OF(X509) * chain);

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/
static ERR_STRING_DATA prxyerr_str_functs[]=
{
    {ERR_PACK(0,PRXYERR_F_PROXY_GENREQ ,0),"proxy_genreq"},
    {ERR_PACK(0,PRXYERR_F_PROXY_SIGN ,0),"proxy_sign"},
    {ERR_PACK(0,PRXYERR_F_VERIFY_CB ,0),"verify_callback"},
    {ERR_PACK(0,PRXYERR_F_PROXY_TMP ,0),"proxy_marshal_tmp"},
    {ERR_PACK(0,PRXYERR_F_INIT_CRED ,0),"proxy_init_cred"},
    {ERR_PACK(0,PRXYERR_F_LOCAL_CREATE, 0),"proxy_local_create"},
    {ERR_PACK(0,PRXYERR_F_CB_NO_PW, 0),"proxy_pw_cb"},
    {ERR_PACK(0,PRXYERR_F_GET_CA_SIGN_PATH, 0),"get_ca_signing_policy_path"},
    {ERR_PACK(0,PRXYERR_F_PROXY_SIGN_EXT ,0),"proxy_sign_ext"},
    {ERR_PACK(0,PRXYERR_F_PROXY_CHECK_SUBJECT_NAME,0),
     "proxy_check_subject_name"},
    {ERR_PACK(0,PRXYERR_F_PROXY_CONSTRUCT_NAME ,0),"proxy_construct_name"},
    {0,NULL},
};

static ERR_STRING_DATA prxyerr_str_reasons[]=
{
    {PRXYERR_R_PROCESS_PROXY_KEY, "processing proxy key"},
    {PRXYERR_R_PROCESS_REQ, "creating proxy req"},
    {PRXYERR_R_PROCESS_SIGN, "while signing proxy req"},
    {PRXYERR_R_MALFORM_REQ, "malformed proxy req"},
    {PRXYERR_R_SIG_VERIFY, "proxy req signature verification error"},
    {PRXYERR_R_SIG_BAD, "proxy req signature does not match"},
    {PRXYERR_R_PROCESS_PROXY, "processing user proxy cert"},
    {PRXYERR_R_PROXY_NAME_BAD, "proxy name does not match"},
    {PRXYERR_R_PROCESS_SIGNC, "while signing proxy cert"},
    {PRXYERR_R_BAD_PROXY_ISSUER, "proxy can only be signed by user"},
    {PRXYERR_R_SIGN_NOT_CA ,"user cert not signed by CA"},
    {PRXYERR_R_PROBLEM_PROXY_FILE ,"problems creating proxy file"},
    {PRXYERR_R_PROCESS_KEY, "processing key"},
    {PRXYERR_R_PROCESS_CERT, "processing cert"},
    {PRXYERR_R_PROCESS_CERTS, "unable to access trusted certificates in:"},
    {PRXYERR_R_PROCESS_PROXY, "processing user proxy cert"},
    {PRXYERR_R_NO_TRUSTED_CERTS, "check X509_CERT_DIR and X509_CERT_FILE"},
    {PRXYERR_R_PROBLEM_KEY_FILE, "bad file system permissions on private key\n"
                                 "    key must only be readable by the user"},
    {PRXYERR_R_SERVER_ZERO_LENGTH_KEY_FILE, "system key file is empty"},
    {PRXYERR_R_USER_ZERO_LENGTH_KEY_FILE, "user private key file is empty"},
    {PRXYERR_R_PROBLEM_SERVER_NOKEY_FILE, "system key cannot be accessed"},
    {PRXYERR_R_PROBLEM_USER_NOKEY_FILE, "user private key cannot be accessed"},
    {PRXYERR_R_PROBLEM_SERVER_NOCERT_FILE, "system certificate not found"},
    {PRXYERR_R_PROBLEM_USER_NOCERT_FILE, "user certificate not found"},
    {PRXYERR_R_INVALID_CERT, "no certificate in file"},
    {PRXYERR_R_REMOTE_CRED_EXPIRED, "remote certificate has expired"},
    {PRXYERR_R_USER_CERT_EXPIRED, "user certificate has expired"},
    {PRXYERR_R_SERVER_CERT_EXPIRED, "system certificate has expired"},
    {PRXYERR_R_PROXY_EXPIRED, "proxy expired: run grid-proxy-init or wgpi first"},
    {PRXYERR_R_NO_PROXY, "no proxy credentials: run grid-proxy-init or wgpi first"},
    {PRXYERR_R_CRL_SIGNATURE_FAILURE, "invalid signature on a CRL"},
    {PRXYERR_R_CRL_NEXT_UPDATE_FIELD, "invalid nextupdate field in CRL"},
    {PRXYERR_R_CRL_HAS_EXPIRED, "outdated CRL found, revoking all certs till you get new CRL"},
    {PRXYERR_R_CERT_REVOKED, "certificate revoked per CRL"},
    {PRXYERR_R_NO_HOME, "can't determine HOME directory"},
    {PRXYERR_R_KEY_CERT_MISMATCH, "user key and certificate don't match"},
    {PRXYERR_R_WRONG_PASSPHRASE, "wrong pass phrase"},
    {PRXYERR_R_CA_POLICY_VIOLATION, "remote certificate CA signature not allowed by policy"},
    {PRXYERR_R_CA_POLICY_ERR,"no matching CA found in file for remote certificate"}, 
    {PRXYERR_R_CA_NOFILE,"could not find CA policy file"}, 
    {PRXYERR_R_CA_NOPATH,"could not determine path to CA policy file"}, 
    {PRXYERR_R_CA_POLICY_RETRIEVE, "CA policy retrieve problems"},
    {PRXYERR_R_CA_POLICY_PARSE, "CA policy parse problems"},
    {PRXYERR_R_CA_UNKNOWN,"remote certificate signed by unknown CA"},
    {PRXYERR_R_PROBLEM_CLIENT_CA, "problems getting client_CA list"},
    {PRXYERR_R_CB_NO_PW, "no proxy credentials: run grid-proxy-init or wgpi first"},
    {PRXYERR_R_CB_CALLED_WITH_ERROR,"certificate failed verify:"},
    {PRXYERR_R_CB_ERROR_MSG, "certificate:"},
    {PRXYERR_R_CLASS_ADD_OID,"can't find CLASS_ADD OID"},
    {PRXYERR_R_CLASS_ADD_EXT,"problem adding CLASS_ADD Extension"},
    {PRXYERR_R_DELEGATE_VERIFY,"problem verifiying the delegate extension"},
    {PRXYERR_R_EXT_ADD,"problem adding extension"},
    {PRXYERR_R_DELEGATE_CREATE,"problem creating delegate extension"},
    {PRXYERR_R_DELEGATE_COPY,"problem copying delegate extension to proxy"},
    {PRXYERR_R_BUFFER_TOO_SMALL,"buffer too small"},
    {PRXYERR_R_CERT_NOT_YET_VALID,"remote certificate not yet valid"},
    {PRXYERR_R_LOCAL_CA_UNKNOWN,"cannot find CA certificate for local credential"},
    {PRXYERR_R_OUT_OF_MEMORY,"out of memory"},
    {PRXYERR_R_BAD_ARGUMENT,"bad argument"},
    {PRXYERR_R_BAD_MAGIC,"bad magic number"},
    {PRXYERR_R_UNKNOWN_CRIT_EXT,"unable to handle critical extension"},
    {0,NULL}
};

int my_txt2nid(char *name)
{
  ASN1_OBJECT *obj = OBJ_txt2obj(name,1);
  int nid = OBJ_obj2nid(obj);
  ASN1_OBJECT_free(obj);

  return nid;
}

/*********************************************************************
Function: X509_NAME_cmp_no_set

Description:
        To circumvent a bug with adding X509_NAME_ENTRIES 
        with the wrong "set", we will compare names without
        the set. 
        This is a temporary fix which will be removed when we
        fix the creation of the names using the correct sets. 
        This is only being done this way for some compatability
        while installing the these fixes. 
        This fix is needed in all previous versions of Globus. 

Parameters:
        same as X509_NAME_cmp
Returns :
        same as X509_NAME_cmp 
********************************************************************/
static int
X509_NAME_cmp_no_set(
    X509_NAME *                         a,
    X509_NAME *                         b)
{
    int                                 i;
    int                                 j;
    X509_NAME_ENTRY *                   na;
    X509_NAME_ENTRY *                   nb;

    if (X509_NAME_entry_count(a) != X509_NAME_entry_count(b))
    {
        return(X509_NAME_entry_count(a) - X509_NAME_entry_count(b));
    }
    
    for (i=X509_NAME_entry_count(a)-1; i>=0; i--)
    {
        ASN1_STRING *val_a, *val_b;

        na = X509_NAME_get_entry(a,i);
        nb = X509_NAME_get_entry(b,i);

        val_a = X509_NAME_ENTRY_get_data(na);
        val_b = X509_NAME_ENTRY_get_data(nb);
        j = val_a->length - val_b->length;

        if (j)
        {
            return(j);
        }
        
        j = memcmp(val_a->data,
                   val_b->data,
                   val_a->length);
        if (j)
        {
            return(j);
        }
    }

    /* We will check the object types after checking the values
     * since the values will more often be different than the object
     * types. */
    for (i=X509_NAME_entry_count(a)-1; i>=0; i--)
    {
        na = X509_NAME_get_entry(a,i);
        nb = X509_NAME_get_entry(b,i);
        j = OBJ_cmp(X509_NAME_ENTRY_get_object(na),
                    X509_NAME_ENTRY_get_object(nb));

        if (j)
        {
            return(j);
        }
    }
    return(0);
}

#ifdef WIN32
/*********************************************************************
Function: getuid, getpid

Descriptions:
        For Windows95, WIN32, we don't have these, so we will default
    to using uid 0 and pid 0 Need to look at this better for NT. 
******************************************************************/
static unsigned long
getuid()
{
    return 0;
}

static int
getpid()
{
    return 0;
}

#endif /* WIN32 */


#if SSLEAY_VERSION_NUMBER < 0x0900

/**********************************************************************
Function: ERR_add_error_data()

Description:
    Dummy routine only defined if running with SSLeay-0.8.x 
    this feature was introduced with SSLeay-0.9.0

Parameters:

Returns:
**********************************************************************/
void PRIVATE
ERR_add_error_data( VAR_PLIST( int, num ))
    VAR_ALIST
{
    VAR_BDEFN(args, int, num);
}

/**********************************************************************
Function: ERR_get_error_line_data()

Description:
    Dummy routine only defined if running with SSLeay-0.8.x 
    this feature was introduced with SSLeay-0.9.0. We will
    simulate it for 0.8.1

Parameters:

Returns:
**********************************************************************/
unsigned long PRIVATE
ERR_get_error_line_data(
    char **                             file,
    int *                               line,
    char **                             data,
    int *                               flags)
{
    if (data)
    {
        *data = "";
    }
    
    if (flags)
    {
        *flags = 0;
    }
    
    return (ERR_get_error_line(file, line));
}

#endif

/**********************************************************************
Function: ERR_set_continue_needed()

Description:
        Sets state information which error display routines can use to
        determine if the error just added is enough information to describe
        the error or if further error information need displayed. 
        (By default gss_display_status will only show one user level error)
        
        note: This function must be called after (or instead of) the ssl add error
        data functions.
        
Parameters:

Returns:
**********************************************************************/
    
void PRIVATE
ERR_set_continue_needed(void)
{
    ERR_STATE *es;
    es = ERR_get_state();
    es->err_data_flags[es->top] = 
        es->err_data_flags[es->top] | ERR_DISPLAY_CONTINUE_NEEDED;
}

/**********************************************************************
Function: ERR_load_prxyerr_strings()

Description:
    Sets up the error tables used by SSL and adds ours
    using the ERR_LIB_USER
    Only the first call does anything.
        Will also add any builtin objects for SSLeay. 

Parameters:
    i should be zero the first time one of the ERR_load functions
    is called and non-zero for each additional call.

Returns:
**********************************************************************/

int PRIVATE
ERR_load_prxyerr_strings(
    int                                 i)
{
    static int                          init = 1;
    struct stat                         stx;
    clock_t cputime;
#if SSLEAY_VERSION_NUMBER  >= 0x00904100L
    const char *                        randfile;
#else
    char *                              randfile;
#endif
#if SSLEAY_VERSION_NUMBER >=  0x0090581fL
    char *                              egd_path;
#endif
    char                                buffer[200];
        
    if (init)
    {
        init = 0;
        
#ifndef RAND_DO_NOT_USE_CLOCK
        clock(); 
#endif
        if (i == 0)
        {
            SSL_load_error_strings();
        }
        
        OBJ_create("1.3.6.1.4.1.3536.1.1.1.1","CLASSADD","ClassAdd");
        OBJ_create("1.3.6.1.4.1.3536.1.1.1.2","DELEGATE","Delegate");
        OBJ_create("1.3.6.1.4.1.3536.1.1.1.3","RESTRICTEDRIGHTS",
                   "RestrictedRights");
        OBJ_create("0.9.2342.19200300.100.1.1","USERID","userId");

        ERR_load_strings(ERR_USER_LIB_PRXYERR_NUMBER,prxyerr_str_functs);
        ERR_load_strings(ERR_USER_LIB_PRXYERR_NUMBER,prxyerr_str_reasons);

        /*
         * We need to get a lot of randomness for good security
         * OpenSSL will use /dev/urandom (if available),
         * uid, time, and gid. 
         *
         * If user has RANDFILE set, or $HOME/.rnd
         * load it for extra random seed.
         * This may also not be enough, so we will also add in
         * the time it takes to run this routine, which includes 
         * reading the randfile.    
         * Later we will also add in some keys and some stats
         * if we have them.
         * look for RAND_add in this source file.
         *
         * Other methods we could use:
         *  * Librand from  Don Mitchell and Matt Blaze
         *  * Doing a netstat -in 
         *  * some form of pstat
         * But /dev/random and/or egd should be enough.
         */

        randfile = RAND_file_name(buffer,200);

        if (randfile)
        {
            RAND_load_file(randfile,1024L*1024L);
        }

#if SSLEAY_VERSION_NUMBER >=  0x0090581fL
        /*
         * Try to use the Entropy Garthering Deamon
         * See the OpenSSL crypto/rand/rand_egd.c 
         */
        egd_path = getenv("EGD_PATH");
        if (egd_path == NULL)
        {
            egd_path = "/etc/entropy";
        }
        RAND_egd(egd_path);
#endif
                
        /* if still not enough entropy*/
        if (RAND_status() == 0)
        {
            stat("/tmp",&stx); /* get times /tmp was modified */
            RAND_add((void*)&stx,sizeof(stx),16);
        }

#ifndef RAND_DO_NOT_USE_CLOCK
        cputime = clock();
        RAND_add((void*)&cputime, sizeof(cputime),8);
#endif

        i++;
#ifdef USE_PKCS11
        i = ERR_load_scerr_strings(i);
#endif

    }
    return i;
}

/**********************************************************************
Function:       checkstat()
Description:    check the status of a file
Parameters:
Returns:
                0 pass all the following tests
                1 does not exist
                2 not owned by user
                3 readable by someone else
                4 zero length
**********************************************************************/
static int checkstat(const char* filename)
{
    struct stat                         stx;

    if (stat(filename,&stx) != 0)
    {
        return 1;
    }

    /*
     * use any stat output as random data, as it will 
     * have file sizes, and last use times in it. 
     */
    RAND_add((void*)&stx,sizeof(stx),2);

#if !defined(WIN32) && !defined(TARGET_ARCH_CYGWIN)
    if (stx.st_uid != getuid())
    {
      return 2;
    }

    if (stx.st_mode & 066)
    {
        return 3;
    }
    
#endif /* !WIN32 && !TARGET_ARCH_CYGWIN */

    if (stx.st_size == 0)
    {
        return 4;
    }
    return 0;

}

/**********************************************************************
Function: proxy_load_user_proxy()

Description:
        Given the user_proxy file, skip the first cert, 
        and add any additional certs to the cert_chain. 
        These must be additional proxies, or the user's cert
        which signed the proxy. 
        This is based on the X509_load_cert_file routine.

Parameters:

Returns:
**********************************************************************/

int PRIVATE
proxy_load_user_proxy(
    STACK_OF(X509) *                    cert_chain,
    const char *                        file)
{

    int                                 ret = -1;
    BIO *                               in = NULL;
    int                                 count=0;
    X509 *                              x = NULL;

    if (file == NULL)
      return(1);

    in = BIO_new(BIO_s_file());


    if ((in == NULL) || (BIO_read_filename(in,file) <= 0))
    {
        X509err(PRXYERR_F_PROXY_LOAD, PRXYERR_R_PROCESS_PROXY);
        goto err;
    }

    for (;;)
    {
        x = PEM_read_bio_X509(in,NULL, OPENSSL_PEM_CB(NULL,NULL));
        if (x == NULL)
        {
            if ((ERR_GET_REASON(ERR_peek_error()) ==
                 PEM_R_NO_START_LINE) && (count > 0))
            {
                ERR_clear_error();
                break;
            }
            else
            {
                X509err(PRXYERR_F_PROXY_LOAD, PRXYERR_R_PROCESS_PROXY);
                goto err;
            }
        }

        if (count) {
          (void)sk_X509_insert(cert_chain,x,sk_X509_num(cert_chain));

          x = NULL;
        }
        
        count++;

        if (x)
        {
            X509_free(x);
            x = NULL;
        }
    }
    ret = count;
        
err:
    if (x != NULL)
    {
        X509_free(x);
    }
    
    if (in != NULL)
    {
        BIO_free(in);
    }
    return(ret);
}


/**********************************************************************
Function: proxy_genreq()

Description:
        generate certificate request for a proxy certificate. 
        This is based on using the current user certificate.
        If the current user cert is NULL, we are asking fke the server
    to fill this in, and give us a new cert. Used with k5cert.

Parameters:

Returns:
**********************************************************************/

int PRIVATE
proxy_genreq(
    X509 *                              ucert,
    X509_REQ **                         reqp,
    EVP_PKEY **                         pkeyp,
    int                                 bits,
    const char *                        newdn,
    int                                 (*callback)())

{
    RSA *                               rsa = NULL;
    EVP_PKEY *                          pkey = NULL;
    EVP_PKEY *                          upkey = NULL;
    X509_NAME *                         name = NULL; 
    X509_REQ *                          req = NULL;
    X509_NAME_ENTRY *                   ne = NULL;
    int                                 rbits;

    if (bits)
    {
        rbits = bits;
    }
    else if (ucert)
    { 
        if ((upkey = X509_get_pubkey(ucert)) == NULL)
        {
            PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
            goto err;
        }
        
        if (EVP_PKEY_id(upkey) != EVP_PKEY_RSA)
        {
            PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
            goto err;
        }
        
        rbits = 8 * EVP_PKEY_size(upkey);
        EVP_PKEY_free(upkey);
    }
    else
    {
        rbits = 512;
    }

    if ((pkey = EVP_PKEY_new()) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
        goto err;
    }

    /*
     * Note: The cast of the callback function is consistent with
     * the declaration of RSA_generate_key() in OpenSSL.  It may
     * trigger a warning if you compile with SSLeay.
     */
    if ((rsa = RSA_generate_key(rbits,
                                RSA_F4,
                                (void (*)(int,int,void *))callback
                                ,NULL)) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
        goto err;
    }
    
    if (!EVP_PKEY_assign_RSA(pkey,rsa))
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
        goto err;
    }
    
    if ((req = X509_REQ_new()) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_REQ);
        goto err;
    }

    X509_REQ_set_version(req,0L);

    if (!newdn) {
      if (ucert) {

        if ((name = X509_NAME_dup(X509_get_subject_name(ucert))) == NULL) {
          PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_REQ);
          goto err;
        }
      }
      else {
        name = X509_NAME_new();
      }
                
        
      if ((ne = X509_NAME_ENTRY_create_by_NID(NULL,NID_commonName,
                                              V_ASN1_APP_CHOOSE,
                                              (unsigned char *)"proxy",
                                              -1)) == NULL) {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_REQ);
        goto err;
      }
      X509_NAME_add_entry(name,
                          ne,
                          X509_NAME_entry_count(name),
                          fix_add_entry_asn1_set_param);
    }
    else {
      name = make_DN(newdn);
      if (!name) {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_REQ);
        goto err;
      }
    }

    X509_REQ_set_subject_name(req,name);
    X509_NAME_free(name);
    name = NULL;
    X509_REQ_set_pubkey(req,pkey);

    if (!X509_REQ_sign(req,pkey,EVP_sha1()))
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_SIGN);
        goto err;
    }
        
    if (ne)
    {
        X509_NAME_ENTRY_free(ne);
        ne = NULL;
    }

    *pkeyp = pkey;
    *reqp = req;
    return 0;

err:
    if (upkey)
      EVP_PKEY_free(upkey);

    if(rsa)
    {
        RSA_free(rsa);
    }
    if (pkey)
    {
        EVP_PKEY_free(pkey);
    }
    if (name)
    {
        X509_NAME_free(name);
    }
    if (req)
    {
        X509_REQ_free(req);
    }
    if (ne)
    {
        X509_NAME_ENTRY_free(ne);
    }
    return 1;
}


/**
 * Sign a certificate request  
 *
 * This function is a wrapper function for proxy_sign_ext. The subject
 * name of the resulting certificate is generated by adding either
 * cn=proxy or cn=limited proxy to the subject name of user_cert. The
 * issuer name is set to the subject name of user_cert.
 *
 * @param user_cert
 *        A certificate to be used for subject and issuer name
 *        information if that information isn't provided.
 * @param user_private_key
 *        The private key to be used for signing the certificate
 *        request.
 * @param req
 *        The certificate request
 * @param new_cert
 *        This parameter will contain the signed certficate upon
 *        success. 
 * @param seconds
 *        The number of seconds the new cert is going to be
 *        valid. The validity should not exceed that of the issuing
 *        key pair. If this parameter is 0 the generated cert will
 *        have the same lifetime as the issuing key pair.
 * @param extensions
 *        Extensions to be placed in the new certificate.
 * @param limited_proxy
 *        If this value is non zero the resulting cert will be a
 *        limited proxy.
 *
 * @return
 *        This functions returns 0 upon success, 1 upon failure. It
 *        will also place a more detailed error on an error stack.
 */

int PRIVATE
proxy_sign(
    X509 *                              user_cert,
    EVP_PKEY *                          user_private_key,
    X509_REQ *                          req,
    X509 **                             new_cert,
    int                                 seconds,
    STACK_OF(X509_EXTENSION) *          extensions,
    int                                 limited_proxy,
    int                                 proxyver,
    const char *                        newdn,
    const char *                        newissuer,
    int                                 pastproxy,
    const char *                        newserial,
    int                                 selfsigned
)
{
    char *                              newcn;
    EVP_PKEY *                          user_public_key;
    X509_NAME *                         subject_name = NULL;
    X509_NAME *                         issuer_name = NULL;
    int                                 rc = 0;

    unsigned char                       md[SHA_DIGEST_LENGTH];
    unsigned int                        len;


    if(proxyver>=3) {
      long sub_hash;

      user_public_key = X509_get_pubkey(user_cert);
#ifdef TYPEDEF_I2D_OF
      ASN1_digest((i2d_of_void*)i2d_PUBKEY, EVP_sha1(), (char *) user_public_key, md, &len);
#else
      ASN1_digest(i2d_PUBKEY, EVP_sha1(), (char *) user_public_key, md, &len);
#endif
      EVP_PKEY_free(user_public_key);

      sub_hash = md[0] + (md[1] + (md[2] + (md[3] >> 1) * 256) * 256) * 256;
 
      newcn = snprintf_wrap("%ld", sub_hash);
    }
    else {
      if(limited_proxy)
        newcn = "limited proxy";
      else
        newcn = "proxy";
    }
    
    if (newdn == NULL) {
      if(proxy_construct_name(
                              user_cert,
                              &subject_name,
                              newcn, -1)) {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_PROCESS_SIGN);
        if (proxyver >= 3)
          free(newcn);
        return 1;
      }
    }
    else
      subject_name = make_DN(newdn);

    if (newissuer)
      issuer_name = make_DN(newissuer);
    else
      issuer_name = NULL;

    if(proxy_sign_ext(user_cert,
                      user_private_key,
                      EVP_sha1(), 
                      req,
                      new_cert,
                      subject_name,
                      issuer_name,
                      seconds,
                      extensions,
                      proxyver,
                      pastproxy,
                      newserial,
                      selfsigned))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_PROCESS_SIGN);
        rc = 1;
    }

    X509_NAME_free(subject_name);

    if (issuer_name)
      X509_NAME_free(issuer_name);

    if (proxyver >= 3)
      free(newcn);

    return rc;
}

/**
 * Sign a certificate request  
 *
 * This function signs the given certificate request. Before signing
 * the certificate the certificate's subject and issuer names may be
 * replaced and extensions may be added to the certificate.
 *
 * @param user_cert
 *        A certificate to be used for lifetime and serial number
 *        information if that information isn't provided.
 * @param user_private_key
 *        The private key to be used for signing the certificate
 *        request.
 * @param method
 *        The method to employ for signing
 * @param req
 *        The certificate request
 * @param new_cert
 *        This parameter will contain the signed certficate upon
 *        success. 
 * @param subject_name
 *        The subject name to be used for the new certificate. If no
 *        subject name is provided the subject name in the certificate
 *        request will remain untouched.
 * @param issuer_name
 *        The issuer name to be used for the new certificate. If no
 *        issuer name is provided the issuer name will be set to the
 *        subject name of the user cert.
 * @param seconds
 *        The number of seconds the new cert is going to be
 *        valid. The validity should not exceed that of the issuing
 *        key pair. If this parameter is 0 the generated cert will
 *        have the same lifetime as the issuing key pair.
 * @param serial_num
 *        The serial number to be used for the new cert. If this
 *        parameter is 0 the serial number of the user_cert is used.
 * @param extensions
 *        Extensions to be placed in the new certificate.
 *
 * @return
 *        This functions returns 0 upon success, 1 upon failure. It
 *        will also place a more detailed error on an error stack.
 */

int PRIVATE 
proxy_sign_ext(
    X509 *                    user_cert,
    EVP_PKEY *                user_private_key,
    const EVP_MD *            method,
    X509_REQ *                req,
    X509 **                   new_cert,
    X509_NAME *               subject_name,
    X509_NAME *               issuer_name,    
    int                       seconds,
    STACK_OF(X509_EXTENSION) *extensions,
    int                       proxyver,
    int                       pastproxy,
    const char               *newserial,
    int                       selfsigned)
{
    EVP_PKEY *                          new_public_key = NULL;
    EVP_PKEY *                          tmp_public_key = NULL;
    X509_CINF *                         user_cert_info;
    X509_EXTENSION *                    extension = NULL;
    time_t                              time_diff, time_now, time_after;
    ASN1_UTCTIME *                      asn1_time = NULL;
    int                                 i;
    unsigned char                       md[SHA_DIGEST_LENGTH];
    unsigned int                        len;

/* for openssl 1.1
    if (!selfsigned)
      user_cert_info = user_cert->cert_info;
*/

    *new_cert = NULL;
    
/*
    if ((req->req_info == NULL) ||
        (req->req_info->pubkey == NULL) ||
        (req->req_info->pubkey->public_key == NULL) ||
        (req->req_info->pubkey->public_key->data == NULL))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_MALFORM_REQ);
        goto err;
    }
*/
    
    if ((new_public_key=X509_REQ_get_pubkey(req)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_MALFORM_REQ);
      goto err;
    }

    i = X509_REQ_verify(req,new_public_key);
    EVP_PKEY_free(new_public_key);
    new_public_key = NULL;

    if (i < 0)
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_SIG_VERIFY);
        goto err;
    }

    if (i == 0)
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_SIG_BAD);
        goto err;
    }

    /* signature ok. */

    if ((*new_cert = X509_new()) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
        goto err;
    }

    /* set the subject name */

    if(subject_name && !X509_set_subject_name(*new_cert,subject_name))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
        goto err;
    }

    /* DEE? will use same serial number, this may help
     * with revocations, or may cause problems.
     */

    if (newserial) {
      BIGNUM *bn = NULL;
      if (BN_hex2bn(&bn, newserial) != 0) {
        ASN1_INTEGER *a_int = BN_to_ASN1_INTEGER(bn, NULL);

        i = X509_set_serialNumber(*new_cert, a_int);
        BN_free(bn);
      }
    }
    else if (proxyver > 2) {
      ASN1_INTEGER *serial = NULL;

//      ASN1_INTEGER_free(X509_get_serialNumber(*new_cert));
          
      new_public_key = X509_REQ_get_pubkey(req);
#ifdef TYPEDEF_I2D_OF
      ASN1_digest((i2d_of_void*)i2d_PUBKEY, EVP_sha1(), (char *) new_public_key, md, &len);
#else
      ASN1_digest(i2d_PUBKEY, EVP_sha1(), (char *) new_public_key, md, &len);
#endif
      EVP_PKEY_free(new_public_key);
      new_public_key = NULL;

	  /* According to ITU-T recommendation X.690 the first nine bites shall not
	   * be 0 or 1, see also https://ggus.eu/index.php?mode=ticket_info&ticket_id=113418.
	   * To obey the demand we put an additional byte at the very beginning. */
	  len++;

      serial = ASN1_INTEGER_new();
      serial->length = len;
      serial->data   = malloc(len);
      if (serial->data == NULL) {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT, PRXYERR_R_PROCESS_PROXY);
        goto err;
      }
      serial->data[0] = 0x01;
      memcpy(serial->data+1, md, SHA_DIGEST_LENGTH);

      i = X509_set_serialNumber(*new_cert, serial);
      ASN1_INTEGER_free(serial);

/*
      (*new_cert)->cert_info->serialNumber = ASN1_INTEGER_new();
      (*new_cert)->cert_info->serialNumber->length = len;
      (*new_cert)->cert_info->serialNumber->data   = malloc(len);

      if (!((*new_cert)->cert_info->serialNumber->data)) {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT, PRXYERR_R_PROCESS_PROXY);
        goto err;
      }
	  (*new_cert)->cert_info->serialNumber->data[0] = 0x01;
      memcpy((*new_cert)->cert_info->serialNumber->data + 1, md, SHA_DIGEST_LENGTH);
*/
    } 
    else if (selfsigned) {
      ASN1_INTEGER *copy = ASN1_INTEGER_new();
      if (copy) {
        ASN1_INTEGER_set(copy, 1);
        i = X509_set_serialNumber(*new_cert, copy);
        ASN1_INTEGER_free(copy);
      }
      else
        goto err;
    }
    else {
#if 0
      ASN1_INTEGER *copy = ASN1_INTEGER_dup(X509_get_serialNumber(user_cert));
      ASN1_INTEGER_free((*new_cert)->cert_info->serialNumber);

      /* Note:  The copy == NULL case is handled immediately below. */
      (*new_cert)->cert_info->serialNumber = copy;
#endif
      i = X509_set_serialNumber(*new_cert, X509_get_serialNumber(user_cert));
    }

    if (i == 0) {
      PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
      goto err;
    }


    /* set the issuer name */

    if (issuer_name)
    {
        if(!X509_set_issuer_name(*new_cert,issuer_name))
        {
            PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
            goto err;
        }
    }
    else
    {
        if(!X509_set_issuer_name(*new_cert,X509_get_subject_name(user_cert)))
        {
            PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
            goto err;
        } 
    }

    /* Allow for a five minute clock skew here. */
 
    X509_gmtime_adj(X509_get_notBefore(*new_cert),-5*60 -pastproxy);

    /* DEE? should accept an seconds parameter, and set to min of
     * hours or the ucert notAfter
     * for now use seconds if not zero. 
     */
    
    if (selfsigned) {
      X509_gmtime_adj(X509_get_notAfter(*new_cert),(long) seconds - pastproxy);
    }
    else {
      /* doesn't create a proxy longer than the user cert */
      asn1_time = ASN1_UTCTIME_new();
      X509_gmtime_adj(asn1_time, -pastproxy);
      time_now = ASN1_UTCTIME_mktime(asn1_time);
      ASN1_UTCTIME_free(asn1_time);
      time_after = ASN1_UTCTIME_mktime(X509_get_notAfter(user_cert));
      time_diff = time_after - time_now;

      if(time_diff > (seconds - pastproxy)) {
        X509_gmtime_adj(X509_get_notAfter(*new_cert),(long) seconds - pastproxy);
      }
      else {
        X509_set_notAfter(*new_cert, X509_get0_notAfter(user_cert));
      }
    }

    /* transfer the public key from req to new cert */
    /* DEE? should this be a dup? */

    new_public_key = X509_REQ_get0_pubkey(req);
    X509_set_pubkey(*new_cert, new_public_key);
//    req->req_info->pubkey = NULL;

    /*
     * We can now add additional extentions here
     * such as to control the usage of the cert
     */

    X509_set_version(*new_cert, 2); /* version 3 certificate */

#if 0
    /* Free the current entries if any, there should not
     * be any I belive 
     */
    
    if (new_cert_info->extensions != NULL)
    {
        sk_X509_EXTENSION_pop_free(new_cert_info->extensions,
                                   X509_EXTENSION_free);
    }
#endif
        
    /* Add extensions provided by the client */

    if (extensions)
    {
#if 0
        if ((new_cert_info->extensions =
             sk_X509_EXTENSION_new_null()) == NULL)
        {
            PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_DELEGATE_COPY);
        }
#endif

        /* Lets 'copy' the client extensions to the new proxy */
        /* we should look at the type, and only copy some */

        for (i=0; i<sk_X509_EXTENSION_num(extensions); i++)
        {
#if 0
            extension = X509_EXTENSION_dup(
                sk_X509_EXTENSION_value(extensions,i));

            if (extension == NULL)
            {
                PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_DELEGATE_COPY);
                goto err;
            }
            
            if (!sk_X509_EXTENSION_push(new_cert_info->extensions,
                                        extension))
            {
                PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_DELEGATE_COPY);
                goto err;
            }
#endif
            extension = sk_X509_EXTENSION_value(extensions, i);
            i = X509_add_ext(*new_cert, extension, -1);
            if (i == 0)
            {
                PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_DELEGATE_COPY);
                goto err;
            }
        }
    }

    /* new cert is built, now sign it */

#ifndef NO_DSA
    /* DEE? not sure what this is doing, I think
     * it is adding from the key to be used to sign to the 
     * new certificate any info DSA may need
     */
    
    tmp_public_key = X509_get_pubkey(*new_cert);
    
    if (EVP_PKEY_missing_parameters(tmp_public_key) &&
        !EVP_PKEY_missing_parameters(user_private_key))
    {
        EVP_PKEY_copy_parameters(tmp_public_key,user_private_key);
    }
#endif

    EVP_PKEY_free(tmp_public_key);

    if (!X509_sign(*new_cert,user_private_key,method))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_SIGNC);
        goto err;
    }

    return 0;

err:
    /* free new_cert upon error */
    
    if (*new_cert)
    {
        X509_free(*new_cert);
    }

    if (new_public_key)
      EVP_PKEY_free(new_public_key);

    return 1;
}




/**
 * Construct a X509 name
 *
 * This function constructs a X509 name by taking the subject name of
 * the certificate and adding a new CommonName field with value newcn
 * (if this parameter is non NULL). The resulting name should be freed
 * using X509_NAME_free.
 *
 * @param cert
 *        The certificate to extract the subject name from.
 * @param name
 *        The resulting name
 * @param newcn
 *        The value of the CommonName field to add. If this value is
 *        NULL this function just returns a copy of the subject name
 *        of the certificate.
 *
 * @return
 *        This functions returns 0 upon success, 1 upon failure. It
 *        will also place a more detailed error on an error stack.
 */

int PRIVATE
proxy_construct_name(
    X509 *                              cert,
    X509_NAME **                        name,
    char *                              newcn,
    unsigned int                        len)
{
    X509_NAME_ENTRY *                   name_entry = NULL;
    *name = NULL;
    
    if ((*name = X509_NAME_dup(X509_get_subject_name(cert))) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_CONSTRUCT_NAME,PRXYERR_R_PROCESS_PROXY);
        goto err;
    }

    if(newcn)
    {
        if ((name_entry = X509_NAME_ENTRY_create_by_NID(NULL,
							NID_commonName,
                                                        V_ASN1_APP_CHOOSE,
                                                        (unsigned char *)newcn,
                                                        len)) == NULL)
        {
            PRXYerr(PRXYERR_F_PROXY_CONSTRUCT_NAME,PRXYERR_R_PROCESS_PROXY);
            goto err;
        }

        if (!X509_NAME_add_entry(*name,
                                 name_entry,
                                 X509_NAME_entry_count(*name),
                                 fix_add_entry_asn1_set_param))
        {
            PRXYerr(PRXYERR_F_PROXY_CONSTRUCT_NAME,PRXYERR_R_PROCESS_PROXY);
            goto err;
        }
        X509_NAME_ENTRY_free(name_entry);
    }
    
    return 0;

err:
    if (*name)
    {
        X509_NAME_free(*name);
    }

    if (name_entry)
    {
        X509_NAME_ENTRY_free(name_entry);
    }

    return 1;
    
}
    


/**********************************************************************
Function: proxy_marshal_bp()

Description:
        Write to a bio the proxy certificate, key, users certificate,
        and any other certificates need to use the proxy.

Parameters:

Returns:
**********************************************************************/
int PRIVATE
proxy_marshal_bp(
    BIO *                               bp,
    X509 *                              ncert,
    EVP_PKEY *                          npkey,
    X509 *                              ucert,
    STACK_OF(X509) *                    cert_chain)
{
    X509 *                              cert;

    if (!PEM_write_bio_X509(bp,ncert))
    {
        return 1;
    }

    if (!PEM_write_bio_RSAPrivateKey(bp,
                                     EVP_PKEY_get0_RSA(npkey),
                                     NULL,
                                     NULL,
                                     0,
                                     OPENSSL_PEM_CB(NULL,NULL)))
    {
        return 2;
    }

    if (ucert)
    {
        if (!PEM_write_bio_X509(bp,ucert))
        {
            return 3;
        }
    }

    if (cert_chain)
    {
        /*
         * add additional certs, but not our cert, or the 
         * proxy cert, or any self signed certs
         */
        int i;

        for(i=0; i < sk_X509_num(cert_chain); i++)
        {
            cert = sk_X509_value(cert_chain,i);
            if (!(!X509_NAME_cmp_no_set(X509_get_subject_name(cert),
                                        X509_get_subject_name(ncert)) 
                  || (ucert &&
                      !X509_NAME_cmp_no_set(X509_get_subject_name(cert),
                                            X509_get_subject_name(ucert)))  
                  || !X509_NAME_cmp_no_set(X509_get_subject_name(cert),
                                           X509_get_issuer_name(cert))))
            {
                if (!PEM_write_bio_X509(bp,cert))
                {
                    return 4;
                }
            }
        }
    }
        
    return 0;
}

/**********************************************************************
Function: canl_proxy_verify_init()

Description:

Parameters:
   
Returns:
**********************************************************************/

void
canl_proxy_verify_init(
    canl_proxy_verify_desc *                 pvd,
    canl_proxy_verify_ctx_desc *             pvxd)
{

    pvd->magicnum = PVD_MAGIC_NUMBER; /* used for debuging */
    pvd->flags = 0;
    pvd->previous = NULL;
    pvd->pvxd = pvxd;
    pvd->proxy_depth = 0;
    pvd->cert_depth = 0;
    pvd->cert_chain = NULL;
    pvd->limited_proxy = 0;
    pvd->multiple_limited_proxy_ok = 0;
}

/**********************************************************************
Function: canl_proxy_verify_ctx_init()

Description:

Parameters:
   
Returns:
**********************************************************************/

void
canl_proxy_verify_ctx_init(
    canl_proxy_verify_ctx_desc *             pvxd)
{

    pvxd->magicnum = PVXD_MAGIC_NUMBER; /* used for debuging */
    pvxd->certdir = NULL;
    pvxd->goodtill = 0;
    pvxd->flags = 0;
    pvxd->ocsp_url = NULL;

}
/**********************************************************************
Function: proxy_verify_release()

Description:

Parameters:
   
Returns:
**********************************************************************/

void
canl_proxy_verify_release(
    canl_proxy_verify_desc *                 pvd)
{
    pvd->cert_chain = NULL;
    pvd->pvxd = NULL;
}

/**********************************************************************
Function: canl_proxy_verify_ctx_release()

Description:

Parameters:
   
Returns:
**********************************************************************/

void
canl_proxy_verify_ctx_release(
    canl_proxy_verify_ctx_desc *             pvxd)
{
    if (pvxd->certdir)
    {
        free(pvxd->certdir);
        pvxd->certdir = NULL;
    }
    
    if (pvxd->ocsp_url)
    {
        free(pvxd->ocsp_url);
        pvxd->ocsp_url = NULL;
    }
}

#if SSLEAY_VERSION_NUMBER >=  0x0090600fL
/**********************************************************************
Function: proxy_app_verify_callback()

Description:
        SSL callback which lets us do the x509_verify_cert
        ourself. We use this to set the ctx->check_issued routine        
        so we can override some of the tests if needed. 

Parameters:
   
Returns:
        Same as X509_verify_cert 
**********************************************************************/

int
proxy_app_verify_callback(X509_STORE_CTX *ctx, UNUSED(void *empty))
{
    /*
     * OpenSSL-0.9.6 has a  check_issued routine which
     * we want to override so we  can replace some of the checks.
     */

    ctx->check_issued = proxy_check_issued;
    return X509_verify_cert(ctx);
}
#endif

/* Ifdef out all extra code not needed for k5cert
 * This includes the OLDGAA
 */

#ifndef BUILD_FOR_K5CERT_ONLY
/**********************************************************************
Function: proxy_check_proxy_name()

Description:
    Check if the subject name is a proxy, and the issuer name
        is the same as the subject name, but without the proxy
    entry. 
        i.e. inforce the proxy signing requirement of 
        only a user or a user's proxy can sign a proxy. 
        Also pass back Rif this is a limited proxy. 

Parameters:

Returns:
        -1  if there was an error
         0  if not a proxy
         1  if a proxy
         2  if a limited proxy

*********************************************************************/

int proxy_check_proxy_name(
    X509 *                              cert)
{
    int                                 ret = 0;
    X509_NAME *                         subject;
    X509_NAME *                         name = NULL;
    X509_NAME_ENTRY *                   ne = NULL;
    ASN1_STRING *                       data;
    int nidv3, nidv4 = 0;
    int indexv3 = -1, indexv4 = -1;
    X509_EXTENSION *ext = NULL;

    nidv3 = my_txt2nid(PROXYCERTINFO_V3);
    nidv4 = my_txt2nid(PROXYCERTINFO_V4);

    if (nidv3 == 0 || nidv4 == 0)
      ERR_clear_error();

    indexv3 = X509_get_ext_by_NID(cert, nidv3, -1);
    indexv4 = X509_get_ext_by_NID(cert, nidv4, -1);

    if (indexv3 != -1 || indexv4 != -1) {
      /* Its a proxy! */
      ext = X509_get_ext(cert, (indexv3 == -1 ? indexv4 : indexv3));

      if (ext) {
        myPROXYCERTINFO *certinfo = NULL;

        certinfo = (myPROXYCERTINFO *)X509V3_EXT_d2i(ext);

        if (certinfo) {
          myPROXYPOLICY *policy = myPROXYCERTINFO_get_proxypolicy(certinfo);

          if (policy) {
/*             ASN1_OBJECT *policylang; */
/*             policylang = myPROXYPOLICY_get_policy_language(policy); */

            /* TO DO:  discover exact type of proxy. */

          }
          myPROXYCERTINFO_free(certinfo);
        }
#if OPENSSL_VERSION_NUMBER >= 0x00908010
#ifdef EXFLAG_PROXY
        X509_set_proxy_flag(cert);
#endif
#endif
        //return 1;
      }
    }
    subject = X509_get_subject_name(cert);
    ne = X509_NAME_get_entry(subject, X509_NAME_entry_count(subject)-1);
    
    if (!OBJ_cmp(X509_NAME_ENTRY_get_object(ne),OBJ_nid2obj(NID_commonName)))
    {
        data = X509_NAME_ENTRY_get_data(ne);
        if ((data->length == 5 && 
             !memcmp(data->data,"proxy",5)) || 
            (data->length == 13 && 
             !memcmp(data->data,"limited proxy",13)))
        {
        
            if (data->length == 13)
            {
                ret = 2; /* its a limited proxy */
            }
            else
            {
                ret = 1; /* its a proxy */
            }
            /*
             * Lets dup the issuer, and add the CN=proxy. This should
             * match the subject. i.e. proxy can only be signed by
             * the owner.  We do it this way, to double check
             * all the ANS1 bits as well.
             */

            /* DEE? needs some more err processing here */

            name = X509_NAME_dup(X509_get_issuer_name(cert));
            ne = X509_NAME_ENTRY_create_by_NID(NULL,
                                               NID_commonName,
                                               V_ASN1_APP_CHOOSE,
                                               (ret == 2) ?
                                               (unsigned char *)
                                               "limited proxy" :
                                               (unsigned char *)"proxy",
                                               -1);

            X509_NAME_add_entry(name,ne,X509_NAME_entry_count(name),0);
            X509_NAME_ENTRY_free(ne);
            ne = NULL;

            if (X509_NAME_cmp_no_set(name,subject))
            {
                /*
                 * Reject this certificate, only the user
                 * may sign the proxy
                 */
                ret = -1;
            }
            X509_NAME_free(name);
        }
        else if (ext != NULL) {
            name = X509_NAME_dup(X509_get_issuer_name(cert));
            ne = X509_NAME_ENTRY_create_by_NID(NULL, NID_commonName,
                                               data->type, data->data, -1);
            X509_NAME_add_entry(name,ne,X509_NAME_entry_count(name),0);
            X509_NAME_ENTRY_free(ne);
            ne = NULL;

            if (X509_NAME_cmp_no_set(name,subject))
            {
                /*
                 * Reject this certificate, only the user
                 * may sign the proxy
                 */
                ret = -1;
            } else
                ret = 1;
            X509_NAME_free(name);
        }
    }

#if OPENSSL_VERSION_NUMBER >= 0x00908010
#ifdef EXFLAG_PROXY
    if (ret > 0) {
      X509_set_proxy_flag(cert);
      if (ret == 1)
        X509_set_proxy_pathlen(cert, -1); /* unlimited */
      else if (ret == 2)
        X509_set_proxy_pathlen(cert, 0); /* Only at top level if limited */
    }
#endif
#endif

    return ret;
}

#if SSLEAY_VERSION_NUMBER >=  0x0090600fL
/**********************************************************************
 Function: proxy_check_issued()

Description:
        Replace the OpenSSL check_issued in x509_vfy.c with our own,
        so we can override the key usage checks if its a proxy. 
        We are only looking for X509_V_ERR_KEYUSAGE_NO_CERTSIGN

Parameters:r
        See OpenSSL check_issued

Returns:
        See OpenSSL check_issued

**********************************************************************/

int PRIVATE
proxy_check_issued(
    UNUSED(X509_STORE_CTX *                    ctx),
    X509 *                              x,
    X509 *                              issuer)
{
    int                                 ret;
    int                                 ret_code = 1;
        
    ret = X509_check_issued(issuer, x);
    if (ret != X509_V_OK)
    {
        ret_code = 0;
        switch (ret)
        {
        case X509_V_ERR_AKID_SKID_MISMATCH:
            /* 
             * If the proxy was created with a previous version of Globus
             * where the extensions where copied from the user certificate
             * This error could arise, as the akid will be the wrong key
             * So if its a proxy, we will ignore this error.
             * We should remove this in 12/2001 
             * At which time we may want to add the akid extension to the proxy.
             */

        case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
            /*
             * If this is a proxy certificate then the issuer
             * does not need to have the key_usage set.
             * So check if its a proxy, and ignore
             * the error if so. 
             */
            if (proxy_check_proxy_name(x) >= 1)
            {
                ret_code = 1;
            }
            break;
        default:
            break;
        }
    }
    return ret_code;
}
#endif

/**********************************************************************
Function: proxy_verify_callback()

Description:
        verify callback for SSL. Used to check that proxy
        certificates are only signed by the correct user, 
        and used for debuging.
        
        Also on the server side, the s3_srvr.c code does not appear
        to save the peer cert_chain, like the client side does. 
        We need these for additional proxies, so we need to 
        copy the X509 to our own stack. 

Parameters:
        ok  1 then we are given one last chance to check
                this certificate.
                0 then this certificate has failed, and ctx has the
                reason (see X509_STORE_CTX_get_error()). We may want
                to override the failure. 
        ctx the X509_STORE_CTX which has as a user arg, our 
                proxy verify desc. 
   
Returns:
        1 - Passed the tests
        0 - failed.  The x509_vfy.c will return a failed to caller. 
**********************************************************************/

int
proxy_verify_callback(
    int                                 ok,
    X509_STORE_CTX *                    ctx)
{
    X509_OBJECT                         obj;
    X509 *                              cert = NULL;
#ifdef X509_V_ERR_CERT_REVOKED
    X509_CRL *                          crl;
    X509_REVOKED *                      revoked;
#endif
    SSL *                               ssl = NULL;
    SSL_CTX *                           ssl_ctx = NULL;
    canl_proxy_verify_desc *                 pvd;
    int                                 itsaproxy = 0;
    int                                 i;
    int                                 ret;
    time_t                              goodtill;
    char *                              cert_dir = NULL;
    EVP_PKEY *key = NULL;
    int       objset = 0;
    canl_ocsprequest_t *ocsp_data = NULL;
    X509 *ctx_cert, *ctx_current_cert, *ctx_current_issuer;
    STACK_OF(X509) *ctx_chain;
    int ctx_error;

    /*
     * If we are being called recursivly to check delegate
     * cert chains, or being called by the grid-proxy-init,
     * a pointer to a canl_proxy_verify_desc will be 
     * pased in the store.  If we are being called by SSL,
     * by a roundabout process, the app_data of the ctx points at
     * the SSL. We have saved a pointer to the  context handle
     * in the SSL, and its magic number should be PVD_MAGIC_NUMBER 
     */
    if (!(pvd = (canl_proxy_verify_desc *)
                X509_STORE_CTX_get_ex_data(ctx,
                    PVD_STORE_EX_DATA_IDX)))
    {
        ssl = (SSL *)X509_STORE_CTX_get_app_data(ctx);
        if (ssl) {
            ssl_ctx = SSL_get_SSL_CTX(ssl);
            pvd = (canl_proxy_verify_desc *)SSL_CTX_get_ex_data(ssl_ctx,
                    PVD_SSL_EX_DATA_IDX);
        }
    }

    /*
     * For now we hardcode the ex_data. We could look at all 
     * ex_data to find ours. 
     * Double check that we are indeed pointing at the context
     * handle. If not, we have an internal error, SSL may have changed
     * how the callback and app_data are handled
     */

    if (pvd) {
      if(pvd->magicnum != PVD_MAGIC_NUMBER) {
          PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_BAD_MAGIC);
          return(0);
      }
    }

    ctx_cert = X509_STORE_CTX_get0_cert(ctx);
    ctx_current_cert = X509_STORE_CTX_get_current_cert(ctx);
    ctx_current_issuer = X509_STORE_CTX_get0_current_issuer(ctx);
    ctx_chain = X509_STORE_CTX_get0_chain(ctx);
    ctx_error = X509_STORE_CTX_get_error(ctx);

    /*
     * We now check for some error conditions which
     * can be disregarded. 
     */
        
    if (!ok)
    {
        switch (ctx_error)
        {
#if SSLEAY_VERSION_NUMBER >=  0x0090581fL
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
            /*
             * Since OpenSSL does not know about proxies,
             * it will count them against the path length
             * So we will ignore the errors and do our
             * own checks later on, when we check the last
             * certificate in the chain we will check the chain.
             */

	    /* Path length exceeded for the CA (should never happen in OpenSSL - famous last words) */
		    /*Log( L_DEBUG, "Shallow Error X509_V_ERR_PATH_LENGTH_EXCEEDED: 
                      Running alternative RFC5280 and RFC3820 compliance tests.\n"); */
	    if (grid_verifyPathLenConstraints(ctx_chain) == X509_V_OK){
                ok = 1;
                break;
            }
#endif

	    /* Path length exceeded for the Proxy! -> Override and continue */
	    /* This is NOT about X509_V_ERR_PATH_LENGTH_EXCEEDED */
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
	    if (ctx_error == X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED)
	        if (grid_verifyPathLenConstraints(ctx_chain) == X509_V_OK){
                    ok = 1;
                    break;
                 }
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
          /*
           * OpenSSL 1.0 causes the cert to be added twice to 
           * the store.
           */
          if (proxy_check_proxy_name(ctx_cert) && 
              !X509_cmp(ctx_cert, ctx_current_cert))
            ok = 1;
          break;
#endif

        case X509_V_ERR_INVALID_CA:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
          /*
           * This may happen since proxy issuers are not CAs
           */
          if (proxy_check_proxy_name(ctx_cert) >= 1) {
            if (proxy_check_issued(ctx, ctx_cert, ctx_current_cert)) {
              ok = 1;
            }
          }
          break;

        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
          if (proxy_check_proxy_name(ctx_cert) >= 1) {
            if (check_critical_extensions(ctx_cert, 1))
              /* Allows proxy specific extensions on proxies. */
              ok = 1;
          }
          break;

        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_CERT_UNTRUSTED:
          if (proxy_check_proxy_name(ctx_current_cert) > 0) {
            /* Server side, needed to fully recognize a proxy. */
            ok = 1;
          }
          break;

#ifdef X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED
        case X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED:
          /* Proxies ARE allowed */
          ok = 1;
          break;
#endif

        default:
            break;
        }                       
        /* if already failed, skip the rest */
        if (!ok)
            goto fail_verify;

        /*openssl failed, but we checked it ourselves and it was OK*/
        X509_STORE_CTX_set_error(ctx, 0);
        //return(ok);
    }

    /* Note: OpenSSL will try to verify the client's chain on the client side 
       before sending it abroad.  However, to properly verify proxy conditions, 
       we need access to pvd, which is not passed.  For this reason, in this
       scenario we assume that if the checks above passed, everything is ok. If
       it is not, it will be discovered during server-side validation of the cert. 
    */
    if (!pvd)
      return ok;

    /* 
     * All of the OpenSSL tests have passed and we now get to 
     * look at the certificate to verify the proxy rules, 
     * and ca-signing-policy rules. We will also do a CRL check
     */

    /*
     * Test if the name ends in CN=proxy and if the issuer
     * name matches the subject without the final proxy. 
     */
        
    ret = proxy_check_proxy_name(ctx_current_cert);
    if (ret < 0)
    {
        PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_BAD_PROXY_ISSUER);
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_SIGNATURE_FAILURE);
        goto fail_verify;
    }
    if (ret > 0)
    {  /* Its a proxy */
        if (ret == 2)
        {
            /*
             * If its a limited proxy, it means it use has been limited 
             * during delegation. It can not sign other certs i.e.  
             * it must be the top cert in the chain. 
             * Depending on who we are, 
             * We may want to accept this for authentication. 
             * 
             *   Globus gatekeeper -- don't accept
             *   sslk5d accept, but should check if from local site.
             *   globus user-to-user Yes, thats the purpose 
             *    of this cert. 
             *
             * We will set the limited_proxy flag, to show we found
             * one. A Caller can then reject. 
             */

          pvd->limited_proxy = 1; /* its a limited proxy */

          if (X509_STORE_CTX_get_error_depth(ctx) && !pvd->multiple_limited_proxy_ok) {
            /* tried to sign a cert with a limited proxy */
            /* i.e. there is still another cert on the chain */
            /* indicating we are trying to sign it! */
            PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_LPROXY_MISSED_USED);
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_SIGNATURE_FAILURE);
            goto fail_verify;
          }
        }

        pvd->proxy_depth++;
        itsaproxy = 1;
    }

    if (!itsaproxy)
    {
                        
#ifdef X509_V_ERR_CERT_REVOKED
        int n = 0;
        /* 
         * SSLeay 0.9.0 handles CRLs but does not check them. 
         * We will check the crl for this cert, if there
         * is a CRL in the store. 
         * If we find the crl is not valid, we will fail, 
         * as once the sysadmin indicates that CRLs are to 
         * be checked, he best keep it upto date. 
         * 
         * When future versions of SSLeay support this better,
         * we can remove these tests. 
         * we come through this code for each certificate,
         * starting with the CA's We will check for a CRL
         * each time, but only check the signature if the
         * subject name matches, and check for revoked
         * if the issuer name matches.
         * this allows the CA to revoke its own cert as well. 
         */
        
        if (X509_STORE_get_by_subject(ctx,
                                      X509_LU_CRL, 
                                      X509_get_subject_name(ctx_current_issuer),
                                      &obj))
        {
            objset = 1;
            crl =  obj.data.crl;
            /* verify the signature on this CRL */

            key = X509_get_pubkey(ctx_current_issuer);
            if (X509_CRL_verify(crl, key) <= 0)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CRL_SIGNATURE_FAILURE);
                X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
                goto fail_verify;
            }

            /* Check date see if expired */

            i = X509_cmp_current_time(X509_CRL_get0_nextUpdate(crl));
            if (i == 0)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CRL_NEXT_UPDATE_FIELD);
                X509_STORE_CTX_set_error(ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
                goto fail_verify;
            }
           

            if (i < 0)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CRL_HAS_EXPIRED);
                X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_HAS_EXPIRED);
                goto fail_verify;
            }

            /* check if this cert is revoked */


            n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
            for (i=0; i<n; i++)
            {
                revoked = (X509_REVOKED *)sk_X509_REVOKED_value(
                    X509_CRL_get_REVOKED(crl),i);

                if(!ASN1_INTEGER_cmp(revoked->serialNumber,
                                     X509_get_serialNumber(ctx_current_cert)))
                {
                    PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CERT_REVOKED);
                    X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
                    goto fail_verify;
                }
            }
        }
#endif /* X509_V_ERR_CERT_REVOKED */

        cert_dir = pvd->pvxd->certdir ? pvd->pvxd->certdir :
            getenv(X509_CERT_DIR);
        /* Do not need to check self signed certs against ca_policy_file */

        if (X509_NAME_cmp(X509_get_subject_name(ctx_current_cert),
                          X509_get_issuer_name(ctx_current_cert)))
        {

            {
                char * error_string = NULL;
                struct policy **signings   = NULL;
                struct policy **namespaces = NULL;
                int result = SUCCESS_UNDECIDED;

                read_pathrestriction(ctx_chain, cert_dir, &namespaces, &signings);

                result = restriction_evaluate(ctx_chain, namespaces, signings);
                
                voms_free_policies(namespaces);
                voms_free_policies(signings);

                if (result != SUCCESS_PERMIT)
                {
                    PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_CA_POLICY_VIOLATION);
                                
                    if (error_string != NULL)
                    {
                        /*
                         * Seperate error message returned from policy check
                         * from above error message with colon
                         */
                        
                        ERR_add_error_data(2, ": ", error_string);
                        free(error_string);
                    }
                    ERR_set_continue_needed();
                    goto fail_verify;
                }
                else
                {
                    if (error_string != NULL)
                    {
                        free(error_string);
                    }
                }
            }
        } /* end of do not check self signed certs */
    }

    /*
     * We want to determine the minimum amount of time
     * any certificate in the chain is good till
     * Will be used for lifetime calculations
     */

    goodtill = ASN1_UTCTIME_mktime(X509_get_notAfter(ctx_current_cert));
    if (pvd->pvxd->goodtill == 0 || goodtill < pvd->pvxd->goodtill)
    {
        pvd->pvxd->goodtill = goodtill;
    }
        
    /* We need to make up a cert_chain if we are the server. 
     * The ssl code does not save this as I would expect. 
     * This is used to create a new proxy by delegation. 
     */

    pvd->cert_depth++;

    if (!check_critical_extensions(ctx_current_cert, itsaproxy)) {
      PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_UNKNOWN_CRIT_EXT);
      X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
      goto fail_verify;
    }

    /*
     * We ignored any path length restrictions above because
     * OpenSSL was counting proxies against the limit. 
     * If we are on the last cert in the chain, we 
     * know how many are proxies, so we can do the 
     * path length check now. 
     * See x509_vfy.c check_chain_purpose
     * all we do is substract off the proxy_dpeth 
     */
    if(ctx_current_cert == ctx_cert) {
       int err;

       err = grid_verifyPathLenConstraints(ctx_chain);
       X509_STORE_CTX_set_error(ctx, err);
       if (err != X509_V_OK)
          goto fail_verify;
    }

    /*
       OCSP check
     */
    ret = 0;
    if (pvd->pvxd->flags & CANL_SSL_OCSP_VERIFY_ALL){
        if (!ocsp_data)
            ocsprequest_init(&ocsp_data);
        if (ocsp_data) {
            if (ctx_current_cert)
                ocsp_data->cert = ctx_current_cert;
            if (ctx_current_issuer)
                ocsp_data->issuer = ctx_current_issuer;
            if (cert_dir)
                ocsp_data->store.ca_dir = cert_dir;

            ocsp_data->skew = MAX_VALIDITY_PERIOD;
            ocsp_data->maxage = -1;
            if (ctx_chain)
                ocsp_data->cert_chain = ctx_chain;
            /*Timeout should be set here 
              ocsp_data->timeout = -1; */
            ret = do_ocsp_verify (ocsp_data);
            /* TODO sign key and cert */
            ocsprequest_free(ocsp_data);
            ocsp_data = NULL;
        }
    }

    EVP_PKEY_free(key);
    if (objset)
        X509_OBJECT_free_contents(&obj);

    if (ret != 0)
        if (ret != CANL_OCSPRESULT_ERROR_NOAIAOCSPURI)
            ok = 0;

    return(ok);

fail_verify:

    if (key)
      EVP_PKEY_free(key);

    if (objset)
      X509_OBJECT_free_contents(&obj);

    return(0);
}

/**********************************************************************
Function: proxy_verify_cert_chain()

Description:

Parameters:

Returns: 1 OK
**********************************************************************/

int PRIVATE
proxy_verify_cert_chain(
    X509 *                              ucert,
    STACK_OF(X509) *                    cert_chain,
    canl_proxy_verify_desc *                 pvd)
{
    int                                 retval = 0;
    X509_STORE *                        cert_store = NULL;
    X509_LOOKUP *                       lookup = NULL;
    X509_STORE_CTX                      csc;
    X509 *                              xcert = NULL;
    X509 *                              scert = NULL;
    int cscinitialized = 0;

    scert = ucert;
    if(!(cert_store = X509_STORE_new())){
       goto err;
    }
    X509_STORE_set_verify_cb_func(cert_store, proxy_verify_callback);
    if (cert_chain != NULL)
    {
        int i =0;
        for (i=0;i<sk_X509_num(cert_chain);i++)
        {
            xcert = sk_X509_value(cert_chain,i);
            if (!scert)
            {
                scert = xcert;
            }
            else
            {
                int j = X509_STORE_add_cert(cert_store, xcert);
                if (!j)
                {
                    if ((ERR_GET_REASON(ERR_peek_error()) ==
                         X509_R_CERT_ALREADY_IN_HASH_TABLE))
                    {
                        ERR_clear_error();
                        break;
                    }
                    else
                    {
                        /*DEE need errprhere */
                        goto err;
                    }
                }
            }
        }
    }
    if ((lookup = X509_STORE_add_lookup(cert_store,
                                        X509_LOOKUP_hash_dir())))
    {
        X509_LOOKUP_add_dir(lookup,pvd->pvxd->certdir,X509_FILETYPE_PEM);
        X509_STORE_CTX_init(&csc,cert_store,scert,NULL);
        cscinitialized = 1;
#if SSLEAY_VERSION_NUMBER >=  0x0090600fL
        /* override the check_issued with our version */
        csc.check_issued = proxy_check_issued;
#endif
        X509_STORE_CTX_set_ex_data(&csc,
                                   PVD_STORE_EX_DATA_IDX, (void *)pvd);
#ifdef X509_V_FLAG_ALLOW_PROXY_CERTS
        X509_STORE_CTX_set_flags(&csc, X509_V_FLAG_ALLOW_PROXY_CERTS);
#endif
        if(X509_verify_cert(&csc) != 1)
        {
            goto err;
        }
    } 
    retval = 1;

err:
    if (cscinitialized) 
      X509_STORE_CTX_cleanup(&csc);
    if (cert_store)
      X509_STORE_free(cert_store);
    return retval;
}
#endif /* NO_PROXY_VERIFY_CALLBACK */


/**********************************************************************
Function: proxy_get_filenames()

Description:
    Gets the filenames for the various files used 
    to store the cert, key, cert_dir and proxy.
    
    
    Environment variables to use:
        X509_CERT_DIR   Directory of trusted certificates
                        File names are hash values, see the SSLeay
                        c_hash script. 
        X509_CERT_FILE  File of trusted certifiates
        X509_USER_PROXY File with a proxy certificate, key, and
                        additional certificates to makeup a chain
                        of certificates used to sign the proxy. 
        X509_USER_CERT  User long term certificate.
        X509_USER_KEY   private key for the long term certificate. 

    All of these are assumed to be in PEM form. If there is a 
    X509_USER_PROXY, it will be searched first for the cert and key. 
    If not defined, but a file /tmp/x509up_u<uid> is
    present, it will be used, otherwise the X509_USER_CERT
    and X509_USER_KEY will be used to find the certificate
    and key. If X509_USER_KEY is not defined, it will be assumed
    that the key is is the same file as the certificate.
 
    If windows, look in the registry HKEY_CURRENT_USER for the 
    GSI_REGISTRY_DIR, then look for the x509_user_cert, etc.

    Then try $HOME/.globus/usercert.pem
    and $HOME/.globus/userkey.pem 
        Unless it is being run as root, then look for 
        /etc/grid-security/hostcert.pem and /etc/grid-security/hostkey.pem

    X509_CERT_DIR and X509_CERT_FILE can point to world readable
    shared director and file. One of these must be present.
    if not use $HOME/.globus/certificates
        or /etc/grid-security/certificates
        or $GLOBUS_DEPLOY_PATH/share/certificates
        or $GLOBUS_LOCATION/share/certificates
        or $GSI_DEPLOY_PATH/share/certificates
        or $GSI_INSTALL_PATH/share/certificates

    The file with the key must be owned by the user,
    and readable only by the user. This could be the X509_USER_PROXY,
    X509_USER_CERT or the X509_USER_KEY

    X509_USER_PROXY_FILE is used to generate the default
    proxy file name.

    In other words:

    proxy_get_filenames() is used by grid-proxy-init, wgpi, grid-proxy-info and
    Indirectly by gss_acquire_creds. For grid-proxy-init and wgpi, the proxy_in
    is 0, for acquire_creds its 1. This is used to signal how the proxy file is
    to be used, 1 for input 0 for output.
        
    The logic for output is to use the provided input parameter, registry,
    environment, or default name for the proxy. Wgpi calls this multiple times
    as the options window is updated. The file will be created if needed.
        
    The logic for input is to use the provided input parameter, registry,
    environment variable. But only use the default file if it exists, is owned
    by the user, and has something in it. But not when run as root.
        
    Then on input if there is a proxy, the user_cert and user_key are set to
    use the proxy.

    Smart card support using PKCS#11 is controled by the USE_PKCS11 flag.

    If the filename for the user key starts with SC: then it is assumed to be
    of the form SC:card:label where card is the name of a smart card, and label
    is the label of the key on the card. The card must be using Cryptoki
    (PKCS#11) This code has been developed using the DataKey implementation
    under Windows 95.

    This will allow the cert to have the same form, with the same label as well
    in the future.  



Parameters:

Returns:
**********************************************************************/

int
proxy_get_filenames(
    int                                 proxy_in,
    char **                             p_cert_file,
    char **                             p_cert_dir,
    char **                             p_user_proxy,
    char **                             p_user_cert,
    char **                             p_user_key)
{

    int                                 status = -1;
    char *                              cert_file = NULL;
    char *                              cert_dir = NULL;
    char *                              user_proxy = NULL;
    char *                              user_cert = NULL;
    char *                              user_key = NULL;
    char *                              home = NULL;
    char *                              default_user_proxy = NULL;
    char *                              default_user_cert = NULL;
    char *                              default_user_key = NULL;
    char *                              default_cert_dir = NULL;
    char *                              installed_cert_dir = NULL;
#ifdef WIN32
    HKEY                                hkDir = NULL;
    char                                val_user_cert[512];
    char                                val_user_key[512];
    char                                val_user_proxy[512];
    char                                val_cert_dir[512];
    char                                val_cert_file[512];
    LONG                                lval;
    DWORD                               type;
#endif

#ifdef WIN32
    RegOpenKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir);
#endif
    
    /* setup some default values */
    if (p_cert_dir)
    {
        cert_dir = *p_cert_dir;
    }


    if (!cert_dir)
    {
        cert_dir = (char *)getenv(X509_CERT_DIR);
    }
#ifdef WIN32
    if (!cert_dir)
    {
        lval = sizeof(val_cert_dir)-1;
        if (hkDir && (RegQueryValueEx(hkDir,"x509_cert_dir",0,&type,
                                      val_cert_dir,&lval) == ERROR_SUCCESS))
        {
            cert_dir = val_cert_dir;
        }
    }
#endif
    if (p_cert_file)
    {
        cert_file = *p_cert_file;
    }
    
    if (!cert_file)
    {
        cert_file = (char *)getenv(X509_CERT_FILE);
    }
#ifdef WIN32
    if (!cert_file)
    {
        lval = sizeof(val_cert_file)-1;
        if (hkDir && (RegQueryValueEx(hkDir,"x509_cert_file",0,&type,
                                      val_cert_file,&lval) == ERROR_SUCCESS))
        {
            cert_file = val_cert_file;
        }
    }
#endif
        
    if (cert_dir == NULL)
    {

        /*
         * If ~/.globus/certificates exists, then use that
         */
        home = getenv("HOME");
#ifndef WIN32
        /* Under windows use c:\windows as default home */
        if (!home)
        {
            home = "c:\\windows";
        }
#endif /* WIN32 */

        if (home) 
        {
            default_cert_dir = snprintf_wrap("%s%s%s",
                    home, FILE_SEPERATOR, X509_DEFAULT_CERT_DIR);

            if (!default_cert_dir)
            {
                PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                goto err;
            }

            if (checkstat(default_cert_dir) != 1)
            {
                /* default_cert_dir exists */
                cert_dir = default_cert_dir;
            }
        }
                

        /* 
         * Now check for host based default directory
         */
        if (!cert_dir)
        {

            if (checkstat(X509_INSTALLED_HOST_CERT_DIR) != 1)
            {
                /* default_cert_dir exists */
                cert_dir = X509_INSTALLED_HOST_CERT_DIR;
            }
        }

        if (!cert_dir)
        {
            /*
             * ...else look for (in order)
             * $GLOBUS_DEPLOY_PATH/share/certificates
             * $GLOBUS_LOCATION/share/certficates
             */
            char *globus_location;


            globus_location = getenv("GLOBUS_DEPLOY_PATH");

            if (!globus_location)
            {               
                globus_location = getenv("GLOBUS_LOCATION");
            }

            if (!globus_location)
            {
                globus_location = getenv("GSI_DEPLOY_PATH");
            }

            if (!globus_location)
            {
                globus_location = getenv("GSI_INSTALL_PATH");
            }

            if (globus_location)
            {
                installed_cert_dir = snprintf_wrap("%s%s%s",
                        globus_location,
                        FILE_SEPERATOR,
                        X509_INSTALLED_CERT_DIR);

                if  (!installed_cert_dir)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                    goto err;
                }

                /*
                 * Previous code always set cert_dir to
                 * default_cert_dir without checking for its
                 * existance, so we'll also skip the existance
                 * check here.
                 */
                cert_dir = installed_cert_dir;
            }
        }

        if (!cert_dir)
        {
            cert_dir = X509_INSTALLED_HOST_CERT_DIR;
        }
    }

    if (cert_dir)
    {
        if (checkstat(cert_dir)  == 1)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERTS); 
            ERR_add_error_data(2,"x509_cert_dir=",cert_dir);
            goto err;
        }
    }

    if (cert_file)
    {
        if (checkstat(cert_file)  == 1)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERTS); 
            ERR_add_error_data(2,"x509_cert_file=",cert_file);
            goto err;
        }
    }
    /* if X509_USER_PROXY is defined, use it for cert and key,
     * and for additional certs. 
     * if not, and the default user_proxy file is present, 
     * use it. 
     * If not, get the X509_USER_CERT and X509_USER_KEY
     * if not, use ~/.globus/usercert.pem ~/.globus/userkey.pem
     */
    if (p_user_proxy)
    {
        user_proxy = *p_user_proxy;
    }
    
    if (!user_proxy)
    {
        user_proxy = (char *)getenv(X509_USER_PROXY);
    }
#ifdef WIN32
    if (!user_proxy)
    {
        lval = sizeof(val_user_proxy)-1;
        if (hkDir && (RegQueryValueEx(hkDir,"x509_user_proxy",0,&type,
                                      val_user_proxy,&lval) == ERROR_SUCCESS))
        {
            user_proxy = val_user_proxy;
        }
    }
#endif
    if (!user_proxy && !getenv("X509_RUN_AS_SERVER"))
    {
        default_user_proxy = snprintf_wrap("%s%s%s%lu",
                                           DEFAULT_SECURE_TMP_DIR,
                                           FILE_SEPERATOR,
                                           X509_USER_PROXY_FILE,
                                           getuid());

        if (!default_user_proxy)
        {
            PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
            goto err;
        }

#ifndef WIN32
        if ((!proxy_in || getuid() != 0)
            && checkstat(default_user_proxy) == 0) 
#endif
        {
            user_proxy = default_user_proxy;
        }
    }
    if (proxy_in && user_proxy)
    {
        user_cert = user_proxy;
        user_key = user_proxy;
    }
    else
    {
        if (!user_proxy && !proxy_in)
        {
            user_proxy = default_user_proxy;
        }

        if (p_user_cert)
        {
            user_cert = *p_user_cert;
        }

        if(!user_cert)
        {
            user_cert = (char *)getenv(X509_USER_CERT);
        }

#ifdef WIN32
        if (!user_cert)
        {
            lval = sizeof(val_user_cert)-1;
            if (hkDir && (RegQueryValueEx(
                              hkDir,
                              "x509_user_cert",
                              0,
                              &type,
                              val_user_cert,&lval) == ERROR_SUCCESS))
            {
                user_cert = val_user_cert;
            }
        }
#endif
        if (user_cert)
        {
            if (p_user_key)
            {
                user_key = *p_user_key;
            }
            if (!user_key)
            {
                user_key = (char *)getenv(X509_USER_KEY);
            }
#ifdef WIN32
            if (!user_key)
            {
                lval = sizeof(val_user_key)-1;
                if (hkDir && (RegQueryValueEx(
                                  hkDir,
                                  "x509_user_key",
                                  0,
                                  &type,
                                  val_user_key,&lval) == ERROR_SUCCESS))
                {
                    user_key = val_user_key;
                }
            }
#endif
            if (!user_key)
            {
                user_key = user_cert;
            }
        }
        else
        {
#ifndef WIN32
            if (getuid() == 0)
            {
                if (checkstat(X509_DEFAULT_HOST_CERT) != 1)
                {
                    user_cert = X509_DEFAULT_HOST_CERT;
                }
                if (checkstat(X509_DEFAULT_HOST_KEY) != 1)
                {
                    user_key = X509_DEFAULT_HOST_KEY;
                }
            }
            else 
#endif
            {
                if (!home)
                {
                    home = getenv("HOME");
                }
                if (!home)
                {
#ifndef WIN32
                    PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_NO_HOME);
                    goto err;
#else
                    home = "c:\\";
#endif
                }
                
                default_user_cert = snprintf_wrap("%s%s%s",
                        home, FILE_SEPERATOR, X509_DEFAULT_USER_CERT);

                if (!default_user_cert)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                    goto err;
                } 

                default_user_key = snprintf_wrap("%s%s%s",
                        home,FILE_SEPERATOR, X509_DEFAULT_USER_KEY);
                                                
                if (!default_user_key)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                    goto err;
                }

                user_cert = default_user_cert;
                user_key = default_user_key;

                /* Support for pkcs12 credentials. */
                {
                  int fd = open(default_user_cert, O_RDONLY);
                  if (fd >= 0)
                    close(fd);
                  else {
                    /* Cannot open normal file -- look for pkcs12. */
                    char *certname = NULL;

                    free(default_user_cert);
                    free(default_user_key);
                    

                    certname = getenv("X509_USER_CRED");

                    if (!certname) {
                      default_user_cert = snprintf_wrap("%s%s%s",
                              home, FILE_SEPERATOR, X509_DEFAULT_USER_CERT_P12);

                      if (!default_user_cert) {
                        PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                        goto err;
                      } 

                      if (checkstat(default_user_cert) != 0) {
                        free(default_user_cert);
                        default_user_cert = snprintf_wrap("%s%s%s",
                                home, FILE_SEPERATOR, X509_DEFAULT_USER_CERT_P12_GT);
                      }

                      if (!default_user_cert) {
                        PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                        goto err;
                      } 

                    }
                    else
                      strcpy(default_user_cert, certname);

                    default_user_key = strndup(default_user_cert, strlen(default_user_cert));

                    if (!default_user_key) {
                      PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                      goto err;
                    }
                                                
                    user_cert = default_user_cert;
                    user_key = default_user_key;
                  }
                }
            }
        }
    }
 
    status = 0;
err:
    if (!status) {
      if (p_cert_file && cert_file && !(*p_cert_file)) {
        *p_cert_file = strdup(cert_file);
      }
      if (p_cert_dir && cert_dir && !(*p_cert_dir)) {
        *p_cert_dir = strdup(cert_dir);
      }
      if (p_user_proxy && user_proxy && !(*p_user_proxy)) {
        *p_user_proxy = strdup(user_proxy);
      }
      if (p_user_cert && user_cert && !(*p_user_cert)) {
        free(*p_user_cert);
        *p_user_cert = strdup(user_cert);
      }
      if (p_user_key && user_key && !(*p_user_key)) {
        free(*p_user_key);
        *p_user_key = strdup(user_key);
      }
    }
#ifdef WIN32
    if (hkDir)
    {
        RegCloseKey(hkDir);
    }
#endif

    free(default_user_proxy);
    free(installed_cert_dir);
    free(default_cert_dir);
    free(default_user_cert);
    free(default_user_key);

    return status;
}
/**********************************************************************
Function: proxy_load_user_cert()

Description:
    loads the users cert. May need a pw callback for Smartcard PIN. 
    May use a smartcard too.   

Parameters:

Returns:
**********************************************************************/

static int cert_load_pkcs12(BIO *bio, int (*pw_cb)(), X509 **cert, EVP_PKEY **key, STACK_OF(X509) **chain) 
{
  PKCS12 *p12 = NULL;
  char *password = NULL;
  char buffer[1024];
  int ret = 0;

  p12 = d2i_PKCS12_bio(bio, NULL);
  if (!p12)
    return 0;

  if (!PKCS12_verify_mac(p12, "", 0)) {

    int sz = 0;

    if (pw_cb)
      sz = pw_cb(buffer, 1024, 0);
    else 
      if (EVP_read_pw_string(buffer, 1024, EVP_get_pw_prompt(), 0) != -1)
        sz = strlen(buffer);

    if (sz)
      password = buffer;
    else
      goto err;
  }
  else
    password="";

  ret = PKCS12_parse(p12, password, key, cert, chain);

 err:
  memset(buffer, 0, 1024);

  if (p12)
     PKCS12_free(p12);

  return ret;
}

int PRIVATE proxy_load_user_cert_and_key_pkcs12(const char *user_cert,
                                                X509 **cert,
                                                STACK_OF(X509) **stack,
                                                EVP_PKEY **pkey,
                                                int (*pw_cb) ())
{
  BIO *bio = BIO_new_file(user_cert, "rb");
  int res = cert_load_pkcs12(bio, pw_cb, cert, pkey, stack);
  BIO_free(bio);

  if (res)
    return 1;
  else {
    if (ERR_peek_error() == ERR_PACK(ERR_LIB_PEM,PEM_F_PEM_READ_BIO,PEM_R_NO_START_LINE)) {
      ERR_clear_error();
      PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_INVALID_CERT);
    } 
    else { 
      PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
    }
    ERR_add_error_data(2, "\n        File=", user_cert);
    return 0;
  }
}



int PRIVATE
proxy_load_user_cert(
    const char *                        user_cert,
    X509 **                              certificate,
    UNUSED(int                                 (*pw_cb)()),
    UNUSED(unsigned long *                     hSession))
{
    int                                 status = -1;
    FILE *                              fp;

    /* Check arguments */
    if (!user_cert)
    {
      PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOCERT_FILE);
      status = PRXYERR_R_PROBLEM_USER_NOCERT_FILE;
        
      ERR_add_error_data(1, "\n        No certificate file found");
      goto err;   
    }

    if (!strncmp(user_cert,"SC:",3))
    {
#ifdef USE_PKCS11
        char * cp;
        char * kp;
        int rc;

        cp = user_cert + 3;
        kp = strchr(cp,':');
        if (kp == NULL)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOCERT_FILE);
            ERR_add_error_data(2, "\n        SmartCard reference=",
                               user_cert);
            status = PRXYERR_R_PROBLEM_USER_NOCERT_FILE;
            goto err;
        }

        kp++; /* skip the : */

        if (*hSession == 0)
        {
            rc = sc_init(hSession, cp, NULL, NULL, CKU_USER, 0);

            if (rc)
            {
                PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
                ERR_add_error_data(
                    1,
                    "\n        Failed to open session to smartcard");
                status = PRXYERR_R_PROCESS_CERT;
                goto err;
            }
        }
        rc = sc_get_cert_obj_by_label(*hSession,kp,
                                      certificate);
        if (rc)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
            ERR_add_error_data(
                2,
                "\n        Could not find certificate on smartcard, label=",
                kp);
            status = PRXYERR_R_PROCESS_CERT;
            goto err;
        }
#else
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
        ERR_add_error_data(
            1,
            "\n       Smartcard support not compiled with this program");
        status = PRXYERR_R_PROCESS_CERT;
        goto err;

        /*
         * DEE? need to add a random number routine here, to use
         * the random number generator on the card
         */ 

#endif /* USE_PKCS11 */
    }
    else
    {
      if((fp = fopen(user_cert,"rb")) == NULL) {
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOCERT_FILE);
        status = PRXYERR_R_PROBLEM_USER_NOCERT_FILE;
                    
        ERR_add_error_data(2, "\n        Cert File=", user_cert);
        goto err;
      }

      if (PEM_read_X509(fp,
                        certificate,
                        OPENSSL_PEM_CB(NULL,NULL)) == NULL) {
        if (ERR_peek_error() == ERR_PACK(ERR_LIB_PEM,PEM_F_PEM_READ_BIO,PEM_R_NO_START_LINE)) {
          ERR_clear_error();
          PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_INVALID_CERT);
          status = PRXYERR_R_INVALID_CERT;
        } 
        else { 
          PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
          status = PRXYERR_R_PROCESS_CERT;
        }

        ERR_add_error_data(2, "\n        File=", user_cert);
        fclose(fp);
        goto err;
      }
      fclose(fp);
    }
    status = 0;
 err:

    return status;
}


/**********************************************************************
Function: proxy_load_user_key()

Description:
    loads the users key. Assumes the cert has been loaded,
    and checks they match. 
    May use a smartcard too.   

Parameters:

Returns:
    an int specifying the error
**********************************************************************/

int PRIVATE
proxy_load_user_key(
    EVP_PKEY **                         private_key,
    X509 *                              ucert,
    const char *                        user_key,
    int                                 (*pw_cb)(),
    UNUSED(unsigned long *                     hSession))
{
    int                                 status = -1;
    FILE *                              fp;
    EVP_PKEY *                          ucertpkey;
    int                                 (*xpw_cb)();

    if (!private_key)
      return 0;

    xpw_cb = pw_cb;
#ifdef WIN32
    if (!xpw_cb)
    {
        xpw_cb = read_passphrase_win32;
    }
#endif

    /* Check arguments */
    if (!user_key)
    {
      PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOKEY_FILE);
      status = PRXYERR_R_PROBLEM_USER_NOKEY_FILE;
      
      ERR_add_error_data(1,"\n        No key file found");
      goto err;   
    }

            
    if (!strncmp(user_key,"SC:",3))
    {
#ifdef USE_PKCS11
        char *cp;
        char *kp;
        int rc;

        cp = user_key + 3;
        kp = strchr(cp,':');
        if (kp == NULL)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_KEY_FILE);
            ERR_add_error_data(2,"\n        SmartCard reference=",user_key);
            status = PRXYERR_R_PROBLEM_KEY_FILE;
            goto err;
        }
        kp++; /* skip the : */
        if (*hSession == 0)
        {
            rc = sc_init(hSession, cp, NULL, NULL, CKU_USER, 0);
            if (rc)
            {
                PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
                ERR_add_error_data(
                    1,
                    "\n        Failed to open session to smartcard");
                status = PRXYERR_R_PROCESS_KEY;
                goto err;
            }
        }
        rc = sc_get_priv_key_obj_by_label(hSession,kp,
                                          private_key);
        if (rc)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
            ERR_add_error_data(
                2,
                "\n        Could not find key on smartcard, label=",
                kp);
            status = PRXYERR_R_PROCESS_KEY;
            goto err;
        }
#else
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
        ERR_add_error_data(
            1,
            "\n       Smartcard support not compiled with this program");
        status = PRXYERR_R_PROCESS_KEY;
        goto err;
        
        /*
         * DEE? could add a random number routine here, to use
         * the random number generator on the card
         */ 

#endif /* USE_PKCS11 */
    }
    else
    {
      int keystatus;

      if ((fp = fopen(user_key,"rb")) == NULL) {
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOKEY_FILE);
        status = PRXYERR_R_PROBLEM_USER_NOKEY_FILE;
        
        ERR_add_error_data(2, "\n        File=",user_key);
        goto err;
      }

      /* user key must be owned by the user, and readable
       * only be the user
       */

      if ((keystatus = checkstat(user_key))) {
        if (keystatus == 4) {
          status = PRXYERR_R_USER_ZERO_LENGTH_KEY_FILE;
          PRXYerr(PRXYERR_F_INIT_CRED,
                  PRXYERR_R_USER_ZERO_LENGTH_KEY_FILE);
        }
        else {
          status = PRXYERR_R_PROBLEM_KEY_FILE;
          PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_KEY_FILE);
        }

        ERR_add_error_data(2, "\n        File=", user_key);
        fclose(fp);
        goto err;
      }

      if (PEM_read_PrivateKey(fp,
                              private_key,
                              OPENSSL_PEM_CB(xpw_cb,NULL)) == NULL) {
        unsigned long error = ERR_peek_error();
        fclose(fp);

#ifdef PEM_F_PEM_DEF_CALLBACK
        if (error == ERR_PACK(ERR_LIB_PEM,
                              PEM_F_PEM_DEF_CALLBACK,
                              PEM_R_PROBLEMS_GETTING_PASSWORD))
#else
          if (error == ERR_PACK(ERR_LIB_PEM,
                                PEM_F_DEF_CALLBACK,
                                PEM_R_PROBLEMS_GETTING_PASSWORD))
#endif
            {
              ERR_clear_error(); 
            }
#ifdef EVP_F_EVP_DECRYPTFINAL_EX
          else if (error == ERR_PACK(ERR_LIB_EVP,
                                     EVP_F_EVP_DECRYPTFINAL_EX,
                                     EVP_R_BAD_DECRYPT))
#else
          else if (error == ERR_PACK(ERR_LIB_EVP,
                                     EVP_F_EVP_DECRYPTFINAL,
                                     EVP_R_BAD_DECRYPT))
#endif
            {
              ERR_clear_error();
              PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_WRONG_PASSPHRASE);
              status = PRXYERR_R_WRONG_PASSPHRASE;
            }
          else {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
            ERR_add_error_data(2, "\n        File=", user_key);
            status = PRXYERR_R_PROCESS_KEY;
          }
        goto err;
      }
      fclose(fp);  
    }

    /* 
     * check that the private key matches the certificate
     * Dont want a mixup of keys and certs
     * Will only check rsa type for now. 
     */
    if (ucert)
    {
        int match;
#if 0
        X509_PUBKEY *key = X509_get_X509_PUBKEY(ucert);
        ucertpkey =  X509_PUBKEY_get(key);
        int mismatch = 0;

        if (ucertpkey!= NULL  && ucertpkey->type == 
            (*private_key)->type)
        {
            if (ucertpkey->type == EVP_PKEY_RSA)
            {
                /* add in key as random data too */
                if (ucertpkey->pkey.rsa != NULL)
                {
                    if(ucertpkey->pkey.rsa->p != NULL)
                    {
                        RAND_add((void*)ucertpkey->pkey.rsa->p->d,
                                 BN_num_bytes(ucertpkey->pkey.rsa->p),
                                 BN_num_bytes(ucertpkey->pkey.rsa->p));
                    }
                    if(ucertpkey->pkey.rsa->q != NULL)
                    {
                        RAND_add((void*)ucertpkey->pkey.rsa->q->d,
                                 BN_num_bytes(ucertpkey->pkey.rsa->q),
                                 BN_num_bytes(ucertpkey->pkey.rsa->q));
                    }
                }
                if ((ucertpkey->pkey.rsa != NULL) && 
                    (ucertpkey->pkey.rsa->n != NULL) &&
                    ((*private_key)->pkey.rsa != NULL) )
                {
                  if ((*private_key)->pkey.rsa->n != NULL
                      && BN_num_bytes((*private_key)->pkey.rsa->n))
                    {
                        if (BN_cmp(ucertpkey->pkey.rsa->n,
                                   (*private_key)->pkey.rsa->n))
                        {
                            mismatch=1;
                        }
                    }
                    else
                    {
                      (*private_key)->pkey.rsa->n =
                            BN_dup(ucertpkey->pkey.rsa->n);
                      (*private_key)->pkey.rsa->e =
                            BN_dup(ucertpkey->pkey.rsa->e);
                    }
                }
            }
        }
        else
        {
            mismatch=1;
        }
        
        EVP_PKEY_free(ucertpkey);
#endif
        match = X509_check_private_key(ucert, *private_key);
        if (match != 1)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_KEY_CERT_MISMATCH);
            status = PRXYERR_R_KEY_CERT_MISMATCH;
            goto err;
        }
    }

    status = 0;

err:
    /* DEE need more cleanup */
    return status;
}


/**********************************************************************
Function: ASN1_UTCTIME_mktime()

Description:
 SSLeay only has compare functions to the current 
 So we define a convert to time_t from which we can do differences
 Much of this it taken from the X509_cmp_current_time()
 routine. 

Parameters:

Returns:
        time_t 
**********************************************************************/

time_t PRIVATE ASN1_TIME_mktime(ASN1_TIME *ctm)
{
  /*
   * note: ASN1_TIME, ASN1_UTCTIME, ASN1_GENERALIZEDTIME are different
   * typedefs of the same type.
   */
  return ASN1_UTCTIME_mktime(ctm);
}

time_t PRIVATE
ASN1_UTCTIME_mktime(
    ASN1_UTCTIME *                      ctm)
{
  char     *str;
  time_t    offset;
  time_t    newtime;
  char      buff1[32];
  char     *p;
  int       i;
  struct tm tm;
  int       size = 0;

  switch (ctm->type) {
  case V_ASN1_UTCTIME:
    size=10;
    break;
  case V_ASN1_GENERALIZEDTIME:
    size=12;
    break;
  }
  p = buff1;
  i = ctm->length;
  str = (char *)ctm->data;
  if ((i < 11) || (i > 17)) {
    return 0;
  }
  memcpy(p,str,size);
  p += size;
  str += size;

  if ((*str == 'Z') || (*str == '-') || (*str == '+')) {
    *(p++)='0'; *(p++)='0';
  }
  else {
    *(p++)= *(str++); *(p++)= *(str++);
  }
  *(p++) = 'Z';
  *p = '\0';

  if (*str == 'Z') {
    offset=0;
  }
  else {
    if ((*str != '+') && (str[5] != '-')) {
      return 0;
    }
    offset=((str[1]-'0')*10+(str[2]-'0'))*60;
    offset+=(str[3]-'0')*10+(str[4]-'0');
    if (*str == '-') {
      offset=-offset;
    }
  }

  tm.tm_isdst = 0;
  int index = 0;
  if (ctm->type == V_ASN1_UTCTIME) {
    tm.tm_year  = (buff1[index++]-'0')*10;
    tm.tm_year += (buff1[index++]-'0');
  }
  else {
    tm.tm_year  = (buff1[index++]-'0')*1000;
    tm.tm_year += (buff1[index++]-'0')*100;
    tm.tm_year += (buff1[index++]-'0')*10;
    tm.tm_year += (buff1[index++]-'0');
  }

  if (tm.tm_year < 70) {
    tm.tm_year+=100;
  }

  if (tm.tm_year > 1900) {
    tm.tm_year -= 1900;
  }

  tm.tm_mon   = (buff1[index++]-'0')*10;
  tm.tm_mon  += (buff1[index++]-'0')-1;
  tm.tm_mday  = (buff1[index++]-'0')*10;
  tm.tm_mday += (buff1[index++]-'0');
  tm.tm_hour  = (buff1[index++]-'0')*10;
  tm.tm_hour += (buff1[index++]-'0');
  tm.tm_min   = (buff1[index++]-'0')*10;
  tm.tm_min  += (buff1[index++]-'0');
  tm.tm_sec   = (buff1[index++]-'0')*10;
  tm.tm_sec  += (buff1[index]-'0');

  /*
   * mktime assumes local time, so subtract off
   * timezone, which is seconds off of GMT. first
   * we need to initialize it with tzset() however.
   */

  tzset();
#if defined(HAVE_TIMEGM)
  newtime = (timegm(&tm) + offset*60*60);
#elif defined(HAVE_TIME_T_TIMEZONE)
  newtime = (mktime(&tm) + offset*60*60 - timezone);
#elif defined(HAVE_TIME_T__TIMEZONE)
  newtime = (mktime(&tm) + offset*60*60 - _timezone);
#else
  newtime = (mktime(&tm) + offset*60*60);
#endif

  return newtime;
}


#ifdef CLASS_ADD

/**********************************************************************
Function: proxy_extension_class_add_create()

Description:
            create a X509_EXTENSION for the class_add info. 
        
Parameters:
                A buffer and length. The date is added as
                ANS1_OCTET_STRING to an extension with the 
                class_add  OID.

Returns:

**********************************************************************/

X509_EXTENSION PRIVATE *
proxy_extension_class_add_create(
    void *                              buffer,
    size_t                              length)

{
    X509_EXTENSION *                    ex = NULL;
    ASN1_OBJECT *                       class_add_obj = NULL;
    ASN1_OCTET_STRING *                 class_add_oct = NULL;
    int                                 crit = 0;

    if(!(class_add_obj = OBJ_nid2obj(OBJ_txt2nid("CLASSADD"))))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_OID);
        goto err;
    }

    if(!(class_add_oct = ASN1_OCTET_STRING_new()))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
        goto err;
    }

    class_add_oct->data = buffer;
    class_add_oct->length = length;

    if (!(ex = X509_EXTENSION_create_by_OBJ(NULL, class_add_obj, 
                                            crit, class_add_oct)))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
        goto err;
    }
    class_add_oct = NULL;

    return ex;

err:
    if (class_add_oct)
    {
        ASN1_OCTET_STRING_free(class_add_oct);
    }
    
    if (class_add_obj)
    {
        ASN1_OBJECT_free(class_add_obj);
    }
    return NULL;
}
#endif


int PRIVATE determine_filenames(char **cacert, char **certdir, char **outfile,
                                 char **certfile, char **keyfile, int noregen)
{
  char *oldoutfile = NULL;

  if (noregen) {
    int modify = 0;

    if (*certfile == NULL && *keyfile == NULL) 
      modify = 1;

    if (proxy_get_filenames(0, NULL, NULL, &oldoutfile, certfile, keyfile))
      goto err;

    if (modify) {
      free(*certfile);
      free(*keyfile);
      *certfile = strdup(oldoutfile);
      *keyfile = oldoutfile;
    }
    else
      free(oldoutfile);

    if (proxy_get_filenames(0, cacert, certdir, outfile, certfile, keyfile))
      goto err;
  }
  else if (proxy_get_filenames(0, cacert, certdir, outfile, certfile, keyfile))
    goto err;

  return 1;

err:
  return 0;
}

int load_credentials(const char *certname, const char *keyname,
                     X509 **cert, STACK_OF(X509) **stack, EVP_PKEY **key,
                     int (*callback)())
{
  STACK_OF(X509) *chain = NULL;

  if (!certname)
    return 0;

  unsigned long hSession = 0;

  if (!strncmp(certname, "SC:", 3))
    EVP_set_pw_prompt("Enter card pin:");
  else
    EVP_set_pw_prompt("Enter GRID pass phrase for this identity:");

  if (strcmp(certname + strlen(certname) - 4, ".p12")) {
    if(proxy_load_user_cert(certname, cert, callback, &hSession))
      goto err;

    EVP_set_pw_prompt("Enter GRID pass phrase:");

    if (keyname) {
      if (!strncmp(keyname, "SC:", 3))
        EVP_set_pw_prompt("Enter card pin:");

      if (proxy_load_user_key(key, *cert, keyname, callback, &hSession))
        goto err;
    }

    if (stack && (strncmp(certname, "SC:", 3) && (!keyname || !strcmp(certname, keyname)))) {
      chain = sk_X509_new_null();
      if (proxy_load_user_proxy(chain, certname) < 0)
        goto err;
      *stack = chain;
    } 
  }
  else {
    if (!proxy_load_user_cert_and_key_pkcs12(certname, cert, stack, key, callback))
      goto err;
  }    

  return 1;

err:
  if (chain)
    sk_X509_free(chain);
  if (cert) {
    X509_free(*cert);
    *cert = NULL;
  }
  if (key) {
    EVP_PKEY_free(*key);
    *key = NULL;
  }
  return 0;
}

int PRIVATE load_certificate_from_file(FILE *file, X509 **cert, 
                                       STACK_OF(X509) **stack)
{
  BIO *in = NULL;

  if (!cert)
    return 0;

  in = BIO_new_fp(file, BIO_NOCLOSE);

  if (in) {
    *cert = PEM_read_bio_X509(in, NULL, 0, NULL);

    if(!*cert)
      goto err;

    if (stack) {
      *stack = load_chain(in, 0);
      if (!(*stack))
        goto err;
    }
  }
  BIO_free(in);
  return 1;

 err:
  BIO_free(in);
  if (cert)
    X509_free(*cert);
  if (stack)
    sk_X509_pop_free(*stack, X509_free);
  return 0;

}

STACK_OF(X509) *load_chain(BIO *in, char *certfile)
{
  STACK_OF(X509_INFO) *sk=NULL;
  STACK_OF(X509) *stack=NULL, *ret=NULL;
  X509_INFO *xi;
  int first = 1;

  if(!(stack = sk_X509_new_null())) {
    if (certfile)
      printf("memory allocation failure\n");
    goto end;
  }

  /* This loads from a file, a stack of x509/crl/pkey sets */
  if(!(sk=PEM_X509_INFO_read_bio(in,NULL,NULL,NULL))) {
    if (certfile)
      printf("error reading the file, %s\n",certfile);
    goto end;
  }

  /* scan over it and pull out the certs */
  while (sk_X509_INFO_num(sk)) {
    /* skip first cert */
    if (first) {
      first = 0;
      continue;
    }
    xi=sk_X509_INFO_shift(sk);
    if (xi->x509 != NULL) {
      sk_X509_push(stack,xi->x509);
      xi->x509=NULL;
    }
    X509_INFO_free(xi);
  }
  if(!sk_X509_num(stack)) {
    if (certfile)
      printf("no certificates in file, %s\n",certfile);
    sk_X509_free(stack);
    goto end;
  }
  ret=stack;
end:
  sk_X509_INFO_free(sk);
  return(ret);
}

static char hextoint(char r, char s)
{
  int v = 0;
  if (isxdigit(r) && isxdigit(s)) {
    v = hex2num(r);
    v <<= 4;
    v += hex2num(s);
  }
  return v;
}

static unsigned char *reencode_string(unsigned char *string, int *len)
{
  unsigned char *temp = string;
  unsigned char *pos  = string;
  char t = '\0';
  char r = '\0';
  *len = 0;

  while(*string) {
    switch (*string) {
    case '\\':
      t = *++string;

      if (t == '\\') {
        *pos++ = '\\';
        ++(*len);
      }
      else if (isxdigit(t)) {
        r = *++string;
        *pos++ = hextoint(tolower(t), tolower(r));
        ++(*len);
        ++string;
      }
      else {
        *pos++ = t;
        ++(*len);
        ++string;
      }
      break;

    default:
      ++(*len);
      *pos++ = *string++;
      break;
    }
  }

  return temp;
}

static X509_NAME *make_DN(const char *dnstring)
{
  char *buffername = (char*)malloc(strlen(dnstring)+1);
  unsigned char *buffervalue = (unsigned char*)malloc(strlen(dnstring)+1);
  char *currentname;
  unsigned char *currentvalue;
  X509_NAME *name = NULL;
  int valuelen = 0;
  char next = 0;

  name = X509_NAME_new();

  int status = 0; /*
                   * 0 = looking for /type
                   * 1 = looking for value
                   */
  do {
    switch (status) {
    case 0:
      /* Parse for /Name= */
      currentname=buffername;
      while (*dnstring) {
        if (*dnstring == '\\') {
          *currentname++ = *++dnstring;
          if (*dnstring == '\0') {
            break;
          }
          dnstring++;
        }
        else if (*dnstring == '=') {
          *currentname='\0';
          break;
        }
        else if (*dnstring == '\0') {
          break;
        }
        else
          *currentname++ = *dnstring++;
      }
      /* now, if *dnstring == '\0' then error; */
   
      if (*dnstring == '\0')
        goto err;
      /* else, we got a type, now look for a value. */
      status = 1;
      dnstring++;
      break;
    case 1:
      /* Parse for value */
      currentvalue=buffervalue;
      while (*dnstring) {
        if (*dnstring == '\\') {
          next = *++dnstring;
          if (next == '\0') {
            break;
          }
          else if (next != '/') {
            *currentvalue++ = '\\';
            *currentvalue++ = next;
          }
          else {
            *currentvalue++ = '/';
          }
          dnstring++;
        }
        else if (*dnstring == '/') {
          *currentvalue='\0';
          break;
        }
        else if (*dnstring == '\0') {
          *currentvalue='\0';
          break;
        }
        else
          *currentvalue++ = *dnstring++;
      }

      *currentvalue='\0';
      if (strlen((char*)buffervalue) == 0)
        goto err;

      /* Now we have both type and value.  Add to the X509_NAME_ENTRY */

      buffervalue = reencode_string(buffervalue, &valuelen);

      X509_NAME_add_entry_by_txt(name, buffername+1,  /* skip initial '/' */
                                 V_ASN1_APP_CHOOSE,
                                 buffervalue, valuelen, X509_NAME_entry_count(name),
                                 0);
      status = 0;
      break;
    }
  } while (*dnstring);

  free(buffername);
  free(buffervalue);

  return name;
 err:
  free(buffername);
  free(buffervalue);
  X509_NAME_free(name);

  return NULL;

}

static int check_critical_extensions(X509 *cert, int itsaproxy)
{
  int i = 0;
  ASN1_OBJECT *extension_obj;
  int nid;
  X509_EXTENSION *ex;

  int nid_pci3 = my_txt2nid(PROXYCERTINFO_V3);
  int nid_pci4 = my_txt2nid(PROXYCERTINFO_V4);


  for (i=0; i < X509_get_ext_count(cert); i++) {
    ex = X509_get_ext(cert,i);


    if(X509_EXTENSION_get_critical(ex)) {
      extension_obj = X509_EXTENSION_get_object(ex);

      nid = OBJ_obj2nid(extension_obj);

      if (itsaproxy) {
        if (nid != NID_basic_constraints &&
            nid != NID_key_usage &&
            nid != NID_ext_key_usage &&
            nid != NID_netscape_cert_type &&
            nid != NID_subject_key_identifier &&
            nid != NID_authority_key_identifier &&
            nid != nid_pci3 &&
            nid != nid_pci4) {
          return 0;
        }
      }
      else {
        if (nid != NID_basic_constraints &&
            nid != NID_key_usage &&
            nid != NID_ext_key_usage &&
            nid != NID_netscape_cert_type &&
            nid != NID_subject_key_identifier &&
            nid != NID_authority_key_identifier) {
           return 0;
        }
      }
    }
  }
  return 1;
}

/* Check if certificate can be used as a CA to sign standard X509 certs */
/*
 * Return 1 if true; 0 if not.
 */
int grid_x509IsCA(X509 *cert)
{
	int idret;

	/* final argument to X509_check_purpose() is whether to check for CAness */
	idret = X509_check_purpose(cert, X509_PURPOSE_SSL_CLIENT, 1);
	if (idret == 1)
		return 1;
	else if (idret == 0)
		return 0;
	else
	{
	/*	Log( L_WARN, "Purpose warning code = %d\n", idret );*/
		return 1;
	}

}

/******************************************************************************
Function:   verify_PROXYCERTINFO_get_policy
Description:
            Get a policy from the PROXYCERTINFO structure
            ******************************************************************************/
PROXYPOLICY *
verify_PROXYCERTINFO_get_policy(PROXYCERTINFO *cert_info) {
        if(cert_info) {
                    return cert_info->policy;
                        }
            return NULL;
}

/******************************************************************************
Function:   verify_PROXYPOLICY_get_policy_language
Description:
            Get the proxy language from the proxy policy
            ******************************************************************************/
ASN1_OBJECT *
verify_PROXYPOLICY_get_policy_language(PROXYPOLICY *policy) {
            return policy->policy_language;
}

/******************************************************************************
Function:   lcmaps_type_of_proxy
Description:
            This function detects the type of certificates
Parameters:
    certificate
Returns:
          NONE
          CA
          EEC
          GT2_PROXY
          RFC_PROXY
          GT2_LIMITED_PROXY
          RFC_LIMITED_PROXY
          GT3_PROXY
          GT3_LIMITED_PROXY

******************************************************************************/
lcmaps_proxy_type_t lcmaps_type_of_proxy(X509 * cert) {
    lcmaps_proxy_type_t pt = NONE;
    char * cert_subjectdn = NULL;
    char * cert_issuerdn = NULL;
    char * tail_str = NULL;
    int len_subject_dn = 0;
    int len_issuer_dn = 0;

    X509_EXTENSION *                    pci_ext = NULL;
    PROXYCERTINFO *                     pci = NULL;
    PROXYPOLICY *                       policy = NULL;
    ASN1_OBJECT *                       policy_lang = NULL;
    int                                 policy_nid;
    int                                 index = -1;
    int                                 retval = 0;

    /* Is it a CA certificate */
    if (grid_x509IsCA(cert)) {
        /* Log (L_DEBUG, "%s: Detected CA certificate", __func__); */
        pt = CA;
        goto finalize;
    }

    int  i;
    char s[80];
    X509_EXTENSION *ex;

    /* Check by OID */
    for (i = 0; i < X509_get_ext_count(cert); ++i) {
        ex = X509_get_ext(cert, i);

        if (X509_EXTENSION_get_object(ex)) {
            OBJ_obj2txt(s, sizeof(s), X509_EXTENSION_get_object(ex), 1);

            if (strcmp(s, OID_RFC_PROXY) == 0) {
                pt = RFC_PROXY;

                /* Find index of OID_RFC_PROXY */
                if((index = X509_get_ext_by_NID(cert, OBJ_txt2nid(OID_RFC_PROXY), -1)) != -1  &&
                    (pci_ext = X509_get_ext(cert,index)) && X509_EXTENSION_get_critical(pci_ext)) {
                    if((pci = X509V3_EXT_d2i(pci_ext)) == NULL) {
                        retval = 1;
                        goto failure;
                    }

                    /* Pull a certificate policy from the extension */
                    if((policy = verify_PROXYCERTINFO_get_policy(pci)) == NULL) {
                        retval = 2;
                        goto failure;
                    }

                    /* Get policy language */
                    if((policy_lang = verify_PROXYPOLICY_get_policy_language(policy)) == NULL) {
                        retval = 3;
                        goto failure;
                    }

                    /* Lang to NID, lang's NID holds RFC Proxy type, like limited. Impersonation is the default */
                    policy_nid = OBJ_obj2nid(policy_lang);

                    if(policy_nid == OBJ_txt2nid(IMPERSONATION_PROXY_OID)) {
                        pt = RFC_PROXY;
                    } else if(policy_nid == OBJ_txt2nid(INDEPENDENT_PROXY_OID)) {
                        pt = RFC_PROXY;
                    } else if(policy_nid == OBJ_txt2nid(LIMITED_PROXY_OID)) {
                        pt = RFC_LIMITED_PROXY;
                    } else {
                        /* RFC_RESTRICTED_PROXY */
                        pt = RFC_PROXY;
                    }

                    if(X509_get_ext_by_NID(cert, OBJ_txt2nid(OID_RFC_PROXY), index) != -1) {
                        retval = 4;
                        goto failure;
                    }
                }
                goto finalize;
            }
            if (strcmp(s, OID_GLOBUS_PROXY_V3) == 0) {
                pt = GT3_PROXY;

                /* Find index of OID_GT3_PROXY - Don't make it search for critical extentions... VOMS doesn't set those. */
                if((index = X509_get_ext_by_NID(cert, OBJ_txt2nid(OID_GLOBUS_PROXY_V3), -1)) != -1  &&
                    (pci_ext = X509_get_ext(cert,index))) {
                    if((pci = X509V3_EXT_d2i(pci_ext)) == NULL) {
                        retval = 5;
                        goto failure;
                    }

                    /* Pull a certificate policy from the extension */
                    if((policy = verify_PROXYCERTINFO_get_policy(pci)) == NULL) {
                        retval = 6;
                        goto failure;
                    }

                    /* Get policy language */
                    if((policy_lang = verify_PROXYPOLICY_get_policy_language(policy)) == NULL) {
                        retval = 16;
                        /*Error(__func__, "Can't get policy language from PROXYCERTINFO extension");*/
                        goto failure;
                    }

                    /* Lang to NID, lang's NID holds RFC Proxy type, like limited. Impersonation is the default */
                    policy_nid = OBJ_obj2nid(policy_lang);

                    if(policy_nid == OBJ_txt2nid(IMPERSONATION_PROXY_OID)) {
                        pt = GT3_PROXY;
                    } else if(policy_nid == OBJ_txt2nid(INDEPENDENT_PROXY_OID)) {
                        pt = GT3_PROXY;
                    } else if(policy_nid == OBJ_txt2nid(LIMITED_PROXY_OID)) {
                        pt = GT3_LIMITED_PROXY;
                    } else {
                        /* GT3_RESTRICTED_PROXY */
                        pt = GT3_PROXY;
                    }

                    if(X509_get_ext_by_NID(cert, OBJ_txt2nid(OID_GLOBUS_PROXY_V3), index) != -1) {
                        retval = 7;
                        goto failure;
                    }
                }

                goto finalize;
            }
            if (strcmp(s, OID_GLOBUS_PROXY_V2) == 0) {
                pt = GT3_PROXY;

                /* Check for GT2_PROXY tail */
                if (cert_subjectdn
                    && (strlen(cert_subjectdn) > strlen("/cn=proxy"))
                    && (tail_str = &cert_subjectdn[strlen(cert_subjectdn) - strlen("/cn=proxy")])
                    && (strcasecmp(tail_str, "/cn=proxy") == 0)
                   ) {
                    pt = GT2_PROXY;
                    goto finalize;
                }

                /* Check for GT2_LIMITED_PROXY tail */
                if (cert_subjectdn
                    && (strlen(cert_subjectdn) > strlen("/cn=limited proxy"))
                    && (tail_str = &cert_subjectdn[strlen(cert_subjectdn) - strlen("/cn=limited proxy")])
                    && (strcasecmp(tail_str, "/cn=limited proxy") == 0)
                   ) {
                    pt = GT2_LIMITED_PROXY;
                    goto finalize;
                }
                retval = 8;
                goto failure;
            }
        }
    }

    /* Options left: GT2_PROXY, GT2_LIMITED_PROXY, EEC */
    /* Extract Subject DN - Needs free */
    if (!(cert_subjectdn = X509_NAME_oneline (X509_get_subject_name (cert), NULL, 0))) {
        retval = 9;
        goto failure;
    }
    if (!(cert_issuerdn = X509_NAME_oneline (X509_get_issuer_name (cert), NULL, 0))) {
        retval = 10;
        goto failure;
    }

    /* Check length of the DNs */
    len_subject_dn = strlen(cert_subjectdn);
    len_issuer_dn  = strlen(cert_issuerdn);


    /* Lower case the Subject DN */
    /* for (j = 0; j < strlen(cert_subjectdn); j++) { cert_subjectdn[j] = tolower(cert_subjectdn[j]); } */

    /* Proxies always has a longer subject_dn then a issuer_dn and
     * the issuer_dn is a substring of the subject_dn
     */
    if (   (len_issuer_dn < len_subject_dn)
        && (strncmp(cert_subjectdn, cert_issuerdn, len_issuer_dn) == 0)
       ) {
        /* Check for GT2_PROXY tail */
        if (cert_subjectdn
            && (strlen(cert_subjectdn) > strlen("/cn=proxy"))
            && (tail_str = &cert_subjectdn[strlen(cert_subjectdn) - strlen("/cn=proxy")])
            && (strcasecmp(tail_str, "/cn=proxy") == 0)
           ) {
            pt = GT2_PROXY;
            goto finalize;
        }

        /* Check for GT2_LIMITED_PROXY tail */
        if (cert_subjectdn
            && (strlen(cert_subjectdn) > strlen("/cn=limited proxy"))
            && (tail_str = &cert_subjectdn[strlen(cert_subjectdn) - strlen("/cn=limited proxy")])
            && (strcasecmp(tail_str, "/cn=limited proxy") == 0)
           ) {
            pt = GT2_LIMITED_PROXY;
            goto finalize;
        }

        /* Check for RFC_PROXY, without the need for OpenSSL proxy support */
        /* Method: Check if the subject_dn is long enough, grab its tail and
         * snip of the 10 characters. Then check if the 10 characters are
         * numbers. */
        if (cert_subjectdn
            && (strlen(cert_subjectdn) > strlen("/cn=0123456789"))
            && (tail_str = strrchr(cert_subjectdn, '='))
            && (tail_str = &tail_str[1])
            && (strtol(tail_str, NULL, 10))
            && (errno != ERANGE)
           ) {
            /* Log (L_DEBUG, "%s: Detected RFC proxy certificate", __func__); */
            pt = RFC_PROXY;
            goto finalize;
        }

        /* Don't know the type of proxy, could be an RFC proxy with
         * improper/incomplete implementation in the active OpenSSL version or
         * a mistake in the client software */
        goto failure;
    }


    /* I have no idea what else it is, so I conclude that it's an EEC */
    pt = EEC;
    goto finalize;

failure:
    /* On failure, or non-distinct selections of the certificate, indicate NONE */
    pt = NONE;
finalize:
    if (cert_subjectdn)
        free(cert_subjectdn);
    if (cert_issuerdn)
        free(cert_issuerdn);

    return pt;
}

/******************************************************************************
Function:   grid_verifyPathLenConstraints
Oscar Koeroo's solution, thank you.
Description:
            This function will check the certificate chain on CA based (RFC5280)
            and RFC3820 Proxy based Path Length Constraints.
Parameters:
    chain of certificates
Returns:
    0       : Not ok, failure in the verification or the verification failed
    1       : Ok, verification has succeeded and positive
******************************************************************************/
static int grid_verifyPathLenConstraints (STACK_OF(X509) * chain)
{
    char *oper = "grid_verifyPathLenConstraints";
    X509 *cert = NULL;
    int i, depth;
    lcmaps_proxy_type_t curr_cert_type = NONE, expe_cert_type = CA|EEC|RFC_PROXY|GT2_PROXY;
    int found_EEC = 0;
    char *cert_subjectdn = NULL;
    char *error_msg = NULL;
    int retval = 0;

    int ca_path_len_countdown    = -1;
    int proxy_path_len_countdown = -1;
    int ex_pcpathlen, ex_pathlen;

    /* No chain, no game */
    if (!chain) {
        retval = 1;
        goto failure;
    }

    /* Go through the list, from the CA(s) down through the EEC to the final delegation */
    depth = sk_X509_num (chain);
    for (i=depth-1; i >= 0; --i) {
        if ((cert = sk_X509_value(chain, i))) {
            /* Init to None, indicating not to have identified it yet */
            curr_cert_type = NONE;

            /* Extract Subject DN - Needs free */
            if (!(cert_subjectdn = X509_NAME_oneline (X509_get_subject_name (cert), NULL, 0))) {
                retval = 1;
                goto failure;
            }

            ex_pcpathlen = X509_get_proxy_pathlen(cert);
            ex_pathlen = X509_get_pathlen(cert);

            /* Log (L_DEBUG, "\tCert here is: %s\n", cert_subjectdn); */
            curr_cert_type = lcmaps_type_of_proxy(cert);
            if (curr_cert_type == NONE) {
                /* Error (oper, "Couldn't classify certificate at depth %d with subject DN \"%s\"\n",
                             depth, cert_subjectdn); */
                retval = 2;
                goto failure;
            }

            /* Mark that we've found an EEC - When we see it again, it's a failure */
            if (curr_cert_type == EEC && found_EEC == 0) {
                found_EEC = 1;
            } else if (curr_cert_type == EEC && found_EEC == 1) {
                /* Error (oper, "Found another EEC classified certificate in the same chain at depth %d with subject DN \"%s\"\n",
                             depth, cert_subjectdn); */
                retval = 3;
                goto failure;
            }


#if 0
                /* NOTE: This is for quick debugging only */
                error_msg = verify_generate_proxy_expectation_error_message(curr_cert_type, expe_cert_type);
                printf("%s: Build chain checker: %s. Cert at depth %d of %d with Subject DN: %s\n",
                            oper,
                            error_msg,
                            i,
                            depth,
                            cert_subjectdn);
                free(error_msg); error_msg = NULL;
#endif

            /* Expectation management */
            if (!((expe_cert_type & curr_cert_type) == curr_cert_type)) {
                /* Failed to comply with the expectations! */
#define USE_STRICT_PATH_VALIDATION
#ifdef USE_STRICT_PATH_VALIDATION
                /* error_msg = verify_generate_proxy_expectation_error_message(curr_cert_type, expe_cert_type);
                Error(oper, "Certificate chain not build in the right order. %s. Cert at depth %d of %d with Subject DN: %s\n",
                            error_msg,
                            i,
                            depth,
                            cert_subjectdn);
                free(error_msg); error_msg = NULL;*/
                goto failure;
#else
                /* error_msg = verify_generate_proxy_expectation_error_message(curr_cert_type, expe_cert_type);
                Log(L_INFO, "%s: Certificate chain not build in the right order. %s. Cert at depth %d of %d with Subject DN: %s\n",
                            oper,
                            error_msg,
                            i,
                            depth,
                            cert_subjectdn);
                free(error_msg); error_msg = NULL; */
                goto continue_after_warning;
#endif
            }
#ifndef USE_STRICT_PATH_VALIDATION
continue_after_warning:
#endif

            if (curr_cert_type == CA) {
                /* Expected next certificate type is: CA or EEC certificate */
                expe_cert_type = CA|EEC;
                /*Log (L_DEBUG, "Current cert is a CA: %s\n", cert_subjectdn);*/

                /* Exceeded CA Path Length ? */
                if (ca_path_len_countdown == 0) {
                    /*Error(oper, "CA Path Length Constraint exceeded on depth %d for certificate \"%s\". No CA certifcates were expected at this stage.\n", i, cert_subjectdn);*/
                    retval = 4;
                    goto failure;
                }

                /* Store pathlen, override when small, otherwise keep the smallest */
                if (ex_pathlen != -1) {
                    /* Update when ca_path_len_countdown is the initial value
                     * or when the PathLenConstraint is smaller then the
                     * remembered ca_path_len_countdown */
                    if ((ca_path_len_countdown == -1) || (ex_pathlen < ca_path_len_countdown)) {
                        ca_path_len_countdown = ex_pathlen;
                    } else {
                        /* If a path length was already issuesd, lower ca_path_len_countdown */
                        if (ca_path_len_countdown != -1)
                            ca_path_len_countdown--;
                    }
                } else {
                    /* If a path length was already issuesd, lower ca_path_len_countdown */
                    if (ca_path_len_countdown != -1)
                        ca_path_len_countdown--;
                }

            } else if (curr_cert_type == EEC) {
                /* Expected next certificate type is: GT2_PROXY, GT3_PROXY, RFC_PROXY or a Limited proxy of these flavors certificate */
                expe_cert_type = GT2_PROXY|GT3_PROXY|RFC_PROXY|GT2_LIMITED_PROXY|GT3_LIMITED_PROXY|RFC_LIMITED_PROXY;
                /*Log (L_DEBUG, "Current cert is a EEC: %s\n", cert_subjectdn);*/

            } else if (curr_cert_type == GT2_PROXY) {
                /* Expected next certificate type is: GT2_PROXY certificate */
                expe_cert_type = GT2_PROXY|GT2_LIMITED_PROXY;
                /*Log (L_DEBUG, "Current cert is a GT2 Proxy: %s\n", cert_subjectdn);*/

            } else if (curr_cert_type == GT2_LIMITED_PROXY) {
                /* Expected next certificate type is: GT2_LIMITED_PROXY certificate */
                expe_cert_type = GT2_LIMITED_PROXY;
                /* Log (L_DEBUG, "Current cert is a GT2 Limited Proxy: %s\n", cert_subjectdn); */

            } else if (curr_cert_type == GT3_PROXY) {
                /* Expected next certificate type is: GT3_PROXY certificate */
                expe_cert_type = GT3_PROXY|GT3_LIMITED_PROXY;
                /* Log (L_DEBUG, "Current cert is a GT3 Proxy: %s\n", cert_subjectdn);*/
            } else if (curr_cert_type == GT3_LIMITED_PROXY) {
                /* Expected next certificate type is: GT3_LIMITED_PROXY certificate */
                expe_cert_type = GT3_LIMITED_PROXY;
                /* Log (L_DEBUG, "Current cert is a GT3 Limited Proxy: %s\n", cert_subjectdn);*/

            } else if (curr_cert_type == RFC_PROXY) {
                /* Expected next certificate type is: RFC_PROXY certificate */
                expe_cert_type = RFC_PROXY|RFC_LIMITED_PROXY;
                /* Log (L_DEBUG, "Current cert is a RFC Proxy: %s\n", cert_subjectdn);*/

                /* Exceeded CA Path Length ? */
                if (proxy_path_len_countdown == 0) {
                  /*   Error(oper, "Proxy Path Length Constraint exceeded on depth %d of %d for certificate \"%s\". No Proxy certifcates were expected at this stage.\n", i, depth, cert_subjectdn);*/
                    goto failure;
                }

                /* Store pathlen, override when small, otherwise keep the smallest */
                if (ex_pcpathlen != -1) {
                    /* Update when proxy_path_len_countdown is the initial value
                     * or when the PathLenConstraint is smaller then the
                     * remembered proxy_path_len_countdown */

                    if ((proxy_path_len_countdown == -1) || (ex_pcpathlen < proxy_path_len_countdown)) {
                        proxy_path_len_countdown = ex_pcpathlen;
                       /*  Log (L_DEBUG, "Cert here is: %s -> Setting proxy path len constraint to: %d\n", cert_subjectdn, cert->ex_pcpathlen);*/
                    } else {
                        /* If a path length was already issuesd, lower ca_path_len_countdown */
                        if (proxy_path_len_countdown != -1)
                            proxy_path_len_countdown--;

                       /*  Log (L_DEBUG, "Cert here is: %s -> Countdown is at %d\n", cert_subjectdn, proxy_path_len_countdown);*/
                    }
                } else {
                    /* If a path length was already issued, lower ca_path_len_countdown */
                    if (proxy_path_len_countdown != -1) {
                        proxy_path_len_countdown--;
                       /*  Log (L_DEBUG, "Cert here is: %s -> Countdown is at %d\n", cert_subjectdn, proxy_path_len_countdown);*/
                    }

                }
            } else if (curr_cert_type == RFC_LIMITED_PROXY) {
                /* Expected next certificate type is: RFC_LIMITED_PROXY certificate */
                expe_cert_type = RFC_LIMITED_PROXY;
               /*  Log (L_DEBUG, "Current cert is a RFC Limited Proxy: %s\n", cert_subjectdn);*/

                /* Exceeded CA Path Length ? */
                if (proxy_path_len_countdown == 0) {
                   /*  Error(oper, "Proxy Path Length Constraint exceeded on depth %d of %d for certificate \"%s\". No Proxy certifcates were expected at this stage.\n", i, depth, cert_subjectdn);*/
                    goto failure;
                }

                /* Store pathlen, override when small, otherwise keep the smallest */
                if (ex_pcpathlen != -1) {
                    /* Update when proxy_path_len_countdown is the initial value
                     * or when the PathLenConstraint is smaller then the
                     * remembered proxy_path_len_countdown */

                    if ((proxy_path_len_countdown == -1) || (ex_pcpathlen < proxy_path_len_countdown)) {
                        proxy_path_len_countdown = ex_pcpathlen;
                       /*  Log (L_DEBUG, "Cert here is: %s -> Setting proxy path len constraint to: %d\n", cert_subjectdn, cert->ex_pcpathlen);*/
                    } else {
                        /* If a path length was already issuesd, lower ca_path_len_countdown */
                        if (proxy_path_len_countdown != -1)
                            proxy_path_len_countdown--;

                        /* Log (L_DEBUG, "Cert here is: %s -> Countdown is at %d\n", cert_subjectdn, proxy_path_len_countdown);*/
                    }
                } else {
                    /* If a path length was already issued, lower ca_path_len_countdown */
                    if (proxy_path_len_countdown != -1) {
                        proxy_path_len_countdown--;
                       /* Log (L_DEBUG, "Cert here is: %s -> Countdown is at %d\n", cert_subjectdn, proxy_path_len_countdown);*/
                    }

                }
            }

            /* Free memory during each cycle */
            if (cert_subjectdn) {
                free(cert_subjectdn);
                cert_subjectdn = NULL;
            }
        }
    }

    /* Return an OK (thumbs up) in the grid_X509_verify_callback() */
    if (cert_subjectdn) {
        free(cert_subjectdn);
        cert_subjectdn = NULL;
    }
    return X509_V_OK;

failure:
    if (cert_subjectdn) {
        free(cert_subjectdn);
        cert_subjectdn = NULL;
    }
    return X509_V_ERR_CERT_REJECTED;
}
