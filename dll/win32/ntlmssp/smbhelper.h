#ifndef _SMBHELPER_H_
#define _SMBHELPER_H_

#include "stdbool.h"
#include "samba/lib/util/data_blob.h"
#include "samba/librpc/ndr/libndr.h"
#include "smbdefs.h"
#include "ntstatus.h"

/* types / functions from samba
 * for wich the samba file is not imported (yet).
 */

//FIXME
#define debug_ntlmssp_flags(a)
#define NDR_PRINT_DEBUG(a,b)
#define smb_panic printf
struct ldb_message {
    char *msg;
};
struct ldb_dn {
    char *msg;
};

/* implemented in ndr_basic.c
 * don't know in wich header it is defined */
enum ndr_err_code ndr_pull_uint32(struct ndr_pull *ndr, int ndr_flags, uint32_t *v);
enum ndr_err_code ndr_push_NTTIME(struct ndr_push *ndr, int ndr_flags, NTTIME t);


/* samba: lib/util/fault.h */
/**
 * assert macros
 */
#define SMB_ASSERT(b) \
do { \
	if (!(b)) { \
		DEBUG(0,("PANIC: assert failed at %s(%d): %s\n", \
			 __FILE__, __LINE__, #b)); \
		smb_panic("assert failed: " #b); \
	} \
} while(0)

/* libcli/util/ntstatus.h:*/
#define NT_STATUS(x) (x)
#define NT_STATUS_V(x) (x)
#define NT_STATUS_IS_OK(x) (/*likely*/(NT_STATUS_V(x) == 0))
#define NT_STATUS_EQUAL(x,y) (NT_STATUS_V(x) == NT_STATUS_V(y))

const char *nt_errstr_const(NTSTATUS nt_code);
const char *nt_errstr(NTSTATUS nt_code);


/* bin/default/include/public/core/error.h */
NTSTATUS map_nt_error_from_unix_common(int unix_error);



/* samba:ntstatus.h */
#define NT_STATUS_HAVE_NO_MEMORY(x) do { \
	if (unlikely(!(x))) {		\
		return NT_STATUS_NO_MEMORY;\
	}\
} while (0)



/*samr.h: */
struct samr_Password {
	uint8_t hash[16];
};/* [flag(LIBNDR_PRINT_ARRAY_HEX),public] */;
/* auth/credentials/credentials_internal.h:	*/
struct samr_Password *nt_hash;



/* bin/default/include/public/core/ntstatus_gen.h */
#define NT_STATUS_SUCCESS NT_STATUS(0x0)
#define NT_STATUS_NOT_IMPLEMENTED NT_STATUS(0xc0000002)
/*#define NT_STATUS_NO_MEDIA_IN_DEVICE NT_STATUS(0xc0000013)
#define NT_STATUS_UNRECOGNIZED_MEDIA NT_STATUS(0xc0000014)
#define NT_STATUS_NONEXISTENT_SECTOR NT_STATUS(0xc0000015)*/
#define NT_STATUS_MORE_PROCESSING_REQUIRED NT_STATUS(0xc0000016)
#define NT_STATUS_NO_MEMORY NT_STATUS(0xc0000017)
/*#define NT_STATUS_CONFLICTING_ADDRESSES NT_STATUS(0xc0000018)
#define NT_STATUS_NOT_MAPPED_VIEW NT_STATUS(0xc0000019)
#define NT_STATUS_UNABLE_TO_FREE_VM NT_STATUS(0xc000001a)
#define NT_STATUS_UNABLE_TO_DELETE_SECTION NT_STATUS(0xc000001b)
#define NT_STATUS_INVALID_SYSTEM_SERVICE NT_STATUS(0xc000001c)*/
#define NT_STATUS_INVALID_PARAMETER NT_STATUS(0xc000000d)
/*bin/default/include/public/core/ntstatus_gen.h:#define NT_STATUS_INVALID_PARAMETER_MIX NT_STATUS(0xc0000030)*/
#define NT_STATUS_OBJECT_NAME_COLLISION NT_STATUS(0xc0000035)
#define NT_STATUS_INTERNAL_ERROR NT_STATUS(0xc00000e5)
/*bin/default/include/public/core/ntstatus_gen.h:#define NT_STATUS_INVALID_PARAMETER_1 NT_STATUS(0xc00000ef)
bin/default/include/public/core/ntstatus_gen.h:#define NT_STATUS_INVALID_PARAMETER_2 NT_STATUS(0xc00000f0)
bin/default/include/public/core/ntstatus_gen.h:#define NT_STATUS_INVALID_PARAMETER_3 NT_STATUS(0xc00000f1)
bin/default/include/public/core/ntstatus_gen.h:#define NT_STATUS_INVALID_PARAMETER_4 NT_STATUS(0xc00000f2)
bin/default/include/public/core/ntstatus_gen.h:#define NT_STATUS_INVALID_PARAMETER_5 NT_STATUS(0xc00000f3)
bin/default/include/public/core/ntstatus_gen.h:#define NT_STATUS_INVALID_PARAMETER_6 NT_STATUS(0xc00000f4)
bin/default/include/public/core/ntstatus_gen.h:#define NT_STATUS_INVALID_PARAMETER_7 NT_STATUS(0xc00000f5)
bin/default/include/public/core/ntstatus_gen.h:#define NT_STATUS_INVALID_PARAMETER_8 NT_STATUS(0xc00000f6)
bin/default/include/public/core/ntstatus_gen.h:#define NT_STATUS_INVALID_PARAMETER_9 NT_STATUS(0xc00000f7)
bin/default/include/public/core/ntstatus_gen.h:#define NT_STATUS_INVALID_PARAMETER_10 NT_STATUS(0xc00000f8)
bin/default/include/public/core/ntstatus_gen.h:#define NT_STATUS_INVALID_PARAMETER_11 NT_STATUS(0xc00000f9)
bin/default/include/public/core/ntstatus_gen.h:#define NT_STATUS_INVALID_PARAMETER_12 NT_STATUS(0xc00000fa)*/
#define NT_STATUS_OK			  NT_STATUS_SUCCESS

/* TODO map status codes above
 * #define <samba nt-status> <nt-status>*/
#define NT_STATUS_IO_TIMEOUT      STATUS_IO_TIMEOUT
#define NT_STATUS_NO_SUCH_USER    STATUS_NO_SUCH_USER
#define NT_STATUS_NO_USER_SESSION_KEY STATUS_NO_USER_SESSION_KEY
#define NT_STATUS_INVALID_PARAMETER_MIX STATUS_INVALID_PARAMETER
#define NT_STATUS_WRONG_PASSWORD  STATUS_WRONG_PASSWORD
#define NT_STATUS_NOT_FOUND       STATUS_NOT_FOUND
#define NT_STATUS_NTLM_BLOCKED    NT_STATUS(0xc0000418)
#define NT_STATUS_ACCESS_DENIED   STATUS_ACCESS_DENIED
#define NT_STATUS_BUFFER_TOO_SMALL STATUS_BUFFER_TOO_SMALL
#define NT_STATUS_ARRAY_BOUNDS_EXCEEDED STATUS_ARRAY_BOUNDS_EXCEEDED
#define NT_STATUS_PORT_MESSAGE_TOO_LONG STATUS_PORT_MESSAGE_TOO_LONG

/*libcli/util/hresult.h*/
#define HRES_ERROR(x) (x)
#define HRES_ERROR_V(x) (x)
#define HRES_SEC_E_UNSUPPORTED_FUNCTION			  HRES_ERROR(0x80090302)



/*libcli/util/ntstatus.h*/
#define NT_STATUS_IS_OK_RETURN(x) do { \
	if (NT_STATUS_IS_OK(x)) {\
		return x;\
	}\
} while (0)

#define NT_STATUS_NOT_OK_RETURN(x) do { \
	if (!NT_STATUS_IS_OK(x)) {\
		return x;\
	}\
} while (0)



/* bin/default/include/public/gen_ndr/netlogon.h */
#define MSV1_0_ALLOW_MSVCHAPV2 ( 0x00010000 )



/*samba: bin/default/lib/param/param_functions.h */
const char *lpcfg_workgroup(struct loadparm_context *x);
const int lpcfg_map_to_guest(struct loadparm_context *x);
const char *lpcfg_netbios_name(struct loadparm_context *x);
const bool lpcfg_lanman_auth(struct loadparm_context *x);
const enum ntlm_auth_level lpcfg_ntlm_auth(struct loadparm_context *x);
const bool lpcfg_client_ntlmv2_auth(struct loadparm_context *x);
const bool lpcfg_client_lanman_auth(struct loadparm_context *x);



/* samba:librpc/ndr/libndr.h */
/* structure passed to functions that print IDL structures */
/*struct ndr_print {
        uint32_t flags; / * LIBNDR_FLAG_* * /
        uint32_t depth;
        struct ndr_token_list *switch_list;
        void (*print)(struct ndr_print *, const char *, ...);
        void *private_data;
};*/



/* libds/common/roles.h: */
/* server roles. If you add new roles, please keep ensure that the
 * existing role values match samr_Role from samr.idl
 */
enum server_role {
	ROLE_STANDALONE    = 0,
	ROLE_DOMAIN_MEMBER = 1,
	ROLE_DOMAIN_BDC    = 2,
	ROLE_DOMAIN_PDC    = 3,

	/* not in samr.idl */
	ROLE_ACTIVE_DIRECTORY_DC = 4,

	/* To determine the role automatically, this is not a valid role */
	ROLE_AUTO          = 100
};



/* samba: lib/util/util.c */
void dump_data(int level, const uint8_t *buf, int len);



/*?? not from samba - ??*/
/* samba: lib/util/time.h: */
//struct timeval_buf { char buf[128]; };
struct timeval timeval_current(void);
struct timeval timeval_add(const struct timeval *tv,
			   uint32_t secs, uint32_t usecs);
NTTIME timeval_to_nttime(const struct timeval *tv);
void nttime_to_timeval(struct timeval *tv, NTTIME t);
bool timeval_expired(const struct timeval *tv);
void push_nttime(uint8_t *base, uint16_t offset, NTTIME t);
void push_nttime(uint8_t *base, uint16_t offset, NTTIME t);



/* advapi32 */
#define MD5_DIGEST_LENGTH 16
/*typedef MD5_CTX AVMD5;
void WINAPI MD5Init(MD5_CTX *ctx);
void WINAPI MD5Update(MD5_CTX *ctx, const unsigned char *buf, unsigned int len);
void WINAPI MD5Final(uint8_t digest[MD5_DIGEST_LENGTH], MD5_CTX *context);
*/



/* gnutls */
typedef struct
{
    BYTE* data;
    ULONG size;
} gnutls_datum_t;

typedef enum
{
    GNUTLS_CIPHER_ARCFOUR_128 = 0
} gnutls_cipher_algorithm_t;
typedef struct
{
    gnutls_cipher_algorithm_t cipher;
    const gnutls_datum_t* key;
} _gnutls_cipher_hd_t, *gnutls_cipher_hd_t;

typedef enum
{
    GNUTLS_DIG_MD5 = 0
} gnutls_digest_algorithm_t;
typedef struct
{
    gnutls_digest_algorithm_t algo;
    MD5_CTX ctx;
} _gnutls_hash_hd_t, *gnutls_hash_hd_t;

typedef enum
{
    GNUTLS_MAC_MD5 = 0
} gnutls_mac_algorithm_t;
typedef struct
{
    gnutls_mac_algorithm_t algo;
    HMAC_MD5_CTX md5ctx;
} _gnutls_hmac_hd_t, *gnutls_hmac_hd_t;

/* gnutls */
NTSTATUS gnutls_error_to_ntstatus(
    IN int returncode,
    IN ULONG error);

int gnutls_cipher_init(
    IN gnutls_cipher_hd_t * handle,
    IN gnutls_cipher_algorithm_t cipher,
    IN const gnutls_datum_t * key,
    IN const gnutls_datum_t * iv);
int gnutls_cipher_encrypt(
    IN const gnutls_cipher_hd_t handle,
    IN OUT void *text,
    IN size_t textlen);
void gnutls_cipher_deinit(
    IN gnutls_cipher_hd_t handle);

int gnutls_hash_init(
    IN gnutls_hash_hd_t *dig,
    IN gnutls_digest_algorithm_t algorithm);
int gnutls_hash(
    IN gnutls_hash_hd_t handle,
    IN const void *text,
    IN size_t textlen);
void gnutls_hash_deinit(
    IN gnutls_hash_hd_t handle,
    OUT void *digest);

int gnutls_hash_fast(
    IN gnutls_digest_algorithm_t algorithm,
    IN const void *text,
    IN size_t textlen,
    OUT void *digest);

int gnutls_hmac_fast(
    IN gnutls_mac_algorithm_t algorithm,
    IN const void *key,
    IN size_t keylen,
    IN const void *text,
    IN size_t textlen,
    IN void *digest);
int gnutls_hmac_init(
    IN gnutls_hmac_hd_t * dig,
    IN gnutls_mac_algorithm_t algorithm,
    IN const void *key,
    IN size_t keylen);
void gnutls_hmac_deinit(
    IN gnutls_hmac_hd_t handle,
    OUT void *digest);
int gnutls_hmac(
    IN gnutls_hmac_hd_t handle,
    IN const void *text,
    IN size_t textlen);



/* samba:lib/crypto/md4.h */
void mdfour(uint8_t *out, const uint8_t *in, int n);



/* misc */
size_t strlcpy(char *destination, const char *source, size_t size);

/* initilise gense_settings
 * loaded from where it should be in real windows */
struct gensec_settings* smbGetGensecSettigs();


/* copy a smb DATA_BLOB to SecBuffer */
SECURITY_STATUS
CopySmbBlobToSecBuffer(
    ULONG ISCContextReq,
    PULONG ISCAttribRet,
    IN DATA_BLOB* blob,
    OUT PSecBuffer buffer);

/* talloc-strdup for EXT_STRINGs */
char *talloc_ExtAStrToAStrDup(const void *t, PEXT_STRING_A str);
char *talloc_ExtWStrToAStrDup(const void *t, PEXT_STRING_W str);

/* map (smb) NTSTATUS to SECURITY_STATUS */
SECURITY_STATUS
error_nt2sec(NTSTATUS st);

void NtlmInitializeSamba();
void NtlmFinalizeSamba();

#endif
