#include "smbhelper.h"
#include "smbincludes.h"
#include "samba/libcli/auth/ntlm_check.h"
#include "samba/lib/param/loadparm.h"
#include "samba/auth/credentials/credentials_internal.h"
#include "samba/lib/talloc/talloc.h"
#include "ciphers.h"

#include "wine/debug.h"
WINE_DEFAULT_DEBUG_CHANNEL(ntlm);

struct loadparam_context;

int __strnlen(const char *s, size_t n)
{
    int len = 0;
    while ((len < n) && (s))
    {
        s++;
        len++;
    }
    return len;
}

/* FIXME */
struct timeval timeval_add(const struct timeval *tv,
			   uint32_t secs, uint32_t usecs)
{
    struct timeval tv2;
    printf("timeval_add\n");

    memset(&tv2, 0, sizeof(tv2));
    return tv2;
}

/* FIXME */
struct timeval timeval_current(void)
{
    struct timeval tv2;
    printf("timeval_current\n");
    memset(&tv2, 0, sizeof(tv2));
    return tv2;
}

/* FIXME */
NTTIME timeval_to_nttime(const struct timeval *tv)
{
    printf("timeval_to_nttime\n");
    return 0;
}

/* FIXME */
void nttime_to_timeval(struct timeval *tv, NTTIME t)
{
    printf("nttime_to_timeval\n");
    memset(tv, 0, sizeof(*tv));
}

/* FIXME tevent.h */
struct timeval tevent_timeval_current(void)
{
    struct timeval t;
    printf("tevent_timeval_current\n");
    memset(&t, 0, sizeof(t));
    return t;
}

bool timeval_expired(const struct timeval *tv)
{
    printf("timeval_expired\n");
    //memset(tv, 0, sizeof(*tv));
    return false;
}

/* from lib/util/time.c */
/**
  put a NTTIME into a packet
*/
void push_nttime(uint8_t *base, uint16_t offset, NTTIME t)
{
	SBVAL(base, offset,   t);
}

/* FIXME */
NTSTATUS map_nt_error_from_unix_common(int unix_error)
{
    printf("map_nt_error_from_unix_common\n");
    return 0;
}



/* ... */
const char *nt_errstr_const(NTSTATUS nt_code)
{
    return "TODO nt_errstr_const";
}

NTSTATUS gnutls_error_to_ntstatus(
    IN int returncode,
    IN ULONG error)
{
    return error;
}

int gnutls_hash_init(
    IN gnutls_hash_hd_t *dig,
    IN gnutls_digest_algorithm_t algorithm)
{
    if (algorithm == GNUTLS_DIG_MD5)
    {
        *dig = talloc(NULL, _gnutls_hash_hd_t);
        (*dig)->algo = algorithm;
        MD5Init(&(*dig)->ctx);
        return 0;
    }
    ERR("gnutls_hash_init: unknown algo!\n");
    return -1;
}

int gnutls_hash(
    IN gnutls_hash_hd_t handle,
    IN const void *text,
    IN size_t textlen)
{
    if (handle->algo == GNUTLS_DIG_MD5)
    {
        MD5Update(&handle->ctx, text, textlen);
        return 0;
    }
    ERR("gnutls_hash: unknown algo!\n");
    return -1;
}

void gnutls_hash_deinit(
    IN gnutls_hash_hd_t handle,
    OUT void *digest)
{
    if (handle->algo == GNUTLS_DIG_MD5)
    {
        if (digest)
        {
            MD5Final(&handle->ctx);
            memcpy(digest, handle->ctx.digest, MD5_DIGEST_LENGTH);
        }
        talloc_free((void*)handle);
        return;
    }
    ERR("gnutls_hash_fast: unknown algo!\n");
    talloc_free((void*)handle);
}



int gnutls_hash_fast(
    IN gnutls_digest_algorithm_t algorithm,
    IN const void *text,
    IN size_t textlen,
    OUT void *digest)
{
    if (algorithm == GNUTLS_DIG_MD5)
    {
        MD5_CTX md5ctx;

        MD5Init(&md5ctx);
        MD5Update(&md5ctx, text, textlen);
        MD5Final(&md5ctx);
        memcpy(digest, md5ctx.digest, MD5_DIGEST_LENGTH);
        return 0;
    }
    ERR("gnutls_hash_fast: unknown algo!\n");
    return -1;
}

int gnutls_cipher_init(
    IN gnutls_cipher_hd_t *handle,
    IN gnutls_cipher_algorithm_t cipher,
    IN const gnutls_datum_t *key,
    IN const gnutls_datum_t *iv)
{
    if (cipher == GNUTLS_CIPHER_ARCFOUR_128)
    {
        if (key->size != 16)
        {
            ERR("gnutls_cipher_init: expected key-size 16, got size %i\n", key->size);
            return -1;
        }
        *handle = talloc(NULL, _gnutls_cipher_hd_t);
        (*handle)->cipher = cipher;
        (*handle)->key = key;
        return 0;
    }
    ERR("gnutls_cipher_init: unknown algo!\n");
    return -1;
}

int gnutls_cipher_encrypt(
    IN const gnutls_cipher_hd_t handle,
    IN OUT void *text,
    IN size_t textlen)
{
    if (handle->cipher == GNUTLS_CIPHER_ARCFOUR_128)
    {
        arcfour_crypt(text, handle->key->data, textlen);
        return 0;
    }
    ERR("gnutls_cipher_encrypt: unknown algo!\n");
    return -1;
}

void gnutls_cipher_deinit(
    IN gnutls_cipher_hd_t handle)
{
    if (handle->cipher == GNUTLS_CIPHER_ARCFOUR_128)
    {
        talloc_free((void*)handle);
        return;
    }
    ERR("gnutls_hmac_deinit: unknown algo!\n");
    talloc_free((void*)handle);
}

int gnutls_hmac_fast(
    IN gnutls_mac_algorithm_t algorithm,
    IN const void *key,
    IN size_t keylen,
    IN const void *text,
    IN size_t textlen,
    IN void *digest)
{
    if (algorithm == GNUTLS_MAC_MD5)
    {
        HMAC_MD5(key, keylen, text, textlen, digest);
        return 0;
    }
    ERR("gnutls_hmac_fast: unknown algo!\n");
    return -1;
}

int gnutls_hmac_init(
    IN gnutls_hmac_hd_t *dig,
    IN gnutls_mac_algorithm_t algorithm,
    IN const void *key,
    IN size_t keylen)
{
    if (algorithm == GNUTLS_MAC_MD5)
    {
        *dig = talloc(NULL, _gnutls_hmac_hd_t);
        (*dig)->algo = algorithm;
        HMACMD5Init(&(*dig)->md5ctx, key, keylen);
        return 0;
    }
    ERR("gnutls_hmac_init: unknown algo!\n");
    return -1;
}

void gnutls_hmac_deinit(
    IN gnutls_hmac_hd_t handle,
    OUT void *digest)
{
    if (handle->algo == GNUTLS_MAC_MD5)
    {
        if (digest)
            HMACMD5Final(&handle->md5ctx, digest);

        talloc_free((void*)handle);
        return;
    }
    ERR("gnutls_hmac_deinit: unknown algo!\n");
    talloc_free((void*)handle);
}

int gnutls_hmac(
    IN gnutls_hmac_hd_t handle,
    IN const void *text,
    IN size_t textlen)
{
    if (handle->algo == GNUTLS_MAC_MD5)
    {
        HMACMD5Update(&handle->md5ctx, text, textlen);
        return 0;
    }
    ERR("gnutls_hmac: unknown algo!\n");
    return -1;
}



/* auth/credentials/credentials.h: */
const char *cli_credentials_get_workstation(struct cli_credentials *cred)
{
    return cred->workstation;
}

bool cli_credentials_is_anonymous(struct cli_credentials *cred)
{
    D_WARNING("FIXME\n");
    return FALSE;
}

void cli_credentials_get_ntlm_username_domain(struct cli_credentials *cred, TALLOC_CTX *mem_ctx,
					      const char **username,
					      const char **domain)
{
    *username = cred->username;
    *domain = cred->domain;
}

const char *cli_credentials_get_password(struct cli_credentials *cred)
{
    char* smbpwd;
    smbpwd = (char*)talloc_memdup(cred, cred->password, cred->passwordLen);
    if (!NtlmUnProtectMemory(smbpwd, cred->passwordLen))
    {
        ERR("NtlmUnProtectMemory failed\n");
        return NULL;
    }
    return smbpwd;
}

struct samr_Password *cli_credentials_get_nt_hash(struct cli_credentials *cred,
						  TALLOC_CTX *mem_ctx)
{
    return talloc_memdup(mem_ctx, cred->nt_hash, sizeof(*(cred->nt_hash)));
}



/* common_auth.h */
void log_authentication_event(struct imessaging_context *msg_ctx,
			      struct loadparm_context *lp_ctx,
			      const struct timeval *start_time,
			      const struct auth_usersupplied_info *ui,
			      NTSTATUS status,
			      const char *account_name,
			      const char *domain_name,
			      struct dom_sid *sid)
{
    D_WARNING("FIXME\n");
    D_DEBUG("log_authentication_event\n");
    D_DEBUG("    account %s, domain %s\n", account_name, domain_name);
    D_DEBUG("    ...\n");
}

void mdfour(uint8_t *out, const uint8_t *in, int n)
{
    MD4(in, n, out);
}

size_t strlcpy(char *destination, const char *source, size_t size)
{
    size_t sourcelen;
    /* hacky strlcpy implementation - sorry */
    strncpy(destination, source, size);
    /* always NULL */
    if (size == 0)
        return 0;
    sourcelen = strlen(source);
    if (sourcelen < size)
        size = sourcelen;
    destination[size] = 0;
    return size;
}

NTSTATUS
CopySmbBlobToSecBuffer(
    ULONG ISCContextReq,
    PULONG ISCAttribRet,
    IN DATA_BLOB* blob,
    OUT PSecBuffer buffer)
{
    /* if should not allocate */
    if (!(ISCContextReq & ISC_REQ_ALLOCATE_MEMORY))
    {
        /* not enough space */
        if(blob->length > buffer->cbBuffer)
            return STATUS_BUFFER_TOO_SMALL;

        buffer->cbBuffer = blob->length;
    }
    else
    {
        /* allocate */
        buffer->pvBuffer = NtlmAllocate(blob->length);
        buffer->cbBuffer = blob->length;

        if(!buffer->pvBuffer)
            return STATUS_NO_MEMORY;

        *ISCAttribRet |= ISC_RET_ALLOCATED_MEMORY;
    }
    memcpy(buffer->pvBuffer, blob->data, blob->length);

    return NT_STATUS_OK;
}

/* talloc-strdup for EXT_STRINGs */
char *talloc_ExtAStrToAStrDup(const void *t, PEXT_STRING_A str)
{
    return talloc_strdup(t, (char*)str->Buffer);
}

char *talloc_ExtWStrToAStrDup(const void *t, PEXT_STRING_W str)
{
    EXT_STRING_A strA;
    char *str2;

    if (!ExtWStrToAStr(&strA, str, FALSE, TRUE))
        return NULL;
    str2 = talloc_strdup(t, (char*)strA.Buffer);
    ExtStrFree(&strA);

    return str2;
}

/* map (smb) NTSTATUS to SECURITY_STATUS */
SECURITY_STATUS
error_nt2sec(NTSTATUS st)
{
    switch (st)
    {
        case NT_STATUS_OK : return SEC_E_OK;
        // 0xC0000001
        //case STATUS_UNSUCCESSFUL
        case STATUS_NOT_IMPLEMENTED : return SEC_E_UNSUPPORTED_FUNCTION;
        //case STATUS_INVALID_INFO_CLASS               ((NTSTATUS)0xC0000003)
        //case STATUS_INFO_LENGTH_MISMATCH             ((NTSTATUS)0xC0000004)
        //case STATUS_ACCESS_VIOLATION                 ((NTSTATUS)0xC0000005)
        //case STATUS_IN_PAGE_ERROR                    ((NTSTATUS)0xC0000006)
        //case STATUS_PAGEFILE_QUOTA                   ((NTSTATUS)0xC0000007)
        //case STATUS_INVALID_HANDLE                   ((NTSTATUS)0xC0000008)
        //case STATUS_BAD_INITIAL_STACK                ((NTSTATUS)0xC0000009)
        //case STATUS_BAD_INITIAL_PC                   ((NTSTATUS)0xC000000A)
        //case STATUS_INVALID_CID                      ((NTSTATUS)0xC000000B)
        //case STATUS_TIMER_NOT_CANCELED               ((NTSTATUS)0xC000000C)
        case STATUS_INVALID_PARAMETER : return SEC_E_INVALID_TOKEN;
        //case STATUS_NO_SUCH_DEVICE                   ((NTSTATUS)0xC000000E)
        //case STATUS_NO_SUCH_FILE                     ((NTSTATUS)0xC000000F)
        //case STATUS_INVALID_DEVICE_REQUEST           ((NTSTATUS)0xC0000010)
        //case STATUS_END_OF_FILE                      ((NTSTATUS)0xC0000011)
        default :
        {
            ERR("can't map NTSTATUS 0x%x to SECURITY_STATUS\n", st);
            return SEC_E_INTERNAL_ERROR;
        }
    }
}

