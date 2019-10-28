#include "smbincludes.h"
#include "samba/libcli/auth/ntlm_check.h"
#include "samba/lib/param/loadparm.h"
#include "samba/auth/credentials/credentials_internal.h"

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

const char *lpcfg_workgroup(struct loadparm_context * x)
{
    D_WARNING("FIXME\n");
    return "WORKGROUP";
}

const char *lpcfg_netbios_name(struct loadparm_context *x)
{
    D_WARNING("FIXME\n");
    return "WORKGROUP";
}

const char *lpcfg_dnsdomain(struct loadparm_context *x)
{
    D_WARNING("FIXME\n");
    return "WORKGROUP";
}

const int lpcfg_map_to_guest(struct loadparm_context *x)
{
    D_WARNING("FIXME\n");
    return 0;//NEVER_MAP_TO_GUEST;
}

const bool lpcfg_lanman_auth(struct loadparm_context *x)
{
    D_WARNING("FIXME\n");
    return true;//NEVER_MAP_TO_GUEST;
}

const enum ntlm_auth_level lpcfg_ntlm_auth(struct loadparm_context *x)
{
    D_WARNING("FIXME\n");
    return NTLM_AUTH_ON;
}

const bool lpcfg_client_ntlmv2_auth(struct loadparm_context *x)
{
    D_WARNING("FIXME\n");
    return false;//NEVER_MAP_TO_GUEST;
}

const bool lpcfg_client_lanman_auth(struct loadparm_context *x)
{
    D_WARNING("FIXME\n");
    return true;//NEVER_MAP_TO_GUEST;
}

/* advapi */
/*void WINAPI MD5Init(MD5_CTX *ctx)
{
    D_WARNING("FIXME\n");
}

void WINAPI MD5Update(MD5_CTX *ctx, const unsigned char *buf, unsigned int len)
{
    D_WARNING("FIXME\n");
}*/

void WINAPI MD5FinalSMB(uint8_t digest[MD5_DIGEST_LENGTH], MD5_CTX *context)
{
    MD5Final(context);
    memcpy(digest, context->digest, MD5_DIGEST_LENGTH);
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
    D_WARNING("FIXME\n");
    return NULL;
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
			      const char *unix_username,
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

struct gensec_settings* gs = NULL;

struct gensec_settings* smbGetGensecSettigs()
{
    if (gs == NULL)
    {
        gs = talloc_zero(NULL, struct gensec_settings);
        gs->lp_ctx = talloc_zero(NULL, struct loadparm_context);

        gs->target_hostname = "targethost";
        gs->backends = NULL;
        gs->server_dns_domain = NULL;
        gs->server_dns_name = NULL;
        gs->server_netbios_domain = NULL;
        gs->server_netbios_name = NULL;
    }

    return gs;
}

void NtlmInitializeSamba()
{
    gs = NULL;
}

void NtlmFinalizeSamba()
{
    if (gs)
    {
        talloc_free(gs->lp_ctx);
        talloc_free(gs);
        gs = NULL;
    }
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
char *talloc_ExtWStrDup(const void *t, PEXT_STRING_W str)
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

