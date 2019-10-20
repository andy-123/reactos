#include "smbincludes.h"
#include "samba/libcli/auth/ntlm_check.h"

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
NTSTATUS ndr_map_error2ntstatus(enum ndr_err_code ndr_err)
{
    printf("ndr_map_error2ntstatus\n");
    return 0;
}

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

char *nt_errstr(NTSTATUS nt_code)
{
    return "TODO nt_errstr";
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
    return true;//NEVER_MAP_TO_GUEST;
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
