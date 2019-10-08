#include "smbincludes.h"

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

const char *lpcfg_netbios_name(struct loadparam_context *x)
{
    D_WARNING("FIXME\n");
    return "WORKGROUP";
}

const char *lpcfg_dnsdomain(struct loadparam_context *x)
{
    D_WARNING("FIXME\n");
    return "WORKGROUP";
}
