#ifndef _SMBHELPER_H_
#define _SMBHELPER_H_

#include "stdbool.h"
#include "samba/lib/util/data_blob.h"
#include "samba/librpc/ndr/libndr.h"
#include "smbdefs.h"

/* types / functions from samba
 * for wich the samba file is not imported (yet).
 */

//FIXME
#define dump_data(a,b,c)
#define debug_ntlmssp_flags(a)
#define NDR_PRINT_DEBUG(a,b)
#define smb_panic printf


/* implemented in ndr_basic.c
 * don't know in wich header it is defined */
enum ndr_err_code ndr_pull_uint32(struct ndr_pull *ndr, int ndr_flags, uint32_t *v);

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

const char *nt_errstr_const(NTSTATUS nt_code);
char *nt_errstr(NTSTATUS nt_code);


/* bin/default/include/public/core/error.h */
NTSTATUS map_nt_error_from_unix_common(int unix_error);



/* samba:ntstatus.h */
#define NT_STATUS_HAVE_NO_MEMORY(x) do { \
	if (unlikely(!(x))) {		\
		return NT_STATUS_NO_MEMORY;\
	}\
} while (0)



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



/*samba: bin/default/lib/param/param_functions.h */
const char *lpcfg_workgroup(struct loadparm_context *);

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



/*?? not from samba - ??*/
/* samba: lib/util/time.h: */
//struct timeval_buf { char buf[128]; };
struct timeval timeval_current(void);
struct timeval timeval_add(const struct timeval *tv,
			   uint32_t secs, uint32_t usecs);
NTTIME timeval_to_nttime(const struct timeval *tv);

#endif
