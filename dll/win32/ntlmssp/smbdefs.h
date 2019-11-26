#ifndef _SMBDEFS_H_
#define _SMBDEFS_H_

#define USE_SAMBA
#define DEBUG_PASSWORD 1

/* general types - needed to compile samba with RosBE */
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#define _PUBLIC_
#define _PRIVATE_
#define unlikely(x) (x)
#define memset_s(a,x_not_used,c,d) memset(a,c,d)
#define FALL_THROUGH

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#ifdef _MSC_VER
#ifdef bool
#undef bool
#endif
typedef int bool;
#endif

/* todo __FUNC__ is obsolete ... remove it !*/
#ifdef _MSC_VER
#define __FUNC__ __FUNCTION__
#define __func__ __FUNCTION__
#else
#define __FUNC__ __func__
#endif

/* defined in stdlib.h ... needs some other defines like _USE_GNU and someting else .. */
typedef int (*__compar_fn_t) (const void *, const void *);
typedef __compar_fn_t comparison_fn_t;

/* we need a unsinged int to pass -1, this is done at some places */
typedef int ssize_t;

/* solves linking error ... not found in lib ... */
int __strnlen(const char *s, size_t n);

/* this cames from port.h */
typedef int pid_t;

/* samba: lib/util/time.h: */
typedef struct TIMEVAL { uint64_t x; } timeval;
typedef uint64_t NTTIME;

#endif

