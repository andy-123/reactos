#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <string.h>

/* samba lib/util/memory.h */
/**
 * Zero a structure given a pointer to the structure.
 */
#ifndef ZERO_STRUCTP
#ifdef __REACTOS__
#define ZERO_STRUCTP(x) do { \
	if ((x) != NULL) { \
		memset((char *)(x), 0, sizeof(*(x))); \
	} \
} while(0)
#else
#define ZERO_STRUCTP(x) do { \
	if ((x) != NULL) { \
		memset_s((char *)(x), sizeof(*(x)), 0, sizeof(*(x))); \
	} \
} while(0)
#endif
#endif

/**
 * Zero a structure.
 */
#ifndef ZERO_STRUCT
//orig #define ZERO_STRUCT(x) memset_s((char *)&(x), sizeof(x), 0, sizeof(x))
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))
#endif

#ifndef SAFE_FREE
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); (x)=NULL;} } while(0)
#endif

#endif
