#ifndef OBL_STRING_H
#define OBL_STRING_H

#include "stddef.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int error_t;
error_t memset_s(void *s, size_t smax, int c, size_t n);

int consttime_memequal(const void *b1, const void *b2, size_t len);

#ifdef __cplusplus
}
#endif

#endif // OBL_STRING_H
