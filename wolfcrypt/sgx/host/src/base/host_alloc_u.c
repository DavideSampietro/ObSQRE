#include <stdlib.h>
#include <stdio.h>

void ocall_host_alloc(void **out, size_t s)
{
	*out = malloc(s);
}

void host_free(void *in)
{
	free(in);
}
