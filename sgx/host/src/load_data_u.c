#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

void ocall_get_file_size(void *fb, size_t *size)
{
	fseek((FILE*)fb, 0, SEEK_END);
	*size = ftell(fb);
}

void ocall_get_blob(void *fb, uint8_t *out, size_t len, size_t offset)
{
	if(offset != -1)
		fseek((FILE*)fb, offset, SEEK_SET);

	fread(out, sizeof(uint8_t), len, (FILE*)fb);
}
