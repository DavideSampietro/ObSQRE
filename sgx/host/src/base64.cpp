#include "base64.h"

#include <cstdint>

static const char *conversion_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const std::uint8_t inv_conversion_table[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0,
	0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0,
	0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };

void base64_enc(std::string &dst, unsigned char *src, int length)
{
	//int buf_size = (length/3 + (length % 3 == 0 ? 0 : 1)) * 4 + 1;
	//char *dst_local = new char[buf_size];

	int full_iters = length / 3;
	int last_iter = length % 3;
	int i;
	std::uint32_t buf;

	// allocate enough storage!!
	dst.reserve(full_iters*4 + last_iter + 1);

	for(i = 0; i < full_iters; i++)
	{
		buf = (src[3*i] << 24) | (src[3*i+1] << 16) | (src[3*i+2] << 8);

		dst.push_back(conversion_table[(buf >> 26) & 0x3F]);
		dst.push_back(conversion_table[(buf >> 20) & 0x3F]);
		dst.push_back(conversion_table[(buf >> 14) & 0x3F]);
		dst.push_back(conversion_table[(buf >> 8) & 0x3F]);
	}

	if(last_iter)
	{
		// pad with =
		dst.push_back('=');
		dst.push_back('=');
		dst.push_back('=');
		dst.push_back('=');

		buf = 0;
		for(int j = 0; j < last_iter; j++)
			buf |= src[3*i + j] << (8*(3-j));

		for(int j = 0; j <= last_iter; j++)
		{
			dst[4*i+j] = conversion_table[(buf & 0xFC000000) >> 26];
			buf <<= 6;
		}
	}
}

int base64_dec(std::vector<unsigned char> &dst, std::string &src)
{
	int length = src.length();

	int no_equals = 0;
	int no_bytes_3;
	int no_bytes_rem;
	int i, full_it;

	if(length % 4 != 0)
		return -1;

	for(int j = length-1; j >= 0 && src[j] == '='; j--)
		++no_equals;

	full_it = ((length - (no_equals ? 4 : 0)) / 4);
	no_bytes_3 = full_it * 3;
	no_bytes_rem = (3 - no_equals) % 3;

	dst.reserve(no_bytes_3 + no_bytes_rem);

	for(i = 0; i < full_it; i++)
	{
		std::uint32_t buf = 0;

		// cast to suppress annoying compiler warnings...
		buf = inv_conversion_table[(std::uint8_t)src[4*i]] << 18 | inv_conversion_table[(std::uint8_t)src[4*i+1]] << 12 |
			inv_conversion_table[(std::uint8_t)src[4*i+2]] << 6 | inv_conversion_table[(std::uint8_t)src[4*i+3]];

		dst[3*i] = buf >> 16;
		dst[3*i+1] = buf >> 8;
		dst[3*i+2] = buf;
	}

	if(no_bytes_rem)
	{
		std::uint32_t buf = 0;

		for(int j = 0; j < (4-no_equals); j++)
			buf |= inv_conversion_table[(std::uint8_t)src[4*i+j]] << (6*(3-j));

		for(int j = 0; j < no_bytes_rem; j++)
			dst[3*i+j] = (buf >> 8*(2-j));
	}

	return no_bytes_3 + no_bytes_rem;
}
