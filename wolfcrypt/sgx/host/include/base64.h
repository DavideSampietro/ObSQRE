#ifndef BASE64_H
#define BASE64_H

#include <vector>
#include <string>

void base64_enc(std::string &dst, unsigned char *src, int length);
int base64_dec(std::vector<unsigned char> &dst, std::string &src);

#endif
