//
// Created by rc on 12/12/18.
//

#ifndef SEAL_WRAPPER_BASE64_H
#define SEAL_WRAPPER_BASE64_H

#include <string>

std::string base64_encode(unsigned char const* , unsigned int len);
std::string base64_decode(std::string const& s);

#endif //SEAL_WRAPPER_BASE64_H
