#include <openssl/sha.h>

#include "hash.h"

namespace SigTool {

SHA256Hash::SHA256Hash(const char *data, size_t len)
  : SHA256Hash(reinterpret_cast<const unsigned char*>(data), len)
{}

SHA256Hash::SHA256Hash(const std::string& str)
  : SHA256Hash(str.data(), str.length())
{}

SHA256Hash::SHA256Hash(const unsigned char *data, size_t len) {
    SHA256(data, len, reinterpret_cast<unsigned char *>(&this->bytes[0]));
}
};
