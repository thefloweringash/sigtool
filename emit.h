//
// Created by lorne on 10/4/20.
//

#ifndef GENSIG_EMIT_H
#define GENSIG_EMIT_H


#include <iostream>
#include <vector>
#include <memory>
#include <arpa/inet.h>
#include <cmath>

static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);

class Emit {

public:
    template<typename T> static std::ostream& writeBytes(std::ostream& os, T value) {
        return os.write(reinterpret_cast<const char *>(&value), sizeof(T));
    }
};

class EmitBE : public Emit {
public:
    static std::ostream& writeUInt32(std::ostream& os, uint32_t value) {
        return EmitBE::writeBytes(os, htonl(value));
    }

    static std::ostream& writeUInt64(std::ostream& os, uint64_t value) {
        return EmitBE::writeBytes<uint64_t >(os, __bswap_constant_64(value));
    }
};

class Read {
public:
    template<typename T>
    static T readBytes(std::istream &is) {
        T value{};
        is.read(reinterpret_cast<char *>(&value), sizeof(value));
        return value;
    }
};

class ReadBE : public Read {
public:
    static uint32_t readUInt32(std::istream& is) {
        return ntohl(Read::readBytes<uint32_t>(is));
    }
};

class ReadLE : public Read {
public:
    static uint32_t readUInt32(std::istream& is) {
        return Read::readBytes<uint32_t>(is);
    }
};


#endif //GENSIG_EMIT_H
