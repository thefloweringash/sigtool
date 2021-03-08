#include <cstring>
#include <iostream>
#include <string>
#include <openssl/asn1.h>

#include "der.h"

namespace {
    ASN1_TYPE *newType(int type, void *value) {
        ASN1_TYPE *t = ASN1_TYPE_new();
        ASN1_TYPE_set(t, type, value);
        return t;
    }

    ASN1_TYPE *newUtf8String(const std::string &str) {
        ASN1_UTF8STRING *s = ASN1_UTF8STRING_new();
        ASN1_STRING_set(s, str.c_str(), str.size());
        return newType(V_ASN1_UTF8STRING, s);
    }

    ASN1_TYPE *sequenceToType(ASN1_SEQUENCE_ANY *sequence) {
        unsigned char *der = nullptr;
        i2d_ASN1_SEQUENCE_ANY(sequence, &der);

        ASN1_STRING *s = ASN1_STRING_new();
        ASN1_STRING_set(s, der, -1);

        return newType(V_ASN1_SEQUENCE, s);
    }

    ASN1_TYPE *newBoolean(bool value) {
        return newType(V_ASN1_BOOLEAN, (void *) value);
    }
}


DERMap::DERMap() : map{sk_ASN1_TYPE_new_null()} {
}

void DERMap::addPair(ASN1_TYPE *key, ASN1_TYPE *value) {
    ASN1_SEQUENCE_ANY *pair = sk_ASN1_TYPE_new_null();

    sk_ASN1_TYPE_push(pair, key);
    sk_ASN1_TYPE_push(pair, value);

    sk_ASN1_TYPE_push(map.get(), sequenceToType(pair));
}


std::string DERMap::toDER() {
    char *der = nullptr;
    i2d_ASN1_SET_ANY(map.get(), (unsigned char **) &der);
    std::string str{der, strlen(der)};
    free(der);
    return str;
}

void DERMap::setBoolean(const std::string &key, bool value) {
    addPair(newUtf8String(key), newBoolean(value));
}
