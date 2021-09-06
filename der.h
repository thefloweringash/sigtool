#ifndef SIGTOOL_DER_HPP
#define SIGTOOL_DER_HPP

#include <memory>
#include <string>
#include <openssl/asn1.h>

struct DERMap {
    DERMap();

    void setBoolean(const std::string &key, bool value);

    std::string toDER();

private:
    void addPair(ASN1_TYPE *key, ASN1_TYPE *value);

    struct ASN1_SEQUENCE_ANY_Deleter {
        void operator()(ASN1_SEQUENCE_ANY *t) {
            sk_ASN1_TYPE_free(t);
        }
    };

    std::unique_ptr<ASN1_SEQUENCE_ANY, ASN1_SEQUENCE_ANY_Deleter> map;
};

#endif // SIGTOOL_DER_HPP