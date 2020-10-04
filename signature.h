#ifndef GENSIG_SIGNATURE_H
#define GENSIG_SIGNATURE_H

#include <iostream>
#include <vector>
#include <memory>
#include <arpa/inet.h>
#include <cmath>

enum {
    CS_ADHOC = 0x00000002,
};

enum {
    CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0,
    CSMAGIC_CODEDIRECTORY = 0xfade0c02,
    CSMAGIC_REQUIREMENTS = 0xfade0c01,
    CSMAGIC_BLOBWRAPPER = 0xfade0b01,
};

enum {
    CS_EXECSEG_MAIN_BINARY = 0x1,
};

enum {
    CS_HASHTYPE_SHA256 = 2,
};

enum CSSlot {
    CSSLOT_CODEDIRECTORY = 0,
    CSSLOT_REQUIREMENTS = 2,
    CSSLOT_SIGNATURESLOT = 0x10000,
};

const int constexpr sha256HashSize = 32;
struct Hash {
    union {
        char bytes[sha256HashSize];
        unsigned int words[sha256HashSize / sizeof(unsigned int)];
    };
};

struct Emittable {
    virtual void emit(std::ostream& os) = 0;
    virtual size_t length() = 0;
};

struct Blob : public Emittable {
    virtual CSSlot slotType() = 0;
};

struct SuperBlob : public Emittable {
    constexpr static const int headerSize = 3 * sizeof(uint32_t);

    std::vector<std::shared_ptr<Blob>> blobs;

    void emit(std::ostream &os) override;
    size_t length() override;
};

struct CodeDirectory : public Blob {
    struct data_t {
        uint32_t magic;
        uint32_t length;
        uint32_t version;
        uint32_t flags;
        uint32_t hashOffset;
        uint32_t identOffset;
        uint32_t nSpecialSlots;
        uint32_t nCodeSlots;
        uint32_t codeLimit;
        uint8_t hashSize;
        uint8_t hashType;
        uint8_t platform;
        uint8_t pageSize;
        uint32_t spare2;
        uint32_t scatterOffset;
        uint32_t teamOffset;
        uint32_t spare3;
        uint64_t codeLimit64;
        uint64_t execSegBase;
        uint64_t execSegLimit;
        uint64_t execSegFlags;
    } __attribute__((packed)) data {};


    CodeDirectory() noexcept;

    CSSlot slotType() override {
        return CSSLOT_CODEDIRECTORY;
    }
    size_t length() override;
    void emit(std::ostream& os) override;

    void setSpecialHash(int index, const Hash& value);
    void setPageSize(uint16_t pageSize);
    void setCodeLimit(uint64_t codeLimit);
    void addCodeHash(const Hash& value);

    std::string identifier;
    std::vector<Hash> codeHashes;
private:
    Hash specialHashes[5]{};
};

// Only empty requirements supported
struct Requirements : public Blob {
    CSSlot slotType() override {
        return CSSLOT_REQUIREMENTS;
    }

    void emit(std::ostream &os) override;
    size_t length() override;
};

// Only empty signatures supported
struct Signature : public Blob {
    CSSlot slotType() override {
        return CSSLOT_SIGNATURESLOT;
    }

    void emit(std::ostream &os) override;
    size_t length() override;
};

#endif //GENSIG_SIGNATURE_H
