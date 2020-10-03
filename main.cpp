#include <iostream>
#include <vector>
#include <memory>
#include <arpa/inet.h>
#include <cmath>

enum {
    CS_ADHOC = 0x00000002,

    CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0,
    CSMAGIC_CODEDIRECTORY = 0xfade0c02,
    CS_HASHTYPE_SHA256 = 2,

    CSSLOT_CODEDIRECTORY = 0,
};

const int constexpr hashSize = 32;

struct Hash {
    char data[hashSize];
};

struct Emittable {
    virtual void emit(std::ostream& os) = 0;
    virtual size_t length() = 0;

    static std::ostream& writeUInt32(std::ostream& os, uint32_t value) {
        return Emittable::writeBytes(os, ntohl(value));
    }

    static std::ostream& writeUInt64(std::ostream& os, uint64_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        return Emittable::writeBytes<uint64_t >(os, __bswap_constant_64(value));
#else
        return Emittable::writeBytes(os, value);
#endif
    }

    template<typename T> static std::ostream& writeBytes(std::ostream& os, T value) {
        return os.write(reinterpret_cast<const char *>(&value), sizeof(T));
    }
};

struct Blob : public Emittable {
    virtual uint32_t slotType() = 0;
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

    CodeDirectory() {
        data.magic = CSMAGIC_CODEDIRECTORY;
        data.version = 0x020400;
        data.flags = CS_ADHOC;
        data.hashSize = 32;
        data.hashType = CS_HASHTYPE_SHA256;
    }

    uint32_t slotType() override {
        return CSSLOT_CODEDIRECTORY;
    }

    size_t length() override {
        size_t length = 0;
        length += sizeof(data);
        length += identifier.length() + 1;
        length += sizeof(Hash::data) * (data.nSpecialSlots + data.nCodeSlots);
        return length;
    }

    void emit(std::ostream& os) override {
        // Layout variable length components
        off_t tail = sizeof(data);

        data.identOffset = tail;
        tail += identifier.length() + 1;

        data.hashOffset = tail + sizeof(Hash::data) * data.nSpecialSlots;
        tail += sizeof(Hash::data) * (data.nSpecialSlots + data.nCodeSlots);

        data.length = tail;
        data.nCodeSlots = codeHashes.size();

        // Stream all components
        Emittable::writeUInt32(os, data.magic);
        Emittable::writeUInt32(os, data.length);
        Emittable::writeUInt32(os, data.version);
        Emittable::writeUInt32(os, data.flags);
        Emittable::writeUInt32(os, data.hashOffset);
        Emittable::writeUInt32(os, data.identOffset);
        Emittable::writeUInt32(os, data.nSpecialSlots);
        Emittable::writeUInt32(os, data.nCodeSlots);
        Emittable::writeUInt32(os, data.codeLimit);
        Emittable::writeBytes<uint8_t>(os, data.hashSize);
        Emittable::writeBytes<uint8_t>(os, data.hashType);
        Emittable::writeBytes<uint8_t>(os, data.platform);
        Emittable::writeBytes<uint8_t>(os, data.pageSize);
        Emittable::writeUInt32(os, data.spare2);
        Emittable::writeUInt32(os, data.scatterOffset);
        Emittable::writeUInt32(os, data.teamOffset);
        Emittable::writeUInt32(os, data.spare3);
        Emittable::writeUInt64(os, data.codeLimit64);
        Emittable::writeUInt64(os, data.execSegBase);
        Emittable::writeUInt64(os, data.execSegLimit);
        Emittable::writeUInt64(os, data.execSegFlags);

        os.write(identifier.c_str(), identifier.length());
        os.put(0);

        if (data.nSpecialSlots > 0) {
            for (int specialIndex = (int) data.nSpecialSlots - 1; specialIndex >= 0; specialIndex--) {
                os.write(specialHashes[specialIndex].data, sizeof(Hash::data));
            }
        }
        for (const Hash& hash : codeHashes) {
            os.write(hash.data, sizeof(Hash::data));
        }
    }

    void setSpecialHash(int index, Hash& value) {
        // index is in the range of (-1 to -5), with -1 being the first, etc
        // for convenience, map that to a regular (0..4) array
        unsigned int storage = (unsigned int)index - 1;
        data.nSpecialSlots = std::max(data.nSpecialSlots, storage + 1);
        specialHashes[storage] = value;
    }

    void setPageSize(uint16_t pageSize) {
        data.pageSize = log2(pageSize);
    }

    std::string identifier;
    std::vector<Hash> codeHashes;

private:
    Hash specialHashes[5]{};
};


struct SuperBlob : public Emittable {
    void emit(std::ostream& os) override {
        Emittable::writeUInt32(os, CSMAGIC_EMBEDDED_SIGNATURE);
        Emittable::writeUInt32(os, length());
        Emittable::writeUInt32(os, blobs.size());

        size_t blobDataOffset =
                3 * sizeof(uint32_t) + // superblob header
                2 * sizeof(uint32_t) * blobs.size(); // blob index entry

        // blob index
        for (const auto& blob : blobs) {
            Emittable::writeUInt32(os, CSSLOT_CODEDIRECTORY);
            Emittable::writeUInt32(os, blobDataOffset);
            blobDataOffset += blob->length();
        }

        for (const auto& blob : blobs) {
            // blob data
            blob->emit(os);
        }
    }

    size_t length() override {
        size_t length = 12; // magic + length + count
        for (const auto& blob : blobs) {
            length += blob->length();
        }
        return length;
    }

    std::vector<std::shared_ptr<Emittable>> blobs;
};


int main() {
    SuperBlob sb {};

    auto codeDirectory = std::make_shared<CodeDirectory>();

    codeDirectory->identifier = "hello";
    codeDirectory->setPageSize(4096);

    Hash h1 = {1};
    Hash h2 = { 2};
    Hash h3 = { 3 };
    Hash h4 = { 4 };

    codeDirectory->setSpecialHash(1, h1);
    codeDirectory->setSpecialHash(3, h2);
    codeDirectory->codeHashes.push_back(h3);
    codeDirectory->codeHashes.push_back(h4);
    
    // codeDirectory->data.execSegFlags |= CS

    sb.blobs.push_back(codeDirectory);
    sb.emit(std::cout);

    return 0;
}
