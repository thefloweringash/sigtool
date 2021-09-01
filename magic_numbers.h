#ifndef SIGTOOL_MAGIC_NUMBERS_H
#define SIGTOOL_MAGIC_NUMBERS_H

namespace SigTool {

enum {
    CS_ADHOC = 0x00000002,
};

enum {
    CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0,
    CSMAGIC_CODEDIRECTORY = 0xfade0c02,
    CSMAGIC_REQUIREMENTS = 0xfade0c01,
    CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171,
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
    CSSLOT_ENTITLEMENTS = 5,
    CSSLOT_SIGNATURESLOT = 0x10000,
};
};

#endif
