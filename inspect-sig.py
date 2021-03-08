#!/usr/bin/env python3

import sys
import math
import enum
from construct import *

# See
# https://opensource.apple.com/source/xnu/xnu-3248.20.55/bsd/sys/codesign.h


class CSFlags(enum.IntFlag):
    CS_VALID = 0x00000001  # dynamically valid
    CS_ADHOC = 0x00000002  # ad hoc signed
    CS_GET_TASK_ALLOW = 0x00000004  # has get-task-allow entitlement
    CS_INSTALLER = 0x00000008  # has installer entitlement

    CS_FORCED_LV = 0x00000010  # Library Validation required by Hardened System Policy
    # (macOS Only) Page invalidation allowed by task port policy
    CS_INVALID_ALLOWED = 0x00000020

    CS_HARD = 0x00000100  # don't load invalid pages
    CS_KILL = 0x00000200  # kill process if it becomes invalid
    CS_CHECK_EXPIRATION = 0x00000400  # force expiration checking
    CS_RESTRICT = 0x00000800  # tell dyld to treat restricted

    CS_ENFORCEMENT = 0x00001000  # require enforcement
    CS_REQUIRE_LV = 0x00002000  # require library validation
    # code signature permits restricted entitlements
    CS_ENTITLEMENTS_VALIDATED = 0x00004000
    # has com.apple.rootless.restricted-nvram-variables.heritable en titlement
    CS_NVRAM_UNRESTRICTED = 0x00008000

    CS_RUNTIME = 0x00010000  # Apply hardened runtime policies
    CS_LINKER_SIGNED = 0x00020000  # Automatically signed by the linker


cs_flags = FlagsEnum(Int32ub, CSFlags)


class CSExecSegFlags(enum.IntFlag):
    CS_EXECSEG_MAIN_BINARY = 0x1			# executable segment denotes main binary
    CS_EXECSEG_ALLOW_UNSIGNED = 0x10		# allow unsigned pages (for debugging)
    CS_EXECSEG_DEBUGGER = 0x20		# main binary is debugger
    CS_EXECSEG_JIT = 0x40		# JIT enabled
    CS_EXECSEG_SKIP_LV = 0x80		# OBSOLETE: skip library validation
    CS_EXECSEG_CAN_LOAD_CDHASH = 0x100		# can bless cdhash for execution
    CS_EXECSEG_CAN_EXEC_CDHASH = 0x200		# can execute blessed cdhash


cs_execseg_flags = FlagsEnum(Int64ub, CSExecSegFlags)


class CSMagic(enum.IntEnum):
    # From cs_blobs.h, which is under Apple's open source license
    CSMAGIC_REQUIREMENT = 0xfade0c00,               # single Requirement blob
    # Requirements vector (internal requirements)
    CSMAGIC_REQUIREMENTS = 0xfade0c01,
    CSMAGIC_CODEDIRECTORY = 0xfade0c02,             # CodeDirectory blob
    CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0,  # embedded form of signature data
    CSMAGIC_EMBEDDED_SIGNATURE_OLD = 0xfade0b02,    # XXX
    CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171,     # embedded entitlements
    # multi-arch collection of embedded signatures
    CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1,
    CSMAGIC_BLOBWRAPPER = 0xfade0b01,       # CMS Signature, among other things


cs_magic = Enum(Int32ub, CSMagic)


class CSHashType(enum.IntEnum):
    CS_HASHTYPE_SHA1 = 1,
    CS_HASHTYPE_SHA256 = 2,
    CS_HASHTYPE_SHA256_TRUNCATED = 3,
    CS_HASHTYPE_SHA384 = 4,


cs_hashtype = Enum(Int8ub, CSHashType)


class CSSlot(enum.IntEnum):
    # slot index for CodeDirectory
    CSSLOT_CODEDIRECTORY = 0,
    CSSLOT_INFOSLOT = 1,
    CSSLOT_REQUIREMENTS = 2,
    CSSLOT_RESOURCEDIR = 3,
    CSSLOT_APPLICATION = 4,
    CSSLOT_ENTITLEMENTS = 5,

    # first alternate CodeDirectory, if any
    CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000,
    # max number of alternate CD slots
    CSSLOT_ALTERNATE_CODEDIRECTORY_MAX = 5,
    # CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX, # one past the last
    CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT = 0x1000 + 5,

    CSSLOT_SIGNATURESLOT = 0x10000,                 # CMS Signature
    CSSLOT_IDENTIFICATIONSLOT = 0x10001,
    CSSLOT_TICKETSLOT = 0x10002,


csslot = Enum(Int32ub, CSSlot)

codeDirectory = Struct(
    "start" / Tell,

    "magic" / cs_magic,
    "length" / Int32ub,
    "version" / Hex(Int32ub),
    "flags" / cs_flags,
    "hashOffset" / Int32ub,
    "identOffset" / Int32ub,
    "nSpecialSlots" / Int32ub,
    "nCodeSlots" / Int32ub,
    "codeLimit" / Int32ub,
    "hashSize" / Int8ub,
    "hashType" / cs_hashtype,
    "platform" / Int8ub,
    "pageSize" / Hex(ExprAdapter(Int8ub, 1 << obj_,
                                 lambda x: math.log2(x))),
    "spare2" / Int32ub,

    "specialHashes" / Pointer(this.start + this.hashOffset - this.nSpecialSlots * this.hashSize,
                              Array(this.nSpecialSlots, Hex(Bytes(this.hashSize)))),

    "codeHashes" / Pointer(this.start + this.hashOffset,
                           Array(this.nCodeSlots, Hex(Bytes(this.hashSize)))),

    "identifier" / Pointer(this.start + this.identOffset,
                           CString("ascii")),

    StopIf(this.version < 0x20100),
    "scatterOffset" / Int32ub,
    StopIf(this.version < 0x020200),
    "teamOffset" / Int32ub,
    StopIf(this.version < 0x020300),
    "spare3" / Int32ub,
    "codeLimit64" / Int64ub,
    StopIf(this.version < 0x020400),
    "execSegBase" / Int64ub,
    "execSegLimit" / Int64ub,
    "execSegFlags" / cs_execseg_flags,
    StopIf(this.version < 0x020500),
    "runtime" / Int32ub,
    "preEncryptionOffset" / Int32ub,
    StopIf(this.version < 0x020600),
    "linkageHashType" / Int8ub,
    "linkageTruncated" / Int8ub,
    "spare4" / Int16ub,
    "linkageOffset" / Int32ub,
    "linkageSize" / Int32ub
)

codeSignature = Struct(
    "cs_magic" / cs_magic,
    "length" / Int32ub,
)

requirementsBlobIndex = Struct(
    "type" / Int32ub,
    "offset" / Int32ub,
)

requirements = Struct(
    "start" / Tell,
    "cs_magic" / cs_magic,
    "length" / Int32ub,
    "count" / Int32ub,
    "raw" / Pointer(this.start, Hex(Bytes(this.length))),
    "items" / Array(this.count, requirementsBlobIndex),
)

signature = Struct(
    "cs_magic" / cs_magic,
    "length" / Int32ub,
    StopIf(this.length == 8),
    "signature" / Hex(Bytes(this.length)),
)

blobIndex = Struct(
    "type" / csslot,
    "offset" / Int32ub,
    "blob" / Pointer(this._.pointer + this.offset, codeSignature),
    "parsed" / Pointer(this._.pointer + this.offset, Switch(this.type, {
        CSSlot.CSSLOT_CODEDIRECTORY.name: codeDirectory,
        CSSlot.CSSLOT_REQUIREMENTS.name: requirements,
        CSSlot.CSSLOT_SIGNATURESLOT.name: signature,
    }, default=Hex(Pointer(this._.pointer + this.offset + 8, Bytes(this.blob.length - 8)))))

)

superBlob = Struct(
    "pointer" / Tell,
    "magic" / cs_magic,
    "length" / Int32ub,
    "count" / Int32ub,
    "index" / Array(this.count, blobIndex)
)


def main(filename):
    print(superBlob.parse_file(filename))


if __name__ == "__main__":
    main(sys.argv[1])
