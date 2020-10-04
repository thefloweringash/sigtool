//
// Created by lorne on 10/4/20.
//

#include <cstring>
#include "macho.h"

MachO::MachO(const std::string &filename) {
    std::ifstream f;
    f.open(filename, std::ifstream::in | std::ifstream::binary);
    if (f.fail()) {
        throw std::runtime_error(std::string{"opening input file: "} + strerror(errno));
    }

    auto magic = Read::readBytes<uint32_t>(f);

    f.read(reinterpret_cast<char *>(&header), sizeof(header));

    for (int cmdIdx = 0; cmdIdx < header.nCommands; cmdIdx++) {
        off_t start = f.tellg();

        uint32_t type = ReadLE::readUInt32(f);
        uint32_t cmdSize = ReadLE::readUInt32(f);

        switch (type) {
            case LC_SEGMENT_64: {
                auto lcSegment = std::make_shared<Segment64LoadCommand>(type, cmdSize);
                f.read(reinterpret_cast<char *>(&lcSegment->data),
                       sizeof(Segment64LoadCommand::data));
                loadCommands.push_back(lcSegment);
                break;
            }

            case LC_CODE_SIGNATURE: {
                auto lcCodeSignature = std::make_shared<CodeSignatureLoadCommand>(type, cmdSize);
                f.read(reinterpret_cast<char *>(&lcCodeSignature->data),
                       sizeof(CodeSignatureLoadCommand::data));
                loadCommands.push_back(lcCodeSignature);
                break;
            }

            default:
                auto lc = std::make_shared<LoadCommand>(type, cmdSize);
                loadCommands.push_back(lc);
        }

        size_t actualRead = f.tellg() - start;

        // Laziness: allow partial reads by skpping ahead
        // TODO: demand complete parses and make this explode instead
        if (actualRead < cmdSize) {
            f.seekg(cmdSize - actualRead, std::ifstream::cur);
        }
    }
}

std::shared_ptr<Segment64LoadCommand> MachO::getSegment64LoadCommand(const std::string& name) {
    for (auto& lc : loadCommands) {
        if (lc->type != LC_SEGMENT_64) {
            continue;
        }

        std::shared_ptr<Segment64LoadCommand> segment64 =
                std::static_pointer_cast<Segment64LoadCommand>(lc);
        if (strncmp(segment64->data.segname, name.c_str(), sizeof(segment64->data.segname)) != 0) {
            continue;
        }

        return segment64;
    }
    return std::shared_ptr<Segment64LoadCommand>{};
}

std::shared_ptr<CodeSignatureLoadCommand> MachO::getCodeSignatureLoadCommand() {
    for (auto& lc : loadCommands) {
        if (lc->type != LC_CODE_SIGNATURE) {
            continue;
        }

        return std::static_pointer_cast<CodeSignatureLoadCommand>(lc);
    }
    return std::shared_ptr<CodeSignatureLoadCommand>{};
}
