#include <algorithm>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <sstream>
#include <sys/stat.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "commands.h"
#include "macho.h"
#include "signature.h"
#include "der.h"

extern char **environ;

constexpr const unsigned int pageSize = 4096;

static std::string readFile(const std::string &filename) {
    std::ifstream in{filename, std::ifstream::in | std::ifstream::binary};
    if (!in.is_open()) {
        throw std::runtime_error{"Failed opening file for read: '"
                                 + filename + "' :" + strerror(errno)};
    }

    std::string str;

    in.seekg(0, std::ifstream::end);
    str.resize(in.tellg());
    in.seekg(0, std::ifstream::beg);
    in.read(&str[0], str.size());

    return str;
}

static Hash hashBlob(const std::shared_ptr<Blob> &blob) {
    std::basic_ostringstream<char> buf;
    blob->emit(buf);
    return Hash{buf.str()};
}

std::string cpuTypeName(uint32_t cpuType) {
    switch (cpuType) {
        case CPUTYPE_X86_64:
            return "x86_64";
        case CPUTYPE_ARM64:
            return "arm64";
        default:
            throw std::runtime_error{std::string{"Unsupported cpu type"} + std::to_string(cpuType)};
    }
}

int Commands::checkRequiresSignature(const std::string &file) {
    try {
        MachOList test{file};
        bool anyRequires = std::any_of(test.machos.begin(), test.machos.end(), [](const std::shared_ptr<MachO> &h) {
            return h->requiresSignature();
        });
        return anyRequires ? 0 : 1;
    } catch (NotAMachOFileException &e) {
        // A shell script or text file, for example, does not require a signature.
        return 1;
    }
}

int Commands::showArch(const std::string &file) {
    MachOList test{file};

    for (const auto &macho : test.machos) {
        std::cout << cpuTypeName(macho->header.cpuType) << std::endl;
    }

    return 0;
}

static SuperBlob signMachO(
        const Commands::SignOptions &options,
        const std::shared_ptr<MachO> &target
) {
    SuperBlob sb{};

    // blob 1: code directory
    auto codeDirectory = std::make_shared<CodeDirectory>();

    codeDirectory->identifier = options.identifier.empty() ? options.filename : options.identifier;
    codeDirectory->setPageSize(pageSize);

    // TOOD: is this sane?
    if (target->header.filetype == MH_EXECUTE) {
        codeDirectory->data.execSegFlags |= CS_EXECSEG_MAIN_BINARY;
    }

    auto textSegment = target->getSegment64LoadCommand("__TEXT");
    if (textSegment) {
        codeDirectory->data.execSegBase = textSegment->data.fileoff;
        codeDirectory->data.execSegLimit = textSegment->data.fileoff + textSegment->data.filesize;
    }

    size_t limit = target->size;

    auto codeSignature = target->getCodeSignatureLoadCommand();
    if (codeSignature) {
        limit = codeSignature->data.dataOff;
        codeDirectory->setCodeLimit(codeSignature->data.dataOff);
    }

    std::ifstream machoFileRaw;
    machoFileRaw.open(options.filename, std::ifstream::in | std::ifstream::binary);
    machoFileRaw.seekg(target->offset);

    if (machoFileRaw.fail()) {
        throw std::runtime_error(std::string{"opening macho file: "} + strerror(errno));
    }

    unsigned int totalPages = (limit + (pageSize - 1)) / pageSize;

    for (int page = 0; page < totalPages; page++) {
        char pageBytes[pageSize];

        off_t thisPageStart = page * pageSize;
        size_t thisPageSize = pageSize;

        if (thisPageStart + thisPageSize > limit) {
            thisPageSize = limit - thisPageStart;
        }

        machoFileRaw.read(&pageBytes[0], thisPageSize);
        if (machoFileRaw.fail()) {
            throw std::runtime_error(std::string{"reading page: "}
                                     + std::to_string(page) + " " + strerror(errno) + " expcted_bytes="
                                     + std::to_string(thisPageSize) + " actual_bytes" +
                                     std::to_string(machoFileRaw.gcount()));
        }

        Hash pageHash{&pageBytes[0], thisPageSize};
        codeDirectory->addCodeHash(pageHash);
    }

    machoFileRaw.close();

    sb.blobs.push_back(codeDirectory);

    // blob 2: requirements index with 0 entries
    auto requirements = std::make_shared<Requirements>();
    codeDirectory->setSpecialHash(requirements->slotType(), hashBlob(requirements));
    sb.blobs.push_back(requirements);

    // optional blob: entitlements
    if (!options.entitlements.empty()) {
        auto entitlements = std::make_shared<Entitlements>(readFile(options.entitlements));
        codeDirectory->setSpecialHash(entitlements->slotType(), hashBlob(entitlements));
        sb.blobs.push_back(entitlements);

        // TODO: BER formatted entitlements
        /*
        DERMap m{};
        m.setBoolean("com.apple.security.hypervisor", true);
        auto entitlementsDer = std::make_shared<EntitlementsDER>(m.toDER());
        codeDirectory->setSpecialHash(entitlementsDer->slotType(), hashBlob(entitlementsDer));
        sb.blobs.push_back(entitlementsDer);
        */
    }

    // blob: empty signature slot
    sb.blobs.emplace_back(std::make_shared<Signature>());

    return sb;
}


int Commands::showSize(const SignOptions &options) {
    MachOList list{options.filename};
    for (const auto &macho : list.machos) {
        auto sb = signMachO(options, macho);
        std::cout << cpuTypeName(macho->header.cpuType) << " " << sb.length() << std::endl;
    }

    return 0;
}

int Commands::generate(const SignOptions &options) {
    MachOList list{options.filename};
    for (const auto &macho : list.machos) {
        auto sb = signMachO(options, macho);
        // TODO: packing them all together is not helpful, but this is still usable
        // for the thin case.
        sb.emit(std::cout);
    }

    return 0;
}

int Commands::inject(const SignOptions &options) {
    MachOList list{options.filename};
    for (const auto &macho : list.machos) {
        auto sb = signMachO(options, macho);

        auto codeSignature = macho->getCodeSignatureLoadCommand();

        if (!codeSignature) {
            throw std::runtime_error{"cannot inject signature without appropriate load command"};
        }

        if (sb.length() > codeSignature->data.dataSize) {
            throw std::runtime_error{
                    std::string{"allocated size too small: need "}
                    + std::to_string(sb.length())
                    + std::string{"but have "}
                    + std::to_string(codeSignature->data.dataSize)
            };
        }

        std::ofstream machoFileWrite;
        machoFileWrite.open(options.filename, std::ofstream::in | std::ofstream::out | std::ofstream::binary);
        if (machoFileWrite.fail()) {
            throw std::runtime_error(std::string{"opening macho file: "} + strerror(errno));
        }

        machoFileWrite.seekp(macho->offset + codeSignature->data.dataOff);
        sb.emit(machoFileWrite);
        machoFileWrite.close();
    }

    return 0;
}

static char **toSpawnArgs(const std::vector<std::string> &args) {
    char **spawnArgs = reinterpret_cast<char **>(
            calloc(args.size() + 1, sizeof(char *)));
    for (int i = 0; i < args.size(); i++) {
        spawnArgs[i] = strdup(args[i].c_str());
    }
    spawnArgs[args.size()] = nullptr;
    return spawnArgs;
}

static void freeArgs(char **spawnArgs, std::vector<std::string>::size_type size) {
    for (int i = 0; i < size; i++) {
        free(spawnArgs[i]);
    }
    free(spawnArgs);
}

int Commands::codesign(const CodesignOptions &options, const std::string &filename) {
    std::string identifier = options.identifier;
    if (identifier.empty()) {
        identifier = std::filesystem::path(filename).filename();
    }
    // Parse and discovery arguments
    MachOList list{filename};
    std::vector<std::string> arguments;

    arguments.emplace_back("codesign_allocate");
    arguments.emplace_back("-i");
    arguments.emplace_back(filename);


    for (const auto &macho : list.machos) {
        auto codeSignature = macho->getCodeSignatureLoadCommand();
        if (!options.force && codeSignature) {
            throw std::runtime_error{"file is already signed. pass -f to sign regardless."};
        }
        auto sb = signMachO(SignOptions{
                .filename = filename,
                .identifier = identifier,
                .entitlements = options.entitlements,
        }, macho);

        arguments.emplace_back("-a");
        arguments.push_back(cpuTypeName(macho->header.cpuType));

        size_t len = sb.length();
        len = ((len + 0xf) & ~0xf) + 1024; // align and pad
        arguments.push_back(std::to_string(len));
    }

    // Make temporary name
    char *tempfileName = strdup((filename + "XXXXXX").c_str());
    int tempfile = mkstemp(tempfileName);

    // Preserve mode
    struct stat sourceFileStat{};
    if (stat(filename.c_str(), &sourceFileStat) != 0) {
        throw std::runtime_error{std::string{"stat of "} + filename + " failed: " + strerror(errno)};
    }

    if (fchmod(tempfile, sourceFileStat.st_mode) != 0) {
        throw std::runtime_error{"chmod temporary file"};
    }

    std::string tempfileFdPath = std::string{"/dev/fd/"} + std::to_string(tempfile);
    arguments.emplace_back("-o");
    arguments.emplace_back(tempfileFdPath);

    // codesign_allocate
    pid_t pid;
    char **spawnArgs = toSpawnArgs(arguments);

    const char *codesign_allocate = getenv("CODESIGN_ALLOCATE");
    if (!codesign_allocate) {
        codesign_allocate = "codesign_allocate";
    }

    int spawn_result;
    if ((spawn_result = posix_spawnp(&pid, codesign_allocate, nullptr, nullptr, spawnArgs, environ)) != 0) {
        throw std::runtime_error{std::string{"Failed to spawn codesign_allocate: "} + strerror(spawn_result)};
    };

    int codesign_status;
    if (waitpid(pid, &codesign_status, 0) <= 0) {
        throw std::runtime_error{
                std::string{"codesign waitpid failed: "} + strerror(errno)
        };
    }
    freeArgs(spawnArgs, arguments.size());

    if (!WIFEXITED(codesign_status) || WEXITSTATUS(codesign_status) != 0) {
        throw std::runtime_error{std::string{"codesign_failed: "} + std::to_string(WEXITSTATUS(codesign_status))};
    }

    if (close(tempfile) != 0) {
        throw std::runtime_error{std::string{"close: "} + strerror(tempfile)};
    }

    // inject
    Commands::inject(SignOptions{
            .filename = tempfileName,
            .identifier = identifier,
            .entitlements = options.entitlements,
    });

    // rename temp file to output
    if (rename(tempfileName, filename.c_str()) != 0) {
        throw std::runtime_error{"rename failed"};
    }

    return 0;
}
