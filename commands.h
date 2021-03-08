#ifndef SIGTOOL_COMMANDS_H
#define SIGTOOL_COMMANDS_H

namespace Commands {
    struct SignOptions {
        std::string filename;
        std::string identifier;
        std::string entitlements;
    };

    int checkRequiresSignature(const std::string &file);
    int showArch(const std::string &file);
    int showSize(const SignOptions& options);
    int inject(const SignOptions& options);
    int generate(const SignOptions& options);
};

#endif // SIGTOOL_COMMANDS_H
