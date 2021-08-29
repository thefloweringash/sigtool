#ifndef SIGTOOL_COMMANDS_H
#define SIGTOOL_COMMANDS_H

#include <string>

namespace Commands {
    struct SignOptions {
        std::string filename;
        std::string identifier;
        std::string entitlements;
    };

    struct CodesignOptions {
        std::string identifier;
        std::string entitlements;
        bool force;
    };

    int checkRequiresSignature(const std::string &file);
    int showArch(const std::string &file);
    int showSize(const SignOptions& options);
    int inject(const SignOptions& options);
    int generate(const SignOptions& options);
    int codesign(const CodesignOptions& options, const std::string& file);
};

#endif // SIGTOOL_COMMANDS_H
