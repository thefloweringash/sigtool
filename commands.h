#ifndef SIGTOOL_COMMANDS_H
#define SIGTOOL_COMMANDS_H

struct Commands {
    static int checkRequiresSignature(const std::string &file);
    static int showArch(const std::string &file);
    static int showSize(const std::string& file, const std::string& identifier);
    static int inject(const std::string& file, const std::string& identifier);
    static int generate(const std::string& file, const std::string& identifier);
};

#endif // SIGTOOL_COMMANDS_H
