#include "commands.h"
#include <CLI11.hpp>

int main(int argc, char **argv) {
    CLI::App app{"codesign"};

    std::string identity, identifier, entitlements;
    bool verify = false, remove = false, force = false;
    std::vector<std::string> files;
    auto sign = app.add_option("-s,--sign", identity, "Code signing identity");
    app.add_flag("--remove-signature", remove, "Remove existing signature");
    app.add_flag("-v", verify, "Verify existing signatures");
    app.add_option("-i,--identifier", identifier, "File identifier");
    app.add_flag("-f,--force", force, "Replace any existing signatures");
    app.add_option("--entitlements", entitlements, "Entitlements plist");
    app.add_option("files", files, "Files to sign");

    CLI11_PARSE(app, argc, argv);

    if (verify) {
        for (const auto &f : files) {
            if (!SigTool::Commands::verifySignature(f))
                return 1;
        }
    } else if (remove) {
        for (const auto &f : files) {
            SigTool::Commands::removeSignature(f);
        }
    } else {
        if (identity != std::string{"-"}) {
            throw std::runtime_error{
                    std::string{"Only ad-hoc identities supported, requested: '"} + identity + "'"};
        }

        SigTool::Commands::CodesignOptions options{
            .identifier = identifier,
            .entitlements = entitlements,
            .force = force,
        };

        for (const auto &f : files) {
            SigTool::Commands::codesign(options, f);
        }
    }

    return 0;
}
