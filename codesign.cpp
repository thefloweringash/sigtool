#include "commands.h"
#include <CLI11.hpp>

int main(int argc, char **argv) {
    CLI::App app{"codesign"};

    std::string identity, identifier, entitlements;
    bool force = false;
    std::vector<std::string> files;
    app.add_option("-s", identity, "Code signing identity")->required();
    app.add_option("-i,--identifier", identifier, "File identifier");
    app.add_flag("-f", force, "Replace any existing signatures");
    app.add_option("--entitlements", entitlements, "Entitlements plist");
    app.add_option("files", files, "Files to sign");

    CLI11_PARSE(app, argc, argv);

    if (identity != std::string{"-"}) {
        throw std::runtime_error{
                std::string{"Only ad-hoc identities supported, requested: '"} + identity + "'"};
    }

    Commands::CodesignOptions options{
            .identifier = identifier,
            .entitlements = entitlements,
            .force = force,
    };

    for (const auto &f : files) {
        Commands::codesign(options, f);
    }

    return 0;
}
