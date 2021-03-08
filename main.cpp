#include <cstring>
#include <iostream>
#include <memory>
#include "commands.h"

#include <CLI11.hpp>

int main(int argc, char **argv) {
    CLI::App app{"sigtool"};
    app.require_subcommand();

    std::string file, identifier;
    app.add_option("-f,--file", file, "Mach-O target file")
            ->required();
    app.add_option("-i,--identifier", identifier, "File identifier");

    app.add_subcommand("check-requires-signature",
                       "Determine if this is a macho file that must be signed");

    app.add_subcommand("size", "Determine size of embedded signature");
    app.add_subcommand("generate", "Generate an embedded signature and emit on stdout");
    app.add_subcommand("inject", "Generate and inject embedded signature");
    app.add_subcommand("show-arch", "Show architecture");

    app.require_subcommand();

    CLI11_PARSE(app, argc, argv);

    if (app.got_subcommand("check-requires-signature")) {
        return Commands::checkRequiresSignature(file);
    }
    else if (app.got_subcommand("show-arch")) {
        return Commands::showArch(file);
    }
    else if (app.got_subcommand("size")) {
        return Commands::showSize(file, identifier);
    }
    else if (app.got_subcommand("generate")) {
        return Commands::generate(file, identifier);
    }
    else if (app.got_subcommand("inject")) {
        return Commands::inject(file, identifier);
    }

    return 0;
}
