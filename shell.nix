{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.cmake
    (pkgs.python3.withPackages (ps: [ ps.construct ]))
    pkgs.cryptopp

    # keep this line if you use bash
    pkgs.bashInteractive
  ];
}
