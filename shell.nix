{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  nativeBuildInputs = [
    pkgs.cmake
    pkgs.pkgconfig
  ];

  buildInputs = [
    (pkgs.python3.withPackages (ps: [ ps.construct ]))
    pkgs.openssl
    pkgs.cli11

    # keep this line if you use bash
    pkgs.bashInteractive
  ];
}
