{ pkgs ? import <nixpkgs> {} }:

let
  makeWith = { localSystem, crossSystem ? localSystem }:
    (import pkgs.path { inherit localSystem crossSystem; }).callPackage ./nix/make.nix {};
in
rec {
  native-cmake = pkgs.callPackage ./nix/cmake.nix {};
  native-cmake-static = native-cmake.override { static = true; };

  # This is used to build bootstrap tools.
  x86_64-darwin-native = makeWith { localSystem = "x86_64-darwin"; };

  # This is included in bootstrap tools.
  aarch64-darwin-cross  = makeWith { localSystem = "x86_64-darwin"; crossSystem = "aarch64-darwin"; };

  # This is built as part of stdenv.
  aarch64-darwin-native  = makeWith { localSystem = "aarch64-darwin"; };

  linux-native  = makeWith { localSystem = "aarch64-linux"; };
  linux-cross   = makeWith { localSystem = "x86_64-linux";  crossSystem = "aarch64-linux"; };
}
