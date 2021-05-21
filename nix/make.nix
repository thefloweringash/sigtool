{ lib, stdenv, pkg-config, cmake, makeWrapper, openssl }:

stdenv.mkDerivation {
  name = "sigtool";

  src = ./..;

  nativeBuildInputs = [ pkg-config makeWrapper ];
  buildInputs = [ openssl ];

  installFlags = [ "PREFIX=$(out)" ];

  postInstall = ''
    wrapProgram $out/bin/codesign \
      --set-default CODESIGN_ALLOCATE \
        "${stdenv.cc.bintools.bintools}/bin/${stdenv.cc.bintools.targetPrefix}codesign_allocate"
  '';
}
