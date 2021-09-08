{ lib, stdenv, cmake, makeWrapper, openssl, static ? false }:

stdenv.mkDerivation {
  name = "sigtool";

  src = ./..;

  nativeBuildInputs = [ makeWrapper cmake ];
  buildInputs = [ openssl ];

  installFlags = [ "PREFIX=$(out)" ];

  cmakeFlags = lib.optionals static [
    "-DBUILD_SHARED_LIBS=OFF"
  ];

  postInstall = ''
    wrapProgram $out/bin/codesign \
      --set-default CODESIGN_ALLOCATE \
        "${stdenv.cc.bintools.bintools}/bin/${stdenv.cc.bintools.targetPrefix}codesign_allocate"
  '';
}
