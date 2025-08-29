{ pkgs ? import <nixpkgs> { } }:

let
  buildPkgs = pkgs.buildPackages;
  armToolchainCross = pkgs.pkgsCross.arm-embedded.buildPackages;

  gccArmEmbeddedOrig = buildPkgs.gcc-arm-embedded;
in
pkgs.mkShell {
  nativeBuildInputs = [
    buildPkgs.python313
    buildPkgs.tio
    buildPkgs.valgrind

    pkgs.pkgsCross.arm-embedded.buildPackages.gcc
  ];

  packages = [
    (buildPkgs.python313.withPackages (python-pkgs: [
      python-pkgs.tqdm
      python-pkgs.pyserial
      python-pkgs.pandas
      python-pkgs.matplotlib
      python-pkgs.jinja2
    ]))
  ];
}
