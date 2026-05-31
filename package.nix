# TODO: move this to nixpkgs
# This file aims to be a replacement for the nixpkgs derivation.

{
  lib,
  rustPlatform,
  fetchFromGitHub,
  buildPackages,
  stdenv,
  openssl,
  pkg-config,
  installShellFiles,
  installShellCompletions ? stdenv.buildPlatform.canExecute stdenv.hostPlatform,
  installManPages ? stdenv.buildPlatform.canExecute stdenv.hostPlatform,
  buildNoDefaultFeatures ? false,
  buildFeatures ? [ ],
}:

let
  version = "0.0.1";
  hash = "";
  cargoHash = "";
  hasNativeTlsFeature = builtins.elem "native-tls" buildFeatures;

in
rustPlatform.buildRustPackage {
  inherit cargoHash version buildNoDefaultFeatures;

  pname = "discover";

  src = fetchFromGitHub {
    inherit hash;
    owner = "pimalaya";
    repo = "pimconf";
    rev = "v${version}";
  };

  env = {
    # OpenSSL should not be provided by vendors, not even on Windows
    OPENSSL_NO_VENDOR = "1";
  };

  nativeBuildInputs = [
    pkg-config
    installShellFiles
  ];

  buildInputs = lib.optional hasNativeTlsFeature openssl;

  buildFeatures = [ "cli" ] ++ buildFeatures;

  doCheck = false;

  postInstall =
    let
      emulator = stdenv.hostPlatform.emulator buildPackages;
      exe = stdenv.hostPlatform.extensions.executable;
    in
    lib.optionalString (lib.hasInfix "wine" emulator) ''
      export WINEPREFIX="''${WINEPREFIX:-$(mktemp -d)}"
      mkdir -p $WINEPREFIX
    ''
    + ''
      mkdir -p $out/share/{completions,man}
      ${emulator} "$out"/bin/discover${exe} manuals "$out"/share/man
      ${emulator} "$out"/bin/discover${exe} completions -d "$out"/share/completions bash elvish fish powershell zsh
    ''
    + lib.optionalString installManPages ''
      installManPage "$out"/share/man/*
    ''
    + lib.optionalString installShellCompletions ''
      installShellCompletion --bash "$out"/share/completions/discover.bash
      installShellCompletion --fish "$out"/share/completions/discover.fish
      installShellCompletion --zsh "$out"/share/completions/_discover
    '';

  meta = rec {
    description = "Client library and CLI to discover PIM-related services, written in Rust";
    mainProgram = "discover";
    homepage = "https://github.com/pimalaya/pimconf";
    changelog = "${homepage}/blob/v${version}/CHANGELOG.md";
    license = with lib.licenses; [
      mit
      asl20
    ];
    maintainers = with lib.maintainers; [ soywod ];
  };
}
