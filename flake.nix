{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    naersk.url = "github:nix-community/naersk";
  };

  outputs =
    {
      self,
      flake-utils,
      nixpkgs,
      naersk,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = (import nixpkgs) {
          inherit system;
        };

        naersk-lib = pkgs.callPackage naersk { };

        recorder = naersk-lib.buildPackage {
          pname = "recorder";
          src = ./.;

          buildInputs = with pkgs; [
            makeWrapper
            ffmpeg-headless
          ];

          postInstall = ''
            wrapProgram $out/bin/recorder \
              --set PATH ${pkgs.ffmpeg-headless}/bin:$PATH
          '';

          passthru = {
            dockerImage = pkgs.dockerTools.buildImage {
              name = "recorder";
              tag = "${recorder.version}";

              copyToRoot = [
                pkgs.cacert
              ];
              config = {
                Cmd = [ "${recorder}/bin/recorder" ];
                Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
              };
            };
          };
        };
      in
      {
        packages = {
          inherit recorder;
          default = recorder;
        };

        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            openssl
          ];

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          packages = with pkgs; [
            rust-analyzer
            sqlx-cli
            ffmpeg-headless
          ];
        };
      }
    );
}
