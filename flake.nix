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

        apiv2Swagger = pkgs.fetchurl {
          url = "https://live.rbg.tum.de/api/v2/docs/apiv2.swagger.json";
          sha256 = "sha256-0TP61ZA6dWt204ciK4KG2M14aU6oK9sEntA7c5ZiKqY=";
        };

        recorder = naersk-lib.buildPackage {
          pname = "recorder";
          src = ./.;

          nativeBuildInputs = with pkgs; [
            sqlx-cli
            jq
            nodejs
            openapi-generator-cli
            tree
          ];

          buildInputs = with pkgs; [
            makeWrapper
            ffmpeg
          ];

          preBuild = ''
            set -e

            cp ${apiv2Swagger} ./apiv2.swagger.json

            jq '.paths |= with_entries(
                  .value |= with_entries(
                    .value |= (if has("operationId") then .operationId |= sub("^API_";"") else . end)

                  )
                )' apiv2.swagger.json > apiv2.clean.swagger.json

            openapi-generator-cli generate \
              -i ./apiv2.clean.swagger.json \
              -g rust \
              -o ./rbg_client \
              --additional-properties=avoidBoxedModels=true,snakeCaseOperationId=true
          '';

          postInstall = ''
            wrapProgram $out/bin/recorder \
              --set PATH ${pkgs.ffmpeg}/bin:$PATH
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
            ffmpeg
          ];
        };
      }
    );
}
