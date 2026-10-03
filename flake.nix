{
  description = "OpenBao Proxmox secrets-engine development tools";

  inputs.nixpkgs.url = "https://flakehub.com/f/DeterminateSystems/nixpkgs-weekly/0.1";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      eachSystem = nixpkgs.lib.genAttrs systems;
    in {
      devShells = eachSystem (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.mkShell {
            packages = with pkgs; [ go_1_27 govulncheck gitleaks markdownlint-cli2 openbao ];
          };
        });
      checks = eachSystem (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          formatting = pkgs.runCommand "go-formatting" { nativeBuildInputs = [ pkgs.go_1_27 ]; } ''
            test -z "$(gofmt -l ${self})"
            touch "$out"
          '';
        });
    };
}
