{
  description = "Description for the project";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    devshell.url = "github:numtide/devshell";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.devshell.flakeModule
      ];
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      perSystem =
        { pkgs, ... }:
        {
          devshells.default = {
            env = [ ];
            commands = [
              {
                help = "Wrapped snowcli to get the latest version";
                name = "snow";
                command = "uvx --from snowflake-cli snow $@";
              }
            ];
            packages = [
              pkgs.grype
              pkgs.dive
            ];
          };
        };
    };
}
