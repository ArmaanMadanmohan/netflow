{
  description = "A Nix-based development environment for the 'flow' project.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        config.allowUnfree = true;
        overlays = [
          rust-overlay.overlays.default
        ];
      };
      rust-stable = pkgs.rust-bin.stable.latest.default;
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          rust-stable
          pkgs.rust-analyzer
          pkgs.cargo-watch
          pkgs.clippy
          pkgs.pkg-config
          pkgs.libpcap
        ];

        RUST_SRC_PATH = "${rust-stable}/lib/rustlib/src/rust/library";

        shellHook = ''
          # Initializes zoxide for bash
          if [ -n "$BASH_VERSION" ]; then
            eval "$(zoxide init bash)"
          fi
          # Initializes zoxide for fish
          if [ -n "$FISH_VERSION" ]; then
            eval "$(zoxide init fish)"
          fi
        '';

      };
    };
}
