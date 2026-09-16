{
  # NOTE: sanity-reviewed for v1.3.0 (2026-09) but NOT built — no nix
  # binary on the authoring machine. `nix flake check` / `nix build`
  # before relying on it; cargoLock below makes dep bumps hash-free.
  description = "ultranix-mcp — Rust MCP server for Linux desktop automation (Wayland/Hyprland-first)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  # Linux-only outputs: pipewire/wayland/libxkbcommon/hyprland cannot
  # build on darwin, so eachDefaultSystem would publish broken attrs
  # (meta.platforms is already linux). Matches the AUR arch list.
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Native build requirements (mirrors docs/PACKAGING.md):
        #   pkg-config + pipewire — pipewire-sys resolves libpipewire-0.3
        #   clang/libclang — pipewire-sys binds via bindgen
        #   wayland / libxkbcommon — wayland-client + xkbcommon crates
        #   onnxruntime — ort's `download-binaries` fetch is unusable in the
        #     sandbox; ORT_STRATEGY=system + ORT_LIB_LOCATION point ort-sys
        #     at this build instead (docs/PACKAGING.md).
        onnxruntime = pkgs.onnxruntime;
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "ultranix-mcp";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;

          src = self;

          # cargoLock vendored straight from Cargo.lock — no fixed
          # cargoHash/vendorHash to go stale on dep bumps. No git
          # dependencies exist, so no outputHashes are needed. If a git
          # dep is ever added, it needs an entry in
          # `cargoLock.outputHashes` — see nixpkgs buildRustPackage docs.
          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = with pkgs; [
            pkg-config
            clang
          ];

          buildInputs = with pkgs; [
            pipewire
            wayland
            libxkbcommon
          ];

          # bindgen needs to locate libclang; ort-sys must not try to
          # download a prebuilt ONNX Runtime inside the offline build.
          env = {
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            ORT_STRATEGY = "system";
            ORT_LIB_LOCATION = "${onnxruntime}/lib";
          };

          # The live-session test suite needs a Wayland compositor and an
          # AT-SPI bus; hermetic tests still run under `cargo test` outside
          # the sandbox — doCheck is left off like most Rust nixpkgs builds.
          doCheck = false;

          meta = with pkgs.lib; {
            description = "Rust MCP server for Linux desktop automation — Wayland/Hyprland-first";
            homepage = "https://github.com/jxoesneon/ultranix-mcp";
            license = licenses.isc;
            mainProgram = "ultranix-mcp";
            platforms = platforms.linux;
          };
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.default ];
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
            # Session tools the providers shell out to (optional at
            # runtime — the whitelist resolves whatever is present).
            hyprland
            grim
            slurp
            wl-clipboard
            xclip
            xsel
            sway
            kdotool
            xdotool
            scrot
            wmctrl
          ];
        };

        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/ultranix-mcp";
        };
      });
}
