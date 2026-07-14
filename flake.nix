{
  description = "Rust development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        # Read the file relative to the flake's root
        overrides = (builtins.fromTOML (builtins.readFile (self + "/rust-toolchain.toml")));
        libPath = with pkgs; lib.makeLibraryPath [
          # load external libraries that you need in your rust project here
        ];
      in
      {
        devShells.default = pkgs.mkShell rec {
          name = "vector";
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = with pkgs; [
            clang
            llvmPackages.bintools
            rustup
            protobuf
            protoc-gen-rust
            cyrus_sasl
            krb5
            cargo-nextest
            openssl
            lldb
            cue
            gcc
            gawk
            nodejs
            python3
            flex
            gh
          ] ++ lib.optionals stdenv.isLinux [ mold ];
          hardeningDisable = [ "fortify" ];

          RUSTC_VERSION = overrides.toolchain.channel;

          # https://github.com/rust-lang/rust-bindgen#environment-variables
          LIBCLANG_PATH = pkgs.lib.makeLibraryPath [ pkgs.llvmPackages_latest.libclang.lib ];

          shellHook = ''
            export PATH=$PATH:''${CARGO_HOME:-~/.cargo}/bin
            #export PATH=$PATH:''${RUSTUP_HOME:-~/.rustup}/toolchains/$RUSTC_VERSION-x86_64-unknown-linux-gnu/bin/
            export OPENSSL_LIB_DIR=$(pkg-config --libs openssl | grep -Po '\-L[^ ]+' | sed -re 's/\-L//g')
            export OPENSSL_INCLUDE_DIR=$(pkg-config --cflags openssl | grep -Po '\-I[^ ]+' | sed -re 's/\-I//g')
            if [[ "${system}" == *"linux"* ]]; then
              export RUSTFLAGS='-C linker=clang -C link-arg=-fuse-ld=mold'
              # fallback '-C link-arg=-fuse-ld=lld'
            elif [[ "${system}" == *"darwin"* ]]; then
              export RUSTFLAGS='-C linker=clang -C link-arg=-fuse-ld=lld'
              # rdkafka-sys builds librdkafka.dylib which links vendored libsasl2.a (with GSSAPI).
              # On macOS, dylib links must resolve all symbols; the MIT Kerberos symbols
              # (_krb5_gss_register_acceptor_identity, _GSS_C_SEC_CONTEXT_SASL_SSF, etc.) are
              # not in Apple GSS.framework — they're only in MIT libgssapi_krb5. Point the
              # C linker at the nix krb5 dylibs so the intermediate dylib link succeeds.
              export LDFLAGS="-L${pkgs.krb5.lib}/lib -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -lkrb5support"
            fi
            rustup component add rust-analyzer
            unset DEVELOPER_DIR
          '';

          # Add precompiled library to rustc search path
          # RUSTFLAGS = ''-C linker=clang -C link-arg=-fuse-ld=mold'';

          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (buildInputs ++ nativeBuildInputs);
        };
      }
    );
}
