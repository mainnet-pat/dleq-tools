## DLEQ Tools

This package is a set of crypto tools to empower cross-chain atomic swaps.

It has routines to compute and verify Discrete logarithm equality proofs for points on Secp256k1 and Ed25519 elliptic curves as well as routines to compute and verify adaptor signatures.

Its primary goal is to expose these functions to JavaScript environment via WebAssembly produced by `wasm-pack`.

### Building

Project requies `wasm-pack` to build WebAssembly, install it with `cargo install wasm-pack`

To build the project, run `wasm-pack build --target nodejs --release ./ -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort`

If you have build issues on macOS, try to install LLVM via homebrew: `brew install llvm`, then build with `PATH=/opt/homebrew/opt/llvm/bin:$PATH wasm-pack build --target nodejs --release ./ -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort`

### Usage

See `SwapWorkflowTest` in `lib.rs`, it employs all exported routines from this package