#!/usr/bin/env bash

set +ex

# Check if jq is installed
if ! [ -x "$(command -v jq)" ]; then
    echo "jq is not installed. use brew install jq" >& 2
    exit 1
fi

if ! [ -x "$(command -v rustup)" ]; then
    echo "rustup is not installed. use brew install rustup && rustup toolchain install nightly && rustup default nightly && rustup target add wasm32-unknown-unknown --toolchain nightly" >& 2
    exit 1
fi

# Clean previous packages
if [ -d "pkg" ]; then
    rm -rf pkg
fi

npm i -g wasm-pack@0.13.0 wasm-pack-inline@0.1.1

# Build wasm
PATH=/opt/homebrew/opt/llvm/bin:$PATH wasm-pack build --out-dir pkg --target web --release ./ -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort

wasm-pack-inline ./pkg --dir ./pkg --name index
rm pkg/dleq_tools*

# Get the package name
PKG_NAME=$(jq -r .name pkg/package.json | sed 's/\-/_/g')

jq ".files += [\"README.md\"]" pkg/package.json \
    | jq ".files -= [\"dleq_tools_bg.wasm\"]" \
    | jq ".repository.url = \"https://github.com/mainnet-pat/dleq-tools\"" \
    | jq ".license = \"MIT\"" > pkg/temp.json

sed -i '' "s/dleq_tools\./index\./g" "pkg/temp.json"

mv pkg/temp.json pkg/package.json
