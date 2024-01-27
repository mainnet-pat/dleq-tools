#!/usr/bin/env bash

set -e

# Check if jq is installed
if ! [ -x "$(command -v jq)" ]; then
    echo "jq is not installed" >& 2
    exit 1
fi

# Clean previous packages
if [ -d "pkg" ]; then
    rm -rf pkg
fi

if [ -d "pkg-node" ]; then
    rm -rf pkg-node
fi

# Build for both targets
PATH=/opt/homebrew/opt/llvm/bin:$PATH wasm-pack build --out-dir pkg --target web --release ./ -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort
PATH=/opt/homebrew/opt/llvm/bin:$PATH wasm-pack build --out-dir pkg-node --target nodejs --release ./ -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort

# Get the package name
PKG_NAME=$(jq -r .name pkg/package.json | sed 's/\-/_/g')

# Merge nodejs & browser packages
cp "pkg-node/${PKG_NAME}.js" "pkg/${PKG_NAME}_node.js"
cp "pkg-node/${PKG_NAME}_bg.wasm" "pkg/${PKG_NAME}_bg_node.wasm"
sed -i '' "s/${PKG_NAME}_bg.wasm/${PKG_NAME}_bg_node.wasm/g" "pkg/${PKG_NAME}_node.js"
jq ".files += [\"${PKG_NAME}_node.js\", \"${PKG_NAME}_bg_node.wasm\", \"README.md\"]" pkg/package.json \
    | jq ".main = \"${PKG_NAME}_node.js\"" > pkg/temp.json
mv pkg/temp.json pkg/package.json
rm -rf pkg-node
