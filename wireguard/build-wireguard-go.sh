#!/usr/bin/env bash

# This script is used to build wireguard-go libraries for all the platforms.

set -eu

function is_android_build {
    for arg in "$@"
    do
        case "$arg" in
            "--android")
                return 0
        esac
    done
    return 1
}

function is_docker_build {
    for arg in "$@"
    do
        case "$arg" in
            "--docker")
                return 0
        esac
    done
    return 1
}


function win_deduce_lib_executable_path {
    msbuild_path="$(which msbuild.exe)"
    msbuild_dir=$(dirname "$msbuild_path")
    find "$msbuild_dir/../../../../" -name "lib.exe" | \
        grep -i "hostx64/x64" | \
        head -n1
}

function win_gather_export_symbols {
   grep -Eo "\/\/export \w+" libwg.go libwg_windows.go | cut -d' ' -f2
}

function win_create_lib_file {
    echo "LIBRARY libwg" > exports.def
    echo "EXPORTS" >> exports.def

    for symbol in $(win_gather_export_symbols); do
        printf "\t%s\n" "$symbol" >> exports.def
    done

    lib_path="$(win_deduce_lib_executable_path)"
    "$lib_path" \
        "/def:exports.def" \
        "/out:libwg.lib" \
        "/machine:X64"

}

function build_windows {
    echo "Building wireguard-go for Windows"
    pushd libwg
        go build -v -o libwg.dll -buildmode c-shared
        win_create_lib_file

        target_dir=../../build/lib/x86_64-pc-windows-msvc/
        mkdir -p $target_dir
        mv libwg.dll libwg.lib $target_dir
    popd
}

function unix_target_triple {
    local platform="$(uname -s)"
    if [[ ("${platform}" == "Linux") ]]; then
        echo "x86_64-unknown-linux-gnu"
    elif [[ ("${platform}" == "Darwin") ]]; then
        local arch="$(uname -m)"
        if [[ ("${arch}" == "arm64") ]]; then
            arch="aarch64"
        fi
        echo "${arch}-apple-darwin"
    else
        echo "Can't deduce target dir for $platform"
        return 1
    fi
}


function build_unix {
    echo "Building wireguard-go for $1"
    pushd libwg
        target_triple_dir="../../build/lib/$(unix_target_triple)"
        mkdir -p $target_triple_dir
        go build -v -o $target_triple_dir/libwg.a -buildmode c-archive
    popd
}

function build_android {
    echo "Building for android"
    local docker_image_hash="f432cb779611284ce69aca59a90a8a601171d4c29728561ae32bd228b1699198"

    if is_docker_build $@; then
        docker run --rm \
            -v "$(pwd)/../":/workspace \
            --entrypoint "/workspace/wireguard/libwg/build-android.sh" \
            quay.io/mullvad/mullvad-android-app-build@sha256:$docker_image_hash
    else
        ./libwg/build-android.sh
    fi
}

function build_wireguard_go {
    if is_android_build $@; then
        build_android $@
        return
    fi

    local platform="$(uname -s)";
    case  "$platform" in
        Linux*|Darwin*) build_unix $platform;;
        MINGW*|MSYS_NT*) build_windows;;
    esac
}

# Ensure we are in the correct directory for the execution of this script
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $script_dir
build_wireguard_go $@
