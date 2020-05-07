// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#![deny(
    nonstandard_style,
    const_err,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    missing_copy_implementations
)]
// This one is hard to avoid.
#![allow(clippy::multiple_crate_versions)]

use cargo_toml::{Manifest, Value};
use serde::Deserialize;
use std::env;
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

const CONFIG_TABLE_NAME: &str = "config";
const MBED_CRYPTO_COMMIT_KEY: &str = "mbed-crypto-commit";

const SETUP_MBED_SCRIPT_PATH: &str = "./setup_mbed_crypto.sh";
const BUILD_CONFIG_FILE_PATH: &str = "./build-conf.toml";

const DEFAULT_NATIVE_MBED_COMPILER: &str = "clang";
const DEFAULT_NATIVE_MBED_ARCHIVER: &str = "ar";
const DEFAULT_ARM64_MBED_COMPILER: &str = "aarch64-linux-gnu-gcc";
const DEFAULT_ARM64_MBED_ARCHIVER: &str = "aarch64-linux-gnu-ar";

#[derive(Debug, Deserialize)]
struct Configuration {
    mbed_config: Option<MbedConfig>,
}

#[derive(Debug, Deserialize)]
struct MbedConfig {
    mbed_path: Option<String>,
    native: Option<Toolchain>,
    aarch64_unknown_linux_gnu: Option<Toolchain>,
}

#[derive(Debug, Deserialize)]
struct Toolchain {
    mbed_compiler: Option<String>,
    mbed_archiver: Option<String>,
}

fn get_configuration_string(parsec_config: &Value, key: &str) -> Result<String> {
    let config_value = get_value_from_table(parsec_config, key)?;
    match config_value {
        Value::String(string) => Ok(string.clone()),
        _ => Err(Error::new(
            ErrorKind::InvalidInput,
            "Configuration key missing",
        )),
    }
}

fn get_value_from_table<'a>(table: &'a Value, key: &str) -> Result<&'a Value> {
    match table {
        Value::Table(table) => table.get(key).ok_or_else(|| {
            println!("Config table does not contain configuration key: {}", key);
            Error::new(ErrorKind::InvalidInput, "Configuration key missing.")
        }),
        _ => Err(Error::new(
            ErrorKind::InvalidInput,
            "Value provided is not a TOML table",
        )),
    }
}

// Get the Mbed Crypto commit from Cargo.toml file. Use that and MbedConfig to pass
// parameters to the setup_mbed_crypto.sh script which clones and builds Mbed Crypto and create
// a static library.
fn setup_mbed_crypto(mbed_config: &MbedConfig, mbed_commit: &str) -> Result<()> {
    let (mbed_compiler, mbed_archiver) =
        if std::env::var("TARGET").unwrap() == "aarch64-unknown-linux-gnu" {
            let toolchain;
            toolchain = mbed_config
                .aarch64_unknown_linux_gnu
                .as_ref()
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "The aarch64_unknown_linux_gnu subtable of mbed_config should exist",
                    )
                })?;
            (
                toolchain
                    .mbed_compiler
                    .clone()
                    .unwrap_or_else(|| DEFAULT_ARM64_MBED_COMPILER.to_string()),
                toolchain
                    .mbed_archiver
                    .clone()
                    .unwrap_or_else(|| DEFAULT_ARM64_MBED_ARCHIVER.to_string()),
            )
        } else {
            let toolchain;
            toolchain = mbed_config.native.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "The native subtable of mbed_config should exist",
                )
            })?;
            (
                toolchain
                    .mbed_compiler
                    .clone()
                    .unwrap_or_else(|| DEFAULT_NATIVE_MBED_COMPILER.to_string()),
                toolchain
                    .mbed_archiver
                    .clone()
                    .unwrap_or_else(|| DEFAULT_NATIVE_MBED_ARCHIVER.to_string()),
            )
        };

    let script_fail = |_| {
        Err(Error::new(
            ErrorKind::Other,
            "setup_mbed_crypto.sh script failed",
        ))
    };

    println!("cargo:rerun-if-changed={}", SETUP_MBED_SCRIPT_PATH);
    println!("cargo:rerun-if-changed={}", "src/c/Makefile");
    println!("cargo:rerun-if-changed={}", "src/c/shim.c");
    println!("cargo:rerun-if-changed={}", "src/c/shim.h");

    if !::std::process::Command::new(SETUP_MBED_SCRIPT_PATH)
        .arg(mbed_commit)
        .arg(
            mbed_config
                .mbed_path
                .clone()
                .unwrap_or_else(|| env::var("OUT_DIR").unwrap()),
        )
        .arg(format!("CC={}", mbed_compiler))
        .arg(format!("AR={}", mbed_archiver))
        .status()
        .or_else(script_fail)?
        .success()
    {
        Err(Error::new(
            ErrorKind::Other,
            "setup_mbed_crypto.sh returned an error status.",
        ))
    } else {
        Ok(())
    }
}

fn generate_mbed_bindings(mbed_config: &MbedConfig) -> Result<()> {
    let mbed_include_dir = mbed_config
        .mbed_path
        .clone()
        .unwrap_or_else(|| env::var("OUT_DIR").unwrap())
        + "/mbedtls/include";
    let header = mbed_include_dir.clone() + "/psa/crypto.h";

    println!("cargo:rerun-if-changed={}", header);

    let shim_bindings = bindgen::Builder::default()
        .clang_arg(format!("-I{}", mbed_include_dir))
        .rustfmt_bindings(true)
        .header("src/c/shim.h")
        .generate_comments(false)
        .generate()
        .or_else(|_| {
            Err(Error::new(
                ErrorKind::Other,
                "Unable to generate bindings to mbed crypto",
            ))
        })?;
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    shim_bindings.write_to_file(out_path.join("shim_bindings.rs"))
}

// Get the compiler, the archiver and the location where to clone the Mbed Crypto repository.
fn parse_config_file() -> Result<Configuration> {
    let config_str = ::std::fs::read_to_string(Path::new(BUILD_CONFIG_FILE_PATH))?;
    Ok(toml::from_str(&config_str).or_else(|e| {
        println!("Error parsing build configuration file ({}).", e);
        Err(Error::new(
            ErrorKind::InvalidInput,
            "Could not parse build configuration file.",
        ))
    })?)
}

fn main() -> Result<()> {
    // Parsing build-conf.toml
    let config = parse_config_file()?;

    // Parsing Cargo.toml
    let toml_path = std::path::Path::new("./Cargo.toml");
    if !toml_path.exists() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Could not find Cargo.toml.",
        ));
    }
    let manifest = Manifest::from_path(&toml_path).or_else(|e| {
        println!("Error parsing Cargo.toml ({}).", e);
        Err(Error::new(
            ErrorKind::InvalidInput,
            "Could not parse Cargo.toml.",
        ))
    })?;

    let package = manifest.package.ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "Cargo.toml does not contain package information.",
        )
    })?;
    let metadata = package.metadata.ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "Cargo.toml does not contain package metadata.",
        )
    })?;
    let parsec_config = get_value_from_table(&metadata, CONFIG_TABLE_NAME)?;

    if true {
        let mbed_config = config.mbed_config.ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "Could not find mbed_config table in the config file.",
            )
        })?;

        let mbed_commit = get_configuration_string(&parsec_config, MBED_CRYPTO_COMMIT_KEY)?;

        setup_mbed_crypto(&mbed_config, &mbed_commit)?;
        generate_mbed_bindings(&mbed_config)?;

        // Request rustc to link the Mbed Crypto static library
        println!(
            "cargo:rustc-link-search=native={}/mbedtls/library/",
            mbed_config
                .mbed_path
                .unwrap_or_else(|| env::var("OUT_DIR").unwrap()),
        );
        println!("cargo:rustc-link-lib=static=mbedcrypto");

        // Also link shim library
        println!(
            "cargo:rustc-link-search=native={}",
            env::var("OUT_DIR").unwrap()
        );
        println!("cargo:rustc-link-lib=static=shim");
    }

    Ok(())
}
