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
use cmake::Config;
use std::env;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;

fn compile_mbed_crypto() -> Result<PathBuf> {
    let mbedtls_dir = String::from("./vendor");
    println!("cargo:rerun-if-changed=src/c/shim.c");
    println!("cargo:rerun-if-changed=src/c/shim.h");

    let out_dir = env::var("OUT_DIR").unwrap();

    // Configure the MbedTLS build for making Mbed Crypto
    if !::std::process::Command::new(mbedtls_dir + "/scripts/config.py")
        .arg("--write")
        .arg(&(out_dir.clone() + "/config.h"))
        .arg("crypto")
        .status()
        .or_else(|_| Err(Error::new(ErrorKind::Other, "configuring mbedtls failed")))?
        .success()
    {
        return Err(Error::new(
            ErrorKind::Other,
            "config.py returned an error status",
        ));
    }

    // Build the MbedTLS libraries
    let mbed_build_path = Config::new("vendor")
        .cflag(format!("-I{}", out_dir))
        .cflag("-DMBEDTLS_CONFIG_FILE='<config.h>'")
        .build();

    Ok(mbed_build_path)
}

fn generate_mbed_crypto_bindings(mbed_include_dir: String) -> Result<()> {
    let header = mbed_include_dir.clone() + "/psa/crypto.h";

    println!("cargo:rerun-if-changed={}", header);

    let shim_bindings = bindgen::Builder::default()
        .clang_arg(format!("-I{}", mbed_include_dir))
        .rustfmt_bindings(true)
        .header("src/c/shim.h")
        .blacklist_type("max_align_t")
        .generate_comments(false)
        .size_t_is_usize(true)
        .generate()
        .or_else(|_| {
            Err(Error::new(
                ErrorKind::Other,
                "Unable to generate bindings to mbed crypto",
            ))
        })?;
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    shim_bindings.write_to_file(out_path.join("shim_bindings.rs"))?;

    Ok(())
}

fn compile_shim_library(include_dir: String) -> Result<()> {
    // Compile and package the shim library
    cc::Build::new()
        .include(include_dir)
        .file("./src/c/shim.c")
        .warnings(true)
        .flag("-Werror")
        .opt_level(2)
        .try_compile("libshim.a")
        .or_else(|_| Err(Error::new(ErrorKind::Other, "compiling shim.c failed")))?;

    // Also link shim library
    println!(
        "cargo:rustc-link-search=native={}",
        env::var("OUT_DIR").unwrap()
    );
    println!("cargo:rustc-link-lib=static=shim");

    Ok(())
}

fn link_to_lib(lib_path: String, link_statically: bool) {
    let link_type = if link_statically { "static" } else { "dylib" };

    // Request rustc to link the Mbed Crypto library
    println!("cargo:rustc-link-search=native={}", lib_path,);
    println!("cargo:rustc-link-lib={}=mbedcrypto", link_type);
}

fn main() -> Result<()> {
    if cfg!(feature = "operations") {
        let lib;
        let statically;
        let include;

        if let (Ok(lib_dir), Ok(include_dir)) =
            (env::var("MBEDTLS_LIB_DIR"), env::var("MBEDTLS_INCLUDE_DIR"))
        {
            lib = lib_dir;
            include = include_dir;
            statically = cfg!(feature = "static") || env::var("MBEDCRYPTO_STATIC").is_ok();
        } else {
            println!("Did not find environment variables, building MbedTLS!");
            let mut mbed_lib_dir = compile_mbed_crypto()?;
            let mut mbed_include_dir = mbed_lib_dir.clone();
            mbed_lib_dir.push("lib");
            mbed_include_dir.push("include");

            lib = mbed_lib_dir.to_str().unwrap().to_owned();
            include = mbed_include_dir.to_str().unwrap().to_owned();
            statically = true;
        }

        // Linking to PSA Crypto library is only needed for the operations.
        link_to_lib(lib, statically);
        generate_mbed_crypto_bindings(include.clone())?;
        compile_shim_library(include)
    } else if cfg!(feature = "interface") {
        if let Ok(include_dir) = env::var("MBEDTLS_INCLUDE_DIR") {
            generate_mbed_crypto_bindings(include_dir.clone())?;
            compile_shim_library(include_dir)
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "interface feature necessitates MBEDTLS_INCLUDE_DIR environment variable",
            ))
        }
    } else {
        Ok(())
    }
}
