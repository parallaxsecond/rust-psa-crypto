// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#![deny(
    nonstandard_style,
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

fn main() -> std::io::Result<()> {
    #[cfg(feature = "operations")]
    return operations::script_operations();

    #[cfg(all(feature = "interface", not(feature = "operations")))]
    return interface::script_interface();

    #[cfg(not(any(feature = "interface", feature = "operations")))]
    Ok(())
}

#[cfg(any(feature = "interface", feature = "operations"))]
mod common {
    use bindgen::callbacks::{ItemInfo, ParseCallbacks};
    use std::env;
    use std::io::{Error, ErrorKind, Result};
    use std::path::{Path, PathBuf};

    pub fn configure_mbed_crypto() -> Result<()> {
        let mbedtls_dir = String::from("./vendor");
        let mbedtls_config = mbedtls_dir + "/scripts/config.py";

        println!("cargo:rerun-if-changed=src/c/shim.c");
        println!("cargo:rerun-if-changed=src/c/shim.h");

        let out_dir = env::var("OUT_DIR").unwrap();

        //  Check for Mbed TLS sources
        if !Path::new(&mbedtls_config).exists() {
            return Err(Error::new(
                ErrorKind::Other,
                "MbedTLS config.py is missing. Have you run 'git submodule update --init'?",
            ));
        }

        // Configure the MbedTLS build for making Mbed Crypto
        if !::std::process::Command::new(mbedtls_config)
            .arg("--write")
            .arg(&(out_dir + "/config.h"))
            .arg("crypto")
            .status()
            .map_err(|_| Error::new(ErrorKind::Other, "configuring mbedtls failed"))?
            .success()
        {
            return Err(Error::new(
                ErrorKind::Other,
                "config.py returned an error status",
            ));
        }

        Ok(())
    }

    // Cargo provides the crate version from Cargo.toml in the environment.
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    // Return a prefix that we hope is globally unique.
    pub fn prefix() -> String {
        format!("psa_crypto_{}_", VERSION.replace('.', "_"))
    }

    #[derive(Debug)]
    struct RenameCallbacks {}

    impl ParseCallbacks for RenameCallbacks {
        fn generated_link_name_override(&self, info: ItemInfo<'_>) -> Option<String> {
            Some(prefix() + info.name)
        }
    }

    pub fn generate_mbed_crypto_bindings(mbed_include_dir: String) -> Result<()> {
        let header = mbed_include_dir.clone() + "/psa/crypto.h";

        println!("cargo:rerun-if-changed={}", header);

        let out_dir = env::var("OUT_DIR").unwrap();

        let shim_bindings = bindgen::Builder::default()
            .clang_arg(format!("-I{}", out_dir))
            .clang_arg("-DMBEDTLS_CONFIG_FILE=<config.h>")
            .clang_arg(format!("-I{}", mbed_include_dir))
            .header("src/c/shim.h")
            .blocklist_type("max_align_t")
            .generate_comments(false)
            .size_t_is_usize(true)
            .parse_callbacks(Box::new(RenameCallbacks {}))
            .generate()
            .map_err(|_| {
                Error::new(
                    ErrorKind::Other,
                    "Unable to generate bindings to mbed crypto",
                )
            })?;
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        shim_bindings.write_to_file(out_path.join("shim_bindings.rs"))?;

        Ok(())
    }

    pub fn compile_shim_library(include_dir: String, metadata: bool) -> Result<PathBuf> {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

        // Compile and package the shim library
        cc::Build::new()
            .include(&out_dir)
            .define("MBEDTLS_CONFIG_FILE", "<config.h>")
            .include(include_dir)
            .file("./src/c/shim.c")
            .warnings(true)
            .flag("-Werror")
            .opt_level(2)
            .cargo_metadata(metadata)
            .try_compile("libmbedcryptoshim.a")
            .map_err(|_| Error::new(ErrorKind::Other, "compiling shim.c failed"))?;

        Ok(out_dir.join("libmbedcryptoshim.a"))
    }
}

#[cfg(all(feature = "interface", not(feature = "operations")))]
mod interface {
    use super::common;
    use std::env;
    use std::io::{Error, ErrorKind, Result};

    // Build script when the interface feature is on and not the operations one
    pub fn script_interface() -> Result<()> {
        if let Ok(include_dir) = env::var("MBEDTLS_INCLUDE_DIR") {
            common::configure_mbed_crypto()?;
            common::generate_mbed_crypto_bindings(include_dir.clone())?;
            let _ = common::compile_shim_library(include_dir, true)?;
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "interface feature necessitates MBEDTLS_INCLUDE_DIR environment variable",
            ))
        }
    }
}

#[cfg(feature = "operations")]
mod operations {
    use super::common;
    use super::common::prefix;
    use cmake::Config;
    use std::env;
    use std::io::{Error, ErrorKind, Result, Write};
    use std::path::PathBuf;
    use walkdir::WalkDir;

    fn compile_mbed_crypto() -> Result<PathBuf> {
        let mbedtls_dir = String::from("./vendor");
        let out_dir = env::var("OUT_DIR").unwrap();

        // Rerun build if any file under the vendor directory has changed.
        for entry in WalkDir::new(&mbedtls_dir)
            .into_iter()
            .filter_map(|entry| entry.ok())
        {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    println!("cargo:rerun-if-changed={}", entry.path().display());
                }
            }
        }

        // Build the MbedTLS libraries
        let mbed_build_path = Config::new(&mbedtls_dir)
            .cflag(format!("-I{}", out_dir))
            .cflag("-DMBEDTLS_CONFIG_FILE='<config.h>'")
            .define("ENABLE_PROGRAMS", "OFF")
            .define("ENABLE_TESTING", "OFF")
            .build();

        Ok(mbed_build_path)
    }

    // Build script when the operations feature is on
    pub fn script_operations() -> Result<()> {
        if env::var("MBEDTLS_LIB_DIR").is_err() ^ env::var("MBEDTLS_INCLUDE_DIR").is_err() {
            return Err(Error::new(
                ErrorKind::Other,
                "both environment variables MBEDTLS_LIB_DIR and MBEDTLS_INCLUDE_DIR need to be set for operations feature",
            ));
        }

        common::configure_mbed_crypto()?;

        if let (Ok(lib_dir), Ok(include_dir)) =
            (env::var("MBEDTLS_LIB_DIR"), env::var("MBEDTLS_INCLUDE_DIR"))
        {
            // Request rustc to link the Mbed Crypto library
            let link_type = if cfg!(feature = "static") || env::var("MBEDCRYPTO_STATIC").is_ok() {
                "static"
            } else {
                "dylib"
            };
            println!("cargo:rustc-link-search=native={}", lib_dir);
            println!("cargo:rustc-link-lib={}=mbedcrypto", link_type);

            common::generate_mbed_crypto_bindings(include_dir.clone())?;
            let _ = common::compile_shim_library(include_dir, true)?;
        } else {
            println!("Did not find environment variables, building MbedTLS!");
            let mut mbed_lib_dir = compile_mbed_crypto()?;
            let mut mbed_include_dir = mbed_lib_dir.clone();
            mbed_lib_dir.push("lib");
            mbed_include_dir.push("include");
            let main_lib = mbed_lib_dir.join("libmbedcrypto.a");

            let include = mbed_include_dir.to_str().unwrap().to_owned();
            common::generate_mbed_crypto_bindings(include.clone())?;
            let shim_lib = common::compile_shim_library(include, false)?;

            // Modify and copy the libraries into a new directory.
            let llib_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("llib");
            let main_lib_name = prefix() + "mbedcrypto";
            let shim_lib_name = prefix() + "shim";
            objcopy(vec![
                (main_lib, llib_path.join(format!("lib{}.a", main_lib_name))),
                (shim_lib, llib_path.join(format!("lib{}.a", shim_lib_name))),
            ])?;
            println!("cargo:rustc-link-search=native={}", llib_path.display());
            println!("cargo:rustc-link-lib=static={}", main_lib_name);
            println!("cargo:rustc-link-lib=static={}", shim_lib_name);
        }

        Ok(())
    }

    pub fn objcopy(liblist: Vec<(PathBuf, PathBuf)>) -> Result<()> {
        // Run nm on the source libraries.
        let mut args = vec![];
        for lib in &liblist {
            let (from, _) = &lib;
            args.push(from.as_os_str());
        }
        let output = std::process::Command::new("nm")
            .args(args)
            .output()
            .expect("failed to run nm");
        if !output.status.success() {
            panic!("nm failed");
        }

        // Extract globally defined symbols.
        let mut syms = vec![];
        let re = regex::Regex::new(r"(?m) +[A-TV-Z] +(.+)$").unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        for (_, [sym]) in re.captures_iter(&stdout).map(|c| c.extract()) {
            syms.push(sym);
        }

        // Generate a file for objcopy containing "old new" in each line.
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        let prefix = prefix();
        let symfile = out_path.join("objcopy_syms");
        {
            let mut file = std::fs::File::create(&symfile).unwrap();
            for sym in syms.iter() {
                file.write_all(format!("{} {}{}\n", sym, prefix, sym).as_bytes())
                    .unwrap();
            }
        }

        for (from, to) in liblist.into_iter() {
            std::fs::create_dir_all(to.parent().unwrap())?;

            // Run objcopy to copy library and rename symbols.
            let status = std::process::Command::new("objcopy")
                .args([
                    "--redefine-syms",
                    symfile.to_str().unwrap(),
                    from.to_str().unwrap(),
                    to.to_str().unwrap(),
                ])
                .status()
                .expect("failed to execute process");
            if !status.success() {
                panic!("objcopy failed");
            }
        }

        Ok(())
    }
}
