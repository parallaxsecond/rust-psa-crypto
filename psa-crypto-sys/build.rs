// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#![allow(renamed_and_removed_lints, unknown_lints)]
#![deny(
    nonstandard_style,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_bounds,
    private_in_public,
    private_interfaces,
    renamed_and_removed_lints,
    unconditional_recursion,
    unnameable_types,
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
    // If the prefix feature is not enabled then set the "CARGO_PKG_LINKS"
    // parameter to mbedcrypto to avoid any duplicate symbols from any other
    // crate. "CARGO_PKG_LINKS" overrides the "links" field in the manifest.
    #[cfg(not(feature = "prefix"))]
    {
        use std::env;
        let cargo_pkg_links = "CARGO_PKG_LINKS";
        env::set_var(cargo_pkg_links, "mbedcrypto");
    }

    #[cfg(feature = "operations")]
    return operations::script_operations();

    #[cfg(all(feature = "interface", not(feature = "operations")))]
    return interface::script_interface();

    #[cfg(not(any(feature = "interface", feature = "operations")))]
    Ok(())
}

#[cfg(any(feature = "interface", feature = "operations"))]
mod common {
    pub const CONFIG_FILE: &str = "custom_config.h";

    #[cfg(feature = "prefix")]
    use bindgen::callbacks::{ItemInfo, ParseCallbacks};

    use std::env;
    use std::io::{Error, ErrorKind, Result};
    use std::path::PathBuf;

    #[cfg(any(feature = "prefix", feature = "operations"))]
    pub fn get_external_mbedtls() -> Option<Result<(String, String)>> {
        if env::var("MBEDTLS_LIB_DIR").is_err() ^ env::var("MBEDTLS_INCLUDE_DIR").is_err() {
            return Some(Err(Error::new(
                ErrorKind::Other,
                "both environment variables MBEDTLS_LIB_DIR and MBEDTLS_INCLUDE_DIR need to be set for operations feature",
            )));
        }

        if let (Ok(lib_dir), Ok(include_dir)) =
            (env::var("MBEDTLS_LIB_DIR"), env::var("MBEDTLS_INCLUDE_DIR"))
        {
            println!("Found environment variables, using external MbedTLS");
            return Some(Ok((include_dir, lib_dir)));
        }

        if let Ok(mbedtls_result) = pkg_config::Config::new()
            .range_version("3.5".."4.0")
            .probe("mbedtls")
        {
            let include_dirs: Vec<String> = mbedtls_result
                .include_paths
                .into_iter()
                .map(|x: PathBuf| -> String { x.into_os_string().into_string().unwrap() })
                .collect();
            let include_dir = include_dirs.join(" ");
            // The current build framework doesn't support multiple lib paths for -L unfortuantely, so
            // we just take the first element, which is enough for now :-(
            let lib_dir = <PathBuf as Clone>::clone(&mbedtls_result.link_paths[0])
                .into_os_string()
                .into_string()
                .unwrap();
            println!("Found pkg-config mbedtls, using external MbedTLS");
            return Some(Ok((include_dir, lib_dir)));
        }

        // No env vars set and no discovered package through pkg-config
        None
    }

    #[cfg(all(feature = "interface", not(feature = "operations")))]
    pub fn get_external_mbedtls_include_only() -> Result<String> {
        if let Ok(include_dir) = env::var("MBEDTLS_INCLUDE_DIR") {
            println!("Found environment variable, using external MbedTLS");
            return Ok(include_dir);
        }

        if let Ok(mbedtls_result) = pkg_config::Config::new()
            .range_version("3.5".."4.0")
            .probe("mbedtls")
        {
            let include_dirs: Vec<String> = mbedtls_result
                .include_paths
                .into_iter()
                .map(|x: PathBuf| -> String { x.into_os_string().into_string().unwrap() })
                .collect();
            let include_dir = include_dirs.join(" ");

            return Ok(include_dir);
        }

        Err(Error::new(
            ErrorKind::Other,
            "interface feature necessitates MBEDTLS_INCLUDE_DIR environment variable",
        ))
    }

    #[cfg(feature = "prefix")]
    // Cargo provides the crate version from Cargo.toml in the environment.
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    #[cfg(feature = "prefix")]
    // Return a prefix that we hope is globally unique.
    pub fn prefix() -> String {
        format!("psa_crypto_{}_", VERSION.replace('.', "_"))
    }

    #[cfg(feature = "prefix")]
    #[derive(Debug)]
    struct RenameCallbacks {}

    #[cfg(feature = "prefix")]
    impl ParseCallbacks for RenameCallbacks {
        fn generated_link_name_override(&self, info: ItemInfo<'_>) -> Option<String> {
            Some(prefix() + info.name)
        }
    }

    pub fn generate_mbed_crypto_bindings(
        mbed_include_dir: String,
        external_mbedtls: bool,
    ) -> Result<()> {
        let header = mbed_include_dir.clone() + "/psa/crypto.h";

        println!("using mbedtls include directory of: {mbed_include_dir}");
        println!("cargo:rerun-if-changed={header}");

        let out_dir = env::var("OUT_DIR").unwrap();

        // Common shim builder settings
        let mut shim_builder = bindgen::Builder::default()
            .clang_arg(format!("-I{out_dir}"))
            .clang_arg(format!("-I{mbed_include_dir}"))
            .header("src/c/shim.h")
            .blocklist_type("max_align_t")
            .use_core()
            .generate_comments(false)
            .size_t_is_usize(true);

        #[cfg(feature = "prefix")]
        {
            shim_builder = shim_builder.parse_callbacks(Box::new(RenameCallbacks {}));
        }

        if !external_mbedtls {
            shim_builder =
                shim_builder.clang_arg(format!("-DMBEDTLS_CONFIG_FILE=\"{CONFIG_FILE}\""));
        }

        // Build the bindings
        let shim_bindings = shim_builder.generate().map_err(|_| {
            Error::new(
                ErrorKind::Other,
                "Unable to generate bindings to mbed crypto",
            )
        })?;

        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        shim_bindings.write_to_file(out_path.join("shim_bindings.rs"))?;

        Ok(())
    }

    pub fn compile_shim_library(
        include_dir: String,
        metadata: bool,
        external_mbedtls: bool,
    ) -> Result<PathBuf> {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

        let shimlib_name = "libmbedcryptoshim.a";

        // Compile and package the shim library
        let mut cfg = cc::Build::new();
        _ = cfg
            .include(&out_dir)
            .include(include_dir)
            .file("./src/c/shim.c")
            .warnings(true)
            .flag("-Werror")
            .opt_level(2)
            .cargo_metadata(metadata);

        if !external_mbedtls {
            let mbedtls_config_define = format!("-DMBEDTLS_CONFIG_FILE=\"{CONFIG_FILE}\"");
            _ = cfg.flag(&mbedtls_config_define);
        }

        cfg.try_compile(shimlib_name)
            .map_err(|_| Error::new(ErrorKind::Other, "compiling shim.c failed"))?;

        // Also link shim library
        #[cfg(not(feature = "prefix"))]
        {
            println!(
                "cargo:rustc-link-search=native={}",
                env::var("OUT_DIR").unwrap()
            );
            println!("cargo:rustc-link-lib=static=mbedcryptoshim");
        }
        Ok(out_dir.join(shimlib_name))
    }
}

#[cfg(all(feature = "interface", not(feature = "operations")))]
mod interface {
    use super::common;
    use std::io::Result;

    // Build script when the interface feature is on and not the operations one
    pub fn script_interface() -> Result<()> {
        let include_dir = common::get_external_mbedtls_include_only()?;

        common::generate_mbed_crypto_bindings(include_dir.clone(), true)?;
        let _ = common::compile_shim_library(include_dir, true, true)?;
        Ok(())
    }
}

#[cfg(feature = "operations")]
mod operations {
    use super::common;
    #[cfg(feature = "prefix")]
    use super::common::prefix;
    use cmake::Config;
    use std::env;
    #[cfg(feature = "prefix")]
    use std::io::Write;
    use std::io::{Error, ErrorKind, Result};
    use std::path::{Path, PathBuf};
    use walkdir::WalkDir;

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
            .arg(&(out_dir + "/" + common::CONFIG_FILE))
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
            .cflag(format!("-I{out_dir}"))
            .cflag(format!(
                "-DMBEDTLS_CONFIG_FILE='\"{}\"'",
                common::CONFIG_FILE
            ))
            .define("ENABLE_PROGRAMS", "OFF")
            .define("ENABLE_TESTING", "OFF")
            .build();

        Ok(mbed_build_path)
    }

    #[cfg(not(feature = "prefix"))]
    fn link_to_lib(lib_path: String, link_statically: bool) {
        let link_type = if link_statically { "static" } else { "dylib" };

        // Request rustc to link the Mbed Crypto library
        println!("cargo:rustc-link-search=native={lib_path}",);
        println!("cargo:rustc-link-lib={link_type}=mbedcrypto");
    }

    #[cfg(not(feature = "prefix"))]
    // Build script when the operations feature is on
    pub fn script_operations() -> Result<()> {
        let lib;
        let statically;
        let include;
        let external_mbedtls;

        match common::get_external_mbedtls() {
            Some(result) => {
                let (include_dir, lib_dir) = result.unwrap();
                lib = lib_dir;
                include = include_dir;
                statically = cfg!(feature = "static") || env::var("MBEDCRYPTO_STATIC").is_ok();
                external_mbedtls = true;
            }
            None => {
                println!("Did not find external MBEDTLS, building MbedTLS!");
                configure_mbed_crypto()?;
                let mut mbed_lib_dir = compile_mbed_crypto()?;
                let mut mbed_include_dir = mbed_lib_dir.clone();
                mbed_lib_dir.push("lib");
                if !mbed_lib_dir.as_path().exists() {
                    _ = mbed_lib_dir.pop();
                    mbed_lib_dir.push("lib64");
                }
                mbed_include_dir.push("include");

                lib = mbed_lib_dir.to_str().unwrap().to_owned();
                include = mbed_include_dir.to_str().unwrap().to_owned();
                statically = true;
                external_mbedtls = false;
            }
        }

        // Linking to PSA Crypto library is only needed for the operations.
        link_to_lib(lib, statically);
        common::generate_mbed_crypto_bindings(include.clone(), external_mbedtls)?;
        match common::compile_shim_library(include, false, external_mbedtls) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    #[cfg(feature = "prefix")]
    // Build script when the operations feature is on
    pub fn script_operations() -> Result<()> {
        match common::get_external_mbedtls() {
            Some(result) => {
                let (include_dir, lib_dir) = result.unwrap();
                // Request rustc to link the Mbed Crypto library
                let link_type = if cfg!(feature = "static") || env::var("MBEDCRYPTO_STATIC").is_ok()
                {
                    "static"
                } else {
                    "dylib"
                };
                println!("cargo:rustc-link-search=native={}", lib_dir);
                println!("cargo:rustc-link-lib={}=mbedcrypto", link_type);

                common::generate_mbed_crypto_bindings(include_dir.clone(), true)?;
                let _ = common::compile_shim_library(include_dir, true, true)?;
            }
            None => {
                println!("Did not find environment variables, building MbedTLS!");
                configure_mbed_crypto()?;
                let mut mbed_lib_dir = compile_mbed_crypto()?;
                let mut mbed_include_dir = mbed_lib_dir.clone();
                mbed_lib_dir.push("lib");
                if !mbed_lib_dir.as_path().exists() {
                    _ = mbed_lib_dir.pop();
                    mbed_lib_dir.push("lib64");
                }

                mbed_include_dir.push("include");
                let main_lib = mbed_lib_dir.join("libmbedcrypto.a");

                let include = mbed_include_dir.to_str().unwrap().to_owned();
                common::generate_mbed_crypto_bindings(include.clone(), false)?;
                let shim_lib = common::compile_shim_library(include, false, false)?;

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
        }

        Ok(())
    }

    #[cfg(feature = "prefix")]
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
