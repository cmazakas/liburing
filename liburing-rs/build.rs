use std::{env, io::Write, path::PathBuf};

extern crate bindgen;

fn print_error_and_die() -> !
{
    eprint!(
            r#"
Crate axboe-liburing unable to generate bindings for header liburing.h
If you see several errors of the form:
    liburing/target/debug/build/axboe-liburing-<hash>/out/src/include/liburing/barrier.h:80:2: error: call to undeclared function 'atomic_load_explicit'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
    liburing/target/debug/build/axboe-liburing-<hash>/out/src/include/liburing/barrier.h:81:9: error: use of undeclared identifier 'memory_order_acquire'
    liburing/target/debug/build/axboe-liburing-<hash>/out/src/include/liburing/barrier.h:77:2: error: call to undeclared function 'atomic_store_explicit'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]

then it means you're most likely missing the required environment variables bindgen needs. Install libclang then set the environment variables below:
    CLANG_PATH = "/usr/bin/clang-22"
    LIBCLANG_PATH = "/usr/lib/llvm-22/lib"
"#
    );
    panic!("Bindings generation failed.");
}

fn main()
{
    println!("cargo::rerun-if-changed=src/");
    println!("cargo::rerun-if-changed=Makefile");
    println!("cargo::rerun-if-changed=Makefile.common");
    println!("cargo::rerun-if-changed=Makefile.quiet");
    println!("cargo::rerun-if-changed=configure");
    println!("cargo::rerun-if-changed=liburing-ffi.pc.in");
    println!("cargo::rerun-if-changed=liburing.spec");
    println!("cargo::rerun-if-changed=liburing.pc.in");
    println!("cargo::rerun-if-changed=liburing-rs/include/liburing_wrapper.h");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // copy everything in src to the OUT_DIR
    // Note, this brings along existing binary artifacts in the source tree
    std::process::Command::new("cp").args(["-r",
                                           "src",
                                           "Makefile",
                                           "Makefile.common",
                                           "Makefile.quiet",
                                           "configure",
                                           "liburing-ffi.pc.in",
                                           "liburing.pc.in",
                                           "liburing.spec",
                                           out_path.to_str().unwrap()])
                                    .spawn()
                                    .unwrap()
                                    .wait()
                                    .unwrap();

    // if there are any binary artifacts in the source for OUT_DIR, clean them
    let r = std::process::Command::new("make").args(["-C", "src", "clean"])
                                              .current_dir(out_path.clone())
                                              .output()
                                              .unwrap();

    std::io::stderr().write_all(&r.stderr).unwrap();
    assert!(r.status.success());

    let r = if cfg!(feature = "sanitizers") {
        std::process::Command::new("./configure").current_dir(out_path.clone())
                                                 .arg("--enable-sanitizer")
                                                 .output()
                                                 .unwrap()
    } else {
        std::process::Command::new("./configure").current_dir(out_path.clone())
                                                 .output()
                                                 .unwrap()
    };

    std::io::stderr().write_all(&r.stderr).unwrap();
    assert!(r.status.success());

    println!("configured liburing repo");

    let r = std::process::Command::new("make").args(["library", "-j12"])
                                              .current_dir(out_path.clone())
                                              .output()
                                              .unwrap();

    std::io::stderr().write_all(&r.stderr).unwrap();
    assert!(r.status.success());

    println!("completed `make library` call");

    if cfg!(feature = "bindgen-cli") {
        let bindgen_cmd = match env::var("BINDGEN_PATH") {
            Ok(s) => s,
            Err(_) => String::from("bindgen"),
        };

        // I hate this hack for getting the rustc version to pass to bindgen, and maybe there's a better way.
        let output = std::process::Command::new("rustc").arg("--version")
                                                        .output()
                                                        .expect("Failed to run rustc");

        // ❯ rustc --version
        // rustc 1.90.0 (1159e78c4 2025-09-14)
        // ❯ rustc +nightly --version
        // rustc 1.92.0-nightly (4da69dfff 2025-10-01)
        let rustc_version = String::from_utf8(output.stdout).unwrap();
        let parts: Vec<&str> = rustc_version.split_whitespace().collect();
        let rustc_version = parts[1];

        let rustc_version = rustc_version.split("-").next().unwrap();

        let r = std::process::Command::new(&bindgen_cmd).args(["liburing-rs/include/liburing_wrapper.h",
                                                       "--anon-fields-prefix",
                                                       "__liburing_anon_",
                                                       "--no-prepend-enum-name",
                                                       "--with-derive-default",
                                                       "--use-core",
                                                       "--rust-edition", "2024",
                                                       "--rust-target", rustc_version,
                                                       "--output",
                                                       out_path.join("liburing_bindings.rs")
                                                               .to_str()
                                                               .unwrap(),
                                                       "--",
                                                       "-std=gnu11",
                                                       &format!("-I{}/src/include",
                                                                out_path.to_str().unwrap()),
                                                       ])
                                                .output()
                                                .unwrap();

        std::io::stderr().write_all(&r.stderr).unwrap();
        if !r.status.success() {
            print_error_and_die();
        }
    } else {
        let bindings = bindgen::Builder::default().clang_arg(format!("-I{}/src/include",
                                                                     out_path.to_str().unwrap()))
                                                  .clang_arg("-std=gnu11")
                                                  .header("liburing-rs/include/liburing_wrapper.h")
                                                  .anon_fields_prefix("__liburing_anon_")
                                                  .prepend_enum_name(false)
                                                  .derive_default(true)
                                                  .use_core()
                                                  .generate();

        let bindings = match &bindings {
            Ok(bindings) => bindings,
            Err(_err) => {
                print_error_and_die();
            }
        };

        bindings.write_to_file(out_path.join("liburing_bindings.rs"))
                .expect("Couldn't write bindings!");
    }

    println!("generated bindings");

    println!("cargo::rustc-link-search={}/src", out_path.to_str().unwrap());
    println!("cargo::rustc-link-lib=static=uring");
}
