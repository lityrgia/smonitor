use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=resources/scall-monitor.rc");
    println!("cargo:rerun-if-changed=resources/scall-monitor.ico");
    println!("cargo:rerun-if-changed=resources/window-icon.png");

    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("windows") {
        return;
    }

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let resource = manifest_dir.join("resources/scall-monitor.rc");
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("scall-monitor.res");
    let compilers: Vec<OsString> = env::var_os("RC")
        .into_iter()
        .chain([OsString::from("llvm-rc"), OsString::from("rc.exe")])
        .collect();

    let mut last_error = None;
    for compiler in compilers {
        match Command::new(&compiler)
            .arg("/nologo")
            .arg(format!("/fo{}", output.display()))
            .arg(&resource)
            .status()
        {
            Ok(status) if status.success() => {
                println!("cargo:rustc-link-arg-bin=smonitor={}", output.display());
                return;
            }
            Ok(status) => last_error = Some(format!("{compiler:?} exited with {status}")),
            Err(error) => last_error = Some(format!("could not run {compiler:?}: {error}")),
        }
    }

    panic!(
        "failed to compile Windows icon resource: {}",
        last_error.unwrap_or_else(|| "no resource compiler found".into())
    );
}
