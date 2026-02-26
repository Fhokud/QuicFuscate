use std::fs;
use std::path::Path;

fn main() {
    // Avoid Cargo's default "scan the entire package tree" behavior for build script rerun decisions.
    // That scan can fail when dev tools create/remove ephemeral directories during tests.
    println!("cargo:rerun-if-changed=build.rs");

    // Ensure the logs directory exists so the workflow can write logs
    let logs_dir = Path::new("scripts/out/logs");
    if !logs_dir.exists() {
        if let Err(e) = fs::create_dir_all(logs_dir) {
            println!("cargo:warning=Failed to create log directory {}: {}", logs_dir.display(), e);
        }
    }
    // No-op otherwise; all native transport and crypto are implemented under src/
}
