//! Build script for scmm-record
//!
//! This creates a placeholder for the eBPF bytecode path.
//! The actual eBPF program is built separately with `cargo xtask build-ebpf`.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Output directory
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Create a placeholder eBPF file for development builds
    // In production, this would be the actual compiled eBPF program
    let ebpf_path = out_dir.join("scmm-ebpf");

    // Check if we have a pre-built eBPF program
    let possible_paths = [
        "../target/bpfel-unknown-none/release/scmm-ebpf",
        "../target/bpfel-unknown-none/debug/scmm-ebpf",
    ];

    let mut found = false;
    for path in &possible_paths {
        if std::path::Path::new(path).exists() {
            fs::copy(path, &ebpf_path).expect("Failed to copy eBPF program");
            found = true;
            println!("cargo:rerun-if-changed={}", path);
            break;
        }
    }

    if !found {
        // Create a minimal placeholder (will fail at runtime but allows building)
        // This is just the ELF magic bytes to pass basic validation
        let placeholder = [
            0x7f, 0x45, 0x4c, 0x46, // ELF magic
            0x02, // 64-bit
            0x01, // Little endian
            0x01, // ELF version
            0x00, // OS/ABI
        ];
        fs::write(&ebpf_path, &placeholder).expect("Failed to write placeholder");

        println!("cargo:warning=eBPF program not found. Build with: cargo xtask build-ebpf");
    }

    println!("cargo:rerun-if-changed=build.rs");
}
