//! Parser for strace text output
//!
//! Parses standard `strace -f -o file` output into the same `ParsedCapture`
//! structure used by the binary `.scmm-cap` parser, so the rest of the
//! extraction pipeline works unchanged.
//!
//! Supported strace output formats:
//! - Single-process: `syscall(args) = retval`
//! - Multi-process (`-f`): `PID  syscall(args) = retval`
//! - Unfinished/resumed lines from concurrent threads

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use regex::Regex;
use tracing::{debug, warn};

use scmm_common::capture::CaptureMetadata;
use scmm_common::categories::x86_64 as syscalls;
use scmm_common::{ArgType, SyscallArg, SyscallEvent, MAX_ARG_STR_LEN};

use crate::parser::ParsedCapture;

/// Parse a strace text output file into a `ParsedCapture`.
pub fn parse_strace(path: &Path) -> Result<ParsedCapture> {
    let content = fs::read_to_string(path).context("Failed to read strace output file")?;

    let name_to_nr = syscalls::build_name_to_nr_map();

    // Regex patterns for different strace line formats
    // Complete syscall: optional PID prefix, syscall(args) = retval
    let re_complete =
        Regex::new(r"^(?:(\d+)\s+)?(\w+)\((.*)?\)\s*=\s*(-?\d+|0x[0-9a-fA-F]+|\?)(.*)$").unwrap();
    // Unfinished syscall: optional PID prefix, syscall(partial_args <unfinished ...>
    let re_unfinished = Regex::new(r"^(?:(\d+)\s+)?(\w+)\((.*?)\s*<unfinished \.\.\.>$").unwrap();
    // Resumed syscall: optional PID prefix, <... syscall resumed>rest_args) = retval
    let re_resumed = Regex::new(
        r"^(?:(\d+)\s+)?<\.\.\.\s+(\w+)\s+resumed>\s*(.*)?\)\s*=\s*(-?\d+|0x[0-9a-fA-F]+|\?)(.*)$",
    )
    .unwrap();

    // Buffered unfinished calls: key = (pid, syscall_name) -> partial args string
    let mut unfinished: HashMap<(u32, String), String> = HashMap::new();

    let mut events = Vec::new();
    let mut pids_seen = std::collections::HashSet::new();
    let mut timestamp_counter: u64 = 0;

    for line in content.lines() {
        let line = line.trim_end();

        // Skip empty lines, signals, exit markers
        if line.is_empty()
            || line.starts_with("---")
            || line.starts_with("+++")
            || line.starts_with("strace:")
        {
            continue;
        }

        // Try complete syscall line
        if let Some(caps) = re_complete.captures(line) {
            let pid = parse_pid(caps.get(1));
            let syscall_name = caps.get(2).unwrap().as_str();
            let args_str = caps.get(3).map_or("", |m| m.as_str());
            let ret_str = caps.get(4).unwrap().as_str();

            if let Some(&syscall_nr) = name_to_nr.get(syscall_name) {
                let ret_val = parse_return_value(ret_str);
                let event = build_event(syscall_nr, pid, args_str, ret_val, &mut timestamp_counter);
                pids_seen.insert(pid);
                events.push(event);
            } else {
                debug!("Unknown syscall: {}", syscall_name);
            }
            continue;
        }

        // Try unfinished syscall
        if let Some(caps) = re_unfinished.captures(line) {
            let pid = parse_pid(caps.get(1));
            let syscall_name = caps.get(2).unwrap().as_str().to_string();
            let partial_args = caps.get(3).map_or("", |m| m.as_str()).to_string();

            unfinished.insert((pid, syscall_name), partial_args);
            continue;
        }

        // Try resumed syscall
        if let Some(caps) = re_resumed.captures(line) {
            let pid = parse_pid(caps.get(1));
            let syscall_name = caps.get(2).unwrap().as_str();
            let rest_args = caps.get(3).map_or("", |m| m.as_str());
            let ret_str = caps.get(4).unwrap().as_str();

            let key = (pid, syscall_name.to_string());
            let full_args = if let Some(partial) = unfinished.remove(&key) {
                if rest_args.is_empty() {
                    partial
                } else {
                    format!("{}{}", partial, rest_args)
                }
            } else {
                rest_args.to_string()
            };

            if let Some(&syscall_nr) = name_to_nr.get(syscall_name) {
                let ret_val = parse_return_value(ret_str);
                let event =
                    build_event(syscall_nr, pid, &full_args, ret_val, &mut timestamp_counter);
                pids_seen.insert(pid);
                events.push(event);
            }
            continue;
        }

        // Lines we can't parse — skip silently (strace can produce various info lines)
        debug!("Skipping unparseable strace line: {}", line);
    }

    if !unfinished.is_empty() {
        warn!(
            "{} unfinished syscalls without matching resume",
            unfinished.len()
        );
    }

    // Synthesize metadata
    let hostname = gethostname::gethostname().to_string_lossy().to_string();
    let working_dir = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let root_pid = pids_seen.iter().copied().min().unwrap_or(0);

    let metadata = CaptureMetadata {
        hostname,
        kernel_release: String::new(),
        command: Vec::new(),
        working_dir,
        environment: Vec::new(),
        root_pid,
        attached: true,
        processes: Vec::new(),
    };

    println!(
        "Parsed {} events from strace output ({} unique PIDs)",
        events.len(),
        pids_seen.len()
    );

    Ok(ParsedCapture { metadata, events })
}

/// Parse an optional PID from a regex capture group, defaulting to 0
fn parse_pid(cap: Option<regex::Match>) -> u32 {
    cap.and_then(|m| m.as_str().parse().ok()).unwrap_or(0)
}

/// Parse strace return value string to i64
fn parse_return_value(s: &str) -> i64 {
    if s == "?" {
        return -1;
    }
    if let Some(hex) = s.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).unwrap_or(-1)
    } else {
        s.parse().unwrap_or(-1)
    }
}

/// Build a SyscallEvent from parsed strace data
fn build_event(
    syscall_nr: u32,
    pid: u32,
    args_str: &str,
    ret_val: i64,
    timestamp_counter: &mut u64,
) -> SyscallEvent {
    *timestamp_counter += 1_000_000; // 1ms increments for ordering

    let mut event = SyscallEvent {
        timestamp_ns: *timestamp_counter,
        pid,
        tid: pid, // strace doesn't distinguish tid from pid in most output
        syscall_nr,
        ret_val,
        ..Default::default()
    };

    // Parse arguments
    let parsed_args = split_strace_args(args_str);
    let path_idx = path_arg_index(syscall_nr);
    let flags_idx = flags_arg_index(syscall_nr);

    for (i, arg_str) in parsed_args.iter().enumerate() {
        if i >= 6 {
            break;
        }

        let arg_str = arg_str.trim();

        if arg_str.starts_with('"') {
            // String/path argument
            let unquoted = unquote_strace_string(arg_str);
            if i as u8 == path_idx {
                set_path_arg(&mut event.args[i], &unquoted);
            } else {
                set_string_arg(&mut event.args[i], &unquoted);
            }
        } else if arg_str.contains("O_") || arg_str.contains("AT_") && arg_str.contains('|') {
            // Flags argument (e.g., O_RDONLY|O_CLOEXEC)
            let flags_val = parse_open_flags(arg_str);
            event.args[i].arg_type = ArgType::Flags;
            event.args[i].raw_value = flags_val;
        } else if arg_str == "AT_FDCWD" {
            // Special constant for openat
            event.args[i].arg_type = ArgType::Fd;
            event.args[i].raw_value = 0xFFFFFF9C_u64; // AT_FDCWD = -100
        } else if arg_str == "NULL" {
            event.args[i].arg_type = ArgType::Pointer;
            event.args[i].raw_value = 0;
        } else if let Some(hex) = arg_str.strip_prefix("0x") {
            // Hex pointer/value
            event.args[i].arg_type = ArgType::Pointer;
            event.args[i].raw_value = u64::from_str_radix(hex, 16).unwrap_or(0);
        } else if let Ok(val) = arg_str.parse::<i64>() {
            // Integer
            event.args[i].arg_type = ArgType::Integer;
            event.args[i].raw_value = val as u64;
        } else if Some(i as u8) == flags_idx {
            // Flags position but didn't match O_ pattern — try parsing anyway
            let flags_val = parse_open_flags(arg_str);
            event.args[i].arg_type = ArgType::Flags;
            event.args[i].raw_value = flags_val;
        }
        // else: leave as Unknown (structs, arrays, etc.)
    }

    event
}

/// Split strace argument string respecting nested quotes, braces, brackets
fn split_strace_args(args: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32; // Brace/bracket nesting depth
    let mut in_quotes = false;
    let mut escape = false;
    let chars = args.chars();

    for ch in chars {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }

        match ch {
            '\\' if in_quotes => {
                current.push(ch);
                escape = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            '{' | '[' if !in_quotes => {
                depth += 1;
                current.push(ch);
            }
            '}' | ']' if !in_quotes => {
                depth -= 1;
                current.push(ch);
            }
            ',' if !in_quotes && depth == 0 => {
                result.push(current.trim().to_string());
                current = String::new();
            }
            _ => {
                current.push(ch);
            }
        }
    }

    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        result.push(trimmed);
    }

    result
}

/// Remove strace quoting from a string argument
/// Input: `"hello world"` or `"/etc/passwd"` or `"long st"...`
/// Output: the unquoted content
fn unquote_strace_string(s: &str) -> String {
    let s = s.trim();

    // Strip leading quote
    let s = s.strip_prefix('"').unwrap_or(s);

    // Strip trailing quote or "... (truncated)
    let s = if let Some(pos) = s.find("\"...") {
        &s[..pos]
    } else {
        s.strip_suffix('"').unwrap_or(s)
    };

    // Handle strace escape sequences
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    #[allow(clippy::while_let_on_iterator)] // chars.next() called inside for escape sequences
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('t') => result.push('\t'),
                Some('r') => result.push('\r'),
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some('0') => result.push('\0'),
                // Octal/hex escapes — just skip (we don't need binary data from paths)
                Some(c) if c.is_ascii_digit() => {
                    // Skip octal: up to 2 more digits
                    for _ in 0..2 {
                        if chars.clone().next().is_some_and(|c| c.is_ascii_digit()) {
                            chars.next();
                        }
                    }
                }
                Some('x') => {
                    // Skip hex: up to 2 digits
                    for _ in 0..2 {
                        if chars.clone().next().is_some_and(|c| c.is_ascii_hexdigit()) {
                            chars.next();
                        }
                    }
                }
                Some(c) => {
                    result.push('\\');
                    result.push(c);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Set a SyscallArg as a Path type with string data
fn set_path_arg(arg: &mut SyscallArg, path: &str) {
    arg.arg_type = ArgType::Path;
    let bytes = path.as_bytes();
    let len = bytes.len().min(MAX_ARG_STR_LEN);
    arg.str_data[..len].copy_from_slice(&bytes[..len]);
    arg.str_len = len as u16;
    // Also set raw_value to a non-zero sentinel so the extractor knows it's valid
    arg.raw_value = 1;
}

/// Set a SyscallArg as a String type with string data
fn set_string_arg(arg: &mut SyscallArg, s: &str) {
    arg.arg_type = ArgType::String;
    let bytes = s.as_bytes();
    let len = bytes.len().min(MAX_ARG_STR_LEN);
    arg.str_data[..len].copy_from_slice(&bytes[..len]);
    arg.str_len = len as u16;
    arg.raw_value = 1;
}

/// Parse strace open flags string into numeric bitmask
/// Input: "O_RDONLY|O_CLOEXEC" or "O_WRONLY|O_CREAT|O_TRUNC"
fn parse_open_flags(s: &str) -> u64 {
    let mut flags: u64 = 0;

    for token in s.split('|') {
        let token = token.trim();
        flags |= match token {
            "O_RDONLY" => 0x0,
            "O_WRONLY" => 0x1,
            "O_RDWR" => 0x2,
            "O_CREAT" => 0x40,
            "O_EXCL" => 0x80,
            "O_NOCTTY" => 0x100,
            "O_TRUNC" => 0x200,
            "O_APPEND" => 0x400,
            "O_NONBLOCK" => 0x800,
            "O_DSYNC" => 0x1000,
            "O_DIRECTORY" => 0x10000,
            "O_NOFOLLOW" => 0x20000,
            "O_CLOEXEC" => 0x80000,
            "O_TMPFILE" => 0x410000,
            "O_LARGEFILE" => 0x8000,
            "O_NOATIME" => 0x40000,
            "O_PATH" => 0x200000,
            _ => {
                // Try parsing as hex literal (strace sometimes outputs raw values)
                if let Some(hex) = token.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).unwrap_or(0)
                } else {
                    0
                }
            }
        };
    }

    flags
}

/// Returns which argument index contains the path for a given syscall (x86_64).
/// Mirrors the eBPF `path_arg_index()` in `scmm-ebpf/src/record.rs`.
/// Returns 255 if no path argument.
fn path_arg_index(syscall_nr: u32) -> u8 {
    match syscall_nr {
        2 => 0,   // open(pathname, flags, mode)
        4 => 0,   // stat(pathname, statbuf)
        6 => 0,   // lstat(pathname, statbuf)
        21 => 0,  // access(pathname, mode)
        59 => 0,  // execve(pathname, argv, envp)
        76 => 0,  // truncate(path, length)
        80 => 0,  // chdir(path)
        82 => 0,  // rename(old, new)
        83 => 0,  // mkdir(pathname, mode)
        84 => 0,  // rmdir(pathname)
        85 => 0,  // creat(pathname, mode)
        86 => 0,  // link(oldpath, newpath)
        87 => 0,  // unlink(pathname)
        88 => 0,  // symlink(target, linkpath)
        89 => 0,  // readlink(pathname, buf, bufsiz)
        90 => 0,  // chmod(pathname, mode)
        92 => 0,  // chown(pathname, owner, group)
        94 => 0,  // lchown(pathname, owner, group)
        137 => 0, // statfs(path, buf)
        161 => 0, // chroot(path)
        257 => 1, // openat(dirfd, pathname, flags, mode)
        258 => 1, // mkdirat(dirfd, pathname, mode)
        259 => 1, // mknodat(dirfd, pathname, dev, mode)
        260 => 1, // fchownat(dirfd, pathname, owner, group, flags)
        262 => 1, // newfstatat(dirfd, pathname, statbuf, flags)
        263 => 1, // unlinkat(dirfd, pathname, flags)
        264 => 1, // renameat(olddirfd, oldpath, newdirfd, newpath)
        265 => 1, // linkat(olddirfd, oldpath, newdirfd, newpath, flags)
        266 => 2, // symlinkat(target, newdirfd, linkpath)
        267 => 1, // readlinkat(dirfd, pathname, buf, bufsiz)
        268 => 1, // fchmodat(dirfd, pathname, mode)
        269 => 1, // faccessat(dirfd, pathname, mode)
        322 => 1, // execveat(dirfd, pathname, argv, envp, flags)
        332 => 1, // statx(dirfd, pathname, flags, mask, statxbuf)
        437 => 1, // openat2(dirfd, pathname, how, size)
        439 => 1, // faccessat2(dirfd, pathname, mode, flags)
        _ => 255,
    }
}

/// Returns which argument index contains flags for a given syscall.
/// Used to identify flag arguments even when they don't contain "O_" prefix.
fn flags_arg_index(syscall_nr: u32) -> Option<u8> {
    match syscall_nr {
        2 => Some(1),   // open(pathname, flags, mode)
        257 => Some(2), // openat(dirfd, pathname, flags, mode)
        437 => Some(2), // openat2(dirfd, pathname, how, size)
        _ => None,
    }
}
