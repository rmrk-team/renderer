use std::env;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let command = env::args().nth(1);
    match command.as_deref() {
        Some("ci") | None => run_ci(),
        Some("help") | Some("--help") | Some("-h") => {
            eprintln!("Usage: cargo ci");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("Unknown xtask command: {other}");
            eprintln!("Usage: cargo ci");
            ExitCode::from(2)
        }
    }
}

fn run_ci() -> ExitCode {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    if !run_step(&cargo, &["fmt", "--check"]) {
        return ExitCode::from(1);
    }
    if !run_step(&cargo, &["clippy", "--all-targets", "--all-features"]) {
        return ExitCode::from(1);
    }
    if !run_step(&cargo, &["test"]) {
        return ExitCode::from(1);
    }
    if !run_external_step("bash", &["./scripts/lint-openapi.sh", "openapi.yaml"]) {
        return ExitCode::from(1);
    }
    if !ensure_cargo_audit_installed(&cargo) {
        return ExitCode::from(1);
    }
    if !run_step(&cargo, &["audit"]) {
        return ExitCode::from(1);
    }
    if !run_external_step("bash", &["./scripts/ci-smoke.sh"]) {
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}

fn ensure_cargo_audit_installed(cargo: &str) -> bool {
    eprintln!("+ {} audit --version", cargo);
    match Command::new(cargo)
        .args(["audit", "--version"])
        .status()
    {
        Ok(status) if status.success() => true,
        Ok(_) => {
            eprintln!("cargo-audit not installed, installing...");
            run_step(cargo, &["install", "cargo-audit"])
        }
        Err(err) => {
            eprintln!("failed to run `{cargo} audit --version`: {err}");
            eprintln!("attempting to install cargo-audit...");
            run_step(cargo, &["install", "cargo-audit"])
        }
    }
}

fn run_step(cargo: &str, args: &[&str]) -> bool {
    eprintln!("+ {} {}", cargo, args.join(" "));
    match Command::new(cargo).args(args).status() {
        Ok(status) => status.success(),
        Err(err) => {
            eprintln!("failed to run `{cargo}`: {err}");
            false
        }
    }
}

fn run_external_step(command: &str, args: &[&str]) -> bool {
    eprintln!("+ {} {}", command, args.join(" "));
    match Command::new(command).args(args).status() {
        Ok(status) => status.success(),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                eprintln!("`{command}` was not found in PATH.");
                if command == "bash" {
                    eprintln!("A POSIX shell is required to run CI helper scripts.");
                }
            } else {
                eprintln!("failed to run `{command}`: {err}");
            }
            false
        }
    }
}
