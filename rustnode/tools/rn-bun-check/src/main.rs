//! The declaration side of the `Bun` surface, without an isolate.
//!
//! `tools/bun-surface-guard.py` has to answer four questions and only one of them
//! needs a running runtime:
//!
//! | question | answered by |
//! | --- | --- |
//! | what does the registry claim? | this binary |
//! | what is deferred, and why? | this binary |
//! | what does Bun 1.4.4 expose? | the Bun oracle |
//! | what does the built `rustnode` expose? | `rustnode --bun-surface` |
//!
//! So the declaration half runs as plain Rust, exactly like `rn-compat`, and the
//! guard never has to trust a JSON file that a human maintains. The registry this
//! reads is the one the runtime assembles from the *same* generated aggregator, so
//! a crate that was dropped by the matcher is absent here too and the guard's
//! "declared but not installed" arm cannot agree with itself by accident.
//!
//! ```bash
//! cargo run -q -p rn-bun-check -- declarations   # {"members": [...], "deferred": [...]}
//! cargo run -q -p rn-bun-check -- deferrals      # only the deferred entries
//! ```
//!
//! Exit codes:
//!   0  the registry assembled
//!   1  the registry refused a registration (a duplicate name, or a contradictory
//!      deferral) — printed on stderr with both crates named
//!   2  usage error

use std::process::ExitCode;

const USAGE: &str = "usage: rn-bun-check declarations | deferrals";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some(subcommand) = arguments.first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };

    // Assembled before either subcommand reads it: a registry that refuses to
    // assemble is the answer to every question below, and printing a partial list
    // would let the guard compare against a set the runtime never builds.
    let registry = match rn_bun_members::install_all() {
        Ok(registry) => registry,
        Err(message) => {
            eprintln!("the Bun contribution registry refused to assemble: {message}");
            return ExitCode::from(1);
        }
    };

    match subcommand.as_str() {
        "declarations" => {
            let members: Vec<Member> = registry
                .declarations()
                .iter()
                .map(|declaration| Member {
                    member: declaration.member.clone(),
                    contributor: declaration.contributor.clone(),
                })
                .collect();
            let deferred: Vec<Deferral> = registry
                .deferrals()
                .iter()
                .map(|deferral| Deferral {
                    member: deferral.member.clone(),
                    contributor: deferral.contributor.clone(),
                    reason: deferral.reason.clone(),
                })
                .collect();
            print_json(&Report { members, deferred });
            ExitCode::SUCCESS
        }
        "deferrals" => {
            let deferred: Vec<Deferral> = registry
                .deferrals()
                .iter()
                .map(|deferral| Deferral {
                    member: deferral.member.clone(),
                    contributor: deferral.contributor.clone(),
                    reason: deferral.reason.clone(),
                })
                .collect();
            print_json(&deferred);
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown subcommand {other:?}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[derive(serde::Serialize)]
struct Report {
    members: Vec<Member>,
    deferred: Vec<Deferral>,
}

#[derive(serde::Serialize)]
struct Member {
    member: String,
    contributor: String,
}

#[derive(serde::Serialize)]
struct Deferral {
    member: String,
    contributor: String,
    reason: String,
}

fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => println!("{text}"),
        Err(error) => eprintln!("cannot print the registry: {error}"),
    }
}
