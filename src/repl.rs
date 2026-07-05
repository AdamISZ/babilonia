//! The default [`Ui`](crate::agent::Ui): a line-oriented CLI **REPL**. It parses typed lines into
//! [`Command`]s and renders [`Event`]s. Because the whole interaction is just those two channels, a
//! GUI (Tauri, …) is a drop-in replacement for this type — nothing else changes.
//!
//! Events arrive asynchronously (a peer's bet proposal can land while you're at the prompt), so a
//! background thread prints them as they come. (rustyline's external-print would tidy the prompt
//! interleaving — a later polish.)

use std::io::{self, Write};
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use crate::agent::{Command, Event, Ui};

const HELP: &str = "\
commands:
  connect <addr>        peer with another node at host:port (BIP324)
  propose               propose a bet to the connected peer
  accept <id>           accept a pending incoming bet
  reject <id>           reject a pending incoming bet
  receive               show a fresh receiving address
  balance               show wallet balance
  send <addr> <sats>    send a plain payment (e.g. fund a peer)
  set <key> <value>     set config (auto_accept, stake_sats, stake_percent)
  config                show config
  help                  this help
  quit | exit           shut down";

/// The CLI REPL. Stateless — all state lives in the node core.
#[derive(Default)]
pub struct Repl;

impl Repl {
    pub fn new() -> Self {
        Repl
    }
}

impl Ui for Repl {
    fn run(&mut self, commands: Sender<Command>, events: Receiver<Event>) {
        // Async event renderer — ends when the core drops the event sender.
        let printer = thread::spawn(move || {
            for ev in events {
                render(&ev);
            }
        });

        println!("babilonia node — type 'help'");
        let stdin = io::stdin();
        let mut line = String::new();
        loop {
            print!("babilonia> ");
            let _ = io::stdout().flush();
            line.clear();
            match stdin.read_line(&mut line) {
                Ok(0) => break, // EOF (Ctrl-D / piped input exhausted)
                Ok(_) => {}
                Err(_) => break,
            }
            let text = line.trim();
            if text.is_empty() {
                continue;
            }
            match parse(text) {
                Ok(Some(Command::Quit)) => {
                    let _ = commands.send(Command::Quit);
                    break;
                }
                Ok(Some(cmd)) => {
                    if commands.send(cmd).is_err() {
                        break; // core gone
                    }
                }
                Ok(None) => {} // handled locally (help)
                Err(msg) => println!("? {msg}"),
            }
        }
        let _ = commands.send(Command::Quit);
        let _ = printer.join();
    }
}

/// Parse one input line into a [`Command`]. `Ok(None)` = handled locally (e.g. `help`).
pub fn parse(line: &str) -> std::result::Result<Option<Command>, String> {
    let mut it = line.split_whitespace();
    let verb = it.next().ok_or("empty")?;
    let rest: Vec<&str> = it.collect();
    let need = |n: usize| -> std::result::Result<(), String> {
        if rest.len() == n {
            Ok(())
        } else {
            Err(format!("'{verb}' expects {n} argument(s), got {}", rest.len()))
        }
    };
    let id = |s: &str| s.parse::<u64>().map_err(|_| format!("bad id '{s}'"));
    let cmd = match verb {
        "help" | "?" => {
            println!("{HELP}");
            return Ok(None);
        }
        "connect" => {
            need(1)?;
            Command::Connect { addr: rest[0].to_string() }
        }
        "propose" => {
            need(0)?;
            Command::Propose
        }
        "accept" => {
            need(1)?;
            Command::Accept(id(rest[0])?)
        }
        "reject" => {
            need(1)?;
            Command::Reject(id(rest[0])?)
        }
        "receive" => {
            need(0)?;
            Command::Receive
        }
        "balance" => {
            need(0)?;
            Command::Balance
        }
        "send" => {
            need(2)?;
            let sats = rest[1].parse::<u64>().map_err(|_| format!("bad amount '{}'", rest[1]))?;
            Command::Send { address: rest[0].to_string(), sats }
        }
        "set" => {
            need(2)?;
            Command::Set { key: rest[0].to_string(), value: rest[1].to_string() }
        }
        "config" => {
            need(0)?;
            Command::ShowConfig
        }
        "quit" | "exit" => Command::Quit,
        other => return Err(format!("unknown command '{other}' (try 'help')")),
    };
    Ok(Some(cmd))
}

/// Render one [`Event`] to stdout.
fn render(ev: &Event) {
    match ev {
        Event::Connected { peer } => println!("\n· connected to {peer}"),
        Event::Proposed { id, from, stake_sats } => {
            println!("\n· bet #{id} proposed by {from}: {stake_sats} sats — 'accept {id}' or 'reject {id}'")
        }
        Event::Progress { msg } => println!("  … {msg}"),
        Event::Outcome { msg } => println!("\n· outcome: {msg}"),
        Event::Address { address } => println!("· receive address: {address}"),
        Event::Balance { sats } => println!("· balance: {sats} sats"),
        Event::Config { text } => println!("{text}"),
        Event::Info { msg } => println!("· {msg}"),
        Event::Error { msg } => println!("! error: {msg}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commands() {
        assert!(matches!(parse("connect 1.2.3.4:8333").unwrap(), Some(Command::Connect { addr }) if addr == "1.2.3.4:8333"));
        assert!(matches!(parse("propose").unwrap(), Some(Command::Propose)));
        assert!(matches!(parse("accept 3").unwrap(), Some(Command::Accept(3))));
        assert!(matches!(parse("reject 7").unwrap(), Some(Command::Reject(7))));
        assert!(matches!(parse("receive").unwrap(), Some(Command::Receive)));
        assert!(matches!(parse("balance").unwrap(), Some(Command::Balance)));
        assert!(matches!(parse("send bcrt1qxyz 50000").unwrap(), Some(Command::Send { sats: 50000, .. })));
        assert!(matches!(parse("set auto_accept true").unwrap(), Some(Command::Set { .. })));
        assert!(matches!(parse("quit").unwrap(), Some(Command::Quit)));
        assert!(matches!(parse("help").unwrap(), None));

        // Errors: unknown verb, wrong arity, bad id.
        assert!(parse("frobnicate").is_err());
        assert!(parse("connect").is_err());
        assert!(parse("accept xyz").is_err());
        assert!(parse("propose extra").is_err());
    }
}
