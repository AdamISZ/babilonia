//! The default [`Ui`](crate::agent::Ui): a line-oriented CLI **REPL**, built on rustyline. It parses
//! typed lines into [`Command`]s and renders [`Event`]s. Because the whole interaction is just those
//! two channels, a GUI (Tauri, …) is a drop-in replacement for this type — nothing else changes.
//!
//! Events arrive asynchronously (a peer's bet proposal can land while you're at the prompt), so a
//! background thread prints them via rustyline's **external printer**, which draws them *above* the
//! prompt without disturbing the line you're editing. rustyline also gives line editing (backspace,
//! cursor keys) and command history (up/down).

use std::io::{self, Write};
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, ExternalPrinter};

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
  set <key> <value>     set config (stake_percent, auto_accept, auto_accept_cap_sats)
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
        let mut rl = match DefaultEditor::new() {
            Ok(rl) => rl,
            Err(e) => {
                eprintln!("repl: cannot initialise line editor: {e}");
                let _ = commands.send(Command::Quit);
                return;
            }
        };

        // Async events print *above* the prompt via rustyline's external printer, so they never
        // clobber the line being typed. (Falls back to inline printing if unavailable.)
        let ev_thread = match rl.create_external_printer() {
            Ok(mut printer) => thread::spawn(move || {
                for ev in events {
                    if printer.print(render_line(&ev)).is_err() {
                        break;
                    }
                }
            }),
            Err(_) => thread::spawn(move || {
                for ev in events {
                    print!("{}", render_line(&ev));
                    let _ = io::stdout().flush();
                }
            }),
        };

        println!("babilonia node — type 'help'");
        loop {
            match rl.readline("babilonia> ") {
                Ok(line) => {
                    let text = line.trim();
                    if text.is_empty() {
                        continue;
                    }
                    let _ = rl.add_history_entry(text);
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
                // Ctrl-C / Ctrl-D / EOF → quit cleanly.
                Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                    let _ = commands.send(Command::Quit);
                    break;
                }
                Err(e) => {
                    eprintln!("repl: {e}");
                    let _ = commands.send(Command::Quit);
                    break;
                }
            }
        }
        let _ = ev_thread.join();
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

/// Render one [`Event`] to a printable line (trailing newline included), for the external printer.
fn render_line(ev: &Event) -> String {
    match ev {
        Event::Connected { peer } => format!("· connected to {peer}\n"),
        Event::Proposed { id, from, stake_sats } => {
            format!("· bet #{id} proposed by {from}: {stake_sats} sats — 'accept {id}' or 'reject {id}'\n")
        }
        Event::Progress { msg } => format!("  … {msg}\n"),
        Event::Outcome { msg } => format!("· outcome: {msg}\n"),
        Event::Address { address } => format!("· receive address: {address}\n"),
        Event::Balance { sats } => format!("· balance: {sats} sats\n"),
        Event::Config { text } => format!("{text}\n"),
        Event::Info { msg } => format!("· {msg}\n"),
        Event::Error { msg } => format!("! error: {msg}\n"),
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
