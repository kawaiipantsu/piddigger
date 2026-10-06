//! Change detection between consecutive snapshots.
//!
//! The live timeline answers "what did the process just do?": descriptors,
//! sockets, threads, children and executable mappings that appeared or vanished.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::model::Snapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    File,
    Net,
    Thread,
    Child,
    Map,
    State,
}

impl EventKind {
    pub fn label(self) -> &'static str {
        match self {
            EventKind::File => "fd",
            EventKind::Net => "net",
            EventKind::Thread => "thread",
            EventKind::Child => "child",
            EventKind::Map => "map",
            EventKind::State => "state",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// RFC 3339 UTC time of the snapshot that revealed the change.
    pub at: String,
    pub kind: EventKind,
    /// `+` appeared, `-` vanished, `~` changed.
    pub sign: char,
    pub text: String,
}

pub fn diff(old: &Snapshot, new: &Snapshot) -> Vec<Event> {
    let mut out = Vec::new();
    let at = new.taken_at.clone();
    let mut push = |kind, sign, text: String| {
        out.push(Event {
            at: at.clone(),
            kind,
            sign,
            text,
        })
    };

    if new.exited && !old.exited {
        push(
            EventKind::State,
            '-',
            format!("process {} exited", old.ident.pid),
        );
        return out;
    }
    if !old.ident.state.is_empty() && old.ident.state != new.ident.state {
        push(
            EventKind::State,
            '~',
            format!("state {} → {}", old.ident.state, new.ident.state),
        );
    }
    if !old.ident.cmdline.is_empty() && old.ident.cmdline != new.ident.cmdline {
        push(
            EventKind::State,
            '~',
            format!("cmdline changed → {}", new.ident.cmdline.join(" ")),
        );
    }
    if !old.ident.comm.is_empty() && old.ident.comm != new.ident.comm {
        push(
            EventKind::State,
            '~',
            format!("name {} → {}", old.ident.comm, new.ident.comm),
        );
    }
    if old.ident.uid != new.ident.uid && old.ident.pid != 0 {
        push(
            EventKind::State,
            '~',
            format!("uid {:?} → {:?}", old.ident.uid, new.ident.uid),
        );
    }

    let old_fds: HashMap<i32, &str> = old.fds.iter().map(|f| (f.fd, f.target.as_str())).collect();
    let new_fds: HashMap<i32, &str> = new.fds.iter().map(|f| (f.fd, f.target.as_str())).collect();
    for f in &new.fds {
        match old_fds.get(&f.fd) {
            None => push(EventKind::File, '+', format!("fd {} → {}", f.fd, f.target)),
            Some(prev) if *prev != f.target => push(
                EventKind::File,
                '~',
                format!("fd {} {} → {}", f.fd, prev, f.target),
            ),
            _ => {}
        }
    }
    for f in &old.fds {
        if !new_fds.contains_key(&f.fd) {
            push(
                EventKind::File,
                '-',
                format!("fd {} closed ({})", f.fd, f.target),
            );
        }
    }

    let describe = |s: &crate::model::SocketEntry| {
        if s.remote.is_empty() || s.remote_is_unspecified() {
            format!("{} {} {}", s.proto, s.local, s.state)
        } else {
            format!("{} {} → {} {}", s.proto, s.local, s.remote, s.state)
        }
    };
    let old_socks: HashMap<String, &str> = old
        .sockets
        .iter()
        .map(|s| (s.key(), s.state.as_str()))
        .collect();
    let new_socks: HashSet<String> = new.sockets.iter().map(|s| s.key()).collect();
    for s in &new.sockets {
        match old_socks.get(&s.key()) {
            None => push(EventKind::Net, '+', describe(s)),
            Some(prev) if *prev != s.state => push(EventKind::Net, '~', describe(s)),
            _ => {}
        }
    }
    for s in &old.sockets {
        if !new_socks.contains(&s.key()) {
            push(EventKind::Net, '-', describe(s));
        }
    }

    let old_tids: HashSet<i32> = old.threads.iter().map(|t| t.tid).collect();
    let new_tids: HashSet<i32> = new.threads.iter().map(|t| t.tid).collect();
    for t in new.threads.iter().filter(|t| !old_tids.contains(&t.tid)) {
        push(
            EventKind::Thread,
            '+',
            format!("thread {} ({})", t.tid, t.comm),
        );
    }
    for t in old.threads.iter().filter(|t| !new_tids.contains(&t.tid)) {
        push(
            EventKind::Thread,
            '-',
            format!("thread {} ({}) exited", t.tid, t.comm),
        );
    }

    let old_kids: HashSet<i32> = old.children.iter().map(|c| c.pid).collect();
    let new_kids: HashSet<i32> = new.children.iter().map(|c| c.pid).collect();
    for c in new.children.iter().filter(|c| !old_kids.contains(&c.pid)) {
        push(
            EventKind::Child,
            '+',
            format!(
                "child {} {}",
                c.pid,
                if c.cmdline.is_empty() {
                    &c.comm
                } else {
                    &c.cmdline
                }
            ),
        );
    }
    for c in old.children.iter().filter(|c| !new_kids.contains(&c.pid)) {
        push(
            EventKind::Child,
            '-',
            format!("child {} ({}) gone", c.pid, c.comm),
        );
    }

    // Executable mappings matter most: new code appearing in the address space.
    if !old.maps.is_empty() {
        let key = |m: &crate::model::MapEntry| (m.start, m.end, m.perms.clone());
        let old_exec: HashSet<_> = old
            .maps
            .iter()
            .filter(|m| m.executable())
            .map(key)
            .collect();
        for m in new.maps.iter().filter(|m| m.executable()) {
            if !old_exec.contains(&key(m)) {
                let what = if m.path.is_empty() {
                    "[anon]"
                } else {
                    m.path.as_str()
                };
                push(
                    EventKind::Map,
                    '+',
                    format!("exec {:x}-{:x} {} {}", m.start, m.end, m.perms, what),
                );
            }
        }
        if old.maps.len() != new.maps.len() {
            push(
                EventKind::Map,
                '~',
                format!("mappings {} → {}", old.maps.len(), new.maps.len()),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo;

    #[test]
    fn detects_new_connection_and_fd() {
        let a = demo::snapshot(0);
        let b = demo::snapshot(1);
        let ev = diff(&a, &b);
        assert!(
            ev.iter().any(|e| e.kind == EventKind::Net && e.sign == '+'),
            "{ev:?}"
        );
        assert!(
            ev.iter()
                .any(|e| e.kind == EventKind::File && e.sign == '+'),
            "{ev:?}"
        );
    }

    #[test]
    fn exit_is_single_event() {
        let a = demo::snapshot(0);
        let mut b = a.clone();
        b.exited = true;
        let ev = diff(&a, &b);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, EventKind::State);
    }
}
