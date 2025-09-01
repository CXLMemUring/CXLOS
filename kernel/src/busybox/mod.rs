use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub mod commands;
pub mod wasm_loader;

#[derive(Debug, Clone)]
pub struct BusyboxCommand {
    pub name: &'static str,
    pub description: &'static str,
    pub category: CommandCategory,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CommandCategory {
    FileSystem,
    Process,
    Network,
    System,
    Text,
    Shell,
}

impl fmt::Display for CommandCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandCategory::FileSystem => write!(f, "FileSystem"),
            CommandCategory::Process => write!(f, "Process"),
            CommandCategory::Network => write!(f, "Network"),
            CommandCategory::System => write!(f, "System"),
            CommandCategory::Text => write!(f, "Text"),
            CommandCategory::Shell => write!(f, "Shell"),
        }
    }
}

pub const BUSYBOX_COMMANDS: &[BusyboxCommand] = &[
    BusyboxCommand {
        name: "ls",
        description: "list directory contents",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "cat",
        description: "concatenate and print files",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "cp",
        description: "copy files and directories",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "mv",
        description: "move/rename files",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "rm",
        description: "remove files or directories",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "mkdir",
        description: "create directories",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "rmdir",
        description: "remove empty directories",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "pwd",
        description: "print working directory",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "cd",
        description: "change directory",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "find",
        description: "search for files and directories",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "chmod",
        description: "change file permissions",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "chown",
        description: "change file ownership",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "touch",
        description: "create empty file or update timestamp",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "df",
        description: "show disk usage",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "du",
        description: "show directory space usage",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "mount",
        description: "mount filesystems",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "umount",
        description: "unmount filesystems",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "ps",
        description: "show process status",
        category: CommandCategory::Process,
    },
    BusyboxCommand {
        name: "kill",
        description: "terminate processes",
        category: CommandCategory::Process,
    },
    BusyboxCommand {
        name: "top",
        description: "display process information",
        category: CommandCategory::Process,
    },
    BusyboxCommand {
        name: "sleep",
        description: "delay for specified time",
        category: CommandCategory::Process,
    },
    BusyboxCommand {
        name: "nice",
        description: "run with modified priority",
        category: CommandCategory::Process,
    },
    BusyboxCommand {
        name: "ping",
        description: "send ICMP echo requests",
        category: CommandCategory::Network,
    },
    BusyboxCommand {
        name: "wget",
        description: "download files from network",
        category: CommandCategory::Network,
    },
    BusyboxCommand {
        name: "ifconfig",
        description: "configure network interfaces",
        category: CommandCategory::Network,
    },
    BusyboxCommand {
        name: "route",
        description: "show/manipulate routing table",
        category: CommandCategory::Network,
    },
    BusyboxCommand {
        name: "netstat",
        description: "show network connections",
        category: CommandCategory::Network,
    },
    BusyboxCommand {
        name: "hostname",
        description: "show or set system hostname",
        category: CommandCategory::System,
    },
    BusyboxCommand {
        name: "date",
        description: "display or set system date/time",
        category: CommandCategory::System,
    },
    BusyboxCommand {
        name: "uptime",
        description: "show system uptime",
        category: CommandCategory::System,
    },
    BusyboxCommand {
        name: "uname",
        description: "print system information",
        category: CommandCategory::System,
    },
    BusyboxCommand {
        name: "free",
        description: "display memory usage",
        category: CommandCategory::System,
    },
    BusyboxCommand {
        name: "dmesg",
        description: "print kernel messages",
        category: CommandCategory::System,
    },
    BusyboxCommand {
        name: "lsmod",
        description: "list loaded modules",
        category: CommandCategory::System,
    },
    BusyboxCommand {
        name: "modprobe",
        description: "load kernel modules",
        category: CommandCategory::System,
    },
    BusyboxCommand {
        name: "reboot",
        description: "restart the system",
        category: CommandCategory::System,
    },
    BusyboxCommand {
        name: "halt",
        description: "halt the system",
        category: CommandCategory::System,
    },
    BusyboxCommand {
        name: "echo",
        description: "display text",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "grep",
        description: "search text patterns",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "sed",
        description: "stream editor",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "awk",
        description: "text processing language",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "cut",
        description: "extract text columns",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "sort",
        description: "sort text lines",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "uniq",
        description: "report or filter unique lines",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "head",
        description: "display first lines",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "tail",
        description: "display last lines",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "wc",
        description: "word/line/byte count",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "tee",
        description: "duplicate output",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "tr",
        description: "translate characters",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "sh",
        description: "shell interpreter",
        category: CommandCategory::Shell,
    },
    BusyboxCommand {
        name: "ash",
        description: "almquist shell",
        category: CommandCategory::Shell,
    },
    BusyboxCommand {
        name: "which",
        description: "locate commands",
        category: CommandCategory::Shell,
    },
    BusyboxCommand {
        name: "alias",
        description: "define command aliases",
        category: CommandCategory::Shell,
    },
    BusyboxCommand {
        name: "export",
        description: "set environment variables",
        category: CommandCategory::Shell,
    },
    BusyboxCommand {
        name: "source",
        description: "execute commands from file",
        category: CommandCategory::Shell,
    },
    BusyboxCommand {
        name: "test",
        description: "evaluate expressions",
        category: CommandCategory::Shell,
    },
    BusyboxCommand {
        name: "true",
        description: "return true",
        category: CommandCategory::Shell,
    },
    BusyboxCommand {
        name: "false",
        description: "return false",
        category: CommandCategory::Shell,
    },
    BusyboxCommand {
        name: "yes",
        description: "output string repeatedly",
        category: CommandCategory::Shell,
    },
    BusyboxCommand {
        name: "seq",
        description: "print sequence of numbers",
        category: CommandCategory::Shell,
    },
    BusyboxCommand {
        name: "basename",
        description: "strip directory from filename",
        category: CommandCategory::Shell,
    },
    BusyboxCommand {
        name: "dirname",
        description: "strip filename from path",
        category: CommandCategory::Shell,
    },
    BusyboxCommand {
        name: "xargs",
        description: "build and execute command lines",
        category: CommandCategory::Shell,
    },
    BusyboxCommand {
        name: "tar",
        description: "archive files",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "gzip",
        description: "compress files",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "gunzip",
        description: "decompress files",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "bzip2",
        description: "compress files with bzip2",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "bunzip2",
        description: "decompress bzip2 files",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "zip",
        description: "compress files to zip",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "unzip",
        description: "extract zip files",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "vi",
        description: "text editor",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "less",
        description: "file pager",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "more",
        description: "file pager",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "dd",
        description: "convert and copy files",
        category: CommandCategory::FileSystem,
    },
    BusyboxCommand {
        name: "hexdump",
        description: "display file in hex",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "od",
        description: "octal dump",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "strings",
        description: "extract strings from binary",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "cmp",
        description: "compare files byte by byte",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "diff",
        description: "compare files line by line",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "patch",
        description: "apply diff patches",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "md5sum",
        description: "compute MD5 checksum",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "sha1sum",
        description: "compute SHA1 checksum",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "sha256sum",
        description: "compute SHA256 checksum",
        category: CommandCategory::Text,
    },
    BusyboxCommand {
        name: "base64",
        description: "base64 encode/decode",
        category: CommandCategory::Text,
    },
];

pub fn get_command(name: &str) -> Option<&'static BusyboxCommand> {
    BUSYBOX_COMMANDS.iter().find(|cmd| cmd.name == name)
}

pub fn list_commands_by_category(category: CommandCategory) -> Vec<&'static BusyboxCommand> {
    BUSYBOX_COMMANDS
        .iter()
        .filter(|cmd| cmd.category == category)
        .collect()
}

pub fn search_commands(query: &str) -> Vec<&'static BusyboxCommand> {
    let query_lower = query.to_lowercase();
    BUSYBOX_COMMANDS
        .iter()
        .filter(|cmd| {
            cmd.name.contains(&query_lower) || cmd.description.to_lowercase().contains(&query_lower)
        })
        .collect()
}
