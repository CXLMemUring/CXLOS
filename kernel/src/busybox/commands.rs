use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write;

pub struct CommandContext {
    pub args: Vec<String>,
    pub current_dir: String,
    pub environment: Vec<(String, String)>,
}

impl CommandContext {
    pub fn new(args: Vec<String>) -> Self {
        Self {
            args,
            current_dir: "/".to_string(),
            environment: Vec::new(),
        }
    }
}

pub trait BusyboxCommandImpl {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String>;
}

pub struct EchoCommand;
impl BusyboxCommandImpl for EchoCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        let mut output = String::new();
        let mut first = true;
        
        for arg in &ctx.args[1..] {
            if !first {
                output.push(' ');
            }
            output.push_str(arg);
            first = false;
        }
        output.push('\n');
        
        Ok(output)
    }
}

pub struct PwdCommand;
impl BusyboxCommandImpl for PwdCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        Ok(format!("{}\n", ctx.current_dir))
    }
}

pub struct UnameCommand;
impl BusyboxCommandImpl for UnameCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        let mut output = String::new();
        
        if ctx.args.len() == 1 || ctx.args.contains(&"-s".to_string()) {
            output.push_str("k23");
        }
        
        if ctx.args.contains(&"-a".to_string()) {
            output.push_str("k23 ");
            output.push_str("kernel ");
            output.push_str(env!("CARGO_PKG_VERSION"));
            output.push(' ');
            
            #[cfg(target_arch = "riscv64")]
            output.push_str("riscv64");
            #[cfg(target_arch = "x86_64")]
            output.push_str("x86_64");
            #[cfg(target_arch = "aarch64")]
            output.push_str("aarch64");
        }
        
        if ctx.args.contains(&"-n".to_string()) {
            output.push_str(" k23-node");
        }
        
        if ctx.args.contains(&"-r".to_string()) {
            output.push(' ');
            output.push_str(env!("CARGO_PKG_VERSION"));
        }
        
        if ctx.args.contains(&"-v".to_string()) {
            output.push(' ');
            output.push_str(concat!(
                "#", env!("CARGO_PKG_VERSION"), "-k23"
            ));
        }
        
        if ctx.args.contains(&"-m".to_string()) {
            output.push(' ');
            #[cfg(target_arch = "riscv64")]
            output.push_str("riscv64");
            #[cfg(target_arch = "x86_64")]
            output.push_str("x86_64");
            #[cfg(target_arch = "aarch64")]
            output.push_str("aarch64");
        }
        
        output.push('\n');
        Ok(output)
    }
}

pub struct DateCommand;
impl BusyboxCommandImpl for DateCommand {
    fn execute(&self, _ctx: &mut CommandContext) -> Result<String, String> {
        Ok("Thu Jan 1 00:00:00 UTC 1970\n".to_string())
    }
}

pub struct WhoamiCommand;
impl BusyboxCommandImpl for WhoamiCommand {
    fn execute(&self, _ctx: &mut CommandContext) -> Result<String, String> {
        Ok("root\n".to_string())
    }
}

pub struct HostnameCommand;
impl BusyboxCommandImpl for HostnameCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        if ctx.args.len() > 1 {
            Err("Setting hostname not supported yet".to_string())
        } else {
            Ok("k23\n".to_string())
        }
    }
}

pub struct TrueCommand;
impl BusyboxCommandImpl for TrueCommand {
    fn execute(&self, _ctx: &mut CommandContext) -> Result<String, String> {
        Ok(String::new())
    }
}

pub struct FalseCommand;
impl BusyboxCommandImpl for FalseCommand {
    fn execute(&self, _ctx: &mut CommandContext) -> Result<String, String> {
        Err("false".to_string())
    }
}

pub struct SleepCommand;
impl BusyboxCommandImpl for SleepCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        if ctx.args.len() < 2 {
            return Err("sleep: missing operand".to_string());
        }
        
        let seconds = ctx.args[1].parse::<u64>()
            .map_err(|_| "sleep: invalid time interval".to_string())?;
        
        tracing::info!("Sleeping for {} seconds...", seconds);
        
        Ok(String::new())
    }
}

pub struct SeqCommand;
impl BusyboxCommandImpl for SeqCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        let mut output = String::new();
        
        let (start, end) = match ctx.args.len() {
            1 => return Err("seq: missing operand".to_string()),
            2 => {
                let end = ctx.args[1].parse::<i32>()
                    .map_err(|_| "seq: invalid number".to_string())?;
                (1, end)
            },
            3 => {
                let start = ctx.args[1].parse::<i32>()
                    .map_err(|_| "seq: invalid start number".to_string())?;
                let end = ctx.args[2].parse::<i32>()
                    .map_err(|_| "seq: invalid end number".to_string())?;
                (start, end)
            },
            _ => return Err("seq: too many arguments".to_string()),
        };
        
        if start <= end {
            for i in start..=end {
                writeln!(output, "{}", i).unwrap();
            }
        } else {
            for i in (end..=start).rev() {
                writeln!(output, "{}", i).unwrap();
            }
        }
        
        Ok(output)
    }
}

pub struct YesCommand;
impl BusyboxCommandImpl for YesCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        let text = if ctx.args.len() > 1 {
            ctx.args[1..].join(" ")
        } else {
            "y".to_string()
        };
        
        let mut output = String::new();
        for _ in 0..10 {
            writeln!(output, "{}", text).unwrap();
        }
        output.push_str("... (continues indefinitely)\n");
        
        Ok(output)
    }
}

pub struct BasenameCommand;
impl BusyboxCommandImpl for BasenameCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        if ctx.args.len() < 2 {
            return Err("basename: missing operand".to_string());
        }
        
        let path = &ctx.args[1];
        let basename = path.split('/').last().unwrap_or(path);
        
        let result = if ctx.args.len() > 2 {
            let suffix = &ctx.args[2];
            if basename.ends_with(suffix) {
                &basename[..basename.len() - suffix.len()]
            } else {
                basename
            }
        } else {
            basename
        };
        
        Ok(format!("{}\n", result))
    }
}

pub struct DirnameCommand;
impl BusyboxCommandImpl for DirnameCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        if ctx.args.len() < 2 {
            return Err("dirname: missing operand".to_string());
        }
        
        let path = &ctx.args[1];
        if let Some(pos) = path.rfind('/') {
            if pos == 0 {
                Ok("/\n".to_string())
            } else {
                Ok(format!("{}\n", &path[..pos]))
            }
        } else {
            Ok(".\n".to_string())
        }
    }
}

pub struct TestCommand;
impl BusyboxCommandImpl for TestCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        if ctx.args.len() < 2 {
            return Err("test: missing operand".to_string());
        }
        
        match ctx.args[1].as_str() {
            "-z" => {
                if ctx.args.len() < 3 {
                    Ok(String::new())
                } else if ctx.args[2].is_empty() {
                    Ok(String::new())
                } else {
                    Err("test failed".to_string())
                }
            },
            "-n" => {
                if ctx.args.len() < 3 {
                    Err("test failed".to_string())
                } else if !ctx.args[2].is_empty() {
                    Ok(String::new())
                } else {
                    Err("test failed".to_string())
                }
            },
            _ => {
                if &ctx.args[1] == ctx.args.get(3).unwrap_or(&String::new()) {
                    Ok(String::new())
                } else {
                    Err("test failed".to_string())
                }
            }
        }
    }
}

pub struct WcCommand;
impl BusyboxCommandImpl for WcCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        if ctx.args.len() < 2 {
            return Err("wc: missing file operand".to_string());
        }
        
        Ok("0 0 0\n".to_string())
    }
}

pub struct ClearCommand;
impl BusyboxCommandImpl for ClearCommand {
    fn execute(&self, _ctx: &mut CommandContext) -> Result<String, String> {
        Ok("\x1b[2J\x1b[H".to_string())
    }
}

pub struct LsCommand;
impl BusyboxCommandImpl for LsCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        let path = if ctx.args.len() > 1 {
            &ctx.args[1]
        } else {
            &ctx.current_dir
        };

        crate::fs::with_vfs(|vfs| {
            match vfs.list_dir(path) {
                Ok(entries) => {
                    let mut output = String::new();
                    for entry in entries {
                        let full_path = if path == "/" {
                            format!("/{}", entry)
                        } else {
                            format!("{}/{}", path, entry)
                        };
                        
                        if let Ok(stat) = vfs.stat(&full_path) {
                            match stat.file_type {
                                crate::fs::FileType::Directory => {
                                    output.push_str(&format!("{}/ ", entry));
                                },
                                _ => {
                                    output.push_str(&format!("{} ", entry));
                                }
                            }
                        } else {
                            output.push_str(&format!("{} ", entry));
                        }
                    }
                    if !output.is_empty() {
                        output.push('\n');
                    }
                    Ok(output)
                }
                Err(e) => Err(format!("ls: {}: {}", path, e))
            }
        }).unwrap_or_else(|| Err("ls: filesystem not initialized".to_string()))
    }
}

pub struct CatCommand;
impl BusyboxCommandImpl for CatCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        if ctx.args.len() < 2 {
            return Err("cat: missing file operand".to_string());
        }

        let path = &ctx.args[1];
        crate::fs::with_vfs(|vfs| {
            match vfs.read_file(path) {
                Ok(content) => {
                    match String::from_utf8(content) {
                        Ok(s) => Ok(s),
                        Err(_) => Ok("[binary data]\n".to_string())
                    }
                }
                Err(e) => Err(format!("cat: {}: {}", path, e))
            }
        }).unwrap_or_else(|| Err("cat: filesystem not initialized".to_string()))
    }
}

pub struct LessCommand;
impl BusyboxCommandImpl for LessCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        if ctx.args.len() < 2 {
            return Ok("(END) -- Press q to quit\n".to_string());
        }
        // Stub implementation
        Ok(format!("less: {}: No such file or directory\n", ctx.args[1]))
    }
}

pub struct MoreCommand;
impl BusyboxCommandImpl for MoreCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        if ctx.args.len() < 2 {
            return Ok("--More--(END)\n".to_string());
        }
        // Stub implementation
        Ok(format!("more: {}: No such file or directory\n", ctx.args[1]))
    }
}

pub struct GrepCommand;
impl BusyboxCommandImpl for GrepCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        if ctx.args.len() < 2 {
            return Err("grep: missing pattern".to_string());
        }
        // Stub implementation
        Ok(String::new())
    }
}

pub struct PsCommand;
impl BusyboxCommandImpl for PsCommand {
    fn execute(&self, _ctx: &mut CommandContext) -> Result<String, String> {
        Ok("  PID TTY          TIME CMD\n    1 ?        00:00:00 init\n    2 ?        00:00:00 kthread\n".to_string())
    }
}

pub struct TopCommand;
impl BusyboxCommandImpl for TopCommand {
    fn execute(&self, _ctx: &mut CommandContext) -> Result<String, String> {
        let mut output = String::new();
        output.push_str("top - 00:00:00 up 0 min,  1 user,  load average: 0.00, 0.00, 0.00\n");
        output.push_str("Tasks:   2 total,   1 running,   1 sleeping,   0 stopped,   0 zombie\n");
        output.push_str("Cpu(s):  0.0%us,  0.0%sy,  0.0%ni,100.0%id,  0.0%wa,  0.0%hi,  0.0%si,  0.0%st\n");
        output.push_str("Mem:    32768k total,     4096k used,    28672k free,        0k buffers\n");
        output.push_str("\n");
        output.push_str("  PID USER      PR  NI  VIRT  RES  SHR S %CPU %MEM     TIME+ COMMAND\n");
        output.push_str("    1 root      20   0  1024  256  128 S  0.0  0.8   0:00.00 init\n");
        Ok(output)
    }
}

pub struct FreeCommand;
impl BusyboxCommandImpl for FreeCommand {
    fn execute(&self, _ctx: &mut CommandContext) -> Result<String, String> {
        let mut output = String::new();
        output.push_str("              total       used       free     shared    buffers     cached\n");
        output.push_str("Mem:         32768       4096      28672          0          0          0\n");
        output.push_str("-/+ buffers/cache:       4096      28672\n");
        output.push_str("Swap:            0          0          0\n");
        Ok(output)
    }
}

pub struct UptimeCommand;
impl BusyboxCommandImpl for UptimeCommand {
    fn execute(&self, _ctx: &mut CommandContext) -> Result<String, String> {
        Ok(" 00:00:00 up 0 min,  1 user,  load average: 0.00, 0.00, 0.00\n".to_string())
    }
}

pub struct DfCommand;
impl BusyboxCommandImpl for DfCommand {
    fn execute(&self, _ctx: &mut CommandContext) -> Result<String, String> {
        let mut output = String::new();
        output.push_str("Filesystem     1K-blocks  Used Available Use% Mounted on\n");
        output.push_str("rootfs             32768  4096     28672  13% /\n");
        output.push_str("devfs                  0     0         0   0% /dev\n");
        Ok(output)
    }
}

pub struct MountCommand;
impl BusyboxCommandImpl for MountCommand {
    fn execute(&self, _ctx: &mut CommandContext) -> Result<String, String> {
        Ok("rootfs on / type rootfs (rw)\ndevfs on /dev type devfs (rw)\n".to_string())
    }
}

pub struct IdCommand;
impl BusyboxCommandImpl for IdCommand {
    fn execute(&self, _ctx: &mut CommandContext) -> Result<String, String> {
        Ok("uid=0(root) gid=0(root) groups=0(root)\n".to_string())
    }
}

pub struct WhichCommand;
impl BusyboxCommandImpl for WhichCommand {
    fn execute(&self, ctx: &mut CommandContext) -> Result<String, String> {
        if ctx.args.len() < 2 {
            return Err("which: missing command name".to_string());
        }
        
        // Check if it's a known busybox command
        if super::get_command(&ctx.args[1]).is_some() {
            Ok(format!("/bin/{}\n", ctx.args[1]))
        } else {
            Err(format!("which: {}: command not found", ctx.args[1]))
        }
    }
}

pub struct HelpCommand;
impl BusyboxCommandImpl for HelpCommand {
    fn execute(&self, _ctx: &mut CommandContext) -> Result<String, String> {
        let mut output = String::new();
        output.push_str("BusyBox v1.36.1 - Built-in shell (ash)\n");
        output.push_str("Enter 'busybox' to see the list of built-in commands.\n");
        output.push_str("\nImplemented commands:\n");
        output.push_str("  echo, pwd, uname, date, whoami, hostname, true, false\n");
        output.push_str("  sleep, seq, yes, basename, dirname, test, wc, clear\n");
        output.push_str("  ls, cat, less, more, grep, ps, top, free, uptime\n");
        output.push_str("  df, mount, id, which, help\n");
        Ok(output)
    }
}

pub fn get_command_impl(name: &str) -> Option<Box<dyn BusyboxCommandImpl>> {
    match name {
        "echo" => Some(Box::new(EchoCommand)),
        "pwd" => Some(Box::new(PwdCommand)),
        "uname" => Some(Box::new(UnameCommand)),
        "date" => Some(Box::new(DateCommand)),
        "whoami" => Some(Box::new(WhoamiCommand)),
        "hostname" => Some(Box::new(HostnameCommand)),
        "true" => Some(Box::new(TrueCommand)),
        "false" => Some(Box::new(FalseCommand)),
        "sleep" => Some(Box::new(SleepCommand)),
        "seq" => Some(Box::new(SeqCommand)),
        "yes" => Some(Box::new(YesCommand)),
        "basename" => Some(Box::new(BasenameCommand)),
        "dirname" => Some(Box::new(DirnameCommand)),
        "test" | "[" => Some(Box::new(TestCommand)),
        "wc" => Some(Box::new(WcCommand)),
        "clear" => Some(Box::new(ClearCommand)),
        "ls" => Some(Box::new(LsCommand)),
        "cat" => Some(Box::new(CatCommand)),
        "less" => Some(Box::new(LessCommand)),
        "more" => Some(Box::new(MoreCommand)),
        "grep" => Some(Box::new(GrepCommand)),
        "ps" => Some(Box::new(PsCommand)),
        "top" => Some(Box::new(TopCommand)),
        "free" => Some(Box::new(FreeCommand)),
        "uptime" => Some(Box::new(UptimeCommand)),
        "df" => Some(Box::new(DfCommand)),
        "mount" => Some(Box::new(MountCommand)),
        "id" => Some(Box::new(IdCommand)),
        "which" => Some(Box::new(WhichCommand)),
        "help" => Some(Box::new(HelpCommand)),
        _ => None,
    }
}