#![allow(clippy::too_many_arguments)]

mod apps;

use core::sync::atomic::{AtomicU64, Ordering};
use core::{fmt::Write, str};

use heapless::{String, Vec};
use spin::Mutex;
use userlib::{console_read, console_write, exit, yield_now};
use zero_abi::channels;
use zero_abi::ipc::Message;
use zero_abi::protocol::{launchd, security};
use zero_abi::syscall::SysError;

use apps::{
    binary_exists, build_storage_path, encode_app_payload, InstallOutcome, APP_REGISTRY,
    APP_VERSION_MAX,
};

const INPUT_MAX: usize = 128;
const USERNAME_MAX: usize = 16;
const PASSWORD_MAX: usize = 32;
const MAX_USERS: usize = 8;
const MAX_SESSIONS: usize = 8;
const MAX_AUDIT_EVENTS: usize = 32;
const HELP_TEXT: &str = "\
Available commands:
  help             Show this help text
  motd             Show the message of the day
  whoami           Display the current user
  who              Display the current user + role
  last             Show recent login history
  users            List registered users (admin only)
  adduser <n> <p> [admin|user]
  passwd <new>     Change password
  deluser <n>      Remove a user (admin only)
  service <...>    Control services (list, restart)
  sessions         Show session table (admin only)
  dashboard        Show system summary
  app <...>        Manage .app bundles (install/list/info/launch/remove)
  su <name>        Switch user (will prompt for password)
  logout           Sign out of the session
  shutdown         Exit the console task
";
const MOTD: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kernel/rootfs/etc/motd"
));

#[derive(Clone, Copy, PartialEq, Eq)]
enum UserRole {
    Admin,
    User,
}

impl UserRole {
    fn as_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::User => "user",
        }
    }
}

#[derive(Clone)]
struct UserRecord {
    username: String<USERNAME_MAX>,
    role: UserRole,
}

impl UserRecord {
    fn new(username: &str, role: UserRole) -> Option<Self> {
        let mut name = String::<USERNAME_MAX>::new();
        name.push_str(username).ok()?;
        Some(Self {
            username: name,
            role,
        })
    }
}

pub extern "C" fn user_entry() -> ! {
    let mut shell = ConsoleShell::new();
    shell.run()
}

struct ConsoleShell {
    line: String<INPUT_MAX>,
    user_cache: Vec<UserRecord, MAX_USERS>,
    session_id: Option<u64>,
    session_user: Option<String<USERNAME_MAX>>,
}

impl ConsoleShell {
    fn new() -> Self {
        APP_REGISTRY.ensure_loaded();
        Self {
            line: String::new(),
            user_cache: Vec::new(),
            session_id: None,
            session_user: None,
        }
    }

    fn run(&mut self) -> ! {
        self.println("\r\nZero OS console ready.");
        loop {
            if let Some(index) = self.prompt_login() {
                self.session(index);
            }
        }
    }

    fn prompt_login(&mut self) -> Option<usize> {
        let _ = self.refresh_user_cache();
        let mut username = String::<USERNAME_MAX>::new();
        let mut password = String::<PASSWORD_MAX>::new();
        loop {
            self.print("\r\nlogin: ");
            if !self.read_into(&mut username, true) {
                continue;
            }
            self.print("password: ");
            if !self.read_into(&mut password, false) {
                self.println("");
                continue;
            }
            self.println("");
            if self.verify_credentials(username.as_str(), password.as_str()) {
                self.println("Login successful.");
                if let Some(idx) = self.user_cache.iter().position(|u| u.username == username) {
                    self.begin_session(username.as_str());
                    return Some(idx);
                }
                // user directory outdated; refresh once and try again
                if self.refresh_user_cache().is_ok() {
                    if let Some(idx) = self.user_cache.iter().position(|u| u.username == username) {
                        self.begin_session(username.as_str());
                        return Some(idx);
                    }
                }
                self.println("Directory out of sync; please try again.");
                return None;
            } else {
                self.println("Authentication failed.");
                AUDIT_LOG.failed(username.as_str());
                username.clear();
                password.clear();
            }
        }
    }

    fn session(&mut self, mut user_index: usize) {
        self.println("");
        self.println(MOTD);
        loop {
            self.print_prompt(user_index);
            let raw = match self.read_line_internal(true) {
                Some(text) => text.trim(),
                None => continue,
            };
            if raw.is_empty() {
                continue;
            }
            let mut command = String::<INPUT_MAX>::new();
            if command.push_str(raw).is_err() {
                self.println("Input too long.");
                continue;
            }
            if !self.handle_command(&mut user_index, command.as_str()) {
                self.println("Signed out.");
                break;
            }
        }
        self.end_session();
    }

    fn handle_command(&mut self, user_index: &mut usize, line: &str) -> bool {
        let mut parts = line.split_whitespace();
        let Some(cmd) = parts.next() else {
            return true;
        };
        let mut args: Vec<&str, 4> = Vec::new();
        for part in parts {
            let _ = args.push(part);
        }
        match cmd {
            "help" => self.print_and_ok(HELP_TEXT),
            "motd" => self.print_and_ok(MOTD),
            "whoami" => self.cmd_whoami(*user_index),
            "who" => self.cmd_who(*user_index),
            "last" => self.cmd_last(),
            "users" => self.cmd_list_users(*user_index),
            "adduser" => self.cmd_add_user(*user_index, &args),
            "passwd" => self.cmd_change_password(*user_index, &args),
            "deluser" => self.cmd_delete_user(*user_index, &args),
            "service" => self.cmd_service_control(*user_index, &args),
            "sessions" => self.cmd_sessions(*user_index),
            "dashboard" => self.cmd_dashboard(*user_index),
            "app" => self.cmd_app(*user_index, &args),
            "su" => self.cmd_switch_user(user_index, &args),
            "logout" => {
                self.end_session();
                false
            }
            "shutdown" => {
                self.end_session();
                exit(0)
            }
            _ => {
                self.println("Unknown command. Type 'help' for a list of commands.");
                true
            }
        }
    }

    fn print_and_ok(&mut self, text: &str) -> bool {
        self.println(text);
        true
    }

    fn cmd_list_users(&mut self, user_index: usize) -> bool {
        if !self.is_admin(user_index) {
            self.println("Permission denied: admin only.");
            return true;
        }
        match self.refresh_user_cache() {
            Ok(()) => {
                if self.user_cache.is_empty() {
                    self.println("\r\nNo registered users.");
                } else {
                    self.println("\r\nRegistered users:");
                    for entry in self.user_cache.iter() {
                        self.print("  - ");
                        self.print(entry.username.as_str());
                        self.print(" (");
                        self.print(entry.role.as_str());
                        self.println(")");
                    }
                }
            }
            Err(err) => self.println(err),
        }
        true
    }

    fn cmd_add_user(&mut self, user_index: usize, args: &Vec<&str, 4>) -> bool {
        if !self.is_admin(user_index) {
            self.println("Permission denied: admin only.");
            return true;
        }
        if args.len() < 2 {
            self.println("Usage: adduser <name> <password> [admin|user]");
            return true;
        }
        let role = match args.get(2).copied().unwrap_or("user") {
            "admin" => UserRole::Admin,
            "user" => UserRole::User,
            _ => {
                self.println("Role must be 'admin' or 'user'.");
                return true;
            }
        };
        match self.send_user_command(security::CMD_USER_ADD, args[0], Some(args[1]), Some(role)) {
            Ok(_) => self.println("User added."),
            Err(err) => self.println(err),
        }
        true
    }

    fn cmd_change_password(&mut self, user_index: usize, args: &Vec<&str, 4>) -> bool {
        if args.is_empty() {
            self.println("Usage: passwd <newpassword>");
            return true;
        }
        let Some(name) = self.current_username(user_index) else {
            self.println("No active user.");
            return true;
        };
        let mut username = String::<USERNAME_MAX>::new();
        if username.push_str(name).is_err() {
            self.println("Username too long.");
            return true;
        }
        match self.send_user_command(
            security::CMD_USER_PASSWD,
            username.as_str(),
            Some(args[0]),
            None,
        ) {
            Ok(_) => self.println("Password updated."),
            Err(err) => self.println(err),
        }
        true
    }

    fn cmd_delete_user(&mut self, user_index: usize, args: &Vec<&str, 4>) -> bool {
        if !self.is_admin(user_index) {
            self.println("Permission denied: admin only.");
            return true;
        }
        if args.is_empty() {
            self.println("Usage: deluser <name>");
            return true;
        }
        let deleting_self = self
            .current_username(user_index)
            .map(|name| name == args[0])
            .unwrap_or(false);
        match self.send_user_command(security::CMD_USER_DELETE, args[0], None, None) {
            Ok(_) => {
                self.println("User removed.");
                if deleting_self {
                    self.println("Current user removed; logging out.");
                    self.end_session();
                    return false;
                }
            }
            Err(err) => self.println(err),
        }
        true
    }

    fn cmd_service_control(&mut self, user_index: usize, args: &Vec<&str, 4>) -> bool {
        if args.is_empty() {
            self.println("Usage: service <list|restart> [name]");
            return true;
        }
        match args[0] {
            "list" => match self.launchd_request(launchd::CMD_LIST_SERVICES, &[]) {
                Ok(resp) if resp.code == 0 => {
                    let listing = extract_string(&resp.payload);
                    if listing.is_empty() {
                        self.println("\r\nNo registered services.");
                    } else {
                        self.println("\r\nServices:");
                        for line in listing.lines() {
                            self.print("  - ");
                            self.println(line);
                        }
                    }
                }
                Ok(_) => self.println("launchd rejected the request."),
                Err(err) => self.println(err),
            },
            "restart" => {
                if !self.is_admin(user_index) {
                    self.println("Permission denied: admin only.");
                    return true;
                }
                if args.len() < 2 {
                    self.println("Usage: service restart <name>");
                    return true;
                }
                let name = args[1];
                let mut payload = [0u8; 64];
                let bytes = name.as_bytes();
                if bytes.len() + 1 > payload.len() {
                    self.println("Service name too long.");
                    return true;
                }
                payload[..bytes.len()].copy_from_slice(bytes);
                payload[bytes.len()] = 0;
                match self.launchd_request(launchd::CMD_RESTART_SERVICE, &payload) {
                    Ok(resp) if resp.code == 0 => self.println("Service restart requested."),
                    Ok(_) => self.println("Service restart failed."),
                    Err(err) => self.println(err),
                }
            }
            _ => self.println("Usage: service <list|restart> [name]"),
        }
        true
    }

    fn cmd_sessions(&mut self, user_index: usize) -> bool {
        if !self.is_admin(user_index) {
            self.println("Permission denied: admin only.");
            return true;
        }
        let sessions = SESSION_TRACKER.snapshot();
        if sessions.is_empty() {
            self.println("\r\nNo recorded sessions.");
            return true;
        }
        self.println("\r\nSession table:");
        for record in sessions.iter() {
            self.print("  [#");
            self.print_u64(record.id);
            self.print("] ");
            self.print(record.username.as_str());
            self.print(" - ");
            self.println(if record.active { "active" } else { "closed" });
        }
        true
    }

    fn cmd_dashboard(&mut self, user_index: usize) -> bool {
        self.println("\r\n==== Zero OS Dashboard ====");
        if let Some(user) = self.user_at(user_index) {
            self.print("User: ");
            self.print(user.username.as_str());
            self.print(" (");
            self.print(user.role.as_str());
            self.println(")");
        } else {
            self.println("User: (unknown)");
        }
        let sessions = SESSION_TRACKER.snapshot();
        let active = sessions.iter().filter(|session| session.active).count();
        self.print("Active sessions: ");
        self.print_usize(active);
        self.print(" / ");
        self.print_usize(sessions.len());
        self.println("");
        match self.launchd_request(launchd::CMD_LIST_SERVICES, &[]) {
            Ok(resp) if resp.code == 0 => {
                self.println("\r\nServices:");
                let listing = extract_string(&resp.payload);
                if listing.is_empty() {
                    self.println("  (no services)");
                } else {
                    for line in listing.lines() {
                        self.print("  - ");
                        self.println(line);
                    }
                }
            }
            Ok(_) => self.println("Services: unavailable (launchd error)"),
            Err(err) => self.println(err),
        }
        let apps = APP_REGISTRY.snapshot();
        self.print("\r\nInstalled apps: ");
        self.print_usize(apps.len());
        if !apps.is_empty() {
            self.println("");
            for app in apps.iter() {
                self.print("  - ");
                self.print(app.name.as_str());
                self.print(" v");
                self.print(app.version.as_str());
                self.print(" -> ");
                self.print(app.binary.as_str());
                self.print(" [keepalive=");
                self.print(if app.keep_alive { "yes" } else { "no" });
                self.print("]");
                self.print(" storage ");
                self.println(app.storage.as_str());
            }
        } else {
            self.println("");
        }
        true
    }

    fn cmd_app(&mut self, user_index: usize, args: &Vec<&str, 4>) -> bool {
        if args.is_empty() {
            self.println("Usage: app <list|install|remove|info|launch> ...");
            return true;
        }
        match args[0] {
            "list" => {
                let apps = APP_REGISTRY.snapshot();
                if apps.is_empty() {
                    self.println("\r\nNo applications registered.");
                } else {
                    self.println("\r\nInstalled applications:");
                    for app in apps.iter() {
                        self.print("  - ");
                        self.print(app.name.as_str());
                        self.print(" v");
                        self.print(app.version.as_str());
                        self.print(" -> ");
                        self.print(app.binary.as_str());
                        self.print(" [storage ");
                        self.print(app.storage.as_str());
                        self.print(", keepalive=");
                        self.println(if app.keep_alive { "yes" } else { "no" });
                    }
                }
            }
            "install" => {
                if !self.is_admin(user_index) {
                    self.println("Permission denied: admin only.");
                    return true;
                }
                if args.len() < 3 {
                    self.println("Usage: app install <name> <binary-path> [--version=X] [--storage=PATH] [--keepalive] [--force] [--skip-verify]");
                    return true;
                }
                let name = args[1];
                let binary = args[2];
                let mut version = "1.0.0";
                let mut storage_override: Option<&str> = None;
                let mut keep_alive_default = false;
                let mut force = false;
                let mut skip_verify = false;
                for opt in args.iter().skip(3) {
                    if let Some(value) = opt.strip_prefix("--version=") {
                        version = value;
                    } else if let Some(value) = opt.strip_prefix("--storage=") {
                        storage_override = Some(value);
                    } else {
                        match *opt {
                            "--keepalive" => keep_alive_default = true,
                            "--force" => force = true,
                            "--skip-verify" => skip_verify = true,
                            "" => {}
                            _ => {
                                self.println("Unknown option for app install.");
                                return true;
                            }
                        }
                    }
                }
                if version.len() > APP_VERSION_MAX {
                    self.println("Version string too long.");
                    return true;
                }
                let storage_path = match build_storage_path(name, storage_override) {
                    Ok(path) => path,
                    Err(err) => {
                        self.println(err);
                        return true;
                    }
                };
                if !skip_verify && !binary_exists(binary) {
                    self.println(
                        "Binary not found in rootfs. Use --skip-verify to bypass this check.",
                    );
                    return true;
                }
                match APP_REGISTRY.install(
                    name,
                    binary,
                    version,
                    storage_path.as_str(),
                    keep_alive_default,
                    force,
                ) {
                    Ok(outcome) => {
                        match outcome {
                            InstallOutcome::Created => self.println("Application registered."),
                            InstallOutcome::Updated => self.println("Application updated."),
                        }
                        let actor = self.current_username(user_index).unwrap_or("unknown");
                        AUDIT_LOG.app_install(actor);
                    }
                    Err(err) => self.println(err),
                }
            }
            "remove" => {
                if !self.is_admin(user_index) {
                    self.println("Permission denied: admin only.");
                    return true;
                }
                if args.len() < 2 {
                    self.println("Usage: app remove <name>");
                    return true;
                }
                if APP_REGISTRY.remove(args[1]) {
                    self.println("Application removed.");
                    let actor = self.current_username(user_index).unwrap_or("unknown");
                    AUDIT_LOG.app_remove(actor);
                } else {
                    self.println("Application not found.");
                }
            }
            "info" => {
                if args.len() < 2 {
                    self.println("Usage: app info <name>");
                    return true;
                }
                if let Some(app) = APP_REGISTRY.find(args[1]) {
                    self.println("\r\nApplication info:");
                    self.print("  Name: ");
                    self.println(app.name.as_str());
                    self.print("  Version: ");
                    self.println(app.version.as_str());
                    self.print("  Binary: ");
                    self.println(app.binary.as_str());
                    self.print("  Storage: ");
                    self.println(app.storage.as_str());
                    self.print("  Keepalive default: ");
                    self.println(if app.keep_alive { "yes" } else { "no" });
                } else {
                    self.println("Application not found.");
                }
            }
            "launch" => {
                if args.len() < 2 {
                    self.println("Usage: app launch <name> [--keepalive|--once] [--foreground|--background|--mode=...]");
                    return true;
                }
                if let Some(app) = APP_REGISTRY.find(args[1]) {
                    let mut keep_alive = app.keep_alive;
                    let mut foreground = false;
                    for opt in args.iter().skip(2) {
                        if let Some(mode) = opt.strip_prefix("--mode=") {
                            match mode {
                                "foreground" => foreground = true,
                                "background" => foreground = false,
                                _ => {
                                    self.println("Unknown mode for app launch.");
                                    return true;
                                }
                            }
                            continue;
                        }
                        match *opt {
                            "--keepalive" => keep_alive = true,
                            "--once" => keep_alive = false,
                            "--foreground" => foreground = true,
                            "--background" => foreground = false,
                            "" => {}
                            _ => {
                                self.println("Unknown option for app launch.");
                                return true;
                            }
                        }
                    }
                    match self.start_application(
                        app.name.as_str(),
                        app.binary.as_str(),
                        keep_alive,
                        foreground,
                    ) {
                        Ok(msg) => {
                            if msg.is_empty() {
                                self.println("Application launch requested.");
                            } else {
                                self.println(msg.as_str());
                            }
                            let actor = self.current_username(user_index).unwrap_or("unknown");
                            AUDIT_LOG.app_launch(actor, self.session_id);
                        }
                        Err(err) => self.println(err.as_str()),
                    }
                } else {
                    self.println("Application not found.");
                }
            }
            _ => self.println("Usage: app <list|install|remove|info|launch> ..."),
        }
        true
    }

    fn is_admin(&self, user_index: usize) -> bool {
        matches!(
            self.user_at(user_index).map(|u| u.role),
            Some(UserRole::Admin)
        )
    }

    fn current_username(&self, user_index: usize) -> Option<&str> {
        self.user_at(user_index).map(|u| u.username.as_str())
    }

    fn user_at(&self, user_index: usize) -> Option<&UserRecord> {
        self.user_cache.get(user_index)
    }

    fn read_into<const N: usize>(&mut self, out: &mut String<N>, echo: bool) -> bool {
        if let Some(line) = self.read_line_internal(echo) {
            out.clear();
            if out.push_str(line.trim()).is_err() {
                return false;
            }
            true
        } else {
            false
        }
    }

    fn read_line_internal<'a>(&'a mut self, echo: bool) -> Option<&'a str> {
        self.line.clear();
        loop {
            let mut byte = [0u8; 1];
            match console_read(&mut byte) {
                Ok(0) => continue,
                Ok(_) => {
                    let ch = byte[0];
                    match ch {
                        b'\r' | b'\n' => {
                            self.print("\r\n");
                            return str::from_utf8(self.line.as_bytes()).ok();
                        }
                        8 | 127 => {
                            if !self.line.is_empty() {
                                self.line.pop();
                                if echo {
                                    self.print("\x08 \x08");
                                }
                            }
                        }
                        0x20..=0x7e => {
                            if self.line.push(ch as char).is_ok() && echo {
                                let _ = console_write(&[ch]);
                            }
                        }
                        _ => {}
                    }
                }
                Err(SysError::WouldBlock) => yield_now(),
                Err(_) => return None,
            }
        }
    }

    fn print_prompt(&self, user_index: usize) {
        self.print("\r\n");
        if let Some(user) = self.user_at(user_index) {
            self.print(user.username.as_str());
            self.print("@zero");
            let prompt = if user.role == UserRole::Admin {
                "# "
            } else {
                "$ "
            };
            self.print(prompt);
        } else {
            self.print("zero$ ");
        }
    }

    fn print(&self, text: &str) {
        let _ = console_write(text.as_bytes());
    }

    fn println(&self, text: &str) {
        self.print(text);
        self.print("\r\n");
    }

    fn cmd_whoami(&mut self, user_index: usize) -> bool {
        if let Some(user) = self.user_at(user_index) {
            self.println("");
            self.println(user.username.as_str());
        }
        true
    }

    fn cmd_who(&mut self, user_index: usize) -> bool {
        if let Some(user) = self.user_at(user_index) {
            self.print("\r\nUser: ");
            self.print(user.username.as_str());
            self.print("  Role: ");
            self.println(user.role.as_str());
        }
        true
    }

    fn cmd_last(&mut self) -> bool {
        let events = AUDIT_LOG.snapshot();
        if events.is_empty() {
            self.println("\r\nNo audit events recorded.");
            return true;
        }
        self.println("\r\nRecent activity:");
        for event in events.iter().rev() {
            self.print("  [#");
            self.print_u64(event.sequence);
            self.print("] ");
            self.print(event.kind.as_str());
            self.print(" ");
            self.print(event.username.as_str());
            if let Some(id) = event.session_id {
                self.print(" (session #");
                self.print_u64(id);
                self.print(")");
            }
            self.println("");
        }
        true
    }

    fn cmd_switch_user(&mut self, user_index: &mut usize, args: &Vec<&str, 4>) -> bool {
        if args.is_empty() {
            self.println("Usage: su <username>");
            return true;
        }
        let target = args[0];
        let mut password = String::<PASSWORD_MAX>::new();
        self.print("password: ");
        if !self.read_into(&mut password, false) {
            self.println("");
            return true;
        }
        self.println("");
        if self.verify_credentials(target, password.as_str()) {
            let _ = self.refresh_user_cache();
            if let Some(idx) = self
                .user_cache
                .iter()
                .position(|u| u.username.as_str() == target)
            {
                *user_index = idx;
                self.rename_session(target);
                self.println("Switched user.");
            } else {
                self.println("User not present in directory.");
            }
        } else {
            self.println("Authentication failed.");
            AUDIT_LOG.failed(target);
        }
        true
    }

    fn begin_session(&mut self, username: &str) {
        self.end_session();
        self.session_id = SESSION_TRACKER.register(username);
        self.session_user = clone_username(username);
        AUDIT_LOG.login(username, self.session_id);
    }

    fn end_session(&mut self) {
        let username = self.session_user.take();
        if let Some(id) = self.session_id.take() {
            SESSION_TRACKER.deactivate(id);
            let name = username
                .as_ref()
                .map(|value| value.as_str())
                .unwrap_or("unknown");
            AUDIT_LOG.logout(name, Some(id));
            return;
        }
        if let Some(name) = username {
            AUDIT_LOG.logout(name.as_str(), None);
        }
    }

    fn rename_session(&mut self, username: &str) {
        self.session_user = clone_username(username);
        if let Some(id) = self.session_id {
            SESSION_TRACKER.rename(id, username);
            AUDIT_LOG.switch(username, Some(id));
        } else {
            AUDIT_LOG.switch(username, None);
        }
    }

    fn print_u64(&self, value: u64) {
        let mut buffer = String::<20>::new();
        let _ = write!(&mut buffer, "{}", value);
        self.print(buffer.as_str());
    }

    fn print_usize(&self, value: usize) {
        self.print_u64(value as u64);
    }

    fn refresh_user_cache(&mut self) -> Result<(), &'static str> {
        let resp = self.security_request(security::CMD_USER_LIST, &[])?;
        if resp.code != 0 {
            return Err("securityd rejected list request");
        }
        let listing = extract_string(&resp.payload);
        self.user_cache.clear();
        for line in listing.lines() {
            let mut parts = line.split(':');
            let (Some(name), Some(role)) = (parts.next(), parts.next()) else {
                continue;
            };
            let role = if role == "admin" {
                UserRole::Admin
            } else {
                UserRole::User
            };
            if let Some(record) = UserRecord::new(name, role) {
                let _ = self.user_cache.push(record);
            }
        }
        Ok(())
    }

    fn verify_credentials(&self, username: &str, password: &str) -> bool {
        let mut buffer = [0u8; 128];
        if encode_fields(&mut buffer, &[username, password]).is_err() {
            self.println("credential payload too long");
            return false;
        }
        match self.security_request(security::CMD_USER_VERIFY, &buffer) {
            Ok(resp) => resp.code == 0,
            Err(err) => {
                self.println(err);
                false
            }
        }
    }

    fn send_user_command(
        &mut self,
        cmd: u32,
        username: &str,
        arg: Option<&str>,
        role: Option<UserRole>,
    ) -> Result<(), &'static str> {
        let mut fields = Vec::<&str, 4>::new();
        fields.push(username).map_err(|_| "payload full")?;
        if let Some(value) = arg {
            fields.push(value).map_err(|_| "payload full")?;
        }
        if let Some(role) = role {
            fields.push(role.as_str()).map_err(|_| "payload full")?;
        }
        let mut buffer = [0u8; 128];
        encode_fields(&mut buffer, fields.as_slice())?;
        let resp = self.security_request(cmd, &buffer)?;
        if resp.code == 0 {
            let _ = self.refresh_user_cache();
            Ok(())
        } else {
            Err("securityd rejected request")
        }
    }

    fn security_request(&self, code: u32, payload: &[u8]) -> Result<Message, &'static str> {
        let mut message = Message::empty();
        message.code = code;
        let len = payload.len().min(message.payload.len());
        message.payload[..len].copy_from_slice(&payload[..len]);
        userlib::ipc_send(channels::SECURITY_USER_REQ, &message)
            .map_err(|_| "securityd offline")?;
        self.wait_for_response(channels::SECURITY_USER_RESP)
    }

    fn launchd_request(&self, code: u32, payload: &[u8]) -> Result<Message, &'static str> {
        let mut message = Message::empty();
        message.code = code;
        let len = payload.len().min(message.payload.len());
        message.payload[..len].copy_from_slice(&payload[..len]);
        userlib::ipc_send(channels::LAUNCHD_CMD_REQ, &message).map_err(|_| "launchd offline")?;
        self.wait_for_response(channels::LAUNCHD_CMD_RESP)
    }

    fn start_application(
        &self,
        name: &str,
        binary: &str,
        keep_alive: bool,
        foreground: bool,
    ) -> Result<String<64>, String<64>> {
        let mut payload = [0u8; 128];
        let flags = (keep_alive as u8) | ((foreground as u8) << 1);
        encode_app_payload(&mut payload, name, binary, flags).map_err(|err| {
            let mut text = String::<64>::new();
            let _ = text.push_str(err);
            text
        })?;
        let resp = self
            .launchd_request(launchd::CMD_START_APPLICATION, &payload)
            .map_err(|err| {
                let mut text = String::<64>::new();
                let _ = text.push_str(err);
                text
            })?;
        if resp.code == 0 {
            let mut message = String::<64>::new();
            let text = extract_string(&resp.payload);
            if !text.is_empty() {
                let _ = message.push_str(text);
            }
            Ok(message)
        } else {
            let err = extract_string(&resp.payload);
            let mut text = String::<64>::new();
            if err.is_empty() {
                let _ = text.push_str("launchd rejected application start");
            } else {
                let _ = text.push_str(err);
            }
            Err(text)
        }
    }

    fn wait_for_response(&self, channel: u32) -> Result<Message, &'static str> {
        let mut response = Message::empty();
        loop {
            match userlib::ipc_receive(channel, &mut response) {
                Ok(_) => return Ok(response),
                Err(SysError::WouldBlock) => yield_now(),
                Err(_) => return Err("ipc receive failed"),
            }
        }
    }
}

fn clone_username(name: &str) -> Option<String<USERNAME_MAX>> {
    let mut out = String::<USERNAME_MAX>::new();
    out.push_str(name).ok()?;
    Some(out)
}

fn encode_fields(buffer: &mut [u8], fields: &[&str]) -> Result<(), &'static str> {
    let mut offset = 0;
    for field in fields {
        let bytes = field.as_bytes();
        if offset + bytes.len() + 1 > buffer.len() {
            return Err("payload too large");
        }
        buffer[offset..offset + bytes.len()].copy_from_slice(bytes);
        offset += bytes.len();
        buffer[offset] = 0;
        offset += 1;
    }
    Ok(())
}

fn extract_string(payload: &[u8]) -> &str {
    let len = payload
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(payload.len());
    core::str::from_utf8(&payload[..len]).unwrap_or("")
}

#[derive(Clone)]
struct SessionRecord {
    id: u64,
    username: String<USERNAME_MAX>,
    active: bool,
}

impl SessionRecord {
    fn new(id: u64, username: &str) -> Option<Self> {
        let mut name = String::<USERNAME_MAX>::new();
        name.push_str(username).ok()?;
        Some(Self {
            id,
            username: name,
            active: true,
        })
    }
}

struct SessionTracker {
    slots: Mutex<Vec<SessionRecord, MAX_SESSIONS>>,
    next_id: AtomicU64,
}

impl SessionTracker {
    const fn new() -> Self {
        Self {
            slots: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn register(&self, username: &str) -> Option<u64> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let Some(record) = SessionRecord::new(id, username) else {
            return None;
        };
        let mut slots = self.slots.lock();
        if slots.len() == slots.capacity() {
            let _ = slots.remove(0);
        }
        slots.push(record).ok()?;
        Some(id)
    }

    fn deactivate(&self, id: u64) {
        let mut slots = self.slots.lock();
        if let Some(entry) = slots.iter_mut().find(|session| session.id == id) {
            entry.active = false;
        }
    }

    fn rename(&self, id: u64, username: &str) {
        let mut slots = self.slots.lock();
        if let Some(entry) = slots.iter_mut().find(|session| session.id == id) {
            entry.username.clear();
            let _ = entry.username.push_str(username);
        }
    }

    fn snapshot(&self) -> Vec<SessionRecord, MAX_SESSIONS> {
        let slots = self.slots.lock();
        let mut out = Vec::new();
        for record in slots.iter() {
            let _ = out.push(record.clone());
        }
        out
    }
}

static SESSION_TRACKER: SessionTracker = SessionTracker::new();

#[derive(Clone, Copy)]
enum AuditEventKind {
    Login,
    Logout,
    FailedLogin,
    Switch,
    AppInstall,
    AppRemove,
    AppLaunch,
}

impl AuditEventKind {
    fn as_str(&self) -> &'static str {
        match self {
            AuditEventKind::Login => "login",
            AuditEventKind::Logout => "logout",
            AuditEventKind::FailedLogin => "failed",
            AuditEventKind::Switch => "switch",
            AuditEventKind::AppInstall => "app-install",
            AuditEventKind::AppRemove => "app-remove",
            AuditEventKind::AppLaunch => "app-launch",
        }
    }
}

#[derive(Clone)]
struct AuditEvent {
    sequence: u64,
    kind: AuditEventKind,
    username: String<USERNAME_MAX>,
    session_id: Option<u64>,
}

impl AuditEvent {
    fn new(
        sequence: u64,
        kind: AuditEventKind,
        username: &str,
        session_id: Option<u64>,
    ) -> Option<Self> {
        let mut name = String::<USERNAME_MAX>::new();
        name.push_str(username).ok()?;
        Some(Self {
            sequence,
            kind,
            username: name,
            session_id,
        })
    }
}

struct AuditLog {
    entries: Mutex<Vec<AuditEvent, MAX_AUDIT_EVENTS>>,
    counter: AtomicU64,
}

impl AuditLog {
    const fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            counter: AtomicU64::new(1),
        }
    }

    fn log(&self, kind: AuditEventKind, username: &str, session_id: Option<u64>) {
        let seq = self.counter.fetch_add(1, Ordering::SeqCst);
        let Some(event) = AuditEvent::new(seq, kind, username, session_id) else {
            return;
        };
        let mut entries = self.entries.lock();
        if entries.len() == entries.capacity() {
            let _ = entries.remove(0);
        }
        let _ = entries.push(event);
    }

    fn login(&self, username: &str, session_id: Option<u64>) {
        self.log(AuditEventKind::Login, username, session_id);
    }

    fn logout(&self, username: &str, session_id: Option<u64>) {
        self.log(AuditEventKind::Logout, username, session_id);
    }

    fn failed(&self, username: &str) {
        self.log(AuditEventKind::FailedLogin, username, None);
    }

    fn switch(&self, username: &str, session_id: Option<u64>) {
        self.log(AuditEventKind::Switch, username, session_id);
    }

    fn app_install(&self, username: &str) {
        self.log(AuditEventKind::AppInstall, username, None);
    }

    fn app_remove(&self, username: &str) {
        self.log(AuditEventKind::AppRemove, username, None);
    }

    fn app_launch(&self, username: &str, session_id: Option<u64>) {
        self.log(AuditEventKind::AppLaunch, username, session_id);
    }

    fn snapshot(&self) -> Vec<AuditEvent, MAX_AUDIT_EVENTS> {
        let entries = self.entries.lock();
        let mut out = Vec::new();
        for event in entries.iter() {
            let _ = out.push(event.clone());
        }
        out
    }
}

static AUDIT_LOG: AuditLog = AuditLog::new();
