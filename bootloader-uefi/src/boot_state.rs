use alloc::format;
use core::str;
use uefi::Status;

use crate::boot_config::BootVariant;
use crate::fs::FileSystem;

const STATE_PATH: &str = "\\EFI\\ZEROOS\\boot.env";
const MAX_FAILURES: u32 = 3;

#[derive(Clone, Debug)]
pub struct BootState {
    boot_failures: u32,
    boot_success: bool,
}

impl Default for BootState {
    fn default() -> Self {
        Self {
            boot_failures: 0,
            boot_success: false,
        }
    }
}

impl BootState {
    pub fn load(fs: &mut FileSystem<'_>) -> Result<Self, Status> {
        match fs.read_to_vec(STATE_PATH) {
            Ok(bytes) => Ok(parse_state(&bytes)),
            Err(_) => Ok(Self::default()),
        }
    }

    pub fn consume_success_flag(&mut self) -> bool {
        if self.boot_success {
            self.boot_success = false;
            self.boot_failures = 0;
            true
        } else {
            false
        }
    }

    pub fn should_force_recovery(&self) -> bool {
        self.boot_failures >= MAX_FAILURES && !self.boot_success
    }

    pub fn failures(&self) -> u32 {
        self.boot_failures
    }

    pub fn record_attempt(
        &mut self,
        fs: &mut FileSystem<'_>,
        variant: BootVariant,
    ) -> Result<(), Status> {
        if variant == BootVariant::Normal {
            self.boot_success = false;
            if self.boot_failures < MAX_FAILURES {
                self.boot_failures += 1;
            }
        }
        self.persist(fs)
    }

    pub fn persist(&self, fs: &mut FileSystem<'_>) -> Result<(), Status> {
        let content = format!(
            "boot_failures={}\nboot_success={}\n",
            self.boot_failures,
            if self.boot_success { 1 } else { 0 }
        );
        match fs.write_file(STATE_PATH, content.as_bytes()) {
            Ok(_) => Ok(()),
            Err(Status::WRITE_PROTECTED) => {
                log_warn!("boot state storage is read-only; skipping persist");
                Ok(())
            }
            Err(status) => Err(status),
        }
    }
}

fn parse_state(bytes: &[u8]) -> BootState {
    let mut state = BootState::default();
    if let Ok(text) = str::from_utf8(bytes) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                match key {
                    "boot_failures" => {
                        if let Ok(parsed) = value.trim().parse() {
                            state.boot_failures = parsed;
                        }
                    }
                    "boot_success" => {
                        let normalized = value.trim().to_ascii_lowercase();
                        state.boot_success =
                            normalized == "1" || normalized == "true" || normalized == "yes";
                    }
                    _ => {}
                }
            }
        }
    }
    state
}
