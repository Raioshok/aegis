use aegis_core::{
    AccessEvent, BlockSets, Connection, Detection, GateVerdict, MapRegion, ProcessEvent,
    Result, SandboxPolicy,
};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub trait EventStream: Send {
    fn next_event(&mut self) -> Option<AccessEvent>;
}

pub trait FileEventSource: Send + Sync {
    fn start(&self, roots: &[PathBuf]) -> Result<Box<dyn EventStream>>;
    fn can_block(&self) -> bool;
}

pub trait AccessGate: Send + Sync {
    fn respond(&self, ev: &AccessEvent, verdict: GateVerdict) -> Result<()>;
}

pub trait ProcStream: Send {
    fn next_event(&mut self) -> Option<ProcessEvent>;
}

pub trait ProcessEventSource: Send + Sync {
    fn start(&self) -> Result<Box<dyn ProcStream>>;
}

pub trait ProcessControl: Send + Sync {
    fn suspend(&self, pid: u32) -> Result<()>;
    fn resume(&self, pid: u32) -> Result<()>;
    fn kill(&self, pid: u32) -> Result<()>;
    fn image_path(&self, pid: u32) -> Option<PathBuf>;
    fn enumerate_pids(&self) -> Result<Vec<u32>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadAnomaly {
    pub tid: u32,
    pub pid: u32,
    pub rip: usize,
    pub start_address: usize,
    pub is_rip_unbacked: bool,
    pub is_start_unbacked: bool,
    pub teb_user_reserved: Option<[usize; 4]>,
    pub is_function_peekaboo: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleStompAnomaly {
    pub module_name: String,
    pub module_path: PathBuf,
    pub base_address: usize,
    pub text_rva: usize,
    pub text_size: usize,
    pub disk_sha256: String,
    pub mem_sha256: String,
}

pub trait MemoryInspector: Send + Sync {
    fn regions(&self, pid: u32) -> Result<Vec<MapRegion>>;
    fn read(&self, pid: u32, r: &MapRegion) -> Result<Vec<u8>>;
    fn find_unbacked_threads(&self, _pid: u32) -> Result<Vec<usize>> {
        Ok(Vec::new())
    }
    fn inspect_threads(&self, _pid: u32) -> Result<Vec<ThreadAnomaly>> {
        Ok(Vec::new())
    }
    fn detect_module_stomping(&self, _pid: u32) -> Result<Vec<ModuleStompAnomaly>> {
        Ok(Vec::new())
    }
}

pub trait NetFilter: Send + Sync {
    fn apply(&self, sets: &BlockSets) -> Result<()>;
    fn connections(&self) -> Vec<Connection>;
}

pub trait Sandbox: Send + Sync {
    fn spawn_confined(
        &self,
        cmd: &mut std::process::Command,
        policy: &SandboxPolicy,
    ) -> Result<std::process::Child>;
}

pub trait SecretStore: Send + Sync {
    fn load_or_create_vault_key(&self) -> Result<Zeroizing<[u8; 32]>>;
}

pub trait ServiceHost: Send + Sync {
    fn run(&self, name: &str, main_fn: Box<dyn FnOnce() + Send>) -> Result<()>;
}

pub trait SystemPaths: Send + Sync {
    fn config_dir(&self) -> PathBuf;
    fn data_dir(&self) -> PathBuf;
    fn runtime_dir(&self) -> PathBuf;
    fn quarantine_dir(&self) -> PathBuf {
        self.data_dir().join("quarantine")
    }
}

pub trait IntegrityChecks: Send + Sync {
    fn scan(&self) -> Vec<Detection>;
}

pub trait AutoStart: Send + Sync {
    fn is_enabled(&self) -> bool;
    fn set_enabled(&self, enabled: bool, app_path: &Path) -> Result<()>;
}

/// Detailed metadata for a known vulnerable driver from LOLDrivers / Microsoft blocklist.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VulnerableDriverInfo {
    pub name: String,
    pub sha256: String,
    pub cve: Option<String>,
    pub vendor: String,
    pub description: String,
}

impl VulnerableDriverInfo {
    pub fn new(
        name: impl Into<String>,
        sha256: impl Into<String>,
        cve: Option<impl Into<String>>,
        vendor: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            sha256: sha256.into().to_ascii_lowercase(),
            cve: cve.map(|c| c.into()),
            vendor: vendor.into(),
            description: description.into(),
        }
    }
}

/// Audit verdict for a driver binary or hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverAuditVerdict {
    /// Driver is safe, clean, and not on any blocklist.
    Allowed {
        sha256: String,
    },
    /// Driver is blocked due to known vulnerability / BYOVD risk.
    Blocked {
        sha256: String,
        reason: String,
        driver_info: Option<VulnerableDriverInfo>,
    },
}

impl DriverAuditVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }

    pub fn sha256(&self) -> &str {
        match self {
            Self::Allowed { sha256 } => sha256,
            Self::Blocked { sha256, .. } => sha256,
        }
    }
}

/// Platform-level security checks and defenses (BYOVD driver blocking, vulnerability auditing).
pub trait PlatformSecurity: Send + Sync {
    /// Check whether a driver hash (SHA-256 hex string, case-insensitive) is present
    /// in the known vulnerable driver blocklist.
    fn is_driver_hash_blocked(&self, sha256_hex: &str) -> bool;

    /// Retrieve metadata for a vulnerable driver by its SHA-256 hash if blocklisted.
    fn get_vulnerable_driver_info(&self, sha256_hex: &str) -> Option<VulnerableDriverInfo>;

    /// Audit a driver file on disk by computing its SHA-256 digest, checking the blocklist,
    /// and verifying signature authenticity.
    fn audit_driver_file(&self, path: &Path) -> Result<DriverAuditVerdict>;

    /// Audit a driver image before service load or driver registration.
    /// Returns Ok(()) if the driver is permitted, or AegisError::Permission if blocked.
    fn verify_driver_load(&self, service_name: &str, image_path: &Path) -> Result<()>;

    /// Audit registered kernel drivers on the system and return detections for any vulnerable drivers found.
    fn audit_registered_drivers(&self) -> Vec<Detection> {
        Vec::new()
    }
}

