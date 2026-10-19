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
