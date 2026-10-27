//! Process Execution Directed Acyclic Graph (DAG) & Lineage Scoring Engine.
//!
//! Models OS process execution lifecycles as a directed graph to detect multi-stage
//! attacks, Living-off-the-Land (LOLBin) execution, and anomalous parent-child
//! relationships. Maps detections directly to MITRE ATT&CK techniques.
//!
//! Features first-class support for AI-agent lineage tracking (Cursor, Claude Code,
//! Copilot agent mode, OpenCode, Codex, Ollama, LM Studio), distinguishing legitimate
//! developer tool execution from anomalous agent-context tampering.

use aegis_core::{ProcessEvent, ProcessEventKind, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::RwLock;

/// Known AI Agent, IDE, or Local LLM Runner context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentType {
    Cursor,
    ClaudeCode,
    Copilot,
    OpenCode,
    Codex,
    Ollama,
    LmStudio,
    JettsTUI,
    Windsurf,
    Aider,
    Devin,
    CustomAgent,
}

impl AgentType {
    pub fn label(self) -> &'static str {
        match self {
            Self::Cursor => "Cursor Agent",
            Self::ClaudeCode => "Claude Code",
            Self::Copilot => "GitHub Copilot",
            Self::OpenCode => "OpenCode CLI",
            Self::Codex => "Codex Agent",
            Self::Ollama => "Ollama Local LLM",
            Self::LmStudio => "LM Studio",
            Self::JettsTUI => "JettsTUI Desktop Agent",
            Self::Windsurf => "Windsurf IDE Agent",
            Self::Aider => "Aider Coding Agent",
            Self::Devin => "Devin Autonomous Agent",
            Self::CustomAgent => "AI Agent Context",
        }
    }
}

/// A node in the Process Execution Directed Acyclic Graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe: PathBuf,
    pub cmdline: Vec<String>,
    pub cmdline_entropy: f64,
    pub timestamp_ms: u64,
    pub is_signed: bool,
    pub signer: Option<String>,
    pub risk_score: u8,
    pub risk_factors: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub is_agent_context: bool,
    pub agent_type: Option<AgentType>,
    pub depth: u32,
    pub children: Vec<u32>,
}

/// A directed edge connecting a parent process to a child execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEdge {
    pub parent_pid: u32,
    pub child_pid: u32,
    pub timestamp_ms: u64,
    pub anomaly_score: u8,
    pub reasons: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

/// An anomaly alert raised by lineage scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageAlert {
    pub alert_id: String,
    pub parent_pid: u32,
    pub parent_name: String,
    pub parent_exe: PathBuf,
    pub child_pid: u32,
    pub child_name: String,
    pub child_exe: PathBuf,
    pub child_cmdline: String,
    pub severity: Severity,
    pub threat: String,
    pub risk_score: u8,
    pub mitre_techniques: Vec<String>,
    pub explanation: String,
    pub agent_context: Option<String>,
    pub timestamp_ms: u64,
}

/// Tree hierarchy node formatted for UI tree-view components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeNodeDto {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub risk_score: u8,
    pub is_signed: bool,
    pub is_agent_context: bool,
    pub agent_type_label: Option<String>,
    pub mitre_techniques: Vec<String>,
    pub children: Vec<ProcessTreeNodeDto>,
}

/// Full snapshot of the live Process Execution DAG for UI and IPC consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDagSnapshot {
    pub total_nodes: usize,
    pub root_processes: usize,
    pub active_alerts: usize,
    pub nodes: Vec<ProcessNode>,
    pub alerts: Vec<LineageAlert>,
    pub trees: Vec<ProcessTreeNodeDto>,
}

/// Calculate Shannon entropy (bits per byte, 0.0 to 8.0) of a string slice.
pub fn calculate_entropy(s: &str) -> f64 {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let len_f = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &count in freq.iter() {
        if count > 0 {
            let p = count as f64 / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Thread-safe in-memory Directed Acyclic Graph tracking OS process execution trees.
pub struct ProcessTreeDag {
    nodes: RwLock<HashMap<u32, ProcessNode>>,
    root_pids: RwLock<HashSet<u32>>,
    alerts: RwLock<Vec<LineageAlert>>,
    max_nodes: usize,
}

impl Default for ProcessTreeDag {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessTreeDag {
    pub fn new() -> Self {
        Self::with_capacity(2048)
    }

    pub fn with_capacity(max_nodes: usize) -> Self {
        Self {
            nodes: RwLock::new(HashMap::with_capacity(max_nodes)),
            root_pids: RwLock::new(HashSet::new()),
            alerts: RwLock::new(Vec::new()),
            max_nodes,
        }
    }

    /// Identify whether an executable or command-line represents an AI coding agent or LLM runner.
    pub fn detect_agent_context(exe_name: &str, cmdline_lower: &str) -> Option<AgentType> {
        let exe = exe_name.to_ascii_lowercase();
        if exe.contains("cursor") || cmdline_lower.contains("cursor-agent") || cmdline_lower.contains(".cursor") {
            return Some(AgentType::Cursor);
        }
        if exe == "claude" || exe == "claude.exe" || cmdline_lower.contains("claude-code") || cmdline_lower.contains("@anthropic-ai/claude-code") {
            return Some(AgentType::ClaudeCode);
        }
        if exe.contains("copilot") || cmdline_lower.contains("copilot-agent") || cmdline_lower.contains("github.copilot") {
            return Some(AgentType::Copilot);
        }
        if exe.contains("opencode") || cmdline_lower.contains("opencode-cli") {
            return Some(AgentType::OpenCode);
        }
        if exe.contains("codex") || cmdline_lower.contains("openai-codex") {
            return Some(AgentType::Codex);
        }
        if exe.contains("ollama") {
            return Some(AgentType::Ollama);
        }
        if exe.contains("lmstudio") || exe.contains("lm-studio") {
            return Some(AgentType::LmStudio);
        }
        if exe.contains("jetts") || cmdline_lower.contains("jettstui") || cmdline_lower.contains("jetts") {
            return Some(AgentType::JettsTUI);
        }
        if exe.contains("windsurf") || cmdline_lower.contains("windsurf") || cmdline_lower.contains("codeium") {
            return Some(AgentType::Windsurf);
        }
        if exe.contains("aider") || cmdline_lower.contains("aider") {
            return Some(AgentType::Aider);
        }
        if exe.contains("devin") || cmdline_lower.contains("devin") {
            return Some(AgentType::Devin);
        }
        if cmdline_lower.contains("--agent") || cmdline_lower.contains("mcp-server") || cmdline_lower.contains("modelcontextprotocol") {
            return Some(AgentType::CustomAgent);
        }
        None
    }

    /// Ingest a process execution event, insert the node into the DAG, and score the lineage.
    pub fn add_process(
        &self,
        event: &ProcessEvent,
        is_signed: bool,
        signer: Option<String>,
    ) -> Vec<LineageAlert> {
        if event.kind == ProcessEventKind::Exit {
            self.remove_process(event.pid);
            return Vec::new();
        }

        let cmdline_str = event.cmdline.join(" ");
        let cmdline_lower = cmdline_str.to_ascii_lowercase();
        let cmdline_entropy = calculate_entropy(&cmdline_str);

        // Split on both separators: Windows-style paths also reach Linux hosts (e.g. guest telemetry).
        let exe_name = event
            .exe
            .to_string_lossy()
            .rsplit(['/', '\\'])
            .next()
            .filter(|n| !n.is_empty())
            .unwrap_or("process")
            .to_string();
        let exe_name_lower = exe_name.to_ascii_lowercase();

        // 1. Detect AI Agent context or inherit from parent
        let direct_agent = Self::detect_agent_context(&exe_name, &cmdline_lower);
        let mut is_agent_context = direct_agent.is_some();
        let mut agent_type = direct_agent;
        let mut depth = 0u32;
        let mut parent_node_opt = None;

        if let Ok(nodes) = self.nodes.read() {
            if let Some(parent) = nodes.get(&event.ppid) {
                depth = parent.depth.saturating_add(1);
                parent_node_opt = Some(parent.clone());
                if !is_agent_context && parent.is_agent_context {
                    is_agent_context = true;
                    agent_type = parent.agent_type;
                }
            }
        }

        let mut risk_score = 0u8;
        let mut risk_factors = Vec::new();
        let mut mitre_techniques = Vec::new();
        let mut new_alerts = Vec::new();

        // 2. Unsigned execution in temporary or user directories
        let path_str = event.exe.to_string_lossy().to_ascii_lowercase();
        let is_in_temp = path_str.contains("temp")
            || path_str.contains("tmp")
            || path_str.contains("/dev/shm")
            || path_str.contains("appdata\\local\\temp");

        if is_in_temp {
            risk_score = risk_score.saturating_add(25);
            risk_factors.push("Executed from temporary/world-writable path".into());
            mitre_techniques.push("T1059".into());
        }

        if !is_signed && is_in_temp {
            risk_score = risk_score.saturating_add(30);
            risk_factors.push("Unsigned binary executed from temp path".into());
            mitre_techniques.push("T1055".into());
        }

        // 3. Command-line entropy / encoded payload check
        if cmdline_str.len() > 60 && cmdline_entropy >= 6.2 {
            risk_score = risk_score.saturating_add(30);
            risk_factors.push(format!("High command-line entropy ({:.2} bits/byte, obfuscated/encoded)", cmdline_entropy));
            mitre_techniques.push("T1027".into());
        }

        // 4. Lineage-specific parent-child relationship scoring
        if let Some(parent) = parent_node_opt.as_ref() {
            let p_name = parent.name.to_ascii_lowercase();

            // Lineage Case A: Document Reader / Phishing Initial Access -> Shell / LOLBin
            let is_doc_reader = p_name.contains("winword")
                || p_name.contains("excel")
                || p_name.contains("powerpnt")
                || p_name.contains("acrobat")
                || p_name.contains("acrord32")
                || p_name.contains("foxit")
                || p_name.contains("outlook");

            let is_shell_or_lolbin = exe_name_lower == "powershell.exe"
                || exe_name_lower == "powershell"
                || exe_name_lower == "cmd.exe"
                || exe_name_lower == "cmd"
                || exe_name_lower == "wscript.exe"
                || exe_name_lower == "cscript.exe"
                || exe_name_lower == "mshta.exe"
                || exe_name_lower == "certutil.exe"
                || exe_name_lower == "bitsadmin.exe"
                || exe_name_lower == "curl.exe"
                || exe_name_lower == "rundll32.exe"
                || exe_name_lower == "bash"
                || exe_name_lower == "sh";

            if is_doc_reader && is_shell_or_lolbin {
                risk_score = 95;
                risk_factors.push(format!("Office document parent ({}) spawned command interpreter ({})", parent.name, exe_name));
                mitre_techniques.push("T1204.002".into());
                mitre_techniques.push("T1059.001".into());
                mitre_techniques.push("T1566".into());

                new_alerts.push(LineageAlert {
                    alert_id: format!("DAG-DOC-{}", event.pid),
                    parent_pid: parent.pid,
                    parent_name: parent.name.clone(),
                    parent_exe: parent.exe.clone(),
                    child_pid: event.pid,
                    child_name: exe_name.clone(),
                    child_exe: event.exe.clone(),
                    child_cmdline: cmdline_str.clone(),
                    severity: Severity::Critical,
                    threat: "Lineage.DocumentSpawnedShell".into(),
                    risk_score: 95,
                    mitre_techniques: vec!["T1204.002".into(), "T1059.001".into(), "T1566".into()],
                    explanation: format!("Document reader {} (PID {}) spawned LOLBin shell {} (PID {})", parent.name, parent.pid, exe_name, event.pid),
                    agent_context: None,
                    timestamp_ms: event.timestamp_ms,
                });
            }

            // Lineage Case B: Web Server / Network Service Spawned Shell (RCE / Web Shell)
            let is_web_parent = p_name.contains("nginx")
                || p_name.contains("httpd")
                || p_name.contains("apache")
                || p_name.contains("w3wp")
                || p_name.contains("tomcat")
                || p_name.contains("caddy");

            let is_interactive_shell = exe_name_lower == "sh"
                || exe_name_lower == "bash"
                || exe_name_lower == "cmd.exe"
                || exe_name_lower == "powershell.exe"
                || exe_name_lower == "whoami"
                || exe_name_lower == "whoami.exe";

            if is_web_parent && is_interactive_shell {
                risk_score = 90;
                risk_factors.push(format!("Web service parent ({}) spawned command shell ({})", parent.name, exe_name));
                mitre_techniques.push("T1190".into());
                mitre_techniques.push("T1505.003".into());

                new_alerts.push(LineageAlert {
                    alert_id: format!("DAG-WEB-{}", event.pid),
                    parent_pid: parent.pid,
                    parent_name: parent.name.clone(),
                    parent_exe: parent.exe.clone(),
                    child_pid: event.pid,
                    child_name: exe_name.clone(),
                    child_exe: event.exe.clone(),
                    child_cmdline: cmdline_str.clone(),
                    severity: Severity::Critical,
                    threat: "Lineage.WebshellSpawn".into(),
                    risk_score: 90,
                    mitre_techniques: vec!["T1190".into(), "T1505.003".into(), "T1059".into()],
                    explanation: format!("Network/Web service {} (PID {}) spawned shell {} (PID {}) — potential Web Shell RCE", parent.name, parent.pid, exe_name, event.pid),
                    agent_context: None,
                    timestamp_ms: event.timestamp_ms,
                });
            }

            // Lineage Case C: AI-Agent Context Monitoring
            if is_agent_context {
                let agent_lbl = agent_type.map(|a| a.label()).unwrap_or("AI Agent");

                // Check for agent tool calling behavior:
                let is_build_tool = exe_name_lower.contains("cargo")
                    || exe_name_lower.contains("rustc")
                    || exe_name_lower.contains("npm")
                    || exe_name_lower.contains("node")
                    || exe_name_lower.contains("python")
                    || exe_name_lower.contains("git")
                    || exe_name_lower.contains("go");

                let is_egress_tool = exe_name_lower.contains("curl")
                    || exe_name_lower.contains("wget")
                    || exe_name_lower.contains("ssh")
                    || exe_name_lower.contains("scp")
                    || exe_name_lower.contains("ncat")
                    || exe_name_lower.contains("nc");

                let is_tamper_tool = cmdline_lower.contains("vssadmin")
                    || cmdline_lower.contains("bcdedit")
                    || cmdline_lower.contains("advfirewall")
                    || cmdline_lower.contains("sethc")
                    || cmdline_lower.contains("reg add")
                    || cmdline_lower.contains("taskkill /f /im aegis");

                if is_tamper_tool {
                    risk_score = 95;
                    risk_factors.push(format!("AI Agent context ({}) executed OS defense tampering or recovery suppression command", agent_lbl));
                    mitre_techniques.push("T1490".into());
                    mitre_techniques.push("T1562.001".into());

                    new_alerts.push(LineageAlert {
                        alert_id: format!("DAG-AGENT-TAMPER-{}", event.pid),
                        parent_pid: parent.pid,
                        parent_name: parent.name.clone(),
                        parent_exe: parent.exe.clone(),
                        child_pid: event.pid,
                        child_name: exe_name.clone(),
                        child_exe: event.exe.clone(),
                        child_cmdline: cmdline_str.clone(),
                        severity: Severity::Critical,
                        threat: "Agent.SecurityTampering".into(),
                        risk_score: 95,
                        mitre_techniques: vec!["T1490".into(), "T1562.001".into()],
                        explanation: format!("Child spawned by {} (PID {}) attempted security policy or shadow copy tampering: {}", agent_lbl, parent.pid, cmdline_str),
                        agent_context: Some(agent_lbl.to_string()),
                        timestamp_ms: event.timestamp_ms,
                    });
                } else if is_egress_tool {
                    risk_score = risk_score.max(35);
                    risk_factors.push(format!("AI Agent tool egress: {} spawned network transfer utility ({})", agent_lbl, exe_name));
                    mitre_techniques.push("T1105".into());
                    mitre_techniques.push("T1071".into());
                } else if is_build_tool {
                    // Benign expected developer activity in agent context
                    risk_score = risk_score.min(10);
                    risk_factors.push(format!("Expected developer build tool in {} context", agent_lbl));
                }
            }
        }

        // Deduplicate MITRE techniques
        mitre_techniques.sort();
        mitre_techniques.dedup();

        let node = ProcessNode {
            pid: event.pid,
            ppid: event.ppid,
            name: exe_name,
            exe: event.exe.clone(),
            cmdline: event.cmdline.clone(),
            cmdline_entropy,
            timestamp_ms: event.timestamp_ms,
            is_signed,
            signer,
            risk_score: risk_score.min(100),
            risk_factors,
            mitre_techniques,
            is_agent_context,
            agent_type,
            depth,
            children: Vec::new(),
        };

        // Insert into graph storage and update parent links
        if let Ok(mut nodes) = self.nodes.write() {
            // Memory bound enforcement: evict oldest if exceeding capacity
            if nodes.len() >= self.max_nodes {
                let oldest_pid = nodes
                    .iter()
                    .min_by_key(|(_, n)| n.timestamp_ms)
                    .map(|(p, _)| *p);
                if let Some(opid) = oldest_pid {
                    nodes.remove(&opid);
                }
            }

            if let Some(parent) = nodes.get_mut(&event.ppid) {
                if !parent.children.contains(&event.pid) {
                    parent.children.push(event.pid);
                }
            } else if let Ok(mut roots) = self.root_pids.write() {
                roots.insert(event.pid);
            }

            nodes.insert(event.pid, node);
        }

        if !new_alerts.is_empty() {
            if let Ok(mut alerts) = self.alerts.write() {
                alerts.extend(new_alerts.clone());
            }
        }

        new_alerts
    }

    /// Mark a process as terminated and remove from graph tracking.
    pub fn remove_process(&self, pid: u32) {
        if let Ok(mut nodes) = self.nodes.write() {
            if let Some(node) = nodes.remove(&pid) {
                if let Some(parent) = nodes.get_mut(&node.ppid) {
                    parent.children.retain(|c| *c != pid);
                }
            }
        }
        if let Ok(mut roots) = self.root_pids.write() {
            roots.remove(&pid);
        }
    }

    /// Retrieve a cloned node by PID.
    pub fn get_process(&self, pid: u32) -> Option<ProcessNode> {
        self.nodes.read().ok()?.get(&pid).cloned()
    }

    /// Get recent lineage alerts.
    pub fn get_alerts(&self, limit: usize) -> Vec<LineageAlert> {
        self.alerts
            .read()
            .map(|a| a.iter().rev().take(limit).cloned().collect())
            .unwrap_or_default()
    }

    /// Builds a full hierarchical tree DTO starting from a node PID.
    fn build_tree_dto(pid: u32, nodes: &HashMap<u32, ProcessNode>, visited: &mut HashSet<u32>) -> Option<ProcessTreeNodeDto> {
        if visited.contains(&pid) {
            return None; // Guard against cycles
        }
        visited.insert(pid);

        let node = nodes.get(&pid)?;
        let mut child_dtos = Vec::new();
        for &cid in &node.children {
            if let Some(child_dto) = Self::build_tree_dto(cid, nodes, visited) {
                child_dtos.push(child_dto);
            }
        }

        Some(ProcessTreeNodeDto {
            pid: node.pid,
            ppid: node.ppid,
            name: node.name.clone(),
            path: node.exe.to_string_lossy().into_owned(),
            risk_score: node.risk_score,
            is_signed: node.is_signed,
            is_agent_context: node.is_agent_context,
            agent_type_label: node.agent_type.map(|a| a.label().to_string()),
            mitre_techniques: node.mitre_techniques.clone(),
            children: child_dtos,
        })
    }

    /// Export an immutable snapshot of the DAG for UI rendering.
    pub fn snapshot(&self) -> ProcessDagSnapshot {
        let nodes_guard = match self.nodes.read() {
            Ok(g) => g,
            Err(_) => return ProcessDagSnapshot {
                total_nodes: 0,
                root_processes: 0,
                active_alerts: 0,
                nodes: Vec::new(),
                alerts: Vec::new(),
                trees: Vec::new(),
            },
        };

        let alerts = self.alerts.read().map(|a| a.clone()).unwrap_or_default();
        let mut trees = Vec::new();
        let mut visited = HashSet::new();

        // 1. First build trees from recognized roots
        if let Ok(roots) = self.root_pids.read() {
            for &rpid in roots.iter() {
                if let Some(tdto) = Self::build_tree_dto(rpid, &nodes_guard, &mut visited) {
                    trees.push(tdto);
                }
            }
        }

        // 2. Add any remaining unparented nodes as roots
        for (&pid, _) in nodes_guard.iter() {
            if !visited.contains(&pid) {
                if let Some(tdto) = Self::build_tree_dto(pid, &nodes_guard, &mut visited) {
                    trees.push(tdto);
                }
            }
        }

        // Sort trees by risk score descending
        trees.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));

        let mut node_list: Vec<ProcessNode> = nodes_guard.values().cloned().collect();
        node_list.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));

        ProcessDagSnapshot {
            total_nodes: nodes_guard.len(),
            root_processes: trees.len(),
            active_alerts: alerts.len(),
            nodes: node_list,
            alerts,
            trees,
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_computation() {
        assert_eq!(calculate_entropy(""), 0.0);
        let low_ent = calculate_entropy("aaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(low_ent, 0.0);
        let high_ent = calculate_entropy("JABzAHQAYQByAHQALQBwAHIAbwBjAGUAcwBzACAALQBGAGkAbABlAFAAYQB0AGgA");
        assert!(high_ent > 3.5);
    }

    #[test]
    fn test_dag_insertion_and_tree_hierarchy() {
        let dag = ProcessTreeDag::new();

        let p1 = ProcessEvent {
            pid: 1000,
            ppid: 1,
            exe: PathBuf::from("C:\\Windows\\System32\\services.exe"),
            cmdline: vec!["services.exe".into()],
            kind: ProcessEventKind::Exec,
            timestamp_ms: 100,
        };
        dag.add_process(&p1, true, Some("Microsoft Windows".into()));

        let p2 = ProcessEvent {
            pid: 1010,
            ppid: 1000,
            exe: PathBuf::from("C:\\Windows\\System32\\svchost.exe"),
            cmdline: vec!["svchost.exe".into(), "-k".into(), "netsvcs".into()],
            kind: ProcessEventKind::Exec,
            timestamp_ms: 110,
        };
        dag.add_process(&p2, true, Some("Microsoft Windows".into()));

        let snap = dag.snapshot();
        assert_eq!(snap.total_nodes, 2);
        assert_eq!(snap.root_processes, 1);
        assert_eq!(snap.trees[0].pid, 1000);
        assert_eq!(snap.trees[0].children.len(), 1);
        assert_eq!(snap.trees[0].children[0].pid, 1010);
    }

    #[test]
    fn test_document_reader_spawning_powershell_anomaly() {
        let dag = ProcessTreeDag::new();

        let doc = ProcessEvent {
            pid: 4004,
            ppid: 1000,
            exe: PathBuf::from("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
            cmdline: vec!["WINWORD.EXE".into(), "invoice.docx".into()],
            kind: ProcessEventKind::Exec,
            timestamp_ms: 200,
        };
        dag.add_process(&doc, true, Some("Microsoft Corporation".into()));

        let shell = ProcessEvent {
            pid: 4008,
            ppid: 4004,
            exe: PathBuf::from("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            cmdline: vec!["powershell.exe".into(), "-ExecutionPolicy".into(), "Bypass".into(), "-enc".into(), "JABz...".into()],
            kind: ProcessEventKind::Exec,
            timestamp_ms: 205,
        };
        let alerts = dag.add_process(&shell, true, Some("Microsoft Windows".into()));

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].threat, "Lineage.DocumentSpawnedShell");
        assert_eq!(alerts[0].risk_score, 95);
        assert!(alerts[0].mitre_techniques.contains(&"T1204.002".to_string()));
        assert!(alerts[0].mitre_techniques.contains(&"T1059.001".to_string()));

        let child_node = dag.get_process(4008).expect("child node");
        assert!(child_node.risk_score >= 95);
        assert!(child_node.mitre_techniques.contains(&"T1204.002".to_string()));
    }

    #[test]
    fn test_ai_agent_context_and_tool_call_scoring() {
        let dag = ProcessTreeDag::new();

        // 1. Spawning Cursor IDE Agent
        let agent = ProcessEvent {
            pid: 5000,
            ppid: 1000,
            exe: PathBuf::from("C:\\Users\\raio\\AppData\\Local\\Programs\\cursor\\Cursor.exe"),
            cmdline: vec!["Cursor.exe".into(), "--agent".into()],
            kind: ProcessEventKind::Exec,
            timestamp_ms: 300,
        };
        dag.add_process(&agent, true, Some("Anysphere Inc.".into()));

        let agent_node = dag.get_process(5000).expect("agent node");
        assert!(agent_node.is_agent_context);
        assert_eq!(agent_node.agent_type, Some(AgentType::Cursor));

        // 2. Agent compiling code via Cargo (expected benign dev activity)
        let build = ProcessEvent {
            pid: 5010,
            ppid: 5000,
            exe: PathBuf::from("C:\\Users\\raio\\.cargo\\bin\\cargo.exe"),
            cmdline: vec!["cargo.exe".into(), "build".into(), "--release".into()],
            kind: ProcessEventKind::Exec,
            timestamp_ms: 310,
        };
        let build_alerts = dag.add_process(&build, false, None);
        assert!(build_alerts.is_empty());
        let build_node = dag.get_process(5010).expect("build node");
        assert!(build_node.is_agent_context);
        assert_eq!(build_node.risk_score, 0); // benign developer activity

        // 3. Agent context attempting security tampering (e.g. prompt injection / rogue tool call)
        let tamper = ProcessEvent {
            pid: 5020,
            ppid: 5000,
            exe: PathBuf::from("C:\\Windows\\System32\\vssadmin.exe"),
            cmdline: vec!["vssadmin.exe".into(), "delete".into(), "shadows".into(), "/all".into(), "/quiet".into()],
            kind: ProcessEventKind::Exec,
            timestamp_ms: 320,
        };
        let tamper_alerts = dag.add_process(&tamper, true, Some("Microsoft Windows".into()));
        assert_eq!(tamper_alerts.len(), 1);
        assert_eq!(tamper_alerts[0].threat, "Agent.SecurityTampering");
        assert_eq!(tamper_alerts[0].risk_score, 95);
        assert!(tamper_alerts[0].mitre_techniques.contains(&"T1490".to_string()));
    }
}
