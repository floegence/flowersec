use crate::{Path, Stage};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCodeDomain {
    Error,
    Event,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticResult {
    Ok,
    Fail,
    Retry,
    Skip,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticEvent {
    pub v: u32,
    pub namespace: String,
    pub path: Path,
    pub stage: Stage,
    pub code_domain: DiagnosticCodeDomain,
    pub code: String,
    pub result: DiagnosticResult,
    pub elapsed_ms: f64,
    pub attempt_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

pub trait Observer: Send + Sync + 'static {
    fn on_diagnostic(&self, event: &DiagnosticEvent);
}

impl<F> Observer for F
where
    F: Fn(&DiagnosticEvent) + Send + Sync + 'static,
{
    fn on_diagnostic(&self, event: &DiagnosticEvent) {
        self(event);
    }
}

pub type SharedObserver = Arc<dyn Observer>;
