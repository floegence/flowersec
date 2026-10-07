//! Trusted local scheduler presets. These values never alter signed Session
//! requirements or add fields to an authenticated application message.
use crate::environment_v4::EnvironmentError;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationResourceProfile {
    Custom,
    Client,
    Server,
    Constrained,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationExecutorConfig {
    pub profile: ApplicationResourceProfile,
    pub running: usize,
    pub ready: usize,
    pub resident_running: usize,
    pub resident_ready: usize,
    pub completion_running: usize,
    pub completion_reserved: usize,
    pub query_owners: usize,
    pub runtime_bytes: u64,
    pub runtime_bytes_per_task: u64,
    pub ordinary_bytes: u64,
    pub execution: bool,
    pub diagnostics: bool,
}
impl Default for ApplicationExecutorConfig {
    fn default() -> Self {
        Self {
            profile: ApplicationResourceProfile::Client,
            running: 26,
            ready: 52,
            resident_running: 18,
            resident_ready: 36,
            completion_running: 2,
            completion_reserved: 4096,
            query_owners: 12,
            runtime_bytes: 0,
            runtime_bytes_per_task: 0,
            ordinary_bytes: 7 << 20,
            execution: false,
            diagnostics: true,
        }
    }
}
impl ApplicationExecutorConfig {
    pub fn preset(
        profile: ApplicationResourceProfile,
        runtime_bytes: u64,
        runtime_bytes_per_task: u64,
        execution: bool,
        diagnostics: bool,
    ) -> Result<Self, EnvironmentError> {
        let mut config = Self {
            profile,
            runtime_bytes,
            runtime_bytes_per_task,
            execution,
            diagnostics,
            ..Self::default()
        };
        match profile {
            ApplicationResourceProfile::Client | ApplicationResourceProfile::Server => {}
            ApplicationResourceProfile::Constrained => {
                config.running = 8;
                config.ready = 16;
                config.resident_running = 6;
                config.resident_ready = 12;
                config.query_owners = 6;
                config.ordinary_bytes = 3 << 20;
            }
            ApplicationResourceProfile::Custom => return Err(EnvironmentError::Configuration),
        }
        config.validate()?;
        Ok(config)
    }
    pub(crate) fn validate(&self) -> Result<(), EnvironmentError> {
        let expected = match self.profile {
            ApplicationResourceProfile::Client | ApplicationResourceProfile::Server => {
                Some((26, 52, 18, 36, 7 << 20, 12))
            }
            ApplicationResourceProfile::Constrained => Some((8, 16, 6, 12, 3 << 20, 6)),
            ApplicationResourceProfile::Custom => None,
        };
        if expected.is_some_and(|expected| {
            expected
                != (
                    self.running,
                    self.ready,
                    self.resident_running,
                    self.resident_ready,
                    self.ordinary_bytes,
                    self.query_owners,
                )
        }) || self.running == 0
            || self.running > 4096
            || self.ready > 8192
            || self.resident_running > self.running
            || self.resident_ready > self.ready
            || self.completion_running != 2
            || self.completion_reserved == 0
            || self.completion_reserved > 4096
            || self.query_owners == 0
            || self.query_owners > 128
            || self.ordinary_bytes == 0
        {
            return Err(EnvironmentError::Configuration);
        }
        let tasks = self.running as u64;
        let slots = self
            .running
            .checked_add(self.ready)
            .ok_or(EnvironmentError::Configuration)? as u64;
        let reserved = self
            .runtime_bytes
            .checked_add(
                tasks
                    .checked_mul(self.runtime_bytes_per_task)
                    .ok_or(EnvironmentError::Configuration)?,
            )
            .and_then(|bytes| bytes.checked_add(slots * 4096 + 16384))
            .ok_or(EnvironmentError::Configuration)?;
        if reserved > self.ordinary_bytes
            || self
                .runtime_bytes_per_task
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(4 * 4096 + 8192))
                .is_none_or(|bytes| bytes > 256 << 10)
        {
            return Err(EnvironmentError::Configuration);
        }
        Ok(())
    }
    pub(crate) fn ordinary_slice(&self) -> u64 {
        (self.ordinary_bytes - self.runtime_bytes) / (self.running + self.ready) as u64
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationExecutorSnapshot {
    pub profile: ApplicationResourceProfile,
    pub ordinary_running: usize,
    pub ordinary_reserved: usize,
    pub ordinary_ready: usize,
    pub resident_running: usize,
    pub resident_reserved: usize,
    pub resident_ready: usize,
    pub completion_running: usize,
    pub completion_reserved: usize,
    pub completion_claims: usize,
    pub completion_ready: usize,
    pub completion_eligible: usize,
    pub completion_owners: usize,
    pub management_running: usize,
    pub management_reserved: usize,
    pub management_ready: usize,
    pub query_running: usize,
    pub query_reserved: usize,
    pub query_ready: usize,
    pub query_owners: usize,
}
impl ApplicationExecutorSnapshot {
    pub(crate) fn empty(profile: ApplicationResourceProfile) -> Self {
        Self {
            profile,
            ordinary_running: 0,
            ordinary_reserved: 0,
            ordinary_ready: 0,
            resident_running: 0,
            resident_reserved: 0,
            resident_ready: 0,
            completion_running: 0,
            completion_reserved: 0,
            completion_claims: 0,
            completion_ready: 0,
            completion_eligible: 0,
            completion_owners: 0,
            management_running: 0,
            management_reserved: 0,
            management_ready: 0,
            query_running: 0,
            query_reserved: 0,
            query_ready: 0,
            query_owners: 0,
        }
    }
}
