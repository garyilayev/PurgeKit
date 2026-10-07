//! Telemetry is deferred. Only the trait and a no-op provider exist; 0.1
//! contains no networking code. When telemetry ships it lives behind a Cargo
//! feature, is off by default, and only ever carries bucketed values.

/// Bucketed, non-identifying events. Never file names, paths, usernames,
/// machine names, URLs or persistent IDs.
#[derive(Debug, Clone)]
pub enum TelemetryEvent {
    ScanCompleted {
        duration_bucket: &'static str,
        size_bucket: &'static str,
    },
    CleanCompleted {
        size_bucket: &'static str,
        error_categories: Vec<&'static str>,
    },
}

pub trait TelemetryProvider: Send + Sync {
    fn record(&self, event: &TelemetryEvent);
}

/// Default provider. Disabled means zero requests.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopTelemetry;

impl TelemetryProvider for NoopTelemetry {
    fn record(&self, _event: &TelemetryEvent) {}
}
