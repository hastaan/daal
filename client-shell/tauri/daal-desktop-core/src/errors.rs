use thiserror::Error;

#[derive(Debug, Error)]
pub enum DesktopError {
    #[error("engine library load failed: {0}")]
    EngineLoad(String),

    #[error("engine symbol missing: {0}")]
    EngineSymbol(String),

    #[error("engine call returned {0}")]
    EngineReturn(i32),

    #[error(
        "engine ABI mismatch: GUI requires daal-core 0.5.x+survivability, got {0}. \
         Reinstall Daal so the GUI and engine are in sync."
    )]
    AbiMismatch(String),

    #[error("engine response was not valid utf-8")]
    EngineUtf8,

    #[error("engine response too large ({0} bytes)")]
    EngineTooLarge(usize),

    #[error("engine heartbeat timed out")]
    HeartbeatLost,

    #[error("sing-box: {0}")]
    Singbox(String),

    #[error("tun helper: {0}")]
    TunHelper(String),

    #[error("bundle: {0}")]
    Bundle(#[from] bundle_rs::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, DesktopError>;
