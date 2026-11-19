use thiserror::Error;

#[derive(Debug, Error)]
pub enum DesktopError {
    #[error("engine library load failed: {0}")]
    EngineLoad(String),

    #[error("engine symbol missing: {0}")]
    EngineSymbol(String),

    #[error("engine call returned {0}")]
    EngineReturn(i32),

    /// An engine call failed and the engine said why. `detail` is the
    /// newest entry of the engine's own `recent_errors` list, read
    /// right after the call returned (see `Engine::failed`).
    #[error("engine call returned {code}: {detail}")]
    EngineFailed { code: i32, detail: String },

    /// The engine library is loaded but `engine_init` did not succeed,
    /// so no engine call can be made. The text after the prefix is the
    /// host's reason. The `engine_unavailable:` prefix is a contract
    /// with the UI, which shows its own sentence for it.
    #[error("engine_unavailable: {0}")]
    EngineUnavailable(String),

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
