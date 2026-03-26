/// Sentry protocol commands.
#[derive(Debug, Clone)]
pub enum Command {
    /// Reload policies from disk.
    PolicyReload,

    /// List all loaded policies.
    PolicyList,

    /// Get information about a specific policy.
    PolicyInfo { name: String },

    /// Rotate the signing key.
    KeyRotate { force: bool, dryrun: bool },

    /// Get signing key information.
    KeyInfo,

    /// Evaluate an authorization request.
    Evaluate { json: String },

    /// Health check.
    Health,

    /// Get a configuration value.
    ConfigGet { key: String },

    /// Set a configuration value.
    ConfigSet { key: String, value: String },

    /// List all configuration values.
    ConfigList,

    /// Authenticate the connection.
    Auth { token: String },

    /// Execute a batch of commands.
    Pipeline(Vec<Command>),
}

/// Get the verb string for a command (for metrics and audit logging).
pub fn command_verb(cmd: &Command) -> &'static str {
    match cmd {
        Command::PolicyReload => "POLICY_RELOAD",
        Command::PolicyList => "POLICY_LIST",
        Command::PolicyInfo { .. } => "POLICY_INFO",
        Command::KeyRotate { .. } => "KEY_ROTATE",
        Command::KeyInfo => "KEY_INFO",
        Command::Evaluate { .. } => "EVALUATE",
        Command::Health => "HEALTH",
        Command::ConfigGet { .. } => "CONFIG",
        Command::ConfigSet { .. } => "CONFIG",
        Command::ConfigList => "CONFIG",
        Command::Auth { .. } => "AUTH",
        Command::Pipeline(_) => "PIPELINE",
    }
}

impl Command {
    /// Whether this is a read-only command (for replication classification).
    pub fn is_read(&self) -> bool {
        matches!(
            self,
            Command::PolicyList
                | Command::PolicyInfo { .. }
                | Command::KeyInfo
                | Command::Evaluate { .. }
                | Command::Health
                | Command::ConfigGet { .. }
                | Command::ConfigList
        )
    }
}
