//! The hosting account (Accounts page): one key per hosting company,
//! kept on this phone apart from any relay.
//!
//! # Why
//!
//! Accounts come before relays: a publisher can connect Hetzner, check
//! the key works, and not build a relay yet. Before this module the
//! hosting key existed only inside a relay (`store_cloud_token` keeps it
//! under `cloud_alias(operator_id)`), so "connected" meant "some relay
//! holds a key" and connecting meant starting the wizard.
//!
//! # The key
//!
//! [`connect`] checks a pasted key with the same read-only call the
//! wizard makes for a key it does not store
//! ([`crate::commands::list_server_types_for`]), then keeps it under
//! [`account_alias`]. A new relay takes a COPY of it inside custody
//! under its own alias (`reuse_cloud_token`), exactly as reusing another
//! relay's key does; the per-relay copy stays, because deleting a relay,
//! the backup and the rebuild all read the relay's own key.
//!
//! [`status`] says per company whether a key is there: the account key,
//! or (for phones set up before the account existed) a live relay's.
//! [`disconnect`] forgets the account key only. Relays keep their own
//! copies and keep working.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::commands::{
    custody_has, custody_put, list_server_types_for, Result, WizardCtx, WizardError,
};

/// The hosting companies Daal knows, with the region a key is checked
/// in (the wizard's `REGION_MAP`). Only Hetzner can build a relay today;
/// the others are listed so a key for one is never stored under a name
/// nobody reads.
pub const PROVIDERS: &[(&str, &str)] = &[
    ("hetzner", "fsn1"),
    ("vultr", "fra"),
    ("digitalocean", "fra1"),
    ("linode", "eu-central"),
];

/// `daal.hosting.<provider>.account.token`.
pub fn account_alias(provider: &str) -> String {
    format!("daal.hosting.{provider}.account.token")
}

/// Every account alias a phone may hold (for the backup).
pub fn all_account_aliases() -> Vec<String> {
    PROVIDERS.iter().map(|(p, _)| account_alias(p)).collect()
}

fn known(provider: &str) -> Result<(&'static str, &'static str)> {
    let p = provider.trim();
    PROVIDERS
        .iter()
        .find(|(id, _)| *id == p)
        .copied()
        .ok_or_else(|| WizardError::Validation(format!("unknown hosting company {p:?}")))
}

/// `wizard_hosting_account_connect`.
///
/// No `Debug`: the token must never reach a log line.
#[derive(Clone, Deserialize)]
pub struct HostingConnectInput {
    pub provider: String,
    pub token: String,
}

/// One hosting company on this phone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostingAccountState {
    /// A key Daal can use is here: the account's, or a live relay's.
    pub connected: bool,
    /// The account key itself is here (what Disconnect forgets).
    pub account: bool,
}

/// Check a pasted key against the hosting company and keep it for every
/// new relay. An empty key is `EmptyToken`; a key the company refuses is
/// the lookup's own error (the company's words) and nothing is kept.
pub fn connect(ctx: &WizardCtx, provider: &str, token: &str) -> Result<HostingAccountState> {
    let (provider, region) = known(provider)?;
    let token = Zeroizing::new(token.trim().to_string());
    if token.is_empty() {
        return Err(WizardError::EmptyToken);
    }
    list_server_types_for(ctx, provider, region, &token).map_err(|e| match e {
        // The company's words, never the key.
        WizardError::Pricing(s) => WizardError::Pricing(s.replace(token.as_str(), "[key]")),
        other => other,
    })?;
    custody_put(ctx, &account_alias(provider), token.as_bytes())?;
    Ok(HostingAccountState {
        connected: true,
        account: true,
    })
}

/// Whether the account key for `provider` is readable right now.
pub fn has_account_key(ctx: &WizardCtx, provider: &str) -> bool {
    custody_has(ctx, &account_alias(provider))
}

/// Per company: connected or not. Local, no network, no secret read
/// into the result.
pub fn status(ctx: &WizardCtx) -> Result<BTreeMap<String, HostingAccountState>> {
    let rows = ctx.db.list()?;
    let mut out = BTreeMap::new();
    for (p, _) in PROVIDERS {
        out.insert(p.to_string(), HostingAccountState::default());
    }
    for (p, st) in out.iter_mut() {
        st.account = has_account_key(ctx, p);
        st.connected = st.account
            || rows.iter().any(|r| {
                r.cloud_provider == *p
                    && r.status != "decommissioned"
                    && !r.cloud_token_keystore_alias.is_empty()
                    && custody_has(ctx, &r.cloud_token_keystore_alias)
            });
    }
    Ok(out)
}

/// Forget the account key. Relays keep their own copies.
pub fn disconnect(ctx: &WizardCtx, provider: &str) -> Result<()> {
    let (provider, _) = known(provider)?;
    let _ = ctx.custody.forget(&account_alias(provider));
    Ok(())
}

#[cfg(test)]
#[path = "hosting_account_tests.rs"]
mod tests;
