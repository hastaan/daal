//! Add-on 1: a standby address (docs/optional-addons-plan.md §1,
//! specs/optional-addons-v1.md §3).
//!
//! A second Hetzner Floating IPv4, attached to the relay from the start
//! and kept back; the signed pack carries only a commitment to it
//! (sealed, the default) or the address itself (open, only when no
//! Everyone file exists — decision D-1).
//!
//! The `daal-deploy` verbs it drives are `standby price | add | promote
//! | remove` (`publisher/deploy/cli/cli_addon_standby.go`), through
//! `CliRunner::run_addon`. The record the helper hands back carries the
//! standby (`standby` member of the OperatorRecord); the next signature
//! writes `_standby` into every route.
//!
//! THE MONEY RULE. Hetzner bills a Floating IP by the hour until it is
//! deleted. The ledger row is written (`building`) BEFORE anything is
//! rented, so a run killed half way leaves a row the app can act on:
//! `add` again adopts what the killed run rented (the helper finds it by
//! its labels), `remove` gives it back, and relay delete releases it
//! with the relay's addresses. A failed `add` — the helper's own steps,
//! or the signature after them — gives the address back before it
//! returns; only when that is impossible (the relay could not be told to
//! drop it) does the row stay, saying the address still bills.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::addons::{
    self, AddonKind, AddonOutcome, AddonProgress, AddonRemoveReport, AddonRow, AddonState, NewAddon,
};
use crate::cli_bridge::{verb_unknown, AddonCliRequest, BridgeError, ProgressEvent};
use crate::commands::{
    coded, custody_get, custody_get_string, map_rotation_err, require_helper_ip, Result, WizardCtx,
    WizardError, E_DEPLOY_TOO_OLD, E_NOT_BUILT, E_NOT_SUPPORTED,
};
use crate::relay_identity::{resign_and_republish, Freshness};

/// Hetzner refused another Floating IP on this account (GATE S-1).
/// Nothing was rented. The UI says "Hetzner has not allowed this account
/// a second address yet" with the support link.
pub const E_STANDBY_LIMIT: &str = "E_STANDBY_LIMIT";
/// The relay can bind an address but binds it where its own traffic could
/// leave from it (relay-v1.5.1 and older: no `scope link`), which would
/// reveal a sealed standby after a lost DHCP lease. The helper asks the
/// box before renting (exit 10), so nothing bills. Only a new relay fixes
/// it; the UI says "This relay is too old for a standby address. Set up a
/// new relay to use it."
pub const E_STANDBY_NEEDS_REBUILD: &str = "E_STANDBY_NEEDS_REBUILD";
/// Open mode asked for while the relay has an Everyone file (D-1).
pub const E_STANDBY_OPEN_REFUSED: &str = "E_STANDBY_OPEN_REFUSED";
/// The standby could not be given back and is still billing; the row
/// stays so the same action is the retry.
pub const E_STANDBY_STILL_BILLING: &str = "E_STANDBY_STILL_BILLING";
/// Removal is waiting for the pack without the standby to reach the
/// refresh addresses (it is not released before that: a released
/// address may be handed to a stranger while packs still name it).
pub const E_STANDBY_NOT_PUBLISHED: &str = "E_STANDBY_NOT_PUBLISHED";

/// `wizard_addon_standby_price`.
#[derive(Debug, Clone, Deserialize)]
pub struct StandbyPriceInput {
    pub operator_id: i64,
}

/// The monthly price of one Floating IPv4 in the relay's location, read
/// live from the hosting company (the confirm sheet shows it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StandbyPrice {
    pub monthly_cents: i64,
    /// ISO 4217, e.g. "EUR".
    pub currency: String,
    /// Whether `monthly_cents` includes VAT. Hetzner quotes both; the
    /// card says "plus tax" when false.
    pub vat_included: bool,
}

/// `wizard_addon_standby_add`: rent, attach, check over the new
/// address, sign. Rolls back what it created on any failure.
#[derive(Debug, Clone, Deserialize)]
pub struct StandbyAddInput {
    pub operator_id: i64,
    /// "sealed" (default) | "open". Open is refused while the relay has
    /// an Everyone file (D-1).
    #[serde(default)]
    pub mode: String,
}

/// `wizard_addon_standby_promote`: "Switch to standby".
#[derive(Debug, Clone, Deserialize)]
pub struct StandbyPromoteInput {
    pub operator_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StandbyPromoteResult {
    pub addon: AddonRow,
    /// The 26-character standby code to send, grouped for reading aloud:
    /// wrapped when every person on the relay holds the secret it is
    /// wrapped under, else the plain key (`key_form` says which;
    /// specs/update-ladder-v2.md §3).
    pub key: String,
    /// `KEY_FORM_WRAPPED` | `KEY_FORM_PLAIN`.
    #[serde(default = "plain_form")]
    pub key_form: String,
    /// The plain key, set only when `key` is wrapped: the quiet fallback
    /// for a person whose phone cannot open the wrapped form (an older
    /// build, or a file not imported yet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plain_key: Option<String>,
    /// The pack signed with the standby as its address reached enough
    /// refresh addresses.
    pub refresh_note_published: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// `wizard_addon_standby_key`: show the key again after the sheet that
/// first showed it was closed.
#[derive(Debug, Clone, Deserialize)]
pub struct StandbyKeyInput {
    pub operator_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StandbyKey {
    /// The code to send (see `StandbyPromoteResult::key`).
    pub key: String,
    /// `KEY_FORM_WRAPPED`: useless without the person's own file, so it
    /// may go by SMS, a call or a messenger. `KEY_FORM_PLAIN`: the
    /// address in readable form (an Everyone file, or not every person
    /// holds the secret yet).
    #[serde(default = "plain_form")]
    pub form: String,
    /// See `StandbyPromoteResult::plain_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plain_key: Option<String>,
}

/// The code is the standby key wrapped under the people's update secret.
pub const KEY_FORM_WRAPPED: &str = "wrapped";
/// The code is the standby key itself.
pub const KEY_FORM_PLAIN: &str = "plain";

fn plain_form() -> String {
    KEY_FORM_PLAIN.to_string()
}

// ---------------------------------------------------------------------
// The helper
// ---------------------------------------------------------------------

fn progress(op: i64, step: &str, state: &str, detail: impl Into<String>) -> AddonProgress {
    AddonProgress {
        operator_id: op,
        kind: AddonKind::Standby,
        step: step.into(),
        state: state.into(),
        detail: detail.into(),
    }
}

/// What the helper's progress lines said about money, for a run that
/// fails: which Floating IP it had in hand, and whether it gave it back.
#[derive(Default)]
struct Seen {
    created: Option<String>,
    released: Vec<String>,
    still_billing: Vec<String>,
}

fn translate(op: i64, ev: &ProgressEvent, seen: &mut Seen, out: &mut dyn FnMut(AddonProgress)) {
    let fip = ev
        .extra
        .get("floating_ip_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    match ev.step.as_str() {
        "standby_renting" => out(progress(op, "renting", "running", "")),
        "standby_created" => {
            seen.created = Some(fip);
            out(progress(op, "renting", "ok", ""));
        }
        "standby_attaching" => out(progress(op, "attaching", "running", "")),
        "standby_checking" => {
            out(progress(op, "attaching", "ok", ""));
            out(progress(op, "checking", "running", ""));
        }
        "standby_ready" => out(progress(op, "checking", "ok", "")),
        "standby_released" => {
            seen.released.push(fip);
            out(progress(op, "releasing", "ok", ""));
        }
        "standby_still_billing" => {
            seen.still_billing.push(fip);
            out(progress(op, "releasing", "failed", ev.message.clone()));
        }
        _ => {}
    }
}

/// The helper's failure, in the error contract.
fn map_cli_err(e: BridgeError) -> WizardError {
    if verb_unknown(&e) {
        return coded(
            E_DEPLOY_TOO_OLD,
            "the setup helper bundled with this app has no standby address",
        );
    }
    if let BridgeError::SubprocessFailed { rc, stderr } = &e {
        match *rc {
            9 => return coded(E_STANDBY_LIMIT, stderr.trim()),
            10 => return coded(E_STANDBY_NEEDS_REBUILD, stderr.trim()),
            8 => return coded(E_NOT_BUILT, stderr.trim()),
            6 => return coded(E_STANDBY_STILL_BILLING, stderr.trim()),
            _ => {}
        }
    }
    map_rotation_err(e)
}

/// The record staged for one helper run, removed when dropped.
struct Staged(std::path::PathBuf);

impl Staged {
    fn write(ctx: &WizardCtx, op: i64, json: &str) -> Result<Self> {
        std::fs::create_dir_all(&ctx.staging_dir)
            .map_err(|e| WizardError::Pricing(format!("mkdir staging: {e}")))?;
        let p = ctx.staging_dir.join(format!("{op}.standby.record.json"));
        std::fs::write(&p, json.as_bytes())
            .map_err(|e| WizardError::Pricing(format!("write record: {e}")))?;
        Ok(Self(p))
    }
    fn arg(&self) -> String {
        self.0.to_string_lossy().to_string()
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// One `daal-deploy standby <verb>` run. The cloud token goes as a 0600
/// file, the signing key (when `box_call`) on stdin, the helper IP as a
/// flag. stdout is parsed and dropped (it carries the standby key).
fn run(
    ctx: &WizardCtx,
    op: i64,
    verb: &str,
    record_json: &str,
    mut args: Vec<String>,
    box_call: bool,
    seen: &mut Seen,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<Value> {
    let row = ctx.db.get(op)?;
    if row.cloud_token_keystore_alias.is_empty() {
        return Err(WizardError::EmptyToken);
    }
    let token = custody_get_string(ctx, &row.cloud_token_keystore_alias)?;
    let staged = Staged::write(ctx, op, record_json)?;
    let mut argv = vec![
        "standby".to_string(),
        verb.to_string(),
        "--record-file".into(),
        staged.arg(),
    ];
    let priv_buf = if box_call {
        let helper_ip = require_helper_ip(ctx, op)?;
        argv.extend([
            "--priv-key".into(),
            "-".into(),
            "--helper-ip".into(),
            helper_ip,
        ]);
        Some(custody_get(ctx, &row.publisher_priv_keystore_alias)?)
    } else {
        None
    };
    argv.append(&mut args);
    let req = AddonCliRequest {
        args: argv,
        secret_files: vec![("--token-file", token.as_str())],
        stdin: priv_buf.as_ref().map(|b| b.as_slice()).unwrap_or(&[]),
        progress: true,
    };
    let out = ctx
        .cli
        .run_addon(req, &mut |ev| translate(op, &ev, seen, on_progress))
        .map_err(map_cli_err)?;
    drop(staged);
    serde_json::from_slice(&out)
        .map_err(|e| WizardError::Subprocess(format!("standby {verb}: unreadable answer: {e}")))
}

// ---------------------------------------------------------------------
// The record and the ledger
// ---------------------------------------------------------------------

fn record(ctx: &WizardCtx, op: i64) -> Result<(String, Value)> {
    let row = ctx.db.get(op)?;
    let v: Value = serde_json::from_str(&row.operator_record_json)
        .map_err(|e| WizardError::Validation(format!("this relay's record is unreadable: {e}")))?;
    Ok((row.operator_record_json, v))
}

fn record_standby(rec: &Value) -> Option<&Value> {
    rec.get("standby").filter(|s| s.is_object())
}

fn without_standby(rec: &Value) -> String {
    let mut v = rec.clone();
    if let Some(m) = v.as_object_mut() {
        m.remove("standby");
    }
    v.to_string()
}

/// The relay's live (not promoted) standby row, if any.
fn live_row(ctx: &WizardCtx, op: i64) -> Result<Option<AddonRow>> {
    Ok(addons::list(ctx, op)?
        .into_iter()
        .find(|r| r.kind == AddonKind::Standby && r.state != AddonState::Promoted))
}

/// Whether the relay has (or had) an Everyone file. The staged copy can
/// be gone after a restore or a cleanup while the file is still in use,
/// so the database's stamp counts too. Any doubt is "yes": the plain
/// code is the safe answer.
fn everyone_file(ctx: &WizardCtx, op: i64) -> bool {
    ctx.staging_dir.join(format!("{op}.shared.sbp")).exists()
        || ctx.db.shared_box_fp(op).map(|f| !f.is_empty()).unwrap_or(true)
}

fn require_hetzner(rec: &Value) -> Result<()> {
    match rec.get("provider").and_then(Value::as_str).unwrap_or("") {
        "hetzner" => Ok(()),
        other => Err(coded(
            E_NOT_SUPPORTED,
            format!("a standby address is only available on Hetzner (this relay is on {other:?})"),
        )),
    }
}

fn provider_ids(fip: &str) -> BTreeMap<String, String> {
    if fip.is_empty() {
        BTreeMap::new()
    } else {
        BTreeMap::from([("floating_ip_id".to_string(), fip.to_string())])
    }
}

// ---------------------------------------------------------------------
// The key
// ---------------------------------------------------------------------

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The standby key's text form from salt (base64, 12 bytes) and the
/// IPv4 address: the 128 bits of salt ‖ ipv4 then two zero bits, as 26
/// Crockford base32 symbols in groups of 6-5-5-5-5. The same function as
/// `bundle.StandbyKeyBytes.Text` (vector pinned in both).
pub fn key_text(salt_b64: &str, ipv4: &str) -> Option<String> {
    let salt = B64.decode(salt_b64.trim()).ok()?;
    let ip: std::net::Ipv4Addr = ipv4.trim().parse().ok()?;
    if salt.len() != 12 {
        return None;
    }
    let mut k = [0u8; 16];
    k[..12].copy_from_slice(&salt);
    k[12..].copy_from_slice(&ip.octets());
    Some(text_of(&k))
}

fn key_of(standby: &Value) -> Option<String> {
    key_text(standby.get("salt")?.as_str()?, standby.get("ip")?.as_str()?)
}

/// The text form of any 16 bytes (a key or a wrapped key).
fn text_of(k: &[u8; 16]) -> String {
    let bit = |i: usize| -> u8 {
        if i >= 128 {
            0
        } else {
            (k[i / 8] >> (7 - (i % 8))) & 1
        }
    };
    let mut s = String::with_capacity(30);
    for sym in 0..26 {
        if matches!(sym, 6 | 11 | 16 | 21) {
            s.push(' ');
        }
        let mut v = 0usize;
        for b in 0..5 {
            v = (v << 1) | bit(sym * 5 + b) as usize;
        }
        s.push(CROCKFORD[v] as char);
    }
    s
}

/// The 16 bytes of a code in text form (`bundle.ParseStandbyKeyText`:
/// case, spaces and `-` ignored, O→0, I/L→1, trailing bits zero).
fn bytes_of_text(s: &str) -> Option<[u8; 16]> {
    let mut vals = Vec::with_capacity(26);
    for c in s.chars() {
        let c = match c.to_ascii_uppercase() {
            ' ' | '-' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        vals.push(CROCKFORD.iter().position(|&x| x as char == c)? as u8);
        if vals.len() > 26 {
            return None;
        }
    }
    if vals.len() != 26 {
        return None;
    }
    let mut k = [0u8; 16];
    for (sym, v) in vals.iter().enumerate() {
        for b in 0..5 {
            let bit = sym * 5 + b;
            let on = v & (0x10 >> b) != 0;
            if bit >= 128 {
                if on {
                    return None;
                }
            } else if on {
                k[bit / 8] |= 0x80 >> (bit % 8);
            }
        }
    }
    Some(k)
}

// ---------------------------------------------------------------------
// The update secret and the wrapped code (specs/update-ladder-v2.md)
// ---------------------------------------------------------------------
//
// The publisher keeps ONE update root (custody, `UPDATE_ROOT_ALIAS`) and
// derives each relay's audience secret from it:
//
//   u = HKDF-SHA256(ikm = root, salt = "daal/update-v2",
//                   info = relay_pack_id ‖ 0x0A ‖ audience)
//
// `relay_pack_id` is the one the relay had when its first secret was
// made, kept for the relay's life in the relay's update state (a
// rotation that renames the pack must not change what phones hold).
// The person's file carries `u` (never the root) in its sealed half; the
// helper gets it in the 0600 creds file it already reads, never as an
// argument (`people_secret_for_file`, `everyone_secret_for_file`).
//
// The code to send is wrapped (`wrap_key`) only when it opens for every
// person: no Everyone file, and every current person's newest file
// carries the current generation. REMOVAL: a person removed while
// holding the current generation could unwrap every later code, so the
// next file made (or the next time the code is asked for) moves the
// relay to a new generation (`people/<g>`). Until every remaining person
// has a file of it, the plain code is the one that works for everyone,
// and `key` says so. The secret is never logged or returned.

/// Custody alias of the publisher's update root (32 random bytes).
pub const UPDATE_ROOT_ALIAS: &str = "update_root";
const UPDATE_SALT: &[u8] = b"daal/update-v2";

pub(crate) fn update_state_alias(op: i64) -> String {
    format!("update_people_{op}")
}

/// One relay's update state (custody, `update_people_<op>`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct UpdateState {
    /// The relay_pack_id the secret is derived with.
    pack_id: String,
    /// The people generation (1 = "people").
    gen: u32,
    /// Recipient fingerprint → the generation of the newest file made
    /// for them.
    holders: BTreeMap<String, u32>,
    /// A tag of the root the state was made under: a root that is not
    /// that one (a restore that did not carry it) resets the state.
    root_tag: String,
}

/// The secret a file carries, for the creds JSON the helper reads
/// (`update_secret`, `update_audience`).
#[derive(Debug, Clone, PartialEq)]
pub struct UpdateSecretForFile {
    pub secret_b64: zeroize::Zeroizing<String>,
    pub audience: String,
    /// The people generation the secret is of (0 for the Everyone
    /// audience). Handed back to `record_holder` once the file is made.
    pub gen: u32,
    /// Where the person's phone looks for the relay's update notes (the
    /// carriers member, `update/carriers.json`), when the relay has a
    /// note switch on (`addon_notes::carriers_member`). Never set for
    /// the Everyone file: the helper refuses it there.
    pub carriers: Option<Value>,
}

impl UpdateSecretForFile {
    /// Adds the secret to the creds JSON the helper reads
    /// (`update_secret`, `update_audience`, and `update_carriers` for a
    /// person's file when the relay has a note switch on).
    pub fn add_to_creds(&self, creds: &mut Value) {
        if let Some(obj) = creds.as_object_mut() {
            obj.insert("update_secret".into(), Value::String(self.secret_b64.to_string()));
            obj.insert("update_audience".into(), Value::String(self.audience.clone()));
            match &self.carriers {
                Some(c) if self.audience != "everyone" => {
                    obj.insert("update_carriers".into(), c.clone());
                }
                _ => {
                    obj.remove("update_carriers");
                }
            }
        }
    }
}

fn people_audience(gen: u32) -> String {
    if gen <= 1 {
        "people".into()
    } else {
        format!("people/{gen}")
    }
}

/// u for (root, pack id, audience).
pub fn derive_update_secret(
    root: &[u8],
    pack_id: &str,
    audience: &str,
) -> zeroize::Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(pack_id.len() + 1 + audience.len());
    info.extend_from_slice(pack_id.as_bytes());
    info.push(0x0A);
    info.extend_from_slice(audience.as_bytes());
    let mut u = zeroize::Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(Some(UPDATE_SALT), root)
        .expand(&info, &mut u[..])
        .expect("32 bytes is a valid HKDF length");
    u
}

/// The wrapped form of a standby key: key XOR HKDF(u, "wrap" ‖ commit)
/// [0:16], commit = SHA-256("daal/standby-v1" ‖ key) as 32 raw bytes.
pub fn wrap_key(key: &[u8; 16], u: &[u8; 32]) -> [u8; 16] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"daal/standby-v1");
    h.update(key);
    let commit = h.finalize();
    let mut info = Vec::with_capacity(4 + 32);
    info.extend_from_slice(b"wrap");
    info.extend_from_slice(&commit);
    let mut pad = [0u8; 16];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(UPDATE_SALT), u)
        .expand(&info, &mut pad)
        .expect("16 bytes is a valid HKDF length");
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = key[i] ^ pad[i];
    }
    out
}

/// The publisher's update root, made on first use. A custody that is
/// locked or broken is an error, never a reason to make a new root (that
/// would silently change every relay's secret).
fn update_root(ctx: &WizardCtx) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    match ctx.custody.get(UPDATE_ROOT_ALIAS) {
        Ok(b) if b.len() == 32 => Ok(zeroize::Zeroizing::new(b)),
        Ok(_) => Err(coded(
            crate::commands::E_CUSTODY_BACKEND,
            "the update root in this device's key store is damaged",
        )),
        Err(crate::device_custody::CustodyError::NotFound(_)) => {
            use rand::RngCore;
            let mut r = zeroize::Zeroizing::new(vec![0u8; 32]);
            rand::rngs::OsRng.fill_bytes(&mut r[..]);
            crate::commands::custody_put(ctx, UPDATE_ROOT_ALIAS, &r)?;
            Ok(r)
        }
        Err(e) => Err(crate::commands::map_custody_err(ctx, UPDATE_ROOT_ALIAS, e)),
    }
}

fn root_tag(root: &[u8]) -> String {
    let u = derive_update_secret(root, "", "root-tag");
    hex::encode(&u[..8])
}

/// The people the relay's files are for now: fingerprints of recipients
/// not removed.
fn current_people(ctx: &WizardCtx, op: i64) -> Result<std::collections::BTreeSet<String>> {
    Ok(ctx
        .db
        .list_recipients(op)?
        .into_iter()
        .filter(|r| r.revoked_at_unix == 0)
        .map(|r| r.fingerprint_hex)
        .collect())
}

/// Loads the relay's state under `root`, applying the removal rule: a
/// holder of the current generation who is no longer a person on the
/// relay moves it to the next one. Saved when anything changed. None
/// when the relay has no signed pack yet (no id to derive with) and no
/// state.
fn load_update_state(ctx: &WizardCtx, op: i64, root: &[u8]) -> Result<Option<UpdateState>> {
    let tag = root_tag(root);
    let mut st: UpdateState = match ctx.custody.get(&update_state_alias(op)) {
        // Damage is an error, never a fresh start: a fresh state would
        // restart at generation 1, the secret every person removed in
        // generation 1 still holds.
        Ok(b) => serde_json::from_slice(&b).map_err(|_| {
            coded(
                crate::commands::E_CUSTODY_BACKEND,
                "this relay's update state in this device's key store is damaged",
            )
        })?,
        Err(crate::device_custody::CustodyError::NotFound(_)) => UpdateState::default(),
        Err(e) => {
            return Err(crate::commands::map_custody_err(
                ctx,
                &update_state_alias(op),
                e,
            ))
        }
    };
    let before = st.clone();
    if st.root_tag != tag {
        st = UpdateState {
            root_tag: tag,
            ..UpdateState::default()
        };
    }
    if st.pack_id.is_empty() {
        match ctx
            .db
            .get(op)?
            .signed_sbp_relay_pack_id
            .filter(|p| !p.is_empty())
        {
            Some(p) => st.pack_id = p,
            None => return Ok(None),
        }
    }
    st.gen = st.gen.max(1);
    let people = current_people(ctx, op)?;
    if st
        .holders
        .iter()
        .any(|(fp, g)| *g == st.gen && !people.contains(fp))
    {
        st.gen += 1;
    }
    st.holders.retain(|fp, _| people.contains(fp));
    if st != before {
        save_update_state(ctx, op, &st)?;
    }
    Ok(Some(st))
}

fn save_update_state(ctx: &WizardCtx, op: i64, st: &UpdateState) -> Result<()> {
    let body = serde_json::to_vec(st).map_err(|e| WizardError::Validation(e.to_string()))?;
    crate::commands::custody_put(ctx, &update_state_alias(op), &body)
}

/// The secret to write into the file being made for one person
/// (`_recipient_fp_hex`, already a recipient of the relay). Nothing is
/// recorded here: the caller calls `record_holder` only once the helper
/// said the file carries the secret (`"update_secret": true`) and the
/// file was written. An older helper ignores the secret, and a person
/// recorded as holding a secret their file lacks would make every
/// wrapped code fail for them. None when the relay has no signed pack
/// yet: that file simply carries no secret, and its codes work in the
/// plain form.
pub fn people_secret_for_file(
    ctx: &WizardCtx,
    op: i64,
    _recipient_fp_hex: &str,
) -> Result<Option<UpdateSecretForFile>> {
    let root = update_root(ctx)?;
    let Some(st) = load_update_state(ctx, op, &root)? else {
        return Ok(None);
    };
    let audience = people_audience(st.gen);
    let u = derive_update_secret(&root, &st.pack_id, &audience);
    Ok(Some(UpdateSecretForFile {
        secret_b64: zeroize::Zeroizing::new(B64.encode(&u[..])),
        audience,
        gen: st.gen,
        carriers: crate::addon_notes::carriers_member(ctx, op),
    }))
}

/// The relay's current people secret, raw, for the note writers
/// (`addon_notes`): the audience the newest files carry. The removal
/// rule applies first (`load_update_state`), so a person removed while
/// holding a generation never gets a note written under it again. None
/// when the relay has no signed pack yet.
pub(crate) fn current_people_secret(
    ctx: &WizardCtx,
    op: i64,
) -> Result<Option<(zeroize::Zeroizing<[u8; 32]>, String)>> {
    let root = update_root(ctx)?;
    let Some(st) = load_update_state(ctx, op, &root)? else {
        return Ok(None);
    };
    let audience = people_audience(st.gen);
    let u = derive_update_secret(&root, &st.pack_id, &audience);
    Ok(Some((u, audience)))
}

/// The raw people secret of `audience` (an audience a note was written
/// under before), for removing what was written. None as above.
pub(crate) fn people_secret_of(
    ctx: &WizardCtx,
    op: i64,
    audience: &str,
) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>> {
    if audience == "everyone" {
        return Ok(None);
    }
    let root = update_root(ctx)?;
    let Some(st) = load_update_state(ctx, op, &root)? else {
        return Ok(None);
    };
    Ok(Some(derive_update_secret(&root, &st.pack_id, audience)))
}

/// The standby key that has been revealed: the most recent switch to a
/// standby (a promoted row's plain key). It is the relay's address now,
/// so the update notes carry it to people whose app could not fetch the
/// new pack. None when the relay never switched.
pub(crate) fn revealed_key(ctx: &WizardCtx, op: i64) -> Option<[u8; 16]> {
    addons::list(ctx, op)
        .ok()?
        .into_iter()
        .rev()
        .filter(|r| r.kind == AddonKind::Standby && r.state == AddonState::Promoted)
        .find_map(|r| r.detail.get("key").and_then(Value::as_str).and_then(bytes_of_text))
}

/// `bundle.StandbyCommit`: base64(SHA-256("daal/standby-v1" ‖ key)), the
/// `_standby.commit` a sealed standby carries.
pub(crate) fn standby_commit(key: &[u8; 16]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"daal/standby-v1");
    h.update(key);
    B64.encode(h.finalize())
}

/// The 26 symbols of a key, run together (the form the note verbs read).
pub(crate) fn key_symbols(key: &[u8; 16]) -> String {
    text_of(key).replace(' ', "")
}

/// Records that the file just made for `recipient_fp_hex` carries the
/// secret of generation `gen` (from `people_secret_for_file`). Call it
/// only after the helper reported `"update_secret": true` and the file
/// was written.
pub fn record_holder(ctx: &WizardCtx, op: i64, recipient_fp_hex: &str, gen: u32) -> Result<()> {
    let root = update_root(ctx)?;
    let Some(mut st) = load_update_state(ctx, op, &root)? else {
        return Ok(());
    };
    st.holders.insert(recipient_fp_hex.to_string(), gen);
    save_update_state(ctx, op, &st)
}

/// The secret to write into the relay's Everyone file. Public by
/// construction; it never wraps a code.
pub fn everyone_secret_for_file(ctx: &WizardCtx, op: i64) -> Result<Option<UpdateSecretForFile>> {
    let root = update_root(ctx)?;
    let Some(st) = load_update_state(ctx, op, &root)? else {
        return Ok(None);
    };
    let u = derive_update_secret(&root, &st.pack_id, "everyone");
    Ok(Some(UpdateSecretForFile {
        secret_b64: zeroize::Zeroizing::new(B64.encode(&u[..])),
        audience: "everyone".into(),
        gen: 0,
        carriers: None,
    }))
}

/// The code to send for a plain key: wrapped when it opens for every
/// person on the relay, else the plain key. Never fails the caller: any
/// doubt is the plain form, which is what the relay sent before.
fn code_to_send(ctx: &WizardCtx, op: i64, plain: &str) -> (String, String, Option<String>) {
    let plain_out = (plain.to_string(), KEY_FORM_PLAIN.to_string(), None);
    if everyone_file(ctx, op) {
        return plain_out;
    }
    let Some(key) = bytes_of_text(plain) else {
        return plain_out;
    };
    // Only read the root here: asking for a code must not make one.
    if !crate::commands::custody_has(ctx, UPDATE_ROOT_ALIAS) {
        return plain_out;
    }
    let Ok(root) = update_root(ctx) else {
        return plain_out;
    };
    let Ok(Some(st)) = load_update_state(ctx, op, &root) else {
        return plain_out;
    };
    let Ok(people) = current_people(ctx, op) else {
        return plain_out;
    };
    if people.is_empty() || !people.iter().all(|fp| st.holders.get(fp) == Some(&st.gen)) {
        return plain_out;
    }
    let u = derive_update_secret(&root, &st.pack_id, &people_audience(st.gen));
    (
        text_of(&wrap_key(&key, &u)),
        KEY_FORM_WRAPPED.to_string(),
        Some(plain.to_string()),
    )
}

// ---------------------------------------------------------------------
// The operations
// ---------------------------------------------------------------------

fn read_price(ctx: &WizardCtx, op: i64, rec_json: &str) -> Result<StandbyPrice> {
    let mut seen = Seen::default();
    let v = run(
        ctx,
        op,
        "price",
        rec_json,
        vec![],
        false,
        &mut seen,
        &mut |_| {},
    )?;
    let cents = v
        .get("monthly_net_cents")
        .and_then(Value::as_i64)
        .unwrap_or(-1);
    if cents < 0 {
        return Err(WizardError::Subprocess(
            "the hosting company's price could not be read".into(),
        ));
    }
    Ok(StandbyPrice {
        monthly_cents: cents,
        currency: v
            .get("currency")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        vat_included: false,
    })
}

pub fn price(
    ctx: &WizardCtx,
    input: StandbyPriceInput,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<StandbyPrice> {
    let (json, rec) = record(ctx, input.operator_id)?;
    require_hetzner(&rec)?;
    read_price(ctx, input.operator_id, &json)
}

pub fn add(
    ctx: &WizardCtx,
    input: StandbyAddInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRow> {
    let op = input.operator_id;
    let mode = match input.mode.trim() {
        "" | "sealed" => "sealed",
        "open" => "open",
        other => {
            return Err(WizardError::Validation(format!(
                "standby mode {other:?} (want sealed or open)"
            )))
        }
    };
    // D-1, before anything costs money.
    if mode == "open" && everyone_file(ctx, op) {
        return Err(coded(
            E_STANDBY_OPEN_REFUSED,
            "this relay has an Everyone file, so the standby address must stay sealed",
        ));
    }
    let (prior_json, rec) = record(ctx, op)?;
    require_hetzner(&rec)?;

    let addon_id = match live_row(ctx, op)? {
        Some(r) if r.state == AddonState::Ready && record_standby(&rec).is_some() => return Ok(r),
        Some(r) if r.state == AddonState::Removing => {
            return Err(WizardError::Validation(
                "this standby address is being removed; finish removing it first".into(),
            ))
        }
        // `building` (a run that stopped) or a ready row whose record
        // lost the standby: the helper adopts what is there.
        Some(r) => r.id,
        None => {
            let price = read_price(ctx, op, &prior_json).ok();
            addons::insert(
                ctx,
                &NewAddon {
                    operator_id: op,
                    kind: Some(AddonKind::Standby),
                    state: Some(AddonState::Building),
                    monthly_cost_cents: price.as_ref().map(|p| p.monthly_cents).unwrap_or(0),
                    cost_currency: price.map(|p| p.currency).unwrap_or_default(),
                    detail: Some(serde_json::json!({ "mode": mode })),
                    ..Default::default()
                },
            )?
        }
    };

    let mut seen = Seen::default();
    let res = run(
        ctx,
        op,
        "add",
        &prior_json,
        vec!["--mode".into(), mode.into()],
        true,
        &mut seen,
        on_progress,
    );
    let out = match res {
        Ok(v) => v,
        Err(e) => {
            // The helper gave back what it rented unless it said
            // otherwise; a row with nothing behind it is forgotten.
            let billing = !seen.still_billing.is_empty()
                || e.to_string().contains("still reserved and billing")
                || (seen.created.is_some()
                    && !seen
                        .released
                        .iter()
                        .any(|r| Some(r) == seen.created.as_ref()));
            if billing {
                let fip = seen
                    .still_billing
                    .first()
                    .cloned()
                    .or(seen.created.clone())
                    .unwrap_or_default();
                let _ = addons::set_provider_ids(ctx, addon_id, &provider_ids(&fip));
            } else {
                let _ = addons::forget(ctx, addon_id);
            }
            return Err(e);
        }
    };
    let new_record = out
        .get("record")
        .filter(|r| record_standby(r).is_some())
        .ok_or_else(|| {
            WizardError::Subprocess("standby add: the answer carries no standby".into())
        })?;
    let fip = out
        .get("floating_ip_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    addons::set_provider_ids(ctx, addon_id, &provider_ids(&fip))?;
    ctx.db.update_record_json(op, &new_record.to_string())?;

    on_progress(progress(op, "signing", "running", ""));
    let resigned = match resign_and_republish(ctx, op, Freshness::AllowCached, &mut |_| {}) {
        Ok(r) => r,
        Err(e) => {
            // ROLLBACK. The pack could not be signed with it: put the
            // record back and give the address back.
            on_progress(progress(op, "signing", "failed", ""));
            ctx.db.update_record_json(op, &prior_json)?;
            let mut seen = Seen::default();
            let back = run(
                ctx,
                op,
                "remove",
                &new_record.to_string(),
                vec![],
                true,
                &mut seen,
                on_progress,
            );
            return Err(match back {
                Ok(_) => {
                    let _ = addons::forget(ctx, addon_id);
                    WizardError::Validation(format!(
                        "{e} — the standby address was given back; nothing is billing"
                    ))
                }
                Err(be) => coded(
                    E_STANDBY_STILL_BILLING,
                    format!(
                        "{e} — and the standby address could not be given back ({be}); \
                         it is still billing. Remove it from this relay's add-ons to try again"
                    ),
                ),
            });
        }
    };
    on_progress(progress(op, "signing", "ok", ""));
    addons::set_detail(
        ctx,
        addon_id,
        &serde_json::json!({
            "mode": mode,
            "refresh_note_published": resigned.refresh_note_published,
            "refresh_note_problem": resigned.refresh_note_problem,
        }),
    )?;
    addons::set_state(ctx, addon_id, AddonState::Ready)?;
    addons::get(ctx, addon_id)
}

pub fn promote(
    ctx: &WizardCtx,
    input: StandbyPromoteInput,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<StandbyPromoteResult> {
    let op = input.operator_id;
    let row = match live_row(ctx, op)? {
        Some(r) if r.state == AddonState::Ready => r,
        _ => {
            return Err(WizardError::Validation(
                "this relay has no standby address ready to switch to".into(),
            ))
        }
    };
    let (prior_json, rec) = record(ctx, op)?;
    if record_standby(&rec).is_none() {
        return Err(WizardError::Validation(
            "this relay's record no longer names its standby address; add it again".into(),
        ));
    }
    on_progress(progress(op, "checking", "running", ""));
    let mut seen = Seen::default();
    let out = run(
        ctx,
        op,
        "promote",
        &prior_json,
        vec![],
        false,
        &mut seen,
        on_progress,
    )?;
    on_progress(progress(op, "checking", "ok", ""));
    let key = out
        .get("key")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let new_record = out.get("record").ok_or_else(|| {
        WizardError::Subprocess("standby promote: the answer carries no record".into())
    })?;
    ctx.db.update_record_json(op, &new_record.to_string())?;

    on_progress(progress(op, "signing", "running", ""));
    let resigned = match resign_and_republish(ctx, op, Freshness::AllowCached, &mut |_| {}) {
        Ok(r) => r,
        Err(e) => {
            // Nothing in the cloud moved: putting the record back undoes
            // the whole switch.
            on_progress(progress(op, "signing", "failed", ""));
            ctx.db.update_record_json(op, &prior_json)?;
            return Err(e);
        }
    };
    on_progress(progress(op, "signing", "ok", ""));
    let mut warnings: Vec<String> = out
        .get("warnings")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|w| w.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if !resigned.refresh_note_problem.is_empty() {
        warnings.push(resigned.refresh_note_problem.clone());
    }
    let prior_fip = out
        .get("prior_floating_ip_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    addons::set_detail(
        ctx,
        row.id,
        &serde_json::json!({
            "mode": row.detail.get("mode").cloned().unwrap_or(Value::Null),
            "key": key,
            "promoted_at_unix": (ctx.clock)(),
            "prior_floating_ip_id": prior_fip,
        }),
    )?;
    addons::set_state(ctx, row.id, AddonState::Promoted)?;
    // The update notes reveal the key now (addon_notes): the micro note
    // for phones that cannot fetch the new pack. Never fails the switch.
    let _ = crate::addon_notes::write_relay(ctx, op);
    // The row keeps the plain key; what is shown is the code to send.
    let (key, key_form, plain_key) = code_to_send(ctx, op, &key);
    Ok(StandbyPromoteResult {
        addon: addons::get(ctx, row.id)?,
        key,
        key_form,
        plain_key,
        refresh_note_published: resigned.refresh_note_published,
        warnings,
    })
}

pub fn key(
    ctx: &WizardCtx,
    input: StandbyKeyInput,
    _on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<StandbyKey> {
    let op = input.operator_id;
    let rows: Vec<AddonRow> = addons::list(ctx, op)?
        .into_iter()
        .filter(|r| r.kind == AddonKind::Standby)
        .collect();
    // A ready standby first: its key is what a switch would send.
    if rows.iter().any(|r| r.state == AddonState::Ready) {
        let (_, rec) = record(ctx, op)?;
        if let Some(k) = record_standby(&rec).and_then(key_of) {
            let (key, form, plain_key) = code_to_send(ctx, op, &k);
            return Ok(StandbyKey { key, form, plain_key });
        }
    }
    // Else the most recent switch.
    if let Some(k) = rows
        .iter()
        .rev()
        .filter(|r| r.state == AddonState::Promoted)
        .find_map(|r| {
            r.detail
                .get("key")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .filter(|k| !k.is_empty())
    {
        let (key, form, plain_key) = code_to_send(ctx, op, &k);
        return Ok(StandbyKey { key, form, plain_key });
    }
    Err(WizardError::Validation(
        "this relay has no standby key".into(),
    ))
}

/// Called by `addons::remove`. Order (plan §1.6): sign again without
/// `_standby` and publish, then unbind on the box, then delete the
/// Floating IP, then `addons::forget`.
pub fn remove(
    ctx: &WizardCtx,
    row: &AddonRow,
    on_progress: &mut dyn FnMut(AddonProgress),
) -> Result<AddonRemoveReport> {
    let op = row.operator_id;
    if row.state == AddonState::Promoted {
        return Err(WizardError::Validation(
            "this address is the relay's own address now; it goes when the relay is deleted".into(),
        ));
    }
    let (json, rec) = record(ctx, op)?;
    let mut report = AddonRemoveReport {
        addon_id: row.id,
        ..Default::default()
    };

    // 1. A pack without it, signed and published, BEFORE the address
    //    can go back to Hetzner's pool.
    let mut record_now = json.clone();
    if record_standby(&rec).is_some() {
        let without = without_standby(&rec);
        let prior_state = row.state;
        ctx.db.update_record_json(op, &without)?;
        addons::set_state(ctx, row.id, AddonState::Removing)?;
        on_progress(progress(op, "signing", "running", ""));
        match resign_and_republish(ctx, op, Freshness::AllowCached, &mut |_| {}) {
            Err(e) => {
                on_progress(progress(op, "signing", "failed", ""));
                ctx.db.update_record_json(op, &json)?;
                addons::set_state(ctx, row.id, prior_state)?;
                return Err(e);
            }
            Ok(r) => {
                on_progress(progress(op, "signing", "ok", ""));
                if r.prior_pack_had_refresh_addresses && !r.refresh_note_published {
                    let mut d = row.detail.clone();
                    if let Some(m) = d.as_object_mut() {
                        m.insert("publish_pending".into(), Value::Bool(true));
                    }
                    addons::set_detail(ctx, row.id, &d)?;
                    return Err(coded(
                        E_STANDBY_NOT_PUBLISHED,
                        format!(
                            "the pack without the standby address could not reach the refresh addresses ({}); \
                             it is kept, and still billing, until it does — try again",
                            r.refresh_note_problem
                        ),
                    ));
                }
            }
        }
        record_now = without;
    } else if row.detail.get("publish_pending").and_then(Value::as_bool) == Some(true) {
        on_progress(progress(op, "publishing", "running", ""));
        let ok = matches!(
            crate::freshness::publish(ctx, op, &mut |_| {}),
            Ok(r) if r.blocked_reason.is_empty() && r.succeeded >= r.min_mirrors
        );
        if !ok {
            on_progress(progress(op, "publishing", "failed", ""));
            return Err(coded(
                E_STANDBY_NOT_PUBLISHED,
                "the pack without the standby address still has not reached the refresh addresses; try again",
            ));
        }
        on_progress(progress(op, "publishing", "ok", ""));
    }

    // 2 + 3. The helper unbinds on the box, then releases every standby
    // of this relay the record does not advertise.
    let mut seen = Seen::default();
    match run(
        ctx,
        op,
        "remove",
        &record_now,
        vec![],
        true,
        &mut seen,
        on_progress,
    ) {
        Ok(out) => {
            report.warnings = out
                .get("warnings")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|w| w.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            addons::forget(ctx, row.id)?;
            report.removed = true;
            Ok(report)
        }
        Err(e) if e.to_string().starts_with(E_STANDBY_STILL_BILLING) => {
            let _ = addons::set_state(ctx, row.id, AddonState::Removing);
            report.still_billing = if seen.still_billing.is_empty() {
                row.provider_ids
                    .get("floating_ip_id")
                    .cloned()
                    .into_iter()
                    .collect()
            } else {
                seen.still_billing
            };
            report.warnings.push(e.to_string());
            Ok(report)
        }
        Err(e) => Err(e),
    }
}

/// Called by `addons::before_relay_destroy`. Nothing to do here: the
/// Floating IP carries the relay's labels, and `decommission
/// --release-addresses` releases every such address once the server is
/// gone. So the row is neither forgotten now (`removed: false`) nor a
/// reason to keep the relay (`keeps_relay: false`): it goes with the
/// relay row, and when an address cannot be released the relay row
/// stays (marked decommissioned, naming what still bills) and this row
/// with it — the same call is the retry.
pub fn on_relay_delete(_ctx: &WizardCtx, row: &AddonRow) -> AddonOutcome {
    AddonOutcome {
        addon_id: row.id,
        kind: row.kind,
        removed: false,
        keeps_relay: false,
        code: "with_relay".into(),
        error: String::new(),
    }
}

#[cfg(test)]
#[path = "addon_standby_tests.rs"]
mod tests;
