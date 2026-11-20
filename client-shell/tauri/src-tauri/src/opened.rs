//! "Open with Daal", "Share to Daal" and the text share sheet
//! (UI spec G.1 and G.2, X-13).
//!
//! Two commands and one event, fixed for the UI lanes:
//!
//! * `take_opened_file() -> string | null`: the file Android handed the
//!   app (VIEW from a messenger or a file manager, SEND with one file,
//!   or SEND with text), copied into `<staging>/opened/`. Returned once,
//!   then null. On desktop: a `.sbp` / `.sbpx` path given on the command
//!   line (a file manager's "Open with"), once.
//! * event `daal://opened-file` with `{ path }`: one that arrives while
//!   the app runs. It fires only after the page has called
//!   `take_opened_file` once (that is how the page says it is
//!   listening), so the page must register its listener BEFORE its first
//!   `take_opened_file`. Before that, a new arrival waits for the take.
//! * `share_text({ text, title })`: the Android share sheet with plain
//!   text; on desktop the text is put on the clipboard.
//!
//! NOTHING IS IMPORTED HERE. A staged path is handed to the page, which
//! shows the file (preview, trust prompt, signature check) and lets the
//! person decide, exactly as for a file picked with "Choose a file".
//!
//! A shared TEXT is decoded with the paste decoder: a Daal file pasted
//! as text is staged as the `.sbp` / `.sbpx` it holds, so the page
//! treats it like any file. Text that holds no Daal file is staged as
//! `opened-<tag>.txt`, which the page's import refuses ("not a Daal
//! file") instead of the share doing nothing.
//!
//! The Android side is `platform/OpenedFiles.kt` and
//! `platform/ShareText.kt` in the daal-platform plugin; which intents
//! are taken and how a staged file is named is decided in
//! `vpn/OpenedIntent.kt` (tested by tools/test-android-jvm.sh).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use daal_desktop_core::cmdlog;
use tauri::{AppHandle, Manager};

use crate::WizardStateMgr;

/// The event a file that arrives while the app runs is announced on.
pub const OPENED_FILE_EVENT: &str = "daal://opened-file";

/// The page has asked for opened files at least once, so it listens
/// for [`OPENED_FILE_EVENT`].
static PAGE_LISTENS: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "android")]
static APP: std::sync::OnceLock<AppHandle> = std::sync::OnceLock::new();

#[derive(Clone, serde::Serialize)]
struct OpenedFilePayload {
    path: String,
}

/// The directory opened files are staged in.
pub fn opened_dir(staging_dir: &Path) -> PathBuf {
    staging_dir.join("opened")
}

fn staging_dir_of(app: &AppHandle) -> PathBuf {
    match app.try_state::<WizardStateMgr>() {
        Some(w) => w.0.staging_dir.clone(),
        // The operator database did not open (see run()). The file can
        // still be shown; a sealed one will be refused by its import.
        None => std::env::temp_dir().join("daal-opened-staging"),
    }
}

/// Called once from the app's setup: remembers the app handle (for the
/// event) and removes files staged by an earlier run. Anything in the
/// directory at launch was handed to a page that is gone; this run has
/// staged nothing yet, because nothing is staged before the page asks.
pub fn install(app: &AppHandle) {
    #[cfg(target_os = "android")]
    {
        let _ = APP.set(app.clone());
    }
    let dir = opened_dir(&staging_dir_of(app));
    clear_dir(&dir);
}

fn clear_dir(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_file() {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
}

/// A shared text, staged as `opened-<tag>.txt`, becomes the file it
/// holds: the same stem with the `.sbp` / `.sbpx` extension. Text that
/// holds no Daal file (or cannot be read) is emptied and its path
/// returned, so the page still refuses it ("not a Daal file", by the
/// extension) but its words are not kept at rest: it may be a private
/// message or a password shared to Daal by mistake. Any other path is
/// returned unchanged.
pub fn finish_staged(path: PathBuf) -> PathBuf {
    let is_txt = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("txt"))
        .unwrap_or(false);
    if !is_txt {
        return path;
    }
    let refuse = |p: PathBuf| -> PathBuf {
        let _ = std::fs::write(&p, b"");
        p
    };
    let too_big = std::fs::metadata(&path)
        .map(|m| m.len() > daal_wizard::recipient_paste::MAX_INPUT_BYTES as u64)
        .unwrap_or(true);
    if too_big {
        return refuse(path);
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return refuse(path);
    };
    let text = String::from_utf8_lossy(&bytes);
    let Ok(decoded) = daal_wizard::recipient_paste::decode_pasted(&text) else {
        return refuse(path);
    };
    let dest = path.with_extension(decoded.kind.extension());
    if write_new_private(&dest, &decoded.bytes).is_err() {
        return refuse(path);
    }
    let _ = std::fs::remove_file(&path);
    dest
}

/// Write a new file (never over an existing name or through a symlink),
/// readable only by the app on unix.
fn write_new_private(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(dest)?;
    if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
        drop(f);
        let _ = std::fs::remove_file(dest);
        return Err(e);
    }
    Ok(())
}

/// The `.sbp` / `.sbpx` file named on a desktop command line, if any:
/// the first argument after the program that is not a flag, ends in one
/// of those extensions and is a file.
#[cfg_attr(target_os = "android", allow(dead_code))]
pub fn arg_file<I: IntoIterator<Item = String>>(args: I) -> Option<String> {
    args.into_iter().skip(1).find(|a| {
        if a.starts_with('-') {
            return false;
        }
        let lower = a.to_ascii_lowercase();
        (lower.ends_with(".sbpx") || lower.ends_with(".sbp")) && Path::new(a).is_file()
    })
}

#[cfg(not(target_os = "android"))]
static ARG_TAKEN: AtomicBool = AtomicBool::new(false);

/// Stage the file or text Android is holding for the page, if any.
#[cfg(target_os = "android")]
fn stage_pending(app: &AppHandle) -> Result<Option<String>, String> {
    let dir = opened_dir(&staging_dir_of(app));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir opened: {e}"))?;
    let raw = android::take(&dir)?;
    Ok(raw.map(|p| finish_staged(PathBuf::from(p)).to_string_lossy().to_string()))
}

#[cfg(not(target_os = "android"))]
fn stage_pending(_app: &AppHandle) -> Result<Option<String>, String> {
    if ARG_TAKEN.swap(true, Ordering::SeqCst) {
        return Ok(None);
    }
    Ok(arg_file(std::env::args()))
}

/// The file the app was opened with, once; then null. See the module
/// docs. Async: on Android it reads another app's provider, which must
/// not hold the thread that drives the window.
#[tauri::command]
pub async fn take_opened_file(app: AppHandle) -> Result<Option<String>, String> {
    PAGE_LISTENS.store(true, Ordering::SeqCst);
    cmdlog::result(
        "take_opened_file",
        tauri::async_runtime::spawn_blocking(move || stage_pending(&app))
            .await
            .map_err(|e| format!("take_opened_file: {e}"))
            .and_then(|r| r),
    )
}

/// Open the share sheet with plain text (Android), or put the text on
/// the clipboard (desktop). An error means neither happened; the page
/// then copies the text itself.
#[tauri::command]
pub async fn share_text(text: String, title: Option<String>) -> Result<(), String> {
    cmdlog::result(
        "share_text",
        tauri::async_runtime::spawn_blocking(move || share_text_blocking(&text, title.as_deref()))
            .await
            .map_err(|e| format!("share_text: {e}"))
            .and_then(|r| r),
    )
}

#[cfg(target_os = "android")]
fn share_text_blocking(text: &str, title: Option<&str>) -> Result<(), String> {
    android::share_text(text, title.unwrap_or(""))
}

#[cfg(not(target_os = "android"))]
fn share_text_blocking(text: &str, _title: Option<&str>) -> Result<(), String> {
    desktop_clipboard::copy(text)
}

#[cfg(target_os = "android")]
mod android {
    use std::path::Path;

    use jni::objects::{JClass, JObject, JString, JValue};
    use jni::JNIEnv;

    const OPENED_FILES: &str = "org/daal/desktop/platform/OpenedFiles";
    const SHARE_TEXT: &str = "org/daal/desktop/platform/ShareText";

    /// Find one of the app's own classes from any thread. `FindClass`
    /// on a thread the JVM did not start (the blocking pool, a spawned
    /// thread) searches the system class loader and misses app classes,
    /// so it falls back to the app context's own loader.
    fn app_class<'l>(env: &mut JNIEnv<'l>, slashed: &str) -> Result<JClass<'l>, String> {
        if let Ok(c) = env.find_class(slashed) {
            return Ok(c);
        }
        let _ = env.exception_clear();
        let ctx = ndk_context::android_context();
        if ctx.context().is_null() {
            return Err("no Android context".into());
        }
        let context = unsafe { JObject::from_raw(ctx.context().cast()) };
        let run = |env: &mut JNIEnv<'l>| -> jni::errors::Result<JObject<'l>> {
            let loader = env
                .call_method(&context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
                .l()?;
            let name = env.new_string(slashed.replace('/', "."))?;
            env.call_method(
                &loader,
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                &[JValue::Object(&name)],
            )?
            .l()
        };
        match run(env) {
            Ok(obj) if !obj.is_null() => Ok(JClass::from(obj)),
            Ok(_) => Err(format!("class {slashed} not found")),
            Err(e) => {
                let _ = env.exception_clear();
                Err(format!("class {slashed}: {e}"))
            }
        }
    }

    fn with_env<T>(f: impl FnOnce(&mut JNIEnv) -> Result<T, String>) -> Result<T, String> {
        let ctx = ndk_context::android_context();
        if ctx.vm().is_null() {
            return Err("no JavaVM".into());
        }
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| format!("attach JavaVM: {e}"))?;
        let out = match vm.attach_current_thread() {
            Ok(mut env) => {
                let r = f(&mut env);
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                r
            }
            Err(e) => Err(format!("attach thread: {e}")),
        };
        // The JavaVM came from a raw pointer ndk_context owns.
        std::mem::forget(vm);
        out
    }

    /// `OpenedFiles.take(destDir)`: the staged path, or None.
    pub fn take(dir: &Path) -> Result<Option<String>, String> {
        let dir = dir.to_string_lossy().to_string();
        with_env(|env| {
            let class = app_class(env, OPENED_FILES)?;
            let j_dir = env.new_string(&dir).map_err(|e| format!("j_dir: {e}"))?;
            let obj = env
                .call_static_method(
                    &class,
                    "take",
                    "(Ljava/lang/String;)Ljava/lang/String;",
                    &[JValue::Object(&j_dir)],
                )
                .and_then(|v| v.l())
                .map_err(|e| format!("call OpenedFiles.take: {e}"))?;
            if obj.is_null() {
                return Ok(None);
            }
            let js = JString::from(obj);
            let s: String = env
                .get_string(&js)
                .map(String::from)
                .map_err(|e| format!("read staged path: {e}"))?;
            Ok(if s.is_empty() { None } else { Some(s) })
        })
    }

    /// `ShareText.share(text, title)`.
    pub fn share_text(text: &str, title: &str) -> Result<(), String> {
        with_env(|env| {
            let class = app_class(env, SHARE_TEXT)?;
            let j_text = env.new_string(text).map_err(|e| format!("j_text: {e}"))?;
            let j_title = env.new_string(title).map_err(|e| format!("j_title: {e}"))?;
            let ok = env
                .call_static_method(
                    &class,
                    "share",
                    "(Ljava/lang/String;Ljava/lang/String;)Z",
                    &[JValue::Object(&j_text), JValue::Object(&j_title)],
                )
                .and_then(|v| v.z())
                .map_err(|e| format!("call ShareText.share: {e}"))?;
            if ok {
                Ok(())
            } else {
                Err("the share sheet could not be opened".into())
            }
        })
    }

    /// `OpenedFiles.nativeArrived()`: a file or text arrived while the
    /// app runs (onNewIntent, on the main thread). Once the page
    /// listens, it is staged on another thread and announced; before
    /// that it waits for the page's first `take_opened_file`.
    #[no_mangle]
    pub extern "system" fn Java_org_daal_desktop_platform_OpenedFiles_nativeArrived<'l>(
        _env: JNIEnv<'l>,
        _this: JObject<'l>,
    ) {
        if !super::PAGE_LISTENS.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let Some(app) = super::APP.get().cloned() else {
            return;
        };
        std::thread::spawn(move || {
            use tauri::Emitter;
            match super::stage_pending(&app) {
                Ok(Some(path)) => {
                    if let Err(e) = app.emit(
                        super::OPENED_FILE_EVENT,
                        super::OpenedFilePayload { path },
                    ) {
                        log::warn!("opened file: could not announce it: {e}");
                    }
                }
                Ok(None) => {}
                Err(e) => log::warn!("opened file: could not stage it: {e}"),
            }
        });
    }
}

#[cfg(not(target_os = "android"))]
mod desktop_clipboard {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// The platform's own clipboard tools, in the order tried. No new
    /// dependency: the shell had no clipboard crate.
    fn tools() -> Vec<(&'static str, Vec<&'static str>)> {
        #[cfg(target_os = "macos")]
        {
            vec![("pbcopy", vec![])]
        }
        #[cfg(target_os = "windows")]
        {
            vec![(
                "powershell",
                vec![
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "[Console]::InputEncoding=[Text.Encoding]::UTF8; Set-Clipboard -Value ([Console]::In.ReadToEnd())",
                ],
            )]
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let mut v: Vec<(&'static str, Vec<&'static str>)> = Vec::new();
            if std::env::var_os("WAYLAND_DISPLAY").is_some() {
                v.push(("wl-copy", vec![]));
            }
            v.push(("xclip", vec!["-selection", "clipboard"]));
            v.push(("xsel", vec!["--clipboard", "--input"]));
            v
        }
    }

    fn run(program: &str, args: &[&str], text: &str) -> bool {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            // CREATE_NO_WINDOW: no console flashes up.
            cmd.creation_flags(0x0800_0000);
        }
        let Ok(mut child) = cmd.spawn() else {
            return false;
        };
        if let Some(mut stdin) = child.stdin.take() {
            if stdin.write_all(text.as_bytes()).is_err() {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
        // xclip, xsel and wl-copy read their input, fork a process that
        // holds the selection, and exit. One still running after a few
        // seconds has taken the text and is holding it.
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status.success(),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Ok(None) => return true,
                Err(_) => return false,
            }
        }
    }

    pub fn copy(text: &str) -> Result<(), String> {
        for (program, args) in tools() {
            if run(program, &args, text) {
                return Ok(());
            }
        }
        Err("no clipboard tool answered".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn a_staged_file_is_returned_unchanged() {
        let d = tmp();
        let p = d.path().join("opened-ab.sbpx");
        std::fs::write(&p, b"DSBP").unwrap();
        assert_eq!(finish_staged(p.clone()), p);
        assert!(p.exists());
    }

    #[test]
    fn shared_text_with_a_daal_file_becomes_that_file() {
        let d = tmp();
        // A zip local-file header followed by enough bytes to be a
        // container, pasted with chatter in front.
        let mut bytes = vec![0x50, 0x4b, 0x03, 0x04];
        bytes.extend(std::iter::repeat(7u8).take(200));
        let text = format!(
            "salam, ino bezan:\n{}",
            daal_wizard::recipient_paste::encode_pasteable(&bytes)
        );
        let p = d.path().join("opened-ab.txt");
        std::fs::write(&p, text).unwrap();
        let out = finish_staged(p.clone());
        assert_eq!(out, d.path().join("opened-ab.sbp"));
        assert_eq!(std::fs::read(&out).unwrap(), bytes);
        assert!(!p.exists(), "the text is removed once its file is staged");
    }

    #[test]
    fn other_shared_text_is_left_for_the_page_to_refuse_but_not_kept() {
        let d = tmp();
        let p = d.path().join("opened-ab.txt");
        std::fs::write(&p, "my password is hunter2").unwrap();
        assert_eq!(finish_staged(p.clone()), p);
        assert!(p.exists(), "the page refuses it by its .txt name");
        assert_eq!(std::fs::read(&p).unwrap().len(), 0, "its words are not kept at rest");
    }

    #[test]
    fn launch_clears_files_an_earlier_run_staged() {
        let d = tmp();
        let dir = opened_dir(d.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("opened-1.sbp"), b"x").unwrap();
        clear_dir(&dir);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        clear_dir(&d.path().join("missing"));
    }

    #[test]
    fn only_a_daal_file_on_the_command_line_is_taken() {
        let d = tmp();
        let f = d.path().join("Maman.SBPX");
        std::fs::write(&f, b"x").unwrap();
        let f = f.to_string_lossy().to_string();
        let prog = "daal-desktop".to_string();
        assert_eq!(arg_file(vec![prog.clone(), "--flag".into(), f.clone()]), Some(f.clone()));
        assert_eq!(arg_file(vec![prog.clone()]), None);
        assert_eq!(arg_file(vec![f.clone()]), None, "the program itself is skipped");
        let missing = d.path().join("gone.sbp").to_string_lossy().to_string();
        assert_eq!(arg_file(vec![prog.clone(), missing]), None);
        let other = d.path().join("x.txt");
        std::fs::write(&other, b"x").unwrap();
        assert_eq!(arg_file(vec![prog, other.to_string_lossy().to_string()]), None);
    }
}
