//! Finding the app's own Java classes from any thread.
//!
//! `FindClass` on a thread the JVM did not start (Tauri's blocking pool,
//! a thread the Go engine made, a spawned worker) searches only the
//! system class loader and misses every app class. The failed lookup
//! leaves a `ClassNotFoundException` pending, and a pending exception at
//! detach kills the app ("FATAL EXCEPTION: Thread-9"). So every native
//! lookup of an app class goes through [`app_class`]: plain `FindClass`
//! first, then the app context's own class loader, and never an
//! exception left pending.

#![cfg(target_os = "android")]

use jni::objects::{JClass, JObject, JValue};
use jni::JNIEnv;

pub fn app_class<'l>(env: &mut JNIEnv<'l>, slashed: &str) -> Result<JClass<'l>, String> {
    if let Ok(c) = env.find_class(slashed) {
        return Ok(c);
    }
    let _ = env.exception_clear();
    let ctx = ndk_context::android_context();
    if ctx.context().is_null() {
        return Err(format!("class {slashed}: no Android context"));
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
    let out = match run(env) {
        Ok(obj) if !obj.is_null() => Ok(JClass::from(obj)),
        Ok(_) => Err(format!("class {slashed} not found")),
        Err(e) => {
            let _ = env.exception_clear();
            Err(format!("class {slashed}: {e}"))
        }
    };
    // The context is borrowed from ndk_context, not ours to delete.
    std::mem::forget(context);
    out
}
