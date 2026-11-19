# Keep JNI-reachable entry points used by the in-process engine.
-keep class org.daal.desktop.platform.DaalCoreBridge { *; }
-keep class org.daal.desktop.vpn.DaalVpnService { *; }
-keepclassmembers class * {
    native <methods>;
}
# PB-3: reached from Rust by JNI (src-tauri save_path_to_downloads).
-keep class org.daal.desktop.platform.DownloadsSaver { *; }
