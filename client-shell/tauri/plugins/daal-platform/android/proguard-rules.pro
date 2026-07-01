# Keep JNI-reachable entry points used by the in-process engine.
-keep class org.daal.desktop.platform.DaalCoreBridge { *; }
-keep class org.daal.desktop.vpn.DaalVpnService { *; }
-keepclassmembers class * {
    native <methods>;
}
