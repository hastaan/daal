# Forwarded to the app's R8 step so DaalVpnService + DaalCoreBridge
# survive minification even when the app enables it.
-keep class org.daal.desktop.platform.DaalCoreBridge { *; }
-keep class org.daal.desktop.vpn.DaalVpnService { *; }
-keepclassmembers class * {
    native <methods>;
}
