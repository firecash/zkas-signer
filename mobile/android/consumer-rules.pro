# JNA resolves the native methods reflectively, so R8 must not strip or rename
# the binding classes or their callbacks.
-keep class info.zkas.mobile.** { *; }
-keep class uniffi.zkas_mobile.** { *; }
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }
