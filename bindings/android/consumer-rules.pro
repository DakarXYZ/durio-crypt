# R8 rules shipped inside the AAR (AN-20): the app needs none of its own.
# JNA reads Structure fields and calls back through reflection; without
# <fields> the release build fails at runtime.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.Structure { <fields>; }
-keep class uniffi.stoat_crypto.** { *; }
-dontwarn java.awt.**
