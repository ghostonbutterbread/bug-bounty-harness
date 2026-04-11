from agents.apk_profiles import ApkHuntProfile


PROFILE = ApkHuntProfile(
    key="native-abuse-hunter",
    title="Native Abuse Hunter",
    description=(
        "Inspect native library loading, JNI bridges, and dynamic dex or class loading for attacker-controlled "
        "code execution or dangerous trust-boundary crossings."
    ),
    surface_types=("native-library", "jni-load", "dynamic-loader"),
    entry_questions=(
        "Which Java classes load native libraries or declare native methods?",
        "Can attacker-controlled file paths, names, bytes, or configuration choose what native code loads or how it is called?",
    ),
    cross_questions=(
        "Do remote, IPC, or deep-link inputs cross into JNI wrappers or dynamic loading code?",
        "Are library names, extraction locations, or loader inputs attacker-influenced?",
    ),
    sink_categories=(
        "System.load or loadLibrary on attacker-controlled path or name",
        "DexClassLoader or similar fed from external storage, downloads, or content URIs",
        "JNI methods processing untrusted bytes or paths with weak validation",
        "Native parsing entry points reachable from exported or remote surfaces",
    ),
    reasoning=(
        "Focus on reachability into loadLibrary, DexClassLoader, and native wrappers. "
        "A dormant native bug is still valuable if the Java side exposes the right entry path."
    ),
    tags=("native", "jni"),
)

