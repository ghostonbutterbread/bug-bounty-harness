from agents.apk_profiles import ApkHuntProfile


PROFILE = ApkHuntProfile(
    key="webview-rce-hunter",
    title="WebView RCE Hunter",
    description=(
        "Analyze WebView usage for JavaScript bridge abuse, local file access, dangerous navigation, "
        "and WebView-to-native code execution paths."
    ),
    surface_types=("webview", "command-exec", "dynamic-loader"),
    entry_questions=(
        "Which classes instantiate or configure WebView and what attacker-controlled content reaches them?",
        "Are JavaScript interfaces, evaluateJavascript, or permissive settings exposed to untrusted pages?",
    ),
    cross_questions=(
        "Can remote or deep-link-supplied content reach a privileged JavaScript bridge?",
        "Do WebView callbacks bridge into command execution, loaders, content providers, or native code?",
    ),
    sink_categories=(
        "addJavascriptInterface on attacker-reachable content",
        "evaluateJavascript fed by attacker-controlled strings",
        "setAllowFileAccess or universal access enabling local file exfiltration",
        "WebView callbacks that invoke Runtime.exec, loaders, or privileged intents",
    ),
    reasoning=(
        "Start from WebView classes, then check whether URI handlers, remote content, or asset pages can reach "
        "native bridges or execution sinks. Distinguish configuration-only code from actually reachable flows."
    ),
    tags=("webview", "javascript"),
)

