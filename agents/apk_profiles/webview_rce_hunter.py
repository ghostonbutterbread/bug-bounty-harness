from agents.apk_profiles import ApkHuntProfile


PROFILE = ApkHuntProfile(
    key="webview-rce-hunter",
    title="WebView RCE Hunter",
    description=(
        "Trace attacker-controlled navigation, bridge exposure, and WebView callbacks into Android-native sinks. "
        "Prioritize evidence-backed WebView exploit chains over configuration-only observations."
    ),
    surface_types=("webview", "command-exec", "dynamic-loader", "url-scheme"),
    entry_questions=(
        "Which WebView classes are reachable from exported activities, deep links, share flows, or externally supplied URLs?",
        "Which exact methods load attacker-influenced URLs, HTML, JS, postMessage payloads, or asset content into a WebView?",
    ),
    cross_questions=(
        "Does attacker-controlled WebView content reach addJavascriptInterface, evaluateJavascript, WebMessagePort, file access, or permissive settings in the same execution path?",
        "After WebView entry, which callbacks or bridge methods can trigger privileged intents, provider access, dynamic loading, or command/native execution?",
    ),
    sink_categories=(
        "Untrusted content reaching addJavascriptInterface or bridge registration",
        "Attacker-controlled strings reaching evaluateJavascript, loadUrl javascript:, or WebMessage channels",
        "WebView settings that enable file or universal access on attacker-reachable pages",
        "Bridge or callback methods that cross into privileged Android actions, loaders, providers, or native code",
    ),
    reasoning=(
        "Use a 0day-style path narrative: entrypoint, attacker control, boundary, gate, sink, exploitability. "
        "Only emit findings when you can name the concrete WebView entry method and the downstream privileged sink or missing guard. "
        "If you only see risky configuration without attacker reachability, return empty output."
    ),
    prompt_addendum=(
        "Prioritize WebViewClient/ChromeClient callbacks, deep-link seeded navigation, share/open/view handlers, "
        "javascript: URLs, postMessage bridges, and classes that convert web content into Android intents or native calls."
    ),
    tags=("webview", "javascript", "evidence-first"),
)

