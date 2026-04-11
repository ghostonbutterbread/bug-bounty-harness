from agents.apk_profiles import ApkHuntProfile


PROFILE = ApkHuntProfile(
    key="deep-link-hunter",
    title="Deep Link Hunter",
    description=(
        "Audit custom URL schemes and exported intent filters for unsafe URI parsing, "
        "open redirects, auth bypass, intent construction abuse, and injection into privileged flows."
    ),
    surface_types=("url-scheme", "exported-activity"),
    entry_questions=(
        "Which exported activities accept attacker-controlled URIs or intent extras?",
        "How are deep-link parameters parsed, normalized, and routed after entry?",
    ),
    cross_questions=(
        "Can a lower-trust URI or intent extra choose a privileged destination or action?",
        "Do deep links bypass auth, origin checks, feature gates, or host/scheme allowlists?",
    ),
    sink_categories=(
        "Unsafe URI parsing and host/path confusion",
        "Intent redirection or nested-intent abuse",
        "WebView navigation seeded from deep-link parameters",
        "File or content URI access derived from attacker input",
    ),
    reasoning=(
        "Treat every custom scheme and exported VIEW/BROWSABLE entry point as attacker-controlled. "
        "Follow URI pieces into routing, auth, file access, and WebView sinks."
    ),
    prompt_addendum=(
        "Prioritize activities named around login, oauth, auth callback, share, redirect, open, view, and browser flows."
    ),
    tags=("deeplink", "intent"),
)

