from agents.apk_profiles import ApkHuntProfile


PROFILE = ApkHuntProfile(
    key="manifest-audit",
    title="Manifest Audit",
    description=(
        "Perform a targeted manifest audit for exported surface sprawl, weak permission protection levels, "
        "debuggable or backup settings, and platform configuration that enlarges the attack surface."
    ),
    surface_types=(
        "permission",
        "exported-activity",
        "exported-service",
        "exported-provider",
        "exported-receiver",
    ),
    entry_questions=(
        "Which manifest declarations expose cross-app attack surface or weak trust boundaries?",
        "Are dangerous permissions, backup settings, or cleartext/network config inconsistent with the app's trust model?",
    ),
    cross_questions=(
        "Do manifest permissions actually protect the exposed components behind them?",
        "Are there configuration mismatches that make otherwise-internal components reachable in practice?",
    ),
    sink_categories=(
        "Exported component sprawl without strong permissions",
        "Custom permissions with weak or missing protectionLevel",
        "allowBackup, debuggable, or cleartext traffic expanding practical attackability",
        "Manifest-declared surfaces that lead into higher-risk smali hints",
    ),
    reasoning=(
        "Use the manifest as the top-level trust map. This profile should connect manifest declarations to the concrete smali files and risky helper APIs behind them."
    ),
    tags=("manifest", "permissions"),
)

