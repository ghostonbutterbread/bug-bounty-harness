from agents.apk_profiles import ApkHuntProfile


PROFILE = ApkHuntProfile(
    key="ipc-surface-hunter",
    title="IPC Surface Hunter",
    description=(
        "Review exported activities, services, and PendingIntent surfaces for intent spoofing, "
        "extra injection, privilege confusion, and command execution reachability."
    ),
    surface_types=("exported-activity", "exported-service", "pending-intent", "command-exec"),
    entry_questions=(
        "Which exported components accept attacker-supplied intents, extras, clip data, or URIs?",
        "Are PendingIntents mutable, implicit, or reused across trust boundaries?",
    ),
    cross_questions=(
        "Can another app cause privileged actions without the app's normal auth or UI flow?",
        "Do intent extras cross from exported components into file access, account actions, or execution sinks?",
    ),
    sink_categories=(
        "Privileged actions reachable from exported services or activities",
        "Mutable or implicit PendingIntent hijacking",
        "Implicit intents carrying attacker-controlled nested intents or URIs",
        "Exported flows reaching Runtime.exec, loaders, or sensitive provider operations",
    ),
    reasoning=(
        "Treat every exported component as an IPC trust boundary. Follow extras, actions, and data URIs into privileged methods, "
        "especially debug, admin, account, upload, and internal routing code."
    ),
    tags=("ipc", "intent"),
)

