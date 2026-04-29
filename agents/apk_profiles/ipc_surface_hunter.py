from agents.apk_profiles import ApkHuntProfile


PROFILE = ApkHuntProfile(
    key="ipc-surface-hunter",
    title="IPC Surface Hunter",
    description=(
        "Trace exported Android IPC entrypoints into privileged actions with a concrete caller-to-sink narrative. "
        "Focus on intent spoofing, nested-intent abuse, mutable PendingIntent misuse, and authz gaps."
    ),
    surface_types=("exported-activity", "exported-service", "pending-intent", "command-exec", "url-scheme"),
    entry_questions=(
        "Which exported activities, services, receivers, or aliases accept attacker-controlled actions, extras, ClipData, nested intents, or URIs?",
        "Which exact entry methods parse those inputs and what caller validation, permission, or auth checks happen before routing onward?",
    ),
    cross_questions=(
        "Can a third-party app trigger a privileged internal action without the normal authenticated UI or user gesture?",
        "Do exported inputs cross into account actions, internal routers, file/provider access, loaders, or execution sinks with missing or weak validation?",
    ),
    sink_categories=(
        "Exported component entrypoints reaching privileged internal methods",
        "Mutable, implicit, or reusable PendingIntent objects crossing trust boundaries",
        "Nested-intent, ClipData, or URI inputs steering internal routing or confused-deputy behavior",
        "IPC-reachable flows that end in execution, provider, account, file, or admin sinks",
    ),
    reasoning=(
        "Work like 0day_team: start from the exported boundary, identify exactly what the attacker controls, then follow that data to the first privileged action or dangerous sink. "
        "Only emit findings when you can explain the missing gate or why the existing gate is bypassable. "
        "If the component is exported but the sink path is not concrete, return empty output."
    ),
    prompt_addendum=(
        "Prioritize handlers named open, view, share, route, debug, auth, callback, upload, intent, pendingintent, proxy, bridge, and internal launcher flows. "
        "Look hard for extras copied into new intents, provider URIs, file operations, or admin/account actions."
    ),
    tags=("ipc", "intent", "evidence-first"),
)

