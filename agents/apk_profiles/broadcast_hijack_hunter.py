from agents.apk_profiles import ApkHuntProfile


PROFILE = ApkHuntProfile(
    key="broadcast-hijack-hunter",
    title="Broadcast Hijack Hunter",
    description=(
        "Review exported receivers and ordered-broadcast flows for spoofing, interception, confused deputy behavior, "
        "and time-of-check/time-of-use issues around broadcasts."
    ),
    surface_types=("exported-receiver", "ordered-broadcast", "pending-intent"),
    entry_questions=(
        "Which receivers are exported or dynamically registered for attacker-reachable actions?",
        "Do ordered broadcasts or sticky broadcasts carry sensitive state or trigger privileged actions?",
    ),
    cross_questions=(
        "Can another app spoof a protected-looking action or win a race on ordered broadcast handling?",
        "Do receiver extras or results cross into auth, file, account, or provider operations?",
    ),
    sink_categories=(
        "Spoofable exported broadcast receivers",
        "Ordered-broadcast result tampering or timing abuse",
        "Receiver-triggered privileged actions without caller validation",
        "PendingIntent or alarm flows rooted in broadcast receivers",
    ),
    reasoning=(
        "Treat broadcast actions, extras, and result bundles as untrusted unless the code proves caller validation or permission enforcement."
    ),
    tags=("broadcast", "receiver"),
)

