from agents.electron_profiles import ElectronHuntProfile


PROFILE = ElectronHuntProfile(
    key="electron-config-auditor",
    title="Electron Config Auditor",
    description=(
        "Audit Electron hardening and BrowserWindow configuration for settings that make "
        "renderer compromise materially more powerful or expose privileged execution paths."
    ),
    surface="electron-config",
    entry_questions=(
        "Where are BrowserWindow, BrowserView, webContents, sessions, and app command-line switches configured?",
        "Which windows load remote content, local files, user-selected files, or attacker-influenced URLs?",
        "Are fuses, sandboxing, CSP, navigation, permission, and devtools controls explicit and consistent?",
    ),
    trust_boundary_questions=(
        "Can untrusted renderer content reach a window with nodeIntegration, disabled contextIsolation, or missing sandbox?",
        "Do navigation, new-window, webview, permission, or certificate handlers allow attacker-controlled origins?",
        "Does the security posture differ between production, beta, dev, or feature-flagged windows?",
    ),
    sink_categories=(
        "BrowserWindow webPreferences: nodeIntegration, contextIsolation, sandbox, webSecurity, allowRunningInsecureContent",
        "Devtools, remote module, Electron fuses, command-line switches, custom sessions, permission handlers",
        "Navigation/open-window handlers, CSP gaps, webview tags, preload path selection, remote/local content loading",
    ),
    focus_globs=(
        "**/main*.{js,ts,mjs,cjs}",
        "**/*electron*.{js,ts,mjs,cjs,json}",
        "**/package.json",
        "**/preload*.{js,ts,mjs,cjs}",
        "**/app/**/*.js",
        "**/src/**/*.ts",
    ),
    code_patterns=(
        "new BrowserWindow",
        "webPreferences",
        "nodeIntegration",
        "contextIsolation",
        "sandbox",
        "setWindowOpenHandler",
        "will-navigate",
        "webviewTag",
        "permissionRequestHandler",
        "ELECTRON_RUN_AS_NODE",
    ),
    reasoning=(
        "Treat configuration as exploitable only when it connects to a concrete renderer entry path, "
        "origin, file load, or follow-on privileged sink. Report weak hardening as dormant unless "
        "the target contains a reachable app-specific trigger."
    ),
    tags=("electron", "config", "hardening"),
)
