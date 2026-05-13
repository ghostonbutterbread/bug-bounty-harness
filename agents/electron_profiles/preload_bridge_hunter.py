from agents.electron_profiles import ElectronHuntProfile


PROFILE = ElectronHuntProfile(
    key="electron-preload-bridge-hunter",
    title="Electron Preload Bridge Hunter",
    description=(
        "Map preload scripts and contextBridge APIs to find renderer-controlled inputs "
        "crossing into privileged Node, native, filesystem, shell, or host RPC sinks."
    ),
    surface="electron-preload-bridge",
    entry_questions=(
        "Which preload scripts are loaded by each window and which APIs do they expose to renderer JavaScript?",
        "Can renderer content control arguments, callbacks, channel names, file paths, URLs, commands, or object keys?",
        "Do exposed APIs forward data to ipcRenderer, Node modules, native modules, filesystem, shell, or update helpers?",
    ),
    trust_boundary_questions=(
        "Does the preload bridge validate types, allowed operations, origins, channels, paths, and URL schemes?",
        "Can a compromised renderer invoke broader host functionality than intended by the UI workflow?",
        "Are bridge objects mutable, prototype-sensitive, callback-capable, or exposing raw ipcRenderer/event objects?",
    ),
    sink_categories=(
        "contextBridge.exposeInMainWorld APIs forwarding privileged operations",
        "ipcRenderer.invoke/send/on wrappers with renderer-controlled channels or payloads",
        "fs, shell, clipboard, native modules, child_process, updater, keychain, local database, and file picker sinks",
    ),
    focus_globs=(
        "**/preload*.{js,ts,mjs,cjs}",
        "**/*bridge*.{js,ts,mjs,cjs}",
        "**/*ipc*.{js,ts,mjs,cjs}",
        "**/renderer/**/*.{js,ts,jsx,tsx}",
        "**/src/**/*.{js,ts,jsx,tsx}",
    ),
    code_patterns=(
        "contextBridge.exposeInMainWorld",
        "ipcRenderer.invoke",
        "ipcRenderer.send",
        "ipcRenderer.on",
        "require('fs')",
        "require(\"fs\")",
        "shell.open",
        "child_process",
        "executeHostFunction",
    ),
    reasoning=(
        "Start from the renderer-callable API surface, then prove whether attacker-controlled renderer "
        "data reaches a privileged operation. Prefer concrete source-to-sink chains over listing every "
        "exposed method."
    ),
    tags=("electron", "preload", "contextBridge", "ipc"),
)
