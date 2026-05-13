from agents.electron_profiles import ElectronHuntProfile


PROFILE = ElectronHuntProfile(
    key="electron-ipc-protocol-hunter",
    title="Electron IPC Protocol Hunter",
    description=(
        "Trace ipcMain handlers, custom protocols, deep links, and URL/file/native/update sinks "
        "for broken authorization, parsing, and renderer-to-main trust boundaries."
    ),
    surface="electron-ipc-protocol",
    entry_questions=(
        "Which ipcMain, protocol, app URL, deep-link, drag/drop, file-open, and command-line entry points accept external input?",
        "What channel names, schemas, URL schemes, path formats, and message types form the app's internal protocol?",
        "Can renderer, local file, remote web content, or OS-level URL/file handlers influence privileged main-process behavior?",
    ),
    trust_boundary_questions=(
        "Do handlers authenticate the sender frame, origin, WebContents, window identity, and expected workflow state?",
        "Are custom protocols and deep links parsed with strict allowlists for schemes, hosts, paths, and decoded values?",
        "Can inputs cross from IPC/protocol parsing into shell.openExternal, filesystem, native, updater, or process sinks?",
    ),
    sink_categories=(
        "ipcMain.handle/on handlers and channel dispatch tables",
        "protocol.handle/register*, app.setAsDefaultProtocolClient, open-url, second-instance, shell.openExternal",
        "Filesystem, file URL, native module, updater, command execution, database, credential, and browser launch sinks",
    ),
    focus_globs=(
        "**/*ipc*.{js,ts,mjs,cjs}",
        "**/*protocol*.{js,ts,mjs,cjs}",
        "**/*deeplink*.{js,ts,mjs,cjs}",
        "**/main/**/*.{js,ts,mjs,cjs}",
        "**/src/**/*.{js,ts,mjs,cjs}",
        "**/package.json",
    ),
    code_patterns=(
        "ipcMain.handle",
        "ipcMain.on",
        "protocol.handle",
        "protocol.register",
        "open-url",
        "second-instance",
        "setAsDefaultProtocolClient",
        "shell.openExternal",
        "new URL(",
        "file://",
    ),
    reasoning=(
        "Model IPC and protocols as an application-defined API. Report only when sender validation, "
        "input validation, or workflow authorization is weak enough to let attacker-controlled data "
        "reach a sensitive main-process sink."
    ),
    tags=("electron", "ipc", "protocol", "deeplink"),
)
