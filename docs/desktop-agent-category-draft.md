# Desktop Dynamic Agent Category Draft

Status: draft / discussion
Owner: Ghost
Created: 2026-05-12
Purpose: manually shaped category-master logic for future dynamic agent grouping. This is not integrated into runtime yet.

## Core idea

We want `0day_team`-style broad specialist agents, but dynamically fed with AppMap/brainstorm hypotheses.

A hypothesis does not have to belong to exactly one agent. If multiple mindsets make sense, duplicate the hypothesis into multiple category-master agents with different framing.

Example:

`OAuth popup callback can bind to wrong account`

Could go to:
- `auth-session-callback-master` for OAuth/state/account reasoning
- `navigation-popup-master` for popup/opener/window reasoning
- `ipc-hostrpc-amplifier-master` only if the callback reaches privileged HostRpc methods

## Draft category-master agents

### 1. UI Intent / Dialog Action Master

Focus: places where the user is shown an object and the app assumes the displayed thing is safe to act on.

Surfaces:
- share dialogs
- invite dialogs
- notification click/double-click
- open/reveal dialogs
- permission prompts
- context menus
- command palette results
- search result actions

Mindset:
- “What did the user intend, and what did the app actually execute?”
- “Can attacker-controlled content become a trusted local action?”

Bug shapes:
- double-click opens/executes attacker-controlled item
- displayed item path/URL differs from action target
- preview safe, action dangerous
- stale selected item after list refresh
- prompt spoofing / permission confusion
- shared item treated like local trusted item

Good hypotheses to feed:
- share popup execution
- open/reveal action confusion
- notification-triggered file/protocol open
- permission prompt origin confusion

### 2. File Lifecycle Master

Focus: the full lifecycle of files from external origin to local trusted behavior.

Surfaces:
- drag/drop
- import
- file associations
- attachment open
- export
- download
- temp files
- reveal/open after save
- archive extraction

Mindset:
- “Where does an attacker-controlled file become a local trusted object?”
- “What automatic or user-assisted action happens after save/import?”

Bug shapes:
- path traversal
- extension/content-type confusion
- unsafe filename/content-disposition
- auto-open or reveal as impact step
- parser-to-renderer trust confusion
- local file overwrite or startup/plugin placement
- command-line injection from file association

Good hypotheses to feed:
- download/export abuse
- file import parser chains
- file association startup args
- archive extraction paths
- attachment preview/open behavior

### 3. Navigation / Window / Origin Master

Focus: browser-like trust boundaries inside desktop shell windows.

Surfaces:
- `window.open`
- popup pass records
- auth windows
- external navigation
- webviews
- embedded browser views
- opener relationships
- navigation allowlists

Mindset:
- “Which window/origin is trusted, and can another one inherit or confuse that trust?”
- “Can attacker navigation reach privileged UI/preload/session state?”

Bug shapes:
- opener confusion
- popup token/pass replay
- remote page gets trusted preload
- redirect bypass after initial URL allowlist
- dangerous scheme reaches `shell.openExternal`
- webview options allow privilege inheritance

Good hypotheses to feed:
- popup pass confusion
- openExternal allowlist gaps
- trusted popup origin confusion
- webRequest/custom scheme allowlist bypass

### 4. Protocol / Router / Startup Master

Focus: app entry routes that arrive from outside normal UI state.

Surfaces:
- custom protocols
- deep links
- OAuth callback schemes
- file association startup args
- command line flags
- local route handlers
- app restart/relaunch args

Mindset:
- “What code runs before the app has re-established auth/session/team state?”
- “Can an external URI or file make the app skip intended UI flow?”

Bug shapes:
- route before auth
- account/team confusion
- argument injection
- URL parser differentials
- dangerous action parameter
- local file route disclosure
- callback consumed by wrong pending request

Good hypotheses to feed:
- canva:// route confusion
- OAuth custom scheme callback
- file association import routing
- relaunch/startup arg influence

### 5. Auth / OAuth / Session Binding Master

Focus: identity, consent, token, team/workspace, and callback binding.

Surfaces:
- OAuth/OIDC
- SSO
- browser-to-desktop handoff
- loopback redirect listener
- custom-scheme callback
- refresh tokens
- multi-account switching
- workspace/team switching

Mindset:
- “Is this auth result bound to the same user/window/team/request that started it?”
- “Can a token or code be injected, leaked, replayed, or consumed in the wrong context?”

Bug shapes:
- missing/weak PKCE
- missing/unbound state/nonce
- redirect URI hijack
- mix-up between auth servers/tenants
- auth code injection/replay
- token leakage in URL/logs/IPC/localStorage
- callback binds to wrong account/team
- stale pending auth request

Good hypotheses to feed:
- OAuth popup race
- token/account confusion
- SSO callback routing
- refresh token storage/leakage

### 6. Rendering / Content Trust Master

Focus: untrusted content rendered inside a desktop shell.

Surfaces:
- rich text
- markdown/HTML
- design templates
- notes/comments
- embeds
- link previews
- SVG/images
- preview panes
- offline/error pages

Mindset:
- “Can shared/user content become script or trusted UI?”
- “If renderer execution happens, what app capabilities become reachable?”

Bug shapes:
- stored XSS
- DOM XSS
- sanitizer bypass
- template injection
- CSP bypass
- prototype pollution affecting app logic
- local custom-scheme reads from renderer
- renderer XSS to HostRpc impact

Good hypotheses to feed:
- rich content rendering
- template/design execution
- note/comment preview
- SVG/link preview processing

### 7. Local Service / Helper Bridge Master

Focus: local daemons, helper processes, localhost APIs, named pipes, and browser-accessible local services.

Surfaces:
- localhost HTTP/WebSocket
- named pipes
- Unix sockets
- helper daemons
- native messaging hosts
- browser extension bridges
- debug ports

Mindset:
- “Can a website, local user, or lower-privileged process talk to this helper?”
- “Does the helper trust localhost or a predictable pipe name too much?”

Bug shapes:
- unauthenticated localhost API
- DNS rebinding
- weak Origin/Host validation
- predictable named pipe abuse
- helper command execution
- debug endpoint exposure
- CSRF against local service

Good hypotheses to feed:
- local API surfaces
- helper bridge methods
- debug server exposure
- native messaging abuse

### 8. Native / Parser / Device Master

Focus: native code, binary parsers, device/capture permissions, and media conversion.

Surfaces:
- native Node addons
- image/video/audio/PDF parsers
- nativeImage
- ffmpeg/converters
- camera/microphone/screen capture
- printer/export drivers
- OCR/media pipelines

Mindset:
- “Can attacker-controlled bytes reach native parsing or device action?”
- “Is the native path sandboxed and is output trusted?”

Bug shapes:
- memory corruption
- unsafe converter command args
- parser output trusted as HTML/file/path
- recording permission confusion
- local media disclosure
- native addon exposes privileged calls

Good hypotheses to feed:
- media parser chains
- nativeImage notification icons
- recording/capture confusion
- print/export native pipeline

### 9. Updater / Installer / Persistence Master

Focus: code update, install, relaunch, persistence, and privileged helpers.

Surfaces:
- updater metadata
- downloaded packages
- installer helpers
- relaunch logic
- privileged services
- temp directories
- DLL/shared library loading

Mindset:
- “Can untrusted data influence what code runs next?”
- “Can local low-privilege input influence privileged updater behavior?”

Bug shapes:
- missing signature verification
- update channel/URL manipulation
- path traversal in update package
- insecure temp file permissions
- DLL search-order hijacking
- downgrade/rollback
- relaunch args/env/cwd injection

Good hypotheses to feed:
- update verification edge cases
- relaunch/process execution
- native library load path
- installer helper local privilege issues

### 10. Storage / Secrets / State Master

Focus: local persistence of sensitive app state.

Surfaces:
- config files
- SQLite/IndexedDB
- localStorage/sessionStorage
- logs/crash reports
- cache
- keychain wrappers
- debug/export bundles

Mindset:
- “What sensitive state exists locally, who can read it, and when should it disappear?”
- “Can one account/team/session consume another’s local state?”

Bug shapes:
- plaintext tokens
- hardcoded secrets
- secrets in logs/crash reports
- data remains after logout
- cross-account cache reuse
- weak local file permissions
- debug bundle leaks

Good hypotheses to feed:
- token storage/leakage
- logout residue
- cross-team cache confusion
- debug/export bundle exposure

### 11. IPC / HostRpc Capability Master

Focus: privileged bridge capabilities as impact amplifiers or standalone critical bugs.

Surfaces:
- Electron IPC
- HostRpc service maps
- preload contextBridge
- message ports
- native bridge dispatch

Mindset:
- “Assume renderer compromise or a specific app entry. What privileged capability becomes reachable?”
- “Is this bridge itself directly exposed enough to be the entry?”

Bug shapes:
- missing sender/origin validation
- overbroad methods
- weak schema validation
- dynamic dispatch confusion
- file/network/shell/native sinks reachable from renderer args
- privileged data returned to untrusted context

Good hypotheses to feed:
- HostRpc boundary hypotheses
- IPC-to-exec/file/network chains
- preload exposed API issues
- native bridge method abuse

Policy note:
- This agent should be capped in first-wave application hunts unless the hypothesis has standalone critical impact or proven app-entry evidence.

## Cross-assignment rule

A hypothesis can be assigned to more than one master when different mindsets are useful.

Examples:

- OAuth popup callback confusion:
  - `auth-session-callback-master`
  - `navigation-window-origin-master`

- Download opens attacker-controlled file:
  - `file-lifecycle-master`
  - `ui-intent-dialog-action-master`

- Custom protocol imports a file then triggers parser:
  - `protocol-router-startup-master`
  - `file-lifecycle-master`
  - `native-parser-device-master`

- Renderer XSS reaches HostRpc download/open:
  - `rendering-content-trust-master`
  - `ipc-hostrpc-capability-master`
  - `download-export-filesystem-master`

## Early recommended master set

If we only start with 6-8 masters, use:

1. `ui-intent-dialog-action-master`
2. `file-lifecycle-master`
3. `navigation-window-origin-master`
4. `protocol-router-startup-master`
5. `auth-oauth-session-binding-master`
6. `rendering-content-trust-master`
7. `storage-secrets-state-master`
8. `ipc-hostrpc-capability-master`

Then add specialized masters for native/updater/local-services as target evidence appears.
