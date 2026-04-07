# TASK: Redesign zero_day_team.py class/vulnerability system

## Target file
/home/ryushe/projects/bug_bounty_harness/agents/zero_day_team.py

## INSTRUCTIONS
1. READ the full target file first
2. Make the changes described below
3. Write the redesigned file back to the same path

---

## DESIGN PRINCIPLES

1. **Class profiles = prose + reasoning, NOT sink lists**
   - Remove hardcoded sink/source arrays from class definitions
   - Use descriptive prose + reasoning questions
   - Agents told: "don't limit yourself to these patterns"

2. **5-step reasoning flow per class**
   ```
   ENTRY  → Where does untrusted data enter?
   CROSS  → Does it cross a trust boundary? (distinct from ENTRY)
   FLOW   → How does it move through the app?
   SINK   → What dangerous operation does it reach?
   EXPLOIT → Can an attacker actually trigger this path?
   ```

3. **Source framing: "data originating outside the current trust context"**
   - NOT a finite list — a conceptual frame
   - Add: "includes but not limited to: IPC messages, file paths, network responses, localStorage, postMessage origins..."
   - The concept scales to novel sources agents discover

4. **Sink categories (as types of dangerous operation, not specific functions)**
   - "DOM operations that interpret content as HTML/JS"
   - "String-to-code evaluation"
   - "Remote resource loading"
   - "File operations on attacker-controlled paths"
   - etc.

5. **Novel findings get their own file**
   - Path: {program}/ghost/reports/novel_findings.md
   - Threshold: must identify a SOURCE + a SINK, even if path between them is unclear
   - Claude reviews these too (same CONFIRMED/DORMANT/REJECTED gate)
   - Never auto-expand class profiles from these

6. **Clean memory per class**
   - Each vulnerability class spawns a fresh agent with clean context
   - Default mode: run ALL classes sequentially
   - --class flag for targeted single-class runs

7. **Report structure**
   - confirmed_{date}.md — CONFIRMED findings with PoC + impact
   - dormant_{date}.md — DORMANT findings with what's needed to chain
   - novel_findings_{date}.md — novel patterns outside any class

---

## CLASSES TO IMPLEMENT

```python
CLASS_PROFILES = {
    "dom-xss": {
        "description": (
            "Cross-Site Scripting in the browser renderer. "
            "Any code that takes data from an external or untrusted source "
            "and passes it to an operation that interprets it as HTML, JS, or CSS."
        ),
        "entry_questions": [
            "What data enters the renderer from outside?",
            "Is any of it derived from user-controlled sources (files, IPC, network)?",
        ],
        "cross_questions": [
            "Does data from a lower-privilege context reach a higher-privilege operation?",
            "Does IPC data from the main process contain unsanitized user-controlled values?",
        ],
        "sink_categories": [
            "DOM operations that interpret content as HTML/JS (innerHTML, outerHTML, insertAdjacentHTML, document.write)",
            "String-to-code evaluation (eval, setTimeout/setInterval with string, Function constructor, new Function, running JS from strings)",
            "Remote resource loading from attacker-controlled URLs (script src, img src, link href, fetch from user-controlled URL)",
        ],
        "reasoning": (
            "Ask: can an attacker position malicious data at this source? "
            "Ask: does the app sanitize or encode before reaching this sink? "
            "Ask: even if sanitized, is there a bypass for this specific context?"
        ),
    },
    "ipc-trust-boundary": {
        "description": (
            "IPC/preload bridge trust boundary abuse. "
            "The preload bridge is a critical trust boundary — data flowing from main process "
            "to renderer should be considered untrusted if the main process can be influenced."
        ),
        "entry_questions": [
            "What functions are exposed via the preload bridge (window.localUserData, etc.)?",
            "Can attacker-controlled data reach these functions?",
        ],
        "cross_questions": [
            "Does IPC data passed through the preload bridge get validated?",
            "Can a compromised renderer call privileged main-process functions?",
        ],
        "sink_categories": [
            "Direct IPC invoke calls to main process methods",
            "fs/child_process access via preload bridge",
            "Arbitrary code execution via executeHostFunction or similar bridges",
        ],
        "reasoning": (
            "Ask: what can the renderer do via the preload bridge that it couldn't do directly? "
            "Ask: if the renderer is compromised, what can it reach via IPC? "
            "Ask: is the preload API surface minimal and safe, or is everything exposed?"
        ),
    },
    "node-integration": {
        "description": (
            "nodeIntegration and contextIsolation misconfiguration. "
            "nodeIntegration:true gives the renderer full Node.js access. "
            "contextIsolation:false means preload scripts share the renderer JS context."
        ),
        "entry_questions": [
            "Is nodeIntegration enabled in BrowserWindow config?",
            "Is contextIsolation disabled?",
            "Is the remote module enabled?",
        ],
        "cross_questions": [
            "Can renderer JS access require(), process, or fs directly?",
            "Can prototype pollution in renderer affect main process?",
        ],
        "sink_categories": [
            "Direct Node.js API access from renderer (require, process, fs, child_process, net, tls)",
            "Prototype pollution reaching main process objects",
            "Remote module exposure to renderer",
        ],
        "reasoning": (
            "Ask: if XSS exists in this renderer, what can the attacker do with Node access? "
            "Ask: is contextIsolation actually protecting anything if preload has vulnerabilities?"
        ),
    },
    "path-traversal": {
        "description": (
            "File operations on attacker-controlled paths. "
            "Any file operation (open, read, write, copy, mkdir, chmod) on a path "
            "derived from user input or external data."
        ),
        "entry_questions": [
            "What file operations exist in the codebase?",
            "Are any paths derived from user input, IPC messages, or file selection dialogs?",
        ],
        "cross_questions": [
            "Can an attacker provide paths outside the intended directory?",
            "Do path traversal protections actually work for all edge cases?",
        ],
        "sink_categories": [
            "File read on attacker-controlled path (readFile, open with user path)",
            "File write on attacker-controlled path (writeFile, copyFile, mkdir creating outside target dir)",
            "Symlink attacks (reading/writing through symlinks to sensitive locations)",
        ],
        "reasoning": (
            "Ask: if an attacker can control the path, what can they read/write? "
            "Ask: does the app handle ~, .., absolute paths, UNC paths (Windows), /proc (Linux)? "
            "Ask: what files are actually accessible via traversal?"
        ),
    },
    "prototype-pollution": {
        "description": (
            "JavaScript prototype pollution. "
            "Merge/object spread operations that pollute Object.prototype or constructor.prototype. "
            "Dangerous in Electron when polluted prototypes affect renderer or main process objects."
        ),
        "entry_questions": [
            "Does the app use JSON.parse on external data?",
            "Are there deep merge/assign operations on user-controlled objects?",
            "Does the app use __proto__, constructor, or prototype in any operation?",
        ],
        "cross_questions": [
            "Can prototype pollution in renderer affect IPC message objects?",
            "Can polluted objects reach main process via preload?",
        ],
        "sink_categories": [
            "Deep object merge/assign without prototype checks",
            "__proto__ assignment in user-data handling",
            "Constructor.prototype assignment",
        ],
        "reasoning": (
            "Ask: if you pollute Object.prototype, what becomes available to all objects? "
            "Ask: can prototype pollution enable a secondary attack (XSS to RCE, auth bypass)?"
        ),
    },
    "native-module-abuse": {
        "description": (
            "Native Node module abuse. "
            "Native modules like better-sqlite3, keytar, fswin have full system access. "
            "If accessible from renderer, any vulnerability in them becomes critical."
        ),
        "entry_questions": [
            "What native modules are loaded (better-sqlite3, keytar, native extensions)?",
            "Are they accessible from the renderer context?",
        ],
        "cross_questions": [
            "Can renderer JS load and interact with native modules?",
            "Do native modules handle untrusted input unsafely?",
        ],
        "sink_categories": [
            "SQL execution via better-sqlite3 with attacker-controlled SQL",
            "Credential storage access via keytar",
            "Arbitrary file access via fswin or similar native fs wrappers",
        ],
        "reasoning": (
            "Ask: what happens when a native module receives malformed input? "
            "Ask: if the renderer can call native modules, what's the blast radius?"
        ),
    },
    "ssrf": {
        "description": (
            "Server-Side Request Forgery. "
            "HTTP requests made by the app where the URL is derived from user input or external data."
        ),
        "entry_questions": [
            "Does the app make HTTP requests?",
            "Are any URLs derived from user input, file contents, or external sources?",
        ],
        "cross_questions": [
            "Can an attacker probe internal services (169.254.169.254, localhost, internal networks)?",
            "Can SSRF exfiltrate cloud metadata or internal API responses?",
        ],
        "sink_categories": [
            "HTTP requests to user-controlled URLs (fetch, axios, request, urllib)",
            "URLs constructed from path parameters or file contents",
            "Redirect following from untrusted sources",
        ],
        "reasoning": (
            "Ask: can an attacker control the destination URL? "
            "Ask: can they read the response (information disclosure) or just trigger the request (blind SSRF)? "
            "Ask: are there cloud metadata endpoints reachable (169.254.169.254)?"
        ),
    },
}
```

---

## SPECIFIC CHANGES TO MAKE

1. Replace any hardcoded CLASS_PROFILES (or create if missing) with the structure above

2. Update `_build_prompt_base()` to use the new class profile structure:
   - Output the `description` as context
   - List `entry_questions` as things to investigate
   - List `cross_questions` as trust boundary checks
   - List `sink_categories` as dangerous operations to look for (with note: "don't limit yourself to these")
   - Include the `reasoning` questions

3. Add `novel_findings_path` to orchestrator:
   ```python
   novel_findings_path = findings_root / "novel_findings.md"
   ```

4. In the review phase, also pass novel findings to Claude with instruction:
   "These are novel patterns outside established vulnerability classes. Assess whether each has a plausible source + sink."
   - CONFIRMED novel → add to novel_findings.md
   - DORMANT novel → add to novel_findings.md with note
   - REJECTED novel → discard

5. Keep --class flag working for targeted runs
6. Default: run ALL classes if no --class specified

7. Keep all existing functionality:
   - Parallel agent spawning
   - Claude review gate
   - Logging
   - Report writing

---

## IMPORTANT
- Keep the file well-commented
- Preserve any existing working functionality
- Don't break the import structure
- Test that `python3 -c "import agents.zero_day_team"` still works after changes
