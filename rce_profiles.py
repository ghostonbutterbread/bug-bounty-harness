    "exec-sink-reachability": VulnerabilityClassProfile(
        key="exec-sink-reachability",
        description=(
            "Remote code execution by reaching a privileged execution sink. "
            "Any flow where attacker-influenced data can control process execution, "
            "dynamic code evaluation, deserialization with gadget execution, "
            "module/plugin/library loading, or execution of downloaded/extracted helpers. "
            "This is the highest-impact RCE class for desktop apps: IPC-to-child_process, "
            "updater abuse, helper tool invocation, and plugin loading from attacker-controlled sources."
        ),
        entry_questions=[
            "What untrusted data enters from IPC, files, archives, network, update metadata, deep links, plugin manifests, or renderer content?",
            "Can any of that data influence commands, executable paths, arguments, code strings, module paths, serialized bytes, or helper selection?",
            "Does the app invoke external helper tools (ffmpeg, convert, tar, unzip, osascript, powershell, gs)?",
            "Does the app have an auto-update or download-and-execute feature?",
        ],
        cross_questions=[
            "Does data cross renderer->preload->main, managed->native, parser->helper, archive->filesystem, or updater->executor boundaries?",
            "Can a lower-privilege component choose what code/process/module executes in a higher-privilege component?",
            "Can attacker-controlled data in a file, archive, or IPC message reach a shell or subprocess invocation?",
        ],
        sink_categories=[
            "OS/process execution sinks (child_process.exec/spawn/fork, subprocess.Popen, Runtime.exec, system/exec/CreateProcess/ShellExecute, os.system, popen, node-pty)",
            "Dynamic code evaluation or embedded interpreter execution (eval, Function, vm.runIn*, ScriptEngine, GroovyShell, Python eval/exec/compile)",
            "Module/plugin/library/class loading from attacker-influenced path, URL, bytes, or name (require, __import__, importlib, dlopen, LoadLibrary, URLClassLoader, defineClass)",
            "Execution of downloaded, extracted, converted, or updated helper artifacts (auto-updater, installer hooks, converter scripts)",
            "Archive extraction writing to autoload directories, startup folders, or search-path locations",
        ],
        reasoning=(
            "Ask: does the attacker control code, command text, executable path, arguments, module path, or serialized payload bytes? "
            "Ask: are there strict allowlists, argument arrays, type gates, signatures, or path constraints in place? "
            "Ask: is execution immediate, or does it require restart, update, or a secondary trigger? "
            "Ask: if a helper tool is invoked, can the attacker control its path, arguments, or input files? "
            "Ask: if an updater downloads and runs a binary, can the attacker intercept or control that binary?"
        ),
    ),
    "unsafe-deserialization": VulnerabilityClassProfile(
        key="unsafe-deserialization",
        description=(
            "Unsafe deserialization leading to arbitrary code execution via gadget chains. "
            "When user-controllable data is deserialized without strict type validation, "
            "an attacker can craft a payload that invokes dangerous operations during reconstruction. "
            "Affects pickle, YAML, JSON (in some languages), XML decoding, and custom binary formats."
        ),
        entry_questions=[
            "What deserialization functions are called in this codebase?",
            "What data reaches them — files, IPC messages, network responses, URL params, localStorage?",
            "Are serialized formats used for IPC, plugin manifests, config files, update metadata, or user data?",
        ],
        cross_questions=[
            "Does deserialized data originate from an untrusted source (renderer, file, network, user input)?",
            "Can an attacker supply a malicious serialized payload?",
            "Are there gadget-capable classes in scope that could be chained during deserialization?",
        ],
        sink_categories=[
            "Python: pickle.loads, dill.loads, yaml.load (unsafe), marshal.loads, any unsafe unpickler",
            "Ruby: Marshal.load, YAML.load (unsafe), Oj.load with unsafe mode",
            "Java: ObjectInputStream.readObject, XMLDecoder, XStream (unsafe configs), SnakeYAML, Kryo, Hessian, Fastjson, Jackson with polymorphic typing",
            "JavaScript/Node: deserialization libraries reviving functions or objects (e.g., node-serialize, deserialize)",
            "Custom binary or protocol deserializers with no type allowlisting",
        ],
        reasoning=(
            "Ask: does user-controllable data reach a deserialization function? "
            "Ask: is there any type validation, signature check, or allowlist before deserialization? "
            "Ask: are there known gadget classes in scope that could execute code or commands when materialized? "
            "Ask: could a crafted payload cause remote code execution, file write, or command execution?"
        ),
    ),
    "memory-unsafe-parser": VulnerabilityClassProfile(
        key="memory-unsafe-parser",
        description=(
            "Memory corruption bugs in native parsers: buffer overflows, integer overflows, "
            "format string vulnerabilities, and unsafe operations in C/C++/Rust code that parses "
            "external input (fonts, media, archives, images, network protocols). "
            "NOTE: Exploitability confirmation requires binary analysis with knowledge of memory layout, "
            "ASLR, canaries, and allocator behavior. Source analysis alone can identify dangerous "
            "patterns but cannot confirm RCE. Flag these as DORMANT unless binary validation is available."
        ),
        entry_questions=[
            "What native code parses external input (files, network data, protocol messages)?",
            "Are there C/C++/Rust parsers for fonts, media, archives, images, or custom protocols?",
            "What data formats are parsed: binary file formats, network protocols, serialization formats?",
        ],
        cross_questions=[
            "Does external data reach native memory operations (memcpy, strcpy, sprintf, read, recv, fread)?",
            "Are size/length fields from the input used without validation in allocation or copy operations?",
            "Can integer overflow in size calculations lead to underallocation or out-of-bounds access?",
        ],
        sink_categories=[
            "Unbounded memory operations: memcpy/memmove/strcpy/strcat/sprintf/vsprintf without length checks",
            "Integer overflow in allocation math: count * size, width * height * channels without overflow checks",
            "Format string bugs: printf/fprintf/sprintf with user-controlled format strings",
            "Unchecked reads: read/recv/fread reading into fixed buffers without validating size",
            "Missing bounds checks in recursive parsers (nested archives, recursive includes, deep font tables)",
            "Rust unsafe: from_raw_parts, copy_nonoverlapping, get_unchecked, unchecked arithmetic",
            "Go unsafe: unsafe.Pointer in cgo or manual slice manipulation with attacker-controlled data",
        ],
        reasoning=(
            "Ask: does attacker-controlled data from a file or network reach a native memory operation? "
            "Ask: are size/length fields from the input used in allocation or copy operations without validation? "
            "Ask: could integer overflow, truncation, or signedness issues cause a wrong size calculation? "
            "Ask: are there format string vulnerabilities where user data reaches a formatting function? "
            "IMPORTANT: Even if a dangerous pattern is found, assess exploitability as UNKNOWN without binary analysis. "
            "Mark as DORMANT and note: requires Ghidra/Binary Ninja analysis + memory layout knowledge to confirm."
        ),
    ),
