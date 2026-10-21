# Local JWT tooling: PyJWT and jwt_tool

Use PyJWT for deterministic inspection, construction, signing and verification; use ticarpi/jwt_tool for targeted JWT-specific mutation and vulnerability checks. These are tools, not proof of authorization failure. A decoded payload is **untrusted** until its signature and expected issuer/audience/claims are verified. A modified token cannot be validly re-signed without an appropriate signing key or a demonstrated verifier flaw. Neither tool decrypts JWE by merely decoding a compact token.

## Install / identify the executable

Check the task interpreter first: `python3 -m pip show PyJWT`; do not assume the Hermes interpreter, system Python, and the BBH checkout's `.venv` share packages. For an isolated user install on an agent host, use a dedicated virtual environment (or the host's approved package manager):

```bash
python3 -m venv "$HOME/.local/share/jwt-tools/venv"
"$HOME/.local/share/jwt-tools/venv/bin/python" -m pip install 'PyJWT[crypto]'
"$HOME/.local/share/jwt-tools/venv/bin/python" -c 'import jwt; print(jwt.__version__)'
```

`jwt_tool` is a separate upstream repository; it is **not** PyJWT's `jwt` module. To install from reviewed source, use the upstream [repository](https://github.com/ticarpi/jwt_tool) and its `requirements.txt`. Record the chosen revision and executable path; a moving upstream branch is not an implicit runtime dependency contract. Example using the revision locally exercised when this reference was authored:

```bash
mkdir -p "$HOME/.local/share/jwt-tools"
git clone https://github.com/ticarpi/jwt_tool.git "$HOME/.local/share/jwt-tools/jwt_tool"
git -C "$HOME/.local/share/jwt-tools/jwt_tool" checkout 3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b
"$HOME/.local/share/jwt-tools/venv/bin/python" -m pip install -r "$HOME/.local/share/jwt-tools/jwt_tool/requirements.txt"
"$HOME/.local/share/jwt-tools/venv/bin/python" "$HOME/.local/share/jwt-tools/jwt_tool/jwt_tool.py" -h
```

If the directory already exists, inspect its revision/cleanliness instead of cloning over it. Recheck upstream and dependencies before upgrading; do not run an unreviewed update merely to make a test pass. Upstream also documents a Docker image, but its sample command uses host networking and mounts the current directory plus `~/.jwt_tool`; prefer the isolated source install for task-scoped work rather than copying that command blindly.

## Offline synthetic self-test (no live token)

```bash
"$HOME/.local/share/jwt-tools/venv/bin/python" - <<'PY'
import jwt
key = "local-fixture-key-with-at-least-32-bytes"
token = jwt.encode({"sub": "owned-fixture", "role": "user"}, key, algorithm="HS256")
assert jwt.get_unverified_header(token)["alg"] == "HS256"
assert jwt.decode(token, options={"verify_signature": False})["role"] == "user"
assert jwt.decode(token, key, algorithms=["HS256"])["sub"] == "owned-fixture"
print("PyJWT synthetic encode/inspect/verify: OK")
PY
```

The unverified decode is for routing only. For an actual verification, supply a trusted key and explicitly allowed algorithm(s), then validate expected `issuer` and `audience` when the application requires them. Never select verification algorithms solely from an untrusted token header. PyJWT's [usage guide](https://pyjwt.readthedocs.io/en/stable/usage.html) covers the exact APIs and optional cryptographic dependencies.

## Select a JWT test

- **Inspect:** PyJWT `get_unverified_header` and `decode(..., options={"verify_signature": False})` in a private process; inspect only safe, redacted claim metadata in shared output. `jwt_tool.py <synthetic-jwt>` also prints decoded header/payload, but upstream may persist tokens in `~/.jwt_tool`.
- **Construct/sign:** PyJWT `encode(claims, key, algorithm="HS256")`, or the appropriate private-key algorithm with a task-owned key. Verify the constructed fixture before testing any parser behavior. Keep real keys out of command arguments, shell history and artifacts.
- **Targeted vulnerability checks:** `jwt_tool.py <synthetic-jwt> -X a` generates an `alg:none` candidate **offline**; `-I -pc role -pv admin` injects a candidate claim (see `-h` for compatible signing/exploit flags). `-M pb` and `-M er` are *live scanning modes* when configured with a target/request: first check scope, ownership, rate, request method/side effects, and active proxy transport. Do not use `-M at` as a default. The exercised upstream revision emitted four offline `-X a` candidates yet exited with status 1; inspect sanitized output and effects rather than interpreting that exit status alone as an assessment result. Load the corresponding JWT technique pack, compare an owned allowed/denied baseline and verify the server-side effect; generated tokens or scanner labels alone are not findings.

**Sensitive-state boundary:** Live JWTs in positional arguments or `-rh`/`-rc` can appear in process listings, history and `jwt_tool` logs. The upstream tool creates `~/.jwt_tool` configuration, keys and logs on first run. Do not put live tokens or key material in chat, broad reports, checked-in files or shared tool-run artifacts. For live testing, use approved private request handling and task-owned storage with restricted permissions; inspect and clean only that task's stored token/log copies afterward. Avoid a shared `~/.jwt_tool` data directory for runs carrying sensitive token material; upstream resolves it from `$HOME`, so use a dedicated task-owned HOME if isolation is required and confirm its effects before use. Never delete another run's home/configuration.

Source: [jwt_tool README and options](https://github.com/ticarpi/jwt_tool); its CLI `-h` is the local source of truth for installed version/flags.
