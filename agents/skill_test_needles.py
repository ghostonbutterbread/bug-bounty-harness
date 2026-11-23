"""Resolve which markdown file each assertion in a skill test reads.

Written because regex resolution of this kept producing false positives: it
matched "not in" as a substring of "do not infer", missed path-join and
helper-function reads, and paired needles with the wrong file. Several wrong
conclusions were drawn from those before this existed. Parsing the AST removes
the guesswork.

Handles module constants built from path joins, locals assigned from a read,
whitespace-flattening wrappers, and `for phrase in (...): assertIn(phrase, hay)`.
"""
import ast, pathlib, sys


def _joined_path(node):
    """SKILLS / "a" / "b.md"  ->  ["a","b.md"] with the base name."""
    parts, cur = [], node
    while isinstance(cur, ast.BinOp) and isinstance(cur.op, ast.Div):
        if isinstance(cur.right, ast.Constant) and isinstance(cur.right.value, str):
            parts.insert(0, cur.right.value)
        cur = cur.left
    base = cur.id if isinstance(cur, ast.Name) else None
    return base, parts


def _read_target(node):
    """Unwrap norm()/" ".join(...split())/X.read_text() and return the path expr."""
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr == "join" and node.args:
            return _read_target(node.args[0])
        if isinstance(f, ast.Attribute) and f.attr == "split" and isinstance(f.value, ast.Call):
            return _read_target(f.value)
        if isinstance(f, ast.Name) and f.id in {"_skn", "norm", "_norm", "text", "read", "raw"}:
            return _read_target(node.args[0]) if node.args else None
        if isinstance(f, ast.Attribute) and f.attr == "read_text":
            return f.value
    return node


def extract(rel):
    src = pathlib.Path(rel).read_text()
    tree = ast.parse(src)
    consts = {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name):
            base, parts = _joined_path(n.value)
            if base in {"ROOT", "SKILLS"} and parts:
                p = "/".join(parts)
                consts[n.targets[0].id] = p if base == "ROOT" else f"skills/{p}"

    def resolve(expr):
        tgt = _read_target(expr)
        if isinstance(tgt, ast.Name):
            return consts.get(tgt.id)
        if isinstance(tgt, ast.Constant) and isinstance(tgt.value, str):
            return tgt.value
        base, parts = _joined_path(tgt) if tgt is not None else (None, [])
        if base in {"ROOT", "SKILLS"} and parts:
            p = "/".join(parts)
            return p if base == "ROOT" else f"skills/{p}"
        return None

    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        local = {}
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                p = resolve(node.value)
                if p:
                    local[node.targets[0].id] = p
        def hay_of(expr):
            if isinstance(expr, ast.Name):
                return local.get(expr.id) or consts.get(expr.id)
            return resolve(expr)
        # direct assertIn("lit", hay) / assert "lit" in hay
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
               and node.func.attr == "assertIn" and len(node.args) == 2:
                a, b = node.args
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    p = hay_of(b)
                    if p: out.append((a.value, p))
            if isinstance(node, ast.Assert) and isinstance(node.test, ast.Compare) \
               and node.test.ops and isinstance(node.test.ops[0], ast.In):
                a, b = node.test.left, node.test.comparators[0]
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    p = hay_of(b)
                    if p: out.append((a.value, p))
        # for phrase in (...): assertIn(phrase, hay)
        for node in ast.walk(fn):
            if not isinstance(node, ast.For) or not isinstance(node.target, ast.Name):
                continue
            lits = [e.value for e in getattr(node.iter, "elts", [])
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if not lits:
                continue
            hays = set()
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute) \
                   and inner.func.attr == "assertIn" and len(inner.args) == 2 \
                   and isinstance(inner.args[0], ast.Name) and inner.args[0].id == node.target.id:
                    p = hay_of(inner.args[1])
                    if p: hays.add(p)
                if isinstance(inner, ast.Assert) and isinstance(inner.test, ast.Compare) \
                   and inner.test.ops and isinstance(inner.test.ops[0], ast.In) \
                   and isinstance(inner.test.left, ast.Name) and inner.test.left.id == node.target.id:
                    p = hay_of(inner.test.comparators[0])
                    if p: hays.add(p)
            for lit in lits:
                for p in hays:
                    out.append((lit, p))
    seen, uniq = set(), []
    for n, p in out:
        if (n, p) not in seen:
            seen.add((n, p)); uniq.append((n, p))
    return uniq


if __name__ == "__main__":
    for rel in sys.argv[1:]:
        pairs = extract(rel)
        print(f"{rel}: {len(pairs)} needle/haystack pairs")
        for n, p in pairs[:6]:
            print(f"    {n[:58]!r} <- {p}")
