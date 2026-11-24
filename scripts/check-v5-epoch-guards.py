import ast
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUARDS = {
    "Go": ("flowersec-go/internal/sessionv3/unreliable.go",
           r"func \(s \*engineSession\) unreliableReceiveRoots\(epoch uint32\)[^{]+\{\s*"
           r"s\.cryptoMu\.RLock\(\)\s*defer s\.cryptoMu\.RUnlock\(\)\s*if ([^{}]+) \{\s*"
           r"return protocolv3\.EpochRoots\{\}, false\s*\}\s*roots, ok := s\.recvRoots\[epoch\]\s*return roots, ok\s*\}",
           "s.recvSessionEpoch", "epoch"),
    "Rust": ("flowersec-rust/src/session_v3.rs",
             r"fn unreliable_receive_epoch_is_committed_v3\(recv_epoch: u32, message_epoch: u32\) -> bool \{([^{}]+)\}",
             "recv_epoch", "message_epoch"),
    "TypeScript": ("flowersec-ts/src/v3/session.ts",
                   r"receiveEpochSecret: \(epoch\) =>\s*([^?{}]+)\? this\.receiveRoots\.get\(epoch\)\?\.epochSecret\s*: undefined,",
                   "this.receiveEpoch", "epoch"),
}


def term(node, numeric_sort):
    if isinstance(node, ast.Name) and node.id in {"current", "candidate"}:
        return node.id
    if isinstance(node, ast.Constant) and type(node.value) is int and 0 <= node.value <= 1:
        return str(node.value) if numeric_sort == "Int" else f"(_ bv{node.value} 32)"
    if isinstance(node, ast.BoolOp):
        operator = {ast.And: "and", ast.Or: "or"}[type(node.op)]
        operands = [term(value, numeric_sort) for value in node.values]
    elif isinstance(node, ast.BinOp):
        operators = {ast.Sub: ("bvsub", "-"), ast.Add: ("bvadd", "+")}
        operator = operators[type(node.op)][numeric_sort == "Int"]
        operands = [term(node.left, numeric_sort), term(node.right, numeric_sort)]
    elif isinstance(node, ast.Compare) and len(node.ops) == 1:
        operators = {ast.LtE: ("bvule", "<="), ast.GtE: ("bvuge", ">="), ast.Gt: ("bvugt", ">"), ast.Lt: ("bvult", "<")}
        operator = operators[type(node.ops[0])][numeric_sort == "Int"]
        operands = [term(node.left, numeric_sort), term(node.comparators[0], numeric_sort)]
    else:
        raise ValueError(f"unsupported epoch guard syntax: {ast.dump(node)}")
    return f"({operator} {' '.join(operands)})"


def arithmetic_checks(node, numeric_sort, enabled="true"):
    if isinstance(node, ast.BoolOp):
        for value in node.values:
            yield from arithmetic_checks(value, numeric_sort, enabled)
            guard = term(value, numeric_sort)
            if isinstance(node.op, ast.Or):
                guard = f"(not {guard})"
            enabled = f"(and {enabled} {guard})"
        return
    if isinstance(node, ast.BinOp):
        if numeric_sort == "Int":
            safe = f"(<= -9007199254740991 {term(node, numeric_sort)} 9007199254740991)"
        elif isinstance(node.op, ast.Sub):
            safe = f"(bvuge {term(node.left, numeric_sort)} {term(node.right, numeric_sort)})"
        else:
            safe = f"(bvuge {term(node, numeric_sort)} {term(node.left, numeric_sort)})"
        yield f"(=> {enabled} {safe})"
    for child in ast.iter_child_nodes(node):
        yield from arithmetic_checks(child, numeric_sort, enabled)


def verify(language, filename, pattern, current, candidate):
    matches = re.findall(pattern, (ROOT / filename).read_text())
    if len(matches) != 1:
        raise ValueError(f"expected one {language} epoch guard, found {len(matches)}")
    expression = re.sub(rf"\b{re.escape(current)}\b", "current", matches[0].strip())
    expression = re.sub(rf"\b{re.escape(candidate)}\b", "candidate", expression)
    expression = expression.replace("&&", " and ").replace("||", " or ")
    numeric_sort = "Int" if language == "TypeScript" else "(_ BitVec 32)"
    syntax = ast.parse(expression, mode="eval").body
    predicate = term(syntax, numeric_sort)
    arithmetic = " ".join(arithmetic_checks(syntax, numeric_sort))
    if language == "Go":
        predicate = f"(not {predicate})"
    domain = ""
    if numeric_sort == "Int":
        domain = "(assert (and (<= 0 current 4294967295) (<= 0 candidate 4294967295)))"
        previous = "(= current (+ candidate 1))"
    else:
        previous = "(and (distinct current #x00000000) (= candidate (bvsub current #x00000001)))"
    query = f"""
(declare-const current {numeric_sort})
(declare-const candidate {numeric_sort})
{domain}
(define-fun actual () Bool {predicate})
(define-fun required () Bool (or (= current candidate) {previous}))
(push)
(assert (or (distinct actual required) (not (and true {arithmetic}))))
(check-sat)
(pop)
(assert actual)
(assert (distinct candidate current))
(check-sat)
"""
    result = subprocess.run(["z3", "-in"], input=query, capture_output=True, text=True, timeout=15, check=True)
    if result.stdout.splitlines() != ["unsat", "sat"]:
        raise ValueError(f"{language} epoch guard disagrees with the contract or rejects every previous epoch: {result.stdout}")
    print(f"{language} receive epoch guard: equivalent on all uint32 pairs", flush=True)


if __name__ == "__main__":
    try:
        for language, guard in GUARDS.items():
            verify(language, *guard)
    except (KeyError, OSError, SyntaxError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
