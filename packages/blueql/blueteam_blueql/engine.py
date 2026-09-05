"""BlueQL: AST-only hunting language. Never concatenates untrusted SQL."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from blueteam_schemas.events import CanonicalEvent

IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
DURATION = re.compile(r"(\d+)([smh])")
STRING = re.compile(r'"((?:\\.|[^"\\])*)"')


class BlueQLError(ValueError):
    pass


@dataclass
class Node:
    kind: str
    value: Any = None
    children: list[Node] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "children": [child.to_dict() for child in self.children],
        }


class _Lexer:
    def __init__(self, text: str) -> None:
        if any(token in text for token in (";", "--", "/*", "*/", "UNION", "DROP", "INSERT", "UPDATE", "DELETE")):
            raise BlueQLError("SQL/control tokens are not legal in BlueQL")
        self.text = text.strip()
        self.pos = 0

    def peek(self) -> str:
        self._skip()
        return self.text[self.pos :]

    def _skip(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos].isspace():
            self.pos += 1

    def take_keyword(self, *words: str) -> str | None:
        self._skip()
        for word in sorted(words, key=len, reverse=True):
            if self.text[self.pos :].upper().startswith(word.upper()) and (
                self.pos + len(word) == len(self.text)
                or not self.text[self.pos + len(word)].isalnum()
            ):
                self.pos += len(word)
                return word.upper()
        return None

    def take_ident(self) -> str:
        self._skip()
        match = IDENTIFIER.match(self.text[self.pos :])
        if not match:
            raise BlueQLError(f"expected identifier at {self.text[self.pos : self.pos + 16]!r}")
        self.pos += match.end()
        return match.group(0)

    def take_value(self) -> Any:
        self._skip()
        if self.peek().startswith('"'):
            match = STRING.match(self.text[self.pos :])
            if not match:
                raise BlueQLError("unterminated string")
            self.pos += match.end()
            return match.group(1)
        if self.take_keyword("TRUE"):
            return True
        if self.take_keyword("FALSE"):
            return False
        match = re.match(r"-?\d+(?:\.\d+)?", self.text[self.pos :])
        if match:
            self.pos += match.end()
            return float(match.group(0)) if "." in match.group(0) else int(match.group(0))
        raise BlueQLError("expected literal")


def parse(query: str) -> Node:
    lexer = _Lexer(query)
    if lexer.take_keyword("FROM"):
        entity = lexer.take_ident()
        if not lexer.take_keyword("WHERE"):
            raise BlueQLError("FROM requires WHERE")
        pred = _or_expr(lexer)
        root = Node("entity", entity, [pred])
    else:
        first = _or_expr(lexer)
        steps = [first]
        while lexer.take_keyword("FOLLOWED_BY"):
            steps.append(_or_expr(lexer))
        within = None
        if lexer.take_keyword("WITHIN"):
            within = _duration(lexer)
        root = Node("sequence" if len(steps) > 1 else "filter", within, steps)
    leftover = lexer.peek()
    if leftover:
        raise BlueQLError(f"unexpected input {leftover!r}")
    return root


def _duration(lexer: _Lexer) -> int:
    lexer._skip()
    match = DURATION.match(lexer.text[lexer.pos :])
    if not match:
        raise BlueQLError("expected duration like 5m")
    lexer.pos += match.end()
    unit = {"s": 1, "m": 60, "h": 3600}[match.group(2)]
    return int(match.group(1)) * unit


def _or_expr(lexer: _Lexer) -> Node:
    left = _and_expr(lexer)
    while lexer.take_keyword("OR"):
        left = Node("or", children=[left, _and_expr(lexer)])
    return left


def _and_expr(lexer: _Lexer) -> Node:
    left = _primary(lexer)
    while lexer.take_keyword("AND"):
        left = Node("and", children=[left, _primary(lexer)])
    return left


def _primary(lexer: _Lexer) -> Node:
    if lexer.take_keyword("NOT"):
        return Node("not", children=[_primary(lexer)])
    if lexer.peek().startswith("("):
        lexer.pos += 1
        node = _or_expr(lexer)
        lexer._skip()
        if not lexer.peek().startswith(")"):
            raise BlueQLError("missing )")
        lexer.pos += 1
        return node
    field = lexer.take_ident()
    if lexer.take_keyword("IN"):
        lexer._skip()
        if not lexer.peek().startswith("("):
            raise BlueQLError("IN requires a parenthesised list")
        lexer.pos += 1
        values = [lexer.take_value()]
        lexer._skip()
        while lexer.peek().startswith(","):
            lexer.pos += 1
            values.append(lexer.take_value())
            lexer._skip()
        if not lexer.peek().startswith(")"):
            raise BlueQLError("missing ) after IN list")
        lexer.pos += 1
        return Node("in", field, [Node("literal", item) for item in values])
    op = None
    for candidate in (">=", "<=", "!=", "=", ">", "<"):
        if lexer.peek().startswith(candidate):
            lexer.pos += len(candidate)
            op = candidate
            break
    if op is None:
        raise BlueQLError(f"expected comparator after {field}")
    return Node("cmp", {"field": field, "op": op}, [Node("literal", lexer.take_value())])


def _field_value(event: CanonicalEvent, field: str) -> Any:
    table: dict[str, Any] = {
        "process.name": event.process.name if event.process else None,
        "parent.name": event.parent_process.name if event.parent_process else None,
        "user.name": event.user.name if event.user else None,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "category": event.category,
        "event_type": event.event_type,
        "outcome": event.outcome,
        "action": event.action,
        "network.external": bool(event.dst_ip) and not str(event.dst_ip).startswith(("10.", "192.168.", "172.")),
        "auth.failures": 1 if event.category == "authentication" and event.outcome == "failure" else 0,
        "auth.success": event.category == "authentication" and event.outcome == "success",
        "privilege.change": event.action in {"add_to_group", "grant_role", "add_member", "elevate"},
    }
    if field not in table:
        raise BlueQLError(f"unknown field {field}")
    return table[field]


def _compare(observed: Any, op: str, expected: Any) -> bool:
    if op == "=":
        if isinstance(observed, bool):
            return observed is True if expected in {True, "true"} else observed is False
        return str(observed).lower() == str(expected).lower()
    if op == "!=":
        return not _compare(observed, "=", expected)
    if observed is None:
        return False
    if op == ">":
        return observed > expected
    if op == ">=":
        return observed >= expected
    if op == "<":
        return observed < expected
    if op == "<=":
        return observed <= expected
    return False


def _eval_pred(node: Node, event: CanonicalEvent) -> bool:
    if node.kind == "and":
        return all(_eval_pred(child, event) for child in node.children)
    if node.kind == "or":
        return any(_eval_pred(child, event) for child in node.children)
    if node.kind == "not":
        return not _eval_pred(node.children[0], event)
    if node.kind == "in":
        observed = _field_value(event, str(node.value))
        return any(_compare(observed, "=", child.value) for child in node.children)
    if node.kind == "cmp":
        return _compare(_field_value(event, node.value["field"]), node.value["op"], node.children[0].value)
    raise BlueQLError(f"cannot evaluate {node.kind}")


def compile_query(query: str) -> Node:
    return parse(query)


def execute(query: str, events: list[CanonicalEvent]) -> list[CanonicalEvent]:
    ast = parse(query)
    if ast.kind == "filter":
        return [event for event in events if _eval_pred(ast.children[0], event)]
    if ast.kind == "entity":
        return [event for event in events if _eval_pred(ast.children[0], event)]
    if ast.kind == "sequence":
        return _execute_sequence(ast, events)
    raise BlueQLError("unsupported query form")


def _execute_sequence(ast: Node, events: list[CanonicalEvent]) -> list[CanonicalEvent]:
    window = int(ast.value or 600)
    ordered = sorted(events, key=lambda item: item.timestamp)
    hits: list[CanonicalEvent] = []
    for index, event in enumerate(ordered):
        if not _eval_pred(ast.children[0], event):
            continue
        cursor = event.timestamp
        matched = [event]
        pos = index + 1
        ok = True
        for step in ast.children[1:]:
            found = None
            while pos < len(ordered):
                candidate = ordered[pos]
                pos += 1
                delta = (candidate.timestamp - cursor).total_seconds()
                if delta > window:
                    break
                if _eval_pred(step, candidate):
                    found = candidate
                    cursor = candidate.timestamp
                    matched.append(candidate)
                    break
            if found is None:
                ok = False
                break
        if ok:
            hits.extend(matched)
    # unique by id, preserve order
    seen: set[str] = set()
    unique = []
    for event in hits:
        if event.id not in seen:
            seen.add(event.id)
            unique.append(event)
    return unique


def explain(ast: Node) -> dict[str, Any]:
    return {
        "form": ast.kind,
        "parameterised": True,
        "backend": "in-memory-canonical-events",
        "cost": "O(n)" if ast.kind == "filter" else "O(n*steps)",
        "sql_concatenation": False,
        "ast": ast.to_dict(),
    }
