"""A strict reader for the small part of YAML that rule packs use.

Supported: block mappings and sequences, plain, single-quoted and
double-quoted scalars (with YAML's escapes), literal and folded block
scalars (|, |-, |+, >, >-, >+), one-line flow sequences ([a, "b"]), empty
flow mappings ({}), comments, and a leading "---".

Not supported, and reported as an error instead of guessed at: anchors,
aliases, tags, flow mappings with content, multi-line plain or quoted
scalars, and more than one document. Nothing is ever executed.
"""

import re


class YamlError(ValueError):
    def __init__(self, message, line=None):
        ValueError.__init__(self, "line %d: %s" % (line, message) if line else message)
        self.line = line


_ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v", "f": "\f",
            "r": "\r", "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0",
            "L": "\u2028", "P": "\u2029"}
_INT = re.compile(r"^[-+]?\d+$")
_FLOAT = re.compile(r"^[-+]?(\d+\.\d*|\.\d+|\d+)([eE][-+]?\d+)?$")


class _Line(object):
    __slots__ = ("no", "indent", "text", "raw")

    def __init__(self, no, raw):
        self.no = no
        self.raw = raw
        stripped = raw.lstrip(" ")
        self.indent = len(raw) - len(stripped)
        self.text = stripped


def loads(text):
    if "\t" in "".join(l[:len(l) - len(l.lstrip())] for l in text.splitlines()):
        raise YamlError("tabs are not allowed for indentation")
    raw_lines = text.splitlines()
    lines = [_Line(i + 1, r.rstrip()) for i, r in enumerate(raw_lines)]
    p = _Parser(lines)
    return p.document()


class _Parser(object):
    def __init__(self, lines):
        self.lines = lines
        self.i = 0

    # Helpers.
    def _skip_blank(self):
        while self.i < len(self.lines):
            t = self.lines[self.i].text
            if t == "" or t.startswith("#"):
                self.i += 1
                continue
            break

    def _peek(self):
        self._skip_blank()
        return self.lines[self.i] if self.i < len(self.lines) else None

    def document(self):
        line = self._peek()
        if line is not None and line.indent == 0 and (line.text == "---" or line.text.startswith("--- ")):
            if line.text != "---":
                raise YamlError("content after '---' is not supported", line.no)
            self.i += 1
        line = self._peek()
        if line is None:
            return None
        value = self.block(line.indent)
        line = self._peek()
        if line is not None:
            if line.text in ("---", "...") and line.indent == 0:
                self.i += 1
                if self._peek() is not None:
                    raise YamlError("more than one document is not supported", line.no)
                return value
            raise YamlError("unexpected content (check the indentation)", line.no)
        return value

    def block(self, indent):
        line = self._peek()
        if line is None:
            return None
        if line.text == "-" or line.text.startswith("- "):
            return self.sequence(line.indent)
        return self.mapping(line.indent)

    def sequence(self, indent):
        out = []
        while True:
            line = self._peek()
            if line is None or line.indent != indent or not (line.text == "-" or line.text.startswith("- ")):
                if line is not None and line.indent > indent:
                    raise YamlError("unexpected indentation in a list", line.no)
                return out
            content = line.text[1:].lstrip(" ")
            if content == "" or content.startswith("#"):
                self.i += 1
                nxt = self._peek()
                if nxt is not None and nxt.indent > indent:
                    out.append(self.block(nxt.indent))
                else:
                    out.append(None)
                continue
            col = indent + (len(line.text) - len(content))
            if _split_key(content, line.no) is not None:
                # "- key: value" starts a mapping whose keys sit at the content column.
                self.lines[self.i] = _Line(line.no, " " * col + content)
                out.append(self.mapping(col))
                continue
            self.i += 1
            out.append(self.value(content, line, col))

    def mapping(self, indent):
        out = {}
        while True:
            line = self._peek()
            if line is None or line.indent < indent:
                return out
            if line.indent > indent:
                raise YamlError("unexpected indentation", line.no)
            if line.text == "-" or line.text.startswith("- "):
                return out
            split = _split_key(line.text, line.no)
            if split is None:
                raise YamlError("expected 'key: value'", line.no)
            key, rest = split
            if key in out:
                raise YamlError("duplicate key %r" % key, line.no)
            self.i += 1
            rest = _strip_comment(rest)
            if rest == "":
                nxt = self._peek()
                if nxt is not None and nxt.indent > indent:
                    out[key] = self.block(nxt.indent)
                elif nxt is not None and nxt.indent == indent and (nxt.text == "-" or nxt.text.startswith("- ")):
                    out[key] = self.sequence(indent)
                else:
                    out[key] = None
            else:
                out[key] = self.value(rest, line, indent + 1)

    def value(self, text, line, min_indent):
        text = _strip_comment(text)
        if text[:1] in ("&", "*", "!"):
            raise YamlError("anchors, aliases and tags are not supported", line.no)
        if text[:1] in ("|", ">") and re.match(r"^[|>][-+]?$", text):
            return self.block_scalar(text, min_indent)
        if text.startswith("["):
            return _flow_seq(text, line.no)
        if text.startswith("{"):
            if text.replace(" ", "") == "{}":
                return {}
            raise YamlError("flow mappings ({...}) are not supported; use block style", line.no)
        value = _scalar(text, line.no)
        nxt = self._peek()
        if nxt is not None and nxt.indent >= min_indent and not (nxt.text.startswith("- ") or nxt.text == "-") \
                and _split_key(nxt.text, nxt.no) is None:
            raise YamlError("multi-line plain or quoted values are not supported; use | or >", nxt.no)
        return value

    def block_scalar(self, header, min_indent):
        style, chomp = header[0], header[1:] or ""
        body = []
        block_indent = None
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if line.text == "":
                body.append("")
                self.i += 1
                continue
            if block_indent is None:
                if line.indent < min_indent:
                    break
                block_indent = line.indent
            if line.indent < block_indent:
                break
            body.append(line.raw[block_indent:])
            self.i += 1
        trailing = 0
        while body and body[-1] == "":
            body.pop()
            trailing += 1
        if style == "|":
            text = "\n".join(body)
        else:
            text = ""
            for j, b in enumerate(body):
                if j == 0:
                    text = b
                elif b == "" or body[j - 1] == "":
                    text += "\n" + b if b else ""
                elif b.startswith(" ") or body[j - 1].startswith(" "):
                    text += "\n" + b
                else:
                    text += " " + b
        if chomp == "-":
            return text
        if chomp == "+":
            return text + "\n" * (1 + trailing) if body else "\n" * trailing
        return text + "\n" if body else ""


def _strip_comment(text):
    quote = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if quote == '"' and ch == "\\":
                i += 2
                continue
            if ch == quote:
                if quote == "'" and text[i + 1:i + 2] == "'":
                    i += 2
                    continue
                quote = None
        elif ch in ("'", '"') and (i == 0 or text[i - 1] in " [,:{"):
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] == " "):
            return text[:i].rstrip()
        i += 1
    return text.rstrip()


def _split_key(text, no):
    """('key', 'rest') when text is a mapping entry, else None."""
    if text.startswith(("'", '"')):
        q = text[0]
        end = _quoted_end(text, q)
        if end is None:
            return None
        after = text[end + 1:]
        if after == ":" or after.startswith(": "):
            return _scalar(text[:end + 1], no), after[1:].lstrip(" ")
        return None
    if text.startswith(("[", "{", "#", "|", ">", "&", "*", "!")):
        return None
    m = re.match(r"^([^#:]+?|[^#]*?[^\s#]):(?:\s+|$)(.*)$", text)
    if not m:
        return None
    key = m.group(1).strip()
    if not key or "\"" in key or "'" in key:
        return None
    return key, m.group(2)


def _quoted_end(text, q):
    i = 1
    while i < len(text):
        ch = text[i]
        if q == '"' and ch == "\\":
            i += 2
            continue
        if ch == q:
            if q == "'" and text[i + 1:i + 2] == "'":
                i += 2
                continue
            return i
        i += 1
    return None


def _scalar(text, no):
    text = text.strip()
    if not text:
        return None
    if text[0] == "'":
        end = _quoted_end(text, "'")
        if end is None or end != len(text) - 1:
            raise YamlError("unterminated or trailing text after a single-quoted value", no)
        return text[1:-1].replace("''", "'")
    if text[0] == '"':
        end = _quoted_end(text, '"')
        if end is None or end != len(text) - 1:
            raise YamlError("unterminated or trailing text after a double-quoted value", no)
        return _unescape(text[1:-1], no)
    if text[0] in ("&", "*", "!", "%", "@", "`"):
        raise YamlError("values starting with %r are not supported" % text[0], no)
    low = text.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "~"):
        return None
    if _INT.match(text):
        return int(text)
    if _FLOAT.match(text):
        return float(text)
    return text


def _unescape(body, no):
    out = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1:i + 2]
        if nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            i += 2
            continue
        width = {"x": 2, "u": 4, "U": 8}.get(nxt)
        if width:
            digits = body[i + 2:i + 2 + width]
            if len(digits) != width or not re.match(r"^[0-9A-Fa-f]+$", digits):
                raise YamlError("bad \\%s escape in a double-quoted value" % nxt, no)
            out.append(chr(int(digits, 16)))
            i += 2 + width
            continue
        raise YamlError("\\%s is not a valid escape in a double-quoted value (in YAML, write regex "
                        "backslashes doubled, or use single quotes)" % nxt, no)
    return "".join(out)


def _flow_seq(text, no):
    if not text.endswith("]"):
        raise YamlError("a [ list must close on the same line", no)
    inner = text[1:-1].strip()
    if not inner:
        return []
    items, cur, quote, i = [], "", None, 0
    while i < len(inner):
        ch = inner[i]
        if quote:
            cur += ch
            if quote == '"' and ch == "\\":
                cur += inner[i + 1:i + 2]
                i += 2
                continue
            if ch == quote:
                if quote == "'" and inner[i + 1:i + 2] == "'":
                    cur += "'"
                    i += 2
                    continue
                quote = None
        elif ch in ("'", '"') and not cur.strip():
            quote = ch
            cur += ch
        elif ch == ",":
            items.append(cur)
            cur = ""
        elif ch in "[]{}":
            raise YamlError("nested flow collections are not supported", no)
        else:
            cur += ch
        i += 1
    items.append(cur)
    return [_scalar(x, no) for x in items if x.strip()]
