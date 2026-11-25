"""Masking for everything dryfire prints.

Every command, reason, path and error text that reaches a report goes through
clean(). It layers, in order:

1. the vendored token patterns (secrets.mask),
2. values that only look secret because of their name or flag
   (TOKEN=..., --password ..., Authorization headers, mysql -p...),
3. long random-looking values,
4. the user's own redact_patterns,
5. the home folder shown as ~, control characters removed, length capped.

The aim is "never show a secret", so it masks more than it needs to.
"""

import math
import re

from . import secrets

HIDDEN = "[hidden: %s]"

_NAME_WORDS = (r"(?:TOKENS?(?![a-z])|SECRET|PASSWORD|PASSWD|PASSPHRASE|API[_\-]?KEY|ACCESS[_\-]?KEY|PRIVATE[_\-]?KEY|"
               r"CREDENTIALS?|AUTH(?![a-z])|SESSION|COOKIE|[A-Z0-9]_PWD)")
# AUTH and TOKEN only as whole name parts (GH_TOKEN, AUTH_KEY): --author and tokenizers are not secrets.
# The search is case-insensitive, so (?![a-z]) also rules out a following capital letter.
# A word that may be a name (GH_TOKEN, api-key, config.secret). Names are found token by token and
# checked for a secret word afterwards: one pattern for "a word that contains TOKEN" backtracks over
# every TOKEN in a long word, which takes seconds on a line built to do that.
_TOKEN = re.compile(r"(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]+")
_NAME_WORDS_RX = re.compile(_NAME_WORDS, re.I)

# A flag's value: one shell word, which may join plain, quoted and escaped parts (pass:"S", pa'ss w'rd,
# $'...', $"...", "a\\"b", a\\ b, $(cmd arg) with one level of ( ) inside, a backslash-newline). Each part
# starts with its own character ('$' is plain only when no quote or '(' follows it), so a word splits into
# parts one way only and is read once. A quote ends at its closing quote or, left open, at the end of the
# line ('admin:S is still masked).
_END = r"(?:\n|\Z)"
_VALUE = (r"((?:'[^'\n]*(?:'|(?=" + _END + r"))|\$'(?:[^'\\\n]|\\.)*(?:'|(?=" + _END + r"))"
          r"|\$?\"(?:[^\"\\\n]|\\[\s\S])*(?:\"|(?=" + _END + r"))|\$\((?:[^()]|\([^()]*\)?)*\)?|\\[\s\S]|\$(?![\"'(])"
          r"|`(?:[^`\\]|\\[\s\S])*(?:`|\Z)|[^\s\"'&;|$\\`])+)")

_NAMED = [
    # Authorization: Bearer xyz, -H 'Authorization: token xyz'. Before the named rule, which would
    # otherwise take the scheme word for the value and leave the token.
    # The scheme needs its own trailing space, so the spaces before a value can be split only one way.
    ("authorization header", re.compile(
        r"(?i)(authorization:[ \t]*(?:(?:bearer|basic|token|digest)[ \t]+)?)([^\s\"']{4,})")),
    ("bearer token", re.compile(r"(?i)(\bbearer\s+)([A-Za-z0-9._~+/\-]{8,}=*)")),
    # --password value, --token=value and friends.
    ("secret flag value", re.compile(
        r"(?i)(--?(?:password|passwd|pass|token|secret|api-?key|auth-?token|access-?token|client-?secret|"
        r"private-?key|passphrase|key-?password)(?:=|\s+))" + _VALUE)),
    # curl -u user:pass, -uuser:pass, -su user:pass, --user=user:pass, -u :pass: the whole shell word, masked
    # after its first ':' as curl splits it ("admin:my S", 'admin':S, $'admin:S', admin:pa\\ S).
    # The letters before u exclude u, so a long cluster is read once rather than once for each u in it.
    ("user password", re.compile(r"((?:^|\s)(?:-[A-Za-tv-z]*u\s*|--user(?:\s+|=)))" + _VALUE)),
    # scheme://user:pass@host with any password length.
    ("password in URL", re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@\"'`]{0,64}:)([^\s@/\"'`]+)(?=@)")),
]

_SCHEMES = ("bearer", "basic", "token", "digest")

# A compound secret name, then a space, then a value that looks generated (aws configure set
# aws_secret_access_key VALUE). The value test keeps 'grep api_key src/' readable.
_SPACED_TAIL = re.compile(r"([\"']?[ \t]+[\"']?)([^\s\"'&;|=:]{8,})")

# What follows a secret name: a quoted value, masked whole, spaces and all (export X_SECRET='a b c'),
# then NAME=value or name: value (export GH_TOKEN=..., "api_key": "..."). The quoted value is
# bounded so an unclosed quote is not read to the end of the line once per name.
# A double-quoted value that starts with a substitution ("$(op read "op://x")") is left to _PLAIN_TAIL, which
# reads its inner quotes as part of one word.
_QUOTED_TAIL = re.compile(r"([\"']?\s*(?:=|:)\s*)(\"(?![$`])[^\"\n]{2,999}\"|'[^'\n]{3,1000}')")
_PLAIN_TAIL = re.compile(r"([\"']?\s*(?:=|:)\s*)" + _VALUE)

# Clients whose password flag takes the next word (or the rest of the word: gap \s*). Every such flag in
# the 500 characters after the client name is masked (keytool -srcstorepass A -deststorepass B), so a
# line repeating the client name is still read only once.


def _client_flag(clients, flags, gap=r"\s+", keep=None):
    """keep: values of this client's flag that are not a password, left as they are."""
    return (re.compile(r"\b(?:%s)\b[^\n|;&]{0,500}" % clients), re.compile(r"\s(?:%s)" % flags),
            re.compile(r"(\s(?:%s)%s)%s" % (flags, gap, _VALUE)), keep)


# A port mapping (27017:27017, 8080:80/tcp) after any client's -p is not a password: docker's -p takes one, and a
# client's name can sit on a container line that maps a port (a container named after the client, then -p).
_PORT_MAP = re.compile(r"\d{1,5}(?::\d{1,5}){1,2}(?:/(?:tcp|udp))?$")
# openssl's pointers to where the password is (env:VAR, file:path, fd:3, stdin); pass:S is the password itself.
_OPENSSL_POINTER = re.compile(r"(?:env|file|fd):|stdin$")

_CLIENT_FLAGS = [
    _client_flag("sshpass", "-p", r"\s*"),
    _client_flag(r"docker\s+login", "-p", r"(?:\s+|=)?"),  # -p S, -p=S and -pS.
    _client_flag("redis-cli", "-a"),
    _client_flag("openssl", "-passout|-passin|-pass", r"(?:\s+|=)", _OPENSSL_POINTER),  # -passin pass:S.
    _client_flag("openssl", "-k", r"(?:\s+|=)"),  # -k takes the password itself, never a pointer.
    _client_flag("ldapsearch|ldapmodify|ldapadd|ldapdelete|ldapwhoami|ldappasswd|ldapcompare", "-w", r"\s*"),
    _client_flag("zip|unzip", "-P", r"\s*"),
    _client_flag("7z|7za|7zr", "-p", r"\s*"),
    _client_flag("sqlcmd", "-P", r"\s*"),
    _client_flag("mongo|mongosh|mongodump|mongorestore|mongoexport|mongoimport", "-p", r"\s*"),
    _client_flag("keytool", "-storepass|-keypass|-srcstorepass|-deststorepass|-srckeypass|-destkeypass"),
    _client_flag("mysql|mysqldump|mysqladmin|mariadb|mariadb-dump", "-p", ""),  # -pSECRET, no space.
]

_TOOL_FLAGS = [
    # smbclient -U user%password, the pair quoted or not.
    re.compile(r"(\b(?:smbclient|rpcclient)\b[^\n|;&]{0,500}?\s(?:-U|--user)(?:\s+|=)[\"']?[^\s%\"']*%)" + _VALUE),
    # vault login TOKEN (flags such as -method=... and key=value pairs are not the token).
    re.compile(r"(\bvault\s+login(?:\s+-\S+)*\s+)([^\s\"'&;|=\-][^\s\"'&;|=]*)(?![^\s&;|])"),
]

# htpasswd -b FILE USER PASSWORD, or htpasswd -nb USER PASSWORD (no file with -n). -C and -r take a number,
# attached or not, and -- ends the options. A word may join quoted and plain parts (pa'ss w'rd).
_HT_WORD = r"(?:'[^'\n]{0,1000}'|\"[^\"\n]{0,1000}\"|[^\s\"'|;&<>])+"
_HTPASSWD = re.compile(r"\bhtpasswd\b((?:[ \t]+-[A-Za-z]*[Cr][ \t]*\d+|[ \t]+-[A-Za-z]+|[ \t]+--(?=[ \t]))+)"
                       r"((?:[ \t]+%s){1,3})" % _HT_WORD)

_LONG = re.compile(r"(?<![A-Za-z0-9+=_\-])([A-Za-z0-9+=_\-]{32,})(?![A-Za-z0-9+=_\-])")
# Base64 keys carry '/' too (AWS secret keys). Paths are left alone: no leading '/', no '.' anywhere near.
_LONG_SLASH = re.compile(r"(?<![A-Za-z0-9+=_\-/.~])([A-Za-z0-9+=_\-]+/[A-Za-z0-9+=_\-/]+)(?![A-Za-z0-9+=_\-/.])")

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u0080-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")


def _entropy(value):
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(value))
    return -sum(c / n * math.log(c / n, 2) for c in counts.values())


# A value that is one reference and nothing else: $VAR, ${VAR}, ${#VAR}, ${A[i]}, $(cmd) or `cmd`, each alone
# or in double quotes. $"..." is a literal; so are a reference joined to a literal ($X-S, ${E}S, "$X"S), a
# default (${P:-S}), and a substitution that may print its own words (see _fetches).
_REFERENCE = re.compile(r'^("?)(?:\$\w+|\$\{#?\w+(?:\[[^\]]*\])?\}|\$\(([^()]*)\)|`([^`]*)`)\1$')
# Inside a substitution: more than one command (;, &&, ||, a newline), a heredoc or here-string (<<), or a
# substitution inside it.
_MANY_COMMANDS = re.compile(r";|&&|\|\||\n|<<|`|\$\(")
# A command name written plainly: no quote, expansion, brace or glob that could spell another name.
_PLAIN_NAME = re.compile(r"^[A-Za-z0-9_./:+-]+$")
# Commands that fetch a secret from a file, a password manager or a cloud tool. Any other command is taken
# as one that may print words given to it (echo, date +S, perl -e, timeout ... echo).
_FETCHERS = {"cat", "head", "tail", "base64", "op", "gh", "pass", "security", "aws", "gcloud", "az", "vault",
             "sops", "gpg", "kubectl", "doppler", "bw", "lpass", "secret-tool", "heroku", "jq", "yq",
             "pbpaste"}
# A fetcher's argument, with one pair of surrounding quotes taken off: no quote inside it (aws --query "'S'",
# gh --jq '"S"' print S), and no word that starts another command (op run -- echo S).
_PLAIN_ARGUMENT = re.compile(r"^[\w./:+=@%~,${}\[\]-]*$")
_RUNS_NEXT = {"--", "run", "exec"}
# Fetcher words that store or take a secret rather than read one (bw unlock S, aws ssm put-parameter,
# heroku config:set, gh api -X PUT), alone or as a part of a word split at '-' or ':'.
_TAKES_SECRET = {"unlock", "set", "create", "edit", "put", "write", "login", "encrypt", "add", "patch", "update",
                 "lookup", "import", "store", "insert"}
_WORD_PARTS = re.compile(r"[-:=]")
# gh api options that send data or change the method (-f k=v, -fk=v, -XPUT, --method=PUT, --input f).
_GH_SENDS = re.compile(r"^(?:-[A-Za-z]*[fFXH]|--(?:method|input|header)(?:=|$))")
_TAKES_SECRET_OPTION = re.compile(r"^(?:--(?:passphrase|from-literal|body|password|secret|value|field|raw-field)"
                                  r"(?:=|$)|-[fF]$)")
# The | and & that join a fetcher's commands; the & of a redirect (2>&1) is part of its word.
_JOINS = re.compile(r"(?<![<>])(?:\|&|[|&])(?!>)")
# A redirect of the fetcher's errors (2>/dev/null, 2>&1), which adds nothing to its output.
_ERRORS_AWAY = re.compile(r"^2>(?:/dev/null|&1)$")
# An option given a whole quoted value (-o jsonpath='{.data.token}'): the value is read as one argument.
_QUOTED_OPTION_VALUE = re.compile(r"^([\w.-]*=)(['\"])([^'\"]*)\2$")
# jq and yq options that make text from their arguments rather than read it.
_MAKES_INPUT = re.compile(r"^(?:-[A-Za-z]*n[A-Za-z]*|--null-input|--arg\w*|--rawfile|--slurpfile|--jsonargs|--args)$")
_READS_FILE = re.compile(r"^\s*<\s*[^\s<>|&;]+\s*$")  # $(< file)


def _is_reference(value):
    """A value that only points at the secret ($VAR, "${VAR}", $(cmd), %VAR%, <file, -), not the secret."""
    # A command substitution's output is the secret, so $(cmd ...) points at it even when the word is cut at
    # the space inside it (still open there); text joined after a closed one ($(true)S) is a literal.
    ref = _REFERENCE.match(value)
    if ref:
        inside = ref.group(2) if ref.group(2) is not None else ref.group(3)
        return inside is None or _fetches(inside)
    return value.startswith(("%", "<")) or value in ("-", "", "''", '""')


def _fetches(inside):
    """True when a substitution's commands only fetch a value: $(< file), or commands joined by | or & that
    are each a known fetcher (cat, op, gh, ...) written plainly, with plain arguments."""
    if _READS_FILE.match(inside):
        return True
    if _MANY_COMMANDS.search(inside):
        return False
    for part in _JOINS.split(inside):
        words = part.split()
        if not words or not _PLAIN_NAME.match(words[0]) or words[0].rsplit("/", 1)[-1] not in _FETCHERS:
            return False
        makes_input = words[0].rsplit("/", 1)[-1] in ("jq", "yq")
        sends = words[0].rsplit("/", 1)[-1] == "gh" and "api" in [w.strip("'\"") for w in words]
        for w in words[1:]:
            if _ERRORS_AWAY.match(w):
                continue
            quoted = _QUOTED_OPTION_VALUE.match(w)
            bare = w[1:-1] if len(w) > 1 and w[0] == w[-1] and w[0] in "\"'" else w
            bare = quoted.group(1) + quoted.group(3) if quoted else bare
            if not _PLAIN_ARGUMENT.match(bare) or bare in _RUNS_NEXT:
                return False
            if _TAKES_SECRET.intersection(_WORD_PARTS.split(bare.lower())):
                return False
            if (
                _TAKES_SECRET_OPTION.match(bare)
                or makes_input and _MAKES_INPUT.match(bare)
                or sends and _GH_SENDS.match(bare)
            ):
                return False
    # A secret given to the fetcher on its own line (gpg --batch --passphrase S) is masked with the rest.
    return _sub_named(inside) == inside


# The most of a value read after one secret name: each name reads its value again, so a word of thousands
# of names kept as references ($(TOKEN=$(...) would otherwise be read once per name. A longer value is
# masked to the end of its line, since where a quoted part of it ends is not known.
MAX_TAIL = 1024


def _after_names(text, tail, keep):
    """Mask the value `tail` finds right after each secret name, unless keep(name, value) says not to."""
    out, last = [], 0
    for m in _TOKEN.finditer(text):
        # The secret word must be in the last dotted part: config.api_key is a name, api_key.txt a file.
        if m.start() < last or not _NAME_WORDS_RX.search(m.group(0).rsplit(".", 1)[-1]):
            continue
        t = tail.match(text, m.end(), m.end() + MAX_TAIL)
        if not t or keep(m.group(0), t.group(2)):
            continue
        out.append(text[last:t.start(2)])
        out.append(HIDDEN % "secret-named value")
        last = t.end(2)
        bound = m.end() + MAX_TAIL
        if bound < len(text) and (last == bound or text[last] not in " \t\n&;|"):
            # The bound cut the value (inside a quote, after a backslash): its end is not known.
            end = text.find("\n", last)
            last = len(text) if end < 0 else end
    out.append(text[last:])
    return "".join(out)


def _keep_named(name, value):
    return _is_reference(value) or value.startswith("[hidden") or value.lower() in _SCHEMES


def _sub_named(text):
    # Authorization and bearer first: the named rule would otherwise take the scheme word for the value.
    for label, rx in _NAMED[:2]:
        text = rx.sub(lambda m, label=label: _masked(m, label), text)
    text = _after_names(text, _QUOTED_TAIL, _keep_named)
    text = _after_names(text, _PLAIN_TAIL, _keep_named)
    for label, rx in _NAMED[2:]:
        text = rx.sub(lambda m, label=label: _masked(m, label), text)
    for rules in _CLIENT_FLAGS:
        text = _sub_client(text, *rules)
    for rx in _TOOL_FLAGS:
        text = rx.sub(_tool_flag, text)
    text = _HTPASSWD.sub(_htpasswd, text)
    return _after_names(text, _SPACED_TAIL, _keep_spaced)


def _masked(m, label):
    value, kept = m.group(2), ""
    if label == "user password":
        user, colon, value = value.partition(":")
        if not colon:
            return m.group(0)  # -u NAME alone: curl asks for the password.
        kept = user + colon
        value = value[:-1] if user[:1] and value[-1:] == user[:1] in "\"'" else value  # "admin:$P"
    if _is_reference(value) or value.startswith("[hidden") or value.lower() in _SCHEMES:
        return m.group(0)
    return m.group(1) + kept + HIDDEN % label


def _tool_flag(m):
    value = m.group(m.lastindex)
    if _is_reference(value) or value.startswith("[hidden"):
        return m.group(0)
    return m.group(0)[:m.start(m.lastindex) - m.start(0)] + HIDDEN % "password"


def _sub_client(text, clients, flag_name, flag, keep):
    out, last, pos = [], 0, 0
    while True:
        c = clients.search(text, pos)
        if not c:
            break
        # Flags are looked for only inside the client's own part of the line, so no search runs past it; the
        # value may still run on past that part (a quoted one).
        for start in flag_name.finditer(text, c.start(), c.end()):
            f = flag.match(text, start.start())
            if not f:
                continue
            value = f.group(2)
            if f.start() < last or _is_reference(value) or value.startswith("[hidden") or _PORT_MAP.match(value):
                continue
            if keep is not None and keep.match(value):
                continue
            if value.startswith("-") and f.group(1)[-1].isspace():  # The next flag, not a value: -p prompts.
                continue
            out.append(text[last:f.start(2)])
            out.append(HIDDEN % "password")
            last = f.end(2)
        pos = c.start() + 1  # A client named again inside this part gets its own 500 characters.
    out.append(text[last:])
    return "".join(out)


def _htpasswd(m):
    flags = m.group(1)
    if "b" not in flags:  # htpasswd reads the password from the line only with -b.
        return m.group(0)
    words = list(re.finditer(_HT_WORD, m.group(2)))
    index = 1 if "n" in flags else 2  # With -n there is no file before the user.
    if len(words) <= index or _is_reference(words[index].group(0)) or words[index].group(0).startswith("[hidden"):
        return m.group(0)
    w = words[index]
    return "htpasswd" + flags + m.group(2)[:w.start()] + HIDDEN % "password" + m.group(2)[w.end():]


def _keep_spaced(name, value):
    """A compound secret name (aws_secret_access_key, GITHUB_TOKEN), a space, then a generated-looking value.

    A lone word such as 'password' may be prose, and 'grep api_key src/' names a folder, so both stay.
    """
    if not ("_" in name.strip("-.") or "-" in name.strip("-.")):
        return True
    kinds = sum(1 for rx in (r"[A-Z]", r"[a-z]", r"[0-9]") if re.search(rx, value))
    return _is_reference(value) or value.startswith(("[hidden", "/", ".", "~", "-")) or kinds < 2


def _sub_long(text):
    def repl(m):
        value = m.group(1)
        has_upper = re.search(r"[A-Z]", value) is not None
        has_lower = re.search(r"[a-z]", value) is not None
        has_digit = re.search(r"[0-9]", value) is not None
        if has_upper and has_lower and has_digit and _entropy(value) >= 4.2:
            return HIDDEN % "long random value"
        return value

    def repl_slash(m):
        value = m.group(1)
        if len(value) < 32 or max(len(part) for part in value.split("/")) < 8:
            return value
        return repl(m) if _entropy(value) >= 4.5 else value
    return _LONG_SLASH.sub(repl_slash, _LONG.sub(repl, text))


_QUANT = re.compile(r"[*+]|\{(?:\d*,\d*|\d*[2-9]\d*|\d{2,})\}")


# Anything that lets a part match in more than one way, optional (?) included: (a?){25} is as slow as (a+)+.
_VARIES = re.compile(r"[*+?]|\{\d*,?\d*\}")
_BRACES = re.compile(r"\{(\d*)(,?)(\d*)\}")
# An inline flag group that turns on verbose mode: (?x), (?ix), (?x:...).
_VERBOSE = re.compile(r"\(\?[aiLmsu]*x[aiLmsux]*(?:-[aiLmsux]*)?[:)]")


def slow_pattern(pattern):
    """True when a repeated group holds a repeat, an optional part or alternatives, as in (a+)+, (a?){25} or
    (x|xy)*; when it turns on verbose mode or holds a comment group (?#...), which can hide that shape; when it has more
    than two wide repeats (a*a*a*b, [ab]{1,200} three times); or when it has more than four repeats of any
    kind (a?a?a?a?a?aaaaa).

    Those are the shapes that can backtrack for minutes on a line built for them. Python's re has no
    time limit, so patterns from a project's config with these shapes are refused (yours are trusted).
    """
    if _VERBOSE.search(pattern) or "(?#" in pattern:
        return True  # Spaces and comments may sit between a group and its repeat: (?x)(a+) +c, (a+)(?#c)+.
    wide, varying = _count_repeats(pattern)
    if wide > 2 or varying > 4:
        return True
    stack = [False]  # Per open group: does it hold a repeat, an optional part or an alternative?
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            stack[-1] = stack[-1] or bool(_VARIES.match(pattern, i))
            continue
        if c == "[":
            i = _class_end(pattern, i)
            stack[-1] = stack[-1] or bool(_VARIES.match(pattern, i))
            continue
        if c == "(":
            stack.append(False)
            i += 1
            continue
        if c == ")":
            inner = stack.pop() if len(stack) > 1 else False
            i += 1
            if _QUANT.match(pattern, i) and inner:
                return True
            stack[-1] = stack[-1] or inner or bool(_VARIES.match(pattern, i))
            continue
        if c == "|":
            stack[-1] = True
        elif _VARIES.match(pattern, i + 1):
            stack[-1] = True
        i += 1
    return False


def _count_repeats(pattern):
    """(wide, varying): repeats that range over more than two counts (*, +, {2,}, {1,200}), and all
    repeats that range at all (those plus ? and {1,2}). Escapes, classes, (? group syntax and a lazy or
    possessive mark after a repeat are not repeats."""
    wide = varying = 0
    i, n, after_repeat = 0, len(pattern), False
    while i < n:
        c, repeat = pattern[i], None
        if c == "\\":
            i += 2
        elif c == "[":
            i = _class_end(pattern, i)
        elif c == "(" and pattern[i + 1:i + 2] == "?":
            i += 2
        elif c in "*+":
            repeat, i = True, i + 1
        elif c == "?":
            repeat, i = False, i + 1
        elif c == "{" and _BRACES.match(pattern, i):
            b = _BRACES.match(pattern, i)
            low = int(b.group(1) or 0)
            high = int(b.group(3)) if b.group(3) else None
            if b.group(2):
                repeat = high is None or high - low > 1 if high != low else None
            i = b.end()
        else:
            i += 1
        if repeat is not None and not after_repeat:
            wide += repeat
            varying += 1
        after_repeat = repeat is not None
    return wide, varying


def _class_end(pattern, i):
    """The index just past the character class that starts at pattern[i] == '['."""
    i += 1
    if i < len(pattern) and pattern[i] == "^":
        i += 1
    if i < len(pattern) and pattern[i] == "]":
        i += 1
    while i < len(pattern) and pattern[i] != "]":
        i += 2 if pattern[i] == "\\" else 1
    return i + 1


def compile_patterns(patterns):
    """Compile user patterns; returns (compiled, errors)."""
    out, errors = [], []
    for p in patterns or []:
        try:
            out.append(re.compile(p))
        except re.error as exc:
            errors.append("redact_patterns: %r does not compile (%s)" % (p, exc))
    return out, errors


class Redactor(object):
    """clean() with the settings of one run."""

    def __init__(self, home=None, redact_home=True, patterns=None, limit=300):
        self.home = (home or "").rstrip("/")
        self.redact_home = redact_home
        self.patterns, self.errors = compile_patterns(patterns)
        self.limit = limit

    @classmethod
    def for_settings(cls, home, values):
        """The redactor a run with these settings uses: your redact_home and redact_patterns."""
        return cls(home, values.get("redact_home", True), values.get("redact_patterns"))

    def keeping_home(self):
        """The same redactor with the home folder spelled out (for a command meant to be pasted)."""
        other = Redactor(self.home, False, limit=self.limit)
        other.patterns, other.errors = self.patterns, self.errors
        return other

    def clean(self, text, limit=None, oneline=True):
        if text is None:
            return ""
        if not isinstance(text, str):
            text = str(text)
        text = _ANSI.sub("", text)
        text = secrets.mask(text)
        text = _sub_named(text)
        text = _sub_long(text)
        cap = self.limit if limit is None else limit
        cut = 0
        if self.patterns and cap and len(text) > cap + 256:
            # Your patterns only need to see what the report will show; a slow one then stays quick.
            cut = len(text) - (cap + 256)
            text = text[:cap + 256]
        for rx in self.patterns:
            text = rx.sub(HIDDEN % "custom pattern", text)
        if self.redact_home and self.home and len(self.home) > 1:
            text = re.sub(re.escape(self.home) + r"(?=/|\b|$)", "~", text)
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        if oneline:
            text = text.replace("\n", " \u23ce ").replace("\t", " ")
            text = _CONTROL.sub("", text)
        else:
            text = "\n".join(_CONTROL.sub("", line.replace("\t", "    ")) for line in text.split("\n"))
        if cap and len(text) > cap:
            text = text[:cap] + "\u2026 (+%d chars)" % (len(text) - cap + cut)
        return text
