#!/usr/bin/env python3
"""
srx_parse.py - Extract objects and rulebases from Juniper SRX (Junos) "show configuration"
output (the curly-brace hierarchical format) and write them to CSV.

Standard library only (Python 3.8+).

Usage:
    python srx_parse.py config.txt [-o output] [--expand] [--max-expand N] [--strict]
                        [--csv-nl-sep STR]
    python srx_parse.py --selftest          # run against the embedded sample config

Each run writes to <output>/<YYYY-MM-DD_HH-MM-SS>/ (a new folder per run; add "output/" to
.gitignore):
    objects.csv            one row per object (addresses, address-sets, applications,
                           application-sets, schedulers, NAT pools)
    object_members.csv     direct and fully-resolved members of every set
    rules_<rulebase>.csv   security-policy, nat-source, nat-destination, nat-static
    rules_expanded.csv     (--expand) security policies: one row per src x dst x application
    warnings.csv           unresolved references, cycles, duplicates, syntax problems

Input notes
  * Two input formats are accepted and detected automatically (override with --input-format):
      - hierarchical:  `show configuration`                (curly-brace format)
      - set:           `show configuration | display set`  (one "set ..." command per line)
    JSON and XML output are not supported.  In set format `deactivate` lines become the
    "disabled" flag; annotations (/* ... */) are not part of display set output, so the
    annotation columns are blank for set input.
  * Prompt lines, `{primary:node0}` banners, `---(more)---` and `[edit]` lines are ignored.
  * `inactive:` statements are kept and flagged as disabled; `/* annotations */` are kept.
  * Root, logical-systems and tenants are each processed as an independent context.
"""
import argparse
import csv
import itertools
import os
import re
import sys
from datetime import datetime

TOOL_VERSION = "0.1.0"

IP4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
IP6_RE = re.compile(r"^[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*(/\d{1,3})?$")
ANY_ADDR = ("any", "any-ipv4", "any-ipv6")

# Partial table of predefined Junos applications (others starting "junos-" are kept by name)
BUILTIN_APPS = {
    "junos-http": "tcp/80", "junos-https": "tcp/443", "junos-ssh": "tcp/22", "junos-telnet": "tcp/23",
    "junos-ftp": "tcp/21", "junos-smtp": "tcp/25", "junos-smtps": "tcp/465", "junos-dns-udp": "udp/53",
    "junos-dns-tcp": "tcp/53", "junos-ntp": "udp/123", "junos-snmp-get": "udp/161",
    "junos-snmp-trap": "udp/162", "junos-syslog": "udp/514", "junos-ldap": "tcp/389",
    "junos-ldaps": "tcp/636", "junos-imap": "tcp/143", "junos-imaps": "tcp/993",
    "junos-pop3": "tcp/110", "junos-pop3s": "tcp/995", "junos-icmp-ping": "icmp/8", "junos-ping": "icmp/8",
    "junos-icmp-all": "icmp", "junos-mysql": "tcp/3306", "junos-ms-sql": "tcp/1433",
    "junos-radius": "udp/1812", "junos-bgp": "tcp/179", "junos-tftp": "udp/69", "junos-ike": "udp/500",
}
APP_KEYS = ("protocol", "source-port", "destination-port", "icmp-type", "icmp-code",
            "icmp6-type", "icmp6-code")

CSV_NL_SEP = [" | "]
_NL_RE = re.compile(r"\r\n|\r|\n")

# --------------------------------------------------------------------------- #
# Rule column specifications: (csv column, kind, key)
#   preset -> value set in code      list   -> values at that path joined with ';'
#   prefix -> everything under path  res    -> resolved values (sets expanded)
# Anything not claimed by a column goes to other_fields, so nothing is dropped.
# --------------------------------------------------------------------------- #
POLICY_SPEC = [
    ("description", "list", "description"), ("annotation", "preset", None), ("disabled", "preset", None),
    ("action", "preset", None), ("action_options", "preset", None),
    ("from_zone", "preset", None), ("to_zone", "preset", None),
    ("source", "list", "match/source-address"), ("source_resolved", "res", "source"),
    ("destination", "list", "match/destination-address"), ("destination_resolved", "res", "destination"),
    ("application", "list", "match/application"), ("application_resolved", "res", "application"),
    ("source_identity", "list", "match/source-identity"),
    ("dynamic_application", "list", "match/dynamic-application"),
    ("url_category", "list", "match/url-category"),
    ("log", "prefix", "then/log"), ("count", "prefix", "then/count"),
    ("scheduler_name", "list", "scheduler-name"),
]
NAT_SPEC = [
    ("description", "list", "description"), ("rule_set_description", "preset", None),
    ("annotation", "preset", None), ("disabled", "preset", None),
    ("from", "preset", None), ("to", "preset", None),
    ("source_address", "list", "match/source-address"),
    ("source_address_name", "list", "match/source-address-name"), ("source_resolved", "res", "source"),
    ("destination_address", "list", "match/destination-address"),
    ("destination_address_name", "list", "match/destination-address-name"),
    ("destination_resolved", "res", "destination"),
    ("source_port", "list", "match/source-port"), ("destination_port", "list", "match/destination-port"),
    ("protocol", "list", "match/protocol"), ("application", "list", "match/application"),
    ("translation", "prefix", "then"), ("translated_resolved", "res", "translated"),
]
RULE_BASE_COLS = ["logical_system", "scope_type", "scope", "rulebase", "rule_number", "name"]
RULE_TAIL_COLS = ["other_fields", "source_line", "config_path"]
OBJECT_COLS = ["logical_system", "scope_type", "scope", "object_type", "name", "description", "annotation",
               "disabled", "value_type", "value", "members", "members_resolved", "attached_zones",
               "referenced_by_rules", "other_fields", "source_line", "config_path"]
MEMBER_COLS = ["logical_system", "scope_type", "scope", "object_type", "object", "level", "member", "via"]
EXPANDED_COLS = ["logical_system", "scope_type", "scope", "rulebase", "rule_number", "name", "action",
                 "disabled", "from_zone", "to_zone", "source", "destination", "application", "description"]


# --------------------------------------------------------------------------- #
# Junos tokenizer and tree builder
# --------------------------------------------------------------------------- #
NOISE = [re.compile(r"^\s*\S+@\S+[>#]"), re.compile(r"^\s*\{(master|primary|secondary|backup)(:\w+)?\}\s*$"),
         re.compile(r"^\s*---\(more.*\)---\s*$"), re.compile(r"^\s*\[edit[^\]]*\]\s*$")]


def clean_noise(text):
    """Blank out CLI noise but keep line numbering intact."""
    out = []
    for line in text.splitlines():
        noisy = any(r.match(line) for r in NOISE)
        if noisy and NOISE[0].match(line) and any(c in line for c in ';{}"'):
            noisy = False   # looks like config text that merely contains '@'
        out.append("" if noisy else line)
    return "\n".join(out)


def tokenize(text):
    """Yield (kind, value, line).  kinds: w word, s quoted string, c annotation, and { } ; [ ]"""
    toks, i, n, line = [], 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j
            body = "\n".join(l.strip() for l in text[i + 2:j].strip().splitlines())
            toks.append(("c", body, line))
            line += text.count("\n", i, j)
            i = j + 2
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif c == '"':
            start, j, buf = line, i + 1, []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                if text[j] == "\n":
                    line += 1
                buf.append(text[j])
                j += 1
            toks.append(("s", "".join(buf), start))
            i = j + 1
        elif c in "{};[]":
            toks.append((c, c, line))
            i += 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in '{};[]"':
                j += 1
            toks.append(("w", text[i:j], line))
            i = j
    return toks


def flat(items):
    out = []
    for x in items:
        out.extend(flat(x) if isinstance(x, list) else [x])
    return out


class Node:
    __slots__ = ("head", "kids", "inactive", "annotation", "line")

    def __init__(self, head, line, inactive=False, annotation=""):
        self.head, self.kids, self.line = head, [], line
        self.inactive, self.annotation = inactive, annotation

    @property
    def name(self):
        return self.head[0] if self.head and isinstance(self.head[0], str) else ""

    def words(self):
        return flat(self.head[1:])

    def find(self, name):
        for k in self.kids:
            if k.name == name:
                return k
        return None

    def find_all(self, name):
        return [k for k in self.kids if k.name == name]


def build_tree(toks):
    root = Node([], 0)
    stack, errors = [root], []
    head, ann, inactive, in_list, hline = [], "", False, None, 0

    def emit(block):
        nonlocal head, ann, inactive
        node = Node(head, hline, inactive, ann)
        stack[-1].kids.append(node)
        if block:
            stack.append(node)
        head, ann, inactive = [], "", False

    for kind, val, ln in toks:
        if kind == "c":
            ann = (ann + "\n" + val) if ann else val
        elif kind in ("w", "s"):
            if in_list is not None:
                in_list.append(val)
            elif kind == "w" and not head and val in ("inactive:", "protect:"):
                inactive = inactive or val == "inactive:"
            else:
                if not head:
                    hline = ln
                head.append(val)
        elif kind == "[":
            in_list = []
        elif kind == "]":
            head.append(in_list or [])
            in_list = None
        elif kind == ";":
            if head:
                emit(False)
        elif kind == "{":
            emit(True)
        elif kind == "}":
            if head:
                emit(False)
            if len(stack) > 1:
                stack.pop()
            else:
                errors.append("line %d: unmatched '}'" % ln)
    if head:
        emit(False)
        errors.append("statement without terminator at end of file")
    if len(stack) > 1:
        errors.append("%d unclosed '{' at end of file (line %d)" % (len(stack) - 1, stack[-1].line))
    return root, errors


# --------------------------------------------------------------------------- #
# "display set" input: convert "set a b c d" lines into the same Node tree
# --------------------------------------------------------------------------- #
SET_TOP = ("security", "applications", "schedulers", "system", "version", "logical-systems", "tenants")
_SET_TOKEN_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|(\S+)')
# Keywords that take ONE name/value word as part of their statement head.  A flat "set" line does
# not say where a statement ends, so the converter needs to know this for the stanzas we parse.
# Unlisted keywords take none (they are containers or flags); unknown stanzas are harmless because
# nothing reads them.
_SET_ARITY1 = {"security-zone", "address-set", "policy", "rule-set", "rule", "pool", "term", "scheduler",
               "application", "application-set", "scheduler-name",
               "description", "source-address", "destination-address", "source-address-excluded",
               "destination-address-excluded", "source-address-name", "destination-address-name",
               "source-identity", "dynamic-application", "url-category", "protocol", "source-port",
               "destination-port", "icmp-type", "icmp-code", "icmp6-type", "icmp6-code", "host-name",
               "version", "prefix", "prefix-name", "start-time", "stop-time", "start-date", "stop-date",
               "ipsec-vpn", "pair-policy", "utm-policy", "zone"}
_GREEDY = -1
_WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "daily")


def tokenize_set(line):
    out = []
    for m in _SET_TOKEN_RE.finditer(line):
        out.append(m.group(1).replace('\\"', '"').replace("\\\\", "\\") if m.group(1) is not None else m.group(2))
    return out


def _set_arity(kwpath, w):
    p = kwpath[-1] if kwpath else ""
    if p in _WEEKDAYS:                         # "monday start-time 08:00:00 stop-time 18:00:00" is one leaf
        return _GREEDY
    if p in ("logical-systems", "tenants"):    # the name is its own node, as in the hierarchical layout
        return 0
    if w == "from-zone":                       # from-zone A to-zone B
        return 3
    if p == "address-book" and len(kwpath) > 1 and kwpath[-2] == "security":
        return 0                               # book name (global / NAME) is its own node, as in the hierarchical layout
    if p in ("source-nat", "destination-nat") and w == "pool":
        return 0                               # "pool { NAME; }" layout: the name becomes a child node
    if p == "static-nat" and w == "prefix":
        return 0                               # "prefix { A; }" layout
    if w in ("from", "to"):                    # NAT rule-set:  from zone trust
        return 2 if p == "rule-set" else 0
    if w == "address":
        if p == "address-set":
            return 1
        if p == "pool":                        # nat pool:  address 1.1.1.1/32 [to 1.1.1.9/32] [port N]
            return _GREEDY
    return 1 if w in _SET_ARITY1 else 0


def _in_book(kwpath):
    """True when the next word is a statement inside an address book (global / named / zone book)."""
    if len(kwpath) >= 2 and kwpath[-1] == "address-book" and kwpath[-2] == "security-zone":
        return True
    return len(kwpath) >= 3 and kwpath[-2] == "address-book" and kwpath[-3] == "security"


def set_to_tree(text):
    """Build the same Node tree that build_tree() produces, from 'show configuration | display set'."""
    root, index, errors = Node([], 0), {}, []
    deactivate, annotate = [], []

    def child(parent, head, ln, create, key=None):
        k = (id(parent), tuple(key or head))
        node = index.get(k)
        if node is None and create:
            node = Node(list(head), ln)
            parent.kids.append(node)
            index[k] = node
        return node

    def walk(words, ln, create):
        node, kwpath, i = root, [], 0
        while i < len(words) and node is not None:
            w, rest = words[i], words[i + 1:]
            if w == "address" and _in_book(kwpath):
                name = rest[0] if rest else ""
                node = child(node, ["address", name], ln, create)
                tail = rest[1:]
                if node is not None and tail and create:
                    if tail[0] == "description":
                        child(node, ["description"] + tail[1:2], ln, True)
                    elif tail[0] == "dns-name" and len(tail) > 1:
                        dn = child(node, ["dns-name", tail[1]], ln, True)
                        for flag in tail[2:]:
                            child(dn, [flag], ln, True)
                    else:                       # one-line value forms: prefix / range-address / wildcard-address
                        node.head = ["address", name] + tail
                return node
            if w == "term":                     # term NAME attr value attr value ... (possibly over several lines)
                node = child(node, ["term", rest[0] if rest else ""], ln, create)
                if node is not None and create:
                    node.head = node.head + rest[1:]
                return node
            n = _set_arity(kwpath, w)
            if n == _GREEDY:
                n = len(rest)
            node = child(node, [w] + rest[:n], ln, create)
            kwpath.append(w)
            i += 1 + n
        return node

    for ln, raw in enumerate(text.splitlines(), 1):
        t = tokenize_set(raw)
        if len(t) < 2 or t[0] not in ("set", "deactivate", "annotate") or t[1] not in SET_TOP:
            continue
        if t[0] == "set":
            walk(t[1:], ln, True)
        elif t[0] == "deactivate":
            deactivate.append((ln, t[1:]))
        elif len(t) > 2:
            annotate.append((ln, t[1:-1], t[-1]))
    for ln, words in deactivate:               # applied last, so the statement exists regardless of line order
        node = walk(words, ln, False)
        if node is None:
            errors.append("line %d: deactivate refers to a statement not found in the set lines" % ln)
        else:
            node.inactive = True
    for ln, words, text_ in annotate:
        node = walk(words, ln, False)
        if node is not None:
            node.annotation = text_
    return root, errors


def detect_format(text):
    sets = braces = 0
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("set ") or s.startswith("deactivate "):
            sets += 1
        elif s.endswith("{") or s == "}" or s.endswith(";"):
            braces += 1
    return "set" if sets >= 3 and sets > braces else "hierarchical"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def flatten_node(node, prefix="", out=None, notes=None):
    """Flatten children into {path: [values]}.  Flags (no value) map to []."""
    if out is None:
        out, notes = {}, []
    for kid in node.kids:
        key = prefix + kid.name
        vals = kid.words()
        if kid.annotation:
            notes.append(("annotation", key, kid.annotation))
        if kid.inactive:
            notes.append(("inactive", key, ""))
        if kid.kids:
            if vals:
                out.setdefault(key, []).extend(vals)
            flatten_node(kid, key + "/", out, notes)
        else:
            out.setdefault(key, []).extend(vals)
    return out, notes


def kv(items, vsep=";"):
    return "; ".join(("%s=%s" % (k, vsep.join(v)) if v else k) for k, v in items)


def pop_prefix(rem, prefix):
    found = []
    for k in list(rem):
        if k == prefix or k.startswith(prefix + "/"):
            found.append((k.split("/")[-1] if k == prefix else k[len(prefix) + 1:], rem.pop(k)))
    return found


def looks_prefix(t):
    return bool(IP4_RE.match(t) or IP6_RE.match(t))


def uniq(pairs):
    seen, out = set(), []
    for text, via in pairs:
        if text and text not in seen:
            seen.add(text)
            out.append((text, via))
    return out


def classify_addr(tokens):
    t = tokens[0]
    if t == "range-address":
        a = tokens[1] if len(tokens) > 1 else ""
        b = tokens[3] if len(tokens) > 3 and tokens[2] == "to" else ""
        return "range-address", "%s-%s" % (a, b)
    if t in ("dns-name", "wildcard-address", "ip-prefix"):
        return t, tokens[1] if len(tokens) > 1 else ""
    if looks_prefix(t):
        return "ip-prefix", t
    return "", " ".join(tokens)


def addr_text(vt, val):
    if vt == "dns-name":
        return "fqdn:" + val
    if vt == "wildcard-address":
        return "wildcard:" + val
    return val


def parse_attr_tokens(tokens, attrs, other, prefix=""):
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if i + 1 < len(tokens):
            if t in APP_KEYS:
                attrs[t] = tokens[i + 1]
            else:
                other.append((prefix + t, [tokens[i + 1]]))
            i += 2
        else:
            other.append((prefix + t, []))
            i += 1


def attr_text(a):
    proto = a.get("protocol", "")
    if proto in ("icmp", "icmp6"):
        t = a.get("icmp-type") or a.get("icmp6-type")
        c = a.get("icmp-code") or a.get("icmp6-code")
        return proto + ("/" + t if t else "") + (" code %s" % c if c else "")
    if proto:
        return proto + ("/" + a["destination-port"] if "destination-port" in a else "") + \
            (" (src %s)" % a["source-port"] if "source-port" in a else "")
    return ""


def pool_addr_text(tokens):
    if not tokens:
        return ""
    t = tokens[0]
    if "to" in tokens[1:]:
        t = "%s-%s" % (tokens[0], tokens[tokens.index("to") + 1])
    if "port" in tokens:
        t += " (port %s)" % tokens[tokens.index("port") + 1]
    return t


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
class Ctx:
    """One configuration context: the root, a logical-system or a tenant."""

    def __init__(self, name):
        self.name = name
        self.scopes = {}                    # (kind, name) -> scope dict
        self.attached = {}                  # zone -> [address-book names]
        self.apps = {"application": {}, "application-set": {}}
        self.scheds = {}
        self.pools = {"source": {}, "destination": {}}
        self.policies, self.nat = [], []


class SrxParser:
    def __init__(self, expand=False, max_expand=100000):
        self.expand, self.max_expand = expand, max_expand
        self.ctxs, self.used = [], set()
        self.warnings, self._wseen = [], set()
        self.unresolved, self.syntax_errors = 0, 0
        self.rule_rows, self.expanded = {}, []
        self.object_rows, self.member_rows = [], []
        self.meta = {"hostname": None, "version": None}

    # ---- diagnostics ----------------------------------------------------- #
    def warn(self, ctx, context, msg):
        key = (ctx.name if ctx else "", context, msg)
        if key not in self._wseen:
            self._wseen.add(key)
            self.warnings.append({"logical_system": ctx.name if ctx else "", "context": context, "message": msg})

    def unres(self, ctx, kind, name, rctx):
        self.unresolved += 1
        self.warn(ctx, rctx, "unresolved %s reference '%s'" % (kind, name))

    # ---- top level ------------------------------------------------------- #
    def parse(self, text, fmt="auto"):
        cleaned = clean_noise(text)
        fmt = detect_format(cleaned) if fmt == "auto" else fmt
        self.meta["format"] = fmt
        root, errors = set_to_tree(cleaned) if fmt == "set" else build_tree(tokenize(cleaned))
        for e in errors:
            self.syntax_errors += 1
            self.warn(None, "syntax", e)
        if not root.kids:
            raise ValueError("no configuration statements found")
        v = root.find("version")
        self.meta["version"] = " ".join(v.words()) if v else None
        hn = root.find("system")
        hn = hn.find("host-name") if hn else None
        self.meta["hostname"] = " ".join(hn.words()) if hn else None
        if not any(root.find(k) for k in ("security", "applications", "logical-systems", "tenants")):
            raise ValueError("no security/applications stanzas found - is this 'show configuration' output "
                             "(hierarchical or '| display set' format)? JSON and XML formats are not supported")

        main = Ctx("")
        self.ctxs.append(main)
        self.ingest(main, root, "")
        for container, label in (("logical-systems", ""), ("tenants", "tenant:")):
            c = root.find(container)
            for ls in (c.kids if c else []):
                ctx = Ctx(label + ls.name)
                self.ctxs.append(ctx)
                self.ingest(ctx, ls, "%s %s " % (container, ls.name))

        self.compute_group_views()
        for ctx in self.ctxs:
            self.process_policies(ctx)
            self.process_nat(ctx)
        self.build_object_rows()

    # ---- ingest ---------------------------------------------------------- #
    def ingest(self, ctx, node, prefix):
        sec = node.find("security")
        if sec:
            self.ingest_security(ctx, sec, prefix + "security ")
        apps = node.find("applications")
        if apps:
            for kid in apps.kids:
                if kid.name == "application":
                    self.add_obj(ctx, ctx.apps["application"], self.make_application(ctx, kid, prefix + "applications "))
                elif kid.name == "application-set":
                    self.add_obj(ctx, ctx.apps["application-set"],
                                 self.make_set(ctx, kid, ("application", "application-set"), "application-set",
                                               "applications", "", prefix + "applications "))
        sch = node.find("schedulers")
        if sch:
            for kid in sch.find_all("scheduler"):
                w = kid.words()
                f, _ = flatten_node(kid)
                desc = " ".join(f.pop("description", []))
                o = self.new_obj("scheduler", w[0] if w else "", "schedulers", "", kid,
                                 prefix + "schedulers scheduler " + (w[0] if w else ""))
                o.update(desc=desc, val=kv(f.items(), " "))
                self.add_obj(ctx, ctx.scheds, o)

    def new_obj(self, otype, name, scope_type, scope, node, path):
        return {"type": otype, "name": name, "scope_type": scope_type, "scope": scope, "desc": "",
                "annotation": node.annotation, "inactive": node.inactive, "vt": "", "val": "",
                "members": [], "other": "", "attached": [], "line": node.line, "path": path, "view": None}

    def add_obj(self, ctx, store, o):
        if o["name"] in store:
            self.warn(ctx, "%s/%s" % (o["type"], o["name"]), "duplicate %s name (later definition wins)" % o["type"])
        store[o["name"]] = o

    def scope(self, ctx, key, scope_type, scope, path):
        if key not in ctx.scopes:
            ctx.scopes[key] = {"objs": {"address": {}, "address-set": {}}, "scope_type": scope_type,
                               "scope": scope, "path": path, "attached": []}
        return ctx.scopes[key]

    def ingest_security(self, ctx, sec, prefix):
        ab = sec.find("address-book")
        for book in (ab.kids if ab else []):
            bname = book.name
            if bname == "global":
                sc = self.scope(ctx, ("global", "global"), "global", "global", prefix + "address-book global ")
            else:
                sc = self.scope(ctx, ("book", bname), "address-book", bname, prefix + "address-book %s " % bname)
            self.ingest_book(ctx, sc, book)
            att = book.find("attach")
            for z in (att.find_all("zone") if att else []):
                for zn in z.words():
                    ctx.attached.setdefault(zn, []).append(bname)
                    sc["attached"].append(zn)
        zones = sec.find("zones")
        for z in (zones.find_all("security-zone") if zones else []):
            zw = z.words()
            zname = zw[0] if zw else ""
            zab = z.find("address-book")
            if zab:
                sc = self.scope(ctx, ("zone", zname), "zone", zname,
                                prefix + "zones security-zone %s address-book " % zname)
                self.ingest_book(ctx, sc, zab)

        pol = sec.find("policies")
        for fz in (pol.find_all("from-zone") if pol else []):
            w = fz.words()
            fzn, tzn = (w[0] if w else ""), (w[2] if len(w) > 2 else "")
            for p in fz.find_all("policy"):
                pw = p.words()
                ctx.policies.append((fzn, tzn, p, fz,
                                     "%spolicies from-zone %s to-zone %s policy %s" % (prefix, fzn, tzn, pw[0] if pw else "")))
        g = pol.find("global") if pol else None
        for p in (g.find_all("policy") if g else []):
            pw = p.words()
            ctx.policies.append((None, None, p, g, "%spolicies global policy %s" % (prefix, pw[0] if pw else "")))

        nat = sec.find("nat")
        for kind in ("source", "destination", "static"):
            kn = nat.find(kind) if nat else None
            if kn is None:
                continue
            for pool in (kn.find_all("pool") if kind in ctx.pools else []):
                self.add_obj(ctx, ctx.pools[kind], self.make_pool(ctx, pool, kind, prefix + "nat %s " % kind))
            for rs in kn.find_all("rule-set"):
                ctx.nat.append((kind, rs, prefix + "nat %s " % kind))

    def ingest_book(self, ctx, sc, book):
        for kid in book.kids:
            if kid.name == "address":
                self.add_obj(ctx, sc["objs"]["address"], self.make_address(sc, kid))
            elif kid.name == "address-set":
                o = self.make_set(ctx, kid, ("address", "address-set"), "address-set", sc["scope_type"],
                                  sc["scope"], sc["path"])
                self.add_obj(ctx, sc["objs"]["address-set"], o)

    def make_address(self, sc, kid):
        args = kid.words()
        name = args[0] if args else ""
        o = self.new_obj("address", name, sc["scope_type"], sc["scope"], kid, sc["path"] + "address " + name)
        f, _ = flatten_node(kid)
        if len(args) > 1:
            o["vt"], o["val"] = classify_addr(args[1:])
        for ch in kid.kids:
            n = ch.name
            if n in ("dns-name", "wildcard-address", "ip-prefix", "range-address"):
                toks = [n] + ch.words()
                if n == "range-address":
                    to = ch.find("to")
                    if to is not None and "to" not in toks:
                        toks += ["to", (to.words() or [k.name for k in to.kids] or [""])[0]]
                o["vt"], o["val"] = classify_addr(toks)
                for k in list(f):
                    if k == n or (n == "range-address" and k.startswith(n + "/")):
                        f.pop(k)
            elif looks_prefix(n):
                o["vt"], o["val"] = "ip-prefix", n
                f.pop(n, None)
        o["desc"] = " ".join(f.pop("description", []))
        o["other"] = kv(f.items())
        return o

    def make_set(self, ctx, kid, kinds, otype, scope_type, scope, path):
        w = kid.words()
        name = w[0] if w else ""
        o = self.new_obj(otype, name, scope_type, scope, kid, path + "%s %s" % (otype, name))
        f, _ = flatten_node(kid)
        for k in kinds:                       # members keep the order they appear in the config
            f.pop(k, None)
        for ch in kid.kids:
            if ch.name in kinds:
                o["members"] += ch.words()
        o["desc"] = " ".join(f.pop("description", []))
        o["other"] = kv(f.items())
        return o

    def make_application(self, ctx, kid, path):
        args = kid.words()
        name = args[0] if args else ""
        o = self.new_obj("application", name, "applications", "", kid, path + "application " + name)
        base, other, terms = {}, [], []
        parse_attr_tokens(args[1:], base, other)
        for ch in kid.kids:
            n, cw = ch.name, ch.words()
            if n == "description":
                o["desc"] = " ".join(cw)
            elif n == "term":
                tname = cw[0] if cw else ""
                a = {}
                parse_attr_tokens(cw[1:], a, other, "term/%s/" % tname)
                for g in ch.kids:
                    if g.name in APP_KEYS and g.words():
                        a[g.name] = g.words()[0]
                    else:
                        other.append(("term/%s/%s" % (tname, g.name), g.words()))
                terms.append(a)
            elif n in APP_KEYS and cw:
                base[n] = cw[0]
            else:
                other.append((n, cw))
        if base:
            terms.insert(0, base)
        o["texts"] = [t for t in (attr_text(a) for a in terms) if t]
        o["vt"] = "/".join(dict.fromkeys(a.get("protocol", "") for a in terms if a.get("protocol")))
        o["val"] = "; ".join(o["texts"])
        o["other"] = kv(other)
        return o

    def make_pool(self, ctx, pool, kind, path):
        w = pool.words()
        name = w[0] if w else ""
        o = self.new_obj("nat-pool-" + kind, name, "nat", kind, pool, path + "pool " + name)
        vals = []
        for ch in pool.find_all("address"):
            if ch.kids:
                vals += [pool_addr_text([k.name] + k.words()) for k in ch.kids]
            else:
                vals.append(pool_addr_text(ch.words()))
        f, _ = flatten_node(pool)
        pop_prefix(f, "address")
        o["desc"] = " ".join(f.pop("description", []))
        o.update(vt="address", val=";".join(v for v in vals if v), vals=[v for v in vals if v], other=kv(f.items()))
        return o

    # ---- resolution ------------------------------------------------------ #
    def zone_chain(self, ctx, zone):
        if zone is None:
            return [("global", "global")]
        return [("zone", zone)] + [("book", b) for b in ctx.attached.get(zone, [])] + [("global", "global")]

    def find_addr(self, ctx, name, chain):
        for key in chain:
            sc = ctx.scopes.get(key)
            if sc:
                for t in ("address", "address-set"):
                    o = sc["objs"][t].get(name)
                    if o:
                        return o
        return None

    def resolve_address(self, ctx, name, chain, rctx, path=()):
        if name in ANY_ADDR:
            return [(name, list(path))]
        o = self.find_addr(ctx, name, chain)
        if o is None:
            if looks_prefix(name):
                return [(name, list(path))]
            self.unres(ctx, "address", name, rctx)
            return [("unresolved:" + name, list(path) + [name])]
        if name in path:
            self.warn(ctx, rctx, "cycle in address-set '%s'" % name)
            return []
        self.used.add(id(o))
        via = list(path) + [name]
        if o["type"] == "address":
            if not o["val"]:
                self.warn(ctx, rctx, "address '%s' has no value" % name)
                return [(name, via)]
            return [(addr_text(o["vt"], o["val"]), via)]
        out = []
        for m in o["members"]:
            out += self.resolve_address(ctx, m, chain, rctx, tuple(via))
        return uniq(out)

    def resolve_app(self, ctx, name, rctx, path=()):
        if name == "any":
            return [("any", list(path))]
        o = ctx.apps["application"].get(name) or ctx.apps["application-set"].get(name)
        if o is None:
            if name.startswith("junos-"):
                return [(BUILTIN_APPS.get(name, name), list(path))]
            self.unres(ctx, "application", name, rctx)
            return [("unresolved:" + name, list(path) + [name])]
        if name in path:
            self.warn(ctx, rctx, "cycle in application-set '%s'" % name)
            return []
        self.used.add(id(o))
        via = list(path) + [name]
        if o["type"] == "application":
            return [(t, via) for t in o["texts"]] or [(name, via)]
        out = []
        for m in o["members"]:
            out += self.resolve_app(ctx, m, rctx, tuple(via))
        return uniq(out)

    def pool_addresses(self, ctx, kind, name, rctx):
        o = ctx.pools.get(kind, {}).get(name)
        if o is None:
            self.unres(ctx, "nat-pool", name, rctx)
            return [("unresolved:" + name, [name])]
        self.used.add(id(o))
        return [(v, [name]) for v in o["vals"]] or [(name, [name])]

    def compute_group_views(self):
        saved, self.used = self.used, set()
        for ctx in self.ctxs:
            for key, sc in ctx.scopes.items():
                chain = [key, ("global", "global")]
                for name, o in sc["objs"]["address-set"].items():
                    o["view"] = self.resolve_address(ctx, name, chain, "set %s" % name)
            for name, o in ctx.apps["application-set"].items():
                o["view"] = self.resolve_app(ctx, name, "set %s" % name)
        self.used = saved

    # ---- rule processing ------------------------------------------------- #
    def build_row(self, base, spec, f, resolved, notes, preset, node):
        rem = dict(f)
        row = dict(base)
        row.update(preset)
        for col, kind, key in spec:
            if kind == "preset":
                row.setdefault(col, "")
            elif kind == "list":
                row[col] = ";".join(rem.pop(key, []))
            elif kind == "res":
                row[col] = ";".join(resolved.get(key, []))
            else:
                row[col] = kv(pop_prefix(rem, key))
        for typ, path, text in notes:
            rem[typ + "@" + path] = [text] if text else []
        row["other_fields"] = kv(rem.items())
        row["source_line"] = node.line
        return row

    def process_policies(self, ctx):
        counters = {}
        for fz, tz, node, parent, path in ctx.policies:
            w = node.words()
            name = w[0] if w else ""
            scope_type, scope = ("global", "global") if fz is None else ("zone-pair", "%s>%s" % (fz, tz))
            counters[scope] = counters.get(scope, 0) + 1
            rctx = "%s/%s" % (scope, name)
            f, notes = flatten_node(node)

            action, opts = "", ""
            for a in ("permit", "deny", "reject"):
                if "then/" + a in f or any(k.startswith("then/%s/" % a) for k in f):
                    action = a
                    f.pop("then/" + a, None)
                    opts = kv(pop_prefix(f, "then/" + a))
                    break

            src_chain, dst_chain = self.zone_chain(ctx, fz), self.zone_chain(ctx, tz)
            resolved = {}
            for field, key, chain in (("source", "match/source-address", src_chain),
                                      ("destination", "match/destination-address", dst_chain)):
                out = []
                for v in f.get(key, []):
                    out += self.resolve_address(ctx, v, chain, rctx)
                resolved[field] = [t for t, _ in uniq(out)]
            for key, chain in (("match/source-address-excluded", src_chain),
                               ("match/destination-address-excluded", dst_chain)):
                for v in f.get(key, []):
                    self.resolve_address(ctx, v, chain, rctx)       # marks usage; value stays in other_fields
            out = []
            for v in f.get("match/application", []):
                out += self.resolve_app(ctx, v, rctx)
            resolved["application"] = [t for t, _ in uniq(out)]
            for s in f.get("scheduler-name", []):
                o = ctx.scheds.get(s)
                if o:
                    self.used.add(id(o))
                else:
                    self.unres(ctx, "scheduler", s, rctx)

            preset = {"annotation": node.annotation, "disabled": "yes" if (node.inactive or parent.inactive) else "",
                      "action": action, "action_options": opts,
                      "from_zone": fz or "", "to_zone": tz or ""}
            base = {"logical_system": ctx.name, "scope_type": scope_type, "scope": scope,
                    "rulebase": "security-policy", "rule_number": counters[scope], "name": name}
            row = self.build_row(base, POLICY_SPEC, f, resolved, notes, preset, node)
            row["config_path"] = path
            self.rule_rows.setdefault("security-policy", []).append(row)

            if self.expand:
                lists = [resolved[k] or [""] for k in ("source", "destination", "application")]
                total = len(lists[0]) * len(lists[1]) * len(lists[2])
                if total > self.max_expand:
                    self.warn(ctx, rctx, "rule expands to %d rows; truncated to %d" % (total, self.max_expand))
                for s, d, a in itertools.islice(itertools.product(*lists), self.max_expand):
                    r = {k: row.get(k, "") for k in EXPANDED_COLS}
                    r.update({"source": s, "destination": d, "application": a})
                    self.expanded.append(r)

    def process_nat(self, ctx):
        for kind, rs, path in ctx.nat:
            rw = rs.words()
            rsname = rw[0] if rw else ""
            rsdesc = rs.find("description")
            fnode, tnode = rs.find("from"), rs.find("to")
            for idx, rule in enumerate(rs.find_all("rule"), 1):
                w = rule.words()
                name = w[0] if w else ""
                rctx = "nat-%s/%s/%s" % (kind, rsname, name)
                f, notes = flatten_node(rule)
                gchain = [("global", "global")]

                def side(lit_key, name_key):
                    out = [(v, []) for v in f.get(lit_key, [])]
                    for v in f.get(name_key, []):
                        out += self.resolve_address(ctx, v, gchain, rctx)
                    return [t for t, _ in uniq(out)]

                resolved = {"source": side("match/source-address", "match/source-address-name"),
                            "destination": side("match/destination-address", "match/destination-address-name"),
                            "translated": [t for t, _ in uniq(self.nat_translated(ctx, rule, rctx))]}
                preset = {"rule_set_description": " ".join(rsdesc.words()) if rsdesc else "",
                          "annotation": "\n".join(x for x in (rs.annotation, rule.annotation) if x),
                          "disabled": "yes" if (rule.inactive or rs.inactive) else "",
                          "from": " ".join(fnode.words()) if fnode else "",
                          "to": " ".join(tnode.words()) if tnode else ""}
                base = {"logical_system": ctx.name, "scope_type": "rule-set", "scope": rsname,
                        "rulebase": "nat-" + kind, "rule_number": idx, "name": name}
                row = self.build_row(base, NAT_SPEC, f, resolved, notes, preset, rule)
                row["config_path"] = "%srule-set %s rule %s" % (path, rsname, name)
                self.rule_rows.setdefault("nat-" + kind, []).append(row)

    def nat_translated(self, ctx, rule, rctx):
        out, then = [], rule.find("then")
        for act in (then.kids if then else []):
            n = act.name
            if n in ("source-nat", "destination-nat"):
                k = "source" if n == "source-nat" else "destination"
                pn = act.find("pool")
                if pn is not None:
                    names = pn.words() + [c.name for c in pn.kids if not c.kids and not c.words()]
                    for p in names:
                        out += self.pool_addresses(ctx, k, p, rctx)
                if act.find("interface") is not None:
                    out.append(("interface", []))
                if act.find("off") is not None:
                    out.append(("off", []))
            elif n == "static-nat":
                pr = act.find("prefix")
                if pr is not None:
                    out += [(t, []) for t in pr.words() + [c.name for c in pr.kids if looks_prefix(c.name)]]
                pn = act.find("prefix-name")
                if pn is not None:
                    for v in pn.words():
                        out += self.resolve_address(ctx, v, [("global", "global")], rctx)
        return out

    # ---- objects --------------------------------------------------------- #
    def build_object_rows(self):
        def emit(ctx, o):
            view = o.get("view")
            referenced = "yes" if id(o) in self.used else "no"
            self.object_rows.append({
                "logical_system": ctx.name, "scope_type": o["scope_type"], "scope": o["scope"],
                "object_type": o["type"], "name": o["name"], "description": o["desc"],
                "annotation": o["annotation"], "disabled": "yes" if o["inactive"] else "",
                "value_type": o["vt"], "value": o["val"], "members": ";".join(o["members"]),
                "members_resolved": ";".join(t for t, _ in view) if view else "",
                "attached_zones": ";".join(o["attached"]), "referenced_by_rules": referenced,
                "other_fields": o["other"], "source_line": o["line"], "config_path": o["path"]})
            ident = {"logical_system": ctx.name, "scope_type": o["scope_type"], "scope": o["scope"],
                     "object_type": o["type"], "object": o["name"]}
            for m in o["members"]:
                self.member_rows.append(dict(ident, level="direct", member=m, via=""))
            for t, via in (view or []):
                self.member_rows.append(dict(ident, level="resolved", member=t, via=">".join(via)))

        for ctx in self.ctxs:
            for key, sc in ctx.scopes.items():
                for t in ("address", "address-set"):
                    for o in sc["objs"][t].values():
                        o["attached"] = sc["attached"] if sc["scope_type"] == "address-book" else []
                        emit(ctx, o)
            for t in ("application", "application-set"):
                for o in ctx.apps[t].values():
                    emit(ctx, o)
            for o in ctx.scheds.values():
                emit(ctx, o)
            for kind in ("source", "destination"):
                for o in ctx.pools[kind].values():
                    emit(ctx, o)


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def write_csv(path, fields, rows):
    """One physical line per record: embedded line breaks are replaced with CSV_NL_SEP."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: (_NL_RE.sub(CSV_NL_SEP[0], v) if isinstance(v, str) else v) for k, v in r.items()})


def make_run_dir(base):
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path, n = os.path.join(base, stamp), 1
    while True:
        try:
            os.makedirs(path)
            return path
        except FileExistsError:
            n += 1
            path = os.path.join(base, "%s_%d" % (stamp, n))


def write_outputs(p, run_dir):
    safe_host = re.sub(r"[^\w.-]", "_", str(p.meta["hostname"]))
    write_csv(os.path.join(run_dir, f"{safe_host}_objects.csv"), OBJECT_COLS, p.object_rows)
    write_csv(os.path.join(run_dir, f"{safe_host}_object_members.csv"), MEMBER_COLS, p.member_rows)
    for rb, rows in p.rule_rows.items():
        spec = POLICY_SPEC if rb == "security-policy" else NAT_SPEC
        write_csv(os.path.join(run_dir, f"{safe_host}_rules_{rb}.csv"),
                RULE_BASE_COLS + [c for c, _, _ in spec] + RULE_TAIL_COLS, rows)
    if p.expand:
        write_csv(os.path.join(run_dir, f"{safe_host}_rules_expanded.csv"), EXPANDED_COLS, p.expanded)
    write_csv(os.path.join(run_dir, f"{safe_host}_warnings.csv"), ["logical_system", "context", "message"], p.warnings)


def print_summary(p):
    print("Device        : %s (version %s)" % (p.meta["hostname"], p.meta["version"]))
    print("Input format  : %s" % ("show configuration | display set" if p.meta.get("format") == "set"
                                  else "show configuration (hierarchical)"))
    print("Contexts      : %s" % ", ".join(c.name or "(root)" for c in p.ctxs))
    counts = {}
    for r in p.object_rows:
        counts[r["object_type"]] = counts.get(r["object_type"], 0) + 1
    print("Objects       : %d  (%s)" % (len(p.object_rows), ", ".join("%s=%d" % x for x in counts.items())))
    for rb, rows in p.rule_rows.items():
        print("Rules         : %-24s %d" % (rb, len(rows)))
    print("Unresolved refs: %d   Syntax problems: %d   Warnings: %d" % (
        p.unresolved, p.syntax_errors, len(p.warnings)))


# --------------------------------------------------------------------------- #
SAMPLE = """admin@SRX01> show configuration
{primary:node0}
## Last changed: 2026-09-30 10:11:12 UTC
version 15.1X49-D100.6;
system {
    host-name SRX01;
}
security {
    address-book {
        global {
            address WEB1 10.1.1.5/32;
            address WEB2 10.1.1.6/32;
            address DMZ-NET 10.1.1.0/24;
            address PARTNER-RANGE range-address 203.0.113.10 to 203.0.113.20;
            address LOOKUP dns-name example.com;
            address WILD wildcard-address 10.0.0.0/255.0.255.0;
            address UNUSED-HOST 192.0.2.99/32;
            address WITH-DESC {
                description "Described host; with a semicolon";
                10.1.1.50/32;
            }
            address FQDN-OPT {
                dns-name intranet.example.com {
                    ipv4-only;
                }
            }
            address-set WEB-SERVERS {
                description "DMZ web tier";
                address WEB1;
                address WEB2;
            }
            address-set ALL-DMZ {
                address-set WEB-SERVERS;
                address DMZ-NET;
            }
            address-set PARTNERS {
                address PARTNER-RANGE;
                address LOOKUP;
            }
            address-set LOOP-A {
                address-set LOOP-B;
            }
            address-set LOOP-B {
                address-set LOOP-A;
            }
        }
        BOOK-DMZ {
            address DMZ-ONLY 172.16.5.0/24;
            attach {
                zone dmz;
            }
        }
    }
    zones {
        security-zone trust {
            address-book {
                address LAN 192.168.0.0/16;
                address MGMT 10.9.9.9/32;
            }
        }
        security-zone untrust;
        security-zone dmz;
    }
    policies {
        from-zone trust to-zone untrust {
            /* Ticket CHG0001234
               approved by NetSec */
            policy Allow-Web-Out {
                description "Outbound web";
                match {
                    source-address LAN;
                    destination-address any;
                    application [ junos-http junos-https ];
                }
                then {
                    permit;
                    log {
                        session-close;
                    }
                }
            }
            inactive: policy Mgmt-SSH {
                match {
                    source-address MGMT;
                    destination-address NOSUCH-OBJECT;
                    application junos-ssh;
                }
                then {
                    permit;
                }
                scheduler-name BUSINESS-HRS;
            }
        }
        from-zone untrust to-zone dmz {
            policy Allow-Partners-Web {
                description "Allow partners to web servers";
                match {
                    source-address PARTNERS;
                    destination-address [ WEB-SERVERS DMZ-ONLY ];
                    application WEB-APPS;
                }
                then {
                    permit {
                        application-services {
                            idp;
                        }
                    }
                    log {
                        session-init;
                        session-close;
                    }
                    count;
                }
            }
            policy Loop-Test {
                match {
                    source-address LOOP-A;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                }
            }
        }
        from-zone trust to-zone dmz {
            policy Trust-To-Dmz {
                match {
                    source-address LAN;
                    destination-address ALL-DMZ;
                    application ALL-SVCS;
                }
                then {
                    permit;
                }
            }
        }
        global {
            policy Global-Deny {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                    log {
                        session-init;
                    }
                }
            }
        }
    }
    nat {
        source {
            pool OUT-POOL {
                address {
                    198.51.100.50/32 to 198.51.100.55/32;
                    198.51.100.60/32;
                }
            }
            rule-set RS-OUT {
                description "Outbound PAT";
                from zone trust;
                to zone untrust;
                /* default PAT */
                rule PAT-ALL {
                    match {
                        source-address 192.168.0.0/16;
                        destination-address 0.0.0.0/0;
                    }
                    then {
                        source-nat {
                            pool {
                                OUT-POOL;
                            }
                        }
                    }
                }
                rule PAT-IFACE {
                    match {
                        source-address-name DMZ-NET;
                    }
                    then {
                        source-nat {
                            interface;
                        }
                    }
                }
            }
        }
        destination {
            pool WEB-DNAT {
                address 10.1.1.5/32 port 8080;
            }
            rule-set RS-IN {
                from zone untrust;
                rule DNAT-WEB {
                    match {
                        destination-address 198.51.100.10/32;
                        destination-port 80;
                        protocol tcp;
                    }
                    then {
                        destination-nat {
                            pool {
                                WEB-DNAT;
                            }
                        }
                    }
                }
            }
        }
        static {
            rule-set RS-STATIC {
                from zone untrust;
                rule STATIC-1 {
                    match {
                        destination-address 198.51.100.20/32;
                    }
                    then {
                        static-nat {
                            prefix {
                                10.1.1.6/32;
                            }
                        }
                    }
                }
            }
        }
    }
}
applications {
    application SVC-HTTPS-ALT {
        protocol tcp;
        source-port 1024-65535;
        destination-port 8443;
        description "Alt HTTPS";
    }
    application SVC-DNS {
        protocol udp;
        destination-port 53;
    }
    application SVC-WEB {
        term t1 protocol tcp destination-port 80;
        term t2 protocol tcp destination-port 8080-8090;
    }
    application PING-ANY {
        protocol icmp;
        icmp-type 8;
        icmp-code 0;
    }
    application-set WEB-APPS {
        application junos-http;
        application junos-https;
        application SVC-WEB;
    }
    application-set ALL-SVCS {
        application-set WEB-APPS;
        application SVC-DNS;
        application SVC-HTTPS-ALT;
    }
}
schedulers {
    scheduler BUSINESS-HRS {
        monday {
            start-time 08:00:00 stop-time 18:00:00;
        }
    }
}
logical-systems {
    LSYS1 {
        security {
            address-book {
                global {
                    address L1-NET 10.77.0.0/16;
                }
            }
            policies {
                from-zone a to-zone b {
                    policy P1 {
                        match {
                            source-address L1-NET;
                            destination-address any;
                            application any;
                        }
                        then {
                            permit;
                        }
                    }
                }
            }
        }
    }
}
admin@SRX01>
"""


SAMPLE_SET = """admin@SRX01> show configuration | display set
{primary:node0}
set version 15.1X49-D100.6
set system host-name SRX01
set security address-book global address WEB1 10.1.1.5/32
set security address-book global address WEB2 10.1.1.6/32
set security address-book global address DMZ-NET 10.1.1.0/24
set security address-book global address PARTNER-RANGE range-address 203.0.113.10 to 203.0.113.20
set security address-book global address LOOKUP dns-name example.com
set security address-book global address WILD wildcard-address 10.0.0.0/255.0.255.0
set security address-book global address UNUSED-HOST 192.0.2.99/32
set security address-book global address WITH-DESC description "Described host; with a semicolon"
set security address-book global address WITH-DESC 10.1.1.50/32
set security address-book global address FQDN-OPT dns-name intranet.example.com ipv4-only
set security address-book global address-set WEB-SERVERS description "DMZ web tier"
set security address-book global address-set WEB-SERVERS address WEB1
set security address-book global address-set WEB-SERVERS address WEB2
set security address-book global address-set ALL-DMZ address-set WEB-SERVERS
set security address-book global address-set ALL-DMZ address DMZ-NET
set security address-book global address-set PARTNERS address PARTNER-RANGE
set security address-book global address-set PARTNERS address LOOKUP
set security address-book global address-set LOOP-A address-set LOOP-B
set security address-book global address-set LOOP-B address-set LOOP-A
set security address-book BOOK-DMZ address DMZ-ONLY 172.16.5.0/24
set security address-book BOOK-DMZ attach zone dmz
set security zones security-zone trust address-book address LAN 192.168.0.0/16
set security zones security-zone trust address-book address MGMT 10.9.9.9/32
set security zones security-zone untrust
set security zones security-zone dmz
set security policies from-zone trust to-zone untrust policy Allow-Web-Out description "Outbound web"
set security policies from-zone trust to-zone untrust policy Allow-Web-Out match source-address LAN
set security policies from-zone trust to-zone untrust policy Allow-Web-Out match destination-address any
set security policies from-zone trust to-zone untrust policy Allow-Web-Out match application junos-http
set security policies from-zone trust to-zone untrust policy Allow-Web-Out match application junos-https
set security policies from-zone trust to-zone untrust policy Allow-Web-Out then permit
set security policies from-zone trust to-zone untrust policy Allow-Web-Out then log session-close
set security policies from-zone trust to-zone untrust policy Mgmt-SSH match source-address MGMT
set security policies from-zone trust to-zone untrust policy Mgmt-SSH match destination-address NOSUCH-OBJECT
set security policies from-zone trust to-zone untrust policy Mgmt-SSH match application junos-ssh
set security policies from-zone trust to-zone untrust policy Mgmt-SSH then permit
set security policies from-zone trust to-zone untrust policy Mgmt-SSH scheduler-name BUSINESS-HRS
set security policies from-zone untrust to-zone dmz policy Allow-Partners-Web description "Allow partners to web servers"
set security policies from-zone untrust to-zone dmz policy Allow-Partners-Web match source-address PARTNERS
set security policies from-zone untrust to-zone dmz policy Allow-Partners-Web match destination-address WEB-SERVERS
set security policies from-zone untrust to-zone dmz policy Allow-Partners-Web match destination-address DMZ-ONLY
set security policies from-zone untrust to-zone dmz policy Allow-Partners-Web match application WEB-APPS
set security policies from-zone untrust to-zone dmz policy Allow-Partners-Web then permit application-services idp
set security policies from-zone untrust to-zone dmz policy Allow-Partners-Web then log session-init
set security policies from-zone untrust to-zone dmz policy Allow-Partners-Web then log session-close
set security policies from-zone untrust to-zone dmz policy Allow-Partners-Web then count
set security policies from-zone untrust to-zone dmz policy Loop-Test match source-address LOOP-A
set security policies from-zone untrust to-zone dmz policy Loop-Test match destination-address any
set security policies from-zone untrust to-zone dmz policy Loop-Test match application any
set security policies from-zone untrust to-zone dmz policy Loop-Test then deny
set security policies from-zone trust to-zone dmz policy Trust-To-Dmz match source-address LAN
set security policies from-zone trust to-zone dmz policy Trust-To-Dmz match destination-address ALL-DMZ
set security policies from-zone trust to-zone dmz policy Trust-To-Dmz match application ALL-SVCS
set security policies from-zone trust to-zone dmz policy Trust-To-Dmz then permit
set security policies global policy Global-Deny match source-address any
set security policies global policy Global-Deny match destination-address any
set security policies global policy Global-Deny match application any
set security policies global policy Global-Deny then deny
set security policies global policy Global-Deny then log session-init
set security nat source pool OUT-POOL address 198.51.100.50/32 to 198.51.100.55/32
set security nat source pool OUT-POOL address 198.51.100.60/32
set security nat source rule-set RS-OUT description "Outbound PAT"
set security nat source rule-set RS-OUT from zone trust
set security nat source rule-set RS-OUT to zone untrust
set security nat source rule-set RS-OUT rule PAT-ALL match source-address 192.168.0.0/16
set security nat source rule-set RS-OUT rule PAT-ALL match destination-address 0.0.0.0/0
set security nat source rule-set RS-OUT rule PAT-ALL then source-nat pool OUT-POOL
set security nat source rule-set RS-OUT rule PAT-IFACE match source-address-name DMZ-NET
set security nat source rule-set RS-OUT rule PAT-IFACE then source-nat interface
set security nat destination pool WEB-DNAT address 10.1.1.5/32 port 8080
set security nat destination rule-set RS-IN from zone untrust
set security nat destination rule-set RS-IN rule DNAT-WEB match destination-address 198.51.100.10/32
set security nat destination rule-set RS-IN rule DNAT-WEB match destination-port 80
set security nat destination rule-set RS-IN rule DNAT-WEB match protocol tcp
set security nat destination rule-set RS-IN rule DNAT-WEB then destination-nat pool WEB-DNAT
set security nat static rule-set RS-STATIC from zone untrust
set security nat static rule-set RS-STATIC rule STATIC-1 match destination-address 198.51.100.20/32
set security nat static rule-set RS-STATIC rule STATIC-1 then static-nat prefix 10.1.1.6/32
set applications application SVC-HTTPS-ALT protocol tcp
set applications application SVC-HTTPS-ALT source-port 1024-65535
set applications application SVC-HTTPS-ALT destination-port 8443
set applications application SVC-HTTPS-ALT description "Alt HTTPS"
set applications application SVC-DNS protocol udp
set applications application SVC-DNS destination-port 53
set applications application SVC-WEB term t1 protocol tcp destination-port 80
set applications application SVC-WEB term t2 protocol tcp destination-port 8080-8090
set applications application PING-ANY protocol icmp
set applications application PING-ANY icmp-type 8
set applications application PING-ANY icmp-code 0
set applications application-set WEB-APPS application junos-http
set applications application-set WEB-APPS application junos-https
set applications application-set WEB-APPS application SVC-WEB
set applications application-set ALL-SVCS application-set WEB-APPS
set applications application-set ALL-SVCS application SVC-DNS
set applications application-set ALL-SVCS application SVC-HTTPS-ALT
set schedulers scheduler BUSINESS-HRS monday start-time 08:00:00 stop-time 18:00:00
set logical-systems LSYS1 security address-book global address L1-NET 10.77.0.0/16
set logical-systems LSYS1 security policies from-zone a to-zone b policy P1 match source-address L1-NET
set logical-systems LSYS1 security policies from-zone a to-zone b policy P1 match destination-address any
set logical-systems LSYS1 security policies from-zone a to-zone b policy P1 match application any
set logical-systems LSYS1 security policies from-zone a to-zone b policy P1 then permit
deactivate security policies from-zone trust to-zone untrust policy Mgmt-SSH
admin@SRX01> 
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description="Parse Juniper SRX 'show configuration' output to CSV")
    ap.add_argument("config", nargs="?", help="path to the 'show configuration' text file")
    ap.add_argument("-o", "--outdir", default="output",
                    help="base output folder (default 'output'); each run writes to "
                         "<outdir>/YYYY-MM-DD_HH-MM-SS")
    ap.add_argument("--expand", action="store_true",
                    help="also write rules_expanded.csv (security policies, one row per src x dst x application)")
    ap.add_argument("--max-expand", type=int, default=100000, help="max expanded rows per rule")
    ap.add_argument("--strict", action="store_true", help="exit 1 on unresolved references or syntax problems")
    ap.add_argument("--csv-nl-sep", default=" | ",
                    help="string replacing line breaks inside CSV fields (default ' | ')")
    ap.add_argument("--input-format", choices=("auto", "hierarchical", "set"), default="auto",
                    help="input format: 'show configuration' (hierarchical) or '| display set' (set); "
                         "default auto-detects")
    ap.add_argument("--selftest", action="store_true",
                    help="run on the embedded sample config (the set-format sample with --input-format set)")
    args = ap.parse_args(argv)
    CSV_NL_SEP[0] = args.csv_nl_sep

    if args.selftest:
        text, args.expand = (SAMPLE_SET if args.input_format == "set" else SAMPLE), True
    elif args.config:
        try:
            with open(args.config, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            print("Cannot read %s: %s" % (args.config, e), file=sys.stderr)
            return 2
    else:
        ap.error("config file required (or --selftest)")

    p = SrxParser(expand=args.expand, max_expand=args.max_expand)
    try:
        p.parse(text, args.input_format)
    except ValueError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 2
    run_dir = make_run_dir(args.outdir)
    write_outputs(p, run_dir)
    print_summary(p)
    print("Output written to: %s" % os.path.abspath(run_dir))
    if args.strict and (p.unresolved or p.syntax_errors):
        print("STRICT: unresolved references or syntax problems found; see warnings.csv.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
