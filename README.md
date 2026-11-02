# srx_parse.py

Extracts the **objects** and **rulebases** from Juniper SRX (Junos) `show configuration` output into CSV files,
preserving policy order, descriptions, annotations and every other attribute. Address-sets and application-sets are
resolved so each policy shows the actual addresses and applications it matches.

- Python 3.8+, **standard library only**, no install step
- Reads one text file, either `show configuration` (hierarchical, curly-brace format) or `show configuration | display set`
  (one `set ...` command per line); the format is detected automatically. Writes a new timestamped folder per run
- Does not connect to any device and does not modify anything

Companion scripts with the same output conventions: `asa_parse.py` (Cisco ASA) and `pan_parse.py` (Palo Alto).

---

## Contents

1. [Quick start](#1-quick-start)
2. [Input](#2-input)
3. [Command-line options](#3-command-line-options)
4. [What is parsed](#4-what-is-parsed)
5. [Output folder layout](#5-output-folder-layout)
6. [CSV output reference](#6-csv-output-reference)
7. [Behaviour notes](#7-behaviour-notes)
8. [Warnings and troubleshooting](#8-warnings-and-troubleshooting)
9. [Verifying the results](#9-verifying-the-results)
10. [Comparing runs](#10-comparing-runs)
11. [Limitations](#11-limitations)

---

## 1. Quick start

```bash
# Smoke test using the built-in sample config (no input file needed)
python srx_parse.py --selftest

# Real run (the format is detected automatically)
python srx_parse.py show-configuration.txt
python srx_parse.py show-configuration-set.txt

# Smoke test of the display-set route
python srx_parse.py --selftest --input-format set

# Real run with the one-row-per-source/destination/application CSV, failing on unresolved references
python srx_parse.py show-configuration.txt --expand --strict
```

Each run creates `output/<YYYY-MM-DD_HH-MM-SS>/` in the current working directory and prints its path.
Add `output/` to your `.gitignore`.

On Windows use `python` or `py`; all examples work unchanged in PowerShell or cmd.

---

## 2. Input

| Item | Detail |
|---|---|
| File | Plain-text output of **either** `show configuration` (hierarchical, `stanza { ... }`) **or** `show configuration \| display set` (`set security ...` lines). The format is detected automatically; override with `--input-format` |
| Encoding | UTF-8; undecodable bytes are replaced rather than aborting. CRLF or LF line endings both work |
| Ignored | CLI prompt lines (`user@host>`), cluster banners (`{primary:node0}`), `---(more)---`, `[edit]` lines, and `#` / `##` comment lines such as `## Last changed:` |
| Not accepted | `\| display json` and `\| display xml`. The script exits with code 2 and explains why |

### Getting a clean config file

```
set cli screen-length 0
show configuration                       # hierarchical format
show configuration | display set         # set format
```

or add `| no-more`. If you capture from a terminal logger, make sure long lines are not wrapped. Either format gives the
same CSV content (see [Set-format notes](#set-format-notes)).

`| display inheritance` output contains extra `##` comments and expanded group content; it should parse (comments are
ignored) but is not tested.

The script does not read passwords, keys or other secrets. The file does contain encrypted password hashes and SNMP
strings, so remove or protect them before sharing it.

### Contexts

The root configuration, every `logical-systems` entry and every `tenants` entry are parsed as independent contexts,
each with its own address books, applications, policies and NAT. The `logical_system` column in every output is blank
for the root, the logical-system name for logical systems, and `tenant:<name>` for tenants.

---

## 3. Command-line options

```
python srx_parse.py [config] [-o OUTDIR] [--expand] [--max-expand N] [--strict]
                    [--csv-nl-sep STR] [--input-format auto|hierarchical|set] [--selftest]
```

| Option | Default | Description |
|---|---|---|
| `config` | (required unless `--selftest`) | Path to the `show configuration` or `show configuration \| display set` text file |
| `-o`, `--outdir` | `output` | **Base** folder. Each run writes to `<outdir>/<timestamp>/` |
| `--expand` | off | Also write `rules_expanded.csv` (security policies only) |
| `--max-expand` | `100000` | Maximum expanded rows per policy. Larger policies are truncated and a warning is raised |
| `--strict` | off | Exit code 1 on unresolved references or syntax problems |
| `--csv-nl-sep` | `" \| "` | Replacement for line breaks inside CSV fields (for example multi-line annotations) |
| `--input-format` | `auto` | `auto`, `hierarchical` or `set`. Auto-detection looks at whether the file is mostly `set` lines or curly-brace statements |
| `--selftest` | off | Run against the embedded sample config (the display-set sample with `--input-format set`); forces `--expand` |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed (warnings may still exist; see `warnings.csv`) |
| 1 | `--strict` was set and there were unresolved references or syntax problems (unbalanced braces etc.) |
| 2 | File unreadable, no configuration found, no `security` / `applications` stanzas (wrong format), or bad arguments |

Cycles and duplicate names are reported as warnings but do **not** trigger `--strict` on their own.

---

## 4. What is parsed

### Objects

| Config construct | Captured as |
|---|---|
| `security address-book global` | Addresses and address-sets, scope `global` |
| `security address-book <NAME>` (with `attach { zone ...; }`) | Addresses and address-sets, scope = book name, `attached_zones` filled |
| `security zones security-zone <Z> address-book` | Addresses and address-sets, scope = zone name |
| `address <name> ...` | `ip-prefix`, `range-address`, `dns-name` (including the block form with options), `wildcard-address`; both the one-line form and the block form with a `description` |
| `address-set <name>` | Members (`address` and `address-set`, in config order), description |
| `applications application <name>` | Protocol, source/destination port, ICMP type/code, `term` entries (one-line and block forms), other attributes |
| `applications application-set <name>` | Members (`application` and `application-set`) |
| `schedulers scheduler <name>` | All attributes |
| `security nat source pool` / `security nat destination pool` | Addresses (ranges and ports included), other attributes |

### Rulebases

| Config construct | Output file |
|---|---|
| `security policies from-zone A to-zone B policy ...` and `security policies global policy ...` | `<hostname>_rules_security-policy.csv` |
| `security nat source rule-set ... rule ...` | `<hostname>_rules_nat-source.csv` |
| `security nat destination rule-set ... rule ...` | `<hostname>_rules_nat-destination.csv` |
| `security nat static rule-set ... rule ...` | `<hostname>_rules_nat-static.csv` |

Every attribute of every policy and NAT rule is kept. Attributes without a dedicated column are written to
`other_fields` as `path=value; path=value` (flags with no value appear as just the path), so nothing is dropped.

### Metadata

- **`description`** on policies, NAT rules, NAT rule-sets, objects.
- **Annotations** (`/* text */` comments placed before a statement) are kept in an `annotation` column. Multi-line
  annotations are joined with `--csv-nl-sep`. `display set` output does not contain annotations, so this column is blank
  for set input.
- **`inactive:`** statements (hierarchical) and **`deactivate`** lines (set format) are kept and flagged in `disabled` (`yes`).
- **Order:** policies appear in configuration order; `rule_number` is the position within the zone pair.

### Reference resolution

| Reference | Result |
|---|---|
| Address | `10.1.1.5/32`, `203.0.113.10-203.0.113.20`, `fqdn:example.com`, `wildcard:10.0.0.0/255.0.255.0` |
| Address-set | Members expanded recursively and de-duplicated |
| `any`, `any-ipv4`, `any-ipv6` | Kept as written |
| Literal prefix (NAT matches) | Kept as written |
| Application | `tcp/80`, `tcp/8080-8090`, `tcp/8443 (src 1024-65535)`, `icmp/8 code 0`; one entry per `term` |
| Application-set | Members expanded recursively |
| Predefined `junos-*` application | Translated if in the built-in table (for example `junos-http` -> `tcp/80`); otherwise kept by name, **no warning** |
| NAT pool (`pool NAME;` or `pool { NAME; }`) | The pool's addresses (and port, for destination pools) |
| NAT `source-nat interface` / `off` | `interface` / `off` |
| NAT `static-nat prefix` / `prefix-name` | The prefix, or the resolved address |
| Anything else not found | `unresolved:<name>` and a warning |

**Where addresses are looked up.** For a policy, the source address is searched in the from-zone's address book
(`security-zone`), then any named address books attached to that zone, then the global address book. The
destination uses the same order for the to-zone. Global policies and NAT `*-address-name` references use the global
address book. The built-in `junos-*` applications are available everywhere.

---

## 5. Output folder layout

```
output/
  2026-10-03_09-36-16/
    <hostname>_objects.csv
    <hostname>_object_members.csv
    <hostname>_rules_security-policy.csv
    <hostname>_rules_nat-source.csv        (only if present in the config)
    <hostname>_rules_nat-destination.csv   (only if present)
    <hostname>_rules_nat-static.csv        (only if present)
    <hostname>_rules_expanded.csv          (only with --expand)
    <hostname>_warnings.csv
```

- Folder names use `YYYY-MM-DD_HH-MM-SS` in **local time**, with no characters that are illegal on Windows.
- If two runs start in the same second, the second folder gets `_2`, then `_3`, and so on. Nothing is overwritten.
- The console summary shows the hostname, Junos version, contexts, object counts by type, rule counts per rulebase, and
  the unresolved / syntax / warning counts, then the full path of the run folder.
- Device hostname is sanitised with non file/folder safe characters being replaced with an `_`.

All CSVs are UTF-8 with a header row, `\n` line endings and **one physical line per record**. Line breaks inside a value
are replaced with `--csv-nl-sep` (default ` | `). Multi-value cells are joined with `;`.

---

## 6. CSV output reference

All output filenames are prefixed with a file/folder safe version of the device hostname. 

### `objects.csv`

`logical_system, scope_type, scope, object_type, name, description, annotation, disabled, value_type, value, members, members_resolved, attached_zones, referenced_by_rules, other_fields, source_line, config_path`

| Column | Meaning |
|---|---|
| `scope_type`, `scope` | `global`/`global`, `address-book`/`<book>`, `zone`/`<zone>`, `applications`, `schedulers`, or `nat`/`source`\|`destination` |
| `object_type` | `address`, `address-set`, `application`, `application-set`, `scheduler`, `nat-pool-source`, `nat-pool-destination` |
| `description`, `annotation` | The `description` statement and any `/* */` annotation |
| `disabled` | `yes` if the object's own statement is `inactive:` |
| `value_type`, `value` | Address: `ip-prefix`, `range-address`, `dns-name` or `wildcard-address` and its value (ranges as `a-b`). Application: protocol(s) and the port text (`tcp/80; tcp/8080-8090`). NAT pool: `address` and the address list. Scheduler: all attributes |
| `members` | Direct members of a set, in config order |
| `members_resolved` | Fully flattened members (sets only) |
| `attached_zones` | Zones a named address book is attached to |
| `referenced_by_rules` | `yes` if reachable from any policy or NAT rule (see [behaviour notes](#7-behaviour-notes)), otherwise `no` |
| `other_fields` | Attributes not given their own column |
| `source_line`, `config_path` | Line number in the input file and the statement's location in the hierarchy |

### `object_members.csv`

`logical_system, scope_type, scope, object_type, object, level, member, via`

One row per set member. `level` is `direct` or `resolved`; `via` shows the chain of nested sets for resolved rows
(for example `ALL-DMZ>WEB-SERVERS`).

### `rules_security-policy.csv`

`logical_system, scope_type, scope, rulebase, rule_number, name, description, annotation, disabled, action, action_options, from_zone, to_zone, source, source_resolved, destination, destination_resolved, application, application_resolved, source_identity, dynamic_application, url_category, log, count, scheduler_name, other_fields, source_line, config_path`

| Column | Meaning |
|---|---|
| `scope_type`, `scope` | `zone-pair` and `trust>untrust`, or `global` and `global` |
| `rulebase` | `security-policy` |
| `rule_number` | 1-based position within the zone pair (or within global) |
| `name` | Policy name |
| `disabled` | `yes` if the policy, or its enclosing `from-zone` block, is `inactive:` |
| `action` | `permit`, `deny` or `reject` |
| `action_options` | Anything under the action, for example `application-services/idp` or tunnel options |
| `from_zone`, `to_zone` | Blank for global policies |
| `source`, `destination`, `application` | As written (names, `any`, bracket lists flattened) |
| `*_resolved` | Flattened contents |
| `source_identity`, `dynamic_application`, `url_category` | As written; **not** resolved |
| `log` | The `then log` options (for example `session-init; session-close`) |
| `count` | `count` if the policy has a count statement, with any options |
| `scheduler_name` | The scheduler name |

### `rules_nat-source.csv`, `rules_nat-destination.csv`, `rules_nat-static.csv`

`logical_system, scope_type, scope, rulebase, rule_number, name, description, rule_set_description, annotation, disabled, from, to, source_address, source_address_name, source_resolved, destination_address, destination_address_name, destination_resolved, source_port, destination_port, protocol, application, translation, translated_resolved, other_fields, source_line, config_path`

| Column | Meaning |
|---|---|
| `scope_type`, `scope` | `rule-set` and the rule-set name |
| `rulebase` | `nat-source`, `nat-destination` or `nat-static` |
| `rule_number` | Position within the rule-set |
| `rule_set_description` | The rule-set's description |
| `annotation` | The rule-set's annotation and the rule's annotation, joined |
| `disabled` | `yes` if the rule or its rule-set is `inactive:` |
| `from`, `to` | For example `zone trust`, `interface ge-0/0/0.0`, `routing-instance X` |
| `source_address`, `destination_address` | Literal prefixes from `match` |
| `source_address_name`, `destination_address_name` | Address-book names from `match` |
| `source_resolved`, `destination_resolved` | Literals plus resolved address names |
| `translation` | Everything under `then`, as `source-nat/pool/OUT-POOL` etc. |
| `translated_resolved` | What the rule translates to: pool addresses, `interface`, `off`, or static prefixes |

### `rules_expanded.csv` (with `--expand`)

`logical_system, scope_type, scope, rulebase, rule_number, name, action, disabled, from_zone, to_zone, source, destination, application, description`

Security policies only. One row per source x destination x application combination. `rule_number` repeats across the
rows of the same policy. `--max-expand` caps the rows per policy.

### `warnings.csv`

`logical_system, context, message`, where `context` is `<zone-pair or rule-set>/<name>` for rule problems, `set <name>`
for set problems, and `syntax` for parsing problems.

---

## 7. Behaviour notes

### Rule order
- Policies are numbered within each zone pair (and within global) in configuration order.
- Effective evaluation order on the device is zone-pair policies first, then global policies. The script lists them in
  config order and does not merge them into one sequence.

### `inactive:` and annotations
- An `inactive:` policy or NAT rule is **kept** and flagged `disabled=yes`; it is still resolved and still counts in `rule_number`.
- Inactive status is taken from the statement itself and its immediate container (`from-zone` for policies, `rule-set` for NAT). It is not
  propagated from higher levels such as an inactive `policies` or `security` stanza.
- Annotations on nested statements inside a policy are written to `other_fields` as `annotation@<path>=<text>`;
  nested `inactive:` statements appear as `inactive@<path>`.

### Set-format notes
A flat `set` line does not say where one statement ends and its sub-statements begin, so for `display set` input the script
rebuilds the same hierarchy that `show configuration` prints before parsing, using the keyword structure of the stanzas it
reads (address books, zones, policies, NAT, applications, schedulers, logical systems and tenants). Anything else in the file
(`interfaces`, `protocols`, `groups`, `routing-options`, IKE, ...) is ignored.

- **Same results.** For the same configuration both formats produce identical CSV content, apart from `source_line` (which is the
  line number in whichever file you gave) and `annotation` (not present in set output). This was verified on a sample by
  converting one configuration to both formats.
- **`deactivate`** lines are applied after all `set` lines, so their position in the file doesn't matter. A `deactivate` that points
  at a statement not present in the set lines is reported as a syntax problem (and fails `--strict`).
- **Order** of group members, addresses and applications follows the order of the `set` lines, which is configuration order in
  `display set` output. Re-sorting or shuffling the lines changes list order and rule numbers.
- **Not supported in set format:** `annotate` lines are accepted if present, but Junos does not print annotations in `display set`.
  Statements hidden by view permissions appear as `ACCESS-DENIED` in Junos output and are not parsed.

### `referenced_by_rules`
An object is `yes` when it is reached while resolving a policy or NAT rule (addresses and sets, applications and sets, schedulers,
NAT pools). `source-address-excluded` / `destination-address-excluded` references also count. Objects used only elsewhere (VPN, IDP,
other stanzas) show `no`. Treat it as "candidate unused", not proof.

### Set resolution
- Nested sets are flattened to any depth and de-duplicated, first occurrence kept.
- Circular references are detected, reported and do not loop.
- Members keep the order they have in the configuration.

### Values with special characters
Quoted strings (descriptions containing `;`, `{`, `}` or `#`) are handled correctly.

---

## 8. Warnings and troubleshooting

| Message (in `warnings.csv`) | Meaning / action |
|---|---|
| `unresolved address reference 'X'` | A policy or set names an address that isn't in the zone, attached-book or global address book it is searched in. Check which zone the policy belongs to |
| `unresolved application reference 'X'` | A non-`junos-` application name isn't defined under `applications` |
| `unresolved nat-pool reference 'X'` | A NAT rule uses a pool that isn't defined in the same NAT type |
| `unresolved scheduler reference 'X'` | A policy refers to a scheduler that isn't defined |
| `cycle in address-set / application-set 'X'` | Circular nesting; the loop is broken |
| `duplicate <type> name (later definition wins)` | Two objects of the same type in the same scope share a name |
| `address 'X' has no value` | An address statement the script couldn't interpret |
| `unmatched '}'` / `N unclosed '{' at end of file` / `statement without terminator` | Syntax problems, usually a truncated or mangled capture |
| `rule expands to N rows; truncated to M` | The expanded output hit `--max-expand` |

| Symptom | Likely cause |
|---|---|
| `ERROR: no security/applications stanzas found ...` | The file is JSON/XML output, isn't a Junos config, or was parsed in the wrong format (try `--input-format hierarchical` or `set`) |
| Unexpected values from a `display set` file | Run the same config in hierarchical format and compare. The set converter relies on keyword structure; send the offending `set` lines if a statement is mis-grouped |
| Everything seems empty | The config has a different top-level structure (for example only `groups`); check that policies and address books are present in the output you captured |
| Unresolved addresses for policies that work on the device | The address lives in a book attached to a different zone, or comes from a group (`apply-groups`). Use `| display inheritance` if the object is group-inherited |
| Syntax warnings at the end of the file | The capture was cut off, or a terminal paging artefact was included |

---

## 9. Verifying the results

The script does not compare itself with the device, so on first use:

1. **Policy counts.** Compare the console summary with the device (`show security policies` lists policies per zone pair) or
   with `grep -c "^ *\(inactive: \)\?policy " show-configuration.txt`.
2. **Spot-check resolution.** Run `show security policies detail` on the SRX; it prints the resolved addresses and
   applications for each policy. Compare several, including ones using nested sets, with the `*_resolved` columns.
3. **Review `warnings.csv`** and any `unresolved:` values before relying on the output.
4. Use `--strict` in scripted runs so problems fail loudly.

### Loading the output

```python
import csv

rules = list(csv.DictReader(open("output/2026-10-03_09-36-16/rules_security-policy.csv", encoding="utf-8")))
for r in rules:
    print(r["scope"], r["rule_number"], r["name"], r["action"], r["source_resolved"], r["application_resolved"])
```

In Excel, import the CSVs as UTF-8.

---

## 10. Comparing runs

Each run is kept in its own folder, so two runs (for example before and after a change window) can be compared directly:

```bash
# Linux / macOS
diff -r output/2026-10-03_09-36-16 output/2026-10-10_09-00-02

# Windows PowerShell (or any platform with git)
git diff --no-index output/2026-10-03_09-36-16 output/2026-10-10_09-00-02
```

- Output files contain no timestamps, so identical configs produce identical CSVs.
- `rule_number` shifts for every policy below an inserted or deleted one, and `source_line` shifts for most rows after any
  edit (and differs between hierarchical and set captures of the same configuration). To match rules between runs, join on `logical_system, scope, rulebase, name`.
- Compare the `*_resolved` columns if you only care about content changes.

Suggested `.gitignore` entry:

```
output/
```

---

## 11. Limitations

- **Not parsed:** `groups` / `apply-groups` content (use `| display inheritance` if you rely on inherited config),
  `default-policy`, zones and interfaces, security profiles (IDP, UTM), VPN, `proxy-arp`, and everything outside address
  books, applications, schedulers, policies and NAT.
- **Predefined applications:** only a subset of `junos-*` applications is translated to protocol/port. Others are kept by name.
  Dynamic applications (`junos:...`) are listed in `dynamic_application` and are not resolved.
- **Policy-level identity and URL fields** (`source_identity`, `url_category`) are copied as written, not resolved.
- **Inactive status** is not inherited from enclosing stanzas (see above).
- **Set format:** the converter knows the keyword structure of the stanzas listed above. A statement with an unusual layout may be
  grouped differently from the hierarchical output; anything not understood ends up in `other_fields` rather than being dropped.
  Annotations are not available in `display set` output.
- **Layout assumptions:** the display formats for NAT pools (`pool { NAME; }` and `address IP port N;`) and address entries with
  descriptions are handled in both common forms, but unusual Junos versions may print other variants. Anything not understood goes to
  `other_fields` or `warnings.csv`; it is not silently dropped.
- **Effective order** across zone-pair and global policies is not computed.
- **`referenced_by_rules`** only considers policies and NAT rules.
- No automated test suite beyond `--selftest`, and no formal schema for the CSVs.
