# PortSwigger SQLi Lab Seeds

Use these as PortSwigger Academy-inspired lane prompts after a likely SQL-backed
surface exists. They are not lab solutions, not an exhaustive methodology, and
not permission to exceed scope.

**Mechanism.** The query is assembled as a string and handed to a parser. A bug
exists when the quoting, comment, or escape handling the defense models differs
from what the database actually parses. Each family below is a bet about that
difference: find which clause the input lands in, then which dialect is parsing
it, and the payload follows from the pair.

## Official References

- SQL injection topic: https://portswigger.net/web-security/sql-injection
- SQL injection labs index: https://portswigger.net/web-security/sql-injection#labs
- SQL injection cheat sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
- All Web Security Academy labs: https://portswigger.net/web-security/all-labs

## Detection Lanes

Each lane is a paired probe: a control that should behave normally and a test
that should differ only if input reaches the parser.

| Lane | Control | Test | Reads as injection when |
|---|---|---|---|
| single-quote parser anomaly | `value` | `value'` | the quote alone changes status, body, or error |
| escaped quote control | `value'` | `value''` | the doubled quote restores normal behavior |
| numeric expression | `id=2` | `id=3-1` | the server resolves the arithmetic |
| boolean pair | `' AND '1'='1` | `' AND '1'='2` | the two differ from each other |
| equivalent-value pair | `' AND 1=1-- ` | `' AND 1=2-- ` | same, in a comment-terminated form |
| time delay pair | a zero-delay condition | a true-condition delay | the delay tracks the condition over repeats |
| OAST pair | a benign hostname | a controlled collector hostname | the collector sees a DB-originated lookup |

Prefer a restoring form (`''`, `'||'`, a closing comment) before a breaking
one: restoring the original value proves parsing without leaving a broken query
in logs.

## Query Context Lanes

- `WHERE` clause string
- `WHERE` clause number
- `ORDER BY` column or direction
- table or column name selection
- `INSERT` value
- `UPDATE` value
- `UPDATE` or `DELETE` predicate
- login credential predicate
- JSON/XML value decoded before SQL
- stored second-order value

## PortSwigger Lab Family Prompts

- hidden data: can a filter expose records normally hidden by application logic?
- application-logic subversion: can a credential or workflow check be altered without destructive impact?
- UNION result shaping: can column count and printable column type be inferred safely?
- database fingerprinting: can version/type be inferred with minimal benign output?
- table/column discovery: is metadata exposure possible without dumping sensitive rows?
- blind conditional response: does the page, redirect, status, or content length change for true vs false?
- blind conditional error: can a controlled condition trigger an error only when true?
- verbose error leakage: does type casting or parser behavior reveal query data or database type?
- blind time delay: can a delay be tied to a true condition with repeated samples?
- OAST SQLi: can the database trigger a controlled external interaction?
- second-order SQLi: does saved input become unsafe when rendered, searched, exported, or used later?

## Dialect Seeds

A payload that works on one dialect and not another **is** the fingerprint, so
run these as discriminators rather than as a list to exhaust. Oracle needs a
`FROM` clause (`FROM dual`) on every `SELECT`; MySQL needs whitespace after
`-- `. Those two quirks alone separate most stacks.

| Primitive | PostgreSQL | MySQL | MSSQL | Oracle | SQLite |
|---|---|---|---|---|---|
| line comment | `--`, `/**/` | `-- ` (trailing space), `#` | `--`, `/**/` | `--`, `/**/` | `--`, `/**/` |
| concatenate | `'a'\|\|'b'` | `CONCAT('a','b')`, `'a' 'b'` | `'a'+'b'` | `'a'\|\|'b'` | `'a'\|\|'b'` |
| substring | `SUBSTRING(s FROM 1 FOR 1)` | `SUBSTRING(s,1,1)` | `SUBSTRING(s,1,1)` | `SUBSTR(s,1,1)` | `SUBSTR(s,1,1)` |
| version | `version()` | `@@version` | `@@version` | `banner FROM v$version` | `sqlite_version()` |
| metadata | `information_schema.tables` | `information_schema.tables` | `information_schema.tables` | `all_tables`, `all_tab_columns` | `sqlite_master` |
| conditional | `CASE WHEN c THEN a ELSE b END` | `IF(c,a,b)` | `CASE WHEN ... END` | `CASE WHEN ... END` | `CASE WHEN ... END` |
| conditional error | `1/0`, `CAST('x' AS int)` | — | `1/0` | `TO_CHAR(1/0)` | — |
| time delay | `pg_sleep(5)` | `SLEEP(5)` | `WAITFOR DELAY '0:0:5'` | `dbms_pipe.receive_message(('a'),5)` | none |
| stacked queries | `;` supported | usually blocked by the driver | `;` supported | not supported | driver-dependent |
| OAST lookup | `dblink`/`COPY` (privileged) | `LOAD_FILE('\\\\host\\a')` (Windows) | `xp_dirtree '\\host\a'` | `UTL_INADDR`, `EXTRACTVALUE` XXE | none |

SQLite and MySQL have no reliable delay primitive in a default configuration,
so a missing delay is a statement about the dialect, not about injectability.
Fall back to a boolean or error lane before concluding the vector is inert.

## Safe Proof Ideas

- paired true/false response delta
- bounded timing delta with repeated control samples
- harmless database fingerprint string
- column-count or printable-column control without sensitive extraction
- own-account hidden-data exposure
- auth check bypass only against an owned disposable account
- controlled OAST callback without data exfiltration
- second-order trigger in an owned resource
