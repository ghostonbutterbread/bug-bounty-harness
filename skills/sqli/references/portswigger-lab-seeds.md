# PortSwigger SQLi Lab Seeds

Use these as PortSwigger Academy-inspired lane prompts after a likely SQL-backed
surface exists. They are not lab solutions, not an exhaustive methodology, and
not permission to exceed scope.

## Official References

- SQL injection topic: https://portswigger.net/web-security/sql-injection
- SQL injection labs index: https://portswigger.net/web-security/sql-injection#labs
- SQL injection cheat sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
- All Web Security Academy labs: https://portswigger.net/web-security/all-labs

## Detection Lanes

- single-quote parser anomaly
- escaped quote control
- numeric expression control
- boolean true/false pair
- equivalent-value pair
- time delay pair
- OAST interaction pair
- syntax that restores the original value
- syntax that produces a deliberately different value

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

- comment syntax differences
- string concatenation differences
- substring syntax
- database version functions
- metadata table names
- conditional expression syntax
- conditional error primitives
- time-delay functions
- stacked-query support
- OAST/DNS lookup primitives

## Safe Proof Ideas

- paired true/false response delta
- bounded timing delta with repeated control samples
- harmless database fingerprint string
- column-count or printable-column control without sensitive extraction
- own-account hidden-data exposure
- auth check bypass only against an owned disposable account
- controlled OAST callback without data exfiltration
- second-order trigger in an owned resource
