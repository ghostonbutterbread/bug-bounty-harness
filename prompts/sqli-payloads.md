# SQLi Payload Reference

Use this only after `prompts/sqli-playbook.md` tells you which lane applies. Prefer the smallest payload that answers the current question.

## Lane Reference

| Lane | Goal | Safe Confirmation Pattern |
|------|------|---------------------------|
| Error | Trigger a parser or DB error | quote or parenthesis mismatch, type conversion error, XML/error function |
| Boolean | Prove true/false branching | paired true predicate and false predicate |
| Time | Prove blind execution | backend-specific delay function with small delay |
| Union | Prove projection control | `NULL` or constant-only projection, never data extraction |

## Database Clues

| Backend | Timing Primitive | Common Error Clue |
|---------|------------------|-------------------|
| MySQL / MariaDB | `SLEEP(n)` | `SQL syntax`, `You have an error in your SQL syntax`, `MariaDB` |
| PostgreSQL | `pg_sleep(n)` | `PG::`, `PostgreSQL`, `unterminated quoted string` |
| MSSQL | `WAITFOR DELAY` | `ODBC SQL Server Driver`, `Unclosed quotation mark`, `Microsoft SQL Server` |
| Oracle | expensive conditional or package call | `ORA-` messages |
| SQLite | no native sleep by default | `SQLite`, `near`, `unrecognized token` |

## Union Notes

- Start with `NULL` placeholders because they are type-tolerant.
- Use constant markers to detect reflection, not table or schema reads.
- Stop after you prove projection control.

## WAF And Filter Adjustments

- Try quote alternates only after confirming the sink likely stays quoted.
- Numeric sinks may need arithmetic or boolean-only forms instead of string delimiters.
- If keywords are blocked, use `agents/payload_mutator.py` with `--type sqli` to generate variants and replay only the one that matches the current lane.

## Safety Rules

- Do not enumerate tables, columns, or user data.
- Keep delays short and repeat only enough times to establish stability.
- Prefer constant projections and logic flips over extraction.
