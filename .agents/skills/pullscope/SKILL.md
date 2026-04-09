# Pullscope — Fetch Bug Bounty Scope

## What It Does
Fetches and parses scope from bug bounty platforms (HackerOne, Bugcrowd, Intigriti).

## Invocation
```
/pullscope <program>
```

## Usage
```
/pullscope superdrug
/pullscope h1/superdrug
/pullscope superdrug --platform hackerone
```

## Output
```
~/Shared/bounty_recon/{program}/scope/
└── in-scope.txt      # All in-scope domains/URLs
```

## How It Works
1. Fetches program page from platform
2. Parses domains and URLs
3. Saves to scope directory
4. All modules then use scope_manager to validate

## Related
- scope_manager.py — validates targets against scope
- All harnesses check scope before testing
