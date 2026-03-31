# IDOR Testing Playbook

## Overview
Insecure Direct Object Reference (IDOR) — accessing other users' resources by manipulating object identifiers.

## Testing Approach

### 1. Identify Object References
- User IDs, document IDs, order IDs, etc.
- Look for sequential, predictable, or guessable patterns
- Find UUIDs, base64-encoded IDs, JWTs

### 2. Horizontal Privilege Escalation
Access resources at the SAME privilege level but belonging to another user:
```
GET /api/v1/user/123/profile
  → Change to GET /api/v1/user/124/profile
  → If 200 OK, IDOR found
```

### 3. Vertical Privilege Escalation
Access resources at a HIGHER privilege level:
```
GET /api/v1/user/123/profile (regular user)
  → Try accessing /api/v1/admin/users (admin endpoint)
```

## Testing Workflow

### Step 1: Capture Baseline
1. Login as User A
2. Perform action to get a resource (view profile, order, etc.)
3. Capture the full request (URL, headers, cookies)

### Step 2: Extract Object Identifiers
- Look for IDs in URL: `/users/123`
- Look for IDs in JSON responses
- Look for references in cookies/tokens

### Step 3: Test Manipulation
1. Replace User A's ID with User B's ID
2. Change the resource path
3. Remove authentication entirely
4. Use User A's session to access User B's resource

### Step 4: Verify Impact
- Can you read private data?
- Can you modify other users' data?
- Can you delete other users' resources?

## Common IDOR Endpoints

| Resource | Example Endpoints |
|----------|------------------|
| User Profile | `/api/v1/user/{id}`, `/profile/{id}` |
| Orders | `/api/orders/{id}`, `/checkout/order/{id}` |
| Documents | `/api/docs/{id}`, `/files/{id}/download` |
| Payments | `/api/payments/{id}`, `/billing/{id}` |
| Messages | `/api/messages/{id}`, `/inbox/{id}` |

## Bypass Techniques

### Mass Assignment
```json
POST /api/v1/user/profile
{"name": "John", "role": "admin"}
```

### HTTP Method Tampering
```
GET /api/v1/resource/123  (should be POST to create)
DELETE /api/v1/resource/123 (unauthorized)
PUT /api/v1/resource/123 (update others)
```

### Parameter Pollution
```
GET /api/v1/user?id=123&id=124
```

### JSON Parameter Injection
```json
{"user_id": 123, "admin": true}
```

## Findings Format

When finding IDOR, document:
```
## IDOR Finding
- **Type**: Horizontal / Vertical / Mass Assignment
- **URL**: https://target.com/api/v1/resource
- **Method**: GET/POST/PUT/DELETE
- **Object ID Parameter**: id
- **User A Resource**: 123
- **User B Resource**: 124
- **Impact**: Read/Modify/Delete other users' data
- **PoC**: curl -X GET "https://target.com/api/v1/resource/124" -H "Cookie: ..."
```

## Files to Update
After finding IDOR, write to:
```
~/Shared/bounty_recon/{program}/ghost/skills/idor/findings.md
```

Include: endpoint, parameter, IDs tested, what was accessed, impact assessment.
