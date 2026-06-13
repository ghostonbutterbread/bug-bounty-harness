# Juice Shop Training Lab

Use this controlled lab to compare generic testing against `/request-exploration`-guided testing.

## Local Lab

Hoster currently has OWASP Juice Shop available on Hoster localhost:

```text
http://127.0.0.1:3001
```

Container pattern:

```text
ghost-juice-shop -> 127.0.0.1:3001:3000
```

Run from Hoster or through an approved tunnel only. Keep the lab bound to localhost unless Ryushe explicitly asks to expose it.

## Best Demo 1: Payback Time

Goal: show how a UI-limited workflow becomes vulnerable when the request body is mutated.

Baseline:

1. Register or log in to an owned Juice Shop account.
2. Add an item to the basket.
3. Use the UI to increase/decrease quantity and observe that the UI does not allow negative quantity.
4. Capture the `PUT /api/BasketItems/{id}` request.

Without `/request-exploration`, a generic agent will usually report: "UI prevents quantity below 1."

With `/request-exploration`, mutate:

```json
{"quantity": -1}
```

Expected controlled-lab result:

```text
200 OK, basket item quantity becomes -1
```

Mutation families exercised:

- integer injection
- high/low value testing
- business-logic constraint bypass
- baseline vs mutated response comparison

## Best Demo 2: Manipulate Basket

Goal: show duplicate-field and HTTP Parameter Pollution style behavior using two owned accounts.

Baseline:

1. Create account A and account B.
2. Add an item to account A's basket normally.
3. Attempt to add directly to account B's `BasketId` using account A's token.
4. Confirm the direct mutation fails with an invalid basket check.

With `/request-exploration`, test duplicate `BasketId` ordering in raw JSON:

```json
{"ProductId":4,"BasketId":"<account_a_basket>","quantity":1,"BasketId":"<account_b_basket>"}
```

Expected controlled-lab result:

```text
Direct BasketId swap fails, but duplicate-field ordering can add to the other owned account's basket.
```

Mutation families exercised:

- field duplication
- parser differential behavior
- access-control boundary observation
- owned-account-only ID mutation

## Evidence Template

Record:

- full local lab URL
- account aliases only, not passwords or tokens
- baseline request method and path
- mutation class
- baseline response
- mutated response
- whether the UI result and API result differ
- cleanup notes
