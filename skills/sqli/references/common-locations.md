# SQLi Common Locations

Use these as "where to look" seeds, not an exhaustive list.

## Query And Filter Inputs

- search boxes
- product/category filters
- sort fields
- pagination controls
- date ranges
- report filters
- admin table filters
- autocomplete endpoints
- global search APIs
- saved views
- analytics queries

## Identity And Object Inputs

- numeric object IDs
- UUID-like object IDs
- usernames
- email addresses
- tenant or workspace IDs
- organization slugs
- invite tokens
- reset or verification tokens
- order, invoice, subscription, or ticket IDs
- access-code or gift-card lookups

## Auth And Workflow Inputs

- login username fields
- login password fields
- SSO account lookup fields
- password reset account identifiers
- MFA recovery fields
- invitation acceptance fields
- checkout coupon or voucher fields
- support ticket search
- admin impersonation or lookup tools

## Structured Request Inputs

- JSON scalar fields
- JSON arrays used as filters
- GraphQL arguments
- XML nodes
- CSV import fields
- multipart text fields
- nested form fields
- headers used for lookup or routing
- cookies that select a user, session, experiment, locale, or tracking record

## Query-Shape Adjacent Inputs

- `order`
- `sort`
- `dir`
- `column`
- `field`
- `filter`
- `where`
- `q`
- `query`
- `search`
- `category`
- `id`
- `ids`
- `user`
- `account`
- `tenant`
- `org`
- `workspace`
- `limit`
- `offset`
- `page`
