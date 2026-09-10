# BountyLens Scripts

## `bountylens_api.py`

- **Purpose:** Call the BountyLens API without shell-sourcing its environment
  file or exposing the API key.
- **Inputs:** HTTP method, API path, query values, optional JSON body, and
  environment-backed configuration.
- **Outputs:** API response JSON or raw response text on stdout.
- **Mutates:** Network state only when the chosen API method and endpoint mutate;
  callers must follow the BountyLens skill's write boundary.
- **Example:** `bbh skills/bountylens/scripts/bountylens_api.py GET /programs`
- **Verification:** `bbh skills/bountylens/scripts/bountylens_api.py --help`
- **Coverage:** This is a transport helper, not an exhaustive inventory of
  BountyLens endpoints or supported workflows.
