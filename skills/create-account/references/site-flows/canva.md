# Canva Auth Flow

Use this when creating or logging into approved Canva test accounts.

## Signup

1. Open Canva and choose **Sign up**.
2. Select **Continue with another way**.
3. Select **Continue with email**.
4. Agree to the Terms of Use and Privacy Policy when prompted.
5. Enter the approved test email address.
6. Ghost/parent retrieves the verification code or mail for that approved alias. For approved program email domains, `ryushe+1@...` and `ryushe+2@...` are forwarded to Ghost's mailbox.
7. Store the resulting credential in Bitwarden and record only the Bitwarden item reference in notes.

## Login

1. Open Canva and choose **Sign in**.
2. Select **Continue with email**.
3. Enter the approved test email address.
4. If Canva sends a code or verification mail for the approved alias, Ghost/parent retrieves it and provides only the short-lived code to the active login step.

## Forwarded Code Aliases

- `ryushe+1@...` and `ryushe+2@...` on approved program email domains should receive forwarded login/signup codes in Ghost's mailbox.
- Child agents should not use `/gmail` directly. Ghost/parent retrieves only the active Canva code or verification message, then passes only the code when needed.
- Do not expose full email bodies, reset links, mailbox metadata, unrelated messages, Gmail access, mailbox sessions, credentials, cookies, or reusable secrets.

## Notes

- Do not use social login for Ghost-managed test accounts.
- Do not create bulk accounts.
- Stop and ask Ryushe if Canva changes the flow, requires a phone number, blocks the browser, or requests information beyond the approved account setup.
