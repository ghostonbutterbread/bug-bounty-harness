# IDOR State-Change Postconditions

Load before evaluating a `POST`, `PUT`, `PATCH`, `DELETE`, revoke, share,
transition, or other owned-resource state-changing IDOR attempt.

## Preconditions

Verify the source account, paired target account, and affected object are owned
and mutable. Exclude protected or `destructible=no` accounts. Capture only the
minimal non-secret fields needed to establish the initial state.

## One Attempt, Then Read Back

1. Send one deliberate normal-application request.
2. Re-fetch or re-list through the normal owner path.
3. When relevant, compare the paired owned account's view.
4. Classify the observed state:
   - **applied:** the expected change occurred, including after a 403/4xx;
   - **not applied:** the owned state is unchanged;
   - **inconclusive:** the state cannot be safely verified.

A response code alone never proves the action did or did not occur. If an action
applies unexpectedly, stop repeated replay, preserve minimum evidence, and
clean up only through a safe normal owned-object action.

## Boundaries

Normal create, edit, comment, restore, and delete actions on verified owned
objects are permitted when program rules allow. Do not use this reference for
unknown/third-party data, prominent public artifacts, staff/customer workflows,
payments, fulfillment, or unclear ownership.
