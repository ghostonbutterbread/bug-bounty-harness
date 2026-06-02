# Refunds, Invoices, Fulfillment

Use when refund, cancellation, invoice, receipt, tax, shipping, fulfillment, download, credit note, or order state can be observed.

## Checks

- Verify invoice, receipt, customer, subscription, and order object ownership across owned accounts before any broader claim.
- Check whether unpaid, declined, canceled, or zero-dollar orders can trigger fulfillment, download, shipment, credits, or paid entitlement.
- Check whether cancellation creates credits, refunds, or extended access beyond the paid/authorized state.
- Check whether tax/shipping/fees are server-side and tied to the actual order.
- Check refund endpoints only on owned disposable transactions and only with explicit approval when a real payment or vendor-visible action is involved.

## Evidence Required

- Object aliases and ownership relationship.
- Invoice/order/subscription URLs and methods.
- Payment status and fulfillment/entitlement status.
- Credit/refund/cancellation result.
- Cleanup state and exact stop condition.

## Stop

Stop before vendor-visible refund abuse, chargeback-like behavior, shipped goods, physical fulfillment, support contact, non-owned invoices, or any action that changes a real billing relationship.
