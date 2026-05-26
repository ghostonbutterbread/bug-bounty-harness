# Storage, CDN, Export, And Media Links

## Related Terms

- signed URL authorization
- pre-signed URL reuse
- CDN object authorization
- storage object IDOR
- export link authorization
- attachment access control
- media object ownership

## Detection Keywords

```text
download, export, attachment, file, media, image, avatar, asset,
cdn, storage, bucket, key, url, signed, signature, expires, token, version
```

## Try

- Load `$HARNESS_ROOT/skills/access-control/references/mutations/idor.md` for storage/media/export object mutations.
- Fetch direct file/export/media URL from another owned account.
- Replay signed URLs after logout, expiration, deletion, replacement, or membership removal.
- Swap storage keys, media IDs, avatar IDs, crop IDs, and version IDs.
- Compare original media URL vs transformed/CDN URL authorization.
- Check whether delete/update/finalize endpoints enforce ownership.

## Proof

Unauthorized subject reads, updates, deletes, reuses, or finalizes protected storage/media/export object.

## Stop

URL exposes non-owned private file content. Capture minimal evidence and stop.
