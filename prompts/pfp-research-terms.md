# Profile Picture Research Terms

Use this file only when the profile-picture flow shows behavior that needs expansion. These are technique families and search terms, not a fixed payload list.

## URL Import / SSRF

- avatar URL import SSRF
- image proxy SSRF
- media fetcher SSRF
- URL preview SSRF
- remote image resize SSRF
- server-side image fetch redirect bypass
- URL parser confusion
- host allowlist bypass
- DNS rebinding
- DNS pinning behavior
- redirect validation order
- IP address representation
- IPv4 decimal/octal/hex notation
- IPv6 mapped IPv4
- localhost alias behavior
- cloud metadata reachability
- container metadata reachability
- HTTP request smuggling through fetcher
- header injection in server-side fetch
- blind SSRF interaction proof

## Upload / Image Parser

- image upload parser differential
- MIME sniffing bypass
- magic byte mismatch
- content-type validation bypass
- extension normalization
- filename canonicalization
- image transcoding security
- EXIF metadata preservation
- SVG upload script handling
- polyglot image upload
- ImageMagick delegate behavior
- libvips image processing
- ExifTool metadata parsing
- malformed image dimension handling
- oversized image processing
- crop/resize parameter tampering

## XSS / Rendering

- stored XSS in image metadata
- avatar filename XSS
- profile image URL reflection
- SVG stored XSS
- CDN URL reflected XSS
- unsafe image error rendering
- profile card rendering XSS
- DOM sink from profile avatar URL
- HTML attribute context injection
- JavaScript string context injection
- image onerror rendering behavior
- CSP interaction with uploaded media

## Storage / CDN / Object Behavior

- predictable avatar storage key
- profile image IDOR
- pre-signed upload authorization
- object overwrite authorization
- delete avatar IDOR
- CDN cache poisoning avatar
- stale avatar cache
- image transformation cache key
- tenant-isolated media storage
- private media public URL
- profile image access control

## Auth / Workflow / Race

- avatar update race
- profile image replace race
- crop then delete race
- pre-signed upload reuse
- upload finalize authorization
- owned account avatar sharing
- profile visibility propagation
- notification/avatar render surface
- workspace member avatar render surface

## WAF / Filter / Evasion Families

- file upload WAF bypass
- MIME allowlist bypass
- extension blacklist bypass
- URL allowlist filter evasion
- SSRF filter bypass
- CDN media validation bypass
- image proxy URL normalization
- request header normalization
- security filter parser differential
