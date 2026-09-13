# Cloud, Container, Internal Service, and Scheme Boundaries

Use only after a server-side fetch boundary is confirmed and program scope is
known. Start with low-sensitivity identity/status proof; do not retrieve, retain,
or use secrets, tokens, user data, or credentials unless the program permits the
minimum necessary proof.

## Destination classes

Classify a small evidence-led set, not a network range:

- loopback, private/link-local/ULA/carrier-grade NAT, cluster/service networks;
- cloud instance or task metadata; Kubernetes/OpenShift API/service DNS;
- container/runtime socket or HTTP proxy surfaces; internal health/debug/metrics
  and admin endpoints; and
- service discovery, registries, queues, caches, search services, databases,
  identity/proxy systems, and recursively reachable URL fetchers.

Use application-map names, ports, and paths. A public callback proves egress,
not internal reachability.

## Metadata taxonomy

The familiar link-local address is not provider-exclusive. Identify provider or
runtime hints before testing a vendor route:

- **AWS EC2:** IMDSv2 requires a session-token request and token header; a
  GET-only fetcher ordinarily cannot satisfy it. IMDSv1 is a distinct legacy
  exposure. ECS task metadata is separate.
- **GCP:** metadata requires `Metadata-Flavor: Google`.
- **Azure:** IMDS requires `Metadata: true` and many routes require an API
  version.
- **Oracle, OpenStack, DigitalOcean, Alibaba, and private clouds:** endpoint
  versions and headers vary; consult current vendor documentation first.

A required header or method is a control boundary. Do not use request smuggling
to cross it without explicit approval and an isolated no-side-effect proof.

## Scheme and secondary-parser inventory

Discover the actual client support at low rate using a benign controlled
endpoint: HTTP(S), WebSocket, FTP/SFTP/TFTP, LDAP, `file`, `data`, `dict`,
`gopher`, `jar`/archive wrappers, Unix-socket/proxy adapters, and framework
wrappers. Also account for XML/XSLT/SVG external loading, PDF/image/HTML
renderers, browser automation, feed/import parsers, and proxy/CDN rewrites.

Unsupported-scheme errors are classification signal—not file-read or arbitrary
protocol proof. Raw CR/LF, gopher, header injection, and protocol smuggling can
produce state-changing traffic: treat them as a high-risk, separately authorized
escalation with an owned receiver/lab. Route header behavior to `/headers`.

## Proof ladder

1. Controlled callback.
2. Controlled redirect/DNS evidence.
3. Internal status/banner/root with no secrets.
4. Permitted redacted metadata root/version shape.
5. Stop at the impact boundary.

## Sources

- AWS, [Configure IMDS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- Google Cloud, [VM metadata](https://cloud.google.com/compute/docs/metadata/overview)
- Microsoft, [Azure IMDS](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
- Oracle, [Instance metadata](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm)
- OpenStack Nova, [Metadata service](https://docs.openstack.org/nova/latest/user/metadata.html)
- Kubernetes, [Access the API from a Pod](https://kubernetes.io/docs/tasks/run-application/access-api-from-pod/)
