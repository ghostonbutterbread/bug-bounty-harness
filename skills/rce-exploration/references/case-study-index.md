# Public Case-Study Index

Use these as models for evidence collection and precondition mapping—not as
exploit templates. Every entry was retrieved from its primary publisher through
safe-fetch.

| Case | Reusable method lesson |
|---|---|
| Project Zero FORCEDENTRY | Treat declared type, detected type, decoder selection, processing stage, and sandbox/process identity as separate facts. Automatic preview/transcoding surfaces deserve the same analysis as direct HTTP inputs.[7] |
| PortSwigger SSTI research | Separate harmless detection from engine identification, then distinguish template **source** control from template-variable data binding before asserting capability.[8] |
| Apache Struts S2-045 | Include headers, validation failures, exception rendering, and parser fallback/error paths in the sink map. Apache describes the affected multipart `Content-Type` error path and publishes affected/fixed versions.[9] |
| GitLab / ExifTool | An extension allowlist can be bypassed by downstream content sniffing. Trace raw bytes through each metadata, preview, conversion, AV, OCR, and extraction consumer—not only the upload gate.[10] |
| Apache Struts S2-052 | Deserialization analysis must name the serializer, protocol/endpoint, type restrictions, and remediation. Apache attributes this route to XML handling through XStream without type filtering.[11] |
| Spring Framework CVE-2022-22965 | Record an explicit environmental precondition matrix. Spring identifies JDK, servlet container, package type, and dependency conditions; a library version alone does not establish the stated path.[12] |
| Atlassian Confluence advisory | Use vendor notices to capture product/deployment class, affected/fixed range, auth condition, exploitation status, and mitigation. They are exposure-triage evidence, not production reproduction instructions.[14] |

## Intake rule

Admit a new case only when its primary source specifies a source/control path,
relevant prerequisites or affected range, a bounded impact description, and a
mitigation/fix. Index the mechanism, not the public payload.

## Sources

[7] https://projectzero.google/2021/12/a-deep-dive-into-nso-zero-click.html
[8] https://portswigger.net/research/server-side-template-injection
[9] https://cwiki.apache.org/confluence/display/WW/S2-045
[10] https://gitlab.com/gitlab-org/gitlab/-/issues/327121
[11] https://cwiki.apache.org/confluence/display/WW/S2-052
[12] https://spring.io/security/cve-2022-22965
[14] https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-03-1130377146.html
