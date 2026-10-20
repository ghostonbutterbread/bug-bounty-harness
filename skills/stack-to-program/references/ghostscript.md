# Ghostscript discovery augment

**Status:** active specialist reference; **owner:** `stack-to-program`; **canonical path:** this file; **supersedes:** the narrower Ghostscript recipe in this same path. Use for Ghostscript, Artifex, `gs`, or a Ghostscript CVE. This is a public composition recipe, **not** exploit guidance; [the generic guide](visibility-and-bridges.md) owns the visibility/evidence model.

Ghostscript is a backend PostScript/PDF interpreter used in rasterization, prepress, OCR and printing. HTTP technology detectors ordinarily do not see it. A PDF preview is not evidence of Ghostscript: alternatives include Poppler, MuPDF, PDFium, Chromium, iText, PDFBox, and PDF.js.

## Pin and expand carefully

- Package/binary names: `ghostscript`, `gs`, `libgs`; verify the advisory's actual affected package and fixed version at NVD/vendor/distro trackers. A CVE's vendor package range and a distribution's backported patched package version can differ.
- Potential wrappers: Pillow's EPS handler (which can call `gs` when available), ImageMagick/GraphicsMagick delegates, OCRmyPDF, CUPS/cups-filters, office and asset processing. Verify each wrapper's actual format and configuration: [Pillow image format documentation](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html) documents the EPS bridge; [ImageMagick resources](https://imagemagick.org/resources/) link to delegate/policy configuration; [OCRmyPDF maintainer docs](https://ocrmypdf.readthedocs.io/en/stable/maintainers.html) discuss alternative rasterizers. A reverse dependency or installed binary does not imply the wrapper invokes Ghostscript on an in-scope path.
- Competing path: a product may use Poppler or Chromium for PDFs while separately installing Ghostscript for another optional feature. Keep this contradiction path-specific rather than treating it as a global negative.

## Public maps (record exact query, URL, and date)

1. Composition: distro reverse-dependencies (`apt-cache rdepends ghostscript` or distro package browser), package manifests and lockfiles. These generate *product leads*, not deployed-version claims.
2. Source/docs: vendor-owned Dockerfiles and installation docs mentioning `apt-get install ghostscript`, `/usr/bin/gs`, `gs -dSAFER`, `delegate.xml`, or `requires ghostscript`. Check the repository belongs to the named product; forks, examples, and development/test dependencies need separate qualification.
3. Disclosure: vendor security advisories and public GHSA/CVE records explicitly linking a wrapper product and Ghostscript.
4. Artifacts: already-indexed `filetype:pdf "GPL Ghostscript"` metadata or public indexed error snippets. Attribute the artifact's producer and ownership; never call a live converter to obtain one in this lane.
5. Directory join: connect a corroborated product/vendor to a published bounty program by explicit program URL, verified owner domain, or exact product name. A platform listing with `bounty: true` is only a hint pending first-party verification.

## Labels

- Vendor Dockerfile/docs naming `gs`: `source-derived` at that revision; production unknown.
- Vendor advisory explicitly naming product + Ghostscript: `disclosure`; affected release still needs checking.
- Attributable indexed PDF Producer metadata: `artifact`; artifact generation location/time uncertain.
- EPS/PS upload with a documented **server-side thumbnail or conversion** path but no product-specific dependency source: `feature-inferred`, separate from corroborated candidates. Generic image uploads without a transform are still weaker leads.
- Docs identifying Poppler/Chromium for **that path**: `contradicted` for the proposed Ghostscript path.

## Sketchfab/Epic retrospective — a discovery test, not a current target claim

[Sketchfab's public texture documentation](https://help.sketchfab.com/en/articles/16152646-materials-and-textures) describes image conversion, but its listed supported texture formats **do not include EPS or PS**. It could have surfaced only a broad conversion lead, not the higher-signal EPS/PS pathway. [Pillow's EPS docs](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html) independently demonstrate a *possible* interpreter bridge. These two sources **do not connect Sketchfab to Pillow or Ghostscript**, identify an affected production version, or establish that every upload is decoded. A separate current Epic policy/scope check would be required before target interaction.

In a historical owned-session case, a thumbnail/avatar resizing route interpreted EPS-like content despite a PNG filename, while other routes stored the bytes without rendering. That route was **not** identifiable from the public texture-format list alone: it took selected-program, owned-session observation to distinguish rendering from raw storage. The saved `web_bounty/epicgames/web/reports/D05/REPORT.md` and `web_bounty/epicgames/web/reports/D05/SUBMISSION.md` (relative to the resolved Shared root; historical records, not reusable scan inputs) disagree on whether Pillow or ImageMagick was the production intermediary. Keep that edge **unresolved**, rather than encoding either claim as confirmed. The observed interpreter version was learned from target-side evidence after selection, not a public banner or inferred wrapper version. Do not present the case as evidence of a current unpatched host or a transferable exploit.

## Selected-program questions

- Does published product documentation describe an eligible transformation of EPS/PS/PDF inputs, or only raw storage? Are relevant assets and file formats permitted under the current rules?
- Which configured caller, delegate policy, renderer, and binary actually handle each path? Could another renderer replace Ghostscript for that feature?
- If live investigation is authorized, which **deployed** build and patch status apply to the advisory, accounting for distribution backports? Route that investigation to `technology-research` and `vulnerability-patch-research` under the normal testing gates.

Do not equate ImageMagick installed with a PDF delegate enabled, or `-dSAFER` with a bypass. The pre-selection recipe does not query candidate conversion services.
