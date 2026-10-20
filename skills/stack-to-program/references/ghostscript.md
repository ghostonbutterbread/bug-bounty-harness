# Ghostscript discovery recipe

Use from `stack-to-program` for Ghostscript, Artifex, `gs`, or a Ghostscript CVE. This is a public composition recipe, **not** exploit guidance.

Ghostscript is a backend PostScript/PDF interpreter used in rasterization, prepress, OCR and printing. HTTP technology detectors ordinarily do not see it. A PDF preview is not evidence of Ghostscript: alternatives include Poppler, MuPDF, PDFium, Chromium, iText, PDFBox, and PDF.js.

## Pin and expand carefully

- Package/binary names: `ghostscript`, `gs`, `libgs`; verify the advisory's actual affected package and fixed version at NVD/vendor/distro trackers. A CVE's vendor package range and a distribution's backported patched package version can differ.
- Potential wrappers: ImageMagick/GraphicsMagick delegates, OCRmyPDF, CUPS/cups-filters, office and asset processing. A reverse dependency or installed binary does not imply the wrapper invokes Ghostscript on an in-scope path.
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
- EPS/PS upload with raster preview but no source: `feature-inferred`, separate from corroborated candidates.
- Docs identifying Poppler/Chromium for **that path**: `contradicted` for the proposed Ghostscript path.

Do not equate ImageMagick installed with PDF delegate enabled, or `-dSAFER` with a bypass. After selection, `technology-research` and `vulnerability-patch-research` own the version/configuration and advisory comparison under published program rules.
