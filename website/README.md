# DeviceLantern website

The standalone project homepage, served at <https://devicelantern.com>.
DeviceLantern was previously named AdvisoryOps; the repository and Python package
keep the `advisoryops` name for now so existing links and automation keep working.

Publish this directory as its own static site;
do not replace `docs/index.html` or change the feed publication output directory.
The existing application continues to run independently, including its daily
advisory updates. This website adds no runtime dependencies or backend.

## Deployment

For a Cloudflare Pages project connected to this public repository:

- Use `main` as the production branch after merging the website change.
- Leave the build command empty and use `website` as the build output directory.
- Configure a preview deployment from the feature branch if reviewing before merge.
- The included `_headers` file supplies a restrictive content security policy,
  disables outbound browser connections from this homepage, and suppresses referrers.
- Production custom domain: `devicelantern.com` (`www.devicelantern.com` redirects to it).

GitHub Pages does not apply Cloudflare's `_headers` syntax. Other static hosts
must configure equivalent response headers using their own controls.

## Application address and separation

All launch links currently target the existing public application at
`https://travisfunk.github.io/advisoryops/`, including `#sbom` deep links. When an
application hostname is selected, update those links in `index.html` together.
Deploy and verify the application independently before changing them. Publishing
this homepage does not migrate the app or configure its DNS.

The homepage uses only local CSS, JavaScript, and a favicon. The workflow graphic
is explicitly illustrative; the downloadable SBOM is the existing synthetic
example from `examples/sbom/medfusion-demo.cdx.json`. It is not real inventory.
Keep the two copies identical when updating the example.

## Usage measurement

Cloudflare Web Analytics is enabled for the `devicelantern.com` zone. Cloudflare
injects its beacon at the edge; nothing analytics-related is in this source. The
beacon reports the page URL, referrer, browser type, and page-load timing. It sets
no cookies and keeps no cross-site identifier. `_headers` allows only that beacon
script (`static.cloudflareinsights.com`) and its report endpoint
(`cloudflareinsights.com`); everything else stays same-origin.

`Referrer-Policy: strict-origin-when-cross-origin` lets the app's own analytics
tell homepage referrals from direct visits: only the origin is sent, never the path.

Homepage analytics alone does not count app visits or completed SBOM checks.

## Checks

Run `node --check website/site.js`. Open a local static preview and verify the
three workflow tabs with clicks and ArrowUp/ArrowDown/Home/End, the FAQ accordions,
the narrow-screen menu, sample download, and app launch/deep links. Check layout
at desktop and mobile widths before production cutover.

The page has no external fonts, forms, APIs, authentication, or storage. Its only
third-party script is the Cloudflare Web Analytics beacon described above.
This is not a HIPAA certification or an assertion about the separate app's
hosting providers. Patient information is outside the intended workflow.
