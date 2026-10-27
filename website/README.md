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

Analytics is not enabled. No provider token, telemetry code, inventory collection,
or private configuration is included. The homepage FAQ accurately discloses that.
Adding homepage analytics alone will not measure direct app visits. Any future
measurement must cover the actual application entry points, review transmitted
URLs and fields, preserve private input handling, and update the disclosures and
security policy intentionally. Separate subdomains alone do not count app usage.

## Checks

Run `node --check website/site.js`. Open a local static preview and verify the
three workflow tabs with clicks and ArrowUp/ArrowDown/Home/End, the FAQ accordions,
the narrow-screen menu, sample download, and app launch/deep links. Check layout
at desktop and mobile widths before production cutover.

The page has no external fonts, scripts, forms, APIs, authentication, or storage.
This is not a HIPAA certification or an assertion about the separate app's
hosting providers. Patient information is outside the intended workflow.
