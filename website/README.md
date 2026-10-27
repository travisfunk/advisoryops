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

Launch links target `https://app.devicelantern.com/`, including `#sbom` deep links.
The `devicelantern-app` Cloudflare Pages project follows `main`, has no build
command, and publishes `docs/`. The daily advisory workflow continues to generate
and commit that directory. Cloudflare deploys those commits independently; the
original `https://travisfunk.github.io/advisoryops/` application remains available.
The `devicelantern` Pages project publishes only `website/` from the same branch.
No Worker Functions, backend, database, paid plan, or new pipeline secrets are used.
Keep automatic analytics injection disabled; use only the isolated counter below.

The homepage uses only local CSS, JavaScript, and a favicon. The workflow graphic
is explicitly illustrative; the downloadable SBOM is the existing synthetic
example from `examples/sbom/medfusion-demo.cdx.json`. It is not real inventory.
Keep the two copies identical when updating the example.

## Usage measurement

Free Cloudflare Web Analytics counts homepage and direct application loads in
separate, fixed-address sandboxed frames. The third-party script cannot access
private inputs, parent URLs, referrers, or browser storage. There is no automatic
script injection into the application. See [visit analytics](../docs/visit-analytics.md)
for data fields, reporting paths, privacy limits, and browser verification.

## Checks

Run `node --check website/site.js`. Open a local static preview and verify the
three workflow tabs with clicks and ArrowUp/ArrowDown/Home/End, the FAQ accordions,
the narrow-screen menu, sample download, and app launch/deep links. Check layout
at desktop and mobile widths before production cutover.

The main page uses local fonts and scripts, with no forms, authentication, or storage.
The isolated analytics frame loads the official Cloudflare beacon.
This is not a HIPAA certification or an assertion about the separate app's
hosting providers. Patient information is outside the intended workflow.
