# Anonymous visit measurement

The homepage and every direct application load include a zero-size, script-only
sandboxed iframe at a fixed public URL:

- `https://devicelantern.pages.dev/usage/home.html`: homepage loads.
- `https://devicelantern.pages.dev/usage/app.html`: application loads, including
  visits through the original GitHub Pages address.

These two paths appear separately in Cloudflare Web Analytics. This is a count
of page loads, not authenticated people, SBOM checks, or successful reviews.
Blocking extensions and browser privacy settings can prevent counting.

The official, free, cookie-free Cloudflare beacon runs only inside the iframe.
The iframe has `sandbox="allow-scripts"`, with no `allow-same-origin`, and
`referrerpolicy="no-referrer"`. Browser origin isolation prevents its code from
reading the parent DOM, URLs, storage, SBOM files, device labels, search strings,
findings, and local reports. There are no messages or data passed to the frame.
Its own fixed public URL contains no query or fragment. Its content security
policy permits only the official script and Cloudflare's analytics endpoint.
There is no session recording, advertising pixel, inventory event, or tracking
identifier stored by DeviceLantern for analytics.

Cloudflare receives the fixed counter URL and basic request/browser/performance
information. As with any HTTPS service, its servers necessarily receive the
request's source network address; do not interpret cookie-free as no network
metadata reaching the provider. The public beacon token is a reporting identifier,
not an account API credential.

The application retains its local-only matching and JSON export behavior. No
SBOM or private device data is sent to an analytics or inventory service. The
counter is optional: an unavailable counter must not block the application.

Run `node tests/analytics_uat.cjs` to test both counters with a hostile analytics
stub that attempts to read the parent and storage. The test also places a private
marker in the parent URL and device input, then verifies that the isolated
request cannot contain it. Existing browser acceptance tests separately exercise
SBOM parsing, matching, reports, and network/storage privacy.
