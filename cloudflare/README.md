# Cloudflare hosting

`devicelantern.com` serves the static homepage in [`website/`](../website/README.md)
as Cloudflare Workers static assets (free plan, no server code, no storage).
`www.devicelantern.com` is a two-line Worker that 301-redirects to the apex.
The advisory application and its daily feed stay on GitHub Pages and are not
affected by these deployments.

Deploy after merging a website change to `main` (requires a Cloudflare login
for the account that owns the `devicelantern.com` zone):

```sh
npx wrangler deploy -c cloudflare/site.jsonc
npx wrangler deploy -c cloudflare/www-redirect.jsonc   # only if the redirect changes
```

Each custom domain creates its own proxied DNS record and certificate. Both
configs disable `workers.dev` and preview URLs so the site has one public
address. `website/.assetsignore` keeps `website/README.md` from being published.
