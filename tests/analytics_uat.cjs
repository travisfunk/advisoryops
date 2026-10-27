"use strict";
// A deliberately hostile analytics stub must not be able to read application input.
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const http = require("node:http");
const root = path.resolve(__dirname, "..");
const marker = "PRIVATE_ANALYTICS_UAT_82bf";
(async () => {
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://localhost");
      const file = path.resolve(root, "." + url.pathname);
      if (!file.startsWith(root + path.sep)) return res.writeHead(403).end();
      const data = await fs.readFile(file);
      res.setHeader("Content-Type", file.endsWith(".html") ? "text/html" : file.endsWith(".js") ? "text/javascript" : "application/json");
      res.end(data);
    } catch { res.writeHead(404).end(); }
  });
  await new Promise(r => server.listen(0, "127.0.0.1", r));
  let browser;
  try {
    browser = await chromium.launch({executablePath: process.env.CHROMIUM_EXECUTABLE || undefined, headless: true});
    const context = await browser.newContext();
    const reports = [];
    await context.route("https://devicelantern.pages.dev/usage/*", async route => {
      const name = new URL(route.request().url()).pathname.split("/").pop();
      await route.fulfill({contentType: "text/html", body: await fs.readFile(path.join(root, "website/usage", name), "utf8")});
    });
    await context.route("https://static.cloudflareinsights.com/beacon.min.js", route => route.fulfill({
      contentType: "text/javascript", headers: {"Access-Control-Allow-Origin": "*"},
      body: `setTimeout(() => {
        let parentReadable = false, storageReadable = false;
        try { parent.document.body.innerText; parentReadable = true; } catch (_) {}
        try { localStorage.length; storageReadable = true; } catch (_) {}
        fetch('https://cloudflareinsights.com/cdn-cgi/rum', {method:'POST', body:JSON.stringify({parentReadable,storageReadable,url:location.href,referrer:document.referrer})});
      }, 500);`
    }));
    await context.route("https://cloudflareinsights.com/**", route => {
      reports.push(JSON.parse(route.request().postData()));
      return route.fulfill({status: 200, headers: {"Access-Control-Allow-Origin": "*"}, body: ""});
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    for (const [document, kind] of [["docs/index.html", "app"], ["website/index.html", "home"]]) {
      const page = await context.newPage();
      await page.goto(`${base}/${document}?${marker}#sbom`);
      if (kind === "app") await page.locator("#sbom-device").fill(marker);
      await page.waitForTimeout(1000);
      const report = reports.at(-1);
      assert.ok(report, "the analytics frame must load");
      assert.equal(report.parentReadable, false);
      assert.equal(report.storageReadable, false);
      assert.equal(report.referrer, "");
      assert.equal(report.url, `https://devicelantern.pages.dev/usage/${kind}.html`);
      assert.ok(!JSON.stringify(report).includes(marker));
      await page.close();
    }
    console.log("PASS homepage and direct application counters cannot read parent inputs, URLs, referrers, or storage");
  } finally {
    await browser?.close();
    await new Promise(r => server.close(r));
  }
})().catch(e => { console.error(e); process.exitCode = 1; });
