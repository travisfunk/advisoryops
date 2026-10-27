"use strict";
/** Browser acceptance checks against the actual served docs, using synthetic inventory only. */
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const root = path.resolve(__dirname, "../docs");
const artifacts = path.resolve(process.env.UAT_ARTIFACT_DIR || "outputs/uat");
const marker = "PRIVATE_SYNTHETIC_UAT_7fc093";
const medfusion = (manufacturer = "Smiths Medical") => ({
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  components: [
    {
      name: "Medfusion 4000",
      version: "1.5",
      manufacturer: { name: manufacturer },
    },
    { name: marker + "_component", version: "1" },
  ],
});
let checks = 0;
function passed(name) {
  checks++;
  console.log("PASS " + name);
}

(async () => {
  // An ephemeral loopback server keeps browser checks independent of deployments.
  const server = http.createServer(async (req, res) => {
    try {
      const pathname = decodeURIComponent(
        new URL(req.url, "http://localhost").pathname,
      );
      const filename = path.resolve(
        root,
        "." + (pathname === "/" ? "/index.html" : pathname),
      );
      if (!filename.startsWith(root + path.sep)) {
        res.writeHead(403).end();
        return;
      }
      const data = await fs.readFile(filename);
      const type = {
        ".html": "text/html",
        ".js": "text/javascript",
        ".json": "application/json",
        ".css": "text/css",
      }[path.extname(filename)];
      res.writeHead(200, {
        "Content-Type": type || "application/octet-stream",
      });
      res.end(data);
    } catch (_) {
      res.writeHead(404).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  let browser;
  try {
    browser = await chromium.launch({
      headless: true,
      executablePath: process.env.CHROMIUM_EXECUTABLE || undefined,
      args: ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
    });
    await fs.mkdir(artifacts, { recursive: true });
    const page = await browser.newPage({
      viewport: { width: 1365, height: 1000 },
    });
    const errors = [],
      requests = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("request", (r) =>
      requests.push({
        method: r.method(),
        url: r.url(),
        body: r.postData() || "",
      }),
    );
    // Analytics isolation is exercised independently by analytics_uat.cjs.
    await page.route("https://devicelantern.pages.dev/usage/*", route =>
      route.fulfill({contentType: "text/html", body: "<!doctype html><title>Visit counter</title>"}));
    const base = `http://127.0.0.1:${server.address().port}`;
    await page.goto(base + "/#sbom");
    await page.locator("#sbom-section.visible").waitFor();
    assert.equal(await page.locator("#sbom-file").getAttribute("type"), "file");
    await page.locator("#sbom-device").focus();
    assert.equal(
      await page
        .locator("#sbom-device")
        .evaluate((e) => e === document.activeElement),
      true,
    );
    passed("SBOM deep link, tab visibility and keyboard focus");
    const upload = async (doc, name = "synthetic.json") => {
      await page.locator("#sbom-file").setInputFiles({
        name,
        mimeType: "application/json",
        buffer: Buffer.from(
          typeof doc === "string" ? doc : JSON.stringify(doc),
        ),
      });
      await page.locator("#sbom-run").click();
    };
    const done = () =>
      page.waitForFunction(() =>
        document
          .querySelector("#sbom-status")
          .textContent.includes("tracked advisories checked"),
      );
    const failed = () =>
      page.waitForFunction(() =>
        document
          .querySelector("#sbom-status")
          .textContent.startsWith("Check failed"),
      );
    await page.locator("#sbom-device").fill(marker);
    await upload(medfusion());
    await done();
    assert.equal(await page.locator("#sbom-results article").count(), 8);
    assert.match(
      await page.locator("#sbom-results").innerText(),
      /partial product name/,
    );
    assert.match(
      await page.locator("#sbom-results").innerText(),
      /CVE-2017-12718/,
    );
    await page.screenshot({
      path: path.join(artifacts, "desktop-sbom.png"),
      fullPage: true,
    });
    passed(
      "actual catalog returns all eight Medfusion CVEs with review evidence",
    );
    for (const article of await page.locator("#sbom-results article").all()) {
      const ids = (await article.innerText()).match(/CVE-\d{4}-\d+/g) || [];
      assert.equal(ids.length, 1, "each Medfusion finding shows its CVE once");
    }
    passed("finding identifiers are displayed once");
    const downloadPromise = page.waitForEvent("download");
    await page.locator("#sbom-download").click();
    const download = await downloadPromise;
    const report = JSON.parse(await fs.readFile(await download.path(), "utf8"));
    assert.equal(report.device, marker);
    assert.equal(report.findings.length, 8);
    assert.ok(
      report.findings.every(
        (f) =>
          f.status === "review_required" &&
          f.evidence_flags.includes("partial product name") &&
          f.vendor_evidence_source.startsWith("https://"),
      ),
    );
    passed(
      "download contains the complete device report and vendor evidence provenance",
    );
    assert.ok(
      requests.every(
        (r) => r.method === "GET" && !JSON.stringify(r).includes(marker),
      ),
    );
    const storage = await page.evaluate(() =>
      JSON.stringify({
        local: { ...localStorage },
        session: { ...sessionStorage },
      }),
    );
    assert.ok(!storage.includes(marker));
    passed(
      "synthetic inventory never enters network requests or browser storage",
    );
    const aliasDocument = medfusion("ICU Medical L.L.C.,");
    aliasDocument.components.pop();
    await upload(aliasDocument);
    await done();
    assert.equal(await page.locator("#sbom-results article").count(), 8);
    const aliasStatus = await page.locator("#sbom-status").innerText();
    assert.match(aliasStatus, /1 component ·/);
    assert.match(aliasStatus, /1 component with candidates/);
    assert.ok(!aliasStatus.includes("1 components"));
    passed(
      "ICU Medical punctuated alias returns eight real-catalog findings with singular component grammar",
    );
    await page.setViewportSize({ width: 320, height: 720 });
    assert.ok(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    );
    await page.screenshot({
      path: path.join(artifacts, "mobile-sbom.png"),
      fullPage: true,
    });
    passed("320px mobile result and controls fit without horizontal overflow");
    await page.setViewportSize({ width: 1365, height: 1000 });
    await page.locator("#sbom-device").fill(marker + " changed");
    assert.equal(await page.locator("#sbom-results").innerText(), "");
    assert.ok(await page.locator("#sbom-download").isDisabled());
    passed("input changes invalidate previous results and downloads");
    await upload(medfusion("Other Medical"));
    await done();
    assert.equal(await page.locator("#sbom-results article").count(), 0);
    assert.match(
      await page.locator("#sbom-results").innerText(),
      /does not establish.*safe/i,
    );
    passed(
      "wrong manufacturer gives no Medfusion candidates and no safety claim",
    );
    await upload({
      spdxVersion: "SPDX-2.3",
      packages: [
        {
          name: "Medfusion 4000",
          originator: "Organization: Smiths Medical",
          versionInfo: "1.5",
        },
      ],
    });
    await done();
    // SPDX originator is not automatically a manufacturer; parser warns about uncertainty.
    assert.match(
      await page.locator("#sbom-status").innerText(),
      /tracked advisories checked/,
    );
    passed("SPDX import completes with the documented identity policy");
    await upload({
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      components: [
        { name: '<img src=x onerror="window.__uatXSS=1">', version: "1" },
      ],
    });
    await done();
    assert.equal(await page.evaluate(() => window.__uatXSS), undefined);
    assert.equal(await page.locator("#sbom-results img").count(), 0);
    passed("component HTML is escaped and cannot execute script");
    await upload("{}");
    await failed();
    assert.ok(await page.locator("#sbom-download").isDisabled());
    passed("unsupported input fails closed with no stale export");
    await upload("{");
    await failed();
    passed("malformed JSON produces a visible error");
    await page.locator("#sbom-file").setInputFiles({
      name: "oversized.json",
      mimeType: "application/json",
      buffer: Buffer.alloc(10 * 1024 * 1024 + 1, 32),
    });
    await page.locator("#sbom-run").click();
    await page.waitForFunction(() =>
      document.querySelector("#sbom-status").textContent.includes("10 MiB"),
    );
    assert.ok(await page.locator("#sbom-download").isDisabled());
    assert.match(await page.locator("#sbom-status").innerText(), /10 MiB/);
    passed("oversized imports fail at the documented file limit");
    await page.route("**/sbom_advisories.json", (route) =>
      route.fulfill({ status: 503, body: "Unavailable" }),
    );
    await upload(medfusion());
    await failed();
    assert.match(await page.locator("#sbom-status").innerText(), /503/);
    assert.ok(await page.locator("#sbom-download").isDisabled());
    await page.unroute("**/sbom_advisories.json");
    passed("catalog failure leaves no findings or usable download");
    await page.route("**/feed_archive/manifest.json", async (route) => {
      const data = JSON.parse(
        await fs.readFile(
          path.join(root, "feed_archive/manifest.json"),
          "utf8",
        ),
      );
      data.generated_at = "mismatched";
      await route.fulfill({ json: data });
    });
    await upload(medfusion());
    await failed();
    assert.match(
      await page.locator("#sbom-status").innerText(),
      /snapshots differ/,
    );
    await page.unroute("**/feed_archive/manifest.json");
    passed("mismatched publication snapshots fail closed");
    await upload(medfusion());
    await done();
    await page.locator("#sbom-clear").click();
    assert.equal(await page.locator("#sbom-file").inputValue(), "");
    assert.equal(await page.locator("#sbom-device").inputValue(), "");
    assert.equal(await page.locator("#sbom-results").innerText(), "");
    passed("clear removes the inventory, device label and findings");
    for (const tab of ["issues", "sources", "methodology", "about", "sbom"]) {
      await page.locator(`[data-tab="${tab}"]`).click();
      assert.ok(await page.locator(`#${tab}-section`).isVisible());
    }
    passed("all five dashboard tabs remain usable");
    await page.locator('[data-tab="issues"]').click();
    await page.locator(".issue-card").first().waitFor();
    const title = await page.locator(".ic-title").first().innerText();
    await page.locator("#search-input").fill(title);
    await page.waitForFunction(
      () => document.querySelectorAll(".issue-card").length > 0,
    );
    await page.locator(".issue-card").first().click();
    assert.ok((await page.locator("#detail-content").innerText()).length > 40);
    await page.locator("#search-input").fill(marker + "_unmatched");
    await page.waitForFunction(() =>
      document
        .querySelector("#issue-list-pane")
        .textContent.includes("No issues match"),
    );
    await page.locator("#search-input").fill("");
    await page.locator("#visit-review-btn").click();
    await page.locator("#visit-changes-btn").click();
    await page.waitForFunction(
      () =>
        document.querySelector("#visit-changes-banner").textContent.length > 0,
    );
    passed("advisory search, detail view and local review controls work");
    const adversarial = await browser.newPage();
    adversarial.on("pageerror", (e) => errors.push(e.message));
    const feed = JSON.parse(
      await fs.readFile(path.join(root, "feed_healthcare.json"), "utf8"),
    );
    const bad = {
      ...feed[0],
      issue_id: "audit');window.__idXSS=1;//",
      title: "Synthetic security acceptance record",
      canonical_link: "javascript:window.__urlXSS=1",
      cves: ['CVE-2026-1234"><img src=x onerror="window.__cveXSS=1">'],
    };
    await adversarial.route("**/feed_healthcare.json", (route) =>
      route.fulfill({ json: [bad] }),
    );
    await adversarial.goto(base);
    await adversarial.locator(".issue-card").first().click();
    assert.equal(
      await adversarial
        .locator('#detail-content a[href^="javascript:"]')
        .count(),
      0,
    );
    assert.equal(await adversarial.locator("#detail-content img").count(), 0);
    await adversarial.locator("#mark-read-btn").click();
    assert.equal(
      await adversarial.evaluate(
        () => window.__idXSS || window.__urlXSS || window.__cveXSS,
      ),
      undefined,
    );
    assert.match(
      await adversarial.locator("#detail-content").innerText(),
      /Source URL unavailable/,
    );
    await adversarial.close();
    passed(
      "main advisory view rejects unsafe URLs, malformed CVE HTML and executable issue IDs",
    );
    assert.deepEqual(errors, []);
    passed("no uncaught JavaScript errors during the acceptance flows");
    await fs.writeFile(
      path.join(artifacts, "result.json"),
      JSON.stringify(
        { checks, passed: true, requestCount: requests.length, errors },
        null,
        2,
      ),
    );
    console.log(`${checks} browser acceptance checks passed`);
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
