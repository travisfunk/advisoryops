/**
 * Offline controller regressions. The small harness implements only DOM methods
 * used by the controller, so behavior stays reproducible without a browser,
 * network service, API key, or third-party JavaScript dependency.
 * Layout is checked separately in a real browser.
 */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const engine = require("../dashboard/sbom.js");

class Element {
  constructor() {
    this.listeners = new Map();
    this.textContent = "";
    this.innerHTML = "";
    this.value = "";
    this.disabled = false;
    this.files = [];
  }
  addEventListener(event, listener) {
    this.listeners.set(event, listener);
  }
  replaceChildren() {
    this.innerHTML = "";
  }
  async emit(event) {
    await this.listeners.get(event)?.();
  }
}

const snapshot = "2026-10-16T00:00:00Z";
function makeHarness() {
  const ids = [
    "file",
    "device",
    "run",
    "status",
    "results",
    "download",
    "clear",
  ];
  const elements = Object.fromEntries(
    ids.map((id) => ["sbom-" + id, new Element()]),
  );
  const requests = [],
    downloads = [],
    blobs = [];
  const state = { failure: false, mismatch: false, fetchOverride: null };
  const catalog = {
    version: 1,
    generated_at: snapshot,
    total_records: 1,
    records_with_products: 1,
    matching_policy: "product_identity_candidates_only",
    issues: [
      {
        issue_id: "CVE-2099-10000",
        title: '<img src=x onerror="alert(1)">',
        affected_products: ["OpenSSL OpenSSL"],
        canonical_link: "javascript:alert(1)",
      },
    ],
  };
  const fetch = async (url, options) => {
    requests.push({ url, options });
    if (state.fetchOverride) return state.fetchOverride(url, options);
    if (state.failure) return { ok: false, status: 503 };
    return {
      ok: true,
      json: async () =>
        url.includes("manifest")
          ? { generated_at: snapshot, total_records: state.mismatch ? 2 : 1 }
          : catalog,
    };
  };
  class LocalURL extends URL {
    static createObjectURL(blob) {
      blobs.push(blob);
      return "blob:local-report";
    }
    static revokeObjectURL() {}
  }
  const document = {
    getElementById: (id) => elements[id],
    createElement: () => ({
      click() {
        downloads.push({ href: this.href, filename: this.download });
      },
    }),
  };
  const source = fs.readFileSync(
    path.join(__dirname, "../dashboard/sbom-ui.js"),
    "utf8",
  );
  vm.runInNewContext(source, {
    window: { AdvisorySBOM: engine },
    document,
    fetch,
    URL: LocalURL,
    Blob,
    AbortController,
    setTimeout,
    clearTimeout,
  });
  const get = (id) => elements["sbom-" + id];
  async function importDocument(doc) {
    const json = JSON.stringify(doc);
    get("file").files = [
      { size: Buffer.byteLength(json), text: async () => json },
    ];
    get("file").value = "synthetic.json";
    await get("file").emit("change");
  }
  return { get, state, requests, downloads, blobs, catalog, importDocument };
}

const documentFor = (name) => ({
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  components: [{ name, version: "1.0" }],
});

(async () => {
  const harness = makeHarness();
  const { get, state } = harness;
  await harness.importDocument(documentFor("openssl"));
  get("device").value = "Synthetic device";
  await get("run").emit("click");
  assert.match(get("status").textContent, /1 tracked advisory checked/);
  assert.equal(get("download").disabled, false);
  assert.deepEqual(
    harness.requests.map((r) => r.url),
    ["sbom_advisories.json", "feed_archive/manifest.json"],
  );
  assert.ok(
    harness.requests.every(
      (r) => !r.options.method || r.options.method === "GET",
    ),
  );
  assert.ok(get("results").innerHTML.includes("&lt;img"));
  assert.ok(!get("results").innerHTML.includes("javascript:"));
  await get("download").emit("click");
  assert.equal(harness.downloads[0].filename, "advisoryops-sbom-report.json");
  const report = JSON.parse(await harness.blobs[0].text());
  assert.equal(report.device, "Synthetic device");
  assert.equal(report.findings[0].status, "review_required");

  assert.match(get("status").textContent, /1 component ·/);
  assert.match(get("status").textContent, /1 component with candidates/);
  assert.match(get("status").textContent, /1 advisory match requiring review/);
  for (const title of [
    "CVE-2099-10000",
    "Pump issue (CVE-2099-10000)",
    "Descriptive pump issue",
  ]) {
    harness.catalog.issues[0].title = title;
    harness.catalog.issues[0].cves = ["CVE-2099-10000", "CVE-2099-10001"];
    await get("run").emit("click");
    const html = get("results").innerHTML;
    assert.equal((html.match(/CVE-2099-10000/g) || []).length, 1);
    assert.equal((html.match(/CVE-2099-10001/g) || []).length, 1);
    assert.ok(html.includes(title));
  }

  // Input changes and failed checks cannot leave an older report available.
  state.failure = true;
  await get("run").emit("click");
  assert.match(get("status").textContent, /HTTP 503/);
  assert.equal(get("results").innerHTML, "");
  assert.equal(get("download").disabled, true);
  state.failure = false;
  state.mismatch = true;
  await get("run").emit("click");
  assert.match(get("status").textContent, /snapshots differ/);
  assert.equal(get("download").disabled, true);
  state.mismatch = false;
  await harness.importDocument({
    spdxVersion: "SPDX-2.3",
    packages: [{ name: "openssl", versionInfo: "3" }],
  });
  await get("run").emit("click");
  assert.equal(get("download").disabled, false);
  await get("device").emit("input");
  assert.equal(get("results").innerHTML, "");
  assert.equal(get("download").disabled, true);

  // A clear while a response is pending must invalidate late completions, too.
  let releaseResponse;
  state.fetchOverride = () =>
    new Promise((resolve) => {
      releaseResponse = resolve;
    });
  const pending = get("run").emit("click");
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(releaseResponse);
  await get("clear").emit("click");
  releaseResponse({ ok: true, json: async () => harness.catalog });
  await pending;
  assert.equal(get("results").innerHTML, "");
  assert.equal(get("download").disabled, true);
  assert.equal(get("device").value, "");
  assert.equal(get("file").value, "");

  state.fetchOverride = null;
  await harness.importDocument({});
  await get("run").emit("click");
  assert.match(get("status").textContent, /Check failed/);
  assert.equal(get("download").disabled, true);
  await harness.importDocument(
    documentFor("<script>untrusted inventory</script>"),
  );
  await get("run").emit("click");
  assert.ok(get("results").innerHTML.includes("&lt;script&gt;"));
  assert.ok(!get("results").innerHTML.includes("<script>"));
  harness.catalog.issues = [
    {
      issue_id: "medfusion-test",
      vendor: "Smiths Medical",
      affected_products: [
        "Smiths-Medical Medfusion 4000 Wireless Syringe Infusion Pump",
      ],
    },
  ];
  await harness.importDocument({
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components: [
      { name: "Medfusion 4000", manufacturer: { name: "Smiths-Medical" } },
    ],
  });
  await get("run").emit("click");
  assert.ok(
    get("results").innerHTML.includes(
      '<span class="badge">partial product name</span>',
    ),
  );
  await get("download").emit("click");
  const partialReport = JSON.parse(await harness.blobs.at(-1).text());
  assert.deepEqual(partialReport.findings[0].evidence_flags, [
    "partial product name",
  ]);

  console.log(
    "PASS SBOM controller: imports, privacy, escaped text, safe links, export, reset, failures and cancellation",
  );
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
