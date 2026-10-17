"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { parseSBOM, buildIndex, matchSBOM } = require("../dashboard/sbom.js");
const cdx = (components) => ({
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  components,
});
const issue = (id, products, extra = {}) => ({
  issue_id: id,
  title: id,
  priority: "P1",
  affected_products: products,
  ...extra,
});
const catalog = (issues) => ({
  version: 1,
  matching_policy: "product_identity_candidates_only",
  generated_at: "2026-10-16T00:00:00Z",
  total_records: issues.length,
  records_with_products: issues.filter(
    (r) => r.affected_products?.length || r.kev_product,
  ).length,
  issues,
});
const check = (components, issues) =>
  matchSBOM(
    parseSBOM(cdx(components), "device-1"),
    buildIndex(catalog(issues)),
  );
let tests = 0;
function test(name, fn) {
  fn();
  tests++;
  console.log("PASS " + name);
}

test("nested components, root, deduplication and device association", () => {
  const doc = cdx([
    {
      name: "openssl",
      version: "1.1.1",
      components: [{ name: "zlib", version: "1.2.8" }],
    },
    { name: "openssl", version: "1.1.1" },
  ]);
  doc.metadata = { component: { name: "Scanner 12", version: "3" } };
  const parsed = parseSBOM("\uFEFF" + JSON.stringify(doc));
  assert.equal(parsed.device, "Scanner 12");
  assert.equal(parsed.components.length, 3);
  assert.equal(
    parsed.components.find((c) => c.name === "zlib").version,
    "1.2.8",
  );
});
test("SPDX versions and external references", () => {
  const parsed = parseSBOM({
    spdxVersion: "SPDX-2.3",
    name: "CT",
    packages: [
      {
        SPDXID: "SPDXRef-ssl",
        name: "openssl",
        versionInfo: "NOASSERTION",
        supplier: "Organization: Distributor",
        externalRefs: [
          {
            referenceType: "purl",
            referenceLocator: "pkg:generic/openssl@1.1.1",
          },
          {
            referenceType: "cpe23Type",
            referenceLocator: "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
          },
        ],
      },
    ],
  });
  assert.equal(parsed.components[0].version, "1.1.1");
  assert.equal(parsed.components[0].vendor, "");
  assert.equal(parsed.components[0].cpes.length, 1);
  assert.equal(parsed.components[0].refs[0], "SPDXRef-ssl");
});
test("unsupported, malformed and empty documents fail without partial inventory", () => {
  for (const doc of [
    null,
    [],
    {},
    { spdxVersion: "SPDX-3.0" },
    cdx([]),
    { ...cdx([]), components: {} },
    cdx([{ name: "x", components: {} }]),
  ])
    assert.throws(() => parseSBOM(doc));
  assert.throws(() => parseSBOM("{"));
});
test("missing versions, invalid identifiers, skipped entries and excluded scope remain visible", () => {
  const parsed = parseSBOM(
    cdx([
      null,
      {},
      { name: "openssl", purl: "pkg:broken%", cpe: "bad", scope: "excluded" },
    ]),
  );
  assert.equal(parsed.skipped_entries, 2);
  assert.equal(parsed.components[0].version, "");
  assert.equal(parsed.warnings.length, 5);
});
test("component limit applies before deduplication", () => {
  assert.throws(
    () =>
      parseSBOM(
        cdx(Array.from({ length: 10001 }, () => ({ name: "openssl" }))),
      ),
    /10,000/,
  );
});
test("exact product identity matches with explanatory evidence, version remains unverified", () => {
  const r = check(
    [{ name: "openssl", version: "9.9.9" }],
    [
      issue("CVE-1", ["OpenSSL OpenSSL"], {
        affected_versions: ["before 1.1.1"],
      }),
    ],
  );
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].status, "review_required");
  assert.deepEqual(r.findings[0].advisory_version_evidence, ["before 1.1.1"]);
  assert.equal(r.findings[0].installed_version, "9.9.9");
  assert.equal(r.unmatched_component_indexes.length, 0);
  assert.match(r.findings[0].evidence, /OpenSSL OpenSSL/);
});
test("no substring, fuzzy, title-only or summary-only matching", () => {
  const r = check(
    [{ name: "ssl" }, { name: "curl" }, { name: "server" }, { name: "log4j" }],
    [
      issue("one", ["curlish", "Super Server"], {
        title: "log4j curl ssl",
        summary: "log4j curl ssl",
      }),
    ],
  );
  assert.equal(r.findings.length, 0);
  assert.equal(r.unmatched_component_indexes.length, 4);
});
test("explicit manufacturers and CPE vendors prevent cross-vendor suffix matches", () => {
  const r = check(
    [
      { name: "log4j", manufacturer: { name: "Other" } },
      {
        name: "unhelpful label",
        cpe: "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
      },
    ],
    [issue("one", ["Apache Log4j"])],
  );
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].component_index, 1);
  assert.match(r.findings[0].evidence, /CPE/);
});
test("PURL package identity preserves installed version and declares ecosystem uncertainty", () => {
  const r = check(
    [
      {
        name: "opaque component",
        purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      },
    ],
    [issue("one", ["Apache Log4j Core"])],
  );
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].installed_version, "2.14.1");
  assert.match(r.findings[0].evidence, /ecosystem not verified/);
});
test("versions and different package scopes are not collapsed", () => {
  const p = parseSBOM(
    cdx([
      { name: "a", purl: "pkg:npm/%40one/a@1" },
      { name: "a", purl: "pkg:npm/%40two/a@1" },
      { name: "a", version: "2" },
    ]),
  );
  assert.equal(p.components.length, 3);
});
test("multi-product and KEV matches deduplicate per component/advisory", () => {
  const r = check(
    [{ name: "openssl" }],
    [issue("one", ["OpenSSL OpenSSL", "openssl"], { kev_product: "openssl" })],
  );
  assert.equal(r.findings.length, 1);
});
test("coverage includes records without product metadata and all historical candidates", () => {
  const r = check(
    [{ name: "openssl" }],
    [
      issue("old", ["OpenSSL OpenSSL"]),
      issue("new", []),
      issue("news", [], { vendor: "OpenSSL", title: "OpenSSL" }),
    ],
  );
  assert.equal(r.advisories_checked, 3);
  assert.equal(r.advisories_without_product_evidence, 2);
  assert.equal(r.findings[0].issue_id, "old");
});
test("catalog failure, duplicate IDs and coverage mismatch cannot produce a clean result", () => {
  assert.throws(() => buildIndex({ ...catalog([]), total_records: 1 }));
  assert.throws(() =>
    buildIndex(catalog([issue("same", []), issue("same", [])])),
  );
  assert.throws(() =>
    buildIndex({
      ...catalog([issue("one", ["openssl"])]),
      records_with_products: 0,
    }),
  );
});
test("actual published catalog matches expected products across the full corpus", () => {
  const data = JSON.parse(fs.readFileSync("docs/sbom_advisories.json", "utf8"));
  const index = buildIndex(data);
  const report = matchSBOM(
    parseSBOM(
      cdx([{ name: "openssl", version: "1.0.2" }]),
      "synthetic-test-device",
    ),
    index,
  );
  assert.equal(report.advisories_checked, data.total_records);
  assert.ok(data.total_records > 750);
  assert.ok(report.findings.length > 0);
  assert.ok(report.findings.every((f) => f.status === "review_required"));
});

test("known CPE vendor also gates fallback declared names", () => {
  const result = check(
    [{ name: "log4j", cpe: "cpe:2.3:a:other:log4j:2.0:*:*:*:*:*:*:*" }],
    [issue("apache-advisory", ["Apache Log4j"])],
  );
  assert.equal(result.findings.length, 0);
});

test("large nested arrays fail at the component guard rather than argument overflow", () => {
  assert.throws(
    () =>
      parseSBOM(
        cdx([
          { name: "root", components: Array(150000).fill({ name: "child" }) },
        ]),
      ),
    /10,000/,
  );
});

test("string size limit counts UTF-8 bytes", () => {
  const oversized = JSON.stringify(
    cdx([{ name: "é".repeat(6 * 1024 * 1024) }]),
  );
  assert.throws(() => parseSBOM(oversized), /10 MiB/);
});

test("SPDX NOASSERTION does not create a false version-conflict warning", () => {
  const parsed = parseSBOM({
    spdxVersion: "SPDX-2.3",
    packages: [
      {
        name: "openssl",
        versionInfo: "NOASSERTION",
        externalRefs: [
          {
            referenceType: "purl",
            referenceLocator: "pkg:generic/openssl@3.0.0",
          },
        ],
      },
    ],
  });
  assert.equal(parsed.components[0].version, "3.0.0");
  assert.deepEqual(parsed.warnings, []);
});

const medfusionLabel =
  "Smiths-Medical Medfusion 4000 Wireless Syringe Infusion Pump";
const medfusionComponent = {
  name: "Medfusion 4000",
  version: "1.5.1",
  manufacturer: { name: "Smiths Medical" },
};

test("Medfusion 4000 matches a longer product label with manufacturer evidence", () => {
  const result = check(
    [medfusionComponent],
    [
      issue("medfusion-advisory", [medfusionLabel], {
        vendor: "Smiths-Medical",
      }),
    ],
  );
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.affected_product, medfusionLabel);
  assert.deepEqual(finding.evidence_flags, ["partial product name"]);
  assert.match(finding.evidence, /Partial product name/);
  assert.equal(finding.installed_version, "1.5.1");
  assert.equal(finding.status, "review_required");
  assert.deepEqual(result.unmatched_component_indexes, []);
});

test("partial product names require a matching declared manufacturer", () => {
  const components = [
    { ...medfusionComponent, manufacturer: { name: "Other vendor" } },
    { ...medfusionComponent, manufacturer: undefined },
    {
      ...medfusionComponent,
      manufacturer: undefined,
      supplier: { name: "Smiths Medical" },
    },
    {
      ...medfusionComponent,
      manufacturer: undefined,
      cpe: "cpe:2.3:a:smiths_medical:medfusion_4000:1.5.1:*:*:*:*:*:*:*",
    },
  ];
  for (const extra of [{ vendor: "Smiths Medical" }, { vendor: "" }, {}]) {
    const result = check(components, [
      issue("medfusion-advisory", [medfusionLabel], extra),
    ]);
    assert.equal(result.findings.length, 0);
  }
});

test("partial product names use whole-word sequences rather than fragments", () => {
  const labels = [
    "Smiths Medical XMedfusion 4000 Wireless Pump",
    "Smiths Medical Medfusion 40000 Wireless Pump",
    "Smiths Medical Medfusion 4000A Wireless Pump",
    "Smiths Medical Medfusion Pro 4000 Wireless Pump",
    "Smiths Medical Medfusion 4000é Wireless Pump",
  ];
  const result = check(
    [medfusionComponent],
    labels.map((label, index) =>
      issue("near-" + index, [label], { vendor: "Smiths Medical" }),
    ),
  );
  assert.equal(result.findings.length, 0);
});

test("partial product names handle case, separators and punctuation boundaries", () => {
  const result = check(
    [medfusionComponent],
    [
      issue(
        "medfusion-advisory",
        ["SMITHS MEDICAL (MEDFUSION-4000), Wireless Pump"],
        { vendor: "SMITHS-MEDICAL" },
      ),
    ],
  );
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0].evidence_flags, ["partial product name"]);
});

test("literal regex characters in component names cannot broaden partial matches", () => {
  const component = {
    ...medfusionComponent,
    name: "Medfusion 4000 (Wireless)",
  };
  const result = check(
    [component],
    [
      issue("literal", ["Smiths Medical Medfusion 4000 (Wireless) Pump"], {
        vendor: "Smiths Medical",
      }),
      issue("not-literal", ["Smiths Medical Medfusion 4000 Wireless Pump"], {
        vendor: "Smiths Medical",
      }),
    ],
  );
  assert.deepEqual(
    result.findings.map((finding) => finding.issue_id),
    ["literal"],
  );
});

test("exact product evidence takes precedence and partial candidates do not duplicate it", () => {
  const result = check(
    [medfusionComponent],
    [
      issue(
        "medfusion-advisory",
        [medfusionLabel, "Smiths Medical Medfusion 4000"],
        { vendor: "Smiths Medical" },
      ),
    ],
  );
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0].evidence_flags, []);
  assert.match(result.findings[0].evidence, /Exact normalized/);
});

test("partial product names reject missing or mismatched advisory vendors", () => {
  for (const fields of [
    { vendor: "Other vendor" },
    { vendor: "" },
    {},
    { vendor: "Smiths Medical Devices" },
  ]) {
    const result = check(
      [medfusionComponent],
      [issue("medfusion-advisory", [medfusionLabel], fields)],
    );
    assert.equal(result.findings.length, 0);
  }
});

test("partial product names accept explicit KEV vendor evidence and deduplicate labels", () => {
  const result = check(
    [medfusionComponent],
    [
      issue(
        "medfusion-advisory",
        [medfusionLabel, medfusionLabel + " System"],
        {
          vendor: "Smiths Medical",
          kev_vendor: "Smiths-Medical",
          kev_product: medfusionLabel,
          product_vendors: [
            { product: medfusionLabel, vendor: "Smiths Medical" },
          ],
        },
      ),
    ],
  );
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0].evidence_flags, ["partial product name"]);
  const kevOnly = check(
    [medfusionComponent],
    [
      issue("kev-advisory", [], {
        kev_vendor: "Smiths-Medical",
        kev_product: medfusionLabel,
      }),
    ],
  );
  assert.equal(kevOnly.findings.length, 1);
});

test("manufacturer corporate suffixes and Smiths division names normalize symmetrically", () => {
  const names = [
    "Smiths Medical",
    "Smiths-Medical",
    "Smiths Medical ASD Inc.",
    "Smiths Medical, LLC",
    "Smiths Medical Corp.",
    "Smiths Medical Ltd.",
  ];
  for (const manufacturer of names) {
    for (const vendor of names) {
      const result = check(
        [{ ...medfusionComponent, manufacturer: { name: manufacturer } }],
        [issue("medfusion", [medfusionLabel], { vendor })],
      );
      assert.equal(result.findings.length, 1, `${manufacturer} vs ${vendor}`);
    }
  }
  for (const vendor of [
    "Smiths Medical Devices Inc.",
    "Other ASD Inc.",
    "Smiths Medical Incorporated Technologies",
  ]) {
    assert.equal(
      check(
        [medfusionComponent],
        [issue("other", [medfusionLabel], { vendor })],
      ).findings.length,
      0,
    );
  }
});

test("actual published catalog returns all eight Medfusion 4000 CVEs", () => {
  const path = require("node:path");
  const published = JSON.parse(
    fs.readFileSync(
      path.join(__dirname, "../docs/sbom_advisories.json"),
      "utf8",
    ),
  );
  const result = matchSBOM(
    parseSBOM(cdx([medfusionComponent])),
    buildIndex(published),
  );
  const expected = [
    "CVE-2017-12718",
    "CVE-2017-12720",
    "CVE-2017-12721",
    "CVE-2017-12722",
    "CVE-2017-12723",
    "CVE-2017-12724",
    "CVE-2017-12725",
    "CVE-2017-12726",
  ];
  assert.ok(result.findings.length >= 8);
  for (const id of expected) {
    const finding = result.findings.find((f) => f.issue_id === id);
    assert.ok(finding, id);
    assert.equal(finding.status, "review_required");
    assert.deepEqual(finding.evidence_flags, ["partial product name"]);
  }
  const wrongManufacturer = matchSBOM(
    parseSBOM(
      cdx([{ ...medfusionComponent, manufacturer: { name: "Other Medical" } }]),
    ),
    buildIndex(published),
  );
  assert.equal(wrongManufacturer.findings.length, 0);
});

test("scoped product evidence prevents cross-vendor partial and exact matches", () => {
  const advisory = issue(
    "multi-vendor",
    ["Alpha Station Pro", "Beta Station Pro"],
    {
      vendor: "Alpha",
      product_vendors: [
        { vendor: "Alpha", product: "Alpha Station Pro" },
        { vendor: "Beta", product: "Beta Station Pro" },
      ],
    },
  );
  for (const vendor of ["Alpha", "Beta"]) {
    const result = check(
      [{ name: "Station", manufacturer: { name: vendor } }],
      [advisory],
    );
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].affected_product, `${vendor} Station Pro`);
  }
  assert.equal(
    check(
      [{ name: "Beta Station Pro", manufacturer: { name: "Alpha" } }],
      [advisory],
    ).findings.length,
    0,
  );
  assert.equal(
    check([{ name: "Station", manufacturer: { name: "Other" } }], [advisory])
      .findings.length,
    0,
  );
});

test("unbound published products cannot borrow a summary vendor", () => {
  const advisory = issue("unbound", [medfusionLabel], {
    vendor: "Smiths Medical",
    product_vendors: [],
  });
  assert.equal(check([medfusionComponent], [advisory]).findings.length, 0);
  const multi = issue(
    "legacy-multi",
    [medfusionLabel, medfusionLabel + " System"],
    { vendor: "Smiths Medical" },
  );
  assert.equal(check([medfusionComponent], [multi]).findings.length, 0);
});

test("corporate normalization retains meaningful words and division identities", () => {
  for (const manufacturer of [
    "Smiths Medical Devices Inc.",
    "Smiths Medical Incognito",
    "Smiths Medical Corporation Systems",
    "Other ASD Inc.",
    "Unknown Inc.",
  ]) {
    assert.equal(
      check(
        [{ ...medfusionComponent, manufacturer: { name: manufacturer } }],
        [issue("medfusion", [medfusionLabel], { vendor: "Smiths Medical" })],
      ).findings.length,
      0,
    );
  }
});

test("exact matches preserve the applicable product vendor evidence", () => {
  const advisory = issue("exact-scoped", ["Station"], {
    product_vendors: [
      {
        product: "Station",
        vendor: "Alpha",
        source: "https://alpha.example/advisory",
      },
      {
        product: "Station",
        vendor: "Beta",
        source: "https://beta.example/advisory",
      },
    ],
  });
  const result = check(
    [{ name: "Station", manufacturer: { name: "Beta Inc." } }],
    [advisory],
  );
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0].evidence_flags, []);
  assert.equal(result.findings[0].matched_vendor, "Beta");
  assert.equal(
    result.findings[0].vendor_evidence_source,
    "https://beta.example/advisory",
  );
  const ambiguous = check([{ name: "Station" }], [advisory]);
  assert.equal(ambiguous.findings[0].matched_vendor, "");
  assert.equal(ambiguous.findings[0].vendor_evidence_source, "");
});

// These identities come from the checked-in published corpus, not a fixture.
// Assert a specific source-bound advisory for every requested manufacturer alias.
const publishedAliases = buildIndex(
  JSON.parse(
    fs.readFileSync(
      require("node:path").join(__dirname, "../docs/sbom_advisories.json"),
      "utf8",
    ),
  ),
);
for (const [product, id, aliases] of [
  [
    "Alaris 8000",
    "CVE-2016-8375",
    [
      "BD",
      "Becton, Dickinson and Company",
      "CareFusion",
      "Becton, Dickinson and Company (BD)",
    ],
  ],
  [
    "Medical Beds",
    "CVE-2017-13077",
    ["Stryker", "Stryker Corporation", "Physio-Control"],
  ],
  [
    "2090 Carelink Programmer",
    "CVE-2018-10596",
    ["Medtronic", "Medtronic plc", "Covidien"],
  ],
  [
    "IntelliVue Information Center iX",
    "CVE-1999-0103",
    ["Philips", "Koninklijke Philips N.V."],
  ],
  [
    "Imaging and Ultrasound Products",
    "CVE-2020-25175",
    ["GE HealthCare", "GE Healthcare", "General Electric"],
  ],
  [
    "ExactaMix",
    "CVE-2017-0143",
    ["Baxter", "Baxter International", "Hillrom", "Hill-rom", "Welch Allyn"],
  ],
  [
    "Medfusion 4000",
    "CVE-2017-12718",
    ["Smiths Medical", "ICU Medical", "Smiths Medical ASD Inc."],
  ],
  [
    "Syngo Sc2000 Firmware",
    "CVE-2017-0143",
    ["Siemens Healthineers", "Siemens Healthcare", "Siemens"],
  ],
]) {
  test(`published catalog manufacturer aliases: ${aliases[0]}`, () => {
    for (const alias of aliases) {
      for (const suffix of [
        "",
        " Inc.",
        " Corp.",
        " Corporation",
        " LLC",
        " plc",
        " N.V.",
        " N.V.,",
        " L.L.C.",
        " L.L.P.,",
        " P.L.C.",
        " Ltd.",
        " Co.",
      ]) {
        const result = matchSBOM(
          parseSBOM(
            cdx([{ name: product, manufacturer: { name: alias + suffix } }]),
          ),
          publishedAliases,
        );
        const finding = result.findings.find((f) => f.issue_id === id);
        assert.ok(finding, `${alias + suffix}: ${product} -> ${id}`);
        assert.equal(finding.status, "review_required");
        if (product === "Medfusion 4000")
          assert.ok(result.findings.length >= 8);
      }
      const wrong = matchSBOM(
        parseSBOM(
          cdx([
            {
              name: product,
              manufacturer: { name: alias + " Unrelated Devices" },
            },
          ]),
        ),
        publishedAliases,
      );
      assert.ok(!wrong.findings.some((f) => f.issue_id === id), alias);
    }
  });
}

test("alias comparison is symmetric and keeps product/vendor scope", () => {
  for (const [canonical, alias] of [
    ["BD", "CareFusion"],
    ["Stryker", "Physio-Control"],
    ["Medtronic", "Covidien"],
    ["Philips", "Koninklijke Philips N.V."],
    ["GE HealthCare", "General Electric"],
    ["Baxter", "Welch Allyn"],
    ["Smiths Medical", "ICU Medical"],
    ["Siemens Healthineers", "Siemens Healthcare"],
  ]) {
    for (const [manufacturer, vendor] of [
      [canonical, alias],
      [alias, canonical],
    ]) {
      const label = "Vendor Specific Pump Model";
      const advisory = issue("alias-scoped", [label], {
        product_vendors: [
          { product: label, vendor, source: "https://example.org/advisory" },
        ],
      });
      const result = check(
        [{ name: "Specific Pump", manufacturer: { name: manufacturer } }],
        [advisory],
      );
      assert.equal(result.findings.length, 1, manufacturer + " -> " + vendor);
      assert.equal(result.findings[0].matched_vendor, vendor);
      assert.deepEqual(result.findings[0].evidence_flags, [
        "partial product name",
      ]);
      assert.equal(
        check(
          [{ name: "Specific PumpX", manufacturer: { name: manufacturer } }],
          [advisory],
        ).findings.length,
        0,
      );
    }
  }
});

console.log(tests + " SBOM behavior checks passed.");
