/**
 * SBOM inventory reader and advisory candidate matcher.
 *
 * Pure, dependency-free functions shared by the dashboard and Node tests. This
 * module never reads files, fetches data, renders HTML, or stores inventory.
 * Matching intentionally stops at product identity: the published feed does not
 * provide trustworthy per-component version applicability. See docs/sbom.md.
 */
(function (root) {
  "use strict";
  const MAX_BYTES = 10 * 1024 * 1024;
  const MAX_COMPONENTS = 10000;
  const MAX_FINDINGS = 100000;
  const text = (value) => (typeof value === "string" ? value.trim() : "");
  const norm = (value) =>
    text(value)
      .toLowerCase()
      .replace(/[_\-./]+/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  // Legal suffixes are identity noise; keep product normalization separate.
  function vendorNorm(value) {
    let vendor = norm(value).replace(/,/g, "").trim();
    vendor = vendor
      .replace(
        /(?:\s+(?:inc|incorporated|llc|corp|corporation|ltd|limited|co|company|plc|llp))+$/,
        "",
      )
      .trim();
    // ASD is Smiths Medical's source-record division name, not a generic suffix.
    if (vendor === "smiths medical asd") vendor = "smiths medical";
    return vendor;
  }
  const list = (value) => (Array.isArray(value) ? value : []);
  const generic = new Set([
    "server",
    "client",
    "core",
    "library",
    "software",
    "system",
    "application",
    "runtime",
    "unknown",
    "noassertion",
  ]);
  function usable(value) {
    return !!value && !["NOASSERTION", "NONE"].includes(value);
  }
  function purl(value) {
    const m = text(value).match(
      /^pkg:([a-z][a-z0-9.+-]*)\/([^?#]+)(?:\?[^#]*)?(?:#.*)?$/,
    );
    if (!m) return null;
    try {
      const at = m[2].lastIndexOf("@");
      const path = at > 0 ? m[2].slice(0, at) : m[2];
      const parts = path.split("/").map(decodeURIComponent);
      if (parts.some((x) => !x)) return null;
      return {
        name: parts.pop(),
        namespace: parts.join("/"),
        version: at > 0 ? decodeURIComponent(m[2].slice(at + 1)) : "",
      };
    } catch (_) {
      return null;
    }
  }
  function cpe(value) {
    const raw = text(value);
    const parts = raw.match(/(?:\\.|[^:])+/g);
    if (!parts || raw.includes("::")) return null;
    let part, vendor, name, version;
    if (raw.startsWith("cpe:2.3:") && parts.length === 13) {
      [part, vendor, name, version] = parts.slice(2, 6);
    } else if (raw.startsWith("cpe:/") && parts.length >= 4) {
      part = parts[1].slice(1);
      [vendor, name, version] = parts.slice(2, 5);
    } else return null;
    if (!["a", "o", "h"].includes(part)) return null;
    try {
      const decode = (v) => decodeURIComponent(v || "").replace(/\\(.)/g, "$1");
      return {
        vendor: decode(vendor),
        name: decode(name),
        version: decode(version),
      };
    } catch (_) {
      return null;
    }
  }
  /**
   * Read supported inventory fields, retaining raw identities and uncertainty.
   * A string is UTF-8 size checked before JSON parsing. Object input supports
   * programmatic callers and tests; it still observes the component limit.
   * @param {string|object} input CycloneDX or SPDX JSON document.
   * @param {string} [device] Local asset label; overrides document metadata.
   * @returns {{device: string, format: string, components: object[], warnings: string[], skipped_entries: number}}
   * @throws {Error} Unsupported/empty document or a resource limit is exceeded.
   */
  function parseSBOM(input, device) {
    if (
      typeof input === "string" &&
      new TextEncoder().encode(input).byteLength > MAX_BYTES
    ) {
      throw Error("SBOM exceeds the 10 MiB file limit.");
    }
    const doc =
      typeof input === "string"
        ? JSON.parse(input.replace(/^\uFEFF/, ""))
        : input;
    if (!doc || typeof doc !== "object" || Array.isArray(doc))
      throw Error("Choose a CycloneDX or SPDX JSON document.");
    let format, entries, suggestedDevice;
    if (
      doc.bomFormat === "CycloneDX" &&
      /^1\.[2-7]$/.test(text(doc.specVersion))
    ) {
      if (doc.components !== undefined && !Array.isArray(doc.components))
        throw Error("CycloneDX components must be an array.");
      format = "CycloneDX " + doc.specVersion;
      suggestedDevice = text(doc.metadata?.component?.name);
      entries = list(doc.components).slice();
      if (doc.metadata?.component) entries.unshift(doc.metadata.component);
    } else if (/^SPDX-2\.[23]$/.test(text(doc.spdxVersion))) {
      if (!Array.isArray(doc.packages))
        throw Error("SPDX packages must be an array.");
      format = doc.spdxVersion;
      suggestedDevice = text(doc.name);
      entries = doc.packages.slice();
    } else
      throw Error(
        "Supported formats: CycloneDX 1.2–1.7 JSON and SPDX 2.2/2.3 JSON.",
      );
    const componentLimitError = () =>
      Error("SBOM exceeds the 10,000 component limit. Split it by device.");
    if (entries.length > MAX_COMPONENTS) throw componentLimitError();
    const components = [],
      warnings = [],
      seen = new Map();
    let visited = 0,
      skipped = 0;
    // Iteration avoids stack overflow on deeply nested, untrusted documents.
    for (let pos = 0; pos < entries.length; pos++) {
      const entry = entries[pos];
      if (++visited > MAX_COMPONENTS) throw componentLimitError();
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        skipped++;
        continue;
      }
      if (entry.components !== undefined && !Array.isArray(entry.components))
        throw Error("Nested components must be an array.");
      const children = list(entry.components);
      if (entries.length + children.length > MAX_COMPONENTS)
        throw componentLimitError();
      // Do not spread an untrusted array into push: that can exceed the JS
      // argument limit before our explicit component guard can run.
      for (const child of children) entries.push(child);
      const name = text(entry.name);
      if (!usable(name)) {
        skipped++;
        continue;
      }
      const refs = list(entry.externalRefs);
      const packageUrl =
        text(entry.purl) ||
        text(refs.find((r) => r?.referenceType === "purl")?.referenceLocator);
      const cpes = [
        text(entry.cpe),
        ...refs
          .filter((r) => ["cpe22Type", "cpe23Type"].includes(r?.referenceType))
          .map((r) => text(r.referenceLocator)),
      ].filter(Boolean);
      const pv = purl(packageUrl);
      if (packageUrl && !pv)
        warnings.push(name + ": unrecognized PURL; using declared name.");
      if (cpes.some((v) => !cpe(v)))
        warnings.push(name + ": unrecognized CPE; using declared name.");
      const declaredVersion = text(entry.version) || text(entry.versionInfo);
      const cpeVersions = [
        ...new Set(
          cpes
            .map(cpe)
            .filter(Boolean)
            .map((c) => c.version)
            .filter((v) => v && !/[?*]/.test(v) && v !== "-"),
        ),
      ];
      const version = usable(declaredVersion)
        ? declaredVersion
        : pv?.version || (cpeVersions.length === 1 ? cpeVersions[0] : "");
      if (
        pv?.version &&
        usable(declaredVersion) &&
        pv.version !== declaredVersion
      )
        warnings.push(
          name + ": PURL and declared versions differ; verify the SBOM.",
        );
      if (cpeVersions.some((v) => v !== version))
        warnings.push(
          name +
            ": CPE versions are ambiguous or conflict with the declared version.",
        );
      const vendor = text(entry.manufacturer?.name) || text(entry.manufacturer);
      const supplier = text(entry.supplier?.name) || text(entry.supplier);
      const component = {
        name,
        version,
        vendor,
        supplier,
        purl: packageUrl,
        cpes,
        scope: text(entry.scope),
        refs: [text(entry["bom-ref"]) || text(entry.SPDXID)].filter(Boolean),
      };
      const key = JSON.stringify([
        name,
        version,
        vendor,
        packageUrl,
        cpes,
        component.scope,
      ]);
      if (seen.has(key)) seen.get(key).refs.push(...component.refs);
      else {
        seen.set(key, component);
        components.push(component);
      }
    }
    if (!components.length)
      throw Error("No named components found in this SBOM.");
    if (skipped)
      warnings.push(skipped + " entries without usable names were skipped.");
    const missing = components.filter((c) => !c.version).length;
    if (missing)
      warnings.push(missing + " components have no installed version.");
    if (components.some((c) => c.scope === "excluded"))
      warnings.push(
        "Excluded/test components are included; confirm whether they ship on the device.",
      );
    return {
      device: text(device) || suggestedDevice || "Unnamed device",
      format,
      components,
      warnings,
      skipped_entries: skipped,
    };
  }
  /**
   * Validate coverage and index product-name suffixes and vendor labels once per check.
   * Values retain the original advisory and label for an auditable match trace.
   * @param {object} catalog Published full-history identity catalog (schema v1).
   * @returns {{catalog: object, index: Map<string, object[]>, vendorProducts: Map<string, object[]>}}
   * @throws {Error} Duplicate IDs, missing records, or inconsistent coverage.
   */
  function buildIndex(catalog) {
    if (
      catalog?.version !== 1 ||
      catalog.matching_policy !== "product_identity_candidates_only" ||
      !Array.isArray(catalog.issues) ||
      catalog.total_records !== catalog.issues.length
    )
      throw Error(
        "Advisory catalog is invalid or incomplete. Retry after the next feed publication.",
      );
    const index = new Map(),
      vendorProducts = new Map(),
      ids = new Set();
    let withProducts = 0;
    for (const issue of catalog.issues) {
      if (!text(issue?.issue_id) || ids.has(issue.issue_id))
        throw Error("Advisory catalog has missing or duplicate issue IDs.");
      ids.add(issue.issue_id);
      const products = list(issue.affected_products).map(text).filter(Boolean);
      if (text(issue.kev_product)) products.push(text(issue.kev_product));
      if (products.length) withProducts++;
      const vendors = new Set(
        [issue.vendor, issue.kev_vendor].map(vendorNorm).filter(Boolean),
      );
      for (const label of new Set(products)) {
        for (const vendor of vendors) {
          if (!vendorProducts.has(vendor)) vendorProducts.set(vendor, []);
          vendorProducts.get(vendor).push({ issue, label });
        }
        const full = norm(label),
          words = full.split(" ");
        // Exact, complete trailing product names; never substring/fuzzy search.
        for (let start = 0; start < words.length; start++) {
          const key = words.slice(start).join(" ");
          if (!key || generic.has(key) || key.length < 4) continue;
          const prefix = words.slice(0, start).join(" ");
          if (!index.has(key)) index.set(key, []);
          index.get(key).push({ issue, label, prefix });
        }
      }
    }
    if (catalog.records_with_products !== withProducts)
      throw Error("Advisory catalog product coverage is inconsistent.");
    return { catalog, index, vendorProducts };
  }
  /**
   * Return review candidates, never a vulnerable/safe classification.
   * A known CPE vendor also constrains a matching declared/PURL product name,
   * so falling back to a weaker name cannot bypass available vendor evidence.
   * @param {object} sbom Inventory returned by parseSBOM.
   * @param {{catalog: object, index: Map<string, object[]>, vendorProducts: Map<string, object[]>}} built Validated index.
   * @returns {object} Versioned report with component/advisory evidence and gaps.
   */
  function matchSBOM(sbom, built) {
    const findings = [],
      unmatched = [];
    for (
      let componentIndex = 0;
      componentIndex < sbom.components.length;
      componentIndex++
    ) {
      const component = sbom.components[componentIndex];
      const cpeIdentities = component.cpes.map(cpe).filter(Boolean);
      function identityVendor(name) {
        if (component.vendor) return component.vendor;
        const vendors = [
          ...new Set(
            cpeIdentities
              .filter(
                (cp) =>
                  norm(cp.name) === norm(name) &&
                  !/[?*]/.test(cp.vendor) &&
                  cp.vendor !== "-",
              )
              .map((cp) => cp.vendor),
          ),
        ];
        return vendors.length === 1 ? vendors[0] : "";
      }
      const identities = [
        {
          name: component.name,
          vendor: identityVendor(component.name),
          via: "declared component name",
        },
      ];
      const pv = purl(component.purl);
      if (pv)
        identities.push({
          name: pv.name,
          vendor: identityVendor(pv.name),
          via: "PURL package name (ecosystem not verified)",
        });
      for (const value of component.cpes) {
        const cp = cpe(value);
        if (cp && !/[?*]/.test(cp.name) && cp.name !== "-")
          identities.push({
            name: cp.name,
            vendor:
              /[?*]/.test(cp.vendor) || cp.vendor === "-" ? "" : cp.vendor,
            via: "CPE vendor/product name",
          });
      }
      const candidates = new Map();
      for (const identity of identities) {
        const name = norm(identity.name),
          vendor = vendorNorm(identity.vendor);
        const keys = new Set([name, vendor ? vendor + " " + name : name]);
        for (const key of keys) {
          for (const hit of built.index.get(key) || []) {
            // Require an exact vendor prefix when one is provided. Supplier and
            // PURL namespace are not assumed to be the software manufacturer.
            if (vendor && hit.prefix && vendorNorm(hit.prefix) !== vendor)
              continue;
            if (vendor && !hit.prefix && norm(hit.label) === name) {
              const advisoryVendors = [hit.issue.vendor, hit.issue.kev_vendor]
                .map(vendorNorm)
                .filter(Boolean);
              if (advisoryVendors.length && !advisoryVendors.includes(vendor))
                continue;
            }
            if (!candidates.has(hit.issue.issue_id))
              candidates.set(hit.issue.issue_id, { ...hit, via: identity.via });
          }
        }
      }
      // A declared manufacturer can qualify a name embedded in a longer product
      // label. Do not broaden this rule to suppliers, PURL namespaces, or inferred
      // CPE vendors. Exact candidates above take precedence over partial evidence.
      const manufacturer = vendorNorm(component.vendor);
      const componentName = norm(component.name);
      if (
        manufacturer &&
        componentName.length >= 4 &&
        !generic.has(componentName)
      ) {
        const escapedName = componentName.replace(
          /[.*+?^${}()|[\]\\]/g,
          "\\$&",
        );
        const wholeName = new RegExp(
          `(^|[^\\p{L}\\p{N}])${escapedName}(?=$|[^\\p{L}\\p{N}])`,
          "u",
        );
        for (const hit of built.vendorProducts.get(manufacturer) || []) {
          if (
            wholeName.test(norm(hit.label)) &&
            !candidates.has(hit.issue.issue_id)
          ) {
            candidates.set(hit.issue.issue_id, {
              ...hit,
              partialProductName: true,
            });
          }
        }
      }
      if (!candidates.size) unmatched.push(componentIndex);
      for (const hit of candidates.values()) {
        if (findings.length >= MAX_FINDINGS)
          throw Error(
            "More than 100,000 candidate matches. Split the SBOM by device.",
          );
        findings.push({
          component_index: componentIndex,
          component: component.name,
          installed_version: component.version,
          issue_id: hit.issue.issue_id,
          title: hit.issue.title || hit.issue.issue_id,
          priority: hit.issue.priority || "",
          cves: list(hit.issue.cves),
          source_url: text(hit.issue.canonical_link),
          affected_product: hit.label,
          advisory_version_evidence: list(hit.issue.affected_versions),
          status: "review_required",
          evidence_flags: hit.partialProductName
            ? ["partial product name"]
            : [],
          evidence: hit.partialProductName
            ? "Partial product name match with matching manufacturer and advisory vendor: " +
              hit.label
            : "Exact normalized product-name match via " +
              hit.via +
              ": " +
              hit.label,
          limitation:
            "Installed-version applicability, package ecosystem, deployment conditions, and exploitability are not verified.",
        });
      }
    }
    findings.sort(
      (a, b) =>
        a.priority.localeCompare(b.priority) ||
        a.component.localeCompare(b.component) ||
        a.issue_id.localeCompare(b.issue_id),
    );
    return {
      version: 1,
      checked_at: new Date().toISOString(),
      device: sbom.device,
      sbom_format: sbom.format,
      catalog_generated_at: built.catalog.generated_at,
      advisories_checked: built.catalog.total_records,
      advisories_with_product_evidence: built.catalog.records_with_products,
      advisories_without_product_evidence:
        built.catalog.total_records - built.catalog.records_with_products,
      components: sbom.components,
      warnings: sbom.warnings,
      skipped_entries: sbom.skipped_entries,
      findings,
      unmatched_component_indexes: unmatched,
      interpretation:
        "Candidates require review. No match does not mean safe; only tracked advisories with usable product names can match. No version ranges are evaluated.",
    };
  }
  const api = { parseSBOM, buildIndex, matchSBOM, MAX_BYTES, MAX_COMPONENTS };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.AdvisorySBOM = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
