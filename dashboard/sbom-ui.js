/**
 * Browser controller for the private Device SBOM tab.
 *
 * The engine lives in sbom.js. This controller owns import state, same-origin
 * catalog reads, escaped rendering, cancellation, and user-requested downloads.
 * Inventory is held only in this closure; it is never persisted or uploaded.
 */
(function () {
  "use strict";
  const { parseSBOM, buildIndex, matchSBOM, MAX_BYTES } = window.AdvisorySBOM;
  const file = document.getElementById("sbom-file");
  if (!file) return;
  const device = document.getElementById("sbom-device"),
    run = document.getElementById("sbom-run");
  const status = document.getElementById("sbom-status"),
    results = document.getElementById("sbom-results");
  const download = document.getElementById("sbom-download"),
    clear = document.getElementById("sbom-clear");
  // Each input change invalidates the previous generation. Aborting network I/O
  // saves work; the generation check also rejects already-resolved stale reads.
  let report = null,
    generation = 0,
    pending = null;
  const escape = (value) =>
    String(value ?? "").replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
  function safeURL(value) {
    try {
      const u = new URL(value);
      return ["https:", "http:"].includes(u.protocol) ? u.href : "";
    } catch (_) {
      return "";
    }
  }
  /** All values entering these templates are escaped; links also require HTTP(S). */
  function renderFinding(finding) {
    const url = safeURL(finding.source_url);
    const versions =
      finding.advisory_version_evidence
        .map((value) =>
          typeof value === "string" ? value : JSON.stringify(value),
        )
        .join("; ") || "not provided";
    const sourceLink = url
      ? `<a href="${escape(url)}" target="_blank" rel="noopener noreferrer">Review source advisory ↗</a>`
      : "<p>No source URL provided.</p>";
    const evidenceFlags = (finding.evidence_flags || [])
      .map((flag) => `<span class="badge">${escape(flag)}</span>`)
      .join(" ");
    // Titles often equal the issue ID; CVE lists repeat it again. Keep the title
    // and show only identifiers it does not already contain, once each.
    const title = String(finding.title || "").trim();
    const titleTokens = new Set(
      title.toUpperCase().match(/[\p{L}\p{N}_-]+/gu) || [],
    );
    const identifiers = [
      ...new Set(
        [finding.issue_id, ...finding.cves]
          .filter(Boolean)
          .map((id) => String(id).trim().toUpperCase()),
      ),
    ].filter((id) => id && !titleTokens.has(id));
    const identity = [title, identifiers.join(", ")]
      .filter(Boolean)
      .map(escape)
      .join("<br>");
    return `<article class="prose-card">
      <h3>${escape(finding.component)} <span class="badge">${escape(finding.priority)}</span> ${evidenceFlags}</h3>
      <p>Installed version: ${escape(finding.installed_version || "unknown")}<br>
        ${identity}</p>
      <p>${escape(finding.evidence)}<br>
        Advisory version text: ${escape(versions)}<br>${escape(finding.limitation)}</p>
      ${sourceLink}
    </article>`;
  }

  function renderReport(report) {
    const unmatched = new Set(report.unmatched_component_indexes);
    const warnings = [
      ...report.warnings,
      ...(Number.isFinite(report.advisories_with_manufacturer_evidence)
        ? [
            `${report.advisories_with_product_evidence - report.advisories_with_manufacturer_evidence} advisories with product names lack manufacturer/product evidence needed for partial-name matches.`,
          ]
        : []),
      ...(report.vendor_evidence_checked_at
        ? [
            `Latest manufacturer evidence check ${report.vendor_evidence_checked_at}.`,
          ]
        : []),
      report.interpretation,
      `${report.advisories_without_product_evidence} advisories have no product names and cannot be matched.`,
      `Catalog published ${report.catalog_generated_at}. Checks use this snapshot; import again to recheck after updates.`,
    ];
    const visibleFindings = report.findings
      .slice(0, 200)
      .map(renderFinding)
      .join("");
    const emptyState = report.findings.length
      ? ""
      : "<p>No component candidates found in the tracked catalog. This does not establish that this device is safe.</p>";
    const overflowNotice =
      report.findings.length > 200
        ? `<p>Showing the first 200 matches. Download JSON for all ${report.findings.length} matches.</p>`
        : "";
    const inventory = report.components
      .map((component, index) => {
        const outcome = unmatched.has(index)
          ? "no tracked candidate"
          : "review required";
        return `<li>${escape(component.name)} ${escape(component.version || "(version unknown)")} — ${outcome}</li>`;
      })
      .join("");
    return `<div class="prose-card"><h3>Coverage and limitations</h3>
      <ul>${warnings.map((warning) => `<li>${escape(warning)}</li>`).join("")}</ul></div>
      <h3>Component matches — review required</h3>
      ${emptyState}${visibleFindings}${overflowNotice}
      <details><summary>Imported components (${report.components.length})</summary>
        <ul>${inventory}</ul></details>`;
  }

  /** Catalog and archive must describe one complete published snapshot. */
  async function loadCatalog(signal) {
    const response = await fetch("sbom_advisories.json", { signal: signal });
    if (!response.ok)
      throw Error(
        "Unable to load advisory catalog (HTTP " + response.status + ").",
      );
    const built = buildIndex(await response.json());
    signal.throwIfAborted();
    const manifestResponse = await fetch("feed_archive/manifest.json", {
      signal: signal,
    });
    if (!manifestResponse.ok)
      throw Error("Unable to verify full-history coverage. Retry the check.");
    const manifest = await manifestResponse.json();
    if (
      manifest.total_records !== built.catalog.total_records ||
      manifest.generated_at !== built.catalog.generated_at
    )
      throw Error(
        "Catalog and full archive snapshots differ. Retry after publication completes.",
      );
    return built;
  }

  function reset() {
    generation++;
    pending?.abort();
    pending = null;
    report = null;
    results.replaceChildren();
    status.textContent = "Choose a device SBOM to check.";
    download.disabled = true;
    run.disabled = false;
  }
  file.addEventListener("change", reset);
  device.addEventListener("input", reset);
  clear.addEventListener("click", () => {
    reset();
    file.value = "";
    device.value = "";
  });
  run.addEventListener("click", async () => {
    reset();
    const selected = file.files[0],
      token = generation;
    if (!selected) {
      status.textContent = "Choose a JSON SBOM first.";
      return;
    }
    if (selected.size > MAX_BYTES) {
      status.textContent = "SBOM exceeds the 10 MiB file limit.";
      return;
    }
    run.disabled = true;
    status.textContent =
      "Reading components and loading the full advisory catalog…";
    const controller = new AbortController();
    pending = controller;
    const timeout = setTimeout(() => controller.abort(), 60000);
    try {
      const sbom = parseSBOM(await selected.text(), device.value);
      if (token !== generation) return;
      const built = await loadCatalog(controller.signal);
      if (token !== generation) return;
      report = matchSBOM(sbom, built);
      const matched =
        report.components.length - report.unmatched_component_indexes.length;
      const count = (n, singular, plural = singular + "s") =>
        `${n.toLocaleString()} ${n === 1 ? singular : plural}`;
      status.textContent =
        `${sbom.device} · ${count(sbom.components.length, "component")} · ` +
        `${count(report.advisories_checked, "tracked advisory", "tracked advisories")} checked · ` +
        `${count(matched, "component")} with candidates · ` +
        `${count(report.findings.length, "advisory match", "advisory matches")} requiring review.`;
      results.innerHTML = renderReport(report);
      download.disabled = false;
    } catch (error) {
      if (token === generation) {
        report = null;
        results.replaceChildren();
        status.textContent =
          error.name === "AbortError"
            ? "Catalog request timed out. Retry the check."
            : "Check failed: " + error.message;
      }
    } finally {
      clearTimeout(timeout);
      if (token === generation) {
        run.disabled = false;
        pending = null;
      }
    }
  });
  download.addEventListener("click", () => {
    if (!report) return;
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(report, null, 2) + "\n"], {
        type: "application/json",
      }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "advisoryops-sbom-report.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
})();
