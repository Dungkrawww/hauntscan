/* HauntScan frontend (task 7, design §7). Plain JS, no build step.
   Talks to: POST /api/scans, POST /api/scans/demo, GET /api/scans,
   GET /api/scans/{id}, GET /api/scans/{id}/stream (SSE).
   SSE event types (design §6): log, stage, finding, done, error. */

"use strict";

const STAGES = ["discovery", "probing", "scanning", "done"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

let currentScanId = null;
let currentFindings = [];
let currentFilter = "all";
let currentScanMeta = null;
let eventSource = null;
let streamTerminated = false;

const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function showSection(id) {
  for (const section of ["section-new-scan", "section-live-scan", "section-findings", "section-history"]) {
    $(section).classList.toggle("hidden", section !== id);
  }
  $("nav-new-scan").classList.toggle("active", id === "section-new-scan");
  $("nav-history").classList.toggle("active", id === "section-history");
}

function showToast(message) {
  $("toast-message").textContent = message;
  $("toast").classList.remove("hidden");
}

function showFormError(message) {
  const el = $("form-error");
  el.textContent = message;
  el.classList.remove("hidden");
}

function clearFormError() {
  $("form-error").classList.add("hidden");
  $("form-error").textContent = "";
}

/* Extract a readable message from a FastAPI error response. */
async function apiErrorMessage(response) {
  try {
    const data = await response.json();
    const detail = data.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map((d) => d.msg || JSON.stringify(d)).join("; ");
    }
    return JSON.stringify(data);
  } catch {
    return `Request failed (HTTP ${response.status})`;
  }
}

function closeStream() {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
}

function setStage(stage) {
  const index = STAGES.indexOf(stage);
  document.querySelectorAll("#progress-bar .seg").forEach((seg, i) => {
    seg.classList.toggle("done", index >= 0 && i < index);
    seg.classList.toggle("active", i === index);
  });
}

function appendLog(message) {
  const log = $("live-log");
  log.textContent += message + "\n";
  log.scrollTop = log.scrollHeight;
}

function openLiveView(scan) {
  closeStream();
  currentScanId = scan.scan_id;
  currentScanMeta = scan;
  streamTerminated = false;
  $("live-target").textContent = scan.target;
  $("live-status").textContent = "Waking the spirits…";
  $("live-log").textContent = "";
  $("live-finding-count").textContent = "0";
  $("live-error").classList.add("hidden");
  setStage("discovery");
  showSection("section-live-scan");
  openStream(scan.scan_id);
}

function openStream(scanId) {
  eventSource = new EventSource(`/api/scans/${scanId}/stream`);
  let found = 0;

  eventSource.onmessage = (event) => {
    let data;
    try {
      data = JSON.parse(event.data);
    } catch {
      return;
    }
    if (data.type === "log") {
      appendLog(data.message || "");
    } else if (data.type === "stage") {
      setStage(data.stage);
      $("live-status").textContent = `Stage: ${data.stage}…`;
    } else if (data.type === "finding") {
      found += 1;
      $("live-finding-count").textContent = String(found);
      appendLog(`[finding] ${data.finding.severity || "?"} ${data.finding.template_id || ""} ${data.finding.matched_url || ""}`);
    } else if (data.type === "done") {
      streamTerminated = true;
      setStage("done");
      $("live-status").textContent = "The hunt is done. 🕸️";
      closeStream();
      loadFindings(scanId);
    } else if (data.type === "error") {
      streamTerminated = true;
      const message = data.message || "Scan failed";
      const err = $("live-error");
      err.textContent = `☠️ ${message}`;
      err.classList.remove("hidden");
      $("live-status").textContent = "The hunt failed.";
      showToast(message);
      closeStream();
    }
  };

  eventSource.onerror = () => {
    // The server closes the stream after replaying a finished scan, and
    // also after done/error. Only complain if no terminal event arrived.
    if (!streamTerminated) {
      $("live-status").textContent = "Stream ended — check History for the latest status.";
    }
    closeStream();
  };
}

async function loadFindings(scanId) {
  let scan;
  try {
    const response = await fetch(`/api/scans/${scanId}`);
    if (!response.ok) {
      showToast(await apiErrorMessage(response));
      return;
    }
    scan = await response.json();
  } catch (err) {
    showToast(`Could not load scan: ${err.message}`);
    return;
  }
  currentScanId = scan.scan_id;
  currentScanMeta = scan;
  currentFindings = scan.findings || [];
  currentFilter = "all";
  $("findings-target").textContent = scan.target;
  const counts = scan.finding_counts || {};
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  $("findings-meta").textContent =
    `${scan.status} · profile ${scan.profile} · ` +
    `${scan.duration_seconds != null ? `${scan.duration_seconds}s` : "still running"} · ${total} findings`;
  renderFilters(counts);
  renderFindings();
  showSection("section-findings");
}

function renderFilters(counts) {
  const container = $("severity-filters");
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const buttons = [{ sev: "all", label: `All (${total})` }].concat(
    SEVERITIES.map((sev) => ({ sev, label: `${sev} (${counts[sev] || 0})` })),
  );
  container.innerHTML = buttons.map((b) =>
    `<button type="button" class="filter-btn${currentFilter === b.sev ? " active" : ""}" data-sev="${b.sev}">${escapeHtml(b.label)}</button>`
  ).join("");
  container.querySelectorAll(".filter-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      currentFilter = btn.dataset.sev;
      renderFilters(counts);
      renderFindings();
    });
  });
}

function severityChip(severity) {
  const sev = (severity || "unknown").toLowerCase();
  return `<span class="chip chip-${escapeHtml(sev)}">${escapeHtml(sev)}</span>`;
}

function renderFindings() {
  const rows = currentFilter === "all"
    ? currentFindings
    : currentFindings.filter((f) => (f.severity || "").toLowerCase() === currentFilter);
  $("findings-empty").classList.toggle("hidden", rows.length > 0);
  $("findings-table").classList.toggle("hidden", rows.length === 0);
  $("findings-body").innerHTML = rows.map((f, i) => `
    <tr data-index="${i}">
      <td>${severityChip(f.severity)}</td>
      <td>${escapeHtml(f.template_id || f.name || "")}</td>
      <td class="url">${escapeHtml(f.matched_url || "")}</td>
      <td>${escapeHtml(f.description || "")}</td>
    </tr>`).join("");
  $("findings-body").querySelectorAll("tr").forEach((tr) => {
    tr.addEventListener("click", () => showFindingDetail(rows[Number(tr.dataset.index)]));
  });
}

function showFindingDetail(finding) {
  if (!finding) return;
  $("dialog-title").textContent = finding.name || finding.template_id || "Finding";
  const fields = [
    ["Severity", finding.severity || ""],
    ["Template ID", finding.template_id || ""],
    ["Matched URL", finding.matched_url || ""],
    ["Description", finding.description || ""],
    ["Matcher", finding.matcher_name || ""],
    ["Extracted results", Array.isArray(finding.extracted_results)
      ? finding.extracted_results.join("\n")
      : (finding.extracted_results || "")],
    ["Curl command", finding.curl_command || ""],
  ];
  $("dialog-fields").innerHTML = fields.map(([label, value]) => {
    const mono = label === "Extracted results" || label === "Curl command";
    return `<dt>${escapeHtml(label)}</dt><dd class="${mono ? "mono" : ""}">${escapeHtml(value || "—")}</dd>`;
  }).join("");
  $("finding-dialog").showModal();
}

async function loadHistory() {
  let scans;
  try {
    const response = await fetch("/api/scans");
    if (!response.ok) {
      showToast(await apiErrorMessage(response));
      return;
    }
    scans = await response.json();
  } catch (err) {
    showToast(`Could not load history: ${err.message}`);
    return;
  }
  $("history-empty").classList.toggle("hidden", scans.length > 0);
  const list = $("history-list");
  list.innerHTML = scans.map((scan) => {
    const counts = scan.finding_counts || {};
    const chips = SEVERITIES.filter((s) => counts[s]).map((s) =>
      `<span class="chip chip-${s}">${s} ${counts[s]}</span>`).join("");
    const statusIcon = scan.status === "running" ? "👻" : scan.status === "completed" ? "✅" : "☠️";
    const duration = scan.duration_seconds != null ? `${scan.duration_seconds}s` : "running…";
    const when = scan.created_at ? new Date(scan.created_at).toLocaleString() : "";
    return `<li class="history-row" data-id="${scan.scan_id}" data-status="${escapeHtml(scan.status)}">
      <span class="status status-${escapeHtml(scan.status)}">${statusIcon} ${escapeHtml(scan.status)}</span>
      <span class="history-target">${escapeHtml(scan.target)}</span>
      <span class="profile-badge">${escapeHtml(scan.profile)}</span>
      <span class="history-meta">${escapeHtml(when)} · ${escapeHtml(duration)}</span>
      <span class="count-chips">${chips}</span>
    </li>`;
  }).join("");
  list.querySelectorAll(".history-row").forEach((row) => {
    row.addEventListener("click", async () => {
      const id = Number(row.dataset.id);
      if (row.dataset.status === "running") {
        const scan = scans.find((s) => s.scan_id === id);
        if (scan) openLiveView(scan);
      } else {
        await loadFindings(id);
      }
    });
  });
  showSection("section-history");
}

async function startScan(event) {
  event.preventDefault();
  clearFormError();
  const target = $("target").value.trim();
  const profile = $("profile").value;
  const authorized = $("authorized").checked;

  if (!authorized) {
    showFormError("You must confirm you are authorized to scan this target.");
    return;
  }
  if (!target) {
    showFormError("Enter a target domain first.");
    return;
  }

  let response;
  try {
    response = await fetch("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, profile, authorized }),
    });
  } catch (err) {
    showFormError(`Could not reach the server: ${err.message}`);
    return;
  }
  if (!response.ok) {
    const message = await apiErrorMessage(response);
    showFormError(message);
    showToast(message);
    return;
  }
  const scan = await response.json();
  openLiveView(scan);
}

async function runDemo() {
  clearFormError();
  let response;
  try {
    response = await fetch("/api/scans/demo", { method: "POST" });
  } catch (err) {
    showFormError(`Could not reach the server: ${err.message}`);
    return;
  }
  if (!response.ok) {
    const message = await apiErrorMessage(response);
    showFormError(message);
    showToast(message);
    return;
  }
  const scan = await response.json();
  openLiveView(scan);
}

$("scan-form").addEventListener("submit", startScan);
$("run-demo").addEventListener("click", runDemo);
$("toast-close").addEventListener("click", () => $("toast").classList.add("hidden"));
$("nav-new-scan").addEventListener("click", () => showSection("section-new-scan"));
$("nav-history").addEventListener("click", loadHistory);
$("live-to-history").addEventListener("click", loadHistory);
$("findings-to-history").addEventListener("click", loadHistory);
$("findings-new-scan").addEventListener("click", () => showSection("section-new-scan"));

// Close the detail dialog when clicking its backdrop.
$("finding-dialog").addEventListener("click", (event) => {
  if (event.target === $("finding-dialog")) $("finding-dialog").close();
});
