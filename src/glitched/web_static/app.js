"use strict";

// Glitched robot scan UI. Talks only to the local API that served this page.

const PARTS = {
  network: "Network · Wi-Fi",
  cloud_link: "Cloud link",
  main_controller: "Main controller",
  debug_port: "Debug port",
  peripherals: "USB / serial",
  whole_robot: "Whole robot",
};
const KINDS = {
  observed: ["Seen in the scan", "A scan saw this on the robot."],
  declared: ["From your answers", "From what you told Glitched about this robot."],
  known_vulnerability: ["Known vulnerability", "A published vulnerability matches this robot's software."],
  possible: ["Untested", "Fits this robot's profile, but nothing has tested it."],
};
const SEVERITY = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
const KIND_ORDER = ["observed", "declared", "known_vulnerability", "possible"];
const STATUS = {
  open: "Open",
  fix_applied: "Fix applied",
  resolved: "Resolved",
  accepted_risk: "Accepted risk",
  not_applicable: "Not applicable",
};
const ACTIVE = new Set(["open", "fix_applied"]);

const state = { robots: [], robot: null, selected: null, detail: null, busy: false, showClosed: false, editing: null,
                scan: null, partFilter: null, showUntested: false, note: null };
const $ = (id) => document.getElementById(id);

// --- helpers -----------------------------------------------------------------

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

async function api(method, path, body) {
  const response = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });
  const data = await response.json().catch(() => ({ error: response.statusText }));
  if (!response.ok) {
    const error = new Error(data.error || `HTTP ${response.status}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

let toastTimer;
function toast(message, isError = false) {
  const node = $("toast");
  node.textContent = message;
  node.className = isError ? "toast error" : "toast";
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, isError ? 8000 : 4000);
}

function ago(iso) {
  if (!iso) return "never";
  const minutes = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.round(hours / 24)} days ago`;
}

async function waitForJob(jobId, onTick) {
  for (;;) {
    const job = await api("GET", `/api/jobs/${jobId}`);
    if (job.state !== "running") return job;
    if (onTick) onTick(job);
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
}

function handleError(error) {
  if (error.status === 409 && error.data && error.data.notice) {
    showNotice(error.data.notice);
    toast("Accept the authorized-use notice first.", true);
  } else {
    toast(error.message, true);
  }
}

// --- notice ------------------------------------------------------------------

function showNotice(text) {
  $("notice-text").textContent = text;
  $("notice").hidden = false;
}

$("notice-button").addEventListener("click", async () => {
  try {
    await api("POST", "/api/acknowledge", { accept: $("notice-accept").checked });
    $("notice").hidden = true;
    toast("Accepted. You won't be asked again.");
  } catch (error) {
    handleError(error);
  }
});

// --- loading -----------------------------------------------------------------

async function loadRobots() {
  const appState = await api("GET", "/api/state");
  if (!appState.acknowledged) showNotice(appState.notice);
  state.robots = await api("GET", "/api/robots");
  if (!state.robots.length) {
    $("empty").hidden = false;
    $("robot-view").hidden = true;
    $("scan-button").hidden = true;
    $("details-button").hidden = true;
    $("plan-button").hidden = true;
    return;
  }
  const select = $("robot-select");
  select.replaceChildren(...state.robots.map((r) =>
    el("option", { value: r.id }, r.name)));
  select.parentElement.hidden = false;  // the robot's name is the page title
  const wanted = Number(new URLSearchParams(location.hash.slice(1)).get("robot")) || state.robots[0].id;
  select.value = String(state.robots.some((r) => r.id === wanted) ? wanted : state.robots[0].id);
  await loadRobot(Number(select.value));
}

async function loadRobot(robotId, keepSelection = false) {
  const linked = Number(new URLSearchParams(location.hash.slice(1)).get("finding"));
  state.robot = await api("GET", `/api/robots/${robotId}`);
  state.robot.findings.forEach(withSeverity);
  $("empty").hidden = true;
  $("robot-view").hidden = false;
  $("scan-button").hidden = false;
  $("details-button").hidden = false;
  $("plan-button").hidden = false;
  const unreachable = state.robot.last_unreachable_at
    && (!state.robot.last_scanned_at || state.robot.last_unreachable_at > state.robot.last_scanned_at);
  $("robot-meta").textContent = `${state.robot.host} · last scanned ${ago(state.robot.last_scanned_at)}`
    + (unreachable ? ` · couldn't reach it ${ago(state.robot.last_unreachable_at)}` : "");
  const findings = state.robot.findings;
  if (!keepSelection && findings.some((f) => f.id === linked)) {
    state.selected = linked;
    keepSelection = true;
  }
  const stillThere = keepSelection && findings.some((f) => f.id === state.selected);
  if (!stillThere) {
    const first = findings.find((f) => ACTIVE.has(f.status)) || findings[0];
    state.selected = first ? first.id : null;
  }
  await select(state.selected);
}

const KIND_SEVERITY = { observed: "high", declared: "medium", known_vulnerability: "medium", possible: "low" };
function withSeverity(f) {
  if (f && !SEVERITY[f.severity]) f.severity = KIND_SEVERITY[f.kind] || "low";
  return f;
}

async function select(findingId, { toggle = false, scroll = false } = {}) {
  if (toggle && findingId === state.selected && state.detail) findingId = null;  // close the open card
  state.selected = findingId;
  if (state.robot) history.replaceState(null, "", `#robot=${state.robot.id}${findingId ? `&finding=${findingId}` : ""}`);
  state.detail = findingId ? withSeverity(await api("GET", `/api/findings/${findingId}`)) : null;
  const finding = state.robot && state.robot.findings.find((x) => x.id === findingId);
  if (finding && finding.kind === "possible") state.showUntested = true;  // its card must be visible
  render();
  if (scroll && findingId) {
    const card = document.querySelector(`[data-finding="${findingId}"]`);
    if (card) card.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
}

function render() {
  renderPanel();
  renderList();
  renderDiagram();
}

// --- the finding panel -------------------------------------------------------

const STEP_ICON = { pending: "○", running: "", not_present: "✓", confirmed: "!", inconclusive: "?" };
const STEP_WORD = { not_present: "Nothing found", confirmed: "Found", inconclusive: "Couldn't tell" };

// The scan, check by check and port by port, while it runs - then its summary.
function renderScan() {
  const scan = state.scan;
  const job = scan.job || { steps: [] };
  const done = scan.finished;
  const steps = job.steps.map((step) => {
    const outcome = step.state === "done" ? step.status : step.state;
    const icon = step.state === "running"
      ? el("span", { class: "spinner", "aria-hidden": "true" })
      : el("span", { class: `step-icon ${outcome}`, "aria-hidden": "true" }, STEP_ICON[outcome] || "○");
    return el("li", { class: `scan-step ${outcome}` },
      icon,
      el("div", {},
        el("div", { class: "scan-step-title" }, step.title,
          step.state === "done" ? el("span", { class: `scan-step-word ${outcome}` }, STEP_WORD[outcome] || "") : null),
        step.state === "running" ? el("div", { class: "muted small" }, step.activity) : null,
        step.state === "done" ? el("div", { class: "small" }, step.detail) : null,
        step.items.length ? el("ul", { class: "probe-list", "aria-label": `${step.title}: what was tried` },
          step.items.map((item) => el("li", { class: item.flag ? "flag" : "" },
            el("span", { class: "probe-label" }, item.label), el("span", {}, item.result)))) : null));
  });
  const summary = [];
  if (done && scan.error) {
    summary.push(el("p", { class: "warning-note" }, scan.error));
  } else if (done && scan.result && scan.result.unreachable) {
    summary.push(el("p", { class: "warning-note" }, `Nothing answered at ${state.robot.host} - is ${state.robot.name} `
      + "switched on, and is that the right address? This doesn't count as a scan; nothing was changed."));
  } else if (done && scan.result) {
    const c = scan.result.findings || {};
    summary.push(el("p", {}, `Done: ${c.new || 0} new, ${c.resolved || 0} resolved, ${c.reopened || 0} reopened.`));
  }
  if (job.manual) {
    summary.push(el("p", { class: "muted small" }, `${job.manual} other threats can't be checked automatically - `
      + "they're listed for you to check by hand. Nothing is sent for them."));
  }
  $("panel").replaceChildren(
    el("div", { class: "panel-head" },
      done ? el("span", { class: "status-dot resolved", "aria-hidden": "true" })
           : el("span", { class: "spinner big", "aria-hidden": "true" }),
      el("div", {}, el("h2", {}, done ? `Scanned ${state.robot.name}` : `Scanning ${state.robot.name}`),
        el("div", { class: "panel-sub" }, `${state.robot.host} · connect-only, one host`))),
    job.steps.length ? el("ol", { class: "scan-steps" }, steps)
                     : el("p", { class: "not-scanned muted" }, "Preparing the checks…"),
    el("div", { class: "scan-summary" }, ...summary,
      done ? el("button", { class: "button", type: "button", onclick: async () => {
        state.scan = null;
        await loadRobot(state.robot.id, true);
      } }, scan.result && !scan.result.unreachable ? "See findings" : "Back") : null));
}

function renderPanel() {
  const panel = $("panel");
  panel.hidden = false;
  if (state.scan) return renderScan();
  if (!state.robot.scanned) {
    const unreachable = state.robot.last_unreachable_at
      ? el("p", { class: "warning-note" }, `Last attempt ${ago(state.robot.last_unreachable_at)}: couldn't reach `
        + `${state.robot.host} - is it switched on, and is that the right address?`) : null;
    panel.replaceChildren(
      el("div", { class: "panel-head" },
        el("span", { class: "status-dot not_applicable", "aria-hidden": "true" }),
        el("div", {}, el("h2", {}, "Not scanned yet"),
          el("div", { class: "panel-sub" }, `${state.robot.name} · ${state.robot.host}`))),
      el("div", { class: "not-scanned" },
        el("p", {}, `Findings appear after ${state.robot.name}'s first scan. Before anything is sent, you'll see `
          + "exactly what the scan does - it only connects and reads; it never logs in or sends commands."),
        unreachable,
        el("button", { class: "button", type: "button", onclick: () => $("scan-button").click() }, "Scan now")));
    return;
  }
  panel.hidden = true;  // findings open as cards in the list below
}

// What an open finding card shows under its header.
function findingBody(f) {
  const [kindLabel] = KINDS[f.kind];
  const steps = el("ol", { class: "steps" },
    step(1, "Finding", [el("span", { class: "chip kind" }, kindLabel)], el("p", { class: "lead-line" }, brief(f.detail || f.title))),
    step(2, "Evidence", [],
      f.evidence ? el("pre", { class: "evidence" }, f.evidence)
                 : el("p", { class: "muted" }, evidenceFallback(f))),
    step(3, "Fix", f.status === "fix_applied" ? [el("span", { class: "chip plain" }, "Applied")] : [],
      el("p", {}, f.fix)),
  );

  // One action for what the user actually does: fix it, then check.
  const actions = el("div", { class: "actions" });
  if (f.kind === "observed") {
    if (f.status === "open") {
      actions.append(el("button", { class: "button", type: "button", onclick: () => recheck(f, true) },
        "I've fixed it - check again"));
      actions.append(el("button", { class: "linklike", type: "button", onclick: () => recheck(f, false) },
        "Just recheck"));
    } else {
      actions.append(el("button", { class: ACTIVE.has(f.status) ? "button" : "button secondary", type: "button",
        onclick: () => recheck(f, false) }, "Check again"));
    }
    actions.append(el("span", { class: "activity", id: "activity" },
      f.last_checked_at ? `Last checked ${ago(f.last_checked_at)}` : ""));
  } else {
    if (f.status === "open") {
      actions.append(el("button", { class: "button secondary", type: "button",
        onclick: () => setStatus(f, { status: "fix_applied" }) }, "Mark fix applied"));
    }
    if (f.recheck_help) actions.append(el("span", { class: "activity" }, `To confirm: ${f.recheck_help}.`));
  }
  const note = state.note && state.note.id === f.id
    ? el("p", { class: `panel-note ${state.note.tone}` }, state.note.text) : null;
  return [note, steps, actions, moreDetails(f)].filter(Boolean);
}

function step(n, label, chips, ...body) {
  return el("li", { class: "step" },
    el("span", { class: "step-num", "aria-hidden": "true" }, n),
    el("div", {}, el("div", { class: "step-label" }, label, ...chips), ...body));
}

// The first sentence or two of a long description: split only where a sentence
// really ends (not inside "1.3.11"), and skip a "X is a ... framework" opener.
function brief(text, limit = 220) {
  if (!text || text.length <= limit) return text;
  let sentences = text.split(/(?<=[a-z0-9)\]"'][.!?])\s+(?=[A-Z])/);
  if (sentences.length > 1 && /^[\w.@/+-]+ is an? /.test(sentences[0])) sentences = sentences.slice(1);
  let out = "";
  for (const sentence of sentences) {
    if (out && (out + " " + sentence).length > limit) break;
    out = out ? `${out} ${sentence}` : sentence;
  }
  return out.length > limit ? out.slice(0, limit).replace(/\s+\S*$/, "") + "…" : out;
}

function evidenceFallback(f) {
  if (f.kind === "possible") return f.detail || "Matches your robot's profile.";
  return "No evidence recorded yet - run a scan.";
}

function reference(f) {
  if (f.source === "cve") return [`${f.ref_id} (NVD)`, `https://nvd.nist.gov/vuln/detail/${f.ref_id}`];
  if (f.source === "check" || f.source === "emb3d") {
    return [`${f.ref_id} (MITRE EMB3D threat)`, `https://emb3d.mitre.org/threats/${f.ref_id}.html`];
  }
  return [`${f.ref_id} (MITRE EMB3D property)`, `https://emb3d.mitre.org/properties-list/`];
}

function moreDetails(f) {
  const note = el("input", { type: "text", placeholder: "Why? (required to accept a risk)", "aria-label": "Reason" });
  const days = el("select", { "aria-label": "Ask again after" },
    ...[30, 90, 180, 365].map((d) => el("option", { value: d, selected: d === 90 }, `${d} days`)));
  const buttons = [];
  if (f.status !== "accepted_risk") {
    buttons.push(el("button", { class: "button secondary", type: "button", onclick: () =>
      setStatus(f, { status: "accepted_risk", note: note.value.trim(), days: Number(days.value) }) }, "Accept risk"));
  }
  if (f.status !== "not_applicable") {
    buttons.push(el("button", { class: "button secondary", type: "button", onclick: () =>
      setStatus(f, { status: "not_applicable", note: note.value.trim() || null }) }, "Not applicable"));
  }
  if (!ACTIVE.has(f.status) || f.status === "fix_applied") {
    buttons.push(el("button", { class: "button secondary", type: "button", onclick: () =>
      setStatus(f, { status: "open", note: note.value.trim() || null }) }, "Reopen"));
  }
  const historyItems = f.history.map((h) =>
    el("li", {}, `${new Date(h.at).toLocaleString()} - ${h.from ? `${STATUS[h.from]} → ` : ""}${STATUS[h.to]}`
      + ` (${h.actor}${h.note ? `: ${h.note}` : ""})`));
  const [refText, refUrl] = reference(f);
  const full = f.detail && brief(f.detail) !== f.detail
    ? el("p", { class: "small full-text" }, f.detail) : null;
  return el("details", { class: "more" },
    el("summary", {}, full ? "More: full description, reference, accept risk, history"
                           : "More: reference, accept risk, history"),
    full,
    el("p", { class: "small" }, "Reference: ", el("a", { href: refUrl, target: "_blank", rel: "noreferrer" }, refText),
      ` · ${KINDS[f.kind][1]}`),
    el("div", { class: "row-actions" }, note, days, ...buttons),
    f.accepted_until && f.status === "accepted_risk"
      ? el("p", { class: "muted" }, `Accepted until ${new Date(f.accepted_until).toLocaleDateString()}.`) : null,
    el("ul", { class: "history" }, historyItems));
}

// --- actions -----------------------------------------------------------------

async function recheck(f, markFixed) {
  if (state.busy) return;
  state.busy = true;
  state.note = null;
  const buttons = document.querySelectorAll(".actions button");
  const activity = $("activity");
  try {
    if (markFixed) await api("PATCH", `/api/findings/${f.id}`, { status: "fix_applied" });
    const { job, activity: text } = await api("POST", `/api/findings/${f.id}/recheck`);
    for (const b of buttons) b.disabled = true;
    buttons[0].replaceChildren(el("span", { class: "spinner", "aria-hidden": "true" }), "Checking");
    activity.textContent = text;
    const done = await waitForJob(job);
    if (done.state === "error") throw new Error(done.error);
    const unreachable = /Nothing answered on any port/.test(done.result.detail || "");
    state.note = { id: f.id, ...(unreachable
      ? { tone: "warn", text: "Couldn't reach the robot - is it switched on? Nothing changed." }
      : done.result.to_status === "resolved" ? { tone: "good", text: "Fixed - the check passed just now." }
      : done.result.to_status === "open" || done.result.status === "confirmed"
        ? { tone: "warn", text: "Still there - the check found it again just now." }
        : { tone: "warn", text: "The check couldn't tell either way - nothing changed." }) };
    await loadRobot(state.robot.id, true);
  } catch (error) {
    handleError(error);
    render();
  } finally {
    state.busy = false;
  }
}

async function setStatus(f, body) {
  try {
    await api("PATCH", `/api/findings/${f.id}`, body);
    toast(`Marked ${STATUS[body.status].toLowerCase()}.`);
    await loadRobot(state.robot.id, true);
  } catch (error) {
    handleError(error);
  }
}

$("scan-button").addEventListener("click", () => {
  if (state.busy || !state.robot) return;
  if (!state.robot.last_scanned_at) showPlan(true);  // first scan: show exactly what will be sent
  else startScan();
});

async function showPlan(withStart) {
  try {
    const plan = await api("GET", `/api/robots/${state.robot.id}/scan-plan`);
    const body = [
      el("p", { class: "lead" }, "Scanning ", el("strong", {}, plan.name), " contacts only ",
        el("span", { class: "address" }, plan.host),
        plan.addresses.join(", ") !== plan.host ? ` (${plan.addresses.join(", ")})` : "", "."),
    ];
    if (plan.refused) {
      body.push(el("p", { class: "warning" }, "This is a public internet address that wasn't approved when the "
        + "robot was added, so a scan will refuse to run."));
    } else if (plan.public) {
      body.push(el("p", { class: "warning" }, "This is a public internet address. You confirmed you're authorized "
        + "to test it when you added the robot."));
    }
    if (plan.checks.length) {
      body.push(el("p", {}, `It runs ${plan.checks.length} passive check${plan.checks.length > 1 ? "s" : ""}, `
        + "one connection at a time:"));
      for (const check of plan.checks) {
        body.push(el("div", { class: "plan-check" },
          el("h3", {}, check.title, el("span", { class: "muted" }, ` · ${check.ref_id}`)),
          el("p", {}, check.sends)));
      }
    } else {
      body.push(el("p", {}, "This robot's profile selects no passive checks, so a scan sends nothing to it."));
    }
    if (plan.manual) {
      body.push(el("p", { class: "muted" }, `${plan.manual} other threats can't be checked passively; they're `
        + "listed for you to verify by hand, and nothing is sent for them."));
    }
    body.push(el("h3", {}, "Never sent"), el("ul", { class: "never" }, plan.never.map((line) => el("li", {}, line))));
    $("plan-body").replaceChildren(...body);
    $("plan-start").hidden = !withStart || plan.refused;
    $("plan-actions").hidden = !withStart;
    $("plan-dialog").showModal();
  } catch (error) {
    handleError(error);
  }
}

$("plan-button").addEventListener("click", () => showPlan(false));
$("plan-start").addEventListener("click", () => { $("plan-dialog").close(); startScan(); });
for (const button of document.querySelectorAll("[data-close-plan]")) {
  button.addEventListener("click", () => $("plan-dialog").close());
}

async function startScan() {
  if (state.busy || !state.robot) return;
  state.busy = true;
  const button = $("scan-button");
  try {
    const { job } = await api("POST", `/api/robots/${state.robot.id}/scans`);
    button.disabled = true;
    button.replaceChildren(el("span", { class: "spinner", "aria-hidden": "true" }), "Scanning");
    state.scan = { job: null, finished: false };
    renderScan();
    const done = await waitForJob(job, (snapshot) => { state.scan.job = snapshot; renderScan(); });
    state.scan = { job: done, finished: true, result: done.result, error: done.state === "error" ? done.error : null };
    renderScan();
    if (done.state === "error") throw new Error(done.error);
    // The summary stays on the panel until "See findings"; refresh the rest behind it.
    const keep = state.scan;
    await loadRobot(state.robot.id, true);
    state.scan = keep;
    renderScan();
  } catch (error) {
    handleError(error);
  } finally {
    state.busy = false;
    button.disabled = false;
    button.replaceChildren("Scan now");
  }
}

$("robot-select").addEventListener("change", (event) => {
  Object.assign(state, { editing: null, partFilter: null, showUntested: false, note: null });
  $("placing").hidden = true;
  loadRobot(Number(event.target.value));
});
$("show-closed").addEventListener("change", (event) => { state.showClosed = event.target.checked; renderList(); });

// --- the list (also the accessible version of the diagram) -------------------

function renderList() {
  const list = $("finding-list");
  document.querySelector(".list-head").hidden = !state.robot.scanned;
  if (!state.robot.scanned) {
    list.replaceChildren();
    return;
  }
  let findings = state.robot.findings.filter((f) => state.showClosed || ACTIVE.has(f.status));
  if (state.partFilter) findings = findings.filter((f) => f.part === state.partFilter);
  const stale = state.robot.profile_changed
    ? el("p", { class: "warning-note" }, "You've changed this robot's answers or software list since its last scan. "
      + "Findings update when you scan again.") : null;
  const filter = state.partFilter
    ? el("div", { class: "filter-chip" }, `Showing: ${partLabel(state.partFilter, state.robot.visual.labels)}`,
      el("button", { type: "button", "aria-label": "Show all parts", onclick: () => { state.partFilter = null; render(); } }, "×"))
    : null;
  $("list-title").textContent = `Findings (${findings.length})`;

  const tested = findings.filter((f) => f.kind !== "possible");
  const untested = findings.filter((f) => f.kind === "possible");
  const groups = SEVERITY_ORDER.map((sev) => [sev, tested.filter((f) => f.severity === sev)]).filter(([, g]) => g.length);
  const nodes = groups.flatMap(([sev, group]) =>
    [el("div", { class: `group-title ${sev}` }, `${SEVERITY[sev]} · ${group.length}`), ...group.map(row)]);
  if (untested.length) {
    nodes.push(el("button", { class: "untested-toggle", type: "button", "aria-expanded": String(state.showUntested),
      onclick: () => { state.showUntested = !state.showUntested; renderList(); } },
      el("span", {}, `${untested.length} untested threat${untested.length > 1 ? "s" : ""} fit this robot`),
      el("span", { class: "muted small" }, state.showUntested ? "Hide" : "Show")));
    if (state.showUntested) nodes.push(...untested.map(row));
  }
  list.replaceChildren(...[stale, filter].filter(Boolean), ...nodes);
  if (!findings.length) {
    list.append(el("p", { class: "muted" }, state.partFilter ? "Nothing open on this part."
      : "Nothing open. Tick “Show closed” to see history."));
  }
}

function row(f) {
  const open = f.id === state.selected && state.detail && state.detail.id === f.id;
  const detail = open ? state.detail : f;
  const header = el("button", {
    class: "row-head", type: "button", "aria-expanded": String(Boolean(open)),
    "aria-controls": `finding-${f.id}`, onclick: () => select(f.id, { toggle: true }),
  },
  el("span", { class: `sev-dot ${f.severity}`, "aria-hidden": "true" }),
  el("span", { class: "row-text" },
    el("span", { class: "row-title" }, detail.title),
    el("span", { class: "row-part" },
      `${SEVERITY[f.severity]} · ${partLabel(f.part, state.robot.visual.labels)} · ${STATUS[detail.status]}`)),
  open ? el("span", { class: `chip sev ${f.severity}` }, SEVERITY[f.severity]) : null,
  el("span", { class: "chevron", "aria-hidden": "true" }, open ? "▴" : "▾"));
  return el("div", { class: `row${open ? " open" : ""}`, "data-finding": f.id },
    header,
    open ? el("div", { class: "row-body", id: `finding-${f.id}`, role: "region",
      "aria-label": detail.title }, ...findingBody(detail)) : null);
}

// --- the robot picture and its parts ------------------------------------------

const PLACEABLE = ["network", "cloud_link", "main_controller", "debug_port", "peripherals"];
let libraryCache = null;

async function getLibrary() {
  if (!libraryCache) libraryCache = await api("GET", "/api/library");
  return libraryCache;
}

function partLabel(part, labels) {
  return (labels && labels[part]) || PARTS[part] || part;
}

function creditText(credit) {
  return `Photo: ${credit.author || "unknown"} · ${credit.license}`;
}

function pictureSrc(visual) {
  if (visual.source === "upload") return `/api/robots/${state.robot.id}/image?v=${visual.image_version}`;
  return `/library/${visual.file || `photos/${visual.template}.jpg`}`;
}

function renderDiagram() {
  const visual = state.editing || state.robot.visual;
  const image = $("robot-image");
  const src = pictureSrc(state.robot.visual);
  if (image.getAttribute("src") !== src) image.src = src;
  image.alt = state.robot.visual.source === "upload" ? `Photo of ${state.robot.name}` : `Drawing of ${state.robot.name}`;
  // Library renders are transparent and sit on the page; uploaded photos get a frame.
  $("stage").classList.toggle("photo", state.robot.visual.source === "upload");
  const credit = state.robot.visual.source === "library" ? state.robot.visual.credit : null;
  $("picture-credit").replaceChildren(...(credit ? [
    "Photo: ", credit.author || "unknown", " · ",
    el("a", { href: credit.license_url || credit.source, target: "_blank", rel: "noreferrer" }, credit.license),
    " · ", el("a", { href: credit.source, target: "_blank", rel: "noreferrer" }, "source"),
  ] : []));
  $("stage").classList.toggle("placing", Boolean(state.editing));

  // Open and fix-applied counts per part ("possible" threats are untested and don't light up parts).
  const counts = {};
  const fixed = {};
  const worst = {};
  for (const f of state.robot.findings) {
    if (f.kind === "possible") continue;
    if (f.status === "open") {
      counts[f.part] = (counts[f.part] || 0) + 1;
      if (!worst[f.part] || SEVERITY_ORDER.indexOf(f.severity) < SEVERITY_ORDER.indexOf(worst[f.part])) {
        worst[f.part] = f.severity;
      }
    }
    if (f.status === "fix_applied") fixed[f.part] = (fixed[f.part] || 0) + 1;
  }
  const selectedPart = state.detail ? state.detail.part : null;

  const nodes = [];
  for (const part of PLACEABLE) {
    const position = visual.anchors[part];
    if (!position) continue;
    const [x, y] = position;
    const open = counts[part] || 0;
    const applied = fixed[part] || 0;
    const name = partLabel(part, visual.labels);
    const editing = Boolean(state.editing);
    const classes = ["anchor", open ? `hot ${worst[part]}` : "", !open && applied ? "fixed" : "",
      !editing && selectedPart === part ? "selected" : "", editing ? "editing" : "",
      editing && state.editing.active === part ? "active" : ""];
    const target = state.robot.findings.find((f) => f.part === part && ACTIVE.has(f.status) && f.kind !== "possible")
      || state.robot.findings.find((f) => f.part === part && ACTIVE.has(f.status))
      || state.robot.findings.find((f) => f.part === part);
    const button = el("button", {
      class: classes.filter(Boolean).join(" "), type: "button",
      "aria-label": editing ? `${name}: selected for moving`
        : `${name}: ${open} open${worst[part] ? ` (worst: ${SEVERITY[worst[part]]})` : ""}`
          + `${applied ? `, ${applied} fix applied` : ""}. Shows this part's findings.`,
      "aria-pressed": editing ? null : String(state.partFilter === part),
      onclick: (event) => {
        event.stopPropagation();
        if (state.editing) { state.editing.active = part; renderPlacing(); renderDiagram(); }
        else {
          state.partFilter = state.partFilter === part ? null : part;  // click again to show everything
          if (target && state.partFilter) select(target.id, { scroll: true }); else render();
        }
      },
    }, open > 1 ? el("span", { class: "badge", "aria-hidden": "true" }, open) : null);
    button.style.left = `${x * 100}%`;
    button.style.top = `${y * 100}%`;
    const tag = el("span", { class: `tag${x > 0.62 ? " left" : ""}${open ? " hot" : ""}`, "aria-hidden": "true" }, name);
    tag.style.left = `${x * 100}%`;
    tag.style.top = `${y * 100}%`;
    nodes.push(tag, button);
  }
  $("overlay").replaceChildren(...nodes);
  placeTags();

  // Findings on parts that aren't on the picture (and whole-robot ones) are still in the list.
  const missing = PLACEABLE.filter((part) => !visual.anchors[part] && (counts[part] || fixed[part]));
  const whole = (counts.whole_robot || 0) + (fixed.whole_robot || 0);
  const notes = [];
  if (missing.length) notes.push(`Not on the picture: ${missing.map((p) => partLabel(p, visual.labels)).join(", ")} - use “Edit parts” to place them.`);
  if (whole) notes.push(`${whole} finding${whole > 1 ? "s" : ""} for the whole robot - see the list.`);
  $("unplaced").textContent = notes.join(" ");
  $("unplaced").hidden = state.editing || !notes.length;
}

// Put each label beside its part without covering another label: try the
// preferred side, then the other side, then shift it down until it's clear.
function placeTags() {
  const stage = $("stage").getBoundingClientRect();
  // Labels avoid each other and every part's marker, but stay next to their own marker:
  // try both sides, nudged up or down by at most about a line; otherwise sit unshifted.
  const placed = [...$("overlay").querySelectorAll(".anchor")].map((a) => a.getBoundingClientRect());
  const overlaps = (a, b) => a.left < b.right + 4 && b.left < a.right + 4 && a.top < b.bottom + 2 && b.top < a.bottom + 2;
  const shifts = [0, -14, 14, -26, 26];
  for (const tag of $("overlay").querySelectorAll(".tag")) {
    const preferLeft = tag.classList.contains("left");
    let fit = null;
    for (const shift of shifts) {
      for (const left of [preferLeft, !preferLeft]) {
        tag.classList.toggle("left", left);
        tag.style.marginTop = `${shift}px`;
        const box = tag.getBoundingClientRect();
        const inside = box.left >= stage.left - 4 && box.right <= stage.right + 4;
        if (inside && !placed.some((other) => overlaps(box, other))) {
          fit = box;
          break;
        }
      }
      if (fit) break;
    }
    if (!fit) {
      tag.classList.toggle("left", preferLeft);
      tag.style.marginTop = "0px";
      fit = tag.getBoundingClientRect();
    }
    placed.push(fit);
  }
}

window.addEventListener("resize", () => { if (state.robot) placeTags(); });
$("robot-image").addEventListener("load", () => { $("stage").classList.remove("broken"); placeTags(); });
$("robot-image").addEventListener("error", () => {
  $("stage").classList.add("broken");
  $("unplaced").hidden = false;
  $("unplaced").textContent = "The robot's picture didn't load - choose it again with “Change picture”. "
    + "(If you just updated Glitched, restart `glitched ui`.)";
});

// Clicking the picture places the active part (while editing).
$("stage").addEventListener("click", (event) => {
  if (!state.editing || !state.editing.active) return;
  const box = $("robot-image").getBoundingClientRect();
  const x = Math.min(1, Math.max(0, (event.clientX - box.left) / box.width));
  const y = Math.min(1, Math.max(0, (event.clientY - box.top) / box.height));
  state.editing.anchors[state.editing.active] = [Number(x.toFixed(4)), Number(y.toFixed(4))];
  // Move on to the next part that isn't placed yet.
  const next = PLACEABLE.find((part) => !state.editing.anchors[part]);
  if (next) state.editing.active = next;
  renderPlacing();
  renderDiagram();
});

document.addEventListener("keydown", (event) => {
  if (!state.editing || !state.editing.active) return;
  const position = state.editing.anchors[state.editing.active];
  const moves = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] };
  if (!position || !moves[event.key] || event.target.tagName === "INPUT") return;
  event.preventDefault();
  const step = event.shiftKey ? 0.05 : 0.01;
  const [dx, dy] = moves[event.key];
  position[0] = Math.min(1, Math.max(0, Number((position[0] + dx * step).toFixed(4))));
  position[1] = Math.min(1, Math.max(0, Number((position[1] + dy * step).toFixed(4))));
  renderDiagram();
});

function startEditing(message) {
  const visual = state.robot.visual;
  state.editing = {
    anchors: JSON.parse(JSON.stringify(visual.anchors || {})),
    labels: { ...(visual.labels || {}) },
    active: PLACEABLE.find((part) => !(visual.anchors || {})[part]) || PLACEABLE[0],
  };
  $("placing-help").replaceChildren(el("strong", {}, message || "Place the parts."),
    " Pick a part, then click where it is on the picture. Arrow keys nudge it (Shift for bigger steps).");
  $("placing").hidden = false;
  renderPlacing();
  renderDiagram();
}

function stopEditing() {
  state.editing = null;
  $("placing").hidden = true;
  renderDiagram();
}

function renderPlacing() {
  const editing = state.editing;
  $("placing-parts").replaceChildren(...PLACEABLE.map((part) => {
    const placed = Boolean(editing.anchors[part]);
    const label = el("input", { type: "text", value: editing.labels[part] || "", placeholder: PARTS[part],
      "aria-label": `Name for ${PARTS[part]}`, maxlength: 40,
      oninput: (event) => { editing.labels[part] = event.target.value; renderDiagram(); } });
    return el("div", { class: "part-row" },
      el("button", { class: "button secondary small pick", type: "button", "aria-pressed": String(editing.active === part),
        onclick: () => { editing.active = part; renderPlacing(); renderDiagram(); } },
        placed ? (editing.active === part ? "Moving…" : "Move") : (editing.active === part ? "Click picture" : "Place")),
      label,
      placed ? el("button", { class: "linklike", type: "button",
        onclick: () => { delete editing.anchors[part]; renderPlacing(); renderDiagram(); } }, "Remove") : el("span"));
  }));
}

$("edit-parts").addEventListener("click", () => (state.editing ? stopEditing() : startEditing()));
$("placing-cancel").addEventListener("click", stopEditing);
$("placing-save").addEventListener("click", async () => {
  try {
    state.robot.visual = await api("PUT", `/api/robots/${state.robot.id}/visual`,
      { anchors: state.editing.anchors, labels: state.editing.labels });
    toast("Parts saved.");
    stopEditing();
  } catch (error) {
    handleError(error);
  }
});

// --- choosing a picture --------------------------------------------------------

$("change-picture").addEventListener("click", async () => {
  try {
    const templates = await getLibrary();
    const current = state.robot.visual.source === "library" ? state.robot.visual.template : null;
    $("picker-grid").replaceChildren(...templates.map((t) =>
      el("button", { class: "template", type: "button", "aria-current": String(t.id === current),
        onclick: () => chooseTemplate(t.id) },
      el("img", { src: `/library/${t.file}`, alt: "" }),
      el("strong", {}, t.name),
      el("span", { class: "hint" }, t.hint),
      t.credit ? el("span", { class: "credit" }, creditText(t.credit)) : null)));
    $("picker").showModal();
  } catch (error) {
    handleError(error);
  }
});
$("picker-close").addEventListener("click", () => $("picker").close());

async function chooseTemplate(templateId) {
  try {
    state.robot.visual = await api("PUT", `/api/robots/${state.robot.id}/visual`, { template: templateId });
    $("picker").close();
    stopEditing();
    toast("Picture changed. Use “Edit parts” to adjust where the parts are.");
  } catch (error) {
    handleError(error);
  }
}

$("upload-input").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file) return;
  if (!["image/png", "image/jpeg", "image/webp"].includes(file.type)) {
    toast("Choose a PNG, JPEG or WebP photo.", true);
    return;
  }
  if (file.size > 8 * 1024 * 1024) {
    toast("That photo is larger than 8 MB - choose a smaller one.", true);
    return;
  }
  try {
    const response = await fetch(`/api/robots/${state.robot.id}/image`, {
      method: "POST", headers: { "Content-Type": file.type }, body: file, credentials: "same-origin",
    });
    const data = await response.json();
    if (!response.ok) throw Object.assign(new Error(data.error || "Upload failed"), { status: response.status });
    state.robot.visual = data;
    $("picker").close();
    startEditing("Photo uploaded - now show where each part is.");
  } catch (error) {
    handleError(error);
  }
});

// --- adding a robot / editing its answers ------------------------------------

let questionsCache = null;
let formMode = "add";

async function openRobotForm(mode) {
  formMode = mode;
  const form = $("robot-form-body");
  form.reset();
  for (const input of form.querySelectorAll("[aria-invalid]")) input.removeAttribute("aria-invalid");
  $("form-error").hidden = true;
  $("public-row").hidden = true;
  try {
    questionsCache = questionsCache || await api("GET", "/api/questions");
    const templates = await getLibrary();
    const current = mode === "edit"
      ? await api("GET", `/api/robots/${state.robot.id}/profile`)
      : { platforms: [], interfaces: [], answers: {}, components: [] };

    $("form-title").textContent = mode === "edit" ? `About ${state.robot.name}` : "Add a robot";
    $("form-submit").textContent = mode === "edit" ? "Save answers" : "Add robot";
    $("basics").hidden = mode === "edit";
    $("picture-fieldset").hidden = mode === "edit";
    for (const input of $("basics").querySelectorAll("input[required]")) input.required = mode === "add";

    $("form-pictures").replaceChildren(
      pictureChoice("", "Pick for me", null, true),
      ...templates.map((t) => pictureChoice(t.id, t.name, `/library/${t.file}`, false)));
    $("form-platforms").replaceChildren(...Object.entries(questionsCache.platforms).map(([key, label]) =>
      chipCheck("platform", key, label, current.platforms.includes(key))));
    form.elements.ros_distro.replaceChildren(el("option", { value: "" }, "Not sure"),
      ...questionsCache.ros_distros.map((d) => el("option", { value: d.id, selected: d.id === current.ros_distro }, d.label)));
    updateRosDistro();
    $("form-interfaces").replaceChildren(...Object.entries(questionsCache.interfaces).map(([key, label]) =>
      chipCheck("interface", key, label, current.interfaces.includes(key))));
    $("form-questions").replaceChildren(...questionsCache.questions.map((q) => questionRow(q, current.answers)));
    updateFollowups();

    const components = current.components || [];
    $("form-components").hidden = !components.length;
    $("form-components").textContent = components.length
      ? `${components.length} components already listed. A new SBOM adds to them.` : "";
    $("robot-form").showModal();
    if (mode === "add") form.elements.name.focus();
  } catch (error) {
    handleError(error);
  }
}

function pictureChoice(value, label, src, checked) {
  return el("label", { class: "mini" },
    el("input", { type: "radio", name: "template", value, checked }),
    src ? el("img", { src, alt: "" }) : el("span", { class: "hint" }, "Chosen from what it's built on"),
    el("span", {}, label));
}

function chipCheck(group, key, label, checked) {
  return el("label", { class: "chip-check" },
    el("input", { type: "checkbox", "data-group": group, value: key, checked }), label);
}

function questionRow(question, answers) {
  const box = el("input", { type: "checkbox", "data-question": question.key, checked: Boolean(answers[question.key]),
    onchange: updateFollowups });
  const row = el("div", { class: "question-wrap" },
    el("label", { class: "question" }, box, el("span", {}, question.prompt)));
  if (question.followups.length) {
    row.append(el("div", { class: "followups", "data-parent": question.key },
      ...question.followups.map((f) => questionRow(f, answers))));
  }
  return row;
}

function updateRosDistro() {
  const ros = document.querySelector('#robot-form input[data-group="platform"][value="ros"]');
  $("ros-distro-row").hidden = !(ros && ros.checked);
}
$("form-platforms").addEventListener("change", updateRosDistro);

function updateFollowups() {
  for (const group of document.querySelectorAll("#form-questions .followups")) {
    const parent = document.querySelector(`#form-questions input[data-question="${group.dataset.parent}"]`);
    group.hidden = !parent.checked;
  }
  const network = document.querySelector('#form-questions input[data-question="network"]');
  $("form-interfaces-wrap").hidden = !(network && network.checked);
}

function formAnswers() {
  const answers = {};
  for (const box of document.querySelectorAll("#form-questions input[data-question]")) {
    // A follow-up only counts if every question above it was answered yes.
    const hidden = box.closest(".followups[hidden]");
    answers[box.dataset.question] = box.checked && !hidden;
  }
  const checked = (group) => [...document.querySelectorAll(`#robot-form input[data-group="${group}"]:checked`)]
    .map((box) => box.value);
  return { answers, platforms: checked("platform"),
           interfaces: $("form-interfaces-wrap").hidden ? [] : checked("interface"),
           ros_distro: $("ros-distro-row").hidden ? null : ($("robot-form-body").elements.ros_distro.value || null) };
}

function formError(error) {
  const box = $("form-error");
  box.textContent = error.message;
  box.hidden = false;
  const data = error.data || {};
  if (data.code === "public_address") $("public-row").hidden = false;
  if (data.field) {
    const input = $("robot-form-body").elements[data.field];
    if (input) {
      input.setAttribute("aria-invalid", "true");
      input.focus();
    }
  }
  if (error.status === 409 && data.notice) showNotice(data.notice);
}

async function uploadSbom(robotId, file) {
  const response = await fetch(`/api/robots/${robotId}/sbom`, {
    method: "POST", headers: { "Content-Type": file.type || "application/octet-stream" }, body: file,
    credentials: "same-origin" });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(`Software list: ${data.error || response.statusText}`), { data });
  return data;
}

$("robot-form-body").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  for (const input of form.querySelectorAll("[aria-invalid]")) input.removeAttribute("aria-invalid");
  $("form-error").hidden = true;
  const submit = $("form-submit");
  submit.disabled = true;
  const pasted = form.elements.packages.value.trim();
  const sbom = form.elements.sbom.files[0] || (pasted ? new Blob([pasted], { type: "text/plain" }) : null);
  try {
    let robotId;
    if (formMode === "add") {
      const created = await api("POST", "/api/robots", {
        name: form.elements.name.value.trim(),
        host: form.elements.host.value.trim(),
        authorization: form.elements.authorization.value.trim(),
        every_hours: Number(form.elements.every_hours.value) || 24,
        allow_public: form.elements.allow_public.checked,
        template: form.elements.template.value || null,
        ...formAnswers(),
      });
      robotId = created.id;
    } else {
      robotId = state.robot.id;
      await api("PUT", `/api/robots/${robotId}/profile`, formAnswers());
    }
    let note = "";
    if (sbom) {
      const result = await uploadSbom(robotId, sbom);
      note = ` Software list: ${result.components} packages.`;
    }
    $("robot-form").close();
    if (formMode === "add") {
      history.replaceState(null, "", `#robot=${robotId}`);
      await loadRobots();
      toast(`Added ${form.elements.name.value.trim()}.${note} Press “Scan now” to check it.`);
    } else {
      await loadRobot(robotId, true);
      toast(`Saved.${note} Findings update at the next scan.`);
    }
  } catch (error) {
    formError(error);
  } finally {
    submit.disabled = false;
  }
});

for (const button of document.querySelectorAll("#robot-form [data-close]")) {
  button.addEventListener("click", () => $("robot-form").close());
}
$("add-button").addEventListener("click", () => openRobotForm("add"));
$("empty-add").addEventListener("click", () => openRobotForm("add"));
$("details-button").addEventListener("click", () => openRobotForm("edit"));

loadRobots().catch(handleError);

// The More menu closes after choosing something, and on Escape or a click elsewhere.
for (const item of document.querySelectorAll("#more-menu .menu-item")) {
  item.addEventListener("click", () => { $("more-menu").open = false; });
}
document.addEventListener("click", (event) => {
  if (!$("more-menu").contains(event.target)) $("more-menu").open = false;
});
document.addEventListener("keydown", (event) => { if (event.key === "Escape") $("more-menu").open = false; });
