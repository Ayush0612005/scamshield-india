"use strict";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function loadExamples() {
  try {
    const res = await fetch("/api/v1/examples");
    const list = await res.json();
    $("chips").innerHTML = "";
    for (const ex of list) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "chip";
      b.textContent = ex.title;
      b.onclick = () => { $("msg").value = ex.text; $("channel").value = ex.channel || ""; check(); };
      $("chips").appendChild(b);
    }
  } catch (_) { /* examples are optional */ }
}

// Merge overlapping flag spans so highlighting never nests.
function mergedSpans(flags) {
  const spans = flags.map((f, i) => ({ start: f.start, end: f.end, ids: [i + 1] })).sort((a, b) => a.start - b.start);
  const out = [];
  for (const s of spans) {
    const last = out[out.length - 1];
    if (last && s.start < last.end) { last.end = Math.max(last.end, s.end); last.ids.push(...s.ids); }
    else out.push({ ...s, ids: [...s.ids] });
  }
  return out;
}

function renderHighlight(text, flags) {
  let html = "", pos = 0;
  for (const s of mergedSpans(flags)) {
    html += esc(text.slice(pos, s.start));
    html += `<mark>${esc(text.slice(s.start, s.end))}<sup>${s.ids.join(",")}</sup></mark>`;
    pos = s.end;
  }
  return html + esc(text.slice(pos));
}

function render(text, d) {
  const cls = d.verdict === "Safe" ? "safe" : d.verdict === "Suspicious" ? "suspicious" : "scam";
  $("verdict").className = "card verdict " + cls;
  $("v-label").textContent = d.verdict;
  $("v-type").textContent = d.scamType === "None" ? "No scam pattern detected" : "Scam type: " + d.scamType;
  $("v-score").textContent = d.riskScore;
  $("v-bar").style.width = d.riskScore + "%";

  $("highlighted").innerHTML = renderHighlight(text, d.redFlags);
  $("flags").innerHTML = d.redFlags.length
    ? d.redFlags.map((f, i) => `<li><span class="n">${i + 1}</span>${esc(f.reason)}<span class="src">${f.source === "ai" ? "AI" : "rule"}</span></li>`).join("")
    : "<li>No red flags found.</li>";

  $("explanation").textContent = d.explanation;
  $("citations").innerHTML = d.citations.length
    ? d.citations.map((c) => `<li><a href="${esc(c.url)}" target="_blank" rel="noopener">${esc(c.title)}</a><br><small>${esc(c.publisher)}${c.date ? ", " + esc(c.date) : ""}</small></li>`).join("")
    : "<li>No advisory needed for this message.</li>";
  $("actions").innerHTML = d.actions.map((a) => `<li>${esc(a)}</li>`).join("");

  const rows = d.ruleSignals.filter((s) => s.weight !== 0)
    .map((s) => `<tr><td>${esc(s.id)}</td><td>${esc(s.reason)}${s.text ? `<br><small>"${esc(s.text)}"</small>` : ""}</td><td class="w ${s.weight < 0 ? "neg" : ""}">${s.weight > 0 ? "+" : ""}${s.weight}</td></tr>`).join("");
  const formula = d.mode === "hybrid"
    ? `Final risk ${d.riskScore} = 0.5 x rule score ${d.ruleScore} + 0.5 x AI score ${d.llmScore} (AI verdict: ${esc(d.llmVerdict)}, model ${esc(d.model)}).`
    : `AI model unavailable or timed out, so this result uses the rule engine only: risk ${d.riskScore} = rule score ${d.ruleScore}.`;
  $("why").innerHTML = `<div class="formula">${formula} Thresholds: below 30 Safe, 30-59 Suspicious, 60+ Likely Scam. Took ${(d.latencyMs / 1000).toFixed(1)} s.</div>`
    + `<table><tr><th>Rule signal</th><th>Reason</th><th class="w">Points</th></tr>${rows || '<tr><td colspan="3">No rule signals fired.</td></tr>'}</table>`;
  $("result").classList.remove("hidden");
}

async function check() {
  const text = $("msg").value.trim();
  const btn = $("check");
  document.querySelectorAll(".err").forEach((e) => e.remove());
  if (!text) { $("msg").focus(); return; }
  btn.disabled = true; btn.textContent = "Checking...";
  try {
    const res = await fetch("/api/v1/analyze", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, channel: $("channel").value || null }),
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.message || "Request failed");
    render(text, d);
    $("result").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    const p = document.createElement("p");
    p.className = "err";
    p.textContent = e.message;
    document.querySelector(".input").appendChild(p);
  } finally {
    btn.disabled = false; btn.textContent = "Check";
  }
}

$("check").addEventListener("click", check);
$("msg").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) check(); });
loadExamples();
