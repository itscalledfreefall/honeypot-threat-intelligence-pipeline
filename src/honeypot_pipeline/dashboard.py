from __future__ import annotations

import argparse
import json
from io import BytesIO
from pathlib import Path
from typing import Any

from flask import Flask, abort, render_template_string, request, send_file

from .dashboard_data import filter_records, get_record_by_id, load_dataset
from .reporting import build_markdown_report, collect_blocklist_ips, get_malicious_records, is_record_malicious

_BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }}</title>
  {% if auto_refresh_seconds %}
  <meta http-equiv="refresh" content="{{ auto_refresh_seconds }}">
  {% endif %}
  <style>
    :root {
      --bg: #f3efe6;
      --paper: #fffdf8;
      --ink: #1c1c18;
      --muted: #5f6059;
      --accent: #165d59;
      --accent-soft: #d8ebe6;
      --danger: #9d2b25;
      --warning: #9a5c11;
      --line: #d7d1c5;
      --shadow: rgba(28, 28, 24, 0.08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background:
        radial-gradient(circle at top left, rgba(22, 93, 89, 0.11), transparent 32%),
        linear-gradient(180deg, #f7f2e7 0%, var(--bg) 100%);
      color: var(--ink);
      font-family: Georgia, "Times New Roman", serif;
    }
    a { color: inherit; }
    .shell {
      max-width: 1200px;
      margin: 0 auto;
      padding: 32px 20px 56px;
    }
    .hero {
      display: grid;
      gap: 12px;
      margin-bottom: 24px;
      padding: 24px;
      border: 1px solid var(--line);
      background: linear-gradient(145deg, rgba(255,253,248,0.98), rgba(237,245,243,0.92));
      box-shadow: 0 18px 40px var(--shadow);
    }
    .eyebrow {
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-size: 12px;
      color: var(--accent);
      font-weight: 700;
    }
    h1, h2, h3 {
      margin: 0;
      font-weight: 600;
      line-height: 1.1;
    }
    h1 { font-size: 38px; }
    h2 { font-size: 24px; margin-bottom: 14px; }
    .muted { color: var(--muted); }
    .nav {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 6px;
    }
    .nav a {
      text-decoration: none;
      padding: 10px 14px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.72);
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 14px;
      margin: 20px 0 28px;
    }
    .card, .panel, .table-wrap, .detail-grid pre {
      border: 1px solid var(--line);
      background: var(--paper);
      box-shadow: 0 10px 24px var(--shadow);
    }
    .card {
      padding: 18px;
      min-height: 124px;
    }
    .card .label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
    }
    .card .value {
      margin-top: 10px;
      font-size: 36px;
      color: var(--accent);
    }
    .panel {
      padding: 18px;
      margin-bottom: 18px;
    }
    .panel ul {
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 10px;
    }
    .panel li {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      padding-bottom: 10px;
      border-bottom: 1px solid rgba(215,209,197,0.7);
    }
    .panel li:last-child { border-bottom: 0; padding-bottom: 0; }
    .table-wrap {
      overflow-x: auto;
      margin-bottom: 18px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 980px;
    }
    th, td {
      text-align: left;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }
    th {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      background: rgba(22,93,89,0.05);
    }
    tr:hover td { background: rgba(22,93,89,0.04); }
    .pill {
      display: inline-block;
      padding: 6px 10px;
      font-size: 12px;
      border-radius: 999px;
      border: 1px solid currentColor;
      color: var(--accent);
      background: var(--accent-soft);
      white-space: nowrap;
    }
    .pill.high { color: var(--danger); background: rgba(157,43,37,0.09); }
    .pill.medium { color: var(--warning); background: rgba(154,92,17,0.10); }
    .pill.low { color: var(--accent); }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
    }
    label {
      display: grid;
      gap: 6px;
      font-size: 13px;
      color: var(--muted);
    }
    input, select {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--line);
      background: #fff;
      font: inherit;
      color: var(--ink);
    }
    .actions {
      display: flex;
      gap: 10px;
      align-items: center;
      margin-top: 14px;
      flex-wrap: wrap;
    }
    .button {
      display: inline-block;
      padding: 11px 16px;
      border: 1px solid var(--accent);
      background: var(--accent);
      color: #fff;
      text-decoration: none;
      cursor: pointer;
      font: inherit;
    }
    .button.secondary {
      background: transparent;
      color: var(--accent);
    }
    .button.ghost {
      background: rgba(255,255,255,0.62);
      color: var(--ink);
      border-color: var(--line);
    }
    .stack {
      display: grid;
      gap: 6px;
    }
    .code {
      font-family: "SFMono-Regular", Consolas, monospace;
      font-size: 12px;
      color: var(--muted);
    }
    .detail-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 18px;
    }
    pre {
      margin: 0;
      padding: 18px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: 13px;
      line-height: 1.45;
      font-family: "SFMono-Regular", Consolas, monospace;
    }
    .kv {
      display: grid;
      gap: 10px;
    }
    .kv .row {
      display: flex;
      justify-content: space-between;
      gap: 14px;
      padding-bottom: 10px;
      border-bottom: 1px solid rgba(215,209,197,0.7);
    }
    .kv .row:last-child {
      border-bottom: 0;
      padding-bottom: 0;
    }
    .event-meta {
      display: grid;
      gap: 10px;
      margin-bottom: 18px;
    }
    .meta-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    @media (max-width: 720px) {
      .shell { padding: 24px 14px 40px; }
      h1 { font-size: 30px; }
      table { min-width: 780px; }
    }
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <div class="eyebrow">Honeypot Intelligence Dashboard</div>
      <h1>{{ title }}</h1>
      <p class="muted">{{ subtitle }}</p>
      <nav class="nav">
        <a href="/">Overview</a>
        <a href="/events">Events</a>
      </nav>
      {% if auto_refresh_seconds %}
      <div class="muted">Auto-refresh every {{ auto_refresh_seconds }} seconds</div>
      {% endif %}
    </section>
    {{ content|safe }}
  </main>
</body>
</html>
"""

_OVERVIEW_CONTENT = """
<section class="grid">
  <article class="card">
    <div class="label">Total Events</div>
    <div class="value">{{ summary.total_events }}</div>
  </article>
  <article class="card">
    <div class="label">Unique Source IPs</div>
    <div class="value">{{ summary.unique_source_ips }}</div>
  </article>
  <article class="card">
    <div class="label">Top Attack Category</div>
    <div class="value" style="font-size: 24px;">{{ top_attack_category }}</div>
  </article>
  <article class="card">
    <div class="label">Skipped Malformed Lines</div>
    <div class="value">{{ skipped_lines }}</div>
  </article>
  <article class="card">
    <div class="label">Malicious Events</div>
    <div class="value">{{ malicious_event_count }}</div>
  </article>
  <article class="card">
    <div class="label">Blocklist Candidates</div>
    <div class="value">{{ blocklist_count }}</div>
  </article>
</section>

<section class="panel">
  <h2>Safe Action Outputs</h2>
  <div class="actions">
    <a class="button" href="/exports/blocklist.txt">Download Blocklist</a>
    <a class="button secondary" href="/exports/malicious.json">Download Malicious Records</a>
    <a class="button ghost" href="/exports/report.md">Download Markdown Report</a>
  </div>
</section>

<section class="panel">
  <h2>Recent Events</h2>
  <ul>
    {% for record in recent_records %}
      <li>
        <div>
          <div><strong>{{ record.event_type }}</strong></div>
          <div class="muted">{{ record.timestamp or "No timestamp" }} | {{ record.source_ip or "No source IP" }}</div>
          <div class="code">{{ record.command_preview or record.url or "No command / URL" }}</div>
        </div>
        <div><a href="/events/{{ record._record_id }}">View</a></div>
      </li>
    {% endfor %}
  </ul>
</section>

<section class="detail-grid">
  <div class="panel">
    <h2>Attack Categories</h2>
    <ul>
      {% for key, value in summary.by_attack_category.items() %}
        <li><span>{{ key }}</span><strong>{{ value }}</strong></li>
      {% else %}
        <li><span>No category data</span><strong>0</strong></li>
      {% endfor %}
    </ul>
  </div>
  <div class="panel">
    <h2>Protocols</h2>
    <ul>
      {% for key, value in summary.by_protocol.items() %}
        <li><span>{{ key }}</span><strong>{{ value }}</strong></li>
      {% else %}
        <li><span>No protocol data</span><strong>0</strong></li>
      {% endfor %}
    </ul>
  </div>
</section>
"""

_EVENTS_CONTENT = """
<section class="panel">
  <h2>Filters</h2>
  <form method="get">
    <div class="form-grid">
      <label>Source IP
        <input type="text" name="source_ip" value="{{ filters.source_ip }}">
      </label>
      <label>Event Type
        <select name="event_type">
          <option value="">All</option>
          {% for option in event_types %}
            <option value="{{ option }}" {% if option == filters.event_type %}selected{% endif %}>{{ option }}</option>
          {% endfor %}
        </select>
      </label>
      <label>Attack Category
        <select name="attack_category">
          <option value="">All</option>
          {% for option in attack_categories %}
            <option value="{{ option }}" {% if option == filters.attack_category %}selected{% endif %}>{{ option }}</option>
          {% endfor %}
        </select>
      </label>
      <label>Protocol
        <select name="protocol">
          <option value="">All</option>
          {% for option in protocols %}
            <option value="{{ option }}" {% if option == filters.protocol %}selected{% endif %}>{{ option }}</option>
          {% endfor %}
        </select>
      </label>
      <label>Refresh
        <select name="refresh">
          {% for option in refresh_options %}
            <option value="{{ option }}" {% if option == filters.refresh %}selected{% endif %}>
              {% if option == "0" %}Off{% else %}{{ option }}s{% endif %}
            </option>
          {% endfor %}
        </select>
      </label>
    </div>
    <div class="actions">
      <label><input type="checkbox" name="malicious_only" value="1" {% if filters.malicious_only %}checked{% endif %}> Malicious only</label>
      <button class="button" type="submit">Apply Filters</button>
      <a class="button secondary" href="/events">Reset</a>
    </div>
  </form>
</section>

<section class="panel">
  <h2>Event Log</h2>
  <p class="muted">Showing {{ records|length }} events.</p>
  <div class="actions">
    <a class="button" href="/exports/blocklist.txt?{{ export_query }}">Blocklist</a>
    <a class="button secondary" href="/exports/malicious.json?{{ export_query }}">Malicious JSON</a>
    <a class="button ghost" href="/exports/report.md?{{ export_query }}">Markdown Report</a>
  </div>
</section>

<section class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Timestamp</th>
        <th>Source IP</th>
        <th>Auth / Session</th>
        <th>Event Type</th>
        <th>Observed Command</th>
        <th>Category</th>
        <th>Protocol</th>
        <th>Threat Intel</th>
        <th>View</th>
      </tr>
    </thead>
    <tbody>
      {% for record in records %}
        <tr>
          <td>{{ record.timestamp or "-" }}</td>
          <td>{{ record.source_ip or "-" }}</td>
          <td>
            <div class="stack">
              <div>{{ record.username or "-" }} / {{ record.password or "-" }}</div>
              <div class="code">{{ record.session_id or "-" }}</div>
            </div>
          </td>
          <td>{{ record.event_type }}</td>
          <td>
            <div class="stack">
              <div>{{ record.command_preview or "-" }}</div>
              <div class="code">{{ record.url or "" }}</div>
            </div>
          </td>
          <td>
            {% set category = record.classification.attack_category if record.classification else "unknown" %}
            {% set severity = record.classification.severity if record.classification else "low" %}
            <span class="pill {{ severity }}">{{ category }}</span>
          </td>
          <td>{{ record.protocol or "-" }}</td>
          <td>
            {% if record.threat_intel and record.threat_intel.score %}
              {% if record.threat_intel.score.is_malicious %}
                <span class="pill high">{{ record.threat_intel.score.confidence }} risk</span>
              {% else %}
                <span class="pill low">No malicious verdict</span>
              {% endif %}
            {% else %}
              <span class="pill low">Not enriched</span>
            {% endif %}
          </td>
          <td><a href="/events/{{ record._record_id }}">Open</a></td>
        </tr>
      {% else %}
        <tr>
          <td colspan="9">No events matched the current filters.</td>
        </tr>
      {% endfor %}
    </tbody>
  </table>
</section>
"""

_DETAIL_CONTENT = """
<section class="panel">
  <div class="event-meta">
    <h2>Event Detail</h2>
    <div class="meta-row">
      <span class="pill">{{ record.event_type }}</span>
      <span class="pill {{ record.classification.severity if record.classification else 'low' }}">
        {{ record.classification.attack_category if record.classification else "unknown" }}
      </span>
      {% if record.threat_intel and record.threat_intel.score and record.threat_intel.score.is_malicious %}
        <span class="pill high">{{ record.threat_intel.score.confidence }} risk</span>
      {% endif %}
    </div>
    <p class="muted">
      {{ record.timestamp or "No timestamp" }} |
      source {{ record.source_ip or "unknown" }} |
      protocol {{ record.protocol or "unknown" }}
    </p>
  </div>
</section>

<section class="detail-grid">
  <section class="panel">
    <h2>Normalized Fields</h2>
    <div class="kv">
      <div class="row"><span>Session</span><strong>{{ record.session_id or "-" }}</strong></div>
      <div class="row"><span>Username</span><strong>{{ record.username or "-" }}</strong></div>
      <div class="row"><span>Password</span><strong>{{ record.password or "-" }}</strong></div>
      <div class="row"><span>Command</span><strong>{{ record.command or "-" }}</strong></div>
      <div class="row"><span>URL</span><strong>{{ record.url or "-" }}</strong></div>
      <div class="row"><span>Source Port</span><strong>{{ record.source_port or "-" }}</strong></div>
    </div>
  </section>
  <section class="panel">
    <h2>Indicators</h2>
    <pre>{{ indicators_json }}</pre>
  </section>
</section>

<section class="detail-grid">
  <section class="panel">
    <h2>Classification</h2>
    <pre>{{ classification_json }}</pre>
  </section>
  <section class="panel">
    <h2>Threat Intel</h2>
    <pre>{{ threat_intel_json }}</pre>
  </section>
</section>

<section class="detail-grid">
  <pre>{{ record_json }}</pre>
  <pre>{{ raw_event_json }}</pre>
</section>
"""


def _render_page(
    title: str,
    subtitle: str,
    content: str,
    auto_refresh_seconds: int | None = None,
    **context: Any,
) -> str:
    return render_template_string(
        _BASE_TEMPLATE,
        title=title,
        subtitle=subtitle,
        auto_refresh_seconds=auto_refresh_seconds,
        content=render_template_string(content, **context),
    )


def _sorted_options(records: list[dict[str, Any]], key: str) -> list[str]:
    values = {record.get(key) for record in records if isinstance(record.get(key), str) and record.get(key)}
    return sorted(values)


def _sorted_category_options(records: list[dict[str, Any]]) -> list[str]:
    values = set()
    for record in records:
        classification = record.get("classification")
        if isinstance(classification, dict):
            category = classification.get("attack_category")
            if isinstance(category, str) and category:
                values.add(category)
    return sorted(values)


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(record)
    command = normalized.get("command")
    if isinstance(command, str) and command:
        preview = command
    else:
        url = normalized.get("url")
        preview = url if isinstance(url, str) else ""
    if len(preview) > 90:
        preview = preview[:87] + "..."
    normalized["command_preview"] = preview
    return normalized


def _build_query_export(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str], str]:
    malicious_records = get_malicious_records(records)
    blocklist_ips = collect_blocklist_ips(records)
    report = build_markdown_report(records, {"total_events": len(records), "unique_source_ips": len({r.get("source_ip") for r in records if r.get("source_ip")})}, blocklist_ips)
    return malicious_records, blocklist_ips, report


def create_app(records_path: Path, summary_path: Path | None = None) -> Flask:
    app = Flask(__name__)
    app.config["RECORDS_PATH"] = records_path
    app.config["SUMMARY_PATH"] = summary_path

    def get_dataset():
        dataset = load_dataset(
            records_path=Path(app.config["RECORDS_PATH"]),
            summary_path=Path(app.config["SUMMARY_PATH"]) if app.config["SUMMARY_PATH"] else None,
        )
        dataset.records = [_normalize_record(record) for record in dataset.records]
        return dataset

    def get_refresh_seconds() -> int | None:
        refresh = request.args.get("refresh", "").strip()
        if not refresh or refresh == "0":
            return None
        try:
            seconds = int(refresh)
        except ValueError:
            return None
        return seconds if seconds > 0 else None

    @app.route("/")
    def overview() -> str:
        dataset = get_dataset()
        summary = dataset.summary
        malicious_records = get_malicious_records(dataset.records)
        blocklist_ips = collect_blocklist_ips(dataset.records)
        top_attack_category = "none"
        category_counts = summary.get("by_attack_category")
        if isinstance(category_counts, dict) and category_counts:
            top_attack_category = max(category_counts.items(), key=lambda item: item[1])[0]

        return _render_page(
            title="Overview",
            subtitle="Read-only dashboard over processed honeypot event records.",
            content=_OVERVIEW_CONTENT,
            auto_refresh_seconds=get_refresh_seconds(),
            summary=summary,
            skipped_lines=dataset.skipped_lines,
            malicious_event_count=len(malicious_records),
            blocklist_count=len(blocklist_ips),
            top_attack_category=top_attack_category,
            recent_records=dataset.records[:8],
        )

    @app.route("/events")
    def events() -> str:
        dataset = get_dataset()
        filters = {
            "source_ip": request.args.get("source_ip", "").strip(),
            "event_type": request.args.get("event_type", "").strip(),
            "attack_category": request.args.get("attack_category", "").strip(),
            "protocol": request.args.get("protocol", "").strip(),
            "refresh": request.args.get("refresh", "").strip() or "0",
            "malicious_only": request.args.get("malicious_only") == "1",
        }
        records = filter_records(
            dataset.records,
            source_ip=filters["source_ip"] or None,
            event_type=filters["event_type"] or None,
            attack_category=filters["attack_category"] or None,
            protocol=filters["protocol"] or None,
            malicious_only=filters["malicious_only"],
        )
        export_query = request.query_string.decode("utf-8")

        return _render_page(
            title="Event Log",
            subtitle="Filter normalized and enriched honeypot events without changing the underlying data.",
            content=_EVENTS_CONTENT,
            auto_refresh_seconds=get_refresh_seconds(),
            filters=filters,
            records=records,
            export_query=export_query,
            event_types=_sorted_options(dataset.records, "event_type"),
            attack_categories=_sorted_category_options(dataset.records),
            protocols=_sorted_options(dataset.records, "protocol"),
            refresh_options=["0", "3", "5", "10"],
        )

    @app.route("/events/<int:record_id>")
    def event_detail(record_id: int) -> str:
        dataset = get_dataset()
        record = get_record_by_id(dataset.records, record_id)
        if record is None:
            abort(404)

        raw_event = record.get("raw_event")
        raw_event_json = json.dumps(raw_event, ensure_ascii=True, indent=2, sort_keys=True)
        return _render_page(
            title="Event Detail",
            subtitle="Detailed inspection of a single honeypot event and its enrichment results.",
            content=_DETAIL_CONTENT,
            auto_refresh_seconds=get_refresh_seconds(),
            record=record,
            indicators_json=json.dumps(record.get("indicators", {}), ensure_ascii=True, indent=2, sort_keys=True),
            classification_json=json.dumps(record.get("classification", {}), ensure_ascii=True, indent=2, sort_keys=True),
            threat_intel_json=json.dumps(record.get("threat_intel", {}), ensure_ascii=True, indent=2, sort_keys=True),
            record_json=json.dumps(record, ensure_ascii=True, indent=2, sort_keys=True),
            raw_event_json=raw_event_json,
        )

    def get_filtered_records() -> list[dict[str, Any]]:
        dataset = get_dataset()
        return filter_records(
            dataset.records,
            source_ip=request.args.get("source_ip", "").strip() or None,
            event_type=request.args.get("event_type", "").strip() or None,
            attack_category=request.args.get("attack_category", "").strip() or None,
            protocol=request.args.get("protocol", "").strip() or None,
            malicious_only=request.args.get("malicious_only") == "1",
        )

    @app.route("/exports/blocklist.txt")
    def export_blocklist():
        records = get_filtered_records()
        blocklist_ips = collect_blocklist_ips(records)
        payload = "\n".join(blocklist_ips) + ("\n" if blocklist_ips else "")
        return send_file(
            BytesIO(payload.encode("utf-8")),
            mimetype="text/plain; charset=utf-8",
            as_attachment=True,
            download_name="blocklist.txt",
        )

    @app.route("/exports/malicious.json")
    def export_malicious_json():
        records = get_filtered_records()
        malicious_records = get_malicious_records(records)
        payload = json.dumps(
            {
                "malicious_record_count": len(malicious_records),
                "records": malicious_records,
            },
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        return send_file(
            BytesIO(payload.encode("utf-8")),
            mimetype="application/json",
            as_attachment=True,
            download_name="malicious-records.json",
        )

    @app.route("/exports/report.md")
    def export_report_markdown():
        records = get_filtered_records()
        dataset = get_dataset()
        blocklist_ips = collect_blocklist_ips(records)
        report = build_markdown_report(records, dataset.summary, blocklist_ips)
        return send_file(
            BytesIO(report.encode("utf-8")),
            mimetype="text/markdown; charset=utf-8",
            as_attachment=True,
            download_name="honeypot-report.md",
        )

    return app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a local read-only dashboard for processed honeypot records."
    )
    parser.add_argument(
        "--records-file",
        type=Path,
        required=True,
        help="Path to the processed JSONL event records file.",
    )
    parser.add_argument(
        "--summary-file",
        type=Path,
        help="Optional path to the JSON summary file generated by the pipeline.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host interface to bind the dashboard server to.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to bind the dashboard server to.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable Flask debug mode.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.records_file.exists():
        parser.error(f"Records file not found: {args.records_file}")

    app = create_app(records_path=args.records_file, summary_path=args.summary_file)
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
