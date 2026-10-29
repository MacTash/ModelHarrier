"""Interactive terminal workspace for ModelHarrier."""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
from pathlib import Path

from rich.console import Console
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, Header, Input, RichLog, Static

from model_harrier import __version__
from model_harrier.data import probes
from model_harrier.db import store


class ModelHarrierApp(App):
    """A keyboard friendly workspace for model security scans."""

    TITLE = "ModelHarrier"
    SUB_TITLE = "Model security workspace"
    CSS = """
    Screen { background: #0b1020; color: #e2e8f0; }
    #topbar { height: 3; padding: 0 1; background: #101a30; color: #8ee6d1; }
    #nav { height: 3; padding: 0 1; background: #111a2c; }
    #nav Button { margin-right: 1; min-width: 13; }
    #body { height: 1fr; padding: 1 2; }
    .view { height: 1fr; display: none; }
    .view.active { display: block; }
    .title { height: 2; color: #8ee6d1; text-style: bold; }
    .muted { color: #94a3b8; }
    .card { height: auto; padding: 1 2; margin: 0 1 1 0; border: round #263754; background: #101a2c; }
    .row { height: auto; }
    .field { width: 1fr; margin-right: 1; }
    Input { border: round #334155; background: #111a2c; }
    Button { background: #183047; border: round #35516d; }
    Button.-primary { background: #087e72; }
    #scan-log, #verify-log { height: 1fr; border: round #263754; background: #0d1526; }
    DataTable { height: 1fr; border: round #263754; }
    #probe-detail { height: 8; padding: 1; border: round #263754; background: #101a2c; }
    #status { height: 2; color: #94a3b8; padding: 0 1; }
    """
    BINDINGS = [("q", "quit", "Quit"), ("ctrl+r", "refresh", "Refresh"), ("1", "show('home')", "Home"),
                ("2", "show('scan')", "Scan"), ("3", "show('history')", "History"),
                ("4", "show('probes')", "Probes"), ("5", "show('watch')", "Watch")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="topbar"):
            yield Static(f"◈  MODELHARRIER   /   MODEL SUPPLY-CHAIN SECURITY               v{__version__}", id="brand")
        with Horizontal(id="nav"):
            for key, label in (("home", "1  Overview"), ("scan", "2  New scan"), ("history", "3  History"),
                               ("probes", "4  Probe library"), ("watch", "5  Watchlist")):
                yield Button(label, id=f"nav-{key}", variant="primary" if key == "home" else "default")
        with Container(id="body"):
            with Vertical(id="home", classes="view active"):
                yield Static("Security overview", classes="title")
                with Horizontal(classes="row"):
                    yield Static("Loading scan summary…", id="summary", classes="card")
                    yield Static("Scan Hugging Face models and local artifacts. Review findings, investigate files, and keep models on a watchlist.", classes="card muted")
                yield Static("Recent scans", classes="title")
                yield DataTable(id="recent-table", cursor_type="row")
                yield Static("Shortcuts:  2 scan  ·  3 history  ·  4 probes  ·  5 watchlist  ·  q quit", classes="muted")
            with Vertical(id="scan", classes="view"):
                yield Static("Run a security scan", classes="title")
                yield Static("Enter a Hugging Face model ID or a local directory. Model scans inspect repository metadata and supported artifacts; local scans analyze pickle based files.", classes="muted")
                with Horizontal(classes="row"):
                    yield Input(placeholder="Hugging Face model ID (e.g. org/model)", id="model-input", classes="field")
                    yield Input(placeholder="Local directory (optional)", id="path-input", classes="field")
                with Horizontal(classes="row"):
                    yield Input(placeholder="Save JSON report to (optional)", id="report-input", classes="field")
                with Horizontal(classes="row"):
                    yield Button("Start scan", id="start-scan", variant="primary")
                    yield Button("Verify pickle file…", id="verify-open")
                with Horizontal(classes="row"):
                    yield Input(placeholder="Pickle file path", id="verify-input", classes="field")
                    yield Button("Verify", id="verify-run")
                yield RichLog(id="scan-log", wrap=True, markup=False, highlight=False)
                yield RichLog(id="verify-log", wrap=True, markup=False, highlight=False)
            with Vertical(id="history", classes="view"):
                yield Static("Scan history", classes="title")
                yield DataTable(id="history-table", cursor_type="row")
                yield Static("Select a row to inspect the stored summary.", id="history-detail", classes="card muted")
            with Vertical(id="probes", classes="view"):
                yield Static("Red team probe library", classes="title")
                yield Static("Browse the reference prompts or run Garak red team probes against a Hugging Face model. Garak is an optional integration.", classes="muted")
                with Horizontal(classes="row"):
                    yield DataTable(id="category-table", cursor_type="row")
                    yield DataTable(id="probe-table", cursor_type="row")
                yield Static("Choose a category and probe to see its details.", id="probe-detail", classes="muted")
                with Horizontal(classes="row"):
                    yield Input(placeholder="Model ID for Garak red teaming", id="garak-model", classes="field")
                    yield Button("Run Garak probes", id="garak-run")
                yield RichLog(id="garak-log", wrap=True, markup=False, highlight=False)
            with Vertical(id="watch", classes="view"):
                yield Static("Model watchlist", classes="title")
                yield Static("Track models you want to rescan. The watchlist stores targets and intervals; scheduled checks can be run from your own automation.", classes="muted")
                with Horizontal(classes="row"):
                    yield Input(placeholder="Hugging Face model ID", id="watch-input", classes="field")
                    yield Input(value="24", placeholder="Hours", id="watch-interval", classes="field")
                    yield Button("Add target", id="watch-add", variant="primary")
                    yield Button("Remove selected", id="watch-remove")
                yield DataTable(id="watch-table", cursor_type="row")
        yield Static("Ready", id="status")
        yield Footer()

    def on_mount(self) -> None:
        store.init_db()
        self._setup_tables()
        self.refresh_data()

    def _setup_tables(self) -> None:
        self._columns("recent-table", ("Model", "Risk", "Level", "Scanned"))
        self._columns("history-table", ("ID", "Model", "Risk", "Level", "Files", "Scanned"))
        self._columns("category-table", ("Category", "Probes"))
        self._columns("probe-table", ("Probe",))
        self._columns("watch-table", ("Model", "Interval", "Last checked"))

    def _columns(self, widget_id: str, columns: tuple[str, ...]) -> None:
        table = self.query_one(f"#{widget_id}", DataTable)
        table.add_columns(*columns)

    def refresh_data(self) -> None:
        scans = store.get_scan_history(limit=100)
        summary = self.query_one("#summary", Static)
        count = len(store.get_scan_history(limit=10000))
        latest = scans[0] if scans else None
        summary.update(f"SCANS  {count}\nLATEST  {latest['model_id'] if latest else 'No scans yet'}\nRISK  {latest['severity'].upper() if latest else '—'}")
        self._fill_history(scans)
        recent = self.query_one("#recent-table", DataTable)
        recent.clear()
        for scan in scans[:6]:
            recent.add_row(scan.get("model_id", ""), f"{scan.get('risk_score', 0):.1f}/10", scan.get("severity", "safe").upper(), scan.get("timestamp", "")[:16])
        self._fill_probes()
        self._fill_watchlist()

    def _fill_history(self, scans: list[dict]) -> None:
        table = self.query_one("#history-table", DataTable)
        table.clear()
        for scan in scans:
            table.add_row(str(scan["id"]), scan.get("model_id", ""), f"{scan.get('risk_score', 0):.1f}/10", scan.get("severity", "safe").upper(), str(scan.get("file_count", 0)), scan.get("timestamp", "")[:16], key=str(scan["id"]))

    def _fill_probes(self) -> None:
        table = self.query_one("#category-table", DataTable)
        table.clear()
        for category in probes.get_probe_categories():
            info = probes.get_category_info(category)
            if info:
                table.add_row(info["name"], str(info["probe_count"]), key=category)
        self._show_probe_category(probes.get_probe_categories()[0])

    def _show_probe_category(self, category: str) -> None:
        items = probes.get_probes_by_category(category)
        table = self.query_one("#probe-table", DataTable)
        table.clear()
        for i, item in enumerate(items):
            table.add_row(item["name"], key=str(i))
        info = probes.get_category_info(category) or {}
        self.query_one("#probe-detail", Static).update(f"{info.get('name', category)}\n{info.get('description', '')}\n\nSelect a probe to inspect its prompt and expected safe behavior.")

    def _fill_watchlist(self) -> None:
        table = self.query_one("#watch-table", DataTable)
        table.clear()
        for target in store.get_watch_targets():
            table.add_row(target.get("model_id", ""), f"{target.get('check_interval_hours', 24)}h", target.get("last_checked", "never")[:16], key=target.get("model_id", ""))

    def action_refresh(self) -> None:
        self.refresh_data()
        self.notify("Workspace refreshed")

    def action_show(self, view: str) -> None:
        for item in self.query(".view"):
            item.remove_class("active")
        self.query_one(f"#{view}").add_class("active")
        for name in ("home", "scan", "history", "probes", "watch"):
            self.query_one(f"#nav-{name}", Button).variant = "primary" if name == view else "default"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id.startswith("nav-"):
            self.action_show(button_id[4:])
        elif button_id == "start-scan":
            self.run_scan()
        elif button_id == "verify-open":
            self.query_one("#verify-input", Input).focus()
        elif button_id == "verify-run":
            self.run_verify()
        elif button_id == "garak-run":
            self.run_garak()
        elif button_id == "watch-add":
            self.add_watch()
        elif button_id == "watch-remove":
            self.remove_watch()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "history-table":
            scan = store.get_scan_by_id(int(event.row_key.value))
            if scan:
                try:
                    details = json.loads(scan.get("summary") or "{}")
                except (ValueError, TypeError):
                    details = {}
                self.query_one("#history-detail", Static).update(f"{scan['model_id']}  ·  {scan['severity'].upper()}  ·  risk {scan['risk_score']:.1f}/10\n{scan.get('timestamp', '')}\n\n{json.dumps(details, indent=2)[:1800]}")
        elif event.data_table.id == "category-table":
            self._show_probe_category(str(event.row_key.value))
        elif event.data_table.id == "probe-table" and event.data_table.cursor_row is not None:
            category_table = self.query_one("#category-table", DataTable)
            category = str(category_table.get_row_at(category_table.cursor_row)[0])
            key = next((key for key in probes.get_probe_categories() if (probes.get_category_info(key) or {}).get("name") == category), None)
            if key:
                probe = probes.get_probes_by_category(key)[int(event.row_key.value)]
                self.query_one("#probe-detail", Static).update(f"{probe['name']}  ·  {key}\n\nPrompt: {probe['prompt']}\n\nExpected safe behavior: {probe['expected_safe']}\n\nRed flags: {', '.join(probe.get('red_flags', []))}")

    async def run_scan(self) -> None:
        model_id = self.query_one("#model-input", Input).value.strip()
        path = self.query_one("#path-input", Input).value.strip()
        report_path = self.query_one("#report-input", Input).value.strip()
        if not model_id and not path:
            self.notify("Enter a model ID or local directory", severity="warning")
            return
        log = self.query_one("#scan-log", RichLog)
        log.clear()
        log.write("Scanning… This can take a while for large repositories.")
        self.query_one("#start-scan", Button).disabled = True
        self.query_one("#status", Static).update(f"Scanning {model_id or path}…")
        result = await asyncio.to_thread(self._scan_to_json, model_id, path, report_path)
        log.clear()
        log.write(self._render_scan_result(result))
        self.query_one("#start-scan", Button).disabled = False
        self.query_one("#status", Static).update("Scan complete")
        self.refresh_data()

    @staticmethod
    def _render_scan_result(result: str) -> str:
        try:
            report = json.loads(result)
        except (json.JSONDecodeError, TypeError):
            return result

        if "results" in report:
            summary = report.get("scan_summary", {})
            lines = [
                f"LOCAL SCAN  {report.get('model', {}).get('id', 'path')}",
                f"VERDICT  {summary.get('severity', 'unknown').upper()}   ·   RISK {summary.get('risk_score', 0)}/10",
                f"FILES  {summary.get('files_scanned', 0)} inspected   ·   {summary.get('risky_files', 0)} high-risk",
                "",
                "FINDINGS",
            ]
            for item in report.get("results", []):
                lines.append(f"  [{item.get('severity', 'unknown').upper()}] {item.get('file', '?')} ({item.get('format', 'unknown')})")
                lines.extend(f"    {finding.get('description', finding.get('issue', 'Finding'))}" for finding in item.get("findings", [])[:5])
            return "\n".join(lines)

        if "scan_summary" in report:
            model = report.get("model", {})
            summary = report.get("scan_summary", {})
            lines = [
                f"MODEL  {model.get('id', 'unknown')}",
                f"VERDICT  {summary.get('severity', 'unknown').upper()}   ·   RISK {summary.get('risk_score', 0)}/10",
                f"FILES  {summary.get('files_scanned', 0)} inspected   ·   {summary.get('risky_files', 0)} risky   ·   {summary.get('alerts_count', 0)} alerts",
                "",
                "FINDINGS",
            ]
            risky_files = [item for item in report.get("file_findings", []) if item.get("category") == "risky"]
            lines.extend(f"  [{item.get('category', 'unknown').upper()}] {item.get('filename', '?')} — {item.get('description', '')}" for item in risky_files[:12])
            alerts = report.get("alerts", [])
            lines.extend(f"  [{item.get('severity', 'info').upper()}] {item.get('description', item.get('type', 'Alert'))}" for item in alerts[:20])
            if not risky_files and not alerts:
                lines.append("  No alerts returned by the scan.")
            lines.extend(["", "Full JSON report is available with: model-harrier scan <model-id> --output report.json"])
            return "\n".join(lines)

        return json.dumps(report, indent=2)

    @staticmethod
    def _scan_to_json(model_id: str, path: str, report_path: str = "") -> str:
        from model_harrier import cli

        stream = io.StringIO()
        old_console = cli.console
        cli.console = Console(file=stream, force_terminal=False, no_color=True, width=100)
        try:
            with contextlib.redirect_stdout(stream):
                if path:
                    cli._scan_local(Path(path), Path(report_path) if report_path else None, True, False)
                else:
                    cli._scan_hf_model(model_id, Path(report_path) if report_path else None, True, None, False, False)
        except BaseException as exc:
            if getattr(exc, "exit_code", None) is None:
                return f"Scan failed: {exc}\n{stream.getvalue()}"
        finally:
            cli.console = old_console
        return stream.getvalue().strip() or "Scan finished with no report output."

    async def run_garak(self) -> None:
        model_id = self.query_one("#garak-model", Input).value.strip()
        if not model_id:
            self.notify("Enter a Hugging Face model ID", severity="warning")
            return
        log = self.query_one("#garak-log", RichLog)
        log.clear()
        log.write(f"Running Garak probes against {model_id}…")
        self.query_one("#status", Static).update(f"Running Garak against {model_id}…")
        text = await asyncio.to_thread(self._run_garak, model_id)
        log.clear()
        log.write(text)
        self.query_one("#status", Static).update("Garak run complete")

    @staticmethod
    def _run_garak(model_id: str) -> str:
        try:
            from model_harrier.scan.garak import garak_available, scan_with_garak

            if not garak_available():
                return "Garak is not installed. Install it with: pip install 'model-harrier[garak]'"
            result = scan_with_garak(model_id)
            if result.get("error"):
                return f"Garak failed: {result['error']}"
            lines = [
                f"MODEL  {model_id}",
                f"PROBES  {result.get('probes_run', 0)} run   ·   {result.get('probes_passed', 0)} passed   ·   {result.get('probes_failed', 0)} failed",
                "",
                "FAILED PROBES",
            ]
            failed = [item for item in result.get("findings", []) if item.get("verdict") == "FAIL"]
            lines.extend(f"  [{item.get('severity', 'unknown').upper()}] {item.get('probe', 'Unnamed probe')}" for item in failed)
            if not failed:
                lines.append("  No failed probes reported.")
            return "\n".join(lines)
        except Exception as exc:
            return f"Garak failed: {exc}"

    async def run_verify(self) -> None:
        value = self.query_one("#verify-input", Input).value.strip()
        if not value:
            self.notify("Enter a pickle file path", severity="warning")
            return
        log = self.query_one("#verify-log", RichLog)
        log.clear()
        log.write("Verifying file…")
        text = await asyncio.to_thread(self._verify_file, value)
        log.clear()
        log.write(text)

    @staticmethod
    def _verify_file(value: str) -> str:
        from model_harrier.scan.pickles import verify_pickle_file

        try:
            result = verify_pickle_file(value)
            verdict = result.consensus.value if result.consensus else result.aieye_result.value
            return "\n".join([f"File: {value}", f"Size: {result.file_size:,} bytes", f"SHA256: {result.file_hash}", f"Verdict: {verdict.upper()}", f"Confidence: {result.confidence:.0%}", "", *[f"• {reason}" for reason in (result.reasoning or [])]])
        except Exception as exc:
            return f"Verification failed: {exc}"

    def add_watch(self) -> None:
        model_id = self.query_one("#watch-input", Input).value.strip()
        if not model_id:
            self.notify("Enter a model ID", severity="warning")
            return
        try:
            interval = max(1, int(self.query_one("#watch-interval", Input).value or "24"))
        except ValueError:
            self.notify("Interval must be a number of hours", severity="warning")
            return
        store.add_watch_target(model_id, interval)
        self.query_one("#watch-input", Input).value = ""
        self._fill_watchlist()
        self.notify(f"Added {model_id} to watchlist")

    def remove_watch(self) -> None:
        table = self.query_one("#watch-table", DataTable)
        if table.row_count == 0:
            self.notify("Watchlist is empty", severity="warning")
            return
        model_id = str(table.get_row_at(table.cursor_row)[0])
        store.remove_watch_target(model_id)
        self._fill_watchlist()
        self.notify(f"Removed {model_id}")


if __name__ == "__main__":
    ModelHarrierApp().run()
