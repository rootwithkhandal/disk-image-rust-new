"""
Terminal User Interface for ForgeLens Memory Forensics.
"""

from __future__ import annotations

import asyncio
import os
import random
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, ListView, ListItem, Label, DataTable, Input, Static

# Assuming we are running from project root
from core.memory.volatility_engine import VolatilityEngine
from core.memory.acquisition import MemoryAcquisition
from core.memory.vt_api import VirusTotalScanner


class HexViewer(Static):
    """A mock Hex Viewer component to display memory regions."""
    def on_mount(self) -> None:
        self.update(self._generate_mock_hex())
        
    def _generate_mock_hex(self) -> str:
        from rich.markup import escape
        lines = []
        base_addr = 0x00400000
        for i in range(16):
            addr = f"{base_addr + (i * 16):08X}"
            hex_bytes = " ".join(f"{random.randint(0, 255):02X}" for _ in range(16))
            ascii_chars = "".join(chr(random.randint(32, 126)) for _ in range(16))
            escaped_ascii = escape(ascii_chars)
            lines.append(f"[bold #8B949E]{addr}[/]  [#00FFC2]{hex_bytes}[/]  [#8B949E]{escaped_ascii}[/]")
        return "\n".join(lines)


class ForgeLensTUI(App):
    """A Textual App to interactively run Volatility3 commands."""

    CSS = """
    Screen {
        background: #0D1117;
    }
    Header, Footer {
        background: #161B22;
        color: #00FFC2;
    }
    #sidebar {
        width: 30;
        dock: left;
        background: #161B22;
        padding: 1;
        border-right: solid #00FFC2;
    }
    .menu_header {
        color: #00FFC2;
        text-style: bold;
        margin-bottom: 1;
        padding-bottom: 1;
        border-bottom: solid #30363D;
    }
    ListView {
        background: #161B22;
    }
    ListItem {
        padding: 0 1;
        color: #8B949E;
    }
    ListItem:hover {
        background: #0D1117;
    }
    ListItem.--highlight {
        background: #00FFC2 15%;
        color: #00FFC2;
        border-left: thick #00FFC2;
        text-style: bold;
    }
    #content {
        width: 1fr;
        height: 100%;
        padding: 1 2;
        background: #0D1117;
    }
    #inspector {
        width: 60;
        dock: right;
        background: #161B22;
        padding: 1;
        border-left: solid #00FFC2;
        display: block;
    }
    #inspector_info {
        margin-bottom: 1;
        color: #8B949E;
    }
    .input_box {
        margin-bottom: 1;
        margin-right: 1;
        background: #161B22;
        border: solid #30363D;
        color: #00FFC2;
    }
    .input_box:focus {
        border: solid #00FFC2;
    }
    #status_label {
        margin-bottom: 1;
        color: #00FFC2;
        text-style: bold;
    }
    DataTable {
        background: #0D1117;
        border: solid #30363D;
        height: 1fr;
    }
    DataTable > .datatable--header {
        background: #161B22;
        color: #8B949E;
        text-style: bold;
    }
    DataTable > .datatable--cursor {
        background: #00FFC2 15%;
        color: #fbfffa;
    }
    HexViewer {
        height: 100%;
        background: #0D1117;
        color: #8B949E;
        border: solid #30363D;
        padding: 1;
        margin-top: 1;
        content-align: left top;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("d", "focus_dump", "Focus Dump Input", show=True),
        Binding("v", "focus_vt", "Focus VT API Key", show=True),
        Binding("ctrl+p", "command_palette", "Command Palette", show=True),
    ]

    def __init__(self, dump_path: str = ""):
        super().__init__()
        self.dump_path = dump_path
        self.engine: VolatilityEngine | None = None
        self.cached_processes = []
        if self.dump_path:
            self.engine = VolatilityEngine(self.dump_path)

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header(show_clock=True)
        
        with Horizontal():
            # Sidebar menu
            with Vertical(id="sidebar"):
                yield Label("[ 01 — ACTIONS ]", classes="menu_header")
                yield ListView(
                    ListItem(Label("1. List Processes"), id="action_processes"),
                    ListItem(Label("2. Network Connections"), id="action_connections"),
                    ListItem(Label("3. Loaded DLLs"), id="action_dlls"),
                    ListItem(Label("4. Malware (Malfind)"), id="action_malfind"),
                    ListItem(Label("5. NTLM Hashes"), id="action_hashes"),
                    ListItem(Label("6. VirusTotal Scan"), id="action_vt_scan"),
                    ListItem(Label("7. Create Memory Dump"), id="action_dump"),
                    id="action_list"
                )
                
            # Main content area
            with Vertical(id="content"):
                yield Label("Status: Waiting for memory dump path..." if not self.dump_path else f"Status: Ready to analyze {self.dump_path}", id="status_label")
                
                with Horizontal():
                    yield Input(
                        placeholder="Enter absolute path to memory dump...", 
                        value=self.dump_path, 
                        id="dump_input",
                        classes="input_box"
                    )
                    
                    # Check for VT API key in environment
                    vt_key = os.environ.get("VT_API_KEY", "")
                    yield Input(
                        placeholder="Enter VirusTotal API Key...",
                        value=vt_key,
                        id="vt_input",
                        classes="input_box",
                        password=True
                    )
                
                yield DataTable(id="data_table", zebra_stripes=True)
                
            # Right Inspector Panel
            with Vertical(id="inspector"):
                yield Label("[ 02 — INSPECTOR ]", classes="menu_header")
                yield Label("Select a row in the table to inspect details.", id="inspector_info")
                yield HexViewer(id="hex_viewer")
                
        yield Footer()

    def on_mount(self) -> None:
        self.title = "nvmdump — Forensic Dashboard"
        table = self.query_one(DataTable)
        table.cursor_type = "row"

    def action_focus_dump(self) -> None:
        self.query_one("#dump_input", Input).focus()

    def action_focus_vt(self) -> None:
        self.query_one("#vt_input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "dump_input":
            self.dump_path = event.value
            if self.dump_path:
                self.engine = VolatilityEngine(self.dump_path)
                self.cached_processes = []
                self.query_one("#status_label", Label).update(f"Status: Dump path set to {self.dump_path}. Select an action from the left.")
            else:
                self.engine = None
                self.query_one("#status_label", Label).update("Status: Waiting for memory dump path...")
        elif event.input.id == "vt_input":
            self.query_one("#status_label", Label).update("Status: VT API Key saved.")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection to update inspector."""
        row_key = event.row_key
        table = self.query_one(DataTable)
        try:
            row_data = table.get_row(row_key)
            if row_data:
                # Use the first column as identifier
                identifier = row_data[0]
                info_label = self.query_one("#inspector_info", Label)
                info_label.update(f"Inspecting item: [bold #00FFC2]{identifier}[/]")
                
                # Regenerate hex viewer data
                hex_viewer = self.query_one("#hex_viewer", HexViewer)
                hex_viewer.update(hex_viewer._generate_mock_hex())
        except Exception:
            pass

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle selection in the sidebar."""
        action_id = event.item.id
        status = self.query_one("#status_label", Label)
        table = self.query_one(DataTable)
        
        if action_id == "action_dump":
            status.update("Status: Acquiring memory dump to 'dump.raw'... (File may exceed RAM size due to padding)")
            table.clear(columns=True)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self._run_acquisition)
            if result.success:
                status.update(f"Status: Memory dumped successfully to {result.dump_path}")
                self.query_one("#dump_input", Input).value = result.dump_path
                self.dump_path = result.dump_path
                self.engine = VolatilityEngine(self.dump_path)
            else:
                status.update(f"Error: {result.error}")
            return

        if action_id == "action_vt_scan":
            vt_key = self.query_one("#vt_input", Input).value
            if not vt_key:
                status.update("Error: Please enter a VirusTotal API Key in the input box first.")
                return
            if not self.engine:
                status.update("Error: Please set a memory dump path to scan its processes.")
                return
                
            status.update("Status: Scanning unique processes against VirusTotal...")
            table.clear(columns=True)
            loop = asyncio.get_event_loop()
            
            # Use cached processes if we already ran action_processes
            if not self.cached_processes:
                proc_res = await loop.run_in_executor(None, self.engine.list_processes)
                if proc_res.success:
                    self.cached_processes = proc_res.data
            
            if not self.cached_processes:
                status.update("Error: Failed to extract processes to scan.")
                return
                
            # Extract names
            names = [p.get("ImageFileName") or p.get("Name") for p in self.cached_processes]
            names = [n for n in names if n]
            
            scanner = VirusTotalScanner(api_key=vt_key)
            vt_results = await loop.run_in_executor(None, scanner.scan_processes, names)
            self._update_vt_table(vt_results)
            return

        # Standard memory actions below
        if not self.engine:
            status.update("Error: Please specify a valid dump path first.")
            return

        table.clear(columns=True)
        status.update("Status: Analyzing... Please wait (this may take a few minutes for large dumps).")

        action_map = {
            "action_processes": ("Processes", self.engine.list_processes),
            "action_connections": ("Network Connections", self.engine.list_connections),
            "action_dlls": ("Loaded DLLs", self.engine.list_dlls),
            "action_malfind": ("Malfind Results", self.engine.detect_malware),
            "action_hashes": ("NTLM Hashes", self.engine.find_hashes),
        }

        if action_id in action_map:
            title, func = action_map[action_id]
            loop = asyncio.get_event_loop()
            try:
                result = await loop.run_in_executor(None, func)
                if action_id == "action_processes" and result.success:
                    self.cached_processes = result.data
                self._update_table(result, title)
            except Exception as e:
                status.update(f"Error: {e}")

    def _run_acquisition(self):
        tool_path = str(Path(__file__).resolve().parent.parent.parent / "tools" / "winpmem_mini_x64_rc2.exe")
        acq = MemoryAcquisition(tool_path)
        return acq.acquire("dump.raw")

    def _update_vt_table(self, vt_results: list) -> None:
        """Populate table with VT results"""
        status = self.query_one("#status_label", Label)
        table = self.query_one(DataTable)
        
        table.add_columns("Process Name", "Malicious", "Suspicious", "Undetected", "Error", "VT Link")
        
        malicious_count = 0
        for r in vt_results:
            if r.malicious > 0:
                malicious_count += 1
                row = [
                    f"[bold #FF453A]{r.process}[/]", 
                    f"[bold #FF453A on #351010] [ MALICIOUS: {r.malicious} ] [/]", 
                    str(r.suspicious), 
                    str(r.undetected), 
                    r.error, 
                    r.vt_link
                ]
            else:
                row = [
                    r.process, 
                    f"[bold #00FFC2 on #003322] [ VERIFIED ] [/]", 
                    str(r.suspicious), 
                    str(r.undetected), 
                    r.error, 
                    r.vt_link
                ]
            table.add_row(*row)
            
        status.update(f"Status: VT Scan Complete. Found {malicious_count} malicious processes.")

    def _update_table(self, result, title: str) -> None:
        """Update the data table with the Volatility result."""
        status = self.query_one("#status_label", Label)
        table = self.query_one(DataTable)
        
        if not result.success:
            status.update(f"Status: Failed - {result.error}")
            return
            
        status.update(f"Status: {title} loaded successfully ({result.row_count} rows).")
        
        if not result.data:
            return
            
        headers = list(result.data[0].keys())
        table.add_columns(*headers)
        
        for row in result.data:
            if row.get("_suspicious"):
                styled_row = [f"[bold #FF453A on #351010]{str(row.get(h, ''))}[/]" for h in headers]
                table.add_row(*styled_row)
            else:
                table.add_row(*[str(row.get(h, "")) for h in headers])

if __name__ == "__main__":
    app = ForgeLensTUI()
    app.run()
