"""
Auth GUI
Tkinter popup for collecting authentication configuration.
Launched when user passes --auth flag on the CLI.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
from typing import Optional
from config.manager import AuthConfig, save_auth_config


# ── Colour palette (dark security-tool aesthetic) ─────────────────────────────
BG        = "#0f1117"
SURFACE   = "#1a1d27"
SURFACE2  = "#252836"
ACCENT    = "#00d4ff"
ACCENT2   = "#7c3aed"
SUCCESS   = "#22c55e"
WARNING   = "#f59e0b"
DANGER    = "#ef4444"
TEXT      = "#e2e8f0"
TEXT_MUTED= "#64748b"
BORDER    = "#2d3148"
ENTRY_BG  = "#1e2235"


def _style_entry(widget):
    widget.configure(
        bg=ENTRY_BG, fg=TEXT, insertbackground=ACCENT,
        relief="flat", highlightthickness=1,
        highlightcolor=ACCENT, highlightbackground=BORDER,
        font=("Consolas", 10), bd=4,
    )


def _style_btn(widget, color=ACCENT, text_color=BG, hover_color=None):
    hover = hover_color or color
    widget.configure(
        bg=color, fg=text_color, activebackground=hover,
        activeforeground=text_color, relief="flat",
        font=("Segoe UI", 10, "bold"), bd=0,
        cursor="hand2", padx=12, pady=6,
    )
    widget.bind("<Enter>", lambda e: widget.configure(bg=hover))
    widget.bind("<Leave>", lambda e: widget.configure(bg=color))


def _label(parent, text, muted=False, bold=False, size=10):
    font = ("Segoe UI", size, "bold" if bold else "normal")
    return tk.Label(
        parent, text=text,
        bg=SURFACE if not muted else SURFACE,
        fg=TEXT_MUTED if muted else TEXT,
        font=font,
    )


# ── Key-Value Row (used for headers & cookies) ────────────────────────────────
class KVRow(tk.Frame):
    def __init__(self, parent, key="", value="", on_remove=None, **kwargs):
        super().__init__(parent, bg=SURFACE2, **kwargs)
        self.on_remove = on_remove

        self.key_var   = tk.StringVar(value=key)
        self.value_var = tk.StringVar(value=value)

        key_entry = tk.Entry(self, textvariable=self.key_var, width=24)
        _style_entry(key_entry)
        key_entry.pack(side="left", padx=(0, 6), ipady=4)

        sep = tk.Label(self, text=":", bg=SURFACE2, fg=TEXT_MUTED,
                       font=("Consolas", 12, "bold"))
        sep.pack(side="left", padx=2)

        val_entry = tk.Entry(self, textvariable=self.value_var, width=36)
        _style_entry(val_entry)
        val_entry.pack(side="left", padx=(6, 8), ipady=4)

        remove_btn = tk.Button(self, text="✕", command=self._remove,
                               bg=SURFACE2, fg=DANGER, relief="flat",
                               font=("Segoe UI", 11, "bold"), cursor="hand2",
                               bd=0, padx=6)
        remove_btn.bind("<Enter>", lambda e: remove_btn.configure(fg=TEXT))
        remove_btn.bind("<Leave>", lambda e: remove_btn.configure(fg=DANGER))
        remove_btn.pack(side="left")

    def _remove(self):
        if self.on_remove:
            self.on_remove(self)
        self.destroy()

    def get(self):
        return self.key_var.get().strip(), self.value_var.get().strip()


# ── Scrollable KV Section ─────────────────────────────────────────────────────
class KVSection(tk.Frame):
    def __init__(self, parent, label_text, placeholder_key="", placeholder_val="", **kwargs):
        super().__init__(parent, bg=SURFACE, **kwargs)
        self.placeholder_key = placeholder_key
        self.placeholder_val = placeholder_val
        self.rows = []

        # Header bar
        header = tk.Frame(self, bg=SURFACE)
        header.pack(fill="x", pady=(0, 6))

        _label(header, label_text, bold=True, size=11).pack(side="left")
        add_btn = tk.Button(header, text="+ Add", command=self.add_row,
                            bg=SURFACE2, fg=ACCENT, relief="flat",
                            font=("Segoe UI", 9, "bold"), cursor="hand2",
                            bd=0, padx=8, pady=3)
        add_btn.bind("<Enter>", lambda e: add_btn.configure(fg=TEXT))
        add_btn.bind("<Leave>", lambda e: add_btn.configure(fg=ACCENT))
        add_btn.pack(side="right")

        # Column labels
        col_labels = tk.Frame(self, bg=SURFACE)
        col_labels.pack(fill="x", padx=2)
        _label(col_labels, "Key / Name", muted=True, size=9).pack(side="left", padx=(4,0))
        _label(col_labels, "Value", muted=True, size=9).pack(side="left", padx=(110,0))

        # Rows container
        self.rows_frame = tk.Frame(self, bg=SURFACE)
        self.rows_frame.pack(fill="x")

        # Empty state label
        self.empty_label = _label(self.rows_frame, "No entries yet — click '+ Add'", muted=True, size=9)
        self.empty_label.pack(pady=6)

    def add_row(self, key="", value=""):
        self.empty_label.pack_forget()
        row = KVRow(
            self.rows_frame,
            key=key or self.placeholder_key,
            value=value or self.placeholder_val,
            on_remove=self._on_remove,
        )
        row.pack(fill="x", pady=3)
        self.rows.append(row)

    def _on_remove(self, row):
        if row in self.rows:
            self.rows.remove(row)
        if not self.rows:
            self.empty_label.pack(pady=6)

    def get_data(self) -> dict:
        result = {}
        for row in self.rows:
            k, v = row.get()
            if k:
                result[k] = v
        return result

    def load_data(self, data: dict):
        for k, v in data.items():
            self.add_row(k, v)


# ── Main Auth Window ──────────────────────────────────────────────────────────
class AuthWindow:
    def __init__(self, existing_config: Optional[AuthConfig] = None):
        self.result: Optional[AuthConfig] = None
        self.existing = existing_config

        self.root = tk.Tk()
        self.root.title("HTTP Smuggler — Auth Configuration")
        self.root.configure(bg=BG)
        self.root.resizable(True, True)
        self.root.minsize(700, 600)

        # Center window
        w, h = 760, 720
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

        self._build_ui()

        if existing_config:
            self._load_existing(existing_config)

    # ── UI Construction ────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Title bar ──
        title_bar = tk.Frame(self.root, bg=BG)
        title_bar.pack(fill="x", padx=24, pady=(20, 0))

        tk.Label(title_bar, text="🔐", bg=BG, font=("Segoe UI", 22)).pack(side="left")
        title_col = tk.Frame(title_bar, bg=BG)
        title_col.pack(side="left", padx=12)
        tk.Label(title_col, text="Authentication Setup",
                 bg=BG, fg=TEXT, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(title_col, text="Configure headers, cookies and session tokens for authenticated scans",
                 bg=BG, fg=TEXT_MUTED, font=("Segoe UI", 9)).pack(anchor="w")

        # ── Divider ──
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", padx=24, pady=14)

        # ── Scrollable main area ──
        canvas_frame = tk.Frame(self.root, bg=BG)
        canvas_frame.pack(fill="both", expand=True, padx=24)

        canvas = tk.Canvas(canvas_frame, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
        self.scroll_frame = tk.Frame(canvas, bg=BG)

        self.scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=self.scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        self._build_sections(self.scroll_frame)

        # ── Bottom action bar ──
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", padx=24, pady=(8, 0))
        self._build_action_bar()

    def _build_sections(self, parent):
        pad = {"fill": "x", "pady": 10}

        # ── 1. Headers ──
        self._section_card(parent, "HTTP Headers",
                           "Custom headers sent with every request (e.g. X-API-Key, User-Agent)",
                           "headers").pack(**pad)

        # ── 2. Cookies ──
        self._section_card(parent, "Cookies",
                           "Session cookies for authenticated scanning",
                           "cookies").pack(**pad)

        # ── 3. Token / Authorization ──
        self._build_token_section(parent).pack(**pad)

        # ── 4. Proxy ──
        self._build_proxy_section(parent).pack(**pad)

        # ── 5. SSL ──
        self._build_ssl_section(parent).pack(**pad)

    def _section_card(self, parent, title, subtitle, attr):
        card = tk.Frame(parent, bg=SURFACE, padx=16, pady=14,
                        highlightthickness=1, highlightbackground=BORDER)

        tk.Label(card, text=title, bg=SURFACE, fg=TEXT,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w")
        tk.Label(card, text=subtitle, bg=SURFACE, fg=TEXT_MUTED,
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 10))

        section = KVSection(card, "")
        section.pack(fill="x")
        setattr(self, f"_{attr}_section", section)

        # Paste raw cookie string (only for cookies)
        if attr == "cookies":
            paste_frame = tk.Frame(card, bg=SURFACE)
            paste_frame.pack(fill="x", pady=(8, 0))
            _label(paste_frame, "Or paste raw cookie string:", muted=True, size=9).pack(anchor="w")
            self._raw_cookie_entry = tk.Entry(paste_frame, width=70)
            _style_entry(self._raw_cookie_entry)
            self._raw_cookie_entry.pack(side="left", pady=4, ipady=4)
            parse_btn = tk.Button(paste_frame, text="Parse →",
                                  command=self._parse_raw_cookies,
                                  bg=ACCENT2, fg=TEXT, relief="flat",
                                  font=("Segoe UI", 9, "bold"), cursor="hand2",
                                  bd=0, padx=10, pady=5)
            parse_btn.pack(side="left", padx=8)

        return card

    def _build_token_section(self, parent):
        card = tk.Frame(parent, bg=SURFACE, padx=16, pady=14,
                        highlightthickness=1, highlightbackground=BORDER)

        tk.Label(card, text="Session / API Token", bg=SURFACE, fg=TEXT,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w")
        tk.Label(card, text="Authorization header will be auto-built from token type + value",
                 bg=SURFACE, fg=TEXT_MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 10))

        row = tk.Frame(card, bg=SURFACE)
        row.pack(fill="x")

        _label(row, "Type:", size=10).pack(side="left", padx=(0, 8))
        self._token_type_var = tk.StringVar(value="Bearer")
        token_type_menu = ttk.Combobox(
            row, textvariable=self._token_type_var,
            values=["Bearer", "Basic", "Custom", "None"],
            width=10, state="readonly",
        )
        token_type_menu.pack(side="left", padx=(0, 16))

        _label(row, "Token value:", size=10).pack(side="left", padx=(0, 8))
        self._token_var = tk.StringVar()
        token_entry = tk.Entry(row, textvariable=self._token_var, width=42, show="")
        _style_entry(token_entry)
        token_entry.pack(side="left", ipady=4)

        # Toggle show/hide
        self._show_token = False
        def toggle_token_visibility():
            self._show_token = not self._show_token
            token_entry.configure(show="" if self._show_token else "•")
            toggle_btn.configure(text="🙈" if self._show_token else "👁")
        token_entry.configure(show="•")
        toggle_btn = tk.Button(row, text="👁", command=toggle_token_visibility,
                               bg=SURFACE, fg=TEXT_MUTED, relief="flat",
                               font=("Segoe UI", 12), cursor="hand2", bd=0, padx=4)
        toggle_btn.pack(side="left", padx=4)

        return card

    def _build_proxy_section(self, parent):
        card = tk.Frame(parent, bg=SURFACE, padx=16, pady=14,
                        highlightthickness=1, highlightbackground=BORDER)

        header_row = tk.Frame(card, bg=SURFACE)
        header_row.pack(fill="x")

        tk.Label(header_row, text="Proxy Settings", bg=SURFACE, fg=TEXT,
                 font=("Segoe UI", 12, "bold")).pack(side="left")

        self._proxy_enabled_var = tk.BooleanVar(value=False)
        proxy_toggle = tk.Checkbutton(
            header_row, text="Enable",
            variable=self._proxy_enabled_var,
            command=self._toggle_proxy,
            bg=SURFACE, fg=ACCENT, selectcolor=SURFACE2,
            activebackground=SURFACE, activeforeground=ACCENT,
            font=("Segoe UI", 10), cursor="hand2",
        )
        proxy_toggle.pack(side="right")

        tk.Label(card, text="Route scan traffic through a proxy (Burp Suite, SOCKS5, etc.)",
                 bg=SURFACE, fg=TEXT_MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 10))

        self._proxy_frame = tk.Frame(card, bg=SURFACE)
        self._proxy_frame.pack(fill="x")

        url_row = tk.Frame(self._proxy_frame, bg=SURFACE)
        url_row.pack(fill="x", pady=4)
        _label(url_row, "Proxy URL:", size=10).pack(side="left", padx=(0, 8), anchor="w")
        self._proxy_url_var = tk.StringVar(value="http://127.0.0.1:8080")
        proxy_url_entry = tk.Entry(url_row, textvariable=self._proxy_url_var, width=42)
        _style_entry(proxy_url_entry)
        proxy_url_entry.pack(side="left", ipady=4)

        creds_row = tk.Frame(self._proxy_frame, bg=SURFACE)
        creds_row.pack(fill="x", pady=4)
        _label(creds_row, "Username:", size=10).pack(side="left", padx=(0, 8))
        self._proxy_user_var = tk.StringVar()
        u_entry = tk.Entry(creds_row, textvariable=self._proxy_user_var, width=18)
        _style_entry(u_entry)
        u_entry.pack(side="left", ipady=4, padx=(0, 16))
        _label(creds_row, "Password:", size=10).pack(side="left", padx=(0, 8))
        self._proxy_pass_var = tk.StringVar()
        p_entry = tk.Entry(creds_row, textvariable=self._proxy_pass_var, width=18, show="•")
        _style_entry(p_entry)
        p_entry.pack(side="left", ipady=4)

        self._toggle_proxy()  # Start disabled
        return card

    def _build_ssl_section(self, parent):
        card = tk.Frame(parent, bg=SURFACE, padx=16, pady=14,
                        highlightthickness=1, highlightbackground=BORDER)

        row = tk.Frame(card, bg=SURFACE)
        row.pack(fill="x")
        tk.Label(row, text="SSL / TLS", bg=SURFACE, fg=TEXT,
                 font=("Segoe UI", 12, "bold")).pack(side="left")
        self._ssl_verify_var = tk.BooleanVar(value=False)
        ssl_check = tk.Checkbutton(
            row, text="Verify SSL certificates",
            variable=self._ssl_verify_var,
            bg=SURFACE, fg=TEXT, selectcolor=SURFACE2,
            activebackground=SURFACE, activeforeground=ACCENT,
            font=("Segoe UI", 10), cursor="hand2",
        )
        ssl_check.pack(side="right")

        tk.Label(card, text="Disable for self-signed certs (common in internal/staging environments)",
                 bg=SURFACE, fg=TEXT_MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 0))

        return card

    def _build_action_bar(self):
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", padx=24, pady=16)

        # Left: import/export
        left = tk.Frame(bar, bg=BG)
        left.pack(side="left")

        import_btn = tk.Button(left, text="📂 Import Config",
                               command=self._import_config,
                               bg=SURFACE2, fg=TEXT_MUTED, relief="flat",
                               font=("Segoe UI", 9), cursor="hand2", bd=0, padx=10, pady=6)
        import_btn.pack(side="left", padx=(0, 8))

        export_btn = tk.Button(left, text="💾 Export Config",
                               command=self._export_config,
                               bg=SURFACE2, fg=TEXT_MUTED, relief="flat",
                               font=("Segoe UI", 9), cursor="hand2", bd=0, padx=10, pady=6)
        export_btn.pack(side="left")

        # Right: main actions
        right = tk.Frame(bar, bg=BG)
        right.pack(side="right")

        cancel_btn = tk.Button(right, text="Cancel",
                               command=self._cancel,
                               bg=SURFACE2, fg=TEXT_MUTED, relief="flat",
                               font=("Segoe UI", 10), cursor="hand2", bd=0, padx=14, pady=7)
        cancel_btn.pack(side="left", padx=(0, 8))

        save_only_btn = tk.Button(right, text="💾 Save Config Only",
                                  command=self._save_only,
                                  bg=ACCENT2, fg=TEXT, relief="flat",
                                  font=("Segoe UI", 10, "bold"), cursor="hand2", bd=0,
                                  padx=14, pady=7)
        save_only_btn.pack(side="left", padx=(0, 8))

        scan_btn = tk.Button(right, text="✅ Save & Start Scan",
                             command=self._save_and_scan,
                             bg=ACCENT, fg=BG, relief="flat",
                             font=("Segoe UI", 10, "bold"), cursor="hand2", bd=0,
                             padx=14, pady=7)
        scan_btn.pack(side="left")

        # Status bar
        self._status_var = tk.StringVar(value="")
        tk.Label(self.root, textvariable=self._status_var,
                 bg=BG, fg=SUCCESS, font=("Segoe UI", 9)).pack(pady=(0, 6))

    # ── Helpers ────────────────────────────────────────────────────────────
    def _toggle_proxy(self):
        state = "normal" if self._proxy_enabled_var.get() else "disabled"
        for widget in self._proxy_frame.winfo_children():
            for child in widget.winfo_children():
                try:
                    child.configure(state=state)
                except Exception:
                    pass

    def _parse_raw_cookies(self):
        raw = self._raw_cookie_entry.get().strip()
        if not raw:
            return
        for part in raw.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                self._cookies_section.add_row(k.strip(), v.strip())
        self._raw_cookie_entry.delete(0, "end")

    def _collect(self) -> AuthConfig:
        return AuthConfig(
            headers=self._headers_section.get_data(),
            cookies=self._cookies_section.get_data(),
            token=self._token_var.get().strip(),
            token_type=self._token_type_var.get(),
            proxy_enabled=self._proxy_enabled_var.get(),
            proxy_url=self._proxy_url_var.get().strip(),
            proxy_username=self._proxy_user_var.get().strip(),
            proxy_password=self._proxy_pass_var.get().strip(),
            ssl_verify=self._ssl_verify_var.get(),
        )

    def _load_existing(self, cfg: AuthConfig):
        self._headers_section.load_data(cfg.headers)
        self._cookies_section.load_data(cfg.cookies)
        self._token_var.set(cfg.token)
        self._token_type_var.set(cfg.token_type)
        self._proxy_enabled_var.set(cfg.proxy_enabled)
        self._proxy_url_var.set(cfg.proxy_url)
        self._proxy_user_var.set(cfg.proxy_username)
        self._proxy_pass_var.set(cfg.proxy_password)
        self._ssl_verify_var.set(cfg.ssl_verify)
        self._toggle_proxy()

    def _save_only(self):
        cfg = self._collect()
        path = save_auth_config(cfg)
        self._status_var.set(f"✓ Config saved to {path}")
        self.root.after(2000, lambda: self._status_var.set(""))

    def _save_and_scan(self):
        self.result = self._collect()
        save_auth_config(self.result)
        self.root.destroy()

    def _cancel(self):
        self.result = None
        self.root.destroy()

    def _import_config(self):
        path = filedialog.askopenfilename(
            title="Import Auth Config",
            filetypes=[("YAML files", "*.yaml *.yml"), ("JSON files", "*.json"), ("All", "*.*")],
        )
        if not path:
            return
        try:
            with open(path) as f:
                if path.endswith(".json"):
                    data = json.load(f)
                else:
                    import yaml
                    data = yaml.safe_load(f)
            cfg = AuthConfig(**{k: v for k, v in data.items() if k in AuthConfig.__dataclass_fields__})
            self._load_existing(cfg)
            self._status_var.set(f"✓ Imported from {path}")
        except Exception as e:
            messagebox.showerror("Import Error", str(e))

    def _export_config(self):
        path = filedialog.asksaveasfilename(
            title="Export Auth Config",
            defaultextension=".yaml",
            filetypes=[("YAML files", "*.yaml"), ("JSON files", "*.json")],
        )
        if not path:
            return
        try:
            cfg = self._collect()
            import yaml
            with open(path, "w") as f:
                if path.endswith(".json"):
                    json.dump(cfg.to_dict(), f, indent=2)
                else:
                    yaml.dump(cfg.to_dict(), f, default_flow_style=False)
            self._status_var.set(f"✓ Exported to {path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def run(self) -> Optional[AuthConfig]:
        self.root.mainloop()
        return self.result


def launch_auth_gui(existing_config: Optional[AuthConfig] = None) -> Optional[AuthConfig]:
    """Launch the auth GUI and return the collected AuthConfig (or None if cancelled)"""
    win = AuthWindow(existing_config=existing_config)
    return win.run()
