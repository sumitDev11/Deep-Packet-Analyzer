from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from queue import Queue, Empty
from contextlib import redirect_stdout
import io

from dpi_engine_py.engine import DPIEngine, Config


class DPIApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("DPI Engine GUI")
        self.geometry("900x650")
        self.minsize(780, 560)

        self.log_queue: Queue[str] = Queue()
        self.worker: threading.Thread | None = None

        self.input_var = tk.StringVar(value=str(Path(".\\test_dpi.pcap")))
        self.output_var = tk.StringVar(value=str(Path(".\\output_py.pcap")))
        self.block_ip_var = tk.StringVar()
        self.block_app_var = tk.StringVar()
        self.block_domain_var = tk.StringVar()
        self.lbs_var = tk.StringVar(value="2")
        self.fps_var = tk.StringVar(value="2")

        self._build_ui()
        self.after(100, self._drain_logs)

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=12)
        root.pack(fill=tk.BOTH, expand=True)

        files = ttk.LabelFrame(root, text="Files", padding=10)
        files.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(files, text="Input PCAP").grid(row=0, column=0, sticky="w")
        ttk.Entry(files, textvariable=self.input_var, width=80).grid(row=0, column=1, padx=8, sticky="ew")
        ttk.Button(files, text="Browse", command=self._browse_input).grid(row=0, column=2)

        ttk.Label(files, text="Output PCAP").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(files, textvariable=self.output_var, width=80).grid(row=1, column=1, padx=8, pady=(8, 0), sticky="ew")
        ttk.Button(files, text="Browse", command=self._browse_output).grid(row=1, column=2, pady=(8, 0))
        files.columnconfigure(1, weight=1)

        rules = ttk.LabelFrame(root, text="Rules (comma-separated)", padding=10)
        rules.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(rules, text="Block IPs").grid(row=0, column=0, sticky="w")
        ttk.Entry(rules, textvariable=self.block_ip_var).grid(row=0, column=1, padx=8, sticky="ew")
        ttk.Label(rules, text="Block Apps").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(rules, textvariable=self.block_app_var).grid(row=1, column=1, padx=8, pady=(8, 0), sticky="ew")
        ttk.Label(rules, text="Block Domains").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(rules, textvariable=self.block_domain_var).grid(row=2, column=1, padx=8, pady=(8, 0), sticky="ew")
        rules.columnconfigure(1, weight=1)

        perf = ttk.LabelFrame(root, text="Thread Settings", padding=10)
        perf.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(perf, text="Load Balancers (--lbs)").grid(row=0, column=0, sticky="w")
        ttk.Entry(perf, textvariable=self.lbs_var, width=10).grid(row=0, column=1, padx=8, sticky="w")
        ttk.Label(perf, text="FP per LB (--fps)").grid(row=0, column=2, sticky="w")
        ttk.Entry(perf, textvariable=self.fps_var, width=10).grid(row=0, column=3, padx=8, sticky="w")

        actions = ttk.Frame(root)
        actions.pack(fill=tk.X, pady=(0, 10))
        self.run_btn = ttk.Button(actions, text="Run DPI", command=self._run_clicked)
        self.run_btn.pack(side=tk.LEFT)
        ttk.Button(actions, text="Clear Log", command=self._clear_log).pack(side=tk.LEFT, padx=8)

        log_frame = ttk.LabelFrame(root, text="Output", padding=8)
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.log = tk.Text(log_frame, wrap="word", state="disabled")
        self.log.pack(fill=tk.BOTH, expand=True)

    def _browse_input(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if path:
            self.input_var.set(path)

    def _browse_output(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
        )
        if path:
            self.output_var.set(path)

    @staticmethod
    def _split_csv(raw: str) -> list[str]:
        return [x.strip() for x in raw.split(",") if x.strip()]

    def _append_log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert(tk.END, text)
        self.log.see(tk.END)
        self.log.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", tk.END)
        self.log.configure(state="disabled")

    def _set_running(self, running: bool) -> None:
        self.run_btn.configure(state=("disabled" if running else "normal"))

    def _run_clicked(self) -> None:
        if self.worker and self.worker.is_alive():
            return

        input_file = self.input_var.get().strip()
        output_file = self.output_var.get().strip()
        if not input_file or not output_file:
            messagebox.showerror("Missing Fields", "Input and output paths are required.")
            return

        try:
            lbs = max(1, int(self.lbs_var.get().strip()))
            fps = max(1, int(self.fps_var.get().strip()))
        except ValueError:
            messagebox.showerror("Invalid Threads", "lbs and fps must be integers.")
            return

        block_ips = self._split_csv(self.block_ip_var.get())
        block_apps = self._split_csv(self.block_app_var.get())
        block_domains = self._split_csv(self.block_domain_var.get())

        self._set_running(True)
        self._append_log("\n=== Starting DPI job ===\n")

        def worker_job() -> None:
            stream = io.StringIO()
            try:
                with redirect_stdout(stream):
                    engine = DPIEngine(Config(num_lbs=lbs, fps_per_lb=fps))
                    for ip in block_ips:
                        engine.block_ip(ip)
                    for app in block_apps:
                        engine.block_app(app)
                    for dom in block_domains:
                        engine.block_domain(dom)
                    ok = engine.process(input_file, output_file)
                    if ok:
                        print(f"\nOutput written to: {output_file}")
                    else:
                        print("\nDPI processing failed.")
            except Exception as exc:
                stream.write(f"\nError: {exc}\n")
            finally:
                self.log_queue.put(stream.getvalue())
                self.log_queue.put("__DONE__")

        self.worker = threading.Thread(target=worker_job, daemon=True)
        self.worker.start()

    def _drain_logs(self) -> None:
        try:
            while True:
                item = self.log_queue.get_nowait()
                if item == "__DONE__":
                    self._set_running(False)
                    self._append_log("=== Job finished ===\n")
                else:
                    self._append_log(item)
        except Empty:
            pass
        self.after(100, self._drain_logs)


if __name__ == "__main__":
    app = DPIApp()
    app.mainloop()

