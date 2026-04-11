#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
import subprocess
import sys

PROFILES = ["blackvue", "thinkware", "generic"]


def run_cmd_async(cmd, log_fn, done_fn):
    def worker():
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:  # type: ignore
                log_fn(line.rstrip())
            rc = proc.wait()
            if rc != 0:
                log_fn(f"[exit {rc}] {' '.join(cmd)}")
        except Exception as e:
            log_fn(f"[error] {e}")
        finally:
            done_fn()
    threading.Thread(target=worker, daemon=True).start()


def main():
    root = tk.Tk()
    root.title("Dashcam Renamer (OCR)")
    root.geometry("720x520")

    src_var = tk.StringVar()
    out_var = tk.StringVar(value=str((Path.home()/"DashcamImports").resolve()))
    prof_vars = {p: tk.BooleanVar(value=(p in ("blackvue","thinkware"))) for p in PROFILES}
    strict_ocr = tk.BooleanVar(value=False)
    prefer_start = tk.BooleanVar(value=False)

    def browse_folder():
        p = filedialog.askdirectory(title="Select Folder or Mounted E01 Extract")
        if p:
            src_var.set(p)

    def browse_e01():
        p = filedialog.askopenfilename(title="Select E01 image", filetypes=[("E01 images", "*.E01 *.e01")])
        if p:
            src_var.set(p)

    def browse_out():
        p = filedialog.askdirectory(title="Select Output Folder")
        if p:
            out_var.set(p)

    frm = tk.Frame(root)
    frm.pack(fill="x", padx=12, pady=8)

    tk.Label(frm, text="Source (folder or .E01)").grid(row=0, column=0, sticky="w")
    tk.Entry(frm, textvariable=src_var, width=60).grid(row=1, column=0, sticky="we", columnspan=2, pady=2)
    tk.Button(frm, text="Browse Folder", command=browse_folder).grid(row=1, column=2, padx=4)
    tk.Button(frm, text="Browse E01", command=browse_e01).grid(row=1, column=3, padx=4)

    tk.Label(frm, text="Output Folder").grid(row=2, column=0, sticky="w", pady=(8,2))
    tk.Entry(frm, textvariable=out_var, width=60).grid(row=3, column=0, sticky="we", columnspan=2)
    tk.Button(frm, text="Change", command=browse_out).grid(row=3, column=2, padx=4)

    opt = tk.Frame(root)
    opt.pack(fill="x", padx=12, pady=8)
    tk.Label(opt, text="Profiles:").grid(row=0, column=0, sticky="w")
    for i, p in enumerate(PROFILES):
        tk.Checkbutton(opt, text=p, variable=prof_vars[p]).grid(row=0, column=i+1, padx=4)
    tk.Checkbutton(opt, text="Strict OCR (ignore metadata)", variable=strict_ocr).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6,0))
    tk.Checkbutton(opt, text="Prefer start (subtract duration for file times)", variable=prefer_start).grid(row=2, column=0, columnspan=3, sticky="w")

    log = tk.Text(root, height=16)
    log.pack(fill="both", expand=True, padx=12, pady=8)

    btn_frame = tk.Frame(root)
    btn_frame.pack(fill="x", padx=12, pady=8)
    run_btn = tk.Button(btn_frame, text="Run", width=12)
    run_btn.pack(side="left")

    def append(s: str):
        log.insert("end", s + "\n")
        log.see("end")

    def set_running(running: bool):
        run_btn.config(state=("disabled" if running else "normal"))

    def on_run():
        src = src_var.get().strip()
        dest = out_var.get().strip()
        if not src:
            messagebox.showerror("Error", "Select a source folder or .E01 first")
            return
        profiles = [p for p,v in prof_vars.items() if v.get()]
        if not profiles:
            messagebox.showerror("Error", "Select at least one profile")
            return
        # If it's E01, call ingest; otherwise rsync folder, then run renamer
        set_running(True)
        Path(dest).mkdir(parents=True, exist_ok=True)
        if src.lower().endswith('.e01'):
            cmd = [sys.executable, '-m', 'dashcam_tools.ingest', '--src', src, '--dest', dest,
                   '--profiles', ",".join(profiles)]
            if strict_ocr.get(): cmd.append('--strict-ocr')
            if prefer_start.get(): cmd.append('--prefer-start')
            append("[start] " + " ".join(cmd))
            run_cmd_async(cmd, append, lambda: set_running(False))
        else:
            # rsync copy then run renamer
            append(f"[copy] {src} -> {dest}")
            cmd_copy = [sys.executable, '-m', 'dashcam_tools.ingest', '--src', src, '--dest', dest,
                        '--profiles', ",".join(profiles), '--renamer-args', '--only-unnamed']
            if strict_ocr.get(): cmd_copy += ['--strict-ocr']
            if prefer_start.get(): cmd_copy += ['--prefer-start']
            run_cmd_async(cmd_copy, append, lambda: set_running(False))

    run_btn.config(command=on_run)
    root.mainloop()

if __name__ == "__main__":
    main()

