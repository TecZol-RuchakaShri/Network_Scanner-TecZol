import tkinter as tk
from tkinter import ttk, messagebox
import threading

class WiFiScannerApp:
    def __init__(self, root, scan_callback, network_details_callback, export_callback, exit_callback, assets_path):
        self.root = root
        self.scan_callback = scan_callback
        self.network_details_callback = network_details_callback
        self.export_callback = export_callback
        self.exit_callback = exit_callback
        self.assets_path = assets_path
        self.results = []
        self.scanning = False
        self.create_widgets()

    def create_widgets(self):
        # Title
        title_label = tk.Label(self.root, text="WiFi Analyzer & Scanner by TecZol", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)

        # IP Range Input
        ip_frame = tk.Frame(self.root)
        ip_frame.pack(pady=10, fill=tk.X, padx=20)
        tk.Label(ip_frame, text="IP Range: ", width=10).pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(ip_frame, width=25, font=("Arial", 10))
        self.ip_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.ip_entry.insert(0, "192.168.1.0/24")

        # Buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10, padx=20)
        ttk.Button(button_frame, text="Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export", command=self.export_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Exit", command=self.exit_callback).pack(side=tk.LEFT, padx=5)

        # Progress Bar
        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.progress.pack(fill=tk.X, pady=5, padx=20)

        # Table
        self.table = ttk.Treeview(self.root, columns=("IP", "MAC", "Vendor"), show="headings")
        self.table.heading("IP", text="IP Address")
        self.table.heading("MAC", text="MAC Address")
        self.table.heading("Vendor", text="Vendor")
        self.table.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.results.clear()
        ip_range = self.ip_entry.get()
        threading.Thread(target=self._scan, args=(ip_range,)).start()

    def _scan(self, ip_range):
        def progress_callback(percent):
            self.progress["value"] = percent
        self.results = self.scan_callback(ip_range, progress_callback)
        self.update_table()
        self.progress["value"] = 0
        self.scanning = False

    def update_table(self):
        for row in self.table.get_children():
            self.table.delete(row)
        for result in self.results:
            self.table.insert("", tk.END, values=(result["ip"], result["mac"], result["vendor"]))

    def export_results(self):
        if self.results:
            self.export_callback(self.results)
        else:
            messagebox.showerror("Error", "No results to export!")

def setup_ui(scan_callback, network_details_callback, export_callback, exit_callback, assets_path):
    root = tk.Tk()
    root.title("WiFi Scanner")
    root.geometry("600x400")
    app = WiFiScannerApp(root, scan_callback, network_details_callback, export_callback, exit_callback, assets_path)
    return root
