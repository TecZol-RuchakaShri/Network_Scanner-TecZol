import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import os
import socket
from app.network_details_window import NetworkDetailsWindow

def get_local_ip():
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.settimeout(0)
      s.connect(('10.254.254.254', 1))
      ip = s.getsockname()[0]
      s.close()
      return ip
    except Exception:
        return None


class WiFiScannerApp:
    def __init__(self, root, scan_callback, network_details_callback):
        self.root = root
        self.root.title("WiFi Analyzer & Scanner")

        # Set the app icon
        icon_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'icons_graphics', 'main_icon.png')
        if os.path.exists(icon_path):
            try:
                icon = tk.PhotoImage(file=icon_path)
                self.root.iconphoto(True, icon)
            except tk.TclError:
                messagebox.showerror("Error", "Could not load icon. Ensure the path is valid")
        else:
            messagebox.showerror("Error", "Icon not found: " + icon_path)
        self.root.state('zoomed')  # Start in full screen mode

        self.results = []
        self.scanning = False
        self.scan_callback = scan_callback # callback to the scan function.
        self.network_details_callback = network_details_callback # callback to network detail function.
        # UI Elements
        self.create_widgets()

    def create_widgets(self):
        # Big Title Label
        title_label = tk.Label(self.root, text="WiFi Analyzer & Scanner by TecZol", font=("Arial", 16, "bold"))
        title_label.pack(pady=20)

        # IP Range Entry and Analyze Button
        ip_frame = tk.Frame(self.root)
        ip_frame.pack(pady=10, fill=tk.X, padx=20)  # fill=tk.X to expand horizontally
        tk.Label(ip_frame, text="IP Range: ", width=10).pack(side=tk.LEFT)
        self.ip_range_entry = tk.Entry(ip_frame, width=25) # decreased the size of IP input
        self.ip_range_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.ip_range_entry.insert(0, "192.168.1.0/24")

        # Button to get current IP
        get_ip_button = tk.Button(ip_frame, text="Get IP", command=self.get_current_ip, width = 7) # added get IP button.
        get_ip_button.pack(side=tk.LEFT, padx=5)

        tk.Button(ip_frame, text="Analyse Network", command=self.get_network_details, width=15).pack(side=tk.LEFT,
                                                                                                     padx=5)

        # Network Scan Group
        scan_group_frame = tk.LabelFrame(self.root, text="Network Scan", font=("Arial", 12, "bold"), padx=20,
                                         pady=10)  # Added font for bolding the group title
        scan_group_frame.pack(pady=10, fill=tk.X, padx=20)  # fill=tk.X for horizontal

        tk.Label(scan_group_frame,
                 text="Analyse the network and copy the current IP range to Text box before scanning.").pack(
            pady=5, anchor=tk.W)  # anchor=tk.W for left align

        # Scan, Stop, and Export Buttons (inline)
        button_frame = tk.Frame(scan_group_frame)
        button_frame.pack(fill=tk.X, pady=5)  # fill=tk.X for horizontal

        self.scan_button = tk.Button(button_frame, text="Scan", command=self.start_scan, width=10)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(button_frame, text="Stop", command=self.stop_scan, width=10,
                                     state=tk.DISABLED)  # disable the button for now
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.export_button = tk.Button(button_frame, text="Export", command=self.export_results, width=10)
        self.export_button.pack(side=tk.LEFT, padx=5)

        self.exit_button = tk.Button(button_frame, text="Exit", command=self.exit_app, width=10)
        self.exit_button.pack(side=tk.LEFT, padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(scan_group_frame, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.progress.pack(fill=tk.X, pady=5)

        # Table
        self.table = ttk.Treeview(self.root,
                                  columns=("IP", "MAC", "Device Type", "Ping", "OS", "Device Name", "Details"),
                                  show="headings")
        self.table.heading("IP", text="IP Address")
        self.table.heading("MAC", text="MAC Address")
        self.table.heading("Device Type", text="Device Type")
        self.table.heading("Ping", text="Ping")
        self.table.heading("OS", text="OS")
        self.table.heading("Device Name", text="Device Name")
        self.table.heading("Details", text="Details")
        self.table.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

    def get_network_details(self):
         self.network_details_callback()

    def start_scan(self):
        ip_range = self.ip_range_entry.get().strip()
        if not ip_range:
            messagebox.showerror("Error", "Please enter a valid IP range.")
            return
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)  # Disable scan button while scanning
        self.stop_button.config(state=tk.NORMAL)  # Enable stop button
        self.progress['value'] = 0
        self.update_progress()  # start the progress bar animation

        self.root.after(100, self._scan, ip_range)  # call the scanning in a separate thread not to stop the ui.

    def _scan(self, ip_range):
        results = self.scan_callback(ip_range)
        self.populate_table(results)
        self.scanning = False  # Set scanning to false after the scan.
        self.scan_button.config(state=tk.NORMAL)  # Enable scan button
        self.stop_button.config(state=tk.DISABLED)  # disable the stop button
        self.progress['value'] = 100  # Fill the progress bar

    def stop_scan(self):
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)  # Enable scan button
        self.stop_button.config(state=tk.DISABLED)  # disable stop button
        self.progress['value'] = 0  # reset the progress bar

    def update_progress(self):
        if self.scanning:
            self.progress['value'] += 1  # increase by one for each loop
            if self.progress['value'] < 90:
                self.root.after(50,
                                self.update_progress)  # schedule next update if scanning and progress not completed.

    def populate_table(self, results):
         self.table.delete(*self.table.get_children())
         for result in results:
            detail_button = tk.Button(self.table, text="Details",
                                      command=lambda ip=result[0]: self.show_device_details(ip))
            self.table.insert("", tk.END, values=result + (detail_button,))
            # detail_button.pack(side=tk.RIGHT)

    def show_device_details(self, ip):
        messagebox.showinfo("Device Details", f"Details for IP: {ip} will appear here!")

    def export_results(self):
        # if self.results:
        #     export_to_csv(self.results)
        # else:
        messagebox.showinfo("Export", "No results to export.")

    def exit_app(self):
        self.scanning = False
        self.root.destroy()  # Close the window

    def get_current_ip(self):
        local_ip = get_local_ip()
        if local_ip:
            self.ip_range_entry.delete(0,tk.END)
            self.ip_range_entry.insert(0, local_ip)
        else:
            messagebox.showerror("Error", "Could not get local IP address.")

def setup_ui(scan_callback, network_details_callback):
    root = tk.Tk()
    app = WiFiScannerApp(root, scan_callback, network_details_callback)
    return root