import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import os
import socket
from app.network_details_window import NetworkDetailsWindow
import subprocess
import threading
import logging
from app.network_scanner import NetworkScanner
from ipaddress import IPv4Interface
import psutil
import concurrent.futures
from app.scan_console import ScanConsole
import queue

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

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
    def __init__(self, root, scan_callback, network_details_callback, assets_path, scanner):
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
        self.scan_callback = scan_callback  # callback to the scan function.
        self.network_details_callback = network_details_callback  # callback to network detail function.
        self.assets_path = assets_path
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=10)  # max 10 threads.
        self.futures = []
        self.scan_console = None
        self.scanner = scanner
        self.result_queue = queue.Queue()
        self.limit = -1
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
        self.ip_range_entry = ttk.Entry(ip_frame, width=25, font=("Arial", 10))  # decreased the size of IP input
        self.ip_range_entry.pack(side=tk.LEFT, padx=(0, 5), expand=True, fill=tk.X)
        self.ip_range_entry.insert(0, "192.168.1.0/24")

        # Button to get current IP
        get_ip_button = ttk.Button(ip_frame, text="Get IP", command=self.get_current_ip,
                                   width=7)  # added get IP button.
        get_ip_button.pack(side=tk.LEFT, padx=(0, 5))

        tk.Button(ip_frame, text="Analyse Network", command=self.get_network_details, width=15).pack(side=tk.LEFT,
                                                                                                     padx=5)
        # Update OUI Database Button
        update_oui_button = ttk.Button(ip_frame, text="Update OUI Database", command=self.start_oui_update, width=15)
        update_oui_button.pack(side=tk.LEFT, padx=5)

        # Limit scan Button
        limit_scan_button = ttk.Button(ip_frame, text="Limit Scan", command=self.open_limit_dialog, width=15)
        limit_scan_button.pack(side=tk.LEFT, padx=5)

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
                                  columns=(
                                  "IP", "MAC", "Device Type", "Ping", "OS", "Device Name", "Model", "Make", "Version",
                                  "Details"),
                                  show="headings")
        self.table.heading("IP", text="IP Address")
        self.table.heading("MAC", text="MAC Address")
        self.table.heading("Device Type", text="Device Type")
        self.table.heading("Ping", text="Ping")
        self.table.heading("OS", text="OS")
        self.table.heading("Device Name", text="Device Name")
        self.table.heading("Model", text="Model")
        self.table.heading("Make", text="Make")
        self.table.heading("Version", text="Version")
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

        # Cancel any existing futures before starting
        if self.scan_console:
            self.scan_console.clear_console()
        for future in self.futures:
            future.cancel()
        self.futures = []  # reset futures list.
        if not self.scan_console or not self.scan_console.winfo_exists():
            self.scan_console = ScanConsole(self.root, "Scanning")  # create the scanning console.
        self.result_queue.queue.clear()

        self.root.after(100, self._scan, ip_range)  # call the scanning in a separate thread not to stop the ui.

    def _scan(self, ip_range):
        scan_generator = self.scan_callback(ip_range)
        self.root.after(10, self._process_scan_generator, scan_generator, ip_range)

    def _process_scan_generator(self, scan_generator, ip_range):
        try:
            results = []
            while True:
                item = next(scan_generator)
                if item == "Progress":
                    progress = next(scan_generator)
                    self.progress['value'] = progress
                    if self.scan_console:
                        self.scan_console.append_message(f"Progress: {progress}%")
                elif isinstance(item, dict):
                    results.append(item)
                    if self.limit != -1 and len(results) >= self.limit:
                        break
            for item in results:
                future = self.thread_pool.submit(self._process_device_info, item, ip_range)
                self.futures.append(future)
            concurrent.futures.wait(self.futures)
            self._populate_table_all()
        except StopIteration:
            self.scanning = False  # Set scanning to false after the scan.
            self.scan_button.config(state=tk.NORMAL)  # Enable scan button
            self.stop_button.config(state=tk.DISABLED)  # disable the stop button
            self.progress['value'] = 100
            concurrent.futures.wait(self.futures)  # wait for all futures to finish before leaving this method.
        except Exception as e:
            messagebox.showerror("Scan Error", f"An error occurred during scanning: {e}")
            self.scanning = False  # Set scanning to false after the scan.
            self.scan_button.config(state=tk.NORMAL)  # Enable scan button
            self.stop_button.config(state=tk.DISABLED)  # disable the stop button
            self.progress['value'] = 100

    def _process_device_info(self, result, ip_range):
        try:
            scanner = NetworkScanner()
            ip = result.get("ip")
            mac = result.get("mac")
            if ip is not None:
                device_type = scanner.get_device_type(mac)
                ping = scanner.ping(ip)
                os_info = scanner.get_os_info(ip)
                device_name = scanner.get_device_name(ip)
                model_info = scanner.get_model_info(mac)
                self.result_queue.put([(ip, mac, device_type, f"{ping:.2f} ms" if ping else "Unreachable", os_info,
                                        device_name, model_info.get("model", "Unknown"), model_info.get("make", "Unknown"),
                                        model_info.get("version", "Unknown"))])
                if self.scan_console:
                    self.scan_console.append_message(f"Found device - IP: {ip}, MAC: {mac}")
        except Exception as e:
            logging.error(f"Error getting device info : {e} for : {result.get('ip', 'Unknown IP')}")
            if self.scan_console:
                self.scan_console.append_message(f"Error - for IP : {result.get('ip', 'Unknown IP')} : {e}")
            self.result_queue.put(
                [(None, None, "Unknown", "Unreachable", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown")])

    def _populate_table_all(self):
        all_results = []
        while not self.result_queue.empty():
            item = self.result_queue.get()
            all_results.extend(item)
        self.root.after(0, self.populate_table, all_results)

    def stop_scan(self):
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)  # Enable scan button
        self.stop_button.config(state=tk.DISABLED)  # disable stop button
        self.progress['value'] = 0  # reset the progress bar
        if self.scan_console:
            self.scan_console.close()

    def update_progress(self):
        if self.scanning:
            self.progress['value'] += 1  # increase by one for each loop
            if self.progress['value'] < 90:
                self.root.after(50,
                                self.update_progress)  # schedule next update if scanning and progress not completed.

    def populate_table(self, results):
        for result in results:
            detail_button = tk.Button(self.table, text="Details",
                                      command=lambda ip=result[0]: self.show_device_details(ip))
            self.table.insert("", tk.END, values=result + (detail_button,))

    def show_device_details(self, ip):
        messagebox.showinfo("Device Details", f"Details for IP: {ip} will appear here!")

    def export_results(self):
        messagebox.showinfo("Export", "No results to export.")

    def exit_app(self):
        self.scanning = False
        self.root.destroy()  # Close the window

    def get_current_ip(self):
        local_ip = get_local_ip()
        if local_ip:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip_address = s.getsockname()[0]
                s.close()
                for interface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET and addr.address == ip_address:
                            netmask = addr.netmask
                            if netmask:
                                ip = IPv4Interface(f"{ip_address}/{netmask}")
                                self.ip_range_entry.delete(0, tk.END)
                                self.ip_range_entry.insert(0, str(ip))
                                return
                self.ip_range_entry.delete(0, tk.END)
                self.ip_range_entry.insert(0, f"{local_ip}/24")  # default to /24 if can not get subnet mask
            except Exception as e:
                self.ip_range_entry.delete(0, tk.END)
                self.ip_range_entry.insert(0, f"{local_ip}/24")
        else:
            messagebox.showerror("Error", "Could not get local IP address.")

    def start_oui_update(self):
        # Build the command to run
        oui_updater_path = os.path.join(os.path.dirname(__file__), 'oui_updater.py')
        command = f'python "{oui_updater_path}"'

        def run_command_in_thread():
            try:
                subprocess.run(command, shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW,
                               cwd=os.path.dirname(__file__))
                messagebox.showinfo("OUI Update", "OUI data downloaded successfully")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("OUI Update", f"Error updating OUI database {e}")
            except FileNotFoundError as e:
                messagebox.showerror("OUI Update", f"Error finding the updater script {e}")

        threading.Thread(target=run_command_in_thread, daemon=True).start()

    def open_limit_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Set Scan Limit")
        dialog.geometry("300x150")
        dialog.resizable(False, False)

        label = ttk.Label(dialog, text="Enter number of hosts to limit:", font=("Arial", 10))
        label.pack(pady=10)

        entry = ttk.Entry(dialog, width=20)
        entry.pack(pady=5)

        def ok_clicked():
            try:
                limit = int(entry.get())
                self.limit = limit
                dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid integer for the limit")

        def cancel_clicked():
            dialog.destroy()

        ok_button = ttk.Button(dialog, text="Ok", command=ok_clicked)
        ok_button.pack(side=tk.LEFT, padx=20)
        cancel_button = ttk.Button(dialog, text="Cancel", command=cancel_clicked)
        cancel_button.pack(side=tk.RIGHT, padx=20)

def setup_ui(scan_callback, network_details_callback, assets_path, scanner):
    root = tk.Tk()
    app = WiFiScannerApp(root, scan_callback, network_details_callback, assets_path, scanner)
    return root
