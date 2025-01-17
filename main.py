from app.ui import setup_ui
from app.network_scanner import NetworkScanner
from app.exporter import export_results_to_file
import os

# Callback functions
def scan_callback(ip_range, progress_callback):
    scanner = NetworkScanner()
    results = scanner.scan(ip_range, progress_callback)
    return results

def network_details_callback():
    # You can implement network analysis here
    print("Analyzing network details...")

def export_callback(results):
    export_results_to_file(results, "scan_results.pdf")
    print("Results exported to scan_results.pdf")

def exit_callback():
    print("Exiting the application.")
    os._exit(0)

if __name__ == "__main__":
    assets_path = "assets"  # Path to icons and assets
    root = setup_ui(scan_callback, network_details_callback, export_callback, exit_callback, assets_path)
    root.mainloop()
