import tkinter as tk
from app.ui import setup_ui
from app.network_scanner import NetworkScanner


def scan_callback(ip_range):
    scanner = NetworkScanner()
    results = scanner.scan(ip_range)
    return results

def network_details_callback():
    # import here to avoid circular import error.
    from app.network_details_window import NetworkDetailsWindow
    from app.network_details import NetworkDetailsApp
    details_app = NetworkDetailsApp(root)
    NetworkDetailsWindow(root, details_app).grab_set()

if __name__ == '__main__':
      root = tk.Tk()
      setup_ui(scan_callback, network_details_callback)
      root.mainloop()