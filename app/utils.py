import csv
import tkinter as tk
from tkinter import messagebox

def export_to_csv(results):
    try:
        with open("resources/output/scan_results.csv", "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["IP Address", "MAC Address", "Device Type", "Ping", "OS", "Device Name"])
            writer.writerows(results)
        messagebox.showinfo("Export", "Results exported successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to export: {e}")
