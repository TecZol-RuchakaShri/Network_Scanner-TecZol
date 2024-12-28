import tkinter as tk
from tkinter import ttk, messagebox, Scrollbar
import subprocess
import platform
import socket
import requests
import json
import speedtest
import threading
import psutil
import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib import colors
import ipaddress


class NetworkDetailsWindow(tk.Toplevel):
    def __init__(self, parent, network_details_app):
        super().__init__(parent)
        self.title("Network Details")
        # Set the app icon
        icon_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'icons_graphics', 'wifi.png')
        if os.path.exists(icon_path):
            try:
                icon = tk.PhotoImage(file=icon_path)
                self.iconphoto(True, icon)
            except tk.TclError:
                messagebox.showerror("Error", "Could not load icon. Ensure the path is valid")
        else:
            messagebox.showerror("Error", "Icon not found: " + icon_path)

        self.geometry("800x600")  # Set the default geometry of the new window.
        self.network_details_app = network_details_app
        self.details = {}
        self.create_widgets()
        self.fetch_and_display_details()

    def create_widgets(self):
        # Buttons at the top
        buttons_frame = tk.Frame(self)
        buttons_frame.pack(side=tk.TOP, fill=tk.X, padx=20, pady=10)

        tk.Button(buttons_frame, text="Exit", command=self.destroy, width=10).pack(side=tk.LEFT, padx=5)
        tk.Button(buttons_frame, text="Export PDF", command=self.export_to_pdf, width=10).pack(side=tk.LEFT, padx=5)

        self.status_label = tk.Label(buttons_frame, text="Loading Details...", font=("Arial", 10, "italic"),
                                     anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, padx=10, expand=True)

        # Progress bar
        self.progress = ttk.Progressbar(self, orient=tk.HORIZONTAL, length=200, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5, padx=20)
        self.progress.start(10)  # start animation

        # Scrollable Frame
        self.canvas = tk.Canvas(self)
        self.scrollbar = Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.details_frame = self.scrollable_frame
        self.copy_buttons = []

    def fetch_and_display_details(self):
        threading.Thread(target=self._fetch_details_thread, daemon=True).start()

    def _fetch_details_thread(self):
        try:
            self.status_label.config(text="Fetching Network Details...")
            self.details = self.network_details_app.get_all_network_details()
            self.status_label.config(text="Displaying...")
            self.progress.stop()
            self.progress.pack_forget()  # remove the progress bar.

            for i, (key, value) in enumerate(self.details.items()):
                frame = tk.Frame(self.details_frame)
                frame.pack(fill=tk.X, pady=10)  # Increased the spacing to 10.

                label = tk.Label(frame, text=f"{key}: ", anchor=tk.W, width=35, font=("Arial", 10, "bold"))
                label.pack(side=tk.LEFT)

                value_label = tk.Label(frame, text=value, anchor=tk.W,
                                       wraplength=500)  # Text wrapping for longer values
                value_label.pack(side=tk.LEFT, expand=True, fill=tk.X)

                copy_button = tk.Button(frame, text="Copy", command=lambda v=value: self.copy_to_clipboard(v))
                copy_button.pack(side=tk.LEFT)

                self.copy_buttons.append(copy_button)
            self.status_label.config(text="Ready", fg="green", font=("Arial", 10, "bold italic"))
        except Exception as e:
            self.status_label.config(text="Error: " + str(e), fg="red", font=("Arial", 10, "bold italic"))

    def copy_to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()

    def export_to_pdf(self):
        threading.Thread(target=self._export_to_pdf_thread, daemon=True).start()

    def _export_to_pdf_thread(self):
        try:
            self.status_label.config(text="Creating PDF...", fg="black", font=("Arial", 10, "italic"))

            doc = SimpleDocTemplate("network_details.pdf", pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            # Title
            title_style = styles['h1']
            story.append(Paragraph("Network Analysis Report by - TecZol WiFi Analyzer", title_style))
            story.append(Spacer(1, 0.2 * inch))

            # Date and Network
            date_time = self.network_details_app.get_current_date_time()
            ssid = self.details.get("SSID", "Not Available")
            story.append(Paragraph(f"Date :- {date_time}", styles['Normal']))
            story.append(Paragraph(f"Network :- {ssid}", styles['Normal']))

            story.append(Spacer(1, 0.2 * inch))

            # Introduction Text
            host = self.details.get("Name of the computer that run the application", "Not Available")
            story.append(
                Paragraph(f"This is Automated Report - This Report was executed on {host} on {ssid}", styles['Normal']))
            story.append(Spacer(1, 0.2 * inch))

            # Prepare Data for Table
            data = [
                ["SSID", ":", self.details.get('SSID', 'Not Available')],
                ["Application Host", ":",
                 self.details.get('Name of the computer that run the application', 'Not Available')],
                ["Current OS", ":", self.details.get('OS version', 'Not Available')],
                ["Host IP", ":", self.details.get('LAN/WAN IP address', 'Not Available')],
                ["Public IP address", ":", self.details.get('Public IP address', 'Not Available')],
                ["ISP to Public Network", ":", self.details.get('ISP Name', 'Not Available')],
                ["Link Upload Speed", ":", self.details.get('Average Internet Upload Speed', 'Not Available')],
                ["Link Download Speed", ":", self.details.get('Average Internet Download Speed', 'Not Available')],
                ["Link Ping", ":", self.details.get('Ping Internet Speed', 'Not Available')],
                ["Average LAN Upload Speed", ":", self.details.get('Average LAN Upload Speed', 'Not Available')],
                ["Average LAN Download Speed", ":", self.details.get('Average LAN Download Speed', 'Not Available')],
                ["LAN Ping", ":", self.details.get('Ping LAN Speed', 'Not Available')],
                ["Default Gateway", ":", self.details.get('Default Gateway', 'Not Available')],
            ]
            iprange = self.details.get("IP Range", "Not Available")
            start_ip = iprange.split(" - ")[0] if " - " in iprange else "Not Available"
            end_ip = iprange.split(" - ")[1] if " - " in iprange else "Not Available"
            data.append(["Start IP Address", ":", start_ip])
            data.append(["End IP Address", ":", end_ip])

            table = Table(data)
            table.setStyle(TableStyle([('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                       ('FONTSIZE', (0, 0), (-1, -1), 10),

                                       ]))  # aligns columns to left, and sets the font size of the content of the table.
            story.append(table)

            story.append(Spacer(1, 0.2 * inch))

            story.append(Paragraph(f"In here it should display SSID:  {ssid}", styles['Normal']))
            story.append(Paragraph(f"Protocol: [example :- Wi-Fi 4 (802.11n)]", styles['Normal']))
            story.append(Paragraph(f"Security type: [Example WPA2-Personal]", styles['Normal']))
            story.append(Paragraph(f"Network band: [Example 2.4 GHz]", styles['Normal']))
            story.append(Paragraph(f"Network channel: [Example 9]", styles['Normal']))

            story.append(Spacer(1, 0.2 * inch))

            story.append(Paragraph("**This is report is generated by Open source Software Developed by TecZol**",
                                   styles['Italic']))

            doc.build(story)
            self.status_label.config(text="Exported to PDF", fg="green", font=("Arial", 10, "bold italic"))

            os.startfile("network_details.pdf")

        except Exception as e:
            self.status_label.config(text="Error: PDF creation failed: " + str(e), fg="red",
                                     font=("Arial", 10, "bold italic"))