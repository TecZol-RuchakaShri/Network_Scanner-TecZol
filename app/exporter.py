from fpdf import FPDF

def export_results_to_file(results, filename="scan_results.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Network Scan Results", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", style="B", size=12)
    pdf.cell(40, 10, "IP Address", border=1)
    pdf.cell(40, 10, "MAC Address", border=1)
    pdf.cell(40, 10, "Vendor", border=1)
    pdf.cell(40, 10, "Device", border=1)
    pdf.cell(40, 10, "OS", border=1)
    pdf.ln()

    pdf.set_font("Arial", size=12)
    for result in results:
        pdf.cell(40, 10, result.get("ip", ""), border=1)
        pdf.cell(40, 10, result.get("mac", ""), border=1)
        pdf.cell(40, 10, result.get("vendor", ""), border=1)
        pdf.cell(40, 10, result.get("device", ""), border=1)
        pdf.cell(40, 10, result.get("os", ""), border=1)
        pdf.ln()

    pdf.output(filename)
    print(f"Exported results to {filename}")
