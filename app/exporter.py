from fpdf import FPDF

def export_results_to_file(results, filename):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Title
    pdf.set_font("Arial", style="B", size=16)
    pdf.cell(200, 10, txt="Network Scan Results", ln=True, align="C")
    pdf.ln(10)

    # Table Headers
    pdf.set_font("Arial", style="B", size=12)
    pdf.cell(60, 10, "IP Address", border=1, align="C")
    pdf.cell(60, 10, "MAC Address", border=1, align="C")
    pdf.cell(60, 10, "Vendor", border=1, align="C")
    pdf.ln()

    # Table Rows
    pdf.set_font("Arial", size=12)
    for result in results:
        pdf.cell(60, 10, result.get("ip", ""), border=1)
        pdf.cell(60, 10, result.get("mac", ""), border=1)
        pdf.cell(60, 10, result.get("vendor", ""), border=1)
        pdf.ln()

    # Save PDF
    pdf.output(filename)
    print(f"Exported results to {filename}")
