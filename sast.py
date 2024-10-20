import os
import subprocess
import re
from fpdf import FPDF

def scan_code(directory):
    # Jalankan Semgrep dan tangkap output
    try:
        result = subprocess.run(['semgrep', '--config', 'auto', directory],
                                capture_output=True, text=True, check=True)
        print("Semgrep Output:\n", result.stdout)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running Semgrep: {e}")
        return None

def format_vulnerabilities(output):
    vulnerabilities = []
    lines = output.splitlines()
    
    file_path = ""
    description = ""
    details = ""
    line_number = ""
    
    for line in lines:
        if line.strip().startswith("/"):
            file_path = line.strip()
        
        if "❯❱" in line or "❯❯❱" in line:
            description = line.strip()

        if line.strip().startswith("Details:"):
            details = line.strip()

        if re.match(r'^\d+┆', line.strip()):
            line_number = line.strip()

        if file_path and description and details and line_number:
            vulnerabilities.append((file_path, line_number, description, details))
            file_path, description, details, line_number = "", "", "", ""
    
    return vulnerabilities

def create_pdf(vulnerabilities, pdf_filename):
    pdf = FPDF()
    pdf.add_page()

    pdf.add_font('DejaVu', '', 'DejaVuSansCondensed.ttf', uni=True)
    pdf.set_font("DejaVu", size=12)
    
    pdf.cell(200, 10, txt="Laporan Kerentanan", ln=True, align='C')
    pdf.ln(10)

    pdf.set_font("DejaVu", size=10)

    if vulnerabilities:
        for vuln in vulnerabilities:
            print(f"Prosess Kerentanan: {vuln}")

            if isinstance(vuln, tuple) and len(vuln) == 4:
                file_path = vuln[0]  
                line_number = vuln[1]  
                description = vuln[2]  
                details = vuln[3] 

                vuln_info = f"File: {file_path}\nLine: {line_number}\nDescription: {description}\nDetails: {details}\n"
            else:
                vuln_info = "Format kerentanan tidak diketahui"

            pdf.multi_cell(0, 10, txt=vuln_info)
            pdf.ln(5)
    else:
        print("Tidak ada kerentanan yang ditemukan untuk diproses.")

    pdf.output(pdf_filename)


def main():
    directory = input("Masukkan direktori untuk dipindai: ")
    if not os.path.exists(directory):
        print("Direktori yang ditentukan tidak ada.")
        return

    output = scan_code(directory)
    
    if output:
        vulnerabilities = format_vulnerabilities(output)
        if vulnerabilities:
            create_pdf(vulnerabilities, "laporan_kerentanan.pdf")
            print("Laporan telah dibuat: laporan_kerentanan.pdf")
        else:
            print("Tidak ada kerentanan ditemukan.")
    else:
        print("Pemindaian gagal.")

if __name__ == "__main__":
    main()
