import os
import re
import csv

# The "Hit List" of classical algorithms that will be broken by Quantum Computers
# or are already deprecated.
VULNERABLE_PATTERNS = {
    "RSA (Prime Factorization)": r"(?i)\bimport\s+rsa\b|\bfrom\s+.*\s+import\s+rsa\b|\.RSA\b",
    "ECC (Elliptic Curve)": r"(?i)\becc\b|\belliptic_curve\b|\becdsa\b",
    "MD5 (Weak Hash)": r"(?i)\bmd5\b",
    "SHA1 (Weak Hash)": r"(?i)\bsha1\b"
}

def scan_directory(directory_path):
    print(f"--- Initiating CBOM Quantum Vulnerability Scan ---")
    print(f"Scanning target directory: {directory_path}\n")
    
    findings = []

    # Walk through all folders and files
    for root, dirs, files in os.walk(directory_path):
        # We MUST skip our virtual environment, otherwise it will flag 
        # thousands of files inside the standard libraries!
        if '.venv' in root or '__pycache__' in root or '.git' in root:
            continue
            
        for file in files:
            if file.endswith(".py"): # We are only scanning Python files for this project
                file_path = os.path.join(root, file)
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                    # Read the file line by line
                    for line_number, line_content in enumerate(lines, 1):
                        # Check each line against our Hit List
                        for algo_name, pattern in VULNERABLE_PATTERNS.items():
                            if re.search(pattern, line_content):
                                findings.append({
                                    "File": file,
                                    "Path": file_path,
                                    "Line Number": line_number,
                                    "Vulnerable Algorithm": algo_name,
                                    "Code Snippet": line_content.strip()
                                })
    return findings

def generate_csv_report(findings, output_filename="cbom_report.csv"):
    if not findings:
        print("[+] Scan Complete. No vulnerable algorithms found! Codebase is Quantum-Safe.")
        return

    print(f"[-] WARNING: Found {len(findings)} vulnerable cryptographic implementations!")
    
    # Write findings to a CSV file 
    keys = findings[0].keys()
    with open(output_filename, 'w', newline='') as f:
        dict_writer = csv.DictWriter(f, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(findings)
        
    print(f"[!] CBOM Report generated: {output_filename}")
    
    # Print a quick summary to the terminal
    print("\n--- Quick Audit Summary ---")
    for finding in findings:
        print(f"File: {finding['File']} (Line {finding['Line Number']}) -> {finding['Vulnerable Algorithm']}")

if __name__ == "__main__":
    # Scan the current directory ('.')
    target_dir = "." 
    scan_results = scan_directory(target_dir)
    generate_csv_report(scan_results)