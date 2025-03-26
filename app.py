from flask import Flask, jsonify,render_template, request, redirect, url_for, session, flash, send_from_directory,send_file
import threading
import os
import requests
import hashlib
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  
import logging
import uuid
import re
import uuid
import os
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
import requests
import hashlib
from werkzeug.utils import secure_filename
from pathlib import Path
import logging
import subprocess
from collections import defaultdict
import math
import ipaddress
import pefile
import magic
import string
import pytesseract
import pyzipper
from PIL import Image
import shutil
import threading
import base64
import joblib
import numpy 
import mysql.connector
from flask import current_app
import uuid
from reportlab.pdfgen import canvas
from textwrap import fill
from reportlab.lib.pagesizes import A4
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps



app = Flask(__name__)
app.secret_key = 'your_secret_key'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
BASE_OUTPUT_FOLDER = "extracted_resources"
os.makedirs(BASE_OUTPUT_FOLDER, exist_ok=True)

trid_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "trid_w32", "trid.exe"))

VIRUSTOTAL_API_KEY = "952bda09ecef7bf22c9a8c9b7dff66701109ef5b8dd5ec33307c193b056538bc"

signature_and_extension = {
    "pdf": ["25 50 44 46"],  
    "jpeg": ["FF D8 FF E1", "FF D8 FF E0", "FF D8 FF FE"],  
    "jpg": ["FF D8 FF E1", "FF D8 FF E0", "FF D8 FF FE"],  
    "png": ["89 50 4E 47"],  
    "zip": ["50 4B 03 04", "50 4B 05 06"],  
    "gif": ["47 49 46"],  
    "bmp": ["42 4D"], 
    "tiff": ["49 20 49", "4D 4D"],  
    "jar": ["50 4B 03 04"],  
    "exe": ["4D 5A"],  
    "elf": ["7F 45 4C 46"],  
}


analysis_results = {}
results_lock = threading.Lock()

def load_models():
    # print("[DEBUG] Loading models...")
    modeldir = os.path.join(BASE_DIR, "model")
    featurizer = joblib.load(os.path.join(modeldir, "featurizer.pkl"))
    ranker = joblib.load(os.path.join(modeldir, "ranker.pkl"))
    # print("[DEBUG] Models loaded successfully.")
    return featurizer, ranker

featurizer, ranker = load_models()

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_pie_chart(stats, chart_path):
    labels = ["Malicious", "Clean", "Suspicious", "Undetected", "Timeout"]
    values = [
        stats.get("malicious", 0), 
        stats.get("harmless", 0),
        stats.get("suspicious", 0), 
        stats.get("undetected", 0), 
        stats.get("timeout", 0)
    ]
    color_map = {
        "Malicious": "red", 
        "Clean": "green", 
        "Suspicious": "orange", 
        "Undetected": "yellow", 
        "Timeout": "gray"
    }

    filtered_labels = [label for label, value in zip(labels, values) if value > 0]
    filtered_values = [value for value in values if value > 0]
    filtered_colors = [color_map[label] for label in filtered_labels]

    total = sum(values)  # ✅ Calculate total
    # print(f"[DEBUG] Total Scanned Reports: {total}")  # Debugging total count

    if filtered_values:
        plt.figure(figsize=(8, 6))
        plt.pie(filtered_values, labels=filtered_labels, autopct="%1.1f%%", startangle=140, colors=filtered_colors)
        plt.title("VirusTotal Scan Results")
        plt.savefig(chart_path)
        plt.close()

    return total  # ✅ Return total count

def check_virustotal(file_path, session_id):
    sha256_hash = calculate_sha256(file_path)
    # print(f"[DEBUG] Calculated SHA256: {sha256_hash}")

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        # print(f"[DEBUG] VirusTotal Response Status Code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            # print(f"[DEBUG] VirusTotal Response JSON: {data}")

            stats = data["data"]["attributes"].get("last_analysis_stats", {})
            # print(f"[DEBUG] Extracted Analysis Stats: {stats}")

            chart_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{session_id}_chart.png")
            
            # Generate chart and get total count
            total_count = generate_pie_chart(stats, chart_path)
            # print(f"[DEBUG] Pie chart generated at: {chart_path}, Total: {total_count}")

            # ✅ Store "total" in the results
            stats["total"] = total_count  

            update_analysis_result(session_id, "stats", stats)
            update_analysis_result(session_id, "chart", f"{session_id}_chart.png")
            # print("[DEBUG] Updated analysis results successfully!")
        else:
            error_message = f"VirusTotal error: {response.status_code}"
            print(f"[ERROR] {error_message}")
            update_analysis_result(session_id, "error", error_message)
    except requests.RequestException as e:
        error_message = f"Request error: {str(e)}"
        print(f"[ERROR] {error_message}")
        update_analysis_result(session_id, "error", error_message)



def update_analysis_result(session_id, key, value):
    with results_lock:
        if session_id not in analysis_results:
            analysis_results[session_id] = {}
        analysis_results[session_id][key] = value

@app.route('/check_status/<session_id>')
def check_status(session_id):
    with results_lock:
        result_data = analysis_results.get(session_id, {})
                # Check if all necessary fields exist in the result
        required_keys = [
            "stats", "chart", "compiler", "filename", "file_size",
            "section_headers", "import_table", "export_table",
            "malicious_strings", "malicious_apis", "emails_found", "urls_found",
            "trid", "ascii_strings", "wide_strings", "ranked_strings",
            "high_entropy_sections", "extracted_resources",
            "metadata", "tactics_techniques", "mbc_data", "capability_namespace"
        ]

        
        # If all required data is present, mark `complete=True`
        result_data["complete"] = all(key in result_data for key in required_keys)
        # Generate PDF only when all data is available
        if result_data["complete"]:
            output_filename = save_results_to_pdf(result_data)
            if output_filename:
                print(f"Generated filename: {output_filename}")  # Debugging
                print(f"Download URL: {url_for('download_report', output_filename=output_filename)}")  # Debugging
                result_data["pdf_report"] = output_filename 
        # print("[DEBUG] API Response:", result_data) 
    return result_data        


def save_results_to_pdf(result_data):
    try:
        UPLOAD_FOLDER = Path(current_app.config["UPLOAD_FOLDER"])
        # unique_id = uuid.uuid4().hex
        # output_filename = f"{unique_id}_report.pdf"
        output_filename = f"Generated_PDF_report.pdf"
        output_path = UPLOAD_FOLDER / output_filename
        output_path_str = str(output_path)
        print(f"Starting PDF generation. Output path: {output_path_str}")

        c = canvas.Canvas(output_path_str, pagesize=A4)
        width, height = A4
        c.setFont("Helvetica", 10)
        y_position = height - 40  
        line_height = 14  
        # print(f"Initial y_position set to: {y_position}")

        def add_line(text, indent=0):
            nonlocal y_position
            # print(f"Adding line: '{text}' with indent: {indent}")
            if y_position < 40:  
                # print("y_position is less than 40, creating a new page.")
                c.showPage()
                c.setFont("Helvetica", 10)
                y_position = height - 40
            c.drawString(50 + indent, y_position, text)
            y_position -= line_height
            # print(f"Updated y_position: {y_position}")

        def add_paragraph(text, indent=0, max_length=90):
            nonlocal y_position
            wrapped_text = fill(text, width=max_length)
            # print(f"Adding paragraph: '{text}' with indent: {indent}")
            for line in wrapped_text.split("\n"):
                add_line(line, indent)

        print(f"Processing result data for filename: {result_data.get('filename', 'Unknown')}")
        add_line(f"Analysis Report for: {result_data.get('filename', 'Unknown')}", indent=0)
        add_line("-" * 80)
        
        add_line(f"File Size: {result_data.get('file_size', 'N/A')} bytes")
        add_line(f"Compiler Details: {result_data.get('compiler', 'N/A')}")
        add_paragraph(f"TrID Analysis: {result_data.get('trid', 'N/A')}")

        # Section Headers
        add_line("Section Headers:")
        for section in result_data.get("section_headers", []):
            # print(f"Processing section: {section}")
            add_line(f"Name: {section['name']}", indent=20)
            add_line(f"Virtual Address: {section['virtual_address']}", indent=20)
            add_line(f"Virtual Size: {section['virtual_size']}", indent=20)
            add_line(f"Raw Size: {section['raw_size']}", indent=20)
            add_line(f"Permissions: {section['permissions']}", indent=20)
            add_line(f"Entropy: {section['entropy']}", indent=20)
            add_line("-" * 80)

        # High Entropy Sections
        add_line("High Entropy Sections:")
        for section in result_data.get("high_entropy_sections", []):
            # print(f"Adding high entropy section: {section}")
            add_line(f"- {section}", indent=20)

        # Import Table
        add_line("Import Table:")
        for entry in result_data.get("import_table", []):
            # print(f"Adding import table entry: {entry}")
            add_line(f"- {entry}", indent=20)

        # Export Table
        add_line("Export Table:")
        for entry in result_data.get("export_table", []):
            # print(f"Adding export table entry: {entry}")
            add_line(f"- {entry}", indent=20)   

        
        add_line("Malicious Strings Found:")
        for string in result_data.get("malicious_strings", []):
            # print(f"Adding malicious string: {string}")
            add_line(f"- {string}", indent=20)
        
        add_line("Malicious APIs Found:")
        for api in result_data.get("malicious_apis", []):
            # print(f"Adding malicious API: {api}")
            add_line(f"- {api}", indent=20)
        
        add_line("URLs Found:")
        for url in result_data.get("urls_found", []):
            # print(f"Adding URL: {url}")
            add_line(f"- {url}", indent=20)
        
        add_line("Emails Found:")
        for email in result_data.get("emails_found", []):
            # print(f"Adding email: {email}")
            add_line(f"- {email}", indent=20)
        
        add_line("Extracted Resources:")
        for resource in result_data.get("extracted_resources", []):
            name = resource.get("name", "Unknown")
            size = resource.get("size", "Unknown")
            rtype = resource.get("type", "Unknown")
            
            add_line(f"- Name: {name}, Size: {size} KB, Type: {rtype}", indent=20)
            
            if "extracted_text" in resource:
                add_line(f"  Extracted Text: {resource['extracted_text']}", indent=40)
            if "raw_content" in resource:
                add_paragraph(f"  Raw Content: {resource['raw_content']}", indent=40)

        # Metadata
        add_line("Metadata:")
        for key, value in result_data.get("metadata", {}).items():
            # print(f"Adding metadata: {key}: {value}")
            add_line(f"- {key}: {value}", indent=20)

        # Attack Tactics & Techniques
        add_line("Attack Tactics & Techniques:")
        for tactic in result_data.get("tactics_techniques", []):
            # print(f"Adding tactic/technique: {tactic}")
            add_paragraph(f"- {tactic}", indent=20)
        
        # MBC Data
        add_line("MBC Data:")
        for mbc in result_data.get("mbc_data", []):
            # print(f"Adding MBC data: {mbc}")
            add_paragraph(f"- {mbc}", indent=20)
        
        # Capability Namespace
        add_line("Capability Namespace:")
        for capability in result_data.get("capability_namespace", []):
            # print(f"Adding capability: {capability}")
            add_line(f"- {capability}", indent=20)
        
        # VirusTotal Scan Results
        scan_results = result_data.get("stats", {})
        add_line("Scan results:", indent=20)
        if isinstance(scan_results, list):
            for stats in scan_results:
                add_line(f"- {stats}", indent=40)
        elif isinstance(scan_results, dict):
            for key, value in scan_results.items():
                add_line(f"- {key}: {value}", indent=40)
        else:
            add_line("VirusTotal Results: Unknown Format")
        # add_line("VirusTotal Scan Results:")
        # for key, value in result_data.get("virus_total_scan", {}).items():
        #     print(f"Adding VirusTotal result: {key}: {value}")
        #     add_line(f"- {key}: {value}", indent=20)
                
        # Chart Image
        if "chart" in result_data:
            chart_path = UPLOAD_FOLDER / result_data["chart"]
            if chart_path.exists():
                print(f"Adding chart image from: {chart_path}")
                c.drawImage(str(chart_path), 50, y_position - 160, width=200, height=200)
                y_position -= 160
        
        # ASCII Strings
        add_line("Extracted ASCII Strings:")
        for string in result_data.get("ascii_strings", []):
            # print(f"Adding ASCII string: {string}")
            add_line(f"- {string}", indent=20)
        
        # Wide Strings
        add_line("Extracted Wide Strings:")
        for entry in result_data.get("wide_strings", []):
            decrypted = entry.get("decrypted", "N/A")
            # print(f"Adding wide string: {entry['encrypted']} (Decrypted: {decrypted})")
            add_line(f"- {entry['encrypted']} (Decrypted: {decrypted})", indent=20)
        
        # Ranked Strings
        add_line("Ranked Strings:")
        for entry in result_data.get("ranked_strings", []):
            if isinstance(entry, tuple) and len(entry) == 2:
                string, score = entry  # Unpack tuple
            elif isinstance(entry, dict):
                string = entry.get("string", "Unknown")
                score = entry.get("score", "Unknown")
            else:
                string, score = str(entry), "Unknown"

            # print(f"Adding ranked string: {string} (Score: {score})")
            add_line(f"- {string} (Score: {score})", indent=20)


        c.save()
        print(f"PDF successfully saved: {output_path_str}")
        return output_filename  
    
    except Exception as e:
        print(f"Error during PDF generation: {e}")
        return None

import os
from flask import send_from_directory, abort

@app.route('/download_report/<path:output_filename>')
def download_report(output_filename):
    
    try:
        UPLOAD_FOLDER = current_app.config["UPLOAD_FOLDER"]

        return send_from_directory(UPLOAD_FOLDER, output_filename, as_attachment=True)
    except Exception as e:
        return f"Error: {e}", 500


def sanitize_filename(filename):
    filename = secure_filename(filename)
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)

def start_analysis_tasks(file_path, session_id):
    threading.Thread(target=perform_analysis, args=(file_path, session_id)).start()
    threading.Thread(target=check_virustotal, args=(file_path, session_id)).start()
    threading.Thread(target=analyze_file_with_trid, args=(file_path, session_id)).start()
    threading.Thread(target=extract_resources_async, args=(file_path, session_id)).start()
    threading.Thread(target=run_capa_analysis, args=(file_path, session_id)).start()


def perform_analysis(file_path, session_id):
    try:
        # print(f"[DEBUG] Starting analysis for session: {session_id}")
        # print(f"[DEBUG] Analyzing file: {file_path}")

        pe = pefile.PE(file_path)
        # print("[DEBUG] PE file successfully loaded.")

        data = open(file_path, 'rb').read()
        # print(f"[DEBUG] Read {len(data)} bytes from file.")

        ascii_strings = extract_ascii_strings(data)
        # print(f"[DEBUG] Extracted {len(ascii_strings)} ASCII strings.")

        wide_strings = extract_wide_strings(data)
        # print(f"[DEBUG] Extracted {len(wide_strings)} wide strings.")

        processed_wide_strings = process_wide_strings(wide_strings)
        # print(f"[DEBUG] Processed {len(processed_wide_strings)} wide strings.")

        section_headers, high_entropy = extract_section_headers(pe)
        # print(f"[DEBUG] Extracted {len(section_headers)} section headers.")
        # print(f"[DEBUG] Found {len(high_entropy)} high entropy sections.")

        import_table = extract_import_table(pe)
        # print(f"[DEBUG] Extracted {len(import_table)} import entries.")

        export_table = extract_export_table(pe)
        # print(f"[DEBUG] Extracted {len(export_table)} export entries.")

        compiler = identify_compiler(pe)
        # print(f"[DEBUG] Identified compiler: {compiler}")

        ranked_strings = rank_strings(ascii_strings + wide_strings, featurizer, ranker, cutoff=50)
        # print(f"[DEBUG] Ranked {len(ranked_strings)} strings.")

        # Call malicious indicator detection
        malicious_strings, malicious_apis, emails, urls = check_for_malicious_indicators(ascii_strings + wide_strings, import_table)

        # print(f"[DEBUG] Found {len(malicious_strings)} malicious string matches.")
        # print(f"[DEBUG] Found {len(malicious_apis)} malicious API matches.")
        # print(f"[DEBUG] Found {len(emails)} email addresses.")
        # print(f"[DEBUG] Found {len(urls)} URLs.")

        # Store results in the session
        update_analysis_result(session_id, "ascii_strings", ascii_strings[:20])
        update_analysis_result(session_id, "wide_strings", processed_wide_strings[:20])
        update_analysis_result(session_id, "section_headers", section_headers)
        update_analysis_result(session_id, "high_entropy_sections", high_entropy)
        update_analysis_result(session_id, "import_table", import_table)
        update_analysis_result(session_id, "export_table", export_table)
        update_analysis_result(session_id, "compiler", compiler)
        update_analysis_result(session_id, "ranked_strings", ranked_strings)
        update_analysis_result(session_id, "malicious_strings", malicious_strings)
        update_analysis_result(session_id, "malicious_apis", malicious_apis)
        update_analysis_result(session_id, "emails_found", emails)
        update_analysis_result(session_id, "urls_found", urls)

        # print(f"[DEBUG] Analysis completed successfully for session: {session_id}")
    except Exception as e:
        error_message = f"Analysis error: {str(e)}"
        print(f"[ERROR] {error_message}")
        update_analysis_result(session_id, "error", error_message)




def is_base64(s):
    """Check if a string is base64 encoded."""
    try:
        # Check if string follows base64 pattern
        if not re.match('^[A-Za-z0-9+/]*[=]{0,2}$', s):
            return False
        # Try to decode
        base64.b64decode(s)
        return True
    except Exception:
        return False


def try_base64_decode(s):
    """Attempt to decode a base64 string and return both original and decoded if successful."""
    try:
        decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
        return True, decoded
    except Exception:
        return False, None

def extract_ascii_strings(data, min_length=4):
    pattern = f'[\\x20-\\x7E]{{{min_length},}}'
    strings = re.findall(pattern.encode(), data)
    return [s.decode(errors='ignore') for s in strings]

def extract_wide_strings(data, min_length=4):
    wide_pattern = f'(?:[\\x20-\\x7E]\\x00){{{min_length},}}'
    wide_strings = re.findall(wide_pattern.encode(), data)
    return [s.decode('utf-16le', errors='ignore') for s in wide_strings]

def process_wide_strings(wide_strings):
    """Process wide strings to attempt base64 decoding."""
    wide_strings_results = []
    for string in wide_strings[:100]:
        if is_base64(string):
            success, decoded = try_base64_decode(string)
            if success:
                wide_strings_results.append({"encrypted": string, "decrypted": decoded})
            else:
                wide_strings_results.append({"encrypted": string, "decrypted": None})
        else:
            wide_strings_results.append({"encrypted": string, "decrypted": None})
    return wide_strings_results

def load_models():
    modeldir = os.path.join(os.path.dirname(__file__), "model")
    featurizer = joblib.load(os.path.join(modeldir, "featurizer.pkl"))
    ranker = joblib.load(os.path.join(modeldir, "ranker.pkl"))
    return featurizer, ranker

def rank_strings(strings, featurizer, ranker, cutoff=None, min_score=numpy.nan):
    if not strings:
        raise ValueError("No strings found for ranking.")
    strings_array = numpy.array(strings, dtype=object)
    X_test = featurizer.transform(strings_array)
    y_scores = ranker.predict(X_test)
    if not numpy.isnan(min_score):
        above_cutoff_indices = numpy.where(y_scores >= min_score)
        y_scores = y_scores[above_cutoff_indices]
        strings_array = strings_array[above_cutoff_indices]
    argsorted_y_scores = numpy.argsort(y_scores)[::-1]
    sorted_strings = strings_array[argsorted_y_scores]
    cutoff_sorted_strings = sorted_strings.tolist()[:cutoff] if cutoff else sorted_strings.tolist()
    return list(zip(cutoff_sorted_strings, y_scores[argsorted_y_scores]))    



def extract_section_headers(pe):
    section_headers = []
    high_entropy_sections = []
    for section in pe.sections:
        section_info = {
            "name": section.Name.decode("utf-8", errors="ignore").rstrip("\x00"),
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": hex(section.Misc_VirtualSize),
            "raw_size": hex(section.SizeOfRawData),
            "permissions": (
                f"{'r' if section.Characteristics & 0x40000000 else '-'}"
                f"{'w' if section.Characteristics & 0x20000000 else '-'}"
                f"{'x' if section.Characteristics & 0x80000000 else '-'}"
            ),
            "entropy": shannon_entropy(section.get_data()),
        }
        section_headers.append(section_info)
        if section_info["entropy"] > 7.2:
            high_entropy_sections.append(section_info["name"])
    return section_headers, high_entropy_sections

def extract_import_table(pe):
    import_table = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            dll_entry = {"dll": dll_name, "functions": []}
            if hasattr(entry, 'imports'):
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else hex(imp.address)
                    dll_entry["functions"].append(func_name)
            import_table.append(dll_entry)
    return import_table

def extract_export_table(pe):
    export_table = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and hasattr(pe.DIRECTORY_ENTRY_EXPORT, 'symbols'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exp_name = exp.name.decode('utf-8', errors='ignore') if exp.name else hex(exp.address)
            export_table.append(exp_name)
    return export_table


def shannon_entropy(data):
    possible = dict(((chr(x), 0) for x in range(0, 256)))
    for byte in data:
        possible[chr(byte)] += 1
    data_len = len(data)
    entropy = 0.0
    for i in possible:
        if possible[i] == 0:
            continue
        p = float(possible[i]) / data_len
        entropy -= p * math.log(p, 2)
    return entropy

def identify_compiler(pe):
    compiler_name = "Unknown Compiler"
    if pe.OPTIONAL_HEADER.Magic == 0x10b:
        compiler_name = "Microsoft Visual C++ 32-bit (MSVC)"
    elif pe.OPTIONAL_HEADER.Magic == 0x20b:
        compiler_name = "Microsoft Visual C++ 64-bit (MSVC)"
    for section in pe.sections:
        if b'.bss' in section.Name or b'.tls' in section.Name:
            compiler_name = "Borland Delphi"
            break
        if b'.gcc_except_table' in section.Name or b'.eh_frame' in section.Name:
            compiler_name = "GCC or G++"
            break
    return compiler_name

def check_for_malicious_indicators(strings, imports):
    MALICIOUS_STRINGS = [
        "malware", "virus", "trojan", "ransomware", "exploit", "payload",
        "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory",
        "ReadProcessMemory", "OpenProcess", "LoadLibraryA",
        "alt_dns", "anon", "bad_asn", "bad_tld", "beacon", "bio", "c2", "capture", "cms"
    ]
    string_counts = defaultdict(int)
    emails_found = []
    urls_found = []
    for s in strings:
        for malicious in MALICIOUS_STRINGS:
            if malicious.lower() in s.lower():
                string_counts[malicious] += 1
        email_matches = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', s)
        emails_found.extend(email_matches)
        url_matches = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', s)
        urls_found.extend(url_matches)
        try:
            ipaddress.ip_address(s)
            string_counts["IP Found"] += 1
        except ValueError:
            pass
        if re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', s):
            string_counts["MAC Found"] += 1
    api_counts = defaultdict(int)
    for entry in imports:
        if hasattr(entry, 'imports'):
            for imp in entry.imports:
                func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else ""
                for malicious_api in MALICIOUS_STRINGS:
                    if malicious_api.lower() in func_name.lower():
                        api_counts[malicious_api] += 1
    return dict(string_counts), dict(api_counts), emails_found, urls_found




def cleanup(folder_path):
    """Delete all previous contents of a folder and recreate it."""
    try:
        if os.path.exists(folder_path):
            print(f"[INFO] Cleaning up folder: {folder_path}")
            shutil.rmtree(folder_path)  # Delete the folder
        os.makedirs(folder_path)  # Recreate the folder
        print(f"[INFO] Recreated folder: {folder_path}")
    except Exception as e:
        print(f"[ERROR] Error cleaning up folder {folder_path}: {e}")



def cleanup_folders(extracted_resources):
    try:
        if os.path.exists(extracted_resources):
            shutil.rmtree(extracted_resources)  
            os.makedirs(extracted_resources)    
    except Exception as e:
        print(f"Error cleaning up folder: {e}")   


def save_resource(resource_data, output_folder, file_extension):
    """ Save extracted resources to disk with debugging information. """
    
    file_hash = hashlib.sha256(resource_data).hexdigest()[:8]  
    file_name = f"extracted_{file_hash}{file_extension}"
    file_path = os.path.join(output_folder, file_name)

    try:
        # print(f"[DEBUG] Attempting to save resource:")
        # print(f"        - Output Folder: {output_folder}")
        # print(f"        - File Name: {file_name}")
        # print(f"        - File Extension: {file_extension if file_extension else 'None'}")
        # print(f"        - File Size: {len(resource_data)} bytes")

        with open(file_path, 'wb') as f:
            f.write(resource_data)
        
        # print(f"[DEBUG] Resource saved successfully: {file_path}")
        return file_path
    
    except Exception as e:
        print(f"[ERROR] Failed to save resource: {file_path}. Error: {e}")
        return None


def extract_resources_async(file_path, session_id):
    try:
        # print(f"[DEBUG] Starting resource extraction for session: {session_id}")
        pe = pefile.PE(file_path)
        output_folder = os.path.join(BASE_OUTPUT_FOLDER)

        os.makedirs(output_folder, exist_ok=True) 

        extracted_resources = extract_from_rsrc(pe, output_folder)

        update_analysis_result(session_id, "extracted_resources", extracted_resources)

        # ✅ Call create_protected_zip synchronously
        zip_password = "SecurePass123"  # Set password dynamically if needed
        zip_name = create_protected_zip(output_folder, zip_password, None)

        if zip_name:
            print(f"[DEBUG] Protected ZIP created successfully: {zip_name}")
            update_analysis_result(session_id, "zip_name", zip_name)
        else:
            print("[ERROR] Failed to create protected ZIP.")

    except Exception as e:
        print(f"[ERROR] Error during resource extraction: {e}")




def create_protected_zip(BASE_OUTPUT_FOLDER, zip_password, zip_path):
    try:
        zip_dir = os.path.join(os.getcwd(), 'static', 'zips')
        os.makedirs(zip_dir, exist_ok=True)
        zip_name = f"{os.path.basename(BASE_OUTPUT_FOLDER)}_protected.zip"
        zip_path = os.path.join(zip_dir, zip_name)
        with pyzipper.AESZipFile(zip_path, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zip_file:
            zip_file.setpassword(zip_password.encode('utf-8'))
            for root, dirs, files_in_dir in os.walk(BASE_OUTPUT_FOLDER):
                for file in files_in_dir:
                    file_path = os.path.join(root, file)
                    zip_file.write(file_path, arcname=os.path.relpath(file_path, BASE_OUTPUT_FOLDER))
        return zip_name  
    except Exception as e:
        print(f"Error creating password-protected ZIP: {e}")
        return None

@app.route('/download_zip/<zip_name>')
def download_zip(zip_name):
    try:
        zip_dir = os.path.join(os.getcwd(), 'static', 'zips')
        return send_from_directory(zip_dir, zip_name, as_attachment=True)
    except Exception as e:
        return f"Error: {e}", 500

def extract_from_rsrc(pe, output_folder):
    extracted_resources = []  
    cleanup_folders(output_folder)

    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        print("[DEBUG] No resource directory found in the PE file.")
        return None, extracted_resources

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if hasattr(entry, 'directory'):
            for resource in entry.directory.entries:
                if hasattr(resource, 'directory'):
                    for res_entry in resource.directory.entries:
                        try:
                            data_rva = res_entry.data.struct.OffsetToData
                            size = res_entry.data.struct.Size
                            resource_data = pe.get_memory_mapped_image()[data_rva:data_rva + size]

                            file_extension = ''
                            if res_entry.name is not None:
                                resource_name = res_entry.name.string.decode('utf-8', errors='ignore')
                                if 'PNG' in resource_name:
                                    file_extension = '.png'
                                elif 'JPEG' in resource_name or 'JPG' in resource_name:
                                    file_extension = '.jpg'
                                elif 'PDF' in resource_name:
                                    file_extension = '.pdf'
                                elif 'TXT' in resource_name:
                                    file_extension = '.txt'

                            file_path = save_resource(resource_data, output_folder, file_extension)

                            if file_path:
                                file_size = os.path.getsize(file_path)
                                file_type = detect_file_type(file_path)  # ✅ Detect file type
                                extracted_text = perform_ocr(file_path) if file_type.startswith("image") else "N/A"  # ✅ OCR if image
                                raw_content = read_raw_content(file_path)  # ✅ Read raw content

                                extracted_resources.append({
                                    "filename": os.path.basename(file_path),
                                    "size": file_size,
                                    "type": file_type,
                                    "details": resource_name if res_entry.name else "N/A",
                                    "extracted_text": extracted_text,
                                    "raw_content": raw_content
                                })
                            else:
                                print(f"[ERROR] Failed to save extracted resource.")

                        except Exception as e:
                            print(f"[ERROR] Error extracting resource: {e}")

    return  extracted_resources

def detect_file_type(file_path):
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        return file_type
    except Exception as e:
        print(f"Error detecting file type: {e}")
        return "Unknown"

def perform_ocr(image_path):
    try:
        image = Image.open(image_path)
        image = image.convert('L')  
        image = image.point(lambda x: 0 if x < 128 else 255, '1')  
        extracted_text = pytesseract.image_to_string(image)
        return extracted_text.strip()
    except Exception as e:
        print(f"Error performing OCR on {image_path}: {e}")
        return ""

def read_raw_content(file_path):
    try:
        with open(file_path, "rb") as file:
            data = file.read()
            printable = "".join(
                chr(b) if chr(b) in string.printable else "" for b in data
            )
            return printable.strip()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return ""


#  TrID Analysis
def analyze_file_with_trid(file_path, session_id):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    logger = logging.getLogger(__name__)

    # Ensure session_id is initialized
    if session_id not in analysis_results:
        analysis_results[session_id] = {}

    if not trid_path or not os.path.exists(trid_path) or not os.access(trid_path, os.X_OK):
        logger.error("❌ TrID executable not found or is not executable.")
        return

    cmd = [trid_path, str(file_path)]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0:
            analysis_results[session_id]["trid"] = parse_trid_analysis(result.stdout.strip())
            logger.info(f"✅ TrID analysis completed for {file_path}")
        else:
            logger.error(f"❌ TrID analysis failed:\nSTDOUT: {result.stdout.strip()}\nSTDERR: {result.stderr.strip()}")

    except subprocess.TimeoutExpired:
        logger.error(f"⏳ TrID analysis timed out for {file_path}")
    except Exception as e:
        logger.error(f"❌ Unexpected error during TrID analysis: {e}")


def parse_trid_analysis(trid_output):
    """
    Parses the TrID analysis output to extract relevant information.
    """
    # Extract the "Definitions found" line
    definitions_line = re.search(r"Definitions found:\s+\d+", trid_output)
    # Extract percentage lines
    percentage_lines = re.findall(r"^\s*\d+\.\d+%.*", trid_output, re.MULTILINE)
    # Combine results
    extracted_data = []
    if definitions_line:
        extracted_data.append(definitions_line.group())
    extracted_data.extend(percentage_lines)
    # Print the extracted data
    return "\n".join(extracted_data)


# Database Configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'cdac@123',
    'database': 'mbc'
}

# Function to connect to the database
def connect_db():
    try:
        conn = mysql.connector.connect(**db_config)
        if conn.is_connected():
            print("___________________________|")
            print("Connected to MySQL database")
            print("___________________________|")
        return conn
    except mysql.connector.Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None
    

def run_capa_analysis(file_path, session_id):
    rules_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "capa-rules-7.4.0"))
    signatures_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "capa/sigs"))
    result = run_capa_terminal(file_path, rules_path, signatures_path)
    # print("[CAPA Analysis Result]")
    # print(result)
    
    formatted_data = format_parsed_data(parse_table(result.splitlines()))
    metadata = extract_metadata(formatted_data)
    tactics_techniques = extract_attack_tactics_techniques(formatted_data)
    mbc_data = extract_mbc(formatted_data)
    capability_namespace_data = extract_capability_namespace(formatted_data)
    
    # print("Extracted Metadata:", metadata)
    # print("Extracted Attack Tactics & Techniques:", tactics_techniques)
    # print("Extracted MBC Data:", mbc_data)
    # print("Extracted Capability Namespace:", capability_namespace_data)
    
    update_analysis_result(session_id, "metadata", metadata)
    update_analysis_result(session_id, "tactics_techniques", tactics_techniques)
    update_analysis_result(session_id, "mbc_data", mbc_data)
    update_analysis_result(session_id, "capability_namespace", capability_namespace_data)

def run_capa_terminal(file_path, rules_path, signatures_path):
    """
    Runs the CAPA tool with the provided file, rules, and signatures paths.

    Args:
        file_path (str): Path to the file to analyze.
        rules_path (str): Path to the CAPA rules.
        signatures_path (str): Path to the CAPA signatures.

    Returns:
        str: CAPA output or an error message.
    """
    try:
        # Validate file paths
        if not os.path.exists(file_path):
            return f"❌ File not found. Please check the file path and try again."
        if not os.path.exists(rules_path):
            return f"❌ Rules file not found. Please check the rules path and try again."
        if not os.path.exists(signatures_path):
            return f"❌ Signatures file not found. Please check the signatures path and try again."

        # Construct and execute the command
        command = [
            "capa",
            file_path,
            "-r", rules_path,
            "--signatures", signatures_path
        ]
        result = subprocess.run(
            command, 
            text=True, 
            capture_output=True, 
            encoding="utf-8", 
            errors="ignore"
        )

        # Handle subprocess result
        if result.returncode != 0:
            return f"❌ Error running CAPA:\n{result.stderr.strip()}"
        else:
            return result.stdout.strip()

    except FileNotFoundError as e:
        return f"❌ CAPA executable not found. Ensure CAPA is installed and added to your system's PATH.\nDetails: {e}"
    except subprocess.SubprocessError as e:
        return f"❌ Subprocess error occurred while running CAPA.\nDetails: {e}"
    except Exception as e:
        return f"❌ An unexpected error occurred during CAPA analysis.\nDetails: {e}"

def parse_table(data):
    row_pattern = r"\u2502(.*?)\u2502(.*?)\u2502"  
    header_pattern = r"\u2503(.*?)\u2503"  
    parsed_data = []
    temp_key = ""
    temp_value = ""
    subtable_flag = False
    last_header = ""
    for line in data:
        header_match = re.match(header_pattern, line)
        row_match = re.match(row_pattern, line)
        if header_match:  
            header = header_match.group(1).strip()
            if header:  
                if subtable_flag:
                    parsed_data.append(("", ""))  
                last_header = header
                parsed_data.append((f"{header} -", ""))
                subtable_flag = True
        elif row_match:  
            key, value = row_match.groups()
            key, value = key.strip(), value.strip()
            if key and value:
                if key and not value:
                    temp_key += ", " + key if temp_key else key
                elif value and not key:
                    temp_value += ", " + value if temp_value else value
                else:  
                    if temp_key or temp_value:  
                        parsed_data.append((temp_key.strip(), temp_value.strip()))
                        temp_key = ""
                        temp_value = ""
                    temp_key, temp_value = key, value
        if temp_key or temp_value and line == data[-1]:
            parsed_data.append((temp_key.strip(), temp_value.strip()))
    return parsed_data

def format_parsed_data(parsed_data):
    formatted_output = []
    seen = set() 
    for key, value in parsed_data:
        if not key and not value:  
            formatted_output.append("")
        else:
            line = f"{key} - {value}"
            if line not in seen: 
                formatted_output.append(line)
                seen.add(line)
    return formatted_output

import re

def extract_metadata(formatted_data):
    # print("Extracting metadata...")
    if isinstance(formatted_data, str):
        formatted_data = formatted_data.splitlines()
    
    metadata = {
        "md5": "",
        "sha1": "",
        "sha256": "",
        "analysis": "",
        "os": "",
        "format": "",
        "arch": ""
    }
    
    patterns = {
        "md5": r"(?i)\bmd5\s*[:\-]?\s*([0-9a-fA-F]{32})",
        "sha1": r"(?i)\bsha1\s*[:\-]?\s*([0-9a-fA-F]{40})",
        "sha256": r"(?i)\bsha256\s*[:\-]?\s*([0-9a-fA-F]{64})",
        "analysis": r"(?i)\banalysis\s*[:\-]?\s*(\w+)",
        "os": r"(?i)\bos\s*[:\-]?\s*([\w\-\.]+)",
        "format": r"(?i)\bformat\s*[:\-]?\s*(\S+)",
        "arch": r"(?i)\barch\s*[:\-]?\s*(\S+)"
    }
    
    for line in formatted_data:
        # print(f"Processing line: {line}")
        for key, pattern in patterns.items():
            if not metadata[key]:  
                match = re.search(pattern, line)
                if match:
                    metadata[key] = match.group(1)
                    # print(f"Extracted {key}: {metadata[key]}")
    
    # print("Final extracted metadata:", metadata)
    return metadata

import re

def extract_attack_tactics_techniques(formatted_data):
    tactics_techniques = []
    pattern = re.compile(r"^(.*?)\s*-\s*(.+?)\s*\[(T\d{4}(?:\.\d{3})?)\]$")

    # Ensure data is a list of lines
    if isinstance(formatted_data, str):
        formatted_data = formatted_data.splitlines()

    for line in formatted_data:
        line = line.strip()
        match = pattern.match(line)
        
        if match:
            tactic = match.group(1).strip()
            technique = match.group(2).strip()
            technique_id = match.group(3).strip()

            # Create hyperlink for the technique
            technique_with_link = f'{technique} <a href="https://attack.mitre.org/techniques/{technique_id}/" target="_blank">{technique_id}</a>'
            tactics_techniques.append((tactic, technique_with_link))
            
            # print(f"Extracted: {tactic} -> {technique_with_link}")
    
    return tactics_techniques

def extract_mbc(formatted_data):
    mbc_data = []
    mbc_section_started = False  
    mbc_pattern = re.compile(r"^([A-Z\s\-]+?)\s*-\s*(.+)$")
    
    if isinstance(formatted_data, str):
        formatted_data = formatted_data.splitlines()
    
    conn = connect_db()  # Establish database connection
    if conn:
        cursor = conn.cursor(dictionary=True)
        
        # Fetch all behavior IDs and links from the database in one query
        cursor.execute("SELECT id, value FROM mbc_link")
        db_results = {row["id"]: row["value"] for row in cursor.fetchall()} 
        
        # Behavior ID pattern to match different formats
        behavior_id_pattern = re.compile(r"\b([A-Z]\d{4}(?:\.\d{3,4}|\.m\d{2,3})?)\b")

        for line in formatted_data:
            line = line.strip()
            
            if "MBC Objective - MBC Behavior" in line:
                mbc_section_started = True
                continue 
            
            if mbc_section_started:
                if not line or "ATT&CK" in line or "-" not in line:
                    break
                
                match = mbc_pattern.match(line)
                if match:
                    objective = match.group(1).strip()
                    behavior = match.group(2).strip()

                    # Find all matching behavior IDs in the behavior description
                    behavior_ids = behavior_id_pattern.findall(behavior)
                    
                    if behavior_ids:
                        for behavior_id in behavior_ids:
                            if behavior_id in db_results:
                                behavior_link = db_results[behavior_id]
                                behavior = behavior.replace(
                                    behavior_id,
                                    f'<a href="{behavior_link}" target="_blank">{behavior_id}</a>'
                                )
                            else:
                                print(f"Behavior ID {behavior_id} not found in database, keeping original.")
                    
                    mbc_data.append((objective, behavior))
        
        cursor.close()
        conn.close()
    
    # print("Final extracted MBC behaviors:", mbc_data)
    return mbc_data

def extract_capability_namespace(formatted_data):
    # print("Extracting capability namespaces...")
    capability_namespace_data = []
    capability_namespace_pattern = re.compile(r"(.+?)\s*-\s*(.+)")
    
    if isinstance(formatted_data, str):
        formatted_data = formatted_data.splitlines()
    
    capability_section = False  
    
    for line in formatted_data:
        line = line.strip() 
        # print(f"Processing line: {line}")
        
        if line.startswith("Capability - Namespace"):
            capability_section = True
            # print("Capability section started...")
            continue  
        
        if capability_section:
            if not line or "-" not in line:
                break
            
            match = capability_namespace_pattern.match(line)
            if match:
                capability = match.group(1).strip()  
                namespace = match.group(2).strip() 
                capability_namespace_data.append((capability, namespace))
                # print(f"Extracted: {capability} -> {namespace}")
    
    # print("Final extracted capability namespaces:", capability_namespace_data)
    return capability_namespace_data






@app.route('/result/<session_id>')
def result(session_id):
    with results_lock:
        result_data = analysis_results.get(session_id, {})
    return render_template('r.html', session_id=session_id, result=result_data)

@app.route('/uploads/<filename>')
def serve_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

from datetime import timedelta

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'
app.permanent_session_lifetime = timedelta(minutes=30)  # Session expires after 30 min

db = SQLAlchemy(app)

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Stores hashed passwords

# Password validation regex: At least 8 characters, 1 uppercase, 1 number, 1 special character
PASSWORD_REGEX = r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"


# Decorators for authentication
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or "session_id" not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for("landing_page"))
        return f(*args, **kwargs)
    return decorated_function

def prevent_navigation_to_restricted_routes(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" in session:
            flash("You are already logged in.", "info")
            return redirect(url_for("upload_dashboard", session_id=session["session_id"]))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/", methods=["GET"])
def landing_page():
    return render_template("login.html")

@app.route("/login", methods=["GET", "POST"])
@prevent_navigation_to_restricted_routes
def login():
    email = request.form.get("email")
    password = request.form.get("password")
    
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        session["user_id"] = user.id
        session["session_id"] = str(uuid.uuid4())
        flash("Login successful!", "success")
        return redirect(url_for("upload_dashboard", session_id=session["session_id"]))
    else:
        flash("Invalid credentials. Please try again.", "error")
        return redirect(url_for("landing_page"))

@app.route("/signup", methods=["GET", "POST"])
@prevent_navigation_to_restricted_routes
def signup():
    if request.method == "GET":
        return render_template("login.html")  # Handle GET properly

    email = request.form.get("email")
    password = request.form.get("password")

    # ✅ Ensure password meets security requirements
    if not re.match(PASSWORD_REGEX, password):
        flash("Password must be at least 8 characters, include 1 uppercase letter, 1 number, and 1 special character.", "error")
        return redirect(url_for("landing_page"))  # Redirect to login page

    # ✅ Check if user already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash("User already exists! Please log in.", "error")
        return redirect(url_for("landing_page"))  # Redirect to login page

    # ✅ Hash the password before storing
    hashed_password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)

    # ✅ Store user in database
    new_user = User(email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    flash("Account created successfully! You can now log in.", "success")
    return redirect(url_for("landing_page"))  # Redirect after successful signup

@app.route("/upload_dashboard/<session_id>", methods=["GET", "POST"])
@login_required
def upload_dashboard(session_id):
    if session.get("session_id") != session_id:
        flash("Invalid session. Please log in again.", "error")
        return redirect(url_for("landing_page"))
    
    return render_template("upload.html") 

@app.route("/upload/<session_id>", methods=["POST"])
@login_required
def upload_file(session_id):
    if session.get("session_id") != session_id:
        flash("Invalid session. Please log in again.", "error")
        return redirect(url_for("landing_page"))

    uploaded_file = request.files.get("file")
    
    if uploaded_file and uploaded_file.filename:
        cleanup(app.config["UPLOAD_FOLDER"])
        safe_filename = sanitize_filename(uploaded_file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_filename)
        uploaded_file.save(file_path)
        
        try:
            pe = pefile.PE(file_path)
            pe.close()
        except Exception as e:
            flash(f"Error processing PE file: {e}", "error")
            return redirect(url_for("upload_dashboard", session_id=session_id))

        file_size = os.path.getsize(file_path)
        update_analysis_result(session_id, "filename", safe_filename)
        update_analysis_result(session_id, "file_size", file_size)

        start_analysis_tasks(file_path, session_id)
        return redirect(url_for("result", session_id=session_id))
    
    flash("No file uploaded.", "error")
    return redirect(url_for("upload_dashboard", session_id=session_id))



# ✅ LOGOUT Route
@app.route("/logout")
@prevent_navigation_to_restricted_routes
def logout():
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("landing_page"))

if __name__ == '__main__':      
    app.run(host="0.0.0.0", port=8080, debug=True)