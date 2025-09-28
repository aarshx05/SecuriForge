from flask import Flask, request, render_template_string, send_file
from hardening_checker import BinaryHardeningChecker
from risk_assessment import ReverseEngineeringRisk
from mal_checker import MalwareChecker
from sbom_gen import SBOMGenerator
import os
import json
import re
import subprocess
import markdown

app = Flask(__name__)

UPLOAD_FOLDER = "./uploads"
REPORTS_FOLDER = "./reports"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

YARA_RULES_DIR = os.path.join(os.path.dirname(__file__), "yara-rules", "yara")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" x-data="{ loading: false }" xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta charset="UTF-8">
  <title>SecuriForge - Binary Security Analyzer</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/alpinejs" defer></script>
  <link href="https://cdn.jsdelivr.net/npm/lucide-static@latest/font/lucide.css" rel="stylesheet">
  <style>
    details > summary { list-style: none; cursor: pointer; }
    summary::-webkit-details-marker { display: none; }
  </style>
</head>
<body class="bg-gray-50 text-gray-800 min-h-screen flex flex-col">
  <!-- Header -->
  <header class="bg-white border-b shadow-sm px-6 py-4 flex items-center justify-between">
    <h1 class="text-2xl font-bold flex items-center gap-2 text-gray-900">
       SecuriForge
    </h1>
    <p class="text-sm text-gray-500">Binary Security Analyzer</p>
  </header>

  <main class="flex-1 flex flex-col md:flex-row gap-6 p-6">
    <!-- Sidebar -->
    <aside class="w-full md:w-72 bg-white rounded-xl shadow p-5 space-y-6">
      <form id="upload-form" method="post" enctype="multipart/form-data" x-on:submit="loading = true">
        <!-- File Upload -->
        <div class="border-2 border-dashed border-gray-300 rounded-xl p-6 flex flex-col items-center justify-center text-gray-500 hover:border-blue-400 transition cursor-pointer">
          <i data-lucide="upload" class="w-8 h-8 mb-2"></i>
          <input type="file" name="file" required class="hidden" id="file-input" onchange="document.getElementById('file-label').textContent = this.files[0].name;">
          <label for="file-input" id="file-label" class="text-sm">Click or drop a file</label>
        </div>

        <!-- Report Mode -->
        <select name="report_mode" class="mt-4 w-full border rounded-lg p-2">
          <option value="summary">Summary</option>
          <option value="remediation">Remediation</option>
          <option value="report" selected>Full Report</option>
        </select>

        <!-- Modules -->
        <div class="mt-4 space-y-2 text-sm">
          <p class="font-medium text-gray-700">Modules</p>
          <label class="flex items-center gap-2"><input type="checkbox" name="modules" value="hardening" checked> Hardening Check</label>
          <label class="flex items-center gap-2"><input type="checkbox" name="modules" value="risk" checked> Risk Assessment</label>
          <label class="flex items-center gap-2"><input type="checkbox" name="modules" value="malware" checked> Malware Detection</label>
          <label class="flex items-center gap-2"><input type="checkbox" name="modules" value="sbom"> SBOM Generation</label>
          <label class="flex items-center gap-2"><input type="checkbox" name="modules" value="combined_report"> AI Combined Report</label>
        </div>

        <!-- Run Button -->
        <button type="submit" class="mt-6 w-full bg-blue-600 hover:bg-blue-700 text-white py-2 rounded-lg font-semibold flex items-center justify-center gap-2">
          <i data-lucide="play"></i> Run Analysis
        </button>
      </form>
    </aside>

    <!-- Results -->
    <section class="flex-1">
      <!-- Loading Overlay -->
      <div x-show="loading" class="absolute inset-0 flex items-center justify-center bg-white/70 z-50">
        <div class="flex flex-col items-center gap-3">
          <i data-lucide="loader-2" class="w-8 h-8 animate-spin text-blue-600"></i>
          <p class="font-medium text-gray-600">Running analysis...</p>
        </div>
      </div>

      <div id="results-container" class="space-y-6">
        {% if results %}
          {% if results.get('error') %}
            <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
              <strong>Error:</strong> {{ results['error'] }}
            </div>
          {% else %}
            <!-- File Info Card -->
            <div class="bg-white rounded-xl shadow p-5">
              <h2 class="text-xl font-semibold mb-3 flex items-center gap-2"><i data-lucide="file"></i> File Info</h2>
              <p><b>File:</b> {{ results["_meta"]["path"] }}</p>
              <p><b>Size:</b> {{ results["_meta"]["file_size_bytes"] }} bytes</p>
              <p><b>Format:</b> {{ results["_meta"]["format"] }}</p>
              <div class="mt-3 flex flex-wrap gap-4 text-sm">
                <a href="/download_file?path={{ results['_meta']['path'] }}" class="text-blue-600 hover:underline">Download Original</a>
                <a href="/download_file?path={{ results['_meta']['json_report'] }}" class="text-green-600 hover:underline">Download JSON</a>
                <a href="/download_file?path={{ results['_meta']['html_report'] }}" class="text-yellow-600 hover:underline">Download HTML</a>
              </div>
            </div>

            <!-- Findings Cards -->
            {% for key in ["hardening","risk","malware","sbom"] %}
              {% if results.get(key) %}
              <details class="bg-white rounded-xl shadow p-5">
                <summary class="text-lg font-semibold flex items-center gap-2">
                  {% if key == 'hardening' %}<i data-lucide="shield"></i>{% endif %}
                  {% if key == 'risk' %}<i data-lucide="alert-triangle"></i>{% endif %}
                  {% if key == 'malware' %}<i data-lucide="bug"></i>{% endif %}
                  {% if key == 'sbom' %}<i data-lucide="settings"></i>{% endif %}
                  {{ key.upper() }} Findings
                </summary>
                <pre class="bg-gray-50 p-4 rounded-lg overflow-x-auto text-sm mt-3">{{ results[key] | tojson(indent=2) }}</pre>
              </details>
              {% endif %}
            {% endfor %}

            <!-- AI Report -->
            {% if results.get('ai_report') %}
              <details open class="bg-white rounded-xl shadow p-5">
                <summary class="text-lg font-semibold flex items-center gap-2"><i data-lucide="bot"></i> AI Combined Report</summary>
                <div class="prose max-w-none bg-gray-50 p-4 rounded-lg text-sm mt-3"> {{ results['ai_report']['html'] | safe }}</div>
              </details>
            {% endif %}
          {% endif %}
        {% endif %}
      </div>
    </section>
  </main>

  <script>
    lucide.createIcons(); // initialize Lucide icons
  </script>
</body>
</html>

"""

def save_reports(combined_reports, filename_base):
    json_path = os.path.join(REPORTS_FOLDER, f"{filename_base}.json")
    html_path = os.path.join(REPORTS_FOLDER, f"{filename_base}.html")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(combined_reports, f, indent=2, default=str)

    html_content = "<html><body><h2>SecuriForge Report</h2>"
    for key, data in combined_reports.items():
        if key != "_meta":
            if key == "ai_report" and isinstance(data, dict):
                html_content += f"<h3>{key.upper()}</h3>{data['html']}"
            else:
                html_content += f"<h3>{key.upper()}</h3><pre>{json.dumps(data, indent=2, default=str)}</pre>"
    html_content += "</body></html>"

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return {"json": json_path, "html": html_path}



def run_ai_report(json_path, api_key, report_mode="report"):
    """Run AI report synchronously and clean unwanted tags or markers"""
    try:
        result = subprocess.run(
            ["python", "report_gen.py", json_path,
             "--api-key", api_key, "--mode", report_mode,
             "--json-type", "combined", "--top-k", "10"],
            capture_output=True, text=True, check=True
        )
        print(result)
        output = result.stdout.strip()
        if not output:
            output = "AI report returned empty output."
        
        # Remove unwanted tags/markers
        output = re.sub(r"</?s>", "", output)        # remove <s> or </s>
        output = re.sub(r"\[/?B_INST\]", "", output) # remove [B_INST] or [/B_INST]
        output = output.strip()

        # Convert Markdown → HTML
        html_report = markdown.markdown(output, extensions=["fenced_code", "tables"])

        # Return both
        return {"text": output, "html": html_report}
    except subprocess.CalledProcessError as e:
        return {"text": f"Error running AI report:\n{e.stderr or e.stdout or str(e)}", "html": ""}



@app.route("/", methods=["GET", "POST"])
def upload_file():
    results = None
    if request.method == "POST":
        file = request.files.get("file")
        selected_modules = request.form.getlist("modules")
        report_mode = request.form.get("report_mode", "report")
        api_key = "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"  # Replace with your actual key

        if file:
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)

            try:
                combined_reports = {}
                _meta = {"path": filepath, "file_size_bytes": os.path.getsize(filepath), "format": "Unknown"}

                if "hardening" in selected_modules:
                    combined_reports["hardening"] = BinaryHardeningChecker(filepath).run_all()
                if "risk" in selected_modules:
                    hardening_report = combined_reports.get("hardening", {}) or {}
                    combined_reports["risk"] = ReverseEngineeringRisk(filepath, hardening_report).run_all()
                    _meta["format"] = combined_reports["risk"].get("_meta", {}).get("format", "Unknown")
                if "malware" in selected_modules:
                    combined_reports["malware"] = MalwareChecker(filepath, yara_rules=YARA_RULES_DIR).run_all().get("findings", {})
                if "sbom" in selected_modules:
                    combined_reports["sbom"] = SBOMGenerator(filepath).run_all()

                filename_base = os.path.splitext(file.filename)[0]
                report_paths = save_reports(combined_reports, filename_base)
                _meta["json_report"] = report_paths["json"]
                _meta["html_report"] = report_paths["html"]

                if "combined_report" in selected_modules and api_key:
                    combined_reports["ai_report"] = run_ai_report(report_paths["json"], api_key, report_mode)

                combined_reports["_meta"] = _meta
                results = combined_reports
            except Exception as e:
                results = {"error": str(e)}

    return render_template_string(HTML_TEMPLATE, results=results)

@app.route("/download_file")
def download_file():
    path = request.args.get("path")
    if not path or not os.path.exists(path):
        return "File not found", 404
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))

if __name__ == "__main__":
    app.run(debug=True, port=5000)
