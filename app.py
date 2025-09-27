from flask import Flask, request, render_template_string, send_file
from hardening_checker import BinaryHardeningChecker
from risk_assessment import ReverseEngineeringRisk
from mal_checker import MalwareChecker
from sbom_gen import SBOMGenerator
import os
import json

app = Flask(__name__)
UPLOAD_FOLDER = "./uploads"
REPORTS_FOLDER = "./reports"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

YARA_RULES_DIR = os.path.join(os.path.dirname(__file__), "yara-rules", "yara")

# -----------------------------
# HTML Template (Modern UI for SecuriForge)
# -----------------------------
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SecuriForge - Binary Security Analyzer</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 text-gray-800 min-h-screen flex flex-col items-center py-10">

  <div class="w-full max-w-4xl">

    <h1 class="text-3xl font-bold mb-6 text-center text-gray-900">SecuriForge</h1>

    <form method="post" enctype="multipart/form-data" class="bg-white p-6 rounded-xl shadow-lg mb-8">
      <div class="flex flex-col md:flex-row items-center gap-4 mb-4">
        <input type="file" name="file" required
               class="border border-gray-300 rounded-lg p-2 w-full md:w-auto">
        <button type="submit"
                class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-semibold flex items-center gap-2">
          <i class="fas fa-play"></i> Run Analysis
        </button>
      </div>

      <div class="flex flex-wrap gap-4">
        <label class="flex items-center gap-2">
          <input type="checkbox" name="modules" value="hardening" checked
                 class="h-4 w-4 text-blue-600">
          Hardening Check
        </label>
        <label class="flex items-center gap-2">
          <input type="checkbox" name="modules" value="risk" checked
                 class="h-4 w-4 text-green-600">
          Risk Assessment
        </label>
        <label class="flex items-center gap-2">
          <input type="checkbox" name="modules" value="malware" checked
                 class="h-4 w-4 text-red-600">
          Malware Detection
        </label>
        <label class="flex items-center gap-2">
          <input type="checkbox" name="modules" value="sbom"
                 class="h-4 w-4 text-purple-600">
          SBOM Generation
        </label>
      </div>
    </form>

    {% if results %}
      {% if results.get('error') %}
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">
          <strong class="font-bold">Error:</strong>
          <span class="block sm:inline">{{ results['error'] }}</span>
        </div>
      {% else %}
        <div class="bg-white p-6 rounded-xl shadow-lg mb-6">
          <h2 class="text-xl font-semibold mb-2 flex items-center gap-2"><i class="fas fa-file"></i> File Info</h2>
          <p><b>File:</b> {{ results["_meta"]["path"] }}</p>
          <p><b>Size:</b> {{ results["_meta"]["file_size_bytes"] }} bytes</p>
          <p><b>Format:</b> {{ results["_meta"]["format"] }}</p>
        </div>

        {% for key in ["hardening","risk","malware","sbom"] %}
          {% if results.get(key) %}
          <div class="bg-white p-6 rounded-xl shadow-lg mb-6">
            <h2 class="text-xl font-semibold mb-2 flex items-center gap-2">
              {% if key == 'hardening' %}<i class="fas fa-shield-alt"></i>{% endif %}
              {% if key == 'risk' %}<i class="fas fa-exclamation-triangle"></i>{% endif %}
              {% if key == 'malware' %}<i class="fas fa-bug"></i>{% endif %}
              {% if key == 'sbom' %}<i class="fas fa-cogs"></i>{% endif %}
              {{ key.upper() }} Findings
            </h2>
            <pre class="bg-gray-50 p-4 rounded-lg overflow-x-auto text-sm">{{ results[key] | tojson(indent=2) }}</pre>
          </div>
          {% endif %}
        {% endfor %}

        {% if results.get('report_paths') %}
          <div class="bg-white p-6 rounded-xl shadow-lg mb-6">
            <h2 class="text-xl font-semibold mb-2 flex items-center gap-2"><i class="fas fa-download"></i> Download Reports</h2>
            <div class="flex flex-wrap gap-3">
              {% for rtype, path in results['report_paths'].items() %}
                <a href="/download_file?path={{ path }}"
                   class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-semibold flex items-center gap-2">
                  <i class="fas fa-file-{{ 'json' if rtype=='json' else 'code' }}"></i> {{ rtype.upper() }}
                </a>
              {% endfor %}
            </div>
          </div>
        {% endif %}
      {% endif %}
    {% endif %}
  </div>
</body>
</html>
"""

LAST_JSON = None
LAST_REPORTS = {}

def save_reports(combined_reports, filename_base):
    """Save JSON and HTML reports"""
    report_paths = {}
    json_path = os.path.join(REPORTS_FOLDER, f"{filename_base}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(combined_reports, f, indent=2)
    report_paths["json"] = json_path

    # Simple HTML report
    html_path = os.path.join(REPORTS_FOLDER, f"{filename_base}.html")
    html_content = "<html><body><h2>SecuriForge Report</h2>"
    for key, data in combined_reports.items():
        if key != "_meta":
            html_content += f"<h3>{key.upper()}</h3><pre>{json.dumps(data, indent=2)}</pre>"
    html_content += "</body></html>"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    report_paths["html"] = html_path

    return report_paths

# -----------------------------
# Flask Routes
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def upload_file():
    global LAST_JSON, LAST_REPORTS
    results = None

    if request.method == "POST":
        file = request.files.get("file")
        selected_modules = request.form.getlist("modules")

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

                # Add metadata
                combined_reports["_meta"] = _meta

                # Save reports
                filename_base = os.path.splitext(file.filename)[0]
                report_paths = save_reports(combined_reports, filename_base)
                combined_reports["report_paths"] = report_paths

                results = combined_reports
                LAST_JSON = results
                LAST_REPORTS = report_paths

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
