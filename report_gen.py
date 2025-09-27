#!/usr/bin/env python
# report_gen.py

import argparse
import json
import os
import sys
import requests
from typing import Dict

# -------------------------
# AI Summary Function
# -------------------------
def ai_summary(
    report_json: Dict,
    detail="brief",
    remediation=True,
    style="actionable",
    openrouter_api_key=None
) -> str:
    """Generates AI summary from report JSON using OpenRouter API."""
    if openrouter_api_key is None:
        openrouter_api_key = os.environ.get("OPENROUTER_API_KEY")
        if not openrouter_api_key:
            print("Error: OpenRouter API key is required. Set via env variable or --openrouter-api-key.", file=sys.stderr)
            sys.exit(1)

    report_to_send = json.dumps(report_json, indent=2)

    prompt = f"""
You are a security analyst summarizing a binary security report.
Detail level: {detail}
Include remediation suggestions: {remediation}
Style: {style}

Report content:
{report_to_send}

Provide a clear, structured summary suitable for management and technical audience.
"""

    try:
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {openrouter_api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "mistralai/mistral-7b-instruct:free",
                "messages": [{"role": "user", "content": prompt}]
            },
            timeout=60
        )
        response.raise_for_status()
        data = response.json()
        summary_text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        return summary_text
    except requests.RequestException as e:
        print(f"Error: Failed to get AI summary: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error: Unexpected error: {e}", file=sys.stderr)
        sys.exit(3)

# -------------------------
# Report Generation Function
# -------------------------
def generate_report(
    reports: Dict,
    output_dir: str,
    types: list,
    report_options: dict,
    openrouter_api_key=None
) -> dict:
    """Generates reports (JSON + AI summary) and returns paths."""
    os.makedirs(output_dir, exist_ok=True)
    report_paths = {}

    # JSON Report
    if "json" in types:
        json_path = os.path.join(output_dir, "report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2)
        report_paths["json"] = json_path

    # AI Summary
    if "summary" in types and "ai_summary" in report_options:
        summary_path = os.path.join(output_dir, "summary.txt")
        summary_text = ai_summary(
            reports,
            detail=report_options["ai_summary"].get("detail", "brief"),
            remediation=report_options["ai_summary"].get("remediation", True),
            style=report_options["ai_summary"].get("style", "actionable"),
            openrouter_api_key=openrouter_api_key
        )
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write(summary_text)
        report_paths["summary.txt"] = summary_path

    return report_paths

# -------------------------
# CLI Entry Point
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Generate AI summary for binary reports (CLI friendly)")
    parser.add_argument("--report-json", required=True, help="Path to combined report JSON file")
    parser.add_argument("--output-dir", default="./reports", help="Directory to save generated reports")
    parser.add_argument("--openrouter-api-key", help="OpenRouter API Key")
    parser.add_argument("--detail", default="brief", choices=["brief","detailed"], help="Summary detail level")
    parser.add_argument("--remediation", action="store_true", help="Include remediation suggestions")
    parser.add_argument("--style", default="actionable", choices=["actionable","formal","friendly"], help="Summary style")
    parser.add_argument("--types", nargs="+", default=["json","summary"], help="Report types to generate: json summary")

    args = parser.parse_args()

    if not os.path.exists(args.report_json):
        print(f"Error: Report JSON file '{args.report_json}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(args.report_json, "r", encoding="utf-8") as f:
        report_json = json.load(f)

    report_options = {
        "ai_summary": {
            "detail": args.detail,
            "remediation": args.remediation,
            "style": args.style
        }
    }

    report_paths = generate_report(
        reports=report_json,
        output_dir=args.output_dir,
        types=args.types,
        report_options=report_options,
        openrouter_api_key=args.openrouter_api_key
    )

    print("Reports generated successfully:")
    for rtype, path in report_paths.items():
        print(f"  {rtype}: {path}")

if __name__ == "__main__":
    main()
