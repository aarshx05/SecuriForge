#!/usr/bin/env python3
"""
report_gen.py — GROQ-powered security report generator (Flask-compatible DEBUG)
"""

import os
import sys
import json
import argparse
import numpy as np
import time
from typing import List, Tuple
from sentence_transformers import SentenceTransformer
from groq import Groq
import markdown


STATIC_GROQ_KEY = ""


def log(msg):
    print(f"[DEBUG] {msg}", file=sys.stderr, flush=True)



def load_embedder():
    log("Loading MiniLM embedding model...")
    model = SentenceTransformer("all-MiniLM-L6-v2")
    log("Embedding model loaded.")
    return model


def embed(model, texts: List[str]) -> np.ndarray:
    log(f"Embedding {len(texts)} text chunks...")
    return model.encode(texts, convert_to_numpy=True, show_progress_bar=False)


def cosine_similarity(query_vec, vectors):
    denom = (np.linalg.norm(vectors, axis=1) * np.linalg.norm(query_vec) + 1e-9)
    return np.dot(vectors, query_vec) / denom


def load_json_flat(paths: List[str]) -> List[Tuple[str, str]]:
    results = []
    for p in paths:
        log(f"Loading JSON file: {p}")
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        def walk(obj, prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    walk(v, f"{prefix}.{k}" if prefix else k)
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    walk(v, f"{prefix}[{i}]")
            else:
                results.append((prefix, str(obj)))

        walk(data)

    log(f"Flattened JSON → {len(results)} entries.")
    return results


def retrieve_context(query: str, docs: List[Tuple[str, str]], model, top_k=5):
    values = [d[1] for d in docs]

    log("Embedding all JSON fields...")
    doc_vecs = embed(model, values)

    log("Embedding query for semantic retrieval...")
    query_vec = embed(model, [query])[0]

    sims = cosine_similarity(query_vec, doc_vecs)
    idxs = sims.argsort()[-top_k:][::-1]

    top = [(i, sims[i]) for i in idxs]
    log(f"Top {top_k} context indices + scores: {top}")

    return [values[i] for i in idxs]


def query_groq(api_key, prompt, context, mode, model="llama-3.3-70b-versatile"):
    log("Creating Groq client...")
    client = Groq(api_key=api_key)

    log("Building GROQ prompt message...")
    msg = f"""
Mode: {mode}

Context (top {len(context)} chunks):
{json.dumps(context, indent=2)}

Task:
{prompt}
"""

    log("Sending request to GROQ...")
    start = time.time()
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a cybersecurity report generator."},
                {"role": "user", "content": msg}
            ],
            temperature=0.25,
            max_completion_tokens=2000
        )
    except Exception as e:
        log(f"GROQ request failed: {e}")
        return f"Error: GROQ request failed: {e}"

    took = time.time() - start
    log(f"GROQ responded in {took:.2f} seconds.")

    out = response.choices[0].message.content
    log("Raw GROQ Output (first 300 chars):")
    log(out[:300] + "..." if len(out) > 300 else out)

    # Always return Markdown → HTML as well for Flask
    html_output = markdown.markdown(out, extensions=["fenced_code", "tables"])
    return {"text": out, "html": html_output}


def main():
    parser = argparse.ArgumentParser(description="AI Security Report Generator (Flask-compatible DEBUG)")
    parser.add_argument("jsons", nargs="+", help="Path to JSON analysis files")
    parser.add_argument("--api-key", help="Groq API key")
    parser.add_argument("--mode", choices=["summary","remediation","report"], default="report")
    parser.add_argument("--json-type", choices=["risk","mal","sbom","harden","combined"], default="combined")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    log("Starting report generation...")

    api_key = args.api_key or os.getenv("GROQ_API_KEY") or STATIC_GROQ_KEY
    log(f"Using API key: {'[MASKED] ' + api_key[-5:]}")

    docs = load_json_flat(args.jsons)
    embedder = load_embedder()

    base_prompts = {
        "summary": "Write an executive summary of the security findings.",
        "remediation": "Generate prioritized and technical security remediations.",
        "report": "Produce a structured security analysis report."
    }

    prompt = base_prompts[args.mode]
    if args.json_type == "combined":
        prompt += " The JSON input contains multiple combined modules."

    log("Retrieving semantic context...")
    context = retrieve_context(prompt, docs, embedder, args.top_k)

    log("Calling GROQ with constructed prompt...")
    output = query_groq(api_key, prompt, context, args.mode)

    # Print both text and HTML for Flask consumption
    print(json.dumps(output, ensure_ascii=False))


if __name__ == "__main__":
    main()
