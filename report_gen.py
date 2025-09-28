#!/usr/bin/env python3
"""
report_ai_indexed.py

Always indexes JSON(s) into embeddings, then queries them via OpenRouter.
Options:
  --mode summary / remediation / report
  --json-type risk / mal / sbom / harden / combined
"""

import os
import json
import argparse
import requests
from sentence_transformers import SentenceTransformer
import numpy as np
from typing import List, Tuple


# ----------------------
# Embedding Utilities
# ----------------------
def get_embedding_model():
    """Load or download embedding model (cached locally)."""
    return SentenceTransformer("all-MiniLM-L6-v2")


def embed_texts(model, texts: List[str]) -> np.ndarray:
    return model.encode(texts, convert_to_numpy=True)


def cosine_sim(query_vec, doc_vecs):
    sims = np.dot(doc_vecs, query_vec) / (
        np.linalg.norm(doc_vecs, axis=1) * np.linalg.norm(query_vec) + 1e-9
    )
    return sims


# ----------------------
# JSON Loader & Indexer
# ----------------------
def load_json_files(paths: List[str]) -> List[Tuple[str, str]]:
    """Load JSON(s) and flatten into (id, text) list for embedding."""
    docs = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        def recurse(obj, prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    recurse(v, f"{prefix}.{k}" if prefix else k)
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    recurse(v, f"{prefix}[{i}]")
            else:
                docs.append((prefix, str(obj)))

        recurse(data)
    return docs


# ----------------------
# Retrieval
# ----------------------
def retrieve_context(query: str, docs: List[Tuple[str, str]], model, top_k=5) -> List[str]:
    texts = [d[1] for d in docs]
    doc_vecs = embed_texts(model, texts)
    query_vec = embed_texts(model, [query])[0]
    sims = cosine_sim(query_vec, doc_vecs)
    idxs = sims.argsort()[-top_k:][::-1]
    return [texts[i] for i in idxs]


# ----------------------
# OpenRouter API
# ----------------------
def ask_openrouter(api_key: str, prompt: str, context: List[str], mode: str,
                   model="mistralai/mistral-7b-instruct:free") -> str:
    query = f"""Mode: {mode}
Context (Top {len(context)} chunks):
{json.dumps(context, indent=2)}

Task: {prompt}
Please provide a detailed, comprehensive answer with enough depth for technical and executive stakeholders.
"""
    response = requests.post(
        url="https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        },
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity report generator. Respond in detail."},
                {"role": "user", "content": query}
            ],
            "max_tokens": 1200  # ask for longer responses
        },
        timeout=90
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


# ----------------------
# Main
# ----------------------
def main():
    parser = argparse.ArgumentParser(description="AI-assisted Security Report Generator (indexed)")
    parser.add_argument("jsons", nargs="+", help="Path to JSON analysis files")
    parser.add_argument("--api-key", help="OpenRouter API key (or set OPENROUTER_API_KEY)")
    parser.add_argument("--mode", choices=["summary", "remediation", "report"], default="summary")
    parser.add_argument("--json-type", choices=["risk", "mal", "sbom", "harden", "combined"],
                        default="combined", help="Which analysis type(s) are included")
    parser.add_argument("--top-k", type=int, default=5, help="Number of context chunks to retrieve")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug output")
    args = parser.parse_args()

    api_key = args.api_key or os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OpenRouter API key must be provided via --api-key or environment variable.")

    # Load + index JSONs
    docs = load_json_files(args.jsons)
    model = get_embedding_model()

    if args.verbose:
        print(f"[DEBUG] Loaded {len(docs)} JSON entries from {len(args.jsons)} files")

    # Build query prompt
    query_prompt = {
        "summary": "Write a detailed executive summary of the binary analysis.",
        "remediation": "Provide prioritized and technical security remediations.",
        "report": "Generate a structured technical report (sections: Hardening, Risk, SBOM, Malware)."
    }[args.mode]

    # Add context about the JSON type(s)
    if args.json_type == "combined":
        query_prompt += " The input includes multiple combined analyses (risk, malware, sbom, hardening)."
    else:
        query_prompt += f" The input corresponds to {args.json_type} analysis only."

    # Retrieve top context
    context = retrieve_context(query_prompt, docs, model, top_k=args.top_k)

    if args.verbose:
        print(f"[DEBUG] Retrieved {len(context)} context chunks:")
        for i, c in enumerate(context, 1):
            print(f"  {i}. {c[:80]}...")

    output = ask_openrouter(api_key, query_prompt, context, args.mode)

    print("\n" + "=" * 60)
    print(f"AI {args.mode.upper()} ({args.json_type.upper()}):\n")
    print(output)
    print("=" * 60)


if __name__ == "__main__":
    main()
