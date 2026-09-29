#!/usr/bin/env python3
"""Pinned local embedding builder and newline-delimited query worker."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import struct
import sys
import time
from typing import Any

import numpy as np
import sentence_transformers
from sentence_transformers import SentenceTransformer
import torch
import transformers


MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
DIMENSION = 384
MAGIC = b"CESEM01\x00"
DOCUMENT_RECIPE = (
    "Toolkit: <toolkit name> (<toolkit slug>).\n"
    "Tool: <tool name>.\n"
    "Action identifier: <tool slug with underscores replaced by spaces>.\n"
    "Description: <tool description>"
)
EXPECTED_VERSIONS = {
    "sentence_transformers": "5.1.0",
    "transformers": "4.56.0",
    "torch": "2.8.0+cpu",
}


def versions() -> dict[str, str]:
    return {
        "sentence_transformers": sentence_transformers.__version__,
        "transformers": transformers.__version__,
        "torch": torch.__version__,
    }


def require_versions() -> None:
    actual = versions()
    if actual != EXPECTED_VERSIONS:
        raise RuntimeError(f"library versions differ from contract: {actual!r}")


def document_text(tool: dict[str, Any]) -> str:
    toolkit = tool["toolkit"]
    identifier = tool["slug"].replace("_", " ")
    return (
        f"Toolkit: {toolkit['name']} ({toolkit['slug']}).\n"
        f"Tool: {tool['name']}.\n"
        f"Action identifier: {identifier}.\n"
        f"Description: {tool['description']}"
    )


def load_catalog(path: Path) -> tuple[list[str], list[str]]:
    slugs: list[str] = []
    texts: list[str] = []
    previous = ""
    with path.open("r", encoding="utf-8-sig") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            tool = json.loads(line)
            slug = str(tool["slug"])
            if previous and slug <= previous:
                raise RuntimeError(f"catalog is not strictly sorted at line {line_number}")
            previous = slug
            slugs.append(slug)
            texts.append(document_text(tool))
    if not slugs:
        raise RuntimeError("catalog is empty")
    return slugs, texts


def validate_embeddings(values: np.ndarray) -> dict[str, Any]:
    if values.ndim != 2 or values.shape[1] != DIMENSION:
        raise RuntimeError(f"embedding shape is {values.shape}, expected (*, {DIMENSION})")
    finite_rows = np.isfinite(values).all(axis=1)
    norms = np.linalg.norm(values, axis=1)
    non_finite = int((~finite_rows).sum())
    zero = int((norms == 0).sum())
    unit_failures = int((np.abs(norms - 1.0) > 1e-4).sum())
    if non_finite or zero or unit_failures:
        raise RuntimeError(
            f"invalid vectors: non_finite={non_finite} zero={zero} unit_failures={unit_failures}"
        )
    return {
        "vectors": int(values.shape[0]),
        "dimension": int(values.shape[1]),
        "non_finite_vectors": non_finite,
        "zero_vectors": zero,
        "unit_norm_failures": unit_failures,
        "norm_min": float(norms.min()),
        "norm_max": float(norms.max()),
    }


def resolved_model_snapshot(cache: Path) -> Path:
    candidate = (
        cache
        / "models--sentence-transformers--all-MiniLM-L6-v2"
        / "snapshots"
        / MODEL_REVISION
    ).resolve()
    if not candidate.is_dir():
        raise RuntimeError(f"model snapshot path is not a directory: {candidate}")
    return candidate


def tree_identity(root: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    files = 0
    total_bytes = 0
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(struct.pack("<Q", size))
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        files += 1
        total_bytes += size
    return {"files": files, "bytes": total_bytes, "sha256": digest.hexdigest()}


def load_model(cache: Path, offline: bool) -> SentenceTransformer:
    require_versions()
    cache.mkdir(parents=True, exist_ok=True)
    return SentenceTransformer(
        MODEL_ID,
        revision=MODEL_REVISION,
        cache_folder=str(cache),
        local_files_only=offline,
        device="cpu",
    )


def build(args: argparse.Namespace) -> int:
    started = time.time()
    catalog_path = Path(args.catalog).resolve()
    output_path = Path(args.output).resolve()
    cache_path = Path(args.cache).resolve()

    if args.batch_size < 1:
        raise ValueError("batch size must be positive")
    if output_path.exists():
        raise RuntimeError(f"refusing to overwrite {output_path}")
    slugs, texts = load_catalog(catalog_path)
    print(f"loading {MODEL_ID}@{MODEL_REVISION}", file=sys.stderr, flush=True)
    model = load_model(cache_path, args.offline)
    if args.reuse:
        source_path = Path(args.reuse).resolve()
        print(f"validating retained vector matrix {source_path}", file=sys.stderr, flush=True)
        with source_path.open("rb") as source:
            if source.read(8) != MAGIC:
                raise RuntimeError("reused embedding file magic mismatch")
            count, dimension = struct.unpack("<II", source.read(8))
            if count != len(slugs) or dimension != DIMENSION:
                raise RuntimeError("reused embedding header differs from catalog contract")
            values = np.frombuffer(source.read(), dtype="<f4").reshape(count, dimension).copy()
    else:
        print(f"encoding {len(texts)} catalog tools on CPU", file=sys.stderr, flush=True)
        values = model.encode(
            texts,
            batch_size=args.batch_size,
            show_progress_bar=True,
            convert_to_numpy=True,
            normalize_embeddings=True,
        ).astype("<f4", copy=False)
    audit = validate_embeddings(values)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("xb") as destination:
        destination.write(MAGIC)
        destination.write(struct.pack("<II", len(slugs), DIMENSION))
        destination.write(values.tobytes(order="C"))
        destination.flush()
        os.fsync(destination.fileno())
    snapshot = resolved_model_snapshot(cache_path)
    metadata = {
        "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
        "document_recipe": DOCUMENT_RECIPE,
        "normalized": True,
        "versions": versions(),
        "model_snapshot": tree_identity(snapshot),
        "model_snapshot_path": str(snapshot),
        "catalog_tools": len(slugs),
        "first_slug": slugs[0],
        "last_slug": slugs[-1],
        "vector_audit": audit,
        "duration_ms": int((time.time() - started) * 1000),
    }
    print("SEMANTIC_METADATA " + json.dumps(metadata, sort_keys=True), flush=True)
    return 0


def worker(args: argparse.Namespace) -> int:
    model = load_model(Path(args.cache).resolve(), offline=True)
    snapshot = resolved_model_snapshot(Path(args.cache).resolve())
    ready = {
        "type": "ready",
        "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
        "dimension": DIMENSION,
        "normalized": True,
        "versions": versions(),
        "model_snapshot": tree_identity(snapshot),
    }
    print(json.dumps(ready, sort_keys=True), flush=True)
    for line in sys.stdin:
        request_id = ""
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("request must be a JSON object")
            request_id = str(request["id"])
            text = request["text"]
            if not isinstance(text, str) or not text.strip():
                raise ValueError("text must be a non-empty string")
            value = model.encode(
                [text],
                show_progress_bar=False,
                convert_to_numpy=True,
                normalize_embeddings=True,
            ).astype(np.float32, copy=False)[0]
            if len(value) != DIMENSION or not all(math.isfinite(float(item)) for item in value):
                raise RuntimeError("query embedding is invalid")
            response = {"id": request_id, "embedding": value.tolist()}
        except Exception as error:  # Keep the worker alive and return a scoped error.
            response = {"id": request_id, "error": str(error)}
        print(json.dumps(response, separators=(",", ":")), flush=True)
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    build_parser = commands.add_parser("build")
    build_parser.add_argument("--catalog", required=True)
    build_parser.add_argument("--output", required=True)
    build_parser.add_argument("--cache", required=True)
    build_parser.add_argument("--batch-size", type=int, default=64)
    build_parser.add_argument("--offline", action="store_true")
    build_parser.add_argument("--reuse")
    worker_parser = commands.add_parser("worker")
    worker_parser.add_argument("--cache", required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    if args.command == "build":
        return build(args)
    return worker(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"semantic embedding failure: {exc}", file=sys.stderr)
        raise SystemExit(1)
