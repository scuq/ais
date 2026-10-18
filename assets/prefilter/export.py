#!/usr/bin/env python3
"""Exports a sentence-transformers bi-encoder to ONNX for prefilter.py.

Build-time only (stage "export" of the Containerfile). Steps:

1. Download the model snapshot and read its pooling configuration.
2. Export with optimum to ONNX (task feature-extraction).
3. Optionally quantize the weights to int8 (onnxruntime dynamic
   quantization, several variants), keeping the first whose embeddings
   stay close to the fp32 ones on the self-test texts; fp32 is shipped
   when none does.
4. Check the ONNX pipeline of prefilter.py against sentence-transformers
   on the same texts, so a wrong pooling or tokenizer fails the build.
5. Write model.json and the tokenizer next to the chosen .onnx file.
"""

import argparse
import json
import os
import shutil
import sys
import tempfile

import numpy as np


def log(msg):
    print(f"export: {msg}", file=sys.stderr, flush=True)


def pooling_of(snapshot):
    """Reads the sentence-transformers pooling mode: mean (default) or cls."""
    cfg = os.path.join(snapshot, "1_Pooling", "config.json")
    if not os.path.exists(cfg):
        log("no 1_Pooling/config.json; assuming mean pooling")
        return "mean"
    with open(cfg, encoding="utf-8") as f:
        p = json.load(f)
    if p.get("pooling_mode_cls_token"):
        return "cls"
    if p.get("pooling_mode_mean_tokens", True):
        return "mean"
    raise SystemExit(f"unsupported pooling configuration: {p}")


def max_length_of(snapshot, default=512):
    for name in ("sentence_bert_config.json", "tokenizer_config.json"):
        p = os.path.join(snapshot, name)
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                d = json.load(f)
            for key in ("max_seq_length", "model_max_length"):
                v = d.get(key)
                if isinstance(v, int) and 0 < v < 100000:
                    return v
    return default


def selftest_texts(path):
    with open(path, encoding="utf-8") as f:
        cases = json.load(f)
    out = []
    for c in cases:
        out += [c["a"], c["b"], c["c"]]
    return out


def quantize_int8(fp32, out, texts, reference, max_length, min_cosine, write_meta):
    """Tries int8 weight quantization variants, most precise first, and
    keeps the first whose embeddings stay within min_cosine of fp32.
    Returns the file name, or None when every variant drifts too far (the
    caller then ships fp32). Dynamic quantization is lossy on some
    architectures; the check decides, not an assumption."""
    import onnx
    from onnxruntime.quantization import QuantType, quantize_dynamic

    import prefilter

    model = onnx.load(fp32, load_external_data=False)
    attn = [n.name for n in model.graph.node if n.name and ("attn" in n.name.lower() or "attention" in n.name.lower())]
    embed = [n.name for n in model.graph.node if n.name and "embed" in n.name.lower()]
    del model
    variants = [
        ("per-channel", dict(per_channel=True, reduce_range=False)),
        ("per-channel, attention excluded", dict(per_channel=True, reduce_range=False, nodes_to_exclude=attn)),
        ("per-channel, attention and embeddings excluded", dict(per_channel=True, reduce_range=False, nodes_to_exclude=attn + embed)),
        ("per-tensor", dict(per_channel=False, reduce_range=False)),
    ]
    int8 = os.path.join(out, "model_int8.onnx")
    for name, kw in variants:
        log(f"quantizing weights to int8 ({name})")
        try:
            quantize_dynamic(fp32, int8, weight_type=QuantType.QInt8, **kw)
        except Exception as e:  # noqa: BLE001 - any failure means "try the next variant"
            log(f"  failed: {e}")
            continue
        write_meta("model_int8.onnx")
        q = prefilter.Embedder(out, threads=2).embed(texts, max_tokens=max_length)
        drift = float(np.min(np.sum(reference * q, axis=1)))
        log(f"  int8 vs fp32: min cosine {drift:.4f} (need {min_cosine})")
        if drift >= min_cosine:
            log(f"int8 model {os.path.getsize(int8) >> 20} MiB ({name})")
            return "model_int8.onnx"
    if os.path.exists(int8):
        os.remove(int8)
    log("no int8 variant is accurate enough; shipping the fp32 model")
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--revision", default="main")
    ap.add_argument("--quantize", default="int8", choices=["int8", "none"])
    ap.add_argument("--out", default="/model")
    ap.add_argument("--selftest", default=os.path.join(os.path.dirname(__file__), "selftest.json"))
    ap.add_argument("--min-int8-cosine", type=float, default=0.95)
    args = ap.parse_args()

    from huggingface_hub import snapshot_download
    from optimum.exporters.onnx import main_export
    from sentence_transformers import SentenceTransformer

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import prefilter  # the run-time pipeline, checked here against the reference

    log(f"downloading {args.model}@{args.revision}")
    snapshot = snapshot_download(args.model, revision=args.revision)
    pooling = pooling_of(snapshot)
    max_length = max_length_of(snapshot)
    log(f"pooling {pooling}, max length {max_length}")

    work = tempfile.mkdtemp(prefix="ais-export-")
    log("exporting to ONNX (optimum, task feature-extraction)")
    main_export(snapshot, output=work, task="feature-extraction", trust_remote_code=False)
    fp32 = os.path.join(work, "model.onnx")
    if not os.path.exists(fp32):
        raise SystemExit(f"optimum wrote no model.onnx in {work}: {os.listdir(work)}")

    os.makedirs(args.out, exist_ok=True)
    for name in ("tokenizer.json", "tokenizer_config.json", "special_tokens_map.json"):
        src = os.path.join(work, name)
        if os.path.exists(src):
            shutil.copy(src, os.path.join(args.out, name))
    if not os.path.exists(os.path.join(args.out, "tokenizer.json")):
        raise SystemExit("the export has no tokenizer.json; prefilter.py needs a fast tokenizer")

    from tokenizers import Tokenizer

    tok = Tokenizer.from_file(os.path.join(args.out, "tokenizer.json"))
    pad_token = None
    for name in ("tokenizer_config.json", "special_tokens_map.json"):
        p = os.path.join(args.out, name)
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                v = json.load(f).get("pad_token")
            if isinstance(v, dict):
                v = v.get("content")
            if isinstance(v, str):
                pad_token = v
                break
    if pad_token is None:
        raise SystemExit("no pad_token in the tokenizer configuration")
    pad_id = tok.token_to_id(pad_token)
    if pad_id is None:
        raise SystemExit(f"pad token {pad_token!r} is not in the vocabulary")

    import onnx

    model = onnx.load(fp32, load_external_data=False)
    output = model.graph.output[0].name
    dim = None
    for d in reversed(model.graph.output[0].type.tensor_type.shape.dim):
        if d.dim_value:
            dim = d.dim_value
            break
    del model

    def write_meta(file_name):
        meta = {
            "name": args.model,
            "revision": args.revision,
            "file": file_name,
            "pooling": pooling,
            "normalize": True,
            "max_length": max_length,
            "pad_id": pad_id,
            "pad_token": pad_token,
            "output": output,
            "dim": dim,
        }
        with open(os.path.join(args.out, "model.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        return meta

    texts = selftest_texts(args.selftest)

    shutil.copy(fp32, os.path.join(args.out, "model.onnx"))
    meta = write_meta("model.onnx")
    ref = SentenceTransformer(snapshot, device="cpu")
    ref_vec = ref.encode(texts, normalize_embeddings=True, convert_to_numpy=True)
    emb = prefilter.Embedder(args.out, threads=2)
    if dim is None:
        dim = int(emb.embed(texts[:1], 128).shape[1])
        meta = write_meta("model.onnx")
    ours = emb.embed(texts, max_tokens=max_length)
    agree = float(np.min(np.sum(ref_vec * ours, axis=1)))
    log(f"fp32 pipeline vs sentence-transformers: min cosine {agree:.4f}")
    if agree < 0.99:
        raise SystemExit("the ONNX pipeline disagrees with sentence-transformers; wrong pooling or tokenizer")

    chosen = "model.onnx"
    if args.quantize == "int8":
        chosen = quantize_int8(fp32, args.out, texts, ours, max_length, args.min_int8_cosine, write_meta) or chosen
    if chosen == "model.onnx":
        write_meta("model.onnx")
        data = os.path.join(work, "model.onnx_data")
        if os.path.exists(data):
            shutil.copy(data, os.path.join(args.out, "model.onnx_data"))
        log(f"fp32 model {os.path.getsize(fp32) >> 20} MiB")
    else:
        os.remove(os.path.join(args.out, "model.onnx"))
        for extra in os.listdir(args.out):
            if extra.endswith(".onnx_data") or extra.endswith(".onnx.data"):
                os.remove(os.path.join(args.out, extra))
    shutil.rmtree(work, ignore_errors=True)
    log(f"wrote {args.out}: {sorted(os.listdir(args.out))}")


if __name__ == "__main__":
    main()
