#!/usr/bin/env python3
"""ais prefilter: scores feed items against inventory targets.

Reads one JSON file (default /work/in.json):

    {"v": 1, "max_tokens": 128,
     "targets": [{"id": "g0", "text": "Palo Alto Networks PAN-OS 11.2 ..."}],
     "items":   [{"key": "ab12", "text": "Title. Summary"}]}

and prints one JSON document on stdout:

    {"v": 1, "model": "...", "dim": 768, "ms": 1234,
     "scores": [{"key": "ab12", "score": 0.71, "best": "g0"}],
     "usage": {"cpu_usec": 5400000, "mem_peak": 812000000, "source": "cgroup"}}

usage is the CPU time and the peak memory of the whole container.

The score is the cosine similarity between the item and the closest
target. Embeddings come from an ONNX export of a sentence-transformers
bi-encoder in /model (see export.py); only onnxruntime, tokenizers and
numpy are needed at run time. The container has no network.
"""

import json
import os
import sys
import time

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

PROTOCOL = 1
MODEL_DIR = os.environ.get("AIS_MODEL_DIR", "/model")
CGROUP_DIR = os.environ.get("AIS_CGROUP_DIR", "/sys/fs/cgroup")


def usage():
    """CPU time and peak memory of this container.

    Reads the container's own cgroup (cgroup v2 with a private cgroup
    namespace, the default of docker and podman). Falls back to the
    process's own resource usage when the files are not readable.
    """
    out = {"cpu_usec": 0, "mem_peak": 0, "source": "cgroup"}
    try:
        with open(os.path.join(CGROUP_DIR, "cpu.stat"), encoding="ascii") as f:
            for line in f:
                key, _, val = line.partition(" ")
                if key == "usage_usec":
                    out["cpu_usec"] = int(val)
        with open(os.path.join(CGROUP_DIR, "memory.peak"), encoding="ascii") as f:
            out["mem_peak"] = int(f.read().strip())
        return out
    except (OSError, ValueError):
        pass
    import resource

    ru = resource.getrusage(resource.RUSAGE_SELF)
    return {"cpu_usec": int((ru.ru_utime + ru.ru_stime) * 1e6), "mem_peak": ru.ru_maxrss * 1024, "source": "rusage"}


class Embedder:
    """Tokenizes, runs the ONNX model, pools and normalizes."""

    def __init__(self, model_dir=MODEL_DIR, threads=None):
        with open(os.path.join(model_dir, "model.json"), encoding="utf-8") as f:
            self.meta = json.load(f)
        self.tok = Tokenizer.from_file(os.path.join(model_dir, "tokenizer.json"))
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = threads or int(os.environ.get("AIS_THREADS", "0")) or (os.cpu_count() or 1)
        opts.inter_op_num_threads = 1
        opts.log_severity_level = 3
        self.sess = ort.InferenceSession(
            os.path.join(model_dir, self.meta["file"]), opts, providers=["CPUExecutionProvider"]
        )
        self.inputs = {i.name for i in self.sess.get_inputs()}
        self.output = self.meta.get("output") or self.sess.get_outputs()[0].name

    def embed(self, texts, max_tokens=None, batch=16):
        max_tokens = min(max_tokens or self.meta["max_length"], self.meta["max_length"])
        self.tok.enable_truncation(max_tokens)
        self.tok.enable_padding(pad_id=self.meta["pad_id"], pad_token=self.meta["pad_token"])
        out = []
        for i in range(0, len(texts), batch):
            enc = self.tok.encode_batch(texts[i : i + batch])
            ids = np.array([e.ids for e in enc], dtype=np.int64)
            mask = np.array([e.attention_mask for e in enc], dtype=np.int64)
            feeds = {"input_ids": ids, "attention_mask": mask}
            if "token_type_ids" in self.inputs:
                feeds["token_type_ids"] = np.zeros_like(ids)
            feeds = {k: v for k, v in feeds.items() if k in self.inputs}
            hidden = self.sess.run([self.output], feeds)[0].astype(np.float32)
            if self.meta["pooling"] == "cls":
                vec = hidden[:, 0]
            else:
                m = mask[..., None].astype(np.float32)
                vec = (hidden * m).sum(1) / np.maximum(m.sum(1), 1e-9)
            vec = vec / np.maximum(np.linalg.norm(vec, axis=1, keepdims=True), 1e-12)
            out.append(vec)
        if not out:
            return np.zeros((0, self.meta["dim"]), dtype=np.float32)
        return np.concatenate(out)


def score(embedder, doc):
    """Returns the output document for an input document."""
    if doc.get("v") != PROTOCOL:
        raise SystemExit(f"input protocol {doc.get('v')!r}, want {PROTOCOL}")
    targets = doc.get("targets") or []
    items = doc.get("items") or []
    max_tokens = int(doc.get("max_tokens") or 128)
    start = time.monotonic()
    scores = []
    if targets and items:
        t_vec = embedder.embed([t["text"] for t in targets], max_tokens)
        i_vec = embedder.embed([it["text"] for it in items], max_tokens)
        sims = i_vec @ t_vec.T  # (items, targets), unit vectors: cosine
        best = sims.argmax(axis=1)
        for it, b, row in zip(items, best, sims):
            scores.append({"key": it["key"], "score": round(float(row[b]), 4), "best": targets[int(b)]["id"]})
    return {
        "v": PROTOCOL,
        "model": embedder.meta.get("name", ""),
        "dim": int(embedder.meta["dim"]),
        "ms": int((time.monotonic() - start) * 1000),
        "scores": scores,
    }


def selftest(embedder, path):
    """Checks that related pairs score above unrelated ones; exits 1 if not."""
    with open(path, encoding="utf-8") as f:
        cases = json.load(f)
    texts = []
    for c in cases:
        texts += [c["a"], c["b"], c["c"]]
    vec = embedder.embed(texts, 128)
    bad = 0
    for n, c in enumerate(cases):
        a, b, u = vec[3 * n], vec[3 * n + 1], vec[3 * n + 2]
        related, unrelated = float(a @ b), float(a @ u)
        flag = "ok " if related > unrelated else "BAD"
        print(f"{flag} related {related:.3f} > unrelated {unrelated:.3f}: {c['a'][:60]}", file=sys.stderr)
        if related <= unrelated:
            bad += 1
    if bad:
        raise SystemExit(f"selftest: {bad} of {len(cases)} cases rank the unrelated text higher")
    print(f"selftest: {len(cases)} cases ok, model {embedder.meta.get('name')} dim {embedder.meta['dim']}", file=sys.stderr)


def main(argv):
    if len(argv) >= 2 and argv[0] == "--selftest":
        selftest(Embedder(), argv[1])
        return 0
    path = argv[0] if argv else "/work/in.json"
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    result = score(Embedder(), doc)
    result["usage"] = usage()
    json.dump(result, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
