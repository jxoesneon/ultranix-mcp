# ADR 0005: ONNX Runtime (`ort`) for OCR and Zero-Shot Icon Finding

- **Status:**Accepted
- **Date:**Phase 3 (vision + browser)
- **Deciders:**ultranix-mcp maintainers
- **Related:**ADR 0003 (AT-SPI2 primary for semantic UI), ADR 0004 (Vision EP chain)

## Context

`VisionProvider` covers two capabilities:

- **OCR**- `find_text_on_screen`: detect words + bounding boxes in a captured
  frame (target <2s uncached, <1ms from the 10s-TTL OCR cache).
- **Zero-shot icon finding**- `find_icon`: locate a UI element described in
  natural language ("the settings gear") with no per-app training.

Options:

1. **Tesseract**(the ultramac path via Tesseract.js) - mature OCR, but C++
   FFI or process-spawn on Linux, poor bounding-box ergonomics, and *no*
   icon-finding story - a second system would still be needed.
2. **Transformers.js**(ultramac's icon finder) - implies shipping a JS runtime
   or an out-of-process model service; breaks the single-binary Rust design
   (ADR 0001).
3. **`ort` (ONNX Runtime Rust bindings)**- one inference stack for both tasks:
   a text-detection/recognition ONNX pipeline for OCR and **OWL-ViT**for
   open-vocabulary, zero-shot object/icon detection. ultrawin already validates
   the crate in-family (ort 2.0.0-rc.9 + DirectML).

Constraints:

- Must run on the verified environment (CachyOS, Rust 1.98.1) with **CPU as the
  guaranteed baseline**, and opportunistically accelerate.
- Models are downloaded once, cached under `~/.ultranix-mcp/models/`, pinned by
  SHA-256 - the binary ships no weights.
- Inference must be `Send + Sync`-safe for the `Arc<dyn VisionProvider>` slot.

## Decision

- **Vision stack: `ort` (ONNX Runtime).**`OnnxVision` implements
  `VisionProvider` with two model families:
  - OCR: a detection+recognition ONNX pipeline returning `DetectedWord`
    (text + bbox), matching ultrawin's `vision::engine::DetectedWord` shape.
  - Icon finding: **OWL-ViT**open-vocabulary detection - natural-language query
    -> ranked bounding boxes; no fine-tuning per application.
- **Execution-provider strategy on Linux: CPU -> OpenVINO -> CUDA.**
  - CPU EP is the always-available baseline and the latency-contract holder.
  - OpenVINO EP is attempted for Intel iGPU/CPU acceleration.
  - CUDA EP is attempted where an NVIDIA GPU + CUDA stack exist.
  - EP selection is part of the Vision chain in ADR 0004: first EP that
    initializes wins; all failing -> `VisionProvider = None`.
- **Model cache:**`~/.ultranix-mcp/models/`; lazy load on first vision call;
  SHA-256-pinned artifacts; `set_spatial_focus` regions feed directly as
  inference ROI to cut latency.

## Consequences

**Positive:**

- **One dependency, two capabilities**- OCR and icon finding share the session,
  EP configuration, and cache; no second ML system.
- **Zero-shot icon finding**via OWL-ViT gives `find_icon` an open-vocabulary
  contract identical in spirit to ultramac's Transformers.js feature, but
  in-process and single-binary.
- **Hardware-portable:**the CPU->OpenVINO->CUDA ladder covers the realistic Linux
  hardware spread without feature-gating the build.
- **In-family precedent:**ultrawin's `ort` + DirectML usage de-risks crate
  maturity, session management, and `DetectedWord` ergonomics.

**Negative / accepted trade-offs:**

- **Model weight + download**- first vision call may fetch ~hundreds of MB;
  mitigated by cache-once semantics and a clear log line; offline installs can
  pre-seed `~/.ultranix-mcp/models/`.
- **CPU-only latency pressure**- OWL-ViT on CPU is the tightest part of the <2s
  `find_icon`/`find_text_on_screen` targets; spatial-focus ROI and the 10s OCR
  cache are the designed mitigations, and OpenVINO/CUDA take the load where
  present.
- **ONNX opset compatibility**- exported model versions must be pinned in CI;
  a model bump requires golden-fixture regeneration for `find_icon` tests.

**Follow-ups:**

- Record exact model names/digests in `docs/MODELS.md` (Phase 3 deliverable).
- Benchmark EP ladder on the CachyOS/Hyprland target and publish numbers into
  the performance table in ARCHITECTURE.md.
- Fuzz note: `find_icon` natural-language queries are unbounded strings -
  covered by the schema-fuzzing entry in TESTING_STRATEGY.md.
