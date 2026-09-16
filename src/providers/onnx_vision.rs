//! ONNX Runtime vision backend - the Phase 3 implementation of ADR 0005.
//!
//! Two capabilities behind one inference stack:
//!
//! - **OCR**([`VisionProvider::recognize_text`]) - a PaddleOCR-style
//!   detection + recognition pipeline. The DB text detector
//!   (`ch_PP-OCRv4_det_infer.onnx`, RapidOCR export) produces a probability
//!   map which we turn into word boxes via connected components + unclip
//!   expansion; each box is then run through the CRNN/CTC recognizer
//!   (`ch_PP-OCRv4_rec_infer.onnx`) and decoded with `ppocr_keys_v1.txt`.
//! - **Zero-shot icon finding**([`VisionProvider::find_icon`]) -
//!   `onnx-community/owlvit-base-patch32-ONNX` (the transformers.js export
//!   of `google/owlvit-base-patch32`), quantized uint8 build for CPU. The
//!   natural-language query is CLIP-BPE-tokenized (`tokenizer.json` via the
//!   `tokenizers` crate) and run jointly with the image; `logits` +
//!   `pred_boxes` are sigmoid-thresholded, rescaled and NMS-deduplicated.
//!
//! ## Model management
//!
//! No weights are bundled. Every artifact is listed in [`MODELS`] with a
//! pinned URL + SHA-256, downloaded on **first use**(never in [`new`],
//! never in tests) into `<state>/models/` - `~/.ultranix-mcp/models/` or
//! the `ULTRANIX_MCP_STATE_DIR` override - verified against the checksum
//! and written `0600`. A corrupted cache entry is re-downloaded.
//!
//! ## Execution providers
//!
//! The prebuilt ONNX Runtime pulled in by `ort/download-binaries` is
//! CPU-only: `ep::CPU` is always registered last so unsupported ops fall
//! back. Building with `--features vision-openvino` / `vision-cuda` /
//! `vision-rocm`
//! prepends the matching EP (implies `ort/load-dynamic`; point
//! `ORT_DYLIB_PATH` at an ORT build containing the EP). If EP registration
//! fails the session is retried CPU-only.
//!
//! ## Testing
//!
//! All pre/post-processing is pure (resize/normalize, component -> box
//! decode, unclip, CTC greedy decode, CLIP padding, sigmoid/NMS) and
//! unit-tested with synthetic tensors. Tests never touch the network or
//! the model cache. The end-to-end inference test is `#[ignore]`d and
//! additionally requires `ULTRANIX_MCP_LIVE_TESTS=1`.
//!
//! SAFETY: `recognize_text`/`find_icon` run inference inside
//! `tokio::task::spawn_blocking` - ORT is blocking, and `reqwest::blocking`
//! (model downloads) must not run on a runtime worker thread.

use std::fs;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Once, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use dashmap::DashMap;
use image::{ImageFormat, RgbImage, imageops::FilterType};
use ort::ep::ExecutionProviderDispatch;
use ort::session::Session;
use ort::session::builder::GraphOptimizationLevel;
use ort::value::Tensor;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::state::StateDir;
use crate::traits::{Detection, Frame, Rect, VisionProvider};

// ---------------------------------------------------------------------------
// Model manifest - pinned URL + SHA-256 for every fetched artifact.
// Checksums verified against the downloaded bytes (HuggingFace LFS `oid`
// is the SHA-256; confirmed locally for the OCR models). Sources:
//   * SWHL/RapidOCR (HF mirror of the RapidOCR/PaddleOCR PP-OCRv4 exports)
//   * PaddlePaddle/PaddleOCR repo, pinned commit (recognizer dictionary)
//   * onnx-community/owlvit-base-patch32-ONNX (transformers.js export of
//     google/owlvit-base-patch32; the uint8-quantized graph for CPU)
// ---------------------------------------------------------------------------

/// One downloadable artifact: state-dir-relative file name, source URL and
/// the SHA-256 the bytes must match before the file is used.
struct ModelSpec {
    file_name: &'static str,
    url: &'static str,
    sha256: &'static str,
}

/// PP-OCRv4 text detector (DB head), dynamic HxW input `x`, output
/// `sigmoid_0.tmp_0` - a `[1,1,H,W]` text-probability map.
const OCR_DET: ModelSpec = ModelSpec {
    file_name: "ch_PP-OCRv4_det_infer.onnx",
    url: "https://huggingface.co/SWHL/RapidOCR/resolve/main/PP-OCRv4/ch_PP-OCRv4_det_infer.onnx",
    sha256: "d2a7720d45a54257208b1e13e36a8479894cb74155a5efe29462512d42f49da9",
};

/// PP-OCRv4 text recognizer (CRNN + CTC), input `x` `[1,3,48,W]` (dynamic
/// width), output `softmax_11.tmp_0` `[1,T,C]` per-timestep class logits.
const OCR_REC: ModelSpec = ModelSpec {
    file_name: "ch_PP-OCRv4_rec_infer.onnx",
    url: "https://huggingface.co/SWHL/RapidOCR/resolve/main/PP-OCRv4/ch_PP-OCRv4_rec_infer.onnx",
    sha256: "48fc40f24f6d2a207a2b1091d3437eb3cc3eb6b676dc3ef9c37384005483683b",
};

/// CTC dictionary for the recognizer (one character per line; index 0 is
/// the CTC blank, line `n` is class `n`). Pinned to a PaddleOCR commit so
/// the byte content - and the hash - cannot drift.
const OCR_KEYS: ModelSpec = ModelSpec {
    file_name: "ppocr_keys_v1.txt",
    url: "https://raw.githubusercontent.com/PaddlePaddle/PaddleOCR/24f06d1a1b018d90c3c16bf49e966f988f55d98d/ppocr/utils/ppocr_keys_v1.txt",
    sha256: "a1c84d9bdb9ab29043c58896224d32941783eb821629618416dcb08f12886492",
};

/// OWL-ViT base-patch32, uint8-quantized single-graph export used by
/// transformers.js. Inputs: `input_ids`/`attention_mask` `[B,16]` int64,
/// `pixel_values` `[B,3,768,768]` f32. Outputs: `logits` `[B,Q,T]`,
/// `pred_boxes` `[B,Q,4]` (normalized cx,cy,w,h), plus unused embeds.
const OWL_MODEL: ModelSpec = ModelSpec {
    file_name: "owlvit-base-patch32-q8.onnx",
    url: "https://huggingface.co/onnx-community/owlvit-base-patch32-ONNX/resolve/main/onnx/model_quantized.onnx",
    sha256: "aabff321fbd0953f2914a6c69e44bf2dfa05ca539319fd665b591d6832e9352f",
};

/// CLIP BPE tokenizer for OWL-ViT text queries (BOS `<|startoftext|>` =
/// 49406, EOS/pad `<|endoftext|>` = 49407 via the RobertaProcessing
/// post-processor).
const OWL_TOKENIZER: ModelSpec = ModelSpec {
    file_name: "owlvit-base-patch32-tokenizer.json",
    url: "https://huggingface.co/onnx-community/owlvit-base-patch32-ONNX/resolve/main/tokenizer.json",
    sha256: "c748fe6027dff0040fbabedc43f4a20724fefa53cce66860e27618f24990622f",
};

/// OCR detection preprocessing (PaddleOCR `DetResizeForTest`-equivalent):
/// downscale so the long edge fits `DET_MAX_SIDE`, then round each side up
/// to a multiple of 32 (the backbone stride).
const DET_MAX_SIDE: u32 = 960;
const DET_STRIDE: u32 = 32;
/// Binarization threshold on the detector's probability map.
const DET_MAP_THRESH: f32 = 0.3;
/// Minimum mean-in-component score for a candidate box to be kept.
const DET_BOX_THRESH: f32 = 0.5;
/// Unclip expansion ratio (DB post-process `unclip_ratio`).
const DET_UNCLIP_RATIO: f32 = 1.6;
/// Smallest box edge (map pixels) worth running recognition on.
const DET_MIN_EDGE: u32 = 3;
/// Hard cap on boxes passed to the recognizer (bounds worst-case latency).
const MAX_OCR_BOXES: usize = 256;
/// ImageNet normalization for the detector input.
const DET_MEAN: [f32; 3] = [0.485, 0.456, 0.406];
const DET_STD: [f32; 3] = [0.229, 0.224, 0.225];

/// Recognizer input height; width is aspect-scaled and capped.
const REC_HEIGHT: u32 = 48;
const REC_MIN_WIDTH: u32 = 8;
const REC_MAX_WIDTH: u32 = 320;

/// OWL-ViT fixed input size (preprocessor_config: size 768×768).
const OWL_IMAGE_SIZE: u32 = 768;
/// Text sequence length (text_config.max_length = 16).
const OWL_SEQ_LEN: usize = 16;
/// CLIP pad/EOS token id (`<|endoftext|>`); attention_mask marks padding.
const OWL_PAD_ID: i64 = 49407;
/// Sigmoid score floor for a query box to count as a detection.
const OWL_SCORE_THRESH: f32 = 0.1;
/// IoU dedupe + result cap for `find_icon`.
const OWL_NMS_IOU: f32 = 0.5;
const OWL_MAX_DETECTIONS: usize = 32;
/// CLIP normalization (preprocessor_config image_mean/image_std); values
/// kept as-published rather than truncated to f32 display precision.
#[allow(clippy::excessive_precision)]
const CLIP_MEAN: [f32; 3] = [0.48145466, 0.4578275, 0.40821073];
#[allow(clippy::excessive_precision)]
const CLIP_STD: [f32; 3] = [0.26862954, 0.26130258, 0.27577711];

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// `ort`-backed [`VisionProvider`]. Construction is cheap - [`new`] only
/// verifies the ONNX Runtime library can initialize; sessions and model
/// downloads are deferred to the first vision call.
pub struct OnnxVision {
    inner: Arc<Inner>,
}

/// Compile-time contract: `VisionProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OnnxVision>();
};

struct Inner {
    state: StateDir,
    ocr: OnceLock<Result<OcrEngine, String>>,
    icon: OnceLock<Result<IconEngine, String>>,
    /// Detection-result cache (ARCHITECTURE §6): blake3-keyed, TTL
    /// [`OCR_CACHE_TTL`], capped at [`OCR_CACHE_CAP`] entries.
    cache: DashMap<String, (Instant, Vec<Detection>)>,
}

struct OcrEngine {
    det: Mutex<Session>,
    rec: Mutex<Session>,
    /// CTC character table; `keys[i]` is class `i + 1` (0 = blank).
    keys: Vec<String>,
}

struct IconEngine {
    session: Mutex<Session>,
    tokenizer: tokenizers::Tokenizer,
}

impl OnnxVision {
    /// Probe constructor for the fallback chain: resolves the state layout
    /// and verifies ONNX Runtime can initialize, **without**downloading
    /// any model. `None` -> the `vision` slot stays unavailable.
    pub fn new() -> Option<Self> {
        let state = StateDir::bootstrap().ok()?;
        if !ort_probe() {
            return None;
        }
        Some(Self {
            inner: Arc::new(Inner {
                state,
                ocr: OnceLock::new(),
                icon: OnceLock::new(),
                cache: DashMap::new(),
            }),
        })
    }
}

/// Cheap ORT availability probe: creating a `SessionBuilder` exercises the
/// loaded ONNX Runtime API (and, under `ort/load-dynamic`, loads the dylib
/// via `ORT_DYLIB_PATH`). `catch_unwind` guards the dylib-load `expect` in
/// `ort`'s lazy init so a missing library degrades to `None` instead of a
/// panic inside the fallback chain.
fn ort_probe() -> bool {
    std::panic::catch_unwind(|| Session::builder().is_ok()).unwrap_or(false)
}

/// One-time `ort` environment init. `commit()` returns `false` when an
/// environment already exists - that's fine (defaults apply).
fn ensure_environment() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        ort::init().with_name("ultranix-mcp").commit();
    });
}

/// EP registration order - ORT places each op on the first EP that claims
/// it, so accelerated EPs precede the always-available CPU fallback.
fn execution_providers() -> Vec<ExecutionProviderDispatch> {
    vec![
        #[cfg(feature = "vision-openvino")]
        ort::ep::OpenVINO::default().build(),
        #[cfg(feature = "vision-cuda")]
        ort::ep::CUDA::default().build(),
        #[cfg(feature = "vision-rocm")]
        ort::ep::ROCm::default().build(),
        ort::ep::CPU::default().build(),
    ]
}

/// Build a session for `path` on the full EP ladder; if accelerated EP
/// registration fails (feature enabled but the loaded ORT build lacks the
/// EP), retry CPU-only - availability beats speed.
fn build_session(path: &Path) -> Result<Session> {
    ensure_environment();
    let threads = std::thread::available_parallelism()
        .map(|n| n.get().min(8))
        .unwrap_or(4);
    let configured = |eps: &[ExecutionProviderDispatch]| -> Result<Session> {
        Session::builder()
            .map_err(|e| anyhow!("ort session builder: {e}"))?
            .with_execution_providers(eps)
            .map_err(|e| anyhow!("ort EP registration: {e}"))?
            .with_optimization_level(GraphOptimizationLevel::All)
            .map_err(|e| anyhow!("ort opt level: {e}"))?
            .with_intra_threads(threads)
            .map_err(|e| anyhow!("ort intra threads: {e}"))?
            .commit_from_file(path)
            .map_err(|e| anyhow!("ort load {}: {e}", path.display()))
    };

    let eps = execution_providers();
    match configured(&eps) {
        Ok(s) => Ok(s),
        Err(first) if eps.len() > 1 => {
            warn!("vision: EP ladder failed ({first:#}); retrying CPU-only");
            configured(&[ort::ep::CPU::default().build()])
        }
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Detection-result cache (ARCHITECTURE §6): a fresh `recognize_text` /
// `find_icon` inference costs up to ~2 s on CPU, while tools routinely
// re-query the same frame (e.g. `find_text_on_screen` retries). Cache
// hits are keyed on the full PNG bytes plus query params - a changed
// pixel or query is always a miss. Entries expire after
// [`OCR_CACHE_TTL`] and the map is capped at [`OCR_CACHE_CAP`] entries
// (oldest evicted on insert).
// ---------------------------------------------------------------------------

/// TTL for one cached detection result.
const OCR_CACHE_TTL: Duration = Duration::from_secs(10);
/// Max entries in the result cache.
const OCR_CACHE_CAP: usize = 64;

type ResultCache = DashMap<String, (Instant, Vec<Detection>)>;

/// `recognize_text` cache key - the full frame bytes.
fn ocr_cache_key(png: &[u8]) -> String {
    format!("ocr:{}", blake3::hash(png).to_hex())
}

/// `find_icon` cache key - frame bytes plus the natural-language query.
fn icon_cache_key(png: &[u8], description: &str) -> String {
    format!("icon:{}:{}", blake3::hash(png).to_hex(), description)
}

/// Cache hit: `Some` only when the entry exists and is younger than
/// [`OCR_CACHE_TTL`]; an expired entry is evicted on the way out.
fn cache_get(cache: &ResultCache, key: &str, now: Instant) -> Option<Vec<Detection>> {
    let entry = cache.get(key)?;
    if now.duration_since(entry.0) >= OCR_CACHE_TTL {
        drop(entry);
        cache.remove(key);
        crate::metrics::set_ocr_cache_entries(cache.len());
        return None;
    }
    Some(entry.1.clone())
}

/// Insert `dets` under `key`, evicting the oldest entry first when the
/// map is at capacity.
fn cache_put(cache: &ResultCache, key: String, dets: Vec<Detection>, now: Instant) {
    if !cache.contains_key(&key) && cache.len() >= OCR_CACHE_CAP {
        let oldest = cache
            .iter()
            .min_by_key(|e| e.value().0)
            .map(|e| e.key().clone());
        if let Some(k) = oldest {
            cache.remove(&k);
        }
    }
    cache.insert(key, (now, dets));
    crate::metrics::set_ocr_cache_entries(cache.len());
}

impl Inner {
    /// Lazily fetch + load the OCR pipeline. `OnceLock` memoizes failures
    /// too - a broken cache/network doesn't retry-download per call.
    fn ocr(&self) -> Result<&OcrEngine> {
        self.ocr
            .get_or_init(|| self.init_ocr().map_err(|e| format!("{e:#}")))
            .as_ref()
            .map_err(|e| anyhow!("vision OCR init: {e}"))
    }

    fn init_ocr(&self) -> Result<OcrEngine> {
        let dir = self.state.models_dir();
        let det_path = ensure_model(&dir, &OCR_DET)?;
        let rec_path = ensure_model(&dir, &OCR_REC)?;
        let keys_path = ensure_model(&dir, &OCR_KEYS)?;
        let keys = load_keys(&keys_path)?;
        info!(?dir, "vision: loading OCR sessions");
        Ok(OcrEngine {
            det: Mutex::new(build_session(&det_path)?),
            rec: Mutex::new(build_session(&rec_path)?),
            keys,
        })
    }

    fn icon(&self) -> Result<&IconEngine> {
        self.icon
            .get_or_init(|| self.init_icon().map_err(|e| format!("{e:#}")))
            .as_ref()
            .map_err(|e| anyhow!("vision icon init: {e}"))
    }

    fn init_icon(&self) -> Result<IconEngine> {
        let dir = self.state.models_dir();
        let model = ensure_model(&dir, &OWL_MODEL)?;
        let tok = ensure_model(&dir, &OWL_TOKENIZER)?;
        let tokenizer = tokenizers::Tokenizer::from_file(&tok)
            .map_err(|e| anyhow!("load OWL-ViT tokenizer: {e}"))?;
        info!(?dir, "vision: loading OWL-ViT session");
        Ok(IconEngine {
            session: Mutex::new(build_session(&model)?),
            tokenizer,
        })
    }

    /// Blocking OCR with the 10 s result cache in front (ARCHITECTURE
    /// §6): identical frame bytes within the TTL return the memoized
    /// `Detection`s and never touch the sessions.
    fn recognize(&self, png: &[u8]) -> Result<Vec<Detection>> {
        let key = ocr_cache_key(png);
        let now = Instant::now();
        if let Some(hit) = cache_get(&self.cache, &key, now) {
            return Ok(hit);
        }
        let dets = self.recognize_uncached(png)?;
        // Timestamp at completion so inference time doesn't eat the TTL.
        cache_put(&self.cache, key, dets.clone(), Instant::now());
        Ok(dets)
    }

    /// Uncached OCR: det -> boxes -> rec per box -> `Detection`s.
    fn recognize_uncached(&self, png: &[u8]) -> Result<Vec<Detection>> {
        let img = decode_png_rgb(png)?;
        let engine = self.ocr()?;

        let (dw, dh) = det_resize_dims(img.width(), img.height());
        let resized = image::imageops::resize(&img, dw, dh, FilterType::Triangle);
        let chw = rgb_to_chw_f32(&resized, DET_MEAN, DET_STD);
        let input = Tensor::from_array((vec![1, 3, dh as i64, dw as i64], chw))
            .context("build det input tensor")?;

        let mut det = lock(&engine.det)?;
        let outputs = det
            .run(ort::inputs![input])
            .map_err(|e| anyhow!("det run: {e}"))?;
        let (shape, map) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| anyhow!("extract det prob map: {e}"))?;
        let dims: Vec<i64> = shape.iter().copied().collect();
        let probs = map.to_vec();
        drop(outputs);
        drop(det);

        // The DB head emits a same-size prob map; tolerate other shapes by
        // scaling into the resized-image space either way.
        let (mh, mw) = match dims.as_slice() {
            [1, 1, h, w] => (*h as u32, *w as u32),
            _ => bail!("det output shape {dims:?}, expected [1,1,H,W]"),
        };
        let scale_x = img.width() as f32 / dw as f32;
        let scale_y = img.height() as f32 / dh as f32;
        let boxes = det_boxes(
            &probs,
            mw,
            mh,
            dw / mw.max(1),
            dh / mh.max(1),
            scale_x,
            scale_y,
        );

        debug!(boxes = boxes.len(), "vision: det candidates");
        let mut out = Vec::new();
        for (rect, det_score) in boxes.into_iter().take(MAX_OCR_BOXES) {
            let Some(crop) = crop_rgb(&img, rect) else {
                continue;
            };
            let (text, rec_score) = self.recognize_word(engine, &crop)?;
            if text.is_empty() {
                continue;
            }
            out.push(Detection {
                text,
                rect,
                confidence: (rec_score * det_score).clamp(0.0, 1.0),
            });
        }
        // Reading order: top-to-bottom, left-to-right.
        out.sort_by_key(|d| (d.rect.y, d.rect.x));
        Ok(out)
    }

    /// One word box through the recognizer -> (text, mean char confidence).
    fn recognize_word(&self, engine: &OcrEngine, crop: &RgbImage) -> Result<(String, f32)> {
        let tw = rec_target_width(crop.width(), crop.height());
        let resized = image::imageops::resize(crop, tw, REC_HEIGHT, FilterType::Triangle);
        // PaddleOCR rec normalization `(v/255 - 0.5) / 0.5` is the same
        // (v/255 - mean)/std shape with mean = std = 0.5.
        let chw = rgb_to_chw_f32(&resized, [0.5; 3], [0.5; 3]);
        let input = Tensor::from_array((vec![1, 3, REC_HEIGHT as i64, tw as i64], chw))
            .map_err(|e| anyhow!("build rec input tensor: {e}"))?;
        let mut rec = lock(&engine.rec)?;
        let outputs = rec
            .run(ort::inputs![input])
            .map_err(|e| anyhow!("rec run: {e}"))?;
        let (shape, logits) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| anyhow!("extract rec logits: {e}"))?;
        let dims: Vec<i64> = shape.iter().copied().collect();
        let (t, c) = match dims.as_slice() {
            [1, t, c] => (*t as usize, *c as usize),
            _ => bail!("rec output shape {dims:?}, expected [1,T,C]"),
        };
        Ok(ctc_greedy_decode(logits, t, c, &engine.keys))
    }

    /// Blocking OWL-ViT zero-shot detection for one text query, behind
    /// the same 10 s result cache as [`Self::recognize`].
    fn find_icon(&self, png: &[u8], description: &str) -> Result<Vec<Detection>> {
        let key = icon_cache_key(png, description);
        let now = Instant::now();
        if let Some(hit) = cache_get(&self.cache, &key, now) {
            return Ok(hit);
        }
        let dets = self.find_icon_uncached(png, description)?;
        cache_put(&self.cache, key, dets.clone(), Instant::now());
        Ok(dets)
    }

    /// Uncached OWL-ViT inference for `(png, description)`.
    fn find_icon_uncached(&self, png: &[u8], description: &str) -> Result<Vec<Detection>> {
        let img = decode_png_rgb(png)?;
        let engine = self.icon()?;

        let enc = engine
            .tokenizer
            .encode(description, true)
            .map_err(|e| anyhow!("tokenize icon query: {e}"))?;
        let (ids, mask) = clip_pad_ids(enc.get_ids(), OWL_SEQ_LEN);

        let resized =
            image::imageops::resize(&img, OWL_IMAGE_SIZE, OWL_IMAGE_SIZE, FilterType::CatmullRom);
        let pixels = rgb_to_chw_f32(&resized, CLIP_MEAN, CLIP_STD);

        let id_t = Tensor::from_array((vec![1, OWL_SEQ_LEN as i64], ids))
            .map_err(|e| anyhow!("build input_ids tensor: {e}"))?;
        let mask_t = Tensor::from_array((vec![1, OWL_SEQ_LEN as i64], mask))
            .map_err(|e| anyhow!("build attention_mask tensor: {e}"))?;
        let px_t = Tensor::from_array((
            vec![1, 3, OWL_IMAGE_SIZE as i64, OWL_IMAGE_SIZE as i64],
            pixels,
        ))
        .map_err(|e| anyhow!("build pixel_values tensor: {e}"))?;

        let mut session = lock(&engine.session)?;
        let outputs = session
            .run(ort::inputs![
                "input_ids" => id_t,
                "attention_mask" => mask_t,
                "pixel_values" => px_t,
            ])
            .map_err(|e| anyhow!("owlvit run: {e}"))?;

        let (lshape, logits) = outputs["logits"]
            .try_extract_tensor::<f32>()
            .map_err(|e| anyhow!("extract owlvit logits: {e}"))?;
        let (bshape, boxes) = outputs["pred_boxes"]
            .try_extract_tensor::<f32>()
            .map_err(|e| anyhow!("extract owlvit boxes: {e}"))?;
        let ld: Vec<i64> = lshape.iter().copied().collect();
        let bd: Vec<i64> = bshape.iter().copied().collect();
        let (queries, text_q) = match (ld.as_slice(), bd.as_slice()) {
            ([1, q, t], [1, bq, 4]) if q == bq => (*q as usize, *t as usize),
            _ => bail!("owlvit output shapes logits={ld:?} boxes={bd:?}"),
        };

        // logits[0][q][k]: k indexes text queries; ours is a single query -> 0.
        let mut dets: Vec<Detection> = Vec::new();
        for q in 0..queries {
            let score = sigmoid(logits[q * text_q]);
            if score < OWL_SCORE_THRESH {
                continue;
            }
            let b = &boxes[q * 4..q * 4 + 4];
            dets.push(Detection {
                text: description.to_string(),
                rect: cxcywh_to_rect(b[0], b[1], b[2], b[3], img.width(), img.height()),
                confidence: score,
            });
        }
        Ok(nms(dets, OWL_NMS_IOU)
            .into_iter()
            .take(OWL_MAX_DETECTIONS)
            .collect())
    }
}

#[async_trait]
impl VisionProvider for OnnxVision {
    async fn recognize_text(&self, frame: &Frame) -> Result<Vec<Detection>> {
        let inner = self.inner.clone();
        let png = frame.png.clone();
        tokio::task::spawn_blocking(move || inner.recognize(&png))
            .await
            .context("vision OCR task join")?
    }

    async fn find_icon(&self, frame: &Frame, description: &str) -> Result<Vec<Detection>> {
        let inner = self.inner.clone();
        let png = frame.png.clone();
        let description = description.to_string();
        tokio::task::spawn_blocking(move || inner.find_icon(&png, &description))
            .await
            .context("vision icon task join")?
    }
}

fn lock(s: &Mutex<Session>) -> Result<MutexGuard<'_, Session>> {
    s.lock()
        .map_err(|_| anyhow!("vision session lock poisoned"))
}

// ---------------------------------------------------------------------------
// Model download + verification (runs on blocking threads only)
// ---------------------------------------------------------------------------

/// Ensure `<dir>/<spec.file_name>` exists with the pinned SHA-256 and `0600`
/// perms, downloading first if missing or corrupted. Writes go to a temp
/// file in the same directory and are renamed into place, so a killed
/// download can never leave a half-written model behind.
fn ensure_model(dir: &Path, spec: &ModelSpec) -> Result<PathBuf> {
    let dest = dir.join(spec.file_name);
    if dest.is_file() {
        match sha256_file(&dest) {
            Ok(h) if h == spec.sha256 => return Ok(dest),
            Ok(h) => {
                warn!(file = spec.file_name, got = %h, "vision: checksum mismatch, re-downloading");
                fs::remove_file(&dest).ok();
            }
            Err(e) => {
                warn!(
                    file = spec.file_name,
                    "vision: unreadable cache entry ({e:#}), re-downloading"
                );
                fs::remove_file(&dest).ok();
            }
        }
    }

    fs::create_dir_all(dir).with_context(|| format!("creating models dir {}", dir.display()))?;
    let tmp = dir.join(format!(".{}.part", spec.file_name));
    info!(
        url = spec.url,
        file = spec.file_name,
        "vision: downloading model"
    );
    fetch_to(spec.url, &tmp).with_context(|| format!("downloading {}", spec.url))?;

    let got = sha256_file(&tmp).context("hash downloaded model")?;
    if got != spec.sha256 {
        fs::remove_file(&tmp).ok();
        bail!(
            "checksum mismatch for {}: expected {}, got {}",
            spec.file_name,
            spec.sha256,
            got
        );
    }
    set_private_file(&tmp)?;
    fs::rename(&tmp, &dest)
        .with_context(|| format!("rename {} -> {}", tmp.display(), dest.display()))?;
    Ok(dest)
}

/// Fetch `url` into `path`. `file://` is supported for hermetic tests;
/// everything else goes through `reqwest::blocking`.
fn fetch_to(url: &str, path: &Path) -> Result<()> {
    if let Some(src) = url.strip_prefix("file://") {
        fs::copy(src, path).with_context(|| format!("copy {src}"))?;
        return Ok(());
    }
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        // Total request budget - a stalled download must not wedge the
        // engine's OnceLock init forever.
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .context("build http client")?;
    let mut resp = client
        .get(url)
        .send()
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("GET {url}"))?;
    let mut out = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    resp.copy_to(&mut out)
        .with_context(|| format!("stream {url}"))?;
    out.flush().ok();
    Ok(())
}

/// Streaming SHA-256 of a file -> lowercase hex.
fn sha256_file(path: &Path) -> Result<String> {
    let f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = BufReader::with_capacity(1 << 16, f);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1 << 16];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<()> {
    Ok(())
}

/// Load the CTC dictionary - one character per line; a line containing a
/// literal space is the space character, so only `\r` is trimmed.
fn load_keys(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let keys: Vec<String> = text
        .lines()
        .map(|l| l.trim_end_matches('\r').to_string())
        .collect();
    if keys.is_empty() {
        bail!("empty CTC dictionary {}", path.display());
    }
    Ok(keys)
}

// ---------------------------------------------------------------------------
// Pure pre/post-processing - unit-tested without any model.
// ---------------------------------------------------------------------------

/// Decode a frame's PNG bytes to RGB8.
fn decode_png_rgb(png: &[u8]) -> Result<RgbImage> {
    Ok(image::load_from_memory_with_format(png, ImageFormat::Png)
        .context("decode frame PNG")?
        .to_rgb8())
}

/// Detector input geometry: downscale to `DET_MAX_SIDE` on the long edge
/// (never upscale), then round each side up to a `DET_STRIDE` multiple.
fn det_resize_dims(w: u32, h: u32) -> (u32, u32) {
    let scale = (DET_MAX_SIDE as f32 / w.max(h) as f32).min(1.0);
    let rw = round_up(((w as f32 * scale) as u32).max(1), DET_STRIDE);
    let rh = round_up(((h as f32 * scale) as u32).max(1), DET_STRIDE);
    (rw, rh)
}

const fn round_up(v: u32, m: u32) -> u32 {
    v.div_ceil(m) * m
}

/// RGB8 -> planar CHW f32 with `(v/255 - mean) / std` normalization.
fn rgb_to_chw_f32(img: &RgbImage, mean: [f32; 3], std: [f32; 3]) -> Vec<f32> {
    let (w, h) = (img.width() as usize, img.height() as usize);
    let mut out = vec![0.0f32; 3 * w * h];
    for c in 0..3 {
        for y in 0..h {
            for x in 0..w {
                out[c * w * h + y * w + x] =
                    (img.get_pixel(x as u32, y as u32)[c] as f32 / 255.0 - mean[c]) / std[c];
            }
        }
    }
    out
}

/// Crop `rect` (clamped to the image) as an owned `RgbImage`.
fn crop_rgb(img: &RgbImage, rect: Rect) -> Option<RgbImage> {
    let (iw, ih) = (img.width() as i32, img.height() as i32);
    let x = rect.x.clamp(0, iw);
    let y = rect.y.clamp(0, ih);
    let x2 = (rect.x + rect.w).clamp(x, iw);
    let y2 = (rect.y + rect.h).clamp(y, ih);
    let (w, h) = (x2 - x, y2 - y);
    if w <= 0 || h <= 0 {
        return None;
    }
    Some(image::imageops::crop_imm(img, x as u32, y as u32, w as u32, h as u32).to_image())
}

/// A binarized component on the detector's probability map.
struct Component {
    x0: u32,
    y0: u32,
    x1: u32,
    y1: u32,
    count: u32,
    score_sum: f32,
}

/// 4-connected component labeling over `prob > thresh`. Returns bounding
/// box, pixel count and summed probability per component - the inputs the
/// box filter/unclip stage needs.
fn prob_map_components(prob: &[f32], w: u32, h: u32, thresh: f32) -> Vec<Component> {
    let (w, h) = (w as usize, h as usize);
    debug_assert_eq!(prob.len(), w * h);
    let mut seen = vec![false; w * h];
    let mut comps = Vec::new();
    for start in 0..w * h {
        if seen[start] || prob[start] <= thresh {
            continue;
        }
        let mut stack = vec![start];
        seen[start] = true;
        let mut c = Component {
            x0: (start % w) as u32,
            y0: (start / w) as u32,
            x1: (start % w) as u32,
            y1: (start / w) as u32,
            count: 0,
            score_sum: 0.0,
        };
        while let Some(i) = stack.pop() {
            let (x, y) = (i % w, i / w);
            c.count += 1;
            c.score_sum += prob[i];
            c.x0 = c.x0.min(x as u32);
            c.y0 = c.y0.min(y as u32);
            c.x1 = c.x1.max(x as u32);
            c.y1 = c.y1.max(y as u32);
            for n in [
                x.checked_sub(1).map(|nx| y * w + nx),
                (x + 1 < w).then_some(y * w + x + 1),
                y.checked_sub(1).map(|ny| ny * w + x),
                (y + 1 < h).then_some((y + 1) * w + x),
            ]
            .into_iter()
            .flatten()
            {
                if !seen[n] && prob[n] > thresh {
                    seen[n] = true;
                    stack.push(n);
                }
            }
        }
        comps.push(c);
    }
    comps
}

/// DB post-process: threshold the probability map, take component bounding
/// boxes, drop low-score/tiny ones, then "unclip" - expand each box by
/// `area * unclip_ratio / perimeter` per side (axis-aligned approximation
/// of PP-OCR's polygon offset, since we skip contour extraction).
///
/// `map_*` indexes the prob map, `cell_*` maps map cells to resized-image
/// pixels, `scale_*` maps resized-image pixels to original frame pixels.
fn det_boxes(
    prob: &[f32],
    map_w: u32,
    map_h: u32,
    cell_w: u32,
    cell_h: u32,
    scale_x: f32,
    scale_y: f32,
) -> Vec<(Rect, f32)> {
    let mut out = Vec::new();
    for c in prob_map_components(prob, map_w, map_h, DET_MAP_THRESH) {
        if c.count == 0 {
            continue;
        }
        let score = c.score_sum / c.count as f32;
        if score < DET_BOX_THRESH {
            continue;
        }
        let (bw, bh) = (c.x1 - c.x0 + 1, c.y1 - c.y0 + 1);
        if bw < DET_MIN_EDGE || bh < DET_MIN_EDGE {
            continue;
        }
        let dist = (bw * bh) as f32 * DET_UNCLIP_RATIO / (2.0 * (bw + bh) as f32);
        let d = dist.max(1.0) as u32;
        let (x0, y0) = (c.x0.saturating_sub(d), c.y0.saturating_sub(d));
        let x1 = (c.x1 + d).min(map_w - 1);
        let y1 = (c.y1 + d).min(map_h - 1);
        // Map cell -> resized image -> original frame coordinates.
        let to_orig = |mx: u32, my: u32| -> (i32, i32) {
            (
                ((mx * cell_w) as f32 * scale_x) as i32,
                ((my * cell_h) as f32 * scale_y) as i32,
            )
        };
        let (ox, oy) = to_orig(x0, y0);
        let (ox1, oy1) = to_orig(x1 + 1, y1 + 1);
        let (w, h) = (ox1 - ox, oy1 - oy);
        if w <= 0 || h <= 0 {
            continue;
        }
        out.push((Rect { x: ox, y: oy, w, h }, score));
    }
    out
}

/// Recognizer input width: aspect-preserved at fixed height 48.
fn rec_target_width(box_w: u32, box_h: u32) -> u32 {
    if box_h == 0 {
        return REC_MIN_WIDTH;
    }
    ((REC_HEIGHT * box_w) / box_h.max(1)).clamp(REC_MIN_WIDTH, REC_MAX_WIDTH)
}

/// CTC greedy decode: argmax per timestep, collapse repeats, drop blank
/// (index 0). Confidence = mean max-probability over emitted characters.
fn ctc_greedy_decode(
    logits: &[f32],
    steps: usize,
    classes: usize,
    keys: &[String],
) -> (String, f32) {
    debug_assert_eq!(logits.len(), steps * classes);
    let mut text = String::new();
    let mut probs = Vec::new();
    let mut prev = usize::MAX;
    for t in 0..steps {
        let row = &logits[t * classes..(t + 1) * classes];
        let (mut best, mut best_p) = (0usize, f32::NEG_INFINITY);
        for (i, &v) in row.iter().enumerate() {
            if v > best_p {
                best_p = v;
                best = i;
            }
        }
        if best != 0
            && best != prev
            && let Some(ch) = keys.get(best - 1)
        {
            text.push_str(ch);
            probs.push(best_p);
        }
        prev = best;
    }
    let conf = if probs.is_empty() {
        0.0
    } else {
        probs.iter().sum::<f32>() / probs.len() as f32
    };
    (text, conf)
}

/// Pad/truncate CLIP token ids to `len` (keeping EOS at the tail when
/// truncating); attention mask marks real tokens.
fn clip_pad_ids(ids: &[u32], len: usize) -> (Vec<i64>, Vec<i64>) {
    let mut ids64: Vec<i64> = ids.iter().map(|&i| i as i64).collect();
    if ids64.len() > len {
        let eos = *ids64.last().unwrap_or(&OWL_PAD_ID);
        ids64.truncate(len);
        if let Some(last) = ids64.last_mut() {
            *last = eos;
        }
    }
    let real = ids64.len();
    ids64.resize(len, OWL_PAD_ID);
    let mask: Vec<i64> = (0..len).map(|i| (i < real) as i64).collect();
    (ids64, mask)
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// OWL-ViT normalized `[cx, cy, w, h]` -> pixel-space `Rect`.
fn cxcywh_to_rect(cx: f32, cy: f32, w: f32, h: f32, img_w: u32, img_h: u32) -> Rect {
    let (iw, ih) = (img_w as f32, img_h as f32);
    let x0 = ((cx - w / 2.0) * iw) as i32;
    let y0 = ((cy - h / 2.0) * ih) as i32;
    let x1 = ((cx + w / 2.0) * iw) as i32;
    let y1 = ((cy + h / 2.0) * ih) as i32;
    Rect {
        x: x0.clamp(0, img_w as i32),
        y: y0.clamp(0, img_h as i32),
        w: (x1 - x0).max(0),
        h: (y1 - y0).max(0),
    }
}

fn iou(a: &Rect, b: &Rect) -> f32 {
    let (ax2, ay2) = (a.x + a.w, a.y + a.h);
    let (bx2, by2) = (b.x + b.w, b.y + b.h);
    let (ix, iy) = (a.x.max(b.x), a.y.max(b.y));
    let (ix2, iy2) = (ax2.min(bx2), ay2.min(by2));
    let (iw, ih) = (ix2 - ix, iy2 - iy);
    if iw <= 0 || ih <= 0 {
        return 0.0;
    }
    let inter = (iw * ih) as f32;
    let union = (a.w * a.h + b.w * b.h) as f32 - inter;
    if union <= 0.0 { 0.0 } else { inter / union }
}

/// Greedy NMS: sort by confidence desc, keep boxes whose IoU with every
/// already-kept box stays under `thresh`.
fn nms(mut dets: Vec<Detection>, thresh: f32) -> Vec<Detection> {
    dets.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));
    let mut keep: Vec<Detection> = Vec::with_capacity(dets.len());
    for d in dets {
        if keep.iter().all(|k| iou(&k.rect, &d.rect) <= thresh) {
            keep.push(d);
        }
    }
    keep
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(file_name: &'static str, url: String, sha256: String) -> ModelSpec {
        // Test-only constructor: ModelSpec holds &'static str for the consts;
        // leaking the test strings keeps the struct simple.
        ModelSpec {
            file_name,
            url: Box::leak(url.into_boxed_str()),
            sha256: Box::leak(sha256.into_boxed_str()),
        }
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ultranix-vision-test-{}-{tag}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // --- geometry / normalization ---

    #[test]
    fn det_resize_caps_long_edge_and_rounds_to_stride() {
        let (w, h) = det_resize_dims(1920, 1080);
        assert_eq!(w, 960); // 1920*0.5 already a multiple of 32
        assert_eq!(h, 544); // 540 -> 544
        let (w, h) = det_resize_dims(100, 50);
        assert_eq!((w, h), (128, 64)); // small frame: scale=1, rounded up to stride
        let (w, h) = det_resize_dims(1, 1);
        assert_eq!((w, h), (32, 32));
        // Extreme aspect: the long edge still caps at DET_MAX_SIDE.
        let (w, h) = det_resize_dims(4000, 30);
        assert_eq!(w, 960);
        assert_eq!(h, 32); // 30*0.24 -> 7 -> rounded up to one stride
        // Portrait orientation scales the same way.
        let (w, h) = det_resize_dims(30, 4000);
        assert_eq!((w, h), (32, 960));
    }

    #[test]
    fn rgb_to_chw_normalizes_and_orders_channels() {
        // 1x2 image: red=255,green=128,blue=0 / red=0,green=0,blue=255.
        let img = RgbImage::from_fn(2, 1, |x, _| {
            if x == 0 {
                image::Rgb([255, 128, 0])
            } else {
                image::Rgb([0, 0, 255])
            }
        });
        let mean = [0.5, 0.5, 0.5];
        let std = [0.25, 0.25, 0.25];
        let t = rgb_to_chw_f32(&img, mean, std);
        // R plane first.
        assert!((t[0] - (1.0 - 0.5) / 0.25).abs() < 1e-6);
        assert!((t[1] - (0.0 - 0.5) / 0.25).abs() < 1e-6);
        // G plane, B plane follow.
        assert!((t[2] - (128.0 / 255.0 - 0.5) / 0.25).abs() < 1e-5);
        assert!((t[5] - 2.0).abs() < 1e-6);
    }

    // --- detector post-processing ---

    #[test]
    fn components_find_blobs_and_skip_background() {
        let (w, h) = (8u32, 8u32);
        let mut m = vec![0.0f32; (w * h) as usize];
        // 2x2 blob at (2..4, 3..5); single hot pixel at (6,6) is separate.
        for y in 3..5 {
            for x in 2..4 {
                m[(y * w + x) as usize] = 0.9;
            }
        }
        m[(6 * w + 6) as usize] = 0.8;
        let comps = prob_map_components(&m, w, h, 0.3);
        assert_eq!(comps.len(), 2);
        let big = comps.iter().find(|c| c.count == 4).unwrap();
        assert_eq!((big.x0, big.y0, big.x1, big.y1), (2, 3, 3, 4));
        assert!((big.score_sum / 4.0 - 0.9).abs() < 1e-6);
    }

    #[test]
    fn det_boxes_filters_and_scales_to_frame() {
        // 32x32 map with a strong blob -> one expanded box in frame coords.
        let (w, h) = (32u32, 32u32);
        let mut m = vec![0.0f32; (w * h) as usize];
        for y in 8..12 {
            for x in 4..20 {
                m[(y * w + x) as usize] = 0.9;
            }
        }
        // identity mapping: cell 1x, scale 1x -> boxes are map-space pixels.
        let boxes = det_boxes(&m, w, h, 1, 1, 1.0, 1.0);
        assert_eq!(boxes.len(), 1);
        let (r, score) = &boxes[0];
        assert!(*score > 0.8);
        // Unclip expands the 16x4 blob by ~1.6*64/40 = 2.56 -> 2 px/side.
        assert!(r.x <= 4 && r.y <= 8 && r.x + r.w >= 20 && r.y + r.h >= 12);

        // Weak blob below DET_BOX_THRESH is dropped.
        let weak = vec![0.4f32; (w * h) as usize];
        assert!(det_boxes(&weak, w, h, 1, 1, 1.0, 1.0).is_empty());
        // All-zero map -> nothing.
        let zero = vec![0.0f32; (w * h) as usize];
        assert!(det_boxes(&zero, w, h, 1, 1, 1.0, 1.0).is_empty());
        // A strong but sub-DET_MIN_EDGE speck is dropped before unclip.
        let mut speck = vec![0.0f32; (w * h) as usize];
        speck[(4 * w + 4) as usize] = 0.95;
        speck[(4 * w + 5) as usize] = 0.95; // 2x1 - under the 3px minimum
        assert!(det_boxes(&speck, w, h, 1, 1, 1.0, 1.0).is_empty());
    }

    #[test]
    fn det_boxes_scales_map_to_original_frame() {
        let w = 16u32;
        let mut m = vec![0.0f32; (w * w) as usize];
        for y in 4..8 {
            for x in 4..8 {
                m[(y * w + x) as usize] = 0.95;
            }
        }
        // cell 1, scale 4 -> a 16px map covering a 64px frame.
        let boxes = det_boxes(&m, w, w, 1, 1, 4.0, 4.0);
        assert_eq!(boxes.len(), 1);
        let r = boxes[0].0;
        assert!(r.w >= 16 && r.h >= 16);
        assert!(r.x <= 16); // blob starts at map x=4 -> frame ~16
    }

    #[test]
    fn rec_width_is_aspect_scaled_and_clamped() {
        assert_eq!(rec_target_width(200, 20), 320); // cap
        assert_eq!(rec_target_width(20, 40), 24);
        assert_eq!(rec_target_width(1, 100), REC_MIN_WIDTH);
        assert_eq!(rec_target_width(10, 0), REC_MIN_WIDTH);
    }

    // --- CTC decode ---

    #[test]
    fn ctc_decodes_collapses_repeats_and_drops_blanks() {
        let keys: Vec<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        // 6 steps x 4 classes: blank,a,a,blank,b,b -> "ab"
        let mut logits = vec![0.0f32; 6 * 4];
        let set = |t: usize, i: usize, v: f32, l: &mut Vec<f32>| l[t * 4 + i] = v;
        set(0, 0, 0.9, &mut logits);
        set(1, 1, 0.8, &mut logits);
        set(2, 1, 0.7, &mut logits);
        set(3, 0, 0.9, &mut logits);
        set(4, 2, 0.6, &mut logits);
        set(5, 2, 0.5, &mut logits);
        let (text, conf) = ctc_greedy_decode(&logits, 6, 4, &keys);
        assert_eq!(text, "ab");
        assert!((conf - 0.7).abs() < 1e-6); // mean of emitted probs (0.8, 0.6)
    }

    #[test]
    fn ctc_blank_only_is_empty() {
        let keys: Vec<String> = vec!["x".to_string()];
        let logits = vec![1.0, 0.0, 1.0, 0.0]; // 2 steps, blank wins
        let (text, conf) = ctc_greedy_decode(&logits, 2, 2, &keys);
        assert_eq!(text, "");
        assert_eq!(conf, 0.0);
    }

    #[test]
    fn ctc_skips_classes_outside_the_dictionary() {
        // 2 steps x 4 classes with a 2-entry dictionary: class 3 wins
        // step 0 (no key -> dropped), class 1 wins step 1.
        let keys: Vec<String> = vec!["a".to_string(), "b".to_string()];
        let logits = [
            0.0, 0.1, 0.2, 0.9, // step 0: class 3 - beyond `keys`
            0.0, 0.8, 0.2, 0.1, // step 1: class 1 -> "a"
        ];
        let (text, conf) = ctc_greedy_decode(&logits, 2, 4, &keys);
        assert_eq!(text, "a");
        assert!((conf - 0.8).abs() < 1e-6);
    }

    // --- CLIP padding ---

    #[test]
    fn clip_pad_pads_and_masks() {
        let (ids, mask) = clip_pad_ids(&[49406, 320, 682, 49407], 8);
        assert_eq!(ids.len(), 8);
        assert_eq!(ids[4..], [OWL_PAD_ID; 4]);
        assert_eq!(mask, [1, 1, 1, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn clip_pad_truncates_keeping_eos() {
        let v: Vec<u32> = (0..20).map(|i| i + 1).chain([49407]).collect();
        let (ids, mask) = clip_pad_ids(&v, 8);
        assert_eq!(ids.len(), 8);
        assert_eq!(*ids.last().unwrap(), 49407); // EOS preserved
        assert_eq!(mask, [1; 8]);
    }

    #[test]
    fn clip_pad_empty_and_exact_fit() {
        // Empty encoding -> all padding, all masked out.
        let (ids, mask) = clip_pad_ids(&[], 4);
        assert_eq!(ids, [OWL_PAD_ID; 4]);
        assert_eq!(mask, [0; 4]);
        // Exactly `len` tokens -> no padding needed, full mask.
        let (ids, mask) = clip_pad_ids(&[1, 2, 3, 4], 4);
        assert_eq!(ids, [1, 2, 3, 4]);
        assert_eq!(mask, [1; 4]);
    }

    // --- icon post-processing ---

    #[test]
    fn cxcywh_converts_and_clamps() {
        let r = cxcywh_to_rect(0.5, 0.5, 0.2, 0.1, 100, 200);
        assert_eq!(
            r,
            Rect {
                x: 40,
                y: 90,
                w: 20,
                h: 20
            }
        );
        let r = cxcywh_to_rect(0.0, 0.0, 0.4, 0.4, 100, 100);
        assert_eq!(r.x, 0);
        assert_eq!(r.y, 0);
        assert!(r.w > 0 && r.h > 0);
    }

    #[test]
    fn iou_and_nms_dedupe_overlaps() {
        let a = Rect {
            x: 0,
            y: 0,
            w: 10,
            h: 10,
        };
        let b = Rect {
            x: 1, // IoU(a,b) ≈ 0.68 - above the 0.5 NMS threshold
            y: 1,
            w: 10,
            h: 10,
        };
        let c = Rect {
            x: 50,
            y: 50,
            w: 10,
            h: 10,
        };
        assert!(iou(&a, &b) > 0.5);
        assert_eq!(iou(&a, &c), 0.0);

        let mk = |rect: Rect, cf: f32| Detection {
            text: "x".into(),
            rect,
            confidence: cf,
        };
        let kept = nms(vec![mk(a, 0.9), mk(b, 0.8), mk(c, 0.7)], 0.5);
        assert_eq!(kept.len(), 2);
        assert!((kept[0].confidence - 0.9).abs() < 1e-6);
        assert_eq!(kept[1].rect, c);

        // Touching-but-not-overlapping edges -> IoU 0, both kept.
        let d = Rect {
            x: 10,
            y: 0,
            w: 10,
            h: 10,
        };
        assert_eq!(iou(&a, &d), 0.0);
        // Degenerate zero-area boxes never overlap.
        let z = Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        };
        assert_eq!(iou(&a, &z), 0.0);
        assert_eq!(iou(&z, &z), 0.0);
        // nms on an empty input is a no-op.
        assert!(nms(vec![], 0.5).is_empty());
    }

    #[test]
    fn sigmoid_bounds() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-6);
        assert!(sigmoid(10.0) > 0.999);
        assert!(sigmoid(-10.0) < 0.001);
    }

    // --- misc pure helpers ---

    #[test]
    fn crop_clamps_to_image() {
        let img = RgbImage::from_pixel(10, 10, image::Rgb([7, 7, 7]));
        // -5..7 horizontally, 0..20 vertically -> clamped to 0..7 x 0..10.
        let r = Rect {
            x: -5,
            y: 0,
            w: 12,
            h: 20,
        };
        let c = crop_rgb(&img, r).unwrap();
        assert_eq!((c.width(), c.height()), (7, 10));
        let outside = Rect {
            x: 50,
            y: 0,
            w: 5,
            h: 5,
        };
        assert!(crop_rgb(&img, outside).is_none());
    }

    #[test]
    fn decode_png_rgb_roundtrip() {
        let img = RgbImage::from_fn(3, 2, |x, y| image::Rgb([x as u8, y as u8, 9]));
        let mut buf = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut buf, ImageFormat::Png)
            .unwrap();
        let back = decode_png_rgb(&buf.into_inner()).unwrap();
        assert_eq!((back.width(), back.height()), (3, 2));
        assert_eq!(back.get_pixel(1, 1).0, [1, 1, 9]);
    }

    #[test]
    fn load_keys_reads_one_char_per_line() {
        let dir = tmp_dir("keys");
        let p = dir.join("k.txt");
        fs::write(&p, "a\nb\n \n中\n").unwrap();
        let keys = load_keys(&p).unwrap();
        assert_eq!(keys, vec!["a", "b", " ", "中"]);
        fs::remove_dir_all(&dir).ok();
    }

    // --- download / verification (file:// only - no network in tests) ---

    #[test]
    fn sha256_file_matches_content() {
        let dir = tmp_dir("sha");
        let p = dir.join("x.bin");
        fs::write(&p, b"hello").unwrap();
        let h = sha256_file(&p).unwrap();
        assert_eq!(h, format!("{:x}", Sha256::digest(b"hello")));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ensure_model_copies_verifies_and_locks_perms() {
        let dir = tmp_dir("model-ok");
        let src = dir.join("src.onnx");
        let bytes = b"fake onnx bytes";
        fs::write(&src, bytes).unwrap();
        let hash = format!("{:x}", Sha256::digest(bytes));
        let s = spec("m.onnx", format!("file://{}", src.display()), hash);

        let dest = ensure_model(&dir.join("models"), &s).unwrap();
        assert!(dest.is_file());
        assert_eq!(fs::read(&dest).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // Second call is a cache hit - same path, no re-copy needed.
        assert_eq!(ensure_model(&dir.join("models"), &s).unwrap(), dest);
        // Temp file cleaned up.
        assert!(!dir.join("models").join(".m.onnx.part").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ensure_model_rejects_checksum_mismatch() {
        let dir = tmp_dir("model-bad");
        let src = dir.join("src.onnx");
        fs::write(&src, b"tampered").unwrap();
        let s = spec(
            "m.onnx",
            format!("file://{}", src.display()),
            "0".repeat(64),
        );
        let err = ensure_model(&dir.join("models"), &s).unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"));
        assert!(!dir.join("models").join("m.onnx").exists());
        assert!(!dir.join("models").join(".m.onnx.part").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fetch_to_supports_file_urls() {
        let dir = tmp_dir("fetch");
        let src = dir.join("src.bin");
        fs::write(&src, b"payload").unwrap();
        let dest = dir.join("out.bin");
        fetch_to(&format!("file://{}", src.display()), &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"payload");
        // A missing source errors rather than creating a partial file.
        assert!(
            fetch_to(
                &format!("file://{}/missing.bin", dir.display()),
                &dir.join("nope.bin"),
            )
            .is_err()
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ort_probe_is_panic_free() {
        // The probe is `catch_unwind`-guarded: it must return a bool
        // whatever the ORT load state is.
        let _ = ort_probe();
    }

    #[test]
    fn build_session_errors_on_missing_or_garbage_model() {
        if !ort_probe() {
            // ORT unavailable in this environment (e.g. load-dynamic
            // with no ORT_DYLIB_PATH) - nothing to exercise.
            return;
        }
        let dir = tmp_dir("sess");
        assert!(build_session(&dir.join("missing.onnx")).is_err());
        let garbage = dir.join("g.onnx");
        fs::write(&garbage, b"this is not an onnx model").unwrap();
        assert!(build_session(&garbage).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ensure_model_redownloads_corrupted_cache() {
        let dir = tmp_dir("model-fix");
        let models = dir.join("models");
        fs::create_dir_all(&models).unwrap();
        let dest = models.join("m.onnx");
        fs::write(&dest, b"corrupt").unwrap();

        let src = dir.join("src.onnx");
        let bytes = b"good bytes";
        fs::write(&src, bytes).unwrap();
        let s = spec(
            "m.onnx",
            format!("file://{}", src.display()),
            format!("{:x}", Sha256::digest(bytes)),
        );
        ensure_model(&models, &s).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), bytes);
        fs::remove_dir_all(&dir).ok();
    }

    // --- detection-result cache (ARCHITECTURE §6) ---

    fn det(text: &str) -> Detection {
        Detection {
            text: text.into(),
            rect: Rect {
                x: 1,
                y: 2,
                w: 3,
                h: 4,
            },
            confidence: 0.9,
        }
    }

    #[test]
    fn cache_hit_returns_memoized_detections() {
        let cache = ResultCache::new();
        let now = Instant::now();
        assert!(cache_get(&cache, "k", now).is_none());
        cache_put(&cache, "k".into(), vec![det("hello")], now);
        let hit = cache_get(&cache, "k", now + Duration::from_secs(5)).unwrap();
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].text, "hello");
        assert_eq!(
            hit[0].rect,
            Rect {
                x: 1,
                y: 2,
                w: 3,
                h: 4
            }
        );
    }

    #[test]
    fn cache_entries_expire_at_ttl() {
        let cache = ResultCache::new();
        let now = Instant::now();
        cache_put(&cache, "k".into(), vec![det("x")], now);
        let just_inside = now + OCR_CACHE_TTL - Duration::from_millis(1);
        assert!(cache_get(&cache, "k", just_inside).is_some());
        // At/over the TTL boundary: miss, and the stale entry is evicted.
        assert!(cache_get(&cache, "k", now + OCR_CACHE_TTL).is_none());
        assert!(!cache.contains_key("k"));
    }

    #[test]
    fn cache_evicts_oldest_at_cap() {
        let cache = ResultCache::new();
        let now = Instant::now();
        for i in 0..OCR_CACHE_CAP {
            cache_put(
                &cache,
                format!("k{i}"),
                vec![det("x")],
                now + Duration::from_millis(i as u64),
            );
        }
        assert_eq!(cache.len(), OCR_CACHE_CAP);
        cache_put(
            &cache,
            "new".into(),
            vec![det("y")],
            now + Duration::from_secs(1),
        );
        assert_eq!(cache.len(), OCR_CACHE_CAP);
        assert!(cache.get("k0").is_none()); // oldest evicted
        assert!(cache.get("k1").is_some());
        assert!(cache.get("new").is_some());
    }

    #[test]
    fn cache_reinsert_refreshes_without_evicting() {
        let cache = ResultCache::new();
        let now = Instant::now();
        for i in 0..OCR_CACHE_CAP {
            cache_put(&cache, format!("k{i}"), vec![det("x")], now);
        }
        cache_put(
            &cache,
            "k0".into(),
            vec![det("fresh")],
            now + Duration::from_millis(1),
        );
        assert_eq!(cache.len(), OCR_CACHE_CAP);
        assert_eq!(cache.get("k0").unwrap().1[0].text, "fresh");
    }

    #[test]
    fn recognize_and_find_icon_serve_cache_hits() {
        // A pre-warmed cache short-circuits before any engine init -
        // the OnceLocks stay untouched and no model is fetched.
        let dir = tmp_dir("cache-hit");
        let inner = Inner {
            state: StateDir::at(dir.join("state")),
            ocr: OnceLock::new(),
            icon: OnceLock::new(),
            cache: DashMap::new(),
        };
        let png = b"fake png bytes";
        cache_put(
            &inner.cache,
            ocr_cache_key(png),
            vec![det("cached")],
            Instant::now(),
        );
        let out = inner.recognize(png).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].text, "cached");
        assert!(inner.ocr.get().is_none());

        cache_put(
            &inner.cache,
            icon_cache_key(png, "gear"),
            vec![det("icon")],
            Instant::now(),
        );
        let out = inner.find_icon(png, "gear").unwrap();
        assert_eq!(out[0].text, "icon");
        assert!(inner.icon.get().is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cache_keys_distinguish_frame_and_query() {
        assert_eq!(ocr_cache_key(b"a"), ocr_cache_key(b"a"));
        assert_ne!(ocr_cache_key(b"a"), ocr_cache_key(b"b"));
        // The capability prefix keeps an OCR entry from colliding with
        // an icon entry over the same frame.
        assert_ne!(ocr_cache_key(b"a"), icon_cache_key(b"a", "x"));
        assert_ne!(icon_cache_key(b"a", "x"), icon_cache_key(b"a", "y"));
        assert_ne!(icon_cache_key(b"a", "x"), icon_cache_key(b"b", "x"));
    }

    // --- end-to-end, gated: needs real models + network on first run ---

    #[test]
    #[ignore = "downloads ~170MB of models; run with --ignored and ULTRANIX_MCP_LIVE_TESTS=1"]
    fn live_ocr_and_icon_end_to_end() {
        if std::env::var_os("ULTRANIX_MCP_LIVE_TESTS").is_none() {
            return;
        }
        let dir = tmp_dir("live");
        let vision = OnnxVision {
            inner: Arc::new(Inner {
                state: StateDir::at(dir.join("state")),
                ocr: OnceLock::new(),
                icon: OnceLock::new(),
                cache: DashMap::new(),
            }),
        };
        // White frame with a black filled "icon-ish" block.
        let img = RgbImage::from_fn(320, 240, |x, y| {
            if (40..80).contains(&x) && (40..80).contains(&y) {
                image::Rgb([0, 0, 0])
            } else {
                image::Rgb([255, 255, 255])
            }
        });
        let mut buf = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut buf, ImageFormat::Png)
            .unwrap();
        let png = buf.into_inner();

        vision.inner.recognize(&png).expect("ocr pipeline ran");
        vision
            .inner
            .find_icon(&png, "a black square")
            .expect("icon pipeline ran");
        fs::remove_dir_all(&dir).ok();
    }
}
