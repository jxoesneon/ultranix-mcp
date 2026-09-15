//! Mock providers — deterministic Phase-0 stand-ins for every trait.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{Value, json};

use crate::traits::{
    BrowserProvider, CaptureProvider, Detection, Frame, InputProvider, Rect, UIAutomationProvider,
    VisionProvider, WindowInfo, WindowProvider,
};

pub struct MockCapture;
pub struct MockInput;
pub struct MockUiAutomation;
pub struct MockWindow;
pub struct MockVision;
pub struct MockBrowser;

#[async_trait]
impl CaptureProvider for MockCapture {
    async fn capture_frame(&self, _region: Option<Rect>) -> Result<Frame> {
        // 1x1 white PNG.
        Ok(Frame {
            png: base64_png_1x1(),
            width: 1,
            height: 1,
        })
    }
    async fn cursor_position(&self) -> Result<(i32, i32)> {
        Ok((0, 0))
    }
    async fn screen_info(&self) -> Result<Value> {
        Ok(json!({"monitors":[{"name":"mock","width":1920,"height":1080}]}))
    }
}

#[async_trait]
impl InputProvider for MockInput {
    async fn mouse_move(&self, _x: i32, _y: i32) -> Result<()> {
        Ok(())
    }
    async fn mouse_click(&self, _x: i32, _y: i32, _button: &str) -> Result<()> {
        Ok(())
    }
    async fn mouse_button(&self, _button: &str, _down: bool) -> Result<()> {
        Ok(())
    }
    async fn scroll(&self, _dx: f64, _dy: f64) -> Result<()> {
        Ok(())
    }
    async fn key_event(&self, _key: &str, _down: bool) -> Result<()> {
        Ok(())
    }
    async fn type_text(&self, _text: &str) -> Result<()> {
        Ok(())
    }
    async fn cursor_position(&self) -> Result<(i32, i32)> {
        Ok((0, 0))
    }
}

#[async_trait]
impl UIAutomationProvider for MockUiAutomation {
    async fn get_root_json(&self, _depth: u32) -> Result<Value> {
        Ok(json!({"role":"desktop","children":[]}))
    }
    async fn get_focused_json(&self) -> Result<Value> {
        Ok(json!({"role":"application","name":"mock"}))
    }
    async fn find_element(&self, _query: &str) -> Result<Option<Rect>> {
        Ok(None)
    }
    async fn invoke_element(&self, _query: &str) -> Result<bool> {
        Ok(false)
    }
}

#[async_trait]
impl WindowProvider for MockWindow {
    async fn list_windows(&self) -> Result<Vec<WindowInfo>> {
        Ok(vec![WindowInfo {
            id: "0x0".into(),
            title: "mock-window".into(),
            class: "mock".into(),
            workspace: 1,
            rect: Rect {
                x: 0,
                y: 0,
                w: 800,
                h: 600,
            },
            focused: true,
            floating: Some(false),
            fullscreen: Some(false),
            pid: Some(1),
            monitor: Some(0),
        }])
    }
    async fn active_window(&self) -> Result<Option<WindowInfo>> {
        Ok(self.list_windows().await?.into_iter().next())
    }
    async fn dispatch(&self, _action: &str, _window_id: &str, _args: &Value) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl VisionProvider for MockVision {
    async fn recognize_text(&self, _frame: &Frame) -> Result<Vec<Detection>> {
        Ok(vec![])
    }
    async fn find_icon(&self, _frame: &Frame, _desc: &str) -> Result<Vec<Detection>> {
        Ok(vec![])
    }
}

#[async_trait]
impl BrowserProvider for MockBrowser {
    async fn query_selector(&self, _selector: &str) -> Result<Value> {
        Ok(json!({"matches":[]}))
    }
    async fn ensure_ready(&self) -> Result<()> {
        Ok(())
    }
}

fn base64_png_1x1() -> Vec<u8> {
    // Smallest valid PNG (1x1 white RGBA). Generated once; static
    // content. The IDAT must hold a full 5-byte scanline (filter byte +
    // RGBA) — a grayscale-length stream decodes as a corrupt deflate.
    const PNG: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0xF8,
        0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x09, 0xFB, 0x03, 0xFD, 0x2A, 0x86, 0xE3, 0x8A, 0x00, 0x00,
        0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];
    PNG.to_vec()
}
