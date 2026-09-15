//! Deterministic-value tests for the Phase-0 mock providers — each trait
//! method returns the canned values documented in src/providers/mock.rs.

use serde_json::{Value, json};
use ultranix_mcp::providers::mock::{
    MockBrowser, MockCapture, MockInput, MockUiAutomation, MockVision, MockWindow,
};
use ultranix_mcp::traits::{
    BrowserProvider, CaptureProvider, Frame, InputProvider, Rect, UIAutomationProvider,
    VisionProvider, WindowProvider,
};

// ---- MockCapture -----------------------------------------------------------

#[tokio::test]
async fn mock_capture_frame_is_1x1_png() {
    let frame = MockCapture.capture_frame(None).await.unwrap();
    assert_eq!((frame.width, frame.height), (1, 1));
    // PNG magic bytes — the canned 1x1 white PNG.
    assert_eq!(
        &frame.png[..8],
        &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
    );
    assert!(frame.png.len() > 8);
}

#[tokio::test]
async fn mock_capture_frame_ignores_region() {
    let region = Rect {
        x: 5,
        y: 7,
        w: 40,
        h: 30,
    };
    let frame = MockCapture.capture_frame(Some(region)).await.unwrap();
    assert_eq!((frame.width, frame.height), (1, 1));
}

#[tokio::test]
async fn mock_capture_cursor_position_is_origin() {
    assert_eq!(MockCapture.cursor_position().await.unwrap(), (0, 0));
}

#[tokio::test]
async fn mock_capture_screen_info_is_single_mock_monitor() {
    let info = MockCapture.screen_info().await.unwrap();
    assert_eq!(
        info,
        json!({"monitors":[{"name":"mock","width":1920,"height":1080}]})
    );
}

// ---- MockInput -------------------------------------------------------------

#[tokio::test]
async fn mock_input_all_ops_ok() {
    MockInput.mouse_move(10, -20).await.unwrap();
    MockInput.mouse_click(1, 2, "left").await.unwrap();
    MockInput.mouse_button("right", true).await.unwrap();
    MockInput.scroll(1.5, -2.5).await.unwrap();
    MockInput.key_event("Return", true).await.unwrap();
    MockInput.type_text("hello").await.unwrap();
    assert_eq!(MockInput.cursor_position().await.unwrap(), (0, 0));
}

// ---- MockUiAutomation -------------------------------------------------------

#[tokio::test]
async fn mock_ui_automation_root_json() {
    let root: Value = MockUiAutomation.get_root_json(3).await.unwrap();
    assert_eq!(root, json!({"role":"desktop","children":[]}));
}

#[tokio::test]
async fn mock_ui_automation_focused_json() {
    let focused = MockUiAutomation.get_focused_json().await.unwrap();
    assert_eq!(focused, json!({"role":"application","name":"mock"}));
}

#[tokio::test]
async fn mock_ui_automation_find_element_returns_none() {
    assert_eq!(
        MockUiAutomation.find_element("anything").await.unwrap(),
        None
    );
}

#[tokio::test]
async fn mock_ui_automation_invoke_returns_false() {
    assert!(!MockUiAutomation.invoke_element("anything").await.unwrap());
}

// ---- MockWindow -------------------------------------------------------------

#[tokio::test]
async fn mock_window_list_is_single_mock_window() {
    let windows = MockWindow.list_windows().await.unwrap();
    assert_eq!(windows.len(), 1);
    let w = &windows[0];
    assert_eq!(w.id, "0x0");
    assert_eq!(w.title, "mock-window");
    assert_eq!(w.class, "mock");
    assert_eq!(w.workspace, 1);
    assert_eq!(
        w.rect,
        Rect {
            x: 0,
            y: 0,
            w: 800,
            h: 600
        }
    );
    assert!(w.focused);
}

#[tokio::test]
async fn mock_window_active_is_first_listed() {
    let active = MockWindow.active_window().await.unwrap().unwrap();
    assert_eq!(active.id, "0x0");
    assert!(active.focused);
}

#[tokio::test]
async fn mock_window_dispatch_is_noop_ok() {
    MockWindow
        .dispatch("focus", "0x0", &json!({}))
        .await
        .unwrap();
}

// ---- MockVision -------------------------------------------------------------

#[tokio::test]
async fn mock_vision_returns_empty_detections() {
    let frame = Frame {
        png: vec![0x89, 0x50, 0x4E, 0x47],
        width: 1,
        height: 1,
    };
    assert!(MockVision.recognize_text(&frame).await.unwrap().is_empty());
    assert!(
        MockVision
            .find_icon(&frame, "hamburger menu")
            .await
            .unwrap()
            .is_empty()
    );
}

// ---- MockBrowser ------------------------------------------------------------

#[tokio::test]
async fn mock_browser_query_returns_no_matches() {
    assert_eq!(
        MockBrowser.query_selector("button.submit").await.unwrap(),
        json!({"matches":[]})
    );
    MockBrowser.ensure_ready().await.unwrap();
}
