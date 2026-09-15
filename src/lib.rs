//! ultranix-mcp — Rust MCP server for Linux desktop automation.
//! Wayland/Hyprland-first, with wlroots → uinput → portal → X11 fallbacks.

pub mod error;
pub mod providers;
pub mod server;
pub mod tools;
pub mod traits;
