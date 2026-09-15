//! ultranix-mcp — Rust MCP server for Linux desktop automation.
//! Wayland/Hyprland-first, with wlroots → uinput → portal → X11 fallbacks.

pub mod backend;
pub mod error;
pub mod metrics;
pub mod providers;
pub mod security;
pub mod server;
pub mod state;
pub mod tools;
pub mod traits;
