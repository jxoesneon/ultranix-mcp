//! Backend auto-detection — session probing + the provider fallback ladder.
//!
//! [`detect::SessionInfo`] snapshots the environment variables that decide
//! which backends can work (Wayland vs. X11 vs. headless, Hyprland vs.
//! generic wlroots); [`detect::detect_providers`] walks each capability's
//! ordered fallback ladder and registers the first backend that reports
//! itself usable. Slots with no working backend stay `None`, which makes
//! the corresponding tools degrade to `-32010 ProviderUnavailable`.

pub mod detect;

pub use detect::{SessionInfo, SessionType, detect_providers, plan_backends};
