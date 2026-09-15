//! AT-SPI2 backend for [`UIAutomationProvider`] — ADR 0003.
//!
//! Connects to the session accessibility bus (`org.a11y.Bus` → registry
//! daemon `org.a11y.atspi.Registry`) via the pure-Rust `atspi` crate
//! (zbus-5 based). The desktop root's children are the running
//! applications; each application root's children are its top-level
//! windows.
//!
//! ## Query syntax (`find_element` / `invoke_element`)
//!
//! - `Save` — bare text: case-insensitive substring over accessible
//!   `name`, `description`, and role name (per TOOLS.md).
//! - `role:push-button` — role match only. Comparison is normalized
//!   (case + separators stripped), so `role:button`, `role:PushButton`
//!   and `role:push button` all match.
//! - `name:Save` / `desc:…` / `description:…` — single-field matches.
//! - `path:/0/2` — child-index path from the desktop root
//!   (`/0` = first application, `/0/2` = its third child).
//! - `path:/org/a11y/atspi/accessible/N` (or any other `/…` value) —
//!   exact/suffix match on the element's D-Bus object path.
//!
//! ## Focus
//!
//! `get_focused_json` does **not** register for `Focus` events; it scans
//! the live tree for the element carrying [`State::Focused`], preferring
//! the application that owns the [`State::Active`] window and falling
//! back to a bounded whole-desktop scan. Stateless, works without event
//! registration; bounded by [`MAX_SEARCH_NODES`].
//!
//! ## Safety
//!
//! `invoke_element` issues a real `org.a11y.atspi.Action::DoAction` call —
//! physical-input-equivalent (TOOLS.md / THREAT_MODEL.md R-13). Tests must
//! never exercise it against the live bus; the code path is covered only
//! through its pure query-parsing half.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use atspi::proxy::accessible::AccessibleProxy;
use atspi::proxy::action::ActionProxy;
use atspi::proxy::application::ApplicationProxy;
use atspi::proxy::component::ComponentProxy;
use atspi::zbus::{self, names::BusName, proxy::CacheProperties};
use atspi::{AccessibilityConnection, CoordType, ObjectRefOwned, Role, State};
use futures_util::future::join_all;
use serde_json::{Map, Value, json};

use crate::traits::{ElementMatch, Rect, UIAutomationProvider};

/// Hard cap on nodes serialized by `get_root_json` (TOOLS.md contract:
/// trees over the cap set `"truncated": true` on the root).
const MAX_TREE_NODES: usize = 5_000;
/// Hard cap on nodes visited by `find_element` / `invoke_element` /
/// `get_focused_json` scans — keeps a wedged or enormous tree from
/// blowing the latency budget.
const MAX_SEARCH_NODES: usize = 16_384;
/// Startup probe budget: a session bus that can't answer within this
/// window is treated as absent rather than blocking provider detection.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Per-call D-Bus budget for AT-SPI interactions — a wedged registry or
/// application must not hang a tool call. Callers degrade exactly like a
/// failed call (`None`/`Err`/defaulted field), so a timeout is just one
/// more failure shape.
const DBUS_TIMEOUT: Duration = Duration::from_secs(5);

/// Run a D-Bus future under [`DBUS_TIMEOUT`]; elapsed surfaces as an
/// error. Covers `zbus::Error`- and `AtspiError`-returning calls alike.
async fn dbus<F, T, E>(fut: F) -> Result<T>
where
    F: Future<Output = std::result::Result<T, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    match tokio::time::timeout(DBUS_TIMEOUT, fut).await {
        Err(_) => Err(anyhow::anyhow!(
            "atspi call timed out after {DBUS_TIMEOUT:?}"
        )),
        Ok(Err(e)) => Err(anyhow::Error::new(e)),
        Ok(Ok(v)) => Ok(v),
    }
}

/// `UIAutomationProvider` over AT-SPI2.
///
/// The `zbus::Connection` inside `AccessibilityConnection` binds to the
/// tokio runtime that was current when it was built — so it must be
/// created lazily on the server's runtime, not inside `new()`'s private
/// probe thread (a connection whose runtime has exited answers no
/// calls). `new()` therefore only *probes* (its temporary connection is
/// dropped); the real connection is established on first use.
pub struct AtspiUi {
    conn: tokio::sync::OnceCell<AccessibilityConnection>,
}

/// Parsed `find_element`/`invoke_element` query — see module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Query {
    /// Bare text: case-insensitive substring over name, description, role.
    Any(String),
    /// `role:<role>` — normalized substring over the kebab-case role name.
    Role(String),
    /// `name:<text>` — case-insensitive substring over the accessible name.
    Name(String),
    /// `desc:<text>` / `description:<text>` — substring over description.
    Description(String),
    /// `path:/i/j/…` — child indices below the desktop root.
    IndexPath(Vec<i32>),
    /// `path:<non-numeric>` — exact/suffix match on the D-Bus object path.
    ObjectPath(String),
}

/// Traversal budget shared by every recursive walk.
struct Budget {
    visited: usize,
    limit: usize,
    truncated: bool,
}

impl Budget {
    fn new(limit: usize) -> Self {
        Self {
            visited: 0,
            limit,
            truncated: false,
        }
    }

    /// Account for one more node; `false` once the limit is reached.
    fn take(&mut self) -> bool {
        if self.visited >= self.limit {
            self.truncated = true;
            return false;
        }
        self.visited += 1;
        true
    }
}

/// In-memory mirror of one accessible node. Kept separate from the D-Bus
/// walk so serialization is unit-testable without a live bus.
#[derive(Debug, Clone, Default, PartialEq)]
struct Node {
    name: String,
    /// Kebab-case role name (`"push-button"`, `"frame"`, …).
    role: String,
    description: String,
    states: Vec<String>,
    bounds: Option<Rect>,
    children: Vec<Node>,
    truncated: bool,
}

impl Node {
    /// TOOLS.md `get_ui_tree` shape: `name`, `role`, `description` (when
    /// non-empty), `states` (when non-empty), `bounds` (when the element
    /// exposes a Component interface), `children`, `truncated` (cap hit).
    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("name".into(), json!(self.name));
        m.insert("role".into(), json!(self.role));
        if !self.description.is_empty() {
            m.insert("description".into(), json!(self.description));
        }
        if !self.states.is_empty() {
            m.insert("states".into(), json!(self.states));
        }
        if let Some(b) = self.bounds {
            m.insert("bounds".into(), bounds_json(b));
        }
        if self.truncated {
            m.insert("truncated".into(), json!(true));
        }
        m.insert(
            "children".into(),
            Value::Array(self.children.iter().map(Node::to_json).collect()),
        );
        Value::Object(m)
    }
}

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

fn bounds_json(b: Rect) -> Value {
    json!({"x": b.x, "y": b.y, "w": b.w, "h": b.h})
}

fn center_json(b: Rect) -> Value {
    json!({"x": b.x + b.w / 2, "y": b.y + b.h / 2})
}

/// `Role::name()` is space-separated (`"push button"`); the tool contract
/// uses kebab-case (`"push-button"`).
fn role_kebab(role: Role) -> String {
    role.name().replace(' ', "-")
}

/// `State` serializes kebab-case via serde — reuse that for state names.
fn state_name(state: State) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{state:?}").to_lowercase())
}

/// Lowercase alnum-only — forgiving comparison for roles (`push-button`
/// ≡ `push button` ≡ `PushButton`).
fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    !needle.is_empty() && haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Parse a `find_element`/`invoke_element` query string.
fn parse_query(raw: &str) -> Result<Query> {
    let q = raw.trim();
    ensure!(!q.is_empty(), "element query must not be empty");

    if let Some((tag, rest)) = q.split_once(':') {
        let value = rest.trim();
        match tag.to_ascii_lowercase().as_str() {
            "role" => {
                ensure!(!value.is_empty(), "role: query must not be empty");
                return Ok(Query::Role(value.into()));
            }
            "name" => {
                ensure!(!value.is_empty(), "name: query must not be empty");
                return Ok(Query::Name(value.into()));
            }
            "desc" | "description" => {
                ensure!(!value.is_empty(), "desc: query must not be empty");
                return Ok(Query::Description(value.into()));
            }
            "path" => return parse_path_query(value),
            // Unknown prefix — fall through to a plain substring match so
            // text containing ':' (e.g. "Error: disk full") still works.
            _ => {}
        }
    }
    Ok(Query::Any(q.into()))
}

/// `path:` value → child-index navigation or object-path suffix match.
fn parse_path_query(value: &str) -> Result<Query> {
    ensure!(!value.is_empty(), "path: query must not be empty");
    if let Some(rest) = value.strip_prefix('/') {
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.iter().all(|p| p.parse::<i32>().is_ok()) {
            return Ok(Query::IndexPath(
                parts
                    .iter()
                    .map(|p| p.parse().expect("checked above"))
                    .collect(),
            ));
        }
    }
    Ok(Query::ObjectPath(value.into()))
}

/// Does a node with these attributes satisfy `query`? Pure predicate
/// mirroring `AtspiUi::node_matches` — exercised by the unit tests so the
/// matching contract is verified without a live bus.
#[cfg(test)]
fn query_matches(query: &Query, name: &str, description: &str, role: &str) -> bool {
    match query {
        Query::Any(v) => {
            contains_ci(name, v) || contains_ci(description, v) || norm(role).contains(&norm(v))
        }
        Query::Role(v) => norm(role).contains(&norm(v)),
        Query::Name(v) => contains_ci(name, v),
        Query::Description(v) => contains_ci(description, v),
        Query::ObjectPath(_) | Query::IndexPath(_) => false,
    }
}

/// Resolve the requested `action` name to a `DoAction` index over the
/// action names an element advertises. Activation verbs resolve against
/// common AT-SPI action names, falling back to index 0 (by convention
/// the default action). Pure — exercised by the unit tests so the
/// matching contract is verified without a live bus.
fn resolve_action_index<'a>(names: impl Iterator<Item = &'a str>, action: &str) -> Option<i32> {
    let names: Vec<&str> = names.collect();
    let wanted = action.trim().to_ascii_lowercase();
    // Activation verbs resolve against common AT-SPI action names,
    // falling back to the conventional default action (index 0).
    let activation = matches!(
        wanted.as_str(),
        "press" | "activate" | "click" | "default" | ""
    );
    let aliases: &[&str] = if activation {
        &["press", "activate", "click", "select"]
    } else {
        &[]
    };
    names
        .iter()
        .position(|a| a.eq_ignore_ascii_case(&wanted))
        .or_else(|| {
            names
                .iter()
                .position(|a| aliases.iter().any(|al| a.eq_ignore_ascii_case(al)))
        })
        .or_else(|| activation.then_some(0))
        .map(|i| i as i32)
}

/// Object-path match for `path:` queries: exact, or path-suffix so
/// `path:/42` matches `/org/a11y/atspi/accessible/42`.
fn object_path_matches(object_path: &str, value: &str) -> bool {
    let value = value.trim_end_matches('/');
    if value.is_empty() {
        return false;
    }
    if object_path == value || object_path.ends_with(value) {
        return true;
    }
    // Convenience: a bare id like "42" matches "/…/accessible/42".
    !value.starts_with('/') && object_path.ends_with(&format!("/{value}"))
}

impl AtspiUi {
    /// Runtime availability check per the `pub fn new() -> Option<Self>`
    /// provider contract: `Some` only when the session bus is reachable,
    /// `org.a11y.Bus` is owned, and the registry daemon answers.
    ///
    /// The atspi API is async but the provider contract is sync, so the
    /// probe runs on a private thread with a throwaway current-thread
    /// runtime — correct whether or not the caller is inside tokio.
    pub fn new() -> Option<Self> {
        std::thread::spawn(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok()?;
            rt.block_on(async move {
                tokio::time::timeout(PROBE_TIMEOUT, Self::probe())
                    .await
                    .ok()
                    .flatten()
            })
        })
        .join()
        .ok()
        .flatten()
        .map(|()| Self {
            conn: tokio::sync::OnceCell::new(),
        })
    }

    /// Async half of [`Self::new`]: session bus → `org.a11y.Bus` owner →
    /// a11y-bus connection → registry root answers `child_count`. The
    /// whole probe additionally sits under [`PROBE_TIMEOUT`]; each call
    /// is still wrapped so a mid-probe wedge cannot eat the whole budget.
    async fn probe() -> Option<()> {
        let session = dbus(zbus::Connection::session()).await.ok()?;
        let reply = dbus(session.call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "NameHasOwner",
            &"org.a11y.Bus",
        ))
        .await
        .ok()?;
        if !reply.body().deserialize::<bool>().ok()? {
            return None;
        }

        // Resolves the a11y bus address via org.a11y.Bus and connects.
        let conn = dbus(AccessibilityConnection::new()).await.ok()?;
        let root = dbus(conn.root_accessible_on_registry()).await.ok()?;
        dbus(root.child_count()).await.ok()?;
        Some(())
    }

    /// The a11y-bus connection, established on first use on the ambient
    /// tokio runtime (see struct docs — it must outlive the probe
    /// thread's runtime).
    async fn conn(&self) -> Result<&AccessibilityConnection> {
        self.conn
            .get_or_try_init(|| async {
                dbus(AccessibilityConnection::new())
                    .await
                    .context("atspi bus connect failed")
            })
            .await
    }

    /// Shorthand for the inner `zbus::Connection`.
    async fn bus(&self) -> Result<&zbus::Connection> {
        Ok(self.conn().await?.connection())
    }

    // ---- proxy plumbing -------------------------------------------------

    /// `ObjectRefOwned` for an accessible we already hold a proxy for
    /// (re-derives bus name + object path from the inner zbus proxy).
    fn object_ref(acc: &AccessibleProxy<'_>) -> Option<ObjectRefOwned> {
        ObjectRefOwned::try_from(acc).ok()
    }

    /// `Accessible` proxy for `obj`. Built from owned bus name + object
    /// path so the result is `'static` (unlike
    /// `ObjectRefExt::as_accessible_proxy`, which borrows the ref).
    async fn accessible_at(&self, obj: &ObjectRefOwned) -> Option<AccessibleProxy<'static>> {
        let name: BusName = obj.name()?.clone().into();
        dbus(
            AccessibleProxy::builder(self.bus().await.ok()?)
                .destination(name)
                .ok()?
                .path(obj.path().clone())
                .ok()?
                .cache_properties(CacheProperties::No)
                .build(),
        )
        .await
        .ok()
    }

    /// Build a `ComponentProxy` for the same object — no interface check;
    /// callers treat method errors as "no component data".
    async fn component_at(&self, obj: &ObjectRefOwned) -> Option<ComponentProxy<'_>> {
        let name: BusName = obj.name()?.clone().into();
        dbus(
            ComponentProxy::builder(self.bus().await.ok()?)
                .destination(name)
                .ok()?
                .path(obj.path().to_owned())
                .ok()?
                .cache_properties(CacheProperties::No)
                .build(),
        )
        .await
        .ok()
    }

    async fn action_at(&self, obj: &ObjectRefOwned) -> Option<ActionProxy<'_>> {
        let name: BusName = obj.name()?.clone().into();
        dbus(
            ActionProxy::builder(self.bus().await.ok()?)
                .destination(name)
                .ok()?
                .path(obj.path().to_owned())
                .ok()?
                .cache_properties(CacheProperties::No)
                .build(),
        )
        .await
        .ok()
    }

    async fn application_at(&self, obj: &ObjectRefOwned) -> Option<ApplicationProxy<'_>> {
        let name: BusName = obj.name()?.clone().into();
        dbus(
            ApplicationProxy::builder(self.bus().await.ok()?)
                .destination(name)
                .ok()?
                .path(obj.path().to_owned())
                .ok()?
                .cache_properties(CacheProperties::No)
                .build(),
        )
        .await
        .ok()
    }

    /// Screen-space extents of an element, `None` when it exposes no
    /// Component interface (or the call otherwise fails).
    async fn extents_at(&self, obj: &ObjectRefOwned) -> Option<Rect> {
        let comp = self.component_at(obj).await?;
        let (x, y, w, h) = dbus(comp.get_extents(CoordType::Screen)).await.ok()?;
        Some(Rect { x, y, w, h })
    }

    /// Fetch the serializable fields of `acc` (children added by the
    /// walk). The five property calls run concurrently — each is an
    /// independent [`DBUS_TIMEOUT`]-wrapped D-Bus call.
    async fn node_meta(&self, acc: &AccessibleProxy<'_>) -> Node {
        let obj = Self::object_ref(acc);
        let bounds_fut = async {
            match obj {
                Some(ref o) => self.extents_at(o).await,
                None => None,
            }
        };
        let (bounds, name, role, description, states) = tokio::join!(
            bounds_fut,
            dbus(acc.name()),
            dbus(acc.get_role()),
            dbus(acc.description()),
            dbus(acc.get_state()),
        );
        Node {
            name: name.unwrap_or_default(),
            role: role.map(role_kebab).unwrap_or_else(|_| "unknown".into()),
            description: description.unwrap_or_default(),
            states: states
                .map(|ss| ss.iter().map(state_name).collect())
                .unwrap_or_default(),
            bounds,
            children: Vec::new(),
            truncated: false,
        }
    }

    // ---- tree walk ------------------------------------------------------

    /// Recursive serializer, `depth_left` levels of children below `acc`.
    /// Returns `None` once the node budget is exhausted.
    fn build_node<'a>(
        &'a self,
        acc: &'a AccessibleProxy<'a>,
        depth_left: u32,
        budget: &'a mut Budget,
    ) -> BoxFut<'a, Option<Node>> {
        Box::pin(async move {
            if !budget.take() {
                return None;
            }
            let mut node = self.node_meta(acc).await;

            if depth_left > 0
                && let Ok(refs) = dbus(acc.get_children()).await
            {
                // Child proxy builds dominate the walk — run them in
                // parallel (null refs end the sibling list, as before).
                // The recursion itself stays serial so budget
                // accounting and child order are unchanged.
                let live: Vec<&ObjectRefOwned> = refs.iter().take_while(|r| !r.is_null()).collect();
                let children = join_all(live.iter().map(|r| self.accessible_at(r))).await;
                for child in children {
                    if budget.visited >= budget.limit {
                        budget.truncated = true;
                        break;
                    }
                    let Some(child) = child else { continue };
                    match self.build_node(&child, depth_left - 1, budget).await {
                        Some(n) => node.children.push(n),
                        None => break,
                    }
                }
            }
            node.truncated = budget.truncated;
            Some(node)
        })
    }

    // ---- element search -------------------------------------------------

    /// Children of `acc` as accessible proxies (dead/skipped refs
    /// dropped). Proxy builds run in parallel; result order matches the
    /// `get_children` order.
    async fn children_of(&self, acc: &AccessibleProxy<'_>) -> Vec<AccessibleProxy<'_>> {
        let Ok(refs) = dbus(acc.get_children()).await else {
            return Vec::new();
        };
        join_all(
            refs.iter()
                .filter(|r| !r.is_null())
                .map(|r| self.accessible_at(r)),
        )
        .await
        .into_iter()
        .flatten()
        .collect()
    }

    /// Application refs from the desktop root, ordered so the app owning
    /// the [`State::Active`] window is searched first (TOOLS.md searches
    /// "the focused application's tree"; remaining apps are the fallback).
    async fn ordered_apps(&self) -> Result<Vec<ObjectRefOwned>> {
        let root = dbus(self.conn().await?.root_accessible_on_registry())
            .await
            .context("atspi registry root unreachable")?;
        let mut apps = dbus(root.get_children()).await.unwrap_or_default();
        apps.retain(|r| !r.is_null());

        // Find the app with an Active-state top-level window. The
        // per-app scans run in parallel — each reports whether one of
        // its windows carries `State::Active`; the first match in root
        // order still wins.
        let active = join_all(apps.iter().map(|r| async move {
            let Some(app) = self.accessible_at(r).await else {
                return false;
            };
            let windows = self.children_of(&app).await;
            join_all(windows.iter().map(|w| dbus(w.get_state())))
                .await
                .into_iter()
                .any(|s| s.map(|ss| ss.contains(State::Active)).unwrap_or(false))
        }))
        .await;
        if let Some(i) = active.iter().position(|a| *a) {
            apps.swap(0, i);
        }
        Ok(apps)
    }

    /// Does `acc` satisfy `query`? Fetches only the fields the query kind
    /// needs (a `role:` query costs one D-Bus call, not three).
    async fn node_matches(&self, acc: &AccessibleProxy<'_>, query: &Query) -> bool {
        match query {
            Query::Role(v) => dbus(acc.get_role())
                .await
                .map(|r| norm(&role_kebab(r)).contains(&norm(v)))
                .unwrap_or(false),
            Query::Name(v) => dbus(acc.name())
                .await
                .map(|n| contains_ci(&n, v))
                .unwrap_or(false),
            Query::Description(v) => dbus(acc.description())
                .await
                .map(|d| contains_ci(&d, v))
                .unwrap_or(false),
            Query::ObjectPath(v) => object_path_matches(acc.inner().path().as_str(), v),
            Query::IndexPath(_) => false,
            Query::Any(v) => {
                let name = dbus(acc.name()).await.unwrap_or_default();
                if contains_ci(&name, v) {
                    return true;
                }
                let desc = dbus(acc.description()).await.unwrap_or_default();
                if contains_ci(&desc, v) {
                    return true;
                }
                dbus(acc.get_role())
                    .await
                    .map(|r| norm(&role_kebab(r)).contains(&norm(v)))
                    .unwrap_or(false)
            }
        }
    }

    /// Preorder DFS over `acc`'s subtree; returns the first match's
    /// `ObjectRefOwned` (name + path, enough to rebuild any proxy).
    fn search_node<'a>(
        &'a self,
        acc: &'a AccessibleProxy<'a>,
        query: &'a Query,
        budget: &'a mut Budget,
    ) -> BoxFut<'a, Option<ObjectRefOwned>> {
        Box::pin(async move {
            if !budget.take() {
                return None;
            }
            if self.node_matches(acc, query).await {
                return Self::object_ref(acc);
            }
            for child in self.children_of(acc).await {
                if budget.visited >= budget.limit {
                    break;
                }
                if let Some(hit) = self.search_node(&child, query, budget).await {
                    return Some(hit);
                }
            }
            None
        })
    }

    /// Navigate a `path:/i/j/…` index path from the desktop root.
    /// Out-of-range or dead references resolve to `None` (not found).
    async fn navigate_index_path(&self, indices: &[i32]) -> Result<Option<ObjectRefOwned>> {
        let mut cur = dbus(self.conn().await?.root_accessible_on_registry())
            .await
            .context("atspi registry root unreachable")?;
        for &i in indices {
            let Ok(r) = dbus(cur.get_child_at_index(i)).await else {
                return Ok(None);
            };
            if r.is_null() {
                return Ok(None);
            }
            let Some(next) = self.accessible_at(&r).await else {
                return Ok(None);
            };
            cur = next;
        }
        Ok(Self::object_ref(&cur))
    }

    /// First element matching `query`, searched across applications
    /// (active-window owner first). `None` = not found.
    async fn find_match(&self, query: &Query) -> Result<Option<ObjectRefOwned>> {
        if let Query::IndexPath(indices) = query {
            return self.navigate_index_path(indices).await;
        }

        let mut budget = Budget::new(MAX_SEARCH_NODES);
        for app_ref in self.ordered_apps().await? {
            let Some(app) = self.accessible_at(&app_ref).await else {
                continue;
            };
            if let Some(hit) = self.search_node(&app, query, &mut budget).await {
                return Ok(Some(hit));
            }
        }
        Ok(None)
    }

    /// Multi-match variant of [`Self::search_node`]: preorder DFS
    /// collecting up to `limit` matches (with metadata) into `out`.
    fn search_node_all<'a>(
        &'a self,
        acc: &'a AccessibleProxy<'a>,
        query: &'a Query,
        budget: &'a mut Budget,
        out: &'a mut Vec<Node>,
        limit: usize,
    ) -> BoxFut<'a, ()> {
        Box::pin(async move {
            if out.len() >= limit || !budget.take() {
                return;
            }
            if self.node_matches(acc, query).await {
                out.push(self.node_meta(acc).await);
            }
            if out.len() >= limit {
                return;
            }
            for child in self.children_of(acc).await {
                if out.len() >= limit || budget.visited >= budget.limit {
                    break;
                }
                self.search_node_all(&child, query, budget, out, limit)
                    .await;
            }
        })
    }

    /// All matches for `query` across applications (active-window owner
    /// first), capped at `limit`, in preorder tree order — the harvest
    /// behind [`UIAutomationProvider::find_elements`].
    async fn find_matches(&self, query: &Query, limit: usize) -> Result<Vec<Node>> {
        if let Query::IndexPath(indices) = query {
            let Some(obj) = self.navigate_index_path(indices).await? else {
                return Ok(Vec::new());
            };
            let Some(acc) = self.accessible_at(&obj).await else {
                return Ok(Vec::new());
            };
            return Ok(vec![self.node_meta(&acc).await]);
        }

        let mut budget = Budget::new(MAX_SEARCH_NODES);
        let mut out = Vec::new();
        for app_ref in self.ordered_apps().await? {
            let Some(app) = self.accessible_at(&app_ref).await else {
                continue;
            };
            self.search_node_all(&app, query, &mut budget, &mut out, limit)
                .await;
            if out.len() >= limit || budget.visited >= budget.limit {
                break;
            }
        }
        Ok(out)
    }

    // ---- focus ----------------------------------------------------------

    /// DFS for a node carrying `state` within `acc`'s subtree.
    fn find_state_in<'a>(
        &'a self,
        acc: &'a AccessibleProxy<'a>,
        state: State,
        budget: &'a mut Budget,
    ) -> BoxFut<'a, Option<ObjectRefOwned>> {
        Box::pin(async move {
            if !budget.take() {
                return None;
            }
            if dbus(acc.get_state())
                .await
                .map(|s| s.contains(state))
                .unwrap_or(false)
            {
                return Self::object_ref(acc);
            }
            for child in self.children_of(acc).await {
                if budget.visited >= budget.limit {
                    break;
                }
                if let Some(hit) = self.find_state_in(&child, state, budget).await {
                    return Some(hit);
                }
            }
            None
        })
    }

    /// Locate the element holding keyboard focus: scan the active-window
    /// app first (usual case), then the remaining apps.
    async fn find_focused(&self) -> Result<Option<ObjectRefOwned>> {
        let apps = self.ordered_apps().await?;
        let mut budget = Budget::new(MAX_SEARCH_NODES);
        for app_ref in &apps {
            let Some(app) = self.accessible_at(app_ref).await else {
                continue;
            };
            if let Some(hit) = self.find_state_in(&app, State::Focused, &mut budget).await {
                return Ok(Some(hit));
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl UIAutomationProvider for AtspiUi {
    /// Serialized a11y tree from the desktop root, `depth` levels of
    /// children deep. Node cap per TOOLS.md; sets `"truncated": true`
    /// when the cap is hit.
    async fn get_root_json(&self, depth: u32) -> Result<Value> {
        let root = dbus(self.conn().await?.root_accessible_on_registry())
            .await
            .context("atspi registry root unreachable")?;
        let mut budget = Budget::new(MAX_TREE_NODES);
        let node = self
            .build_node(&root, depth, &mut budget)
            .await
            .context("a11y tree exceeded node budget")?;
        Ok(node.to_json())
    }

    /// TOOLS.md `get_focused_element` shape: `{found, name, role, states,
    /// bounds, center, application, pid}` or `{found: false}`.
    async fn get_focused_json(&self) -> Result<Value> {
        let Some(obj) = self.find_focused().await? else {
            return Ok(json!({"found": false}));
        };
        let acc = self
            .accessible_at(&obj)
            .await
            .context("focused element vanished")?;
        let node = self.node_meta(&acc).await;

        let mut m = Map::new();
        m.insert("found".into(), json!(true));
        m.insert("name".into(), json!(node.name));
        m.insert("role".into(), json!(node.role));
        if !node.states.is_empty() {
            m.insert("states".into(), json!(node.states));
        }
        if let Some(b) = node.bounds {
            m.insert("bounds".into(), bounds_json(b));
            m.insert("center".into(), center_json(b));
        }

        // Owning application: name + pid (Application::Id, best-effort —
        // toolkits may leave it unset).
        if let Ok(app_ref) = dbus(acc.get_application()).await
            && !app_ref.is_null()
            && let Some(app) = self.accessible_at(&app_ref).await
        {
            if let Ok(n) = dbus(app.name()).await {
                m.insert("application".into(), json!(n));
            }
            if let Some(ap) = self.application_at(&app_ref).await
                && let Ok(id) = dbus(ap.id()).await
            {
                m.insert("pid".into(), json!(id));
            }
        }
        Ok(Value::Object(m))
    }

    /// First match's screen-space bounding rect; `None` when absent
    /// ("not found" is data, not a fault — TOOLS.md conventions).
    async fn find_element(&self, query: &str) -> Result<Option<Rect>> {
        let query = parse_query(query)?;
        let Some(obj) = self.find_match(&query).await? else {
            return Ok(None);
        };
        Ok(self.extents_at(&obj).await)
    }

    /// Real multi-match: every element satisfying `query`, up to
    /// `limit`, in preorder tree order with name/role/states harvested
    /// via [`Self::node_meta`]. Elements that expose no `Component`
    /// interface report a zeroed `bounds` — they still matched.
    async fn find_elements(&self, query: &str, limit: usize) -> Result<Vec<ElementMatch>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let query = parse_query(query)?;
        let nodes = self.find_matches(&query, limit).await?;
        Ok(nodes
            .into_iter()
            .map(|n| ElementMatch {
                name: n.name,
                role: n.role,
                states: n.states,
                bounds: n.bounds.unwrap_or(Rect {
                    x: 0,
                    y: 0,
                    w: 0,
                    h: 0,
                }),
            })
            .collect())
    }

    /// Find the match, then invoke its default AT-SPI Action
    /// (`do_action(0)` — by convention the first action is the default).
    /// `Ok(false)` when nothing matched or the element exposes no
    /// actions; D-Bus failures surface as errors.
    async fn invoke_element(&self, query: &str) -> Result<bool> {
        self.invoke_element_action(query, "press").await
    }

    /// Named-action invoke: enumerate `GetActions`, match `action`
    /// against action names (case-insensitive, with a small alias set
    /// for activation verbs), and `DoAction` the resolved index.
    /// `Ok(false)` when nothing matched or no action by that name.
    async fn invoke_element_action(&self, query: &str, action: &str) -> Result<bool> {
        let query = parse_query(query)?;
        let Some(obj) = self.find_match(&query).await? else {
            return Ok(false);
        };
        let Some(proxy) = self.action_at(&obj).await else {
            return Ok(false);
        };
        let actions = dbus(proxy.get_actions()).await.unwrap_or_default();
        if actions.is_empty() {
            return Ok(false);
        }
        let Some(i) = resolve_action_index(actions.iter().map(|a| a.name.as_str()), action) else {
            return Ok(false);
        };
        dbus(proxy.do_action(i))
            .await
            .context("atspi do_action failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- query parsing --------------------------------------------------

    #[test]
    fn parse_bare_substring() {
        assert_eq!(parse_query("Save").unwrap(), Query::Any("Save".into()));
        // ':' without a known prefix stays a plain substring.
        assert_eq!(
            parse_query("Error: disk full").unwrap(),
            Query::Any("Error: disk full".into())
        );
    }

    #[test]
    fn parse_prefixed_queries() {
        assert_eq!(
            parse_query("role:button").unwrap(),
            Query::Role("button".into())
        );
        assert_eq!(
            parse_query("name:Save").unwrap(),
            Query::Name("Save".into())
        );
        assert_eq!(
            parse_query("desc:hints").unwrap(),
            Query::Description("hints".into())
        );
        assert_eq!(
            parse_query("description:tooltip").unwrap(),
            Query::Description("tooltip".into())
        );
        // Prefix tag is case-insensitive.
        assert_eq!(
            parse_query("Role:Frame").unwrap(),
            Query::Role("Frame".into())
        );
    }

    #[test]
    fn parse_path_queries() {
        assert_eq!(
            parse_query("path:/0/2/1").unwrap(),
            Query::IndexPath(vec![0, 2, 1])
        );
        assert_eq!(
            parse_query("path:/org/a11y/atspi/accessible/42").unwrap(),
            Query::ObjectPath("/org/a11y/atspi/accessible/42".into())
        );
        assert_eq!(
            parse_query("path:42").unwrap(),
            Query::ObjectPath("42".into())
        );
        // "/" alone is not a valid index path → object path.
        assert_eq!(
            parse_query("path:/").unwrap(),
            Query::ObjectPath("/".into())
        );
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(parse_query("").is_err());
        assert!(parse_query("   ").is_err());
        assert!(parse_query("role:").is_err());
        assert!(parse_query("name:").is_err());
        assert!(parse_query("path:").is_err());
    }

    // ---- matching -------------------------------------------------------

    #[test]
    fn any_query_matches_name_desc_or_role() {
        let q = Query::Any("save".into());
        assert!(query_matches(&q, "Save As", "", "push-button"));
        assert!(query_matches(&q, "", "saves the file", "push-button"));
        // Role names normalize across separators/case.
        assert!(query_matches(
            &Query::Any("pushbutton".into()),
            "",
            "",
            "push-button"
        ));
        assert!(!query_matches(&q, "Cancel", "", "push-button"));
    }

    #[test]
    fn role_query_is_normalized_substring() {
        assert!(query_matches(
            &Query::Role("button".into()),
            "",
            "",
            "push-button"
        ));
        assert!(query_matches(
            &Query::Role("PushButton".into()),
            "",
            "",
            "push-button"
        ));
        assert!(!query_matches(
            &Query::Role("button".into()),
            "",
            "",
            "frame"
        ));
    }

    #[test]
    fn name_and_desc_queries() {
        assert!(query_matches(
            &Query::Name("SAVE".into()),
            "Save As",
            "",
            ""
        ));
        assert!(!query_matches(
            &Query::Name("SAVE".into()),
            "Cancel",
            "save it",
            ""
        ));
        assert!(query_matches(
            &Query::Description("file".into()),
            "",
            "the file",
            ""
        ));
    }

    #[test]
    fn object_path_matching() {
        let p = "/org/a11y/atspi/accessible/42";
        assert!(object_path_matches(p, p));
        assert!(object_path_matches(p, "/42"));
        assert!(object_path_matches(p, "42"));
        assert!(object_path_matches(p, "accessible/42"));
        assert!(!object_path_matches(p, "/43"));
        assert!(!object_path_matches(p, "4"));
        assert!(!object_path_matches("/org/a11y/atspi/accessible/4", "/42"));
    }

    // ---- serialization --------------------------------------------------

    #[test]
    fn node_to_json_minimal() {
        let node = Node {
            name: "New Tab".into(),
            role: "frame".into(),
            ..Node::default()
        };
        let v = node.to_json();
        assert_eq!(v["name"], "New Tab");
        assert_eq!(v["role"], "frame");
        assert_eq!(v["children"], json!([]));
        // Absent fields stay absent (TOOLS.md: states when non-default).
        assert!(v.get("states").is_none());
        assert!(v.get("description").is_none());
        assert!(v.get("bounds").is_none());
        assert!(v.get("truncated").is_none());
    }

    #[test]
    fn node_to_json_full() {
        let node = Node {
            name: "Sign in".into(),
            role: "push-button".into(),
            description: "Opens the login dialog".into(),
            states: vec!["sensitive".into(), "visible".into()],
            bounds: Some(Rect {
                x: 980,
                y: 64,
                w: 96,
                h: 36,
            }),
            children: vec![Node {
                name: "icon".into(),
                role: "image".into(),
                ..Node::default()
            }],
            truncated: true,
        };
        let v = node.to_json();
        assert_eq!(v["description"], "Opens the login dialog");
        assert_eq!(v["states"], json!(["sensitive", "visible"]));
        assert_eq!(v["bounds"], json!({"x": 980, "y": 64, "w": 96, "h": 36}));
        assert_eq!(v["truncated"], true);
        assert_eq!(v["children"][0]["role"], "image");
    }

    #[test]
    fn role_and_state_names() {
        assert_eq!(role_kebab(Role::Button), "button");
        assert_eq!(role_kebab(Role::PushButtonMenu), "push-button-menu");
        assert_eq!(role_kebab(Role::Frame), "frame");
        assert_eq!(state_name(State::Focused), "focused");
        assert_eq!(state_name(State::Sensitive), "sensitive");
    }

    #[test]
    fn budget_caps_and_flags_truncated() {
        let mut b = Budget::new(2);
        assert!(b.take());
        assert!(b.take());
        assert!(!b.take());
        assert!(b.truncated);
        assert_eq!(b.visited, 2);
        // A zero-limit budget truncates on the very first node.
        let mut b = Budget::new(0);
        assert!(!b.take());
        assert!(b.truncated);
        assert_eq!(b.visited, 0);
    }

    // ---- query parsing edge cases -------------------------------------

    #[test]
    fn parse_path_query_edge_cases() {
        // Whitespace inside the `path:` value is trimmed by parse_query.
        assert_eq!(
            parse_query("path: /0/1").unwrap(),
            Query::IndexPath(vec![0, 1])
        );
        // Negative indices parse as an index path (navigation reports
        // out-of-range as not-found at walk time).
        assert_eq!(parse_query("path:/-1").unwrap(), Query::IndexPath(vec![-1]));
        // A trailing-slash segment is not an integer → object path.
        assert_eq!(
            parse_query("path:/0/").unwrap(),
            Query::ObjectPath("/0/".into())
        );
        // Mixed numeric/non-numeric → object path.
        assert_eq!(
            parse_query("path:/0/x").unwrap(),
            Query::ObjectPath("/0/x".into())
        );
        // A path value with no leading slash is an object-path suffix.
        assert_eq!(
            parse_query("path:accessible/7").unwrap(),
            Query::ObjectPath("accessible/7".into())
        );
    }

    #[test]
    fn parse_rejects_more_empties() {
        assert!(parse_query("desc:").is_err());
        assert!(parse_query("description:   ").is_err());
        assert!(parse_query("path:  ").is_err());
    }

    #[test]
    fn object_path_matches_edge_cases() {
        let p = "/org/a11y/atspi/accessible/42";
        // Trailing slashes on the query are ignored.
        assert!(object_path_matches(p, "/42/"));
        // "/" alone carries no signal.
        assert!(!object_path_matches(p, "/"));
        assert!(!object_path_matches(p, ""));
        // Non-"/" values match by plain path suffix — "2" does match
        // ".../42" and even a mid-segment partial like "le/42" (tail of
        // "accessible/42") hits; documented behavior for `path:…` queries.
        assert!(object_path_matches(p, "2"));
        assert!(object_path_matches(p, "le/42"));
        assert!(!object_path_matches(p, "ess/42"));
        // But a "/…" query cannot match mid-segment: "/2" ≠ ".../42".
        assert!(!object_path_matches(p, "/2"));
    }

    // ---- matching: non-node query kinds never hit nodes -----------------

    #[test]
    fn query_matches_rejects_path_kinds() {
        // ObjectPath/IndexPath are resolved by navigation, not per-node
        // attribute checks.
        assert!(!query_matches(
            &Query::ObjectPath("/x".into()),
            "x",
            "x",
            "x"
        ));
        assert!(!query_matches(&Query::IndexPath(vec![0]), "x", "x", "x"));
    }

    #[test]
    fn contains_ci_empty_needle_never_matches() {
        // An empty needle must not degenerate into a match-everything.
        assert!(!contains_ci("anything", ""));
        assert!(contains_ci("Anything", "any"));
    }

    // ---- serialization helpers ----------------------------------------

    #[test]
    fn center_and_bounds_json() {
        let r = Rect {
            x: 10,
            y: 20,
            w: 30,
            h: 40,
        };
        assert_eq!(bounds_json(r), json!({"x": 10, "y": 20, "w": 30, "h": 40}));
        assert_eq!(center_json(r), json!({"x": 25, "y": 40}));
        // Odd sizes truncate toward the top-left half — integer math is
        // deliberate (compositor pixel centers).
        let odd = Rect {
            x: 0,
            y: 0,
            w: 3,
            h: 3,
        };
        assert_eq!(center_json(odd), json!({"x": 1, "y": 1}));
    }

    // ---- action resolution ---------------------------------------------

    #[test]
    fn resolve_action_prefers_exact_name() {
        let names = ["press", "scroll", "show-menu"];
        // Exact (case-insensitive) name wins over the alias/default arms.
        assert_eq!(
            resolve_action_index(names.iter().copied(), "SCROLL"),
            Some(1)
        );
        assert_eq!(
            resolve_action_index(names.iter().copied(), "show-menu"),
            Some(2)
        );
        assert_eq!(
            resolve_action_index(names.iter().copied(), "nonexistent"),
            None
        );
    }

    #[test]
    fn resolve_action_activation_verbs_hit_aliases_and_default() {
        // An element with an oddly-named first action still resolves
        // "press" → index 0 via the conventional default.
        let names = ["frob"];
        assert_eq!(
            resolve_action_index(names.iter().copied(), "press"),
            Some(0)
        );
        assert_eq!(
            resolve_action_index(names.iter().copied(), "click"),
            Some(0)
        );
        assert_eq!(resolve_action_index(names.iter().copied(), ""), Some(0));
        // A non-default alias resolves to its real index.
        let names = ["check", "activate"];
        assert_eq!(
            resolve_action_index(names.iter().copied(), "default"),
            Some(1)
        );
        // Non-activation verbs have no default fallback.
        assert_eq!(resolve_action_index(names.iter().copied(), "toggle"), None);
        // Whitespace around the name is trimmed before matching.
        let names = ["press"];
        assert_eq!(
            resolve_action_index(names.iter().copied(), "  press  "),
            Some(0)
        );
    }

    // ---- live bus (opt-in; read-only; NEVER invoke) ---------------------

    /// Live checks run only with `ULTRANIX_MCP_LIVE_TESTS=1` *and*
    /// `cargo test -- --ignored`. Reads only — `invoke_element` is
    /// deliberately untested against the real bus.
    fn live_provider() -> Option<AtspiUi> {
        if std::env::var("ULTRANIX_MCP_LIVE_TESTS").ok().as_deref() != Some("1") {
            return None;
        }
        AtspiUi::new()
    }

    #[tokio::test]
    #[ignore = "requires a live AT-SPI2 bus; set ULTRANIX_MCP_LIVE_TESTS=1"]
    async fn live_root_tree_reads_apps() {
        let Some(ui) = live_provider() else { return };
        let v = ui.get_root_json(1).await.unwrap();
        assert!(v["role"].is_string());
        assert!(v["children"].is_array());
    }

    #[tokio::test]
    #[ignore = "requires a live AT-SPI2 bus; set ULTRANIX_MCP_LIVE_TESTS=1"]
    async fn live_find_element_does_not_panic() {
        let Some(ui) = live_provider() else { return };
        // "found" depends on the desktop; we only require no error/panic.
        let _ = ui.find_element("role:frame").await.unwrap();
        let _ = ui.find_element("path:/0").await.unwrap();
        assert!(ui.find_element("").await.is_err());
    }

    #[tokio::test]
    #[ignore = "requires a live AT-SPI2 bus; set ULTRANIX_MCP_LIVE_TESTS=1"]
    async fn live_focused_element_is_object() {
        let Some(ui) = live_provider() else { return };
        let v = ui.get_focused_json().await.unwrap();
        assert!(v.is_object());
        if v["found"] == true {
            assert!(v["role"].is_string());
        }
    }
}
