//! `tools/list` surface: exactly the frozen 32 tools, each name present
//! once, correct category-filter subsets, spec-shaped input schemas.

mod common;

use std::collections::BTreeSet;

use common::{ALL_TOOL_NAMES, TOOLS};
use ultranix_mcp::tools::list_tools;

fn names(tools: &[rmcp::model::Tool]) -> Vec<String> {
    tools.iter().map(|t| t.name.to_string()).collect()
}

fn cats(categories: &[&str]) -> Vec<String> {
    categories.iter().map(|s| s.to_string()).collect()
}

#[test]
fn list_all_returns_exactly_32_tools() {
    let tools = list_tools(None);
    assert_eq!(
        tools.len(),
        32,
        "expected exactly 32 tools, got: {:?}",
        names(&tools)
    );
}

#[test]
fn every_frozen_name_present_exactly_once() {
    let tools = list_tools(None);
    let listed: BTreeSet<String> = names(&tools).into_iter().collect();

    // No duplicates — set cardinality equals vector length.
    assert_eq!(
        listed.len(),
        tools.len(),
        "duplicate tool names advertised: {:?}",
        names(&tools)
    );

    // All 32 frozen names are present.
    for name in ALL_TOOL_NAMES {
        assert!(listed.contains(*name), "missing frozen tool {name}");
    }

    // And nothing beyond the frozen surface.
    for tool in &listed {
        assert!(
            ALL_TOOL_NAMES.contains(&tool.as_str()),
            "unexpected tool advertised: {tool}"
        );
    }
}

#[test]
fn every_tool_has_spec_shaped_schema() {
    for tool in list_tools(None) {
        let schema = &*tool.input_schema;
        assert_eq!(
            schema.get("type").and_then(|v| v.as_str()),
            Some("object"),
            "{}: inputSchema.type must be \"object\"",
            tool.name
        );
        assert!(
            schema.get("properties").is_some_and(|p| p.is_object()),
            "{}: inputSchema.properties must be an object",
            tool.name
        );
        // Every schema in docs/TOOLS.md is closed.
        assert_eq!(
            schema.get("additionalProperties").and_then(|v| v.as_bool()),
            Some(false),
            "{}: inputSchema.additionalProperties must be false",
            tool.name
        );
    }
}

#[test]
fn category_filter_mouse_returns_7() {
    let tools = list_tools(Some(&cats(&["mouse"])));
    let got: BTreeSet<String> = names(&tools).into_iter().collect();
    let want: BTreeSet<String> = TOOLS
        .iter()
        .filter(|(_, c)| *c == "mouse")
        .map(|(n, _)| n.to_string())
        .collect();
    assert_eq!(want.len(), 7);
    assert_eq!(got, want);
}

#[test]
fn category_filter_each_category() {
    let expected = [
        ("mouse", 7usize),
        ("keyboard", 2),
        ("vision", 12),
        ("automation", 4),
        ("admin", 7),
    ];
    for (cat, count) in expected {
        let tools = list_tools(Some(&cats(&[cat])));
        assert_eq!(
            tools.len(),
            count,
            "category {cat}: expected {count} tools, got {:?}",
            names(&tools)
        );
        let got: BTreeSet<String> = names(&tools).into_iter().collect();
        let want: BTreeSet<String> = TOOLS
            .iter()
            .filter(|(_, c)| *c == cat)
            .map(|(n, _)| n.to_string())
            .collect();
        assert_eq!(got, want, "category {cat} returned wrong subset");
    }
}

#[test]
fn category_filter_mouse_keyboard_returns_9() {
    let tools = list_tools(Some(&cats(&["mouse", "keyboard"])));
    assert_eq!(tools.len(), 9, "got {:?}", names(&tools));
    let got: BTreeSet<String> = names(&tools).into_iter().collect();
    for name in ["mouse_click", "mouse_drag", "type_text", "key_control"] {
        assert!(got.contains(name), "missing {name}");
    }
    assert!(!got.contains("screenshot"));
}

#[test]
fn category_filter_all_five_returns_32() {
    let tools = list_tools(Some(&cats(&[
        "mouse",
        "keyboard",
        "vision",
        "automation",
        "admin",
    ])));
    assert_eq!(tools.len(), 32, "got {:?}", names(&tools));
}

#[test]
fn category_filter_unknown_returns_empty() {
    // Per spec an unknown category yields no tools — the listing surface
    // shrinks rather than erroring (list_tools has no error channel).
    let tools = list_tools(Some(&cats(&["no_such_category"])));
    assert!(tools.is_empty(), "got {:?}", names(&tools));
}

#[test]
fn category_filter_mixed_known_and_unknown_keeps_known() {
    let tools = list_tools(Some(&cats(&["mouse", "no_such_category"])));
    assert_eq!(tools.len(), 7, "got {:?}", names(&tools));
}

#[test]
fn category_filter_is_order_independent() {
    let a = names(&list_tools(Some(&cats(&["mouse", "admin"]))));
    let b = names(&list_tools(Some(&cats(&["admin", "mouse"]))));
    let sa: BTreeSet<String> = a.into_iter().collect();
    let sb: BTreeSet<String> = b.into_iter().collect();
    assert_eq!(sa, sb);
    assert_eq!(sa.len(), 14);
}
