use std::sync::LazyLock;

use ammonia::Builder;
use pulldown_cmark::{
    BlockQuoteKind, CodeBlockKind, CowStr, Event, Options, Parser, Tag, TagEnd, html,
};

use crate::highlight::{
    Error, MAX_RENDERED_BYTES, mark_deceptive_characters, replace_control_characters,
};
use crate::{Highlighter, Html};

const OPTIONS: Options = Options::ENABLE_TABLES
    .union(Options::ENABLE_STRIKETHROUGH)
    .union(Options::ENABLE_TASKLISTS)
    .union(Options::ENABLE_FOOTNOTES)
    .union(Options::ENABLE_GFM);

/// Shared ammonia sanitizer. Extends the default allowlist with `class` on any tag (needed for
/// syntax-highlight spans and alert blockquotes) and the handful of attributes pulldown-cmark
/// emits on task-list checkboxes.
static SANITIZER: LazyLock<Builder<'static>> = LazyLock::new(|| {
    let mut builder = Builder::default();
    builder.add_generic_attributes(["class"]);
    builder.add_tags(["input"]);
    builder.add_tag_attributes("input", ["checked", "disabled"]);
    // `type` is pinned rather than merely allowed: ammonia treats a generic attribute allowance
    // as permitting every value, which would let a paste render a password field.
    builder.add_tag_attribute_values("input", "type", ["checkbox"]);
    builder
});

/// Deepest markup nesting handed to the sanitizer.
///
/// Building the DOM is quadratic in nesting depth, and raw HTML in a paste reaches it verbatim:
/// a megabyte of `<div>` is a quarter million levels deep and costs minutes of CPU. Prose does not
/// come close to this bound — deeply nested lists sit around a dozen levels.
const MAX_NESTING_DEPTH: usize = 256;

/// HTML elements that never open a level, so they must not count towards the depth.
const VOID_ELEMENTS: [&str; 14] = [
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// Leading run of `fragment` that forms a tag name, empty when it names nothing.
fn tag_name(fragment: &str) -> &str {
    let len = fragment
        .find(|c: char| !c.is_ascii_alphanumeric())
        .unwrap_or(fragment.len());

    &fragment[..len]
}

/// Return the deepest element nesting in `html`.
///
/// This walks the tag soup the parser produced rather than a tree, so it is an approximation.
/// Overstating is safe — it only rejects — but understating hands the sanitizer the very tree the
/// limit exists to refuse, so every approximation here has to round upwards.
///
/// That is why the open elements are tracked by name rather than counted. html5ever drops a close
/// tag naming nothing that is open, so treating one as closing a level let `<div></span>` report
/// depth 1 however often it was repeated, while the parser really nested every `div`.
fn nesting_depth(html: &str) -> usize {
    let mut open: Vec<&str> = Vec::new();
    let mut max_depth: usize = 0;

    for fragment in html.split('<').skip(1) {
        if let Some(rest) = fragment.strip_prefix('/') {
            let name = tag_name(rest);
            if name.is_empty() {
                continue;
            }

            // Closing an element also closes whatever is still open inside it; a name that is not
            // open closes nothing at all.
            if let Some(at) = open.iter().rposition(|el| el.eq_ignore_ascii_case(name)) {
                open.truncate(at);
            }

            continue;
        }

        // Comments, doctypes and bare `<` in text open nothing.
        let name = tag_name(fragment);
        if name.is_empty() {
            continue;
        }

        // Only a void element closes itself. HTML5 discards a trailing slash on anything else, so
        // `<div/>` opens a level however it is spelled — counting it as self-closing let a paste
        // report depth 0 and still build the tree the limit is here to refuse.
        if VOID_ELEMENTS
            .iter()
            .any(|void| name.eq_ignore_ascii_case(void))
        {
            continue;
        }

        open.push(name);
        max_depth = max_depth.max(open.len());

        // Nothing past the limit needs measuring, and stopping bounds both this scan and the
        // stack it walks — without it, a document of unmatched close tags would be quadratic.
        if max_depth > MAX_NESTING_DEPTH {
            break;
        }
    }

    max_depth
}

/// Render `CommonMark` `text` to HTML. Fenced code blocks with a known language are syntax
/// highlighted via `highlighter`; unknown languages fall back to plain text.
///
/// Raw HTML embedded in the source is passed through the parser and then sanitized by
/// [`ammonia`], so tags like `<details>` or `<kbd>` survive while `<script>`, inline event
/// handlers, `javascript:` URLs and other XSS vectors are stripped.
///
/// Markup nested deeper than [`MAX_NESTING_DEPTH`] is rejected instead of sanitized.
pub fn render(text: &str, highlighter: &Highlighter) -> Result<Html, Error> {
    let text = replace_control_characters(text);
    let parser = Parser::new_ext(&text, OPTIONS);
    let events = rewrite_events(parser, highlighter)?;

    let mut raw = String::with_capacity(text.len());
    html::push_html(&mut raw, events.into_iter());

    let depth = nesting_depth(&raw);
    if depth > MAX_NESTING_DEPTH {
        return Err(Error::TooDeeplyNested(MAX_NESTING_DEPTH));
    }

    let cleaned = SANITIZER.clean(&raw).to_string();

    // After the sanitizer, not before: it escapes `<` and `>` inside attribute values, so a tag is
    // exactly what it looks like and the marker cannot land inside one. Its own markup is this
    // crate's, and the character it wraps is not markup-significant, so nothing reopens what the
    // sanitizer just closed.
    let marked = mark_deceptive_characters(&cleaned);

    // The size check above ran on the unmarked document, and a paste of nothing but zero-width
    // spaces gains a wrapper on every one of them.
    if marked.len() > MAX_RENDERED_BYTES {
        return Err(Error::TooLarge(MAX_RENDERED_BYTES));
    }

    Ok(Html::new(marked.into_owned()))
}

fn rewrite_events<'a>(
    parser: Parser<'a>,
    highlighter: &Highlighter,
) -> Result<Vec<Event<'a>>, Error> {
    let mut out = Vec::new();
    let mut pending: Option<(String, String)> = None;
    // Each block bounds itself, but a document is free to hold many of them.
    let mut highlighted_bytes: usize = 0;

    for event in parser {
        match event {
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(lang))) => {
                pending = Some((lang.to_string(), String::new()));
            }
            Event::Text(text) => match pending.as_mut() {
                Some((_, buf)) => buf.push_str(&text),
                None => out.push(Event::Text(text)),
            },
            Event::End(TagEnd::CodeBlock) => match pending.take() {
                Some((lang, code)) => {
                    let html = highlighter.highlight_code_block(&code, &lang)?;

                    highlighted_bytes = highlighted_bytes.saturating_add(html.len());
                    if highlighted_bytes > MAX_RENDERED_BYTES {
                        return Err(Error::TooLarge(MAX_RENDERED_BYTES));
                    }

                    out.push(Event::Html(CowStr::from(html)));
                }
                None => out.push(Event::End(TagEnd::CodeBlock)),
            },
            Event::Start(Tag::BlockQuote(Some(kind))) => {
                out.push(Event::Start(Tag::BlockQuote(Some(kind))));
                out.push(Event::Html(CowStr::from(alert_title(kind))));
            }
            other => out.push(other),
        }
    }

    Ok(out)
}

/// Return the HTML injected at the top of a GFM alert blockquote.
fn alert_title(kind: BlockQuoteKind) -> String {
    let label = match kind {
        BlockQuoteKind::Note => "Note",
        BlockQuoteKind::Tip => "Tip",
        BlockQuoteKind::Important => "Important",
        BlockQuoteKind::Warning => "Warning",
        BlockQuoteKind::Caution => "Caution",
    };
    format!("<p class=\"markdown-alert-title\">{label}</p>")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_string(text: &str, highlighter: &Highlighter) -> Result<std::sync::Arc<str>, Error> {
        render(text, highlighter).map(Html::into_inner)
    }

    /// The sanitizer drops U+0000 but passes every other C0 control through, so an escape or a
    /// bell in a paste reached the page verbatim — invalid in an HTML document, and the one output
    /// of this crate that is never re-escaped afterwards.
    #[test]
    fn control_characters_do_not_reach_the_markup() -> Result<(), Box<dyn std::error::Error>> {
        let highlighter = Highlighter::default();
        let html = render_string("a\u{0}b\u{7}c\u{1b}d\n\n```\nx\u{7}y\n```\n", &highlighter)?;

        for control in ['\u{0}', '\u{7}', '\u{1b}'] {
            assert!(!html.contains(control), "{control:?} survived: {html:?}");
        }
        assert!(html.contains("a\u{fffd}b\u{fffd}c\u{fffd}d"), "got: {html}");
        assert!(html.contains("x\u{fffd}y"), "code block: {html}");

        // Tab is left alone — inside a fence it is content, not indentation.
        let html = render_string("```\na\tb\n```\n", &highlighter)?;
        assert!(html.contains("a\tb"), "got: {html}");

        Ok(())
    }

    #[test]
    fn heading() -> Result<(), Box<dyn std::error::Error>> {
        let html = render_string("# Hello", &Highlighter::default())?;
        assert!(html.contains("<h1>Hello</h1>"), "got: {html}");
        Ok(())
    }

    #[test]
    fn table() -> Result<(), Box<dyn std::error::Error>> {
        let md = "| a | b |\n|---|---|\n| 1 | 2 |\n";
        let html = render_string(md, &Highlighter::default())?;
        assert!(html.contains("<table>"), "got: {html}");
        assert!(html.contains("<th>a</th>"), "got: {html}");
        Ok(())
    }

    #[test]
    fn task_list() -> Result<(), Box<dyn std::error::Error>> {
        let html = render_string("- [x] done\n- [ ] open\n", &Highlighter::default())?;
        assert!(html.contains("type=\"checkbox\""), "got: {html}");
        assert!(html.contains("checked"), "got: {html}");
        Ok(())
    }

    #[test]
    fn input_type_is_restricted_to_checkboxes() -> Result<(), Box<dyn std::error::Error>> {
        let html = render_string(
            r#"<input type="password" name="pw"><input type="checkbox" checked>"#,
            &Highlighter::default(),
        )?;

        // Task lists are the only reason `input` is allowed at all. A password field in a
        // rendered paste is a password-manager autofill phishing primitive.
        assert!(!html.contains("password"), "got: {html}");
        assert!(html.contains(r#"type="checkbox""#), "got: {html}");

        Ok(())
    }

    #[test]
    fn strikethrough() -> Result<(), Box<dyn std::error::Error>> {
        let html = render_string("~~gone~~", &Highlighter::default())?;
        assert!(html.contains("<del>gone</del>"), "got: {html}");
        Ok(())
    }

    #[test]
    fn code_block_is_highlighted() -> Result<(), Box<dyn std::error::Error>> {
        let md = "```rust\nfn main() {}\n```\n";
        let html = render_string(md, &Highlighter::default())?;
        assert!(
            html.contains("class=\"code-block language-rust\""),
            "got: {html}"
        );
        assert!(html.contains("<span class=\""), "got: {html}");
        Ok(())
    }

    #[test]
    fn code_block_unknown_language_falls_back() -> Result<(), Box<dyn std::error::Error>> {
        let md = "```not-a-real-lang\nhello\n```\n";
        let html = render_string(md, &Highlighter::default())?;
        assert!(html.contains("<pre"), "got: {html}");
        assert!(html.contains("hello"), "got: {html}");
        Ok(())
    }

    #[test]
    fn code_block_without_language() -> Result<(), Box<dyn std::error::Error>> {
        let md = "```\nraw\n```\n";
        let html = render_string(md, &Highlighter::default())?;
        assert!(html.contains("class=\"code-block\""), "got: {html}");
        assert!(!html.contains("language-"), "got: {html}");
        Ok(())
    }

    #[test]
    fn code_block_malicious_language_is_sanitized() -> Result<(), Box<dyn std::error::Error>> {
        let md = "```\"><script>\ncode\n```\n";
        let html = render_string(md, &Highlighter::default())?;
        assert!(!html.contains("<script>"), "got: {html}");
        Ok(())
    }

    #[test]
    fn gfm_alert_note() -> Result<(), Box<dyn std::error::Error>> {
        let md = "> [!NOTE]\n> body\n";
        let html = render_string(md, &Highlighter::default())?;
        assert!(
            html.contains("<blockquote class=\"markdown-alert-note\">"),
            "got: {html}"
        );
        assert!(
            html.contains("<p class=\"markdown-alert-title\">Note</p>"),
            "got: {html}"
        );
        assert!(html.contains("body"), "got: {html}");
        Ok(())
    }

    #[test]
    fn gfm_alert_variants() -> Result<(), Box<dyn std::error::Error>> {
        for (marker, class, label) in [
            ("TIP", "markdown-alert-tip", "Tip"),
            ("IMPORTANT", "markdown-alert-important", "Important"),
            ("WARNING", "markdown-alert-warning", "Warning"),
            ("CAUTION", "markdown-alert-caution", "Caution"),
        ] {
            let md = format!("> [!{marker}]\n> body\n");
            let html = render_string(&md, &Highlighter::default())?;
            assert!(html.contains(class), "{marker}: {html}");
            assert!(
                html.contains(&format!("<p class=\"markdown-alert-title\">{label}</p>")),
                "{marker}: {html}"
            );
        }
        Ok(())
    }

    #[test]
    fn plain_blockquote_is_not_an_alert() -> Result<(), Box<dyn std::error::Error>> {
        let html = render_string("> just a quote\n", &Highlighter::default())?;
        assert!(html.contains("<blockquote>"), "got: {html}");
        assert!(!html.contains("markdown-alert"), "got: {html}");
        Ok(())
    }

    #[test]
    fn dangerous_raw_html_is_stripped() -> Result<(), Box<dyn std::error::Error>> {
        let md =
            "<script>alert(1)</script>\n\n<a href=\"javascript:alert(1)\" onclick=\"x\">x</a>\n";
        let html = render_string(md, &Highlighter::default())?;
        assert!(!html.contains("<script"), "got: {html}");
        assert!(!html.contains("alert(1)"), "got: {html}");
        assert!(!html.contains("javascript:"), "got: {html}");
        assert!(!html.contains("onclick"), "got: {html}");
        Ok(())
    }

    /// A fenced block went through the syntax engine whole, with none of the bounds the source
    /// view applies. Highlighting expands heavily — 468 KB of Perl quotes became 49 MB of markup —
    /// and the request timeout does not reclaim it, because `spawn_blocking` is not cancellable.
    #[test]
    fn a_hugely_expanding_code_block_is_refused() {
        // Escaping alone expands a quote sixfold, which is enough to blow the budget without
        // depending on how fast the syntax engine happens to be in this build profile.
        let body = "\"".repeat(3 * 1024 * 1024);
        let md = format!("```pl\n{body}\n```\n");

        let result = render(&md, &Highlighter::default());

        assert!(
            matches!(result, Err(Error::TooLarge(_))),
            "expected TooLarge"
        );
    }

    /// A single enormous line is where the regex engines misbehave worst, so it is escaped rather
    /// than highlighted — the same cutoff the source view applies per row.
    #[test]
    fn an_overlong_code_block_line_is_not_highlighted() {
        let line = "a ".repeat(4096);
        let md = format!("```rs\n{line}\n```\n");

        let html = render_string(&md, &Highlighter::default()).unwrap();

        assert!(html.contains(&line), "content was dropped");
        assert!(
            !html.contains("<span class=\"source rust\">"),
            "long line was still highlighted: {}",
            &html[..html.len().min(200)]
        );
    }

    /// The rendered view is read to judge a paste just as the source view is, so the characters
    /// that reorder a line have to be visible there too — in prose and inside a fenced block.
    #[test]
    fn a_reordering_character_is_marked() -> Result<(), Box<dyn std::error::Error>> {
        let highlighter = Highlighter::default();

        for md in [
            "Some \u{202e}reordered prose.\n",
            "```rs\nlet admin = \u{202e}false;\n```\n",
            "- a list item with \u{200b}a zero-width space\n",
        ] {
            let html = render_string(md, &highlighter)?;

            assert!(html.contains("data-cp=\"U+"), "not marked: {html}");
        }

        Ok(())
    }

    /// Marking runs after the sanitizer, so it must not become a way back in: the wrapper is this
    /// crate's own markup and the character it holds is not markup-significant.
    #[test]
    fn marking_does_not_reopen_the_sanitizer() -> Result<(), Box<dyn std::error::Error>> {
        let highlighter = Highlighter::default();
        let md = "<script>alert(1)</script>\n\n<img src=x onerror=alert(2)> \u{202e}text\n";

        let html = render_string(md, &highlighter)?;

        assert!(!html.contains("<script"), "script survived: {html}");
        assert!(!html.contains("onerror"), "handler survived: {html}");
        assert!(html.contains("data-cp=\"U+202E\""), "not marked: {html}");

        Ok(())
    }

    /// A marker written inside an attribute would break out of it. The sanitizer escapes `>` in
    /// attribute values before this runs, so a tag is exactly what it looks like.
    #[test]
    fn an_attribute_is_never_marked() -> Result<(), Box<dyn std::error::Error>> {
        let highlighter = Highlighter::default();
        // A URL attribute is percent-encoded by the sanitizer, so the character only survives
        // verbatim in a plain one like `title` — which is where marking a tag would break out.
        let md = "<a title=\"x\u{202e}y\" href=\"https://example.com\">z\u{202e}w</a>\n";

        let html = render_string(md, &highlighter)?;

        for (start, _) in html.match_indices('<') {
            let end = start + html[start..].find('>').unwrap_or(0);
            let tag = &html[start..=end.max(start)];
            assert!(
                !tag.contains("<span class=\"uc\"") || tag.starts_with("<span class=\"uc\""),
                "marker written into a tag: {tag}"
            );
        }

        Ok(())
    }

    #[test]
    fn deeply_nested_markup_is_rejected() {
        let md = "<div>".repeat(MAX_NESTING_DEPTH + 10);
        let result = render(&md, &Highlighter::default());
        assert!(matches!(result, Err(Error::TooDeeplyNested(_))));
    }

    /// html5ever discards a close tag naming nothing that is open, so it must not cancel an open
    /// level here either. Letting it decrement made `<div></span>` report depth 1 however often it
    /// was repeated, walking the limit straight past the sanitizer it guards.
    #[test]
    fn a_close_tag_matching_nothing_open_does_not_reduce_the_depth() {
        assert_eq!(nesting_depth("<div></span>"), 1);
        assert_eq!(nesting_depth(&"<div></span>".repeat(5)), 5);
    }

    #[test]
    fn nesting_hidden_behind_unmatched_close_tags_is_rejected() {
        let md = "<div></span>".repeat(MAX_NESTING_DEPTH + 10);
        let result = render(&md, &Highlighter::default());
        assert!(matches!(result, Err(Error::TooDeeplyNested(_))));
    }

    /// HTML5 ignores a trailing slash on anything but a void element, so `<div/>` opens a level
    /// just like `<div>`. Honouring the slash on any tag let a paste declare itself flat and hand
    /// the sanitizer the deep tree the limit exists to refuse.
    #[test]
    fn a_slash_does_not_close_a_non_void_element() {
        let md = "<div/>".repeat(MAX_NESTING_DEPTH + 10);
        let result = render(&md, &Highlighter::default());
        assert!(matches!(result, Err(Error::TooDeeplyNested(_))));
    }

    #[test]
    fn nesting_within_the_limit_still_renders() -> Result<(), Box<dyn std::error::Error>> {
        let md = "<div>".repeat(32);
        let html = render_string(&md, &Highlighter::default())?;
        assert!(html.contains("<div>"), "got: {html}");
        Ok(())
    }

    #[test]
    fn flat_markup_is_not_mistaken_for_nesting() -> Result<(), Box<dyn std::error::Error>> {
        // Siblings and void elements open no levels, so a long flat document must render.
        let md = format!("{}\n\n{}", "<div>x</div>".repeat(500), "<br>".repeat(500));
        let html = render_string(&md, &Highlighter::default())?;
        assert!(html.contains("<div>"), "got: {html}");
        Ok(())
    }

    #[test]
    fn nesting_depth_counts_levels_not_tags() {
        assert_eq!(nesting_depth(""), 0);
        assert_eq!(nesting_depth("<p>hi</p>"), 1);
        assert_eq!(nesting_depth("<div><p>hi</p></div>"), 2);
        assert_eq!(nesting_depth("<p>a</p><p>b</p>"), 1);
        assert_eq!(nesting_depth("<br><br><br>"), 0);
        assert_eq!(nesting_depth("<img src=\"x\"/>"), 0);
        // A slash cannot close a `div`, so these nest rather than sit side by side.
        assert_eq!(nesting_depth("<div/><div/>"), 2);
        // Text containing a bare `<` must not be read as markup.
        assert_eq!(nesting_depth("1 < 2"), 0);
    }

    #[test]
    fn safe_raw_html_survives() -> Result<(), Box<dyn std::error::Error>> {
        let md = "<details><summary>more</summary>hidden</details>\n\nPress <kbd>Ctrl</kbd>.\n";
        let html = render_string(md, &Highlighter::default())?;
        assert!(html.contains("<details>"), "got: {html}");
        assert!(html.contains("<summary>more</summary>"), "got: {html}");
        assert!(html.contains("<kbd>Ctrl</kbd>"), "got: {html}");
        Ok(())
    }
}
