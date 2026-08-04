use std::fmt::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use syntect::html::{ClassStyle, ClassedHTMLGenerator, line_tokens_to_classed_spans};
use syntect::parsing::{
    BasicScopeStackOp, ParseState, Scope, ScopeStack, ScopeStackOp, SyntaxReference, SyntaxSet,
};
use syntect::util::LinesWithEndings;

#[expect(deprecated)]
use syntect::parsing::SCOPE_REPO;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("syntax highlighting error: {0}")]
    SyntaxHighlighting(#[from] syntect::Error),
    #[error("syntax parsing error: {0}")]
    SyntaxParsing(#[from] syntect::parsing::ParsingError),
    #[error("markup nested deeper than {0} levels")]
    TooDeeplyNested(usize),
    #[error("rendered output would exceed {0} bytes")]
    TooLarge(usize),
}

const HIGHLIGHT_LINE_LENGTH_CUTOFF: usize = 2048;

/// Largest document one render may emit.
///
/// Every line is wrapped in gutter and row markup, so the rendered size follows the line count
/// rather than the byte count: a paste of nothing but newlines expanded by 78x, turning a 1 MiB
/// body into 81 MB held whole in memory, per request, and far too large for the cache to ever
/// absorb — so every fetch paid for it again. The bound is on what one response may cost, not on
/// what a paste may hold: `/raw` and the download still serve the bytes.
const MAX_RENDERED_BYTES: usize = 16 * 1024 * 1024;

/// How long one render may spend in the syntax engine before the rest is emitted unhighlighted.
///
/// The syntax is chosen by the URL's extension, and the regex-heavy ones cost orders of magnitude
/// more per byte than plain text — the same 1 MiB paste read as Perl took 43 s of a core versus
/// 0.4 s as text, and a caller may ask for that as often as it likes. Degrading to plain rows
/// keeps the page correct; each row is already self-contained, which is what lets highlighting
/// stop part-way through a document.
const HIGHLIGHT_TIME_BUDGET: Duration = Duration::from_secs(2);

/// Name syntect gives the Markdown syntax.
const MARKDOWN_SYNTAX_NAME: &str = "Markdown";

/// Rendered HTML, shared so that cloning is a refcount bump rather than a copy of the whole
/// document.
#[derive(Clone)]
pub struct Html(Arc<str>);

pub struct Highlighter {
    syntax_set: SyntaxSet,
    /// Indices into `syntax_set.syntaxes()`, ordered by lower-cased syntax name.
    ordered_syntaxes: Vec<usize>,
}

/// Syntax reference.
pub struct Syntax<'a> {
    /// Name of the syntax or the language it is related to.
    pub name: &'a str,
    /// List of possible filename extensions.
    pub extensions: &'a [String],
}

impl Default for Highlighter {
    fn default() -> Self {
        let syntax_set = two_face::syntax::extra_newlines();
        let mut ordered_syntaxes: Vec<usize> = (0..syntax_set.syntaxes().len()).collect();
        ordered_syntaxes
            .sort_by_cached_key(|&i| syntax_set.syntaxes().get(i).map(|s| s.name.to_lowercase()));

        Self {
            syntax_set,
            ordered_syntaxes,
        }
    }
}

/// Escape HTML tags in `s` and write output to `buf`.
fn escape(s: &str, buf: &mut String) {
    // Because the internet is always right, turns out there's not that many
    // characters to escape: http://stackoverflow.com/questions/7381974
    let mut last = 0;
    for (i, ch) in s.bytes().enumerate() {
        let escaping = match ch {
            b'>' => "&gt;",
            b'<' => "&lt;",
            b'&' => "&amp;",
            b'\'' => "&#39;",
            b'"' => "&quot;",
            _ => continue,
        };

        buf.push_str(&s[last..i]);
        buf.push_str(escaping);
        last = i + 1;
    }

    buf.push_str(&s[last..]);
}

/// Transform `scope` atoms to CSS style classes and write output to `s`.
fn scope_to_classes(s: &mut String, scope: Scope) {
    #[expect(deprecated)]
    let repo = SCOPE_REPO.lock().expect("lock");
    for i in 0..(scope.len()) {
        let atom = scope.atom_at(i as usize);
        let atom_s = repo.atom_str(atom);
        if i != 0 {
            s.push(' ');
        }
        s.push_str(atom_s);
    }
}

/// Return `true` if `scope` will be used to render a Markdown link.
fn is_markdown_link(scope: Scope) -> bool {
    #[expect(deprecated)]
    let repo = SCOPE_REPO.lock().expect("lock");

    (0..scope.len()).all(|index| {
        matches!(
            repo.atom_str(scope.atom_at(index as usize)),
            "markup" | "underline" | "link" | "markdown"
        )
    })
}

/// Return `true` if `target` may be handed to an `href`.
///
/// Unlike rendered Markdown, this output never passes through ammonia — the escaping in this file
/// is all that stands between a paste and the page, and escaping a `javascript:` URL still leaves
/// a working one. Only the schemes that navigate somewhere are allowed; anything else is shown as
/// text, which is what it reads as anyway.
fn is_navigable_target(target: &str) -> bool {
    // Browsers drop tabs, newlines and other control characters before resolving a URL, so
    // `java&#9;script:alert(1)` navigates exactly like `javascript:alert(1)`. Compare with them
    // taken out rather than trusting the literal spelling.
    let cleaned: String = target
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .collect();

    let Some(colon) = cleaned.find(':') else {
        // No scheme at all, so the target is relative and resolves against this origin.
        return true;
    };

    let scheme = &cleaned[..colon];

    // A colon that follows a path separator never delimited a scheme: `notes/todo:2` is relative.
    if scheme.contains(['/', '?', '#']) {
        return true;
    }

    ["http", "https", "mailto"]
        .iter()
        .any(|allowed| scheme.eq_ignore_ascii_case(allowed))
}

/// Number of unmatched `</span>` closes encountered before the running balance recovers.
fn open_span_prefix(formatted: &str) -> usize {
    formatted
        .split('<')
        .skip(1)
        .scan(0_isize, |balance, chunk| {
            if chunk.starts_with("/span>") {
                *balance -= 1;
            } else if chunk.starts_with("span>") || chunk.starts_with("span ") {
                *balance += 1;
            }
            Some(*balance)
        })
        .min()
        .unwrap_or(0)
        .min(0)
        .unsigned_abs()
}

/// Modified version of [`syntect::html::line_tokens_to_classed_spans`] that outputs HTML anchors
/// for Markdown links.
fn line_tokens_to_classed_spans_md(
    line: &str,
    ops: &[(usize, ScopeStackOp)],
    stack: &mut ScopeStack,
) -> Result<(String, isize), syntect::Error> {
    let mut s = String::with_capacity(line.len() + ops.len() * 8); // a guess
    let mut cur_index = 0;
    let mut span_delta = 0;

    let mut span_empty = false;
    let mut span_start = 0;
    // Set when a link scope opens. The target is the scope's own text, so it is not known until
    // that text arrives — which is where the anchor is emitted, if it is emitted at all.
    let mut pending_link = false;
    // Whether an `<a>` was actually opened and so still needs closing.
    let mut link_open = false;

    for &(i, ref op) in ops {
        if i > cur_index {
            span_empty = false;
            let text = &line[cur_index..i];

            if pending_link {
                pending_link = false;

                if is_navigable_target(text) {
                    // Insert href and close attribute ...
                    s.push_str(r#"<a href=""#);
                    escape(text, &mut s);
                    s.push_str(r#"">"#);
                    link_open = true;
                }
            }

            escape(text, &mut s);

            cur_index = i;
        }
        stack.apply_with_hook(op, |basic_op, _| match basic_op {
            BasicScopeStackOp::Push(scope) => {
                span_start = s.len();
                span_empty = true;
                s.push_str("<span class=\"");
                scope_to_classes(&mut s, scope);
                s.push_str("\">");
                span_delta += 1;

                if is_markdown_link(scope) {
                    pending_link = true;
                }
            }
            BasicScopeStackOp::Pop => {
                if link_open {
                    s.push_str("</a>");
                    link_open = false;
                }
                pending_link = false;
                if span_empty {
                    s.truncate(span_start);
                } else {
                    s.push_str("</span>");
                }
                span_delta -= 1;
                span_empty = false;
            }
        })?;
    }
    escape(&line[cur_index..line.len()], &mut s);
    Ok((s, span_delta))
}

impl Highlighter {
    /// Return the syntax `ext` resolves to, falling back to plain text.
    fn syntax_for(&self, ext: Option<&str>) -> &SyntaxReference {
        ext.filter(|ext| *ext != "txt")
            .and_then(|ext| self.syntax_set.find_syntax_by_extension(ext))
            .unwrap_or_else(|| self.syntax_set.find_syntax_plain_text())
    }

    /// Return `true` if `ext` selects a syntax of its own.
    ///
    /// Extensions that do not are all rendered as plain text, so they produce identical output and
    /// callers may treat them as interchangeable.
    #[must_use]
    pub fn knows_extension(&self, ext: &str) -> bool {
        ext != "txt" && self.syntax_set.find_syntax_by_extension(ext).is_some()
    }

    /// Return `true` if `ext` names any extension the syntax set lists.
    ///
    /// Unlike [`Highlighter::knows_extension`], `txt` counts: that exclusion only serves callers
    /// asking whether two extensions render alike, and `txt` is one of the values [`Self::syntaxes`]
    /// offers, so rejecting it here would turn the site's own plain-text choice into an error.
    #[must_use]
    pub fn has_extension(&self, ext: &str) -> bool {
        self.syntax_set.find_syntax_by_extension(ext).is_some()
    }

    /// Return `true` if `ext` resolves to the Markdown syntax, i.e. the paste can also be served
    /// as rendered HTML.
    #[must_use]
    pub fn is_markdown(&self, ext: Option<&str>) -> bool {
        self.syntax_for(ext).name == MARKDOWN_SYNTAX_NAME
    }

    /// Highlight `text` with the given file extension which is used to
    /// determine the right syntax. If not given or does not exist, plain text will be generated.
    pub fn highlight(&self, text: String, ext: Option<String>) -> Result<Html, Error> {
        let syntax_ref = self.syntax_for(ext.as_deref());
        let is_markdown = syntax_ref.name == MARKDOWN_SYNTAX_NAME;
        let mut parse_state = ParseState::new(syntax_ref);
        let mut scope_stack = ScopeStack::new();

        // The gutter only depends on the number of lines, so emit it up front and append the code
        // to the same buffer. Counting costs one scan of the source; keeping the code in its own
        // buffer would cost a copy of the whole rendered document.
        let mut html = String::from(r#"<div id="line-numbers" aria-hidden="true">"#);

        for line_number in 1..=LinesWithEndings::from(&text).count() {
            let _ = write!(
                html,
                r##"<div id="L{line_number}"><a href="#L{line_number}">{line_number}</a></div>"##
            );

            if html.len() > MAX_RENDERED_BYTES {
                return Err(Error::TooLarge(MAX_RENDERED_BYTES));
            }
        }

        html.push_str(r#"</div><div class="src-code"><code>"#);

        let started = Instant::now();
        // Set once the syntax engine has had its budget; the remaining lines are escaped only.
        let mut plain_from_here = false;

        for (line_idx, line) in LinesWithEndings::from(&text).enumerate() {
            let (formatted, delta) = if plain_from_here || line.len() > HIGHLIGHT_LINE_LENGTH_CUTOFF
            {
                // Too long, or past the time budget, to highlight — but it still goes into the
                // page verbatim otherwise.
                let mut escaped = String::with_capacity(line.len());
                escape(line, &mut escaped);
                (escaped, 0)
            } else {
                let parsed = parse_state.parse_line(line, &self.syntax_set)?;

                if is_markdown {
                    line_tokens_to_classed_spans_md(line, parsed.as_slice(), &mut scope_stack)?
                } else {
                    line_tokens_to_classed_spans(
                        line,
                        parsed.as_slice(),
                        ClassStyle::Spaced,
                        &mut scope_stack,
                    )?
                }
            };

            let line_number = line_idx + 1;
            let _ = write!(html, r#"<div id="LC{line_number}">"#);

            // The line may close spans opened on earlier lines before opening any of its own.
            // Track the minimum running span balance so we can prepend bare `<span>`s to keep
            // the line's HTML self-contained — using only `delta` would let `</span>` precede
            // its match within the line, producing misnested output.
            let prepend = open_span_prefix(&formatted);
            html.extend(std::iter::repeat_n("<span>", prepend));
            html.extend(formatted.split('\n'));
            html.extend(std::iter::repeat_n(
                "</span>",
                prepend.saturating_add_signed(delta),
            ));

            html.push_str("</div>");

            if html.len() > MAX_RENDERED_BYTES {
                return Err(Error::TooLarge(MAX_RENDERED_BYTES));
            }

            if !plain_from_here && started.elapsed() > HIGHLIGHT_TIME_BUDGET {
                plain_from_here = true;
            }
        }

        html.push_str("</code></div>");

        Ok(Html::new(html))
    }

    /// Highlight a fenced code block. `token` is the info string (e.g. `rust`, `py`); unknown or
    /// empty tokens fall back to plain text. Unlike [`Highlighter::highlight`], the output is a
    /// compact `<pre><code>` without line numbers, suitable for embedding into rendered Markdown.
    pub(crate) fn highlight_code_block(&self, text: &str, token: &str) -> Result<String, Error> {
        let syntax = self
            .syntax_set
            .find_syntax_by_token(token)
            .unwrap_or_else(|| self.syntax_set.find_syntax_plain_text());

        let mut generator = ClassedHTMLGenerator::new_with_class_style(
            syntax,
            &self.syntax_set,
            ClassStyle::Spaced,
        );

        for line in LinesWithEndings::from(text) {
            generator.parse_html_for_line_which_includes_newline(line)?;
        }

        let inner = generator.finalize();
        let is_safe_token = !token.is_empty()
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        let class = if is_safe_token {
            format!("code-block language-{token}")
        } else {
            String::from("code-block")
        };

        Ok(format!("<pre class=\"{class}\"><code>{inner}</code></pre>"))
    }

    /// Return iterator over all available [`Syntax`]es with their canonical name and usual file
    /// extensions.
    pub fn syntaxes(&self) -> impl Iterator<Item = Syntax<'_>> {
        self.ordered_syntaxes.iter().filter_map(|&i| {
            let syntax = self.syntax_set.syntaxes().get(i)?;
            Some(Syntax {
                name: syntax.name.as_ref(),
                extensions: syntax.file_extensions.as_slice(),
            })
        })
    }
}

impl Html {
    /// Wrap an already-HTML string. Callers are responsible for ensuring the content is safe to
    /// insert into a page (i.e. produced by a trusted renderer).
    pub(crate) fn new(html: String) -> Self {
        Self(Arc::from(html))
    }

    #[must_use]
    pub fn into_inner(self) -> Arc<str> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Row and gutter markup follows the line count, not the byte count, so a body of newlines
    /// rendered to nearly a hundred times its size — buffered whole, per request, and too big for
    /// the cache to hold, so nothing ever amortised it.
    #[test]
    fn a_render_far_larger_than_its_input_is_refused() {
        let highlighter = Highlighter::default();
        // Well under a default `WASTEBIN_MAX_BODY_SIZE`, and 81 MB of HTML before the bound.
        let text = "\n".repeat(1024 * 1024);

        assert!(
            matches!(
                highlighter.highlight(text, Some("txt".into())),
                Err(Error::TooLarge(_))
            ),
            "an enormous render was produced anyway"
        );
    }

    /// The bound must not be reachable by anything a person would actually paste.
    #[test]
    fn an_ordinary_paste_still_renders() -> Result<(), Box<dyn std::error::Error>> {
        let highlighter = Highlighter::default();
        let text = "fn main() { println!(\"hello\"); }\n".repeat(10_000);

        let html = highlighter.highlight(text, Some("rs".into()))?.into_inner();

        assert!(html.contains("id=\"LC10000\""), "last row missing");

        Ok(())
    }

    #[test]
    fn long_lines_are_escaped() -> Result<(), Box<dyn std::error::Error>> {
        let highlighter = Highlighter::default();
        let line = format!(
            "{}<script>alert(1)</script>",
            "a".repeat(HIGHLIGHT_LINE_LENGTH_CUTOFF)
        );
        assert!(line.len() > HIGHLIGHT_LINE_LENGTH_CUTOFF);

        let html = highlighter
            .highlight(line, Some("txt".into()))?
            .into_inner();

        assert!(!html.contains("<script>"), "raw markup leaked: {html}");
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));

        Ok(())
    }

    #[test]
    fn markdown_detection_follows_the_syntax_set() {
        let highlighter = Highlighter::default();

        for ext in ["md", "markdown", "mdown"] {
            assert!(
                highlighter.is_markdown(Some(ext)),
                "{ext} should be markdown"
            );
        }

        for ext in ["rs", "txt", ""] {
            assert!(
                !highlighter.is_markdown(Some(ext)),
                "{ext} should not be markdown"
            );
        }

        assert!(!highlighter.is_markdown(None));
    }

    #[test]
    fn markdown_links() -> Result<(), Box<dyn std::error::Error>> {
        let highlighter = Highlighter::default();

        let html = highlighter.highlight(
            "[hello](https://github.com/matze/wastebin)".into(),
            Some("md".into()),
        )?;

        assert!(html.into_inner().contains("<span class=\"markup underline link markdown\"><a href=\"https://github.com/matze/wastebin\">https://github.com/matze/wastebin</a></span>"));

        Ok(())
    }

    /// The source view builds anchors itself and never passes them through ammonia, so the
    /// scheme check here is the only thing stopping a paste from shipping a working
    /// `javascript:` URL. Escaping does not help: it keeps the attribute intact, which is
    /// exactly what makes the URL work.
    #[test]
    fn a_link_target_that_is_not_navigable_gets_no_anchor() -> Result<(), Box<dyn std::error::Error>>
    {
        let highlighter = Highlighter::default();

        for target in [
            "javascript:alert(document.domain)",
            "JaVaScRiPt:alert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "vbscript:msgbox(1)",
        ] {
            let html = highlighter
                .highlight(format!("[click]({target})"), Some("md".into()))?
                .into_inner();

            // The gutter is full of its own `#L1` anchors, so only the code rows are the subject.
            let (_, code) = html
                .split_once(r#"<div class="src-code">"#)
                .expect("rendered rows");

            assert!(
                !code.contains("<a href"),
                "{target} was turned into an anchor: {code}"
            );
            // The target is still readable, just not clickable.
            assert!(code.contains("click"), "{target} lost its text: {code}");
        }

        Ok(())
    }

    /// Browsers drop tabs and newlines before resolving a URL, so a scheme may be spelled with
    /// them in between. The markdown syntax happens to tokenise those spellings apart before they
    /// reach the emitter, so the predicate is checked on its own rather than through a paste.
    #[test]
    fn a_scheme_spelled_with_control_characters_is_not_navigable() {
        for target in [
            "java\tscript:alert(1)",
            "java\nscript:alert(1)",
            "java\rscript:alert(1)",
            "  javascript:alert(1)",
            "jav\u{0}ascript:alert(1)",
        ] {
            assert!(
                !is_navigable_target(target),
                "{target:?} was accepted as navigable"
            );
        }
    }

    /// The ordinary case must keep working, including a relative target.
    #[test]
    fn a_navigable_link_target_still_gets_one() -> Result<(), Box<dyn std::error::Error>> {
        let highlighter = Highlighter::default();

        for target in [
            "https://example.com/a",
            "http://example.com",
            "mailto:someone@example.com",
            "./relative/path",
        ] {
            let html = highlighter
                .highlight(format!("[click]({target})"), Some("md".into()))?
                .into_inner();

            assert!(
                html.contains(&format!(r#"<a href="{target}">"#)),
                "{target} lost its anchor: {html}"
            );
        }

        Ok(())
    }

    /// Per-row HTML must be self-balanced: every `</span>` should have a matching `<span>`
    /// earlier on the same row. Returns the minimum running balance encountered.
    fn min_span_balance(row: &str) -> isize {
        let bytes = row.as_bytes();
        let mut i = 0;
        let mut balance: isize = 0;
        let mut min_balance: isize = 0;
        while i < bytes.len() {
            let rest = &row[i..];
            if rest.starts_with("</span>") {
                balance -= 1;
                if balance < min_balance {
                    min_balance = balance;
                }
                i += "</span>".len();
            } else if rest.starts_with("<span") && matches!(bytes.get(i + 5), Some(b' ' | b'>')) {
                balance += 1;
                i += rest.find('>').map_or(1, |c| c + 1);
            } else {
                i += 1;
            }
        }
        assert_eq!(balance, 0, "row not balanced: {row}");
        min_balance
    }

    #[test]
    fn rows_are_self_balanced_for_markdown_lists() -> Result<(), Box<dyn std::error::Error>> {
        let highlighter = Highlighter::default();
        let text = "## Features\n\n\
            * [axum](https://github.com/tokio-rs/axum) and [sqlite3](https://www.sqlite.org) backend\n\
            * comes as a single binary with low memory footprint\n";
        let html = highlighter
            .highlight(text.into(), Some("md".into()))?
            .into_inner();

        for row in html.split("</div>").filter(|s| s.contains("id=\"LC")) {
            assert!(
                min_span_balance(row) >= 0,
                "row has unmatched </span>: {row}"
            );
        }
        Ok(())
    }

    #[test]
    fn markdown_link_is_well_nested() -> Result<(), Box<dyn std::error::Error>> {
        let highlighter = Highlighter::default();
        let html = highlighter
            .highlight("[hi](https://example.com)".into(), Some("md".into()))?
            .into_inner();

        assert!(
            !html.contains("</span></a>"),
            "anchor must close before its enclosing span: {html}"
        );
        Ok(())
    }
}
