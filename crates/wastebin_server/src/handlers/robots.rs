/// Return robots.txt content.
#[must_use]
pub async fn get() -> &'static str {
    r"User-agent: *
Disallow: /"
}
