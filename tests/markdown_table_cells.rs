//! Every markdown table in this repository must render with all the text its source holds.
//!
//! GitHub Flavored Markdown splits a table row into cells on every `|` *before* it parses any
//! inline syntax (GFM spec §4.10), so a code span is no shelter: `` `--proto tcp|udp` `` is two
//! cells, not one. Two things then go wrong, and only the first is obvious:
//!
//! - In the **body**, "if a row has more cells than the header, the excess is ignored" — a
//!   three-column table given a four-cell row renders the first three and silently drops the rest
//!   of the line. (A row with *fewer* cells is fine; the spec pads it with empty ones, and nothing
//!   is lost. This guard does not object to those.)
//! - In the **header**, the delimiter row must have exactly as many cells as the header row or the
//!   block is not a table at all. One stray `|` up there and the whole thing renders as a paragraph
//!   of pipes — worse than the body case, and just as quiet.
//!
//! Neither is a cosmetic wart; both are data loss with no warning anywhere. The source file still
//! holds the sentence, `git diff` still shows it, and the rendered page a reader actually consults
//! stops mid-word. The body case reached this repository already —
//! `docs/PARITY_GAP_ANALYSIS.md`'s whois row writes Go's flag as `` `--proto tcp|udp` ``, and
//! everything after `tcp` vanishes from the rendered ledger, including the pointer to §6 that tells
//! a reader which half of the gap the row is about. The escape is one character (`tcp\|udp`), which
//! is exactly why nobody notices it is missing.
//!
//! So the rule is checked instead of remembered. Every prose document in the repository is embedded
//! with [`include_str!`] — the same trick `tests/engine_doc_publish_verdicts.rs`,
//! `tests/design_deferral_taxonomy.rs` and `tests/parity_audit_ledger.rs` use to hold a document to
//! something firmer than the next editor's eye — each of its table rows is split the way the
//! renderer will split it, and every header is counted against the delimiter row beneath it.
//!
//! One row is a recorded exception rather than a fix; [`KNOWN_SPLIT_ROWS`] says which and why, and
//! [`the_recorded_exception_is_still_needed`] deletes itself by failing once that row is repaired.

/// Every prose document in the repository, by repository-relative path.
///
/// Not just the seven that hold a table today: a table added to `CONTRIBUTING.md` tomorrow should
/// be covered the moment it is written, not the moment someone remembers this list exists.
///
/// `CHANGELOG.md` is out because release-please writes it, and the two beads files
/// (`.beads/README.md`, `.agents/skills/beads/SKILL.md`) are out because the tool vendors them —
/// the second is not even present in a fresh checkout, so `include_str!` could not read it.
const DOCS: &[(&str, &str)] = &[
    ("README.md", include_str!("../README.md")),
    ("AGENTS.md", include_str!("../AGENTS.md")),
    ("CLAUDE.md", include_str!("../CLAUDE.md")),
    ("CONTRIBUTING.md", include_str!("../CONTRIBUTING.md")),
    ("SECURITY.md", include_str!("../SECURITY.md")),
    (
        "docs/CONFIGURE_SCOPE.md",
        include_str!("../docs/CONFIGURE_SCOPE.md"),
    ),
    ("docs/DESIGN.md", include_str!("../docs/DESIGN.md")),
    ("docs/ENGINE.md", include_str!("../docs/ENGINE.md")),
    (
        "docs/ENGINE_ASKS.md",
        include_str!("../docs/ENGINE_ASKS.md"),
    ),
    (
        "docs/FILE_CP_PARITY.md",
        include_str!("../docs/FILE_CP_PARITY.md"),
    ),
    (
        "docs/PARITY_GAP_ANALYSIS.md",
        include_str!("../docs/PARITY_GAP_ANALYSIS.md"),
    ),
    ("docs/TESTING.md", include_str!("../docs/TESTING.md")),
    (
        "docs/THREAT_MODEL.md",
        include_str!("../docs/THREAT_MODEL.md"),
    ),
    (
        "packaging/README.md",
        include_str!("../packaging/README.md"),
    ),
    (
        "packaging/homebrew/README.md",
        include_str!("../packaging/homebrew/README.md"),
    ),
    (
        "test-support/headscale/README.md",
        include_str!("../test-support/headscale/README.md"),
    ),
];

/// Rows that split today and are *not* repaired by this change, keyed by document and by the text
/// their first cell starts with (a line number would be stale within a week — §4.5 of the parity
/// ledger is rewritten by nearly every pass).
///
/// `docs/PARITY_GAP_ANALYSIS.md`'s whois row is deferred, not defended. Two things are true about
/// it: the unescaped pipe truncates the rendered cell, *and* the row is stale — its first cell
/// still asserts "`tnet whois` has no `--proto`, and no `ip[:port]` form", which stopped being true
/// when `whois` grew both (`tests/whois_flow_arguments.rs`). That first cell renders today,
/// unaffected by the pipe, so escaping the pipe would not mislead anyone who is not already misled;
/// the reason to wait is that the real repair is a rewrite of the row, and rewrites of §4.5 belong
/// to the pass that owns the ledger, which cannot take a second concurrent branch on the same
/// lines. The escape lands with that rewrite. Until then the row is recorded here so it cannot be
/// quietly forgotten.
const KNOWN_SPLIT_ROWS: &[(&str, &str)] = &[(
    "docs/PARITY_GAP_ANALYSIS.md",
    "`tnet whois` has no `--proto`, and no `ip[:port]` form",
)];

/// What went wrong with one line of one table.
#[derive(Debug, PartialEq, Eq)]
enum Defect {
    /// A body row with more cells than its header. The renderer keeps `header_cells` of them and
    /// discards `dropped`.
    RowOverflows {
        header_cells: usize,
        row_cells: usize,
        /// The cells past the header's width — the text the renderer throws away.
        dropped: String,
    },
    /// A header row whose width disagrees with the delimiter row beneath it. GFM then does not
    /// recognise the block as a table at all, so *every* line of it renders as literal pipes.
    HeaderWidthMismatch {
        header_cells: usize,
        delimiter_cells: usize,
    },
}

/// One offending line, located.
#[derive(Debug)]
struct TableDefect {
    doc: &'static str,
    line: usize,
    /// The line's first cell, trimmed: what [`KNOWN_SPLIT_ROWS`] matches on.
    first_cell: String,
    defect: Defect,
}

impl TableDefect {
    /// The failure text a reader gets: where it is, what the renderer does with it, and the repair.
    fn explain(&self) -> String {
        match &self.defect {
            Defect::RowOverflows {
                header_cells,
                row_cells,
                dropped,
            } => format!(
                "{}:{} — header declares {header_cells} columns, this row splits into {row_cells}. \
                 The renderer keeps the first {header_cells} and DROPS: {}\n    Escape the `|` as \
                 `\\|` (a code span does not protect it), or reword the cell.",
                self.doc,
                self.line,
                dropped.trim(),
            ),
            Defect::HeaderWidthMismatch {
                header_cells,
                delimiter_cells,
            } => format!(
                "{}:{} — this header row splits into {header_cells} cells but its delimiter row \
                 declares {delimiter_cells}. They must agree, so GFM does not render this block as \
                 a table at all — the whole thing comes out as a paragraph of pipes.\n    Escape \
                 the stray `|` as `\\|` (a code span does not protect it), or widen the delimiter \
                 row.",
                self.doc, self.line,
            ),
        }
    }
}

/// Split one table line into cells the way the renderer does: on every `|` that is not
/// backslash-escaped, with no regard for code spans, emphasis or links, because GFM performs this
/// split before it parses any of them. A leading or trailing `|` is optional delimiter syntax and
/// contributes no cell.
fn cells(line: &str) -> Vec<String> {
    let line = line.trim();
    let mut out = vec![String::new()];
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            out.last_mut().expect("`out` is never empty").push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => {
                out.last_mut().expect("`out` is never empty").push(ch);
                escaped = true;
            }
            '|' => out.push(String::new()),
            _ => out.last_mut().expect("`out` is never empty").push(ch),
        }
    }
    // The outer pipes each produced one exactly-empty element; a cell that is merely *blank*
    // (`|  | b |`) keeps its spaces and survives, as it does in the renderer.
    if out.first().is_some_and(String::is_empty) {
        out.remove(0);
    }
    if out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out
}

/// A GFM delimiter row: every cell is dashes, optionally fenced by alignment colons.
fn is_delimiter_row(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells.iter().all(|cell| {
            let cell = cell.trim().trim_start_matches(':').trim_end_matches(':');
            !cell.is_empty() && cell.chars().all(|ch| ch == '-')
        })
}

fn first_cell(cells: &[String]) -> String {
    cells
        .first()
        .map(|cell| cell.trim().to_string())
        .unwrap_or_default()
}

/// Every line in `doc` that a renderer would truncate or refuse to make a table of.
fn table_defects(doc: &'static str, text: &str) -> Vec<TableDefect> {
    let mut found = Vec::new();
    let mut fenced = false;
    // `Some(n)` only while inside a table body, so a stray pipe in prose is never a "row".
    let mut expected: Option<usize> = None;
    // The last pipe-prefixed line seen, as `(1-based line, cells)`. When a delimiter row turns up
    // it is that line's header, and the two widths have to agree.
    let mut previous: Option<(usize, Vec<String>)> = None;

    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with("```") || line.starts_with("~~~") {
            fenced = !fenced;
            expected = None;
            previous = None;
            continue;
        }
        if fenced {
            continue;
        }
        if !line.starts_with('|') {
            expected = None;
            previous = None;
            continue;
        }

        let row = cells(line);
        if is_delimiter_row(&row) {
            // Only the delimiter that *opens* a table has a header above it; an all-dashes line in
            // a body is a body row, and comparing it to the row before would invent a defect.
            if expected.is_none()
                && let Some((header_line, header)) = previous.take()
                && header.len() != row.len()
            {
                found.push(TableDefect {
                    doc,
                    line: header_line,
                    first_cell: first_cell(&header),
                    defect: Defect::HeaderWidthMismatch {
                        header_cells: header.len(),
                        delimiter_cells: row.len(),
                    },
                });
            }
            expected = Some(row.len());
            previous = None;
            continue;
        }
        previous = Some((index + 1, row.clone()));

        let Some(header_cells) = expected else {
            continue;
        };
        // Only *excess* cells are discarded. A short row is padded with empty cells and loses
        // nothing, so it is not this guard's business.
        if row.len() > header_cells {
            found.push(TableDefect {
                doc,
                line: index + 1,
                first_cell: first_cell(&row),
                defect: Defect::RowOverflows {
                    header_cells,
                    row_cells: row.len(),
                    dropped: row[header_cells..].join("|"),
                },
            });
        }
    }
    found
}

/// Every defect across every document, in the order the documents are declared.
fn all_table_defects() -> Vec<TableDefect> {
    DOCS.iter()
        .flat_map(|(path, text)| table_defects(path, text))
        .collect()
}

fn is_known(defect: &TableDefect) -> bool {
    KNOWN_SPLIT_ROWS
        .iter()
        .any(|(doc, first_cell)| *doc == defect.doc && defect.first_cell.starts_with(first_cell))
}

/// The guard itself: a table that the renderer would truncate — or refuse to draw — is a defect,
/// unless it is the row recorded in [`KNOWN_SPLIT_ROWS`].
#[test]
fn no_table_in_this_repository_loses_text_when_rendered() {
    let offenders: Vec<String> = all_table_defects()
        .iter()
        .filter(|defect| !is_known(defect))
        .map(TableDefect::explain)
        .collect();

    assert!(
        offenders.is_empty(),
        "{} markdown table line(s) lose text when rendered:\n\n{}",
        offenders.len(),
        offenders.join("\n\n"),
    );
}

/// The self-retiring half. `KNOWN_SPLIT_ROWS` is a deferral, not a licence: once the ledger pass
/// rewrites the whois row, this fails and the entry has to go with it — which is the only way a
/// recorded exception stays honest. Each entry is checked against the row it names, not against
/// "some surviving defect in that document", so a second entry cannot hide behind the first.
#[test]
fn the_recorded_exception_is_still_needed() {
    let defects = all_table_defects();
    for (doc, first_cell) in KNOWN_SPLIT_ROWS {
        assert!(
            defects
                .iter()
                .any(|defect| defect.doc == *doc && defect.first_cell.starts_with(first_cell)),
            "`{doc}`'s row starting `{first_cell}` no longer breaks its table — good. Delete its \
             entry from `KNOWN_SPLIT_ROWS` so the guard covers that row unconditionally.",
        );
    }
}

/// The splitter has to agree with the renderer about what a cell is, or the guard measures the
/// wrong thing. Pinned on the shape that started this: a pipe inside a code span is a delimiter,
/// and the backslash escape is what makes it text again.
#[test]
fn cells_split_the_way_gfm_splits_them() {
    assert_eq!(cells("| a | b | c |").len(), 3, "plain three-column row");
    assert_eq!(cells("| a | b | c").len(), 3, "trailing pipe is optional");
    assert_eq!(
        cells("|  | b | c |").len(),
        3,
        "a blank cell is still a cell"
    );
    assert_eq!(
        cells("| `--proto tcp|udp` | b | c |").len(),
        4,
        "a code span does not protect a pipe — this is the defect the guard exists for",
    );
    assert_eq!(
        cells(r"| `--proto tcp\|udp` | b | c |").len(),
        3,
        "the backslash escape is what makes it one cell again",
    );
}

/// And the scanner has to find that shape in a document, inside a table and nowhere else.
#[test]
fn the_scanner_reports_the_split_row_and_ignores_prose_and_code() {
    let doc = "\
| Item | Note |
| --- | --- |
| fine | ok |
| broken | `tcp|udp` |

Prose with a | pipe in it is not a row.

```
| not | a | table | at | all |
```
";
    let found = table_defects("test.md", doc);
    assert_eq!(found.len(), 1, "exactly the one broken row: {found:#?}");
    assert_eq!(found[0].line, 4);
    assert_eq!(
        found[0].defect,
        Defect::RowOverflows {
            header_cells: 2,
            row_cells: 3,
            dropped: "udp` ".to_string(),
        },
        "the reported loss is the text the renderer throws away",
    );
}

/// A row *shorter* than its header is legal GFM — the renderer inserts the missing cells and no
/// text is lost — so reporting it would be a false alarm with no repair to offer.
#[test]
fn a_row_shorter_than_its_header_is_not_a_defect() {
    let doc = "\
| a | b | c |
| --- | --- | --- |
| only one |
| two | cells |
";
    assert_eq!(
        table_defects("test.md", doc).len(),
        0,
        "short rows are padded, not truncated",
    );
}

/// The header case, which is the worse of the two: a stray pipe up there and GFM never sees a
/// table, so the delimiter row and every body row render as literal pipes.
#[test]
fn a_header_that_disagrees_with_its_delimiter_row_is_reported() {
    let doc = "\
| `tcp|udp` | Note |
| --- | --- |
| a | b |
";
    let found = table_defects("test.md", doc);
    assert_eq!(found.len(), 1, "exactly the header: {found:#?}");
    assert_eq!(found[0].line, 1);
    assert_eq!(
        found[0].defect,
        Defect::HeaderWidthMismatch {
            header_cells: 3,
            delimiter_cells: 2,
        },
    );
    assert!(
        found[0]
            .explain()
            .contains("does not render this block as a table"),
        "the message has to name the failure mode, which is not truncation: {}",
        found[0].explain(),
    );
}

/// A well-formed table produces nothing at all — the guard is only as useful as its silence.
#[test]
fn a_well_formed_table_is_silent() {
    let doc = "\
| Item | Note |
| :-- | --: |
| a | b |
| `tcp\\|udp` | escaped, so one cell |
";
    let found = table_defects("test.md", doc);
    assert!(found.is_empty(), "nothing to report here: {found:#?}");
}
