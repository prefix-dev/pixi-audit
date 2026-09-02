//! A minimal column-aligned grid: a header row, cells padded to the widest
//! value in their column, two spaces between columns. No borders, like
//! `pixi list` and grype.

use iocraft::prelude::*;

/// One styled run of text inside a cell.
#[derive(Debug, Clone, Default)]
pub struct Span {
    pub text: String,
    pub color: Option<Color>,
    pub weight: Weight,
    pub hyperlink: Option<String>,
}

impl Span {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            ..Default::default()
        }
    }

    pub fn color(mut self, color: impl Into<Option<Color>>) -> Self {
        self.color = color.into();
        self
    }

    pub fn weight(mut self, weight: Weight) -> Self {
        self.weight = weight;
        self
    }

    pub fn hyperlink(mut self, url: Option<String>) -> Self {
        self.hyperlink = url;
        self
    }
}

/// One rendered cell: a sequence of spans, so a marker and a name can carry
/// different styles in the same column.
#[derive(Debug, Clone, Default)]
pub struct Cell {
    pub spans: Vec<Span>,
}

impl Cell {
    /// A cell holding one span of `text`.
    pub fn new(text: impl Into<String>) -> Self {
        Self::from(Span::new(text))
    }

    /// An empty cell, for values the row does not have.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Appends another span.
    pub fn then(mut self, span: Span) -> Self {
        self.spans.push(span);
        self
    }

    /// Styles the last span; convenience for single-span cells.
    pub fn color(self, color: impl Into<Option<Color>>) -> Self {
        self.map_last(|span| span.color(color))
    }

    pub fn weight(self, weight: Weight) -> Self {
        self.map_last(|span| span.weight(weight))
    }

    pub fn hyperlink(self, url: Option<String>) -> Self {
        self.map_last(|span| span.hyperlink(url))
    }

    fn map_last(mut self, f: impl FnOnce(Span) -> Span) -> Self {
        if let Some(last) = self.spans.pop() {
            self.spans.push(f(last));
        }
        self
    }

    fn width(&self) -> usize {
        self.spans
            .iter()
            .map(|span| span.text.chars().count())
            .sum()
    }
}

impl From<Span> for Cell {
    fn from(span: Span) -> Self {
        Self { spans: vec![span] }
    }
}

/// Lays out `rows` under `headers`. Every row must have one cell per header.
pub fn grid(headers: &[&'static str], rows: Vec<Vec<Cell>>) -> Element<'static, View> {
    let widths: Vec<u32> = headers
        .iter()
        .enumerate()
        .map(|(i, header)| {
            rows.iter()
                .map(|row| row[i].width())
                .max()
                .unwrap_or(0)
                .max(header.len()) as u32
        })
        .collect();
    let header_cells: Vec<(&'static str, u32)> = headers
        .iter()
        .copied()
        .zip(widths.iter().copied())
        .collect();
    let body: Vec<Vec<(Cell, u32)>> = rows
        .into_iter()
        .map(|row| row.into_iter().zip(widths.iter().copied()).collect())
        .collect();

    element! {
        View(flex_direction: FlexDirection::Column) {
            View(gap: 2) {
                #(header_cells.into_iter().map(|(header, width)| element! {
                    View(width: width) {
                        Text(content: header, weight: Weight::Bold, color: Color::Cyan, wrap: TextWrap::NoWrap)
                    }
                }))
            }
            #(body.into_iter().map(|row| element! {
                View(gap: 2) {
                    #(row.into_iter().map(|(cell, width)| element! {
                        View(width: width) {
                            #(cell.spans.into_iter().map(|span| element! {
                                Text(
                                    content: span.text,
                                    color: span.color,
                                    weight: span.weight,
                                    hyperlink: span.hyperlink,
                                    wrap: TextWrap::NoWrap,
                                )
                            }))
                        }
                    }))
                }
            }))
        }
    }
}
