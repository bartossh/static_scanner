use std::fmt::Debug;

#[cfg(test)]
mod mod_test;

/// Lines ends provider provides numner of line if can be calculated or None otherwise.
///
pub trait LinesEndsProvider: Debug {
    fn get_line(&self, start: usize) -> Option<usize>;
}

#[derive(Debug)]
pub struct LinesEnds {
    inner: Vec<usize>,
}

impl LinesEnds {
    #[inline(always)]
    pub fn from_str(buf: &str) -> impl LinesEndsProvider {
        let mut inner = Vec::new();
        let mut end = 0;
        for l in buf.lines() {
            end += l.chars().count();
            inner.push(end);
        }

        Self {inner}
    }
}

impl LinesEndsProvider for LinesEnds {
    #[inline(always)]
    fn get_line(&self, start: usize) -> Option<usize> {
        for (l, end) in self.inner.iter().enumerate() {
            if start < *end {
                return Some(l + 1);
            }
        }
        None
    }
}
