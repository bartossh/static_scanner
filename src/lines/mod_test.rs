use crate::lines::LinesEnds;

mod tests {
    use crate::lines::LinesEndsProvider;

    use super::*;

    #[test]
    fn it_should_get_proper_lines_number() {
        let text = r#"1234567890
1234567890
1234567890
1234567890
1234567890
1234567890
1234567890
1234567890
1234567890
1234567890
1234567890
1234567890
1234567890
1234567890
1234567890
1234567890
1234567890
1234567890
1234567890
"#;

        let lines_ends = LinesEnds::from_str(&text);
        let mut line: usize = 1;
        for i in (5..185).step_by(10) {
            let Some(calc_line) = lines_ends.get_line(i) else {
                continue;
            };
            assert_eq!(calc_line, line);
            line += 1;
        }
    }
}
