/// Cleans up large spaces in the buffer string.
///
pub fn cleanup_large_spaces(buf: &str) -> String {
    let mut s: String = String::with_capacity(buf.len());
    let mut got_space = false;
    for c in buf.chars() {
        if (c == ' ' || c == '\t') && got_space {
            continue;
        }
        if c == ' ' || c == '\t' {
            got_space = true;
            s.push(' ');
            continue;
        }
        got_space = false;
        s.push(c)
    }
    s.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_should_remove_unnecessary_tabs_and_spaces() {
        struct TestCase {
            given: String,
            expected: String,
        }

        let test_cases: [TestCase; 4] = [
            TestCase {
                given: "This   has    tabs     to      remove.     ".to_string(),
                expected: "This has tabs to remove.".to_string(),
            },
            TestCase {
                given: "        This   has    spaces     to      remove.     ".to_string(),
                expected: "This has spaces to remove.".to_string(),
            },
            TestCase {
                given: " This has spaces to trim. ".to_string(),
                expected: "This has spaces to trim.".to_string(),
            },
            TestCase {
                given: "This s s has s s s no spaces s s s s to s s s s s remove.".to_string(),
                expected: "This s s has s s s no spaces s s s s to s s s s s remove.".to_string(),
            },
        ];
        for test_case in test_cases.iter() {
            let result = cleanup_large_spaces(&test_case.given);
            assert_eq!(result, test_case.expected);
        }
    }
}
