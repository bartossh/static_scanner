pub mod secret;
use aho_corasick::AhoCorasick;

pub fn dummy_aho_count(s: &str, patterns: &[String]) -> usize {
    let ac = AhoCorasick::new(patterns).unwrap();
    let mut counter = 0;
    ac.find_iter(s).for_each(|_| counter += 1);
    counter
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_should_find_all_existing_patterns() {
        struct TestCase<'a> {
            input: &'a str,
            patterns: Vec<String>,
            result: usize,
        }

        let test_cases: [TestCase; 2] = [
            TestCase {
                input: "Nobody likes maple in their apple flavored Snapple.",
                patterns: vec![
                    "apple".to_string(),
                    "maple".to_string(),
                    "Snapple".to_string(),
                ],
                result: 3,
            },
            TestCase {
                input: "On the other hand, we denounce with righteous indignation and dislike men who are so beguiled and demoralized by the charms of pleasure of the moment, so blinded by desire, that they cannot foresee the pain and trouble that are bound to ensue; and equal blame belongs to those who fail in their duty through weakness of will, which is the same as saying through shrinking from toil and pain. These cases are perfectly simple and easy to distinguish. In a free hour, when our power of choice is untrammelled and when nothing prevents our being able to do what we like best, every pleasure is to be welcomed and every pain avoided. But in certain circumstances and owing to the claims of duty or the obligations of business it will frequently occur that pleasures have to be repudiated and annoyances accepted. The wise man therefore always holds in these matters to this principle of selection: he rejects pleasures to secure other greater pleasures, or else he endures pains to avoid worse pains.",
                patterns: vec![
                    "charms".to_string(),
                    "hand".to_string(),
                    "indignation".to_string(),
                ],
                result: 3,
            },
        ];

        test_cases.iter().for_each(|tc| {
            let result = dummy_aho_count(&tc.input, &tc.patterns);
            assert_eq!(result, tc.result)
        });
    }
}
