use criterion::{criterion_group, criterion_main, Criterion};
use crossbeam_channel::unbounded;
use rogue::{detectors::{Scanner, regex::Builder}, lines::{LinesEndsProvider, LinesEnds}};


const TEST_CRIME_AWS_GCP: &str = r#"
[default]
aws_access_key_id=ASIAIOSFODNN7EXAMPLE
aws_secret_access_key =wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_session_token = IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZVERYLONGSTRINGEXAMPLE

[user1]
aws_access_key_id= ASIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
aws_session_token=fcZib3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZVERYLONGSTRINGEXAMPLE

[
  {
    "type": "service_account",
    "project_id": "",
    "private_key_id": "1234567890",
    "private_key": "-----BEGIN PRIVATE KEY-----MIIBWgIBADCCATMGByqGSM44BAEwggEmAoGBANnjjqR/ZTyjbyT5tRt/QJbX4imO0133m4dr6GHqufhL38S0m5duefYkSOB56njVVInEgdCnvupWcNH06FuxFNFopQkjn7z1PfsCOTL9Ar6DmHW0D94pt8HOaPEqTP1xgy2p93e8r5Wr1BPL2PdClTgtRUFcNGJitTAB7o1QjbznAh0AiZKwMNhX/fGhVWzdeocxdZeDGq+VWs0cIUKmkQKBgFHExnrSQvguEFJZZmPzRuGCjl12xHdAk2O8e7PEe5OSweE8bAIUguLQroVYu+wAEYM8iNW/SwfU2XwpolV0J74/UO/4952hUd6caWfLFZG5aI8/+4QdMpKeIgazgpMo3d0sI9DY1Y6dbbMrdWC1BGn66CGWt4m/V4LlSNFdlIc2BB4CHA0WiwYund93kHt8N0cwM4Jbg9fpDtwVfTMEiIU=-----END PRIVATE KEY-----\n",
    "client_email": "",
    "client_id": "",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": ""
  },
  {
    "type": "service_account",
    "project_id": "",
    "private_key_id": "9876543210",
    "private_key": "-----BEGIN PRIVATE KEY-----MIIBWgIBADCCATMGByqGSM44BAEwggEmAoGBANnjjqR/ZTyjbyT5tRt/QJbX4imO0133m4dr6GHqufhL38S0m5duefYkSOB56njVVInEgdCnvupWcNH06FuxFNFopQkjn7z1PfsCOTL9Ar6DmHW0D94pt8HOaPEqTP1xgy2p93e8r5Wr1BPL2PdClTgtRUFcNGJitTAB7o1QjbznAh0AiZKwMNhX/fGhVWzdeocxdZeDGq+VWs0cIUKmkQKBgFHExnrSQvguEFJZZmPzRuGCjl12xHdAk2O8e7PEe5OSweE8bAIUguLQroVYu+wAEYM8iNW/SwfU2XwpolV0J74/UO/4952hUd6caWfLFZG5aI8/+4QdMpKeIgazgpMo3d0sI9DY1Y6dbbMrdWC1BGn66CGWt4m/V4LlSNFdlIc2BB4CHA0WiwYund93kHt8N0cwM4Jbg9fpDtwVfTMEiIU=-----END PRIVATE KEY-----\n",
    "client_email": "",
    "client_id": "",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": ""
  }
]
"#;

fn benchmark_generic_detector_create_scanner(c: &mut Criterion) {
    c.bench_function(
        "benchmark_generic_detector_create_scanner",
        |b| {
            b.iter(|| {
                let Ok(_scanner) = Builder::new().
                    with_secret_regexes(&[r#"KEY-----[\a-zA-Z0-9]*-----END"#])
                    .with_keys_required(&["auth_provider_x509_cert_url"])
                    .with_variables(&["auth_uri", "token_uri","auth_provider_x509_cert_url"], &[r#"https://[a-zA-Z-0-9./]*"#]).try_build_scanner() else {
                            assert!(false);
                            return;
                        };
            });
        }
    );
}

#[derive(Debug)]
struct LinesEnd{}

impl LinesEndsProvider for LinesEnd {
    #[inline(always)]
    fn get_line(&self, _: usize) -> Option<usize> {
        return None;
    }
}

fn benchmark_generic_detector_scan_with_scanner(c: &mut Criterion) {
    let line_ends = LinesEnd{};

    c.bench_function(
        "benchmark_generic_detector_scan_with_scanner",
        |b| {
            let Ok(scanner) = Builder::new().
                with_secret_regexes(&[r#"KEY-----[\a-zA-Z0-9]*-----END"#])
                .with_keys_required(&["auth_provider_x509_cert_url"])
                .with_variables(&["auth_uri", "token_uri","auth_provider_x509_cert_url"], &[r#"https://[a-zA-Z-0-9./]*"#]).try_build_scanner() else {
                        assert!(false);
                        return;
                    };
            let (sx, _) = unbounded();
            b.iter(|| {
                scanner.scan(&line_ends, TEST_CRIME_AWS_GCP, "benchmark_generic_detector_v2_scan_with_scanner", "---- test", sx.clone());
            });
        }
    );
}

fn benchmark_line_calculation(c: &mut Criterion) {
    let mut text = String::new();

    for _ in 0..100 {
        text.push_str("12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\n")
    }

    c.bench_function(
        "benchmark_line_calculation",
        |b| {
            b.iter(|| {
                LinesEnds::from_str(&text);
            });
        }
    );
}

fn benchmark_get_line(c: &mut Criterion) {
    let mut text = String::new();

    for _ in 0..100 {
        text.push_str("12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\n")
    }

    c.bench_function(
        "benchmark_get_line",
        |b| {
            let lines_ends = LinesEnds::from_str(&text);

            b.iter(|| {
                for i in (100..20000).step_by(200) {
                    let Some (_) = lines_ends.get_line(i) else {
                        println!("exhaused");
                        break;
                    };
                }
            });
        }
    );
}

criterion_group!(
    benches,
    benchmark_generic_detector_create_scanner,
    benchmark_generic_detector_scan_with_scanner,
    benchmark_line_calculation,
    benchmark_get_line,
);
criterion_main!(benches);
