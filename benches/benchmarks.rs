use criterion::{criterion_group, criterion_main, Criterion};
use paton::preprocessor::cleanup_large_spaces;
use paton::secret::Inspector;
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

const TEST_CRIME_TWITTER: &str = r#"
[
  {
    "Api Key":                "5PAgMqo1gXn7QyHzzGASDFN9Q",
    "Api Key Secret":         "PDrhKbxeYhxeWz6R1UddxdJFXCRsZadTtsDmwlUBxPGB4bU2aU",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAINuBw0mowW3KpPh0zxGB2vgGY7g%3DXePv83wPJ5VOvROMkfGwkPtptd5w9xAAGUHrgfkhppjXA2JWN5",
    "Access Token":           "955116647488028672-NvXaA5BEnf9gYAcK40hNZGTbPdlwmaU",
    "Access Token Secret":    "H1xeoEa7i6PnarMvpKIz2WiVgqJetEmnMRlRBVaZrOekd"
  },
  {
    "Api Key":                "IwSJrHZeuP1Hl9Edz9VQyqT7x",
    "Api Key Secret":         "hR7vHE72b5IIoKGh0icOBprExoZkamRrvjidXDadn5gudqff6z",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAwi3BY9v2NbI1%2BsINLKs0gNCF%2Fio%3DRwh43tAmNVdRVTzkvUx29gQ0exqGtFaQyTffzI1juiicxuT2W7",
    "Access Token":           "955116647488028672-dde5wWYS29lJUVaKoktDvyMlJS0zsKY",
    "Access Token Secret":    "BRyuRAFLPwQH1W0vIQlVxcJvbfOUV5j5xdUj4KbALU8RC"
  },
  {
    "Api Key":                "PyjocY7kHdiekmGsi6ndao2hR",
    "Api Key Secret":         "16hHCNCpykZliz6juLF5xkHuGniueh4PFRRjKLLnfhuuNjJPyE",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAASO6z6R5Iw8rIb8cCspGTp%2B6ERwo%3Dvt0hpY8WXq0HJisC9aikQn8ocDZLEIXSdoLTezIBcFlzLUkzJY",
    "Access Token":           "955116647488028672-RdYFDr6FkMrZN4bk3O4stZj3xqDc7AM",
    "Access Token Secret":    "69yZI4oq1IZXEtr2T6BQo05KqQLadzphmEqrI5rWRUHW7"
  },
  {
    "Api Key":                "oYBUjCeergTCyrbvhGhMQ6vG4",
    "Api Key Secret":         "sp1mizKQPorh0UCCL0G6WZVvtD15ourLcTOKutSiYywCl851QX",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAZv3%2BaU5t0Vtzwxa69CpXFLcG72E%3DqYWvGr4WKYaebn6qypSsRw3xzMvK1g4KciyYVqrPYwMVvPAgzL",
    "Access Token":           "955116647488028672-VPc28faQNZtHp0fikUhNFAcophLbcBH",
    "Access Token Secret":    "1zJUU8Nfeg0JyFNGGl3HqiW4eHvCD9PWRSINmdUBx4SXg"
  },
  {
    "Api Key":                "04NoreYdRRE7JyYSTagqUIhkm",
    "Api Key Secret":         "WfRLkulliRNtWaTEGmoTllgyB01di83cnRjPNMBGpkpGgd6SM0",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAEBVfpu94kepJoMULqERWxIL7g68%3DC3Jy2zaUnTrHNxZNRSrlOCIOjoBVyPDILDaffVoxxcQzwkPoGj",
    "Access Token":           "955116647488028672-iIPUHS2KA6t2A1MMuA71e9ujmrvLfo6",
    "Access Token Secret":    "QDmKy2R8Sy3owzAU5fn6Fm6nXQqvChybdp5Ha4zIy5jT9"
  },
  {
    "Api Key":                "53kDReVLIm9ekk7a7kWHxdQ6c",
    "Api Key Secret":         "f7a1xMAUjJMsd76SyfuqxIZiZvFDXTkaLE0OHaPZDpcG7YJ2Rb",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAM%2BcWWEICaBtt9kG6ho8WK9I%2FoTk%3DX3U2VpxkKYUEikurhLgV9HmuwMS61Pz94dp9IQkVJ1RAFNNFKi",
    "Access Token":           "955116647488028672-pTjShSi8sMSrBjMIvZH2cs8glCayepI",
    "Access Token Secret":    "hJGLZDjVIRBLu5v3YxMg7GzQ36GbJ1eW2zhCkwsHYSD0H"
  },
  {
    "Api Key":                "LPTtKbnTGgnzj4XrCBCYSqRcP",
    "Api Key Secret":         "nahpwSPzIsg14Z43O9o9anKbuCWYL6ZyjymrJDxngMxRLFxKfR",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAU7sfX1jG7feA1J3x%2FLOG4eioLy0%3DqW2ryZPU3PPo8yajka1CKgEDSFMjPRQijhydINoNBRqtZZKVUq",
    "Access Token":           "955116647488028672-QoKBPDd1td4Ngyp669xvZBFLjvEqrSh",
    "Access Token Secret":    "1PO1ztph22zLU39QZxqpcKlSoSugpsZSNClSROIu9JELs"
  },
  {
    "Api Key":                "NCYWHSACCsWdyVAYXZxb5cj30",
    "Api Key Secret":         "bsipEFMsDAJLS4Ac4xB1WWOGwtT2OfLgmPO4EtNXgnJGakgOQS",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAkVMyeUwCzFuIkozZ%2BWvu4li9wZg%3D2Q3dzqJZg41Hz7IYahNuY8VbA1lAzvi0ftOYt9UcC3BTAN1ssM",
    "Access Token":           "955116647488028672-v09GALnNJIyprRoly7y35ppWOT8cTuJ",
    "Access Token Secret":    "bAXEnYpxgIA9DetJPGbPRvIvOy6AugxnBQSnaYl1dvGqi"
  },
  {
    "Api Key":                "Wzd3WBYr9HhThzhFMBlYMLE9S",
    "Api Key Secret":         "K7Hw32JdwfCC3Iwgm6rgh3EUjiweyLD8L3tPC98VnDsQ715S5G",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAZVe4Znhi14HRCDDQHWZj4JhDT1I%3DUlwU7UWD90SmfWetqc2mLCl6NzaIWvTQeHusTGdvDdB0eAbtmj",
    "Access Token":           "955116647488028672-K4uKNEEep8jMHHcPLzFOWORzuK6yHX4",
    "Access Token Secret":    "5NS4g8AL56zI4rnnufTMujG0lXUk5KUAeKTjB22RFnFpl"
  },
  {
    "Api Key":                "QPLHSazDh18efjex1DCe9vqSV",
    "Api Key Secret":         "kskbOBkj7dk3h7Kee6VmVrKp8Lo4m5socnFE9Z3pOSZH7oXi0C",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAQKu0SOsxZH4b9cz0NVWkIRxfxK4%3D0aR3NAlIjohUPj1lf39LirIeSO2y4RvsDGPFRgUiFuUD52YFqR",
    "Access Token":           "955116647488028672-JKMlfU95YvQqjmAjoNsJbQjQdBUtVlA",
    "Access Token Secret":    "vW36iduHNPQAq0EZobWTDDDCmXVPC3dmzYNjc7yORkQQR"
  }
]"#;

const TEST_JSON: &str = r#"{
  "Api Key":                "5PAgMqo1gXn7QyHzzGASDFN9Q",
  "Api Key Secret":         "PDrhKbxeYhxeWz6R1UddxdJFXCRsZadTtsDmwlUBxPGB4bU2aU",
  "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAINuBw0mowW3KpPh0zxGB2vgGY7g%3DXePv83wPJ5VOvROMkfGwkPtptd5w9xAAGUHrgfkhppjXA2JWN5",
  "Access Token":           "955116647488028672-NvXaA5BEnf9gYAcK40hNZGTbPdlwmaU",
  "Access Token Secret":    "H1xeoEa7i6PnarMvpKIz2WiVgqJetEmnMRlRBVaZrOekd"
}"#;

fn benchmark_inspector_for_assets_config_aws_gcp_yaml(c: &mut Criterion) {
    c.bench_function("benchmark_inspector_for_assets_config_aws_gcp_yaml", |b| {
        let Ok(inspector) = Inspector::try_new("./assets/config.yaml") else {
            assert!(false);
            return;
        };

        b.iter(|| {
            let _ = inspector.scan(TEST_CRIME_AWS_GCP);
        });
    });
}

fn benchmark_inspector_for_assets_config_aws_yaml(c: &mut Criterion) {
    c.bench_function("benchmark_inspector_for_assets_config_aws_yaml", |b| {
        let Ok(inspector) = Inspector::try_new("./assets/config_aws.yaml") else {
            assert!(false);
            return;
        };

        b.iter(|| {
            let _ = inspector.scan(TEST_CRIME_AWS_GCP);
        });
    });
}

fn benchmark_inspector_for_assets_config_gcp_yaml(c: &mut Criterion) {
    c.bench_function("benchmark_inspector_for_assets_config_gcp_yaml", |b| {
        let Ok(inspector) = Inspector::try_new("./assets/config_gcp.yaml") else {
            assert!(false);
            return;
        };

        b.iter(|| {
            let _ = inspector.scan(TEST_CRIME_AWS_GCP);
        });
    });
}

fn benchmark_inspector_for_assets_config_twitter_yaml(c: &mut Criterion) {
    c.bench_function("benchmark_inspector_for_assets_config_twitter_yaml", |b| {
        let Ok(inspector) = Inspector::try_new("./assets/config_twitter.yaml") else {
            assert!(false);
            return;
        };

        b.iter(|| {
            let _ = inspector.scan(TEST_CRIME_TWITTER);
        });
    });
}

fn benchmark_inspector_for_assets_config_twitter_yaml_json_parse(c: &mut Criterion) {
    c.bench_function(
        "benchmark_inspector_for_assets_config_twitter_yaml_json_parse",
        |b| {
            let Ok(inspector) = Inspector::try_new("./assets/config_twitter.yaml") else {
                assert!(false);
                return;
            };

            b.iter(|| {
                let _ = inspector.scan(TEST_JSON);
            });
        },
    );
}

fn benchmark_inspector_for_cleanup_large_spaces(c: &mut Criterion) {
    c.bench_function("benchmark_inspector_for_cleanup_large_spaces", |b| {
        b.iter(|| {
            let _ = cleanup_large_spaces(TEST_CRIME_TWITTER);
        });
    });
}

criterion_group!(
    benches,
    benchmark_inspector_for_assets_config_aws_gcp_yaml,
    benchmark_inspector_for_assets_config_aws_yaml,
    benchmark_inspector_for_assets_config_gcp_yaml,
    benchmark_inspector_for_assets_config_twitter_yaml,
    benchmark_inspector_for_assets_config_twitter_yaml_json_parse,
    benchmark_inspector_for_cleanup_large_spaces,
);
criterion_main!(benches);
