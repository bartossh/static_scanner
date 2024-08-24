# Rogue

Configurable secret scanner and genric credentials detector ensuring your secret will not leave your sandbox.

[![Rust](https://github.com/OpenSourceScannerCollective/static_scanner/actions/workflows/rust.yml/badge.svg)](https://github.com/OpenSourceScannerCollective/static_scanner/actions/workflows/rust.yml)

## Goals

Scanner aims to:
  - be correct (near 1.0 true positive rate and 0.0 false positive rate)
  - be fast and use little RAM (scanning shall be done frequently and on large data sets, we have other things to spare resources for)
  - be versatile (scan for multiple secrets that are easily configured)
  - be modular (possibility to extend scanner with dedicated and specialised scanners)
  - be easy to use (simple cmd tool that is run in a pipeline)
  - be compact (easy to install single binary runnable without need for interpreters and other dependencies that create development bottlenecks and security concerns)


## Features

- [x] The Regex scanner is based on the yaml file configuration.
- [x] Regex scanner to use required keys to remove false positives - create using a yaml config file.
- [x] The Regex scanner will use a key pattern based on regex from the yaml config file.
- [ ] The Laxer scanner with file context awareness and string literals parsing.
- [ ] The Laxer stochastic scanner.
- [ ] The Laxer scanner to remove false positives.
- [ ] False positive filter with stochastic models.
- [ ] Decoder for base16 (hex), base32, base58, base64, base85.
- [ ] Decoder for JWT.
- [x] Omits files that have given file extension.
- [x] Omits package managers: npm, venv, go/pkg/, ruby gems, ...
- [x] Reports file name, line number, raw secret, detector type and decoder type if used.
- [x] Report summary per decoder and detector.
- [x] Analytics - summarise findings, statistical data,
- [x] Trivial de-dupe reoccurring secrets on a file and branch level.
- [ ] Local DAG scan history to deduplicate findings with.
- [x] Scan filesystem - takes the path to the root directory to scan.
- [x] Scan the git remote branch via the given URL, which scans all or specifed branches.
- [x] Scan the git local branch via the given PATH, which scans all or specified branches.
- [ ] Scan the git incrementally - from some date range, from some commit hash.
- [ ] Scan the git and identify authors - who introduced the secret.
- [ ] Scan the git for specified branches diff.
- [x] Scan archives (tar, zip, jar).
- [x] Scan binaries.
- [ ] Scan Confulance and Jira.
- [ ] Scan slack.
- [ ] Scan Postgres database.
- [ ] Scan MongoDB database.
- [ ] Found secret per person.
- [ ] Validate secret.
- [ ] Identify when a finding has been remediated.
- [ ] Identify when a finding has been remediated, or triaged based on known information
- [ ] Run scanner as a GRPC API server - perform all above via GRPC request.
- [ ] Expose for Golang, NodeJS and Python as a package to be easy to use.


## Test and build

- Test (will optimize for performance), remember to use one thread for testsing as the git source shares a single temporary folder and flushes it on finish.

```sh
cargo test -- --nocapture --test-threads-1
```
- Bench (optimized build)

```sh
cargo bench -- --nocapture
```

- Build release

```sh
cargo build --release
```

# Usage

- Print usage main

```sh
./target/release/rogue --help
Detector scans for secrets according to configurations patterns.

Usage: detector <COMMAND>

Commands:
  filesystem  Scan filesystem
  git         Scan remote git repository
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

- Print usage filesystem

```sh
./target/release/rogue filesystem --help
Scan filesystem

Usage: detector filesystem [OPTIONS]

Options:
      --path <Path>    Path to direcory to scan.
      --config <Path>  Path to config YAML file used for scanner configuration.
      --omit <String>  Space separated file patterns to ommit
      --dedup <u64>    Level of de duplications. 0 or not specified - no dedup, 1 - file level dedup
      --nodeps         If specified omits default dependencies such as npm, venv, gems, ect.
      --scan-archives  If specified performs archive scanning.
      --scan-binary    If specified performs binary files scanning.
  -h, --help           Print help
  -V, --version        Print version
```

- Print usage git

```sh
./target/release/rogue git --help
Scan remote git repository

Usage: detector git [OPTIONS]

Options:
      --url <String>       URL to git repository to scan.
      --config <Path>      Path to config YAML file used for scanner configuration.
      --omit <String>      Space separated file patterns to ommit
      --dedup              If dpecified fe duplicates recurring secrets. De duplication happens in the order of scanners in the config file.
      --nodeps             If specified omits default dependencies such as npm, venv, gems, ect.
      --scan-local         If specified scans all local brancheses.
      --scan-remote        If specified scans all remote brancheses.
      --branches <String>  If specified scans branches from the given list, otherwise HEAD is scanned or all branches with flag --scan-local or -scan-remote.
  -h, --help               Print help
  -V, --version            Print version
```


- Example with config from assets:

```sh
./target/release/rogue filesystem --config assets/config.yaml --path <folder-with-expired-creds-to-scan>
```
