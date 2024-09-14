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
- [x] Save config to remote storage and load configurations from remote storage.
- [ ] The Laxer scanner with file context awareness and string literals parsing.
- [ ] Provide finding score.
- [ ] Remove false positives.
- [ ] Decoder for base16 (hex), base32, base58, base64, base85.
- [x] Omits files that have given file extension.
- [x] Omits package managers: npm, venv, go/pkg/, ruby gems, ...
- [x] Reports file name, line number, raw secret, detector type and decoder type if used.
- [x] Report summary per decoder and detector.
- [x] Analytics - summarise findings, statistical data,
- [x] Formated Otput: standard beautiful, json, yaml.
- [x] Trivial de-dupe reoccurring secrets on a file and branch level.
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
- [ ] Store in local or remote DAG database.
- [ ] Read DAG statistics.
- [ ] Identify when a finding has been remediated.
- [ ] Identify when a finding has been remediated, or triaged based on known information
- [ ] Run scanner as a GRPC API server - perform all above via GRPC request.
- [ ] Expose for Golang, NodeJS and Python as a package to be easy to use.


## Test and build

- Test (will optimize for performance), remember to use one thread for testsing as the git source shares a single temporary folder and flushes it on finish.

```sh
cargo test -- --nocapture --test-threads=1
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

```text
./target/release/rogue --help
Detector scans for secrets according to configurations patterns.

Usage: rogue <COMMAND>

Commands:
  workshop    Provides workshop functionalities, creating account. reading, saving and sharing configuration.
  filesystem  Scan filesystem
  git         Scan remote git repository
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

- Print usage filesystem

```text
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
      --json           Formats output to json, has precedance over yaml.
      --yaml           Formats output to yaml.
  -h, --help           Print help
  -V, --version        Print version
```

- Print usage git

```text
./target/release/rogue git --help
Scan remote git repository

Usage: detector git [OPTIONS]

Options:
      --url <String>       URL to git repository to scan.
      --path <Path>        Path to direcory to scan.
      --config <Path>      Path to config YAML file used for scanner configuration.
      --omit <String>      Space separated file patterns to ommit
      --dedup <u64>        Level of de duplications. 0 or not specified - no dedup, 1 - branch level dedup, 2 - file level dedup.
      --nodeps             If specified omits default dependencies such as npm, venv, gems, ect.
      --scan-local         If specified scans all local brancheses.
      --scan-remote        If specified scans all remote brancheses.
      --branches <String>  If specified scans branches from the given list, otherwise HEAD is scanned or all branches with flag --scan-local or -scan-remote.
      --scan-archives      If specified performs archive scanning.
      --scan-binary        If specified performs binary files scanning.
      --json               Formats output to json, has precedance over yaml.
      --yaml               Formats output to yaml.
  -h, --help               Print help
  -V, --version            Print version
```

- Example with config from assets:

```sh
./target/release/rogue filesystem --config assets/config.yaml --path <folder-with-expired-creds-to-scan>
```

- Print usage workshop

```sh
./target/release/rogue workshop --help
Provides workshop functionalities, creating account. reading, saving and sharing configuration.

Usage: rogue workshop [OPTIONS]

Options:
      --private <Path>        Path to RSA private key. It works with 4096 length key only.
      --public <Path>         Path to RSA public key.
      --keys-create           Create RSA keys.
      --account-create        Create account in the remote repository.
      --config-create <Path>  Creates config from given config path.
      --config-read <Path>    Reads config from the workshop remote repository and saves it to gitven path.
      --verified              Specifies if workshop shall return only verified connfigurations.
      --groups <String>       Space separated names of a groups for query filter. Allowed groups are: common, http, ssl, jwt, credentials, database, key, cookie, seed, hash.
      --from <String>         Beginning date in RFC-3339 format to search from, if not specified the unix time 0 is used.
      --to <String>           Maximum date in RFC-3339 format to serch to, if not specified now time is used.
  -h, --help                  Print help
  -V, --version               Print version
```
