# Static Scanner

The static scanner uses config to create a scan per secret description, then performs detection.

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
- [x] Scan filesystem - takes the path to the root directory to scan.
- [x] Scan the git remote branch via the given URL, which scans all files in the main / master branch.
- [ ] Scan Confulance and Jira.
- [ ] Scan slack.
- [ ] Scan Postgres database.
- [ ] Scan MongoDB database.
- [x] Omits files that have given file extension.
- [x] Omits package managers: npm, venv, go/pkg/, ruby gems, ...
- [x] Reports file name, line number, raw secret, detector type and decoder type if used.
- [x] Report summary per decoder and detector.
- [x] Analitics - summarize findings, statistical data,
- [ ] Found secret per person.
- [x] De-dupe reoccurring secrets.
- [ ] Scan archives.
- [x] Scan specified branches.
- [ ] Scan specified branches diff.
- [ ] Scan incrementally - from some date range.
- [ ] Identify authors - who introduced the secret.
- [ ] Archive scanning.
- [ ] Validate secret.
- [ ] Identify when a finding has been remediated.
- [ ] Scann binaries.
- [ ] Identify when a finding has been remediated, or triaged based on known information
- [ ] Run scanner as a GRPC API server - perform all above via GRPC request.
- [ ] Expose for Golang, NodeJS and Python as a package to be easy to use.


## Test and build

- Test (will optimize for performance)

```sh
cargo test -- --nocapture
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
./target/release/static_detector --help
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
./target/release/static_detector filesystem --help
Scan filesystem

Usage: detector filesystem [OPTIONS]

Options:
      --path <Path>    Path to direcory to scan.
      --config <Path>  Path to config YAML file used for scanner configuration.
      --omit <String>  Space separated file patterns to ommit
      --dedup          De duplicates recurring secrets. De duplication happens in the order of scanners in the config file.
      --nodeps         Omits default dependencies such as npm, venv, gems, ect.
  -h, --help           Print help
  -V, --version        Print version
```

- Print usage git

```sh
./target/release/static_detector git --help
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
./target/release/static_detector filesystem --config assets/config.yaml --path <folder-with-expired-creds-to-scan>
```
