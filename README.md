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
  -h, --help           Print help
  -V, --version        Print version
```

- Example with config from assets:

```sh
./target/release/static_detector filesystem --config assets/config.yaml --path <folder-with-expired-creds-to-scan>
```
