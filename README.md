# 3a5ad8eb8d518f6477eaeaa493870c662ce0bae5

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
