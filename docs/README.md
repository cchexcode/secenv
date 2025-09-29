# secenv

Secure, profile-based environment variable management with HOCON configuration, optional PGP decryption, and GCP Secret Manager integration.

## Features

- 🔐 **PGP decryption (with provided private key)**: Decrypt values using an ASCII-armored private key you supply
- ☁️ **GCP Secret Manager**: Load secrets at runtime using `gcloud`
- 🗂️ **Profiles**: Organize variables by profile (dev, staging, prod, …)
- 🧩 **Multiple providers**: `literal`, `environment`, `file`, `gcp.plain`, `gcp.pgp`
- 🧪 **Docs & tooling**: Built-in manual and shell completion generators
- ⚡ **Fast & safe**: Rust-based CLI

## Installation

### From source

```bash
git clone https://github.com/cchexcode/secenv
cd secenv
cargo build --release
```

The binary will be at `target/release/secenv`.

## Quick start

### 1) Create `secenv.conf` (HOCON)

```hocon
version = "0.0.0"  # Config version must be compatible with the CLI version

profiles.default.env {
  # Optional regex patterns of variables to keep when executing a command
  # If set, the child environment is cleared first, then only matching host vars are kept.
  # If omitted, the full host environment is kept.
  # keep = ["^PATH$", "^SHELL$", "^LC_.*"]

  vars {
    APP_NAME.literal = "myapp"
    HOME_DIR.environment = "HOME"
    CONFIG_JSON.file = "/etc/myapp/config.json"

    # Retrieve a secret value directly from GCP Secret Manager (plain text)
    DB_PASSWORD.gcp.plain.secret = "projects/123456789/secrets/db-password"

    # Decrypt a PGP-encrypted value using a private key stored in GCP Secret Manager
    # - secret: GCP secret holding the ASCII-armored private key
    # - value.literal: ASCII-armored PGP message (or use value.base64)
    SERVICE_TOKEN.gcp.pgp {
      secret = "projects/123456789/secrets/pgp-private-key"
      value.literal = """
      -----BEGIN PGP MESSAGE-----
      ...
      -----END PGP MESSAGE-----
      """
    }
  }
}

profiles.production.env.vars {
  APP_NAME.literal = "myapp"
  DB_PASSWORD.gcp.plain.secret = "projects/123456789/secrets/prod-db-password"
}
```

Notes:
- The `version` field is validated against the CLI version. The config must not be newer than the CLI, and major versions must match.
- For `gcp.pgp`, the private key must be a valid ASCII‑armored OpenPGP private key stored in GCP Secret Manager.

### 2) Unlock variables

```bash
# Print key=value pairs for the default profile
secenv unlock

# Use a specific profile and config path
secenv unlock --config /path/to/secenv.conf --profile production

# Load into current shell (bash/zsh/fish)
eval "$(secenv unlock --profile production)"
```

To run a command with the variables set:

```bash
# Run a program inheriting host environment (default behavior)
secenv unlock --profile production -- env | sort

# With keep configured in the profile, only matching host vars are preserved
secenv unlock --profile production -- printenv | sort

# Execute a command
secenv unlock --profile production -- make deploy
```

Output format when printing:
```
APP_NAME=myapp
DB_PASSWORD=...
HOME_DIR=/Users/you
```

## Configuration reference (HOCON)

### Top-level

```hocon
version = "<semver>"
profiles = { <name> = { env = { keep = [<regex>], vars = { ... } } } }
```

### Profiles and environment

```hocon
profiles.<profile>.env.keep = ["^PATH$", "^LC_.*"]  # optional
profiles.<profile>.env.vars {                          # required
  KEY.literal = "value"
  KEY.environment = "ENV_NAME"
  KEY.file = "/path/to/file"

  # From GCP Secret Manager (plain)
  KEY.gcp.plain.secret = "projects/<project>/secrets/<name>"

  # Decrypt PGP with a private key retrieved from GCP Secret Manager
  KEY.gcp.pgp.secret = "projects/<project>/secrets/<private-key>"
  KEY.gcp.pgp.value.literal = "-----BEGIN PGP MESSAGE-----..."
  # or
  KEY.gcp.pgp.value.base64 = "<base64-encoded-ASCII-armored-message>"
}
```

### Providers

- **literal**: Hard-coded string
- **environment**: Reads an existing host environment variable
- **file**: Reads file contents as string
- **gcp.plain**: Reads a secret value directly from GCP Secret Manager
- **gcp.pgp**: Fetches a private key from GCP Secret Manager and decrypts a PGP message you provide

Important:
- Decryption by fingerprint/key ID is not supported. You must provide a private key for decryption (e.g., via `gcp.pgp`).

## CLI reference

Global options:
- `-e, --experimental` – enable experimental features

Commands:

### unlock
Unlock values and optionally execute a command with the variables set.

```bash
secenv unlock [OPTIONS] [--] [COMMAND...]

Options:
  -c, --config <path>     Path to config (default: secenv.conf)
  -p, --profile <name>    Profile name (default: default)
```

Behavior:
- Without `COMMAND`, prints `KEY=VALUE` lines to stdout.
- With `COMMAND`, executes it with variables set. If `env.keep` is set in the profile, the child environment is cleared first and only host variables matching any regex in `keep` are preserved; otherwise, the full host environment is kept.

### man
Render the manual pages or markdown help.

```bash
secenv man --out <directory> --format <manpages|markdown>
```

### autocomplete
Generate shell completion scripts.

```bash
secenv autocomplete --out <directory> --shell <bash|zsh|fish|elvish|powershell>
```

### init
Initialize a new HOCON config file.

```bash
secenv init [--path <path>] [--force]
```

Notes:
- Creates an empty file at `--path` (default: `secenv.conf`). You should edit it to add `version`, `profiles`, and `vars` as shown above.

## GCP requirements

- Install and authenticate `gcloud` (`gcloud auth login` or service account with suitable permissions).
- Ensure the identity has access to the relevant secrets (e.g., Secret Manager Secret Accessor).
- Accepted secret identifier format: `projects/<project>/secrets/<name>` (optional `/versions/<version>`; defaults to `latest`).

## Troubleshooting

- **"Profile '<name>' not found"**: Verify `profiles.<name>` exists in the config.
- **"Failed to parse HOCON config"**: Validate HOCON syntax and file path.
- **GCP access errors**: Check `gcloud` authentication, project, permissions, and secret name.
- **PGP decryption errors**: Ensure the private key is valid ASCII‑armored and corresponds to the message.

For verbose logs:

```bash
RUST_LOG=debug secenv unlock
```

## Testing

```
cargo run -- unlock -- env
```

The password for all private keys for testing is `test`.

## Contributing

### Development

```bash
git clone https://github.com/cchexcode/secenv
cd secenv
cargo build
cargo test
```

## License

MIT – see [LICENSE](../LICENSE).

## Related projects

- [sops](https://github.com/mozilla/sops)
- [age](https://github.com/FiloSottile/age)
- [pass](https://www.passwordstore.org/)
