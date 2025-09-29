# secenv

Secure, profile-based environment variable management with HOCON configuration, PGP decryption, and optional GCP Secret Manager integration for retrieving PGP private keys.

## Features

- 🔐 **PGP decryption**: Decrypt PGP-encrypted values using a private key provided via file, literal, GPG keyring (by fingerprint), or GCP Secret Manager
- ☁️ **GCP Secret Manager**: Fetch the PGP private key at runtime via `gcloud`
- 🗂️ **Profiles**: Organize variables by profile (dev, staging, prod, …)
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
version = "0.0.0"  # Must be semver and compatible with the CLI version

profiles.default.env {
  # Optional regex patterns of variables to keep when executing a command.
  # If set, the child environment is cleared first, then only matching host vars are kept.
  # If omitted, the full host environment is kept.
  # keep = ["^PATH$", "^SHELL$", "^LC_.*"]

  vars {
    # Plain inline values
    APP_NAME.plain.literal = "myapp"
    # DB_HOST.plain.base64 = "bG9jYWxob3N0"  # "localhost"

    # Secure PGP-decrypted value using a GPG key from local keyring by fingerprint
    SECRET_TOKEN.secure {
      secret.pgp.gpg.fingerprint = "1E1BAC706C352094D490D5393F5167F1F3002043"
      value.base64 = "<base64-encoded ASCII-armored PGP message>"
    }

    # Secure PGP-decrypted value using a private key stored in GCP Secret Manager
    # secret.pgp.gcp.secret must be a fully qualified resource:
    #   projects/<project>/secrets/<name>[/versions/<version>]
    # version defaults to "latest" if omitted.
    SERVICE_TOKEN.secure {
      secret.pgp.gcp.secret = "projects/123456789/secrets/pgp-private-key"
      # secret.pgp.gcp.version = "latest"  # optional
      value.literal = """
      -----BEGIN PGP MESSAGE-----
      ...
      -----END PGP MESSAGE-----
      """
    }
  }
}
```

Notes:
- The `version` field is validated against the CLI version. The config cannot be newer than the CLI, and major versions must match.
- Supported secret sources for PGP private keys: `secret.pgp.literal`, `secret.pgp.file`, `secret.pgp.gpg.fingerprint`, `secret.pgp.gcp.secret` (+ optional `.version`).

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
SECRET_TOKEN=...
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
  # Plain values (inline only)
  KEY.plain.literal = "value"
  KEY.plain.base64  = "<base64-encoded string>"

  # Secure values (PGP-decrypted)
  KEY.secure {
    # One of the following PGP private key sources:
    # Inline (EncodedValue): choose one encoding
    # secret.pgp.literal.literal = """
    # -----BEGIN PGP PRIVATE KEY BLOCK-----
    # ...
    # -----END PGP PRIVATE KEY BLOCK-----
    # """
    # or
    # secret.pgp.literal.base64 = "<base64-encoded ASCII-armored private key>"
    # OR
    # secret.pgp.file = "/path/to/private.key"
    # OR
    # secret.pgp.gpg.fingerprint = "<fingerprint>"
    # OR
    # secret.pgp.gcp.secret = "projects/<project>/secrets/<name>"
    # secret.pgp.gcp.version = "latest"  # optional

    # Encrypted value to decrypt (ASCII-armored PGP message)
    value.literal = "-----BEGIN PGP MESSAGE-----..."
    # or
    # value.base64 = "<base64-encoded-ASCII-armored-message>"
  }
}
```

### Providers

- **plain**: Inline string value via `literal` or `base64`
- **secure**: Decrypts a PGP message using a provided PGP private key (`secret.pgp.*`)

Important:
- Reading plain values from files or environment variables is not supported in the new manifest. Provide plain values inline via `literal`/`base64`.
- Decryption via GPG keyring is supported only by specifying a `fingerprint`.

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
- Creates an example file at `--path` (default: `secenv.conf`). Review and adapt it to add your `version`, `profiles`, and `vars` as shown above.

## GCP requirements

- Install and authenticate `gcloud` (`gcloud auth login` or service account with suitable permissions).
- Ensure the identity has access to the relevant secrets (e.g., Secret Manager Secret Accessor).
- Accepted secret identifier format: `projects/<project>/secrets/<name>` (optional `/versions/<version>`; defaults to `latest`).

## Troubleshooting

- "Profile '<name>' not found": Verify `profiles.<name>` exists in the config.
- "Failed to parse HOCON config": Validate HOCON syntax and file path.
- GCP access errors: Check `gcloud` authentication, project, permissions, and secret name.
- PGP decryption errors: Ensure the private key is valid ASCII‑armored and corresponds to the message.

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
