# secenv

Secure, profile-based environment variable management with HOCON configuration, PGP decryption, and optional GCP Secret Manager integration for retrieving PGP private keys.

## Features

- 🔐 **PGP decryption**: Decrypt PGP-encrypted values using a private key provided via file, literal, GPG keyring (by fingerprint), or GCP Secret Manager
- ☁️ **GCP Secret Manager**: Fetch the PGP private key at runtime via `gcloud`
- 🗂️ **Profiles**: Organize variables by profile (dev, staging, prod, …)
- 📄 **Temporary files**: Create temporary files with plain or encrypted content that are automatically cleaned up after command execution
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

### 1) Create `secenv.conf` (JSON or HOCON)

```hocon
version = "0.0.0"  # Must be semver and compatible with the CLI version

profiles.default {
  # Optional: Define temporary files that will be created before command execution
  # and automatically cleaned up afterwards
  files {
    # Plain file example
    # "./config.json".plain.literal = '{"key": "value"}'
    
    # Secure file with PGP-encrypted content
    # "./credentials.key".secure {
    #   secret.pgp.gpg.fingerprint = "1E1BAC706C352094D490D5393F5167F1F3002043"
    #   value.base64 = "<base64-encoded ASCII-armored PGP message>"
    # }
  }

  env {
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
}
```

Notes:
- The config file can be in JSON or HOCON format (HOCON is a superset of JSON).
- Use `secenv init` to generate a JSON example file, or write your own in HOCON format.
- The `version` field is validated against the CLI version. The config cannot be newer than the CLI, and major versions must match.
- Supported secret sources for PGP private keys: `secret.pgp.literal`, `secret.pgp.file`, `secret.pgp.gpg.fingerprint`, `secret.pgp.gcp.secret` (+ optional `.version`).

### 2) Unlock variables and manage temporary files

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

# Execute a command (temporary files defined in the profile will be created and cleaned up)
secenv unlock --profile production -- make deploy

# Overwrite existing files if they already exist
secenv unlock --profile production --force -- make deploy
```

Output format when printing:
```
APP_NAME=myapp
SECRET_TOKEN=...
```

**Note**: When executing a command, any files defined in `profiles.<profile>.files` are created before the command runs and automatically deleted after the command completes. Use `--force` to overwrite existing files.

## Temporary files

The temporary files feature allows you to create files with sensitive content that are automatically managed by `secenv`. This is useful for:

- **Credential files**: Create temporary credential files (e.g., `.kubeconfig`, `.aws/credentials`, service account keys) that are needed by commands but should not persist on disk
- **Configuration files**: Generate temporary config files with decrypted secrets
- **SSH keys**: Provide temporary SSH keys for deployment scripts
- **Certificate files**: Supply temporary SSL/TLS certificates and keys

### How it works

1. **Definition**: Files are defined in the `profiles.<profile>.files` section of the config
2. **Content types**: Files can contain plain text or PGP-encrypted content (same as environment variables)
3. **Creation**: Before running a command (or printing env vars), all files are created with their decrypted content
4. **Directory creation**: Parent directories are automatically created if they don't exist
5. **Conflict handling**: If a file already exists, the operation fails unless `--force` is used
6. **Cleanup**: After the command completes (or env vars are printed), all created files are automatically deleted
7. **Error handling**: If cleanup fails, an error is printed to stderr, but the original command's exit code is preserved

### Example use case

```hocon
profiles.production {
  files {
    # Temporary kubeconfig for kubectl commands
    "./kubeconfig".secure {
      secret.pgp.gcp.secret = "projects/myproject/secrets/pgp-key"
      value.base64 = "<base64-encoded-pgp-message>"
    }
    
    # Temporary service account key
    "./service-account.json".secure {
      secret.pgp.gpg.fingerprint = "1E1BAC706C352094D490D5393F5167F1F3002043"
      value.base64 = "<base64-encoded-pgp-message>"
    }
  }
  
  env.vars {
    KUBECONFIG.plain.literal = "./kubeconfig"
    GOOGLE_APPLICATION_CREDENTIALS.plain.literal = "./service-account.json"
  }
}
```

Then run:
```bash
secenv unlock --profile production -- kubectl get pods
# The kubeconfig and service account files are created, kubectl runs, then files are deleted
```

## Configuration reference (JSON/HOCON)

### Top-level

```hocon
version = "<semver>"
profiles = { 
  <name> = { 
    files = { ... }              # optional
    env = { 
      keep = [<regex>],          # optional
      vars = { ... }             # required
    } 
  } 
}
```

### Profiles and temporary files

```hocon
profiles.<profile>.files {
  # Define temporary files that will be created before command execution
  # and automatically cleaned up afterwards
  
  # Plain file content
  "/path/to/file".plain.literal = "file content"
  "/path/to/file".plain.base64 = "<base64-encoded content>"
  
  # Secure file content (PGP-decrypted)
  "/path/to/secure.key".secure {
    # Use any of the same PGP secret sources as environment variables
    secret.pgp.file = "/path/to/private.key"
    # or secret.pgp.literal, secret.pgp.gpg.fingerprint, secret.pgp.gcp.secret
    
    value.literal = "-----BEGIN PGP MESSAGE-----..."
    # or value.base64 = "<base64-encoded-ASCII-armored-message>"
  }
}
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
Unlock values, create temporary files, and optionally execute a command with the variables set.

```bash
secenv unlock [OPTIONS] [--] [COMMAND...]

Options:
  -c, --config <path>     Path to config (default: secenv.conf)
  -p, --profile <name>    Profile name (default: default)
  -f, --force             Overwrite existing files defined in the manifest
```

Behavior:
- Without `COMMAND`, prints `KEY=VALUE` lines to stdout. If the profile defines temporary files, they are created and immediately cleaned up.
- With `COMMAND`, executes it with variables set and temporary files created. Files are automatically cleaned up after the command completes.
- If `env.keep` is set in the profile, the child environment is cleared first and only host variables matching any regex in `keep` are preserved; otherwise, the full host environment is kept.
- Temporary files defined in `profiles.<profile>.files` are created before command execution:
  - Parent directories are automatically created if they don't exist
  - If a file already exists, the command fails unless `--force` is specified
  - Files support both plain and secure (PGP-encrypted) content
  - All created files are automatically removed after command execution or when printing environment variables

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
Initialize a new config file.

```bash
secenv init [--path <path>] [--force]
```

Notes:
- Creates an example file at `--path` (default: `secenv.conf`) in JSON format.
- The config file can be in JSON or HOCON format (HOCON is a superset of JSON, so both work).
- Review and adapt the generated file to add your `version`, `profiles`, and `vars` as shown in the examples.

## GCP requirements

- Install and authenticate `gcloud` (`gcloud auth login` or service account with suitable permissions).
- Ensure the identity has access to the relevant secrets (e.g., Secret Manager Secret Accessor).
- Accepted secret identifier format: `projects/<project>/secrets/<name>` (optional `/versions/<version>`; defaults to `latest`).

## Troubleshooting

- "Profile '<name>' not found": Verify `profiles.<name>` exists in the config.
- "Failed to parse HOCON config": Validate HOCON syntax and file path.
- "File '<path>' already exists": A temporary file defined in the profile conflicts with an existing file. Use `--force` to overwrite or remove the existing file.
- GCP access errors: Check `gcloud` authentication, project, permissions, and secret name.
- PGP decryption errors: Ensure the private key is valid ASCII‑armored and corresponds to the message.
- File cleanup errors: If temporary file cleanup fails after command execution, an error message will be printed to stderr, but the command exit code will still be preserved.

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
