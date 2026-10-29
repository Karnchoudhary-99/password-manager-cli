# CLI Password Manager

A password manager for the terminal, in Zig — no runtime dependencies,
a single static binary. An encrypted local vault, a password generator,
and a workflow that never prints secrets to the shell history.

## Roadmap

- [x] Project scaffold (build.zig, CLI skeleton, smoke test, CI, README)
- [x] Vault: encrypted storage with a master password (key derivation + authenticated encryption)
- [x] Entries: add, get, list, remove, search
- [x] Generator: configurable length, character sets, entropy reporting
- [x] Import/export + backup, then self-review checklist, then public

## Quick start

```sh
zig build        # builds zig-out/bin/pm
zig build test   # runs the test suite
./zig-out/bin/pm --help
sh examples/demo.sh   # full tour against a throwaway vault
```

## Usage

```sh
pm init                                            # create the vault (prompts twice for the master password)
pm add github --username alice --password '...' --notes "personal account"
pm add github --username alice                     # password prompted, hidden (no echo)
pm get github                                      # prints username, password, notes
pm list                                            # entry names only — never secrets
pm search git                                      # case-insensitive over name, username, notes
pm remove github
pm gen --length 24                                 # password on stdout, entropy report on stderr
pm gen --no-symbols                                # exclude a character set
pm add api --generate                              # store a fresh generated password
pm export --format csv --out backup.csv            # plaintext export (0600) — handle with care
pm import backup.csv --format csv                  # skips existing entries unless --force
pm backup                                          # sealed copy to <vault>.bak (stays encrypted)
pm restore vault.bak --force                       # replace the vault with a sealed backup
pm change-password                                 # re-seal the vault under a new master password
```

Environment variables:

- `PM_VAULT` — vault file path (default: `$HOME/.pm-vault`)
- `PM_MASTER_PASSWORD` — master password for scripts/tests (otherwise
  prompted interactively, with terminal echo disabled)

## Generator, import/export, backup

- **Generator:** uniform random picks from the enabled sets (lowercase,
  uppercase, digits, symbols) using the OS crypto random source, with
  guaranteed coverage of every enabled set. Entropy is reported as
  `length × log2(charset size)` bits and banded weak (< 50), moderate
  (50–80), strong (≥ 80). `pm gen` prints the password to stdout so it
  can be captured (`pw=$(pm gen)`) and the report to stderr.
- **Import/export:** JSON (default) and CSV (header
  `name,username,password,notes`, RFC-4180-style quoting). Exports are
  plaintext — `--out` files are written `0600`, and stdout export warns.
  Imports are strict: a malformed row fails the whole import, and
  existing entries are skipped unless `--force` overwrites them.
- **Backup/restore:** a backup is a byte copy of the sealed vault file,
  so it needs no master password and stays encrypted at rest. Restore
  refuses to overwrite an existing vault unless `--force` is given.

## Security design

- **Key derivation:** the master password is stretched with scrypt
  (interactive parameters) into a 256-bit key. There is no stored hash to
  steal: the only way to test a guess is to derive the key and try to
  open the vault.
- **Authenticated encryption:** the whole vault (entries as JSON) is
  sealed with AES-256-GCM under a fresh random salt and nonce per save,
  so identical vaults seal differently and any tampering — or a wrong
  master password — fails authentication instead of decrypting garbage.
- **File format:** `PMV1` magic + version byte + salt/nonce/ciphertext/
  tag. Entry names are inside the sealed blob, so they don't leak
  either.
- **Safe writes:** saves go to a temporary sibling file with `0600`
  permissions and are renamed over the old vault, so a crash mid-save
  never leaves a half-written vault.
- **No history leaks:** the master password and entry passwords are
  never passed as visible shell history when prompted; use the prompt
  (not `--password`) for real secrets, and prefer `pm list` over `pm get`
  when someone might be looking over your shoulder.

## License

MIT — see [LICENSE](LICENSE).
