# CLI Password Manager

A password manager for the terminal, in Zig — no runtime dependencies,
a single static binary. An encrypted local vault, a password generator,
and a workflow that never prints secrets to the shell history.

## Roadmap

- [x] Project scaffold (build.zig, CLI skeleton, smoke test, CI, README)
- [x] Vault: encrypted storage with a master password (key derivation + authenticated encryption)
- [x] Entries: add, get, list, remove, search
- [ ] Generator: configurable length, character sets, entropy reporting
- [ ] Import/export + backup, then self-review checklist, then public

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
```

Environment variables:

- `PM_VAULT` — vault file path (default: `$HOME/.pm-vault`)
- `PM_MASTER_PASSWORD` — master password for scripts/tests (otherwise
  prompted interactively, with terminal echo disabled)

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
