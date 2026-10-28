# CLI Password Manager

A password manager for the terminal, in Zig — no runtime dependencies,
a single static binary. An encrypted local vault, a password generator,
and a workflow that never prints secrets to the shell history.

## Roadmap

- [x] Project scaffold (build.zig, CLI skeleton, smoke test, CI, README)
- [ ] Vault: encrypted storage with a master password (key derivation + authenticated encryption)
- [ ] Entries: add, get, list, remove, search
- [ ] Generator: configurable length, character sets, entropy reporting
- [ ] Import/export + backup, then self-review checklist, then public

## Quick start

```sh
zig build        # builds zig-out/bin/pm
zig build test   # runs the test suite
./zig-out/bin/pm --help
```

## License

MIT — see [LICENSE](LICENSE).
