const std = @import("std");
const vault_mod = @import("vault.zig");
const password_mod = @import("password.zig");
const generator_mod = @import("generator.zig");
const ioformat_mod = @import("ioformat.zig");
const Vault = vault_mod.Vault;

const usage_text =
    \\Usage: pm <command> [options]
    \\
    \\Commands:
    \\  init                 create a new encrypted vault
    \\  add <name>           store a new entry
    \\  get <name>           retrieve an entry
    \\  list                 list entry names
    \\  remove <name>        delete an entry
    \\  search <query>       search entries by name, username or notes
    \\  gen                  generate a password (prints entropy to stderr)
    \\  export               export entries as plaintext JSON or CSV
    \\  import <file>        import entries from a JSON or CSV export
    \\  backup [path]        copy the sealed vault file (default: <vault>.bak)
    \\  restore <file>       replace the vault with a sealed backup copy
    \\  change-password      re-seal the vault under a new master password
    \\
    \\Options:
    \\  --username <u>       username for `add`
    \\  --password <p>       password for `add` (else prompted, hidden)
    \\  --notes <n>          notes for `add`
    \\  --force              overwrite on `add`, replace on `init`/`restore`
    \\  --generate           generate the entry password on `add`
    \\  --length <n>         password length for `gen`/`add --generate` (default 20)
    \\  --no-symbols         exclude symbols from generated passwords
    \\  --no-digits          exclude digits from generated passwords
    \\  --no-uppercase       exclude uppercase letters from generated passwords
    \\  --no-lowercase       exclude lowercase letters from generated passwords
    \\  --format <json|csv>  format for `export`/`import` (default json)
    \\  --out <path>         output file for `export` (default: stdout)
    \\
    \\Environment:
    \\  PM_VAULT             vault file path (default: $HOME/.pm-vault)
    \\  PM_MASTER_PASSWORD   master password (else prompted, hidden)
    \\  PM_NEW_MASTER_PASSWORD new master password for `change-password`
    \\
;

fn printUsage(writer: anytype) !void {
    try writer.writeAll(usage_text);
}

/// Value of `--<name> <value>` or `--<name>=<value>`, if present.
fn flagValue(args: []const []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (!std.mem.startsWith(u8, arg, "--")) continue;
        if (std.mem.indexOfScalar(u8, arg, '=')) |eq| {
            if (std.mem.eql(u8, arg[2..eq], name)) return arg[eq + 1 ..];
        } else if (arg.len == name.len + 2 and std.mem.eql(u8, arg[2..], name)) {
            if (i + 1 < args.len) return args[i + 1];
        }
    }
    return null;
}

/// First positional argument, skipping `--flag <value>` pairs and bare flags.
fn firstPositional(args: []const []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--username") or std.mem.eql(u8, arg, "--password") or std.mem.eql(u8, arg, "--notes") or std.mem.eql(u8, arg, "--length") or std.mem.eql(u8, arg, "--format") or std.mem.eql(u8, arg, "--out")) {
            i += 1;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--")) continue;
        return arg;
    }
    return null;
}

fn hasFlag(args: []const []const u8, name: []const u8) bool {
    for (args) |a| {
        if (std.mem.eql(u8, a, name)) return true;
    }
    return false;
}

const CliError = error{
    InvalidLength,
    InvalidFormat,
};

/// Generator options from `--length` / `--no-*` flags. Length is capped
/// at 512: longer passwords add no usable security and invite abuse.
fn parseGenOptions(args: []const []const u8) !generator_mod.Options {
    var opts = generator_mod.Options{};
    if (flagValue(args, "length")) |raw| {
        opts.length = std.fmt.parseInt(usize, raw, 10) catch return CliError.InvalidLength;
        if (opts.length < 1 or opts.length > 512) return CliError.InvalidLength;
    }
    if (hasFlag(args, "--no-symbols")) opts.use_symbols = false;
    if (hasFlag(args, "--no-digits")) opts.use_digits = false;
    if (hasFlag(args, "--no-uppercase")) opts.use_upper = false;
    if (hasFlag(args, "--no-lowercase")) opts.use_lower = false;
    return opts;
}

/// `--format` flag for export/import: json by default, csv on request.
fn parseFormat(args: []const []const u8) !ioformat_mod.Format {
    const raw = flagValue(args, "format") orelse return .json;
    if (std.mem.eql(u8, raw, "json")) return .json;
    if (std.mem.eql(u8, raw, "csv")) return .csv;
    return CliError.InvalidFormat;
}

/// Read a whole file by path (absolute or relative to cwd).
fn readPathBytes(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const loc = try openVaultDir(allocator, path);
    defer allocator.free(loc.name);
    var dir = loc.dir;
    const needs_close = dir.fd != std.fs.cwd().fd;
    defer if (needs_close) dir.close();
    return dir.readFileAlloc(allocator, loc.name, 16 * 1024 * 1024);
}

/// Write bytes to a path with `0600` permissions (exports and backups
/// hold secrets, sealed or not). Creates/truncates the file.
fn writePathBytes(path: []const u8, bytes: []const u8, allocator: std.mem.Allocator) !void {
    const loc = try openVaultDir(allocator, path);
    defer allocator.free(loc.name);
    var dir = loc.dir;
    const needs_close = dir.fd != std.fs.cwd().fd;
    defer if (needs_close) dir.close();
    var file = try dir.createFile(loc.name, .{ .truncate = true, .mode = 0o600 });
    defer file.close();
    try file.writeAll(bytes);
}

/// Split a vault path into the directory to open and the file name inside it.
fn openVaultDir(allocator: std.mem.Allocator, path: []const u8) !struct { dir: std.fs.Dir, name: []const u8 } {
    const dir_part = std.fs.path.dirname(path);
    const name = std.fs.path.basename(path);
    if (dir_part == null or dir_part.?.len == 0) {
        return .{ .dir = std.fs.cwd(), .name = try allocator.dupe(u8, name) };
    }
    const dir = if (std.fs.path.isAbsolute(dir_part.?))
        try std.fs.openDirAbsolute(dir_part.?, .{})
    else
        try std.fs.cwd().openDir(dir_part.?, .{});
    return .{ .dir = dir, .name = try allocator.dupe(u8, name) };
}

fn loadVault(allocator: std.mem.Allocator, path: []const u8, master: []const u8) !Vault {
    const loc = try openVaultDir(allocator, path);
    defer allocator.free(loc.name);
    var dir = loc.dir;
    const needs_close = dir.fd != std.fs.cwd().fd;
    defer if (needs_close) dir.close();
    return Vault.loadFrom(allocator, dir, loc.name, master);
}

fn saveVault(vault: *Vault, path: []const u8, master: []const u8, allocator: std.mem.Allocator) !void {
    const loc = try openVaultDir(allocator, path);
    defer allocator.free(loc.name);
    var dir = loc.dir;
    const needs_close = dir.fd != std.fs.cwd().fd;
    defer if (needs_close) dir.close();
    return vault.saveTo(dir, loc.name, master);
}

fn vaultExists(path: []const u8, allocator: std.mem.Allocator) !bool {
    const loc = try openVaultDir(allocator, path);
    defer allocator.free(loc.name);
    var dir = loc.dir;
    const needs_close = dir.fd != std.fs.cwd().fd;
    defer if (needs_close) dir.close();
    _ = dir.statFile(loc.name) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

fn run(allocator: std.mem.Allocator, args: []const []const u8) anyerror!void {
    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    if (args.len < 2 or std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "help")) {
        try printUsage(stdout);
        return;
    }

    const command = args[1];
    const rest = args[2..];
    const vault_path = try password_mod.defaultVaultPath(allocator);
    defer allocator.free(vault_path);

    if (std.mem.eql(u8, command, "init")) {
        if (try vaultExists(vault_path, allocator) and !hasFlag(rest, "--force")) {
            stderr.writeAll("pm: vault already exists (use --force to replace it)\n") catch {};
            return error.VaultExists;
        }
        const master = try password_mod.promptPassword(allocator, "Master password: ");
        defer allocator.free(master);
        const confirm = try password_mod.promptPassword(allocator, "Confirm master password: ");
        defer allocator.free(confirm);
        if (!std.mem.eql(u8, master, confirm)) {
            stderr.writeAll("pm: passwords do not match\n") catch {};
            return error.PasswordMismatch;
        }
        var vault = Vault.initEmpty(allocator);
        defer vault.deinit();
        try saveVault(&vault, vault_path, master, allocator);
        try stdout.print("vault created at {s}\n", .{vault_path});
        return;
    }

    if (std.mem.eql(u8, command, "add")) {
        const name = firstPositional(rest) orelse {
            stderr.writeAll("pm: add needs an entry name\n") catch {};
            return error.MissingArgument;
        };
        const master = try password_mod.promptPassword(allocator, "Master password: ");
        defer allocator.free(master);
        var vault = try loadVault(allocator, vault_path, master);
        defer vault.deinit();
        if (vault.find(name) != null) {
            if (!hasFlag(rest, "--force")) {
                stderr.writeAll("pm: entry already exists (use --force to overwrite)\n") catch {};
                return error.EntryExists;
            }
            _ = vault.remove(name);
        }
        var entry_password: []const u8 = undefined;
        var owned_entry_password: ?[]u8 = null;
        defer if (owned_entry_password) |p| allocator.free(p);
        var generated: ?[]u8 = null;
        defer if (generated) |g| allocator.free(g);
        if (flagValue(rest, "password")) |p| {
            entry_password = p;
        } else if (hasFlag(rest, "--generate")) {
            const opts = try parseGenOptions(rest);
            generated = try generator_mod.generate(allocator, std.crypto.random, opts);
            entry_password = generated.?;
        } else {
            const prompt = try std.fmt.allocPrint(allocator, "Password for {s}: ", .{name});
            defer allocator.free(prompt);
            owned_entry_password = try password_mod.promptPassword(allocator, prompt);
            entry_password = owned_entry_password.?;
        }
        try vault.add(.{
            .name = name,
            .username = flagValue(rest, "username") orelse "",
            .password = entry_password,
            .notes = flagValue(rest, "notes") orelse "",
        });
        try saveVault(&vault, vault_path, master, allocator);
        try stdout.print("added {s}\n", .{name});
        if (generated) |g| try stdout.print("generated password: {s}\n", .{g});
        return;
    }

    if (std.mem.eql(u8, command, "get")) {
        const name = firstPositional(rest) orelse {
            stderr.writeAll("pm: get needs an entry name\n") catch {};
            return error.MissingArgument;
        };
        const master = try password_mod.promptPassword(allocator, "Master password: ");
        defer allocator.free(master);
        var vault = try loadVault(allocator, vault_path, master);
        defer vault.deinit();
        const entry = vault.find(name) orelse {
            stderr.print("pm: no such entry '{s}'\n", .{name}) catch {};
            return error.NoSuchEntry;
        };
        try stdout.print("username: {s}\npassword: {s}\n", .{ entry.username, entry.password });
        if (entry.notes.len > 0) try stdout.print("notes: {s}\n", .{entry.notes});
        return;
    }

    if (std.mem.eql(u8, command, "list")) {
        const master = try password_mod.promptPassword(allocator, "Master password: ");
        defer allocator.free(master);
        var vault = try loadVault(allocator, vault_path, master);
        defer vault.deinit();
        // Names only: listing must never leak secrets.
        for (vault.entries.items) |e| {
            try stdout.print("{s}\n", .{e.name});
        }
        return;
    }

    if (std.mem.eql(u8, command, "remove")) {
        const name = firstPositional(rest) orelse {
            stderr.writeAll("pm: remove needs an entry name\n") catch {};
            return error.MissingArgument;
        };
        const master = try password_mod.promptPassword(allocator, "Master password: ");
        defer allocator.free(master);
        var vault = try loadVault(allocator, vault_path, master);
        defer vault.deinit();
        if (!vault.remove(name)) {
            stderr.print("pm: no such entry '{s}'\n", .{name}) catch {};
            return error.NoSuchEntry;
        }
        try saveVault(&vault, vault_path, master, allocator);
        try stdout.print("removed {s}\n", .{name});
        return;
    }

    if (std.mem.eql(u8, command, "search")) {
        const query = firstPositional(rest) orelse {
            stderr.writeAll("pm: search needs a query\n") catch {};
            return error.MissingArgument;
        };
        const master = try password_mod.promptPassword(allocator, "Master password: ");
        defer allocator.free(master);
        var vault = try loadVault(allocator, vault_path, master);
        defer vault.deinit();
        var found: usize = 0;
        for (vault.entries.items) |e| {
            if (vault_mod.matches(e, query)) {
                try stdout.print("{s}\n", .{e.name});
                found += 1;
            }
        }
        if (found == 0) try stdout.writeAll("(no matches)\n");
        return;
    }

    if (std.mem.eql(u8, command, "change-password")) {
        const old_master = try password_mod.promptPassword(allocator, "Current master password: ");
        defer allocator.free(old_master);
        var vault = try loadVault(allocator, vault_path, old_master);
        defer vault.deinit();
        const new_master = try password_mod.promptNewPassword(allocator, "New master password: ");
        defer allocator.free(new_master);
        const confirm = try password_mod.promptNewPassword(allocator, "Confirm new master password: ");
        defer allocator.free(confirm);
        if (!std.mem.eql(u8, new_master, confirm)) {
            stderr.writeAll("pm: passwords do not match\n") catch {};
            return error.PasswordMismatch;
        }
        // Re-sealing mints a fresh salt and nonce, so the new vault file
        // is unlinkable to the old one.
        try saveVault(&vault, vault_path, new_master, allocator);
        try stdout.print("master password changed\n", .{});
        return;
    }

    if (std.mem.eql(u8, command, "gen")) {
        const opts = try parseGenOptions(rest);
        const pw = try generator_mod.generate(allocator, std.crypto.random, opts);
        defer allocator.free(pw);
        // The password goes to stdout so it can be captured (`pw=$(pm gen)`);
        // the entropy report goes to stderr so it never pollutes the capture.
        try stdout.print("{s}\n", .{pw});
        const bits = generator_mod.entropyBits(opts);
        try stderr.print("entropy: {d:.1} bits ({s})\n", .{ bits, generator_mod.strength(bits) });
        return;
    }

    if (std.mem.eql(u8, command, "export")) {
        const format = try parseFormat(rest);
        const master = try password_mod.promptPassword(allocator, "Master password: ");
        defer allocator.free(master);
        var vault = try loadVault(allocator, vault_path, master);
        defer vault.deinit();
        const text = switch (format) {
            .json => try ioformat_mod.toJson(allocator, vault.entries.items),
            .csv => try ioformat_mod.toCsv(allocator, vault.entries.items),
        };
        defer allocator.free(text);
        if (flagValue(rest, "out")) |out_path| {
            try writePathBytes(out_path, text, allocator);
            try stdout.print("exported {d} entries to {s}\n", .{ vault.entries.items.len, out_path });
        } else {
            stderr.writeAll("warning: plaintext export — entries contain secrets\n") catch {};
            try stdout.writeAll(text);
        }
        return;
    }

    if (std.mem.eql(u8, command, "import")) {
        const file_path = firstPositional(rest) orelse {
            stderr.writeAll("pm: import needs a file path\n") catch {};
            return error.MissingArgument;
        };
        const format = try parseFormat(rest);
        const text = readPathBytes(allocator, file_path) catch {
            stderr.print("pm: cannot read import file '{s}'\n", .{file_path}) catch {};
            return error.ImportFileUnreadable;
        };
        defer allocator.free(text);
        const imported = switch (format) {
            .json => try ioformat_mod.fromJson(allocator, text),
            .csv => try ioformat_mod.fromCsv(allocator, text),
        };
        defer {
            for (imported) |e| {
                allocator.free(e.name);
                allocator.free(e.username);
                allocator.free(e.password);
                allocator.free(e.notes);
            }
            allocator.free(imported);
        }
        const master = try password_mod.promptPassword(allocator, "Master password: ");
        defer allocator.free(master);
        var vault = try loadVault(allocator, vault_path, master);
        defer vault.deinit();
        const force = hasFlag(rest, "--force");
        var added: usize = 0;
        var skipped: usize = 0;
        for (imported) |e| {
            if (vault.find(e.name) != null) {
                if (!force) {
                    skipped += 1;
                    continue;
                }
                _ = vault.remove(e.name);
            }
            try vault.add(e);
            added += 1;
        }
        try saveVault(&vault, vault_path, master, allocator);
        try stdout.print("imported {d} entries, skipped {d} existing\n", .{ added, skipped });
        return;
    }

    if (std.mem.eql(u8, command, "backup")) {
        // No master password needed: a backup is a byte copy of the
        // already-sealed vault file, so it stays encrypted at rest.
        // The default destination is allocated; a positional one borrows
        // from argv and must NOT be freed.
        var owned_dest: ?[]u8 = null;
        defer if (owned_dest) |d| allocator.free(d);
        const dest = firstPositional(rest) orelse blk: {
            owned_dest = try std.fmt.allocPrint(allocator, "{s}.bak", .{vault_path});
            break :blk owned_dest.?;
        };
        const bytes = try readPathBytes(allocator, vault_path);
        defer allocator.free(bytes);
        try writePathBytes(dest, bytes, allocator);
        try stdout.print("backed up vault to {s}\n", .{dest});
        return;
    }

    if (std.mem.eql(u8, command, "restore")) {
        const src = firstPositional(rest) orelse {
            stderr.writeAll("pm: restore needs a backup file path\n") catch {};
            return error.MissingArgument;
        };
        if (try vaultExists(vault_path, allocator) and !hasFlag(rest, "--force")) {
            stderr.writeAll("pm: vault already exists (use --force to replace it)\n") catch {};
            return error.VaultExists;
        }
        const bytes = readPathBytes(allocator, src) catch {
            stderr.print("pm: cannot read backup file '{s}'\n", .{src}) catch {};
            return error.ImportFileUnreadable;
        };
        defer allocator.free(bytes);
        try writePathBytes(vault_path, bytes, allocator);
        try stdout.print("restored vault from {s}\n", .{src});
        return;
    }

    stderr.writeAll("pm: unknown command (try: pm --help)\n") catch {};
    return error.UnknownCommand;
}

pub fn main() void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = std.process.argsAlloc(allocator) catch {
        std.io.getStdErr().writeAll("pm: out of memory\n") catch {};
        std.process.exit(1);
    };
    defer std.process.argsFree(allocator, args);

    run(allocator, args) catch |err| {
        const stderr = std.io.getStdErr().writer();
        switch (err) {
            error.FileNotFound => stderr.print("pm: no vault found (run: pm init first)\n", .{}) catch {},
            error.AuthenticationFailed => stderr.print("pm: wrong master password or corrupt vault\n", .{}) catch {},
            error.InvalidMagic, error.UnsupportedVersion => stderr.print("pm: not a pm vault file (or corrupt)\n", .{}) catch {},
            error.VaultExists, error.PasswordMismatch, error.UnknownCommand, error.EntryExists, error.MissingArgument, error.NoSuchEntry, error.ImportFileUnreadable => {},
            error.NoCharacterSets => stderr.print("pm: no character sets enabled for generation\n", .{}) catch {},
            error.LengthTooShort => stderr.print("pm: length too short for the enabled character sets\n", .{}) catch {},
            error.InvalidLength => stderr.print("pm: invalid --length (use 1..512)\n", .{}) catch {},
            error.InvalidFormat => stderr.print("pm: invalid --format (use json or csv)\n", .{}) catch {},
            error.MalformedCsv => stderr.print("pm: malformed CSV import\n", .{}) catch {},
            error.EmptyCsv => stderr.print("pm: empty CSV import\n", .{}) catch {},
            else => stderr.print("pm: {s}\n", .{@errorName(err)}) catch {},
        }
        std.process.exit(1);
    };
}

test "smoke" {
    try std.testing.expect(true);
}
