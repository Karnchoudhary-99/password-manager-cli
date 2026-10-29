const std = @import("std");
const vault_mod = @import("vault.zig");
const password_mod = @import("password.zig");
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
    \\
    \\Options:
    \\  --username <u>       username for `add`
    \\  --password <p>       password for `add` (else prompted, hidden)
    \\  --notes <n>          notes for `add`
    \\  --force              overwrite on `add`, replace on `init`
    \\
    \\Environment:
    \\  PM_VAULT             vault file path (default: $HOME/.pm-vault)
    \\  PM_MASTER_PASSWORD   master password (else prompted, hidden)
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
        if (std.mem.eql(u8, arg, "--username") or std.mem.eql(u8, arg, "--password") or std.mem.eql(u8, arg, "--notes")) {
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
        if (flagValue(rest, "password")) |p| {
            entry_password = p;
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
            error.VaultExists, error.PasswordMismatch, error.UnknownCommand, error.EntryExists, error.MissingArgument, error.NoSuchEntry => {},
            else => stderr.print("pm: {s}\n", .{@errorName(err)}) catch {},
        }
        std.process.exit(1);
    };
}

test "smoke" {
    try std.testing.expect(true);
}
