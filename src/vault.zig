//! The encrypted vault file.
//!
//! File layout:
//!
//! ```text
//! "PMV1" || version (1 byte, currently 1) || crypto blob (see crypto.zig)
//! ```
//!
//! Entries are serialized as JSON and then sealed as one blob, so a single
//! file is the whole vault: easy to back up, and nothing about its contents
//! (not even entry names) leaks in plaintext. Files are written to a
//! temporary sibling and renamed over the old vault, so a crash mid-save
//! never leaves a half-written vault behind.

const std = @import("std");
const crypto = @import("crypto.zig");

pub const magic = "PMV1";
pub const version: u8 = 1;
const max_vault_bytes = 16 * 1024 * 1024;

pub const VaultError = error{
    InvalidMagic,
    UnsupportedVersion,
    EntryExists,
};

pub const Entry = struct {
    name: []const u8,
    username: []const u8,
    password: []const u8,
    notes: []const u8 = "",
};

/// The shape serialized to JSON inside the sealed blob.
const VaultData = struct {
    entries: []Entry,
};

pub const Vault = struct {
    arena: std.heap.ArenaAllocator,
    entries: std.ArrayList(Entry),

    pub fn initEmpty(allocator: std.mem.Allocator) Vault {
        // NOTE: the entry list must NOT use arena.allocator() here: taking
        // an arena's allocator pins a pointer to the arena struct, and this
        // Vault is returned by value (moving it would dangle that pointer
        // and crash stringify). Strings are duped into the arena at add
        // time via self.arena.allocator(), which is re-taken on each call.
        return .{
            .arena = std.heap.ArenaAllocator.init(allocator),
            .entries = std.ArrayList(Entry).init(allocator),
        };
    }

    pub fn deinit(self: *Vault) void {
        self.entries.deinit();
        self.arena.deinit();
    }

    /// Load and unlock the vault file `name` inside `dir`.
    pub fn loadFrom(allocator: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, password: []const u8) !Vault {
        var vault = initEmpty(allocator);
        errdefer vault.deinit();

        const bytes = try dir.readFileAlloc(allocator, name, max_vault_bytes);
        defer allocator.free(bytes);
        if (bytes.len < magic.len + 1) return VaultError.InvalidMagic;
        if (!std.mem.eql(u8, bytes[0..magic.len], magic)) return VaultError.InvalidMagic;
        if (bytes[magic.len] != version) return VaultError.UnsupportedVersion;

        const plain = try crypto.decrypt(allocator, password, bytes[magic.len + 1 ..]);
        defer allocator.free(plain);
        var parsed = try std.json.parseFromSlice(VaultData, allocator, plain, .{});
        defer parsed.deinit();

        const a = vault.arena.allocator();
        for (parsed.value.entries) |e| {
            try vault.entries.append(.{
                .name = try a.dupe(u8, e.name),
                .username = try a.dupe(u8, e.username),
                .password = try a.dupe(u8, e.password),
                .notes = try a.dupe(u8, e.notes),
            });
        }
        return vault;
    }

    /// Seal and atomically store this vault as `name` inside `dir`.
    pub fn saveTo(self: *Vault, dir: std.fs.Dir, name: []const u8, password: []const u8) !void {
        const allocator = self.arena.allocator();
        const data = VaultData{ .entries = self.entries.items };
        const plain = try std.json.stringifyAlloc(allocator, data, .{});
        const blob = try crypto.encrypt(allocator, password, plain);

        var out = try allocator.alloc(u8, magic.len + 1 + blob.len);
        @memcpy(out[0..magic.len], magic);
        out[magic.len] = version;
        @memcpy(out[magic.len + 1 ..], blob);

        const tmp_name = try std.fmt.allocPrint(allocator, "{s}.tmp", .{name});
        var file = try dir.createFile(tmp_name, .{ .truncate = true, .mode = 0o600 });
        try file.writeAll(out);
        file.close();
        try dir.rename(tmp_name, name);
    }

    pub fn find(self: *Vault, name: []const u8) ?*Entry {
        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, e.name, name)) return e;
        }
        return null;
    }

    /// Append an entry; fails with `EntryExists` on a duplicate name.
    pub fn add(self: *Vault, entry: Entry) !void {
        if (self.find(entry.name) != null) return VaultError.EntryExists;
        const a = self.arena.allocator();
        try self.entries.append(.{
            .name = try a.dupe(u8, entry.name),
            .username = try a.dupe(u8, entry.username),
            .password = try a.dupe(u8, entry.password),
            .notes = try a.dupe(u8, entry.notes),
        });
    }

    /// Remove an entry by exact name. Returns false when it was not present.
    pub fn remove(self: *Vault, name: []const u8) bool {
        for (self.entries.items, 0..) |e, i| {
            if (std.mem.eql(u8, e.name, name)) {
                _ = self.entries.orderedRemove(i);
                return true;
            }
        }
        return false;
    }
};

/// Case-insensitive substring match over name, username and notes.
/// An empty query matches every entry.
pub fn matches(entry: Entry, query: []const u8) bool {
    if (query.len == 0) return true;
    return containsIgnoreCase(entry.name, query) or
        containsIgnoreCase(entry.username, query) or
        containsIgnoreCase(entry.notes, query);
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var ok = true;
        for (needle, 0..) |c, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(c)) {
                ok = false;
                break;
            }
        }
        if (ok) return true;
    }
    return false;
}

fn sampleVault(allocator: std.mem.Allocator) !Vault {
    var vault = Vault.initEmpty(allocator);
    try vault.add(.{ .name = "github", .username = "karn", .password = "s3cret", .notes = "personal account" });
    try vault.add(.{ .name = "bank", .username = "karn@example.com", .password = "hunter2" });
    return vault;
}

test "vault save/load round-trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var vault = try sampleVault(allocator);
    defer vault.deinit();
    try vault.saveTo(tmp.dir, "vault.pm", "master-pw");

    var loaded = try Vault.loadFrom(allocator, tmp.dir, "vault.pm", "master-pw");
    defer loaded.deinit();
    try std.testing.expectEqual(@as(usize, 2), loaded.entries.items.len);
    const gh = loaded.find("github").?;
    try std.testing.expectEqualStrings("karn", gh.username);
    try std.testing.expectEqualStrings("s3cret", gh.password);
    try std.testing.expectEqualStrings("personal account", gh.notes);
    try std.testing.expectEqualStrings("", loaded.find("bank").?.notes);
}

test "vault wrong master password fails" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var vault = try sampleVault(allocator);
    defer vault.deinit();
    try vault.saveTo(tmp.dir, "vault.pm", "right");
    try std.testing.expectError(
        crypto.CryptoError.AuthenticationFailed,
        Vault.loadFrom(allocator, tmp.dir, "vault.pm", "wrong"),
    );
}

test "vault bad magic and version are rejected" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile("bad.pm", .{});
    try file.writeAll("NOPE\x01junkjunkjunkjunkjunkjunk");
    file.close();
    try std.testing.expectError(VaultError.InvalidMagic, Vault.loadFrom(allocator, tmp.dir, "bad.pm", "pw"));

    var file2 = try tmp.dir.createFile("future.pm", .{});
    try file2.writeAll("PMV1\x09junkjunkjunkjunkjunkjunk");
    file2.close();
    try std.testing.expectError(VaultError.UnsupportedVersion, Vault.loadFrom(allocator, tmp.dir, "future.pm", "pw"));
}

test "vault add duplicate and remove" {
    const allocator = std.testing.allocator;
    var vault = Vault.initEmpty(allocator);
    defer vault.deinit();
    try vault.add(.{ .name = "a", .username = "u", .password = "p" });
    try std.testing.expectError(VaultError.EntryExists, vault.add(.{ .name = "a", .username = "u2", .password = "p2" }));
    try std.testing.expectEqual(@as(usize, 1), vault.entries.items.len);
    try std.testing.expect(vault.remove("a"));
    try std.testing.expect(!vault.remove("a"));
    try std.testing.expectEqual(@as(usize, 0), vault.entries.items.len);
}

test "vault search matches case-insensitively" {
    const e = Entry{ .name = "GitHub", .username = "KarnDev", .password = "p", .notes = "code hosting" };
    try std.testing.expect(matches(e, "git"));
    try std.testing.expect(matches(e, "KARN"));
    try std.testing.expect(matches(e, "host"));
    try std.testing.expect(!matches(e, "bank"));
    try std.testing.expect(matches(e, ""));
}
