//! Plaintext import/export formats for vault entries.
//!
//! Export exists for migration and backup tooling, not for routine use:
//! an exported file holds secrets in plaintext, so `pm export --out`
//! writes it with `0600` permissions and the CLI warns on stdout export.
//! JSON is the native shape (an array of entries); CSV is the
//! spreadsheet-friendly shape with RFC-4180-style quoting.
//!
//! Both parsers are strict: a malformed row fails the whole import rather
//! than silently dropping an entry.

const std = @import("std");
const vault_mod = @import("vault.zig");
const Entry = vault_mod.Entry;

pub const Format = enum { json, csv };

pub const IoError = error{
    MalformedCsv,
    EmptyCsv,
};

/// The JSON shape: one object per entry. `notes` defaults to "" so older
/// exports without notes still parse.
const JsonEntry = struct {
    name: []const u8,
    username: []const u8,
    password: []const u8,
    notes: []const u8 = "",
};

/// Serialize entries as a JSON array. Caller owns the result.
pub fn toJson(allocator: std.mem.Allocator, entries: []const Entry) ![]u8 {
    return std.json.stringifyAlloc(allocator, entries, .{ .whitespace = .indent_2 });
}

/// Parse a JSON array of entries. Strings are duped into `allocator` via
/// the arena-free path: the parsed values borrow from `text`, so each
/// field is copied before `parsed` is freed. Caller owns the result.
pub fn fromJson(allocator: std.mem.Allocator, text: []const u8) ![]Entry {
    var parsed = try std.json.parseFromSlice([]JsonEntry, allocator, text, .{});
    defer parsed.deinit();
    var out = std.ArrayList(Entry).init(allocator);
    errdefer out.deinit();
    for (parsed.value) |e| {
        try out.append(.{
            .name = try allocator.dupe(u8, e.name),
            .username = try allocator.dupe(u8, e.username),
            .password = try allocator.dupe(u8, e.password),
            .notes = try allocator.dupe(u8, e.notes),
        });
    }
    return out.toOwnedSlice();
}

fn csvNeedsQuoting(field: []const u8) bool {
    for (field) |c| {
        if (c == ',' or c == '"' or c == '\n' or c == '\r') return true;
    }
    return false;
}

fn writeCsvField(writer: anytype, field: []const u8) !void {
    if (!csvNeedsQuoting(field)) {
        try writer.writeAll(field);
        return;
    }
    try writer.writeByte('"');
    for (field) |c| {
        if (c == '"') try writer.writeByte('"');
        try writer.writeByte(c);
    }
    try writer.writeByte('"');
}

/// Serialize entries as CSV with a header row. Caller owns the result.
pub fn toCsv(allocator: std.mem.Allocator, entries: []const Entry) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    const writer = out.writer();
    try writer.writeAll("name,username,password,notes\n");
    for (entries) |e| {
        try writeCsvField(writer, e.name);
        try writer.writeByte(',');
        try writeCsvField(writer, e.username);
        try writer.writeByte(',');
        try writeCsvField(writer, e.password);
        try writer.writeByte(',');
        try writeCsvField(writer, e.notes);
        try writer.writeByte('\n');
    }
    return out.toOwnedSlice();
}

/// Parse one CSV record starting at `pos`. Returns the fields and the
/// position just past the record's line ending. Handles quoted fields,
/// doubled quotes, and commas/newlines inside quotes.
fn parseCsvRecord(allocator: std.mem.Allocator, text: []const u8, pos: usize) !struct { fields: [][]u8, next: usize } {
    var fields = std.ArrayList([]u8).init(allocator);
    errdefer {
        for (fields.items) |f| allocator.free(f);
        fields.deinit();
    }
    var i = pos;
    while (true) {
        var field = std.ArrayList(u8).init(allocator);
        errdefer field.deinit();
        if (i < text.len and text[i] == '"') {
            i += 1;
            var closed = false;
            while (i < text.len) {
                if (text[i] == '"') {
                    if (i + 1 < text.len and text[i + 1] == '"') {
                        try field.append('"');
                        i += 2;
                    } else {
                        i += 1;
                        closed = true;
                        break;
                    }
                } else {
                    try field.append(text[i]);
                    i += 1;
                }
            }
            if (!closed) return IoError.MalformedCsv;
            if (i < text.len and text[i] != ',' and text[i] != '\n' and text[i] != '\r') return IoError.MalformedCsv;
        } else {
            while (i < text.len and text[i] != ',' and text[i] != '\n' and text[i] != '\r') {
                try field.append(text[i]);
                i += 1;
            }
        }
        try fields.append(try field.toOwnedSlice());
        if (i < text.len and text[i] == ',') {
            i += 1;
            // A trailing comma means exactly one more (empty) field, and
            // the record ends there — do not parse a second empty field.
            if (i >= text.len or text[i] == '\n' or text[i] == '\r') {
                try fields.append(try allocator.dupe(u8, ""));
                break;
            }
            continue;
        }
        break;
    }
    // Consume one line ending (CRLF or LF).
    if (i < text.len and text[i] == '\r') i += 1;
    if (i < text.len and text[i] == '\n') i += 1;
    return .{ .fields = try fields.toOwnedSlice(), .next = i };
}

/// Parse CSV text (header row + one entry per record). The header must be
/// exactly `name,username,password,notes`. Caller owns the result; each
/// entry's strings are individually owned.
pub fn fromCsv(allocator: std.mem.Allocator, text: []const u8) ![]Entry {
    if (text.len == 0) return IoError.EmptyCsv;
    const header = try parseCsvRecord(allocator, text, 0);
    defer {
        for (header.fields) |f| allocator.free(f);
        allocator.free(header.fields);
    }
    if (header.fields.len != 4 or
        !std.mem.eql(u8, header.fields[0], "name") or
        !std.mem.eql(u8, header.fields[1], "username") or
        !std.mem.eql(u8, header.fields[2], "password") or
        !std.mem.eql(u8, header.fields[3], "notes"))
    {
        return IoError.MalformedCsv;
    }

    var entries = std.ArrayList(Entry).init(allocator);
    errdefer {
        for (entries.items) |e| {
            allocator.free(e.name);
            allocator.free(e.username);
            allocator.free(e.password);
            allocator.free(e.notes);
        }
        entries.deinit();
    }
    var pos = header.next;
    // Skip a trailing blank line; a blank line mid-file is malformed.
    while (pos < text.len) {
        if (text[pos] == '\n' or text[pos] == '\r') {
            // Only allowed as the final line ending.
            var rest = pos;
            while (rest < text.len and (text[rest] == '\n' or text[rest] == '\r')) rest += 1;
            if (rest != text.len) return IoError.MalformedCsv;
            break;
        }
        const rec = try parseCsvRecord(allocator, text, pos);
        defer {
            for (rec.fields) |f| allocator.free(f);
            allocator.free(rec.fields);
        }
        if (rec.fields.len != 4) return IoError.MalformedCsv;
        try entries.append(.{
            .name = try allocator.dupe(u8, rec.fields[0]),
            .username = try allocator.dupe(u8, rec.fields[1]),
            .password = try allocator.dupe(u8, rec.fields[2]),
            .notes = try allocator.dupe(u8, rec.fields[3]),
        });
        pos = rec.next;
    }
    return entries.toOwnedSlice();
}

fn freeEntries(allocator: std.mem.Allocator, entries: []Entry) void {
    for (entries) |e| {
        allocator.free(e.name);
        allocator.free(e.username);
        allocator.free(e.password);
        allocator.free(e.notes);
    }
    allocator.free(entries);
}

test "json round-trip preserves every field" {
    const allocator = std.testing.allocator;
    const entries = [_]Entry{
        .{ .name = "github", .username = "karn", .password = "s3cret", .notes = "personal, with comma" },
        .{ .name = "bank", .username = "karn@example.com", .password = "hunter2" },
    };
    const text = try toJson(allocator, &entries);
    defer allocator.free(text);
    const parsed = try fromJson(allocator, text);
    defer freeEntries(allocator, parsed);
    try std.testing.expectEqual(@as(usize, 2), parsed.len);
    try std.testing.expectEqualStrings("personal, with comma", parsed[0].notes);
    try std.testing.expectEqualStrings("", parsed[1].notes);
    try std.testing.expectEqualStrings("hunter2", parsed[1].password);
}

test "csv round-trip with commas, quotes and newlines in fields" {
    const allocator = std.testing.allocator;
    const entries = [_]Entry{
        .{ .name = "weird", .username = "u,ser", .password = "pa\"ss", .notes = "line1\nline2" },
        .{ .name = "plain", .username = "p", .password = "q" },
    };
    const text = try toCsv(allocator, &entries);
    defer allocator.free(text);
    const parsed = try fromCsv(allocator, text);
    defer freeEntries(allocator, parsed);
    try std.testing.expectEqual(@as(usize, 2), parsed.len);
    try std.testing.expectEqualStrings("u,ser", parsed[0].username);
    try std.testing.expectEqualStrings("pa\"ss", parsed[0].password);
    try std.testing.expectEqualStrings("line1\nline2", parsed[0].notes);
}

test "csv rejects bad header, wrong field count and unterminated quotes" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(IoError.MalformedCsv, fromCsv(allocator, "name,username,password\nx,y,z\n"));
    try std.testing.expectError(IoError.MalformedCsv, fromCsv(allocator, "name,username,password,notes\na,b,c\n"));
    try std.testing.expectError(IoError.MalformedCsv, fromCsv(allocator, "name,username,password,notes\n\"unterminated,b,c,d\n"));
    try std.testing.expectError(IoError.EmptyCsv, fromCsv(allocator, ""));
}
