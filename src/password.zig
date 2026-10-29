//! Master-password input and vault location.
//!
//! The master password comes from `PM_MASTER_PASSWORD` when set (scripts,
//! tests, CI) and otherwise from an interactive prompt that disables
//! terminal echo while typing, so the secret never appears on screen or
//! in shell history. The vault lives at `PM_VAULT` when set, else
//! `$HOME/.pm-vault`.

const std = @import("std");

/// Read a password: env var first, else a (hidden, on a TTY) prompt.
/// The caller owns the returned slice.
pub fn promptPassword(allocator: std.mem.Allocator, prompt: []const u8) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, "PM_MASTER_PASSWORD")) |pw| {
        return pw;
    } else |_| {}
    return promptInteractive(allocator, prompt);
}

/// Read a NEW master password for `change-password`: `PM_NEW_MASTER_PASSWORD`
/// first (scripts/tests), else an interactive prompt. It must NOT fall back
/// to `PM_MASTER_PASSWORD` — that would silently "change" the password to
/// itself. The caller owns the returned slice.
pub fn promptNewPassword(allocator: std.mem.Allocator, prompt: []const u8) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, "PM_NEW_MASTER_PASSWORD")) |pw| {
        return pw;
    } else |_| {}
    return promptInteractive(allocator, prompt);
}

/// Interactive prompt with terminal echo disabled on a TTY.
fn promptInteractive(allocator: std.mem.Allocator, prompt: []const u8) ![]u8 {
    const stderr = std.io.getStdErr().writer();
    try stderr.writeAll(prompt);
    const stdin = std.io.getStdIn();
    const is_tty = std.posix.isatty(stdin.handle);

    // Echo is disabled only on a TTY and always restored, even if
    // reading fails. (On Linux, lflag is a packed struct with an ECHO bit.)
    var original: ?std.posix.termios = null;
    if (is_tty) {
        if (std.posix.tcgetattr(stdin.handle)) |t| {
            original = t;
            var noecho = t;
            if (comptime @import("builtin").os.tag == .linux) {
                noecho.lflag.ECHO = false;
            }
            std.posix.tcsetattr(stdin.handle, .NOW, noecho) catch {};
        } else |_| {}
    }
    defer if (original) |t| {
        std.posix.tcsetattr(stdin.handle, .NOW, t) catch {};
    };

    const line = try stdin.reader().readUntilDelimiterOrEofAlloc(allocator, '\n', 4096);
    if (is_tty) try stderr.writeAll("\n");
    if (line) |l| return allocator.dupe(u8, trimLineEnd(l));
    return allocator.dupe(u8, "");
}

/// The vault file path: `PM_VAULT`, else `$HOME/.pm-vault`, else a
/// `./.pm-vault` fallback when HOME is unset. Caller owns the result.
pub fn defaultVaultPath(allocator: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, "PM_VAULT")) |p| {
        return p;
    } else |_| {}
    if (std.process.getEnvVarOwned(allocator, "HOME")) |home| {
        defer allocator.free(home);
        return std.fmt.allocPrint(allocator, "{s}/.pm-vault", .{home});
    } else |_| {}
    return allocator.dupe(u8, ".pm-vault");
}

fn trimLineEnd(line: []const u8) []const u8 {
    var end = line.len;
    while (end > 0 and (line[end - 1] == '\r' or line[end - 1] == '\n')) end -= 1;
    return line[0..end];
}

test "password line trimming" {
    try std.testing.expectEqualStrings("secret", trimLineEnd("secret\r\n"));
    try std.testing.expectEqualStrings("secret", trimLineEnd("secret\n"));
    try std.testing.expectEqualStrings("", trimLineEnd("\r\n"));
}
