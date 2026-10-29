//! Password generation: uniform random picks from configurable character
//! sets, with guaranteed coverage (at least one character from every
//! enabled set) and an honest entropy report.
//!
//! Generation takes a `std.Random` so the CLI can pass the OS crypto
//! random (`std.crypto.random`) while tests pass a seeded PRNG. The
//! entropy figure is the theoretical maximum for uniform picks from the
//! charset: `length * log2(charset size)` bits. Coverage enforcement
//! (overwriting a few positions) costs a fraction of a bit on short
//! passwords and is not subtracted — the reported figure is an upper
//! bound, and the strength bands below are conservative.

const std = @import("std");

pub const lower = "abcdefghijklmnopqrstuvwxyz";
pub const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const digits = "0123456789";
pub const symbols = "!@#$%^&*()-_=+[]{};:,.<>?";

pub const Options = struct {
    length: usize = 20,
    use_lower: bool = true,
    use_upper: bool = true,
    use_digits: bool = true,
    use_symbols: bool = true,
};

pub const GeneratorError = error{
    NoCharacterSets,
    LengthTooShort,
};

/// The pooled charset for the given options, in lower/upper/digits/symbols
/// order. Caller owns the returned slice.
pub fn charset(allocator: std.mem.Allocator, opts: Options) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    if (opts.use_lower) try out.appendSlice(lower);
    if (opts.use_upper) try out.appendSlice(upper);
    if (opts.use_digits) try out.appendSlice(digits);
    if (opts.use_symbols) try out.appendSlice(symbols);
    return out.toOwnedSlice();
}

const SetList = struct {
    items: [4][]const u8,
    len: usize,
};

fn enabledSets(opts: Options) SetList {
    var sets: [4][]const u8 = undefined;
    var n: usize = 0;
    if (opts.use_lower) {
        sets[n] = lower;
        n += 1;
    }
    if (opts.use_upper) {
        sets[n] = upper;
        n += 1;
    }
    if (opts.use_digits) {
        sets[n] = digits;
        n += 1;
    }
    if (opts.use_symbols) {
        sets[n] = symbols;
        n += 1;
    }
    return .{ .items = sets, .len = n };
}

/// Number of enabled character sets (0 when all are off).
pub fn setCount(opts: Options) usize {
    var n: usize = 0;
    if (opts.use_lower) n += 1;
    if (opts.use_upper) n += 1;
    if (opts.use_digits) n += 1;
    if (opts.use_symbols) n += 1;
    return n;
}

/// Generate a password. Fails when no set is enabled or when the length
/// cannot hold one character per enabled set. Caller owns the result.
pub fn generate(allocator: std.mem.Allocator, random: std.Random, opts: Options) ![]u8 {
    const sets = enabledSets(opts);
    if (sets.len == 0) return GeneratorError.NoCharacterSets;
    if (opts.length < sets.len) return GeneratorError.LengthTooShort;
    const set_list = sets.items[0..sets.len];

    const pool = try charset(allocator, opts);
    defer allocator.free(pool);

    const out = try allocator.alloc(u8, opts.length);
    errdefer allocator.free(out);
    for (out) |*c| {
        c.* = pool[random.intRangeLessThan(usize, 0, pool.len)];
    }

    // Guarantee coverage: overwrite one distinct position per set with a
    // character drawn from that set.
    var used = std.AutoHashMap(usize, void).init(allocator);
    defer used.deinit();
    for (set_list) |set| {
        var pos = random.intRangeLessThan(usize, 0, opts.length);
        while (used.contains(pos)) {
            pos = random.intRangeLessThan(usize, 0, opts.length);
        }
        try used.put(pos, {});
        out[pos] = set[random.intRangeLessThan(usize, 0, set.len)];
    }
    return out;
}

/// Theoretical entropy in bits for uniform picks from the charset.
pub fn entropyBits(opts: Options) f64 {
    var size: usize = 0;
    if (opts.use_lower) size += lower.len;
    if (opts.use_upper) size += upper.len;
    if (opts.use_digits) size += digits.len;
    if (opts.use_symbols) size += symbols.len;
    if (size == 0) return 0;
    return @as(f64, @floatFromInt(opts.length)) * @log2(@as(f64, @floatFromInt(size)));
}

/// Plain-language strength band for an entropy figure.
pub fn strength(bits: f64) []const u8 {
    if (bits < 50) return "weak";
    if (bits < 80) return "moderate";
    return "strong";
}

fn containsAny(password: []const u8, set: []const u8) bool {
    for (password) |c| {
        if (std.mem.indexOfScalar(u8, set, c) != null) return true;
    }
    return false;
}

test "generator covers every enabled set and stays in charset" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(1234);
    const opts = Options{ .length = 32 };
    const pw = try generate(allocator, prng.random(), opts);
    defer allocator.free(pw);
    try std.testing.expectEqual(@as(usize, 32), pw.len);
    const pool = try charset(allocator, opts);
    defer allocator.free(pool);
    for (pw) |c| {
        try std.testing.expect(std.mem.indexOfScalar(u8, pool, c) != null);
    }
    try std.testing.expect(containsAny(pw, lower));
    try std.testing.expect(containsAny(pw, upper));
    try std.testing.expect(containsAny(pw, digits));
    try std.testing.expect(containsAny(pw, symbols));
}

test "generator honours disabled sets" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(7);
    const opts = Options{ .length = 24, .use_symbols = false, .use_upper = false };
    const pw = try generate(allocator, prng.random(), opts);
    defer allocator.free(pw);
    try std.testing.expect(containsAny(pw, lower));
    try std.testing.expect(containsAny(pw, digits));
    try std.testing.expect(!containsAny(pw, upper));
    try std.testing.expect(!containsAny(pw, symbols));
}

test "generator rejects empty charset and too-short length" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(1);
    const random = prng.random();
    try std.testing.expectError(
        GeneratorError.NoCharacterSets,
        generate(allocator, random, .{ .use_lower = false, .use_upper = false, .use_digits = false, .use_symbols = false }),
    );
    try std.testing.expectError(
        GeneratorError.LengthTooShort,
        generate(allocator, random, .{ .length = 2 }),
    );
}

test "generator entropy and strength bands" {
    // 20 chars over 87 symbols: 20 * log2(87) ~= 128.9 bits.
    const bits = entropyBits(.{ .length = 20 });
    try std.testing.expect(bits > 128 and bits < 130);
    try std.testing.expectEqualStrings("weak", strength(40));
    try std.testing.expectEqualStrings("moderate", strength(60));
    try std.testing.expectEqualStrings("strong", strength(128.9));
    try std.testing.expectEqual(@as(f64, 0), entropyBits(.{
        .use_lower = false,
        .use_upper = false,
        .use_digits = false,
        .use_symbols = false,
    }));
}
