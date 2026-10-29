//! Key derivation and authenticated encryption for the vault.
//!
//! A master password is stretched with scrypt (interactive parameters) into
//! a 256-bit key, which then seals plaintext with AES-256-GCM. The sealed
//! blob layout is:
//!
//! ```text
//! salt (16 bytes) || nonce (12 bytes) || ciphertext || tag (16 bytes)
//! ```
//!
//! The salt and nonce are fresh randomness per encryption, so two seals of
//! the same plaintext differ. A wrong password (or any tampering) fails
//! authentication instead of returning garbage.

const std = @import("std");
const scrypt = std.crypto.pwhash.scrypt;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const salt_length = 16;
pub const nonce_length = Aes256Gcm.nonce_length;
pub const tag_length = Aes256Gcm.tag_length;
pub const key_length = Aes256Gcm.key_length;

/// Overhead added to a plaintext by `encrypt`: salt + nonce + tag.
pub const overhead = salt_length + nonce_length + tag_length;

pub const CryptoError = error{
    TooShort,
    AuthenticationFailed,
};

/// Stretch `password` with `salt` into a 256-bit encryption key.
/// Uses scrypt's interactive parameters: fast enough for a CLI unlock
/// (~0.1s) while still costing an attacker real memory per guess.
pub fn deriveKey(password: []const u8, salt: [salt_length]u8) ![key_length]u8 {
    var key: [key_length]u8 = undefined;
    try scrypt.kdf(std.heap.page_allocator, &key, password, &salt, scrypt.Params.interactive);
    return key;
}

/// Seal `plaintext` under `password`. The caller owns the returned blob.
pub fn encrypt(allocator: std.mem.Allocator, password: []const u8, plaintext: []const u8) ![]u8 {
    var salt: [salt_length]u8 = undefined;
    var nonce: [nonce_length]u8 = undefined;
    std.crypto.random.bytes(&salt);
    std.crypto.random.bytes(&nonce);

    const key = try deriveKey(password, salt);
    const out = try allocator.alloc(u8, plaintext.len + overhead);
    errdefer allocator.free(out);

    const salt_part = out[0..salt_length];
    const nonce_part = out[salt_length .. salt_length + nonce_length];
    const cipher_part = out[salt_length + nonce_length .. salt_length + nonce_length + plaintext.len];
    const tag_part = out[salt_length + nonce_length + plaintext.len ..][0..tag_length];

    @memcpy(salt_part, &salt);
    @memcpy(nonce_part, &nonce);
    var tag: [tag_length]u8 = undefined;
    Aes256Gcm.encrypt(cipher_part, &tag, plaintext, "", nonce, key);
    @memcpy(tag_part, &tag);
    return out;
}

/// Open a blob produced by `encrypt`. The caller owns the returned plaintext.
/// Fails with `AuthenticationFailed` on a wrong password or any tampering.
pub fn decrypt(allocator: std.mem.Allocator, password: []const u8, blob: []const u8) ![]u8 {
    if (blob.len < overhead) return CryptoError.TooShort;
    const salt: [salt_length]u8 = blob[0..salt_length].*;
    const nonce: [nonce_length]u8 = blob[salt_length .. salt_length + nonce_length].*;
    const cipher = blob[salt_length + nonce_length .. blob.len - tag_length];
    const tag: [tag_length]u8 = blob[blob.len - tag_length ..][0..tag_length].*;

    const key = try deriveKey(password, salt);
    const out = try allocator.alloc(u8, cipher.len);
    Aes256Gcm.decrypt(out, cipher, tag, "", nonce, key) catch {
        allocator.free(out);
        return CryptoError.AuthenticationFailed;
    };
    return out;
}

test "crypto round-trip" {
    const allocator = std.testing.allocator;
    const blob = try encrypt(allocator, "correct horse", "hello, vault");
    defer allocator.free(blob);
    const plain = try decrypt(allocator, "correct horse", blob);
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("hello, vault", plain);
}

test "crypto round-trip empty plaintext" {
    const allocator = std.testing.allocator;
    const blob = try encrypt(allocator, "pw", "");
    defer allocator.free(blob);
    try std.testing.expectEqual(blob.len, overhead);
    const plain = try decrypt(allocator, "pw", blob);
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("", plain);
}

test "crypto wrong password fails authentication" {
    const allocator = std.testing.allocator;
    const blob = try encrypt(allocator, "right-password", "secret");
    defer allocator.free(blob);
    try std.testing.expectError(CryptoError.AuthenticationFailed, decrypt(allocator, "wrong-password", blob));
}

test "crypto tampered ciphertext fails authentication" {
    const allocator = std.testing.allocator;
    var blob = try encrypt(allocator, "pw", "secret");
    defer allocator.free(blob);
    blob[blob.len - 1] ^= 0xff; // flip a tag byte
    try std.testing.expectError(CryptoError.AuthenticationFailed, decrypt(allocator, "pw", blob));
}

test "crypto same plaintext seals differently" {
    const allocator = std.testing.allocator;
    const a = try encrypt(allocator, "pw", "same");
    defer allocator.free(a);
    const b = try encrypt(allocator, "pw", "same");
    defer allocator.free(b);
    try std.testing.expect(!std.mem.eql(u8, a, b));
}

test "crypto short blob is rejected" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(CryptoError.TooShort, decrypt(allocator, "pw", "tiny"));
}

test "crypto derived keys are deterministic per salt" {
    const salt = [_]u8{7} ** salt_length;
    const a = try deriveKey("pw", salt);
    const b = try deriveKey("pw", salt);
    try std.testing.expectEqualSlices(u8, &a, &b);
    const other_salt = [_]u8{8} ** salt_length;
    const c = try deriveKey("pw", other_salt);
    try std.testing.expect(!std.mem.eql(u8, &a, &c));
}
