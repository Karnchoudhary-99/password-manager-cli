const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const stdout = std.io.getStdOut().writer();
    if (args.len < 2 or std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "help")) {
        try stdout.writeAll(
            \\Usage: pm <command>
            \\
            \\Commands (coming with the vault):
            \\  add <name>     store a new entry
            \\  get <name>     retrieve an entry
            \\  list           list entry names
            \\  gen            generate a password
            \\
        );
        return;
    }
    try stdout.print("pm: unknown command '{s}' (try: pm --help)\n", .{args[1]});
    std.process.exit(1);
}

test "smoke" {
    try std.testing.expect(true);
}
