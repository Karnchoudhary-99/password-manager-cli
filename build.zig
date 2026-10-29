const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "pm",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // One test artifact per module: `zig test` on main.zig alone only runs
    // main's own tests, so each module gets its own artifact here and
    // `zig build test` runs the whole suite (14 unique tests; the crypto
    // tests also run a second time as part of the vault artifact).
    const test_step = b.step("test", "Run unit tests");
    const test_files = [_][]const u8{
        "src/main.zig",
        "src/crypto.zig",
        "src/vault.zig",
        "src/password.zig",
    };
    for (test_files) |file| {
        const unit_tests = b.addTest(.{
            .root_source_file = b.path(file),
            .target = target,
            .optimize = optimize,
        });
        const run_unit_tests = b.addRunArtifact(unit_tests);
        test_step.dependOn(&run_unit_tests.step);
    }
}
