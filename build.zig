const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mdns = b.addModule("mdns", .{
        .root_source_file = b.path("src/mdns.zig"),
        .target = target,
        .optimize = optimize,
    });

    const mdns_listen = b.addExecutable(.{
        .name = "mdns-listen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/mdns-listen.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    if (target.result.os.tag == .windows) mdns_listen.linkLibC();
    b.installArtifact(mdns_listen);
    b.step("listen", "").dependOn(&b.addRunArtifact(mdns_listen).step);

    const mdns_query = b.addExecutable(.{
        .name = "mdns-query",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/mdns-query.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    if (target.result.os.tag == .windows) mdns_query.linkLibC();
    b.installArtifact(mdns_query);
    const run_query = b.addRunArtifact(mdns_query);
    b.step("query", "").dependOn(&run_query.step);
    if (b.args) |args| {
        run_query.addArgs(args);
    }

    const mdtest = b.addTest(.{
        .root_module = mdns,
        .use_llvm = true,
    });

    b.step("test", "").dependOn(&b.addRunArtifact(mdtest).step);
}
