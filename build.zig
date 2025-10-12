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
        .root_module = mdns,
    });
    b.installArtifact(mdns_listen);
    b.step("run", "").dependOn(&b.addRunArtifact(mdns_listen).step);

    const mdtest = b.addTest(.{
        .root_module = mdns,
    });

    b.step("test", "").dependOn(&b.addRunArtifact(mdtest).step);
}
