const std = @import("std");
const mdns = @import("mdns.zig");
const Socket = @import("socket.zig");

pub fn main() !void {
    var gpa_impl = std.heap.GeneralPurposeAllocator(.{}).init;
    const gpa = gpa_impl.allocator();
    defer _ = gpa_impl.deinit();

    const addr = try std.net.Address.parseIp("224.0.0.251", 5353);
    const sock = try Socket.open(.{
        .addr = addr,
    });
    defer sock.close();

    const stdout_fd = std.fs.File.stdout();
    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer = stdout_fd.writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    var pac_buf: [1024]u8 = undefined;
    while (true) {
        const data = try sock.receive(&pac_buf);
        if (data.len < mdns.Packet.HeaderSize) continue;
        try stdout.print("data: \"{f}\"\n", .{std.zig.fmtString(data)});
        var packet: mdns.Packet = .{};
        packet.parse(gpa, data) catch |err| {
            try stdout.print("parse error: \"{}\"\n", .{err});
            continue;
        };
        defer packet.deinit(gpa);

        try stdout.print("packet: {f}\nskipped_records: {d}\n", .{
            std.json.fmt(packet.header, .{}),
            packet.skipped_records,
        });
        for (packet.questions, 0..) |q, i| {
            try stdout.print("q: {d}\n{f}\n", .{
                i,
                std.json.fmt(q, .{}),
            });
        }
        for (packet.records, 0..) |r, i| {
            try stdout.print("r: {d}\n{f}\n", .{
                i,
                std.json.fmt(r, .{}),
            });
        }
        try stdout.flush();
    }
}
