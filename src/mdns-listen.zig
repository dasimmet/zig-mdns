const std = @import("std");
const mdns = @import("mdns.zig");

pub fn main() !void {
    var gpa_impl = std.heap.GeneralPurposeAllocator(.{}).init;
    const gpa = gpa_impl.allocator();
    defer _ = gpa_impl.deinit();

    const addr = try std.net.Address.parseIp("224.0.0.251", 5353);
    const sock = try std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.DGRAM,
        std.posix.IPPROTO.UDP,
    );
    defer std.posix.close(sock);
    try std.posix.setsockopt(
        sock,
        std.posix.SOL.SOCKET,
        std.posix.SO.REUSEADDR,
        &std.mem.toBytes(@as(c_int, 1)),
    );
    try std.posix.bind(sock, &addr.any, addr.getOsSockLen());

    const addr_any = try std.net.Address.resolveIp("0.0.0.0", 5353);
    try std.posix.setsockopt(
        sock,
        std.posix.IPPROTO.IP,
        std.os.linux.IP.ADD_MEMBERSHIP,
        @ptrCast(&mdns.ip_mreqn{
            .imr_multiaddr = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr)).*,
            .imr_address = @as(*const [4]u8, @ptrCast(&addr_any.in.sa.addr)).*,
        }),
    );

    const stdout_fd = std.fs.File.stdout();
    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer = stdout_fd.writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    var pac_buf: [1024]u8 = undefined;
    while (true) {
        const len = try std.posix.recv(sock, &pac_buf, 0);
        if (len < mdns.Packet.HeaderSize) continue;
        const data = pac_buf[0..len];
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

// try stdout.print("packet: {f}\n", .{struct {
//     pac: mdns.Packet,
//     pub fn format(self: @This(), w: *std.io.Writer) !void {
//         return std.zon.stringify.serialize(self.pac, .{}, w);
//     }
// }{
//     .pac = packet,
// }});
