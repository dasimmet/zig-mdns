const std = @import("std");
const mdns = @import("mdns.zig");

pub fn main() !void {
    var gpa_impl = std.heap.GeneralPurposeAllocator(.{}).init;
    const gpa = gpa_impl.allocator();
    defer _ = gpa_impl.deinit();

    const addr = try std.net.Address.parseIp("224.0.0.251", 5353);
    const addr2 = try std.net.Address.parseIp("0.0.0.0", 5353);
    const sock = try std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK,
        std.posix.IPPROTO.UDP,
    );
    defer std.posix.close(sock);
    try std.posix.setsockopt(
        sock,
        std.posix.SOL.SOCKET,
        std.posix.SO.REUSEADDR,
        &std.mem.toBytes(@as(c_int, 1)),
    );
    try std.posix.bind(sock, &addr2.any, addr.getOsSockLen());
    try std.posix.setsockopt(
        sock,
        std.posix.SOL.IP,
        std.os.linux.IP.ADD_MEMBERSHIP,
        &.{224,0,0,251},
    );

    const stdout_fd = std.fs.File.stdout();
    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer = stdout_fd.writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    const query = "\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x0b_googlecast\x04_tcp\x05local\x00\x00\x0c\x80\x01\x05_http\xc0\x18\x00\x0c\x80\x01";
    _ = try std.posix.sendto(sock, query, 0, &addr.any, addr.getOsSockLen());

    const t = std.time.microTimestamp();
    var pac_buf: [1024]u8 = undefined;
    while (std.time.microTimestamp() - t < 3 * std.time.us_per_s) {
        const len = std.posix.recv(sock, &pac_buf, 0) catch |err| switch (err) {
            error.WouldBlock => {
                std.Thread.sleep(std.time.ms_per_s);
                continue;
            },
            else => return err,
        };
        if (len < mdns.Packet.HeaderSize) continue;
        const data = pac_buf[0..len];
        try stdout.print("data: \"{f}\"\n", .{std.zig.fmtString(data)});
        var packet: mdns.Packet = undefined;
        packet.parse(gpa, data) catch |err| {
            try stdout.print("parse error: \"{}\"\n", .{err});
            packet.deinit(gpa);
            continue;
        };
        defer packet.deinit(gpa);

        try stdout.print("packet: {f} skipped_records: {d}\n", .{
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
