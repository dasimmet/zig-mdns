const std = @import("std");
const mdns = @import("mdns.zig");

pub fn main() !void {
    var gpa_impl = std.heap.GeneralPurposeAllocator(.{}).init;
    const gpa = gpa_impl.allocator();
    defer _ = gpa_impl.deinit();

    const addr = try std.net.Address.resolveIp("224.0.0.251", 5353);
    // const addr6 = try std.net.Address.resolveIp("ff02::fb", 5353);
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

    const query1 = "\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x0b_googlecast\x04_tcp\x05local\x00\x00\x0c\x80\x01\x05_http\xc0\x18\x00\x0c\x80\x01";
    _ = try std.posix.sendto(sock, query1, 0, &addr.any, addr.getOsSockLen());
    // const query2 = "\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x04_smb\x04_tcp\x05local\x00\x00\x0c\x00\x01\x0c_device-info\xc0\x11\x00\x0c\x00\x01";
    // const query2 = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0233\x03132\x03168\x03192\x07in-addr\x04arpa\x05local\x00\x00\x0c\x00\x01";
    // const query2 = "                                                                                                                       ";
    // _ = try std.posix.sendto(sock, query1, 0, &addr.any, addr.getOsSockLen());

    const t = std.time.microTimestamp();
    var pac_buf: [1024]u8 = undefined;
    var pacs_received: usize = 0;
    var queries_received: usize = 0;
    var responses_received: usize = 0;
    while (std.time.microTimestamp() - t < 3 * std.time.us_per_s) {
        const len = std.posix.recv(sock, &pac_buf, 0) catch |err| switch (err) {
            error.WouldBlock => {
                std.Thread.sleep(10 * std.time.ns_per_ms);
                continue;
            },
            else => return err,
        };
        pacs_received += 1;
        if (len < mdns.Packet.HeaderSize) continue;
        const data = pac_buf[0..len];
        try stdout.print("data: \"{f}\"\n", .{std.zig.fmtString(data)});
        var packet: mdns.Packet = .{};
        packet.parse(gpa, data) catch |err| {
            try stdout.print("parse error: \"{}\"\n", .{err});
            try stdout.flush();
            continue;
        };
        defer packet.deinit(gpa);
        switch (packet.header.flags.qr) {
            .query => queries_received += 1,
            .response => responses_received += 1,
        }

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

    try stdout.print("pacs: {d}\nqueries: {d}\nresponses: {d}\n", .{
        pacs_received,
        queries_received,
        responses_received,
    });
    try stdout.flush();
}

// try stdout.print("packet: {f}\n", .{struct {
//     pac: mdns.Packet,
//     pub fn format(self: @This(), w: *std.io.Writer) !void {
//         return std.zon.stringify.serialize(self.pac, .{}, w);
//     }
// }{
//     .pac = packet,
// }});
