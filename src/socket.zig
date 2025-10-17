const std = @import("std");

sock: std.posix.socket_t,
addr: std.net.Address,

pub const Options = struct {
    addr: std.net.Address,
    blocking: bool = true,
};

pub fn open(opt: Options) !@This() {
    var flags: u32 = std.posix.SOCK.DGRAM;
    if (!opt.blocking) flags = flags | std.posix.SOCK.NONBLOCK;
    const self: @This() = .{
        .addr = opt.addr,
        .sock = try std.posix.socket(
            std.posix.AF.INET,
            flags,
            std.posix.IPPROTO.UDP,
        ),
    };
    try std.posix.setsockopt(
        self.sock,
        std.posix.SOL.SOCKET,
        std.posix.SO.REUSEADDR,
        &std.mem.toBytes(@as(c_int, 1)),
    );
    if (@hasDecl(std.posix.SO, "REUSEPORT")) {
        try std.posix.setsockopt(
            self.sock,
            std.posix.SOL.SOCKET,
            std.posix.SO.REUSEPORT,
            &std.mem.toBytes(@as(c_int, 1)),
        );
    }
    try std.posix.setsockopt(
        self.sock,
        std.posix.IPPROTO.IP,
        std.os.linux.IP.MULTICAST_TTL,
        &.{255},
    );
    try std.posix.setsockopt(
        self.sock,
        std.posix.IPPROTO.IP,
        std.os.linux.IP.TTL,
        &.{255},
    );
    try std.posix.setsockopt(
        self.sock,
        std.posix.IPPROTO.IP,
        std.os.linux.IP.MULTICAST_LOOP,
        &.{1},
    );

    try std.posix.bind(self.sock, &opt.addr.any, opt.addr.getOsSockLen());
    const addr_any = try std.net.Address.resolveIp("0.0.0.0", opt.addr.getPort());
    try std.posix.setsockopt(
        self.sock,
        std.posix.IPPROTO.IP,
        std.os.linux.IP.ADD_MEMBERSHIP,
        @ptrCast(&ip_mreqn{
            .imr_multiaddr = @as(*const [4]u8, @ptrCast(&opt.addr.in.sa.addr)).*,
            .imr_address = @as(*const [4]u8, @ptrCast(&addr_any.in.sa.addr)).*,
        }),
    );

    return self;
}

pub fn send(self: @This(), data: []const u8) !void {
    const res = try std.posix.sendto(
        self.sock,
        data,
        0,
        &self.addr.any,
        self.addr.getOsSockLen(),
    );
    if (res != data.len) return error.SendSocket;
}

pub fn receive(self: @This(), buf: []u8) ![]u8 {
    const len = try std.posix.recv(self.sock, buf, 0);
    return buf[0..len];
}

pub fn close(self: @This()) void {
    std.posix.close(self.sock);
}

pub const ip_mreqn = extern struct {
    /// multicast group address
    imr_multiaddr: [4]u8 = @splat(0),
    /// local ip address
    imr_address: [4]u8 = @splat(0),
    // Interface index; cast to uint32_t
    imr_ifindex: u32 = 0,
};
