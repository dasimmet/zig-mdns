const std = @import("std");
const builtin = @import("builtin");

sock: std.posix.socket_t,
group: std.net.Address,
bind: std.net.Address,

pub const Options = struct {
    group: std.net.Address = mdns_addr,
    bind: std.net.Address = zero_addr,
    blocking: bool = true,
};

const zero_addr = std.net.Address.parseIp("0.0.0.0", 5353) catch unreachable;
const mdns_addr = std.net.Address.parseIp("224.0.0.251", 5353) catch unreachable;

pub fn open(opt: Options) !@This() {
    var flags: u32 = std.posix.SOCK.DGRAM;
    if (!opt.blocking) flags = flags | std.posix.SOCK.NONBLOCK;
    const self: @This() = .{
        .group = opt.group,
        .bind = opt.bind,
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
        os.MULTICAST_TTL,
        &.{255},
    );
    try std.posix.setsockopt(
        self.sock,
        std.posix.IPPROTO.IP,
        os.IP_TTL,
        &.{255},
    );
    try std.posix.setsockopt(
        self.sock,
        std.posix.IPPROTO.IP,
        os.MULTICAST_LOOP,
        &.{1},
    );

    try std.posix.bind(
        self.sock,
        &opt.bind.any,
        opt.bind.getOsSockLen(),
    );
    try std.posix.setsockopt(
        self.sock,
        std.posix.IPPROTO.IP,
        os.IP_ADD_MEMBERSHIP,
        @ptrCast(&ip_mreqn{
            .imr_multiaddr = @as(*const [4]u8, @ptrCast(&opt.group.in.sa.addr)).*,
            .imr_sourceaddr = @as(*const [4]u8, @ptrCast(&opt.bind.in.sa.addr)).*,
        }),
    );

    return self;
}

pub fn send(self: @This(), data: []const u8) !void {
    const res = try std.posix.sendto(
        self.sock,
        data,
        0,
        &self.group.any,
        self.group.getOsSockLen(),
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

pub const os = switch (builtin.os.tag) {
    .linux => struct {
        pub const IP_ADD_MEMBERSHIP: c_int = std.os.linux.IP.ADD_MEMBERSHIP;
        pub const IP_TTL: c_int = std.os.linux.IP.TTL;
        pub const MULTICAST_LOOP: c_int = std.os.linux.IP.MULTICAST_LOOP;
        pub const MULTICAST_TTL: c_int = std.os.linux.IP.MULTICAST_TTL;
    },
    .windows => struct {
        pub const IP_TTL: c_int = std.os.windows.ws2_32.IP_TTL; // winsock.IP_TTL
        pub const MULTICAST_LOOP: c_int = std.os.windows.ws2_32.IP_MULTICAST_LOOP; // winsock.IP_MULTICAST_LOOP
        pub const IP_ADD_MEMBERSHIP: c_int = std.os.windows.ws2_32.IP_ADD_MEMBERSHIP; // winsock.IP_ADD_SOURCE_MEMBERSHIP
        pub const MULTICAST_TTL: c_int = std.os.windows.ws2_32.IP_MULTICAST_TTL; // winsock.IP_MULTICAST_TTL;
    },
    else => @compileError("OS NOT SUPPORTED: " ++ @tagName(builtin.os.tag)),
};

pub const ip_mreqn = extern struct {
    /// multicast group address
    imr_multiaddr: [4]u8 = @splat(0),
    /// local ip address
    imr_sourceaddr: [4]u8 = @splat(0),
    // Interface index; cast to uint32_t
    imr_interface: u32 = 0,
};

// pub const IN_ADDR = extern struct {
//     S_un: extern union {
//         S_un_b: extern struct {
//             s_b1: u8 = 0,
//             s_b2: u8 = 0,
//             s_b3: u8 = 0,
//             s_b4: u8 = 0,
//         },
//         S_un_w: extern struct {
//             s_w1: c_ushort = 0,
//             s_w2: c_ushort = 0,
//         },
//         S_addr: winsock.u_long,
//     },
// };
// pub const struct_ip_mreq_source = extern struct {
//     imr_multiaddr: IN_ADDR = @import("std").mem.zeroes(IN_ADDR),
//     imr_sourceaddr: IN_ADDR = @import("std").mem.zeroes(IN_ADDR),
//     imr_interface: IN_ADDR = @import("std").mem.zeroes(IN_ADDR),
// };
