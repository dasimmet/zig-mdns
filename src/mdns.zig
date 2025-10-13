const std = @import("std");

pub fn main() !void {
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
    var buf: [1024]u8 = undefined;
    while (true) {
        const len = try std.posix.recv(sock, &buf, 0);
        if (len < packed_size(Header)) continue;
        const data = buf[0..len];
        std.debug.print("data: \"{f}\"\n", .{std.zig.fmtString(data)});
        var packet: MDNSPacket = undefined;
        packet.from_bytes(data);
    }
}

pub const MDNSPacket = struct {
    header: Header,

    fn from_bytes(self: *@This(), src: []const u8) void {
        var namebuf: [256]u8 = undefined;
        var parser: Parser = .{
            .packet = self,
            .source = src,
            .current_name = .initBuffer(&namebuf),
        };
        parser.parse();
    }
};

const Parser = struct {
    packet: *MDNSPacket,
    current_name: std.ArrayList(u8),
    offset: usize = packed_size(Header),
    source: []const u8,

    pub fn parse(self: *@This()) void {
        self.packet.header.from_bytes(self.source);
        std.log.info("header: {any}\n", .{self.packet.header});

        std.debug.print("questions: {d}\n", .{self.packet.header.num_questions});
        for (0..self.packet.header.num_questions) |i| {
            std.log.warn("question: {d}", .{i});
            self.read_name(self.offset);
            std.log.warn("question: {any}", .{.{
                .type = self.source[self.offset .. self.offset + 2],
                .class = self.source[self.offset + 2 .. self.offset + 4],
            }});
            self.offset += 4;
        }
        const num_others = self.packet.header.num_others();
        std.debug.print("others: {d}\n", .{num_others});
        for (0..num_others) |i| {
            self.read_name(self.offset);
            var record: Record = undefined;
            record.from_bytes(self.source_remaining());
            std.debug.print("record: {d} {any}:\n", .{ i, record });
            self.offset += packed_size(Record);
            self.read_record(record);
        }
        std.log.warn("end: {any}", .{.{ .len = self.source.len, .ofs = self.offset }});
        std.debug.assert(self.offset == self.source.len);
    }

    fn source_remaining(self: @This()) []const u8 {
        return self.source[self.offset..];
    }

    fn read_name(self: *@This(), offset: usize) void {
        self.current_name.items.len = 0;
        return self.read_name_recurse(offset);
    }

    fn read_name_recurse(self: *@This(), offset: usize) void {
        var ofs = offset;
        while (ofs < self.source.len) {
            const pos = ofs;
            const len: u8 = self.source[pos];
            // std.log.warn("pos: {any}", .{.{
            //     .src = self.source.len,
            //     .ofs = ofs,
            //     .len = len,
            // }});
            if (len == 0) {
                self.offset = ofs + 1;
                std.log.warn("name: {s}\n", .{self.current_name.items});
                return;
            }
            if (len < 0x40) {
                ofs += 1 + len;

                const label = self.source[pos + 1 .. pos + 1 + len];
                // std.debug.print("label: {s}\n", .{label});
                self.current_name.appendSliceBounded(label) catch unreachable;
                self.current_name.appendBounded('.') catch unreachable;
                continue;
            }
            if (len < 0xC0) {
                @panic("INVALID DNS NAME LENGTH");
            }
            // dns compression pointer thingy
            const link_data = self.source[ofs + 1];
            const link: u16 = @as(u16, (len & 0x3F)) * 256 + link_data;
            std.debug.print("link: {d} {d}\n", .{ link_data, link });

            if (link > self.source.len) {
                @panic("OVERSIZED DNS LINK");
            }

            if (link == ofs) {
                @panic("SELF REFERENTIAL LINK");
            }
            self.read_name_recurse(link);
            self.offset = ofs + 2;
            return;
        }
        @panic("READ NAME OUT OF BOUNDS");
    }

    fn read_record(self: *@This(), record: Record) void {
        switch (record.type) {
            .A => {
                self.read_string(4);
            },
            .CNAME, .PTR => {
                self.read_name(self.offset);
            },
            .TXT => {
                self.read_string(record.length);
            },
            .SRV => {
                var service: Service = undefined;
                service.from_bytes(self.source_remaining());
                std.debug.print("service: {any}\n", .{service});
                self.offset += packed_size(Service);
                self.read_name(self.offset);
            },
            else => {
                std.debug.print("RECORD NOT IMPLEMENTED: {any}:\n", .{record});
                self.offset += record.length;
            },
        }
    }

    fn read_string(self: *@This(), length: usize) void {
        const end = self.offset + length;
        std.debug.print("string: {s}\n", .{self.source[self.offset..end]});
        self.offset = end;
    }
};

pub const Header = packed struct {
    pub const Flags = packed struct { // in reverse order network
        recursion_desired: bool,
        truncated: bool,
        authoritative_answer: bool,
        opcode: u4,
        qr: enum(u1) {
            query,
            response,
        },

        response_code: enum(u4) {
            ok,
            format_error,
            server_failure,
            name_error,
            not_implemented,
            refused,
            yx_domain,
            yx_rr_set,
            nx_rr_set,
            not_auth,
            not_zone,
            _,
        },
        __reserved: u3,
        recursion_available: bool,
    };
    id: u16,
    flags: Flags,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,

    fn from_bytes(self: *@This(), src: []const u8) void {
        const dstslice = @as([]u8, @ptrCast(@alignCast(self)));
        @memcpy(
            dstslice[0..packed_size(@This())],
            src[0..packed_size(@This())],
        );
        if (@import("builtin").cpu.arch.endian() == .little) {
            self.id = @byteSwap(self.id);
            self.num_questions = @byteSwap(self.num_questions);
            self.num_answers = @byteSwap(self.num_answers);
            self.num_authorities = @byteSwap(self.num_authorities);
            self.num_additionals = @byteSwap(self.num_additionals);
        }
    }

    fn num_others(self: @This()) u16 {
        return self.num_answers + self.num_authorities + self.num_additionals;
    }
};

pub const Record = packed struct {
    type: enum(u16) {
        A = 1,
        NS = 2,
        MD = 3,
        MF = 4,
        CNAME = 5,
        SOA = 6,
        MB = 7,
        MG = 8,
        MR = 9,
        NULL = 10,
        WKS = 11,
        PTR = 12,
        HINFO = 13,
        MINFO = 14,
        MX = 15,
        TXT = 16,
        AAAA = 28,
        SRV = 33,
        NSEC = 47,
        ANY = 255,
        _,
    },
    class: u16,
    ttl: u32,
    length: u16,

    fn from_bytes(self: *@This(), src: []const u8) void {
        @memcpy(
            @as([]u8, @ptrCast(@alignCast(self)))[0..packed_size(@This())],
            src[0..packed_size(@This())],
        );
        std.mem.byteSwapAllFields(@This(), self);
    }
};

pub const Service = packed struct {
    priority: u16,
    weight: u16,
    port: u16,

    fn from_bytes(self: *@This(), src: []const u8) void {
        @memcpy(
            @as([]u8, @ptrCast(@alignCast(self)))[0..packed_size(@This())],
            src[0..packed_size(@This())],
        );
        std.mem.byteSwapAllFields(@This(), self);
    }
};

fn packed_size(T: type) usize {
    return @bitSizeOf(T) / 8;
}

test "parseQueryResponse" {
    const query = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0b\x5f\x67\x6f\x6f\x67\x6c\x65\x63\x61\x73\x74\x04\x5f\x74\x63\x70\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0c\x80\x01";
    const response = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x03\x0b\x5f\x67\x6f\x6f\x67\x6c\x65\x63\x61\x73\x74\x04\x5f\x74\x63\x70\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0c\x00\x01\x00\x00\x00\x78\x00\x2e\x2b\x4d\x69\x54\x56\x2d\x41\x46\x4d\x55\x30\x2d\x38\x37\x61\x31\x35\x37\x31\x31\x32\x62\x36\x65\x64\x38\x31\x37\x65\x66\x35\x65\x31\x66\x36\x34\x38\x33\x66\x61\x36\x61\x31\x35\xc0\x0c\xc0\x2e\x00\x10\x80\x01\x00\x00\x11\x94\x00\xbe\x23\x69\x64\x3d\x38\x37\x61\x31\x35\x37\x31\x31\x32\x62\x36\x65\x64\x38\x31\x37\x65\x66\x35\x65\x31\x66\x36\x34\x38\x33\x66\x61\x36\x61\x31\x35\x23\x63\x64\x3d\x37\x37\x46\x39\x43\x46\x37\x42\x30\x34\x37\x30\x41\x45\x36\x35\x30\x46\x33\x46\x39\x41\x42\x31\x35\x37\x30\x41\x34\x37\x33\x44\x07\x77\x70\x3d\x38\x30\x31\x30\x03\x72\x6d\x3d\x05\x76\x65\x3d\x30\x35\x0d\x6d\x64\x3d\x4d\x69\x54\x56\x2d\x41\x46\x4d\x55\x30\x12\x69\x63\x3d\x2f\x73\x65\x74\x75\x70\x2f\x69\x63\x6f\x6e\x2e\x70\x6e\x67\x10\x66\x6e\x3d\x58\x69\x61\x6f\x6d\x69\x20\x54\x56\x20\x42\x6f\x78\x09\x63\x61\x3d\x32\x36\x36\x37\x35\x37\x04\x73\x74\x3d\x30\x0f\x62\x73\x3d\x46\x41\x38\x46\x44\x44\x39\x43\x34\x38\x44\x33\x04\x6e\x66\x3d\x33\x09\x63\x74\x3d\x45\x42\x35\x43\x43\x32\x03\x72\x73\x3d\xc0\x2e\x00\x21\x80\x01\x00\x00\x00\x78\x00\x2d\x00\x00\x00\x00\x1f\x49\x24\x38\x37\x61\x31\x35\x37\x31\x31\x2d\x32\x62\x36\x65\x2d\x64\x38\x31\x37\x2d\x65\x66\x35\x65\x2d\x31\x66\x36\x34\x38\x33\x66\x61\x36\x61\x31\x35\xc0\x1d\xc1\x38\x00\x01\x80\x01\x00\x00\x00\x78\x00\x04\xc0\xa8\x84\xd9";
    const complex_query = "\x00\x00\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x011\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x03ip6\x04arpa\x00\x00\xff\x00\x01\rsimmet-tuxedo\x05local\x00\x00\xff\x00\x01\x011\x010\x010\x03127\x07in-addr\xc0P\x00\xff\x00\x01\xc0Z\x00\x01\x00\x01\x00\x00\x00x\x00\x04\x7f\x00\x00\x01\xc0s\x00\x0c\x00\x01\x00\x00\x00x\x00\x02\xc0Z\xc0Z\x00\x1c\x00\x01\x00\x00\x00x\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00x\x00\x02\xc0Z";
    var packet: MDNSPacket = undefined;
    packet.from_bytes(query);
    std.debug.assert(packet.header.flags.qr == .query);

    packet.from_bytes(response);
    std.debug.print("0x{x}\n{any}\n\n", .{
        @as([]u8, @ptrCast(@alignCast(&packet.header))),
        packet.header,
    });
    std.debug.assert(packet.header.flags.qr == .response);
    std.debug.assert(packet.header.flags.authoritative_answer);

    packet.from_bytes(complex_query);
    std.debug.assert(packet.header.flags.qr == .query);
}
