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
        if (len < Header.packed_size()) continue;
        const data = buf[0..len];
        var packet: MDNSPacket = undefined;
        packet.from_bytes(data);
        std.debug.print("{x}\n{any}\n\n", .{ data, packet.header });
    }
}

const MDNSPacket = struct {
    header: Header,

    fn from_bytes(self: *@This(), src: []const u8) void {
        self.header.from_packet(src);
        var ofs: usize = Header.packed_size();
        std.debug.print("questions:\n", .{});
        for (0..self.header.num_questions) |_| {
            ofs = self.read_name(src, ofs);
        }
        std.debug.print("others:\n", .{});
        const num_others = self.header.num_answers + self.header.num_authorities + self.header.num_additionals;
        for (0..num_others) |_| {
            ofs = self.read_name(src, ofs);
            var record: Record = undefined;
            record.from_bytes(src[ofs..]);
            std.debug.print("{any}:\n", .{record});
            ofs += 10;
            ofs = self.read_record(src, ofs, record);
        }
    }

    fn read_name(self: *@This(), src: []const u8, ofs_in: usize) usize {
        var ofs = ofs_in;
        while (ofs < src.len) {
            const pos = ofs;
            const len: u8 = src[pos];
            std.debug.print("pos {any}\n", .{.{
                .src = src.len,
                .ofs = ofs,
                .len = len,
            }});
            if (len > src.len) {
                @panic("OVERSIZED DNS NAME LENGTH");
            }
            if (len == 0) {
                return ofs + 1;
            }
            if (len < 0x40) {
                ofs += 1 + len;

                const label = src[pos + 1 .. pos + 1 + len];
                std.debug.print("label: {s}\n", .{label});
                continue;
            }
            if (len < 0xC0) {
                @panic("INVALID DNS NAME LENGTH");
            }
            // dns compression pointer thingy
            const link_data = src[ofs + 1];
            const link: u16 = @as(u16, (len & 0x3F)) * 256 + link_data;
            std.debug.print("link: {d} {d}\n", .{ link_data, link });

            if (link > src.len) {
                @panic("OVERSIZED DNS LINK");
            }

            if (link == ofs) {
                @panic("SELF REFERENTIAL LINK");
            }
            _ = self.read_name(src, link);
            ofs += 2;
            return ofs;
        }
        @panic("READ NAME OUT OF BOUNDS");
    }

    fn read_record(self: *@This(), src: []const u8, ofs_in: usize, record: Record) usize {
        var ofs = ofs_in;
        switch (record.type) {
            .CNAME, .PTR => {
                ofs = self.read_name(src, ofs);
            },
            .TXT => {
                ofs = self.read_string(src, ofs, record.length);
            },
            else => @panic("RECORD NOT IMPLEMENTED"),
        }
        return ofs;
    }

    fn read_string(self: *@This(), src: []const u8, ofs_in: usize, length: usize) usize {
        _ = self;
        const ofs = ofs_in + length;
        std.debug.print("string: {s}\n", .{src[ofs_in .. ofs_in + length]});
        return ofs;
    }
};

const Record = packed struct {
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
            @as([]u8, @ptrCast(@alignCast(self))),
            src[0..@sizeOf(Record)],
        );
        std.mem.byteSwapAllFields(@This(), self);
        // self.type = @enumFromInt(@byteSwap(@intFromEnum(self.type)));
        // self.class = @byteSwap(self.class);
        // self.ttl = @byteSwap(self.ttl);
        // self.length = @byteSwap(self.length);
    }
};

// def _read_questions(self) -> None:
// """Reads questions section of packet"""
// view = self.view
// questions = self._questions
// for _ in range(self._num_questions):
//     name = self._read_name()
//     offset = self.offset
//     self.offset += 4
//     # The question has 2 unsigned shorts in network order
//     type_ = view[offset] << 8 | view[offset + 1]
//     class_ = view[offset + 2] << 8 | view[offset + 3]
//     question = DNSQuestion(name, type_, class_)
//     if question.unique:  # QU questions use the same bit as unique
//         self._has_qu_question = True
//     questions.append(question)

// def _read_name(self) -> str:
// """Reads a domain name from the packet."""
// labels: List[str] = []
// seen_pointers: Set[int] = set()
// original_offset = self.offset
// self.offset = self._decode_labels_at_offset(original_offset, labels, seen_pointers)
// self._name_cache[original_offset] = labels
// name = ".".join(labels) + "."
// if len(name) > MAX_NAME_LENGTH:
//     raise IncomingDecodeError(
//         f"DNS name {name} exceeds maximum length of {MAX_NAME_LENGTH} from {self.source}"
//     )
// return name

const Header = packed struct {
    const Flags = packed struct { // in reverse order network
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

    fn from_packet(self: *@This(), src: []const u8) void {
        const dstslice = @as([]u8, @ptrCast(@alignCast(self)));
        @memcpy(dstslice, src[0..dstslice.len]);
        if (@import("builtin").cpu.arch.endian() == .little) {
            self.id = @byteSwap(self.id);
            self.num_questions = @byteSwap(self.num_questions);
            self.num_answers = @byteSwap(self.num_answers);
            self.num_authorities = @byteSwap(self.num_authorities);
            self.num_additionals = @byteSwap(self.num_additionals);
        }
    }

    fn packed_size() usize {
        return @bitSizeOf(@This()) / 8;
    }
};

test "parseQueryResponse" {
    const query = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0b\x5f\x67\x6f\x6f\x67\x6c\x65\x63\x61\x73\x74\x04\x5f\x74\x63\x70\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0c\x80\x01";
    const response = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x03\x0b\x5f\x67\x6f\x6f\x67\x6c\x65\x63\x61\x73\x74\x04\x5f\x74\x63\x70\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0c\x00\x01\x00\x00\x00\x78\x00\x2e\x2b\x4d\x69\x54\x56\x2d\x41\x46\x4d\x55\x30\x2d\x38\x37\x61\x31\x35\x37\x31\x31\x32\x62\x36\x65\x64\x38\x31\x37\x65\x66\x35\x65\x31\x66\x36\x34\x38\x33\x66\x61\x36\x61\x31\x35\xc0\x0c\xc0\x2e\x00\x10\x80\x01\x00\x00\x11\x94\x00\xbe\x23\x69\x64\x3d\x38\x37\x61\x31\x35\x37\x31\x31\x32\x62\x36\x65\x64\x38\x31\x37\x65\x66\x35\x65\x31\x66\x36\x34\x38\x33\x66\x61\x36\x61\x31\x35\x23\x63\x64\x3d\x37\x37\x46\x39\x43\x46\x37\x42\x30\x34\x37\x30\x41\x45\x36\x35\x30\x46\x33\x46\x39\x41\x42\x31\x35\x37\x30\x41\x34\x37\x33\x44\x07\x77\x70\x3d\x38\x30\x31\x30\x03\x72\x6d\x3d\x05\x76\x65\x3d\x30\x35\x0d\x6d\x64\x3d\x4d\x69\x54\x56\x2d\x41\x46\x4d\x55\x30\x12\x69\x63\x3d\x2f\x73\x65\x74\x75\x70\x2f\x69\x63\x6f\x6e\x2e\x70\x6e\x67\x10\x66\x6e\x3d\x58\x69\x61\x6f\x6d\x69\x20\x54\x56\x20\x42\x6f\x78\x09\x63\x61\x3d\x32\x36\x36\x37\x35\x37\x04\x73\x74\x3d\x30\x0f\x62\x73\x3d\x46\x41\x38\x46\x44\x44\x39\x43\x34\x38\x44\x33\x04\x6e\x66\x3d\x33\x09\x63\x74\x3d\x45\x42\x35\x43\x43\x32\x03\x72\x73\x3d\xc0\x2e\x00\x21\x80\x01\x00\x00\x00\x78\x00\x2d\x00\x00\x00\x00\x1f\x49\x24\x38\x37\x61\x31\x35\x37\x31\x31\x2d\x32\x62\x36\x65\x2d\x64\x38\x31\x37\x2d\x65\x66\x35\x65\x2d\x31\x66\x36\x34\x38\x33\x66\x61\x36\x61\x31\x35\xc0\x1d\xc1\x38\x00\x01\x80\x01\x00\x00\x00\x78\x00\x04\xc0\xa8\x84\xd9";
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
}
