const std = @import("std");

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

pub const Packet = struct {
    header: Header = std.mem.zeroes(Header),
    questions: []Query = &.{},
    records: []Record = &.{},
    skipped_records: usize = 0,

    pub const HeaderSize = packed_bytesize(Header);
    pub const Header = packed struct {
        pub const Flags = packed struct { // in reverse order network
            recursion_desired: bool,
            truncated: bool,
            authoritative_answer: bool,
            opcode: enum(u4) {
                Query = 0,
                IQuery = 1,
                Status = 2,
                Unassigned = 3,
                Notify = 4,
                Update = 5,
                DSO = 6,
                _,
            },
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
                dstslice[0..HeaderSize],
                src[0..HeaderSize],
            );
            if (@import("builtin").cpu.arch.endian() == .little) {
                self.id = @byteSwap(self.id);
                self.num_questions = @byteSwap(self.num_questions);
                self.num_answers = @byteSwap(self.num_answers);
                self.num_authorities = @byteSwap(self.num_authorities);
                self.num_additionals = @byteSwap(self.num_additionals);
            }
        }

        fn num_others(self: @This()) usize {
            return @as(usize, self.num_answers) + @as(usize, self.num_authorities) + @as(usize, self.num_additionals);
        }
    };

    pub fn deinit(self: @This(), alloc: std.mem.Allocator) void {
        for (self.questions) |q| {
            q.deinit(alloc);
        }
        alloc.free(self.questions);
        for (self.records) |rec| {
            rec.deinit(alloc);
        }
        alloc.free(self.records);
    }

    pub fn parse(self: *@This(), alloc: std.mem.Allocator, src: []const u8) ParseError!void {
        var namebuf: [DNS_MAX_LEN]u8 = undefined;
        var parser: Parser = .{
            .packet = self,
            .allocator = alloc,
            .source = src,
            .current_name = .initBuffer(&namebuf),
        };
        try parser.parse();
    }
};

const DNS_MAX_LEN = 256;

pub const ParseError = error{
    OutOfMemory,
    SourceTooShort,
    TrailingBytes,
} || ReadRecordError;

pub const ReadRecordError = error{
    InvalidRecordLength,
    OutOfMemory,
    ReadStringOutOfBounds,
    SourceTooShort,
} || ReadNameError;

pub const ReadNameError = error{
    DNSNameTooLarge,
    InvalidLabelLength,
    LabelLengthGreaterThanSource,
    OversizedLink,
    ReadNameOutOfBounds,
    SelfReferentialLink,
    SourceEndsWithPointer,
};

const Parser = struct {
    packet: *Packet,
    allocator: std.mem.Allocator,
    current_name: std.ArrayList(u8),
    questions: std.ArrayList(Query) = .empty,
    records: std.ArrayList(Record) = .empty,
    offset: usize = Packet.HeaderSize,
    source: []const u8,

    fn deinit(self: *@This()) void {
        for (self.questions.items) |q| {
            q.deinit(self.allocator);
        }
        self.questions.deinit(self.allocator);
        for (self.records.items) |r| {
            r.deinit(self.allocator);
        }
        self.records.deinit(self.allocator);
    }

    pub fn parse(self: *@This()) ParseError!void {
        if (self.source.len < Packet.HeaderSize) return error.SourceTooShort;
        self.packet.header.from_bytes(self.source);
        self.packet.skipped_records = 0;
        defer self.deinit();

        for (0..self.packet.header.num_questions) |_| {
            try self.read_name(self.offset);
            if (self.source_remaining().len < Query.FooterSize) return error.SourceTooShort;
            var question: Query.Footer = undefined;
            question.from_bytes(self.source_remaining());
            self.offset += Query.FooterSize;
            const question_name = try self.allocator.dupe(u8, self.current_name.items);
            errdefer self.allocator.free(question_name);

            try self.questions.append(self.allocator, .{
                .name = question_name,
                .footer = question,
            });
        }
        self.packet.questions = try self.questions.toOwnedSlice(self.allocator);
        errdefer {
            for (self.packet.questions) |q| {
                q.deinit(self.allocator);
            }
            self.allocator.free(self.packet.questions);
        }

        const records = self.packet.header.num_others();
        for (0..records) |_| {
            try self.read_name(self.offset);
            if (self.source_remaining().len < Record.HeaderSize) return error.SourceTooShort;
            var record_header: Record.Header = undefined;
            record_header.from_bytes(self.source_remaining());
            self.offset += Record.HeaderSize;
            try self.read_record(record_header);
        }
        self.packet.records = try self.records.toOwnedSlice(self.allocator);
        errdefer {
            for (self.packet.records) |r| {
                r.deinit(self.allocator);
            }
            self.allocator.free(self.packet.records);
        }

        if (self.offset != self.source.len) {
            return error.TrailingBytes;
        }
    }

    fn source_remaining(self: @This()) []const u8 {
        return self.source[self.offset..];
    }

    fn read_name(self: *@This(), offset: usize) ReadNameError!void {
        self.current_name.items.len = 0;
        return self.read_name_recurse(offset);
    }

    fn read_name_recurse(self: *@This(), offset: usize) ReadNameError!void {
        var ofs = offset;
        while (ofs < self.source.len) {
            const pos = ofs;
            const len: u8 = self.source[pos];
            if (len == 0) {
                self.offset = ofs + 1;
                return;
            }
            if (len < 0x40) {
                ofs += 1 + len;
                const label_end = pos + 1 + len;
                if (label_end > self.source.len) return error.LabelLengthGreaterThanSource;

                const label = self.source[pos + 1 .. label_end];
                self.current_name.appendSliceBounded(label) catch return error.DNSNameTooLarge;
                self.current_name.appendBounded('.') catch return error.DNSNameTooLarge;
                continue;
            }
            if (len < 0xC0) {
                return error.InvalidLabelLength;
            }
            // dns compression pointer thingy
            if (ofs + 1 >= self.source.len) return error.SourceEndsWithPointer;
            const link_data = self.source[ofs + 1];
            const link: u16 = @as(u16, (len & 0x3F)) * 256 + link_data;

            if (link > self.source.len) {
                return error.OversizedLink;
            }

            if (link == ofs) {
                return error.SelfReferentialLink;
            }
            try self.read_name_recurse(link);
            self.offset = ofs + 2;
            return;
        }
        return error.ReadNameOutOfBounds;
    }

    fn read_record(self: *@This(), record: Record.Header) ReadRecordError!void {
        switch (record.type) {
            .A => {
                if (record.length != 4) return error.InvalidRecordLength;
                var rec: Record = .{
                    .name = try self.allocator.dupe(u8, self.current_name.items),
                    .header = record,
                    .body = .{
                        .A = undefined,
                    },
                };
                errdefer self.allocator.free(rec.name);
                @memcpy(&rec.body.A, try self.read_string(4));
                try self.records.append(self.allocator, rec);
            },
            .AAAA => {
                if (record.length != 16) return error.InvalidRecordLength;
                var rec: Record = .{
                    .name = try self.allocator.dupe(u8, self.current_name.items),
                    .header = record,
                    .body = .{
                        .AAAA = undefined,
                    },
                };
                errdefer self.allocator.free(rec.name);
                @memcpy(&rec.body.AAAA, try self.read_string(16));
                try self.records.append(self.allocator, rec);
            },
            .PTR => {
                const name = try self.allocator.dupe(u8, self.current_name.items);
                errdefer self.allocator.free(name);
                try self.read_name(self.offset);
                const ptr = try self.allocator.dupe(u8, self.current_name.items);
                errdefer self.allocator.free(ptr);
                try self.records.append(self.allocator, .{
                    .name = name,
                    .header = record,
                    .body = .{
                        .PTR = ptr,
                    },
                });
            },
            .CNAME => {
                const name = try self.allocator.dupe(u8, self.current_name.items);
                errdefer self.allocator.free(name);
                try self.read_name(self.offset);
                const cname = try self.allocator.dupe(u8, self.current_name.items);
                errdefer self.allocator.free(cname);
                try self.records.append(self.allocator, .{
                    .name = name,
                    .header = record,
                    .body = .{
                        .CNAME = cname,
                    },
                });
            },
            .TXT => {
                const name = try self.allocator.dupe(u8, self.current_name.items);
                errdefer self.allocator.free(name);
                try self.records.append(self.allocator, .{
                    .name = name,
                    .header = record,
                    .body = .{
                        .TXT = try self.allocator.dupe(u8, try self.read_string(record.length)),
                    },
                });
            },
            .SRV => {
                const name = try self.allocator.dupe(u8, self.current_name.items);
                errdefer self.allocator.free(name);
                if (self.source_remaining().len < Service.HeaderSize) return error.SourceTooShort;
                var service: Service.Header = undefined;
                service.from_bytes(self.source_remaining());
                self.offset += Service.HeaderSize;
                try self.read_name(self.offset);
                const srvname = try self.allocator.dupe(u8, self.current_name.items);
                errdefer self.allocator.free(srvname);
                try self.records.append(self.allocator, .{
                    .name = name,
                    .header = record,
                    .body = .{
                        .SRV = .{
                            .header = service,
                            .body = srvname,
                        },
                    },
                });
            },
            else => {
                self.packet.skipped_records += 1;
                self.offset += record.length;
            },
        }
    }

    fn read_string(self: *@This(), length: usize) error{ReadStringOutOfBounds}![]const u8 {
        const end = self.offset + length;
        if (end > self.source.len) return error.ReadStringOutOfBounds;
        const data = self.source[self.offset..end];
        self.offset = end;
        return data;
    }
};

pub const Type = enum(u16) {
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
    RP = 17,
    AAAA = 28,
    SRV = 33,
    NSEC = 47,
    ANY = 255,
    TA = 32768, //  DNSSEC Trust Authorities
    DLV = 32769, // DNSSEC Lookaside Validation (OBSOLETE) [RFC8749][RFC4431]
    _,
};

pub const Class = enum(u16) {
    Reserved1 = 0,
    IN = 1,
    Unassigned = 2,
    CH = 3,
    HS = 4,
    NONE = 254,
    ANY = 255,
    Reserved2 = 65535,
    _,
};

pub const Query = struct {
    name: []const u8,
    footer: Footer,

    pub const FooterSize = packed_bytesize(Footer);
    pub const Footer = packed struct {
        type: Type,
        class: Class,

        fn from_bytes(self: *@This(), src: []const u8) void {
            @memcpy(
                @as([]u8, @ptrCast(@alignCast(self))),
                src[0..FooterSize],
            );
            std.mem.byteSwapAllFields(Footer, self);
        }
    };

    pub fn deinit(self: @This(), alloc: std.mem.Allocator) void {
        alloc.free(self.name);
    }
};

pub const Record = struct {
    name: []u8,
    header: Header,
    body: Body,

    pub fn deinit(self: @This(), alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        switch (self.body) {
            .PTR => |ptr| alloc.free(ptr),
            .CNAME => |cname| alloc.free(cname),
            .TXT => |txt| alloc.free(txt),
            .SRV => |srv| alloc.free(srv.body),
            else => {},
        }
    }

    pub const Body = union(Type) {
        A: [4]u8,
        NS,
        MD,
        MF,
        CNAME: []u8,
        SOA,
        MB,
        MG,
        MR,
        NULL,
        WKS,
        PTR: []u8,
        HINFO,
        MINFO,
        MX,
        TXT: []u8,
        RP,
        AAAA: [16]u8,
        SRV: Service,
        NSEC,
        ANY,
        TA,
        DLV,
    };

    pub const HeaderSize = packed_bytesize(Header);
    pub const Header = packed struct {
        type: Type,
        class: Class,
        ttl: u32,
        length: u16,

        fn from_bytes(self: *@This(), src: []const u8) void {
            @memcpy(
                @as([]u8, @ptrCast(@alignCast(self)))[0..HeaderSize],
                src[0..HeaderSize],
            );
            std.mem.byteSwapAllFields(@This(), self);
        }
    };
};

pub const Service = struct {
    header: Header,
    body: []const u8,
    pub const HeaderSize = packed_bytesize(Header);
    pub const Header = packed struct {
        priority: u16,
        weight: u16,
        port: u16,

        fn from_bytes(self: *@This(), src: []const u8) void {
            @memcpy(
                @as([]u8, @ptrCast(@alignCast(self)))[0..HeaderSize],
                src[0..HeaderSize],
            );
            std.mem.byteSwapAllFields(@This(), self);
        }
    };
};

fn packed_bytesize(T: type) usize {
    return @bitSizeOf(T) / 8;
}

test "parseQueryResponse" {
    const query = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0b\x5f\x67\x6f\x6f\x67\x6c\x65\x63\x61\x73\x74\x04\x5f\x74\x63\x70\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0c\x80\x01";
    const response = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x03\x0b\x5f\x67\x6f\x6f\x67\x6c\x65\x63\x61\x73\x74\x04\x5f\x74\x63\x70\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0c\x00\x01\x00\x00\x00\x78\x00\x2e\x2b\x4d\x69\x54\x56\x2d\x41\x46\x4d\x55\x30\x2d\x38\x37\x61\x31\x35\x37\x31\x31\x32\x62\x36\x65\x64\x38\x31\x37\x65\x66\x35\x65\x31\x66\x36\x34\x38\x33\x66\x61\x36\x61\x31\x35\xc0\x0c\xc0\x2e\x00\x10\x80\x01\x00\x00\x11\x94\x00\xbe\x23\x69\x64\x3d\x38\x37\x61\x31\x35\x37\x31\x31\x32\x62\x36\x65\x64\x38\x31\x37\x65\x66\x35\x65\x31\x66\x36\x34\x38\x33\x66\x61\x36\x61\x31\x35\x23\x63\x64\x3d\x37\x37\x46\x39\x43\x46\x37\x42\x30\x34\x37\x30\x41\x45\x36\x35\x30\x46\x33\x46\x39\x41\x42\x31\x35\x37\x30\x41\x34\x37\x33\x44\x07\x77\x70\x3d\x38\x30\x31\x30\x03\x72\x6d\x3d\x05\x76\x65\x3d\x30\x35\x0d\x6d\x64\x3d\x4d\x69\x54\x56\x2d\x41\x46\x4d\x55\x30\x12\x69\x63\x3d\x2f\x73\x65\x74\x75\x70\x2f\x69\x63\x6f\x6e\x2e\x70\x6e\x67\x10\x66\x6e\x3d\x58\x69\x61\x6f\x6d\x69\x20\x54\x56\x20\x42\x6f\x78\x09\x63\x61\x3d\x32\x36\x36\x37\x35\x37\x04\x73\x74\x3d\x30\x0f\x62\x73\x3d\x46\x41\x38\x46\x44\x44\x39\x43\x34\x38\x44\x33\x04\x6e\x66\x3d\x33\x09\x63\x74\x3d\x45\x42\x35\x43\x43\x32\x03\x72\x73\x3d\xc0\x2e\x00\x21\x80\x01\x00\x00\x00\x78\x00\x2d\x00\x00\x00\x00\x1f\x49\x24\x38\x37\x61\x31\x35\x37\x31\x31\x2d\x32\x62\x36\x65\x2d\x64\x38\x31\x37\x2d\x65\x66\x35\x65\x2d\x31\x66\x36\x34\x38\x33\x66\x61\x36\x61\x31\x35\xc0\x1d\xc1\x38\x00\x01\x80\x01\x00\x00\x00\x78\x00\x04\xc0\xa8\x84\xd9";
    const complex_query = "\x00\x00\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x011\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x03ip6\x04arpa\x00\x00\xff\x00\x01\rsimmet-tuxedo\x05local\x00\x00\xff\x00\x01\x011\x010\x010\x03127\x07in-addr\xc0P\x00\xff\x00\x01\xc0Z\x00\x01\x00\x01\x00\x00\x00x\x00\x04\x7f\x00\x00\x01\xc0s\x00\x0c\x00\x01\x00\x00\x00x\x00\x02\xc0Z\xc0Z\x00\x1c\x00\x01\x00\x00\x00x\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00x\x00\x02\xc0Z";
    const nsec = "\x00\x00\x84\x00\x00\x00\x00\x0c\x00\x00\x00\x06\x01C\x014\x016\x012\x01C\x01D\x013\x019\x015\x015\x019\x010\x016\x014\x01D\x01F\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x018\x01E\x01F\x03ip6\x04arpa\x00\x00\x0c\x80\x01\x00\x00\x00x\x000(Android_6f875634ba73460b8a33e14c5d2b16a0\x05local\x00\xc0`\x00\x1c\x80\x01\x00\x00\x00x\x00\x10\xfe\x80\x00\x00\x00\x00\x00\x00\xfdF\tU\x93\xdc&L\x018\x016\x01B\x01D\x014\x01B\x015\x01D\x012\x01E\x012\x018\x01A\x015\x014\x015\x014\x018\x011\x013\x016\x010\x017\x019\x01E\x01E\x010\x010\x013\x010\x010\x012\xc0L\x00\x0c\x80\x01\x00\x00\x00x\x00\x02\xc0`\xc0`\x00\x1c\x80\x01\x00\x00\x00x\x00\x10 \x03\x00\xee\x97\x061\x84TZ\x82\xe2\xd5\xb4\xdbh\x016\x012\x012\x01B\x01A\x01A\x013\x01E\x01E\x01A\x010\x013\x014\x012\x018\x017\xc0\xcc\x00\x0c\x80\x01\x00\x00\x00x\x00\x02\xc0`\xc0`\x00\x1c\x80\x01\x00\x00\x00x\x00\x10 \x03\x00\xee\x97\x061\x84x$0\xae\xe3\xaa\xb2&\x03217\x03132\x03168\x03192\x07in-addr\xc0P\x00\x0c\x80\x01\x00\x00\x00x\x00\x02\xc0`\xc0`\x00\x01\x80\x01\x00\x00\x00x\x00\x04\xc0\xa8\x84\xd9\x11_androidtvremote2\x04_tcp\xc0\x89\x00\x0c\x00\x01\x00\x00\x11\x94\x00\x10\rXiaomi TV Box\xc1\x96\xc1\xb9\x00!\x80\x01\x00\x00\x00x\x00\x08\x00\x00\x00\x00\x19B\xc0`\xc1\xb9\x00\x10\x80\x01\x00\x00\x11\x94\x009\x14bt=70:68:71:C4:C7:99\x07wp=6465\x1bisDeviceInStandbyMode=false\t_services\x07_dns-sd\x04_udp\xc0\x89\x00\x0c\x00\x01\x00\x00\x11\x94\x00\x02\xc1\x96\xc0\x0c\x00/\x80\x01\x00\x00\x00x\x00\x06\xc0\x0c\x00\x02\x00\x08\xc0`\x00/\x80\x01\x00\x00\x00x\x00\x08\xc0`\x00\x04@\x00\x00\x08\xc0\xac\x00/\x80\x01\x00\x00\x00x\x00\x06\xc0\xac\x00\x02\x00\x08\xc1\x16\x00/\x80\x01\x00\x00\x00x\x00\x06\xc1\x16\x00\x02\x00\x08\xc1`\x00/\x80\x01\x00\x00\x00x\x00\x06\xc1`\x00\x02\x00\x08\xc1\xb9\x00/\x80\x01\x00\x00\x00x\x00\t\xc1\xb9\x00\x05\x00\x00\x80\x00@";
    var packet: Packet = .{};
    try packet.parse(std.testing.allocator, query);
    std.debug.assert(packet.header.flags.qr == .query);
    std.debug.assert(packet.questions.len == 1);
    packet.deinit(std.testing.allocator);

    try packet.parse(std.testing.allocator, response);
    std.debug.assert(packet.header.flags.qr == .response);
    std.debug.assert(packet.header.flags.authoritative_answer);
    packet.deinit(std.testing.allocator);

    try packet.parse(std.testing.allocator, complex_query);
    std.debug.assert(packet.header.flags.qr == .query);
    std.debug.assert(packet.questions.len == 3);
    std.debug.assert(packet.records.len == 4);
    packet.deinit(std.testing.allocator);

    try packet.parse(std.testing.allocator, nsec);
    packet.deinit(std.testing.allocator);
}

test "fuzzParser" {
    const alloc = std.testing.allocator;
    const FuzzParser = struct {
        fn testOne(ctx: *@This(), inbuf: []const u8) anyerror!void {
            _ = ctx;
            var pkg: Packet = .{};
            pkg.parse(alloc, inbuf) catch |err| {
                if (std.testing.allocator_instance.detectLeaks()) return err;
                return;
            };
            pkg.deinit(alloc);
        }
    };
    var ctx: FuzzParser = .{};
    try std.testing.fuzz(&ctx, FuzzParser.testOne, .{});
}

pub const ip_mreqn = extern struct {
    /// multicast group address
    imr_multiaddr: [4]u8 = @splat(0),
    /// local ip address
    imr_address: [4]u8 = @splat(0),
    // Interface index; cast to uint32_t
    imr_ifindex: u32 = 0,
};
