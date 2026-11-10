//! TLS-wrapped Transport using std.crypto.tls.Client.
//!
//! Architecture: TlsTransport owns an inner TcpTransport (the encrypted
//! socket layer) plus a `std.crypto.tls.Client` that wraps its
//! reader/writer. The Transport vtable exposed by TlsTransport routes
//! through the TLS Client's plaintext reader/writer, so callers
//! upstream (Client, ResultStream) see decrypted bytes transparently.
//!
//! ClickHouse's TLS port is 9440 (separate-port style, NOT STARTTLS).
//! Construct a Config with `.port = 9440` and connect via
//! `Client.fromTransport(..., tls_transport.transport(), ...)`.
//!
//! Verification modes:
//!   .insecure   — accept any cert, no host check. Test/dev only.
//!   .system_ca  — use `std.crypto.Certificate.Bundle` populated from
//!                 the OS's trust store via `rescan`. Verifies the
//!                 server cert was issued for `Config.host`.
//!
//! This file exceeds 100 lines because the TLS handshake, vtable, and
//! lifecycle bookkeeping must live together — splitting would scatter
//! the @fieldParentPtr-sensitive Reader/Writer interfaces across files.

const std = @import("std");
const Io = std.Io;
const transport_mod = @import("transport.zig");

pub const VerifyMode = union(enum) {
    /// Skip both CA verification and hostname verification. INSECURE —
    /// only acceptable for local dev / smoke against self-signed certs.
    insecure,
    /// Verify against the OS-supplied CA bundle. Hostname must match
    /// the server's certificate common-name or SAN.
    system_ca,
};

pub const Options = struct {
    /// Hostname for SNI + cert verification. Should match Config.host.
    host: []const u8,
    verify: VerifyMode = .system_ca,
    /// Read buffer for the encrypted ingress stream. Must be at least
    /// `std.crypto.tls.Client.min_buffer_len` (~16 KiB).
    encrypted_read_buffer_size: usize = 32 * 1024,
    /// Write buffer for the encrypted egress stream.
    encrypted_write_buffer_size: usize = 16 * 1024,
};

pub const Error = error{
    OutOfMemory,
    TlsHandshakeFailed,
    InsufficientBuffer,
} || transport_mod.ConnectError;

pub const TlsTransport = struct {
    allocator: std.mem.Allocator,
    io: Io,
    inner: *transport_mod.TcpTransport,
    /// Loaded only when verify == .system_ca. Owned.
    ca_bundle: ?*std.crypto.Certificate.Bundle = null,
    ca_lock: ?*std.Io.RwLock = null,
    /// Heap-stable so tls_client.reader / .writer interfaces (which
    /// fieldParentPtr back to *Client) stay valid for the transport's
    /// lifetime.
    tls_client: *std.crypto.tls.Client,
    /// The TLS client's own cleartext buffers. They must not be the inner
    /// transport's: that one holds the ciphertext going in and out, and
    /// sharing it, the two overwrite each other once records get longer
    /// than the handshake's.
    clear_read: []u8,
    clear_write: []u8,
    /// What the Client writes through. std's tls.Client flush only seals
    /// the buffered cleartext into the inner writer's buffer; it does not
    /// flush the inner writer, so a request would sit there unsent. This
    /// writer's flush goes through both, as std.http.Client does.
    out: Io.Writer = .{ .vtable = &out_vtable, .buffer = &.{} },
    closed: bool = false,
    read_timeout_ms: ?u32 = null,
    write_timeout_ms: ?u32 = null,

    /// Construct over an already-connected TcpTransport. The
    /// TlsTransport takes ownership of `inner` and will close it on
    /// `deinit`. The TLS handshake completes before this returns.
    pub fn over(
        allocator: std.mem.Allocator,
        io: Io,
        inner: *transport_mod.TcpTransport,
        opts: Options,
    ) Error!*TlsTransport {
        const self = try allocator.create(TlsTransport);
        errdefer allocator.destroy(self);
        const tls_client = try allocator.create(std.crypto.tls.Client);
        errdefer allocator.destroy(tls_client);

        // The inner TcpTransport's read/write buffers must each be
        // ≥ tls.max_ciphertext_record_len for the TLS Client to operate.
        if (inner.read_buf.len < std.crypto.tls.Client.min_buffer_len) return error.InsufficientBuffer;
        if (inner.write_buf.len < std.crypto.tls.Client.min_buffer_len) return error.InsufficientBuffer;

        const min = std.crypto.tls.Client.min_buffer_len;
        const clear_read = try allocator.alloc(u8, @max(opts.encrypted_read_buffer_size, min));
        errdefer allocator.free(clear_read);
        const clear_write = try allocator.alloc(u8, @max(opts.encrypted_write_buffer_size, min));
        errdefer allocator.free(clear_write);

        var ca_bundle_ptr: ?*std.crypto.Certificate.Bundle = null;
        var lock_ptr: ?*std.Io.RwLock = null;
        errdefer if (ca_bundle_ptr) |b| {
            b.deinit(allocator);
            allocator.destroy(b);
        };
        errdefer if (lock_ptr) |l| allocator.destroy(l);

        const tls_opts: std.crypto.tls.Client.Options = blk: {
            var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
            io.random(&entropy);
            const realtime: std.Io.Timestamp = std.Io.Clock.now(.real, io);

            // Note: we duplicate the entropy onto the stack here; the
            // tls.Client.Options.entropy pointer is only read during
            // init, so a stack lifetime is safe.
            switch (opts.verify) {
                .insecure => break :blk .{
                    .host = .no_verification,
                    .ca = .no_verification,
                    .write_buffer = clear_write,
                    .read_buffer = clear_read,
                    .entropy = &entropy,
                    .realtime_now = realtime,
                },
                .system_ca => {
                    ca_bundle_ptr = try allocator.create(std.crypto.Certificate.Bundle);
                    ca_bundle_ptr.?.* = .empty;
                    // A system CA bundle that cannot be read is a TLS setup
                    // failure for the caller, whatever the file error was.
                    ca_bundle_ptr.?.rescan(allocator, io, realtime) catch |e| switch (e) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.Canceled => return error.Canceled,
                        else => return error.TlsHandshakeFailed,
                    };
                    lock_ptr = try allocator.create(std.Io.RwLock);
                    lock_ptr.?.* = .init;
                    break :blk .{
                        .host = .{ .explicit = opts.host },
                        .ca = .{ .bundle = .{
                            .gpa = allocator,
                            .io = io,
                            .lock = lock_ptr.?,
                            .bundle = ca_bundle_ptr.?,
                        } },
                        .write_buffer = clear_write,
                        .read_buffer = clear_read,
                        .entropy = &entropy,
                        .realtime_now = realtime,
                    };
                },
            }
        };

        // The encrypted-stream reader/writer come from the inner TCP
        // transport. tls.Client wraps them and surfaces decrypted
        // reader/writer via its own fields.
        const inner_reader = inner.transport().reader();
        const inner_writer = inner.transport().writer();

        // Stack alloc through indirection: init the value-typed Client
        // into the heap slot we allocated.
        tls_client.* = std.crypto.tls.Client.init(inner_reader, inner_writer, tls_opts) catch
            return error.TlsHandshakeFailed;

        self.* = .{
            .allocator = allocator,
            .io = io,
            .inner = inner,
            .ca_bundle = ca_bundle_ptr,
            .ca_lock = lock_ptr,
            .tls_client = tls_client,
            .clear_read = clear_read,
            .clear_write = clear_write,
        };
        return self;
    }

    pub fn deinit(self: *TlsTransport) void {
        if (self.closed) return;
        self.closed = true;
        // Best-effort close-notify; ignore error since we're tearing down.
        self.tls_client.end() catch {};
        self.inner.transport().writer().flush() catch {};
        self.inner.deinit();
        self.allocator.destroy(self.inner);
        self.allocator.destroy(self.tls_client);
        self.allocator.free(self.clear_read);
        self.allocator.free(self.clear_write);
        if (self.ca_bundle) |b| {
            b.deinit(self.allocator);
            self.allocator.destroy(b);
        }
        if (self.ca_lock) |l| self.allocator.destroy(l);
    }

    pub fn transport(self: *TlsTransport) transport_mod.Transport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: transport_mod.Transport.VTable = .{
        .reader = readerImpl,
        .writer = writerImpl,
        .close = closeImpl,
        .setReadTimeout = setReadTimeoutImpl,
        .setWriteTimeout = setWriteTimeoutImpl,
        .lastReadError = lastReadErrorImpl,
        .lastWriteError = lastWriteErrorImpl,
    };

    fn readerImpl(ptr: *anyopaque) *Io.Reader {
        const self: *TlsTransport = @ptrCast(@alignCast(ptr));
        return &self.tls_client.reader;
    }
    fn writerImpl(ptr: *anyopaque) *Io.Writer {
        const self: *TlsTransport = @ptrCast(@alignCast(ptr));
        return &self.out;
    }

    const out_vtable: Io.Writer.VTable = .{ .drain = outDrain, .flush = outFlush };

    /// Unbuffered: everything goes straight into the TLS writer, which
    /// buffers and seals records itself.
    fn outDrain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *TlsTransport = @alignCast(@fieldParentPtr("out", w));
        const tw = &self.tls_client.writer;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try tw.writeAll(d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            try tw.writeAll(last);
            n += last.len;
        }
        return n;
    }

    fn outFlush(w: *Io.Writer) Io.Writer.Error!void {
        const self: *TlsTransport = @alignCast(@fieldParentPtr("out", w));
        try self.tls_client.writer.flush();
        try self.inner.transport().writer().flush();
    }
    fn closeImpl(ptr: *anyopaque) void {
        const self: *TlsTransport = @ptrCast(@alignCast(ptr));
        self.deinit();
    }
    fn setReadTimeoutImpl(ptr: *anyopaque, ms: ?u32) anyerror!void {
        const self: *TlsTransport = @ptrCast(@alignCast(ptr));
        self.read_timeout_ms = ms;
        try self.inner.transport().setReadTimeout(ms);
    }
    fn setWriteTimeoutImpl(ptr: *anyopaque, ms: ?u32) anyerror!void {
        const self: *TlsTransport = @ptrCast(@alignCast(ptr));
        self.write_timeout_ms = ms;
        try self.inner.transport().setWriteTimeout(ms);
    }
    fn lastReadErrorImpl(ptr: *anyopaque) ?anyerror {
        const self: *TlsTransport = @ptrCast(@alignCast(ptr));
        return self.inner.transport().lastReadError();
    }
    fn lastWriteErrorImpl(ptr: *anyopaque) ?anyerror {
        const self: *TlsTransport = @ptrCast(@alignCast(ptr));
        return self.inner.transport().lastWriteError();
    }
};

test "TlsTransport compiles" {
    // Nothing else references these on the test path: without this, a
    // std API change in the TLS path goes unnoticed until a caller links it.
    std.testing.refAllDecls(TlsTransport);
    _ = &TlsTransport.over;
}
