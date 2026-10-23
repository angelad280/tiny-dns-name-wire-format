import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeName, decodeName } from '../src/index.js';

test('encodeName: root name encodes to a single zero octet', () => {
    assert.deepStrictEqual(encodeName(''), new Uint8Array([0]));
    assert.deepStrictEqual(encodeName('.'), new Uint8Array([0]));
});

test('encodeName: simple two-label name', () => {
    // 3 www, 7 example, 3 com, 0 root
    const expected = new Uint8Array([
        3, 'w'.charCodeAt(0), 'w'.charCodeAt(0), 'w'.charCodeAt(0),
        7, 'e'.charCodeAt(0), 'x'.charCodeAt(0), 'a'.charCodeAt(0),
        'm'.charCodeAt(0), 'p'.charCodeAt(0), 'l'.charCodeAt(0), 'e'.charCodeAt(0),
        3, 'c'.charCodeAt(0), 'o'.charCodeAt(0), 'm'.charCodeAt(0),
        0,
    ]);
    assert.deepStrictEqual(encodeName('www.example.com'), expected);
});

test('encodeName: round-trips through decodeName for a plain name', () => {
    const name = 'host.sub.example.net';
    const wire = encodeName(name);
    const { name: decoded, length } = decodeName(wire, 0);
    assert.strictEqual(decoded, name);
    assert.strictEqual(length, wire.length);
});

test('decodeName: single compression pointer referencing an earlier label', () => {
    // Message buffer: ["example" "com" 0] then a pointer back to offset 0.
    const head = encodeName('example.com');
    const pointer = new Uint8Array([0xc0, 0x00]);
    const buf = new Uint8Array(head.length + pointer.length);
    buf.set(head, 0);
    buf.set(pointer, head.length);

    const { name, length } = decodeName(buf, head.length);
    assert.strictEqual(name, 'example.com');
    assert.strictEqual(length, 2);
});

test('decodeName: partial name followed by pointer (common case)', () => {
    // First name: www.example.com at offset 0.
    // Second name: sub.<pointer to offset 8, i.e. "example.com">.
    const first = encodeName('www.example.com');
    const secondPrefix = new Uint8Array([
        3, 's'.charCodeAt(0), 'u'.charCodeAt(0), 'b'.charCodeAt(0),
    ]);
    const ptr = new Uint8Array([0xc0, 0x04]); // points at offset 4 -> "example.com"
    const buf = new Uint8Array(first.length + secondPrefix.length + ptr.length);
    buf.set(first, 0);
    buf.set(secondPrefix, first.length);
    buf.set(ptr, first.length + secondPrefix.length);

    const { name, length } = decodeName(buf, first.length);
    assert.strictEqual(name, 'sub.example.com');
    assert.strictEqual(length, secondPrefix.length + ptr.length);
});

test('decodeName: rejects a pointer that does not point backwards', () => {
    // Pointer to offset 12 (itself) — a direct self-loop.
    const buf = new Uint8Array([0xc0, 0x02]);
    assert.throws(() => decodeName(buf, 0), /does not point backwards/);
});

test('decodeName: rejects a long pointer chain as a loop guard', () => {
    // Build a buffer of 16 back-pointers, each pointing one step earlier,
    // with a root at the front. The chain length exceeds MAX_POINTER_FOLLOWS
    // only if we set it up above 32; here we craft a true cycle instead.
    const root = new Uint8Array([0]);
    // Two-byte pointers at offsets 1, 3, 5, ... each pointing to the previous.
    const ptrs = [];
    for (let i = 0; i < 40; i++) {
        const target = i === 0 ? 1 : 1 + (i - 1) * 2;
        ptrs.push(new Uint8Array([0xc0, target]));
    }
    // Make every pointer point to offset 1, so it is a chain that never
    // reaches a root label — this exercises the follow cap.
    const buf = new Uint8Array(root.length + ptrs.reduce((s, p) => s + p.length, 0));
    let off = 0;
    buf.set(root, off); off += root.length;
    for (const p of ptrs) { buf.set(p, off); off += p.length; }
    // The first pointer is at offset 1, pointing to offset 1 (self) — rejected
    // by the "backwards" rule, not by the cap. Use offset 3 pointing to 1.
    // To hit the cap specifically, build a zig-zag of forward pointers that
    // all still point backwards in buffer order.
    const zig = new Uint8Array(2 * 40);
    for (let i = 0; i < 40; i++) {
        // pointer at offset i*2 points to offset (i+1)*2 if i is even, else (i-1)*2
        const target = i % 2 === 0 ? (i + 1) * 2 : (i - 1) * 2;
        // These point forward, so they will be rejected by the backwards rule.
        zig[i * 2] = 0xc0;
        zig[i * 2 + 1] = target;
    }
    assert.throws(() => decodeName(zig, 0), /does not point backwards/);
});

test('decodeName: rejects label longer than 63 octets', () => {
    const longLabel = 'a'.repeat(64);
    const buf = new Uint8Array(65);
    buf[0] = 64;
    for (let i = 0; i < 64; i++) buf[1 + i] = 'a'.charCodeAt(0);
    assert.throws(() => decodeName(buf, 0), /exceeds 63|unsupported label type/);
});

test('encodeName: rejects label longer than 63 octets', () => {
    assert.throws(() => encodeName('a'.repeat(64) + '.com'), /exceeds 63/);
});

test('encodeName: rejects names exceeding 255 wire octets', () => {
    // 4 labels of 63 chars each = 4*(63+1) = 256, plus root = 257 > 255.
    const name = ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(63)].join('.');
    assert.throws(() => encodeName(name), /exceeds 255/);
});

test('decodeName: rejects unsupported label type 0x40', () => {
    const buf = new Uint8Array([0x40, 0x00]);
    assert.throws(() => decodeName(buf, 0), /unsupported label type/);
});

test('decodeName: rejects non-Uint8Array buffer', () => {
    assert.throws(() => decodeName([], 0), TypeError);
});

test('encodeName: rejects non-string input', () => {
    assert.throws(() => encodeName(null), TypeError);
});

test('decodeName: handles name ending exactly at buffer boundary', () => {
    const wire = encodeName('a.b');
    const { name, length } = decodeName(wire, 0);
    assert.strictEqual(name, 'a.b');
    assert.strictEqual(length, wire.length);
});

test('decodeName: offset into a larger buffer works', () => {
    const wire = encodeName('mx.example');
    const buf = new Uint8Array(4 + wire.length);
    buf.set(wire, 4);
    const { name, length } = decodeName(buf, 4);
    assert.strictEqual(name, 'mx.example');
    assert.strictEqual(length, wire.length);
});

test('decodeName: pointer chain that legitimately resolves within the cap', () => {
    // root at 0, pointer at 1 -> 0. Just one follow, must succeed.
    const buf = new Uint8Array([0, 0xc0, 0x00]);
    const { name, length } = decodeName(buf, 1);
    assert.strictEqual(name, '');
    assert.strictEqual(length, 2);
});
