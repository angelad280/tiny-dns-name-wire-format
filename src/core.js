/**
 * tiny-dns-name-wire-format
 *
 * Encode and decode DNS domain names using the wire format defined in
 * RFC 1035 section 4.1.4, including message-compression pointer back-references.
 *
 * No third-party dependencies; ESM only.
 */

/**
 * The maximum number of compression pointers that will be followed while
 * decoding. RFC 1035 places no hard limit on pointer chains, but without a
 * cap a single malformed message can force the decoder to loop effectively
 * forever. 32 is far more than any legitimate message uses, and it keeps
 * the detection of pointer loops cheap.
 */
const MAX_POINTER_FOLLOWS = 32;

/**
 * Maximum total length of a wire-format domain name, including the
 * terminating zero-length label but excluding compression pointers (RFC 1035
 * section 2.3.4, derived from 255-octet overall limit on names).
 */
const MAX_WIRE_NAME_LENGTH = 255;

/**
 * Convert a DNS domain name in textual presentation form into its
 * uncompressed wire representation (RFC 1035 section 3.1, 4.1.4).
 *
 * The output is a Uint8Array containing one length-prefixed label per part
 * followed by a single zero octet marking the root. No compression pointers
 * are written: pointers only make sense in the context of a larger DNS
 * message where earlier names can be referenced, so this function does not
 * attempt to synthesise them.
 *
 * An empty input string or a single "." produces the root name — a single
 * zero octet.
 *
 * @param {string} name — dotted domain name, e.g. "www.example".
 * @returns {Uint8Array} wire bytes.
 * @throws {TypeError} if the input is not a string.
 * @throws {Error} if any label exceeds 63 octets, if the total wire length
 *   exceeds 255, or if a label contains an octet that cannot be represented
 *   in a byte (code point above 255).
 */
export function encodeName(name) {
    if (typeof name !== 'string') {
        throw new TypeError('name must be a string');
    }

    if (name === '' || name === '.') {
        return new Uint8Array([0]);
    }

    const labels = name.split('.');
    const parts = [];
    let total = 1; // reserve one octet for the terminating zero

    for (const label of labels) {
        const codePoints = [...label].map((c) => c.codePointAt(0));
        for (const cp of codePoints) {
            if (cp > 255) {
                throw new Error(
                    `label contains octet out of byte range: U+${cp.toString(16).toUpperCase()}`
                );
            }
        }
        const len = codePoints.length;
        if (len > 63) {
            throw new Error(
                `label exceeds 63 octets: length ${len} not allowed (RFC 1035 3.1)`
            );
        }
        const buf = new Uint8Array(len + 1);
        buf[0] = len;
        for (let i = 0; i < len; i++) {
            buf[i + 1] = codePoints[i];
        }
        parts.push(buf);
        total += len + 1;
        if (total > MAX_WIRE_NAME_LENGTH) {
            throw new Error(
                `wire name exceeds ${MAX_WIRE_NAME_LENGTH} octets (RFC 1035 2.3.4)`
            );
        }
    }

    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
        out.set(p, off);
        off += p.length;
    }
    out[off] = 0;
    return out;
}

/**
 * Decode a DNS domain name from a buffer starting at `offset`, honouring
 * compression pointers per RFC 1035 section 4.1.4.
 *
 * Returns the name in presentation form (dotted, no trailing dot) together
 * with the number of octets consumed from the buffer. The consumed length
 * counts only the bytes of the name at its original position; when a pointer
 * is encountered the pointer's two octets are included but nothing beyond
 * them is.
 *
 * Pointer loops and overlong pointer chains are rejected: the caller
 * receives an Error rather than hanging or slowly churning.
 *
 * @param {Uint8Array} buf — the DNS message buffer.
 * @param {number} [offset=0] — byte offset at which the name begins.
 * @returns {{name: string, length: number}} decoded name and consumed octets.
 * @throws {TypeError} if `buf` is not a Uint8Array.
 * @throws {RangeError} if `offset` is outside `buf`.
 * @throws {Error} on malformed input, oversize names, or pointer loops.
 */
export function decodeName(buf, offset = 0) {
    if (!(buf instanceof Uint8Array)) {
        throw new TypeError('buf must be a Uint8Array');
    }
    if (!Number.isInteger(offset) || offset < 0 || offset > buf.length) {
        throw new RangeError(`offset ${offset} out of range for buffer of length ${buf.length}`);
    }

    const labels = [];
    let pointerFollows = 0;
    let pos = offset;
    let end = offset; // octet past the last consumed byte at the original position
    let jumped = false;

    // We manually guard the loop because the termination condition (hitting a
    // zero-length label or a pointer) can be satisfied after a jump, and we
    // must also cap pointer follows to detect loops.
    for (;;) {
        if (pos >= buf.length) {
            throw new Error('name runs past end of buffer');
        }
        const len = buf[pos];
        const high = len & 0xc0;

        if (high === 0xc0) {
            // Compression pointer: two bytes, big-endian offset into the message.
            if (pos + 1 >= buf.length) {
                throw new Error('pointer runs past end of buffer');
            }
            const ptr = ((len & 0x3f) << 8) | buf[pos + 1];
            if (ptr >= pos) {
                // RFC 1035 4.1.4 says pointers must point to earlier positions.
                // Allowing forward or self pointers would admit trivial loops.
                throw new Error(`pointer ${ptr} does not point backwards (pos ${pos})`);
            }
            if (!jumped) {
                end = pos + 2;
                jumped = true;
            }
            pointerFollows += 1;
            if (pointerFollows > MAX_POINTER_FOLLOWS) {
                throw new Error(`too many compression pointers (>${MAX_POINTER_FOLLOWS}); possible loop`);
            }
            pos = ptr;
            continue;
        }

        if (high === 0x00) {
            // Ordinary label.
            if (len > 63) {
                throw new Error(`label length ${len} exceeds 63 (RFC 1035 3.1)`);
            }
            if (pos + 1 + len > buf.length) {
                throw new Error('label runs past end of buffer');
            }
            if (len === 0) {
                // Root: end of name.
                if (!jumped) {
                    end = pos + 1;
                }
                break;
            }
            let s = '';
            for (let i = 0; i < len; i++) {
                s += String.fromCodePoint(buf[pos + 1 + i]);
            }
            labels.push(s);
            pos += 1 + len;
            continue;
        }

        // Reserved high-bits patterns 0x40 and 0x80 are not in use by RFC 1035;
        // reject them rather than guess at an extension that was never specified.
        throw new Error(`unsupported label type 0x${len.toString(16).padStart(2, '0')}`);
    }

    const totalWire = labels.reduce((sum, l) => sum + l.length + 1, 0) + 1;
    if (totalWire > MAX_WIRE_NAME_LENGTH) {
        throw new Error(`decoded name exceeds ${MAX_WIRE_NAME_LENGTH} octets`);
    }

    return { name: labels.join('.'), length: end - offset };
}
