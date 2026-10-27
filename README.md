# tiny-dns-name-wire-format

Encode and decode DNS domain names in the wire format defined by RFC 1035 section 4.1.4, including compression pointers that reference earlier names in a message. Pure ESM, zero dependencies.

```js
import { encodeName, decodeName } from 'tiny-dns-name-wire-format';

// Presentation form -> wire bytes (uncompressed).
const wire = encodeName('www.example.com');

// Wire bytes -> presentation form, following compression pointers.
const { name, length } = decodeName(wire, 0);
// name === 'www.example.com', length === wire.length
```

## Why this exists

DNS messages pack names densely by letting later names point back into earlier ones with two-byte pointers. Parsing that structure by hand is fiddly: you have to follow pointers without losing track of how many bytes the name actually occupied at its original position, and you have to refuse to loop forever on a malformed pointer chain. This library does exactly that, and nothing else — it does not parse whole DNS messages, handle record types, or manage TCP length prefixes. The trade-off is deliberately small scope: if you need full message parsing, compose this with your own header and record readers.

## Edge cases worth knowing

- The empty string and `"."` both encode to the root name — a single zero octet — and decode back to the empty string (no trailing dot is produced).
- `encodeName` writes no compression pointers. Compression only makes sense relative to a surrounding message; synthesising it here would require inventing policy the caller probably wants to control. Call `decodeName` on a buffer that already contains pointers to resolve them.
- Pointers must point backwards in the buffer, and no more than 32 pointers are followed in a single decode. A real DNS message never approaches either limit; the cap exists purely to turn malformed input into a clean Error instead of an infinite loop.
- Label lengths are enforced at 63 octets and total wire name length at 255, per RFC 1035.

## Exports

- `encodeName(name: string): Uint8Array` — encodes a dotted name to uncompressed wire bytes.
- `decodeName(buf: Uint8Array, offset?: number): { name: string, length: number }` — decodes a wire name starting at `offset`, following compression pointers. `length` is the number of bytes consumed at the original position.

## Running the tests

```
node --test
```

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

