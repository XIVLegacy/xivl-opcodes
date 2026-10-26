# Map clientbound 0x0144 state route

The eight-byte application supplies a packed actor word `W`, a separate mode
byte and a motion-pack word. The border is `(W >> 20) & 15`. It does not come
from the mode byte. The Scene route carries that mode byte as a zero-extended
u16 at its own payload offset `+0x04`.

## Wire fields and Lua consumers

`W` is the little-endian application u32 at `+0x00`. The historical structural
byte labels remain breakage at `+0`, chantId at `+1`, guard at `+2`, waste at
`+3`, mode at `+4`, an unknown byte at `+5`, and motionPack at `+6`. Those byte
labels do not define independent enum domains within `W`.

The published opcode and border findings are
`xivl-decomp:docs/actor/battle-npc-body-parts.md#opcode-0x0144-and-exact-bit-order`
and `#bytes-0x01-and-0x02`, revision
`48f6926cbefdd8f08f04b5dfb92827b646dcafaa`, file SHA-256
`c3467b0689abf22096d9b084f8644fcfa70ed93c78589165cd861b5810de4fc6`.
They establish these separate consumers:

| Input | Consumer |
| --- | --- |
| Full `W` | `0x00588C5A-0x00588C5C` stores it at CharaElement `+0xF8`. Its packed readers include the breakage bits and context-dependent chant/object nibbles. |
| Border `(W >> 20) & 15` | `0x00588C80-0x00588C92 -> 0x00575280`, ActorImpl virtual `+0x158`, `0x0075A9A0 -> 0x008A32C0 -> 0x006EECB0` stores the border byte at CharaSubStatStorage `+0x18`. |
| Separate application `+0x04` u8 | `0x00575290`, ActorImpl virtual `+0x15C`, `0x0075AA20 -> 0x008A3310 -> 0x007084E0` prepares `_onChangeSubStatMode` only when new and previous mode bytes differ. A border change alone does not pass this equality gate. |

The packed actor word is distinct from a status-row word obtained through
`0x0179`, from the Scene model-state word, and from border storage. The
historical chantId label does not establish a chant enum. The retained
sixty-sample product contains 40-byte subpackets with eight application bytes.
It is not a complete corpus count or evidence of causal packet ordering.

## Producer packing

Original-PE decoding of `0x00588C50` establishes the following construction.
At `0x00588C62-0x00588C6E`, the application byte at `+0x04` is zero-extended
and stored as a word at CharaElement `+0xFC`. The application word at `+0x06`
is stored at `+0xFE`. After the Lua publication calls, the routine reloads
those element fields and builds this eight-byte local record at
`0x00588CAB-0x00588CD3`:

| Local record offset | Value |
| --- | --- |
| `+0x00`, u32 | CharaElement `+0xF8`, the stored packed `W` |
| `+0x04`, u16 | CharaElement `+0xFC`, the stored zero-extended mode byte |
| `+0x06`, u16 | CharaElement `+0xFE`, the stored motion-pack word |

At `0x00588CF9-0x00588D04`, it passes this record, size eight and selector
`0x3B` to `0x004D7980` with the same CharaElement as receiver. Application
`+0x05` is not copied into the high byte of this local record's `+0x04` word.
The record is assembled from reloaded element fields after the two calls;
the instructions do not establish an atomic snapshot against reentrant writes.

## Scene bus and recipient

At `0x004D79C0-0x004D79DC`, the broadcaster passes the element key at
`+0x88`, selector plus `0x15`, source pointer and length to `0x004EC080`.
It submits the returned record through virtual `+0x0C` of the object at
element `+0x84`, at `0x004D79EA-0x004D79F6`. Thus selector `0x3B` becomes
internal command `0x50`.

The remaining bus and recipient edges use these published findings at the
same decomp revision:

- `xivl-decomp:docs/actor/chara-look-at-consumers.md#record-path`, SHA-256
  `74d91cf28a839db5ee51358fa68c77db6037d0bada0bec5a11275813f3acd1d7`,
  identifies element `+0x84` as SceneModule, vtable `0x00F91DE8`, whose
  slot 3 is `0x004E8390`. It queues the record for the scene thread.
- `xivl-decomp:docs/actor/item-appearance-boundary.md#native-consumption-chain`,
  SHA-256 `35ec056021fdeca26e7a183c359409f5a6ce99a612d9e203187e35acc4607a3d`,
  establishes the constructor's inline payload copy for lengths at most
  `0x78`, and the queue pump's unchanged key, command, payload and length.
- `xivl-decomp:docs/event/inn-position-record.md#producer-and-builder`,
  SHA-256 `97abb879b14c1173df242bcca2c45fd2734e7bcf35db5e43450c2eb71db7bf0d`,
  records the size-eight inline-copy arguments and the constructor's return
  of the temporary record.

The published pump route is `0x004E9700 -> 0x0060C140 -> 0x007C93C0`.
The container resolves the key in its actor registries. An unresolved key
produces no actor dispatch. For commands `0x15..0x115`, it subtracts `0x15`
and invokes the resolved actor's virtual `+0x274` with the unchanged payload
and length. When that actor is a CharaActor, slot 157 is `0x00662D30`.
That handler returns while bit 6 of actor `+0x2B70` is set and bounds the
selector to `0..0x63`. For an admitted selector `0x3B`, its published tables
select case `0x006638A4`.

The case reads the packed u32 at Scene payload `+0x00` for the type-2 path
and the u16 at `+0x04` for the type-3 path. The latter therefore consumes the
record's zero-extended mode byte, rather than the application u16 at `+0x04`.
The type-2 case is published in the body-part finding's
`#break-and-recovery-presentation`. The type-3 case is published in
`xivl-decomp:docs/actor/model-state-color-transitions.md#m049-model-state-route`,
same revision, SHA-256
`ee7348655b78f0881c91f7cf2d8bb1749c253742c55a0c64cc97deaf45af1d07`.

Type-3 publication queues model state on actor `+0x1110`; it does not by itself
launch a scheduler. A real substatus-kick drain, the loaded model's metadata
count and supported mask, and a nonnull resource root remain separate gates.
The static route does not establish state-value names, encounter phases,
server policy, delivery timing or a rendered result.

## Scene payload +0x06 stores

Once the resolved CharaActor reaches case `0x006638A4` and its type-2 and
type-3 calls return, the case passes the Scene payload's `+0x06` u16 to
`0x007A5260`. Entry `0x00662D46` takes the payload pointer from `[EBP+0x0C]`
into ESI, and `0x00662D4A` preserves the incoming actor receiver in EDI.
The case advances EDI by `0x1110` at `0x006638A6`. At
`0x006638C0-0x006638C7`, it zero-extends the payload word to a 32-bit stack
argument and calls `0x007A5260` with `ECX = actor + 0x1110`.

The complete callee loads that argument into EAX at `0x007A5260`. It stores
AX as a 16-bit word at receiver `+0x12` at `0x007A5264`, so this destination
is actor `+0x1122`. It then loads the 32-bit pointer at receiver `+0x00`
into ECX at `0x007A5268` and stores AX as a 16-bit word at that pointer
`+0xC20` at `0x007A526A`. The pointer-derived destination is not established
as the incoming actor by these instructions.

The callee has no branch, call or null-pointer check. At `0x007A5271`,
`RET 4` removes the stack argument. EAX still holds the zero-extended word
supplied by this caller; that register value does not establish a success
status. The stores do not establish a motion-pack enum, motion-bank selection
or a later visible effect. The missing link is a downstream reader of receiver
`+0x12` or the pointer-derived `+0xC20` word that connects the stored value to
such behavior. This storage result leaves the actor-lifetime, reentrant
snapshot and presentation gates above unchanged.

## Binary and method

The input is retail 1.23b `ffxivgame.exe`, PE32 x86, size 15996808 bytes,
SHA-256 `9341f2b4567440b310a4d494f5cc5599ca334ba51c8042247317ff466492f2e9`,
image base `0x00400000`. All executable addresses above are VAs.
pefile 2024.8.26 mapped the selected RVA ranges to original file offsets.
Capstone 5.0.7 decoded x86 in 32-bit mode after retained listing instruction
bytes matched the original PE.

Function metadata came from a local Ghidra `DumpFunctions.java` symbol export,
`config/ffxivgame.symbols.json`, SHA-256
`0639fc4a84a0778e67dc2f781f36f2132e83c3bb66ac6b6d0bf0eba9ebf33f81`.
This ignored local output is distinct from the published findings cited above.
Its tracked producer is
`xivl-decomp:tools/ghidra_scripts/DumpFunctions.java`, method `run`, at revision
`48f6926cbefdd8f08f04b5dfb92827b646dcafaa`. The script exports each function's
entry RVA, name and summed body-range size, along with its instruction listing.
The export's unique `FUN_00588c50` row has RVA `0x188C50` and size `0xC1`.
Adding the image base gives the exact
half-open range `[0x00588C50,0x00588D11)`: 193 bytes and 51 instructions.
The same local export's `FUN_004d7980` row has RVA `0xD7980` and body-range sum
`0xCA`. Its retained instruction addresses establish two disjoint half-open
ranges, `[0x004D7980,0x004D7A22)` and `[0x004D7A2D,0x004D7A55)`:
202 bytes and 59 instructions. The omitted eleven-byte gap was not decoded
or interpreted. The producer and broadcaster instruction union is 395 bytes
and 110 instructions.

The same export's unique `FUN_00662d30` row has RVA `0x262D30` and body-range
sum `0xDB8`. Original-PE decoding covers only its three selected half-open
ranges: `[0x00662D30,0x00662D78)`, `[0x006638A4,0x006638E0)` and
`[0x00663AD4,0x00663AE8)`, totaling 152 bytes and 53 instructions. The unique
`FUN_007a5260` row has RVA `0x3A5260` and size `0x14`; its dense complete
range `[0x007A5260,0x007A5274)` contains 20 bytes and five instructions.
The full Scene dispatcher, its tables and the constructor body were not read
from the original PE for this finding. Their remaining edges use the published
sources above.
