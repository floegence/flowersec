# Flowersec IDL Spec (fidl.json)

## Overview

The IDL used in this repository is a JSON-based schema with the suffix `.fidl.json`.
`tools/idlgen` reads these files and generates Go and TypeScript types.

The generator scans the input directory recursively for `*.fidl.json` files. The
`namespace` field is required and drives output paths.

This document describes the exact JSON syntax supported by the current generator
(`tools/idlgen`). It is intended for first-time users who need to write IDL JSON
from scratch.

## Quick start

1) Create a file under `idl/flowersec/<domain>/<version>/` with suffix `.fidl.json`.

2) Write a single JSON object with at least:

- `namespace`: `flowersec.<domain>.<version>`
- `messages`: one or more message definitions (or an empty object)

3) Run code generation from repo root:

```
make gen
```

Generated outputs:

- Go: `flowersec-go/gen/flowersec/<domain>/<version>/types.gen.go` (and `rpc.gen.go` if `services` is present)
- TypeScript: `flowersec-ts/src/gen/flowersec/<domain>/<version>.gen.ts` (and `<version>.rpc.gen.ts` if `services` is present)

## File layout and namespace

Typical layout in this repo follows:

```
idl/flowersec/<domain>/<version>/*.fidl.json
```

The expected namespace pattern is:

```
flowersec.<domain>.<version>
```

The generator extracts:

- `domain` as the second segment (e.g. `rpc` in `flowersec.rpc.v1`).
- `version` as the last segment (e.g. `v1`).

Notes:

- The generator trusts the `namespace` to determine output paths; it does not infer
  `domain`/`version` from the on-disk directory names.
- The `domain` is a logical protocol area. In this repo you will see domains like
  `tunnel`, `e2ee`, `rpc`, and `controlplane`.

## JSON schema

Each `.fidl.json` file is a single JSON object.

### Supported top-level keys

The generator recognizes the following top-level keys:

- `namespace` (required): string
- `enums` (optional): object
- `messages` (optional): object
- `services` (optional): object

Unknown keys are ignored by the current generator (Go's JSON decoder ignores unknown fields),
but you should avoid relying on that behavior. For compatibility and clarity, use only the
keys listed above.

### Full shape (reference)

```
{
  "namespace": "flowersec.<domain>.<version>",
  "enums": {
    "EnumName": {
      "comment": "Optional enum doc.",
      "type": "u8|u16|u32 (default u32 when omitted)",
      "values": {
        "value_name": 1
      },
      "value_comments": {
        "value_name": "Optional value doc."
      }
    }
  },
  "messages": {
    "MessageName": {
      "comment": "Optional message doc.",
      "fields": [
        {
          "name": "field_name",
          "type": "string|bool|u8|u16|u32|u64|i32|i64|json|map<string,string>|[]T|EnumOrMessage",
          "optional": true,
          "comment": "Optional field doc."
        }
      ]
    }
  },
  "services": {
    "ServiceName": {
      "comment": "Optional service doc.",
      "methods": {
        "MethodName": {
          "comment": "Optional method doc.",
          "kind": "request|notify",
          "type_id": 123,
          "request": "RequestMessage",
          "response": "ResponseMessage (request only)"
        }
      }
    }
  }
}
```

Notes:

- `enums` and `messages` can be empty or omitted.
- `services` can be empty or omitted. When present, `idlgen` generates typed RPC stubs (Go and TS).
- `comment` and `value_comments` are optional and only affect generated doc comments.
- Enum `type` is only used for Go output; `u8` -> `uint8`, `u16` -> `uint16`, otherwise `uint32`.

## Naming and style guidelines

- File suffix must be `.fidl.json`.
- `namespace` must be non-empty.
- Message and enum names become code identifiers; prefer `PascalCase` names:
  - `ChannelInitGrant`, `RpcEnvelope`, `StreamHello`
- Field names are expected to be `snake_case` because the wire format is JSON:
  - `channel_id`, `e2ee_psk_b64u`, `endpoint_instance_id`

Go output:

- Field names are converted to exported `PascalCase` struct fields.

TypeScript output:

- Field names remain `snake_case` because the generated types represent the wire JSON.
- A separate “camelCase API layer” is not generated automatically; if you want that, wrap it in your own facade.

## Enums

Enums are defined under the `enums` map:

```
"enums": {
  "Role": {
    "comment": "Endpoint role for tunnel attach.",
    "type": "u8",
    "values": {
      "client": 1,
      "server": 2
    },
    "value_comments": {
      "client": "Client endpoint.",
      "server": "Server endpoint."
    }
  }
}
```

Rules and behavior:

- Enum names are keys in `enums` (example: `"Role"`).
- `values` is a map of string keys to integer values.
- `type` (optional) only affects Go output integer width:
  - `u8` -> `uint8`
  - `u16` -> `uint16`
  - anything else / omitted -> `uint32`
- TS always generates a `number`-backed `enum`.
- Generated TS also includes runtime validation for enum-typed fields: the number must be one of the declared values.

## Messages

Messages are defined under the `messages` map.

Example:

```
"messages": {
  "ChannelInitGrant": {
    "comment": "Grant issued by controlplane to attach and start E2EE.",
    "fields": [
      { "name": "tunnel_url", "type": "string" },
      { "name": "channel_id", "type": "string" },
      { "name": "idle_timeout_seconds", "type": "i32" },
      { "name": "allowed_suites", "type": "[]Suite" },
      { "name": "token", "type": "string" }
    ]
  }
}
```

### Field object keys

Each field object supports:

- `name` (required): string
- `type` (required): string
- `optional` (optional): boolean
- `comment` (optional): string

Optional fields:

- Go: pointer field + `omitempty`
- TS: optional property (`field_name?: Type`)

## Supported field types

The `type` string supports:

- Scalars: `string`, `bool`, `u8`, `u16`, `u32`, `u64`, `i32`, `i64`
- JSON escape hatch: `json`
- Map: `map<string,string>`
- Array: `[]T` (example: `[]u32`, `[]Suite`, `[]Attach`)
- Reference: `EnumOrMessage` (must match a declared enum or message name)

Type mappings:

```
string             -> Go string            | TS string
bool               -> Go bool              | TS boolean
u8                 -> Go uint8             | TS number
u16                -> Go uint16            | TS number
u32                -> Go uint32            | TS number
u64                -> Go uint64            | TS number (must be a safe integer)
i32                -> Go int32             | TS number
i64                -> Go int64             | TS number (must be a safe integer)
json               -> Go json.RawMessage   | TS unknown
map<string,string> -> Go map[string]string | TS Record<string, string>
[]T                -> Go []T               | TS T[]
EnumOrMessage      -> Go EnumOrMessage     | TS EnumOrMessage
```

Important JSON/TS constraints:

- The wire format is JSON, so TS uses `number` for numeric values.
- For `u64` and `i64` in TS, runtime validation enforces `Number.isSafeInteger(...)` to avoid silent precision loss.
- For `u8`/`u16`/`u32` in TS, runtime validation enforces integer-ness and upper bounds.

## Services and typed RPC stubs

The `services` section binds stable RPC `type_id` values to named methods and message types.
It does not change the RPC wire envelope format; it only generates ergonomic, strongly typed wrappers.

Rules:

- `kind` must be either `request` or `notify`.
- `type_id` must be non-zero and unique within a single `.fidl.json` file.
- `request` must refer to a message declared in the same file.
- For `request` methods, `response` must refer to a message declared in the same file.
- For `notify` methods, `response` must be omitted.

### Service object keys

`services` is a map of service name -> service definition. Each service definition supports:

- `comment` (optional): string
- `methods` (required for useful output): object map of method name -> method definition

Each method definition supports:

- `comment` (optional): string
- `kind` (required): `"request"` or `"notify"`
- `type_id` (required): integer (non-zero)
- `request` (required): message name (must exist in this file)
- `response` (required for `request`): message name (must exist in this file)

### Minimal end-to-end example (request + notify)

```
{
  "namespace": "flowersec.demo.v1",
  "enums": {},
  "messages": {
    "PingRequest": { "comment": "Ping request.", "fields": [] },
    "PingResponse": {
      "comment": "Ping response.",
      "fields": [{ "name": "ok", "type": "bool", "comment": "Whether the request succeeded." }]
    },
    "HelloNotify": {
      "comment": "Hello notification payload.",
      "fields": [{ "name": "hello", "type": "string", "comment": "Hello message." }]
    }
  },
  "services": {
    "Demo": {
      "comment": "Demo service used by examples and integration tests.",
      "methods": {
        "Ping": { "kind": "request", "type_id": 1, "request": "PingRequest", "response": "PingResponse" },
        "Hello": { "kind": "notify", "type_id": 2, "request": "HelloNotify" }
      }
    }
  }
}
```

## Runtime validation in generated TypeScript

For every generated message and enum, `idlgen` emits runtime `assert*` helpers in `<version>.gen.ts`:

- `assert<MessageName>(v: unknown): MessageName`

These helpers validate:

- required fields exist
- enum values are within the declared set
- numeric values are integers and within the declared bounds (`u8`, `u16`, `u32`, `i32`, and safe integers for `u64`/`i64`)

Typed RPC stubs use these asserts automatically.

## Generator outputs

Given `-go-out` and `-ts-out`:

- Go: `flowersec-go/gen/flowersec/<domain>/<version>/types.gen.go` with package name `v1`.
- TypeScript: `flowersec-ts/src/gen/flowersec/<domain>/<version>.gen.ts`.

When `services` is present:

- Go: `flowersec-go/gen/flowersec/<domain>/<version>/rpc.gen.go` (typed stubs; constants + clients + registration helpers).
- TypeScript: `flowersec-ts/src/gen/flowersec/<domain>/<version>.rpc.gen.ts` (typed client factory).
- TypeScript: `flowersec-ts/src/gen/flowersec/<domain>/<version>.facade.gen.ts` (ergonomic helpers: connect wrappers + service bundling).

Go handler ergonomics:

- Generated server handler interfaces return `(*Resp, error)` (instead of exposing the wire `RpcError` type).
- To return a non-500 RPC error code/message, return `&rpc.Error{Code: ..., Message: ...}` (from `github.com/floegence/flowersec/flowersec-go/rpc`).
- Any other non-nil error is treated as an internal error: `code=500`, `message="internal error"`.

## Deterministic ordering

To keep diffs stable, the generator sorts:

- input `.fidl.json` file paths
- enum names, message names, and service names
- enum value keys and service method names

## Usage

From the repository root:

```
make gen
```

Or run the generator directly:

```
go run ./tools/idlgen -in ./idl -go-out ./flowersec-go/gen -ts-out ./flowersec-ts/src/gen
```

## Example

A simplified example based on `idl/flowersec/tunnel/v1/tunnel.fidl.json`:

```
{
  "namespace": "flowersec.tunnel.v1",
  "enums": {
    "Role": {
      "comment": "Endpoint role for tunnel attach.",
      "type": "u8",
      "values": { "client": 1, "server": 2 },
      "value_comments": {
        "client": "Client endpoint.",
        "server": "Server endpoint."
      }
    }
  },
  "messages": {
    "Attach": {
      "comment": "Tunnel attach request payload.",
      "fields": [
        { "name": "channel_id", "type": "string", "comment": "Channel identifier." },
        { "name": "role", "type": "Role", "comment": "Endpoint role." },
        { "name": "caps", "type": "map<string,string>", "optional": true, "comment": "Optional capability map." }
      ]
    }
  }
}
```

## FAQ / common mistakes

### “Generation failed: unknown request/response message”

For typed RPC stubs, method `request`/`response` must refer to a message defined in the same `.fidl.json` file.

### “My u64/i64 values break in TypeScript”

The wire format is JSON and TS represents numbers as IEEE-754 doubles. Values must be safe integers.
If you need full 64-bit integer support in JS, you must represent them as strings in the wire schema
(not currently supported by this generator).

### “Does the IDL support `bytes`, `errors`, or union types?”

Not in the current generator. The supported field type keywords are listed in "Supported field types".
