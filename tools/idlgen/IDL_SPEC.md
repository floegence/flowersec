# Flowersec IDL Spec (fidl.json)

## Overview

The IDL used in this repository is a JSON-based schema with the suffix `.fidl.json`.
`tools/idlgen` reads these files and generates Go and TypeScript types.

The generator scans the input directory recursively for `*.fidl.json` files. The
`namespace` field is required and drives output paths.

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

## JSON schema

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
  }
}
```

Notes:

- `enums` and `messages` can be empty or omitted.
- `comment` and `value_comments` are optional and only affect generated doc comments.
- Enum `type` is only used for Go output; `u8` -> `uint8`, `u16` -> `uint16`, otherwise `uint32`.

## Supported field types and mappings

```
string             -> Go string            | TS string
bool               -> Go bool              | TS boolean
u8                 -> Go uint8             | TS number
u16                -> Go uint16            | TS number
u32                -> Go uint32            | TS number
u64                -> Go uint64            | TS number
i32                -> Go int32             | TS number
i64                -> Go int64             | TS number
json               -> Go json.RawMessage   | TS unknown
map<string,string> -> Go map[string]string | TS Record<string, string>
[]T                -> Go []T               | TS T[]
EnumOrMessage      -> Go EnumOrMessage     | TS EnumOrMessage
```

## Optional fields

When `optional: true` is set on a field:

- Go: the field type becomes a pointer and the JSON tag includes `omitempty`.
- TypeScript: the field becomes optional (`field_name?: Type`).

## Naming rules

- Field names are expected to be `snake_case`. Go output converts them to exported
  `PascalCase` field names. The special field name `json` becomes `JSON` in Go.
- Enum values are emitted with the enum name prefix, for example `Role_client`.
- Message and enum type names are used verbatim in both Go and TypeScript output.

## Generator outputs

Given `-go-out` and `-ts-out`:

- Go: `go/gen/flowersec/<domain>/<version>/types.gen.go` with package name `v1`.
- TypeScript: `ts/src/gen/flowersec/<domain>/<version>.gen.ts`.

## Usage

From the repository root:

```
make gen
```

Or run the generator directly:

```
go run ./tools/idlgen -in ./idl -go-out ./go/gen -ts-out ./ts/src/gen
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
