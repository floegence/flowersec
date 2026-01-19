package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type schema struct {
	Namespace string                `json:"namespace"`
	Enums     map[string]enumDef    `json:"enums"`
	Messages  map[string]messageDef `json:"messages"`
	Services  map[string]serviceDef `json:"services"`
}

type enumDef struct {
	Type          string            `json:"type"`
	Comment       string            `json:"comment"`
	Values        map[string]int    `json:"values"`
	ValueComments map[string]string `json:"value_comments"`
}

type messageDef struct {
	Comment string     `json:"comment"`
	Fields  []fieldDef `json:"fields"`
}

type fieldDef struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Comment  string `json:"comment"`
	Optional bool   `json:"optional"`
}

type serviceDef struct {
	Comment string               `json:"comment"`
	Methods map[string]methodDef `json:"methods"`
}

type methodDef struct {
	Comment  string `json:"comment"`
	Kind     string `json:"kind"`    // "request" or "notify"
	TypeID   uint32 `json:"type_id"` // RPC type_id constant
	Request  string `json:"request"` // Request/notify payload message
	Response string `json:"response"`
}

func main() {
	var inDir string
	var goOut string
	var tsOut string
	var manifestPath string
	flag.StringVar(&inDir, "in", "", "input idl directory")
	flag.StringVar(&goOut, "go-out", "", "output directory for Go")
	flag.StringVar(&tsOut, "ts-out", "", "output directory for TypeScript")
	flag.StringVar(&manifestPath, "manifest", "", "optional manifest file listing .fidl.json paths (relative to -in)")
	flag.Parse()

	if strings.TrimSpace(inDir) == "" {
		fmt.Fprintln(os.Stderr, "missing -in")
		os.Exit(2)
	}
	if strings.TrimSpace(goOut) == "" && strings.TrimSpace(tsOut) == "" {
		fmt.Fprintln(os.Stderr, "missing -go-out and -ts-out (need at least one)")
		os.Exit(2)
	}

	var files []string
	var err error
	if strings.TrimSpace(manifestPath) != "" {
		files, err = listFIDLFilesFromManifest(inDir, manifestPath)
	} else {
		files, err = listFIDLFiles(inDir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "no *.fidl.json files found")
		os.Exit(1)
	}

	schemas := make([]schema, 0, len(files))
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		var s schema
		if err := json.Unmarshal(b, &s); err != nil {
			fmt.Fprintf(os.Stderr, "decode %s: %v\n", p, err)
			os.Exit(1)
		}
		if strings.TrimSpace(s.Namespace) == "" {
			fmt.Fprintf(os.Stderr, "missing namespace in %s\n", p)
			os.Exit(1)
		}
		schemas = append(schemas, s)
	}

	for _, s := range schemas {
		if err := validateSchema(s); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if strings.TrimSpace(goOut) != "" {
			if err := genGo(goOut, s); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := genGoRPC(goOut, s); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		if strings.TrimSpace(tsOut) != "" {
			if err := genTS(tsOut, s); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := genTSRPC(tsOut, s); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := genTSFacade(tsOut, s); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
	}
}

func listFIDLFilesFromManifest(root string, manifestPath string) ([]string, error) {
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	out := make([]string, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for i, line := range lines {
		raw := strings.TrimSpace(line)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		p := raw
		if !filepath.IsAbs(p) {
			p = filepath.Join(root, p)
		}
		p = filepath.Clean(p)
		if !strings.HasSuffix(p, ".fidl.json") {
			return nil, fmt.Errorf("manifest line %d: %q is not a .fidl.json path", i+1, raw)
		}
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("manifest line %d: %q: %w", i+1, raw, err)
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func listFIDLFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".fidl.json") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func genGo(outRoot string, s schema) error {
	domain, version, err := domainAndVersion(s.Namespace)
	if err != nil {
		return err
	}
	outDir := filepath.Join(outRoot, "flowersec", domain, version)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("// Code generated by idlgen. DO NOT EDIT.\n\n")
	buf.WriteString("package v1\n\n")
	buf.WriteString("import \"encoding/json\"\n\n")

	enumNames := sortedKeys(s.Enums)
	for _, name := range enumNames {
		ed := s.Enums[name]
		writeGoComment(&buf, ed.Comment, "")
		goType := "uint32"
		if strings.TrimSpace(ed.Type) == "u8" {
			goType = "uint8"
		} else if strings.TrimSpace(ed.Type) == "u16" {
			goType = "uint16"
		}
		fmt.Fprintf(&buf, "type %s %s\n\n", name, goType)
		buf.WriteString("const (\n")
		valueNames := sortedKeysInt(ed.Values)
		for _, vn := range valueNames {
			valueComment := ""
			if ed.ValueComments != nil {
				valueComment = ed.ValueComments[vn]
			}
			writeGoComment(&buf, valueComment, "\t")
			fmt.Fprintf(&buf, "\t%s_%s %s = %d\n", name, vn, name, ed.Values[vn])
		}
		buf.WriteString(")\n\n")
	}

	msgNames := sortedKeys(s.Messages)
	for _, name := range msgNames {
		md := s.Messages[name]
		writeGoComment(&buf, md.Comment, "")
		fmt.Fprintf(&buf, "type %s struct {\n", name)
		for _, f := range md.Fields {
			writeGoComment(&buf, f.Comment, "\t")
			goFieldName := exportName(f.Name)
			goType, err := goFieldType(f.Type)
			if err != nil {
				return fmt.Errorf("go type %s.%s: %w", name, f.Name, err)
			}
			if f.Optional {
				goType = "*" + goType
			}
			tag := fmt.Sprintf("`json:\"%s", f.Name)
			if f.Optional {
				tag += ",omitempty"
			}
			tag += "\"`"
			fmt.Fprintf(&buf, "\t%s %s %s\n", goFieldName, goType, tag)
		}
		buf.WriteString("}\n\n")
	}

	// Helper alias for JSON payloads.
	buf.WriteString("type JSON = json.RawMessage\n")

	outFile := filepath.Join(outDir, "types.gen.go")
	return os.WriteFile(outFile, buf.Bytes(), 0o644)
}

func genGoRPC(outRoot string, s schema) error {
	if len(s.Services) == 0 {
		return nil
	}
	domain, version, err := domainAndVersion(s.Namespace)
	if err != nil {
		return err
	}
	outDir := filepath.Join(outRoot, "flowersec", domain, version)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	var buf bytes.Buffer
	buf.WriteString("// Code generated by idlgen. DO NOT EDIT.\n\n")
	buf.WriteString("package v1\n\n")
	buf.WriteString("import (\n")
	buf.WriteString("\t\"context\"\n")
	buf.WriteString("\t\"encoding/json\"\n\n")
	buf.WriteString("\trpcwirev1 \"github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1\"\n")
	buf.WriteString("\t\"github.com/floegence/flowersec/flowersec-go/rpc\"\n")
	buf.WriteString(")\n\n")

	serviceNames := sortedKeys(s.Services)
	for _, svcName := range serviceNames {
		svc := s.Services[svcName]
		methodNames := sortedKeys(svc.Methods)
		for _, mn := range methodNames {
			m := svc.Methods[mn]
			constName := exportName(svcName) + "TypeID_" + exportName(mn)
			writeGoComment(&buf, m.Comment, "")
			fmt.Fprintf(&buf, "const %s uint32 = %d\n\n", constName, m.TypeID)
		}
	}

	for _, svcName := range serviceNames {
		svc := s.Services[svcName]
		svcExport := exportName(svcName)

		writeGoComment(&buf, svc.Comment, "")
		fmt.Fprintf(&buf, "type %sClient struct {\n\tc *rpc.Client\n}\n\n", svcExport)

		fmt.Fprintf(&buf, "func New%sClient(c *rpc.Client) *%sClient { return &%sClient{c: c} }\n\n", svcExport, svcExport, svcExport)

		// Server handler interface (request methods only).
		hasRequest := false
		methodNames := sortedKeys(svc.Methods)
		for _, mn := range methodNames {
			if strings.TrimSpace(svc.Methods[mn].Kind) == "request" {
				hasRequest = true
				break
			}
		}
		if hasRequest {
			fmt.Fprintf(&buf, "type %sHandler interface {\n", svcExport)
			for _, mn := range methodNames {
				m := svc.Methods[mn]
				if strings.TrimSpace(m.Kind) != "request" {
					continue
				}
				writeGoComment(&buf, m.Comment, "\t")
				fmt.Fprintf(&buf, "\t%s(ctx context.Context, req *%s) (*%s, error)\n", exportName(mn), exportName(m.Request), exportName(m.Response))
			}
			buf.WriteString("}\n\n")

			fmt.Fprintf(&buf, "func Register%s(r *rpc.Router, h %sHandler) {\n", svcExport, svcExport)
			for _, mn := range methodNames {
				m := svc.Methods[mn]
				if strings.TrimSpace(m.Kind) != "request" {
					continue
				}
				typeIDConst := svcExport + "TypeID_" + exportName(mn)
				reqType := exportName(m.Request)
				respType := exportName(m.Response)
				handlerMethod := exportName(mn)
				fmt.Fprintf(&buf, "\tr.Register(%s, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcwirev1.RpcError) {\n", typeIDConst)
				fmt.Fprintf(&buf, "\t\tvar req %s\n", reqType)
				buf.WriteString("\t\tif len(payload) != 0 {\n")
				fmt.Fprintf(&buf, "\t\t\tif err := json.Unmarshal(payload, &req); err != nil {\n")
				buf.WriteString("\t\t\t\treturn nil, rpc.ToWireError(&rpc.Error{Code: 400, Message: \"invalid payload\"})\n")
				buf.WriteString("\t\t\t}\n")
				buf.WriteString("\t\t}\n")
				fmt.Fprintf(&buf, "\t\tresp, err := h.%s(ctx, &req)\n", handlerMethod)
				buf.WriteString("\t\tif err != nil {\n")
				buf.WriteString("\t\t\treturn nil, rpc.ToWireError(err)\n")
				buf.WriteString("\t\t}\n")
				fmt.Fprintf(&buf, "\t\tvar zero %s\n", respType)
				buf.WriteString("\t\tif resp == nil {\n")
				buf.WriteString("\t\t\tresp = &zero\n")
				buf.WriteString("\t\t}\n")
				buf.WriteString("\t\tb, err := json.Marshal(resp)\n")
				buf.WriteString("\t\tif err != nil {\n")
				buf.WriteString("\t\t\treturn nil, rpc.ToWireError(err)\n")
				buf.WriteString("\t\t}\n")
				buf.WriteString("\t\treturn b, nil\n")
				buf.WriteString("\t})\n\n")
			}
			buf.WriteString("}\n\n")
		}

		// Client methods.
		for _, mn := range methodNames {
			m := svc.Methods[mn]
			kind := strings.TrimSpace(m.Kind)
			typeIDConst := svcExport + "TypeID_" + exportName(mn)
			if kind == "request" {
				reqType := exportName(m.Request)
				respType := exportName(m.Response)
				writeGoComment(&buf, m.Comment, "")
				fmt.Fprintf(&buf, "func (x *%sClient) %s(ctx context.Context, req *%s) (*%s, error) {\n", svcExport, exportName(mn), reqType, respType)
				buf.WriteString("\tif req == nil {\n")
				buf.WriteString("\t\treq = &" + reqType + "{}\n")
				buf.WriteString("\t}\n")
				buf.WriteString("\tb, err := json.Marshal(req)\n")
				buf.WriteString("\tif err != nil {\n\t\treturn nil, err\n\t}\n")
				fmt.Fprintf(&buf, "\tpayload, rpcErr, err := x.c.Call(ctx, %s, b)\n", typeIDConst)
				buf.WriteString("\tif err != nil {\n\t\treturn nil, err\n\t}\n")
				buf.WriteString("\tif rpcErr != nil {\n")
				fmt.Fprintf(&buf, "\t\treturn nil, rpc.NewCallError(%s, rpcErr)\n", typeIDConst)
				buf.WriteString("\t}\n")
				fmt.Fprintf(&buf, "\tvar resp %s\n", respType)
				buf.WriteString("\tif len(payload) != 0 {\n")
				buf.WriteString("\t\tif err := json.Unmarshal(payload, &resp); err != nil {\n\t\t\treturn nil, err\n\t\t}\n")
				buf.WriteString("\t}\n")
				buf.WriteString("\treturn &resp, nil\n")
				buf.WriteString("}\n\n")
				continue
			}
			if kind == "notify" {
				reqType := exportName(m.Request)
				writeGoComment(&buf, m.Comment, "")
				fmt.Fprintf(&buf, "func (x *%sClient) On%s(h func(*%s)) (unsubscribe func()) {\n", svcExport, exportName(mn), reqType)
				fmt.Fprintf(&buf, "\treturn x.c.OnNotify(%s, func(payload json.RawMessage) {\n", typeIDConst)
				fmt.Fprintf(&buf, "\t\tvar msg %s\n", reqType)
				buf.WriteString("\t\tif err := json.Unmarshal(payload, &msg); err != nil {\n\t\t\treturn\n\t\t}\n")
				buf.WriteString("\t\th(&msg)\n")
				buf.WriteString("\t})\n")
				buf.WriteString("}\n\n")

				writeGoComment(&buf, m.Comment, "")
				fmt.Fprintf(&buf, "func Notify%s%s(n interface{ Notify(uint32, json.RawMessage) error }, msg *%s) error {\n", svcExport, exportName(mn), reqType)
				buf.WriteString("\tif msg == nil {\n")
				buf.WriteString("\t\tmsg = &" + reqType + "{}\n")
				buf.WriteString("\t}\n")
				buf.WriteString("\tb, err := json.Marshal(msg)\n")
				buf.WriteString("\tif err != nil {\n\t\treturn err\n\t}\n")
				fmt.Fprintf(&buf, "\treturn n.Notify(%s, b)\n", typeIDConst)
				buf.WriteString("}\n\n")
				continue
			}
		}
	}

	outFile := filepath.Join(outDir, "rpc.gen.go")
	return os.WriteFile(outFile, buf.Bytes(), 0o644)
}

func goFieldType(t string) (string, error) {
	switch t {
	case "string":
		return "string", nil
	case "bool":
		return "bool", nil
	case "u8":
		return "uint8", nil
	case "u16":
		return "uint16", nil
	case "u32":
		return "uint32", nil
	case "u64":
		return "uint64", nil
	case "i32":
		return "int32", nil
	case "i64":
		return "int64", nil
	case "json":
		return "json.RawMessage", nil
	case "map<string,string>":
		return "map[string]string", nil
	default:
		if strings.HasPrefix(t, "[]") {
			elem, err := goFieldType(strings.TrimPrefix(t, "[]"))
			if err != nil {
				return "", err
			}
			return "[]" + elem, nil
		}
		// Treat as enum or message reference.
		return t, nil
	}
}

func genTS(outRoot string, s schema) error {
	domain, version, err := domainAndVersion(s.Namespace)
	if err != nil {
		return err
	}
	outDir := filepath.Join(outRoot, "flowersec", domain)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	outFile := filepath.Join(outDir, version+".gen.ts")

	var buf bytes.Buffer
	buf.WriteString("// Code generated by idlgen. DO NOT EDIT.\n\n")

	enumNames := sortedKeys(s.Enums)
	for _, name := range enumNames {
		ed := s.Enums[name]
		writeTSComment(&buf, ed.Comment, "")
		buf.WriteString("export enum " + name + " {\n")
		valueNames := sortedKeysInt(ed.Values)
		for _, vn := range valueNames {
			valueComment := ""
			if ed.ValueComments != nil {
				valueComment = ed.ValueComments[vn]
			}
			writeTSComment(&buf, valueComment, "  ")
			fmt.Fprintf(&buf, "  %s_%s = %d,\n", name, vn, ed.Values[vn])
		}
		buf.WriteString("}\n\n")
	}

	msgNames := sortedKeys(s.Messages)
	for _, name := range msgNames {
		md := s.Messages[name]
		writeTSComment(&buf, md.Comment, "")
		buf.WriteString("export interface " + name + " {\n")
		for _, f := range md.Fields {
			writeTSComment(&buf, f.Comment, "  ")
			tsType, err := tsFieldType(f.Type)
			if err != nil {
				return fmt.Errorf("ts type %s.%s: %w", name, f.Name, err)
			}
			opt := ""
			if f.Optional {
				opt = "?"
			}
			fmt.Fprintf(&buf, "  %s%s: %s;\n", f.Name, opt, tsType)
		}
		buf.WriteString("}\n\n")
	}

	writeTSAsserts(&buf, s)
	return os.WriteFile(outFile, buf.Bytes(), 0o644)
}

func genTSRPC(outRoot string, s schema) error {
	if len(s.Services) == 0 {
		return nil
	}
	domain, version, err := domainAndVersion(s.Namespace)
	if err != nil {
		return err
	}
	outDir := filepath.Join(outRoot, "flowersec", domain)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	outFile := filepath.Join(outDir, version+".rpc.gen.ts")

	var buf bytes.Buffer
	buf.WriteString("// Code generated by idlgen. DO NOT EDIT.\n\n")

	// Import shared RPC caller interface and shared call error.
	buf.WriteString("import type { RpcCaller } from \"../../../rpc/caller.js\";\n")
	buf.WriteString("import { RpcCallError } from \"../../../rpc/callError.js\";\n")

	// Collect referenced message types.
	typeNames := make(map[string]struct{})
	for _, svc := range s.Services {
		for _, m := range svc.Methods {
			if m.Request != "" {
				typeNames[m.Request] = struct{}{}
			}
			if strings.TrimSpace(m.Kind) == "request" && m.Response != "" {
				typeNames[m.Response] = struct{}{}
			}
		}
	}
	importNames := make([]string, 0, len(typeNames)*2)
	for tn := range typeNames {
		importNames = append(importNames, tn)
		importNames = append(importNames, "assert"+tn)
	}
	sort.Strings(importNames)
	if len(importNames) > 0 {
		buf.WriteString("import {\n")
		for _, n := range importNames {
			buf.WriteString("  " + n + ",\n")
		}
		buf.WriteString("} from \"./" + version + ".gen.js\";\n\n")
	}

	serviceNames := sortedKeys(s.Services)
	for _, svcName := range serviceNames {
		svc := s.Services[svcName]
		svcExport := exportName(svcName)
		writeTSComment(&buf, svc.Comment, "")
		buf.WriteString("export function create" + svcExport + "Client(rpc: RpcCaller) {\n")
		buf.WriteString("  return {\n")
		methodNames := sortedKeys(svc.Methods)
		for _, mn := range methodNames {
			m := svc.Methods[mn]
			kind := strings.TrimSpace(m.Kind)
			typeID := int(m.TypeID)
			methodLower := lowerCamel(mn)
			writeTSComment(&buf, m.Comment, "    ")
			if kind == "request" {
				reqType := m.Request
				respType := m.Response
				buf.WriteString("    " + methodLower + ": async (req: " + reqType + ", opts: Readonly<{ signal?: AbortSignal }> = {}) => {\n")
				buf.WriteString("      const checkedReq = assert" + reqType + "(req);\n")
				fmt.Fprintf(&buf, "      const resp = await rpc.call(%d, checkedReq, opts.signal);\n", typeID)
				buf.WriteString("      if (resp.error != null) throw new RpcCallError(resp.error.code, resp.error.message, " + fmt.Sprintf("%d", typeID) + ");\n")
				buf.WriteString("      return assert" + respType + "(resp.payload);\n")
				buf.WriteString("    },\n")
				continue
			}
			if kind == "notify" {
				reqType := m.Request
				// onX subscription
				buf.WriteString("    on" + exportName(mn) + ": (handler: (v: " + reqType + ") => void) => {\n")
				fmt.Fprintf(&buf, "      return rpc.onNotify(%d, (payload) => {\n", typeID)
				buf.WriteString("        handler(assert" + reqType + "(payload));\n")
				buf.WriteString("      });\n")
				buf.WriteString("    },\n")
				continue
			}
		}
		buf.WriteString("  };\n")
		buf.WriteString("}\n\n")
	}

	return os.WriteFile(outFile, buf.Bytes(), 0o644)
}

func genTSFacade(outRoot string, s schema) error {
	if len(s.Services) == 0 {
		return nil
	}
	domain, version, err := domainAndVersion(s.Namespace)
	if err != nil {
		return err
	}
	outDir := filepath.Join(outRoot, "flowersec", domain)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	outFile := filepath.Join(outDir, version+".facade.gen.ts")

	serviceNames := sortedKeys(s.Services)
	if len(serviceNames) == 0 {
		return nil
	}

	var buf bytes.Buffer
	buf.WriteString("// Code generated by idlgen. DO NOT EDIT.\n\n")

	// This file is an ergonomic layer on top of typed RPC stubs.
	buf.WriteString("import type { Client } from \"../../../client.js\";\n")
	buf.WriteString("import { connectDirect } from \"../../../direct-client/connect.js\";\n")
	buf.WriteString("import type { DirectConnectOptions } from \"../../../direct-client/connect.js\";\n")
	buf.WriteString("import { connectTunnel } from \"../../../tunnel-client/connect.js\";\n")
	buf.WriteString("import type { TunnelConnectOptions } from \"../../../tunnel-client/connect.js\";\n")
	buf.WriteString("import type { ChannelInitGrant } from \"../../../gen/flowersec/controlplane/v1.gen.js\";\n")
	buf.WriteString("import type { DirectConnectInfo } from \"../../../gen/flowersec/direct/v1.gen.js\";\n")
	buf.WriteString("import {\n")
	for _, svcName := range serviceNames {
		svcExport := exportName(svcName)
		buf.WriteString("  create" + svcExport + "Client,\n")
	}
	buf.WriteString("} from \"./" + version + ".rpc.gen.js\";\n\n")

	if len(serviceNames) == 1 {
		svcName := serviceNames[0]
		svcExport := exportName(svcName)
		prop := lowerCamel(svcName)

		buf.WriteString("export type " + svcExport + "Session = Client & Readonly<{ " + prop + ": ReturnType<typeof create" + svcExport + "Client> }>;\n\n")

		buf.WriteString("export function create" + svcExport + "Session(client: Client): " + svcExport + "Session {\n")
		buf.WriteString("  return { ...client, " + prop + ": create" + svcExport + "Client(client.rpc) };\n")
		buf.WriteString("}\n\n")

		buf.WriteString("export async function connect" + svcExport + "Tunnel(grant: ChannelInitGrant, opts: TunnelConnectOptions): Promise<" + svcExport + "Session>;\n")
		buf.WriteString("export async function connect" + svcExport + "Tunnel(grant: unknown, opts: TunnelConnectOptions): Promise<" + svcExport + "Session> {\n")
		buf.WriteString("  const client = await connectTunnel(grant, opts);\n")
		buf.WriteString("  return create" + svcExport + "Session(client);\n")
		buf.WriteString("}\n\n")

		buf.WriteString("export async function connect" + svcExport + "Direct(info: DirectConnectInfo, opts: DirectConnectOptions): Promise<" + svcExport + "Session>;\n")
		buf.WriteString("export async function connect" + svcExport + "Direct(info: unknown, opts: DirectConnectOptions): Promise<" + svcExport + "Session> {\n")
		buf.WriteString("  const client = await connectDirect(info, opts);\n")
		buf.WriteString("  return create" + svcExport + "Session(client);\n")
		buf.WriteString("}\n")

		return os.WriteFile(outFile, buf.Bytes(), 0o644)
	}

	apiExport := exportName(domain)
	buf.WriteString("export type " + apiExport + "Api = Client & Readonly<{\n")
	for _, svcName := range serviceNames {
		prop := lowerCamel(svcName)
		svcExport := exportName(svcName)
		buf.WriteString("  " + prop + ": ReturnType<typeof create" + svcExport + "Client>;\n")
	}
	buf.WriteString("}>;\n\n")

	buf.WriteString("export function create" + apiExport + "Api(client: Client): " + apiExport + "Api {\n")
	buf.WriteString("  return {\n")
	buf.WriteString("    ...client,\n")
	for _, svcName := range serviceNames {
		prop := lowerCamel(svcName)
		svcExport := exportName(svcName)
		buf.WriteString("    " + prop + ": create" + svcExport + "Client(client.rpc),\n")
	}
	buf.WriteString("  };\n")
	buf.WriteString("}\n\n")

	buf.WriteString("export async function connect" + apiExport + "Tunnel(grant: ChannelInitGrant, opts: TunnelConnectOptions): Promise<" + apiExport + "Api>;\n")
	buf.WriteString("export async function connect" + apiExport + "Tunnel(grant: unknown, opts: TunnelConnectOptions): Promise<" + apiExport + "Api> {\n")
	buf.WriteString("  const client = await connectTunnel(grant, opts);\n")
	buf.WriteString("  return create" + apiExport + "Api(client);\n")
	buf.WriteString("}\n\n")

	buf.WriteString("export async function connect" + apiExport + "Direct(info: DirectConnectInfo, opts: DirectConnectOptions): Promise<" + apiExport + "Api>;\n")
	buf.WriteString("export async function connect" + apiExport + "Direct(info: unknown, opts: DirectConnectOptions): Promise<" + apiExport + "Api> {\n")
	buf.WriteString("  const client = await connectDirect(info, opts);\n")
	buf.WriteString("  return create" + apiExport + "Api(client);\n")
	buf.WriteString("}\n")

	return os.WriteFile(outFile, buf.Bytes(), 0o644)
}

func tsFieldType(t string) (string, error) {
	switch t {
	case "string":
		return "string", nil
	case "bool":
		return "boolean", nil
	case "u8", "u16", "u32", "u64", "i32", "i64":
		return "number", nil
	case "json":
		return "unknown", nil
	case "map<string,string>":
		return "Record<string, string>", nil
	default:
		if strings.HasPrefix(t, "[]") {
			elem, err := tsFieldType(strings.TrimPrefix(t, "[]"))
			if err != nil {
				return "", err
			}
			return elem + "[]", nil
		}
		return t, nil
	}
}

func validateSchema(s schema) error {
	// Verify all service methods reference known message types and have valid kinds.
	seen := map[uint32]string{}
	for svcName, svc := range s.Services {
		for methodName, m := range svc.Methods {
			kind := strings.TrimSpace(m.Kind)
			if kind != "request" && kind != "notify" {
				return fmt.Errorf("schema %s: service %s method %s: invalid kind %q", s.Namespace, svcName, methodName, m.Kind)
			}
			if m.TypeID == 0 {
				return fmt.Errorf("schema %s: service %s method %s: missing type_id", s.Namespace, svcName, methodName)
			}
			if prev, ok := seen[m.TypeID]; ok {
				return fmt.Errorf("schema %s: duplicate type_id %d (%s and %s.%s)", s.Namespace, m.TypeID, prev, svcName, methodName)
			}
			seen[m.TypeID] = svcName + "." + methodName
			if strings.TrimSpace(m.Request) == "" {
				return fmt.Errorf("schema %s: service %s method %s: missing request type", s.Namespace, svcName, methodName)
			}
			if _, ok := s.Messages[m.Request]; !ok {
				return fmt.Errorf("schema %s: service %s method %s: unknown request message %q", s.Namespace, svcName, methodName, m.Request)
			}
			if kind == "request" {
				if strings.TrimSpace(m.Response) == "" {
					return fmt.Errorf("schema %s: service %s method %s: missing response type", s.Namespace, svcName, methodName)
				}
				if _, ok := s.Messages[m.Response]; !ok {
					return fmt.Errorf("schema %s: service %s method %s: unknown response message %q", s.Namespace, svcName, methodName, m.Response)
				}
			} else {
				if strings.TrimSpace(m.Response) != "" {
					return fmt.Errorf("schema %s: service %s method %s: notify must not have response", s.Namespace, svcName, methodName)
				}
			}
		}
	}
	return nil
}

func domainAndVersion(ns string) (domain string, version string, err error) {
	parts := strings.Split(ns, ".")
	if len(parts) < 3 {
		return "", "", fmt.Errorf("invalid namespace: %s", ns)
	}
	// Expected: flowersec.<domain>.v1 (or deeper, where <domain> is parts[1]).
	domain = parts[1]
	version = parts[len(parts)-1]
	return domain, version, nil
}

func exportName(s string) string {
	parts := strings.Split(s, "_")
	for i := range parts {
		if parts[i] == "" {
			continue
		}
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	out := strings.Join(parts, "")
	if out == "Json" {
		return "JSON"
	}
	return out
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysInt(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func lowerCamel(s string) string {
	p := exportName(s)
	if p == "" {
		return ""
	}
	return strings.ToLower(p[:1]) + p[1:]
}

func splitCommentLines(comment string) []string {
	comment = strings.TrimSpace(comment)
	if comment == "" {
		return nil
	}
	lines := strings.Split(comment, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, strings.TrimRight(line, "\r"))
	}
	return out
}

func writeGoComment(buf *bytes.Buffer, comment string, indent string) {
	lines := splitCommentLines(comment)
	if len(lines) == 0 {
		return
	}
	for _, line := range lines {
		if line == "" {
			fmt.Fprintf(buf, "%s//\n", indent)
			continue
		}
		fmt.Fprintf(buf, "%s// %s\n", indent, line)
	}
}

func writeTSComment(buf *bytes.Buffer, comment string, indent string) {
	lines := splitCommentLines(comment)
	if len(lines) == 0 {
		return
	}
	if len(lines) == 1 {
		fmt.Fprintf(buf, "%s/** %s */\n", indent, lines[0])
		return
	}
	fmt.Fprintf(buf, "%s/**\n", indent)
	for _, line := range lines {
		if line == "" {
			fmt.Fprintf(buf, "%s *\n", indent)
			continue
		}
		fmt.Fprintf(buf, "%s * %s\n", indent, line)
	}
	fmt.Fprintf(buf, "%s */\n", indent)
}

func writeTSAsserts(buf *bytes.Buffer, s schema) {
	if len(s.Messages) == 0 && len(s.Enums) == 0 {
		return
	}

	// Shared helpers.
	buf.WriteString("function isRecord(v: unknown): v is Record<string, unknown> {\n")
	buf.WriteString("  return typeof v === \"object\" && v != null && !Array.isArray(v);\n")
	buf.WriteString("}\n\n")
	buf.WriteString("function assertString(name: string, v: unknown): string {\n")
	buf.WriteString("  if (typeof v !== \"string\") throw new Error(`bad ${name}`);\n")
	buf.WriteString("  return v;\n")
	buf.WriteString("}\n\n")
	buf.WriteString("function assertBoolean(name: string, v: unknown): boolean {\n")
	buf.WriteString("  if (typeof v !== \"boolean\") throw new Error(`bad ${name}`);\n")
	buf.WriteString("  return v;\n")
	buf.WriteString("}\n\n")
	buf.WriteString("function assertSafeInt(name: string, v: unknown): number {\n")
	buf.WriteString("  if (typeof v !== \"number\" || !Number.isSafeInteger(v)) throw new Error(`bad ${name}`);\n")
	buf.WriteString("  return v;\n")
	buf.WriteString("}\n\n")
	buf.WriteString("function assertU32(name: string, v: unknown): number {\n")
	buf.WriteString("  const n = assertSafeInt(name, v);\n")
	buf.WriteString("  if (n < 0 || n > 0xffffffff) throw new Error(`bad ${name}`);\n")
	buf.WriteString("  return n;\n")
	buf.WriteString("}\n\n")
	buf.WriteString("function assertU16(name: string, v: unknown): number {\n")
	buf.WriteString("  const n = assertU32(name, v);\n")
	buf.WriteString("  if (n > 0xffff) throw new Error(`bad ${name}`);\n")
	buf.WriteString("  return n;\n")
	buf.WriteString("}\n\n")
	buf.WriteString("function assertU8(name: string, v: unknown): number {\n")
	buf.WriteString("  const n = assertU32(name, v);\n")
	buf.WriteString("  if (n > 0xff) throw new Error(`bad ${name}`);\n")
	buf.WriteString("  return n;\n")
	buf.WriteString("}\n\n")
	buf.WriteString("function assertU64(name: string, v: unknown): number {\n")
	buf.WriteString("  const n = assertSafeInt(name, v);\n")
	buf.WriteString("  if (n < 0) throw new Error(`bad ${name}`);\n")
	buf.WriteString("  return n;\n")
	buf.WriteString("}\n\n")
	buf.WriteString("function assertI32(name: string, v: unknown): number {\n")
	buf.WriteString("  const n = assertSafeInt(name, v);\n")
	buf.WriteString("  if (n < -2147483648 || n > 2147483647) throw new Error(`bad ${name}`);\n")
	buf.WriteString("  return n;\n")
	buf.WriteString("}\n\n")
	buf.WriteString("function assertI64(name: string, v: unknown): number {\n")
	buf.WriteString("  return assertSafeInt(name, v);\n")
	buf.WriteString("}\n\n")
	buf.WriteString("function assertStringMap(name: string, v: unknown): Record<string, string> {\n")
	buf.WriteString("  if (!isRecord(v)) throw new Error(`bad ${name}`);\n")
	buf.WriteString("  for (const [k, vv] of Object.entries(v)) {\n")
	buf.WriteString("    void k;\n")
	buf.WriteString("    if (typeof vv !== \"string\") throw new Error(`bad ${name}`);\n")
	buf.WriteString("  }\n")
	buf.WriteString("  return v as Record<string, string>;\n")
	buf.WriteString("}\n\n")

	// Enum value sets.
	enumNames := sortedKeys(s.Enums)
	enumSet := map[string]struct{}{}
	for _, name := range enumNames {
		ed := s.Enums[name]
		enumSet[name] = struct{}{}
		_ = ed
		buf.WriteString("const _" + name + "Values = new Set<number>([\n")
		valueNames := sortedKeysInt(ed.Values)
		for _, vn := range valueNames {
			fmt.Fprintf(buf, "  %d,\n", ed.Values[vn])
		}
		buf.WriteString("]);\n\n")
		buf.WriteString("function assert" + name + "(name: string, v: unknown): " + name + " {\n")
		buf.WriteString("  const n = assertSafeInt(name, v);\n")
		buf.WriteString("  if (!_" + name + "Values.has(n)) throw new Error(`bad ${name}`);\n")
		buf.WriteString("  return n as " + name + ";\n")
		buf.WriteString("}\n\n")
	}

	// Message asserts.
	msgNames := sortedKeys(s.Messages)
	for _, name := range msgNames {
		md := s.Messages[name]
		_ = md
		buf.WriteString("export function assert" + name + "(v: unknown): " + name + " {\n")
		buf.WriteString("  if (!isRecord(v)) throw new Error(\"bad " + name + "\");\n")
		buf.WriteString("  const o = v as Record<string, unknown>;\n")
		for _, f := range md.Fields {
			fieldExpr := "o[\"" + f.Name + "\"]"
			fieldName := name + "." + f.Name
			if f.Optional {
				buf.WriteString("  if (o[\"" + f.Name + "\"] !== undefined) {\n")
				buf.WriteString("    ")
			} else {
				buf.WriteString("  if (o[\"" + f.Name + "\"] === undefined) throw new Error(\"bad " + fieldName + "\");\n")
				buf.WriteString("  ")
			}

			writeTSAssertExpr(buf, fieldName, f.Type, fieldExpr, "  ", enumSet)
			if f.Optional {
				buf.WriteString("  }\n")
			}
		}
		buf.WriteString("  return o as unknown as " + name + ";\n")
		buf.WriteString("}\n\n")
	}
}

func writeTSAssertExpr(buf *bytes.Buffer, name string, typ string, expr string, indent string, enumSet map[string]struct{}) {
	switch typ {
	case "string":
		fmt.Fprintf(buf, "assertString(%q, %s);\n", name, expr)
	case "bool":
		fmt.Fprintf(buf, "assertBoolean(%q, %s);\n", name, expr)
	case "u8":
		fmt.Fprintf(buf, "assertU8(%q, %s);\n", name, expr)
	case "u16":
		fmt.Fprintf(buf, "assertU16(%q, %s);\n", name, expr)
	case "u32":
		fmt.Fprintf(buf, "assertU32(%q, %s);\n", name, expr)
	case "u64":
		fmt.Fprintf(buf, "assertU64(%q, %s);\n", name, expr)
	case "i32":
		fmt.Fprintf(buf, "assertI32(%q, %s);\n", name, expr)
	case "i64":
		fmt.Fprintf(buf, "assertI64(%q, %s);\n", name, expr)
	case "json":
		fmt.Fprintf(buf, "void %s;\n", expr)
	case "map<string,string>":
		fmt.Fprintf(buf, "assertStringMap(%q, %s);\n", name, expr)
	default:
		if strings.HasPrefix(typ, "[]") {
			elem := strings.TrimPrefix(typ, "[]")
			fmt.Fprintf(buf, "if (!Array.isArray(%s)) throw new Error(%q);\n", expr, "bad "+name)
			fmt.Fprintf(buf, "for (let i = 0; i < (%s as unknown[]).length; i++) {\n", expr)
			elemExpr := fmt.Sprintf("(%s as unknown[])[i]", expr)
			writeTSAssertExpr(buf, name+"[]", elem, elemExpr, indent+"  ", enumSet)
			buf.WriteString("}\n")
			return
		}
		// Enum or message reference.
		if _, ok := enumSet[typ]; ok {
			fmt.Fprintf(buf, "assert%s(%q, %s);\n", typ, name, expr)
		} else {
			fmt.Fprintf(buf, "assert%s(%s);\n", typ, expr)
		}
	}
}
