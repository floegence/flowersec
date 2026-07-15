package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	var inDir string
	var goOut string
	var tsOut string
	var rustOut string
	var swiftOut string
	var swiftImport string
	var manifestPath string
	showVersion := false

	fs := flag.NewFlagSet("idlgen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&inDir, "in", "", "input idl directory")
	fs.StringVar(&goOut, "go-out", "", "output directory for Go")
	fs.StringVar(&tsOut, "ts-out", "", "output directory for TypeScript")
	fs.StringVar(&rustOut, "rust-out", "", "output directory for Rust")
	fs.StringVar(&swiftOut, "swift-out", "", "output directory for Swift")
	fs.StringVar(&swiftImport, "swift-import", "", "optional module imported by generated Swift files")
	fs.StringVar(&manifestPath, "manifest", "", "optional manifest file listing .fidl.json paths (relative to -in)")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  idlgen -in <dir> (-go-out <dir> | -ts-out <dir> | -rust-out <dir> | -swift-out <dir>) [flags]")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  # Generate Go + TS stubs for stable protocol IDLs.")
		fmt.Fprintln(out, "  idlgen \\")
		fmt.Fprintln(out, "    -in ./idl \\")
		fmt.Fprintln(out, "    -manifest ./idl/manifest.core.txt \\")
		fmt.Fprintln(out, "    -go-out ./flowersec-go/gen \\")
		fmt.Fprintln(out, "    -ts-out ./flowersec-ts/src/gen")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Output:")
		fmt.Fprintln(out, "  writes files under -go-out and/or -ts-out")
		fmt.Fprintln(out, "  stderr: errors")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Exit codes:")
		fmt.Fprintln(out, "  0: success")
		fmt.Fprintln(out, "  2: usage error (bad flags/missing required)")
		fmt.Fprintln(out, "  1: runtime error")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Flags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if showVersion {
		_, _ = fmt.Fprintln(stdout, versionString())
		return 0
	}

	if strings.TrimSpace(inDir) == "" {
		fmt.Fprintln(stderr, "missing -in")
		fs.Usage()
		return 2
	}
	if strings.TrimSpace(goOut) == "" && strings.TrimSpace(tsOut) == "" && strings.TrimSpace(rustOut) == "" && strings.TrimSpace(swiftOut) == "" {
		fmt.Fprintln(stderr, "missing language output (need at least one of -go-out, -ts-out, -rust-out, -swift-out)")
		fs.Usage()
		return 2
	}

	var files []string
	var err error
	if strings.TrimSpace(manifestPath) != "" {
		files, err = listFIDLFilesFromManifest(inDir, manifestPath)
	} else {
		files, err = listFIDLFiles(inDir)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if len(files) == 0 {
		fmt.Fprintln(stderr, "no *.fidl.json files found")
		return 1
	}

	schemas := make([]schema, 0, len(files))
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		var s schema
		if err := json.Unmarshal(b, &s); err != nil {
			fmt.Fprintf(stderr, "decode %s: %v\n", p, err)
			return 1
		}
		if strings.TrimSpace(s.Namespace) == "" {
			fmt.Fprintf(stderr, "missing namespace in %s\n", p)
			return 1
		}
		schemas = append(schemas, s)
	}

	for _, s := range schemas {
		if err := validateSchema(s); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if strings.TrimSpace(goOut) != "" {
			if err := genGo(goOut, s); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			if err := genGoRPC(goOut, s); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		}
		if strings.TrimSpace(tsOut) != "" {
			if err := genTS(tsOut, s); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			if err := genTSRPC(tsOut, s); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			if err := genTSFacade(tsOut, s); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		}
		if strings.TrimSpace(rustOut) != "" {
			if err := genRust(rustOut, s); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			if err := genRustRPC(rustOut, s); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		}
		if strings.TrimSpace(swiftOut) != "" {
			if err := genSwift(swiftOut, swiftImport, s); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		}
	}
	return 0
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

func genRust(outRoot string, s schema) error {
	domain, version, err := domainAndVersion(s.Namespace)
	if err != nil {
		return err
	}
	outDir := filepath.Join(outRoot, "flowersec", domain)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := ensureRustModule(outRoot, "flowersec"); err != nil {
		return err
	}
	if err := ensureRustModule(filepath.Join(outRoot, "flowersec"), domain); err != nil {
		return err
	}
	if err := ensureRustModule(outDir, version); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("// Code generated by idlgen. DO NOT EDIT.\n\n")
	buf.WriteString("#![allow(non_camel_case_types)]\n\n")
	buf.WriteString("use serde::{Deserialize, Serialize};\n")
	if len(s.Enums) > 0 {
		buf.WriteString("use serde_repr::{Deserialize_repr, Serialize_repr};\n")
	}
	if schemaUsesType(s, "map<string,string>") {
		buf.WriteString("use std::collections::BTreeMap;\n")
	}
	buf.WriteString("\n")

	for _, name := range sortedKeys(s.Enums) {
		ed := s.Enums[name]
		writeRustComment(&buf, ed.Comment, "")
		repr := "u32"
		if strings.TrimSpace(ed.Type) == "u8" {
			repr = "u8"
		} else if strings.TrimSpace(ed.Type) == "u16" {
			repr = "u16"
		}
		buf.WriteString("#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize_repr, Deserialize_repr)]\n")
		fmt.Fprintf(&buf, "#[repr(%s)]\n", repr)
		fmt.Fprintf(&buf, "pub enum %s {\n", name)
		for _, valueName := range sortedKeysInt(ed.Values) {
			writeRustComment(&buf, ed.ValueComments[valueName], "    ")
			fmt.Fprintf(&buf, "    %s = %d,\n", rustTypeName(valueName), ed.Values[valueName])
		}
		buf.WriteString("}\n\n")
	}

	for _, name := range sortedKeys(s.Messages) {
		md := s.Messages[name]
		writeRustComment(&buf, md.Comment, "")
		buf.WriteString("#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]\n")
		fmt.Fprintf(&buf, "pub struct %s {\n", name)
		for _, field := range md.Fields {
			writeRustComment(&buf, field.Comment, "    ")
			fieldType, err := rustFieldType(field.Type)
			if err != nil {
				return fmt.Errorf("rust type %s.%s: %w", name, field.Name, err)
			}
			if field.Optional {
				buf.WriteString("    #[serde(default, skip_serializing_if = \"Option::is_none\")]\n")
				fieldType = "Option<" + fieldType + ">"
			}
			fmt.Fprintf(&buf, "    pub %s: %s,\n", field.Name, fieldType)
		}
		buf.WriteString("}\n\n")
	}

	return os.WriteFile(filepath.Join(outDir, version+".rs"), buf.Bytes(), 0o644)
}

func genRustRPC(outRoot string, s schema) error {
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
	if err := ensureRustModule(outDir, version+"_rpc"); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("// Code generated by idlgen. DO NOT EDIT.\n\n")
	buf.WriteString("use super::*;\n")
	buf.WriteString("use crate::generated::flowersec::rpc::v1::RpcError as WireRpcError;\n")
	buf.WriteString("use crate::rpc::{Router, RpcClient, RpcError, RpcSubscription};\n")
	buf.WriteString("use std::sync::Arc;\n\n")
	for _, serviceName := range sortedKeys(s.Services) {
		service := s.Services[serviceName]
		serviceExport := exportName(serviceName)
		for _, methodName := range sortedKeys(service.Methods) {
			method := service.Methods[methodName]
			writeRustComment(&buf, method.Comment, "")
			fmt.Fprintf(&buf, "pub const %s_TYPE_ID_%s: u32 = %d;\n", strings.ToUpper(serviceExport), strings.ToUpper(snakeName(methodName)), method.TypeID)
		}
		buf.WriteString("\n")
		writeRustComment(&buf, service.Comment, "")
		fmt.Fprintf(&buf, "#[derive(Clone, Debug)]\npub struct %sClient {\n    rpc: RpcClient,\n}\n\n", serviceExport)
		fmt.Fprintf(&buf, "impl %sClient {\n", serviceExport)
		buf.WriteString("    pub fn new(rpc: RpcClient) -> Self { Self { rpc } }\n\n")
		for _, methodName := range sortedKeys(service.Methods) {
			method := service.Methods[methodName]
			constName := strings.ToUpper(serviceExport) + "_TYPE_ID_" + strings.ToUpper(snakeName(methodName))
			writeRustComment(&buf, method.Comment, "    ")
			if strings.TrimSpace(method.Kind) == "request" {
				fmt.Fprintf(&buf, "    pub async fn %s(&self, request: &%s) -> Result<%s, RpcError> {\n", snakeName(methodName), method.Request, method.Response)
				fmt.Fprintf(&buf, "        self.rpc.call_typed(%s, request).await\n", constName)
				buf.WriteString("    }\n\n")
			} else if strings.TrimSpace(method.Kind) == "notify" {
				fmt.Fprintf(&buf, "    pub fn on_%s<F, Fut>(&self, handler: F) -> RpcSubscription\n", snakeName(methodName))
				buf.WriteString("    where\n")
				fmt.Fprintf(&buf, "        F: Fn(%s) -> Fut + Send + Sync + 'static,\n", method.Request)
				buf.WriteString("        Fut: std::future::Future<Output = ()> + Send + 'static,\n")
				buf.WriteString("    {\n")
				fmt.Fprintf(&buf, "        self.rpc.on_notify_typed(%s, handler)\n", constName)
				buf.WriteString("    }\n\n")
			}
		}
		buf.WriteString("}\n\n")

		requestMethods := make([]string, 0, len(service.Methods))
		for _, methodName := range sortedKeys(service.Methods) {
			if strings.TrimSpace(service.Methods[methodName].Kind) == "request" {
				requestMethods = append(requestMethods, methodName)
			}
		}
		if len(requestMethods) > 0 {
			fmt.Fprintf(&buf, "#[async_trait::async_trait]\npub trait %sHandler: Send + Sync + 'static {\n", serviceExport)
			for _, methodName := range requestMethods {
				method := service.Methods[methodName]
				writeRustComment(&buf, method.Comment, "    ")
				fmt.Fprintf(&buf, "    async fn %s(&self, request: %s) -> Result<%s, WireRpcError>;\n", snakeName(methodName), method.Request, method.Response)
			}
			buf.WriteString("}\n\n")
			fmt.Fprintf(&buf, "pub async fn register_%s(router: &Router, handler: Arc<dyn %sHandler>) {\n", snakeName(serviceName), serviceExport)
			for _, methodName := range requestMethods {
				method := service.Methods[methodName]
				constName := strings.ToUpper(serviceExport) + "_TYPE_ID_" + strings.ToUpper(snakeName(methodName))
				buf.WriteString("    {\n")
				buf.WriteString("        let handler = handler.clone();\n")
				fmt.Fprintf(&buf, "        router.register(%s, move |payload| {\n", constName)
				buf.WriteString("            let handler = handler.clone();\n")
				buf.WriteString("            async move {\n")
				fmt.Fprintf(&buf, "                let request: %s = serde_json::from_value(payload).map_err(|_| WireRpcError {\n", method.Request)
				buf.WriteString("                    code: 400,\n                    message: Some(\"invalid payload\".to_owned()),\n                })?;\n")
				fmt.Fprintf(&buf, "                let response = handler.%s(request).await?;\n", snakeName(methodName))
				buf.WriteString("                serde_json::to_value(response).map_err(|_| WireRpcError {\n")
				buf.WriteString("                    code: 500,\n                    message: Some(\"response encoding failed\".to_owned()),\n                })\n")
				buf.WriteString("            }\n        }).await;\n    }\n")
			}
			buf.WriteString("}\n\n")
		}
	}
	return os.WriteFile(filepath.Join(outDir, version+"_rpc.rs"), buf.Bytes(), 0o644)
}

func ensureRustModule(dir, module string) error {
	if strings.TrimSpace(module) == "" {
		return errors.New("rust module name is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "mod.rs")
	modules := map[string]struct{}{module: {}}
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "pub mod ") && strings.HasSuffix(line, ";") {
				modules[strings.TrimSuffix(strings.TrimPrefix(line, "pub mod "), ";")] = struct{}{}
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	for _, name := range names {
		fmt.Fprintf(&buf, "pub mod %s;\n", name)
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func rustFieldType(t string) (string, error) {
	switch t {
	case "string":
		return "String", nil
	case "bool":
		return "bool", nil
	case "u8", "u16", "u32", "u64", "i32", "i64":
		return t, nil
	case "json":
		return "serde_json::Value", nil
	case "map<string,string>":
		return "BTreeMap<String, String>", nil
	default:
		if strings.HasPrefix(t, "[]") {
			elem, err := rustFieldType(strings.TrimPrefix(t, "[]"))
			if err != nil {
				return "", err
			}
			return "Vec<" + elem + ">", nil
		}
		return t, nil
	}
}

func schemaUsesType(s schema, target string) bool {
	for _, message := range s.Messages {
		for _, field := range message.Fields {
			if field.Type == target || strings.TrimPrefix(field.Type, "[]") == target {
				return true
			}
		}
	}
	return false
}

func genSwift(outRoot, importModule string, s schema) error {
	domain, version, err := domainAndVersion(s.Namespace)
	if err != nil {
		return err
	}
	outDir := filepath.Join(outRoot, "Generated", domain)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("// Code generated by idlgen. DO NOT EDIT.\n\n")
	buf.WriteString("import Foundation\n\n")
	if importModule = strings.TrimSpace(importModule); importModule != "" {
		fmt.Fprintf(&buf, "import %s\n\n", importModule)
	}
	for _, name := range sortedKeys(s.Enums) {
		ed := s.Enums[name]
		writeSwiftComment(&buf, ed.Comment, "")
		rawType := "UInt32"
		if strings.TrimSpace(ed.Type) == "u8" {
			rawType = "UInt8"
		} else if strings.TrimSpace(ed.Type) == "u16" {
			rawType = "UInt16"
		}
		fmt.Fprintf(&buf, "enum %s: %s, Codable, Sendable {\n", swiftWireType(domain, name), rawType)
		for _, valueName := range sortedKeysInt(ed.Values) {
			writeSwiftComment(&buf, ed.ValueComments[valueName], "  ")
			fmt.Fprintf(&buf, "  case %s = %d\n", lowerCamel(rustTypeName(valueName)), ed.Values[valueName])
		}
		buf.WriteString("}\n\n")
	}
	for _, name := range sortedKeys(s.Messages) {
		md := s.Messages[name]
		writeSwiftComment(&buf, md.Comment, "")
		fmt.Fprintf(&buf, "struct %s: Codable, Sendable {\n", swiftWireType(domain, name))
		for _, field := range md.Fields {
			fieldType, err := swiftFieldType(field.Type, domain)
			if err != nil {
				return fmt.Errorf("swift type %s.%s: %w", name, field.Name, err)
			}
			if field.Optional {
				fieldType += "?"
			}
			fmt.Fprintf(&buf, "  var %s: %s\n", lowerCamel(exportName(field.Name)), fieldType)
		}
		if len(md.Fields) > 0 {
			buf.WriteString("\n  enum CodingKeys: String, CodingKey {\n")
			for _, field := range md.Fields {
				fmt.Fprintf(&buf, "    case %s = \"%s\"\n", lowerCamel(exportName(field.Name)), field.Name)
			}
			buf.WriteString("  }\n")
		}
		buf.WriteString("}\n\n")
	}
	for _, serviceName := range sortedKeys(s.Services) {
		service := s.Services[serviceName]
		serviceType := "Wire" + exportName(domain) + exportName(serviceName)
		for _, methodName := range sortedKeys(service.Methods) {
			method := service.Methods[methodName]
			fmt.Fprintf(
				&buf,
				"let %sTypeID%s: UInt32 = %d\n",
				serviceType,
				exportName(methodName),
				method.TypeID,
			)
		}
		buf.WriteString("\n")
		fmt.Fprintf(&buf, "struct %sClient {\n  let rpc: RPCClient\n\n", serviceType)
		for _, methodName := range sortedKeys(service.Methods) {
			method := service.Methods[methodName]
			methodExport := exportName(methodName)
			methodSwift := lowerCamel(methodExport)
			requestType := swiftWireType(domain, method.Request)
			constant := serviceType + "TypeID" + methodExport
			writeSwiftComment(&buf, method.Comment, "  ")
			switch strings.TrimSpace(method.Kind) {
			case "request":
				responseType := swiftWireType(domain, method.Response)
				fmt.Fprintf(&buf, "  func %s(_ request: %s, timeout: Duration = .seconds(8)) async throws -> %s {\n", methodSwift, requestType, responseType)
				fmt.Fprintf(&buf, "    try await rpc.call(%s, request, timeout: timeout)\n  }\n\n", constant)
			case "notify":
				fmt.Fprintf(&buf, "  func notify%s(_ payload: %s) async throws {\n", methodExport, requestType)
				fmt.Fprintf(&buf, "    try await rpc.notify(%s, payload)\n  }\n\n", constant)
				fmt.Fprintf(&buf, "  func on%s(_ handler: @escaping @Sendable (%s) async -> Void) -> RPCSubscription {\n", methodExport, requestType)
				fmt.Fprintf(&buf, "    rpc.onNotify(%s) { data in\n", constant)
				fmt.Fprintf(&buf, "      guard let value = try? JSONDecoder().decode(%s.self, from: data) else { return }\n", requestType)
				buf.WriteString("      await handler(value)\n    }\n  }\n\n")
			}
		}
		buf.WriteString("}\n\n")

		fmt.Fprintf(&buf, "protocol %sHandler: Sendable {\n", serviceType)
		for _, methodName := range sortedKeys(service.Methods) {
			method := service.Methods[methodName]
			methodSwift := lowerCamel(exportName(methodName))
			requestType := swiftWireType(domain, method.Request)
			if strings.TrimSpace(method.Kind) == "request" {
				fmt.Fprintf(&buf, "  func %s(_ request: %s) async throws -> %s\n", methodSwift, requestType, swiftWireType(domain, method.Response))
			} else {
				fmt.Fprintf(&buf, "  func %s(_ payload: %s) async\n", methodSwift, requestType)
			}
		}
		buf.WriteString("}\n\n")
		fmt.Fprintf(&buf, "func register%s(router: RPCRouter, handler: any %sHandler) async {\n", serviceType, serviceType)
		for _, methodName := range sortedKeys(service.Methods) {
			method := service.Methods[methodName]
			methodExport := exportName(methodName)
			methodSwift := lowerCamel(methodExport)
			requestType := swiftWireType(domain, method.Request)
			constant := serviceType + "TypeID" + methodExport
			fmt.Fprintf(&buf, "  await router.register(%s) { payload in\n", constant)
			fmt.Fprintf(&buf, "    let request = try JSONDecoder().decode(%s.self, from: payload)\n", requestType)
			if strings.TrimSpace(method.Kind) == "request" {
				fmt.Fprintf(&buf, "    let response = try await handler.%s(request)\n", methodSwift)
				buf.WriteString("    return try JSONEncoder().encode(response)\n")
			} else {
				fmt.Fprintf(&buf, "    await handler.%s(request)\n", methodSwift)
				buf.WriteString("    return Data(\"null\".utf8)\n")
			}
			buf.WriteString("  }\n")
		}
		buf.WriteString("}\n\n")
	}
	source := append(bytes.TrimRight(buf.Bytes(), "\n"), '\n')
	return os.WriteFile(filepath.Join(outDir, domain+"_"+version+".gen.swift"), source, 0o644)
}

func swiftFieldType(t, domain string) (string, error) {
	switch t {
	case "string":
		return "String", nil
	case "bool":
		return "Bool", nil
	case "u8":
		return "UInt8", nil
	case "u16":
		return "UInt16", nil
	case "u32":
		return "UInt32", nil
	case "u64":
		return "UInt64", nil
	case "i32":
		return "Int32", nil
	case "i64":
		return "Int64", nil
	case "json":
		return "Data", nil
	case "map<string,string>":
		return "[String: String]", nil
	default:
		if strings.HasPrefix(t, "[]") {
			elem, err := swiftFieldType(strings.TrimPrefix(t, "[]"), domain)
			if err != nil {
				return "", err
			}
			return "[" + elem + "]", nil
		}
		return swiftWireType(domain, t), nil
	}
}

func swiftWireType(domain, name string) string {
	return "Wire" + exportName(domain) + name
}

func rustTypeName(value string) string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '_' || r == '-' })
	var b strings.Builder
	for _, part := range parts {
		if part == "" {
			continue
		}
		lower := strings.ToLower(part)
		b.WriteString(strings.ToUpper(lower[:1]))
		b.WriteString(lower[1:])
	}
	return b.String()
}

func snakeName(value string) string {
	var b strings.Builder
	for i, r := range value {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		if r == '-' || r == ' ' {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func writeRustComment(buf *bytes.Buffer, comment, indent string) {
	writeLineComment(buf, comment, indent, "/// ")
}

func writeSwiftComment(buf *bytes.Buffer, comment, indent string) {
	writeLineComment(buf, comment, indent, "/// ")
}

func writeLineComment(buf *bytes.Buffer, comment, indent, prefix string) {
	for _, line := range strings.Split(strings.TrimSpace(comment), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		buf.WriteString(indent + prefix + strings.TrimSpace(line) + "\n")
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

func versionString() string {
	v := strings.TrimSpace(version)
	c := strings.TrimSpace(commit)
	d := strings.TrimSpace(date)

	if info, ok := debug.ReadBuildInfo(); ok {
		// Prefer module version when -ldflags were not provided.
		if v == "" || v == "dev" || v == "(devel)" {
			if mv := strings.TrimSpace(info.Main.Version); mv != "" && mv != "(devel)" {
				v = mv
			}
		}
		// Best-effort VCS metadata when -ldflags were not provided.
		if c == "" || c == "unknown" {
			if rev := buildSetting(info, "vcs.revision"); rev != "" {
				c = rev
			}
		}
		if d == "" || d == "unknown" {
			if t := buildSetting(info, "vcs.time"); t != "" {
				d = t
			}
		}
	}

	out := v
	if out == "" {
		out = "dev"
	}
	if c != "" && c != "unknown" {
		out += " (" + c + ")"
	}
	if d != "" && d != "unknown" {
		out += " " + d
	}
	return out
}

func buildSetting(info *debug.BuildInfo, key string) string {
	if info == nil {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}
