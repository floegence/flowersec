package protocolv4

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/unicode151"
	"golang.org/x/net/idna"
)

type idnaWireProperty struct {
	first, last rune
	kind        string
}

func (p *idnaWireProperty) UnmarshalJSON(raw []byte) error {
	var row [3]json.RawMessage
	if err := json.Unmarshal(raw, &row); err != nil {
		return err
	}
	if err := json.Unmarshal(row[0], &p.first); err != nil {
		return err
	}
	if err := json.Unmarshal(row[1], &p.last); err != nil {
		return err
	}
	if len(row[2]) > 0 && row[2][0] == '"' {
		return json.Unmarshal(row[2], &p.kind)
	}
	p.kind = string(row[2])
	return nil
}

type wireIDNA map[string][]idnaWireProperty

var runtimeWireIDNA = sync.OnceValues(func() (wireIDNA, error) {
	var data wireIDNA
	if err := json.Unmarshal([]byte(idnaWirePropertiesJSON), &data); err != nil {
		return nil, err
	}
	for _, rows := range data {
		for i, row := range rows {
			if row.first > row.last || i > 0 && rows[i-1].last >= row.first {
				return nil, CBORFailure("registry_unresolved")
			}
		}
	}
	return data, nil
})

func (r wireIDNA) prop(table string, cp rune) string {
	rows := r[table]
	i := sort.Search(len(rows), func(i int) bool { return rows[i].last >= cp })
	if i < len(rows) && rows[i].first <= cp {
		return rows[i].kind
	}
	return ""
}

// One parser's fixed text scratch covers the maximum decoded A-label. Punycode
// is only an arithmetic codec; all validity, context and Bidi properties below
// come from the pinned registry data, never the host's current Unicode tables.
type wireIDNAWorkspace struct {
	work, scratch [63 * utf8.UTFMax * unicode151.MaxCanonicalDecomposition]rune
}

func (r wireIDNA) contextJ(label []rune, i int) bool {
	if i > 0 && r.prop("ccc", label[i-1]) == "9" {
		return true
	}
	if label[i] == 0x200d {
		return false
	}
	left, right := i-1, i+1
	for left >= 0 && r.prop("joining", label[left]) == "T" {
		left--
	}
	for right < len(label) && r.prop("joining", label[right]) == "T" {
		right++
	}
	if left < 0 || right >= len(label) {
		return false
	}
	l, rj := r.prop("joining", label[left]), r.prop("joining", label[right])
	return (l == "L" || l == "D") && (rj == "R" || rj == "D")
}
func (r wireIDNA) contextO(label []rune, i int) bool {
	cp := label[i]
	switch cp {
	case 0xb7:
		return i > 0 && i+1 < len(label) && label[i-1] == 'l' && label[i+1] == 'l'
	case 0x375:
		return i+1 < len(label) && r.prop("scripts", label[i+1]) == "Greek"
	case 0x5f3, 0x5f4:
		return i > 0 && r.prop("scripts", label[i-1]) == "Hebrew"
	case 0x30fb:
		for _, c := range label {
			s := r.prop("scripts", c)
			if s == "Han" || s == "Hiragana" || s == "Katakana" {
				return true
			}
		}
		return false
	}
	if cp >= 0x660 && cp <= 0x669 || cp >= 0x6f0 && cp <= 0x6f9 {
		for _, c := range label {
			if cp <= 0x669 && c >= 0x6f0 && c <= 0x6f9 || cp >= 0x6f0 && c >= 0x660 && c <= 0x669 {
				return false
			}
		}
		return true
	}
	return false
}
func (r wireIDNA) bidi(label []rune) bool {
	first := r.prop("bidi", label[0])
	rtl := first == "R" || first == "AL"
	if !rtl && first != "L" {
		return false
	}
	last := ""
	arabic, european := false, false
	for _, cp := range label {
		dir := r.prop("bidi", cp)
		switch dir {
		case "ES", "CS", "ET", "ON", "BN", "NSM", "EN":
		case "L":
			if rtl {
				return false
			}
		case "R", "AL", "AN":
			if !rtl {
				return false
			}
		default:
			return false
		}
		if dir != "NSM" {
			last = dir
		}
		arabic = arabic || dir == "AN"
		european = european || dir == "EN"
	}
	if rtl {
		return (last == "R" || last == "AL" || last == "EN" || last == "AN") && !(arabic && european)
	}
	return last == "L" || last == "EN"
}

func wireDNS(value string, workspace *wireIDNAWorkspace) error {
	if len(value) == 0 || len(value) > 253 {
		return CBORFailure("idna_domain_length")
	}
	r, err := runtimeWireIDNA()
	if err != nil {
		return err
	}
	var points [253]rune
	var boundaries [128][2]int
	count, used := 0, 0
	bidi := false
	for name := range strings.SplitSeq(value, ".") {
		if len(name) == 0 || len(name) > 63 || count == len(boundaries) {
			return CBORFailure("idna_label_length")
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return CBORFailure("idna_wire_noncanonical")
			}
		}
		decoded := name
		if strings.HasPrefix(name, "xn--") {
			decoded, err = idna.Punycode.ToUnicode(name)
			if err != nil {
				return CBORFailure("idna_alabel_roundtrip")
			}
			if !strings.ContainsFunc(decoded, func(c rune) bool { return c >= 128 }) {
				return CBORFailure("idna_fake_alabel")
			}
			encoded, err := idna.Punycode.ToASCII(decoded)
			if err != nil || encoded != name {
				return CBORFailure("idna_alabel_roundtrip")
			}
		}
		if !unicode151.IsNFC([]byte(decoded), workspace.work[:], workspace.scratch[:]) {
			return CBORFailure("idna_nfc")
		}
		start := used
		for _, cp := range decoded {
			if used == len(points) {
				return CBORFailure("idna_label_length")
			}
			points[used] = cp
			used++
		}
		label := points[start:used]
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' || len(label) >= 4 && label[2] == '-' && label[3] == '-' {
			return CBORFailure("idna_hyphen")
		}
		if strings.HasPrefix(r.prop("categories", label[0]), "M") {
			return CBORFailure("idna_initial_mark")
		}
		for i, cp := range label {
			kind := r.prop("mapping", cp)
			if kind != "valid" && kind != "deviation" {
				return CBORFailure("idna_validity")
			}
			switch r.prop("classes", cp) {
			case "PVALID":
			case "CONTEXTJ":
				if !r.contextJ(label, i) {
					return CBORFailure("idna_contextj")
				}
			case "CONTEXTO":
				if !r.contextO(label, i) {
					return CBORFailure("idna_contexto")
				}
			default:
				return CBORFailure("idna2008_validity")
			}
			dir := r.prop("bidi", cp)
			bidi = bidi || dir == "R" || dir == "AL" || dir == "AN"
		}
		boundaries[count] = [2]int{start, used}
		count++
	}
	if bidi {
		for _, bound := range boundaries[:count] {
			if !r.bidi(points[bound[0]:bound[1]]) {
				return CBORFailure("idna_bidi")
			}
		}
	}
	return nil
}
