package protocolv4

// Test-only Unicode 15.1 IDNA reference. Mapping, contextual and Bidi
// properties come from pinned tables, not the host's Unicode or URL libraries.
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

type idnaProperty struct {
	first, last rune
	kind        string
	mapped      []rune
}

func (p *idnaProperty) UnmarshalJSON(raw []byte) error {
	var row []json.RawMessage
	if err := json.Unmarshal(raw, &row); err != nil {
		return err
	}
	if len(row) < 3 || len(row) > 4 {
		return cborRefError("idna_table")
	}
	if err := json.Unmarshal(row[0], &p.first); err != nil {
		return err
	}
	if err := json.Unmarshal(row[1], &p.last); err != nil {
		return err
	}
	if len(row[2]) > 0 && row[2][0] == '"' {
		if err := json.Unmarshal(row[2], &p.kind); err != nil {
			return err
		}
	} else {
		var n uint64
		if err := json.Unmarshal(row[2], &n); err != nil {
			return err
		}
		p.kind = strconv.FormatUint(n, 10)
	}
	if len(row) == 4 {
		return json.Unmarshal(row[3], &p.mapped)
	}
	return nil
}

type idnaReference struct {
	nfc     *nfcReference
	tables  map[string][]idnaProperty
	sources map[string]struct{ SHA256 string }
}

func newIDNAReference(t testing.TB, reference *cborReference) *idnaReference {
	t.Helper()
	pin := reference.registry.Unicode.IDNAData
	if pin.Path != "testdata/unicode15_1/idna_generated.json" {
		t.Fatal("unexpected IDNA table path")
	}
	raw, err := os.ReadFile(filepath.Join("../../..", pin.Path))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != pin.SHA256 {
		t.Fatal("IDNA table hash drift")
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	var version, nfcHash string
	var revision int
	if json.Unmarshal(data["unicode_version"], &version) != nil || version != "15.1.0" || json.Unmarshal(data["uts46_revision"], &revision) != nil || revision != 31 || json.Unmarshal(data["nfc_data_sha256"], &nfcHash) != nil || nfcHash != reference.registry.Unicode.NFCData.SHA256 {
		t.Fatal("IDNA/NFC version drift")
	}
	r := &idnaReference{nfc: reference.unicode, tables: map[string][]idnaProperty{}}
	if err := json.Unmarshal(data["sources"], &r.sources); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mapping", "classes", "categories", "bidi", "ccc", "joining", "scripts"} {
		var rows []idnaProperty
		if err := json.Unmarshal(data[name], &rows); err != nil {
			t.Fatal(err)
		}
		for i, row := range rows {
			if row.first > row.last || (i > 0 && rows[i-1].last >= row.first) {
				t.Fatal("unordered IDNA table")
			}
		}
		r.tables[name] = rows
	}
	return r
}

func (r *idnaReference) lookup(table string, cp rune) idnaProperty {
	rows := r.tables[table]
	i := sort.Search(len(rows), func(i int) bool { return rows[i].last >= cp })
	if i < len(rows) && rows[i].first <= cp {
		return rows[i]
	}
	return idnaProperty{}
}

func (r *idnaReference) prop(table string, cp rune) string { return r.lookup(table, cp).kind }

const punyMax uint64 = 0x7fffffff

func punyThreshold(k, bias uint64) uint64 {
	if k <= bias+1 {
		return 1
	}
	if k >= bias+26 {
		return 26
	}
	return k - bias
}

func punyAdapt(delta, count uint64, first bool) uint64 {
	if first {
		delta /= 700
	} else {
		delta /= 2
	}
	delta += delta / count
	k := uint64(0)
	for delta > 455 {
		delta /= 35
		k += 36
	}
	return k + 36*delta/(delta+38)
}

func punyDigit(n uint64) byte {
	if n < 26 {
		return byte(n) + 'a'
	}
	return byte(n-26) + '0'
}

func punyEncode(input []rune) (string, error) {
	out := []byte{}
	for _, cp := range input {
		if !utf8.ValidRune(cp) {
			return "", cborRefError("punycode_scalar")
		}
		if cp < 128 {
			out = append(out, byte(cp))
		}
	}
	handled, basic := uint64(len(out)), uint64(len(out))
	n, delta, bias := uint64(128), uint64(0), uint64(72)
	if basic > 0 {
		out = append(out, '-')
	}
	for handled < uint64(len(input)) {
		next := uint64(0x110000)
		for _, cp := range input {
			if uint64(cp) >= n && uint64(cp) < next {
				next = uint64(cp)
			}
		}
		if next-n > (punyMax-delta)/(handled+1) {
			return "", cborRefError("punycode_overflow")
		}
		delta += (next - n) * (handled + 1)
		n = next
		for _, cp := range input {
			if uint64(cp) < n {
				if delta == punyMax {
					return "", cborRefError("punycode_overflow")
				}
				delta++
			}
			if uint64(cp) != n {
				continue
			}
			q := delta
			for k := uint64(36); ; k += 36 {
				threshold := punyThreshold(k, bias)
				if q < threshold {
					break
				}
				out = append(out, punyDigit(threshold+(q-threshold)%(36-threshold)))
				q = (q - threshold) / (36 - threshold)
			}
			out = append(out, punyDigit(q))
			bias = punyAdapt(delta, handled+1, handled == basic)
			delta = 0
			handled++
		}
		if delta == punyMax {
			return "", cborRefError("punycode_overflow")
		}
		delta++
		n++
	}
	return string(out), nil
}

func punyDecode(input string) ([]rune, error) {
	for _, b := range []byte(input) {
		if b >= 128 {
			return nil, cborRefError("punycode_ascii")
		}
	}
	out := []rune{}
	index := 0
	if dash := strings.LastIndexByte(input, '-'); dash > 0 {
		out = []rune(input[:dash])
		index = dash + 1
	}
	n, i, bias := uint64(128), uint64(0), uint64(72)
	for index < len(input) {
		old, weight := i, uint64(1)
		for k := uint64(36); ; k += 36 {
			if index == len(input) {
				return nil, cborRefError("punycode_truncated")
			}
			b := input[index]
			index++
			var digit uint64
			switch {
			case b >= 'a' && b <= 'z':
				digit = uint64(b - 'a')
			case b >= 'A' && b <= 'Z':
				digit = uint64(b - 'A')
			case b >= '0' && b <= '9':
				digit = uint64(b-'0') + 26
			default:
				return nil, cborRefError("punycode_digit")
			}
			if digit > (punyMax-i)/weight {
				return nil, cborRefError("punycode_overflow")
			}
			i += digit * weight
			threshold := punyThreshold(k, bias)
			if digit < threshold {
				break
			}
			if weight > punyMax/(36-threshold) {
				return nil, cborRefError("punycode_overflow")
			}
			weight *= 36 - threshold
		}
		count := uint64(len(out)) + 1
		bias = punyAdapt(i-old, count, old == 0)
		if i/count > punyMax-n {
			return nil, cborRefError("punycode_overflow")
		}
		n += i / count
		i %= count
		if n > 0x10ffff || !utf8.ValidRune(rune(n)) {
			return nil, cborRefError("punycode_scalar")
		}
		out = append(out, 0)
		copy(out[int(i)+1:], out[int(i):])
		out[int(i)] = rune(n)
		i++
	}
	return out, nil
}

func (r *idnaReference) contextJ(label []rune, index int) bool {
	if index > 0 && r.prop("ccc", label[index-1]) == "9" {
		return true
	}
	if label[index] == 0x200d {
		return false
	}
	left, right := index-1, index+1
	for left >= 0 && r.prop("joining", label[left]) == "T" {
		left--
	}
	for right < len(label) && r.prop("joining", label[right]) == "T" {
		right++
	}
	return left >= 0 && right < len(label) && slices.Contains([]string{"L", "D"}, r.prop("joining", label[left])) && slices.Contains([]string{"R", "D"}, r.prop("joining", label[right]))
}

func (r *idnaReference) contextO(label []rune, i int) bool {
	cp := label[i]
	switch cp {
	case 0xb7:
		return i > 0 && i+1 < len(label) && label[i-1] == 'l' && label[i+1] == 'l'
	case 0x375:
		return i+1 < len(label) && r.prop("scripts", label[i+1]) == "Greek"
	case 0x5f3, 0x5f4:
		return i > 0 && r.prop("scripts", label[i-1]) == "Hebrew"
	case 0x30fb:
		for _, v := range label {
			if slices.Contains([]string{"Hiragana", "Katakana", "Han"}, r.prop("scripts", v)) {
				return true
			}
		}
		return false
	}
	if cp >= 0x660 && cp <= 0x669 || cp >= 0x6f0 && cp <= 0x6f9 {
		for _, v := range label {
			if cp <= 0x669 && v >= 0x6f0 && v <= 0x6f9 || cp >= 0x6f0 && v >= 0x660 && v <= 0x669 {
				return false
			}
		}
		return true
	}
	return false
}

func (r *idnaReference) bidi(label []rune) error {
	first := r.prop("bidi", label[0])
	rtl := first == "R" || first == "AL"
	if !rtl && first != "L" {
		return cborRefError("idna_bidi_start")
	}
	allowed, ends := []string{"L", "EN", "ES", "CS", "ET", "ON", "BN", "NSM"}, []string{"L", "EN"}
	if rtl {
		allowed, ends = []string{"R", "AL", "AN", "EN", "ES", "CS", "ET", "ON", "BN", "NSM"}, []string{"R", "AL", "EN", "AN"}
	}
	last, arabic, european := "", false, false
	for _, cp := range label {
		direction := r.prop("bidi", cp)
		if !slices.Contains(allowed, direction) {
			return cborRefError("idna_bidi_character")
		}
		if direction != "NSM" {
			last = direction
		}
		arabic, european = arabic || direction == "AN", european || direction == "EN"
	}
	if !slices.Contains(ends, last) {
		return cborRefError("idna_bidi_end")
	}
	if rtl && arabic && european {
		return cborRefError("idna_bidi_digits")
	}
	return nil
}

func (r *idnaReference) validUTSLabel(label []rune) error {
	if len(label) == 0 {
		return cborRefError("idna_empty_label")
	}
	if r.nfc.normalize(string(label)) != string(label) {
		return cborRefError("idna_nfc")
	}
	if label[0] == '-' || label[len(label)-1] == '-' || len(label) >= 4 && label[2] == '-' && label[3] == '-' {
		return cborRefError("idna_hyphen")
	}
	if strings.HasPrefix(r.prop("categories", label[0]), "M") {
		return cborRefError("idna_initial_mark")
	}
	for i, cp := range label {
		kind := r.prop("mapping", cp)
		if kind != "valid" && kind != "deviation" {
			return cborRefError("idna_validity")
		}
		if (cp == 0x200c || cp == 0x200d) && !r.contextJ(label, i) {
			return cborRefError("idna_contextj")
		}
	}
	return nil
}

func (r *idnaReference) process(input string) (string, [][]rune, bool, error) {
	if !utf8.ValidString(input) {
		return "", nil, false, cborRefError("idna_surrogate")
	}
	mapped := []rune{}
	for _, cp := range input {
		row := r.lookup("mapping", cp)
		switch row.kind {
		case "valid", "deviation", "disallowed", "disallowed_STD3_valid", "disallowed_STD3_mapped", "":
			// UTS46 r31 performs validity checks after NFC composition.
			mapped = append(mapped, cp)
		case "mapped":
			mapped = append(mapped, row.mapped...)
		case "ignored":
		default:
			return "", nil, false, cborRefError("idna_mapping")
		}
	}
	names := strings.Split(r.nfc.normalize(string(mapped)), ".")
	trailing := names[len(names)-1] == ""
	if trailing {
		names = names[:len(names)-1]
	}
	if len(names) == 0 {
		return "", nil, trailing, cborRefError("idna_empty_domain")
	}
	labels := make([][]rune, 0, len(names))
	bidiDomain := false
	for _, name := range names {
		label := []rune(name)
		if strings.HasPrefix(name, "xn--") {
			if len(name) > 63 {
				return "", nil, trailing, cborRefError("idna_label_length")
			}
			var err error
			label, err = punyDecode(name[4:])
			if err != nil {
				return "", nil, trailing, err
			}
			if !slices.ContainsFunc(label, func(cp rune) bool { return cp >= 128 }) {
				return "", nil, trailing, cborRefError("idna_fake_alabel")
			}
			encoded, err := punyEncode(label)
			if err != nil || "xn--"+encoded != name {
				return "", nil, trailing, cborRefError("idna_alabel_roundtrip")
			}
		}
		if err := r.validUTSLabel(label); err != nil {
			return "", nil, trailing, err
		}
		for _, cp := range label {
			bidiDomain = bidiDomain || slices.Contains([]string{"R", "AL", "AN"}, r.prop("bidi", cp))
		}
		labels = append(labels, label)
	}
	ascii := []string{}
	for _, label := range labels {
		if bidiDomain {
			if err := r.bidi(label); err != nil {
				return "", nil, trailing, err
			}
		}
		text := string(label)
		if slices.ContainsFunc(label, func(cp rune) bool { return cp >= 128 }) {
			encoded, err := punyEncode(label)
			if err != nil {
				return "", nil, trailing, err
			}
			text = "xn--" + encoded
		}
		if len(text) < 1 || len(text) > 63 {
			return "", nil, trailing, cborRefError("idna_label_length")
		}
		ascii = append(ascii, text)
	}
	result := strings.Join(ascii, ".")
	if len(result) > 253 {
		return "", nil, trailing, cborRefError("idna_domain_length")
	}
	if trailing {
		result += "."
	}
	return result, labels, trailing, nil
}

func (r *idnaReference) issuerDNS(input string) (string, error) {
	if !utf8.ValidString(input) {
		return "", cborRefError("idna_surrogate")
	}
	for _, cp := range input {
		if !r.nfc.assigned(cp) {
			return "", cborRefError("idna_unassigned")
		}
	}
	ascii, labels, trailing, err := r.process(input)
	if err != nil {
		return "", err
	}
	if trailing {
		return "", cborRefError("idna_trailing_dot")
	}
	for _, label := range labels {
		for i, cp := range label {
			if !r.nfc.assigned(cp) {
				return "", cborRefError("idna_unassigned")
			}
			kind := r.prop("classes", cp)
			if kind != "PVALID" && !(kind == "CONTEXTJ" && r.contextJ(label, i)) && !(kind == "CONTEXTO" && r.contextO(label, i)) {
				return "", cborRefError("idna2008_validity")
			}
		}
	}
	return ascii, nil
}

func (r *idnaReference) wireDNS(input string) error {
	if input == "" || strings.ContainsFunc(input, func(cp rune) bool { return cp >= 128 }) {
		return cborRefError("idna_wire_ascii")
	}
	ascii, err := r.issuerDNS(input)
	if err != nil {
		return err
	}
	if input != ascii {
		return cborRefError("idna_wire_noncanonical")
	}
	return nil
}

var idnaEscapes = regexp.MustCompile(`\\u([0-9A-Fa-f]{4})|\\x\{([0-9A-Fa-f]+)\}`)

func idnaUnescape(input string) string {
	points, offset := []rune{}, 0
	for _, match := range idnaEscapes.FindAllStringSubmatchIndex(input, -1) {
		points = append(points, []rune(input[offset:match[0]])...)
		start, end := match[2], match[3]
		if start < 0 {
			start, end = match[4], match[5]
		}
		n, err := strconv.ParseUint(input[start:end], 16, 32)
		if err != nil || n > 0x10ffff {
			points = append(points, utf8.RuneError)
		} else {
			points = append(points, rune(n))
		}
		offset = match[1]
	}
	points = append(points, []rune(input[offset:])...)
	out := []rune{}
	for i := 0; i < len(points); i++ {
		if points[i] >= 0xd800 && points[i] <= 0xdbff && i+1 < len(points) && points[i+1] >= 0xdc00 && points[i+1] <= 0xdfff {
			out = append(out, utf16.DecodeRune(points[i], points[i+1]))
			i++
		} else {
			out = append(out, points[i])
		}
	}
	return string(out)
}

// v4.cbor.idna_conformance
func TestCBORIDNAReferenceConformance(t *testing.T) {
	r := newIDNAReference(t, newCBORReference(t))
	raw, err := os.ReadFile("../../../testdata/unicode15_1/IdnaTestV2.txt")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != r.sources["IdnaTestV2.txt"].SHA256 {
		t.Fatal("IDNA conformance corpus hash drift")
	}
	cases, failures := 0, 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		cols := strings.Split(line, ";")
		if len(cols) < 5 {
			t.Fatal("malformed IDNA corpus row")
		}
		for i := range cols {
			cols[i] = idnaUnescape(strings.TrimSpace(cols[i]))
		}
		input, expected, status := cols[0], cols[3], cols[4]
		if expected == "" {
			expected = cols[1]
			if expected == "" {
				expected = input
			}
		}
		if status == "" {
			status = cols[2]
			if status == "" {
				status = "[]"
			}
		}
		actual, _, _, err := r.process(input)
		if status == "[]" && (err != nil || actual != expected) || status != "[]" && err == nil {
			failures++
			if failures <= 20 {
				t.Errorf("case %d input %q: got %q/%v, want %q/status %s", cases, input, actual, err, expected, status)
			}
		}
		cases++
	}
	if cases != 6265 || failures != 0 {
		t.Fatalf("%d/%d IDNA conformance failures", failures, cases)
	}
	t.Logf("all %d official Unicode 15.1 nontransitional ToASCII cases passed", cases)
}

// v4.cbor.idna_context
func TestCBORIDNAReferenceContext(t *testing.T) {
	r := newIDNAReference(t, newCBORReference(t))
	for _, input := range []string{
		"\u0375\u03b1.example", "\u05d0\u05f3.example", "\u05d0\u05f4.example",
		"\u30ab\u30fb\u30ca.example", "\u30fb\u4e00.example", "\u0627\u0660\u0661.example", "\u0627\u06f0\u06f1.example",
		"\u0915\u094d\u200d\u0937.example", "\u0915\u094d\u200c\u0937.example", "a1.\u0645\u062b\u0627\u0644",
	} {
		ascii, err := r.issuerDNS(input)
		if err != nil {
			t.Fatalf("valid contextual label %q: %v", input, err)
		}
		if err := r.wireDNS(ascii); err != nil {
			t.Fatalf("valid contextual A-label %q: %v", ascii, err)
		}
	}
	for _, input := range []string{
		"\u0375a.example", "\u05f3\u05d0.example", "\u05f4\u05d0.example", "a\u30fbb.example", "\u0627\u0660\u06f0.example",
		"\u0915\u200d\u0937.example", "\u0628\u200c\u0301a.example", "a\u200c\u0628.example", "1.\u0645\u062b\u0627\u0644",
		"\U0001f600.example", "xn--e28h.example", "xn--abc-.example", "xn--a!", "a_b.example", "\U0001cc00.example",
	} {
		if _, err := r.issuerDNS(input); err == nil {
			t.Fatalf("invalid contextual/IDNA2008 label accepted: %q", input)
		}
	}
	// UTS46 permits this symbol, while the additional IDNA2008 predicate does
	// not. Official UTS conformance alone cannot establish Flowersec DNS rules.
	if ascii, _, _, err := r.process("\U0001f600.example"); err != nil || ascii != "xn--e28h.example" {
		t.Fatalf("UTS/IDNA2008 boundary lost: %q/%v", ascii, err)
	}
}
