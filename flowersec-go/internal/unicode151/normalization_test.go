package unicode151

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestNormalizationConformance(t *testing.T) {
	f, err := os.Open("../../../testdata/unicode15_1/NormalizationTest.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	work, scratch := make([]rune, 1024), make([]rune, 1024)
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" || strings.HasPrefix(line, "@") {
			continue
		}
		columns := strings.Split(line, ";")
		var text [5]string
		for i := range text {
			var runes []rune
			for _, s := range strings.Fields(columns[i]) {
				cp, err := strconv.ParseInt(s, 16, 32)
				if err != nil {
					t.Fatal(err)
				}
				runes = append(runes, rune(cp))
			}
			text[i] = string(runes)
		}
		for i, input := range text {
			want := text[1]
			if i >= 3 {
				want = text[3]
			}
			out, ok := Normalize([]byte(input), work, scratch)
			if !ok || string(out) != want {
				t.Fatalf("case %d column %d: %U != %U", count, i, out, []rune(want))
			}
			if IsNFC([]byte(input), work, scratch) != (input == want) {
				t.Fatalf("case %d NFC predicate", count)
			}
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 19074 {
		t.Fatalf("incomplete corpus: %d", count)
	}
}

func TestNormalizationFiniteWorkspace(t *testing.T) {
	work, scratch := make([]rune, 256), make([]rune, 256)
	if IsNFC([]byte{0xff}, work, scratch) || IsNFC([]byte("\U00001c89"), work, scratch) {
		t.Fatal("invalid or future codepoint accepted")
	}
	if _, ok := Normalize([]byte("hello"), work[:1], scratch); ok {
		t.Fatal("undersized reservation accepted")
	}
	if n := testing.AllocsPerRun(100, func() {
		if !IsNFC([]byte("Å 한글"), work, scratch) {
			panic("NFC")
		}
	}); n != 0 {
		t.Fatalf("normalization allocated: %g", n)
	}
}
