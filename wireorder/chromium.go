package wireorder

import (
	"encoding/binary"
	"math/bits"
	"slices"
	"strings"
)

// rapidhash.h RAPID_SEED and rapid_secret: WTF's string hash from Chromium 134 on.
const (
	rapidSeed    = 0xbdd89aa982704029
	rapidSecret0 = 0x2d358dccaa6c78a5
	rapidSecret1 = 0x8bb84b93962eacc9
	rapidSecret2 = 0x4b33a62ed433d4a3
)

func rapidMum(a, b uint64) (lo, hi uint64) {
	hi, lo = bits.Mul64(a, b)
	return lo, hi
}

func rapidMix(a, b uint64) uint64 {
	lo, hi := rapidMum(a, b)
	return lo ^ hi
}

// blinkHash mirrors HTTPHeaderMap's case-folding rapidhash over UTF-16 units, masked to 24 bits; name must be lower-case ASCII.
func blinkHash(name string) uint32 {
	p := make([]byte, 2*len(name))
	for i := range len(name) {
		p[2*i] = name[i]
	}
	n := uint64(len(p))
	seed := rapidSeed ^ rapidMix(rapidSeed^rapidSecret0, rapidSecret1) ^ n
	r32 := func(o uint64) uint64 { return uint64(binary.LittleEndian.Uint32(p[o:])) }
	r64 := func(o uint64) uint64 { return binary.LittleEndian.Uint64(p[o:]) }
	var a, b uint64
	switch {
	case n <= 16 && n >= 4:
		last := n - 4
		a = r32(0)<<32 | r32(last)
		delta := (n & 24) >> (n >> 3)
		b = r32(delta)<<32 | r32(last-delta)
	case n <= 16 && n > 0:
		a = uint64(p[0]) | uint64(p[1])<<8
	case n > 16:
		i, o := n, uint64(0)
		if i > 48 {
			see1, see2 := seed, seed
			for {
				seed = rapidMix(r64(o)^rapidSecret0, r64(o+8)^seed)
				see1 = rapidMix(r64(o+16)^rapidSecret1, r64(o+24)^see1)
				see2 = rapidMix(r64(o+32)^rapidSecret2, r64(o+40)^see2)
				o += 48
				i -= 48
				if i < 48 {
					break
				}
			}
			seed ^= see1 ^ see2
		}
		if i > 16 {
			seed = rapidMix(r64(o)^rapidSecret2, r64(o+8)^seed^rapidSecret1)
			if i > 32 {
				seed = rapidMix(r64(o+16)^rapidSecret2, r64(o+24)^seed)
			}
		}
		a = r64(o + i - 16)
		b = r64(o + i - 8)
	}
	a ^= rapidSecret1
	b ^= seed
	a, b = rapidMum(a, b)
	h := uint32(rapidMix(a^rapidSecret0^n, b^rapidSecret1) & (1<<24 - 1))
	if h == 0 {
		h = 0x80000000 >> 8
	}
	return h
}

// blinkTable mirrors WTF HashMap: triangular probing, grow at half load, rehash in old bucket order.
type blinkTable struct {
	slots []string
	keys  int
}

func (b *blinkTable) place(t []string, k string) {
	mask := uint32(len(t) - 1)
	i := blinkHash(k) & mask
	for probe := uint32(1); t[i] != ""; probe++ {
		i = (i + probe) & mask
	}
	t[i] = k
}

func (b *blinkTable) rehash(size int) {
	next := make([]string, size)
	for _, k := range b.slots {
		if k != "" {
			b.place(next, k)
		}
	}
	b.slots = next
}

func (b *blinkTable) add(k string) {
	if b.slots == nil {
		b.rehash(8)
	}
	mask := uint32(len(b.slots) - 1)
	i := blinkHash(k) & mask
	for probe := uint32(1); b.slots[i] != ""; probe++ {
		if b.slots[i] == k {
			return
		}
		i = (i + probe) & mask
	}
	b.slots[i] = k
	b.keys++
	if b.keys*2 >= len(b.slots) {
		b.rehash(len(b.slots) * 2)
	}
}

func (b *blinkTable) clone() blinkTable {
	return blinkTable{slots: slices.Clone(b.slots), keys: b.keys}
}

func (b *blinkTable) iterate() []string {
	out := make([]string, 0, b.keys)
	for _, k := range b.slots {
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}

func blinkMap(adds []string) []string {
	var b blinkTable
	for _, k := range adds {
		b.add(k)
	}
	return b.iterate()
}

func chromiumOrder(law *chromiumLaw, r *Request, calls []string) []string {
	page := calls
	switch r.Class {
	case ClassFetch:
		// FetchHeaderList is a case-insensitively sorted std::multimap.
		page = slices.Clone(calls)
		slices.SortStableFunc(page, strings.Compare)
	case ClassXHR:
		page = blinkMap(calls)
	}
	adds := slices.Clone(page)
	for _, name := range law.BlinkSetOrder {
		if name == "user-agent" || slices.Contains(r.Added.ClientHints, name) {
			adds = append(adds, name)
		}
	}
	block := blinkMap(adds)
	out := make([]string, 0, len(block)+len(law.NetworkAfter)+len(law.NetworkTail)+5)
	if !r.HTTP2 {
		out = append(out, law.HTTP1Prefix...)
	}
	if r.Added.Body {
		out = append(out, "content-length")
	}
	out = append(out, block...)
	if !slices.Contains(calls, "accept") {
		out = append(out, "accept")
	}
	for _, name := range law.NetworkAfter {
		if r.Added.present(name) {
			out = append(out, name)
		}
	}
	for _, name := range law.NetworkTail {
		if r.Added.present(name) && !slices.Contains(block, name) {
			out = append(out, name)
		}
	}
	if r.HTTP2 && r.Added.Priority {
		out = append(out, "priority")
	}
	return out
}
