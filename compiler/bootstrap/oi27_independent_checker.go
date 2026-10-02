// OI-27 release-only independent checker for the bounded M11/M14 bootstrap subset.
// It deliberately shares no Python implementation code with the primary seed.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const (
	cidSize        = 32
	chunkLen       = 1024
	blockLen       = 64
	flagChunkStart = 1
	flagChunkEnd   = 2
	flagParent     = 4
	flagRoot       = 8
)

var iv = [8]uint32{0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19}
var perm = [16]int{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

type b3Output struct {
	cv       [8]uint32
	block    [16]uint32
	counter  uint64
	blockLen uint32
	flags    uint32
}

func rotr(x uint32, n uint) uint32 { return x>>n | x<<(32-n) }
func g(s *[16]uint32, a, b, c, d int, mx, my uint32) {
	s[a] = s[a] + s[b] + mx
	s[d] = rotr(s[d]^s[a], 16)
	s[c] += s[d]
	s[b] = rotr(s[b]^s[c], 12)
	s[a] = s[a] + s[b] + my
	s[d] = rotr(s[d]^s[a], 8)
	s[c] += s[d]
	s[b] = rotr(s[b]^s[c], 7)
}
func compress(cv [8]uint32, m [16]uint32, counter uint64, n uint32, flags uint32) [16]uint32 {
	var s [16]uint32
	copy(s[:8], cv[:])
	copy(s[8:12], iv[:4])
	s[12] = uint32(counter)
	s[13] = uint32(counter >> 32)
	s[14] = n
	s[15] = flags
	sched := m
	for round := 0; round < 7; round++ {
		g(&s, 0, 4, 8, 12, sched[0], sched[1])
		g(&s, 1, 5, 9, 13, sched[2], sched[3])
		g(&s, 2, 6, 10, 14, sched[4], sched[5])
		g(&s, 3, 7, 11, 15, sched[6], sched[7])
		g(&s, 0, 5, 10, 15, sched[8], sched[9])
		g(&s, 1, 6, 11, 12, sched[10], sched[11])
		g(&s, 2, 7, 8, 13, sched[12], sched[13])
		g(&s, 3, 4, 9, 14, sched[14], sched[15])
		var next [16]uint32
		for i, p := range perm {
			next[i] = sched[p]
		}
		sched = next
	}
	for i := 0; i < 8; i++ {
		s[i] ^= s[i+8]
		s[i+8] ^= cv[i]
	}
	return s
}
func words(block []byte) [16]uint32 {
	var w [16]uint32
	var tmp [64]byte
	copy(tmp[:], block)
	for i := 0; i < 16; i++ {
		w[i] = binary.LittleEndian.Uint32(tmp[i*4:])
	}
	return w
}
func (o b3Output) chaining() [8]uint32 {
	x := compress(o.cv, o.block, o.counter, o.blockLen, o.flags)
	var out [8]uint32
	copy(out[:], x[:8])
	return out
}
func parentOutput(left, right [8]uint32) b3Output {
	var b [16]uint32
	copy(b[:8], left[:])
	copy(b[8:], right[:])
	return b3Output{iv, b, 0, 64, flagParent}
}
func chunkOutput(data []byte, counter uint64) b3Output {
	cv := iv
	blocks := (len(data) + 63) / 64
	if blocks == 0 {
		blocks = 1
	}
	for i := 0; i < blocks; i++ {
		start := i * 64
		end := start + 64
		if end > len(data) {
			end = len(data)
		}
		b := data[start:end]
		flags := uint32(0)
		if i == 0 {
			flags |= flagChunkStart
		}
		if i == blocks-1 {
			return b3Output{cv, words(b), counter, uint32(len(b)), flags | flagChunkEnd}
		}
		x := compress(cv, words(b), counter, 64, flags)
		copy(cv[:], x[:8])
	}
	panic("unreachable")
}
func blake3sum(data []byte) [32]byte {
	chunks := (len(data) + chunkLen - 1) / chunkLen
	if chunks == 0 {
		chunks = 1
	}
	var stack [][8]uint32
	for i := 0; i < chunks-1; i++ {
		out := chunkOutput(data[i*chunkLen:(i+1)*chunkLen], uint64(i))
		cv := out.chaining()
		total := i + 1
		for total&1 == 0 {
			left := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			cv = parentOutput(left, cv).chaining()
			total >>= 1
		}
		stack = append(stack, cv)
	}
	start := (chunks - 1) * chunkLen
	out := chunkOutput(data[start:], uint64(chunks-1))
	for i := len(stack) - 1; i >= 0; i-- {
		out = parentOutput(stack[i], out.chaining())
	}
	x := compress(out.cv, out.block, 0, out.blockLen, out.flags|flagRoot)
	var digest [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(digest[i*4:], x[i])
	}
	return digest
}

// ---- independent canonical container / hash checker ----
type cursor struct {
	b []byte
	p int
}

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || c.p+n > len(c.b) {
		return nil, errors.New("truncated")
	}
	out := c.b[c.p : c.p+n]
	c.p += n
	return out, nil
}
func (c *cursor) uleb() (uint64, error) {
	var v uint64
	var shift uint
	start := c.p
	for {
		if c.p >= len(c.b) || shift >= 64 {
			return 0, errors.New("bad uleb")
		}
		q := c.b[c.p]
		c.p++
		v |= uint64(q&0x7f) << shift
		if q&0x80 == 0 {
			if c.p-start > 1 && q == 0 {
				return 0, errors.New("noncanonical uleb")
			}
			return v, nil
		}
		shift += 7
	}
}
func encULEB(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			return out
		}
	}
}

type object struct {
	cid        [32]byte
	kind       uint64
	schema     uint64
	refs       [][32]byte
	body       []byte
	record     []byte
	offset     int
	payloadLen int
}
type store struct {
	raw      []byte
	root     [32]byte
	objects  []*object
	byCID    map[[32]byte]*object
	metadata [][]byte
}

func lessCID(a, b [32]byte) bool { return bytes.Compare(a[:], b[:]) < 0 }
func semanticCID(o *object) [32]byte {
	var x []byte
	x = append(x, []byte("XAX-SEM-1")...)
	x = append(x, encULEB(o.kind)...)
	x = append(x, encULEB(o.schema)...)
	x = append(x, encULEB(uint64(len(o.refs)))...)
	for _, r := range o.refs {
		x = append(x, r[:]...)
	}
	x = append(x, encULEB(uint64(len(o.body)))...)
	x = append(x, o.body...)
	return blake3sum(x)
}
func parseStore(data []byte) (*store, error) {
	c := cursor{b: data}
	magic, e := c.take(4)
	if e != nil || !bytes.Equal(magic, []byte{'X', 'A', 'X', 0}) {
		return nil, errors.New("bad magic")
	}
	maj, e := c.uleb()
	if e != nil || maj != 1 {
		return nil, errors.New("bad major")
	}
	_, e = c.uleb()
	if e != nil {
		return nil, e
	}
	suite, e := c.uleb()
	if e != nil || suite != 1 {
		return nil, errors.New("bad suite")
	}
	rb, e := c.take(32)
	if e != nil {
		return nil, e
	}
	var root [32]byte
	copy(root[:], rb)
	n, e := c.uleb()
	if e != nil {
		return nil, e
	}
	mn, e := c.uleb()
	if e != nil {
		return nil, e
	}
	flags, e := c.uleb()
	if e != nil || flags != 0 {
		return nil, errors.New("unsupported flags")
	}
	s := &store{raw: data, root: root, byCID: map[[32]byte]*object{}}
	var prev [32]byte
	havePrev := false
	for i := uint64(0); i < n; i++ {
		off := c.p
		plen, e := c.uleb()
		if e != nil {
			return nil, e
		}
		pfx := c.p - off
		payload, e := c.take(int(plen))
		if e != nil {
			return nil, e
		}
		pc := cursor{b: payload}
		cb, e := pc.take(32)
		if e != nil {
			return nil, e
		}
		var cid [32]byte
		copy(cid[:], cb)
		kind, e := pc.uleb()
		if e != nil {
			return nil, e
		}
		schema, e := pc.uleb()
		if e != nil || schema != 1 {
			return nil, errors.New("bad schema")
		}
		rn, e := pc.uleb()
		if e != nil {
			return nil, e
		}
		refs := make([][32]byte, rn)
		for j := range refs {
			b, e := pc.take(32)
			if e != nil {
				return nil, e
			}
			copy(refs[j][:], b)
			if j > 0 && !lessCID(refs[j-1], refs[j]) {
				return nil, errors.New("references not strict sorted")
			}
		}
		bl, e := pc.uleb()
		if e != nil {
			return nil, e
		}
		body, e := pc.take(int(bl))
		if e != nil || pc.p != len(pc.b) {
			return nil, errors.New("bad object length")
		}
		o := &object{cid: cid, kind: kind, schema: schema, refs: refs, body: append([]byte(nil), body...), record: append([]byte(nil), data[off:c.p]...), offset: off, payloadLen: int(plen)}
		if semanticCID(o) != cid {
			return nil, errors.New("object cid mismatch")
		}
		if havePrev && !lessCID(prev, cid) {
			return nil, errors.New("records not strict sorted")
		}
		prev = cid
		havePrev = true
		s.objects = append(s.objects, o)
		s.byCID[cid] = o
		_ = pfx
	}
	var prevMeta []byte
	for i := uint64(0); i < mn; i++ {
		off := c.p
		plen, e := c.uleb()
		if e != nil {
			return nil, e
		}
		_, e = c.take(int(plen))
		if e != nil {
			return nil, e
		}
		rec := append([]byte(nil), data[off:c.p]...)
		if prevMeta != nil && bytes.Compare(prevMeta, rec) >= 0 {
			return nil, errors.New("metadata not strict sorted")
		}
		prevMeta = rec
		s.metadata = append(s.metadata, rec)
	}
	il, e := c.uleb()
	if e != nil {
		return nil, e
	}
	idx, e := c.take(int(il))
	if e != nil {
		return nil, e
	}
	digestEnd := c.p
	stored, e := c.take(32)
	if e != nil {
		return nil, e
	}
	trail, e := c.take(4)
	if e != nil || !bytes.Equal(trail, []byte("XAXE")) || c.p != len(data) {
		return nil, errors.New("bad trailer")
	}
	d := blake3sum(data[:digestEnd])
	if !bytes.Equal(stored, d[:]) {
		return nil, errors.New("store digest mismatch")
	}
	ic := cursor{b: idx}
	for _, o := range s.objects {
		cb, e := ic.take(32)
		if e != nil || !bytes.Equal(cb, o.cid[:]) {
			return nil, errors.New("index cid mismatch")
		}
		off, e := ic.uleb()
		if e != nil || int(off) != o.offset {
			return nil, errors.New("index offset mismatch")
		}
		ln, e := ic.uleb()
		if e != nil || int(ln) != o.payloadLen {
			return nil, errors.New("index length mismatch")
		}
	}
	if ic.p != len(ic.b) {
		return nil, errors.New("index trailing bytes")
	}
	if s.byCID[s.root] == nil {
		return nil, errors.New("root missing")
	}
	for _, o := range s.objects {
		for _, r := range o.refs {
			if s.byCID[r] == nil {
				return nil, errors.New("reference missing")
			}
		}
	}
	seen := map[[32]byte]bool{}
	active := map[[32]byte]bool{}
	var walk func([32]byte) error
	walk = func(id [32]byte) error {
		if active[id] {
			return errors.New("cid cycle")
		}
		if seen[id] {
			return nil
		}
		active[id] = true
		for _, r := range s.byCID[id].refs {
			if e := walk(r); e != nil {
				return e
			}
		}
		delete(active, id)
		seen[id] = true
		return nil
	}
	if e := walk(s.root); e != nil {
		return nil, e
	}
	if len(seen) != len(s.objects) {
		return nil, errors.New("unreachable object")
	}
	return s, nil
}
func emitStore(s *store) []byte {
	var out []byte
	out = append(out, 'X', 'A', 'X', 0)
	out = append(out, encULEB(1)...)
	out = append(out, encULEB(0)...)
	out = append(out, encULEB(1)...)
	out = append(out, s.root[:]...)
	out = append(out, encULEB(uint64(len(s.objects)))...)
	out = append(out, encULEB(uint64(len(s.metadata)))...)
	out = append(out, 0)
	type ix struct {
		id      [32]byte
		off, ln int
	}
	var ids []ix
	for _, o := range s.objects {
		off := len(out)
		out = append(out, o.record...)
		ids = append(ids, ix{o.cid, off, o.payloadLen})
	}
	for _, m := range s.metadata {
		out = append(out, m...)
	}
	var idx []byte
	for _, x := range ids {
		idx = append(idx, x.id[:]...)
		idx = append(idx, encULEB(uint64(x.off))...)
		idx = append(idx, encULEB(uint64(x.ln))...)
	}
	out = append(out, encULEB(uint64(len(idx)))...)
	out = append(out, idx...)
	d := blake3sum(out)
	out = append(out, d[:]...)
	out = append(out, 'X', 'A', 'X', 'E')
	return out
}

// ---- exact semantic verifier for the bounded M11/M14 subset ----
type value struct{ tag, block, index, result uint64 }
type parsedBlock struct {
	params  [][32]byte
	nodes   []parsedNode
	term    uint64
	returns []value
	cond    *value
	edges   []edge
}
type parsedNode struct {
	op       uint64
	entity   *[32]byte
	operands []value
	results  [][32]byte
}
type edge struct {
	target uint64
	args   []value
}
type parsedGraph struct {
	entry  uint64
	blocks []parsedBlock
}

func refAt(o *object, i uint64) ([32]byte, error) {
	if i >= uint64(len(o.refs)) {
		return [32]byte{}, errors.New("reference index out of range")
	}
	return o.refs[i], nil
}
func readValue(c *cursor) (value, error) {
	t, e := c.uleb()
	if e != nil || t > 1 {
		return value{}, errors.New("bad value tag")
	}
	b, e := c.uleb()
	if e != nil {
		return value{}, e
	}
	i, e := c.uleb()
	if e != nil {
		return value{}, e
	}
	v := value{tag: t, block: b, index: i}
	if t == 1 {
		r, e := c.uleb()
		if e != nil {
			return value{}, e
		}
		v.result = r
	}
	return v, nil
}
func parseGraph(o *object) (parsedGraph, error) {
	c := cursor{b: o.body}
	bc, e := c.uleb()
	if e != nil || bc == 0 {
		return parsedGraph{}, errors.New("bad block count")
	}
	entry, e := c.uleb()
	if e != nil || entry >= bc {
		return parsedGraph{}, errors.New("bad entry")
	}
	g := parsedGraph{entry: entry, blocks: make([]parsedBlock, bc)}
	used := map[[32]byte]bool{}
	for bi := range g.blocks {
		pc, e := c.uleb()
		if e != nil {
			return g, e
		}
		for j := uint64(0); j < pc; j++ {
			ri, e := c.uleb()
			if e != nil {
				return g, e
			}
			r, e := refAt(o, ri)
			if e != nil {
				return g, e
			}
			g.blocks[bi].params = append(g.blocks[bi].params, r)
			used[r] = true
		}
		nc, e := c.uleb()
		if e != nil {
			return g, e
		}
		for j := uint64(0); j < nc; j++ {
			op, e := c.uleb()
			if e != nil {
				return g, e
			}
			if op != 1 && op != 3 && op != 5 && op != 35 && op != 36 && op != 37 {
				return g, fmt.Errorf("unsupported op %d", op)
			}
			n := parsedNode{op: op}
			if op == 5 {
				ri, e := c.uleb()
				if e != nil {
					return g, e
				}
				r, e := refAt(o, ri)
				if e != nil {
					return g, e
				}
				n.entity = &r
				used[r] = true
			}
			oc, e := c.uleb()
			if e != nil {
				return g, e
			}
			for k := uint64(0); k < oc; k++ {
				v, e := readValue(&c)
				if e != nil {
					return g, e
				}
				n.operands = append(n.operands, v)
			}
			rc, e := c.uleb()
			if e != nil {
				return g, e
			}
			for k := uint64(0); k < rc; k++ {
				ri, e := c.uleb()
				if e != nil {
					return g, e
				}
				r, e := refAt(o, ri)
				if e != nil {
					return g, e
				}
				n.results = append(n.results, r)
				used[r] = true
			}
			if op >= 35 && op <= 37 {
				ac, e := c.uleb()
				if e != nil || ac != 0 {
					return g, errors.New("meta attributes unsupported")
				}
			}
			g.blocks[bi].nodes = append(g.blocks[bi].nodes, n)
		}
		term, e := c.uleb()
		if e != nil {
			return g, e
		}
		g.blocks[bi].term = term
		switch term {
		case 2:
			v, e := readValue(&c)
			if e != nil {
				return g, e
			}
			g.blocks[bi].cond = &v
			for x := 0; x < 2; x++ {
				t, e := c.uleb()
				if e != nil {
					return g, e
				}
				ac, e := c.uleb()
				if e != nil {
					return g, e
				}
				ed := edge{target: t}
				for k := uint64(0); k < ac; k++ {
					v, e := readValue(&c)
					if e != nil {
						return g, e
					}
					ed.args = append(ed.args, v)
				}
				g.blocks[bi].edges = append(g.blocks[bi].edges, ed)
			}
		case 3:
			rc, e := c.uleb()
			if e != nil {
				return g, e
			}
			for k := uint64(0); k < rc; k++ {
				v, e := readValue(&c)
				if e != nil {
					return g, e
				}
				g.blocks[bi].returns = append(g.blocks[bi].returns, v)
			}
		default:
			return g, fmt.Errorf("unsupported terminator %d", term)
		}
	}
	if c.p != len(c.b) {
		return g, errors.New("graph trailing bytes")
	}
	if len(used) != len(o.refs) {
		return g, errors.New("unused graph reference")
	}
	return g, nil
}
func verifyType(o *object) error {
	if o.kind != 4 {
		return errors.New("expected type")
	}
	c := cursor{b: o.body}
	form, e := c.uleb()
	if e != nil {
		return e
	}
	switch form {
	case 1:
		w, e := c.uleb()
		if e != nil || w < 1 || len(o.refs) != 0 {
			return errors.New("bad bits type")
		}
	case 5:
		k, e := c.uleb()
		if e != nil || (k != 3 && k != 6 && k != 7) || len(o.refs) != 0 {
			return errors.New("bad opaque type")
		}
	default:
		return fmt.Errorf("unsupported type form %d", form)
	}
	if c.p != len(c.b) {
		return errors.New("type trailing bytes")
	}
	return nil
}
func refList(o *object, allowed map[uint64]bool, s *store) error {
	c := cursor{b: o.body}
	n, e := c.uleb()
	if e != nil || n != uint64(len(o.refs)) {
		return errors.New("bad reference list")
	}
	for i := uint64(0); i < n; i++ {
		x, e := c.uleb()
		if e != nil || x != i {
			return errors.New("noncanonical reference-list index")
		}
		if !allowed[s.byCID[o.refs[x]].kind] {
			return errors.New("reference kind mismatch")
		}
	}
	if c.p != len(c.b) {
		return errors.New("reference-list trailing")
	}
	return nil
}
func functionParts(o *object) ([32]byte, [][32]byte, [][32]byte, error) {
	var z [32]byte
	c := cursor{b: o.body}
	used := map[[32]byte]bool{}
	gi, e := c.uleb()
	if e != nil {
		return z, nil, nil, e
	}
	g, e := refAt(o, gi)
	if e != nil {
		return z, nil, nil, e
	}
	used[g] = true
	pn, e := c.uleb()
	if e != nil {
		return z, nil, nil, e
	}
	var ps [][32]byte
	for i := uint64(0); i < pn; i++ {
		ri, e := c.uleb()
		if e != nil {
			return z, nil, nil, e
		}
		r, e := refAt(o, ri)
		if e != nil {
			return z, nil, nil, e
		}
		ps = append(ps, r)
		used[r] = true
	}
	rn, e := c.uleb()
	if e != nil {
		return z, nil, nil, e
	}
	var rs [][32]byte
	for i := uint64(0); i < rn; i++ {
		ri, e := c.uleb()
		if e != nil {
			return z, nil, nil, e
		}
		r, e := refAt(o, ri)
		if e != nil {
			return z, nil, nil, e
		}
		rs = append(rs, r)
		used[r] = true
	}
	if c.p != len(c.b) {
		return z, nil, nil, errors.New("function trailing")
	}
	if len(used) != len(o.refs) {
		return z, nil, nil, errors.New("unused function reference")
	}
	return g, ps, rs, nil
}
func typeOf(v value, g parsedGraph) ([32]byte, error) {
	var z [32]byte
	if v.block >= uint64(len(g.blocks)) {
		return z, errors.New("value block")
	}
	b := g.blocks[v.block]
	if v.tag == 0 {
		if v.index >= uint64(len(b.params)) {
			return z, errors.New("parameter index")
		}
		return b.params[v.index], nil
	}
	if v.index >= uint64(len(b.nodes)) {
		return z, errors.New("node index")
	}
	n := b.nodes[v.index]
	if v.result >= uint64(len(n.results)) {
		return z, errors.New("result index")
	}
	return n.results[v.result], nil
}
func verifyGraph(o *object, s *store) error {
	g, e := parseGraph(o)
	if e != nil {
		return e
	}
	for bi, b := range g.blocks {
		for _, t := range b.params {
			if e := verifyType(s.byCID[t]); e != nil {
				return e
			}
		}
		for ni, n := range b.nodes {
			for _, v := range n.operands {
				if v.block > uint64(bi) || (v.block == uint64(bi) && v.tag == 1 && v.index >= uint64(ni)) {
					return errors.New("dominance")
				}
				if _, e := typeOf(v, g); e != nil {
					return e
				}
			}
			for _, t := range n.results {
				if e := verifyType(s.byCID[t]); e != nil {
					return e
				}
			}
			switch n.op {
			case 1, 3:
				if len(n.operands) != 2 || len(n.results) != 1 {
					return errors.New("arithmetic arity")
				}
				a, _ := typeOf(n.operands[0], g)
				b2, _ := typeOf(n.operands[1], g)
				if a != b2 || a != n.results[0] {
					return errors.New("arithmetic type")
				}
			case 5:
				if n.entity == nil || s.byCID[*n.entity].kind != 3 {
					return errors.New("call entity")
				}
				_, ps, rs, e := functionParts(s.byCID[*n.entity])
				if e != nil {
					return e
				}
				if len(ps) != len(n.operands) || len(rs) != len(n.results) {
					return errors.New("call arity")
				}
				for i, v := range n.operands {
					t, _ := typeOf(v, g)
					if t != ps[i] {
						return errors.New("call input type")
					}
				}
				for i, t := range n.results {
					if t != rs[i] {
						return errors.New("call output type")
					}
				}
			case 35, 36, 37:
				if len(n.operands) != 1 || len(n.results) != 1 {
					return errors.New("meta arity")
				}
				in, _ := typeOf(n.operands[0], g)
				if n.op == 35 || n.op == 36 {
					if !isOpaque(s.byCID[in], 6) {
						return errors.New("meta object input")
					}
				} else if !isOpaque(s.byCID[in], 3) {
					return errors.New("materialize function input")
				}
				if n.op == 35 && !isOpaque(s.byCID[n.results[0]], 7) {
					return errors.New("canonical store result")
				}
				if n.op == 36 && !isBits(s.byCID[n.results[0]], 1) {
					return errors.New("verify result")
				}
				if n.op == 37 && !isOpaque(s.byCID[n.results[0]], 6) {
					return errors.New("materialize result")
				}
			}
		}
		if b.term == 3 {
			for _, v := range b.returns {
				if v.block != uint64(bi) {
					return errors.New("return value not block-local")
				}
				if _, e := typeOf(v, g); e != nil {
					return e
				}
			}
		}
		if b.term == 2 {
			ct, e := typeOf(*b.cond, g)
			if e != nil || !isBits(s.byCID[ct], 1) {
				return errors.New("condition type")
			}
			for _, ed := range b.edges {
				if ed.target >= uint64(len(g.blocks)) || len(ed.args) != len(g.blocks[ed.target].params) {
					return errors.New("edge arity")
				}
				for i, v := range ed.args {
					t, _ := typeOf(v, g)
					if t != g.blocks[ed.target].params[i] {
						return errors.New("edge type")
					}
				}
			}
		}
	}
	return nil
}
func isBits(o *object, w uint64) bool {
	if o == nil || o.kind != 4 {
		return false
	}
	c := cursor{b: o.body}
	f, e := c.uleb()
	if e != nil || f != 1 {
		return false
	}
	x, e := c.uleb()
	return e == nil && x == w && c.p == len(c.b)
}
func isOpaque(o *object, k uint64) bool {
	if o == nil || o.kind != 4 {
		return false
	}
	c := cursor{b: o.body}
	f, e := c.uleb()
	if e != nil || f != 5 {
		return false
	}
	x, e := c.uleb()
	return e == nil && x == k && c.p == len(c.b)
}
func verifySemantics(s *store) error {
	for _, o := range s.objects {
		switch o.kind {
		case 1:
			if e := refList(o, map[uint64]bool{2: true}, s); e != nil {
				return e
			}
		case 2:
			if e := refList(o, map[uint64]bool{3: true, 4: true}, s); e != nil {
				return e
			}
		case 3:
			g, ps, rs, e := functionParts(o)
			if e != nil {
				return e
			}
			if s.byCID[g] == nil || s.byCID[g].kind != 7 {
				return errors.New("function graph")
			}
			for _, t := range append(ps, rs...) {
				if e := verifyType(s.byCID[t]); e != nil {
					return e
				}
			}
			pg, e := parseGraph(s.byCID[g])
			if e != nil {
				return e
			}
			if pg.blocks[pg.entry].params == nil && len(ps) != 0 {
				return errors.New("function parameters")
			}
			if len(pg.blocks[pg.entry].params) != len(ps) {
				return errors.New("function parameter count")
			}
			for i, t := range ps {
				if pg.blocks[pg.entry].params[i] != t {
					return errors.New("function parameter type")
				}
			}
			for _, b := range pg.blocks {
				if b.term == 3 {
					if len(b.returns) != len(rs) {
						return errors.New("return arity")
					}
					for i, v := range b.returns {
						t, e := typeOf(v, pg)
						if e != nil || t != rs[i] {
							return errors.New("return type")
						}
					}
				}
			}
		case 4:
			if e := verifyType(o); e != nil {
				return e
			}
		case 7:
			if e := verifyGraph(o, s); e != nil {
				return e
			}
		default:
			return fmt.Errorf("unsupported object kind %d", o.kind)
		}
	}
	return nil
}

func report(path string, s *store, mode string) map[string]any {
	sh := sha256.Sum256(s.raw)
	b3 := blake3sum(s.raw)
	return map[string]any{"format": "xax-oi27-independent-check-v1", "mode": mode, "path": path, "root": hex.EncodeToString(s.root[:]), "objects": len(s.objects), "bytes": len(s.raw), "sha256": hex.EncodeToString(sh[:]), "blake3_256": hex.EncodeToString(b3[:])}
}
func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: checker <container|verify|rewrite|hash> <input> [output|expected-root]")
		os.Exit(2)
	}
	mode, path := os.Args[1], os.Args[2]
	data, e := os.ReadFile(path)
	if e != nil {
		panic(e)
	}
	if mode == "hash" {
		d := blake3sum(data)
		fmt.Println(hex.EncodeToString(d[:]))
		return
	}
	s, e := parseStore(data)
	if e == nil && mode != "container" {
		e = verifySemantics(s)
	}
	if e == nil && len(os.Args) >= 4 && mode != "rewrite" && os.Args[3] != "-" {
		if hex.EncodeToString(s.root[:]) != os.Args[3] {
			e = errors.New("expected root mismatch")
		}
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if mode == "rewrite" {
		if len(os.Args) != 4 {
			os.Exit(2)
		}
		out := emitStore(s)
		if e := os.WriteFile(os.Args[3], out, 0644); e != nil {
			panic(e)
		}
	}
	r := report(path, s, mode)
	enc, _ := json.Marshal(r)
	fmt.Println(string(enc))
}
