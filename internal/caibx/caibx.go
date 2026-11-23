// Package caibx is casync's .caibx index format and its chunk IDs, as the
// off-host backups (internal/backup) write them; in a package of its own,
// with no system calls, so that the owner's tool (trajrl, on every OS)
// can read an index it downloads.
package caibx

import (
	"bufio"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// The index is casync's .caibx format, as desync reads and writes it
// (github.com/folbricht/desync, format.go and index.go), written here
// without the library: it would have brought some eighty modules with it.
// Compatibility is checked against the desync CLI (tests/backup-minio.sh).
//
//	FormatIndex  size=48, type, feature flags, chunk size min, avg, max
//	FormatTable  size=MaxUint64, type, then per chunk: end offset, chunk ID
//	tail         0, 0, 48 (index offset), table size, tail marker
//
// All integers little-endian. Chunk IDs are SHA-512/256 of the chunk's
// bytes (feature flag CaFormatSHA512256), desync's default.
const (
	caFormatIndex           = 0x96824d9c7b129ff9
	caFormatTable           = 0xe75b9e112f17417d
	caFormatTableTailMarker = 0x4b4f050e5549ecd1
	caFormatSHA512256       = 0x2000000000000000
	// desync make sets these for a blob index: an image of a byte stream.
	caFormatExcludeNoDump = 0x8000000000000000
)

// ChunkSize is the size of every chunk but the last of a disk: 1 MiB,
// blockdiff.ChunkSize, so that a block the guest wrote maps to one chunk.
const ChunkSize = 1 << 20

// ID names a chunk: the SHA-512/256 of its bytes.
type ID [32]byte

func (id ID) String() string { return hex.EncodeToString(id[:]) }

// Sum is the ID of data.
func Sum(data []byte) ID { return sha512.Sum512_256(data) }

// ZeroID is the ID of a chunk of ChunkSize zero bytes: every hole in a
// sparse disk.
var ZeroID = Sum(make([]byte, ChunkSize))

// Chunk is one entry of an index.
type Chunk struct {
	ID   ID
	Size uint32
}

// Index is a disk as a list of chunks, in order.
type Index struct {
	Chunks []Chunk
	// Min, Avg and Max are the chunker's sizes, as the header records them.
	// Fixed-size chunks: all three ChunkSize.
	Min, Avg, Max uint64
}

// Length is the size of the disk the index describes.
func (x *Index) Length() int64 {
	var n int64
	for _, c := range x.Chunks {
		n += int64(c.Size)
	}
	return n
}

// WriteTo writes the index in .caibx format.
func (x *Index) WriteTo(w io.Writer) (int64, error) {
	bw := bufio.NewWriter(w)
	var n int64
	put := func(v ...uint64) {
		var b [8]byte
		for _, u := range v {
			binary.LittleEndian.PutUint64(b[:], u)
			bw.Write(b[:])
			n += 8
		}
	}
	min, avg, max := x.Min, x.Avg, x.Max
	if max == 0 {
		min, avg, max = ChunkSize, ChunkSize, ChunkSize
	}
	put(48, caFormatIndex, caFormatSHA512256|caFormatExcludeNoDump, min, avg, max)
	put(^uint64(0), caFormatTable)
	table := int64(16)
	var off uint64
	for _, c := range x.Chunks {
		off += uint64(c.Size)
		put(off)
		bw.Write(c.ID[:])
		n += 32
		table += 40
	}
	put(0, 0, 48, uint64(table+40), caFormatTableTailMarker)
	return n, bw.Flush()
}

// ReadIndex reads an index in .caibx format.
func ReadIndex(r io.Reader) (*Index, error) {
	br := bufio.NewReader(r)
	get := func() (uint64, error) {
		var b [8]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return 0, err
		}
		return binary.LittleEndian.Uint64(b[:]), nil
	}
	var h [6]uint64
	for i := range h {
		v, err := get()
		if err != nil {
			return nil, fmt.Errorf("index header: %w", err)
		}
		h[i] = v
	}
	if h[0] != 48 || h[1] != caFormatIndex {
		return nil, errors.New("not a caibx index")
	}
	if h[2]&caFormatSHA512256 == 0 {
		return nil, errors.New("the index uses SHA-256 chunk IDs; only SHA-512/256 is read here")
	}
	x := &Index{Min: h[3], Avg: h[4], Max: h[5]}
	if size, err := get(); err != nil || size != ^uint64(0) {
		return nil, errors.New("index: no chunk table")
	}
	if typ, err := get(); err != nil || typ != caFormatTable {
		return nil, errors.New("index: no chunk table")
	}
	var last uint64
	for {
		off, err := get()
		if err != nil {
			return nil, fmt.Errorf("index table: %w", err)
		}
		if off == 0 { // the tail: zero fill, then index offset, size, marker
			var t [4]uint64
			for i := range t {
				if t[i], err = get(); err != nil {
					return nil, fmt.Errorf("index tail: %w", err)
				}
			}
			if t[3] != caFormatTableTailMarker {
				return nil, errors.New("index: bad tail marker")
			}
			return x, nil
		}
		var c Chunk
		if _, err := io.ReadFull(br, c.ID[:]); err != nil {
			return nil, fmt.Errorf("index table: %w", err)
		}
		if off <= last || off-last > x.Max || off-last > 1<<32-1 {
			return nil, fmt.Errorf("index: chunk ending at %d is out of order or larger than %d", off, x.Max)
		}
		c.Size = uint32(off - last)
		last = off
		x.Chunks = append(x.Chunks, c)
	}
}
