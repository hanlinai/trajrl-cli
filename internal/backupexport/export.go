// Package backupexport is how a sandbox's owner takes a copy of its
// off-host backup (#44, #118 D9): the encrypted disk's index, every chunk it
// lists and, for a v2 disk, its lower image, in the bucket's own layout, so
// that the offline restore (docs/offline-restore.md) runs on that copy with
// the owner's key alone and no part of the platform.
//
// The bucket's credentials stay with the platform. The control plane reads
// the backup's record and index, and answers the owner's "backup export"
// with a Plan: short-lived URLs that each read one object of that backup and
// nothing else (S3 presigned GETs), a page of chunks at a time. Download
// fetches them and checks what it can without trusting the platform: every
// chunk against its ID (the hash of its bytes), the set of chunks against
// the index it downloaded, and the lower image against its dm-verity
// parameters when the caller can check them. The index and record are the
// platform's word; the disk they describe opens only with the owner's keys,
// and dm-integrity refuses any block that is not the disk's.
//
// No system calls: trajrl runs this on Linux, macOS and Windows.
package backupexport

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hanlinai/trajrl-cli/internal/caibx"
)

// PageSize is how many chunk URLs one Plan holds at most: about 1 GiB of
// chunks, fetched well within a URL's life (TTL). A variable for tests.
var PageSize = 1000

// TTL is how long the URLs of a Plan read their objects.
const TTL = time.Hour

// MaxFirst is how many chunks one request may ask for as first written.
const MaxFirst = 64

// Object is one object of the backup and a URL that reads it.
type Object struct {
	Key string `json:"key"`
	URL string `json:"url"`
	// ID is a chunk's ID, in hex.
	ID string `json:"id,omitempty"`
}

// Plan is the control plane's answer to "backup export NAME [BACKUP]
// --json": the backup's record and index, its lower image if it has one,
// and one page of its chunks, each with a URL that reads it until Expires.
type Plan struct {
	Sandbox string    `json:"sandbox"`
	Backup  string    `json:"backup"`
	Expires time.Time `json:"expires"`
	Record  Object    `json:"record"`
	Index   Object    `json:"index"`
	Image   *Object   `json:"image,omitempty"`
	// Chunks are the distinct chunks the index lists, in the order of
	// their IDs, from From; ChunksTotal is how many there are, and Next
	// where the next page starts (0: this is the last).
	Chunks      []Object `json:"chunks"`
	From        int      `json:"from"`
	ChunksTotal int      `json:"chunks_total"`
	Next        int      `json:"next"`
}

// DistinctChunks are the chunks an index lists, each once, in the order of
// their IDs: the order Plan pages them in.
func DistinctChunks(idx *caibx.Index) []caibx.ID {
	seen := map[caibx.ID]bool{}
	var out []caibx.ID
	for _, c := range idx.Chunks {
		if !seen[c.ID] {
			seen[c.ID] = true
			out = append(out, c.ID)
		}
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i][:]) < string(out[j][:]) })
	return out
}

// The bucket's layout, as internal/backup writes it.
func chunkKey(id caibx.ID) string {
	s := id.String()
	return "chunks/" + s[:4] + "/" + s
}

// Asker asks the control plane for a Plan: the page of chunks from from, or
// with first set, URLs that read those chunks as first written (a chunk
// whose newest version does not match its ID was overwritten).
type Asker func(ctx context.Context, from int, first []string) (*Plan, error)

// Options are Download's.
type Options struct {
	// HTTP fetches the URLs (http.DefaultClient if nil).
	HTTP *http.Client
	// Progress, if set, is told how far the download is.
	Progress io.Writer
	// VerifyImage, if set, checks the lower image against the record's
	// dm-verity parameters ("roothash,data_blocks,salt").
	VerifyImage func(path, verity string) error
	// Parallel is how many objects are fetched at once (8 if zero).
	Parallel int
}

// Result says what Download wrote.
type Result struct {
	Dir     string `json:"dir"`
	Sandbox string `json:"sandbox"`
	Backup  string `json:"backup"`
	// Index and Record are the paths of the index and record in Dir.
	Index  string `json:"index"`
	Record string `json:"record"`
	// Image is the lower image's path, "" for none.
	Image       string `json:"image,omitempty"`
	ImageVerity string `json:"image_verity,omitempty"`
	DiskFormat  string `json:"disk_format"`
	DiskBytes   int64  `json:"disk_bytes"`
	Chunks      int    `json:"chunks"`
	// Fetched is how many chunks were fetched now; the others were in Dir
	// already, with the right hash (a download started again).
	Fetched int   `json:"fetched"`
	Bytes   int64 `json:"bytes"`
	// ImageVerified says whether the lower image was checked against its
	// dm-verity parameters here.
	ImageVerified bool `json:"image_verified,omitempty"`
}

// record is the part of internal/backup's Record that is checked here.
type record struct {
	Sandbox     string `json:"sandbox"`
	Name        string `json:"name"`
	DiskBytes   int64  `json:"disk_bytes"`
	DiskFormat  string `json:"disk_format"`
	LowerImage  string `json:"lower_image"`
	LowerVerity string `json:"lower_verity"`
}

// Download writes the backup the Plans describe to dir in the bucket's
// layout: dir/indexes/SANDBOX/BACKUP.caibx and .json, dir/chunks/..., and
// dir/images/ROOTHASH.img. Chunks already in dir with the right hash are
// kept, so a download that stopped can be run again.
func Download(ctx context.Context, dir string, ask Asker, o Options) (*Result, error) {
	client := o.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	par := o.Parallel
	if par <= 0 {
		par = 8
	}
	say := func(format string, a ...any) {
		if o.Progress != nil {
			fmt.Fprintf(o.Progress, format+"\n", a...)
		}
	}
	plan, err := ask(ctx, 0, nil)
	if err != nil {
		return nil, err
	}
	if err := checkPlanNames(plan); err != nil {
		return nil, err
	}
	res := &Result{Dir: dir, Sandbox: plan.Sandbox, Backup: plan.Backup}
	base := filepath.Join(dir, "indexes", plan.Sandbox, plan.Backup)
	res.Index, res.Record = base+".caibx", base+".json"
	if err := os.MkdirAll(filepath.Dir(base), 0o700); err != nil {
		return nil, err
	}
	if err := fetchTo(ctx, client, plan.Record.URL, res.Record, 1<<20, nil); err != nil {
		return nil, fmt.Errorf("the backup's record: %w", err)
	}
	if err := fetchTo(ctx, client, plan.Index.URL, res.Index, 64<<20, nil); err != nil {
		return nil, fmt.Errorf("the backup's index: %w", err)
	}
	var rec record
	if b, err := os.ReadFile(res.Record); err != nil || json.Unmarshal(b, &rec) != nil {
		return nil, errors.New("the backup's record is not one")
	}
	if rec.Sandbox != plan.Sandbox || rec.Name != plan.Backup {
		return nil, fmt.Errorf("the record is of %s/%s, not of %s/%s", rec.Sandbox, rec.Name, plan.Sandbox, plan.Backup)
	}
	f, err := os.Open(res.Index)
	if err != nil {
		return nil, err
	}
	idx, err := caibx.ReadIndex(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("the backup's index: %w", err)
	}
	if idx.Length() != rec.DiskBytes {
		return nil, fmt.Errorf("the index describes %d bytes, the record %d", idx.Length(), rec.DiskBytes)
	}
	res.DiskFormat, res.DiskBytes = rec.DiskFormat, rec.DiskBytes
	want := DistinctChunks(idx)
	res.Chunks = len(want)
	say("%s/%s: %s, %d MiB, %d distinct chunks", plan.Sandbox, plan.Backup, rec.DiskFormat, rec.DiskBytes>>20, len(want))

	// The lower image, once, by the root hash the record names.
	if rec.LowerImage != "" {
		if plan.Image == nil {
			return nil, fmt.Errorf("the record names the lower image %s, and the platform gave no URL for it", rec.LowerImage)
		}
		if !isHex64(rec.LowerImage) || plan.Image.Key != "images/"+rec.LowerImage+".img" {
			return nil, fmt.Errorf("the platform's URL for the lower image is for %q, the record names %q", plan.Image.Key, rec.LowerImage)
		}
		res.Image, res.ImageVerity = filepath.Join(dir, "images", rec.LowerImage+".img"), rec.LowerVerity
		if err := os.MkdirAll(filepath.Dir(res.Image), 0o700); err != nil {
			return nil, err
		}
		if _, err := os.Stat(res.Image); err != nil {
			say("lower image %s", rec.LowerImage)
			if err := fetchTo(ctx, client, plan.Image.URL, res.Image, 1<<40, nil); err != nil {
				return nil, fmt.Errorf("the lower image: %w", err)
			}
		}
		if o.VerifyImage != nil && rec.LowerVerity != "" {
			if err := o.VerifyImage(res.Image, rec.LowerVerity); err != nil {
				os.Remove(res.Image)
				return nil, fmt.Errorf("the lower image: %w", err)
			}
			res.ImageVerified = true
		}
	}

	// The chunks, a page at a time, each page asked for as it is fetched.
	for from := 0; ; {
		if from > 0 {
			if plan, err = ask(ctx, from, nil); err != nil {
				return nil, err
			}
		}
		if plan.Sandbox != res.Sandbox || plan.Backup != res.Backup || plan.From != from || plan.ChunksTotal != len(want) {
			return nil, fmt.Errorf("the platform's page from %d is of %s/%s from %d of %d chunks; the index lists %d", from, plan.Sandbox, plan.Backup, plan.From, plan.ChunksTotal, len(want))
		}
		if len(plan.Chunks) == 0 && from < len(want) {
			return nil, fmt.Errorf("the platform's page from %d lists no chunks", from)
		}
		page := map[caibx.ID]Object{}
		for i, c := range plan.Chunks {
			id, err := parseID(c.ID)
			if err != nil || from+i >= len(want) || id != want[from+i] || c.Key != chunkKey(id) {
				return nil, fmt.Errorf("the platform's chunk %d (%s) is not the index's", from+i, c.ID)
			}
			page[id] = c
		}
		bad, fetched, bytes, err := fetchChunks(ctx, client, dir, page, par)
		if err != nil {
			return nil, err
		}
		// A chunk whose newest version is not its bytes was overwritten
		// (a raw PUT): the first version is the one written by the backup.
		for len(bad) > 0 {
			n := min(len(bad), MaxFirst)
			var ids []string
			for _, id := range bad[:n] {
				ids = append(ids, id.String())
			}
			fp, err := ask(ctx, 0, ids)
			if err != nil {
				return nil, err
			}
			retry := map[caibx.ID]Object{}
			for _, c := range fp.Chunks {
				if id, err := parseID(c.ID); err == nil && c.Key == chunkKey(id) {
					retry[id] = c
				}
			}
			for _, id := range bad[:n] {
				if _, ok := retry[id]; !ok {
					return nil, fmt.Errorf("chunk %s: the platform gave no URL for its first version", id)
				}
			}
			still, f2, b2, err := fetchChunks(ctx, client, dir, retry, par)
			if err != nil {
				return nil, err
			}
			if len(still) > 0 {
				return nil, fmt.Errorf("chunk %s: no version the platform serves has that hash", still[0])
			}
			fetched, bytes = fetched+f2, bytes+b2
			bad = bad[n:]
		}
		res.Fetched += fetched
		res.Bytes += bytes
		from += len(plan.Chunks)
		say("chunks: %d of %d", from, len(want))
		if plan.Next == 0 || from >= len(want) {
			break
		}
		if plan.Next != from {
			return nil, fmt.Errorf("the platform's next page starts at %d, after %d", plan.Next, from)
		}
	}
	// Every chunk of the index is there, with its hash.
	for _, id := range want {
		if ok, err := haveChunk(filepath.Join(dir, filepath.FromSlash(chunkKey(id))), id); err != nil || !ok {
			return nil, fmt.Errorf("chunk %s of the index was not fetched", id)
		}
	}
	return res, nil
}

func checkPlanNames(p *Plan) error {
	ok := strings.HasPrefix(p.Sandbox, "sbx-") && !strings.ContainsAny(p.Sandbox, "/\\. ") &&
		p.Backup != "" && !strings.ContainsAny(p.Backup, "/\\ ") && !strings.Contains(p.Backup, "..")
	if !ok {
		return fmt.Errorf("the platform's answer names the backup %q/%q", p.Sandbox, p.Backup)
	}
	if p.Record.Key != "indexes/"+p.Sandbox+"/"+p.Backup+".json" || p.Index.Key != "indexes/"+p.Sandbox+"/"+p.Backup+".caibx" {
		return errors.New("the platform's URLs for the record and index are not of that backup")
	}
	return nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

func parseID(s string) (caibx.ID, error) {
	var id caibx.ID
	if !isHex64(s) {
		return id, fmt.Errorf("chunk ID %q", s)
	}
	hex.Decode(id[:], []byte(s))
	return id, nil
}

// haveChunk says whether path holds a chunk with that ID.
func haveChunk(path string, id caibx.ID) (bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return caibx.Sum(b) == id, nil
}

// fetchChunks fetches the chunks of page not yet in dir, and returns those
// whose bytes did not match their ID.
func fetchChunks(ctx context.Context, client *http.Client, dir string, page map[caibx.ID]Object, par int) (bad []caibx.ID, fetched int, bytes int64, err error) {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		ferr error
		sem  = make(chan struct{}, par)
	)
	ids := make([]caibx.ID, 0, len(page))
	for id := range page {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return string(ids[i][:]) < string(ids[j][:]) })
	for _, id := range ids {
		path := filepath.Join(dir, filepath.FromSlash(chunkKey(id)))
		if ok, _ := haveChunk(path, id); ok {
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(id caibx.ID, o Object) {
			defer func() { <-sem; wg.Done() }()
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				mu.Lock()
				ferr = err
				mu.Unlock()
				return
			}
			var n int64
			err := fetchTo(ctx, client, o.URL, path, caibx.ChunkSize, func(b []byte) error {
				n = int64(len(b))
				if caibx.Sum(b) != id {
					return errMismatch
				}
				return nil
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case errors.Is(err, errMismatch):
				bad = append(bad, id)
			case err != nil:
				if ferr == nil {
					ferr = fmt.Errorf("chunk %s: %w", id, err)
				}
			default:
				fetched++
				bytes += n
			}
		}(id, page[id])
	}
	wg.Wait()
	sort.Slice(bad, func(i, j int) bool { return string(bad[i][:]) < string(bad[j][:]) })
	return bad, fetched, bytes, ferr
}

var errMismatch = errors.New("its bytes do not match its ID")

// fetchTo writes what url reads to path, whole or not at all, refusing more
// than max bytes; check, if set, sees the bytes first (small objects only).
func fetchTo(ctx context.Context, client *http.Client, url, path string, max int64, check func([]byte) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if resp.StatusCode == http.StatusForbidden {
			return fmt.Errorf("refused (%d): the URL has expired or is not for this object; run the export again (it keeps what it has): %s", resp.StatusCode, strings.TrimSpace(string(msg)))
		}
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	tmp := path + ".partial"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(tmp)
		}
	}()
	if check != nil {
		b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
		if err != nil {
			return err
		}
		if int64(len(b)) > max {
			return fmt.Errorf("more than %d bytes", max)
		}
		if err := check(b); err != nil {
			return err
		}
		if _, err := f.Write(b); err != nil {
			return err
		}
	} else {
		n, err := io.Copy(f, io.LimitReader(resp.Body, max+1))
		if err != nil {
			return err
		}
		if n > max {
			return fmt.Errorf("more than %d bytes", max)
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}
