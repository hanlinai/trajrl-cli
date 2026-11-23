package attest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/pcs"
)

// fakePCS serves a fakePKI's collateral over HTTP. The Intel URL asked for
// travels in the query; pcsClient puts it there.
func fakePCS(t *testing.T, f *fakePKI) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, body, err := f.Get(r.URL.Query().Get("u"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		for k, v := range h {
			w.Header()[k] = v
		}
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// pcsClient fetches every Intel URL from the fake PCS, over real HTTP.
type pcsClient struct{ base string }

func (c pcsClient) Get(u string) (map[string][]string, []byte, error) {
	resp, err := http.Get(c.base + "/?u=" + url.QueryEscape(u))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("%s: status %d", u, resp.StatusCode)
	}
	return resp.Header, body, nil
}

// The cache's whole life against a fake PCS: served while fresh, kept
// through an outage while Intel's validity lasts, refused once stale.
func TestCollateralCache(t *testing.T) {
	raw, pol, rd := hwPolicy(t)
	f := newFakePKI(t, raw, hwCollat, hwTime).allCurrent()
	// TCB info is the first collateral to go stale: three hours from now.
	f.tcbInfo["nextUpdate"] = hwTime.Add(3 * time.Hour).Format(time.RFC3339)
	cache := NewCollateralCache(pcsClient{fakePCS(t, f).URL}, time.Hour)
	v := f.verifier(pol)
	v.getter = nil // everything comes through the cache, over HTTP
	v.Collateral = cache
	verify := func() error {
		_, err := v.Verify(context.Background(), f.quote(nil), rd, hwSandboxID)
		return err
	}
	down := func(string) error { return errors.New("PCS unreachable") }

	if err := verify(); err != nil {
		t.Fatalf("first verification: %v", err)
	}
	if len(f.fetched) != 4 {
		t.Fatalf("first verification fetched %d responses, want 4: %v", len(f.fetched), f.fetched)
	}
	if err := verify(); err != nil || len(f.fetched) != 4 {
		t.Fatalf("within the refresh interval: %v, %d fetches (want none new)", err, len(f.fetched)-4)
	}
	if len(cache.entries) != 4 || cache.entries[f.urlTCB] == nil {
		t.Errorf("cache entries: %d, TCB info not keyed by its URL", len(cache.entries))
	}

	// Past the refresh interval, Intel down, everything still within its
	// nextUpdate: the cached responses carry the verification.
	f.now = hwTime.Add(2 * time.Hour)
	f.fail = down
	if err := verify(); err != nil {
		t.Fatalf("PCS down, collateral not yet stale: %v", err)
	}
	if n := cache.FetchErrors(); n != 4 {
		t.Errorf("FetchErrors = %d, want 4 (one per response)", n)
	}
	// And for the next couple of minutes Intel is not asked again: an outage
	// must not make every boot wait out the fetch timeout.
	f.now = hwTime.Add(2*time.Hour + time.Minute)
	if err := verify(); err != nil || cache.FetchErrors() != 4 {
		t.Fatalf("within the retry pause: %v, %d errors (want 4: no new attempts)", err, cache.FetchErrors())
	}

	// Past TCB info's nextUpdate with Intel down: refused, never stale.
	f.now = hwTime.Add(4 * time.Hour)
	err := verify()
	if err == nil {
		t.Fatal("a verification was made with stale TCB info")
	}
	if !strings.Contains(err.Error(), "no unexpired copy is cached") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	// Intel back, with fresh TCB info: fetched again and accepted.
	f.fail = nil
	f.tcbInfo["nextUpdate"] = hwTime.Add(30 * time.Hour).Format(time.RFC3339)
	before := len(f.fetched)
	if err := verify(); err != nil {
		t.Fatalf("PCS back: %v", err)
	}
	if got := strings.Join(f.fetched[before:], " "); !strings.Contains(got, f.urlTCB) {
		t.Errorf("TCB info was not fetched again: %s", got)
	}
}

// countingPCS answers from a fixed table and counts requests per URL.
type countingPCS struct {
	bodies map[string]string
	asked  map[string]int
}

func (c *countingPCS) Get(u string) (map[string][]string, []byte, error) {
	c.asked[u]++
	b, ok := c.bodies[u]
	if !ok {
		return nil, nil, errors.New("no such resource")
	}
	return nil, []byte(b), nil
}

// Responses are keyed by URL, so two platform families each get their own
// TCB info; and a response whose nextUpdate cannot be read is never kept.
func TestCollateralCacheKeysAndUncacheable(t *testing.T) {
	now := hwTime
	next := now.Add(24 * time.Hour).Format(time.RFC3339)
	a, b := pcs.TcbInfoURL("00906ed50000"), pcs.TcbInfoURL("90c06f000000")
	noDate := pcs.QeIdentityURL()
	up := &countingPCS{asked: map[string]int{}, bodies: map[string]string{
		a:      `{"tcbInfo":{"fmspc":"00906ED50000","nextUpdate":"` + next + `"},"signature":"00"}`,
		b:      `{"tcbInfo":{"fmspc":"90C06F000000","nextUpdate":"` + next + `"},"signature":"00"}`,
		noDate: `{"enclaveIdentity":{"id":"TD_QE"},"signature":"00"}`,
	}}
	g := NewCollateralCache(up, time.Hour).at(func() time.Time { return now })
	for range 3 {
		for _, u := range []string{a, b} {
			_, body, err := g.Get(u)
			if err != nil || !strings.Contains(string(body), strings.ToUpper(u[len(u)-12:])) {
				t.Fatalf("%s: %q %v", u, body, err)
			}
		}
		if _, _, err := g.Get(noDate); err != nil {
			t.Fatal(err)
		}
	}
	if up.asked[a] != 1 || up.asked[b] != 1 {
		t.Errorf("each FMSPC's TCB info should be fetched once: %v", up.asked)
	}
	if up.asked[noDate] != 3 {
		t.Errorf("a response without nextUpdate was cached: fetched %d times for 3 requests", up.asked[noDate])
	}
	// An unknown resource is an error, not an empty success, and leaves
	// nothing behind: a made-up FMSPC does not grow the cache.
	if _, _, err := g.Get(pcs.TcbInfoURL("ffffffffffff")); err == nil {
		t.Error("a failed fetch with nothing cached succeeded")
	}
	if n := len(g.c.entries); n != 2 {
		t.Errorf("%d entries kept, want 2 (the two cacheable responses)", n)
	}
	// The map has a ceiling.
	for i := range maxEntries + 10 {
		u := pcs.TcbInfoURL(fmt.Sprintf("%012x", i))
		up.bodies[u] = `{"tcbInfo":{"nextUpdate":"` + next + `"},"signature":"00"}`
		g.Get(u)
	}
	if n := len(g.c.entries); n > maxEntries {
		t.Errorf("%d entries, more than %d", n, maxEntries)
	}
}
