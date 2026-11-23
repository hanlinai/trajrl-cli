package attest

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-tdx-guest/verify/trust"
)

// DefaultCollateralRefresh is how long a cached collateral response is used
// before it is fetched again while Intel's PCS is reachable. It bounds how
// late the broker learns of a new TCB rating or a new revocation.
const DefaultCollateralRefresh = time.Hour

// BoundedGetter fetches from Intel PCS with retries, but gives up after 20
// seconds. The library's default retries for two minutes, longer than a
// guest's session is allowed to wait for its verdict.
func BoundedGetter() trust.HTTPSGetter {
	return &trust.RetryHTTPSGetter{Timeout: 20 * time.Second, MaxRetryDelay: 5 * time.Second, Getter: &trust.SimpleHTTPSGetter{}}
}

// CollateralCache keeps Intel's collateral responses (TCB info, QE identity,
// PCK and root CA CRLs) so that an Intel outage does not stop every boot.
// Entries are keyed by URL: the TCB info URL carries the FMSPC, the PCK CRL
// URL the CA.
//
// It never decides anything. A response served from the cache is handed to
// the library exactly as Intel sent it, and the library verifies it in full
// on every verification: signatures, issuer chain, revocation, and expiry
// against the verifier's clock. The cache only decides when to ask Intel
// again:
//
//   - before refresh has passed since the fetch, and before Intel's own
//     nextUpdate: the cached response is used;
//   - after refresh, before nextUpdate: it is fetched again; if Intel cannot
//     be reached, the cached response, still within the validity Intel gave
//     it, is used and the failure counted;
//   - at or after nextUpdate the response is stale: it is dropped and fetched
//     again, and if that fails the fetch fails and with it the verification.
//     A stale response is never served.
//
// After a failed refresh the cached response (still within nextUpdate) is
// served without asking Intel again for retryAfter, so that an outage does
// not make every boot wait out the fetch timeout. Only URLs that produced a
// cacheable response are kept, and at most maxEntries of them: the FMSPC in
// a TCB info URL comes from a certificate not yet verified when the
// collateral is fetched, so a stranger could otherwise grow the map.
//
// A response whose nextUpdate cannot be read is passed through, not kept.
type CollateralCache struct {
	upstream trust.HTTPSGetter
	refresh  time.Duration
	errors   atomic.Uint64

	mu      sync.Mutex
	entries map[string]*cacheEntry
}

type cacheEntry struct {
	// mu serialises fetches of one URL, so a burst of boots asks Intel once.
	mu         sync.Mutex
	header     map[string][]string
	body       []byte
	fetched    time.Time
	nextUpdate time.Time
	retryAt    time.Time // after a failed refresh: do not ask Intel before this
	valid      bool
}

const (
	retryAfter = 2 * time.Minute
	maxEntries = 256
)

// NewCollateralCache returns an empty cache that fetches through upstream
// (BoundedGetter if nil) and refetches after refresh (DefaultCollateralRefresh
// if not positive).
func NewCollateralCache(upstream trust.HTTPSGetter, refresh time.Duration) *CollateralCache {
	if upstream == nil {
		upstream = BoundedGetter()
	}
	if refresh <= 0 {
		refresh = DefaultCollateralRefresh
	}
	return &CollateralCache{upstream: upstream, refresh: refresh, entries: map[string]*cacheEntry{}}
}

// FetchErrors is the number of failed fetches from Intel PCS so far.
func (c *CollateralCache) FetchErrors() uint64 { return c.errors.Load() }

// at returns the cache as a getter that judges freshness by the given clock,
// the verifier's: a verification pinned to a time sees the cache as it would
// be at that time.
func (c *CollateralCache) at(now func() time.Time) *cacheView {
	return &cacheView{c: c, now: now}
}

type cacheView struct {
	c   *CollateralCache
	now func() time.Time
}

func (v *cacheView) Get(url string) (map[string][]string, []byte, error) {
	return v.GetContext(context.Background(), url)
}

func (v *cacheView) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	return v.c.get(ctx, url, v.now())
}

// entry returns the URL's entry; a new one is not in the map until a fetch
// for it produced something worth keeping (keep).
func (c *CollateralCache) entry(url string) *cacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[url]; e != nil {
		return e
	}
	return &cacheEntry{}
}

// keep puts an entry in the map, if there is room.
func (c *CollateralCache) keep(url string, e *cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries[url] == nil && len(c.entries) < maxEntries {
		c.entries[url] = e
	}
}

func (c *CollateralCache) get(ctx context.Context, url string, now time.Time) (map[string][]string, []byte, error) {
	e := c.entry(url)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.valid && !now.Before(e.nextUpdate) {
		e.valid, e.header, e.body = false, nil, nil // stale: never served again
	}
	if e.valid && (now.Before(e.fetched.Add(c.refresh)) || now.Before(e.retryAt)) {
		return e.header, e.body, nil
	}
	h, b, err := trust.GetWith(ctx, c.upstream, url)
	if err != nil {
		c.errors.Add(1)
		if e.valid {
			e.retryAt = now.Add(retryAfter)
			return e.header, e.body, nil // past refresh, within Intel's validity
		}
		return nil, nil, fmt.Errorf("collateral %s could not be fetched and no unexpired copy is cached: %w", url, err)
	}
	next, ok := nextUpdate(b)
	if !ok || !now.Before(next) {
		// Not cacheable: handed on as fetched, for the library to judge.
		e.valid, e.header, e.body = false, nil, nil
		return h, b, nil
	}
	e.header, e.body, e.fetched, e.nextUpdate, e.retryAt, e.valid = h, b, now, next, time.Time{}, true
	c.keep(url, e)
	return h, b, nil
}

// nextUpdate reads when Intel says a collateral response stops being valid.
func nextUpdate(body []byte) (time.Time, bool) {
	if strings.HasPrefix(strings.TrimSpace(string(body[:min(len(body), 16)])), "{") {
		var outer map[string]json.RawMessage
		if json.Unmarshal(body, &outer) != nil {
			return time.Time{}, false
		}
		for _, name := range []string{"tcbInfo", "enclaveIdentity"} {
			raw, ok := outer[name]
			if !ok {
				continue
			}
			var inner struct {
				NextUpdate time.Time `json:"nextUpdate"`
			}
			if json.Unmarshal(raw, &inner) != nil || inner.NextUpdate.IsZero() {
				return time.Time{}, false
			}
			return inner.NextUpdate, true
		}
		return time.Time{}, false
	}
	crl, err := x509.ParseRevocationList(body)
	if err != nil || crl.NextUpdate.IsZero() {
		return time.Time{}, false
	}
	return crl.NextUpdate, true
}
