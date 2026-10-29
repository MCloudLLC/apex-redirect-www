package state

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var testLimits = Limits{MaxDomains: 10, AdmissionsPerWindow: 10, Window: time.Hour}

func testDirectory(t *testing.T) string {
	t.Helper()
	// Keep test artifacts inside the checkout, never in the system temp area.
	path, err := os.MkdirTemp(".", ".state-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			t.Error(err)
		}
	})
	return path
}

func openTestStore(t *testing.T, limits Limits) (*Store, string) {
	t.Helper()
	path := filepath.Join(testDirectory(t), "private", "state.db")
	store, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store, path
}

func addTestBlock(t *testing.T, store *Store, kind, value string, expiry time.Time) int64 {
	t.Helper()
	id, err := store.AddBlock(context.Background(), Block{
		Kind: kind, Value: value, Reason: "reported abuse", Operator: "test operator", ExpiresAt: expiry,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func assertBlocked(t *testing.T, store *Store, host, client string, want bool) {
	t.Helper()
	var addr netip.Addr
	if client != "" {
		addr = netip.MustParseAddr(client)
	}
	got, err := store.CheckBlocked(context.Background(), host, addr)
	if err != nil || got != want {
		t.Fatalf("CheckBlocked(%q,%q) = %v, %v; want %v", host, client, got, err, want)
	}
}

func TestDomainBlocksAndAudit(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t, testLimits)
	id := addTestBlock(t, store, "domain", "WWW.Example.COM.", time.Time{})
	assertBlocked(t, store, "EXAMPLE.COM.", "", true)
	assertBlocked(t, store, "otherexample.com", "", false)
	assertBlocked(t, store, "child.example.com", "", false)
	assertBlocked(t, store, "", "", false)
	if err := store.ReserveAdmission(ctx, "example.com"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("blocked www admission = %v", err)
	}
	blocks, err := store.ListBlocks(ctx)
	if err != nil || len(blocks) != 1 || blocks[0].Value != "www.example.com" ||
		blocks[0].CreatedAt.IsZero() || blocks[0].Reason != "reported abuse" || blocks[0].Operator != "test operator" {
		t.Fatalf("stored blocks = %#v, %v", blocks, err)
	}
	if err := store.RemoveBlock(ctx, id); err != nil {
		t.Fatal(err)
	}
	assertBlocked(t, store, "example.com", "", false)
	if err := store.RemoveBlock(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second removal = %v", err)
	}
	nextID := addTestBlock(t, store, "domain", "other.com", time.Time{})
	if nextID <= id {
		t.Fatal("removed block identifiers must not be reused")
	}
	var adds, removes int
	if err := store.db.QueryRow("SELECT count(*) FROM block_audit WHERE operation='add'").Scan(&adds); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM block_audit WHERE operation='remove'").Scan(&removes); err != nil {
		t.Fatal(err)
	}
	if adds != 2 || removes != 1 {
		t.Fatalf("audit adds=%d removes=%d", adds, removes)
	}
}

func TestWildcardLabelBoundaries(t *testing.T) {
	store, _ := openTestStore(t, testLimits)
	addTestBlock(t, store, "wildcard", "*.Example.com.", time.Time{})
	for _, host := range []string{"example.com", "a.example.com", "a.b.example.com"} {
		assertBlocked(t, store, host, "", true)
	}
	for _, host := range []string{"notexample.com", "example.com.evil.net", "other.com"} {
		assertBlocked(t, store, host, "", false)
	}
	second, _ := openTestStore(t, testLimits)
	addTestBlock(t, second, "wildcard", "*.www.example.com", time.Time{})
	assertBlocked(t, second, "example.com", "", false)
	assertBlocked(t, second, "www.example.com", "", true)
}

func TestSourceIPAndCIDRBlocks(t *testing.T) {
	tests := []struct {
		kind, value, canonical string
		match, miss            []string
	}{
		{"ip", "::ffff:192.0.2.1", "192.0.2.1", []string{"192.0.2.1", "::ffff:192.0.2.1"}, []string{"192.0.2.2", "2001:db8::1"}},
		{"ip", "2001:0db8::1", "2001:db8::1", []string{"2001:db8::1"}, []string{"2001:db8::2", "2001:db8::1%eth0"}},
		{"cidr", "192.0.2.45/24", "192.0.2.0/24", []string{"192.0.2.1", "::ffff:192.0.2.2"}, []string{"192.0.3.1"}},
		{"cidr", "::ffff:192.0.2.45/120", "192.0.2.0/24", []string{"192.0.2.1", "::ffff:192.0.2.2"}, []string{"192.0.3.1"}},
		{"cidr", "2001:db8:abcd::1/48", "2001:db8:abcd::/48", []string{"2001:db8:abcd:1::1"}, []string{"2001:db8:abce::1", "2001:db8:abcd::1%eth0"}},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			store, _ := openTestStore(t, testLimits)
			addTestBlock(t, store, tt.kind, tt.value, time.Time{})
			for _, ip := range tt.match {
				assertBlocked(t, store, "", ip, true)
				assertBlocked(t, store, "example.com", ip, true)
			}
			for _, ip := range tt.miss {
				assertBlocked(t, store, "", ip, false)
			}
			assertBlocked(t, store, "example.com", "", false)
			blocks, err := store.ListBlocks(context.Background())
			if err != nil || blocks[0].Value != tt.canonical {
				t.Fatalf("canonical block = %#v, %v", blocks, err)
			}
			if err := store.ReserveAdmission(context.Background(), "example.com"); err != nil {
				t.Fatalf("IP block must not affect cert admission: %v", err)
			}
		})
	}
}

func TestBlockValidationAndParameterization(t *testing.T) {
	store, _ := openTestStore(t, testLimits)
	for _, tt := range []struct{ kind, value string }{
		{"domain", "*"}, {"domain", "example.com'; DROP TABLE blocks; --"},
		{"domain", "https://example.com"}, {"domain", "example..com"}, {"domain", "localhost"},
		{"wildcard", "*"}, {"wildcard", "*com"}, {"wildcard", "*.*.example.com"},
		{"wildcard", "*.com"}, {"ip", "nope"}, {"ip", "fe80::1%eth0"},
		{"cidr", "fe80::%eth0/64"}, {"cidr", "::ffff:192.0.2.1/80"},
		{"cidr", "192.0.2.1/33"}, {"unknown", "example.com"},
	} {
		t.Run(tt.kind+tt.value, func(t *testing.T) {
			if _, err := store.AddBlock(context.Background(), Block{Kind: tt.kind, Value: tt.value, Reason: "abuse", Operator: "tester"}); err == nil {
				t.Fatalf("accepted invalid %s block %q", tt.kind, tt.value)
			}
		})
	}
	for _, b := range []Block{
		{Kind: "domain", Value: "example.com", Reason: " ", Operator: "tester"},
		{Kind: "domain", Value: "example.com", Reason: "abuse", Operator: "---"},
		{Kind: "domain", Value: "example.com", Reason: "abuse", Operator: "tester", ExpiresAt: time.Unix(1, 0)},
		{Kind: "domain", Value: "example.com", Reason: "abuse", Operator: "tester", ExpiresAt: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		if _, err := store.AddBlock(context.Background(), b); err == nil {
			t.Fatal("accepted invalid block metadata/expiry")
		}
	}
	metadata := "operator'; DROP TABLE blocks; --"
	if _, err := store.AddBlock(context.Background(), Block{
		Kind: "domain", Value: "bücher.de", Reason: metadata, Operator: metadata,
	}); err != nil {
		t.Fatal(err)
	}
	assertBlocked(t, store, "xn--bcher-kva.de", "", true)
	blocks, err := store.ListBlocks(context.Background())
	if err != nil || len(blocks) != 1 || blocks[0].Reason != metadata || blocks[0].Operator != metadata {
		t.Fatalf("parameterized metadata = %#v, %v", blocks, err)
	}
}

func TestBlockExpiryAndLiveChangesAcrossStores(t *testing.T) {
	ctx := context.Background()
	first, path := openTestStore(t, testLimits)
	second, err := Open(path, testLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	now := time.Now().UTC()
	first.now = func() time.Time { return now }
	second.now = func() time.Time { return now }
	assertBlocked(t, second, "example.com", "", false)
	id := addTestBlock(t, first, "domain", "example.com", now.Add(time.Second))
	assertBlocked(t, second, "example.com", "", true)
	if err := second.ReserveAdmission(ctx, "example.com"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("live block reservation = %v", err)
	}
	now = now.Add(time.Second)
	assertBlocked(t, second, "example.com", "", false)
	if err := second.ReserveAdmission(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := first.RemoveBlock(ctx, id); err != nil {
		t.Fatal(err)
	}
	id = addTestBlock(t, first, "domain", "example.com", time.Time{})
	if err := second.ReserveAdmission(ctx, "example.com"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("existing admission must honor new block: %v", err)
	}
	if err := first.RemoveBlock(ctx, id); err != nil {
		t.Fatal(err)
	}
	assertBlocked(t, second, "example.com", "", false)
}

func TestRestartAndBudgetSurvivesForget(t *testing.T) {
	ctx := context.Background()
	limits := Limits{MaxDomains: 2, AdmissionsPerWindow: 1, Window: time.Hour}
	store, path := openTestStore(t, limits)
	now := time.Now().UTC()
	store.now = func() time.Time { return now }
	if err := store.ReserveAdmission(ctx, "EXAMPLE.COM."); err != nil {
		t.Fatal(err)
	}
	if err := store.ReserveAdmission(ctx, "example.com"); err != nil {
		t.Fatalf("idempotent reservation: %v", err)
	}
	if err := store.ForgetAdmission(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := store.ForgetAdmission(ctx, "example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("forget missing = %v", err)
	}
	addTestBlock(t, store, "domain", "blocked.com", time.Time{})
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.now = func() time.Time { return now }
	assertBlocked(t, store, "blocked.com", "", true)
	for _, host := range []string{"example.com", "other.com"} {
		if err := store.ReserveAdmission(ctx, host); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("persisted budget for %q = %v", host, err)
		}
	}
	now = now.Add(time.Hour)
	if err := store.ReserveAdmission(ctx, "other.com"); err != nil {
		t.Fatalf("expired sliding window = %v", err)
	}
	admissions, err := store.ListAdmissions(ctx)
	if err != nil || len(admissions) != 1 || admissions[0].Domain != "other.com" || !admissions[0].CreatedAt.Equal(now) {
		t.Fatalf("admissions = %#v, %v", admissions, err)
	}
}

func TestConcurrentReservationsAcrossStores(t *testing.T) {
	ctx := context.Background()
	limits := Limits{MaxDomains: 1, AdmissionsPerWindow: 1, Window: time.Hour}
	first, path := openTestStore(t, limits)
	second, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	stores := []*Store{first, second}
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < cap(errs); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- stores[i%2].ReserveAdmission(ctx, "example.com")
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("duplicate reservation race: %v", err)
		}
	}
	var count int
	if err := first.db.QueryRow("SELECT count(*) FROM admission_events").Scan(&count); err != nil || count != 1 {
		t.Fatalf("budget events = %d, %v", count, err)
	}
	if err := first.ReserveAdmission(ctx, "other.com"); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity = %v", err)
	}
	if err := first.ForgetAdmission(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := second.ReserveAdmission(ctx, "other.com"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("forget must retain budget = %v", err)
	}
}

func TestConcurrentDifferentDomainBudgets(t *testing.T) {
	for _, limits := range []Limits{
		{MaxDomains: 1, AdmissionsPerWindow: 10, Window: time.Hour},
		{MaxDomains: 10, AdmissionsPerWindow: 1, Window: time.Hour},
	} {
		first, path := openTestStore(t, limits)
		second, err := Open(path, limits)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		result := make(chan error, 2)
		go func() { <-start; result <- first.ReserveAdmission(context.Background(), "example.com") }()
		go func() { <-start; result <- second.ReserveAdmission(context.Background(), "other.com") }()
		close(start)
		var successes, denials int
		for i := 0; i < 2; i++ {
			err := <-result
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrCapacity), errors.Is(err, ErrRateLimited):
				denials++
			default:
				t.Fatalf("reservation race = %v", err)
			}
		}
		second.Close()
		if successes != 1 || denials != 1 {
			t.Fatalf("race successes=%d denials=%d", successes, denials)
		}
	}
}

func TestConcurrentOpenAndMigration(t *testing.T) {
	path := filepath.Join(testDirectory(t), "private", "state.db")
	start := make(chan struct{})
	type result struct {
		store *Store
		err   error
	}
	results := make(chan result, 8)
	for i := 0; i < cap(results); i++ {
		go func() {
			<-start
			store, err := Open(path, testLimits)
			results <- result{store, err}
		}()
	}
	close(start)
	for i := 0; i < cap(results); i++ {
		r := <-results
		if r.err != nil {
			t.Errorf("concurrent open: %v", r.err)
		} else {
			r.store.Close()
		}
	}
}

func TestProtectedDatabasePath(t *testing.T) {
	root := testDirectory(t)
	for _, path := range []string{"", ":memory:"} {
		if store, err := Open(path, testLimits); err == nil {
			store.Close()
			t.Fatalf("accepted unsafe path %q", path)
		}
	}
	public := filepath.Join(root, "public")
	if err := os.Mkdir(public, 0755); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(filepath.Join(public, "state.db"), testLimits); err == nil {
		store.Close()
		t.Fatal("accepted public containing directory")
	}
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(private, "state.db")
	if err := os.WriteFile(dbPath, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(dbPath, testLimits); err == nil {
		store.Close()
		t.Fatal("accepted public DB")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(filepath.Join(link, "other.db"), testLimits); err == nil {
		store.Close()
		t.Fatal("accepted symlink directory")
	}
	fileLink := filepath.Join(private, "linked.db")
	if err := os.Symlink(dbPath, fileLink); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(fileLink, testLimits); err == nil {
		store.Close()
		t.Fatal("accepted symlink file")
	}
	good, path := openTestStore(t, testLimits)
	if err := good.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Dir(path), path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(name)
		want := os.FileMode(0600)
		if name == filepath.Dir(path) {
			want = 0700
		}
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("protected path mode %q: %#v, %v", name, info, err)
		}
	}
}

func TestStoreErrorsAndSchemaSafety(t *testing.T) {
	if store, err := Open(filepath.Join(testDirectory(t), "bad.db"), Limits{}); err == nil {
		store.Close()
		t.Fatal("accepted invalid limits")
	}
	ctx := context.Background()
	store, path := openTestStore(t, testLimits)
	if err := store.ReserveAdmission(ctx, "bad host"); err == nil {
		t.Fatal("accepted invalid admission")
	}
	if err := store.ForgetAdmission(ctx, "bad host"); err == nil {
		t.Fatal("accepted invalid forget domain")
	}
	if _, err := store.CheckBlocked(ctx, "bad host", netip.Addr{}); err == nil {
		t.Fatal("accepted invalid block-check domain")
	}
	if _, err := store.db.Exec("PRAGMA user_version=2"); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if reopened, err := Open(path, testLimits); err == nil {
		reopened.Close()
		t.Fatal("accepted unknown newer schema")
	}
	if err := store.Ping(ctx); err == nil {
		t.Fatal("closed store reports healthy")
	}
	if _, err := store.ListBlocks(ctx); err == nil {
		t.Fatal("closed store lists blocks")
	}
	if err := store.ReserveAdmission(ctx, "example.com"); err == nil {
		t.Fatal("closed store reserves admission")
	}
}

func TestRefusesUnrecognizedExistingDatabase(t *testing.T) {
	store, path := openTestStore(t, testLimits)
	if _, err := store.db.Exec("PRAGMA user_version=0"); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if reopened, err := Open(path, testLimits); err == nil {
		reopened.Close()
		t.Fatal("silently migrated an unrecognized existing database")
	}
}
