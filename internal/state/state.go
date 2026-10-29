// Package state stores private operator policy and admission reservations.
package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"mc-apex-redirect/internal/domain"

	"modernc.org/sqlite"
)

var (
	ErrBlocked     = errors.New("domain is blocked")
	ErrCapacity    = errors.New("active domain capacity reached")
	ErrRateLimited = errors.New("new domain admission budget reached")
	ErrNotFound    = errors.New("record not found")
)

type Limits struct {
	MaxDomains          int
	AdmissionsPerWindow int
	Window              time.Duration
}

type Block struct {
	ID        int64
	Kind      string
	Value     string
	Reason    string
	Operator  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Admission struct {
	Domain    string
	CreatedAt time.Time
}

type Store struct {
	db     *sql.DB
	limits Limits
	now    func() time.Time
}

// Open creates a private local store, or opens an existing private database.
// Admission events count reservations, not ACME orders or issued certificates.
func Open(path string, limits Limits) (*Store, error) {
	if limits.MaxDomains <= 0 || limits.AdmissionsPerWindow <= 0 || limits.Window <= 0 {
		return nil, errors.New("state limits and window must be positive")
	}
	path, err := protectedPath(path)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Set("_txlock", "immediate")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, errors.New("open state database")
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, limits: limits, now: time.Now}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = s.initialize(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func protectedPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" || path == ":memory:" {
		return "", errors.New("state requires a persistent database path")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("invalid state path")
	}
	parent := filepath.Dir(absolute)
	// Reject symlinks in existing path components before creating anything.
	for current := absolute; ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("state path must not contain symlinks")
		}
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return "", errors.New("cannot inspect state path")
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	if err := os.MkdirAll(parent, 0700); err != nil {
		return "", errors.New("create private state directory")
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", errors.New("state directory must have mode 0700")
	}
	file, err := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		if err = file.Close(); err != nil {
			return "", errors.New("close new state database")
		}
	} else if !errors.Is(err, os.ErrExist) {
		return "", errors.New("create state database")
	}
	for _, name := range []string{absolute, absolute + "-wal", absolute + "-shm", absolute + "-journal"} {
		info, err = os.Lstat(name)
		if errors.Is(err, os.ErrNotExist) && name != absolute {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return "", errors.New("state database and sidecars must be regular files with mode 0600")
		}
	}
	return absolute, nil
}

func (s *Store) initialize(ctx context.Context) error {
	// SQLite's journal-mode transition can return BUSY without honoring the busy
	// timeout while another process initializes the same new database.
	for {
		var journal string
		err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journal)
		if err == nil {
			if journal != "wal" {
				return errors.New("enable state WAL")
			}
			break
		}
		var sqliteErr *sqlite.Error
		if !errors.As(err, &sqliteErr) || (sqliteErr.Code()&0xff != 5 && sqliteErr.Code()&0xff != 6) {
			return errors.New("enable state WAL")
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.New("timed out enabling state WAL")
		case <-timer.C:
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("begin state migration")
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return errors.New("read state schema version")
	}
	if version < 0 || version > 1 {
		return errors.New("state database uses an unsupported schema")
	}
	if version == 0 {
		var tables int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil || tables != 0 {
			return errors.New("refusing to initialize an unrecognized state database")
		}
		if _, err := tx.ExecContext(ctx, `
CREATE TABLE blocks (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 kind TEXT NOT NULL CHECK(kind IN ('domain','wildcard','ip','cidr')),
 value TEXT NOT NULL,
 reason TEXT NOT NULL,
 operator TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER
);
CREATE TABLE block_audit (
 id INTEGER PRIMARY KEY,
 operation TEXT NOT NULL CHECK(operation IN ('add','remove')),
 block_id INTEGER NOT NULL,
 kind TEXT NOT NULL,
 value TEXT NOT NULL,
 reason TEXT NOT NULL,
 operator TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER,
 recorded_at INTEGER NOT NULL
);
CREATE TABLE admissions (
 domain TEXT PRIMARY KEY,
 created_at INTEGER NOT NULL
);
CREATE TABLE admission_events (
 id INTEGER PRIMARY KEY,
 domain TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE INDEX admission_events_time ON admission_events(created_at);
PRAGMA user_version=1;`); err != nil {
			return errors.New("initialize state schema")
		}
	}
	if err := tx.Commit(); err != nil {
		return errors.New("commit state migration")
	}
	return nil
}

func (s *Store) Close() error                   { return s.db.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func normalizeBlock(b Block) (Block, error) {
	b.Reason = strings.TrimSpace(b.Reason)
	b.Operator = strings.TrimSpace(b.Operator)
	if !meaningful(b.Reason) || !meaningful(b.Operator) || len(b.Reason) > 4096 || len(b.Operator) > 256 {
		return Block{}, errors.New("block requires meaningful reason and operator metadata")
	}
	var err error
	switch b.Kind {
	case "domain":
		b.Value, err = domain.Normalize(b.Value)
	case "wildcard":
		if !strings.HasPrefix(b.Value, "*.") {
			return Block{}, errors.New("wildcard must start with '*.'")
		}
		var host string
		host, err = domain.Normalize(strings.TrimPrefix(b.Value, "*."))
		if err == nil {
			b.Value = "*." + host
		}
	case "ip":
		var addr netip.Addr
		addr, err = netip.ParseAddr(b.Value)
		if err == nil {
			if addr.Zone() != "" {
				err = errors.New("zoned IP addresses are unsupported")
			} else {
				b.Value = addr.Unmap().String()
			}
		}
	case "cidr":
		var prefix netip.Prefix
		prefix, err = netip.ParsePrefix(b.Value)
		if err == nil {
			addr := prefix.Addr()
			bits := prefix.Bits()
			if addr.Is4In6() {
				if bits < 96 {
					return Block{}, errors.New("mapped IPv4 CIDR must have at least 96 prefix bits")
				}
				prefix = netip.PrefixFrom(addr.Unmap(), bits-96)
			}
			b.Value = prefix.Masked().String()
		}
	default:
		return Block{}, errors.New("unsupported block kind")
	}
	if err != nil {
		return Block{}, errors.New("invalid block value")
	}
	return b, nil
}

func meaningful(value string) bool {
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			return true
		}
	}
	return false
}

func expiryValue(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().UnixNano()
}

func (s *Store) AddBlock(ctx context.Context, b Block) (int64, error) {
	b, err := normalizeBlock(b)
	if err != nil {
		return 0, err
	}
	b.CreatedAt = s.now().UTC()
	if !b.ExpiresAt.IsZero() && !b.ExpiresAt.After(b.CreatedAt) {
		return 0, errors.New("block expiry must be in the future")
	}
	if !b.ExpiresAt.IsZero() && !time.Unix(0, b.ExpiresAt.UnixNano()).Equal(b.ExpiresAt) {
		return 0, errors.New("block expiry is outside the supported timestamp range")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, errors.New("begin block update")
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "INSERT INTO blocks(kind,value,reason,operator,created_at,expires_at) VALUES(?,?,?,?,?,?)",
		b.Kind, b.Value, b.Reason, b.Operator, b.CreatedAt.UnixNano(), expiryValue(b.ExpiresAt))
	if err != nil {
		return 0, errors.New("save block")
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, errors.New("read block identifier")
	}
	if err := auditBlock(ctx, tx, "add", id, b.CreatedAt); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, errors.New("commit block update")
	}
	return id, nil
}

func auditBlock(ctx context.Context, tx *sql.Tx, operation string, id int64, now time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO block_audit(operation,block_id,kind,value,reason,operator,created_at,expires_at,recorded_at)
SELECT ?,id,kind,value,reason,operator,created_at,expires_at,? FROM blocks WHERE id=?`, operation, now.UTC().UnixNano(), id)
	if err != nil {
		return errors.New("save private block audit")
	}
	return nil
}

func (s *Store) RemoveBlock(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("begin block removal")
	}
	defer tx.Rollback()
	if err := auditBlock(ctx, tx, "remove", id, s.now()); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM blocks WHERE id=?", id)
	if err != nil {
		return errors.New("remove block")
	}
	n, err := result.RowsAffected()
	if err != nil {
		return errors.New("read block removal count")
	}
	if n == 0 {
		return ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return errors.New("commit block removal")
	}
	return nil
}

type querier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func listBlocks(ctx context.Context, q querier) ([]Block, error) {
	rows, err := q.QueryContext(ctx, "SELECT id,kind,value,reason,operator,created_at,expires_at FROM blocks ORDER BY id")
	if err != nil {
		return nil, errors.New("list blocks")
	}
	defer rows.Close()
	blocks := make([]Block, 0)
	for rows.Next() {
		var b Block
		var created int64
		var expiry sql.NullInt64
		if err := rows.Scan(&b.ID, &b.Kind, &b.Value, &b.Reason, &b.Operator, &created, &expiry); err != nil {
			return nil, errors.New("read block")
		}
		b.CreatedAt = time.Unix(0, created).UTC()
		if expiry.Valid {
			b.ExpiresAt = time.Unix(0, expiry.Int64).UTC()
		}
		blocks = append(blocks, b)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("read blocks")
	}
	return blocks, nil
}

// ListBlocks includes expired blocks so operators can inspect retained policy.
func (s *Store) ListBlocks(ctx context.Context) ([]Block, error) {
	return listBlocks(ctx, s.db)
}

func checkBlocked(ctx context.Context, q querier, apex string, client netip.Addr, now time.Time) (bool, error) {
	blocks, err := listBlocks(ctx, q)
	if err != nil {
		return false, err
	}
	client = client.Unmap()
	for _, b := range blocks {
		if !b.ExpiresAt.IsZero() && !now.Before(b.ExpiresAt) {
			continue
		}
		switch b.Kind {
		case "domain":
			if apex != "" && (b.Value == apex || b.Value == "www."+apex) {
				return true, nil
			}
		case "wildcard":
			suffix := strings.TrimPrefix(b.Value, "*")
			if apex != "" && (strings.HasSuffix(apex, suffix) || strings.HasSuffix("www."+apex, suffix)) {
				return true, nil
			}
		case "ip":
			addr, err := netip.ParseAddr(b.Value)
			if err != nil {
				return false, errors.New("invalid stored IP block")
			}
			if client.IsValid() && client.Zone() == "" && client == addr {
				return true, nil
			}
		case "cidr":
			prefix, err := netip.ParsePrefix(b.Value)
			if err != nil {
				return false, errors.New("invalid stored network block")
			}
			if client.IsValid() && client.Zone() == "" && prefix.Contains(client) {
				return true, nil
			}
		default:
			return false, errors.New("invalid stored block kind")
		}
	}
	return false, nil
}

func (s *Store) CheckBlocked(ctx context.Context, apex string, client netip.Addr) (bool, error) {
	if apex != "" {
		var err error
		apex, err = domain.Normalize(apex)
		if err != nil {
			return false, errors.New("invalid domain for block check")
		}
	}
	return checkBlocked(ctx, s.db, apex, client, s.now())
}

// ReserveAdmission atomically checks current domain policy and reserves capacity
// and a sliding-window event. Forgetting active capacity never erases events.
func (s *Store) ReserveAdmission(ctx context.Context, apex string) error {
	apex, err := domain.Normalize(apex)
	if err != nil {
		return errors.New("invalid admission domain")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("begin admission reservation")
	}
	defer tx.Rollback()
	now := s.now().UTC()
	blocked, err := checkBlocked(ctx, tx, apex, netip.Addr{}, now)
	if err != nil {
		return err
	}
	if blocked {
		return ErrBlocked
	}
	var known int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM admissions WHERE domain=?", apex).Scan(&known); err != nil {
		return errors.New("check existing admission")
	}
	if known != 0 {
		return tx.Commit()
	}
	var active int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM admissions").Scan(&active); err != nil {
		return errors.New("count active admissions")
	}
	if active >= s.limits.MaxDomains {
		return ErrCapacity
	}
	cutoff := now.Add(-s.limits.Window).UnixNano()
	var recent int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM admission_events WHERE created_at>?", cutoff).Scan(&recent); err != nil {
		return errors.New("count admission budget")
	}
	if recent >= s.limits.AdmissionsPerWindow {
		return ErrRateLimited
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO admissions(domain,created_at) VALUES(?,?)", apex, now.UnixNano()); err != nil {
		return errors.New("reserve active domain")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO admission_events(domain,created_at) VALUES(?,?)", apex, now.UnixNano()); err != nil {
		return errors.New("reserve admission budget")
	}
	// Only obsolete history is pruned; current-window events survive removal.
	if _, err := tx.ExecContext(ctx, "DELETE FROM admission_events WHERE created_at<=?", cutoff); err != nil {
		return errors.New("prune expired admission events")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("commit admission reservation")
	}
	return nil
}

func (s *Store) ListAdmissions(ctx context.Context) ([]Admission, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT domain,created_at FROM admissions ORDER BY domain")
	if err != nil {
		return nil, errors.New("list admissions")
	}
	defer rows.Close()
	admissions := make([]Admission, 0)
	for rows.Next() {
		var a Admission
		var created int64
		if err := rows.Scan(&a.Domain, &created); err != nil {
			return nil, errors.New("read admission")
		}
		a.CreatedAt = time.Unix(0, created).UTC()
		admissions = append(admissions, a)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("read admissions")
	}
	return admissions, nil
}

func (s *Store) ForgetAdmission(ctx context.Context, name string) error {
	name, err := domain.Normalize(name)
	if err != nil {
		return errors.New("invalid admission domain")
	}
	result, err := s.db.ExecContext(ctx, "DELETE FROM admissions WHERE domain=?", name)
	if err != nil {
		return errors.New("forget active admission")
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read forgotten admission count: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}
