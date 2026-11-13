package process

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"path/filepath"
	"slices"

	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/scanbudget"
	"github.com/cplieger/go/filesafe"
)

// claimsFile is the flat layout's ownership record, at the root of /output. A
// flat artifact's name keeps only the last directory and the file name of its
// source, so without the record a new process cannot tell which input a flat
// artifact belongs to. The mirror layout writes none: there an artifact's path
// names its source.
const claimsFile = ".cert-converter-claims.json"

// claimsVersion is the record format this build reads and writes.
const claimsVersion = 1

// claimsPathBytes bounds one path as the record stores it: PATH_MAX, times the
// six bytes encoding/json may spend escaping one byte (\u00XX), plus the quotes,
// separators and field names around it.
const claimsPathBytes = 6*4096 + 64

// claimsCeiling bounds the record for an /input walk of maxEntries entries: each
// enumerated source appears at most once as a stem key, once as a member and once
// as an owner, so a record for any tree one scan can enumerate fits.
func claimsCeiling(maxEntries int) int64 {
	return int64(scanbudget.Effective(maxEntries))*3*claimsPathBytes + claimsPathBytes
}

// stemClaim is one flat output stem's entry in the ownership record: its
// claimant ledger (rules of claimLedger) and the input whose conversion wrote
// or verified its artifacts.
type stemClaim struct {
	Owner   string   `json:"owner,omitempty"`
	Members []string `json:"members"`
}

// claimRecord is the ownership record as it is stored.
type claimRecord struct {
	Stems   map[string]stemClaim `json:"stems"`
	Version int                  `json:"version"`
}

// encodeClaims renders claims in the stored form. Members are kept sorted and
// encoding/json sorts the map, so equal records encode to equal bytes, which is
// how persistClaims tells a change.
func encodeClaims(claims map[string]stemClaim) ([]byte, error) {
	if claims == nil {
		claims = map[string]stemClaim{}
	}
	return json.Marshal(claimRecord{Version: claimsVersion, Stems: claims})
}

// errClaimsInvalid marks a record that decoded but does not describe a flat tree.
var errClaimsInvalid = errors.New("invalid ownership record")

// decodeClaims parses and validates a stored record. Any invalid entry rejects
// the whole record: a partly trusted record would protect or reap on a guess.
func decodeClaims(data []byte) (map[string]stemClaim, error) {
	var record claimRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	if record.Version != claimsVersion {
		return nil, fmt.Errorf("%w: version %d, want %d", errClaimsInvalid, record.Version, claimsVersion)
	}
	for stem, claim := range record.Stems {
		if err := validClaim(stem, claim); err != nil {
			return nil, err
		}
	}
	if record.Stems == nil {
		record.Stems = map[string]stemClaim{}
	}
	return record.Stems, nil
}

func validClaim(stem string, claim stemClaim) error {
	if !cleanLocal(stem) || len(claim.Members) == 0 || !slices.IsSorted(claim.Members) {
		return fmt.Errorf("%w: stem %q", errClaimsInvalid, stem)
	}
	for i, member := range claim.Members {
		if !cleanLocal(member) || !layout.IsSource(member) || layout.FlatStem(layout.SourceStem(member)) != stem ||
			(i > 0 && claim.Members[i-1] == member) {
			return fmt.Errorf("%w: stem %q member %q", errClaimsInvalid, stem, member)
		}
	}
	if claim.Owner != "" && !slices.Contains(claim.Members, claim.Owner) {
		return fmt.Errorf("%w: stem %q owner %q is not a member", errClaimsInvalid, stem, claim.Owner)
	}
	return nil
}

func cleanLocal(rel string) bool {
	return filepath.IsLocal(rel) && path.Clean(rel) == rel
}

// readClaims reads the stored record. found is false when there is none.
func (s *store) readClaims(ctx context.Context, maxEntries int) (claims map[string]stemClaim, found bool, err error) {
	fi, err := s.root.Lstat(claimsFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false, nil
	case err != nil:
		return nil, true, err
	case !fi.Mode().IsRegular():
		return nil, true, fmt.Errorf("%w: not a regular file (%s)", errClaimsInvalid, fi.Mode().Type())
	case fi.Size() > claimsCeiling(maxEntries):
		return nil, true, fmt.Errorf("%w: %d bytes, over the %d-byte ceiling", errClaimsInvalid, fi.Size(), claimsCeiling(maxEntries))
	}
	data, err := readBoundedInRoot(ctx, s.root, claimsFile, claimsCeiling(maxEntries))
	if err != nil {
		return nil, true, err
	}
	claims, err = decodeClaims(data)
	return claims, true, err
}

// errArtifactFound stops holdsArtifacts' walk at the first artifact.
var errArtifactFound = errors.New("output artifact found")

// holdsArtifacts reports whether /output may hold an artifact of either format:
// one is there, or the bounded walk could not finish for a reason other than
// shutdown.
func (s *store) holdsArtifacts(ctx context.Context) bool {
	budget := scanbudget.NewCounter(s.maxEntries)
	every := outputpolicy.Formats{PFX: true, PEM: true}
	err := filesafe.WalkDirInRoot(ctx, s.root, func(rel string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case !budget.Charge():
			return errOutputBudgetExceeded
		case d.Type().IsRegular() && layout.IsOutputShape(rel, every):
			return errArtifactFound
		}
		return nil
	})
	return err != nil && !IsShutdown(err)
}

// claimsRebuiltMsg reports a flat start with artifacts in /output and no record.
const claimsRebuiltMsg = "the flat ownership record was missing and is rebuilt from this scan; an artifact whose input is unreachable during this scan is not protected"

// claimsUnreadableMsg reports a record the app cannot use.
const claimsUnreadableMsg = "the flat ownership record could not be used; starting from an empty record"

// claimsUnwritableMsg reports a record the app could not write.
const claimsUnwritableMsg = "the flat ownership record could not be written; this process keeps using its record in memory"

// loadClaims loads the ownership record before a flat scanner's first scan.
// Nothing about the record fails a scan or health: a record it cannot use is
// reported and replaced by the next ownership change.
func (s *Scanner) loadClaims(ctx context.Context, out *store) {
	s.claimsLoaded = true
	claims, found, err := out.readClaims(ctx, s.opts.MaxScanEntries)
	switch {
	case err != nil:
		slog.Warn(claimsUnreadableMsg,
			attrCondition, condClaimsUnreadable, "path", logtext.Path(claimsFile), "error", logtext.Path(err.Error()),
			"remediation", "delete the file; cert-converter rebuilds it")
	case !found:
		if out.holdsArtifacts(ctx) {
			slog.Warn(claimsRebuiltMsg, attrCondition, condClaimsRebuilt, "path", logtext.Path(claimsFile))
		}
	default:
		s.claims = claims
		s.claimsPersisted, _ = encodeClaims(claims)
	}
}

// persistClaims writes the ownership record when this scan changed it, and
// retries on every scan until a write succeeds. A shutdown does not stop the
// write: the ledger change it carries is already what this process acts on.
func (s *Scanner) persistClaims(ctx context.Context, out *store) {
	if s.claimsPersisted == nil && len(s.claims) == 0 {
		return
	}
	data, err := encodeClaims(s.claims)
	if err == nil && bytes.Equal(data, s.claimsPersisted) {
		return
	}
	if err == nil {
		err = out.replaceLinkAt(claimsFile)
	}
	if err == nil {
		err = out.writeBounded(context.WithoutCancel(ctx), claimsFile, data, claimsCeiling(s.opts.MaxScanEntries))
	}
	key := standingKey{kind: condClaimsUnwritable}
	if err != nil {
		level := slog.LevelDebug
		if s.standing.report(key, 1) {
			level = slog.LevelWarn
		}
		slog.Log(context.Background(), level, claimsUnwritableMsg,
			attrCondition, condClaimsUnwritable, "path", logtext.Path(claimsFile), "error", logtext.Path(err.Error()),
			"remediation", "make /output writable by the app's user; until then a restart forgets which input owns each flat artifact")
		return
	}
	s.claimsPersisted = data
	s.standing.clear(key)
}

// replaceLinkAt removes a symlink at the /output root entry rel, so the atomic
// write that follows puts a regular file there instead of refusing the link.
// Removing a link never touches its target.
func (s *store) replaceLinkAt(rel string) error {
	fi, err := s.root.Lstat(rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case fi.Mode()&fs.ModeSymlink == 0:
		return nil
	}
	return s.root.Remove(rel)
}

// ownersSnapshot returns each flat stem's owner as the record stood before this
// scan's ledger update: the reaper's owner gate reads it.
func (s *Scanner) ownersSnapshot() map[string]string {
	owners := make(map[string]string)
	for stem, claim := range s.claims {
		if claim.Owner != "" {
			owners[stem] = claim.Owner
		}
	}
	return owners
}
