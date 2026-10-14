// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	json "encoding/json/v2"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
)

// Shared member roster (DESIGN.md §5.2). One publisher (usually the granter)
// seals the current non-revoked membership — fingerprint, name, and keys per
// member — under the repository data key and signs the seal, storing it at
// the single key MembersKey. Any member opens it with the master they
// already hold, verifies the publisher against their own trust list, and
// adopts the entries: onboarding a new machine costs one human check (the
// granter/publisher) instead of one per member.
//
// The roster proposes trust, never access: slots still gate every byte, so
// replaying the file into another repository only re-asserts the same
// people. What it does not do: exclude a member revoked after export
// (re-publish on every trust change), or hide membership from ex-members
// (they hold the master forever, §4.6). Adopting is explicit per `members
// sync` run and logged, never silent.

// MembersVersion is the roster payload format version.
const MembersVersion = 1

// MembersKey is the single repository key holding the published roster.
// One publisher per repository avoids lost-update races between concurrent
// publishers; readers tolerate a missing or stale file.
const MembersKey = "members.json"

// membersPayload is the sealed bytes: base64 public files of every
// non-revoked member in the publisher's view.
type membersPayload struct {
	Version    int       `json:"version"`
	Publisher  string    `json:"publisher"`
	ExportedAt time.Time `json:"exported_at"`
	Members    []string  `json:"members"`
}

// membersEnvelope stores the publisher hint (plaintext, like a slot's
// granter hint) with the sealed payload bytes and the publisher's signature
// over the sealed bytes. The hint is never trusted: after opening, the
// payload must name the same publisher, and the signature must verify with
// the looked-up key.
type membersEnvelope struct {
	Publisher string `json:"publisher"`
	Sealed    string `json:"sealed"`
	Signature string `json:"signature"`
}

// MembersSummary reports what one sync adopted.
type MembersSummary struct {
	// Publisher is the roster publisher the record was verified for.
	Publisher Fingerprint
	// ExportedAt is when the roster was published.
	ExportedAt time.Time
	// Adopted counts newly trusted members (already-trusted ones stay).
	Adopted int
}

// PublishMembers seals the publisher's current non-revoked membership under
// dataKey with associated data binding the repository and publisher, signs
// the seal, and returns the envelope bytes. now supplies the export time;
// nil means time.Now.
func PublishMembers(publisher *PrivateIdentity, trust *TrustStore, dataKey crypto.SecretKey, repositoryID string, now func() time.Time) ([]byte, error) {
	if publisher == nil {
		return nil, errors.New("publish members: publisher is nil")
	}
	if trust == nil {
		return nil, errors.New("publish members: trust store is nil")
	}
	if now == nil {
		now = time.Now
	}
	listed, err := trust.List()
	if err != nil {
		return nil, err
	}
	payload := membersPayload{
		Version:    MembersVersion,
		Publisher:  publisher.Fingerprint().String(),
		ExportedAt: now().UTC(),
	}
	for _, id := range listed {
		revoked, err := trust.IsRevoked(id.Fingerprint)
		if err != nil {
			return nil, err
		}
		if revoked {
			continue
		}
		pub, err := MarshalPublic(&id)
		if err != nil {
			return nil, err
		}
		payload.Members = append(payload.Members, base64.StdEncoding.EncodeToString(pub))
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal members: %w", err)
	}
	ad := crypto.AssociatedData(repositoryID, "members", publisher.Fingerprint().String())
	sealed, err := dataKey.Seal(raw, ad)
	if err != nil {
		return nil, fmt.Errorf("seal members: %w", err)
	}
	sig, err := publisher.Sign(crypto.ContextMembers, sealed)
	if err != nil {
		return nil, err
	}
	return json.Marshal(membersEnvelope{
		Publisher: publisher.Fingerprint().String(),
		Sealed:    base64.StdEncoding.EncodeToString(sealed),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
}

// AdoptMembers opens the roster envelope with dataKey, resolves the
// publisher's signing key through lookup applied to the envelope's unverified
// hint, verifies the signature, and trusts every listed member. Lookup
// failures propagate verbatim so callers return ErrUntrustedSigner for
// unknown publishers; the publisher must additionally be currently trusted,
// otherwise adoption is refused. Entries naming locally revoked members are
// skipped, never re-trusted. A bad seal wraps ErrAuthFailed; a bad signature
// wraps ErrBadSignature.
func AdoptMembers(envBytes []byte, dataKey crypto.SecretKey, repositoryID string, store *TrustStore, lookup func(publisher string) ([]byte, error)) (*MembersSummary, error) {
	if store == nil {
		return nil, errors.New("adopt members: trust store is nil")
	}
	if lookup == nil {
		return nil, errors.New("adopt members: lookup is nil")
	}
	hint, sealed, sig, err := parseMembersEnvelope(envBytes)
	if err != nil {
		return nil, err
	}
	publisherPub, err := lookup(hint)
	if err != nil {
		return nil, err
	}
	if err := Verify(publisherPub, crypto.ContextMembers, sealed, sig); err != nil {
		return nil, err
	}
	publisher, err := ParseFingerprint(hint)
	if err != nil {
		return nil, fmt.Errorf("adopt members: %w", err)
	}
	trusted, err := store.IsTrusted(publisher)
	if err != nil {
		return nil, err
	}
	if !trusted {
		return nil, fmt.Errorf("%w: roster publisher %s", pverrors.ErrUntrustedSigner, publisher.Grouped())
	}
	ad := crypto.AssociatedData(repositoryID, "members", hint)
	raw, err := dataKey.Open(sealed, ad)
	if err != nil {
		return nil, fmt.Errorf("adopt members: %w", err)
	}
	list, err := parseMembersPayload(raw)
	if err != nil {
		return nil, err
	}
	if list.publisher.String() != hint {
		return nil, fmt.Errorf("%w: roster names publisher %s, envelope hint %s", pverrors.ErrIntegrity, list.publisher.Grouped(), hint)
	}
	adopted := 0
	for _, raw := range list.members {
		pub, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: roster holds a bad identity", pverrors.ErrIntegrity)
		}
		id, err := ParsePublic(pub)
		if err != nil {
			return nil, fmt.Errorf("adopt members: %w", err)
		}
		if revoked, err := store.IsRevoked(id.Fingerprint); err != nil {
			return nil, err
		} else if revoked {
			continue
		}
		already, err := store.IsTrusted(id.Fingerprint)
		if err != nil {
			return nil, err
		}
		if err := store.Add(id); err != nil {
			return nil, fmt.Errorf("adopt members: %w", err)
		}
		if !already {
			adopted++
		}
	}
	return &MembersSummary{
		Publisher:  publisher,
		ExportedAt: list.exportedAt,
		Adopted:    adopted,
	}, nil
}

// parsedMembers is a decoded roster payload.
type parsedMembers struct {
	publisher  Fingerprint
	exportedAt time.Time
	members    []string
}

func parseMembersEnvelope(envBytes []byte) (hint string, sealed, sig []byte, err error) {
	var env membersEnvelope
	if err := json.Unmarshal(envBytes, &env, json.RejectUnknownMembers(true)); err != nil {
		return "", nil, nil, fmt.Errorf("decode members: %w", err)
	}
	if _, err := ParseFingerprint(env.Publisher); err != nil {
		return "", nil, nil, fmt.Errorf("decode members: %w", err)
	}
	sealed, err = base64.StdEncoding.DecodeString(env.Sealed)
	if err != nil || len(sealed) == 0 {
		return "", nil, nil, fmt.Errorf("decode members: %w: invalid seal", pverrors.ErrIntegrity)
	}
	sig, err = base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != SignSignatureSize {
		return "", nil, nil, fmt.Errorf("decode members: %w: invalid signature", pverrors.ErrIntegrity)
	}
	return env.Publisher, sealed, sig, nil
}

func parseMembersPayload(raw []byte) (*parsedMembers, error) {
	var wire membersPayload
	if err := json.Unmarshal(raw, &wire, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("decode members: %w", err)
	}
	if wire.Version != MembersVersion {
		return nil, fmt.Errorf("decode members: unsupported version %d: want %d", wire.Version, MembersVersion)
	}
	publisher, err := ParseFingerprint(wire.Publisher)
	if err != nil {
		return nil, fmt.Errorf("decode members: %w", err)
	}
	if wire.ExportedAt.IsZero() {
		return nil, errors.New("decode members: exported_at is missing")
	}
	return &parsedMembers{
		publisher:  publisher,
		exportedAt: wire.ExportedAt.UTC(),
		members:    wire.Members,
	}, nil
}
