package and

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"

	"github.com/google/uuid"
)

type RawANDFullPeerSessionInfo struct {
	PeerID                     string
	SessionID                  []byte
	RootCertificateDer         []byte
	HandshakeKeyCertificateDer []byte
}

func MakeRawANDFullPeerSessionInfo(peer_session ANDPeerSession) RawANDFullPeerSessionInfo {
	return RawANDFullPeerSessionInfo{
		PeerID:                     peer_session.Peer.ID(),
		SessionID:                  peer_session.SessionID[:],
		RootCertificateDer:         peer_session.Peer.RootCertificateDer(),
		HandshakeKeyCertificateDer: peer_session.Peer.HandshakeKeyCertificateDer(),
	}
}

type RawANDIdentity struct {
	PeerID    string
	SessionID []byte
}

func MakeRawANDIdentity(peer_session ANDPeerSession) RawANDIdentity {
	return RawANDIdentity{
		PeerID:    peer_session.Peer.ID(),
		SessionID: peer_session.SessionID[:],
	}
}

func MakeRawANDIdentity2(identity ANDIdentity) RawANDIdentity {
	return RawANDIdentity{
		PeerID:    identity.PeerID,
		SessionID: identity.SessionID[:],
	}
}

// AHMP message formats
// TODO: keyasint

type RawJN struct {
	SenderSessionID []byte
	Path            string
}

func (r *RawJN) TryParse() (*JN, error) {
	ssid, err := uuid.FromBytes(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	return &JN{ssid, r.Path}, nil
}
func (r RawJN) String() string {
	return fmt.Sprintf("JN{SenderSessionID: %s, Path: %s}", hex.EncodeToString(r.SenderSessionID[:4]), r.Path)
}

type RawJOK struct {
	SenderSessionID []byte
	RecverSessionID []byte
	URL             string
	Neighbors       []RawANDFullPeerSessionInfo
}

func (r *RawJOK) TryParse() (*JOK, error) {
	ssid, err := uuid.FromBytes(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.FromBytes(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	neig, _, err := functional.Filter_until_err(r.Neighbors, func(i RawANDFullPeerSessionInfo) (ANDFullPeerSessionInfo, error) {
		psid, err := uuid.FromBytes(i.SessionID)
		if err != nil {
			return ANDFullPeerSessionInfo{}, err
		}
		return ANDFullPeerSessionInfo{
			ANDIdentity: ANDIdentity{
				PeerID:    i.PeerID,
				SessionID: psid,
			},
			RootCertificateDer:         i.RootCertificateDer,
			HandshakeKeyCertificateDer: i.HandshakeKeyCertificateDer,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	return &JOK{
		SenderSessionID: ssid,
		RecverSessionID: rsid,
		URL:             r.URL,
		Neighbors:       neig,
	}, nil
}
func (r RawJOK) String() string {
	return fmt.Sprintf("JOK{SenderSessionID: %s, RecverSessionID: %s, URL: %s, Neighbors: %d}", hex.EncodeToString(r.SenderSessionID[:4]), hex.EncodeToString(r.RecverSessionID[:4]), r.URL, len(r.Neighbors))
}

type RawJNI struct {
	SenderSessionID []byte
	RecverSessionID []byte
	Joiner          RawANDFullPeerSessionInfo
	Fwd             bool
}

func (r *RawJNI) TryParse() (*JNI, error) {
	ssid, err := uuid.FromBytes(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.FromBytes(r.RecverSessionID)
	if err != nil {
		return nil, err
	}

	psid, err := uuid.FromBytes(r.Joiner.SessionID)
	if err != nil {
		return nil, err
	}
	return &JNI{
		SenderSessionID: ssid,
		RecverSessionID: rsid,
		Neighbor: ANDFullPeerSessionInfo{
			ANDIdentity: ANDIdentity{
				PeerID:    r.Joiner.PeerID,
				SessionID: psid,
			},
			RootCertificateDer:         r.Joiner.RootCertificateDer,
			HandshakeKeyCertificateDer: r.Joiner.HandshakeKeyCertificateDer,
		},
		Fwd: r.Fwd,
	}, nil
}
func (r RawJNI) String() string {
	return fmt.Sprintf("JNI{SenderSessionID: %s, RecverSessionID: %s, Joiner: %s:%s, Fwd: %t}", hex.EncodeToString(r.SenderSessionID[:4]), hex.EncodeToString(r.RecverSessionID[:4]), r.Joiner.PeerID[:8], hex.EncodeToString(r.Joiner.SessionID[:4]), r.Fwd)
}

type RawMEM struct {
	SenderSessionID []byte
	RecverSessionID []byte
}

func (r *RawMEM) TryParse() (*MEM, error) {
	ssid, err := uuid.FromBytes(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.FromBytes(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	return &MEM{ssid, rsid}, nil
}
func (r RawMEM) String() string {
	return fmt.Sprintf("MEM{SenderSessionID: %s, RecverSessionID: %s}", hex.EncodeToString(r.SenderSessionID[:4]), hex.EncodeToString(r.RecverSessionID[:4]))
}

type RawSJN struct {
	SenderSessionID []byte
	RecverSessionID []byte
	MemberInfos     []RawANDIdentity
}

func (r *RawSJN) TryParse() (*SJN, error) {
	ssid, err := uuid.FromBytes(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.FromBytes(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	infos, _, err := functional.Filter_until_err(r.MemberInfos,
		func(info_raw RawANDIdentity) (ANDIdentity, error) {
			id, err := uuid.FromBytes(info_raw.SessionID)
			return ANDIdentity{
				PeerID:    info_raw.PeerID,
				SessionID: id,
			}, err
		})
	if err != nil {
		return nil, err
	}
	return &SJN{ssid, rsid, infos}, nil
}
func (r RawSJN) String() string {
	return fmt.Sprintf("SJN{SenderSessionID: %s, RecverSessionID: %s, Members: %d}", hex.EncodeToString(r.SenderSessionID[:4]), hex.EncodeToString(r.RecverSessionID[:4]), len(r.MemberInfos))
}

type RawCRR struct {
	SenderSessionID []byte
	RecverSessionID []byte
	MemberInfos     []RawANDIdentity
}

func (r *RawCRR) TryParse() (*CRR, error) {
	ssid, err := uuid.FromBytes(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.FromBytes(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	infos, _, err := functional.Filter_until_err(r.MemberInfos,
		func(info_raw RawANDIdentity) (ANDIdentity, error) {
			id, err := uuid.FromBytes(info_raw.SessionID)
			return ANDIdentity{
				PeerID:    info_raw.PeerID,
				SessionID: id,
			}, err
		})
	if err != nil {
		return nil, err
	}
	return &CRR{ssid, rsid, infos}, nil
}
func (r RawCRR) String() string {
	return fmt.Sprintf(
		"CRR{SenderSessionID: %s, RecverSessionID: %s, Members: %s}",
		hex.EncodeToString(r.SenderSessionID[:4]),
		hex.EncodeToString(r.RecverSessionID[:4]),
		"["+strings.Join(
			functional.Filter(
				r.MemberInfos,
				func(i RawANDIdentity) string {
					return i.PeerID[:8] + ":" + hex.EncodeToString(i.SessionID[:4])
				},
			),
			", ",
		)+"]",
	)
}

type RawRST struct {
	SenderSessionID []byte
	RecverSessionID []byte
	Code            int
	Message         string
}

func (r *RawRST) TryParse() (*RST, error) {
	ssid, err := uuid.FromBytes(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.FromBytes(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	return &RST{ssid, rsid, r.Code, r.Message}, nil
}
func (r RawRST) String() string {
	return fmt.Sprintf("RST{SenderSessionID: %s, RecverSessionID: %s, Code: %d, Message: %s}", hex.EncodeToString(r.SenderSessionID[:4]), hex.EncodeToString(r.RecverSessionID[:4]), r.Code, r.Message)
}

type RawObjectInfo struct {
	ID        []byte
	Address   string
	Transform [7]float32
}
type RawSOA struct {
	SenderSessionID []byte
	RecverSessionID []byte
	Objects         []RawObjectInfo
}

func (r *RawSOA) TryParse() (*SOA, error) {
	ssid, err := uuid.FromBytes(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.FromBytes(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	objects, _, err := functional.Filter_until_err(
		r.Objects,
		func(object_raw RawObjectInfo) (ObjectInfo, error) {
			oid, err := uuid.FromBytes(object_raw.ID)
			return ObjectInfo{
				ID:        oid,
				Addr:      object_raw.Address,
				Transform: object_raw.Transform,
			}, err
		},
	)
	if err != nil {
		return nil, err
	}
	return &SOA{ssid, rsid, objects}, nil
}
func (r RawSOA) String() string {
	return fmt.Sprintf("SOA{SenderSessionID: %s, RecverSessionID: %s, Objects: %d}", hex.EncodeToString(r.SenderSessionID[:4]), hex.EncodeToString(r.RecverSessionID[:4]), len(r.Objects))
}

type RawSOD struct {
	SenderSessionID []byte
	RecverSessionID []byte
	ObjectIDs       [][]byte
}

func (r *RawSOD) TryParse() (*SOD, error) {
	ssid, err := uuid.FromBytes(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.FromBytes(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	oids, _, err := functional.Filter_until_err(
		r.ObjectIDs,
		func(oid_raw []byte) (uuid.UUID, error) {
			oid, err := uuid.FromBytes(oid_raw)
			return oid, err
		},
	)
	if err != nil {
		return nil, err
	}
	return &SOD{ssid, rsid, oids}, nil
}
func (r RawSOD) String() string {
	return fmt.Sprintf("SOD{SenderSessionID: %s, RecverSessionID: %s, ObjectIDs: %d}", hex.EncodeToString(r.SenderSessionID[:4]), hex.EncodeToString(r.RecverSessionID[:4]), len(r.ObjectIDs))
}
