package and

import (
	"net/netip"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"

	"github.com/google/uuid"
)

type RawSessionInfoForDiscovery struct {
	PeerID                     string
	AddressCandidates          []string
	SessionID                  string
	TimeStamp                  int64
	RootCertificateDer         []byte
	HandshakeKeyCertificateDer []byte
}

func MakeRawSessionInfoForDiscovery(entry *peerWorldSessionState) RawSessionInfoForDiscovery {
	return RawSessionInfoForDiscovery{
		PeerID:                     entry.Peer.ID(),
		AddressCandidates:          functional.Filter(entry.AddressCandidates, func(a netip.AddrPort) string { return a.String() }),
		SessionID:                  entry.SessionID.String(),
		TimeStamp:                  entry.TimeStamp.UnixMilli(),
		RootCertificateDer:         entry.Peer.RootCertificateDer(),
		HandshakeKeyCertificateDer: entry.Peer.HandshakeKeyCertificateDer(),
	}
}

type RawSessionInfoForSJN struct {
	PeerID    string
	SessionID string
}

func MakeRawSessionInfoForSJN(entry *peerWorldSessionState) RawSessionInfoForSJN {
	return RawSessionInfoForSJN{
		PeerID:    entry.Peer.ID(),
		SessionID: entry.SessionID.String(),
	}
}

// AHMP message formats
// TODO: keyasint

type RawJN struct {
	SenderSessionID string
	Path            string
	TimeStamp       int64
}

func (r *RawJN) TryParse() (*JN, error) {
	ssid, err := uuid.Parse(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	return &JN{ssid, r.Path, time.UnixMilli(r.TimeStamp)}, nil
}

type RawJOK struct {
	SenderSessionID string
	RecverSessionID string
	URL             string
	TimeStamp       int64
	Neighbors       []RawSessionInfoForDiscovery
}

func (r *RawJOK) TryParse() (*JOK, error) {
	ssid, err := uuid.Parse(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.Parse(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	neig, _, err := functional.Filter_until_err(r.Neighbors, func(i RawSessionInfoForDiscovery) (ANDFullPeerSessionInfo, error) {
		addrs, _, err := functional.Filter_until_err(i.AddressCandidates, netip.ParseAddrPort)
		if err != nil {
			return ANDFullPeerSessionInfo{}, err
		}
		psid, err := uuid.Parse(i.SessionID)
		if err != nil {
			return ANDFullPeerSessionInfo{}, err
		}
		return ANDFullPeerSessionInfo{
			PeerID:                     i.PeerID,
			AddressCandidates:          addrs,
			SessionID:                  psid,
			TimeStamp:                  time.UnixMilli(i.TimeStamp),
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
		TimeStamp:       time.UnixMilli(r.TimeStamp),
		Neighbors:       neig,
	}, nil
}

type RawJDN struct {
	RecverSessionID string
	Code            int
	Message         string
}

func (r *RawJDN) TryParse() (*JDN, error) {
	rsid, err := uuid.Parse(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	return &JDN{
		RecverSessionID: rsid,
		Code:            r.Code,
		Message:         r.Message,
	}, nil
}

type RawJNI struct {
	SenderSessionID string
	RecverSessionID string
	Neighbor        RawSessionInfoForDiscovery
}

func (r *RawJNI) TryParse() (*JNI, error) {
	ssid, err := uuid.Parse(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.Parse(r.RecverSessionID)
	if err != nil {
		return nil, err
	}

	addrs, _, err := functional.Filter_until_err(r.Neighbor.AddressCandidates, netip.ParseAddrPort)
	if err != nil {
		return nil, err
	}
	psid, err := uuid.Parse(r.Neighbor.SessionID)
	if err != nil {
		return nil, err
	}
	return &JNI{ssid, rsid, ANDFullPeerSessionInfo{
		PeerID:                     r.Neighbor.PeerID,
		AddressCandidates:          addrs,
		SessionID:                  psid,
		TimeStamp:                  time.UnixMilli(r.Neighbor.TimeStamp),
		RootCertificateDer:         r.Neighbor.RootCertificateDer,
		HandshakeKeyCertificateDer: r.Neighbor.HandshakeKeyCertificateDer,
	}}, nil
}

type RawMEM struct {
	SenderSessionID string
	RecverSessionID string
	TimeStamp       int64
}

func (r *RawMEM) TryParse() (*MEM, error) {
	ssid, err := uuid.Parse(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.Parse(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	return &MEM{ssid, rsid, time.UnixMilli(r.TimeStamp)}, nil
}

type RawSJN struct {
	SenderSessionID string
	RecverSessionID string
	MemberInfos     []RawSessionInfoForSJN
}

func (r *RawSJN) TryParse() (*SJN, error) {
	ssid, err := uuid.Parse(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.Parse(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	infos, _, err := functional.Filter_until_err(r.MemberInfos,
		func(info_raw RawSessionInfoForSJN) (ANDPeerSessionIdentity, error) {
			id, err := uuid.Parse(info_raw.SessionID)
			return ANDPeerSessionIdentity{
				PeerID:    info_raw.PeerID,
				SessionID: id,
			}, err
		})
	if err != nil {
		return nil, err
	}
	return &SJN{ssid, rsid, infos}, nil
}

type RawCRR struct {
	SenderSessionID string
	RecverSessionID string
	MemberInfos     []RawSessionInfoForSJN
}

func (r *RawCRR) TryParse() (*CRR, error) {
	ssid, err := uuid.Parse(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.Parse(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	infos, _, err := functional.Filter_until_err(r.MemberInfos,
		func(info_raw RawSessionInfoForSJN) (ANDPeerSessionIdentity, error) {
			id, err := uuid.Parse(info_raw.SessionID)
			return ANDPeerSessionIdentity{
				PeerID:    info_raw.PeerID,
				SessionID: id,
			}, err
		})
	if err != nil {
		return nil, err
	}
	return &CRR{ssid, rsid, infos}, nil
}

type RawRST struct {
	SenderSessionID string
	RecverSessionID string
	Message         string
}

func (r *RawRST) TryParse() (*RST, error) {
	ssid, err := uuid.Parse(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.Parse(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	return &RST{ssid, rsid, r.Message}, nil
}

type RawObjectInfo struct {
	ID        string
	Address   string
	Transform [7]float32
}
type RawSOA struct {
	SenderSessionID string
	RecverSessionID string
	Objects         []RawObjectInfo
}

func (r *RawSOA) TryParse() (*SOA, error) {
	ssid, err := uuid.Parse(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.Parse(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	objects, _, err := functional.Filter_until_err(r.Objects,
		func(object_raw RawObjectInfo) (ObjectInfo, error) {
			oid, err := uuid.Parse(object_raw.ID)
			return ObjectInfo{
				ID:        oid,
				Addr:      object_raw.Address,
				Transform: object_raw.Transform,
			}, err
		})
	if err != nil {
		return nil, err
	}
	return &SOA{ssid, rsid, objects}, nil
}

type RawSOD struct {
	SenderSessionID string
	RecverSessionID string
	ObjectIDs       []string
}

func (r *RawSOD) TryParse() (*SOD, error) {
	ssid, err := uuid.Parse(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	rsid, err := uuid.Parse(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	oids, _, err := functional.Filter_until_err(r.ObjectIDs,
		func(oid_raw string) (uuid.UUID, error) {
			oid, err := uuid.Parse(oid_raw)
			return oid, err
		})
	if err != nil {
		return nil, err
	}
	return &SOD{ssid, rsid, oids}, nil
}
