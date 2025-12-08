package ahmp

import (
	"errors"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/aurl"
	abyss "github.com/kadmila/Abyss-Browser/abyss_core/interfaces"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"

	"github.com/google/uuid"
)

type RawSessionInfoForDiscovery struct {
	AURL                       string
	SessionID                  string
	TimeStamp                  int64
	RootCertificateDer         []byte
	HandshakeKeyCertificateDer []byte
}

type RawSessionInfoForSJN struct {
	PeerHash  string
	SessionID string
}

const (
	JN_T int = iota
	JOK_T
	JDN_T
	JNI_T
	MEM_T
	SJN_T
	CRR_T
	RST_T

	SOA_T
	SOD_T
)

// Msg_type_names for debug
var Msg_type_names = [...]string{"JN", "JOK", "JDN", "JNI", "MEM", "SJN", "CRR", "RST", "SOA", "SOD"}

type RawJN struct {
	SenderSessionID string
	Text            string
	TimeStamp       int64
}

func (r *RawJN) TryParse() (*JN, error) {
	ssid, err := uuid.Parse(r.SenderSessionID)
	if err != nil {
		return nil, err
	}
	return &JN{ssid, r.Text, time.UnixMilli(r.TimeStamp)}, nil
}

type RawJOK struct {
	SenderSessionID string
	RecverSessionID string
	TimeStamp       int64
	Text            string
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
	neig, ok := functional.Filter_strict_ok(r.Neighbors, func(i RawSessionInfoForDiscovery) (abyss.ANDFullPeerSessionIdentity, bool) {
		abyss_url, err := aurl.TryParse(i.AURL)
		if err != nil {
			return abyss.ANDFullPeerSessionIdentity{}, false
		}
		psid, err := uuid.Parse(i.SessionID)
		if err != nil {
			return abyss.ANDFullPeerSessionIdentity{}, false
		}
		return abyss.ANDFullPeerSessionIdentity{
			AURL:                       abyss_url,
			SessionID:                  psid,
			TimeStamp:                  time.UnixMilli(i.TimeStamp),
			RootCertificateDer:         i.RootCertificateDer,
			HandshakeKeyCertificateDer: i.HandshakeKeyCertificateDer,
		}, true
	})
	if !ok {
		return nil, errors.New("failed to parse session information")
	}
	return &JOK{ssid, rsid, time.UnixMilli(r.TimeStamp), neig, r.Text}, nil
}

type RawJDN struct {
	RecverSessionID string
	Code            int
	Text            string
}

func (r *RawJDN) TryParse() (*JDN, error) {
	rsid, err := uuid.Parse(r.RecverSessionID)
	if err != nil {
		return nil, err
	}
	return &JDN{rsid, r.Text, r.Code}, nil
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

	abyss_url, err := aurl.TryParse(r.Neighbor.AURL)
	if err != nil {
		return nil, err
	}
	psid, err := uuid.Parse(r.Neighbor.SessionID)
	if err != nil {
		return nil, err
	}
	return &JNI{ssid, rsid, abyss.ANDFullPeerSessionIdentity{
		AURL:                       abyss_url,
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
		func(info_raw RawSessionInfoForSJN) (abyss.ANDPeerSessionIdentity, error) {
			id, err := uuid.Parse(info_raw.SessionID)
			return abyss.ANDPeerSessionIdentity{
				PeerHash:  info_raw.PeerHash,
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
		func(info_raw RawSessionInfoForSJN) (abyss.ANDPeerSessionIdentity, error) {
			id, err := uuid.Parse(info_raw.SessionID)
			return abyss.ANDPeerSessionIdentity{
				PeerHash:  info_raw.PeerHash,
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
		func(object_raw RawObjectInfo) (abyss.ObjectInfo, error) {
			oid, err := uuid.Parse(object_raw.ID)
			return abyss.ObjectInfo{
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
