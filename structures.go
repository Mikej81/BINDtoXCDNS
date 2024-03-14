package main

const (
	RecordType_UNKNOWN    = 0  // unset
	RecordType_A          = 1  // a host address
	RecordType_NS         = 2  // an authoritative name server
	RecordType_MD         = 3  // a mail destination (OBSOLETE - use MX)
	RecordType_MF         = 4  // a mail forwarder (OBSOLETE - use MX)
	RecordType_CNAME      = 5  // the canonical name for an alias
	RecordType_SOA        = 6  // marks the start of a zone of authority
	RecordType_MB         = 7  // a mailbox domain name (EXPERIMENTAL)
	RecordType_MG         = 8  // a mail group member (EXPERIMENTAL)
	RecordType_MR         = 9  // a mail rename domain name (EXPERIMENTAL)
	RecordType_NULL       = 10 // a null RR (EXPERIMENTAL)
	RecordType_WKS        = 11 // a well known service description
	RecordType_PTR        = 12 // a domain name pointer
	RecordType_HINFO      = 13 // host information
	RecordType_MINFO      = 14 // mailbox or mail list information
	RecordType_MX         = 15 // mail exchange
	RecordType_TXT        = 16 // text strings
	RecordType_RP         = 17 // for Responsible Person
	RecordType_AFSDB      = 18 // for AFS Data Base location
	RecordType_X25        = 19 // for X.25 PSDN address
	RecordType_ISDN       = 20 // for ISDN address
	RecordType_RT         = 21 // for Route Through
	RecordType_NSAP       = 22 // for NSAP address, NSAP style A record
	RecordType_NSAP_PTR   = 23 // spelled "NSAP-PTR", for domain name pointer, NSAP style
	RecordType_SIG        = 24 // for security signature
	RecordType_KEY        = 25 // for security key
	RecordType_PX         = 26 // X.400 mail mapping information
	RecordType_GPOS       = 27 // Geographical Position
	RecordType_AAAA       = 28 // IP6 Address
	RecordType_LOC        = 29 // Location Information
	RecordType_NXT        = 30 // Next Domain (OBSOLETE)
	RecordType_EID        = 31 // Endpoint Identifier
	RecordType_NIMLOC     = 32 // Nimrod Locator
	RecordType_SRV        = 33 // Server Selection
	RecordType_ATMA       = 34 // ATM Address
	RecordType_NAPTR      = 35 // Naming Authority Pointer
	RecordType_KX         = 36 // Key Exchanger
	RecordType_CERT       = 37 // CERT
	RecordType_A6         = 38 // A6 (OBSOLETE - use AAAA)
	RecordType_DNAME      = 39 // DNAME
	RecordType_SINK       = 40 // SINK
	RecordType_OPT        = 41 // OPT
	RecordType_APL        = 42 // APL
	RecordType_DS         = 43 // Delegation Signer
	RecordType_SSHFP      = 44 // SSH Key Fingerprint
	RecordType_IPSECKEY   = 45 // IPSECKEY
	RecordType_RRSIG      = 46 // RRSIG
	RecordType_NSEC       = 47 // NSEC
	RecordType_DNSKEY     = 48 // DNSKEY
	RecordType_DHCID      = 49 // DHCID
	RecordType_NSEC3      = 50 // NSEC3
	RecordType_NSEC3PARAM = 51 // NSEC3PARAM
	RecordType_TLSA       = 52 // TLSA
	RecordType_SMIMEA     = 53 // S/MIME cert association
	// Unassigned 54
	RecordType_HIP        = 55 // Host Identity Protocol
	RecordType_NINFO      = 56 // NINFO
	RecordType_RKEY       = 57 // RKEY
	RecordType_TALINK     = 58 // Trust Anchor LINK
	RecordType_CDS        = 59 // Child DS
	RecordType_CDNSKEY    = 60 // DNSKEY(s) the Child wants reflected in DS
	RecordType_OPENPGPKEY = 61 // OpenPGP Key
	RecordType_CSYNC      = 62 // Child-To-Parent Synchronization
	RecordType_ZONEMD     = 63 // message digest for DNS zone
	// Unassigned	64-98
	RecordType_SPF    = 99  // declares which hosts are, and are not, authorized to use a domain name for the "HELO" and "MAIL FROM" identities (OBSOLETE - use TXT)
	RecordType_UINFO  = 100 // [IANA-Reserved]
	RecordType_UID    = 101 // [IANA-Reserved]
	RecordType_GID    = 102 // [IANA-Reserved]
	RecordType_UNSPEC = 103 // [IANA-Reserved]
	RecordType_NID    = 104 // values for Node Identifiers that will be used for ILNP-capable nodes
	RecordType_L32    = 105 // 32-bit Locator values for ILNPv4-capable nodes
	RecordType_L64    = 106 // unsigned 64-bit Locator values for ILNPv6-capable nodes
	RecordType_LP     = 107 // the name of a subnetwork for ILNP
	RecordType_EUI48  = 108 // an EUI-48 address
	RecordType_EUI64  = 109 // an EUI-64 address
	// Unassigned 110-248
	RecordType_TKEY     = 249 // Transaction Key
	RecordType_TSIG     = 250 // Transaction Signature
	RecordType_IXFR     = 251 // incremental transfer
	RecordType_AXFR     = 252 // transfer of an entire zone
	RecordType_MAILB    = 253 // mailbox-related RRs (MB, MG or MR)
	RecordType_MAILA    = 254 // mail agent RRs (OBSOLETE - see MX)
	RecordType_all      = 255 // Spelled "*", A request for some or all records the server has available
	RecordType_URI      = 256 // URI
	RecordType_CAA      = 257 // Certification Authority Restriction
	RecordType_AVC      = 258 // Application Visibility and Control
	RecordType_DOA      = 259 // Digital Object Architecture
	RecordType_AMTRELAY = 260 // Automatic Multicast Tunneling Relay
	// Unassigned	261-32767
	RecordType_TA  = 32768 // DNSSEC Trust Authorities
	RecordType_DLV = 32769 // DNSSEC Lookaside Validation
	// Unassigned	32770-65279
	// Private use	65280-65534
	// Reserved	65535
)

const (
	RecordClass_UNKNOWN = 0   // unset
	RecordClass_IN      = 1   // the Internet
	RecordClass_CS      = 2   // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	RecordClass_CH      = 3   // the CHAOS class
	RecordClass_HS      = 4   // Hesiod [Dyer 87]
	RecordClass_any     = 255 // any class (spelled: *; appears only in the question section of a query; included for completeness)
)

type DNSRecord struct {
	TTL         int          `json:"ttl,omitempty"`
	ARecord     *ARecord     `json:"a_record,omitempty"`
	SRVRecord   *SRVRecord   `json:"srv_record,omitempty"`
	MXRecord    *[]MXValue   `json:"mx_record,omitempty"`  // Assume MXValue struct includes Name if needed
	TXTRecord   *TXTRecord   `json:"txt_record,omitempty"` // Adjust if a name field is needed
	CNAMERecord *CNAMERecord `json:"cname_record,omitempty"`
	CAARecord   *CAARecord   `json:"caa_record,omitempty"`
	NSRecord    *NSRecord    `json:"ns_record,omitempty"`
	AAAARecord  *[]string    `json:"aaaa_record,omitempty"` // Adjust similarly
}

// MXValue struct represents an individual MX record's priority and value.
type MXValue struct {
	Priority int    `json:"priority"`
	Value    string `json:"value"`
}

type AAAARecord struct {
	Name   string   `json:"name,omitempty"`
	Values []string `json:"values"`
}

type ARecord struct {
	Name   string   `json:"name,omitempty"`
	Values []string `json:"values"`
}

type SRVRecord struct {
	Name   string   `json:"name,omitempty"`
	Values []string `json:"values"`
}

type CNAMERecord struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value"`
}

type CAARecord struct {
	Name  string `json:"name,omitempty"`
	Flags string `json:"flags,omitempty"`
	Tag   string `json:"tag,omitempty"`
	Value string `json:"value"`
}

type NSRecord struct {
	Name   string   `json:"name,omitempty"`
	Values []string `json:"values"`
}

type TXTRecord struct {
	Name   string   `json:"name,omitempty"`
	Values []string `json:"values"`
}

type SOAParameters struct {
	Refresh     int `json:"refresh"`
	Retry       int `json:"retry"`
	Expire      int `json:"expire"`
	NegativeTTL int `json:"negative_ttl"`
	TTL         int `json:"ttl"`
}

type ZoneConfig struct {
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		Description string            `json:"description"`
		Disable     bool              `json:"disable"`
	} `json:"metadata"`
	Spec struct {
		Primary struct {
			SOAParameters     SOAParameters `json:"default_soa_parameters"` // Renamed to match the provided format
			DefaultRRSetGroup []DNSRecord   `json:"default_rr_set_group"`
			DNSSECMode        DNSSECMode    `json:"dnssec_mode"` // Added for DNSSEC configuration
			//AllowHTTPLoadBalancerManagedRecords bool          `json:"allow_http_lb_managed_records"`
		} `json:"primary"`
	} `json:"spec"`
}

type DisabledType struct{}

// DNSSECMode adjusted to use the DisabledType for clarity
type DNSSECMode struct {
	Disable DisabledType `json:"disable"`
}

type RecordClass int

func (rc RecordClass) String() string {
	switch rc {
	case RecordClass_IN:
		return "IN"
	case RecordClass_CS:
		return "CS"
	case RecordClass_CH:
		return "CH"
	case RecordClass_HS:
		return "HS"
	case RecordClass_any:
		return "*"
	}

	return "[UNKNOWN]"
}

type RecordType int

func (rt RecordType) String() string {
	switch rt {
	case RecordType_A:
		return "A"
	case RecordType_NS:
		return "NS"
	case RecordType_MD:
		return "MD"
	case RecordType_MF:
		return "MF"
	case RecordType_CNAME:
		return "CNAME"
	case RecordType_SOA:
		return "SOA"
	case RecordType_MB:
		return "MB"
	case RecordType_MG:
		return "MG"
	case RecordType_MR:
		return "MR"
	case RecordType_NULL:
		return "NULL"
	case RecordType_WKS:
		return "WKS"
	case RecordType_PTR:
		return "PTR"
	case RecordType_HINFO:
		return "HINFO"
	case RecordType_MINFO:
		return "MINFO"
	case RecordType_MX:
		return "MX"
	case RecordType_TXT:
		return "TXT"
	case RecordType_RP:
		return "RP"
	case RecordType_AFSDB:
		return "AFSDB"
	case RecordType_X25:
		return "X25"
	case RecordType_ISDN:
		return "ISDN"
	case RecordType_RT:
		return "RT"
	case RecordType_NSAP:
		return "NSAP"
	case RecordType_NSAP_PTR:
		return "NSAP-PTR"
	case RecordType_SIG:
		return "SIG"
	case RecordType_KEY:
		return "KEY"
	case RecordType_PX:
		return "PX"
	case RecordType_GPOS:
		return "GPOS"
	case RecordType_AAAA:
		return "AAAA"
	case RecordType_LOC:
		return "LOC"
	case RecordType_NXT:
		return "NXT"
	case RecordType_EID:
		return "EID"
	case RecordType_NIMLOC:
		return "NIMLOC"
	case RecordType_SRV:
		return "SRV"
	case RecordType_ATMA:
		return "ATMA"
	case RecordType_NAPTR:
		return "NAPTR"
	case RecordType_KX:
		return "KX"
	case RecordType_CERT:
		return "CERT"
	case RecordType_A6:
		return "A6"
	case RecordType_DNAME:
		return "DNAME"
	case RecordType_SINK:
		return "SINK"
	case RecordType_OPT:
		return "OPT"
	case RecordType_APL:
		return "APL"
	case RecordType_DS:
		return "DS"
	case RecordType_SSHFP:
		return "SSHFP"
	case RecordType_IPSECKEY:
		return "IPSECKEY"
	case RecordType_RRSIG:
		return "RRSIG"
	case RecordType_NSEC:
		return "NSEC"
	case RecordType_DNSKEY:
		return "DNSKEY"
	case RecordType_DHCID:
		return "DHCID"
	case RecordType_NSEC3:
		return "NSEC3"
	case RecordType_NSEC3PARAM:
		return "NSEC3PARAM"
	case RecordType_TLSA:
		return "TLSA"
	case RecordType_SMIMEA:
		return "SMIMEA"
	case RecordType_HIP:
		return "HIP"
	case RecordType_NINFO:
		return "NINFO"
	case RecordType_RKEY:
		return "RKEY"
	case RecordType_TALINK:
		return "TALINK"
	case RecordType_CDS:
		return "CDS"
	case RecordType_CDNSKEY:
		return "CDNSKEY"
	case RecordType_OPENPGPKEY:
		return "OPENPGPKEY"
	case RecordType_CSYNC:
		return "CSYNC"
	case RecordType_ZONEMD:
		return "ZONEMD"
	case RecordType_SPF:
		return "SPF"
	case RecordType_UINFO:
		return "UINFO"
	case RecordType_UID:
		return "UID"
	case RecordType_GID:
		return "GID"
	case RecordType_UNSPEC:
		return "UNSPEC"
	case RecordType_NID:
		return "NID"
	case RecordType_L32:
		return "L32"
	case RecordType_L64:
		return "L64"
	case RecordType_LP:
		return "LP"
	case RecordType_EUI48:
		return "EUI48"
	case RecordType_EUI64:
		return "EUI64"
	case RecordType_TKEY:
		return "TKEY"
	case RecordType_TSIG:
		return "TSIG"
	case RecordType_IXFR:
		return "IXFR"
	case RecordType_AXFR:
		return "AXFR"
	case RecordType_MAILB:
		return "MAILB"
	case RecordType_MAILA:
		return "MAILA"
	case RecordType_all:
		return "*"
	case RecordType_URI:
		return "URI"
	case RecordType_CAA:
		return "CAA"
	case RecordType_AVC:
		return "AVC"
	case RecordType_DOA:
		return "DOA"
	case RecordType_AMTRELAY:
		return "AMTRELAY"
	case RecordType_TA:
		return "TA"
	case RecordType_DLV:
		return "DLV"
	}

	return "[UNKNOWN]"
}
