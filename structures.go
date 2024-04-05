package main

const (
	RecordClass_UNKNOWN = 0   // unset
	RecordClass_IN      = 1   // the Internet
	RecordClass_CS      = 2   // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	RecordClass_CH      = 3   // the CHAOS class
	RecordClass_HS      = 4   // Hesiod [Dyer 87]
	RecordClass_any     = 255 // any class (spelled: *; appears only in the question section of a query; included for completeness)
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

type DNSRecord struct {
	TTL         int          `json:"ttl,omitempty"`
	ARecord     *ARecord     `json:"a_record,omitempty"`
	SRVRecord   *SRVRecord   `json:"srv_record,omitempty"`
	MXRecord    *[]MXValue   `json:"mx_record,omitempty"`
	TXTRecord   *TXTRecord   `json:"txt_record,omitempty"`
	CNAMERecord *CNAMERecord `json:"cname_record,omitempty"`
	CAARecord   *CAARecord   `json:"caa_record,omitempty"`
	NSRecord    *NSRecord    `json:"ns_record,omitempty"`
	AAAARecord  *AAAARecord  `json:"aaaa_record,omitempty"`
	Description string       `json:"description,omitempty"`
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
	Name   string `json:"name"`
	Values []struct {
		Priority int    `json:"priority"`
		Weight   int    `json:"weight"`
		Port     int    `json:"port"`
		Target   string `json:"target"`
	} `json:"values"`
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

type TXTRecordWithDesc struct {
	TXTRecord   *TXTRecord
	Description string
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
			SOAParameters     SOAParameters `json:"soa_parameters"` // Renamed to match the provided format
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
