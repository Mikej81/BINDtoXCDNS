package main

type DNSRecord struct {
	TTL         int          `json:"ttl,omitempty"`
	ARecord     *ARecord     `json:"a_record,omitempty"`
	MXRecord    *[]MXValue   `json:"mx_record,omitempty"`  // Assume MXValue struct includes Name if needed
	TXTRecord   *TXTRecord   `json:"txt_record,omitempty"` // Adjust if a name field is needed
	CNAMERecord *CNAMERecord `json:"cname_record,omitempty"`
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

type CNAMERecord struct {
	Name  string `json:"name,omitempty"`
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
