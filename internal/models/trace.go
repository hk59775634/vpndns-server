package models

// ResolveTrace is optional per-query routing detail for admin query logs (JSON).
type ResolveTrace struct {
	Steps []string `json:"steps,omitempty"`

	VIP            string `json:"vip,omitempty"`
	RealIPMapped   string `json:"real_ip_mapped,omitempty"`
	PublicIPForECS string `json:"public_ip_for_ecs,omitempty"`

	Question        string `json:"question,omitempty"`
	ClientEDNS      string `json:"client_edns,omitempty"`
	EffectiveSubnet string `json:"effective_subnet,omitempty"`

	CNUpstreamUsed    bool   `json:"cn_upstream_used"`
	CNUpstreamEndpoint string `json:"cn_upstream_endpoint,omitempty"` // e.g. DoH URL or UDP address
	// CNUpstreamRequestURL is the full Google JSON GET URL when upstream uses json_get /resolve.
	CNUpstreamRequestURL string `json:"cn_upstream_request_url,omitempty"`
	CNECSWithUpstream string `json:"cn_ecs,omitempty"`
	CNQuerySummary    string `json:"cn_query_summary,omitempty"`
	CNResponseSummary string `json:"cn_response_summary,omitempty"`
	CNResponseWire    string `json:"cn_response_wire,omitempty"`

	IPClassification string `json:"ip_classification,omitempty"`

	OUTUpstreamUsed     bool   `json:"out_upstream_used"`
	OUTUpstreamEndpoint string `json:"out_upstream_endpoint,omitempty"`
	OUTUpstreamRequestURL string `json:"out_upstream_request_url,omitempty"`
	OUTECSWithUpstream  string `json:"out_ecs,omitempty"`
	OUTResponseSummary string `json:"out_response_summary,omitempty"`
	OUTResponseWire    string `json:"out_response_wire,omitempty"`

	FromCache     string `json:"from_cache,omitempty"`
	BlockedReason string `json:"blocked_reason,omitempty"`

	// Client transport (admin log detail).
	Transport            string `json:"transport,omitempty"` // udp | tcp | doh | doh-json
	DoHURL               string `json:"doh_url,omitempty"`
	DoHPostBodyHex       string `json:"doh_post_body_hex,omitempty"`
	DoHPostBodyTruncated bool   `json:"doh_post_body_truncated,omitempty"`
}
