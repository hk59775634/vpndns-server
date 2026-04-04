package api

import (
	"encoding/json"
	"net/http"
	"strconv"
)

type geoCIDRResponse struct {
	Total   int      `json:"total"`
	IPv4    int      `json:"ipv4"`
	IPv6    int      `json:"ipv6"`
	Page    int      `json:"page"`
	PerPage int      `json:"per_page"`
	CIDRs   []string `json:"cidrs"`
}

func (s *Server) listGeoIPCIDRs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	switch per {
	case 20, 50, 100, 500:
	default:
		per = 100
	}
	total, v4, v6, rows := s.cn.CIDRListPage(page, per)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(geoCIDRResponse{
		Total:   total,
		IPv4:    v4,
		IPv6:    v6,
		Page:    page,
		PerPage: per,
		CIDRs:   rows,
	})
}
