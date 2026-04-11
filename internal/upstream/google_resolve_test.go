package upstream

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/vpndns/cdn/internal/ecs"
)

func TestIsGoogleJSONResolveURL(t *testing.T) {
	if !isGoogleJSONResolveURL("https://dns.google/resolve") {
		t.Fatal("expected true")
	}
	if !isGoogleJSONResolveURL("https://dns.google/resolve?name=x") {
		t.Fatal("expected true with query")
	}
	if isGoogleJSONResolveURL("https://dns.google/dns-query") {
		t.Fatal("dns-query is RFC 8484, not json")
	}
}

func TestGoogleResolveJSONToMsg_sample(t *testing.T) {
	raw := `{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": false,
  "CD": false,
  "Question": [{"name": "www.qq.com.", "type": 1}],
  "Answer": [
    {"name": "www.qq.com.", "type": 5, "TTL": 300, "data": "ins-r23tsuuf.ias.tencent-cloud.net."},
    {"name": "ins-r23tsuuf.ias.tencent-cloud.net.", "type": 1, "TTL": 120, "data": "42.81.179.153"}
  ]
}`
	var gj googleResolveJSON
	if err := json.Unmarshal([]byte(raw), &gj); err != nil {
		t.Fatal(err)
	}
	req := new(dns.Msg)
	req.SetQuestion("www.qq.com.", dns.TypeA)
	out, err := googleResolveJSONToMsg(req, &gj)
	if err != nil {
		t.Fatal(err)
	}
	if out.Rcode != dns.RcodeSuccess || len(out.Answer) != 2 {
		t.Fatalf("rcode=%d answers=%d", out.Rcode, len(out.Answer))
	}
}

func TestGoogleSubnetQueryParam_matchesPriorBehavior(t *testing.T) {
	ip := net.ParseIP("58.56.59.66")
	s := ecs.GoogleSubnetQueryParam(ip, 24)
	if s != "58.56.59.0/24" {
		t.Fatalf("got %q", s)
	}
}

func TestGoogleResolveJSON_ednsClientSubnetField(t *testing.T) {
	raw := `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"edns_client_subnet":"58.56.59.0/18","Question":[{"name":"x.","type":1}],"Answer":[]}`
	var gj googleResolveJSON
	if err := json.Unmarshal([]byte(raw), &gj); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(gj.EdnsClientSubnet) != "58.56.59.0/18" {
		t.Fatalf("echo: %q", gj.EdnsClientSubnet)
	}
}
