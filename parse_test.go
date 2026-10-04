package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const (
	testUUID = "2c31c154-6f63-499e-b3e5-9f70291ae0a8"
	testPBK  = "QzGE3bqkQpSspfZZeoLTUiKH-oMn0I6878WUjP9x8lY"
)

func one(t *testing.T, link string) *Node {
	t.Helper()
	ns := ParseLinks(link)
	if len(ns) != 1 {
		t.Fatalf("want 1 node from %q, got %d", link, len(ns))
	}
	return ns[0]
}

func sub(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("%q missing or not an object in %v", key, m)
	}
	return v
}

func TestVLESSReality(t *testing.T) {
	n := one(t, "vless://"+testUUID+"@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk="+testPBK+"&sid=ab12&type=tcp#My%20Node")
	if n.Type != "vless" || n.Server != "1.2.3.4" || n.Port != 443 || n.Name != "My Node" || n.UDP {
		t.Fatalf("bad node: %+v", n)
	}
	o := n.Outbound
	if o["uuid"] != testUUID || o["flow"] != "xtls-rprx-vision" {
		t.Fatalf("bad outbound: %v", o)
	}
	tls := sub(t, o, "tls")
	if tls["server_name"] != "www.microsoft.com" {
		t.Fatalf("sni: %v", tls)
	}
	r := sub(t, tls, "reality")
	if r["public_key"] != testPBK || r["short_id"] != "ab12" {
		t.Fatalf("reality: %v", r)
	}
	if sub(t, tls, "utls")["fingerprint"] != "chrome" {
		t.Fatalf("utls: %v", tls)
	}
	if _, has := o["transport"]; has {
		t.Fatal("tcp must not produce a transport")
	}
}

func TestVLESSRealityWithoutKeyRejected(t *testing.T) {
	if ns := ParseLinks("vless://" + testUUID + "@1.2.3.4:443?security=reality&sni=x.com#a"); len(ns) != 0 {
		t.Fatal("reality without pbk must be dropped")
	}
}

func TestVLESSWebsocketTLS(t *testing.T) {
	n := one(t, "vless://"+testUUID+"@example.com:8443?security=tls&sni=example.com&type=ws&path=%2Fws&host=cdn.example.com&alpn=h2%2Chttp%2F1.1#ws")
	tr := sub(t, n.Outbound, "transport")
	if tr["type"] != "ws" || tr["path"] != "/ws" {
		t.Fatalf("transport: %v", tr)
	}
	if sub(t, tr, "headers")["Host"] != "cdn.example.com" {
		t.Fatalf("ws host: %v", tr)
	}
	alpn := sub(t, n.Outbound, "tls")["alpn"].([]string)
	if len(alpn) != 2 || alpn[0] != "h2" {
		t.Fatalf("alpn: %v", alpn)
	}
}

func TestVLESSGRPCAndIPv6(t *testing.T) {
	n := one(t, "vless://"+testUUID+"@[2001:db8::1]:443?security=tls&type=grpc&serviceName=svc#v6")
	if n.Server != "2001:db8::1" {
		t.Fatalf("ipv6 host: %q", n.Server)
	}
	if sub(t, n.Outbound, "transport")["service_name"] != "svc" {
		t.Fatalf("grpc: %v", n.Outbound)
	}
}

func TestUnsupportedTransportDropped(t *testing.T) {
	for _, typ := range []string{"xhttp", "kcp", "quic", "splithttp"} {
		if ns := ParseLinks("vless://" + testUUID + "@1.2.3.4:443?security=tls&type=" + typ + "#x"); len(ns) != 0 {
			t.Errorf("type=%s must be dropped, otherwise it silently becomes plain TCP", typ)
		}
	}
	if ns := ParseLinks("vless://" + testUUID + "@1.2.3.4:443?security=tls&type=tcp&headerType=http#x"); len(ns) != 0 {
		t.Error("http-obfuscated tcp must be dropped")
	}
}

func TestVMess(t *testing.T) {
	js := `{"v":"2","ps":"vm node","add":"vm.example.com","port":"443","id":"` + testUUID + `","aid":"0","scy":"auto","net":"ws","host":"h.example.com","path":"/p","tls":"tls","sni":"s.example.com"}`
	n := one(t, "vmess://"+base64.StdEncoding.EncodeToString([]byte(js)))
	if n.Type != "vmess" || n.Name != "vm node" || n.Server != "vm.example.com" || n.Port != 443 {
		t.Fatalf("bad node: %+v", n)
	}
	if n.Outbound["security"] != "auto" || n.Outbound["uuid"] != testUUID {
		t.Fatalf("outbound: %v", n.Outbound)
	}
	if sub(t, n.Outbound, "tls")["server_name"] != "s.example.com" {
		t.Fatalf("tls: %v", n.Outbound)
	}
	// numeric port / aid (some panels emit numbers, not strings)
	js2 := `{"ps":"n","add":"a.com","port":8443,"id":"` + testUUID + `","aid":0,"net":"tcp"}`
	if n2 := one(t, "vmess://"+base64.RawStdEncoding.EncodeToString([]byte(js2))); n2.Port != 8443 {
		t.Fatalf("numeric port: %+v", n2)
	}
}

func TestVMessGRPCServiceNameFromPath(t *testing.T) {
	js := `{"ps":"g","add":"a.com","port":"443","id":"` + testUUID + `","net":"grpc","path":"mysvc","tls":"tls"}`
	n := one(t, "vmess://"+base64.StdEncoding.EncodeToString([]byte(js)))
	if sub(t, n.Outbound, "transport")["service_name"] != "mysvc" {
		t.Fatalf("vmess grpc service name lost: %v", n.Outbound)
	}
}

func TestTrojan(t *testing.T) {
	n := one(t, "trojan://s3cret@tj.example.com:443?sni=tj.example.com&type=ws&path=%2Ft#tj")
	if n.Type != "trojan" || n.Outbound["password"] != "s3cret" {
		t.Fatalf("bad: %+v", n)
	}
	if sub(t, n.Outbound, "tls")["enabled"] != true { // trojan is TLS by default
		t.Fatal("tls must be on by default")
	}
}

func TestShadowsocksVariants(t *testing.T) {
	ui := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pa55"))
	cases := map[string]string{
		"sip002":           "ss://" + ui + "@ss.example.com:8388#n",
		"sip002 slash":     "ss://" + ui + "@ss.example.com:8388/#n",
		"padded+escaped":   "ss://" + strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pa55")), "=", "%3D") + "@ss.example.com:8388#n",
		"plain":            "ss://aes-256-gcm:pa55@ss.example.com:8388#n",
		"plain escaped":    "ss://aes-256-gcm%3Apa55@ss.example.com:8388#n",
		"legacy whole-b64": "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pa55@ss.example.com:8388")) + "#n",
	}
	for name, link := range cases {
		n := one(t, link)
		if n.Type != "shadowsocks" || n.Server != "ss.example.com" || n.Port != 8388 ||
			n.Outbound["method"] != "aes-256-gcm" || n.Outbound["password"] != "pa55" {
			t.Errorf("%s: bad node %+v %v", name, n, n.Outbound)
		}
	}
	if ns := ParseLinks("ss://" + ui + "@h.com:1/?plugin=obfs-local%3Bobfs%3Dhttp#p"); len(ns) != 0 {
		t.Error("plugins are unsupported and must be dropped")
	}
}

func TestHysteria2(t *testing.T) {
	n := one(t, "hy2://pw@hy.example.com:8443?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=op#hy")
	if n.Type != "hysteria2" || !n.UDP || n.Outbound["password"] != "pw" {
		t.Fatalf("bad: %+v", n)
	}
	if sub(t, n.Outbound, "tls")["insecure"] != true || sub(t, n.Outbound, "obfs")["password"] != "op" {
		t.Fatalf("outbound: %v", n.Outbound)
	}
	if n2 := one(t, "hysteria2://pw@hy.example.com#x"); n2.Port != 443 {
		t.Fatalf("default port: %d", n2.Port)
	}
}

func TestParseLinksSubscriptionFormats(t *testing.T) {
	a := "vless://" + testUUID + "@1.1.1.1:443?security=tls&type=tcp#a"
	b := "trojan://pw@2.2.2.2:443#b"
	junk := "# comment\nnot-a-link\nvless://broken\n"
	plain := a + "\r\n" + junk + b + "\n" + a + "\n" // CRLF + junk + duplicate
	ns := ParseLinks(plain)
	if len(ns) != 2 {
		t.Fatalf("plain list: want 2 unique nodes, got %d", len(ns))
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		body := enc.EncodeToString([]byte(a + "\n" + b))
		if got := ParseLinks(body); len(got) != 2 {
			t.Errorf("base64 body not decoded (%T): %d nodes", enc, len(got))
		}
		// providers often wrap base64 at 76 columns
		wrapped := ""
		for i := 0; i < len(body); i += 20 {
			wrapped += body[i:min(i+20, len(body))] + "\n"
		}
		if got := ParseLinks(wrapped); len(got) != 2 {
			t.Errorf("wrapped base64 not decoded: %d nodes", len(got))
		}
	}
	if len(ParseLinks("")) != 0 || len(ParseLinks("<html>403 forbidden</html>")) != 0 {
		t.Error("garbage must give no nodes")
	}
}

func TestNodeIDStableAcrossRename(t *testing.T) {
	a := one(t, "trojan://pw@2.2.2.2:443#first")
	b := one(t, "trojan://pw@2.2.2.2:443#renamed")
	c := one(t, "trojan://pw2@2.2.2.2:443#first")
	if a.ID != b.ID {
		t.Error("ID must not depend on the display name")
	}
	if a.ID == c.ID {
		t.Error("ID must change when the outbound changes")
	}
	if len(a.ID) != 40 || !strings.HasPrefix(a.Tag(), "n-") || len(a.Tag()) != 12 {
		t.Errorf("id/tag shape: %s %s", a.ID, a.Tag())
	}
	if _, err := json.Marshal(a.Outbound); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidPorts(t *testing.T) {
	for _, l := range []string{"trojan://pw@h.com:0#x", "trojan://pw@h.com:70000#x", "trojan://pw@:443#x", "trojan://pw@h.com#x"} {
		if ns := ParseLinks(l); len(ns) != 0 {
			t.Errorf("%s must be rejected", l)
		}
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestTLSServerNameFallsBackToHost(t *testing.T) {
	n := ParseLinks("vless://" + testUUID + "@1.2.3.4:443?security=tls&type=ws&host=cdn.example.com&path=/w#a\n" +
		"vless://" + testUUID + "@1.2.3.5:443?security=tls&type=ws&host=cdn.example.com&sni=real.example.com&path=/w#b\n" +
		"vless://" + testUUID + "@1.2.3.6:443?security=tls&type=tcp&host=ignored.example.com#c")
	if len(n) != 3 {
		t.Fatalf("parsed %d", len(n))
	}
	sn := func(x *Node) any {
		tl, _ := x.Outbound["tls"].(map[string]any)
		return tl["server_name"]
	}
	if sn(n[0]) != "cdn.example.com" || sn(n[1]) != "real.example.com" || sn(n[2]) != nil {
		t.Fatalf("server names: %v %v %v", sn(n[0]), sn(n[1]), sn(n[2]))
	}
}
