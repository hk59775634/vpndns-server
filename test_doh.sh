# 证书里的主机名（与你 YAML 里 Cloudflare Origin 证书一致）
DOH_HOST='ai101.eu.org'
DOH_PORT='8053'

# google.com A 的 DNS wire（28 字节）
printf '\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01' > /tmp/doh-q.bin

echo '=== 本地 DoH HTTP/1.1（跳过校验证书链，仅测功能）==='
curl -sk --http1.1 --tlsv1.2 \
  --resolve "${DOH_HOST}:${DOH_PORT}:127.0.0.1" \
  "https://${DOH_HOST}:${DOH_PORT}/dns-query" \
  -H 'Content-Type: application/dns-message' \
  -H 'Accept: application/dns-message' \
  --data-binary @/tmp/doh-q.bin \
  -w 'http=%{http_code} bytes=%{size_download}\n' -o /tmp/doh-r.bin

echo '=== 本地 DoH HTTP/2（需已用新二进制启动，带 ALPN h2）==='
curl -skv --http2 --tlsv1.2 \
  --resolve "${DOH_HOST}:${DOH_PORT}:127.0.0.1" \
  "https://${DOH_HOST}:${DOH_PORT}/dns-query" \
  -H 'Content-Type: application/dns-message' \
  -H 'Accept: application/dns-message' \
  --data-binary @/tmp/doh-q.bin \
  -o /dev/null 2>&1 | grep -E 'ALPN, server accepted|POST /dns-query HTTP/|HTTP/2 200'

echo '=== 公网 Cloudflare DoH（JSON，测出口/上游可达）==='
curl -sk --http2 'https://cloudflare-dns.com/dns-query?name=google.com&type=A' \
  -H 'accept: application/dns-json' | head -c 220; echo

echo '=== 公网 Google DoH（JSON）==='
curl -sk --http2 'https://dns.google/resolve?name=google.com&type=A' | head -c 220; echo
