from awe_net.awe_session import AweSessionManager


packet = (
    "GET /login/ HTTP/1.1\r\n"
    "Host: tryhackme.com\r\n"
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
).encode()

sessionManager = AweSessionManager()
response = sessionManager.request(raw_req_pkt=packet)
print(response)