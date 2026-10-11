# Safety: what a scan sends, and the guardrails

Only scan devices you own or are explicitly authorized to test, ideally on an
isolated lab network. Glitched enforces this as far as software can:

- **One-time notice.** The first scan asks you to accept an authorized-use
  notice (`glitched acknowledge`). Unattended runs such as `autoscan` from cron
  never prompt: they refuse until it's been accepted.
- **Private addresses only, unless approved.** A target that resolves outside
  private, loopback or link-local ranges needs an explicit confirmation, or
  `--allow-public` in scripts. The approval is stored with the assessment or
  device and re-checked right before probing, so a hostname that later
  resolves to a public address is skipped. The host is looked up once per
  scan and every probe connects to that address, so a DNS answer that changes
  mid-scan can't redirect it.
- **One host at a time.** Devices are single hosts; ranges, lists and CIDR
  blocks are refused.
- **Automated checks are passive.** Active steps (crafted input, changing the
  device) are only listed for you to perform and record with `glitched approve`.

**What a scan sends** to the one target host, one connection at a time:

| Check | Traffic |
|---|---|
| Open ports (TID-408) | A TCP connect to 13 common ports (22, 23, 80, 443, 554, 1883, 2222, 5683, 8080, 8443, 8883, 9090, 11311), 2 s timeout each. On each open port it waits half a second for the server's greeting (SSH announces itself), then, if it isn't SSH, attempts a TLS handshake. No other data is sent. SSH and TLS count as encrypted; Telnet, HTTP, MQTT, RTSP, CoAP, rosbridge and the ROS master without TLS as plaintext; anything else is reported as unknown. |
| Weak TLS (TID-411) | The same connects and handshakes; it records the negotiated TLS version. |
| Unauthenticated access (TID-406) | One `GET /` over HTTP on ports 80, 8080 and 9090 and over HTTPS on 443 and 8443, 3 s timeout, no credentials or payload; redirects aren't followed. It reads the status, headers and up to 64 KB of the page: a credentials prompt, a redirect to a login page or a login form counts as protected; data (JSON) without logging in as exposed; any other page as "check by hand". On 9090 (rosbridge) and any port that asks for a WebSocket, it also opens a WebSocket handshake with no token - accepted means exposed - and closes it at once; no ROS messages are sent. |
| `profile detect` / onboarding | The same connects (greeting, then a TLS handshake attempt) to the 13 ports above plus 29999 (Universal Robots dashboard), to suggest profile entries you confirm. |
