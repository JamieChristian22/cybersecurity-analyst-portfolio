# CASE-004 — Endpoint and network correlation

**Evidence origin:** authored, inert simulation. The XML is Windows-style exported event
XML, not a captured EVTX file. The PCAP is a valid packet file generated locally; no traffic
was transmitted. The generator never launches PowerShell or creates a scheduled task.

## Objective

Investigate an Office-parent PowerShell process, a correlated network event, periodic
connection attempts and a later task-registration event. Demonstrate exactly what each
source supports and where correlation stops short of causation.

## Evidence inventory

| Evidence | Location | Purpose |
|---|---|---|
| Six raw event records | [windows_events.xml](../lab/fixtures/endpoint/windows_events.xml) | Process, network and task context |
| Thirteen packet records | [traffic.pcap](../lab/fixtures/network/traffic.pcap) | One DNS question and twelve TCP SYN packets |
| Authored expected findings | [forensics_expected.json](../lab/fixtures/forensics_expected.json) | Acceptance criteria independent of detector execution |
| Parsed event records | [normalized_events.json](../evidence/endpoint/normalized_events.json) | Inspect fields used by correlation |
| Endpoint alert | [alerts.json](../evidence/endpoint/alerts.json) | GUID-linked process/network finding |
| Parsed packets | [packets.json](../evidence/network/packets.json) | Packet numbers, times, addresses and TCP flags |
| Periodicity finding | [findings.json](../evidence/network/findings.json) | Six attempts with 60-second gaps |
| Independent decoder results | [independent_verification.json](../evidence/network/independent_verification.json) | dpkt agreement and IPv4/TCP checksum verification |
| Evidence hashes | [forensics_manifest.json](../evidence/forensics_manifest.json) | SHA-256 and declared synthetic provenance |

The simulation assigns LAB-WS01 the address 192.0.2.10, reflected in Sysmon record 103.
In a real case, verify that mapping against DHCP/asset records for the event time.

## UTC timeline

| Time | Evidence | Observation |
|---|---|---|
| 11:59:50 | Sysmon 1, record 101 | WINWORD.EXE starts under explorer.exe |
| 11:59:58 | PCAP packet 1 | 192.0.2.10 asks 192.0.2.53 for telemetry.lab.example |
| 12:00:00 | Sysmon 1, record 102 | Office-parent PowerShell uses an encoded command |
| 12:00:00–12:05:00 | Packet numbers 2, 5, 7, 8, 10, 12 | Six SYN attempts to 203.0.113.50:443, 60 seconds apart |
| 12:00:01 | Sysmon 3, record 103 | Same ProcessGuid has network event to 203.0.113.50:443 |
| 12:06:00 | TaskScheduler 106, record 104 | LabTelemetry task registration for LAB\\alex |
| 13:00:00–13:00:01 | Sysmon records 201–202 | Separate service-parent maintenance script and network event |

Packet numbering is generated from timestamp order and is checked against the emitted
packet list. Use the output files as the authoritative event/packet references.

## Findings and confidence

**High confidence in the observed chain:** record 102 has an Office parent and an encoded
PowerShell argument. Record 103 matches the host and ProcessGuid and is one second later.
ENDPOINT-001 requires those correlations; a different host/GUID or out-of-window network
event does not qualify. A service-parent inventory script is a negative control.

**High confidence in periodic connection attempts:** the PCAP contains six SYN-only packets
to the same destination and port with 60-second gaps. NET-001 flags low interval variation.
The irregular background source is not flagged.

**Malicious intent is not established:** decoding the authored command as UTF-16LE gives
`Write-Output 'LAB'`, a harmless command. Encoded PowerShell is not inherently malicious.
For this known simulation, the analyst disposition is **benign positive / authorized lab**.
The automated alert deliberately requests review before that context is applied.

**Connection success, payload transfer and C2 are unproven:** the fixture contains no SYN-ACK,
completed TCP handshake or application payload. It must not be described as confirmed C2,
TLS traffic, a download or exfiltration simply because the destination port is 443.

**DNS association is unproven:** the query has no answer packet. The capture does not establish
that telemetry.lab.example resolved to 203.0.113.50.

**Task causation is unproven:** record 104 shares a user and occurs later, but has no process
GUID linking task registration to PowerShell. Treat it as context requiring enrichment,
not proof that the process established persistence.

## Response and handoff

In an unknown real environment, preserve the original evidence and request script contents,
signature/reputation, user confirmation, process ancestry, task XML and network/session logs.
If unauthorized execution is corroborated, request approved endpoint isolation and session
review. In this authored case no isolation, account reset or network block is warranted.
Document the authorized exercise and retain the alert as a benign-positive training example.

## Reproduction and analyst pivots

```bash
python -m pip install -r requirements-verification.txt
python -m lab.reproduce --with-independent-pcap
```

To regenerate the authored fixtures deliberately: `python -m lab.build_forensics`.
Regeneration is optional; the delivered fixture bytes are already present.
Open `traffic.pcap` in Wireshark and use these filters:

- `dns.qry.name == "telemetry.lab.example"`
- `ip.src == 192.0.2.10 && ip.dst == 203.0.113.50 && tcp.flags.syn == 1 && tcp.flags.ack == 0`
- `ip.src == 192.0.2.20` for the irregular negative control.

Wireshark itself was not executed for this delivery. Native PCAP decoding and checksums
were independently verified with dpkt. The teaching parser intentionally rejects unsupported
PCAP variants, fragmented IP and compressed DNS question names rather than silently guessing.
