# Maintaining the Detection Data

The detection lists live in `data_*.go` files, separate from the matching
logic in `bot_filter.go`.

| File                   | Contents                                  | Staleness risk |
|------------------------|-------------------------------------------|----------------|
| `data_user_agents.go`  | Broad and specific bot user-agent patterns | Medium         |
| `data_referrers.go`    | Referrer spam domains                      | Medium         |
| `data_paths.go`        | Bot and malicious path patterns            | Low            |
| `data_ip_ranges.go`    | Data-center / cloud CIDR ranges            | High           |

## Rules for every list

- Entries must be lowercase and unique (CIDRs: valid, no host bits set, unique).
- These rules are enforced by the `data_*_test.go` files, so
  `go test ./...` fails if you break them.
- Keep entries alphabetical within a group where the file already does so.
- Add a short trailing comment when a pattern is not self-explanatory.

## Adding a single entry

1. Add the entry to the matching `data_*.go` file.
2. Add a case to `bot_filter_test.go` if the entry has special matching
   behavior (word boundary, suffix match, etc.).
3. Run `gofmt -l . && go vet ./... && go test ./...`.

## Refreshing the data-center CIDR ranges

`data_ip_ranges.go` is hand-maintained and uses coarse ranges (for example AWS
and Azure `/8` blocks), so it drifts from the providers' real allocations.
Review it periodically, for example every 6 to 12 months or when you see
false positives or missed cloud traffic.

### Sources

| Provider     | Published ranges                                                                                                   |
|--------------|--------------------------------------------------------------------------------------------------------------------|
| AWS          | https://ip-ranges.amazonaws.com/ip-ranges.json                                                                     |
| GCP          | https://www.gstatic.com/ipranges/cloud.json                                                                        |
| Azure        | Download "Azure IP Ranges and Service Tags - Public Cloud" from the Microsoft Download Center (`ServiceTags_Public.json`) |
| Cloudflare   | https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6                                            |
| Others (Hetzner, OVH, DigitalOcean, ...) | Look up the provider's ASNs (for example with `bgp.he.net`) and list the announced prefixes |

### Procedure

1. Download the current range files for each provider you want to refresh.
2. Extract the prefixes. For AWS, take `prefixes[].ip_prefix` and
   `ipv6_prefixes[].ipv6_prefix`; for GCP, `prefixes[].ipv4Prefix` and
   `prefixes[].ipv6Prefix`. Keep only the services that represent compute or
   hosting (for AWS, `EC2`). Skip CDN and edge services (such as
   `CLOUDFRONT`) if you do not want to flag them.
3. Aggregate the prefixes (merge adjacent and contained ranges) to keep the
   list small. Prefer exact provider prefixes over coarse blocks.
4. Replace the provider's group in `data_ip_ranges.go`, keeping the
   `// Provider` comment headers and the IPv4/IPv6 sections.
5. Run `go test ./...`. The CIDR test rejects invalid, duplicate, or
   non-canonical entries (for example `2600:1f01::/24`, which normalizes to
   `2600:1f00::/24`).
6. Spot-check with `IsDataCenterIP` against a few known addresses from each
   provider and a few ordinary residential addresses.
7. Note the refresh date and sources in the commit message.

### Trade-offs

- Precise lists are more accurate but much longer, and `IsDataCenterIP` scans
  the list linearly. If the list grows into the thousands, consider switching
  to a prefix trie or a sorted structure.
- Coarse blocks catch more traffic but risk false positives on non-datacenter
  addresses. Document any coarse block you keep.

### Possible automation

If manual refreshes become a burden, generate the file instead of editing it:
write a small script under `tools/` (or `go:generate`) that downloads the
sources above and writes `data_ip_ranges.go`. The existing CIDR test will
validate the generated output.
