# Windows four-validator localnet

These scripts run a real four-validator CometBFT network on one Windows host.
Each validator has its own Asteria ABCI process, `redb` database, CometBFT
home, validator key, P2P/RPC ports, logs, and PID record.

CometBFT is pinned to `v0.38.23`. That upstream tag still prints `0.38.22`
from `cometbft version`, so the scripts verify the executable's embedded Go
module metadata instead of accepting the displayed version alone.

## Start

Run these commands from the repository root in Windows PowerShell 5.1 or
PowerShell 7:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\comet\windows\Install-CometBft.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\comet\windows\Start-Localnet.ps1
```

`Start-Localnet.ps1` is intentionally strict. It returns successfully only
after every node reports four validators, three connected peers, no catch-up,
an identical app hash at a common height, and a new common height observed
during the startup check. `Get-LocalnetStatus.ps1` samples twice over five
seconds and applies the same liveness requirement.

Initialization enables CometBFT vote extensions at height `1`, generates a
fresh 3-of-4 FROST private-order keyset, and binds each lower-case Comet
validator address to threshold validator ID `1` through `4`. The public keyset
is embedded in genesis. Secret shares remain only under
`data\localnet\secrets\private-order`, protected by non-inheriting ACLs for the
current user and `SYSTEM`. Key generation is staged under that protected parent,
and `dkg-session.json` binds the ceremony to the chain domain and a fresh random
ceremony ID. Child processes receive only the share-file path; the Rust node
opens it without following reparse points, validates the DACL on the open file
handle, and reads the contents into zeroizing memory. Raw shares are never
placed in the environment, `manifest.json`, process arguments, PID records, or
logs.

The default development authority is:

```text
ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
```

Its development-only base64 secret is:

```text
AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
```

Never use that identity outside this local network.

To initialize a different development chain, pass the same values every time
the localnet is started:

```powershell
powershell -File deploy\comet\windows\Start-Localnet.ps1 `
  -LocalnetRoot data\custom-localnet `
  -ChainId custom-localnet-1 `
  -Authority ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

## Topology

| Node | HTTP | ABCI | Comet RPC | P2P | Metrics |
| --- | ---: | ---: | ---: | ---: | ---: |
| node0 | 8080 | 26658 | 26657 | 26656 | 26660 |
| node1 | 8081 | 26758 | 26757 | 26756 | 26760 |
| node2 | 8082 | 26858 | 26857 | 26856 | 26860 |
| node3 | 8083 | 26958 | 26957 | 26956 | 26960 |

All listeners bind to `127.0.0.1`. Persistent state defaults to
`data\localnet`; runtime logs and exact process identity records are stored
under the same root.

## Operate

```powershell
# Re-check process, peer, validator, height, and app-hash agreement.
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\comet\windows\Get-LocalnetStatus.ps1 -RequireHealthy

# Stop only the eight processes recorded for this localnet.
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\comet\windows\Stop-Localnet.ps1

# Restart from the same databases, CometBFT homes, and threshold keyset.
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\comet\windows\Start-Localnet.ps1
```

Stopping removes only localnet PID metadata from the filesystem. It preserves
Asteria databases, CometBFT block/WAL/state data, validator keys, private-order
shares, genesis, and logs. Initialization reuses a complete matching network.
Legacy or partial managed state without matching vote-extension, keyset, and
validator-binding configuration is rebuilt destructively; active recorded
processes must be stopped first.

The local generator simulates all four official FROST DKG participants inside
one offline process. It exercises the same session/epoch and key adaptation as
the protocol, but it is not a production distributed ceremony: production must
run each participant separately over authenticated broadcast and confidential
point-to-point channels.
