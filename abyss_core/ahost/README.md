# ahost (Abyss Host)

This package defines the main interface of abyss_core library, AbyssHost.
AbyssHost 

## Major Features

### Member variables

: Holds AbyssNode (`net`) and AND algorithm provider (`and`), along with a world OnTimeout event reservation queue (`timer_queue`) for AND operation.

All internal procedures under AbyssHost should run under a service context (`service_ctx`), and the host should be shut down when the context is cancelled (`service_cancelfunc`).

As AND algorithm is inherently not thread-safe, we have host-wide mutex (`mtx`).
When a peer connects/disconnects, an AND message arrives, or AND-related API is called, all the world-related operations should be conducted while occupying the mutex.

The host actively accepts peer connections, reads AHMP messages, and call AND algorithms on worlds.
As the product, the host maintains a set of worlds (`worlds`), their mapping with join paths (`world_path_mapping, exposed_worlds`), each peer's participating worlds (`peer_participating_worlds`), and worlds expecting new peers (`requested_peers`).
The structure of requested_peers may be a bit confusing.
The reason why it takes `map[uuid.UUID]*and.World` as values is to filter out duplicate peer requests from a world, ensuring only one `PeerConnected()` calls happen for a peer on a world.


| Member | Population | Depopulation |
| -------- | -------- | -------- |
| `peers` | when accepted the peer | when the peer serving loop returns (should call `World.PeerDisconnected()`) |
| `worlds` | `JoinWorld()`, `OpenWorld()` | `CloseWorld()` |
| `world_path_mapping`, `exposed_worlds` | `ExposeWorldForJoin()` | `HideWorld()`, `CloseWorld()` |
| `peer_participating_worlds` | `JoinWorld()`, received `JN` or `MEM` (should call `World.PeerConnected()`) | `EANDPeerDiscard`, when the peer serving loop returns |
| `requested_peers` | `EANDPeerRequest` but peer did not exist | when accepted the peer, `CloseWorld()` |

Peer failures are primarily detected at servePeer() routine, which will return with error.
Handling this is a bit messy now.
`World` may raise `EANDPeerDiscard` event when a peer is considered malfunctioning. 
At this moment, the peer has already been removed from the `World`.
Also, the peer service routine calls `World.PeerDisconnected()` when returning (deferred).
This removes the peer from the `World` without raising `EANDPeerDiscard`.


All the resulting events are queued to a channel (`event_ch`), which the client-side is expected to consume.

### Bind()

: Calls Listen() AbyssNode.

### Serve()

: Runs all internal loops