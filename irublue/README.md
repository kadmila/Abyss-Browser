# Irublue.com : public peer registry 

## Structure

Irublue.com has two servers, one standard https(http) server, 
and another http/3 server.

The first server handles most of the requests of the irublue.com, including content service, API requests, etc.
The second server is for collocated http/3 client access, which the handshake authenticates the peer.

Using the collocated http/3 server, irublue.com can acquire peers' addresses. 
It returns the address back to each peer, so that the peer can update its handshake key certificate, which includes its address candidiates.
Along with the addess, irublue.com provides *peer authentication token* as a cookie (with no expiration).
A peer authentication token is a secret the client can use to authenticate itself.
The two servers share the auth token <-> peer information relationships.
Inside irublue.com, peer information expires if the auth token has not been presented for a minute.

Peer may provide handshake key certificate to irublue.com, which is referred to as the *contact information* when combined with the peer's root certificate.
Irublue.com caches the contact information for 10 minutes.

An *anchor* is a content from irublue.com that serves as a join request accepter of the peer.
While the anchor is live, it does traditional http fetch spin waiting.
When it receives a (irublue) join request, the spin wait returnes one of the followings:
1) A peer's contact information
2) contact information request 
3) error (requires content restart)
As irublue.com periodically receives spin waiting, the authentication token expiration time will be elongated.

## Scenario - Anchor Main Loop

1) A peer loads an anchor from irublue.com
2) The anchor sends fetch GET to https://irublue.com:3344, with collocated HTTP/3 client.
3) Irublue.com:3344 issue a new peer authentication token, and invalidate the old one, if exists.
4) Irublue.com:3344 responds with the peer's public ip/port (from connection) and sets the authentication token.
5) The anchor sends fetch GET to https://irublue.com/wait
6) Irublue.com checks the token, and waits for a join request. - if returns empty 500, anchor goes back to 5.
7) When there was a join request, irublue.com returns the corresponding information. 
If the contact information has expired, or some error occured, the anchor resets itself.
8) For a join request, the anchor calls `host.appendKnownPeer()`, and `Dial()`.

## Scenario - Anchor Random Join

1) A peer clicks a button on the anchor.
2) The anchor sends fetch GET to irublue.com/random
3) irublue.com picks up a random pending waiting peer, and responds with the peer's contact information.
5) Atomically, irublue.com responds with the waiting peer's contact information.
