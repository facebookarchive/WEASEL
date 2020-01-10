# WEASEL: A Stealthy DNS Beacon

WEASEL is a small in-memory implant using Python 3 with no dependencies. The beacon client sends a small amount of identifying information about its host to a DNS
zone you control. WEASEL server can task clients to execute pre-baked or arbitrary
commands.

WEASEL is a stage 1 payload, meant to be difficult to detect and useful for regaining access when your noisy full-featured stages are caught.

**Status**

* Has been successfully used on an operation and evaded detections.
* Client can initialize a session with the server and establish bi-directional
  communication.
* Server has a fully working CLI.
* Client supports a number of functions that the server can task.
* Client is 5.2KB when minified + obfuscated.
* Automatic obfuscation is lacking and needs manual fixing (see [Limitations in client README](client/README.md)).
* Server does not have multi-player (simultaneous multiple operator) support.

## Examples

See usage in [client's README](client/README.md) and [server's README](server/README.md) for specific instructions.

To start the server or client, execute the scripts directly or pass them to the Python interpreter.

Ensure the C2 domains each have an NS record with the IP address of the host running server.py.

## Requirements
WEASEL requires Python 3.6+.

The client is self-contained and only uses standard libraries, therefore it can be run on macOS, Linux, etc.

The server has a few dependencies from pip, included in [server's requirements.txt](server/requirements.txt). The server should be run on Linux, but there is nothing preventing it from running on macOS or other *nix.

## Testing / Running in Development

No need to obfuscate and minimize the beacon in this case. Print statements are
preserved. As with Usage above, ensure NS records for the domain(s) in
`servers` in beacon.py point to the IP address of server.py.

On the server host:

```sudo python3 server.py```

On the victim host (can be the same as server):

```python3 beacon.py```

## Architecture

**You do not need to understand any of this to use WEASEL.**

Beacon communicates over DNS using AAAA queries and answers. It does not use
TXT records due to those being known as being used by DNS malware and tunnels.
Blue teams often have DNS tunneling detections that alert on large TXT queries.

The client side does not need root to operate, does not use raw sockets, and
does not create malformed DNS packets. It uses regular system and language
provided interfaces to make DNS requests. The information is encoded +
encrypted in the records themselves.

* A single A record (IPv4 address) can contain 4 bytes of information.
* A single AAAA record (IPv6 address) can contain 16 bytes of information.
* CNAME records and hostnames used in queries can contain up to 64 bytes per
  subdomain and should be no longer than 255 total bytes per RFC. However, SANS
  DNS detection guidelines say that subdomains longer than 52 characters are
  suspect. For this reason we limit subdomains to 52 characters (configurable
  in the code) and we try to use no more subdomains and requests than we need.
* A response can contain multiple records, up to the size limit of a UDP
  datagram (65,507 bytes).

This beacon is meant to be low and slow, with little bandwidth. It should tell
us which hosts it is on and give us a way to launch further stages as needed,
and nothing more. While this does have arbitrary command support, it is not
meant to be used as a regular interactive shell or communications channel.

WEASEL is a stage 1 that you leave running, ensuring ongoing access as your
full featured (and therefore noisier) stages get caught.

## Persistence

WEASEL was initially targeted for high uptime servers where we had a reliable
foothold/exploitation vector. Evading forensics was a high priority. As a
result, it has no native persistence features. 

You can make it persistent by adding its execution to your favorite persistence
technique, which is left as an exercise to the reader :)

## Protocol and Message Format

### Client Request

A **request (from the client)** is a single AAAA query for a name formatted
like:

```<preamble><data>.<stream>.<session>.domain.tld```

The preamble is 2 bytes. Preamble[0] is that packet's sequence number.
Preamble[1] is the total number of packets in that stream.

Data is limited to 50 bytes (configurable) and contains the payload. The
payload is base32 encoded with a custom alphabet.

#### Payload Encoding

First, all 'w' chars are swapped for '-'.

Next, the padding character is swapped from '=' to 'w' to conform to the DNS
character set: [a-z0-9] and [-].

We don't swap '=' with '-' directly because the padding will always be at the
end of the string, and ending a hostname on '---' is both suspicious and
against DNS RFC. This way when a string does have padding it will end on 'www',
which is both less suspicious and RFC compliant.

### Server Response

A **response (from the server)** is comprised of one or more AAAA answers.

Each AAAA answer is a 16 byte encrypted payload represented as an IPv6 address
using `socket.inet_ntop`. Answers in a DNS response do not maintain their order in
transit, so they are sequenced and reassembled like the client requests.

The transport payload is a string of data elements separated by a ^ character.

### Transport Format

Requests and responses follow this format:

```<type>|<data>```

| Type | Meaning (sender) | AKA | Data |
|------|------------------|-----|------|
| 0    | Acknowledged | ACK | Random hex |
| 1    | Checking in (client) | PING | Random hex |
| 2    | Terminate yourself (server), terminating myself (client) | FIN ||
| 3    | Initialization message (client) | SYN | `version|hostname|kernel` |
| 4    | Reconnect (server) | RST ||
| 5    | Set callback interval (server) || seconds |
| 6    | Get network interface data || `eth0 1.2.3.4/24\neth1 fe80:::/64\n...` |
| 8    | Eval arbitrary Python3 code up to 666 bytes (server), returning first 400 bytes of output (client) | EVAL | python3 oneliner script |
| 9    | Execute arbitrary command up to 666 bytes (server), returning first 400 bytes of output (client) | EXEC | bash command |

### Sessions

Sessions are long lived: a client initiates a session when the beacon is first
executed and that session should last for the entire time the beacon is active
on that client. Note that since the beacon is in-memory and not persistent the
session data is stored in that Python process' memory. Any new invocation of
the beacon will initiate a new session.

Initiating a session involves the client crafting a message with a uniquely
identifying non-data preamble (to signal to the server that this is a new
session): the concatenation of a 32 bytes Diffie-Hellman public key and a 16
byte random AES IV.

The server receives this and responds with its own 32 byte public key. At this
point the client and server have established a shared session key that will be
used for the lifetime of this session to encrypt data payloads using AES-128 in
CTR mode. The Diffie-Hellman Ephemeral exchange ensures each client-server
connection uses a unique session key with forward secrecy.

### Encryption Badness

The crypto is purposefully bad for a number of reasons:

* We are emulating real attackers who generally have little clue how to build
  robust crypto systems and are fans of rolling their own
* The bandwidth of beacon is as low as possible, which means our DHE exchange
  must be kept very small
* Non-attribution is important, we don't authenticate the server
* It is less fun for responders if we use state of the art crypto they can't
  hope to break

Here are some known issues with the crypto scheme:

1. Diffie-Hellman modulus `p` is RFC 3526 Group 5 truncated to the first 32
   bytes. Not only does this limit the public and private keys to 32 bytes, but
   Group 5 is already deprecated and recommended against.
   I call this bad decision "Group 1".
2. We use random.randint() for the exponent `a` instead of a CSPRNG.
3. We use a small amount of data from os.urandom() for session ID and stream ID generation instead of a
   UUID, meaning collisions are likely. We account for this by retrying until we get an ID that isn't being used.
4. The AES-CTR cipher is re-initialized with the same IV (which is long lived
   like the session key) for every stream. This means that the same plaintext
   in the same position across streams will produce the same ciphertext.
5. In AES-CTR the IV is correctly called a nonce, but in our implementation we
   aren't using the number once so it would be a bit rude to call it that.

### Streams

Each message sent between a client and server has to be packetized into max 50
byte packets, in order to stay under that 52 byte limit for common DNS covert
channel detections. All packets for a particular message are part of the same
stream. Message == Stream.

Streams are identified with a 2 byte random hex number. Recall the client
request format is:
```<preamble><data>.<stream>.<session>.domain.tld```

The 2 byte preamble of each packet in the stream has a sequence number and the
total number of packets in that stream. This enables the server to know when
everything has arrived. 

Because this is DNS we're doing this all over UDP, which doesn't provide any
guarantees about the order datagrams will arrive. That is why WEASEL has to
account for sequencing, reassembly, and tracking multiple streams from many
beacons.

Each stream reinitializes a globally shared AES-128-CTR cipher to
encrypt/decrypt payloads.

The payload can only be decrypted once a stream is complete (all packets have
arrived). If it wasn't for base32, we could decrypt what we have of the message
even if we were missing packets (because AES-CTR is a stream cipher) but we
cannot base32 decode partial streams. Oh well. By the nature of DNS clients,
requests are made multiple times (generally 2 or 4 times) until a response is
received, so we have a good probability that we will receive all packets in a
stream as each packet should be sent by the client at least twice. If we do
drop packets or streams, it isn't a big deal, the beacon will check in again
later and will probably have better luck then.

## Join the WEASEL community

See the [CONTRIBUTING](CONTRIBUTING.md) file for how to help out.

## License

WEASEL is MIT licensed, as found in the [LICENSE](LICENSE) file.
