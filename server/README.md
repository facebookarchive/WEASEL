# WEASEL Server (C2)

This is the part that runs on your server. It pretends to be an upstanding DNS
server until a beacon comes along.

## How it works

It uses [dnslib](https://pypi.org/project/dnslib/) to run a rudimentary
nameserver and programmatically controls every answer. This enables it to do
funky stuff like support a set of static DNS records (like a regular DNS
server) while also responding with dynamic AAAA answers if it detects an
inbound query coming from a beacon.

It exposes a commandline interface (REPL) that has tab completion and pretty
printing of all the beacons it knows about. Through the REPL an operator can
task beacons and receive their responses.

It is self contained in a single file and does not use a proper database -- all
state is stored in memory in two god objects. There is save and autosave
functionality that serializes (via [dill](https://pypi.org/project/dill/))
state to disk.

There is no multi-player support (that is, multiple operators each with their
own interface). We have done multi-player by sharing a tmux pane, it's not
great.

As you can tell this was a PoC that served its purpose. A more robust server is
in the works which will have support for multi-player and a better interface.

## Usage

1. Install the Python 3 modules it depends on:
```
$ pip3 install -r requirements.txt
```

2. Ensure ADDR and PORT will bind to the interface you want the C2 available
   on. Don't forget about iptables and hosting provider firewalls: the port is
   UDP.

    Note that you should probably not change PORT from 53 since that is where
    DNS queries for your domain will go. You may want to change it to
    another port if you are using a redirector or port forwarding, but I
    recommend leaving it on 53 even with redirectors.

3. Optionally, change TTL. This applies to every dynamic response. Note that
   many resolvers on the internet will completely ignore this and use whatever
   TTL they think is appropriate, but they will lie and pass on your TTL in the
   DNS response.

4. Set STATIC_RECORDS for your zone(s). At a minimum, you'll want to be
   authoritative for the C2 domains pointed at this server. That means each
   domain will need SOA, NS, and A records. You can add additional records if
   you want to serve up non-WEASEL things from the same domain.

5. Run it as root. Dnslib needs this for raw socket() access.
```
$ sudo python3 server.py
```

## Commands

There is tab completion.

Run `help` or `h`! To get help text for a specific command try `help [command]`.

```
Available commands (server v1)
==============================
autosave         cancel  function  interval  queue    sessions  
autosave_cancel  delete  help      kill      restore  shell     
autotask         exit    info      now       save     shellasync
```
