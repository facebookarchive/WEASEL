# WEASEL Beacon/Implant (Client)

This is the part that runs on your target. You need to find a way to deliver
this payload to the target and have the Python 3 interpreter execute it
(`python3 beacon.py` or `cat beacon.py | python3`).

## How it works

Beacon checks in every `interval` seconds by making a DNS query for the IPv6
address of a random/unique subdomain under the C2 domain.

The C2 server returns one or more IPv6 address answers (AAAA) containing
the encoded response.

Beacon decrypts, decodes, and reassembles the replies then acts on them.

Beacon initiates all communications, the C2 server cannot proactively reach out
to a beacon, it has to wait for a beacon to check in then reply with tasking.

Because we're (ab)using DNS, beacon does not need a clear path to the internet
and it does not need to know anything about the networking layout of the
environment it detonates in. It trusts Python and the underlying OS to make DNS
queries and provide the response. In this way it successfully operates in
heavily segmented networks because DNS is usually forwarded out.

Hence, it weasels its way through firewalls and "air gaps"!

## Usage

Ensure the C2 domain(s) has an NS record with the IP address of the host
running server.py.

Edit beacon.py in the configurable section:

* Set `servers` (list of strings) to the C2 domains, each should be base64
  encoded to frustrate basic strings IOC searches.
* Set `interval` (integer) to the number of seconds to wait between checkins.
  This is also configurable per-client from the C2.
* Optionally, change `max_connection_attempts_before_next_server` (integer) to
  configure how many times beacon attempts a domain in the `servers` list
  before accepting it's unreachable and trying the next one. An attempt is
  counted initialization doesn't succeed. If a server times out, beacon tries a
  new server immediately under the assumption that the existing server is dead.
* Optionally, change `all_my_servers_are_dead_sleep_time` (integer) to
  configure how many seconds beacon waits after it has run through all
  available servers before starting over from the beginning. This only applies
  when every server has timed out.
* Optionally, change `MIN_TIMEOUT` (integer) to the number of seconds to wait
  for a response before deciding that a server is unreachable and to
  reinitialize with the next server in the list.

### Obfuscate the payload

1. Remove single line comments, DEV lines, and print statements. By removing
   DEV lines this makes the production beacon silently eat all exceptions and
   run indefinitely.

    ```
    $ grep -vE '^\s*#[^!]|^\s*#$|# DEV|^\s*$|print\(' beacon.py > beacon.min.py
    ```

    Ensure the code is indented correctly after lines were removed. Common
    culprit is the first line of `if name == main` at the end of the file,
    around line 340: `lastrun = 0`.

2. Obfuscate the code.

    ```
    $ pyminifier -O --obfuscate-import-methods --replacement-length=2 beacon.min.py > beacon.obf.py
    ```

3. Manually fix the things pyminifier broke. Here are the known issues. I use
   `qx` in these instructions but that name is different every pyminifier run.
	1. Remove the last line in the file: "# Created by pyminifier".

	2. Remove all left over multiline comments.

	3. It tries to obfuscate sys.stdout object reference by doing something
	   like `qx=sys.stdout` in the top of the file, before our code.
	   Because of how fd redirection works in Python this doesn't do what
	   pyminifer wants: that is, qx isn't a replacement for sys.stdout.

	    **Fix:** find `qx=sys.stdout` around line 35.
	    Replace all instances of `qx` in the code with `sys.stdout`.

	4. It tries and fails to obfuscate exec(arg) calls. For some reason,
	   the line `qx=exec` never gets written but pyminifier goes on
	   thinking it did, so you'll get the code qx(arg) which won't execute
	   because qx doesn't exist.

	    **Fix:** find `qx(cmd)` around line 150. It will be close to the top
	    of a function, in a tree like: def->try->if->try.
            Replace all instances of `qx(cmd)` with `exec(cmd)`.

	5. The AES code gets mangled and won't execute. For some reason it
	   starts obfuscating it and gives up part way through, leaving broken
	   references everywhere. It's not worth fixing this every time, so we
	   have a lightly (manually) obfuscated version of the AES code in
	   pyaes/pyaes-test.obf.py.

 	    **Fix:** find the obfuscated AES code in beacon.obf.py, it will be
   	    at the end of the file, the last 3 classes before `if name == main`.

	    The last of those classes is AES128CTR and it has 2 methods besides
	    init: encrypt() and decrypt() in that order. Note the names of this
	    class and methods.

	    Copy the code in pyaes-test.obf.py (leaving out `main()` please) and
	    paste it in place of the code in beacon.obf.py.

	    Rename the last class `I` and its two methods `p` and `P`, to
	    whatever the obfuscated code used. This fixes references in the rest
            of beacon.obf.py.

	    Rename `self.p(q)` in the last method (decrypt() aka P()) to
            self.X(q) where X is the name of the obfuscated encrypt() method aka p().

4. Compress the final payload.

    ```
    $ pyminifier --bzip2 beacon.obf.py > beacon.obf.bz2.py
    ```

5. Remove the last line in the file: "# Created by pyminifier".

#### Limitations

The following are not obfuscated or mangled:

* String and int literals, leaving baked-in shell commands intact and the
  crypto primitives
  * The C2 domains in `servers`
* Imports
* Imported function/method names (from class import func)
* Function arguments (def x(arg1, arg2=default):)
* Builtin functions (String.encode())
* Multiline comments

Strings and ints can be manually split and encoded in something that won't be
super obvious if someone `cat` or `strings` the file.

Function argument names can be manually obfuscated by replacing the args with
less informative variants: `is_domain` -> `x`.

Builtins and the `import` statement annoying, but can be done with a bit of
work: https://benkurtovic.com/2014/06/01/obfuscating-hello-world.html

## Functionality

It can:

* Kill self
* Reconnect/reinitialize
* Set check in interval
* Get network interfaces and associated IPs
* Eval arbitrary Python 3 code, either silently or returning the output
* Execute arbitrary shell commands, either silently or returning the output

Additional functionality is easy to add. I kept it simple because it was
designed to be a stealthy implant from which we launch noisier interactive
shells that were more likely to be caught (at which point we would fallback
to beacon and launch another stage).

## Files

* **beacon.py** is the beacon client, it includes its own AES implementation
* **pyaes/** contains the AES-128-CTR Python 3 implementation used in beacon.py
