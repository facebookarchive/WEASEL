This code has been adapted from [ricmoo/pyaes](https://github.com/ricmoo/pyaes).

The goal was to break out AES-128-CTR functionality into the smallest
reasonable implementation, so it can be included in a single payload.

The obfuscated file has single character object names so it is slightly less
obvious what the code does. This is what is pasted into payloads.

Running either file should work with no additional crypto dependencies.
