from __future__ import print_function
import datetime
import ipaddress
import os
import pyinotify
import re
import subprocess
import time
import importlib.machinery
import glob

# Ban any peer that has at least THRESHOLD authentication failures in TIMESPAN.
BAN_THRESHOLD = 10
BAN_TIMESPAN = datetime.timedelta(0, 5 * 60)

def ban_ip(ip):
    if ip.is_private:
        print("Ignoring private IP address {}".format(ip))
        return

    if ip.is_link_local:
        print("Ignoring link-local IP address {}".format(ip))
        return

    if ip.is_reserved:
        print("Ignoring reserved IP address {}".format(ip))
        return

    if ip.version == 4:
        cmd = ['iptables', '-A', 'bandit', '-s', ip.exploded, '-j', 'DROP']
        print(datetime.datetime.now(), '>', ' '.join(cmd))
        subprocess.call(cmd)
    else:
        print("{}: Can't handle IP address version {}".format(ip, ip.version))

class Bandit(pyinotify.ProcessEvent):
    def __init__(self, filters, ban_handler):
        self.ban_handler = ban_handler

        self.path_filters = {}
        self.dir_paths = {}
        self.path_fps = {}
        self.fp_inodes = {}
        self.fp_paths = {}

        self.sightings = {}
        self.banned_ips = set()

        self.watch_manager = pyinotify.WatchManager()
        self.notifier = pyinotify.Notifier(self.watch_manager, self, timeout=10000)

        for name, props in filters.items():
            for path in props['files']:
                if path not in self.path_filters:
                    self.reopen_file(path)
                    self.path_filters[path] = []

                    dirpath = os.path.dirname(path)
                    if dirpath not in self.dir_paths:
                        self.dir_paths[dirpath] = []
                        self.watch_manager.add_watch(dirpath, pyinotify.IN_CREATE, rec=True)

                    self.dir_paths[dirpath].append(path)

                self.path_filters[path].append(props['deriv'])

    def process_IN_CREATE(self, event):
        def check_path(path):
            old_fp = self.path_fps.get(path, None)
            new_stat = os.stat(path)
            if old_fp is None or new_stat.st_ino != self.fp_inodes.get(old_fp, -1):
                self.reopen_file(path)

        if event.pathname in self.path_filters:
            check_path(event.pathname)

    def process_IN_MODIFY(self, event):
        def consume_from(path):
            lines = self.path_fps[path].readlines()

            for line in lines:
                line = line.strip()

                for deriv in self.path_filters[path]:
                    res = deriv(line)
                    if res is not None:
                        when, ip = res
                        self.handle_bandit(when, ip)
                        break

        if event.pathname in self.path_filters:
            consume_from(event.pathname)

    def reopen_file(self, path):
        if path in self.path_fps:
            print("Reopening {}".format(path))
            old_fp = self.path_fps[path]
            old_fp.close()
            del self.path_fps[path]
            del self.fp_inodes[old_fp]
            del self.fp_paths[old_fp]
        else:
            print("Opening {}".format(path))

        try:
            fp = open(path, 'r')
            fp.seek(0, os.SEEK_END)

            self.path_fps[path] = fp
            self.fp_paths[fp] = path

            self.fp_inodes[fp] = os.fstat(fp.fileno()).st_ino

            self.watch_manager.add_watch(path, pyinotify.IN_MODIFY, rec=True)

        except IOError as e:
            print("Error opening {}: {}".format(path, e))

    def handle_bandit(self, when_str, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as e:
            print('Invalid IP address \'{}\''.format(ip_str))
            return

        try:
            when = datetime.datetime.strptime(when_str, '%Y-%m-%d %H:%M:%S')
        except ValueError as e:
            print('Invalid timestamp \'{}\''.format(when_str))
            return

        ip_seen = self.sightings.get(ip, [])
        ip_seen.append(when)
        self.sightings[ip] = ip_seen[-BAN_THRESHOLD:]

        count = len(ip_seen)

        if count >= BAN_THRESHOLD:
            if ip not in self.banned_ips:
                timespan = when - ip_seen[0]

                if timespan < BAN_TIMESPAN:
                    print("{} Banning {}: {} failed attempts in {} seconds".format(
                        when, ip.compressed, count, timespan.total_seconds()))
                    self.ban_handler(ip)
                    self.banned_ips.add(ip)

    def run(self):
        while True:
            while self.notifier.check_events():
                self.notifier.read_events()
                self.notifier.process_events()
