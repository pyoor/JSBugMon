#!/usr/bin/env python
# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# The Original Code is ADBFuzz.
#
# The Initial Developer of the Original Code is Christian Holler (decoder).
#
# Contributors:
#  Christian Holler <decoder@mozilla.com> (Original Developer)
#
# ***** END LICENSE BLOCK *****

import argparse
import base64
import binascii
import io
import json
import logging
import os
import platform
import re
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta

import requests
from autobisect.bisect import BisectionResult, Bisector
from autobisect.build_manager import BuildManager
from autobisect.evaluator import BrowserEvaluator, JSEvaluator
from bugsy import Bug, Bugsy
from fuzzfetch import BuildFlags, Fetcher, FetcherException
from fuzzfetch.fetch import Platform

log = logging.getLogger("bugmon")

# ToDo: Move ALLOWED_OPTS to autobisect's JS evaluator
ALLOWED_OPTS = [
    '--fuzzing-safe',
    '--ion-eager',
    '--baseline-eager',
    '--ion-regalloc=backtracking',
    # '--ion-regalloc=lsra', Invalid arg
    '--thread-count=2',
    '--cpu-count=2',
    # '--ion-parallel-compile=off', Invalid arg
    '--ion-offthread-compile=off',
    '--ion-check-range-analysis',
    '--ion-gvn=pessimistic',
    '--ion-gvn=off',
    '--no-ion',
    '--no-baseline',
    '--arm-sim-icache-checks',
    '--arm-asm-nop-fill=1',
    '--no-threads',
    # '--unboxed-objects', Invalid arg
    # '--ion-fuzzer-checks', Invalid arg
    '--ion-extra-checks',
    '--arm-hwcap=vfp',
    '--ion-shared-stubs=on',
    '--ion-pgo=on',
    '--nursery-strings=on',
    '--nursery-strings=off',
    # '--enable-experimental-fields', Invalid arg
    '--ion-warmup-threshold=0',
    '--ion-warmup-threshold=1',
    '--baseline-warmup-threshold=0',
    '--baseline-warmup-threshold=1',
    '-D'
]

AVAILABLE_BRANCHES = ['mozilla-central', 'mozilla-beta', 'mozilla-release']
HTTP_SESSION = requests.Session()


def _get_url(url):
    """
    Retrieve requested URL
    """
    data = HTTP_SESSION.get(url, stream=True)
    data.raise_for_status()
    return data


def enum(*sequential, **named):
    enums = dict(list(zip(sequential, list(range(len(sequential))))), **named)
    return type('Enum', (), enums)


class BugException(Exception):
    pass


class ReproductionResult(object):
    PASSED = 0
    CRASHED = 1
    FAILED = 2
    NO_BUILD = 3

    def __init__(self, status, build=None):
        self.status = status
        self.build = build


class BugMonitor:
    def __init__(self, bugsy, bug_num, working_dir, dry_run=False):
        """

        :param bugsy: Bugsy instance used for retrieving bugs
        :param bug_num: Bug number to analyze
        :param working_dir: Path to working directory
        :param dry_run: Boolean indicating if changes should be made to the bug
        """
        self.bugsy = bugsy
        self.bug = self.bugsy.get(bug_num, '_default')
        self.working_dir = working_dir
        self.dry_run = dry_run

        # Raise if target os doesn't match current platform.system()
        self.os = self.identify_os()

        # Raise if testcase extraction fails
        self.testcase = self.extract_testcase()

        # Determine what type of bug we're evaluating
        if self.bug.component.startswith('Javascript Engine'):
            self.target = 'js'
            self.evaluator = JSEvaluator(self.testcase, flags=self.runtime_opts)
        else:
            self.target = 'firefox'
            prefs_path = None
            for filename in os.listdir(self.working_dir):
                with open(os.path.join(self.working_dir, filename)) as f:
                    if filename.endswith('.js') and 'user_pref' in f.read():
                        prefs_path = os.path.join(self.working_dir, filename)
            self.evaluator = BrowserEvaluator(self.testcase, prefs=prefs_path)

        self._original_rev = None
        self._build_flags = None
        self._arch = None

        self.build_manager = BuildManager()

        # Identify current mozilla-central release
        milestone = _get_url('https://hg.mozilla.org/mozilla-central/raw-file/tip/config/milestone.txt')
        version = milestone.text.splitlines()[-1]
        self.central_version = int(version.split('.', 1)[0])

    @property
    def original_rev(self):
        """
        Attempt to enumerate the original rev specified in comment 0 or bugmon origRev command
        """
        if self._original_rev is None:
            if 'origRev' in self.commands and re.match('^([a-f0-9]{12}|[a-f0-9]{40})$', self.commands['origRev']):
                self._original_rev = ['origRev']
            else:
                comments = self.bug.get_comments()
                tokens = comments[0].text.split(' ')
                for token in tokens:
                    if re.match(r'^([a-f0-9]{12}|[a-f0-9]{40})$', token, re.IGNORECASE):
                        # Match 12 or 40 character revs
                        self._original_rev = token
                        break
                    elif re.match(r'^([0-9]{8}-)([a-f0-9]{12})$', token, re.IGNORECASE):
                        # Match fuzzfetch build identifiers
                        self._original_rev = token.split('-')[1]
                        break
                else:
                    self._original_rev = None

        return self._original_rev

    @property
    def runtime_opts(self):
        """
        Attempt to enumerate the runtime flags specified in comment 0
        """
        comments = self.bug.get_comments()
        if len(comments) >= 1:
            comment = comments[0].text
            return list(filter(lambda flag: flag in comment, ALLOWED_OPTS))

        return []

    @property
    def build_flags(self):
        """
        Attempt to enumerate build type based on flags listed in comment 0
        """
        if self._build_flags is None:
            comments = self.bug.get_comments()
            text = comments[0].text
            asan = 'AddressSanitizer: ' in text or '--enable-address-sanitizer' in text
            tsan = 'ThreadSanitizer: ' in text or '--enable-thread-sanitizer' in text
            debug = '--enable-debug' in text
            fuzzing = '--enable-fuzzing' in text
            coverage = '--enable-coverage' in text
            valgrind = False  # Ignore valgrind for now
            self._build_flags = BuildFlags(asan, tsan, debug, fuzzing, coverage, valgrind)

        return self._build_flags

    @property
    def arch(self):
        """
        Attempt to enumerate the original architecture associated with the bug
        """
        if self._arch is None:
            if self.bug.platform == 'ARM':
                return 'ARM64'
            elif self.bug.platform == 'x86':
                return 'i686'
            elif self.bug.platform == 'x86_64':
                return 'AMD64'

        return platform.machine()

    @property
    def commands(self):
        """
        Attempt to extract commands from whiteboard
        """
        commands = {}
        if self.bug.whiteboard:
            match = re.search(r'(?<=\[bugmon:).[^\]]*', self.bug.whiteboard)
            if match is not None:
                for command in match.group(0).split(','):
                    if '=' in command:
                        name, value = command.split('=')
                        commands[name] = value
                    else:
                        commands[command] = None

        return commands

    @commands.setter
    def commands(self, value):
        parts = [f"{k}={v}" if v is not None else k for k, v in value.items()]
        self.bug.whiteboard = re.sub(r'(?<=bugmon:)(.[^\]]*)', ','.join(parts), self.bug.whiteboard)

    def add_command(self, key, value=None):
        """
        Add a bugmon command to the whiteboard
        :return:
        """
        commands = self.commands
        commands[key] = value
        self.commands = commands

    def remove_command(self, key):
        """
        Remove a bugmon command to the whiteboard
        :return:
        """
        commands = self.commands
        if key in commands:
            del commands[key]

        self.commands = commands

    def identify_os(self):
        """
        Attempt to enumerate the original OS associated with the bug
        """
        op_sys = self.bug.op_sys
        if op_sys is not None:
            if 'Linux' in op_sys:
                os_ = 'Linux'
            elif 'Windows' in op_sys:
                os_ = 'Windows'
            elif 'Mac OS' in op_sys:
                os_ = 'Darwin'
            else:
                os_ = platform.system()

            if os_ != platform.system():
                raise BugException('Cannot process non-native bug (%s)' % os_)
            else:
                return os_
        else:
            return platform.system()

    def extract_testcase(self):
        """
        Extract all attachments and iterate over each until a working testcase is identified
        """
        attachments = list(filter(lambda a: not a.is_obsolete, self.bug.get_attachments()))
        for attachment in sorted(attachments, key=lambda a: a.creation_time):
            try:
                data = base64.decodebytes(attachment.data.encode('utf-8'))
            except binascii.Error as e:
                log.warning('Failed to decode attachment: ', e)
                continue

            if attachment.file_name.endswith('.zip'):
                try:
                    z = zipfile.ZipFile(io.BytesIO(data))
                except zipfile.BadZipFile as e:
                    log.warning('Failed to decompress attachment: ', e)
                    continue

                for filename in z.namelist():
                    if os.path.exists(filename):
                        log.warning('Duplicate filename identified: ', filename)
                    z.extract(filename, self.working_dir)
            else:
                with open(os.path.join(self.working_dir, attachment.file_name), 'wb') as file:
                    file.write(data)

        for filename in os.listdir(self.working_dir):
            if filename.lower().startswith('testcase'):
                return os.path.join(self.working_dir, filename)

        raise BugException('Failed to identify testcase!')

    def confirm_open(self, baseline):
        """
        Attempt to confirm open test cases

        :param baseline: A reproduction result
        """
        test_rev = baseline.build.changeset[:12]

        comments = []
        if baseline.status == ReproductionResult.CRASHED:
            log.info(f"Verified as reproducible on {baseline.build.changeset}...")
            if 'confirmed' not in self.commands:
                comments.append(f"BugMon: Verified bug as reproducible on {baseline.build.changeset}")
                # Mark bug as confirmed
                self.add_command('confirmed')
                comments.append(self.bisect(find_fix=False))
            else:
                last_change = datetime.strptime('2019-05-16T18:05:38Z', '%Y-%m-%dT%H:%M:%SZ')
                if datetime.now() - timedelta(days=30) > last_change:
                    comments.append(f"BugMon: Bug remains reproducible on {baseline.build.changeset}")
        elif baseline.status == ReproductionResult.PASSED:
            # ToDo: Don't comment if we haven't confirmed the bug as open before
            log.info(f"Unable to reproduce bug on {baseline.build.changeset}...")
            comments.append(f"BugMon:Unable to reproduce bug on rev {baseline.build.changeset}")

            if 'bugmon' in self.bug.keywords:
                self.bug.keywords.remove('bugmon')

            if 'close' in self.commands:
                self.bug.status = 'RESOLVED'
                self.bug.resolution = 'WORKSFORME'

            if self.original_rev is not None:
                original_result = self.reproduce_bug('central', self.original_rev)
                if original_result.status == ReproductionResult.CRASHED:
                    log.info(f"Initial rev ({self.original_rev} crashes but {test_rev} does not")
                    log.info(f"Attempting to bisect the fix")
                    comments.append(self.bisect(find_fix=True))

        # Remove the confirm command
        if 'confirm' in self.commands:
            self.remove_command('confirm')

        self.report(comments)

    def verify_fixed(self, baseline):
        """
        Attempt to verify the bug state

        Bugs marked as resolved and fixed are verified to ensure that they are in fact, fixed
        All other bugs will be tested to determine if the bug still reproduces

        """
        test_rev = baseline.build.changeset[:12]

        comments = []
        if baseline.status == ReproductionResult.PASSED:
            log.info(f"Verified as fixed on rev {test_rev}")
            comments.append(f"BugMon: Verified bug as fixed on rev {test_rev}")

            if 'bugmon' in self.bug.keywords:
                self.bug.keywords.remove('bugmon')

            if 'close' in self.commands:
                self.bug.status = "VERIFIED"
        elif baseline.status == ReproductionResult.CRASHED:
            log.info(f"Bug is marked as resolved but still reproduces on rev {test_rev}")
            comments.append(f"BugMon: Bug is marked as FIXED but it still reproduces on rev {test_rev}")

        # Only check branches if bug is marked as fixed
        for rel_num in range(self.central_version - 2, self.central_version):
            flag = f'cf_status_firefox{rel_num}'
            if getattr(self.bug, flag) == 'fixed':
                branch = AVAILABLE_BRANCHES[self.central_version - rel_num]
                baseline = self.reproduce_bug(branch)
                if baseline.status == ReproductionResult.PASSED:
                    log.info(f"Verified fixed on Fx{rel_num}")
                    comments.append(f"BugMon: Verified bug as fixed on Fx{rel_num}")

                    # Mark branch as verified
                    setattr(self.bug, flag, 'verified')
                elif baseline.status == ReproductionResult.CRASHED:
                    log.info(f"Bug remains vulnerable on Fx{rel_num}")
                    # Mark branch as affected
                    if getattr(self.bug, flag) != 'affected':
                        setattr(self.bug, flag, 'affected')

        self.report(comments)

    def bisect(self, find_fix):
        """
        Attempt to enumerate the changeset that introduced the bug or,
        if find_fix=True, the changeset that fixed it.

        :param find_fix: Boolean to indicate whether to search for a bug or fix
        """
        if not find_fix:
            start = None
            end = self.original_rev
        else:
            start = self.original_rev
            end = 'latest'

        platform_ = Platform(self.os, self.arch)
        bisector = Bisector(self.evaluator, self.target, 'central', start, end, self.build_flags, platform_, find_fix)
        result = bisector.bisect()

        # Remove bisect command
        if 'bisect' in self.commands:
            self.remove_command('bisect')

        if result.status != BisectionResult.SUCCESS:
            log.warning(f'Failed to bisect testcase')
            output = [f'Bugmon: Failed to bisect testcase ({result.message})',
                      f'> Start: {result.start.changeset} ({result.start.build_id})',
                      f'> End: {result.end.changeset} ({result.end.build_id})']
            return "\n".join(output)

        output = [f'> Start: {result.start.changeset} ({result.start.build_id})',
                  f'> End: {result.end.changeset} ({result.end.build_id})',
                  f'> Pushlog: {result.pushlog}']

        log.info(f'Reduced build range to...')
        for text in output:
            log.info(text)

        range_string = "\n".join(output)
        return f'Bugmon: Reduced build range to...\n{range_string}'

    def process(self):
        """
        Process Bugmon commands present in whiteboard

        Available commands:
        verify - Attempt to verify the bug state
        bisect - Attempt to bisect the bug regression or, if RESOLVED, the bug fix
        """
        baseline = self.reproduce_bug('central')
        if baseline.status == ReproductionResult.NO_BUILD:
            log.warning(f'Could not find matching build to verify status')
            return
        if baseline.status == ReproductionResult.FAILED:
            log.warning(f'Unable to verify status due to bad build')
            return

        # ToDo: Verify and confirm are conflicting commands
        #   No valid scenario exists where both commands should be present on a bug at the same time
        #   We should likely warn via a bug comment or handle this explicitly
        if 'verify' in self.commands or (self.bug.status == 'RESOLVED' and self.bug.resolution == 'FIXED'):
            self.verify_fixed(baseline)
        elif 'confirm' in self.commands or self.bug.status in {'NEW', 'UNCONFIRMED', 'REOPENED'}:
            self.confirm_open(baseline)

        if 'bisect' in self.commands:
            find_fix = baseline.status == ReproductionResult.PASSED
            result = self.bisect(find_fix)
            self.report([result])

    def reproduce_bug(self, branch, rev=None):
        try:
            platform_ = Platform(self.os, self.arch)
            if rev is not None:
                build = Fetcher(self.target, branch, rev, self.build_flags, platform_, nearest=Fetcher.BUILD_ORDER_ASC)
            else:
                build = Fetcher(self.target, branch, 'latest', self.build_flags, platform_,
                                nearest=Fetcher.BUILD_ORDER_DESC)
        except FetcherException as e:
            log.error(f"Error fetching build: {e}")
            return ReproductionResult(ReproductionResult.NO_BUILD)

        with self.build_manager.get_build(build) as build_path:
            status = self.evaluator.evaluate_testcase(build_path)
            if status == Bisector.BUILD_CRASHED:
                return ReproductionResult(ReproductionResult.CRASHED, build)
            elif status == Bisector.BUILD_PASSED:
                return ReproductionResult(ReproductionResult.PASSED, build)
            else:
                return ReproductionResult(ReproductionResult.FAILED, build)

    def report(self, messages):
        """
        Push changes or if dry_run, report to log
        :param messages: List of comments
        :return:
        """
        diff = self.bug.diff()
        if not self.dry_run:
            for message in messages:
                self.bug.add_comment(message)

            # If changes were made to the bug, push and update
            if diff:
                self.bugsy.put(self.bug)
                self.bug.update()
        else:
            for message in messages:
                for line in message.splitlines():
                    log.info(f"Comment: {line}")
            log.info(f"Changes: {json.dumps(diff)}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser()

    # Optional args
    parser.add_argument('-d', '--dry-run', action='store_true', help="If enabled, don't make any remote changes")

    # Bug selection
    bug_list = parser.add_mutually_exclusive_group(required=True)
    bug_list.add_argument('--bugs', nargs='+', help='Space separated list of bug numbers')
    bug_list.add_argument('-s', '--search-params', help='Path to advanced search parameters')
    args = parser.parse_args(argv)

    if args.search_params and not os.path.isfile(args.search_params):
        raise parser.error('Search parameter path does not exist!')

    return args


def console_init_logging():
    log_level = logging.INFO
    log_fmt = "[%(asctime)s] %(message)s"
    if bool(os.getenv("DEBUG")):
        log_level = logging.DEBUG
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    logging.basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)


def main(argv=None):
    args = parse_args(argv)

    # Get the API root, default to bugzilla.mozilla.org
    api_root = os.environ.get('BZ_API_ROOT')
    api_key = os.environ.get('BZ_API_KEY')

    bugsy = Bugsy(api_key=api_key, bugzilla_url=api_root)

    bug_ids = []
    if args.bugs:
        bug_ids.extend(args.bugs)
    else:
        with open(args.search_params) as f:
            params = json.load(f)
            response = bugsy.request('bug', params=params)
            bugs = [Bug(bugsy, **bug) for bug in response['bugs']]
            bug_ids.extend([bug.id for bug in bugs])

    for bug_id in bug_ids:
        with tempfile.TemporaryDirectory() as temp_dir:
            bugmon = BugMonitor(bugsy, bug_id, temp_dir, args.dry_run)
            log.info(f"Analyzing bug {bug_id} (Status: {bugmon.bug.status}, Resolution: {bugmon.bug.resolution})")
            bugmon.process()


if __name__ == '__main__':
    console_init_logging()
    sys.exit(main())
