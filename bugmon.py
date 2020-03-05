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

        # Initialize placeholders
        self._arch = None
        self._branch = None
        self._branches = None
        self._build_flags = None
        self._comment_zero = None
        self._env_vars = None
        self._original_rev = None
        self._os = None
        self._runtime_ops = None

        self.fetch_attachments()
        self.testcase = self.identify_testcase()

        # Determine what type of bug we're evaluating
        if self.bug.component.startswith('JavaScript Engine'):
            self.target = 'js'
            self.evaluator = JSEvaluator(self.testcase, flags=self.runtime_opts)
        else:
            self.target = 'firefox'
            self.evaluator = BrowserEvaluator(self.testcase, env=self.env_vars, prefs=self.identify_prefs())

        self.build_manager = BuildManager()

        # Identify mozilla-central version number
        milestone = _get_url('https://hg.mozilla.org/mozilla-central/raw-file/tip/config/milestone.txt')
        version = milestone.text.splitlines()[-1]
        self.central_version = int(version.split('.', 1)[0])

    @property
    def arch(self):
        """
        Attempt to enumerate the original architecture associated with the bug
        """
        if self._arch is None:
            if self.bug.platform == 'ARM':
                self._arch = 'ARM64'
            elif self.bug.platform == 'x86':
                self._arch = 'i686'
            elif self.bug.platform == 'x86_64':
                self._arch = 'AMD64'
            else:
                self._arch = platform.machine()

        return self._arch

    @property
    def version(self):
        match = re.match(r'\d+', self.bug.version)
        if match:
            return match.group(0)

        return self.central_version

    @property
    def branch(self):
        """
        Attempt to enumerate the branch the bug was filed against
        """
        if self._branch is None:
            for alias, actual in self.branches.items():
                if self.version == actual:
                    self._branch = alias
                    break

        return self._branch

    @property
    def branches(self):
        """
        Create map of fuzzfetch branch aliases and bugzilla version tags
        :return:
        """
        if self._branches is None:
            self._branches = {
                'central': self.central_version,
                'beta': self.central_version - 1,
                'release': self.central_version - 2,
            }

            for alias in ['esr-next', 'esr-stable']:
                try:
                    rel_num = Fetcher.resolve_esr(alias)
                    if rel_num is not None:
                        self._branches[rel_num] = rel_num
                except FetcherException:
                    pass

        return self._branches

    @property
    def build_flags(self):
        """
        Attempt to enumerate build type based on flags listed in comment 0
        """
        if self._build_flags is None:
            self.comment_zero
            asan = 'AddressSanitizer: ' in self.comment_zero or '--enable-address-sanitizer' in self.comment_zero
            tsan = 'ThreadSanitizer: ' in self.comment_zero or '--enable-thread-sanitizer' in self.comment_zero
            debug = '--enable-debug' in self.comment_zero
            fuzzing = '--enable-fuzzing' in self.comment_zero
            coverage = '--enable-coverage' in self.comment_zero
            valgrind = False  # Ignore valgrind for now
            self._build_flags = BuildFlags(asan, tsan, debug, fuzzing, coverage, valgrind)

        return self._build_flags

    @property
    def comment_zero(self):
        """
        Helper function for retrieving comment zero
        """
        if self._comment_zero is None:
            comments = self.bug.get_comments()
            self._comment_zero = comments[0].text

        return self._comment_zero

    @property
    def env_vars(self):
        """
        Attempt to enumerate any env_variables required
        """
        if self._env_vars is None:
            variables = {}
            tokens = self.comment_zero.split(' ')
            for token in tokens:
                if token.startswith('`') and token.endswith('`'):
                    token = token[1:-1]
                if re.match(r'([a-z0-9_]+=[a-z0-9])', token, re.IGNORECASE):
                    name, value = token.split('=')
                    variables[name] = value

            self._env_vars = variables

        return self._env_vars

    @property
    def original_rev(self):
        """
        Attempt to enumerate the original rev specified in comment 0 or bugmon origRev command
        """
        if self._original_rev is None:
            if 'origRev' in self.commands and re.match('^([a-f0-9]{12}|[a-f0-9]{40})$', self.commands['origRev']):
                self._original_rev = ['origRev']
            else:
                tokens = self.comment_zero.split(' ')
                for token in tokens:
                    if token.startswith('`') and token.endswith('`'):
                        token = token[1:-1]

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
    def os(self):
        """
        Attempt to enumerate the original OS associated with the bug
        """
        if self._os is None:
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
                    self._os = os_
            else:
                self._os = platform.system()

        return self._os

    @property
    def runtime_opts(self):
        """
        Attempt to enumerate the runtime flags specified in comment 0
        """
        if self._runtime_ops is None:
            self._runtime_ops = list(filter(lambda flag: flag in self.comment_zero, ALLOWED_OPTS))

        return self._runtime_ops

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

    def fetch_attachments(self):
        """
        Download all attachments and store them in self.working_dir
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

    def identify_testcase(self):
        """
        Identify testcase in working_dir
        """
        for filename in os.listdir(self.working_dir):
            if filename.lower().startswith('testcase'):
                return os.path.join(self.working_dir, filename)

        raise BugException('Failed to identify testcase!')

    def identify_prefs(self):
        """
        Identify prefs in working_dir
        """
        prefs_path = None
        for filename in os.listdir(self.working_dir):
            with open(os.path.join(self.working_dir, filename)) as f:
                if filename.endswith('.js') and 'user_pref' in f.read():
                    prefs_path = os.path.join(self.working_dir, filename)
        return prefs_path

    def confirm_open(self, baseline):
        """
        Attempt to confirm open test cases

        :param baseline: A reproduction result
        """
        test_rev = baseline.build.changeset[:12]

        comments = []
        if baseline.status == ReproductionResult.CRASHED:
            log.info(f"Verified as reproducible on {test_rev}...")
            if 'confirmed' not in self.commands:
                comments.append(f"BugMon: Verified bug as reproducible on {test_rev}")
                # Mark bug as confirmed
                self.add_command('confirmed')
                comments.append(self.bisect(find_fix=False))
            else:
                last_change = datetime.strptime('2019-05-16T18:05:38Z', '%Y-%m-%dT%H:%M:%SZ')
                if datetime.now() - timedelta(days=30) > last_change:
                    comments.append(f"BugMon: Bug remains reproducible on {test_rev}")
        elif baseline.status == ReproductionResult.PASSED:
            # ToDo: Don't comment if we haven't confirmed the bug as open before
            log.info(f"Unable to reproduce bug on {test_rev}...")
            comments.append(f"BugMon:Unable to reproduce bug on rev {test_rev}")

            if 'bugmon' in self.bug.keywords:
                self.bug.keywords.remove('bugmon')

            if 'close' in self.commands:
                self.bug.status = 'RESOLVED'
                self.bug.resolution = 'WORKSFORME'

            if self.original_rev is not None:
                original_result = self.reproduce_bug(self.branch, self.original_rev)
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
            if self.original_rev is not None:
                initial = self.reproduce_bug(self.branch, self.original_rev)
                if initial.status != ReproductionResult.CRASHED:
                    msg = f"Bug appears to be fixed on rev {test_rev} but " \
                          f"BugMon was unable to reproduce using the initial rev {self.original_rev}"
                    log.info(msg)
                    comments.append(f"BugMon: {msg}")
                else:
                    log.info(f"Verified as fixed on rev {test_rev}")
                    comments.append(f"BugMon: Verified bug as fixed on rev {test_rev}")

            if 'bugmon' in self.bug.keywords:
                self.bug.keywords.remove('bugmon')

            if 'close' in self.commands:
                self.bug.status = "VERIFIED"
        elif baseline.status == ReproductionResult.CRASHED:
            log.info(f"Bug is marked as resolved but still reproduces on rev {test_rev}")
            comments.append(f"BugMon: Bug is marked as FIXED but it still reproduces on rev {test_rev}")

        for alias, rel_num in self.branches.items():
            if isinstance(rel_num, int):
                flag = f'cf_status_firefox{rel_num}'
            else:
                flag = f'cf_status_firefox_{rel_num}'

            # Only check branches if bug is marked as fixed
            if getattr(self.bug, flag) == 'fixed':
                baseline = self.reproduce_bug(alias)
                if baseline.status == ReproductionResult.PASSED:
                    log.info(f"Verified fixed on {flag}")
                    setattr(self.bug, flag, 'verified')
                elif baseline.status == ReproductionResult.CRASHED:
                    log.info(f"Bug remains vulnerable on {flag}")
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
        bisector = Bisector(self.evaluator, self.target, self.branch, start, end, self.build_flags, platform_, find_fix)
        result = bisector.bisect()

        # Remove bisect command
        if 'bisect' in self.commands:
            self.remove_command('bisect')

        if result.status != BisectionResult.SUCCESS:
            log.warning(f'Failed to bisect testcase')
            output = [f'BugMon: Failed to bisect testcase ({result.message})',
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
        return f'BugMon: Reduced build range to...\n{range_string}'

    def process(self):
        """
        Process bugmon commands present in whiteboard

        Available commands:
        verify - Attempt to verify the bug state
        bisect - Attempt to bisect the bug regression or, if RESOLVED, the bug fix
        """

        if self.branch is None:
            if 'bugmon' in self.bug.keywords:
                self.bug.keywords.remove('bugmon')
            log.warning(f'Bug filed against non-supported branch ({self.version})')
            self.report([f'Bug filed against non-supported branch ({self.version})'])
            return

        baseline = self.reproduce_bug(self.branch)
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
            log.info(f"Attempting to reproduce bug on mozilla-{branch} {build.build_id}-{build.changeset[:12]}")
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
