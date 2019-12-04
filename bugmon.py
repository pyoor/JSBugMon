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
import shutil
import sys
import tempfile
import traceback
import zipfile

from autobisect.bisect import BisectionResult, Bisector
from autobisect.build_manager import BuildManager
from autobisect.config import BisectionConfig
from autobisect.evaluator.js import JSEvaluator
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


def enum(*sequential, **named):
    enums = dict(list(zip(sequential, list(range(len(sequential))))), **named)
    return type('Enum', (), enums)


class BugException(Exception):
    pass


class ReproductionResult(object):
    PASSED = 0
    CRASHED = 1
    FAILED = 2

    def __init__(self, build, status):
        self.build = build
        self.status = status


class BugMonitor:
    def __init__(self, bugsy, bug_num, repo_root, dry_run=False):
        """

        :param bugsy: Bugsy instance used for retrieving bugs
        :param bug_num: Bug number to analyze
        :param repo_root: Path to mozilla-unified repo
        :param dry_run: Boolean indicating if changes should be made to the bug
        """
        self.bugsy = bugsy
        self.bug = self.bugsy.get(bug_num, '_default')
        self.repo_root = repo_root
        self.dry_run = dry_run

        # Raise if testcase extraction fails
        self.working_dir = tempfile.TemporaryDirectory()
        self.testcase = self.extract_testcase()

        self._original_rev = None
        self._runtime_opts = None
        self._build_flags = None
        self._arch = None
        self._os = None

        build_config = BisectionConfig()
        self.build_manager = BuildManager(build_config)

        milestone = os.path.join(repo_root, 'mozilla-central', 'config', 'milestone.txt')
        with open(milestone, 'r') as f:
            last = f.readlines()[-1]
            self.centralVersion = int(last.split('.', 1)[0])

    @property
    def original_rev(self):
        """
        Attempt to enumerate the original rev specified in comment 0 or jsbugmon origRev command
        """
        if self._original_rev is None:
            if 'origRev' in self.commands and re.match('^([a-f0-9]{12}|[a-f0-9]{40})$', self.commands['origRev']):
                self._original_rev = ['origRev']
            else:
                comments = self.bug.get_comments()
                tokens = comments[0].text.split(' ')
                for token in tokens:
                    if re.match(r'^([a-f0-9]{12}|[a-f0-9]{40})$', token, re.IGNORECASE):
                        self._original_rev = token
                        break
                else:
                    self._original_rev = None

        return self._original_rev

    @property
    def runtime_opts(self):
        """
        Attempt to enumerate the runtime flags specified in comment 0
        """
        if self._runtime_opts is None:
            comments = self.bug.get_comments()
            if len(comments) >= 1:
                comment = comments[0].text
                self._runtime_opts = list(filter(lambda flag: flag in comment, ALLOWED_OPTS))

        return self._runtime_opts

    @property
    def build_flags(self):
        """
        Attempt to enumerate build type based on flags listed in comment 0
        """
        if self._build_flags is None:
            comments = self.bug.get_comments()
            text = comments[0].text
            asan = 'AddressSanitizer: ' in text or '--enable-address-sanitizer' in text
            debug = '--enable-debug' in text
            fuzzing = '--enable-fuzzing' in text
            coverage = '--enable-coverage' in text
            valgrind = False  # Ignore valgrind for now
            self._build_flags = BuildFlags(asan, debug, fuzzing, coverage, valgrind)

        return self._build_flags

    @property
    def os(self):
        """
        Attempt to enumerate the original OS associated with the bug
        """
        if self._os is None:
            op_sys = self.bug.op_sys
            if op_sys is not None:
                if 'Linux' in op_sys:
                    self._os = 'Linux'
                elif 'Windows' in op_sys:
                    self._os = 'Windows'
                elif 'Mac OS' in op_sys:
                    self._os = 'Darwin'
                else:
                    self._os = platform.system()
            else:
                self._os = platform.system()

        return self._os

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
            match = re.search(r'(?<=\[jsbugmon:).[^\]]*', self.bug.whiteboard)
            if match is not None:
                for command in match.group(0).split(','):
                    if '=' in command:
                        name, value = command.split('=')
                        commands[name] = value
                    else:
                        commands[command] = None

        return commands

    def extract_testcase(self):
        """
        Attempt to extract a testcase from the bug or raise an Exception
        """
        attachments = list(filter(lambda a: not a.is_obsolete, self.bug.get_attachments()))
        for attachment in sorted(attachments, key=lambda a: a.creation_time):
            self.clean_up()
            try:
                data = base64.decodebytes(attachment.data.encode('utf-8'))
            except binascii.Error as e:
                log.warn('Failed to decode attachment: ', e.message)
                continue

            if attachment.file_name.endswith('.js'):
                filename = os.path.join(self.working_dir.name, attachment.file_name)
                with open(filename, 'wb') as file:
                    file.write(data)
                    return filename
            elif attachment.file_name.endswith('.zip'):
                try:
                    z = zipfile.ZipFile(io.BytesIO(data))
                    z.extractall(self.working_dir.name)
                except zipfile.BadZipFile as e:
                    log.warn('Failed to decompress attachment: ', e)
                    continue

                testcases = list(filter(lambda f: f.endswith('.js'), os.listdir(self.working_dir.name)))
                if len(testcases) != 1:
                    log.warn('Failed to isolate testcase in zip!')
                else:
                    return os.path.join(self.working_dir.name, testcases[0])

    def clean_up(self):
        for file in os.listdir(self.working_dir.name):
            file_path = os.path.join(self.working_dir.name, file)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                log.error('Failed to delete %s: %s', (file_path, e))

    def confirm_open(self, baseline):
        """
        Attempt to confirm open test cases

        :param baseline: A reproduction result
        """
        test_rev = baseline.build.changeset[:12]

        comments = []
        if baseline.status == ReproductionResult.CRASHED:
            log.info(f"Verified as reproducible on {baseline.build.changeset}...")
            if self.bug.status == 'NEW' and 'confirmed' not in self.commands:
                comments.append(f"JSBugMon: Verified bug as reproducible on {baseline.build.changeset}")
                # Mark bug as confirmed
                self.bug.whiteboard = re.sub(r'(?<=jsbugmon:)(.[^\]]*)', r'\1,confirmed', self.bug.whiteboard)
                comments.append(self.bisect(find_fix=False))
            # ToDo: Add check to see if last activity is > 30 days
            elif self.dry_run:
                comments.append(f"JSBugMon: Bug remains reproducible on {baseline.build.changeset}")
        elif baseline.status == ReproductionResult.PASSED:
            log.info(f"Unable to reproduce bug on {baseline.build.changeset}...")
            comments.append(f"JSBugMon: This bug no longer reproduces on rev {baseline.build.changeset}")

            if 'jsbugmon' in self.bug.keywords:
                self.bug.keywords.remove('jsbugmon')

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
            match = re.search(r'(?<=jsbugmon:)(.[^\]]*)', self.bug.whiteboard)
            if match is not None:
                replacement = match.group(0).replace('confirm', '')
                self.bug.whiteboard = re.sub(r'(?<=jsbugmon:)(.[^\]]*)', replacement, self.bug.whiteboard)

        if not self.dry_run:
            map(lambda c: self.bug.add_comment(c), comments)

            # If changes were made to the bug, push and update
            if self.bug.diff():
                self.bugsy.put(self.bug)
                self.bug.update()

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
            comments.append(f"JSBugMon: Verified bug as fixed on rev {test_rev}")

            if 'jsbugmon' in self.bug.keywords:
                self.bug.keywords.remove('jsbugmon')

            if 'close' in self.commands:
                self.bug.status = "VERIFIED"
        elif baseline.status == ReproductionResult.CRASHED:
            log.info(f"Bug is marked as resolved but still reproduces on rev {test_rev}")
            comments.append(f"JSBugMon: Bug is marked as FIXED but it still reproduces on rev {test_rev}")

        # Only check branches if bug is marked as fixed
        for rel_num in range(self.centralVersion - 2, self.centralVersion):
            flag = 'cf_status_firefox{0}'.format(rel_num)
            if getattr(self.bug, flag) == 'fixed':
                branch = AVAILABLE_BRANCHES[self.centralVersion - rel_num]
                baseline = self.reproduce_bug(branch)
                if baseline.status == ReproductionResult.PASSED:
                    log.info(f"Verified fixed on Fx{rel_num}")
                    comments.append(f"JSBugMon: Verified bug as fixed on Fx{rel_num}")

                    # Mark branch as verified
                    setattr(self.bug, flag, 'verified')

        if not self.dry_run:
            map(lambda c: self.bug.add_comment(c), comments)

            # If changes were made to the bug, push and update
            if self.bug.diff():
                self.bugsy.put(self.bug)
                self.bug.update()

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

        evaluator = JSEvaluator(self.testcase, flags=' '.join(self.runtime_opts))
        platform_ = Platform(self.os, self.arch)
        bisector = Bisector(evaluator, 'js', 'central', start, end, self.build_flags, platform_, find_fix)
        result = bisector.bisect()

        # Remove bisect command
        if 'bisect' in self.commands:
            match = re.search(r'(?<=jsbugmon:)(.[^\]]*)', self.bug.whiteboard)
            if match is not None:
                replacement = match.group(0).replace('bisect', '')
                self.bug.whiteboard = re.sub(r'(?<=jsbugmon:)(.[^\]]*)', replacement, self.bug.whiteboard)

        if result.status != BisectionResult.SUCCESS:
            log.warning(f'Failed to bisect testcase')
            return f'JSBugmon: Failed to bisect testcase ({result.message}).'

        output = [f'> Start: {result.start.changeset} ({result.start.build_id})',
                  f'> End: {result.end.changeset} ({result.end.build_id})'
                  f'> Pushlog: {result.pushlog}']

        log.info(f'Reduced build range to...')
        for text in output:
            log.info(text)

        range_string = "\n".join(output)
        return f'JSBugmon: Reduced build range to...\n{range_string}'

    def process(self):
        """
        Process Bugmon commands present in whiteboard

        Available commands:
        verify - Attempt to verify the bug state
        bisect - Attempt to bisect the bug regression or, if RESOLVED, the bug fix
        """
        baseline = self.reproduce_bug('central')
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
            if not self.dry_run:
                self.bug.add_comment(result)

                # If changes were made to the bug, push and update
                if self.bug.diff():
                    self.bugsy.put(self.bug)
                    self.bug.update()

    def reproduce_bug(self, branch, rev=None):
        try:
            platform_ = Platform(self.os, self.arch)
            if rev is not None:
                build = Fetcher('js', branch, rev, self.build_flags, platform_, nearest=Fetcher.BUILD_ORDER_ASC)
            else:
                build = Fetcher('js', branch, 'latest', self.build_flags, platform_, nearest=Fetcher.BUILD_ORDER_DESC)
        except FetcherException as e:
            log.error(e)
            return

        evaluator = JSEvaluator(self.testcase, flags=' '.join(self.runtime_opts))
        with self.build_manager.get_build(build) as build_path:
            status = evaluator.evaluate_testcase(build_path)
            if status == Bisector.BUILD_CRASHED:
                return ReproductionResult(build, ReproductionResult.CRASHED)
            elif status == Bisector.BUILD_PASSED:
                return ReproductionResult(build, ReproductionResult.PASSED)
            else:
                return ReproductionResult(build, ReproductionResult.FAILED)


def parse_args(argv=None):
    parser = argparse.ArgumentParser()

    # Optional args
    parser.add_argument('-d', '--dry-run', action='store_true', help="If enabled, don't make any remote changes")

    # Required args
    parser.add_argument('-r', '--repobase', default=None, required=True, help='Repository base directory.')

    # Bug selection
    bug_list = parser.add_mutually_exclusive_group(required=True)
    bug_list.add_argument('--bugs', nargs='+', help='Space separated list of bug numbers')
    bug_list.add_argument('-s', '--search-params', help='Path to advanced search parameters')
    args = parser.parse_args(argv)

    if args.search_params and not os.path.isfile(args.search_params):
        raise parser.error('Search parameter path does not exist!')
    if not os.path.isdir(args.repobase):
        raise parser.error('Repobase path does not exist!')

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
        bugmon = None
        try:
            bugmon = BugMonitor(bugsy, bug_id, args.repobase, args.dry_run)
            log.info("Begin analysis of bug {0} (Status: {1}, Resolution: {2})"
                     .format(bug_id, bugmon.bug.status, bugmon.bug.resolution))
            bugmon.process()
        except BugException as b:
            log.error("Cannot process bug: {0}".format(str(b)))
            log.error(traceback.format_exc())
        except Exception as e:
            log.error("Uncaught exception: {0}".format(str(e)))
            log.error(traceback.format_exc())
        finally:
            if bugmon is not None and bugmon.working_dir:
                shutil.rmtree(bugmon.work, ignore_errors=True)


if __name__ == '__main__':
    console_init_logging()
    sys.exit(main())
