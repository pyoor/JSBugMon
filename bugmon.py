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
import json
import logging
import os
import re
import subprocess
import sys
import time
import traceback

from bugsy import Bugsy, Bug
from funfuzz.js.build_options import parse_shell_opts
from funfuzz.js.compile_shell import CompiledShell

from test_binary import testBinary

log = logging.getLogger("bugmon")


def enum(*sequential, **named):
    enums = dict(list(zip(sequential, list(range(len(sequential))))), **named)
    return type('Enum', (), enums)


class BugException(Exception):
    pass


class InternalException(Exception):
    pass


class BugMonitorResult:
    # Different result states:
    #  FAILED               - Unable to reproduce on original revision
    #  REPRODUCED_FIXED     - Reproduced on original revision but not on tip (fixed on tip)
    #  REPRODUCED_TIP       - Reproduced on both revisions
    #  REPRODUCED_SWITCHED  - Reproduced on tip, but with a different crash/signal
    statusCodes = enum('FAILED', 'REPRODUCED_FIXED', 'REPRODUCED_TIP', 'REPRODUCED_SWITCHED')

    def __init__(self, branchName, origRev, tipRev, testFlags, testPath, arch, ctype, buildFlags, status):
        self.branchName = branchName
        self.origRev = origRev
        self.tipRev = tipRev
        self.testFlags = testFlags
        self.testPath = testPath
        self.arch = arch
        self.ctype = ctype
        self.buildFlags = buildFlags
        self.status = status


class BugMonitor:

    def __init__(self, api_root, api_key, bug_num, repo_root):
        self.bugsy = Bugsy(api_key=api_key, bugzilla_url=api_root)
        self.bug = self.bugsy.get(bug_num, '_default')
        self.repo_root = repo_root

        # Here we store the tip revision per repository for caching purposes
        self.tip_rev = {}

        self.allowed_opts = [
            '--fuzzing-safe',
            '--ion-eager',
            '--baseline-eager',
            '--ion-regalloc=backtracking',
            '--ion-regalloc=lsra',
            '--thread-count=2',
            '--cpu-count=2',
            '--ion-parallel-compile=off',
            '--ion-offthread-compile=off',
            '--ion-check-range-analysis',
            '--ion-gvn=pessimistic',
            '--ion-gvn=off',
            '--no-ion',
            '--no-baseline',
            '--arm-sim-icache-checks',
            '--arm-asm-nop-fill=1',
            '--no-threads',
            '--unboxed-objects',
            '--ion-fuzzer-checks',
            '--ion-extra-checks',
            '--arm-hwcap=vfp',
            '--ion-shared-stubs=on',
            '--ion-pgo=on',
            '--nursery-strings=on',
            '--nursery-strings=off',
            '--enable-experimental-fields',
            '--ion-warmup-threshold=0',
            '--ion-warmup-threshold=1',
            '--baseline-warmup-threshold=0',
            '--baseline-warmup-threshold=1',
            '-D'
        ]

        milestone = os.path.join(repo_root, 'mozilla-central', 'config', 'milestone.txt')
        with open(milestone, 'r') as f:
            last = f.readlines()[-1]
            self.centralVersion = int(last.split('.', 1)[0])

        self.branches = ['mozilla-central', 'mozilla-aurora', 'mozilla-beta', 'mozilla-release']

    def verifyFixedBug(self, updateBug):
        bugModified = False
        bugVerified = False
        verifiedFlags = []
        comments = []

        if self.bug.status == "RESOLVED" and self.bug.resolution == "FIXED":
            result = self.reproduceBug()

            if result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED:
                if updateBug:
                    log.info("Marking bug {0} as verified fixed...".format(self.bug.id))
                    # Mark VERIFIED FIXED now
                    bugVerified = True
                    bugModified = True

                    # Add a comment
                    comments.append("JSBugMon: This bug has been automatically verified fixed.")
                else:
                    log.debug("Would mark bug {0} as verified fixed...".format(self.bug.id))

        for branchNum in range(self.centralVersion - 3, self.centralVersion):
            statusFlagName = 'cf_status_firefox' + str(branchNum)
            if getattr(self.bug, statusFlagName) == 'fixed':
                branchRepo = self.branches[self.centralVersion - branchNum]
                branchRepoRev = self.hgFindFixParent(os.path.join(self.repo_root, branchRepo))

                if branchRepoRev is None:
                    log.warning("Unable to find fix parent for bug {} on repository {}".format(self.bug.id, branchRepo))
                    continue

                result = self.reproduceBug(branchRepo, branchRepoRev)

                if result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED:
                    if updateBug:
                        log.info("Marking bug {0} as verified fixed on Fx{1} ...".format(self.bug.id, branchNum))
                        verifiedFlags.append(statusFlagName)
                        bugModified = True
                        comments.append(
                            "JSBugMon: This bug has been automatically verified fixed on Fx" + str(branchNum))
                    else:
                        log.debug("Would mark bug {0} as verified fixed on Fx{1} ...".format(self.bug.id, branchNum))

        if bugModified:
            while True:
                for flag in verifiedFlags:
                    setattr(self.bug, flag, 'verified')

                if bugVerified:
                    self.bug.status = "VERIFIED"
                    setattr(self.bug, 'cf_status_firefox' + str(self.centralVersion), 'verified')

                try:
                    if self.bug.diff():
                        self.bugsy.put(self.bug)
                        self.bug.update()
                    break
                except Exception as e:
                    log.error("Caught exception: {0}".format(str(e)))
                    log.error(traceback.format_exc())
                    time.sleep(1)
                except:
                    log.warning("Failed to submit bug change, sleeping one second and retrying...")
                    time.sleep(1)

        if len(comments) > 0:
            comment = "\n".join(comments)
            log.info("Commenting: ")
            log.info(comment)
            self.bug.add_comment(comment)
        return

    def confirmOpenBug(self, updateBug, updateBugPositive):
        if self.bug.status != "RESOLVED" and self.bug.status != "VERIFIED":
            bugUpdateRequested = False
            bugConfirmRequested = False
            bugCloseRequested = False
            bugUpdated = False

            closeBug = False

            wbOpts = []
            if self.bug.whiteboard:
                ret = re.compile('\[jsbugmon:([^\]]+)\]').search(self.bug.whiteboard)
                if ret:
                    wbOpts = ret.group(1).split(",")

            # Explicitly marked to ignore this bug
            if 'ignore' in wbOpts:
                return

            if 'update' in wbOpts:
                bugUpdateRequested = True

            if 'reconfirm' in wbOpts:
                bugConfirmRequested = True

            if 'close' in wbOpts:
                bugCloseRequested = True

            result = self.reproduceBug()

            comments = []

            if result.status == BugMonitorResult.statusCodes.REPRODUCED_TIP:
                if updateBugPositive or bugConfirmRequested:
                    log.info("Marking bug {0} as confirmed on tip...".format(self.bug.id))
                    # Add a comment
                    comments.append(
                        "JSBugMon: This bug has been automatically confirmed to be still valid (reproduced on revision " + result.tipRev + ").")
                    bugUpdated = True
                else:
                    log.debug("Would mark bug {0} as confirmed on tip...".format(self.bug.id))
            elif result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED:
                if updateBug or bugUpdateRequested:
                    log.info("Marking bug {0} as non-reproducing on tip...".format(self.bug.id))
                    # Add a comment
                    comments.append(
                        "JSBugMon: The testcase found in this bug no longer reproduces (tried revision " + result.tipRev + ").")
                    bugUpdated = True

                    # Close bug only if requested to do so
                    closeBug = bugCloseRequested
                else:
                    log.debug("Would mark bug {0} as non-reproducing on tip...".format(self.bug.id))

            if bugUpdated:
                wb = re.sub(r'(?<=jsbugmon:)(.[^\]]*)', r'\1,ignore', self.bug.whiteboard)

                while True:
                    try:
                        # We add "ignore" to our bugmon options so we don't update the bug a second time
                        self.bug.whiteboard = wb

                        # Mark bug as WORKSFORME if confirmed to no longer reproduce
                        if closeBug:
                            self.bug.status = "RESOLVED"
                            self.bug.resolution = "WORKSFORME"

                        self.bugsy.put(self.bug)
                        self.bug.update()
                        break
                    except Exception as e:
                        log.error(e)
                        log.info("Failed to submit bug change, sleeping one second and retrying...")
                        time.sleep(1)

            if len(comments) > 0:
                comment = "\n".join(comments)
                log.info("Posting comment: ")
                log.info(comment)
                self.bug.add_comment(comment)

        return

    def processCommand(self):
        bugUpdateRequested = False
        bugConfirmRequested = False
        bugCloseRequested = False
        bugVerifyRequested = False
        bugBisectRequested = False
        bugBisectFixRequested = False
        bugBisectForceCompile = False
        bugFailureMsg = None
        bugUpdated = False

        closeBug = False
        verifyBug = False

        wbOpts = []
        if self.bug.whiteboard is not None:
            ret = re.compile('\[jsbugmon:([^\]]+)\]').search(self.bug.whiteboard)
            if ret:
                wbOpts = ret.group(1).split(",")

            # Explicitly marked to ignore this bug
            if 'ignore' in wbOpts:
                return

            if 'update' in wbOpts:
                bugUpdateRequested = True

            if 'reconfirm' in wbOpts:
                bugConfirmRequested = True

            if 'close' in wbOpts:
                bugCloseRequested = True

            if 'verify' in wbOpts:
                bugVerifyRequested = True

            if 'bisect' in wbOpts:
                bugBisectRequested = True

            if 'bisectfix' in wbOpts:
                bugBisectFixRequested = True

            if 'bisect-force-compile' in wbOpts:
                bugBisectForceCompile = True

            log.debug("Whiteboard: {}".format(', '.join(self.bug.whiteboard)))

            comments = []

            # Keep bisect comments separate so we can remove bisect/bisectfix commands separately
            bisectComments = []
            bisectFixComments = []

            result = None

            for opt in wbOpts:
                if opt.find("=") > 0:
                    (cmd, param) = opt.split('=')
                    if cmd == 'verify-branch' and param is not None:
                        branches = param.split(';')
                        for branch in branches:
                            if branch not in self.branches:
                                continue
                            log.debug("Branch ", branch)
                            branchResult = self.reproduceBug(branch)
                            if branchResult.status == BugMonitorResult.statusCodes.REPRODUCED_TIP:
                                log.info("Marking bug {0} as reproducing on branch {1}".format(self.bug.id, branch))
                                # Add a comment
                                comments.append(
                                    "JSBugMon: This bug has been automatically confirmed to be still valid on branch " + branch + "  (reproduced on revision " + branchResult.tipRev + ").")
                            elif branchResult.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED:
                                log.info("Marking bug {0} as non-reproducing on branch {1}".format(self.bug.id, branch))
                                comments.append(
                                    "JSBugMon: The testcase found in this bug does not reproduce on branch " + branch + " (tried revision " + branchResult.tipRev + ").")
                            else:
                                log.info("Marking bug {0} as not processable ...".format(self.bug.id))
                                comments.append(
                                    "JSBugMon: Command failed during processing this bug: " + opt + " (branch " + branch + ")")

            if bugVerifyRequested:
                if self.bug.status == "RESOLVED":
                    if result is None:
                        result = self.reproduceBug()
                    if result.status == BugMonitorResult.statusCodes.REPRODUCED_TIP:
                        log.info("Marking bug {0} as cannot verify fixed...".format(self.bug.id))
                        # Add a comment
                        comments.append(
                            "JSBugMon: Cannot confirm fix, issue is still valid. (tried revision " + result.tipRev + ").")
                    elif result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED:
                        log.info("Marking bug {0} as verified fixed...".format(self.bug.id))
                        comments.append(
                            "JSBugMon: This bug has been automatically verified fixed. (tried revision " + result.tipRev + ").")
                        verifyBug = True
                    else:
                        log.info("Marking bug {0} as not processable ...".format(self.bug.id))
                        comments.append("JSBugMon: Command failed during processing this bug: verify")

            if bugUpdateRequested:
                if self.bug.status != "RESOLVED" and self.bug.status != "VERIFIED":
                    if result is None:
                        try:
                            result = self.reproduceBug()
                        except BugException as b:
                            bugFailureMsg = "JSBugMon: Cannot process bug: " + str(b)
                        except InternalException:
                            # Propagate internal failures, don't update the bug
                            raise
                        except Exception as e:
                            bugFailureMsg = "JSBugMon: Cannot process bug: Unknown exception (check manually)"
                            log.error("Caught exception: {0}".format(str(e)))
                            log.error(traceback.format_exc())

                    if result is not None:
                        if (
                            result.status == BugMonitorResult.statusCodes.REPRODUCED_TIP or result.status == BugMonitorResult.statusCodes.REPRODUCED_SWITCHED):
                            bugReproduced = True
                            if bugConfirmRequested:
                                log.info("Marking bug {0} as confirmed on tip...".format(self.bug.id))
                                # Add a comment
                                comments.append(
                                    "JSBugMon: This bug has been automatically confirmed to be still valid (reproduced on revision " + result.tipRev + ").")

                        elif result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED:
                            log.info("Marking bug {0} as non-reproducing on tip...".format(str(self.bug.id)))
                            # Add a comment
                            comments.append(
                                "JSBugMon: The testcase found in this bug no longer reproduces (tried revision " + result.tipRev + ").")
                            if bugCloseRequested:
                                closeBug = True

                        elif result.status == BugMonitorResult.statusCodes.FAILED:
                            bugFailureMsg = "JSBugMon: Cannot process bug: Unable to automatically reproduce, please track manually."

            # If we already failed with the update command, don't try to bisect for now
            if bugFailureMsg is not None:
                bugBisectRequested = False
                bugBisectFixRequested = False

            if bugBisectRequested and self.bug.status != "RESOLVED" and self.bug.status != "VERIFIED":
                if result is None:
                    try:
                        result = self.reproduceBug()
                    except BugException as b:
                        bisectComments.append("JSBugMon: Bisection requested, failed due to error: " + str(b))
                        bisectComments.append("")
                if (result is not None and (
                    result.status == BugMonitorResult.statusCodes.REPRODUCED_TIP or result.status == BugMonitorResult.statusCodes.REPRODUCED_SWITCHED or result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED)):
                    log.info("Bisecting bug {0} ...".format(self.bug.id))
                    bisectComment = self.bisectBug(result, forceCompile=bugBisectForceCompile)
                    if bisectComment is not None:
                        log.info(bisectComment)
                        if len(bisectComment) > 0:
                            bisectComments.append("JSBugMon: Bisection requested, result:")
                            bisectComments.extend(bisectComment)
                        else:
                            bisectComments.append("JSBugMon: Bisection requested, failed due to error (try manually).")
                            bisectComments.append("")
                    else:
                        # Threat this as a temporary failure, don't remove the whiteboard tag
                        bugBisectRequested = False

            if bugBisectFixRequested:
                if result is None:
                    try:
                        result = self.reproduceBug()
                    except BugException as b:
                        bisectComments.append("JSBugMon: Fix Bisection requested, failed due to error: " + str(b))
                        bisectComments.append("")
                if result is not None and result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED:
                    log.info("Bisecting fix for bug {0} ...".format(str(self.bug.id)))
                    bisectComment = self.bisectBug(result, bisectForFix=True, forceCompile=bugBisectForceCompile)
                    if bisectComment is not None:
                        log.info(bisectComment)
                        if len(bisectComment) > 0:
                            bisectFixComments.append("JSBugMon: Fix Bisection requested, result:")
                            bisectFixComments.extend(bisectComment)
                        else:
                            bisectFixComments.append(
                                "JSBugMon: Fix Bisection requested, failed due to error (try manually).")
                            bisectFixComments.append("")
                    else:
                        # Threat this as a temporary failure, don't remove the whiteboard tag
                        bugBisectFixRequested = False

            wbParts = []
            whiteBoardModified = False
            if closeBug or verifyBug or len(comments) > 0:
                whiteBoardModified = True
                wbOpts.append('ignore')

            if bugBisectRequested:
                whiteBoardModified = True
                wbOpts.remove('bisect')
                comments.extend(bisectComments)

            if bugBisectFixRequested and len(bisectFixComments) > 0:
                whiteBoardModified = True
                wbOpts.remove('bisectfix')
                comments.extend(bisectFixComments)

            if (bugBisectRequested or (bugBisectFixRequested and len(bisectFixComments) > 0)) and bugBisectForceCompile:
                whiteBoardModified = True
                wbOpts.remove('bisect-force-compile')

            if bugFailureMsg is not None and bugUpdateRequested:
                whiteBoardModified = True
                wbOpts.remove('update')
                comments.append(bugFailureMsg)

            while True:
                # Fetch the bug again
                self.bug.update()

                bugModified = False

                # Mark bug as WORKSFORME if confirmed to no longer reproduce
                if closeBug:
                    bugModified = True
                    self.bug.status = "RESOLVED"
                    self.bug.resolution = "WORKSFORME"

                # Mark bug as VERIFIED if we verified it successfully
                if verifyBug:
                    bugModified = True
                    self.bug.status = "VERIFIED"

                if whiteBoardModified:
                    # We add "ignore" to our bugmon options so we don't update the bug a second time
                    bugModified = True
                    wb = re.sub(r'(?<=jsbugmon:)(.[^\]]*)', ",".join(wbOpts), self.bug.whiteboard)
                    self.bug.whiteboard = wb

                try:
                    if bugModified:
                        self.bugsy.put(self.bug)
                        self.bug.update()
                    break
                except Exception as e:
                    log.error("Caught exception: " + str(e))
                    log.error(traceback.format_exc())
                    time.sleep(1)
                except:
                    log.error("Failed to submit bug change, sleeping one second and retrying...")
                    time.sleep(1)

            if len(comments) > 0:
                comment = "\n".join(comments)
                log.info("Posting comment: ")
                log.info(comment)
                self.bug.add_comment(comment)

        return

    def bisectBug(self, reproductionResult, bisectForFix=False, forceCompile=False):
        if forceCompile:
            return self.bisectBugCompile(reproductionResult, bisectForFix)

        buildOpts = '-R %s' % (os.path.join(self.repo_root, reproductionResult.branchName))
        if reproductionResult.buildFlags is not None and len(reproductionResult.buildFlags) > 0:
            buildOpts += ' %s' % " ".join(reproductionResult.buildFlags)

        cmd = ['python', '/srv/repos/funfuzz/autobisect-js/autoBisect.py', '-T', '-b', buildOpts, '-p',
               " ".join(reproductionResult.testFlags) + " " + reproductionResult.testPath, '-i', 'crashes',
               '--timeout=10']
        log.debug("Attempting binary bisection: %s" % str(cmd))
        outLines = None
        try:
            outLines = subprocess.check_output(cmd).split("\n")
        except subprocess.CalledProcessError:
            # Threat this as a temporary failure, fallback to compiled bisection
            return self.bisectBugCompile(reproductionResult, bisectForFix)

        retLines = []
        found = False
        for outLine in outLines:
            if not found and (outLine.find("Build Bisection Results by autoBisect ===") != -1):
                found = True

            if found:
                retLines.append(outLine)

        if not found:
            # Binary bisection failed for some reason, fallback to compiled bisection
            return self.bisectBugCompile(reproductionResult, bisectForFix)

        return retLines

    def bisectBugCompile(self, reproductionResult, bisectForFix=False):
        # By default, bisect for the regressing changeset
        revFlag = '-e'
        if bisectForFix:
            revFlag = '-s'

        buildOpts = '-R %s' % (os.path.join(self.repo_root, reproductionResult.branchName))
        if reproductionResult.buildFlags is not None and len(reproductionResult.buildFlags) > 0:
            buildOpts += ' %s' % " ".join(reproductionResult.buildFlags)

        cmd = ['python', '/srv/repos/funfuzz/autobisect-js/autoBisect.py', '-b', buildOpts, revFlag,
               reproductionResult.origRev, '-p',
               " ".join(reproductionResult.testFlags) + " " + reproductionResult.testPath,
               '-i', 'crashes', '--timeout=10']
        log.debug(' '.join(cmd))
        outLines = None
        try:
            outLines = subprocess.check_output(cmd).split("\n")
        except subprocess.CalledProcessError:
            # Threat this as a temporary failure
            return None

        retLines = []
        found = False
        for outLine in outLines:
            if not found and (outLine.find("autoBisect shows this is probably related") != -1 or outLine.find(
                "Due to skipped revisions") != -1):
                found = True

            if found:
                # Remove possible email address
                if outLine.find("user:") != -1:
                    outLine = re.sub("\s*<.+>", "", outLine)

                # autobisect emits a date at the end, skip that
                if (re.match("^\w+:", outLine) is None) and re.search("\s+\d{1,2}:\d{1,2}:\d{1,2}\s+",
                                                                      outLine) is not None:
                    continue

                retLines.append(outLine)

        return retLines

    def reproduceBug(self, tipBranch=None, tipBranchRev=None):
        # Determine comment to look at and revision
        testCommentIdx = 0
        rev = None

        if tipBranch is not None and tipBranchRev is not None:
            rev = tipBranchRev

        if self.bug.whiteboard is not None:
            ret = re.compile('\[jsbugmon:([^\]]+)\]').search(self.bug.whiteboard)
            if ret:
                wbOpts = ret.group(1).split(",")
                for opt in wbOpts:
                    if opt.find("=") > 0:
                        (cmd, param) = opt.split('=')
                        if cmd is not None and param is not None:
                            if cmd == "origRev" and rev is None:
                                rev = param
                            elif cmd == "testComment" and param.isdigit():
                                testCommentIdx = int(param)

        # Look for the first comment
        comments = self.bug.get_comments()
        comment = comments[testCommentIdx] if len(comments) > testCommentIdx else None

        if comment is None:
            raise BugException("Error: Specified bug does not have any comments")

        text = comment.text

        # Isolate revision to test for
        if rev is None:
            rev = self.extractRevision(text)
        else:
            # Sanity check of the revision
            rev = self.extractRevision(rev)

        if rev is None:
            raise BugException("Error: Failed to isolate original revision for test")

        buildFlags = []

        checkFlags = ["--enable-more-deterministic", "--enable-simulator=arm", "--enable-simulator=arm64",
                      "--enable-arm-simulator", "--enable-debug", "--disable-debug", "--enable-optimize",
                      "--disable-optimize"]

        for flag in checkFlags:
            if re.search(flag + "[^-a-zA-Z0-9]", text) is not None:
                buildFlags.append(flag)

        # Flags to use when searching for the test ("scanning") using SyntaxError method
        scanOpts = ['--fuzzing-safe']
        viableOptsList = []
        opts = []

        for opt in self.allowed_opts:
            if text.find(opt) != -1:
                opts.append(opt)

        viableOptsList.append(opts)

        # We need to use experimental fields when scanning, otherwise we get a syntax error
        if '--enable-experimental-fields' in opts:
            scanOpts.append('--enable-experimental-fields')

        log.info("Extracted options: %s" % (' '.join(opts)))

        # Special hack for flags that changed
        if "--ion-parallel-compile=off" in opts:
            optsCopy = []
            for opt in opts:
                if opt == "--ion-parallel-compile=off":
                    optsCopy.append("--ion-offthread-compile=off")
                else:
                    optsCopy.append(opt)
            viableOptsList.append(optsCopy)

        if '--fuzzing-safe' not in opts:
            opts.append('--fuzzing-safe')

        if self.bug.version == "Trunk":
            reponame = "mozilla-central"
        elif self.bug.version == "Other Branch":
            reponame = "ionmonkey"
        else:
            raise BugException("Error: Unsupported branch \"" + self.bug.version + "\" required by bug")

        # Default to using the bug.version field as repository specifier
        repoDir = os.path.join(self.repo_root, reponame)

        # If told to use a different tipBranch, use that for tip testing
        if tipBranch is None:
            tipBranch = reponame

        tipRepoDir = os.path.join(self.repo_root, tipBranch)

        # If we are given a specific revision even for testing, then use
        # the tipBranch for all testing, including initial reproduction
        if tipBranchRev is not None:
            repoDir = tipRepoDir

        log.info("Using repository at %s with revision %s for initial reproduction" % (repoDir, rev))
        log.info("Using repository at %s with tip revision for testing" % tipRepoDir)

        arch = None
        archList = None
        if self.bug.platform == "x86_64":
            arch = "64"
        elif self.bug.platform == "x86":
            arch = "32"
        elif self.bug.platform == "All":
            arch = "64"
            archList = ["64", "32"]  # TODO: Detect native platform here

            # When auto-detecting, avoid using ARM simulator for now
            if "--enable-simulator=arm" in buildFlags:
                buildFlags.remove("--enable-simulator=arm")
        elif self.bug.platform == "ARM":
            arch = "32"
            buildFlags.append("--enable-simulator=arm")
        elif self.bug.platform == "ARM64":
            arch = "64"
            buildFlags.append("--enable-simulator=arm64")
        else:
            raise BugException("Error: Unsupported architecture \"" + self.bug.platform + "\" required by bug")

        # We need at least some shell to extract the test from the bug,
        # so we build a debug shell here already
        try:
            (testShell, testRev) = self.getShell("cache/", arch, "dbg", 0, rev, False, repoDir, buildFlags)
        except Exception:
            trace = sys.exc_info()[2]
            raise InternalException("Failed to compile tip shell (toolchain broken?)").with_traceback(trace)

        # If the file already exists, then we can reuse it
        if testCommentIdx > 0:
            testFile = "bug" + str(self.bug.id) + "-" + str(testCommentIdx) + ".js"
        else:
            testFile = "bug" + str(self.bug.id) + ".js"

        if os.path.exists(testFile):
            log.info("Using existing (cached) testfile " + testFile)
        else:

            # We need to detect where our test is.
            blocks = text.split("\n\n")
            found = False
            cnt = 0
            for i, block in enumerate(blocks):
                # Write our test to file
                outFile = open(testFile, "w")
                outFile.write(block)
                outFile.close()
                log.info("Testing syntax with shell %s" % testShell)
                (err, ret) = testBinary(testShell, testFile, scanOpts, 0, timeout=30)

                if err.find("SyntaxError") < 0:
                    # We have found the test (or maybe only the start of the test)
                    # Try adding more code until we hit an error or are out of
                    # blocks.
                    oldBlock = block
                    curBlock = block
                    for j, block in enumerate(blocks):
                        if j > i:
                            curBlock = curBlock + "\n" + block
                            # Write our test to file
                            outFile = open(testFile, "w")
                            outFile.write(curBlock)
                            outFile.close()
                            (err, ret) = testBinary(testShell, testFile, scanOpts, 0, timeout=30)
                            if err.find("SyntaxError") >= 0:
                                # Too much, write oldBlock and break
                                outFile = open(testFile, "w")
                                outFile.write(oldBlock)
                                outFile.close()
                                break
                            else:
                                oldBlock = curBlock

                    found = True
                    log.info("Isolated possible testcase starting in textblock {0}".format(cnt))
                    break
                cnt += 1
            if not found:
                # First try to find a suitable attachment
                attachments = self.bug.get_attachments()
                for attachment in attachments:
                    if attachment.is_obsolete:
                        continue
                    # Seriously, we don't need anything larger than 512kb here^^
                    if attachment.size <= 512 * 1024:
                        try:
                            rawData = base64.b64decode(attachment.data)
                            # Write our data to file
                            outFile = open(testFile, "w")
                            outFile.write(rawData)
                            outFile.close()
                            (err, ret) = testBinary(testShell, testFile, scanOpts, 0, timeout=30)
                            if err.find("SyntaxError") < 0:
                                # Found something that looks like JS :)
                                found = True
                                break
                        except TypeError:
                            pass

                # If we still haven't found any test, give up here...
                if not found:
                    # Ensure we don't cache the wrong test
                    os.remove(testFile)
                    raise BugException("Error: Failed to isolate test from comment")

        (oouterr, oret) = (None, None)
        (origShell, origRev) = (None, None)

        # If we have an exact architecture, we will only test that
        if archList is None:
            archList = [arch]

        for compileType in ['dbg', 'opt']:
            for archType in archList:
                try:
                    (origShell, origRev) = self.getShell("cache/", archType, compileType, 0, rev, False, repoDir,
                                                         buildFlags)
                except Exception:
                    # Unlike compilation failures on tip, we must not ignore compilation failures with the original
                    # revision, as it could mean that the bug was filed with a broken revision.
                    raise BugException("Error: Failed to compile specified revision %s (maybe try another?)" % rev)

                for opts in viableOptsList:
                    (oouterr, oret) = testBinary(origShell, testFile, opts, 0, timeout=30)
                    if oret < 0:
                        break

                # If we reproduced with one arch, then we don't need to try the others
                if oret < 0:
                    break

            # If we reproduced with dbg, then we don't need to try opt
            if oret < 0:
                break

        # Check if we reproduced at all (dbg or opt)
        if oret < 0:
            log.info("Successfully reproduced bug (exit code {0}) on original revision {1}:".format(oret, rev))
            errl = oouterr.split("\n")
            if len(errl) > 2: errl = errl[-2:]
            for err in errl:
                log.error(err)

            # Try running on tip now
            log.info("Testing bug on tip...")

            # Update to tip and cache result:
            updated = False
            if tipRepoDir not in self.tip_rev:
                # If we don't know the tip revision for this branch, update and get it
                self.tip_rev[tipRepoDir] = self.hgUpdate(tipRepoDir)
                updated = True

            try:
                (tipShell, tipRev) = self.getShell("cache/", archType, compileType, 0, self.tip_rev[tipRepoDir],
                                                   updated,
                                                   tipRepoDir, buildFlags)
            except Exception:
                trace = sys.exc_info()[2]
                raise InternalException("Failed to compile tip shell (toolchain broken?)").with_traceback(trace)

            tipOpts = None
            for opts in viableOptsList:
                (touterr, tret) = testBinary(tipShell, testFile, opts, 0, timeout=30)
                if tret < 0:
                    tipOpts = opts
                    break

            if tret < 0:
                if tret == oret:
                    if opts == tipOpts:
                        log.info("Result: Bug still reproduces")
                        return BugMonitorResult(reponame, rev, self.tip_rev[tipRepoDir], opts, testFile, archType,
                                                compileType,
                                                buildFlags, BugMonitorResult.statusCodes.REPRODUCED_TIP)
                    else:
                        # TODO need another code here in the future
                        log.info(
                            "Result: Bug still reproduces, but with different options: {0}".format(" ".join(tipOpts)))
                        return BugMonitorResult(reponame, rev, self.tip_rev[tipRepoDir], opts, testFile, archType,
                                                compileType,
                                                buildFlags, BugMonitorResult.statusCodes.REPRODUCED_TIP)
                else:
                    # Unlikely but possible, switched signal
                    log.info("Result: Bug now reproduces with signal {0} (previously {1})".format(tret, oret))
                    return BugMonitorResult(reponame, rev, self.tip_rev[tipRepoDir], opts, testFile, archType,
                                            compileType,
                                            buildFlags, BugMonitorResult.statusCodes.REPRODUCED_SWITCHED)
            else:
                log.info("Result: Bug no longer reproduces")
                return BugMonitorResult(reponame, rev, self.tip_rev[tipRepoDir], opts, testFile, archType, compileType,
                                        buildFlags, BugMonitorResult.statusCodes.REPRODUCED_FIXED)
        else:
            log.info("Error: Failed to reproduce bug on original revision")
            # return BugMonitorResult(reponame, rev, self.tipRev[tipRepoDir], opts, testFile, archType, compileType, buildFlags, BugMonitorResult.statusCodes.FAILED)
            return BugMonitorResult(reponame, rev, None, opts, testFile, archType, compileType, buildFlags,
                                    BugMonitorResult.statusCodes.FAILED)

    def extractOptions(self, text):
        ret = re.compile('((?: \-[a-z])+)', re.DOTALL).search(text)
        if ret:
            return ret.group(1).lstrip().split(" ")

        return None

    def extractRevision(self, text):
        if text is None:
            return None
        tokens = text.split(' ')
        for token in tokens:
            if re.match('^[a-f0-9]{12}[^a-f0-9]?', token):
                return token[0:12]
        return None

    def hgFindFixParent(self, repoDir):
        prevRev = None
        cmd = ['hg', 'log', '-l', '10000', '--template', '{node} {desc}\n']
        output = subprocess.check_output(cmd, cwd=repoDir, universal_newlines=True)
        for line in reversed(output.split('\n')):
            line = line.split(' ', 1)

            if len(line) < 2:
                continue

            rev = line[0][0:12]

            if line[1].find(str(self.bug.id)) != -1:
                return prevRev

            prevRev = rev
        return None

    def hgUpdate(self, repo_dir, rev=None):
        try:
            log.info("Running hg update...")
            if rev is not None:
                subprocess.check_call(['hg', 'update', '-C', '-r', rev], cwd=repo_dir)
            else:
                subprocess.check_call(['hg', 'update', '-C'], cwd=repo_dir)

            new_rev = subprocess.check_output(['hg', 'id', '-i'], cwd=repo_dir)
            return new_rev.strip().decode('utf-8')
        except Exception:
            raise ("Unexpected error while updating HG:", sys.exc_info()[0])

    def getShell(self, shellCacheDir, archNum, compileType, valgrindSupport, rev, updated, repoDir, buildFlags=None):
        # This code maps the old "-c dbg / -c opt" configurations to their configurations
        haveDebugOptFlags = False

        if buildFlags is not None:
            haveDebugOptFlags = ('--enable-debug' in buildFlags) or ('--disable-debug' in buildFlags) or (
                '--enable-optimize' in buildFlags) or ('--disable-optimize' in buildFlags)

        log.info("haveDebugOptFlags: %s %s" % (str(haveDebugOptFlags), " ".join(buildFlags)))

        if compileType == 'dbg':
            if buildFlags is not None:
                if not haveDebugOptFlags:
                    buildFlags.append('--enable-debug')
                    buildFlags.append('--enable-optimize')
            else:
                buildFlags = ['--enable-debug', '--enable-optimize']
        elif compileType == 'opt':
            if buildFlags is not None:
                if not haveDebugOptFlags:
                    buildFlags.append('--disable-debug')
                    buildFlags.append('--enable-optimize')
            else:
                buildFlags = ['--disable-debug', '--enable-optimize']

        if archNum == "32":
            buildFlags.append('--32')

        buildOpts = '-R %s' % repoDir
        if buildFlags is not None and len(buildFlags) > 0:
            buildOpts += ' %s' % " ".join(buildFlags)

        if rev is None:
            rev = self.hgUpdate(repoDir, rev)

        log.info("Compiling a new shell for revision {0}".format(rev))

        args = parse_shell_opts(buildOpts)
        shell = CompiledShell(args, rev)
        shell.run(["-b", buildOpts, "-r", rev])
        path = str(shell.get_shell_cache_js_bin_path())

        return path, rev


def parse_args(argv=None):
    parser = argparse.ArgumentParser()

    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument('-c', '--confirm',
                         action='store_true',
                         help='Attempt to confirm open bugs')
    actions.add_argument('-v', '--verify-fixed',
                         action='store_true',
                         help='Verify fix and comment')
    actions.add_argument('-p', '--process',
                         action='store_true',
                         help='Process commands on listed in bug whiteboard')

    # Optional args
    parser.add_argument('-u', '--update-bug',
                        action='store_true',
                        help='Update the bug')
    parser.add_argument('-P', '--update-bug-positive',
                        action='store_true',
                        default=False,
                        help='Update the bug when even if state isn\'t changed')
    # Required args
    parser.add_argument('-r', '--repobase',
                        default=None,
                        required=True,
                        help='Repository base directory.')

    # Bug selection
    bug_list = parser.add_mutually_exclusive_group(required=True)
    bug_list.add_argument('-b', '--bugs',
                          nargs='+',
                          help='Space separated list of bug numbers')
    bug_list.add_argument('-s', '--search-params',
                          help='Path to advanced search parameters')

    args = parser.parse_args(argv)

    if args.update_bug_positive and not args.confirm:
        raise parser.error('Option update-bug-positive only applicable with --confirm')
    if args.search_params and not os.path.isfile(args.search_params):
        raise parser.error('Search parameter path does not exist!')
    if not os.path.isdir(args.repobase):
        raise parser.error('Repobase path does not exist!')

    return args


def main(argv=None):
    args = parse_args(argv)

    if bool(os.getenv("DEBUG")):
        log_level = logging.DEBUG
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    else:
        log_level = logging.INFO
        log_fmt = "[%(asctime)s] %(message)s"
    logging.basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

    # Get the API root, default to bugzilla.mozilla.org
    api_root = os.environ.get('BZ_API_ROOT')
    api_key = os.environ.get('BZ_API_KEY')

    bug_ids = []
    if args.bugs:
        bug_ids.extend(args.bugs)
    else:
        bugsy = Bugsy(api_key=api_key, bugzilla_url=api_root)
        with open(args.search_params) as f:
            params = json.load(f)
            response = bugsy.request('bug', params=params)
            bugs = [Bug(bugsy, **bug) for bug in response['bugs']]
            bug_ids.extend([bug.id for bug in bugs])

    for bug_id in bug_ids:
        bugmon = BugMonitor(api_root, api_key, bug_id, args.repobase)

        log.info("====== Analyzing bug {0} ======".format(bug_id))
        try:
            if args.verify_fixed:
                bugmon.verify(args.update_bug)
            elif args:
                bugmon.confirm_open(args.update_bug, args.update_bug_positive)
            elif args.process:
                bugmon.process_whiteboard()
        except BugException as b:
            log.error("Cannot process bug: {0}".format(str(b)))
            log.error(traceback.format_exc())
        except Exception as e:
            log.error("Uncaught exception: {0}".format(str(e)))
            log.error(traceback.format_exc())


if __name__ == '__main__':
    main()
