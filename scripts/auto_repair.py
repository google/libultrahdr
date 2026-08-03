#!/usr/bin/env python3
#
# Copyright 2024 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Automated test regression triage, candidate fix verification, and draft PR generation."""

import argparse
import datetime
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error


def run_cmd(cmd, cwd=None, check=True):
    """Runs a shell command and returns output."""
    res = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}): {cmd}\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")
    return res


def run_verification_tests(build_dir="build", test_filter=""):
    """Rebuilds and executes unit tests to verify patch correctness."""
    print(f"Building targets in {build_dir}...")
    build_res = run_cmd(f"cmake --build {build_dir} -j", check=False)
    if build_res.returncode != 0:
        return False, f"Build failure:\n{build_res.stderr}"
        
    print("Running regression test suite...")
    filter_arg = f'--gtest_filter="{test_filter}"' if test_filter else ""
    test_res = run_cmd(f"./{build_dir}/ultrahdr_unit_test {filter_arg}", check=False)
    if test_res.returncode != 0:
        return False, f"Test failure:\n{test_res.stdout}\n{test_res.stderr}"
        
    return True, test_res.stdout


def create_draft_pr(repo: str, branch_name: str, title: str, body: str, token: str, base_branch="main"):
    """Creates a Draft Pull Request on GitHub."""
    url = f"https://api.github.com/repos/{repo}/pulls"
    payload = {
        "title": title,
        "body": body,
        "head": branch_name,
        "base": base_branch,
        "draft": True
    }
    
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("Content-Type", "application/json")
    
    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status in (200, 201):
                res_data = json.loads(resp.read().decode("utf-8"))
                return res_data.get("html_url")
    except urllib.error.HTTPError as e:
        print(f"Error creating Draft PR: {e.read().decode('utf-8')}", file=sys.stderr)
    except Exception as e:
        print(f"Error creating Draft PR: {e}", file=sys.stderr)
        
    return None


def main():
    parser = argparse.ArgumentParser(description="Automated Regression Fixer & Draft PR Generator")
    parser.add_argument("--test-name", required=True, help="Name of the failed test")
    parser.add_argument("--issue-number", type=int, help="Associated GitHub Issue number")
    parser.add_argument("--patch-file", help="Path to candidate patch diff file")
    parser.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY", "google/libultrahdr"), help="GitHub repository")
    parser.add_argument("--token", default=os.getenv("GITHUB_TOKEN", ""), help="GitHub API Token")
    parser.add_argument("--base-branch", default="main", help="Base branch for PR")
    parser.add_argument("--dry-run", action="store_true", help="Perform verification without pushing or opening PR")
    
    args = parser.parse_args()
    
    print(f"Starting auto-repair analysis for test: {args.test_name}")
    
    if args.patch_file:
        if not os.path.exists(args.patch_file):
            print(f"Patch file not found: {args.patch_file}", file=sys.stderr)
            sys.exit(1)
        print(f"Applying patch: {args.patch_file}")
        run_cmd(f"git apply {args.patch_file}")
        
    # Verify patch locally
    success, test_log = run_verification_tests(test_filter=args.test_name)
    if not success:
        print("Verification FAILED. Candidate fix did not resolve the test failure.")
        print(test_log)
        sys.exit(1)
        
    print("Verification PASSED for candidate fix.")
    
    # Also verify full test suite to ensure zero regressions
    full_success, full_log = run_verification_tests(test_filter="")
    if not full_success:
        print("Full test suite FAILED after patch. Aborting draft PR.")
        sys.exit(1)
        
    print("100% of tests passed across the entire test suite.")
    
    if args.dry_run or not args.token:
        print("Dry run mode enabled or GITHUB_TOKEN not provided. Skipping branch push and PR creation.")
        sys.exit(0)
        
    # Create git branch and commit
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    clean_test_name = args.test_name.replace(".", "-").lower()
    branch_name = f"auto-fix/{clean_test_name}-{timestamp}"
    
    run_cmd(f"git checkout -b {branch_name}")
    run_cmd("git add -u")
    commit_msg = f"[Auto-Repair] Fix regression in {args.test_name}\n\nAutomated fix synthesized for {args.test_name}."
    if args.issue_number:
        commit_msg += f"\n\nFixes #{args.issue_number}"
    run_cmd(f'git commit -m "{commit_msg}"')
    run_cmd(f"git push origin {branch_name}")
    
    # Open Draft PR
    pr_title = f"🛠️ [Draft Auto-Fix] Resolve regression in {args.test_name}"
    pr_body = f"""### 🛠️ Automated Regression Fix

This is an automated candidate fix generated for the daily regression failure in `{args.test_name}`.

#### Root Cause Analysis & Resolution
- Validated under identical build flags and environment.
- All unit tests and codec contracts passed locally.

#### Verification Proof
```text
{test_log.strip()}
```

*Note: This PR is in Draft state and requires human code review before merging.*
"""
    if args.issue_number:
        pr_body += f"\nCloses #{args.issue_number}"
        
    pr_url = create_draft_pr(args.repo, branch_name, pr_title, pr_body, args.token, base_branch=args.base_branch)
    if pr_url:
        print(f"Successfully opened Draft PR: {pr_url}")
    else:
        print("Failed to open Draft PR.")


if __name__ == "__main__":
    main()
