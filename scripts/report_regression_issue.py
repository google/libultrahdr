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

"""Automated regression failure triage, fingerprint deduplication, and issue reporter."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error


def parse_failures(log_text: str):
    """Parses Google Test / CTest output to extract failing test cases and stack traces."""
    failed_tests = []
    
    # Matches "[  FAILED  ] Suite.Test"
    failed_pattern = re.compile(r'\[\s+FAILED\s+\]\s+([A-Za-z0-9_]+\.[A-Za-z0-9_]+)')
    matches = failed_pattern.findall(log_text)
    
    for test_name in matches:
        if test_name not in failed_tests:
            failed_tests.append(test_name)
            
    return failed_tests


def extract_test_snippet(log_text: str, test_name: str) -> str:
    """Extracts failure log lines for a specific test case."""
    lines = log_text.splitlines()
    snippet_lines = []
    recording = False
    
    start_tag = f"[ RUN      ] {test_name}"
    end_tag = f"[  FAILED  ] {test_name}"
    
    for line in lines:
        if start_tag in line:
            recording = True
        if recording:
            snippet_lines.append(line)
        if end_tag in line and recording:
            break
            
    if not snippet_lines:
        snippet_lines = lines[-50:]
        
    return "\n".join(snippet_lines)


def get_git_commit_history(count=5) -> str:
    """Retrieves recent git commit log for culprit analysis."""
    try:
        res = subprocess.run(
            ["git", "log", f"-n{count}", "--pretty=format:%h - %an: %s (%cr)"],
            capture_output=True,
            text=True,
            check=True
        )
        return res.stdout.strip()
    except Exception as e:
        return f"Unable to fetch git log: {e}"


def get_current_commit() -> str:
    """Retrieves current git commit hash."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True
        )
        return res.stdout.strip()
    except Exception:
        return "unknown"


def generate_fingerprint(os_name: str, compiler: str, test_name: str, snippet: str) -> str:
    """Computes a stable SHA-256 fingerprint for deduplicating issues."""
    failure_line = ""
    for line in snippet.splitlines():
        if "Failure" in line or "error:" in line.lower():
            failure_line = line.strip()
            break
            
    raw_key = f"{os_name}:{compiler}:{test_name}:{failure_line}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:12]


def find_existing_github_issue(repo: str, fingerprint: str, token: str):
    """Searches for an open GitHub issue containing the unique fingerprint."""
    url = f"https://api.github.com/repos/{repo}/issues?state=open&labels=regression"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    
    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status == 200:
                issues = json.loads(resp.read().decode("utf-8"))
                for issue in issues:
                    if f"Fingerprint: `{fingerprint}`" in issue.get("body", ""):
                        return issue
    except Exception as e:
        print(f"Warning: Failed to query existing GitHub issues: {e}", file=sys.stderr)
        
    return None


def post_github_issue(repo: str, title: str, body: str, token: str, labels=None):
    """Creates a new issue on GitHub."""
    if labels is None:
        labels = ["regression", "automated-test", "bug"]
        
    url = f"https://api.github.com/repos/{repo}/issues"
    payload = {
        "title": title,
        "body": body,
        "labels": labels
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
        print(f"Error creating GitHub issue: {e.read().decode('utf-8')}", file=sys.stderr)
    except Exception as e:
        print(f"Error creating GitHub issue: {e}", file=sys.stderr)
        
    return None


def comment_github_issue(repo: str, issue_number: int, comment: str, token: str):
    """Posts a comment on an existing issue."""
    url = f"https://api.github.com/repos/{repo}/issues/{issue_number}/comments"
    payload = {"body": comment}
    
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("Content-Type", "application/json")
    
    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status in (200, 201):
                return True
    except Exception as e:
        print(f"Error commenting on GitHub issue #{issue_number}: {e}", file=sys.stderr)
    return False


def main():
    parser = argparse.ArgumentParser(description="Automated Regression Reporter & Triage")
    parser.add_argument("--log-file", required=True, help="Path to test runner log file")
    parser.add_argument("--os", default=os.getenv("RUNNER_OS", "Linux"), help="Operating system")
    parser.add_argument("--compiler", default="default", help="Compiler used")
    parser.add_argument("--config", default="", help="CMake config flags")
    parser.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY", "google/libultrahdr"), help="GitHub repository (owner/repo)")
    parser.add_argument("--token", default=os.getenv("GITHUB_TOKEN", ""), help="GitHub API Token")
    parser.add_argument("--run-url", default=os.getenv("GITHUB_RUN_URL", ""), help="URL of the CI Run")
    parser.add_argument("--dry-run", action="store_true", help="Print report instead of posting")
    
    args, unknown = parser.parse_known_args()
    
    if not os.path.exists(args.log_file):
        print(f"Log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(1)
        
    with open(args.log_file, "r", encoding="utf-8", errors="replace") as f:
        log_content = f.read()
        
    failed_tests = parse_failures(log_content)
    if not failed_tests:
        print("No test failures detected in log.")
        sys.exit(0)
        
    commit_sha = get_current_commit()
    recent_commits = get_git_commit_history(count=5)
    
    print(f"Detected {len(failed_tests)} failing test(s): {', '.join(failed_tests)}")
    
    for test_name in failed_tests:
        snippet = extract_test_snippet(log_content, test_name)
        fingerprint = generate_fingerprint(args.os, args.compiler, test_name, snippet)
        
        title = f"🚨 [Daily Regression] {test_name} failed on {args.os} ({args.compiler})"
        
        body = f"""### 🚨 Automated Daily Regression Report

**Failed Test**: `{test_name}`
**Fingerprint**: `{fingerprint}`
**Commit**: `{commit_sha}`
**CI Run**: {args.run_url if args.run_url else 'N/A'}

#### Environment Matrix
- **OS**: {args.os}
- **Compiler**: {args.compiler}
- **Build Flags**: `{args.config}`

#### Failure Log Snippet
```text
{snippet}
```

#### Exact Local Reproduction
```bash
cmake -B build {args.config} -DUHDR_BUILD_TESTS=ON
cmake --build build -j
./build/ultrahdr_unit_test --gtest_filter="{test_name}"
```

#### Recent Commits in Window (Potential Culprits)
```text
{recent_commits}
```

---
*Generated automatically by libultrahdr Regression CI.*
"""
        if args.dry_run or not args.token:
            print("\n" + "="*80)
            print(f"TITLE: {title}")
            print("="*80)
            print(body)
            print("="*80 + "\n")
            continue
            
        existing_issue = find_existing_github_issue(args.repo, fingerprint, args.token)
        if existing_issue:
            issue_num = existing_issue["number"]
            issue_url = existing_issue["html_url"]
            print(f"Found existing open issue #{issue_num}: {issue_url}. Appending comment...")
            comment_body = f"""⚠️ **Regression recurring in daily CI run**
- **Commit**: `{commit_sha}`
- **CI Run**: {args.run_url}
- **Environment**: {args.os} ({args.compiler})

```text
{snippet}
```
"""
            comment_github_issue(args.repo, issue_num, comment_body, args.token)
        else:
            print(f"Creating new issue for {test_name} (Fingerprint: {fingerprint})...")
            new_issue_url = post_github_issue(args.repo, title, body, args.token)
            if new_issue_url:
                print(f"Created issue: {new_issue_url}")


if __name__ == "__main__":
    main()
