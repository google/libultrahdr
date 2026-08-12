#!/usr/bin/env python3
#
# Copyright 2026 The Android Open Source Project
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

"""Verifies that Git release tags, CMakeLists.txt, and ultrahdr_api.h version strings match."""

import argparse
import os
import re
import sys


def parse_cmake_version(cmake_path: str) -> str:
  with open(cmake_path, "r", encoding="utf-8") as f:
    content = f.read()

  major = re.search(r"set\s*\(\s*UHDR_MAJOR_VERSION\s+(\d+)\s*\)", content)
  minor = re.search(r"set\s*\(\s*UHDR_MINOR_VERSION\s+(\d+)\s*\)", content)
  patch = re.search(r"set\s*\(\s*UHDR_PATCH_VERSION\s+(\d+)\s*\)", content)

  if not (major and minor and patch):
    raise ValueError(f"Could not parse version numbers from {cmake_path}")

  return f"{major.group(1)}.{minor.group(1)}.{patch.group(1)}"


def parse_header_version(header_path: str) -> str:
  with open(header_path, "r", encoding="utf-8") as f:
    content = f.read()

  major = re.search(r"#define\s+UHDR_LIB_VER_MAJOR\s+(\d+)", content)
  minor = re.search(r"#define\s+UHDR_LIB_VER_MINOR\s+(\d+)", content)
  patch = re.search(r"#define\s+UHDR_LIB_VER_PATCH\s+(\d+)", content)

  if not (major and minor and patch):
    raise ValueError(f"Could not parse version numbers from {header_path}")

  return f"{major.group(1)}.{minor.group(1)}.{patch.group(1)}"


def main() -> int:
  parser = argparse.ArgumentParser(description="Verify libultrahdr version consistency.")
  parser.add_argument("--repo-root", default=".", help="Path to libultrahdr repository root")
  parser.add_argument("--tag", default=None, help="Git tag name to validate (e.g. 'v2.0.1')")
  args = parser.parse_args()

  cmake_file = os.path.join(args.repo_root, "CMakeLists.txt")
  header_file = os.path.join(args.repo_root, "ultrahdr_api.h")

  if not os.path.exists(cmake_file):
    print(f"Error: {cmake_file} not found.", file=sys.stderr)
    return 1
  if not os.path.exists(header_file):
    print(f"Error: {header_file} not found.", file=sys.stderr)
    return 1

  cmake_ver = parse_cmake_version(cmake_file)
  header_ver = parse_header_version(header_file)

  print(f"[INFO] CMakeLists.txt version : {cmake_ver}")
  print(f"[INFO] ultrahdr_api.h version : {header_ver}")

  if cmake_ver != header_ver:
    print(
        f"[ERROR] Version mismatch: CMakeLists.txt ({cmake_ver}) != ultrahdr_api.h ({header_ver})",
        file=sys.stderr,
    )
    return 1

  if args.tag:
    tag_clean = args.tag.lstrip("v")
    print(f"[INFO] Git tag to validate    : {args.tag} (normalized: {tag_clean})")
    if tag_clean != cmake_ver:
      print(
          f"[ERROR] Tag mismatch: Git tag '{args.tag}' ({tag_clean}) does not match repository version ({cmake_ver})!",
          file=sys.stderr,
      )
      return 1
    print(f"[SUCCESS] Git tag '{args.tag}' matches repository version ({cmake_ver}) exactly.")
  else:
    print(f"[SUCCESS] In-tree version strings are consistent ({cmake_ver}).")

  return 0


if __name__ == "__main__":
  sys.exit(main())
