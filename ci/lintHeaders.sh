#!/usr/bin/env bash

# Finds files in a given directory with a given file extension that don't have
# an MPL license header.

license="/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */"

files=$(find src -type f -name "*.rs")

echo "Checking the following files for license headers: ${files[@]}"
result=0

headerLineNumbers() {
   grep -Fn -e "$license1" -e "$license2" -e "$license3" "$1" | cut -f1 -d:
}

expectedHeaderLineNumbers='1
2
3'

for file in ${files[@]}; do
  if ! [[ "$(head -n3 "$1")" = "$license" ]]; then
    echo "$file"
    result=1
  fi
done

exit $result
