#!/usr/bin/env bash

# Finds files in a given directory with a given file extension that don't have
# an MPL license header.

license="/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */"

files=( $(find src -name "*.rs") )

echo "Checking the following files for license headers: ${files[@]}"
result=0

echo ""

for file in ${files[@]}; do
  if ! [ "$(head $file -n3)" = "$license" ]; then
    echo "Incorrect header in $file"
    result=1
  fi
done    

echo ""

exit $result