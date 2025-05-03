# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Generates some documentation from the python files.
# This currently includes the following:
# * Json schema for the test vectors
PYTHON=python3
DIR=.
OUT_DIR=$DIR/schemas

g4 open $OUT_DIR/*_schema.json
rm $OUT_DIR/*_schema.json
$PYTHON gen_schema.py --internal --out_dir=$OUT_DIR

