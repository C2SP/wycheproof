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

# Regenerates the tables
PYTHON=python3
DIR=/google/src/cloud/bleichen/keymaster1/google3/experimental/users/bleichen/wycheproof
TABLES=$DIR/tables

fopen() {
  g4 open $1
  rm $1
}

fopen $TABLES/special_ec_points_table.json
$PYTHON ec_special.py > $TABLES/special_ec_points_table.json

