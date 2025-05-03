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
# * g3doc equivalent for the Json schema.
# * Html equivalent for the Json schema.
PYTHON=python3
DIR=.
DEFINITIONS=$DIR/schemas_v1


rm $DEFINITIONS/*_schema.json
$PYTHON gen_schema.py --out_dir=$DIR

