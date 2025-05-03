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
G3DOC_DIR=$DIR/g3doc
HTML_DIR=$DIR/html
TABLE_DIR=$DIR/tables
TESTVECTORS=$DIR/testvectors

fopen() {
  g4 open $1
  rm $1
}

g4 sync
fopen $G3DOC_DIR/types.md
$PYTHON gen_doc.py > $G3DOC_DIR/types.md
mdformat --compatibility --in_place $G3DOC_DIR/types.md

fopen $G3DOC_DIR/files.md
$PYTHON file_stats.py --testvector_path=$DIR/testvectors/ > $G3DOC_DIR/files.md
mdformat --compatibility --in_place $G3DOC_DIR/files.md

# ===== Html
# fopen $HTML_DIR/types.html 
# $PYTHON gen_doc.py --format=html --out=$HTML_DIR/types.html
#
# fopen $HTML_DIR/files.html 
# $PYTHON file_stats.py --format=html > $HTML_DIR/files.html

# ===== Json
# fopen $TABLE_DIR/files.json
# $PYTHON file_stats.py --format=json > $TABLE_DIR/files.json

# ===== Test vector generation
# fopen $G3DOC_DIR/dependencies.md
# $PYTHON gen_dependency_graph.py > $G3DOC_DIR/dependencies.md

# fopen $G3DOC_DIR/type_dependencies.md 
# $PYTHON gen_type_dependency_graph.py > $G3DOC_DIR/type_dependencies.md

# fopen $G3DOC_DIR/generators.md
# $PYTHON gen_generators.py > $G3DOC_DIR/generators.md
# mdformat --in_place $G3DOC_DIR/generators.md

