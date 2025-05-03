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

# DEPRECATED: Use gen_rsa_pub_key.py instead
import gen_rsa_pub_key

# DEPRECATED: Use gen_rsa_pub_key.py instead
def main(namespace):
  gen_rsa_pub_key.RsaPubKeyProducer().produce(namespace)

# DEPRECATED: Use gen_rsa_pub_key.py instead
if __name__ == "__main__":
  gen_rsa_pub_key.RsaPubKeyProducer().produce_with_args()
