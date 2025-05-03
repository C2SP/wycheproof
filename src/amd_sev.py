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

# TODO: Deprecated.
# This file has been split into amd_sev_rsa, amd_sev_ec and amd_sev_util
# The reason for this change is to reduce dependencies to simplity
# the migration of the test generation code.
from amd_sev_ec import amd_sev_curves, le_encode, group_id, encode_ec_public, encode_ec_private, ecdsa_sig
from amd_sev_rsa import encode_rsa_public, encode_rsa_pss_signature

