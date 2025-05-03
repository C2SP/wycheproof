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

class MQV1Encryptor:
  def __init__(self, curve, priv_key_sender, pub_key_receiver):
     self.curve = curve
     self.priv_key_sender = priv_key_sender
     self.pub_key_sender = priv_key_sender.public_key()
     self.pub_key_receiver = pub_key_receiver
     self.aead = None
     self.shared_static = pub_key_receiver * priv_key_sender
     

  def derive_shared_secret(self, ephemeral_priv, ctx):
    # Section 5.7.2.3.2
    kdf_input = join(ephemeral_priv, shared_static, pub_key_sender, pub_key_receiver)
    return KDF(kdf_input, ctx)
 

  def encrypt(msg, ctx):
    epriv, epub = self.generate_ephemeral_pair()
    z = self.derive_shared(epriv, ctx)
    crypter = self.aead(z)
    


