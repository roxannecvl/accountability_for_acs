# Copyright 2026 Google LLC
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

# EC test circuits and benchmarks (not used in production).

# CFT variant: full credential prove/verify (P-256 ECDSA + flat SHA-256
# commitment + ElGamal-style outputs c1..c4).
proofs_add_test(prove_verify_test prove_verify_shared.cc)
target_link_libraries(prove_verify_test flatsha)

# no-CFT variant: same proof minus ID binding / ElGamal outputs.
proofs_add_test(prove_verify_no_cft_test prove_verify_no_cft_shared.cc)
target_link_libraries(prove_verify_no_cft_test flatsha)
