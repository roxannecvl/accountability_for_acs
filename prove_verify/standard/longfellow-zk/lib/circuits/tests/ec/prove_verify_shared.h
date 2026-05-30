// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_PROVE_VERIFY_SHARED_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_PROVE_VERIFY_SHARED_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "arrays/dense.h"
#include "ec/p256.h"

namespace proofs {

constexpr size_t kProveVerifyRate = 7;
constexpr size_t kProveVerifyQueries = 132;

extern const char kP256ExtRootX[];
extern const char kP256ExtRootY[];
constexpr uint64_t kP256ExtRootOrder = 1ull << 31;

// 32 attribute slots; flat SHA-256 over Merkle-style leaves SHA256(be32(i)||value_i);
// 7 slots used (0,1,4,5,6,14,15). Slot index is in the leaf (not a UTF-8 claim label).
constexpr size_t kProveVerifyCredentialAttrs = 32;
constexpr size_t kProveVerifyAttrBytes = 32;
constexpr size_t kProveVerifyCredentialMsgBytes =
    kProveVerifyCredentialAttrs * kProveVerifyAttrBytes;
constexpr size_t kProveVerifyCredentialShaBlocks = 17;
constexpr size_t kProveVerifyCommitMsgBytes = 5 * 32;
constexpr size_t kProveVerifyCommitShaBlocks = 3;
constexpr size_t kProveVerifyTsBits = 43;

struct P256Traits {
  using Field = Fp256Base;
  using Scalar = Fp256Scalar;
  using EC = P256;

  static const EC& ec();
  static const Field& field();
  static const Scalar& scalar_field();
};

constexpr size_t kProveVerifyPubIdxIssuerX = 1;
constexpr size_t kProveVerifyPubIdxIssuerY = 2;
constexpr size_t kProveVerifyPubIdxElgamalX = 3;
constexpr size_t kProveVerifyPubIdxElgamalY = 4;
constexpr size_t kProveVerifyPubIdxT = 5;
constexpr size_t kProveVerifyPubIdxC1x = 6;
constexpr size_t kProveVerifyPubIdxC1y = 7;
constexpr size_t kProveVerifyPubIdxC2x = 8;
constexpr size_t kProveVerifyPubIdxC2y = 9;
constexpr size_t kProveVerifyPubIdxC3x = 10;
constexpr size_t kProveVerifyPubIdxC3y = 11;
constexpr size_t kProveVerifyPubIdxC4 = 12;
constexpr size_t kProveVerifyPubIdxM = 13;
constexpr size_t kProveVerifyPubIdxNow = 14;
constexpr size_t kProveVerifyPubIdxMaxBirth = 15;

class ProveVerifyHarnessP256;

struct ProveVerifyHarnessP256Deleter {
  void operator()(ProveVerifyHarnessP256* p) const;
};

using ProveVerifyHarnessP256Ptr =
    std::unique_ptr<ProveVerifyHarnessP256, ProveVerifyHarnessP256Deleter>;

ProveVerifyHarnessP256Ptr MakeProveVerifyHarnessP256(size_t numInstances);

bool ProveP256(ProveVerifyHarnessP256& h);
std::unique_ptr<Dense<Fp256Base>> PublicInputsP256(
    const ProveVerifyHarnessP256& h);
bool VerifyP256(const ProveVerifyHarnessP256& h, const Dense<Fp256Base>& pub);

inline bool ProveAndVerifyP256(ProveVerifyHarnessP256& h) {
  if (!ProveP256(h)) return false;
  auto pub = PublicInputsP256(h);
  return VerifyP256(h, *pub);
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_PROVE_VERIFY_SHARED_H_
