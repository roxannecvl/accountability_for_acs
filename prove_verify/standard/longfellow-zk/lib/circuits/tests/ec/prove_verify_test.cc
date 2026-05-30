// Copyright 2026 Google LLC
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

// Thin benchmark driver for the credential prove/verify circuit (CFT variant).
// Shared circuit + witness logic lives in `prove_verify_shared.cc`.

#include "circuits/tests/ec/prove_verify_shared.h"

#include "benchmark/benchmark.h"

namespace proofs {

static void BM_ProveVerifyProver_P256(benchmark::State& state) {
  auto h = MakeProveVerifyHarnessP256(state.range(0));
  for (auto s : state) {
    benchmark::DoNotOptimize(ProveP256(*h));
  }
}
BENCHMARK(BM_ProveVerifyProver_P256)->Arg(1);

static void BM_ProveVerifyVerifier_P256(benchmark::State& state) {
  auto h = MakeProveVerifyHarnessP256(state.range(0));
  ProveP256(*h);
  auto pub = PublicInputsP256(*h);
  for (auto s : state) {
    benchmark::DoNotOptimize(VerifyP256(*h, *pub));
  }
}
BENCHMARK(BM_ProveVerifyVerifier_P256)->Arg(1);

static void BM_ProveVerifyFullCycle_P256(benchmark::State& state) {
  auto h = MakeProveVerifyHarnessP256(state.range(0));
  for (auto s : state) {
    benchmark::DoNotOptimize(ProveAndVerifyP256(*h));
  }
}
BENCHMARK(BM_ProveVerifyFullCycle_P256)->Arg(1);

}  // namespace proofs
