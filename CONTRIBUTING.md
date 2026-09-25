# Contributing to Inter-Cluster Fabric

Inter-Cluster Fabric (ICF) is developed by Summon Software Labs and released under the
Apache License, Version 2.0.

## Contribution terms

By submitting a contribution (a patch, pull request, or any other form of change) to this
project you agree that:

1. You license your contribution under the **Apache License, Version 2.0**, the same terms
   that govern this project. Section 5 of that license ("Submission of Contributions")
   applies: unless you explicitly state otherwise, any contribution intentionally submitted
   for inclusion in this work shall be under the terms of the Apache License, Version 2.0,
   without any additional terms or conditions.
2. You have the right to submit the contribution. If your employer has rights to
   intellectual property that you create, you represent that you have permission to make the
   contribution on behalf of that employer, or that the employer has waived such rights.
3. You retain copyright to your contribution. **No Contributor License Agreement (CLA) is
   required and none will be requested.** There is no copyright assignment.
4. Contributions are provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
   KIND, either express or implied, as described in the Apache License, Version 2.0.

## Development expectations

* C++20, CMake 3.20 or newer. Builds must be warning-clean at the project warning level
  (`/W4` on MSVC, `-Wall -Wextra -Wpedantic` elsewhere).
* Every behavioral claim in a pull request must be backed by a test that runs by default in
  the test suite. Do not add CTest `TIMEOUT` properties or shell timeouts: a hang is a
  defect to be diagnosed, not masked.
* Do not add new runtime dependencies on third-party code without discussing it first. The
  runtime deliberately depends only on the C++ standard library and the platform socket API.
* Keep the adjacent-runtime boundary explicit: ICF owns cross-cluster connectivity
  authority. It does not own cluster internals, generic WAN/site routing, workload
  migration, storage replication, authentication infrastructure, or optical hardware
  control. Pull requests that widen that boundary will be asked to narrow it.
* Never report missing evidence as success. New code paths must preserve the distinction
  between the negative outcomes the runtime already models (UNKNOWN, UNSUPPORTED, STALE,
  CONFLICTING, INCOMPLETE, INDETERMINATE, REFUSED, CANCELLED, INVALID, and so on).
* No telemetry. The runtime must not transmit usage data anywhere; it only talks to the
  peers an operator configures.

## Reporting defects

Open an issue with the exact command line, the observed output, and the expected output. If
a defect involves persistence, include the relevant state directory contents (the store is
self-describing: magic, format version, and per-record CRC are in the file header).
