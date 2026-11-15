# degas fixed-PD input-current limit

This candidate replaces the factory normal-PD 1.7 A input limit with the lesser of the selected fixed 9 V PDO current, the current explicit PD contract and the existing 3 A basic-charger ceiling, rounded down to 50 mA. The observed 9 V / 2.22 A contract selects 2.2 A instead of 1.7 A. All later stock current and thermal clamps still run. This does not establish 67 W HyperCharge support.

The helper performs read-only native calls. Invalid caps, unsuccessful/incomplete verification, PPS, voltage mismatch, missing contract or changed connection state retain the original DT fallback. The 5 V path, battery authentication, charge pumps, JEITA/SIC/thermal policy and firmware are preserved.

The patch applies only to the three factory modules pinned in `patch-module.py`. It replaces one instruction in `do_algorithm` and appends a freestanding AArch64 helper and context wrapper. The existing export ABI, symbol indices, relocations, CFI checks, alternatives, module metadata and import CRCs remain unchanged. The one added import is `tcpm_inquire_pd_contract`, with the CRC taken from the matching factory `tcpc_class.ko`; that module is already a dependency. The factory framework has no appended Linux module signature. Signed GKI modules and signature enforcement are unchanged. The helper uses PAC return signing, a balanced shadow call stack and the same task stack-canary offset as the factory module.

644 Unicorn cases execute the actual modified instructions and cover both current bounds, selected versus other PDOs, invalid/error/PPS/disconnect states, all general registers and flags, SIMD/FP state, aligned SP, balanced SCS and a canary failure. Actual kernel loading, boot, hardware PAC and charging power are unverified. This branch is a hardware-validation candidate.

## Reproduce

Validated compiler: Apple Clang 21.0.0, targeting `aarch64-linux-gnu`. Use Python with `pyelftools`, `capstone` and `unicorn`. The script checks exact binary inputs and code layout; another compiler may require a reviewed layout update. Get the original inputs from the unmodified `pixelos-17` branch or prepare the matching factory package. Keep the original three modules together in a separate directory.

```sh
python3 patches/pd-icl/patch-module.py --source-dir /absolute/path/to/factory/modules/vendor_ramdisk
python3 patches/pd-icl/test-module.py
cmp patches/pd-icl/mtk_charger_framework.ko modules/vendor_ramdisk/mtk_charger_framework.ko
```

`stock-kernel.factory.lock.json` records the factory inputs. `stock-kernel.lock.json` records the active candidate, with one documented overlay. The generated module/object files in this directory are ignored by Git.
