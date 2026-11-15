# Xiaomi 14T (degas) — PixelOS 17 kernel prebuilts

Matching stock kernel, DTB, DTBO and loadable modules for the [PixelOS 17 degas device tree](https://github.com/mt6897-degas/android_device_xiaomi_degas/tree/pixelos-17).

This branch uses **HyperOS OS3.0.306.0.WNEEUXM**, EEA, Android 16. 518 active payloads remain factory-identical. This candidate branch replaces only `mtk_charger_framework.ko` with the [fixed-PD ICL patch](patches/pd-icl/README.md); its code and package checks pass, while hardware validation is pending. PixelOS packages these prebuilts into its boot and DLKM images. Building the kernel itself requires a separate kernel source checkout.

The original [degas kernel-prebuilt repository](https://github.com/degas-developers/android_device_xiaomi_degas-kernel) was maintained by **[Mikhail Mlhcnn (Advnirr)](https://github.com/Advnirr)** / [Degas Developers](https://github.com/degas-developers). Its history and notices are preserved; the PixelOS branch updates the stock inputs and module layout.

## Contents

| Path | Content |
| --- | --- |
| `Image.lz4` | Stock GKI kernel `6.1.157-android14-11-g78a0a76cd7b7-ab15497637` |
| `dtb/degas.dtb` | Unchanged DTB payload from factory `vendor_boot.img` |
| `dtbo.img` | Complete factory DTBO partition image, 8,388,608 bytes |
| `modules/system/` | 60 modules from `system_dlkm` |
| `modules/vendor/` | 241 modules from `vendor_dlkm` |
| `modules/vendor_ramdisk/` | 215 platform vendor-ramdisk modules |
| `stock-kernel.lock.json` | SHA256 hashes for all 519 active payload files, including the documented PD overlay |
| `stock-kernel.factory.lock.json` | Original factory hashes before the PD overlay |
| `patches/pd-icl/` | Reproducible patch source, machine-code tests and verification reports |
| `reference/lineage-23.2/` | Original DTS, thermal patches, modified DTB and UAPI headers for the older Lineage stock kernel; retained for reference |

The kernel's embedded build date is May 26, 2026. The directory split preserves distinct factory versions of zram and zsmalloc. Preserve the selected active module contents during packaging. Signed modules retain their factory signatures; the modified vendor framework was unsigned. Do not strip or disable signature enforcement.

The `.dtb` filename is required by Android's prebuilt DTB rule. Place only the active `degas.dtb` in the consumed `dtb/` directory; the original modified `mt6897.dtb` is stored under `reference/` and is not selected by the PixelOS device tree. Its legacy thermal changes are not applied to the current stock DTB. The older UAPI header archive is also reference material for the older kernel.

## Use with PixelOS

From the Android checkout root:

```bash
git clone -b pixelos-17-pd-icl https://github.com/mt6897-degas/android_device_xiaomi_degas-kernel.git device/xiaomi/degas-kernel
python3 device/xiaomi/degas/tools/validate-tree.py
```

Use the sibling device tree's `pixelos-17` branch. Its `BoardConfig.mk` selects `Image.lz4`, `dtb/degas.dtb`, `dtbo.img` and the partition-specific module directories. Kernel prebuilts need no standalone Android makefile because those paths are consumed directly by the device configuration.

The initial PixelOS 17 build included the original factory kernel and DTB payloads. This PD ICL candidate has not been booted on a device. Device boot with SELinux enforcing and later fixes has been checked. No custom kernel was compiled for this port, and comprehensive hardware, suspend and battery testing remains incomplete.

## Reproduce from stock firmware

Use the matching OS3.0.306.0.WNEEUXM fastboot package, `fsck.erofs`, `lz4`, and the sibling device tree's preparation tool. Choose new output directories:

```bash
python3 device/xiaomi/degas/tools/prepare-stock.py \
    /absolute/path/to/degas_eea_global_images_OS3.0.306.0.WNEEUXM_16.0 \
    --work "$PWD/stock/degas-verification" \
    --kernel "$PWD/stock/degas-kernel-verification"
```

The tool extracts the matching boot/vendor_boot payloads and platform modules, preserving their partition layout and recording their hashes. The extracted stock payloads match `stock-kernel.factory.lock.json`. Apply the documented PD overlay to obtain the active `stock-kernel.lock.json` payloads.

## Verify payload hashes

From this repository root:

```bash
python3 - <<'PY'
import hashlib, json
from pathlib import Path
root = Path('.')
lock = json.loads((root / 'stock-kernel.lock.json').read_text())
for name, expected in lock['files'].items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name
print(f"Verified {len(lock['files'])} active payloads")
PY
```

The sibling device tree's validator additionally checks the DT table/FDT layout, module-load lists and required vendor modules. Retain matching kernel/modules/DTB/DTBO together when updating the stock base.

## License and source references

Original copyright and licensing notices are retained in [LICENSE](LICENSE). The Linux kernel contributors, Google, Xiaomi and MediaTek retain ownership of the factory binaries. Mikhail Mlhcnn's original DTS changes remain available under `reference/lineage-23.2/dts/` and in the upstream history.

Kernel source references: [Android common kernel, android14-6.1](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1), [MiCode/Xiaomi_Kernel_OpenSource](https://github.com/MiCode/Xiaomi_Kernel_OpenSource), [MiCode/MTK_kernel_modules](https://github.com/MiCode/MTK_kernel_modules) and [MiCode/kernel_build](https://github.com/MiCode/kernel_build). This repository contains factory prebuilts and reference material; it is not a complete kernel source release.
