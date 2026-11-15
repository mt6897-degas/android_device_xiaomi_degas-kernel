#!/usr/bin/env python3
"""Execute the actual extended AArch64 code with mocked native exports."""
from pathlib import Path
from io import BytesIO
import hashlib, json, random, struct
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from importlib.util import spec_from_file_location, module_from_spec

WORK = Path(__file__).resolve().parent
spec = spec_from_file_location('patch_module', WORK / 'patch-module.py')
patch = module_from_spec(spec); spec.loader.exec_module(patch)
REPORT = json.loads((WORK / 'MODULE-VERIFICATION.json').read_text())
DATA = (WORK / 'mtk_charger_framework.ko').read_bytes()
assert hashlib.sha256(DATA).hexdigest() == REPORT['output_sha256']
ELF = ELFFile(BytesIO(DATA))
TEXT = ELF.get_section_by_name('.text').data()
SYMS = ELF.get_section_by_name('.symtab')
BASE, STUBS, MEMORY = 0x100000, 0x200000, 0x300000
CHARGER, ADAPTER, PRIVATE, PORTS, TCPC = [MEMORY + x for x in [0, 0x10000, 0x11000, 0x12000, 0x13000]]
STACK, SCS, TASK = MEMORY + 0x30000, MEMORY + 0x40000, MEMORY + 0x45000
X = [globals()[f'UC_ARM64_REG_X{i}'] for i in range(31)]

def run(case, flags=0, tamper=False):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(BASE, 0x30000); uc.mem_write(BASE, TEXT)
    uc.mem_map(STUBS, 0x1000); uc.mem_map(MEMORY, 0x50000)
    names = {}
    for rel in ELF.get_section_by_name('.rela.text').iter_relocations():
        if rel['r_offset'] < REPORT['original_text_bytes']:
            continue
        name = SYMS.get_symbol(rel['r_info_sym']).name
        if name not in names:
            names[name] = STUBS + 16 * len(names)
        address = BASE + rel['r_offset']
        uc.mem_write(address, patch.branch(address, names[name], True))
    reverse = {v: k for k, v in names.items()}
    w32 = lambda p, v: uc.mem_write(p, struct.pack('<I', v & 0xffffffff))
    w64 = lambda p, v: uc.mem_write(p, struct.pack('<Q', v & 0xffffffffffffffff))
    uc.reg_write(UC_ARM64_REG_SP_EL0, TASK)
    w64(TASK + 1592, 0x91ff3217cafed00d)
    fallback = case.get('fallback', 1700000)
    w32(CHARGER + 4432, fallback)
    w64(CHARGER + 1896, 0 if case.get('no_adapter') else ADAPTER)
    w64(ADAPTER + 1512, 0 if case.get('no_private') else PRIVATE)
    w32(PRIVATE + 8, case.get('port_index', 0))
    w32(PRIVATE + 64, case.get('nr_ports', 1))
    w64(PRIVATE + 72, 0 if case.get('no_ports') else PORTS)
    for i in range(8):
        w64(PORTS + 8 * i, 0 if case.get('no_tcpc') else TCPC)
    rng = random.Random(100)
    initial = [rng.getrandbits(64) for _ in X]
    initial[0] = case.get('vbus', 8600); initial[18] = SCS; initial[19] = CHARGER
    for reg, value in zip(X, initial): uc.reg_write(reg, value)
    vectors = [rng.getrandbits(128) for _ in range(32)]
    for i, value in enumerate(vectors): uc.reg_write(globals()[f'UC_ARM64_REG_Q{i}'], value)
    uc.reg_write(UC_ARM64_REG_SP, STACK)
    uc.reg_write(UC_ARM64_REG_NZCV, flags)
    uc.reg_write(UC_ARM64_REG_FPCR, 0x400000)
    before_fpcr = uc.reg_read(UC_ARM64_REG_FPCR)
    uc.reg_write(UC_ARM64_REG_FPSR, 0x10)
    before_fpsr = uc.reg_read(UC_ARM64_REG_FPSR)
    calls, counts, lock_depth = [], {}, 0
    stopped = {'resume': False, 'stack_fail': False}
    resume = BASE + REPORT['hook_text_offset'] + 4

    def hook(u, address, size, _):
        nonlocal lock_depth
        if address == resume:
            stopped['resume'] = True; u.emu_stop(); return
        if address not in reverse: return
        name = reverse[address]; calls.append(name)
        counts[name] = counts.get(name, 0) + 1
        args = [u.reg_read(r) for r in X[:3]]
        assert u.reg_read(UC_ARM64_REG_SP) % 16 == 0
        assert u.reg_read(X[18]) == SCS + 8, 'shadow call stack is active'
        result = 0
        if name == '__stack_chk_fail':
            stopped['stack_fail'] = True; u.emu_stop(); return
        if name == 'adapter_dev_get_property':
            assert args[:2] == [ADAPTER, 1]
            result = case.get('pd_type', 3)
            if counts[name] > 1: result = case.get('pd_type_after', result)
        elif name == 'usb_get_property':
            assert args[0] in (3, 19)
            prop = args[0]
            value = case.get('done', 1) if prop == 19 else case.get('verifying', 0)
            if counts[name] > 2:
                value = case.get('done_after', value) if prop == 19 else case.get('verifying_after', value)
            w32(args[1], value)
            result = case.get('usb_error', 0)
        elif name == 'adapter_dev_get_cap':
            assert args[:2] == [ADAPTER, 2]
            cap = bytearray(268)
            cap[0] = case.get('selected', 1); cap[1] = case.get('nr', 2)
            for i in range(10):
                # PDO0 advertises more current than the selected PDO1.
                maximum = 5000 if i == 0 else case.get('max_mv', 9000)
                minimum = 5000 if i == 0 else case.get('min_mv', 9000)
                current = 3000 if i == 0 else case.get('offered_ma', 2220)
                struct.pack_into('<I', cap, 16 + 4 * i, maximum)
                struct.pack_into('<I', cap, 56 + 4 * i, minimum)
                struct.pack_into('<I', cap, 96 + 4 * i, current & 0xffffffff)
                cap[216 + i] = case.get('cap_type', 0)
            u.mem_write(args[2], bytes(cap)); result = case.get('cap_error', 0)
        elif name == 'mutex_lock':
            assert args[0] == PRIVATE + 16 and lock_depth == 0; lock_depth += 1
        elif name == 'mutex_unlock':
            assert args[0] == PRIVATE + 16 and lock_depth == 1; lock_depth -= 1
        elif name == 'tcpm_inquire_pd_contract':
            assert args[0] == TCPC and lock_depth == 0
            w32(args[1], case.get('contract_mv', 9000))
            w32(args[2], case.get('contract_ma', 2220))
            result = case.get('contract_error', 0)
            if tamper: w64(TASK + 1592, 0xdeadbeef)
            if case.get('replace_adapter'): w64(CHARGER + 1896, ADAPTER + 8)
        elif name == 'get_vbus':
            assert args[0] == CHARGER
            result = case.get('vbus_after', case.get('vbus', 8600))
        else: raise AssertionError(name)
        # Every native call may destroy all caller-saved registers and flags.
        lr = u.reg_read(X[30])
        for i in range(18): u.reg_write(X[i], 0xabcd000000000000 + i)
        u.reg_write(X[0], result & 0xffffffffffffffff)
        u.reg_write(UC_ARM64_REG_NZCV, 0xf0000000 ^ flags)
        u.reg_write(UC_ARM64_REG_PC, lr)

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(BASE + REPORT['hook_text_offset'], BASE + len(TEXT), count=10000)
    if tamper:
        assert stopped['stack_fail'] and not stopped['resume']
        return {'canary_failure_traps': True}
    assert stopped['resume'] and not stopped['stack_fail'] and lock_depth == 0
    actual = uc.reg_read(X[8])
    expected = case['expected']
    assert actual == expected, (case, actual, expected, calls)
    for i, reg in enumerate(X):
        assert uc.reg_read(reg) == (expected if i == 8 else initial[i]), ('register', i, case)
    assert uc.reg_read(UC_ARM64_REG_SP) == STACK
    assert uc.reg_read(UC_ARM64_REG_NZCV) == flags
    assert uc.reg_read(UC_ARM64_REG_FPCR) == before_fpcr
    assert uc.reg_read(UC_ARM64_REG_FPSR) == before_fpsr
    for i, value in enumerate(vectors): assert uc.reg_read(globals()[f'UC_ARM64_REG_Q{i}']) == value
    return {'expected_icl_ua': expected, 'calls': len(calls)}

cases = [{'expected': 2200000}, {'pd_type': 4, 'expected': 2200000},
         {'contract_ma': 2000, 'expected': 2000000},
         {'offered_ma': 1000, 'expected': 1000000},
         {'offered_ma': 5000, 'contract_ma': 5000, 'expected': 3000000},
         {'contract_ma': 49, 'expected': 1700000}]
for key, value in [('no_adapter', True), ('no_private', True), ('no_ports', True),
                   ('no_tcpc', True), ('nr_ports', 0), ('nr_ports', 9), ('port_index', -1),
                   ('port_index', 1), ('vbus', 8249), ('vbus', 9751), ('vbus_after', 5000),
                   ('pd_type', 5), ('pd_type', 0), ('pd_type_after', 5), ('done', 0),
                   ('done_after', 0), ('verifying', 1), ('verifying_after', 1),
                   ('usb_error', -19), ('cap_error', 4), ('contract_error', -13),
                   ('contract_mv', 5000), ('nr', 0), ('nr', 11), ('selected', 2),
                   ('selected', 255), ('selected', 0), ('cap_type', 3), ('cap_type', 1),
                   ('min_mv', 5000), ('max_mv', 12000), ('offered_ma', 0),
                   ('offered_ma', 5001), ('contract_ma', 5001), ('replace_adapter', True)]:
    cases.append({key: value, 'expected': 1700000})
for vbus in [8250, 9750]: cases.append({'vbus': vbus, 'expected': 2200000})
cases.append({'fallback': 1400000, 'done': 0, 'expected': 1400000})
results = [run(c, (i % 16) << 28) for i, c in enumerate(cases)]
rng = random.Random(6897)
for _ in range(600):
    offered, contract = rng.randrange(50, 5001), rng.randrange(50, 5001)
    case = {'offered_ma': offered, 'contract_ma': contract,
            'expected': min(offered, contract, 3000) // 50 * 50000}
    results.append(run(case, rng.randrange(16) << 28))
canary = run({'expected': 2200000}, tamper=True)
report = {'module_sha256': REPORT['output_sha256'], 'machine_code_cases': len(results),
          'all_passed': True, 'all_x0_x30_sp_nzcv_simd_fpcr_fpsr_preserved_except_w8': True,
          'shadow_call_stack_balanced': True, 'stack_canary_tamper': canary,
          'selected_pdo_and_explicit_contract_both_limit_icl': True,
          'pd_authentication_thermal_pumps_unmodified': True,
          'pac_instructions_preserved_but_hardware_pac_not_verified': True,
          'kernel_module_loader_boot_and_real_charging_verified': False}
(WORK / 'MACHINE-CODE-TESTS.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
