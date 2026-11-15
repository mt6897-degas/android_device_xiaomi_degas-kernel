#!/usr/bin/env python3
"""Extend the exact factory ELF module without altering its existing ABI."""
from pathlib import Path
from io import BytesIO
import argparse, hashlib, json, struct, subprocess
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

WORK = Path(__file__).resolve().parent
ROOT = WORK.parents[1]
PINS = {
    'mtk_charger_framework.ko': 'da5a3a940f235597c63c034d890c722af5361b94ba179d0af4dd818212221df5',
    'mtk_pd_adapter.ko': '23a87931cfae7a60a6dd092595d3ef7e520a2bac860cdfe3626c7b5c542df6de',
    'tcpc_class.ko': '7ff3a82d0bed63f5837ab0a5dff90cf4c3b2fa94986f4d348d838a1a1f54e65e',
}
FLAGS = ['--target=aarch64-linux-gnu', '-O2', '-ffreestanding', '-fno-builtin',
         '-fno-strict-aliasing', '-mgeneral-regs-only', '-ffixed-x18',
         '-fsanitize=shadow-call-stack', '-mbranch-protection=pac-ret',
         '-fstack-protector-strong', '-mstack-protector-guard=sysreg',
         '-mstack-protector-guard-reg=sp_el0', '-mstack-protector-guard-offset=1592',
         '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-fno-addrsig',
         '-Wall', '-Wextra', '-Werror']

def sha(data):
    return hashlib.sha256(data).hexdigest()

def symbol_index(elf, name):
    matches = [(i, s) for i, s in enumerate(elf.get_section_by_name('.symtab').iter_symbols()) if s.name == name]
    assert len(matches) == 1, (name, len(matches))
    return matches[0]

def branch(source, destination, link=False):
    delta = destination - source
    assert delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27)
    return struct.pack('<I', (0x94000000 if link else 0x14000000) | ((delta // 4) & 0x3ffffff))

def extend(source_dir, output):
    modules = {}
    for name, digest in PINS.items():
        data = (source_dir / name).read_bytes()
        assert sha(data) == digest, f'Unsupported factory module: {name}'
        modules[name] = data
    original = modules['mtk_charger_framework.ko']
    assert not original.endswith(b'~Module signature appended~\n')
    elf = ELFFile(BytesIO(original))
    assert elf.elfclass == 64 and elf.little_endian
    assert elf['e_type'] == 'ET_REL' and elf['e_machine'] == 'EM_AARCH64'
    assert elf['e_phnum'] == 0 and elf['e_shentsize'] == 64
    sections = list(elf.iter_sections())
    indices = {s.name: i for i, s in enumerate(sections)}
    text_id = indices['.text']
    symtab = elf.get_section_by_name('.symtab')
    syms = list(symtab.iter_symbols())
    _, function = symbol_index(elf, 'do_algorithm')
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    function_text = sections[text_id].data()[function['st_value']:function['st_value'] + function['st_size']]
    hooks = [i for i in md.disasm(function_text, function['st_value'])
             if i.mnemonic == 'ldr' and i.op_str == 'w8, [x19, #0x1150]']
    assert len(hooks) == 1
    hook = hooks[0].address
    assert hook == 84532 and hook - function['st_value'] == 916
    text = bytearray(sections[text_id].data())
    assert text[hook:hook + 4] == bytes.fromhex('685251b9')
    following = list(md.disasm(text[hook + 4:hook + 20], hook + 4))
    assert following[0].mnemonic == 'b' and following[0].op_str == '#0x14a44'
    assert following[-1].mnemonic == 'ldr' and following[-1].op_str == 'w9, [x19, #0xcb4]'

    # Validate the native USB property IDs rather than assuming older source enums.
    _, table = symbol_index(elf, 'usb_sysfs_field_tbl')
    getters = {}
    for rel in elf.get_section_by_name('.rela.data').iter_relocations():
        offset = rel['r_offset'] - table['st_value']
        if 0 <= offset < 38 * 56 and offset % 56 == 48:
            s = syms[rel['r_info_sym']]
            getters[offset // 56] = s['st_value'] + rel['r_addend']
    for prop, name in [(3, 'pd_verifying_get'), (19, 'pd_verify_done_get')]:
        assert getters[prop] == symbol_index(elf, name)[1]['st_value']

    tcpc = ELFFile(BytesIO(modules['tcpc_class.ko']))
    _, contract = symbol_index(tcpc, 'tcpm_inquire_pd_contract')
    assert contract['st_shndx'] != 'SHN_UNDEF' and contract['st_size'] == 252
    _, crc_symbol = symbol_index(tcpc, '__crc_tcpm_inquire_pd_contract')
    crc_section = tcpc.get_section(crc_symbol['st_shndx'])
    crc = crc_section.data()[crc_symbol['st_value']:crc_symbol['st_value'] + 4]
    assert crc == bytes.fromhex('fbb62ab5')
    assert b'tcpc_class' in elf.get_section_by_name('.modinfo').data()
    assert not any(s.name == 'tcpm_inquire_pd_contract' for s in syms)

    subprocess.run(['clang', *FLAGS, '-c', str(WORK / 'pd_icl.c'), '-o', str(WORK / 'pd_icl.o')], check=True)
    subprocess.run(['clang', '--target=aarch64-linux-gnu', '-c', str(WORK / 'pd_icl_wrapper.S'),
                    '-o', str(WORK / 'pd_icl_wrapper.o')], check=True)
    fragments = []
    for name in ['pd_icl.o', 'pd_icl_wrapper.o']:
        fragment = ELFFile(BytesIO((WORK / name).read_bytes()))
        assert fragment['e_type'] == 'ET_REL' and fragment['e_machine'] == 'EM_AARCH64'
        assert not any(s['sh_size'] and s.name.startswith(('.rodata', '.data', '.bss')) for s in fragment.iter_sections())
        while len(text) % 4:
            text.append(0)
        start = len(text)
        text.extend(fragment.get_section_by_name('.text').data())
        fragments.append((fragment, start))
    helper_start, wrapper_start = [start for _, start in fragments]
    text[hook:hook + 4] = branch(hook, wrapper_start)

    strtab = bytearray(elf.get_section_by_name('.strtab').data())
    new_import_name = b'tcpm_inquire_pd_contract\0'
    new_name_offset = len(strtab)
    strtab.extend(new_import_name)
    new_import_index = len(syms)
    new_symbol = struct.pack('<IBBHQQ', new_name_offset, 0x10, 0, 0, 0, 0)
    text_symbols = [i for i, s in enumerate(syms) if s['st_info']['type'] == 'STT_SECTION' and s['st_shndx'] == text_id]
    assert len(text_symbols) == 1
    text_symbol = text_symbols[0]
    original_rela = elf.get_section_by_name('.rela.text').data()
    new_rela = bytearray(original_rela)
    imported = set()
    for fragment, start in fragments:
        fs = fragment.get_section_by_name('.symtab')
        for rel in fragment.get_section_by_name('.rela.text').iter_relocations():
            target = fs.get_symbol(rel['r_info_sym'])
            location = start + rel['r_offset']
            kind = rel['r_info_type']
            assert kind in (282, 283), (target.name, kind)
            if target.name in ('degas_pd_icl', 'degas_pd_icl_resume'):
                destination = helper_start if target.name == 'degas_pd_icl' else hook + 4
                text[location:location + 4] = branch(location, destination + rel['r_addend'], kind == 283)
            else:
                assert target['st_shndx'] == 'SHN_UNDEF'
                index = new_import_index if target.name == 'tcpm_inquire_pd_contract' else symbol_index(elf, target.name)[0]
                imported.add(target.name)
                new_rela.extend(struct.pack('<QQq', location, (index << 32) | kind, rel['r_addend']))
    assert imported == {'adapter_dev_get_property', 'usb_get_property', 'adapter_dev_get_cap',
                        'mutex_lock', 'mutex_unlock', 'tcpm_inquire_pd_contract', 'get_vbus', '__stack_chk_fail'}
    assert len(text) == 129016
    versions = elf.get_section_by_name('__versions').data()
    assert len(versions) % 64 == 0
    assert all(versions[i + 8:i + 64].split(b'\0')[0] != new_import_name[:-1] for i in range(0, len(versions), 64))
    version_entry = crc + bytes(4) + new_import_name.ljust(56, b'\0')
    replacements = {'.text': bytes(text), '.rela.text': bytes(new_rela),
                    '.strtab': bytes(strtab), '.symtab': symtab.data() + new_symbol,
                    '__versions': versions + version_entry}
    build_id = bytearray(elf.get_section_by_name('.note.gnu.build-id').data())
    assert len(build_id) == 36 and build_id[12:16] == b'GNU\0'
    build_id[16:36] = hashlib.sha1(bytes(text)).digest()
    replacements['.note.gnu.build-id'] = bytes(build_id)

    # Keep all section indices/symbol indices and all original bytes/relocations.
    # Rebuild the section file layout only; ET_REL has no program headers.
    result = bytearray(original[:64])
    new_headers = []
    for i, section in enumerate(sections):
        header = list(struct.unpack_from('<IIQQQQIIQQ', original, elf['e_shoff'] + 64 * i))
        if i == 0:
            new_headers.append(bytes(64))
            continue
        align = section['sh_addralign'] or 1
        result.extend(bytes((-len(result)) % align))
        data = replacements.get(section.name, section.data())
        header[4], header[5] = len(result), len(data)
        if section['sh_type'] != 'SHT_NOBITS':
            result.extend(data)
        new_headers.append(struct.pack('<IIQQQQIIQQ', *header))
    result.extend(bytes((-len(result)) % 8))
    struct.pack_into('<Q', result, 40, len(result))
    result.extend(b''.join(new_headers))
    patched = ELFFile(BytesIO(result))
    for old, new in zip(sections, patched.iter_sections()):
        assert old.name == new.name
        for field in ('sh_type', 'sh_flags', 'sh_link', 'sh_info', 'sh_entsize', 'sh_addralign', 'sh_addr'):
            assert old[field] == new[field], (old.name, field)
        assert new.data() == replacements.get(old.name, old.data()), old.name
    assert patched.get_section_by_name('.symtab').data()[:len(symtab.data())] == symtab.data()
    assert patched.get_section_by_name('.rela.text').data()[:len(original_rela)] == original_rela
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(result)
    report = {'source_pins': PINS, 'output_sha256': sha(result), 'output_bytes': len(result),
              'hook_text_offset': hook, 'hook_original_file_offset': sections[text_id]['sh_offset'] + hook,
              'helper_text_offset': helper_start, 'wrapper_text_offset': wrapper_start,
              'original_text_bytes': len(sections[text_id].data()),
              'changed_original_text_bytes': 4, 'added_text_bytes': len(text) - len(sections[text_id].data()),
              'changed_sections': sorted(replacements), 'new_import': 'tcpm_inquire_pd_contract',
              'new_import_crc_le': crc.hex(), 'module_signature_present': False,
              'existing_symbol_indices_and_records_preserved': True,
              'existing_relocations_preserved': True, 'existing_import_crcs_preserved': True,
              'existing_exports_modinfo_cfi_alternatives_preserved': True,
              'helper_compiler_flags': FLAGS, 'runtime_verified': False}
    (WORK / 'MODULE-VERIFICATION.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-dir', type=Path, default=(ROOT / 'modules/vendor_ramdisk' if (ROOT / 'modules/vendor_ramdisk').is_dir() else ROOT / 'device/xiaomi/degas-kernel/modules/vendor_ramdisk'))
    parser.add_argument('--output', type=Path, default=WORK / 'mtk_charger_framework.ko')
    args = parser.parse_args()
    extend(args.source_dir, args.output)
