import hashlib
import os
import sys
import json
import mimetypes
import re
import pefile
import peutils

def calculate_md5(sample_name):
    hasher = hashlib.md5()
    with open(sample_name, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

def calculate_sha1(sample_name):
    hasher = hashlib.sha1()
    with open(sample_name, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

def calculate_sha256(sample_name):
    hasher = hashlib.sha256()
    with open(sample_name, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

def get_size(sample_name):
    file_stats = os.stat(sample_name)
    return file_stats.st_size

def get_filetype(sample_name):
    mime_type, _ = mimetypes.guess_type(sample_name)
    return mime_type

def extract_strings(filename):
    with open(filename, 'rb') as f:
        content = f.read()

    ascii_strings = re.findall(b'[ -~]{4,}', content)
    unicode_strings = re.findall(b'(?:[\x20-\x7E][\x00]){4,}', content)

    return [s.decode('ascii') for s in ascii_strings], [s.decode('utf-16') for s in unicode_strings]

def get_pe_info(sample_name):
    pe_info = {}
    try:
        pe = pefile.PE(sample_name)
        pe_info['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        pe_info['sections'] = []
        for section in pe.sections:
            pe_info['sections'].append({
                'name': section.Name.decode().strip(),
                'virtual_address': hex(section.VirtualAddress),
                'size_of_raw_data': section.SizeOfRawData
            })
    except (pefile.PEFormatError, FileNotFoundError) as e:
        pe_info['error'] = str(e)
    return pe_info

sample_path = sys.argv[1]
sample_name = sys.argv[2]
sample = os.path.join(sample_path, sample_name)

md5 = calculate_md5(sample)
sha1 = calculate_sha1(sample)
sha256 = calculate_sha256(sample)
size = get_size(sample)
filetype = get_filetype(sample)

ascii_strings, unicode_strings = extract_strings(sample)

pe_info = get_pe_info(sample)

data = {
    "meaningful_name": sample_name,
    "md5": md5,
    "sha1": sha1,
    "sha256": sha256,
    "size": size,
    "filetype": filetype,
    "ascii_strings": ascii_strings,
    "unicode_strings": unicode_strings,
    "pe_info": pe_info
}

json_filename = os.path.join(sample_path, 'core_summary-report.json')
with open(json_filename, 'w') as json_file:
    json.dump(data, json_file, indent=4)


