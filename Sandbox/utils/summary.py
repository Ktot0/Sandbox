import hashlib
import os
import sys
import json
import mimetypes
import re
import pefile
import zlib
import math

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

def get_crc32(sample_name):
    with open(sample_name, 'rb') as f:
        file_data = f.read()
        return format(zlib.crc32(file_data) & 0xFFFFFFFF, '08X')

def get_pdb_path(sample_name):
    try:
        pe = pefile.PE(sample_name)
        for dir_entry in pe.DIRECTORY_ENTRY_DEBUG:
            if dir_entry.entry.SymType == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                pdb_info = dir_entry.entry.PDBFileName
                return pdb_info.decode() if pdb_info else 'No PDB path found'
    except Exception as e:
        return f'Error: {e}'
    return 'No PDB path found'

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

def calculate_entropy(data):
    """Calculate the entropy of a byte string."""
    if not data:
        return 0
    frequency = {}
    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1
    entropy = 0
    total_bytes = len(data)
    for count in frequency.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)
    return entropy

def get_pe_info(sample_name):
    """Extract information from a PE file, including section entropy, resources, and imports."""
    pe_info = {}
    try:
        pe = pefile.PE(sample_name)
        
        # Entry Point
        pe_info['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        
        # Sections and their entropy
        pe_info['sections'] = []
        for section in pe.sections:
            section_data = pe.get_data(section.PointerToRawData, section.SizeOfRawData)
            pe_info['sections'].append({
                'name': section.Name.decode().strip(),
                'virtual_address': hex(section.VirtualAddress),
                'size_of_raw_data': section.SizeOfRawData,
                'entropy': calculate_entropy(section_data)
            })
        
        # Resources
        pe_info['resources'] = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            def extract_resource_data(resource_entry):
                """Extract data from a resource entry."""
                try:
                    offset = resource_entry.data.struct.OffsetToData
                    size = resource_entry.data.struct.Size
                    return pe.get_data(offset, size)
                except Exception as e:
                    return None

            def process_resource_directory(directory):
                """Recursively process a resource directory."""
                resources = []
                for entry in directory.entries:
                    if hasattr(entry, 'directory'):
                        for subentry in entry.directory.entries:
                            resources.extend(process_resource_directory(subentry.directory))
                    else:
                        resource_data = extract_resource_data(entry)
                        if resource_data:
                            resources.append({
                                'type': entry.name.decode() if entry.name else 'Unknown',
                                'id': entry.id,
                                'language': entry.id,
                                'entropy': calculate_entropy(resource_data)
                            })
                return resources
            
            resources = process_resource_directory(pe.DIRECTORY_ENTRY_RESOURCE)
            pe_info['resources'] = resources
        
        # Imports
        pe_info['imports'] = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imports = []
                for imp in entry.imports:
                    imports.append({
                        'name': imp.name.decode() if imp.name else None,
                        'address': hex(imp.address)
                    })
                pe_info['imports'].append({
                    'dll': entry.dll.decode(),
                    'imports': imports
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
crc32 = get_crc32(sample)
pdb_path = get_pdb_path(sample)
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
    "pe_info": pe_info,
    "crc32": crc32,
    "pdb_path": pdb_path
}

json_filename = os.path.join(sample_path, 'core_summary-report.json')
with open(json_filename, 'w') as json_file:
    json.dump(data, json_file, indent=4)


