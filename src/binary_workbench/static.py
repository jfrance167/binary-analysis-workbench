"""Specialist parser adapters and bounded static evidence normalization."""
import hashlib
import ipaddress
import math
import re
import struct
from collections import Counter
from bisect import bisect_right
from importlib.metadata import version
from io import BytesIO

CAP = 50000


def entropy(data):
    if not data:
        return None
    value=-sum((count/len(data))*math.log2(count/len(data)) for count in Counter(data).values())
    return min(8.0,max(0.0,value))  # Clamp floating-point rounding to Shannon's byte bounds.


def text(value):
    return value.decode('utf-8', 'replace') if isinstance(value, bytes) else str(value)


def location(offset, length=0):
    return {'file_offset': offset, 'length': length}


def mapped_offset(regions, address, size):
    """Map only a unique, valid file-backed VA. Overlap and zero-fill are unknown."""
    matches = []
    for region in regions:
        delta = address - region['va']
        if 0 <= delta < region['file_size'] and region['valid']:
            offset = region['offset'] + delta
            if 0 <= offset < size:
                matches.append(offset)
    return matches[0] if len(matches) == 1 else None


class AddressMap:
    """Precompute unique file-backed spans so controller joins stay O(log n)."""
    def __init__(self,regions,size):
        events={}
        for index,region in enumerate(regions):
            if not region['valid'] or region['file_size']<=0:
                continue
            start,end=region['va'],region['va']+region['file_size']
            events.setdefault(start,[]).append((index,True))
            events.setdefault(end,[]).append((index,False))
        active=set();previous=None;self.spans=[];self.size=size
        for address,changes in sorted(events.items()):
            if previous is not None and previous<address and len(active)==1:
                row=regions[next(iter(active))]
                self.spans.append((previous,address,row['offset']-row['va']))
            for index,added in changes:
                if added:active.add(index)
                else:active.discard(index)
            previous=address
        self.starts=[row[0] for row in self.spans]

    def offset(self,address):
        index=bisect_right(self.starts,address)-1
        if index>=0:
            start,end,delta=self.spans[index]
            offset=address+delta
            if start<=address<end and 0<=offset<self.size:
                return offset
        return None


def extract_strings(data):
    """Printable runs at either alignment; intended boundaries remain unknown.

    ASCII-subset wide runs need no terminator. Additional printable BMP Unicode
    wide runs require a NUL terminator to reduce random-binary false positives.
    Surrogate pairs are not decoded by this bounded lexical extractor.
    """
    strings, retained = [], 0
    truncated = False
    patterns = [('ascii', rb'[\x20-\x7e]{4,}'), ('utf-16le', rb'(?:[\x20-\x7e]\x00){4,}')]
    for encoding, pattern in patterns:
        for match in re.finditer(pattern, data):
            if len(strings) >= 20000 or retained >= 8*1024**2:
                truncated = True
                break
            maximum = 4096 * (2 if encoding == 'utf-16le' else 1)
            maximum=min(maximum,8*1024**2-retained)
            if encoding=='utf-16le':maximum-=maximum%2
            if maximum < (8 if encoding=='utf-16le' else 4):
                truncated=True;break
            raw = match.group()[:maximum]
            value = raw.decode(encoding)
            retained += len(raw)
            strings.append({'id': f'string:{encoding}:{match.start():x}', 'text':value,
                            'encoding':encoding, **location(match.start(),len(raw)),
                            'truncated':len(match.group()) > maximum})
    seen={item['id'] for item in strings}
    wide_unicode=re.compile(r'[^\x00-\x1f\x7f-\x9f\ud800-\udfff\ufffd]{4,}')
    for alignment in (0,1):
        if len(strings)>=20000 or retained>=8*1024**2:
            truncated=True;break
        end=len(data)-(len(data)-alignment)%2
        decoded=data[alignment:end].decode('utf-16le',errors='surrogatepass')
        cursor,byte_cursor=0,alignment
        for match in wide_unicode.finditer(decoded):
            if len(strings)>=20000 or retained>=8*1024**2:
                truncated=True;break
            # Consume each gap once. UTF-16 surrogate pairs change character
            # indices, so offsets cannot be inferred as decoded_index * 2.
            byte_cursor+=len(decoded[cursor:match.start()].encode('utf-16le',errors='surrogatepass'))
            value=match.group()
            raw=value.encode('utf-16le',errors='surrogatepass')
            offset=byte_cursor
            byte_cursor+=len(raw);cursor=match.end()
            identity=f'string:utf-16le:{offset:x}'
            terminated=match.end()<len(decoded) and decoded[match.end()]=='\0'
            if identity in seen or not terminated or not all(ord(c)<=0xffff and c.isprintable() for c in value):
                continue
            maximum=min(8192,8*1024**2-retained);maximum-=maximum%2
            if maximum<8:
                truncated=True;break
            kept=raw[:maximum];retained+=len(kept)
            strings.append({'id':identity,'text':kept.decode('utf-16le'),'encoding':'utf-16le',
                            **location(offset,len(kept)),'truncated':len(raw)>8192})
            seen.add(identity)
    return sorted(strings,key=lambda x:(x['file_offset'],x['encoding'])), truncated


def extract_indicators(strings):
    indicators = []
    pattern = re.compile(r'https?://[^\s<>"\x27]+|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}|(?:\d{1,3}\.){3}\d{1,3}|\[?[0-9a-fA-F]*:[0-9a-fA-F:]+\]?')
    for string in strings:
        for match in pattern.finditer(string['text']):
            candidate = match.group().rstrip('.,;)')
            kind = 'url' if candidate.startswith(('http://','https://')) else 'domain'
            if kind != 'url' and (re.fullmatch(r'[\d.]+', candidate) or ':' in candidate):
                try:
                    ipaddress.ip_address(candidate.strip('[]'))
                    kind = 'ip'
                except ValueError:
                    continue
            indicators.append({'id':f"indicator:{string['id']}:{match.start()}", 'kind':kind,
                               'value':candidate,'source_id':string['id'],
                               **location(string['file_offset']+match.start()*(2 if string['encoding']=='utf-16le' else 1),
                                          len(candidate)*(2 if string['encoding']=='utf-16le' else 1))})
            if len(indicators) >= CAP:
                return indicators, True
    return indicators, False


def analyze(data):
    result = {'sha256':hashlib.sha256(data).hexdigest(), 'size':len(data), 'format':'unknown',
              'status':'unsupported', 'warnings':[], 'sections':[], 'segments':[], 'regions':[],
              'imports':[], 'exports':[], 'symbols':[], 'dependencies':[], 'resources':[],
              'certificates':[], 'overlay':None, 'file_entropy':entropy(data), 'headers':{}}
    strings, truncated = extract_strings(data)
    result['strings'], result['strings_truncated'] = strings, truncated
    result['indicators'], result['indicators_truncated'] = extract_indicators(strings)
    try:
        if data.startswith(b'MZ'):
            parse_pe(data,result)
        elif data.startswith(b'\x7fELF'):
            parse_elf(data,result)
        else:
            result['warnings'].append('unsupported_format')
    except Exception as error:
        # Parser-specific strings may contain private paths or evidence; expose only type.
        result['status'] = 'partial'
        result['warnings'].append('parser_failure:' + type(error).__name__)
    return result


def region(data, name, offset, file_size, va, memory_size, permissions):
    valid = (0 <= offset <= len(data) and 0 <= file_size <= len(data)-offset and
             0<=va<2**64 and va+max(file_size,memory_size)<=2**64)
    return {'name':name, 'offset':offset,'file_size':file_size,'va':va,'memory_size':memory_size,
            'permissions':permissions,'valid':valid,
            'entropy':entropy(data[offset:offset+file_size]) if valid else None}


def parse_pe(data,out):
    import pefile
    out['format'], out['parser'] = 'PE', {'name':'pefile','version':version('pefile')}
    pe = pefile.PE(data=data,fast_load=True)
    try:
        machine = pe.FILE_HEADER.Machine
        bits = 64 if pe.OPTIONAL_HEADER.Magic == 0x20b else 32
        base = pe.OPTIONAL_HEADER.ImageBase
        out.update(architecture={0x14c:'x86',0x8664:'x64'}.get(machine,'unsupported'), bitness=bits,
                   endianness='little', image_base=hex(base), entry_rva=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                   entry_va=hex(base+pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        if base+pe.OPTIONAL_HEADER.AddressOfEntryPoint>=2**bits:
            out['warnings'].append('entry_address_outside_declared_width')
        out['headers'] = {k:getattr(pe.FILE_HEADER,k) for k in ('Machine','NumberOfSections','TimeDateStamp','Characteristics')}
        for section in pe.sections[:CAP]:
            flags = section.Characteristics
            permissions = ''.join(c for mask,c in ((0x40000000,'r'),(0x80000000,'w'),(0x20000000,'x')) if flags & mask)
            row = region(data,text(section.Name.rstrip(b'\0')),section.PointerToRawData,section.SizeOfRawData,
                         base+section.VirtualAddress,section.Misc_VirtualSize,permissions)
            row['rva'], row['id'] = hex(section.VirtualAddress),f'section:{len(out["sections"])}'
            if row['va']+max(row['memory_size'],row['file_size'])>2**bits:
                row['valid']=False;out['warnings'].append('section_address_outside_declared_width')
            out['sections'].append(row)
            out['regions'].append(row)
        out['regions'].append(region(data,'headers',0,min(pe.OPTIONAL_HEADER.SizeOfHeaders,len(data)),base,
                                     pe.OPTIONAL_HEADER.SizeOfHeaders,'r'))
        pe.parse_data_directories(directories=[0,1,2,13,14])
        out['managed'] = bool(len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>14 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress)
        for key in ('DIRECTORY_ENTRY_IMPORT','DIRECTORY_ENTRY_DELAY_IMPORT'):
            for dll in getattr(pe,key,[])[:CAP]:
                out['dependencies'].append(text(dll.dll))
                for entry in dll.imports[:CAP-len(out['imports'])]:
                    out['imports'].append({'id':f'import:{len(out["imports"])}','library':text(dll.dll),
                        'name':text(entry.name) if entry.name else f'ordinal:{entry.ordinal}',
                        'va':hex(entry.address),'delayed':key.endswith('DELAY_IMPORT'),
                        'file_offset':mapped_offset(out['regions'],entry.address,len(data))})
        for entry in getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[])[:CAP]:
            out['exports'].append({'name':text(entry.name) if entry.name else f'ordinal:{entry.ordinal}',
                                   'rva':hex(entry.address),'va':hex(base+entry.address),
                                   'forwarder':text(entry.forwarder) if entry.forwarder else None})
        def resources(directory, parents, visited):
            if len(parents)>8 or id(directory) in visited:
                out['warnings'].append('resource_recursion_limit')
                return
            visited.add(id(directory))
            for entry in directory.entries[:CAP-len(out['resources'])]:
                names = parents+[text(entry.name) if entry.name else str(entry.id)]
                if hasattr(entry,'directory'):
                    resources(entry.directory,names,visited)
                elif hasattr(entry,'data'):
                    item = entry.data.struct
                    offset = mapped_offset(out['regions'],base+item.OffsetToData,len(data))
                    out['resources'].append({'id':f'resource:{len(out["resources"])}','path':names,
                        'rva':hex(item.OffsetToData),'size':item.Size,'file_offset':offset,
                        'valid':offset is not None and item.Size<=len(data)-offset})
        if hasattr(pe,'DIRECTORY_ENTRY_RESOURCE'):
            resources(pe.DIRECTORY_ENTRY_RESOURCE,[],set())
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>4:
            certificate = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if certificate.Size:
                out['certificates'].append({'file_offset':certificate.VirtualAddress,'size':certificate.Size,
                    'valid':0<=certificate.VirtualAddress<=len(data) and certificate.Size<=len(data)-certificate.VirtualAddress,
                    'verification':'not_performed'})
        end = max((s['offset']+s['file_size'] for s in out['sections'] if s['valid']),default=0)
        end = max(end,min(pe.OPTIONAL_HEADER.SizeOfHeaders,len(data)))
        if end<len(data):
            out['overlay'] = {'file_offset':end,'size':len(data)-end,'interpretation':'trailing_data_including_validated_certificate_ranges'}
        parse_coff_symbols(data, pe, out)
        out['warnings'].extend(pe.get_warnings()[:100])
        out['status'] = 'complete' if out['architecture']!='unsupported' else 'unsupported'
        expected_header_end=pe.DOS_HEADER.e_lfanew+24+pe.FILE_HEADER.SizeOfOptionalHeader+40*pe.FILE_HEADER.NumberOfSections
        if expected_header_end>len(data) or pe.OPTIONAL_HEADER.SizeOfHeaders>len(data) or len(pe.sections)!=pe.FILE_HEADER.NumberOfSections:
            out['warnings'].append('truncated_headers_or_section_table')
        if any(not s['valid'] for s in out['sections']) or out['warnings']:
            out['status']='partial'
    finally:
        pe.close()


def parse_coff_symbols(data, pe, out):
    """Normalize bounded fixed-size COFF records; complex PE parsing stays in pefile.

    COFF auxiliary records are skipped, not interpreted. Long names are accepted only
    inside the validated string table. Malformed tables remain explicitly partial.
    """
    offset, count = pe.FILE_HEADER.PointerToSymbolTable, pe.FILE_HEADER.NumberOfSymbols
    table = {'file_offset':offset, 'count':count, 'status':'absent'}
    out['symbol_table'] = table
    if not count:
        return
    if offset <= 0 or count > CAP or offset + count*18 + 4 > len(data):
        table['status']='invalid_or_limit'; out['warnings'].append('coff_symbols_unavailable'); return
    end = offset + count*18
    size = struct.unpack_from('<I', data, end)[0]
    if size < 4 or end+size > len(data):
        table['status']='invalid'; out['warnings'].append('coff_string_table_invalid'); return
    index = 0
    while index < count:
        position = offset + index*18
        raw, value, section, symbol_type, storage, auxiliary = struct.unpack_from('<8sIhHBB',data,position)
        if raw[:4] == b'\0'*4:
            string_offset = int.from_bytes(raw[4:],'little')
            if not 4 <= string_offset < size:
                table['status']='partial'; out['warnings'].append('coff_symbol_name_invalid'); return
            stop = data.find(b'\0',end+string_offset,min(end+size,end+string_offset+4097))
            if stop < 0:
                table['status']='partial'; out['warnings'].append('coff_symbol_name_unterminated'); return
            name = text(data[end+string_offset:stop])
        else:
            name = text(raw.rstrip(b'\0'))
        va = None
        if 1 <= section <= len(pe.sections):
            va = pe.OPTIONAL_HEADER.ImageBase + pe.sections[section-1].VirtualAddress + value
        out['symbols'].append({'name':name,'va':hex(va) if va is not None else None,
            'section_number':section,'value':hex(value),'type':symbol_type,'storage_class':storage,
            'source':'COFF','file_offset':position,'auxiliary_count':auxiliary})
        if index+auxiliary >= count:
            table['status']='partial';out['warnings'].append('coff_auxiliary_count_invalid');return
        index += 1+auxiliary
    table['status']='complete'


def parse_elf(data,out):
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    out['format'],out['parser']='ELF',{'name':'pyelftools','version':version('pyelftools')}
    elf = ELFFile(BytesIO(data))
    machine, type_name = elf.header['e_machine'], elf.header['e_type']
    out.update(architecture={'EM_386':'x86','EM_X86_64':'x64'}.get(machine,'unsupported'),
               bitness=elf.elfclass, endianness='little' if elf.little_endian else 'big',
               entry_va=hex(elf.header['e_entry']), managed=False)
    out['headers']={k:elf.header[k] for k in ('e_machine','e_type','e_entry','e_phnum','e_shnum')}
    for index,segment in enumerate(elf.iter_segments()):
        if index>=CAP:
            out['warnings'].append('segments_truncated');break
        flags=segment['p_flags']
        permissions=''.join(c for mask,c in ((4,'r'),(2,'w'),(1,'x')) if flags&mask)
        row=region(data,segment['p_type'],segment['p_offset'],segment['p_filesz'],segment['p_vaddr'],segment['p_memsz'],permissions)
        row['id']=f'segment:{index}'
        out['segments'].append(row)
        if segment['p_type']=='PT_LOAD':out['regions'].append(row)
        if hasattr(segment,'iter_tags'):
            for index,tag in enumerate(segment.iter_tags()):
                if index>=CAP:break
                if tag.entry.d_tag=='DT_NEEDED':out['dependencies'].append(tag.needed)
    for index,section in enumerate(elf.iter_sections()):
        if index>=CAP:out['warnings'].append('sections_truncated');break
        flags=section['sh_flags']
        permissions='r'+('w' if flags&1 else '')+('x' if flags&4 else '')
        raw_size=0 if section['sh_type']=='SHT_NOBITS' else section['sh_size']
        row=region(data,section.name,section['sh_offset'],raw_size,section['sh_addr'],section['sh_size'],permissions)
        row.update(id=f'section:{index}', type=section['sh_type'])
        out['sections'].append(row)
        if isinstance(section,SymbolTableSection):
            for symbol in section.iter_symbols():
                if len(out['symbols'])>=CAP:out['warnings'].append('symbols_truncated');break
                if not symbol.name:continue
                item={'name':symbol.name,'va':hex(symbol['st_value']),'size':symbol['st_size'],
                      'type':symbol['st_info']['type'],'binding':symbol['st_info']['bind'],
                      'defined':symbol['st_shndx']!='SHN_UNDEF','source':section.name}
                out['symbols'].append(item)
                if not item['defined']:out['imports'].append(dict(item,id=f'import:{len(out["imports"])}',library=None))
                elif item['binding'] in ('STB_GLOBAL','STB_WEAK'):out['exports'].append(item)
    for row in out['segments']+out['sections']:
        if row['va']+max(row['memory_size'],row['file_size'])>2**elf.elfclass:
            row['valid']=False;out['warnings'].append('address_outside_declared_width')
    out['status']='complete' if out['architecture']!='unsupported' and elf.little_endian and type_name in ('ET_EXEC','ET_DYN') else 'unsupported'
    if any(not row['valid'] for row in out['segments']+out['sections']):out['status']='partial'
