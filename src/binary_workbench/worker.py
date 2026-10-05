"""Private worker entry point. This runs our parsers, never the submitted file."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from binary_workbench.safeio import MAX_INPUT, write_new
from binary_workbench.static import analyze


def signatures(data, source):
    from importlib.metadata import version
    import yara_x
    compiler = yara_x.Compiler()
    compiler.enable_includes(False)
    compiler.add_source(source)
    scanner = yara_x.Scanner(compiler.build())
    scanner.set_timeout(10)
    scanner.max_matches_per_pattern(100)
    matches = []
    truncated = False
    pattern_cap_reached = False
    for rule in scanner.scan(data).matching_rules:
        before=len(matches)
        for pattern in rule.patterns:
            pattern_count=0
            for match in pattern.matches:
                if len(matches) >= 10000:
                    truncated = True
                    break
                matches.append({'rule':rule.identifier, 'pattern':pattern.identifier,
                                'file_offset':match.offset, 'length':match.length})
                pattern_count+=1
            if pattern_count>=100:
                pattern_cap_reached=True
            if truncated:
                break
        if len(matches)==before and not truncated:
            matches.append({'rule':rule.identifier, 'pattern':None, 'file_offset':None, 'length':0})
        if truncated:
            break
    return {'status':'complete', 'engine':'yara-x', 'version':version('yara-x'),
            'matches':matches, 'truncated':truncated or pattern_cap_reached, 'pattern_match_cap':100,
            'pattern_cap_reached':pattern_cap_reached}


def main():
    mode, input_path, output_path = sys.argv[1:4]
    with Path(input_path).open('rb') as stream:
        data = stream.read(MAX_INPUT+1)
    if len(data)>MAX_INPUT:
        raise ValueError('input_limit')
    if mode == 'static':
        result = analyze(data)
    elif mode == 'signatures':
        try:
            source = Path(sys.argv[4]).read_text(encoding='utf-8')
            if len(source.encode('utf-8'))>4*1024**2:
                raise ValueError('rule_limit')
            result = signatures(data,source)
            import hashlib
            result['sha256']=hashlib.sha256(data).hexdigest()
        except ImportError:
            result = {'status':'unavailable','reason':'engine_not_installed','matches':[]}
        except Exception as error:
            result = {'status':'failed','reason':type(error).__name__,'matches':[]}
    else:
        raise ValueError('unknown_mode')
    write_new(output_path,json.dumps(result,ensure_ascii=True,allow_nan=False),32*1024**2)


if __name__ == '__main__':
    main()
