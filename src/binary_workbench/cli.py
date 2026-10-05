"""CLI: sample text is always JSON-escaped before entering a terminal."""
import argparse
import json
import sys
from pathlib import Path
from .backend import read_json
from .core import analyze_file
from .reports import export, validate_report, JSON_CAP
from .safeio import new_run

EXIT={'complete':0,'partial':2,'unsupported':3,'failed':4,'unavailable':5,'timeout':6,'output_limit':6}


def emit(value):
    print(json.dumps(value,ensure_ascii=True,allow_nan=False,indent=2))


def main(argv=None):
    parser=argparse.ArgumentParser(description='Offline PE/ELF evidence workbench. Never executes submitted samples.')
    sub=parser.add_subparsers(dest='command',required=True)
    analyze=sub.add_parser('analyze',help='Analyze an authorized file into a new private local run')
    analyze.add_argument('file');analyze.add_argument('--runtime-root')
    analyze.add_argument('--tools-config',help='Trusted JSON with absolute ghidra and java paths')
    analyze.add_argument('--select',default='',help='Comma-separated function names or a hexadecimal address')
    analyze.add_argument('--static-only',action='store_true');analyze.add_argument('--rules',help='Explicit local UTF-8 YARA rules; includes disabled')
    analyze.add_argument('--timeout',type=int,default=180)
    for name in ('functions','inspect','export'):
        child=sub.add_parser(name);child.add_argument('report',help='Existing version 1.0.0 JSON report')
        if name=='inspect':child.add_argument('selection',help='Function name or address within a function')
        if name=='export':child.add_argument('--runtime-root')
    doctor=sub.add_parser('doctor');doctor.add_argument('--tools-config')
    args=parser.parse_args(argv)
    try:
        if args.command=='doctor':
            from importlib.metadata import version,PackageNotFoundError
            result={'host':sys.platform,'python':sys.version.split()[0],'packages':{},'backend':'not_configured'}
            result['controls']={'process_memory':'Mandatory suspended-start Job Object setup at each analysis; this inventory does not probe it.',
                'disk':'256 MiB sampled worker budget; overshoot possible.',
                'network':'No network feature; use an offline VM/firewall for enforced isolation.',
                'runtime':'Private local storage outside OneDrive; other sync products require user review.'}
            for package in ('pefile','pyelftools','yara-x'):
                try:result['packages'][package]=version(package)
                except PackageNotFoundError:result['packages'][package]='not_installed'
            if args.tools_config:
                config=read_json(args.tools_config,64*1024)
                result['backend']='configured_paths_exist' if all(Path(config[k]).is_file() if k=='java' else Path(config[k]).is_dir() for k in ('java','ghidra')) else 'missing_paths'
            emit(result);return 0
        if args.command=='analyze':
            if not 1<=args.timeout<=180 or len(args.select)>4096 or '\x00' in args.select:
                raise ValueError('Timeout must be 1..180 seconds; selection must be bounded text')
            config=read_json(args.tools_config,64*1024) if args.tools_config else None
            report,run=analyze_file(args.file,runtime_root=args.runtime_root,config=config,selection=args.select,
                static_only=args.static_only,rules=args.rules,timeout=args.timeout)
            emit({'status':report['status'],'sha256':report['sample']['sha256'],
                  'reverse_engineering':report['reverse_engineering']['status'],
                  'signature_check':report['signatures']['status'],'findings':len(report['findings']),
                  'report_json':str(run/'report.json'),'report_html':str(run/'report.html')})
            return EXIT[report['status']]
        report=validate_report(read_json(args.report,JSON_CAP))
        backend=report['reverse_engineering']
        if args.command=='functions':
            emit({'status':backend['status'],'functions':backend.get('functions',[])})
            return 0 if backend.get('functions') else 5
        if args.command=='inspect':
            if args.selection.startswith('0x'):
                address=int(args.selection,16)
                selected=[d for d in backend.get('details',[]) if any(
                    i['address']['space']=='ram' and int(i['address']['value'],16)<=address<
                    int(i['address']['value'],16)+len(i['bytes'])//2 for i in d['instructions'])]
            else:
                selected=[d for d in backend.get('details',[]) if d['name']==args.selection]
            if not selected:
                emit({'status':'unavailable','reason':'Function details absent; re-analyze with --select NAME or ADDRESS.'});return 5
            emit(selected);return 0
        if args.command=='export':
            run=new_run(args.runtime_root);export(report,run);emit({'directory':str(run)});return 0
    except (OSError,ValueError,KeyError,TypeError,RuntimeError) as error:
        # Never echo parser exception strings or original input/private rules paths.
        emit({'status':'failed','error_type':type(error).__name__,
              'guidance':'Check local regular-file paths, size limits, private runtime permissions, report version and trusted tool configuration.'})
        return 4


if __name__ == '__main__':
    raise SystemExit(main())
