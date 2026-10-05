"""Inspect installed verified parser/signature APIs without opening samples."""
import inspect
import yara_x
from pathlib import Path

for cls in (yara_x.Compiler, yara_x.Scanner):
    print(cls.__name__, [n for n in dir(cls) if not n.startswith('_')])
print(yara_x.compile.__doc__)
print(yara_x.Scanner.scan.__doc__)
rules = yara_x.compile('rule benign { strings: $marker = "BENIGN" condition: $marker }')
scanner = yara_x.Scanner(rules)
result = scanner.scan(b'xxBENIGNyy')
for rule in result.matching_rules:
    print(rule.identifier, [(p.identifier, [(m.offset,m.length) for m in p.matches]) for p in rule.patterns])
