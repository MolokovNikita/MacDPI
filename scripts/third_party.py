import json, pathlib, subprocess, sys
root = pathlib.Path(__file__).resolve().parent.parent
output = root / 'build/MacDPI.app/Contents/Resources/Legal'
output.mkdir(parents=True, exist_ok=True)
raw = subprocess.check_output([sys.argv[1], 'list', '-m', '-json', 'all'], cwd=root / 'daemon', text=True)
decoder = json.JSONDecoder()
entries = []
while raw.strip():
    module, count = decoder.raw_decode(raw.lstrip())
    raw = raw.lstrip()[count:]
    if module.get('Main') or 'Dir' not in module:
        continue
    name = module['Path']
    entries.append(f"{name} {module.get('Version', '')}")
    directory = pathlib.Path(module['Dir'])
    for source in directory.iterdir():
        if source.is_file() and source.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE', 'COPYRIGHT')):
            target = output / name.replace('/', '_')
            target.mkdir(exist_ok=True)
            (target / source.name).write_bytes(source.read_bytes())
(output / 'DEPENDENCIES.txt').write_text('\n'.join(entries) + '\n')

# Protocol test patterns and their exact upstream provenance.
reference = root / 'reference/flowseal'
if reference.exists():
    target = output / 'Flowseal-patterns'
    target.mkdir(exist_ok=True)
    for name in ['SOURCE.json', 'ATTRIBUTION.txt']:
        source = reference / name
        if source.exists(): (target / name).write_bytes(source.read_bytes())
