"""Add the profile's signing identity to the explicitly requested capabilities."""
import pathlib, plistlib, subprocess, sys
profile_path, requested_path, output_path = sys.argv[1:]
profile = plistlib.loads(subprocess.check_output(['/usr/bin/security','cms','-D','-i',profile_path]))
allowed = profile['Entitlements']
requested = plistlib.loads(pathlib.Path(requested_path).read_bytes())
for key, value in requested.items():
    granted = allowed.get(key)
    if isinstance(value,list):
        if not isinstance(granted,list) or not all(v in granted for v in value):
            raise SystemExit(f'Provisioning profile does not permit {key}: {value}')
    elif value != granted:
        raise SystemExit(f'Provisioning profile does not permit {key}')
for key in ['com.apple.application-identifier','application-identifier','com.apple.developer.team-identifier']:
    if key in allowed:
        requested[key] = allowed[key]
pathlib.Path(output_path).write_bytes(plistlib.dumps(requested))
