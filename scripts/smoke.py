"""Exercise the built proxy without modifying any macOS network settings."""
import pathlib, select, subprocess
root = pathlib.Path(__file__).resolve().parent.parent
binary = root / 'build/MacDPI.app/Contents/Resources/macdpi-daemon'
for mode in ['system', 'doh']:
    process = subprocess.Popen([str(binary), '--listen', '127.0.0.1:0', '--dns', mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready, _, _ = select.select([process.stdout], [], [], 5)
        if not ready:
            raise RuntimeError('daemon readiness timeout')
        line = process.stdout.readline().strip()
        if not line.startswith('READY '):
            raise RuntimeError(line)
        address = line.split()[1]
        result = subprocess.run(['/usr/bin/curl', '--silent', '--show-error', '--noproxy', '', '--proxy', 'http://' + address, '--max-time', '20', '--output', '/dev/null', '--write-out', '%{http_code} %{ssl_verify_result}', 'https://example.com/'], capture_output=True, text=True)
        if result.returncode != 0 or result.stdout != '200 0':
            raise RuntimeError(f'{mode}: {result.stdout} {result.stderr}')
        print(f'{mode}: HTTPS 200, certificate verified')
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
