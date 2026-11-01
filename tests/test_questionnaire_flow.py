"""Exercise the production questionnaire, bootstrap and checkpoints in a PTY.

Only absolute deployment paths, host probes and VPN phase executables are
substituted. Actual reads, input validation, manifests, target persistence,
bootstrap publication and phase checkpoint code run unchanged. No host service,
package, certificate, firewall or network is modified by these fixtures.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SSH_CONNECTION = '198.51.100.4 45000 8.8.4.4 2222'

# Run the PTY parent as root as well: it must inspect the root0700 state that
# the real bootstrap publishes, and remove only its private fixture afterwards.
RUNNER = r"""
import codecs, errno, hashlib, json, os, pathlib, pty, re, select, shlex, shutil
import signal, subprocess, sys, termios, time

settings = json.loads(sys.argv[1])
root = pathlib.Path(settings['root']).resolve()
assert root.parent == pathlib.Path('/tmp') and root.name.startswith('vpn-questionnaire-flow.')
source = root / 'source'
installed = root / 'installed'
state = root / 'state'
target = root / 'target.env'
events = root / 'events'
real_python = sys.executable
keys = ('TARGET_ADDRESS_MODE', 'TARGET_IPV4', 'TARGET_FQDN', 'TARGET_INTERFACE',
        'TARGET_SSH_PORT', 'TARGET_DEVICE_LIMIT', 'TARGET_REALITY_SNI', 'TARGET_LABEL', 'ACME_EMAIL')

def event(value):
    with events.open('a', encoding='utf-8') as output:
        output.write(value + '\n')

def executable(path, text):
    path.write_text(text, encoding='utf-8')
    path.chmod(0o700)

def prepare():
    shutil.copytree(settings['production'], source,
                    ignore=shutil.ignore_patterns('.git', '__pycache__'))
    replacements = {
        '/var/lib/vpn-installer': str(state),
        '/opt/vpn-installer': str(installed),
        '/etc/germanyvpn-target.env': str(target),
        '/run/vpn-installer.lock': str(root / 'installer.lock'),
        '/run/vpn-installer.': str(root / 'task.'),
        '/etc/os-release': str(root / 'os-release'),
        '/etc/krysyuk-standalone/access.env': str(root / 'access.env'),
        '/etc/germanyvpn-xhttp-test/promotion.json': str(root / 'promotion.json'),
    }
    entrypoint = source / 'install.sh'
    text = entrypoint.read_text(encoding='utf-8')
    for old, new in replacements.items():
        assert old in text, old
        text = text.replace(old, new)
    entrypoint.write_text(text, encoding='utf-8')
    (root / 'os-release').write_text('ID=ubuntu\nVERSION_ID=24.04\n')
    (root / 'access.env').write_text('FIXTURE_ACCESS_ONLY=1\n')
    binary = root / 'bin'
    binary.mkdir()
    shell = '#!/bin/bash\nset -Eeuo pipefail\n'
    executable(binary / 'dpkg', shell + 'printf "amd64\\n"\n')
    executable(binary / 'ps', shell + 'printf "systemd\\n"\n')
    executable(binary / 'ip', shell + '''
if [[ $* == '-4 route get 1.1.1.1' ]]; then
  printf '1.1.1.1 via 8.8.4.1 dev enp1s0 src 8.8.4.4\\n'
elif [[ $* == '-o -4 address show' ]]; then
  printf '2: enp1s0 inet 8.8.4.4/24 brd 8.8.4.255 scope global enp1s0\\n'
else exit 92; fi
''')
    executable(binary / 'curl', shell + 'printf "NETWORK\\n" >>"$FIXTURE_ROOT/events"\nexit 93\n')
    # The actual SNI CLI validates input and checks a bounded external TLS
    # probe. Only OpenSSL's network interaction is replaced by this fixture.
    executable(binary / 'openssl', shell + '''
printf 'SNI_TLS:%s\\n' "$TARGET_REALITY_SNI" >>"$FIXTURE_ROOT/events"
[[ $1 == s_client && " $* " == *' -tls1_3 '* && " $* " == *' -verify_return_error '* &&
   " $* " == *" -servername $TARGET_REALITY_SNI "* &&
   " $* " == *" -verify_hostname $TARGET_REALITY_SNI "* && " $* " == *' -alpn h2 '* ]] || exit 95
case ",$FIXTURE_TLS_FAIL_SNIS," in
  *",$TARGET_REALITY_SNI,"*) printf 'fixture TLS probe rejected\\n' >&2; exit 1;;
esac
printf 'Protocol : TLSv1.3\\nALPN protocol: h2\\nVerification: OK\\n'
''')
    # All validation invocations use the actual production CLI. The full
    # inventory's unrelated external host/network checks remain stubbed.
    executable(binary / 'python3', shell + '''
arguments=("$@")
while [[ ${1:-} == -B || ${1:-} == -I ]]; do shift; done
if [[ ${1:-} == */tools/preflight.py ]]; then
  script=$1; shift
  if [[ ${1:-} == --inputs-only ]]; then
    printf 'INPUT_VALIDATION\\n' >>"$FIXTURE_ROOT/events"
  elif [[ ${1:-} == --check-reality-sni ]]; then
    printf 'SNI_PROBE:%s\\n' "$TARGET_REALITY_SNI" >>"$FIXTURE_ROOT/events"
    exec "$FIXTURE_PYTHON" -B "$script" --check-reality-sni
  else printf 'FULL_PREFLIGHT\\n' >>"$FIXTURE_ROOT/events"; fi
  exec "$FIXTURE_PYTHON" -B "$script" --inputs-only
fi
exec "$FIXTURE_PYTHON" "${arguments[@]}"
''')
    executable(binary / 'mv', shell + '''
last=${@: -1}
case "$last" in
  "$FIXTURE_ROOT/installed"|"$FIXTURE_ROOT/state"|"$FIXTURE_ROOT/target.env")
    printf 'BOOTSTRAP_PUBLISH\\n' >>"$FIXTURE_ROOT/events";;
esac
exec /usr/bin/mv "$@"
''')
    executable(binary / 'apt-get', shell + 'printf "APT:%s\\n" "$*" >>"$FIXTURE_ROOT/events"\n')
    for name in ('systemctl', 'ufw', 'nft', 'iptables', 'ip6tables', 'useradd'):
        executable(binary / name, shell + 'printf "UNEXPECTED_MUTATION\\n" >>"$FIXTURE_ROOT/events"\nexit 94\n')
    executable(binary / 'certbot', shell + '''
[[ " $* " == *' --non-interactive '* ]] || exit 95
printf 'PHASE:renewal\\n' >>"$FIXTURE_ROOT/events"
''')
    paths = {
        'base/install-pinned-base.sh': 'base', 'base/install-certbot.sh': 'certbot',
        'base/acme.sh': 'tls', 'scripts/configure-standalone.sh': 'direct',
        'scripts/expose-panel-https.sh': 'panel', 'base/install-nginx-restart.sh': 'nginx-restart',
        'base/install-cert-reconcile.sh': 'cert-reconcile',
        'warp-egress/scripts/install-warp.sh': 'warp', 'scripts/enable-dual-egress.sh': 'dual',
    }
    for relative, name in paths.items():
        body = shell
        if name == 'certbot':
            body += 'if [[ ${1:-} == --check-only ]]; then exit 0; fi\n'
        body += 'printf "PHASE:' + name + '\\n" >>"$FIXTURE_ROOT/events"\n'
        if name == 'base':
            # A timeout is different from EOF: the phase must receive /dev/null
            # even though the PTY and its controlling terminal remain open.
            body += '''
if IFS= read -r -t .2 unexpected; then exit 96; else rc=$?; fi
[[ $rc == 1 ]] || exit 97
printf 'BASE_STDIN_EOF\\n' >>"$FIXTURE_ROOT/events"
"$FIXTURE_PYTHON" -I -c 'import json,os,pathlib;pathlib.Path(os.environ["FIXTURE_ROOT"],"phase-inputs.json").write_text(json.dumps({k:v for k,v in os.environ.items() if k.startswith("TARGET_") or k=="ACME_EMAIL"}))'
apt-get update
apt-get upgrade -y --no-remove
'''
        executable(source / 'bundle' / relative, body)
    executable(source / 'bundle/scripts/finalize-xhttp.py',
               'import os,pathlib\nwith pathlib.Path(os.environ["FIXTURE_ROOT"],"events").open("a") as f:f.write("PHASE:xhttp\\n")\n')
    executable(source / 'tools/verify.sh', shell + '''
printf 'PHASE:verify\\n' >>"$FIXTURE_ROOT/events"
"$FIXTURE_PYTHON" -I -c 'import json,os,pathlib;pathlib.Path(os.environ["FIXTURE_ROOT"],"verify-inputs.json").write_text(json.dumps({k:v for k,v in os.environ.items() if k.startswith("TARGET_") or k=="ACME_EMAIL"}))'
''')
    # The test changes only its private copy. Recompute its actual source
    # manifest so bootstrap and resume exercise real checksum verification.
    manifest = source / 'SHA256SUMS'
    manifest.write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' +
                        path.relative_to(source).as_posix() + '\n'
                        for path in sorted(source.rglob('*')) if path.is_file() and path != manifest))

def environment():
    env = {key: value for key, value in os.environ.items()
           if not key.startswith('TARGET_') and key not in ('SSH_CONNECTION', 'ACME_EMAIL', 'NO_COLOR')}
    env.update(PATH=str(root / 'bin') + ':/usr/sbin:/usr/bin:/sbin:/bin',
               FIXTURE_ROOT=str(root), FIXTURE_PYTHON=real_python, LC_ALL='C', LANG='C',
               TERM=settings.get('term', 'dumb'),
               FIXTURE_TLS_FAIL_SNIS=','.join(settings.get('tls_fail_snis', [])))
    if settings.get('ssh_connection'):
        env['SSH_CONNECTION'] = settings['ssh_connection']
    if 'no_color' in settings:
        env['NO_COLOR'] = settings['no_color']
    env.update(settings.get('caller_inputs', {}))
    return env

def questionnaire_steps():
    steps = []
    if not settings.get('ssh_connection'):
        steps.append(('SSH порт', settings.get('port', '2222')))
    menu = settings.get('menu_answers', [settings.get('address_choice', '2')])
    steps.extend(('Выберите вариант [1]:', value) for value in menu)
    if menu[-1] == '2':
        steps.extend(('Домен VPN:', value) for value in
                     settings.get('domain_answers', [settings.get('domain', 'vpn.example.com')]))
    if 'sni_steps' in settings:
        steps.extend(settings['sni_steps'])
    else:
        sni_choice = settings.get('sni_choice', '1')
        steps.append(('Выберите SNI [1]:', sni_choice))
        if sni_choice == '2':
            steps.extend(('Свой SNI:', value) for value in
                         settings.get('custom_sni_answers', ['example.org']))
    for index, value in settings.get('override', {}).items():
        marker, _ = steps[int(index)]
        steps[int(index)] = (marker, value)
    return steps

def transcript(steps, eof=None):
    pid, descriptor = pty.fork()
    if pid == 0:
        attributes = termios.tcgetattr(0)
        attributes[3] &= ~termios.ECHO
        termios.tcsetattr(0, termios.TCSANOW, attributes)
        os.execve('/bin/bash', ['bash', str(source / 'install.sh')], environment())
    decoder = codecs.getincrementaldecoder('utf-8')('strict')
    buffer, output, index = '', '', 0
    deadline = time.monotonic() + 45
    try:
        while True:
            if time.monotonic() > deadline:
                raise AssertionError('Questionnaire hung at step ' + str(index) + ': ' + output[-3000:])
            if not select.select([descriptor], [], [], .1)[0]:
                continue
            try:
                data = os.read(descriptor, 65536)
            except OSError as error:
                if error.errno == errno.EIO: break
                raise
            if not data: break
            value = decoder.decode(data)
            output += value
            buffer += value
            plain = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', buffer)
            if index < len(steps) and steps[index][0] in plain:
                if index == eof or steps[index][1] is None:
                    event('EOF:' + str(index))
                    os.write(descriptor, b'\x04')
                    index = len(steps)
                else:
                    event('ANSWER:' + str(index))
                    os.write(descriptor, (steps[index][1] + '\n').encode('utf-8'))
                    index += 1
                buffer = ''
        _, status = os.waitpid(pid, 0)
        pid = None
        return os.waitstatus_to_exitcode(status), output
    finally:
        os.close(descriptor)
        if pid is not None:
            try: os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError: pass
            os.waitpid(pid, 0)

try:
    prepare()
    code, output = transcript(questionnaire_steps(), settings.get('eof'))
    observed = events.read_text().splitlines() if events.exists() else []
    persisted = {}
    phase_inputs = {}
    resume = None
    if target.exists():
        persisted = {key: shlex.split(raw)[0] for key, raw in
                     (line.split('=', 1) for line in target.read_text().splitlines())}
    if (root / 'phase-inputs.json').exists():
        phase_inputs = json.loads((root / 'phase-inputs.json').read_text())
    if settings.get('resume') and code == 0:
        if settings.get('saved_resume_inputs'):
            # Model an existing installation with earlier saved parameters.
            # Fresh defaults must never replace these on --resume.
            text = target.read_text()
            for key, value in settings['saved_resume_inputs'].items():
                assert key in ('ACME_EMAIL', 'TARGET_LABEL', 'TARGET_REALITY_SNI', 'TARGET_DEVICE_LIMIT')
                text, replaced = re.subn('^' + key + '=.*$',
                                         lambda match: key + '=' + shlex.quote(value), text, flags=re.M)
                assert replaced == 1
            target.write_text(text)
        before = target.read_bytes()
        before_events = len(observed)
        env = environment()
        # Deliberately conflicting values must not replace saved answers.
        env.update(TARGET_LABEL='caller-must-not-win', ACME_EMAIL='caller@example.invalid')
        child = subprocess.run(['/bin/bash', str(installed / 'install.sh'), '--resume'],
                               env=env, stdin=subprocess.DEVNULL, capture_output=True,
                               start_new_session=True, timeout=30)
        verify_inputs = json.loads((root / 'verify-inputs.json').read_text())
        resume = {'exit': child.returncode, 'output': (child.stdout + child.stderr).decode(),
                  'events': events.read_text().splitlines()[before_events:],
                  'target_unchanged': target.read_bytes() == before,
                  'phase_inputs': verify_inputs}
    print(json.dumps({'exit': code, 'output': output, 'events': observed,
                      'persisted': persisted, 'phase_inputs': phase_inputs,
                      'managed': [installed.exists(), state.exists(), target.exists()],
                      'resume': resume}, ensure_ascii=True))
finally:
    # Every removed path is strictly inside the random /tmp fixture root.
    for path in (source, installed, state, root / 'bin'):
        if path.exists(): shutil.rmtree(path)
    for path in root.glob('*.bootstrap.*'):
        if path.is_dir(): shutil.rmtree(path)
        else: path.unlink()
    for path in root.glob('task.*'):
        if path.is_dir(): shutil.rmtree(path)
    for path in (target, root / 'phase-inputs.json', root / 'verify-inputs.json'):
        path.unlink(missing_ok=True)
"""


@unittest.skipIf(os.name == 'nt', 'Actual root/PTY entrypoint fixtures run in Ubuntu CI')
class QuestionnaireFlow(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.prefix = []
        elif shutil.which('sudo') and subprocess.run(
                ['sudo', '-n', 'true'], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL).returncode == 0:
            self.prefix = ['sudo', '-n']
        else:
            if os.environ.get('CI'):
                self.fail('Ubuntu CI must execute actual root questionnaire fixtures')
            self.skipTest('Root or passwordless sudo required')

    def fixture(self, **settings):
        with tempfile.TemporaryDirectory(prefix='vpn-questionnaire-flow.', dir='/tmp') as temporary:
            payload = dict(settings, root=temporary, production=str(ROOT))
            result = subprocess.run([*self.prefix, 'python3', '-B', '-c', RUNNER,
                                     json.dumps(payload)], capture_output=True, text=True, timeout=95)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return json.loads(result.stdout)

    def assert_unpublished(self, result):
        self.assertNotEqual(result['exit'], 0, result['output'])
        self.assertEqual(result['managed'], [False, False, False], result['output'])
        self.assertFalse(any(event.startswith(('BOOTSTRAP', 'PHASE:', 'APT:', 'FULL_PREFLIGHT',
                                               'UNEXPECTED_MUTATION', 'NETWORK'))
                             for event in result['events']), result['events'])

    def assert_wizard_labels_and_no_ip(self, result):
        plain = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', result['output'])
        self.assertIn('[Установка]', plain)
        wizard = plain.split('[Установка]', 1)[0]
        labels = [line.strip() for line in wizard.splitlines()]
        self.assertIn('1. По IP-адресу', labels)
        self.assertIn('2. По доменному имени', labels)
        self.assertIn('1. По умолчанию max.ru', labels)
        self.assertIn('2. Свой', labels)
        self.assertNotRegex(wizard, r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')
        for removed in ('Ваш email', 'Начало названий', 'REALITY SNI [',
                        'Лимит IP', 'Установить VPN', 'Проверьте параметры перед запуском:'):
            self.assertNotIn(removed, wizard)

    def test_eof_at_each_question_publishes_nothing(self):
        # Console: port, mode, domain, SNI choice. SSH omits the port.
        for index in range(4):
            with self.subTest(eof=index):
                self.assert_unpublished(self.fixture(eof=index))
        self.assert_unpublished(self.fixture(ssh_connection=SSH_CONNECTION,
                                             address_choice='1', eof=0))

    def test_invalid_answers_never_bootstrap_or_start_a_phase(self):
        for index, value in ((0, '8444'), (2, 'bad;name.example')):
            with self.subTest(field=index):
                self.assert_unpublished(self.fixture(override={str(index): value}))

    def test_default_sni_starts_install_and_resume_preserves_saved_parameters(self):
        injected = dict(ACME_EMAIL='caller@example.invalid', TARGET_LABEL='Caller VPN',
                        TARGET_REALITY_SNI='example.org', TARGET_DEVICE_LIMIT='99')
        saved = dict(ACME_EMAIL='legacy@example.com', TARGET_LABEL='Старый VPN',
                     TARGET_REALITY_SNI='example.net', TARGET_DEVICE_LIMIT='17')
        result = self.fixture(ssh_connection=SSH_CONNECTION, address_choice='', resume=True,
                              sni_choice='', term='xterm-256color', caller_inputs=injected,
                              saved_resume_inputs=saved)
        self.assertEqual(result['exit'], 0, result['output'])
        self.assert_wizard_labels_and_no_ip(result)
        expected = dict(TARGET_ADDRESS_MODE='ip', TARGET_IPV4='8.8.4.4',
                        TARGET_FQDN='8.8.4.4', TARGET_INTERFACE='enp1s0',
                        TARGET_SSH_PORT='2222', TARGET_DEVICE_LIMIT='0',
                        TARGET_REALITY_SNI='max.ru', TARGET_LABEL='Мой VPN', ACME_EMAIL='')
        self.assertEqual(result['persisted'], expected)
        self.assertEqual({key: result['phase_inputs'].get(key) for key in expected}, expected)
        events = result['events']
        self.assertEqual([event for event in events if event.startswith('ANSWER:')], ['ANSWER:0', 'ANSWER:1'])
        self.assertLess(events.index('ANSWER:1'), events.index('SNI_PROBE:max.ru'))
        self.assertLess(events.index('SNI_PROBE:max.ru'), events.index('SNI_TLS:max.ru'))
        self.assertLess(events.index('SNI_TLS:max.ru'), events.index('INPUT_VALIDATION'))
        self.assertLess(events.index('INPUT_VALIDATION'), events.index('FULL_PREFLIGHT'))
        self.assertLess(events.index('FULL_PREFLIGHT'), events.index('BOOTSTRAP_PUBLISH'))
        self.assertLess(events.index('BOOTSTRAP_PUBLISH'), events.index('PHASE:base'))
        self.assertLess(events.index('PHASE:base'), events.index('APT:update'))
        self.assertIn('BASE_STDIN_EOF', events)
        self.assertIn('\x1b[', result['output'])
        self.assertIn('VPN', result['output'])
        self.assertRegex(result['output'], r'3X-?UI')
        release = re.search(r"^readonly release='([^']+)'$", (ROOT / 'install.sh').read_text(encoding='utf-8'), re.M)
        self.assertIsNotNone(release)
        self.assertIn(release.group(1), result['output'])
        resumed = result['resume']
        self.assertEqual(resumed['exit'], 0, resumed['output'])
        self.assertTrue(resumed['target_unchanged'])
        self.assertEqual({key: resumed['phase_inputs'].get(key) for key in saved}, saved)
        self.assertEqual(resumed['events'], ['PHASE:verify'])
        self.assertNotIn('Установить VPN', resumed['output'])
        self.assertNotIn('Домен VPN', resumed['output'])
        self.assertNotIn('Выберите вариант', resumed['output'])
        self.assertNotIn('Выберите SNI', resumed['output'])
        self.assertNotIn('\x1b[', resumed['output'])

    def test_domain_name_and_console_port_precede_default_sni_choice(self):
        for domain in (True, False):
            with self.subTest(domain=domain):
                values = (dict(ssh_connection=SSH_CONNECTION, address_choice='2') if domain
                          else dict(address_choice='1', port=''))
                result = self.fixture(**values)
                self.assertEqual(result['exit'], 0, result['output'])
                self.assert_wizard_labels_and_no_ip(result)
                self.assertEqual(result['persisted']['TARGET_ADDRESS_MODE'], 'domain' if domain else 'ip')
                self.assertEqual(result['persisted']['TARGET_FQDN'], 'vpn.example.com' if domain else '8.8.4.4')
                self.assertEqual(result['persisted']['TARGET_SSH_PORT'], '2222' if domain else '22')
                self.assertEqual(result['persisted']['TARGET_LABEL'], 'Мой VPN')
                self.assertEqual(result['persisted']['TARGET_REALITY_SNI'], 'max.ru')
                self.assertEqual(result['persisted']['TARGET_DEVICE_LIMIT'], '0')
                self.assertEqual(result['persisted']['ACME_EMAIL'], '')
                self.assertEqual(result['phase_inputs']['ACME_EMAIL'], '')
                self.assertEqual([event for event in result['events'] if event.startswith('ANSWER:')],
                                 ['ANSWER:0', 'ANSWER:1', 'ANSWER:2'])
                self.assertEqual('Домен VPN:' in result['output'], domain)
                self.assertEqual('SSH порт [22]' in result['output'], not domain)
                self.assertLess(result['events'].index('ANSWER:2'), result['events'].index('SNI_PROBE:max.ru'))
                self.assertNotIn('\x1b[', result['output'])

    def test_invalid_menu_retries_and_eof_cannot_start_installation(self):
        result = self.fixture(menu_answers=['invalid', '3', '2'])
        self.assertEqual(result['exit'], 0, result['output'])
        self.assertEqual(result['persisted']['TARGET_ADDRESS_MODE'], 'domain')
        self.assertEqual(result['persisted']['TARGET_FQDN'], 'vpn.example.com')
        self.assertEqual(result['output'].count('Выберите вариант [1]:'), 3)
        self.assertLess(result['events'].index('ANSWER:5'), result['events'].index('FULL_PREFLIGHT'))
        self.assert_unpublished(self.fixture(menu_answers=['invalid', None]))
        self.assert_unpublished(self.fixture(domain_answers=['', None]))

    def test_custom_sni_retries_format_and_tls_failures_before_installation(self):
        result = self.fixture(ssh_connection=SSH_CONNECTION, address_choice='1', sni_choice='2',
                              custom_sni_answers=['failed.example.org', 'bad;name.example', 'example.org'],
                              tls_fail_snis=['failed.example.org'])
        self.assertEqual(result['exit'], 0, result['output'])
        self.assert_wizard_labels_and_no_ip(result)
        self.assertEqual(result['persisted']['TARGET_REALITY_SNI'], 'example.org')
        self.assertEqual(result['phase_inputs']['TARGET_REALITY_SNI'], 'example.org')
        events = result['events']
        self.assertEqual([event for event in events if event.startswith('SNI_PROBE:')],
                         ['SNI_PROBE:failed.example.org', 'SNI_PROBE:bad;name.example', 'SNI_PROBE:example.org'])
        self.assertEqual([event for event in events if event.startswith('SNI_TLS:')],
                         ['SNI_TLS:failed.example.org', 'SNI_TLS:example.org'])
        self.assertLess(events.index('SNI_TLS:example.org'), events.index('INPUT_VALIDATION'))
        self.assertLess(events.index('INPUT_VALIDATION'), events.index('BOOTSTRAP_PUBLISH'))
        self.assertLess(events.index('BOOTSTRAP_PUBLISH'), events.index('APT:update'))

        # Failed default returns to its menu; a custom target can then succeed.
        fallback = self.fixture(ssh_connection=SSH_CONNECTION, address_choice='1',
                                sni_steps=[['Выберите SNI [1]:', '1'], ['Выберите SNI [1]:', '2'],
                                           ['Свой SNI:', 'example.net']], tls_fail_snis=['max.ru'])
        self.assertEqual(fallback['exit'], 0, fallback['output'])
        self.assertEqual(fallback['persisted']['TARGET_REALITY_SNI'], 'example.net')
        self.assertEqual([event for event in fallback['events'] if event.startswith('SNI_TLS:')],
                         ['SNI_TLS:max.ru', 'SNI_TLS:example.net'])

        rejected = self.fixture(ssh_connection=SSH_CONNECTION, address_choice='1', sni_choice='2',
                                custom_sni_answers=['failed.example.org', None],
                                tls_fail_snis=['failed.example.org'])
        self.assert_unpublished(rejected)
        blank = self.fixture(ssh_connection=SSH_CONNECTION, address_choice='1', sni_choice='2',
                             custom_sni_answers=['', None])
        self.assert_unpublished(blank)
        self.assertIn('EOF:3', blank['events'])
        self.assertFalse(any(event.startswith('SNI_PROBE:') for event in blank['events']))

    def test_no_color_disables_ansi_even_in_color_capable_pty(self):
        result = self.fixture(ssh_connection=SSH_CONNECTION, address_choice='1',
                              term='xterm-256color', no_color='')
        self.assertEqual(result['exit'], 0, result['output'])
        self.assertNotIn('\x1b[', result['output'])


if __name__ == '__main__':
    unittest.main()
