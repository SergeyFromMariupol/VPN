"""Real foreground phase/checkpoint and cosmetic renderer lifecycle fixtures."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

RUNNER = r"""
import errno, json, os, pathlib, pty, re, select, shutil, signal, subprocess, sys, time
config = json.loads(sys.argv[1])
root = pathlib.Path(config['root']).resolve()
assert root.parent == pathlib.Path('/tmp') and root.name.startswith('vpn-progress-test.')
source = pathlib.Path(config['source'])
canary = 'PRIVATE_PHASE_CANARY_MUST_NOT_REACH_TERMINAL'
driver = root / 'driver.sh'
driver.write_text(r'''
set -Eeuo pipefail
umask 077
state=$FIXTURE_ROOT/state
mkdir -m 0700 "$state" "$FIXTURE_ROOT/progress"
exec 9>"$FIXTURE_ROOT/installer.lock"
flock -n 9
source "$PROGRESS_LIBRARY"
source "$PHASE_LIBRARY"
cleanup() {
  local rc=$?
  trap - EXIT HUP INT TERM
  installer_progress_stop || :
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM
export INSTALLER_PARENT_PID=$BASHPID
if [[ $CASE == count ]]; then
  date -u +%FT%TZ >"$state/verify.done"
  stat -c '%d:%i' "$state/verify.done" >"$FIXTURE_ROOT/verify.before"
fi
if [[ $CASE == prep ]]; then
  # Preparatory activity must not display a false 0% on an existing installation.
  for name in base certbot tls; do date -u +%FT%TZ >"$state/$name.done"; done
fi
installer_progress_init "$FIXTURE_ROOT/progress" "$PROGRESS_PYTHON"
# Observe the real renderer owned by each phase subshell, without changing it.
definition=$(declare -f installer_progress_begin)
eval "${definition/installer_progress_begin/_fixture_real_progress_begin}"
installer_progress_begin() {
  _fixture_real_progress_begin "$@"
  printf '%s:%s:%s\n' "$BASHPID" "${installer_progress_pid:-}" \
    "${installer_progress_child_identity:-}" >>"$FIXTURE_ROOT/renderers"
  return 0
}
hold() {
  printf '%s\n' "$CANARY"
  : >"$FIXTURE_ROOT/started"
  while [[ ! -e $FIXTURE_ROOT/release ]]; do sleep .02; done
  case $CASE in fail|killed-fail) return 42;;
    term) printf committed >"$FIXTURE_ROOT/committed"; kill -TERM "$INSTALLER_PARENT_PID";; esac
}
instant() { printf '%s\n' "$CANARY"; }
case $CASE in
  prep)
    installer_progress_begin "$PROGRESS_STAGE"
    hold >"$state/prep.log"
    installer_progress_end "$PROGRESS_STAGE" "$PROGRESS_RESULT";;
  group-term)
    # The PTY driver owns its session/group; this can never reach the CI runner.
    [[ $(ps -o pgid= -p "$BASHPID" | tr -d '[:space:]') == "$BASHPID" ]] || exit 98
    phase direct bash -c '
      trap "" TERM
      printf "%s\n" "$CANARY"
      printf "%s\n" "$PPID" >"$FIXTURE_ROOT/command-parent"
      : >"$FIXTURE_ROOT/started"
      while [[ ! -e $FIXTURE_ROOT/release ]]; do sleep .02; done
      printf committed >"$FIXTURE_ROOT/committed"
      kill -TERM 0
    ';;
  orphan)
    installer_progress_begin direct
    : >"$FIXTURE_ROOT/started"
    kill -STOP "$BASHPID";;
  count)
    for name in base certbot tls direct panel nginx-restart cert-reconcile warp dual xhttp renewal; do
      phase "$name" instant
      if [[ $name == base ]]; then phase base instant; fi
    done
    phase --always verify hold;;
  *) phase direct hold;;
esac
''', encoding='utf-8')
driver.chmod(0o700)
environment = dict(os.environ, FIXTURE_ROOT=str(root), CASE=config['case'], CANARY=canary,
                   PROGRESS_LIBRARY=str(source / 'tools/progress.sh'),
                   PHASE_LIBRARY=str(source / 'tools/phases.sh'),
                   PROGRESS_PYTHON=str(source / 'tools/progress.py'),
                   PROGRESS_STAGE=config.get('stage', ''),
                   PROGRESS_RESULT=str(config.get('result', '0')),
                   TERM=config.get('term', 'xterm-256color'), LC_ALL='C', LANG='C')
environment.pop('NO_COLOR', None)
if config.get('no_color'): environment['NO_COLOR'] = '1'
process = None
if config.get('tty', True):
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execve('/bin/bash', ['bash', str(driver)], environment)
else:
    process = subprocess.Popen(['/bin/bash', str(driver)], env=environment,
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    pid, descriptor = process.pid, process.stdout.fileno()

def identity(pid):
    try:
        fields = pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
        return fields[0], int(fields[1]), fields[19]
    except (OSError, IndexError, ValueError): return None

def history():
    result = []
    path = root / 'renderers'
    if path.exists():
        for line in path.read_text().splitlines(keepends=True):
            match = re.fullmatch(r'(\d+):(\d*):(\d*)\n', line)
            if match and match[2] and match[3]:
                result.append((int(match[1]), int(match[2]), match[3]))
    return result

def alive(record):
    info = identity(record[1])
    return info is not None and info[0] not in ('Z', 'X') and info[2] == record[2]

def frames(raw, label, preparatory=False):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw.decode('utf-8', 'replace'))
    result = []
    for line in re.split(r'[\r\n]', text):
        count = re.search(r'\[(\d+)/12\]', line)
        clock = re.search(r'\b(\d+):(\d{2})\b', line)
        spinner = re.search('[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]', line)
        if clock and label in line and (count or (preparatory and spinner)):
            result.append((int(count[1]) if count else None,
                           int(clock[1]) * 60 + int(clock[2])))
    return result

data = b''
owner_identity = identity(pid)
waited = False
released = killed = owner_killed = False
fd9_seen = False
held_counts = []
held_elapsed = held_seconds = 0
checkpoint_before = False
started_at = None
deadline = time.monotonic() + 45
try:
    while True:
        if time.monotonic() > deadline: raise AssertionError('progress fixture timed out: ' + data.decode('utf-8', 'replace')[-2000:])
        if select.select([descriptor], [], [], .05)[0]:
            try: block = os.read(descriptor, 65536)
            except OSError as error:
                if error.errno == errno.EIO: break
                raise
            if not block: break
            data += block
        if not (root / 'started').exists() or released or owner_killed: continue
        if started_at is None: started_at = time.monotonic()
        records = history()
        live = [record for record in records if alive(record)]
        if live:
            current = live[-1]
            # Never signal a reused PID or an unrelated process.
            assert identity(current[1])[1] == current[0]
            fd9_seen |= pathlib.Path(f'/proc/{current[1]}/fd/9').exists()
        case = config['case']
        label = {'sni-check': 'Проверка REALITY SNI', 'preflight': 'Проверка сервера',
                 'bootstrap': 'Подготовка установки'}.get(config.get('stage')) if case == 'prep' else None
        observed = frames(data, label or ('Итоговая проверка' if case == 'count' else 'Прямые профили'),
                          preparatory=(case == 'prep'))
        if case == 'orphan' and live and observed:
            os.kill(pid, signal.SIGKILL)
            owner_killed = True
            continue
        ready = False
        if not config.get('tty', True): ready = time.monotonic() - started_at > .25
        elif case.startswith('killed-') and live and observed:
            os.kill(live[-1][1], signal.SIGKILL)
            killed = ready = True
        elif case == 'count': ready = any(count == 11 for count, elapsed in observed)
        elif config.get('term') == 'dumb':
            ready = len({elapsed for count, elapsed in observed}) >= 2 and max(elapsed for count, elapsed in observed) >= 10
        else: ready = len({elapsed for count, elapsed in observed}) >= 2
        if ready:
            held_counts = [count for count, elapsed in observed if count is not None]
            held_elapsed = max((elapsed for count, elapsed in observed), default=0)
            held_seconds = time.monotonic() - started_at
            checkpoint_before = (root / 'state/direct.done').exists() if case != 'count' else False
            (root / 'release').touch()
            released = True
    if process is None:
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        os.close(descriptor)
    else:
        code = process.wait(timeout=3)
        process.stdout.close()
    waited = True
    records = history()
    until = time.monotonic() + 3
    while any(alive(record) for record in records) and time.monotonic() < until: time.sleep(.05)
    lock_free = subprocess.run(['flock', '-n', str(root / 'installer.lock'), 'true']).returncode == 0
    def valid(name):
        return subprocess.run(['/bin/bash', '-c', 'source "$1"; installer_checkpoint_valid "$2"',
                               '_', str(source / 'tools/phases.sh'), str(root / 'state' / (name + '.done'))],
                              capture_output=True).returncode == 0
    names = 'base certbot tls direct panel nginx-restart cert-reconcile warp dual xhttp renewal verify'.split()
    verify = root / 'state/verify.done'
    replaced = ((root / 'verify.before').read_text().strip() != f'{verify.stat().st_dev}:{verify.stat().st_ino}') if config['case'] == 'count' else False
    output = data.decode('utf-8', 'strict')
    print(json.dumps(dict(code=code, output=output, renderer_count=len(records),
          renderers_alive=sum(alive(record) for record in records), fd9_seen=fd9_seen,
          lock_free=lock_free, checkpoint_before=checkpoint_before, held_counts=held_counts,
          held_elapsed=held_elapsed, held_seconds=held_seconds, killed=killed,
          command_parent_matches=(int((root / 'command-parent').read_text()) == records[-1][0]) if config['case'] == 'group-term' else None,
          direct_valid=valid('direct'), valid_count=sum(valid(name) for name in names),
          verify_replaced=replaced, canary_logged=any(canary in path.read_text() for path in (root / 'state').glob('*.log')))))
finally:
    current_owner = identity(pid)
    owned_group = (current_owner is not None and owner_identity is not None and
                   current_owner[2] == owner_identity[2]) or any(alive(record) for record in history())
    if owned_group:
        try: os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError: pass
    if not waited:
        if process is None:
            os.close(descriptor)
            os.waitpid(pid, 0)
        else:
            process.wait(timeout=3)
            process.stdout.close()
    # Only this random, validated disposable root is removed.
    shutil.rmtree(root)
"""


@unittest.skipIf(os.name == 'nt', 'Actual root/PTY progress fixtures run in Ubuntu CI')
class Progress(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.prefix = []
        elif shutil.which('sudo') and subprocess.run(['sudo', '-n', 'true'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            self.prefix = ['sudo', '-n']
        else:
            if os.environ.get('CI'): self.fail('Ubuntu CI must execute root progress fixtures')
            self.skipTest('Root or passwordless sudo required')

    def fixture(self, case, **options):
        with tempfile.TemporaryDirectory(prefix='vpn-progress-test.', dir='/tmp') as directory:
            config = dict(options, root=directory, source=str(ROOT), case=case)
            result = subprocess.run([*self.prefix, 'python3', '-B', '-c', RUNNER, json.dumps(config)],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = json.loads(result.stdout)
            self.assertTrue(result['lock_free'], result)
            self.assertEqual(result['renderers_alive'], 0, result)
            self.assertFalse(result['fd9_seen'], result)
            self.assertNotIn('PRIVATE_PHASE_CANARY', result['output'])
            self.assertNotRegex(result['output'], r'[^\r\n]*%[^\r\n]*— (?:готово|уже завершено)')
            return result

    def test_live_pty_frames_precede_foreground_completion_and_checkpoint(self):
        result = self.fixture('live', no_color=True)
        self.assertEqual(result['code'], 0, result['output'])
        self.assertFalse(result['checkpoint_before'])
        self.assertGreater(result['renderer_count'], 0)
        self.assertGreaterEqual(result['held_elapsed'], 1)
        self.assertEqual(set(result['held_counts']), {0})
        self.assertTrue(result['direct_valid'])
        self.assertTrue(result['canary_logged'])
        self.assertIn('Общий прогресс: ', result['output'])
        self.assertIn('[1/12]', result['output'])
        self.assertIn('░', result['output'])
        self.assertNotIn('\x1b', result['output'])

    def test_failure_term_and_renderer_crash_preserve_transaction_outcomes(self):
        for case, code, committed in (('fail', 1, False), ('term', 143, True),
                                       ('group-term', 143, True),
                                       ('killed-success', 0, True), ('killed-fail', 1, False)):
            with self.subTest(case=case):
                result = self.fixture(case)
                self.assertEqual(result['code'], code, result['output'])
                self.assertEqual(result['direct_valid'], committed)
                self.assertFalse(result['checkpoint_before'])
                if case == 'group-term': self.assertTrue(result['command_parent_matches'])
                if case.startswith('killed-'): self.assertTrue(result['killed'])

    def test_true_twelve_count_excludes_historical_verify_and_duplicate_skip(self):
        result = self.fixture('count')
        self.assertEqual(result['code'], 0, result['output'])
        self.assertEqual(result['valid_count'], 12)
        self.assertTrue(result['verify_replaced'])
        self.assertEqual(set(result['held_counts']), {11})
        self.assertRegex(result['output'], r'Общий прогресс: \[[█░]+\] 100% \[12/12\]')
        self.assertIn('✓ Итоговая проверка', result['output'])
        self.assertIn('✓ Подготовка Ubuntu (уже завершено)', result['output'])
        self.assertRegex(result['output'], r'Общий прогресс: \[[█░]+\] 8% \[1/12\]')
        self.assertNotRegex(result['output'], r'[^\r\n]*%[^\r\n]*(?:готово|уже завершено)')
        self.assertNotRegex(result['output'], r'\[(?:1[3-9]|[2-9][0-9])/12\]')

    def test_preparatory_pty_activity_and_outcomes_have_no_overall_percentage(self):
        stages = {'sni-check': 'Проверка REALITY SNI', 'preflight': 'Проверка сервера',
                  'bootstrap': 'Подготовка установки'}
        outcomes = {'0': '✓ {label} — готово', 'skip': '✓ {label} — уже завершено',
                    '1': '! {label} — остановлено'}
        for stage, label in stages.items():
            for code, outcome in outcomes.items():
                with self.subTest(stage=stage, result=code):
                    result = self.fixture('prep', stage=stage, result=code)
                    self.assertEqual(result['code'], 0, result['output'])
                    self.assertGreater(result['renderer_count'], 0)
                    self.assertGreaterEqual(result['held_elapsed'], 1)
                    self.assertEqual(result['held_counts'], [])
                    self.assertEqual(result['valid_count'], 3)
                    self.assertTrue(result['canary_logged'])
                    self.assertIn(outcome.format(label=label), result['output'])
                    self.assertNotRegex(result['output'], r'%|/12|[█░]')
                    self.assertRegex(result['output'], r'[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏][^\r\n]*' + label)
                    if code == '1': self.assertNotIn('готово', result['output'])

    def test_plain_preparatory_status_has_no_renderer_or_overall_percentage(self):
        for stage, label in (('sni-check', 'Проверка REALITY SNI'),
                             ('preflight', 'Проверка сервера'),
                             ('bootstrap', 'Подготовка установки')):
            with self.subTest(stage=stage):
                result = self.fixture('prep', tty=False, stage=stage)
                self.assertEqual(result['code'], 0, result['output'])
                self.assertEqual(result['renderer_count'], 0)
                self.assertEqual(result['valid_count'], 3)
                self.assertIn(label + ' — выполняется…', result['output'])
                self.assertIn('✓ ' + label + ' — готово', result['output'])
                self.assertNotRegex(result['output'], r'%|/12|[█░\r\x1b]')

    def test_plain_pipe_has_no_renderer_and_dumb_pty_has_real_ten_second_heartbeat(self):
        pipe = self.fixture('live', tty=False)
        self.assertEqual(pipe['code'], 0, pipe['output'])
        self.assertEqual(pipe['renderer_count'], 0)
        self.assertIn('[0/12]', pipe['output'])
        self.assertIn('[1/12]', pipe['output'])
        self.assertNotRegex(pipe['output'], r'[\r\x1b]')
        dumb = self.fixture('live', term='dumb')
        self.assertEqual(dumb['code'], 0, dumb['output'])
        self.assertGreaterEqual(dumb['held_seconds'], 8)
        self.assertGreaterEqual(dumb['held_elapsed'], 10)
        self.assertNotRegex(dumb['output'].replace('\r\n', '\n'), r'[\r\x1b]')

    def test_renderer_exits_when_owner_is_killed_without_cleanup(self):
        result = self.fixture('orphan')
        self.assertEqual(result['code'], -9, result['output'])
        self.assertGreater(result['renderer_count'], 0)


if __name__ == '__main__':
    unittest.main()
