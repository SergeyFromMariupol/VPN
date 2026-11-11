"""Run the actual local-target shell transaction in a private Linux file tree."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'bundle/base/install-reality-decoy.sh'


@unittest.skipUnless(os.name == 'posix' and all(shutil.which(name) for name in
                    ('bash', 'flock', 'tar', 'install', 'sha256sum', 'stat')), 'Linux shell tools required')
class DecoyTransaction(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpn-decoy-transaction-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('bundle/base', 'bundle/scripts', 'bundle/templates', 'etc/nginx/conf.d',
                     'etc/nginx/sites-enabled', 'etc/letsencrypt/live/own.example.test',
                     'etc/letsencrypt/renewal-hooks/deploy', 'etc/x-ui', 'usr/local/x-ui',
                     'etc/systemd/system', 'etc/ufw', 'var/www', 'var/backups', 'run', 'bin'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.root / 'etc/x-ui/x-ui.db') as database:
            database.execute('CREATE TABLE original(value TEXT)')
            database.execute("INSERT INTO original VALUES ('preserved')")
        (self.root / 'state.json').write_text(json.dumps({'active': False, 'enabled': 'disabled'}))
        contract = self.root / 'bundle/scripts/target-contract.sh'
        contract.write_text('''export TARGET_REALITY_MODE=decoy TARGET_FQDN=own.example.test TARGET_IPV4=203.0.113.10
export TARGET_ADDRESS_MODE=domain TARGET_TLS_MODE=letsencrypt TARGET_REALITY_SNI=max.ru
verify_target_certificate() { return 0; }
''')
        shutil.copyfile(ROOT / 'bundle/templates/55-vpn-reality-decoy', self.root / 'bundle/templates/55-vpn-reality-decoy')
        shutil.copyfile(ROOT / 'bundle/templates/reality-decoy-site.html',
                        self.root / 'bundle/templates/reality-decoy-site.html')
        shutil.copyfile(ROOT / 'bundle/base/reality-decoy.py', self.root / 'bundle/base/production-decoy.py')
        (self.root / 'bundle/base/reality-decoy.py').write_text('''import importlib.util,os,sys
from pathlib import Path
s=importlib.util.spec_from_file_location('production',Path(__file__).with_name('production-decoy.py'))
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
if sys.argv[1:]==['--nginx']:sys.stdout.write(m.render(os.environ))
elif sys.argv[1:]==['--default-page']:sys.stdout.write(m.BODY)
elif sys.argv[1:] in (['--probe-target'],['--probe-tls']):
    r=Path(os.environ['VPN_DECOY_FIXTURE'])
    sys.exit(1 if (r/'fail-probe').exists() or (sys.argv[1:]==['--probe-target'] and (r/'php-only-page').exists()) else 0)
else:sys.exit(2)
''')
        (self.root / 'bundle/base/enable-reality-decoy-php.sh').write_text(
            '#!/usr/bin/env bash\nprintf called >"$VPN_DECOY_FIXTURE/php-helper-called"\n')
        self.stub('systemctl', r'''
import json,os,sys
from pathlib import Path
r=Path(os.environ['VPN_DECOY_FIXTURE']);a=sys.argv[1:];p=r/'state.json';s=json.loads(p.read_text())
with (r/'calls.jsonl').open('a') as f:f.write(json.dumps(a)+'\n')
if a[0]=='is-active':
    if '--quiet' not in a:print('active' if s['active'] else 'inactive')
    sys.exit(0 if s['active'] else 1)
if a[0]=='is-enabled':
    if '--quiet' not in a:print(s['enabled'])
    sys.exit(0 if s['enabled']=='enabled' else 1)
if a[0]=='show':print('ActiveState='+('active' if s['active'] else 'inactive')+'\nMainPID='+('123' if s['active'] else '0'));sys.exit(0)
if a[0]=='disable':
    if (r/'fail-stop').exists():sys.exit(1)
    s.update(active=False,enabled='disabled')
elif a[0]=='enable':
    s['enabled']='enabled'
    if '--now' in a:s['active']=True
elif a[0]=='unmask':
    if s['enabled']=='masked':s['enabled']='disabled'
elif a[0]=='mask':s['enabled']='masked'
elif a[0]=='start':s['active']=True
elif a[0]=='reload':
    if (r/'fail-reload-once').exists():(r/'fail-reload-once').unlink();sys.exit(1)
    if not s['active']:sys.exit(1)
else:sys.exit(2)
p.write_text(json.dumps(s))
''')
        self.stub('ss', r'''
import json,os
from pathlib import Path
r=Path(os.environ['VPN_DECOY_FIXTURE']);s=json.loads((r/'state.json').read_text())
if (s['active'] and (r/'etc/nginx/conf.d/vpn-reality-decoy.conf').exists()) or (r/'occupied-target').exists():
    print('LISTEN 0 128 127.0.0.1:9443 0.0.0.0:*')
    if (r/'extra-public-listener').exists():print('LISTEN 0 128 0.0.0.0:9443 0.0.0.0:*')
if (r/'large-socket-inventory').exists():
    for i in range(20000):print('LISTEN 0 128 203.0.113.10:'+str(30000+i)+' 0.0.0.0:*')
''')
        self.stub('nginx', "import os,sys\nfrom pathlib import Path\nsys.exit(1 if (Path(os.environ['VPN_DECOY_FIXTURE'])/'fail-nginx').exists() else 0)\n")
        self.stub('openssl', "import sys\nprint('same-public-key')\n")
        self.stub('ufw', "print('Status: inactive')\n")
        self.stub('nft', "print('# fixture firewall')\n")
        self.stub('sqlite3', r'''
import sqlite3,sys
a=sys.argv[1:]
if a[0]=='-readonly':a=a[1:]
with sqlite3.connect(a[0]) as db:
    if a[1].startswith('.backup '):
        with sqlite3.connect(a[1].split("'",2)[1]) as out:db.backup(out)
    else:
        for row in db.execute(a[1]):print(row[0])
''')
        script = SCRIPT.read_text()
        for old, new in (
                ('[[ $EUID == 0 ]]', f'[[ $EUID == {os.getuid()} ]]'),
                ('0:0:', f'{os.getuid()}:{os.getgid()}:'),
                ('== 0:0 ]]', f'== {os.getuid()}:{os.getgid()} ]]'),
                ('install -o root -g root', 'install'),
                ('-C / ', '-C ' + self.root.as_posix() + ' '),
                ('/etc/', self.root.as_posix() + '/etc/'),
                ('/var/www', self.root.as_posix() + '/var/www'),
                ('/var/backups', self.root.as_posix() + '/var/backups'),
                ('-p /run ', '-p ' + self.root.as_posix() + '/run '),
                ('/run/vpn-reality-decoy.lock', self.root.as_posix() + '/run/lock')):
            script = script.replace(old, new)
        self.script = self.root / 'bundle/base/install-reality-decoy.sh'
        self.script.write_text(script)
        self.env = dict(os.environ, PATH=str(self.root / 'bin') + os.pathsep + os.environ['PATH'],
                        VPN_DECOY_FIXTURE=str(self.root))
        self.config = self.root / 'etc/nginx/conf.d/vpn-reality-decoy.conf'
        self.marker = self.root / 'etc/vpn-reality-decoy'
        self.site = self.root / 'var/www/vpn-decoy'
        self.hook = self.root / 'etc/letsencrypt/renewal-hooks/deploy/55-vpn-reality-decoy'

    def stub(self, name, body):
        path = self.root / 'bin' / name
        path.write_text('#!' + sys.executable + '\n' + body)
        path.chmod(0o755)

    def run_script(self, mode='--apply', *, success=True):
        result = subprocess.run(['bash', str(self.script), mode], env=self.env,
                                text=True, capture_output=True, timeout=30)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_prepare_then_checkpoint_loss_recovery_keeps_site_and_snapshot(self):
        self.run_script()
        self.assertTrue((self.marker / 'COMMITTED').is_file())
        self.assertTrue((self.site / 'public/index.html').is_file())
        self.run_script('--check-only')
        self.run_script()
        self.assertEqual(len(list((self.root / 'var/backups').iterdir())), 1)

    def test_payload_failure_rolls_back_only_the_new_resources(self):
        (self.root / 'fail-probe').touch()
        result = self.run_script(success=False)
        self.assertIn('REALITY_DECOY_ROLLBACK_OK=1', result.stderr)
        for path in (self.config, self.marker, self.site, self.hook):
            self.assertFalse(path.exists())
        self.assertEqual(json.loads((self.root / 'state.json').read_text()), {'active': False, 'enabled': 'disabled'})
        with sqlite3.connect(self.root / 'etc/x-ui/x-ui.db') as db:
            self.assertEqual(db.execute('SELECT value FROM original').fetchone(), ('preserved',))

    def test_manage_failure_restores_the_already_running_public_panel(self):
        panel = self.config.with_name('3x-ui-public.conf')
        panel.write_text('# preserved public panel'); panel.chmod(0o600)
        (self.root / 'state.json').write_text(json.dumps({'active': True, 'enabled': 'enabled'}))
        (self.root / 'fail-probe').touch()
        result = self.run_script('--manage-apply', success=False)
        self.assertIn('REALITY_DECOY_ROLLBACK_OK=1', result.stderr)
        self.assertEqual(panel.read_text(), '# preserved public panel')
        self.assertEqual(json.loads((self.root / 'state.json').read_text()), {'active': True, 'enabled': 'enabled'})

    def test_unexpected_nginx_site_is_rejected_before_mutation(self):
        foreign = self.config.with_name('foreign.conf'); foreign.write_text('preserve')
        self.run_script(success=False)
        self.assertEqual(foreign.read_text(), 'preserve')
        self.assertEqual(list((self.root / 'var/backups').iterdir()), [])

    def test_failed_service_stop_retains_owned_resources_and_reports_failed_rollback(self):
        (self.root / 'fail-probe').touch(); (self.root / 'fail-stop').touch()
        result = self.run_script(success=False)
        self.assertIn('REALITY_DECOY_ROLLBACK_RESOURCES_RETAINED=1', result.stderr)
        self.assertIn('REALITY_DECOY_ROLLBACK_OK=0', result.stderr)
        self.assertTrue(self.config.is_file())
        self.assertTrue(self.site.is_dir())

    def test_php_only_upload_can_enable_php_without_loosening_tls_proof(self):
        self.run_script()
        (self.site / 'public/index.html').unlink()
        (self.site / 'public/index.php').write_text('<?php echo "My PHP landing";')
        (self.root / 'php-only-page').touch()
        # Before PHP enable the root page is unavailable, but TLS remains valid.
        self.run_script('--check-only', success=False)
        self.run_script('--enable-php')
        self.assertEqual((self.root / 'php-helper-called').read_text(), 'called')

    def test_php_enable_still_rejects_failed_tls_before_calling_the_php_helper(self):
        self.run_script()
        (self.root / 'fail-probe').touch()
        self.run_script('--enable-php', success=False)
        self.assertFalse((self.root / 'php-helper-called').exists())

    def test_occupied_target_is_rejected_with_a_socket_inventory_larger_than_a_pipe_buffer(self):
        panel = self.config.with_name('3x-ui-public.conf')
        panel.write_text('# preserved public panel'); panel.chmod(0o600)
        (self.root / 'state.json').write_text(json.dumps({'active': True, 'enabled': 'enabled'}))
        (self.root / 'occupied-target').touch()
        (self.root / 'large-socket-inventory').touch()
        result = self.run_script('--manage-apply', success=False)
        self.assertIn('target port is occupied', result.stderr)
        self.assertFalse(self.config.exists())
        self.assertFalse(self.site.exists())
        self.assertEqual(list((self.root / 'var/backups').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
