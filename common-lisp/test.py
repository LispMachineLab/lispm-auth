#!/usr/bin/env python3
"""Exercise the Common Lisp service using public compatibility vectors."""
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SERVICE = os.environ.get('LISPM_AUTH_SERVICE', str(ROOT.parent / 'build' / 'lispm-auth-service'))


def call(op, *args):
    p = subprocess.run(
        [SERVICE],
        input='\t'.join((op, *args)) + '\n', text=True,
        capture_output=True, timeout=30, check=True)
    assert not p.stderr, 'unexpected service stderr'
    return p.stdout.rstrip('\n')


def ok(result):
    assert result.startswith('ok\t'), result
    return result[3:]


def main():
    key = ok(call('random'))
    assert len(key) == 64 and key != ok(call('random'))
    pw = 'correct horse ☃'.encode().hex()
    identifier = 'id\0☃'.encode().hex()
    message = b'\x00secret\xff\n'.hex()
    wrapped_fixture = '4c415701d8b8e7d8492488838ee7dbcb588f3238b4463b89eeb65303c1177392ee6417f97a50977af5d3530a4c1314bc745e4d3f279c86667684d70bc4f6c94e156bfefdb6a389cb09b60a84bb3aefb2c9b91fcbf6e1d515751b6d60'
    item_fixture = '4c414901bee6c686a567731adfbdd0f7919c6399156b95342c911b8d526ccb8d9b190d5ca13421a386b822cbf8ec3ed2a4fd'
    assert ok(call('unwrap', wrapped_fixture, '70617373776f7264')) == '00' * 32
    assert ok(call('decrypt', '00' * 32, '6964', item_fixture)) == '736563726574'
    wrapped = ok(call('wrap', key, pw))
    assert len(wrapped) == 184 and wrapped.startswith('4c415701')
    assert ok(call('unwrap', wrapped, pw)) == key
    assert call('unwrap', wrapped, '77726f6e67') == 'error\tauth'
    for index in (0, 10, 45, 100, 182):
        bad = wrapped[:index] + ('0' if wrapped[index] != '0' else '1') + wrapped[index+1:]
        assert call('unwrap', bad, pw) == ('error\tinvalid' if index == 0 else 'error\tauth')
    assert call('unwrap', wrapped + '00', pw) == 'error\tinvalid'
    for msg in ('', message):
        encrypted = ok(call('encrypt', key, identifier, msg))
        assert encrypted.startswith('4c414901')
        assert ok(call('decrypt', key, identifier, encrypted)) == msg
        assert call('decrypt', key, '', encrypted) == 'error\tauth'
        altered = encrypted[:-2] + ('00' if encrypted[-2:] != '00' else '01')
        assert call('decrypt', key, identifier, altered) == 'error\tauth'
    for args in [('random', '00'), ('wrap', '00', ''), ('decrypt', key, '', ''),
                 ('encrypt', key, '', 'z0'), ('encrypt', key, '', '0')]:
        assert call(*args) == 'error\tinvalid'
    print('Common Lisp fixed vectors, round trips and negative cases passed')


if __name__ == '__main__':
    main()
