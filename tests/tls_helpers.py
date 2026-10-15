"""Ephemeral synthetic localhost certificates; never real router material."""
from contextlib import contextmanager
from pathlib import Path
import ssl
import subprocess
from tempfile import TemporaryDirectory


@contextmanager
def localhost_tls(*, san='IP:127.0.0.1,DNS:localhost'):
    with TemporaryDirectory(prefix='router-test-tls-') as directory:
        cert = Path(directory) / 'ca.pem'
        key = Path(directory) / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=synthetic-localhost', '-addext', f'subjectAltName={san}'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        yield context, str(cert)
