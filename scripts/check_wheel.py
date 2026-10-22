"""Credential-free build verification; never imports authentication or transport."""
from pathlib import Path
import json
import zipfile

wheel, = Path('dist').glob('*.whl')
with zipfile.ZipFile(wheel) as archive:
    names = set(archive.namelist())
    for filename in ('catalog.json', 'native_audit.json', 'expansion_2026_10_15.json', 'webui_operations_v1.json'):
        json.loads(archive.read('router_agent/data/' + filename))
    metadata_name, = (name for name in names if name.endswith('.dist-info/METADATA'))
    metadata = archive.read(metadata_name).decode()
    assert 'License-Expression: MIT' in metadata
    assert 'Requires-Dist: asusrouter==1.21.3' in metadata
    assert any(name.endswith('/licenses/LICENSE') for name in names)
print('Wheel JSON data and MIT/pinned-dependency metadata verified.')
