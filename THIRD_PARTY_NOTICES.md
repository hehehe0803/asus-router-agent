# Third-party notices

The MIT license applies to this project's original work. Dependencies and derived
source contracts keep their respective licenses; MIT does not relicense them.

## AsusRouter 1.21.3

Source: https://github.com/Vaskivskyi/asusrouter/tree/1.21.3
Copyright Yevhenii Vaskivskyi. Licensed under Apache License 2.0.
The pinned package supplies router protocol handling. The project also derives
selected protocol field maps, serialization behavior and source inventories from
that source. Source contracts and references are retained in packaged metadata.
The upstream Apache license and NOTICE are reproduced under
`third_party/asusrouter/`. No installed upstream package is forked or modified.
Local guards, selected output and orchestration are separate project code.

## Other runtime dependencies

- aiohttp 3.14.5: Apache License 2.0; https://github.com/aio-libs/aiohttp
- keyring 25.x: MIT License; https://github.com/jaraco/keyring

Dependencies are installed as separate distributions and ship their own notices,
including notices for transitive/vendored components. Development tools such as
pytest and tiktoken are optional, separately distributed dependencies. This source
export does not redistribute their package code. Consult each installed package's
metadata and license files for its exact version and transitive terms.
