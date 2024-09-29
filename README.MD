# TC_TEA: Tencent modified TEA algorithm

Provides 2 classes:

- `ECB` (insecure)
    - ref: `TeaEncryptECB` / `TeaDecryptECB`
- `CBC`
    - ref: `oi_symmetry_encrypt2` / `oi_symmetry_decrypt2`

Also exposes the following convenience methods:

- CBC mode:
    - `encrypt` - also its alias [`oi_symmetry_encrypt2`] (returns new buffer).
    - `decrypt` - also its alias [`oi_symmetry_decrypt2`] (returns new buffer, can throw error).
- ECB mode (insecure):
    - `TeaEncryptECB`
    - `TeaDecryptECB`

## License

MIT License

[`oi_symmetry_encrypt2`]: https://github.com/TarsCloud/TarsCpp/blob/v3.0.20/util/src/tc_tea.cpp#L172

[`oi_symmetry_decrypt2`]: https://github.com/TarsCloud/TarsCpp/blob/v3.0.20/util/src/tc_tea.cpp#L23
