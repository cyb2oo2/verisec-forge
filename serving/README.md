# Serving

Serving is exposed through:

- `vrf serve --config configs\serving_mock.json`
- `vrf serve-once --config configs\serving_mock.json --prompt "..."`

The online and offline flows share the same generation schema to reduce parser drift.
