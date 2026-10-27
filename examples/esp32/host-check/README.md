# Host checks for the ESP32 status API

Builds `../src/api.rs` and `../src/api_model.rs` on the host, with the device-only
crates replaced by stubs (`stubs/`). `yggdrasil-lite` is the real crate.
Runs the JSON tests with `serde_json`. Needs no ESP toolchain or hardware.

```sh
cd examples/esp32/host-check
cargo test          # JSON model tests (incl. serde_json validation)
cargo run -q        # type-checks the device hooks and prints a stats response
```

Note: this checks types and logic, not the firmware itself. Build the firmware
with the ESP toolchain (see `../README.md`).
