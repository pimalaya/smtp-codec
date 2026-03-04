# Welcome to smtp-codec's (and smtp-types') contributing guide

Thanks for investing your time to help with this project! Keep in mind that this project is driven by volunteers. Be patient and polite, and empower others to improve. Always use your best judgment and be excellent to each other.

## Principles

### Misuse resistance

We use strong-typing to eliminate invalid state.
Ask yourself: Can I instantiate a type with an invalid variable setting?
If yes, consider how to eliminate it.
If you're unsure, let's figure it out together!

## Project management

We use the [just](https://github.com/casey/just) command runner for Continuous Integration (CI).
The GitHub Actions infrastructure merely calls `just` to execute jobs.
This means that you can run all required tests for a PR using `just ci`.

### Code formatting

Please ensure that all code is formatted using `cargo +nightly fmt`.

### Testing

Run tests with `cargo test --all-features`.

## License

By contributing to this project, you agree to license your contributions under the same license as the project (MIT OR Apache-2.0).
