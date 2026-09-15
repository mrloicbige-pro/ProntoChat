# chat

Terminal P2P encrypted messenger in C.

See [spec.md](spec.md) for the project specification and implementation order.

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

Development build with sanitizers:

```bash
cmake -S . -B build-asan -DCHAT_ENABLE_SANITIZERS=ON
cmake --build build-asan
ctest --test-dir build-asan
```
