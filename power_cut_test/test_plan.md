# Test Plan

## Power Cut Test Cases:

1. power cut during writing firmware
2. power cut during reading firmware

## How to run power cut test:

```
power_cut_test/setup_dependencies.sh
mbed compile -t GCC_ARM -m K64F
mbedgt --test-spec power_cut_test/test_spec.json -e power_cut_test/host_tests/ -v -V
```
