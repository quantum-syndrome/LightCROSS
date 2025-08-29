# LightCROSS

## Overview

An efficient and memory optimised implementation of the CROSS signature scheme. This repository is a fork of the
[pqm4 library](https://github.com/mupq/pqm4) with just the optimised CROSSv2.1 implementations included in `crypto_sign` and `mupq/crypto_sign`. 
The code in the `crypto_sign` and `mupq/crypto_sign` is exactly the same, the only difference is in the 
`crypto_sign/crossv2.0-sha3-r-sdp-1-small/light/parameters.h` the `OPT_DSP` flag is turned off for the `mupq/crypto_sign` variant to prevent it being platform specific. Thus the `mupq/crypto_sign` implementations are generic C optimisations, whereas the `crypto_sign` implementation is M4 specific.

This implementation achieves the following improvements over the reference:

**Memory:**
- Key Generation: 58-95\% Smaller
- Signing: 48-60\% Smaller
- Verifying: 62-77\% Smaller

**Speed:**
- Key Generation: 22-33\% Slower
- Signing: 0-24\% Faster
- Verifying: 2-33\% Faster

Note the speed measurements are *with* the DSP optimisations. The optimisations
can be customised by turning various compiler flags in the `parameters.h` file on or off.

## Instructions

Note: All of the scripts were written and run with python-3.12.11. Some parts of the
scripts require features only available in python-3.12 or later. Please check your
python version if you have any errors.

### Benchmarking

1. Activate the python environment defined by `requirements.txt`, can be done with:
  ```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
2. Connect the nucleo-l4r5zi board to your computer
3. Verify the serial connection, check which port it is on (e.g. `/dev/ttyACM0`)
4. Run `./scripts/benchmark.sh`.
  N.B. If it is not correctly connecting to the serial port with the device, make sure to check `/dev/ttyACM0` is correct (and adjust in the script if not)
5. Run `python3 ./convert_benchmarks.py csv > results/<result_file_name>.csv`
6. Run `python3 ./results/process-data.py -f ./results/<result_file_name>.csv`

#### Debugging Benchmarking

`serial.serialutil.SerialException: [Errno 2] could not open port /dev/ttyACM<number>`:
  This means that the board is not connected at the expected port. Please check that the
  correct port is in the script and it matches the one that the board shows up on your
  computer.

Lots of `Permission denied` errors:
  This can happen when trying to compile from a zip file. The easiest way to deal with this
  is by just setting user permissions on everything, `sudo chmod u+rwx -R .`.

Compilation error `expected identifier or '(' before '.' token`:
  Especially if it shows what look like relative paths in the error body. This means
  that the symlinks are broken in the repository. Usually it will be in two places the
  `mupq/crypto_sign` and `crypto_sign` directories. Run 
  `python3 ./scripts/fix-symlink.py -d ./mupq/crypto_sign` and 
  `python3 ./scripts/fix-symlink.py -d ./crypto_sign`
  and check if that has repaired the symlinks. Unsure if this works on Windows.
