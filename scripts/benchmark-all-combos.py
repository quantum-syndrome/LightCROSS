import itertools
import pathlib
import re
import subprocess

PARAM_F = "../mupq/crypto_sign/crossv2.0-sha3-r-sdp-1-small/light/parameters.h"
PARAM_R = r'\/* *\#define *(OPT_\w*)\s*$'
#OPTS = ["OPT_KEYGEN", "OPT_MERKLE", "OPT_HASH_CMT1", "OPT_HASH_Y", "OPT_V_BAR", "OPT_E_BAR_PRIME", "OPT_OTF_MERKLE", "OPT_GGM", "OPT_DSP", "OPT_Y_U_OVERLAP", "OPT_KEYGEN_BLOCKS"]
OPTS = ["OPT_GGM", "OPT_DSP", "OPT_Y_U_OVERLAP", "OPT_KEYGEN_BLOCKS"]


def main():
    script_dir = pathlib.Path(__file__).parent
    # Load the parameters file
    param_file = script_dir / pathlib.Path(PARAM_F)
    # Build regex opt line matcher
    pattern = re.compile(PARAM_R)
    opt_lines = {}
    # Read parameter file
    with open(param_file, "r") as f:
        orig_param_file_lines = f.readlines()
    param_file_lines = []
    # Find the optimisation lines
    for i,line in enumerate(orig_param_file_lines):
        m = pattern.fullmatch(line)
        if m is not None:
            opt = m.group(1)
            opt_lines[opt] = i
            param_file_lines.append(f"// #define {opt}\n")
        else:
            param_file_lines.append(line)

    # Clean compilation (allow fail)
    subprocess.run(["make", f"--directory={script_dir.parent}", "clean"])

    for combo in itertools.combinations(OPTS, 1):
        # Set optimisations on
        for opt in combo:
            param_file_lines[opt_lines[opt]] = f"#define {opt}\n"
        # Write to param file
        with open(param_file, "w") as f:
            f.write("".join(param_file_lines))
        # Benchmark
        subprocess.run([str(script_dir / "benchmark.sh")], check=True)
        # Save results
        results = subprocess.run([str(script_dir.parent / "convert_benchmarks.py"), "csv",], check=True, capture_output=True).stdout
        with open(f"{script_dir.parent / "results"}/benchmark_{'_'.join(combo)}.csv", "w") as f:
            f.write(results.decode('utf-8'))
        # Set optimisations off
        for opt in combo:
            param_file_lines[opt_lines[opt]] = f"// #define {opt}\n"
        # Clean compilation
        subprocess.run(["make", f"--directory={script_dir.parent}", "clean"], check=True)


    # Restore original parameter file
    with open(param_file, "w") as f:
        f.write("".join(orig_param_file_lines))


if __name__ == "__main__":
    main()
