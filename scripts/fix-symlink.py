"""Walks through the given directory and fixes symlinks.

This repository relies a lot on symlinks to compile different
versions of the schemes and to link shared source around. This
can be broken by various git exports. The goal of this script
is to identify files which previously were linux symlinks (the
content of the file is a single line with the target path) and
rebuild the symlink.

Typical usage:
    
    python3 ./scripts/fix-symlinks.py -d ./mupq

"""
import argparse
import pathlib
import re
import sys

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-d", "--directory", help="Directory to run in, default CWD.", default=".")
    parser.add_argument("-p", "--pattern", help="Only fix symlink files that match this pattern. Default '.*\\.[ch]'", default=r".*\.[ch]$")

    args = parser.parse_args()
    pat = args.pattern
    cwd = pathlib.Path(args.directory)

    for dir, _, files in cwd.walk():
        for file in files:
            f_path = dir / file
            if re.match(pat, file):
                lines = []
                with open(f_path, "r") as f:
                    lines = f.readlines()
                if len(lines) == 1 and not f_path.is_symlink():
                    dest = (dir / pathlib.Path(lines[0])).resolve()
                    if dest.exists():
                        # Destination exists and is not a symlink, fix
                        print(file, ": ", dest)
                        f_path.unlink()
                        f_path.symlink_to(dest)

if __name__ == "__main__":
    main()
