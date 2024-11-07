#!/usr/bin/python3

import argparse

# Generate The GoDroplets
def generateGoDroplets(path: str, arg: str, format: str):
    # TODO
    pass

def main():
    parser = argparse.ArgumentParser(description="Generate the Go droplets given a binary.")
    parser.add_argument("--path", type=str, required=True, help="Path to the binary to be wrapped to create the Go dropper")
    parser.add_argument("--arg", type=str, required=True, help="Argument that are needed for the binary")
    parser.add_argument("--format",
                        choices=["exe", "svc", "dll", "all"],
                        required=True,
                        type=str,
                        help="Format of the droplet, can be exe, svc, dll or all of the above")
    args = parser.parse_args()
    path = args.path
    arg = args.arg
    format = args.format

    print(path, arg, format)

if __name__ == "__main__":
    main()
