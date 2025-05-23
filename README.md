
PoC to read partial coredump.
It works only for ARM 32 bits for now.

# Usage
```
Read partial coredump (Proof of Concept). (it works only for ARM 32bits, for now)

Usage: readcore [OPTIONS] <CORE>

Arguments:
  <CORE>  Coredump file

Options:
  -a, --address <ADDRESS>        Address to be printed
  -s, --stagingdir <STAGINGDIR>  Staging directory
  -h, --help                     Print help
  -V, --version                  Print version
```
