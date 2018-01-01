## pepatch

A hacky tool for patching PE format binaries.

## Examples

Please take a look at the files under example/

## Dependencies

* For pypi packages: See `requirements.txt`. Use this command to install all the dependencies:

```
pip install -r requirements.txt
```
* [pefile](https://github.com/erocarrera/pefile): This project contains a slightly modified version of `pefile` module for better usage.

## Few notes

* The idea comes from [patchkit](https://github.com/lunixbochs/patchkit) after I found this fascinating small tool.
* More features will be added in future.
* This project is not thoroughly tested, and as you know, patching PE files can sometimes be clumsy and error-prone, so **ALWAYS** keep a copy of backup before applying any patch to the binary.

