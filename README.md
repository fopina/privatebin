# PrivateBin CLI

A CLI for PrivateBin allowing easy pasting from the Terminal.

## Installation

Download [latest release](https://github.com/fopina/privatebin/releases/latest)

## Usage

Currently, `pbin` only supports piping inputs:

```shell
$ echo test | pbin
https://privatebin.net/?231effdfe253fb88#FSQ5aE6AwbDoXgB9itjDp8Egf4hf1KDSgsGCh6gyg9X7

$ cat README.md | pbin
https://privatebin.net/?d4d97a693aff2afd#BqRRZ6QrJmbfH8R37cSZVGK3gwh9pfCoo35MjGdk21LW
```

Available options:

```shell
$ pbin -h
Usage of pbin:
  -a, --attach string   attach a file
  -e, --expire string   expiration (default "1week")
  -u, --url string      privatebin host (default "privatebin.net")
  -v, --version         display version
```

Default server used is the official one, [privatebin.net](https://privatebin.net/) but you can specify another one using `--url`

```
echo test | pbin -u cpaste.org
https://cpaste.org/?f1941a91284e2e27#2jGroLY1GEcd2c5SuRP7RREYvPyHA6KoPAdASoDraH32
```

Officially curated list of hosted servers available [here](https://privatebin.info/directory/)

Official server has disabled file attachments but if you pick one that supports them, you can attach files with `--attach`

```shell
$ echo test | pbin -u cpaste.org -a README.md
https://cpaste.org/?a833a657b910f453#4tXc88H9JxDAnFB7BeWwg1gXMT1NaShJVowFGRBziJXo
```

**NOTE**: `cpaste.org` was randomly picked from the list for demo purposes, I do not endorse it in any way. If you plan to use 3rd party servers with the web UI, remember that script injection can leak the client-side encryption key. Due diligence recommended.
