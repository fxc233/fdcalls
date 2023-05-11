# fdcalls

**author: fxc**

## Version

latest: v1.3

## Introduction

**fdcalls** purpose is to help security researchers view dangerous function calls across files.

Due to my rushed writing time, there may be many bugs in it.

Welcome to provide suggestions.

## Usage

```shell
fdcalls -b [path/to/target_binary] -d [path/to/file_system_dir] -l [level=0]
```

## Setup

first choice，but it may be an old version

```shell
pip install fdcalls
```

second choice

```shell
git clone https://github.com/fxc233/fdcalls
cd fdcalls
sudo python3 setup.py install
```

## Results

![1](./img/1.png)

## Contact

FXC030618@outlook.com

## Related articles

[https://www.cnblogs.com/pwnfeifei/p/17369551.html](https://www.cnblogs.com/pwnfeifei/p/17369551.html)

## License

[GNU General Public License v3.0](https://github.com/fxc233/fdcalls/blob/main/LICENSE)