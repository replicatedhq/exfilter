# Installation

## Download and install latest version of Go.
```wget https://go.dev/dl/go1.17.5.linux-amd64.tar.gz```

```sudo rm -rf /usr/local/go && tar -C /usr/local -xzf go1.17.5.linux-amd64.tar.gz```
## Install build essentials
```sudo apt update```

```sudo apt install build-essential```

## Install latest version of libbcc
While there are release versions available, it's recommended to build bcc from source.
### Install build dependencies
```sudo apt install -y bison build-essential cmake flex git libedit-dev libllvm7 llvm-7-dev libclang-7-dev python zlib1g-dev libelf-dev libfl-dev python3-distutils ```

### Install and compile bcc
```git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd 
```

## Install exfilter
```git clone https://github.com/replicatedhq/exfilter.git```


# Testing
```cd exfilter/pkg/cmd```

Start the local agent.

```go run example/main.go```

It loads the rules from the example.rules file and logs the events that matches the rules to the exfilter.log file. Any changes to the rules file will take effect after agent restarts. The agent currently captures all tcp egress events and ssl_write events. For https, it tries to find corresponding encrypted payload and replace it with plain text based on PID and timestamp.
