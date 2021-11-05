# tcpparser
A Python /proc/net/tcp parser with something else

**tcpparser** is Linux utility that reades and parsers the `/proc/net/tcp` continuously in a certain period of time (each 10 seconds) looking for threads and blocking it automatically.
 those source IPs that have more than 3 established connections in different ports to the host where **tcpparser** is running.

**NOTE:** This automation is just for educational purpose and shouldn't be used on production or as a replacement of other Linux tools to show current open sockets in your machine.

# Demo

```
tcpparser starting...

2021-11-01 21:11:53:     New connection:  206.11.237.209:52239 -> 172.31.59.87:22
2021-11-01 21:11:53:     New connection:  206.11.237.209:57588 -> 172.31.59.87:22
2021-11-01 21:11:53:     New connection:   172.31.63.176:50368 -> 172.31.59.87:22
2021-11-01 21:11:53:     New connection:     99.84.191.103:443 <- 172.31.59.87:37474
```
At the first 10 seconds everything looks good
```
2021-11-01 21:12:03:     New connection:   172.31.63.176:53804 -> 172.31.59.87:445
2021-11-01 21:12:03:     New connection:  206.11.237.209:52239 -> 172.31.59.87:22
2021-11-01 21:12:03:     New connection:   172.31.63.176:55656 -> 172.31.59.87:80
2021-11-01 21:12:03:     New connection:  206.11.237.209:57588 -> 172.31.59.87:22
2021-11-01 21:12:03:     New connection:   172.31.63.176:50368 -> 172.31.59.87:22
```
Something is up. `172.31.63.176` now is connected on other 2 ports (445 and 80)
```
2021-11-01 21:12:13:     New connection:   172.31.63.176:53804 -> 172.31.59.87:445
2021-11-01 21:12:13:     New connection:  206.11.237.209:52239 -> 172.31.59.87:22
2021-11-01 21:12:13:     New connection:   172.31.63.176:55656 -> 172.31.59.87:80
2021-11-01 21:12:13:     New connection:  206.11.237.209:57588 -> 172.31.59.87:22
2021-11-01 21:12:13:     New connection:   172.31.63.176:50368 -> 172.31.59.87:22
2021-11-01 21:12:13:     New connection:   172.31.63.176:51900 -> 172.31.59.87:25
2021-11-01 21:12:13: Port scan detected:         172.31.63.176 -> 172.31.59.87 on ports 80,25,445,22
```
Very suspicious eh? In the last 30 seconds `172.31.63.176` connected on 4 ports.  **tcpparser** tread that as port scan and block that ip immediately using *iptables* as we can see bellow:
```
iptables -L -n
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
DROP       all  --  172.31.63.176        0.0.0.0/0
```
After that, everything looks good again
```
2021-11-01 21:12:23:     New connection:  206.11.237.209:52239 -> 172.31.59.87:22
2021-11-01 21:12:23:     New connection:  206.11.237.209:57588 -> 172.31.59.87:22
2021-11-01 21:12:33:     New connection:  206.11.237.209:52239 -> 172.31.59.87:22
2021-11-01 21:12:33:     New connection:  206.11.237.209:57588 -> 172.31.59.87:22
2021-11-01 21:12:43:     New connection:  206.11.237.209:52239 -> 172.31.59.87:22
2021-11-01 21:12:43:     New connection:  206.11.237.209:57588 -> 172.31.59.87:22
2021-11-01 21:12:53:     New connection:  206.11.237.209:52239 -> 172.31.59.87:22
2021-11-01 21:12:53:     New connection:  206.11.237.209:57588 -> 172.31.59.87:22
```

# Features

Sure it has features:

 - Simplest command line usage. No arguments is necessary.
 - It parses the annoying `/proc/net/tcp` and shows only the what really matter in a friendly way
 - No action required. **tcpparser** detects the thread and blocks it automatically
 - Connection count metrics are exposed on http://localhost:3021/. Configure you prometheus to scrape the metrics from that endpoint
 - Easy installation using `pip`
 - Don't wanna to install in your machine. Don't worry, **tcpparser** is containerized using Docker

# Installation

## Using docker

It's highly recommend to use docker to run **tcpparser**. It isolates your system having the same features as it was running on the host machine.
To install using docker, first clone tcpparser repository:
```
git clone https://github.com/brunocriado/tcpparser.git
```
Go inside the directory and build a new docker image
```
cd tcpparser
docker build . -t tcpparser
```
To run the new container:
```
docker run --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW -ti tcpparser
```

 - `--net=host`: will allow tcpparser to reads the `/proc/net/tcp` from the host machine
 - `--cap-add=NET_ADMIN --cap-add=NET_RAW`: will allow `iptables` running on docker container to do changes on the host `iptables`

## Using pip

Yeah, we have **tcpparser** available on pip as well.
Friendly reminder, to avoid any problem, install and execute **tcpparser** as *root* user
To install:
```
sudo python3 -m pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ tcpparser
```
To run:
```
sudo tcpparser
```
**NOTE:** This current version of tcpparser was tested only on Python 3.8.10

# Running without installation of the package
If you want to run it without install the package, just clone this repository and the dependencies:
```
git clone https://github.com/brunocriado/tcpparser.git
cd tcpparser
pip install -r requirements.txt
```
And then you can run it:
```
sudo python3 tcpparser-runner.py
```
If you intend to run the tests:
```
tox
```
To build a package:
```
tox -e build
```
