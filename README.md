# Scanport Detector

A simple tool to detect port scans on servers. 

It's able to detect simple port scans and distribute the information to other servers if a Redis server is available.

For educational purposes only and to learn packet capture using GoLang.

WIP! A lot of refactoring is needed.

## Instalation

To compile and run in Linux you must install the PCap development library first:
```
apt install libpcap-dev
```
Then rename "config.yml.example" to "config.yml" and modify.

Finally run:

```
go run main.go
```

## Config

Information loaded from config.yml:

- device: local network device 
- ip: specific local ip to watch
- portrange: only scan this range of local ports
- portignore: don't care this common ports

## To Do:
- Detect more advanced features of Nmap's port scanning.
- Run commands on detect port scanning: iptables, firewall,etc
- Ingest data into a SIEM (Security Information and Event Management) systems.
- Better documentation :p
