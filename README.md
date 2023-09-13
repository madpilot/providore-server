# Providore

Providore is a simple, yet secure IoT provisioning system for your home IoT network. It runs over HTTP and HTTPS.

See [https://github.com/madpilot/providore](https://github.com/madpilot/providore) for the main project

## Requirements

Node 14+

## Getting started

Providore runs from the command line, so you will need to install it globally.

`npm -g install providore`

### Docker

`docker start madpilot/providore:latest -v /path/to/config:/config -v /path/to/devices:/devices -v /path/to/tls:/tls -v /path/to/ca:/ca -p 3000:3000`

## Running

## Configuring devices
