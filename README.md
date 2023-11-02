# Yggdrasil-rs

[![Build status](https://github.com/arrza/yggdrasil-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/rust/yggdrasil-rs/actions/workflows/rust.yml)

## Introduction

Yggdrasil-rs is a Rust implementation of [Yggdrasil](https://github.com/yggdrasil-network/yggdrasil-go), providing a fully end-to-end encrypted IPv6 network. It retains the features of the original Yggdrasil project while taking advantage of Rust's performance benefits. Currently, it aims for compatibility with version 0.4.7 of the original Yggdrasil project.

## Supported Platforms

Yggdrasil-rs is currently being developed for Linux.

## Building

To build Yggdrasil-rs from source, follow these steps:

1. Install Rust.
2. Clone this repository.
3. Run `cargo build --release`.

## Usage

### Generate Configuration

To generate a configuration, use the following command:

```
yggdrasil-rs --genconf > /path/to/yggdrasil.conf
```

### Run Yggdrasil-rs

You can run Yggdrasil-rs using the generated configuration:

```
yggdrasil-rs --useconffile /path/to/yggdrasil.conf
```

### Admin API

To access the Admin API, use the original "yggdrasilctl" command:

```
yggdrasilctl -endpoint=tcp://[::1]:9001 getself
```