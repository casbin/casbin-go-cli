# casbin-go-cli

[![Go Report Card](https://goreportcard.com/badge/github.com/casbin/casbin-go-cli)](https://goreportcard.com/report/github.com/casbin/casbin-go-cli)
[![Build](https://github.com/casbin/casbin-go-cli/actions/workflows/build.yml/badge.svg)](https://github.com/casbin/casbin-go-cli/actions/workflows/build.yml)
[![Coverage Status](https://coveralls.io/repos/github/casbin/casbin-go-cli/badge.svg?branch=master)](https://coveralls.io/github/casbin/casbin-go-cli?branch=master)
[![Godoc](https://godoc.org/github.com/casbin/casbin-go-cli?status.svg)](https://pkg.go.dev/github.com/casbin/casbin-go-cli)
[![Release](https://img.shields.io/github/release/casbin/casbin-go-cli.svg)](https://github.com/casbin/casbin-go-cli/releases/latest)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)

casbin-go-cli is a command-line tool based on Casbin (Go language), enabling you to use all of Casbin APIs in the shell.

## Installation

1. Clone project from repository

```shell
git clone https://github.com/casbin/casbin-go-cli.git
```

2. Build project

```shell
cd casbin-go-cli
go build -o casbin
```

## Options
| options        | description                                  | must |                    
|----------------|----------------------------------------------|------|
| `-m, --model`  | The path of the model file or model text     | y    |
| `-p, --policy` | The path of the policy file or policy text   | y    |  
| `enforce`      | Check permissions                            | n    |
| `enforceEx`    | Check permissions and get which policy it is | n    |

## Get started

- Check whether Alice has read permission on data1

    ```shell
    ./casbin enforce -m "test/basic_model.conf" -p "test/basic_policy.csv" "alice" "data1" "read"
    ```
    > {"allow":true,"explain":[]}

- Check whether Alice has write permission for data1 (with explanation)

    ```shell
    ./casbin enforceEx -m "test/basic_model.conf" -p "test/basic_policy.csv" "alice" "data1" "write"
    ```
    > {"allow":false,"explain":[]}

- Check whether Alice has read permission on data1 in domain1 (with explanation)

    ```shell
    ./casbin enforceEx -m "test/rbac_with_domains_model.conf" -p "test/rbac_with_domains_policy.csv" "alice" "domain1" "data1" "read"
    ```
    > {"allow":true,"explain":["admin","domain1","data1","read"]}
