# ldk-node-sample
Sample lightning node command-line app built on top of [Ldk Node](https://github.com/lightningdevkit/ldk-node)


## Installation
```
git clone https://github.com/optout21/ldk-node-sample
```

## Usage
```
cd ldk-node-sample
cargo run [<datadir>] [<listening_port>] [<network>]
```

`datadir` is a subfolder for keeping state, defaults to `datadir`

`listening-port`: defaults to 9735.

`network`: default is testnet, one of: testnet, mainnet, signet, regtest.


For the interactive commands, type `help`.


## TODO
- Move parsing etc. utils to separate .rs
- Proper exit
- Add args for btc node/service


## License

Licensed under either:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
