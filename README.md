# Taiyi(太一) - an Ethereum L1 Preconfirmation Protocol


![image](https://github.com/user-attachments/assets/83a56bc0-da7f-45ef-8833-c0931cb01130)

Taiyi (太一) is Luban’s solution for Ethereum L1 preconfirmation. To learn more about Taiyi refer our docs [here](https://docs.luban.wtf/taiyi_overview).


### For Validators

Please refer node operator guide in our [docs](https://docs.luban.wtf/node_operator_setup_guide/holesky/overview).

### For Users

Please refer technical docs(TBA).

### Building and testing

Prerequisites:
- The Minimum Supported Rust Version (MSRV) of this project is 1.85.0.
- Docker engine installed and running
- Foundry
- [Kurtosis](https://docs.kurtosis.com/install)

We've a suite of e2e-tests which can be run by

First, clone the repository:

```sh
git clone https://github.com/lu-bann/taiyi
cd taiyi
```


Next, run the e2e tests:

```sh
make e2e
```

Stopping and cleaning the devnet resources:
```sh
make e2e-clean
```

### Contributing

If you want to contribute our contributor guidelines can be found in [`CONTRIBUTING.md`](./CONTRIBUTING.md).