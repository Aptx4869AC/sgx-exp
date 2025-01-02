# SGX-EXP
SGX代码的简单示例

## :memo: 文件概览

- #### YES_or_NO_of_SGX/
    - 检查本机是否支持 SGX ，需要提前在 BIOS 打开

- #### bls_v1_test/
  - BLS 签名在 Enclave 中执行的可扩展版本，借助 ECall 实现 REE 与 TEE 调度环节

- #### bls_v2_test/
  - BLS 签名在 Enclave 中执行，最简单版本

- #### addTwo_test/
  - 两数相加

- #### mcl_test/
  - 仅支持 `make SGX_MODE=SIM` 模式，如果能启用 `SGX-MCL` ，**那将会是大突破**
