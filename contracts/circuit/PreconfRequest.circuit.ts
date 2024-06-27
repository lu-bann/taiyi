import { addToCallback, CircuitValue, CircuitValue256, constant, sub, getTx } from '@axiom-crypto/client';

export const defaultInputs = {
  "tipTxGasLimit": 100000,
  "tipTxFrom": "0x8018fe32fCFd3d166E8b4c4E37105318A84BA11c",
  "tipTxTo": "0x8018fe32fCFd3d166E8b4c4E37105318A84BA11c",
  "tipTxPrePay": 100000,
  "tipTxAfterPay": 200000,
  "tipTxNonce": 1,
  "preconfConditionsStartingBlockNumber": 10,
  "preconfConditionsTxCount": 1,
  "preconfConditionsIndex": 0,
  "PreconfConditionsBlockNumber": 20,
  "preconfTxTo": "0x8018fe32fCFd3d166E8b4c4E37105318A84BA11c",
  "preconfTxValue": 10,
  "preconfTxCallData": "0x8018fe32fCFd3d166E8b4c4E37105318A84BA11c",
  "preconfTxEthTransfer": 1,
  "tipTxSignature": "0x000",
  "initSignature": "0x000",
  "preconferSignature": "0x000"
};

export interface CircuitInputs {
  tipTxGasLimit: CircuitValue256;
  tipTxFrom: CircuitValue;
  tipTxTo: CircuitValue;
  tipTxPrePay: CircuitValue256;
  tipTxAfterPay: CircuitValue256;
  tipTxNonce: CircuitValue256;
  preconfConditionsStartingBlockNumber: CircuitValue256;
  preconfConditionsTxCount: CircuitValue256;
  preconfConditionsIndex: CircuitValue256;
  PreconfConditionsBlockNumber: CircuitValue256;
  preconfTxTo: CircuitValue;
  preconfTxValue: CircuitValue256;
  preconfTxCallData: CircuitValue;
  preconfTxEthTransfer: CircuitValue;
  tipTxSignature: CircuitValue256;
  initSignature: CircuitValue256;
  preconferSignature: CircuitValue256;
}


export const circuit = async (inputs: CircuitInputs) => {

    /*//////////////////////////////////////////////////////
                          INPUTS
    //////////////////////////////////////////////////////*/
    const gasLimit: CircuitValue256 = inputs.tipTxGasLimit;
    const from: CircuitValue = inputs.tipTxFrom;
    const to: CircuitValue = inputs.tipTxTo;
    const prePay: CircuitValue256 = inputs.tipTxPrePay;
    const afterPay: CircuitValue256 = inputs.tipTxAfterPay;
    const nonce: CircuitValue256 = inputs.tipTxNonce;

    const startingBlockNumber: CircuitValue256 = inputs.preconfConditionsStartingBlockNumber;
    const txCount: CircuitValue256 = inputs.preconfConditionsTxCount;
    const index: CircuitValue256 = inputs.preconfConditionsIndex;
    const blockNumber: CircuitValue256 =inputs.PreconfConditionsBlockNumber;

    const preconfTxTo: CircuitValue = inputs.preconfTxTo;
    const preconfValue: CircuitValue256 = inputs.preconfTxValue;
    const callData: CircuitValue = inputs.preconfTxCallData;
    const ethTransfer: CircuitValue = inputs.preconfTxEthTransfer;

    const initSignature: CircuitValue256 = inputs.initSignature;
    const preconferSig: CircuitValue256 = inputs.preconferSignature;

    /*//////////////////////////////////////////////////////
                          OUTPUTS
    //////////////////////////////////////////////////////*/


    // TipTx
    // index: 0
    addToCallback(gasLimit);
    // index: 1
    addToCallback(from);
    // index: 2
    addToCallback(to);
    // index: 3
    addToCallback(prePay);
    // index: 4
    addToCallback(afterPay);
    // index: 5
    addToCallback(nonce);

    // PreconConditions
    // index: 6
    addToCallback(startingBlockNumber);
    // index: 7
    addToCallback(txCount);
    // index: 8
    addToCallback(index);
    // index: 9
    addToCallback(blockNumber);

    // PreconfTx 
    // index: 10
    addToCallback(preconfTxTo);
    // index: 11
    addToCallback(preconfValue);
    // index: 12
    addToCallback(callData);
    // index: 13
    addToCallback(ethTransfer);

    // Signatures
    // index: 14
    addToCallback(initSignature);
    // index: 15
    addToCallback(preconferSig);

    // Output
    if(index.toCircuitValue().number() !== 0) {
      // index starts at 1 as 0 indicates no ordering requested
      // but when querying the block number, we need to subtract 1 
      // since index starts at 0
      const blockIndex: CircuitValue = sub(index.toCircuitValue().number(), 1);
      const tx = getTx(blockNumber.toCircuitValue(), blockIndex);
      // index: 16
      addToCallback(await tx.to());
      // index: 17
      addToCallback(await tx.functionSelector());
    } else {
      // If no ordering requested, return 0
      // index: 16
      addToCallback(constant(0).toCircuitValue256());
      // index: 17
      addToCallback(constant(0).toCircuitValue256());
    }
};
