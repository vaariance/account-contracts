// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import "account-abstraction/interfaces/PackedUserOperation.sol";
import "account-abstraction/core/EntryPointSimulations.sol";

contract DebugScript is Script {
  function run() external {
    PackedUserOperation memory userOp = PackedUserOperation({
      sender: 0xdf9950701Ba33FC8e6C6be0414F6c61dD35EbF0F,
      nonce: 0x0,
      initCode: "0x690832791538ff4dd15407817b0dac54456631bce2bb0bd211443c760977081fa9e927b08cab268f6e6783621f2a40102d8cc586e6dee3bcf5dee907a9f28e50eab51b699ff6becf2783fa5f6cf0d83186e6c8a29f84e7a66e5794995bfe01a6166731db5de6caf5a9cf232364cb816ac6626d46abf8d7590000000000000000000000000000000000000000000000000000000000000000",
      callData: hex"b61d27f60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000",
      accountGasLimits: bytes32(
        bytes.concat(bytes16(uint128(0x989680)), bytes16(uint128(0x989680)))
      ),
      preVerificationGas: 0x5208,
      gasFees: bytes32(
        bytes.concat(bytes16(uint128(0x171f5b1180)), bytes16(uint128(0x171f5b1180)))
      ),
      signature: "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c",
      paymasterAndData: new bytes(0)
    });
    EntryPointSimulations simulator = new EntryPointSimulations();
    simulator.simulateHandleOp(userOp, address(0), "");
  }
}
