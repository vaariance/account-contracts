// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "@~/P256Account.sol";
import "@~/P256AccountFactory.sol";
import "./Config.sol";
import "@p256/verifier/P256Verifier.sol";
import "@~/library/P256.sol";

contract SimpleP256AccountHarness is P256Account {
  constructor(IEntryPoint _entryPoint) P256Account(_entryPoint) {}

  function exposed_validateSignature(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash
  ) public returns (uint256 validationData) {
    return _validateSignature(userOp, userOpHash);
  }

  function exposed_initialize(bytes calldata creation) public {
    _initialize(creation);
  }
}

contract TestSimplePasskeyAccount is Test {
  SimpleP256AccountHarness simpleP256Account;
  SimpleP256AccountHarness account;
  Config.NetworkConfig config;
  Config conf;

  function setUp() public {
    vm.etch(P256.VERIFIER, type(P256Verifier).runtimeCode);
    conf = new Config();
    config = conf.getAndroidTest();
    simpleP256Account = new SimpleP256AccountHarness(IEntryPoint(config.entrypoint));
    bytes memory creation = abi.encode(
      address(0),
      config.credentialHex,
      config.xy[0],
      config.xy[1]
    );
    account = SimpleP256AccountHarness(
      payable(
        new ERC1967Proxy{salt: bytes32(0)}(
          address(simpleP256Account),
          abi.encodeCall(P256Account.initialize, (creation))
        )
      )
    );
  }

  function buildUserOp() internal view returns (PackedUserOperation memory) {
    return
      PackedUserOperation({
        sender: address(0),
        nonce: 0,
        initCode: new bytes(0),
        callData: new bytes(0),
        accountGasLimits: bytes32(0),
        preVerificationGas: 0x0,
        gasFees: bytes32(0),
        paymasterAndData: new bytes(0),
        signature: abi.encode(
          config.rs[0],
          config.rs[1],
          config.authenticatorData,
          config.clientDataJsonPre,
          config.clientDataJsonPost
        )
      });
  }

  function testValidateSignature() public {
    PackedUserOperation memory userOp = buildUserOp();
    uint256 value = account.exposed_validateSignature(userOp, config.testHash);
    uint256 expected = 0;
    assertEq(value, expected);
  }

  function testGetPublicKey() public {
    uint256[2] memory value = account.getPublicKey();
    assertEq(value[0], config.xy[0]);
    assertEq(value[1], config.xy[1]);
  }

  function testMalleability() public {
    uint256 s = config.rs[1];
    assertTrue(s <= P256.P256_N_DIV_2);

    Config.p256VerifyStruct memory seStruct = conf.getSecureEnclaveTest();
    assertTrue(seStruct.s <= P256.P256_N_DIV_2);
  }

  function testBase64urlEncoding() public {
    string memory execHashBase64 = B64Encoder.encode(bytes.concat(config.testHash));
    assertEq(execHashBase64, config.challenge);
  }

  function testSeDemo() public {
    Config.p256VerifyStruct memory seStruct = conf.getSecureEnclaveTest();

    uint256 res = P256.verify(seStruct.hash, [seStruct.r, seStruct.s], [seStruct.x, seStruct.y]);
    assertEq(res, 0);
  }

  function testSecureEnclave() public {
    Config.p256VerifyStruct memory seStruct = conf.getSecureEnclaveTest();

    bytes memory creation = abi.encode(address(0), bytes32(0), seStruct.x, seStruct.y);

    account.exposed_initialize(creation);

    PackedUserOperation memory userOp = buildUserOp();
    userOp.signature = abi.encode(seStruct.r, seStruct.s);

    uint256 value = account.exposed_validateSignature(userOp, bytes32(0));
    uint256 expected = 0;
    assertEq(value, expected);
  }
}
