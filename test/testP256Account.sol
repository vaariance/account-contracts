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
    bytes memory creation = bytes.concat(
      config.credentialHex,
      bytes32(config.xy[0]),
      bytes32(config.xy[1])
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

  function addPublicKey() internal {
    vm.startPrank(address(account));
    account.addPublicKey(config.xy[0], config.xy[1], config.credentialHex);
    vm.stopPrank();
  }

  function testValidateSignature() public {
    PackedUserOperation memory userOp = buildUserOp();
    userOp.signature = bytes.concat(bytes32(0), userOp.signature);
    uint256 value = account.exposed_validateSignature(userOp, config.testHash);
    uint256 expected = 0;
    assertEq(value, expected);
  }

  function testValidateSignatureWithSelectedPublicKey() public {
    addPublicKey();
    addPublicKey();
    addPublicKey();

    PackedUserOperation memory userOp = buildUserOp();
    uint256 expected = 0;

    userOp.signature = bytes.concat(bytes32(uint256(1)), userOp.signature);
    uint256 value = account.exposed_validateSignature(userOp, config.testHash);

    PackedUserOperation memory userOp1 = buildUserOp();
    userOp1.signature = bytes.concat(bytes32(uint256(2)), userOp1.signature);
    uint256 value2 = account.exposed_validateSignature(userOp1, config.testHash);

    PackedUserOperation memory userOp2 = buildUserOp();
    userOp2.signature = bytes.concat(bytes32(uint256(3)), userOp2.signature);
    uint256 value3 = account.exposed_validateSignature(userOp2, config.testHash);

    PackedUserOperation memory userOp3 = buildUserOp();
    userOp3.signature = bytes.concat(bytes32(uint256(4)), userOp3.signature);
    uint256 value4 = account.exposed_validateSignature(userOp3, config.testHash);

    assertEq(value, expected);
    assertEq(value2, expected);
    assertEq(value3, expected);
    assertEq(value4, 1);
  }

  function testGetPublicKey() public {
    uint256[3] memory value = account.getSigner(0);
    assertEq(value[1], config.xy[0]);
    assertEq(value[2], config.xy[1]);

    addPublicKey();

    uint256[3] memory value2 = account.getSigner(1);

    assertEq(value2[1], config.xy[0]);
    assertEq(value2[2], config.xy[1]);
  }

  function testAddPublicKey() public {
    addPublicKey();
    uint256[3] memory value = account.getSigner(1);
    assertEq(value[1], config.xy[0]);
    assertEq(value[2], config.xy[1]);

    addPublicKey();
    uint256[3] memory value2 = account.getSigner(2);
    assertEq(value2[1], config.xy[0]);
    assertEq(value2[2], config.xy[1]);

    addPublicKey();
    uint256[3] memory value3 = account.getSigner(3);
    assertEq(value3[1], config.xy[0]);
    assertEq(value3[2], config.xy[1]);

    addPublicKey();
    uint256[3] memory value4 = account.getSigner(4);
    assertEq(value4[1], config.xy[0]);
    assertEq(value4[2], config.xy[1]);

    vm.expectRevert(IndexOutOfBounds.selector);
    addPublicKey();
  }

  function testRemovePublicKey() public {
    addPublicKey();
    vm.startPrank(address(account));
    account.removePublicKey(1);

    uint256[3] memory value = account.getSigner(1);
    assertEq(value[1], 0);
    assertEq(value[2], 0);

    vm.expectRevert(IndexOutOfBounds.selector);
    account.removePublicKey(0);

    vm.expectRevert(IndexOutOfBounds.selector);
    account.removePublicKey(4);
    vm.stopPrank();
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

    vm.startPrank(address(account));
    account.addPublicKey(seStruct.x, seStruct.y, bytes32(0));
    vm.stopPrank();

    PackedUserOperation memory userOp = buildUserOp();
    userOp.signature = bytes.concat(bytes32(uint256(1)), abi.encodePacked(seStruct.r, seStruct.s));
    uint256 value = account.exposed_validateSignature(userOp, bytes32(0));
    uint256 expected = 0;
    assertEq(value, expected);
  }
}
