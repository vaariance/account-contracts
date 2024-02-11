// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Test.sol";
import "@~/PasskeyAccount.sol";
import "@~/AccountFactory.sol";
import "./Config.sol";
import "@p256/verifier/P256Verifier.sol";
import "@~/library/P256.sol";

contract SimplePasskeyAccountHarness is PasskeyAccount {
  constructor(IEntryPoint _entryPoint) PasskeyAccount(_entryPoint) {}

  function exposed_validateSignature(
    UserOperation calldata userOp,
    bytes32 userOpHash
  ) public returns (uint256 validationData) {
    return _validateSignature(userOp, userOpHash);
  }
}

contract TestSimplePasskeyAccount is Test {
  SimplePasskeyAccountHarness simplePasskeyAccount;
  SimplePasskeyAccountHarness account;
  Config.NetworkConfig config;
  Config conf;

  function setUp() public {
    vm.etch(P256.VERIFIER, type(P256Verifier).runtimeCode);
    conf = new Config();
    config = conf.getAndroidTest();
    simplePasskeyAccount = new SimplePasskeyAccountHarness(IEntryPoint(config.entrypoint));
    account = SimplePasskeyAccountHarness(
      payable(
        new ERC1967Proxy{salt: bytes32(0)}(
          address(simplePasskeyAccount),
          abi.encodeCall(
            PasskeyAccount.initialize,
            (config.credentialHex, config.xy[0], config.xy[1])
          )
        )
      )
    );
  }

  function buildUserOp() internal view returns (UserOperation memory) {
    return
      UserOperation({
        sender: address(0),
        nonce: 0,
        initCode: new bytes(0),
        callData: new bytes(0),
        callGasLimit: 0x0,
        verificationGasLimit: 0x0,
        preVerificationGas: 0x0,
        maxFeePerGas: 0x0,
        maxPriorityFeePerGas: 0x0,
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
    UserOperation memory userOp = buildUserOp();
    userOp.signature = bytes.concat(bytes32(0), userOp.signature);
    uint256 value = account.exposed_validateSignature(userOp, config.testHash);
    uint256 expected = 0;
    assertEq(value, expected);
  }

  function testValidateSignatureWithSelectedPublicKey() public {
    addPublicKey();
    addPublicKey();
    addPublicKey();

    UserOperation memory userOp = buildUserOp();
    uint256 expected = 0;

    userOp.signature = bytes.concat(bytes32(uint256(1)), userOp.signature);
    uint256 value = account.exposed_validateSignature(userOp, config.testHash);

    UserOperation memory userOp1 = buildUserOp();
    userOp1.signature = bytes.concat(bytes32(uint256(2)), userOp1.signature);
    uint256 value2 = account.exposed_validateSignature(userOp1, config.testHash);

    UserOperation memory userOp2 = buildUserOp();
    userOp2.signature = bytes.concat(bytes32(uint256(3)), userOp2.signature);
    uint256 value3 = account.exposed_validateSignature(userOp2, config.testHash);

    UserOperation memory userOp3 = buildUserOp();
    userOp3.signature = bytes.concat(bytes32(uint256(4)), userOp3.signature);
    uint256 value4 = account.exposed_validateSignature(userOp3, config.testHash);

    assertEq(value, expected);
    assertEq(value2, expected);
    assertEq(value3, expected);
    assertEq(value4, 1);
  }

  function testGetCredentialId() public {
    string memory value = account.getCredentialIdBase64(0);
    string memory expected = config.credentialId;

    addPublicKey();

    string memory value2 = account.getCredentialIdBase64(1);

    assertEq(value, expected);
    assertEq(keccak256(bytes(value)), keccak256(bytes(expected)));

    assertEq(value2, expected);
    assertEq(keccak256(bytes(value2)), keccak256(bytes(expected)));
  }

  function testGetPublicKey() public {
    uint256[2] memory value = account.getPublicKey(0);
    assertEq(value[0], config.xy[0]);
    assertEq(value[1], config.xy[1]);

    addPublicKey();

    uint256[2] memory value2 = account.getPublicKey(1);

    assertEq(value2[0], config.xy[0]);
    assertEq(value2[1], config.xy[1]);
  }

  function testAddPublicKey() public {
    addPublicKey();
    uint256[2] memory value = account.getPublicKey(1);
    assertEq(value[0], config.xy[0]);
    assertEq(value[1], config.xy[1]);

    addPublicKey();
    uint256[2] memory value2 = account.getPublicKey(2);
    assertEq(value2[0], config.xy[0]);
    assertEq(value2[1], config.xy[1]);

    addPublicKey();
    uint256[2] memory value3 = account.getPublicKey(3);
    assertEq(value3[0], config.xy[0]);
    assertEq(value3[1], config.xy[1]);

    addPublicKey();
    uint256[2] memory value4 = account.getPublicKey(4);
    assertEq(value4[0], config.xy[0]);
    assertEq(value4[1], config.xy[1]);

    vm.expectRevert(IndexOutOfBounds.selector);
    addPublicKey();
  }

  function testRemovePublicKey() public {
    addPublicKey();
    vm.startPrank(address(account));
    account.removePublicKey(1);

    uint256[2] memory value = account.getPublicKey(1);
    assertEq(value[0], 0);
    assertEq(value[1], 0);

    vm.expectRevert(IndexOutOfBounds.selector);
    account.removePublicKey(0);

    vm.expectRevert(IndexOutOfBounds.selector);
    account.removePublicKey(4);
    vm.stopPrank();
  }

  function testMalleability() public {
    uint256 s = config.rs[1];
    assertTrue(s <= P256.P256_N_DIV_2);
  }

  function testBase64urlEncoding() public {
    string memory execHashBase64 = Base64URL.encode(bytes.concat(config.testHash));
    assertEq(execHashBase64, config.challenge);
  }

  function testSeDemo() public {
    Config.p256VerifyStruct memory seStruct = conf.getSecureEnclaveTest();

    uint256 res = P256.verify(seStruct.hash, [seStruct.r, seStruct.s], [seStruct.x, seStruct.y]);
    assertEq(res, 0);
  }
}
