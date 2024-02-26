// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@~/P256Account.sol";

/**
 * A sample factory contract for P256Account
 * A UserOperations "initCode" holds the address of the factory, and a method call (to createAccount, in this sample factory).
 * The factory's createAccount returns the target account address even if it is already installed.
 * This way, the entryPoint.getSenderAddress() can be called either before or after the account is created.
 */
contract P256AccountFactory {
  P256Account public immutable p256Account;

  constructor(IEntryPoint _entryPoint) {
    p256Account = new P256Account(_entryPoint);
  }

  function createP256Account(
    uint256 salt,
    bytes calldata creation
  ) public returns (P256Account ret) {
    address addr = getP256AccountAddress(salt, creation);
    uint codeSize = addr.code.length;
    if (codeSize > 0) {
      return P256Account(payable(addr));
    }
    ret = P256Account(
      payable(
        new ERC1967Proxy{salt: bytes32(salt)}(
          address(p256Account),
          abi.encodeCall(P256Account.initialize, (creation))
        )
      )
    );
  }

  function getP256AccountAddress(
    uint256 salt,
    bytes calldata creation
  ) public view returns (address) {
    return
      Create2.computeAddress(
        bytes32(salt),
        keccak256(
          abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(p256Account), abi.encodeCall(P256Account.initialize, (creation)))
          )
        )
      );
  }
}
