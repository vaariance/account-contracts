// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@~/SimpleAccount.sol";
import "@~/PasskeyAccount.sol";

/**
 * A sample factory contract for SimpleAccount
 * A UserOperations "initCode" holds the address of the factory, and a method call (to createAccount, in this sample factory).
 * The factory's createAccount returns the target account address even if it is already installed.
 * This way, the entryPoint.getSenderAddress() can be called either before or after the account is created.
 */
contract AccountFactory {
  SimpleAccount public immutable simpleAccount;
  PasskeyAccount public immutable passkeyAccount;

  constructor(IEntryPoint _entryPoint) {
    simpleAccount = new SimpleAccount(_entryPoint);
    passkeyAccount = new PasskeyAccount(_entryPoint);
  }

  /**
   * create an account, and return its address.
   * returns the address even if the account is already deployed.
   * Note that during UserOperation execution, this method is called only if the account is not deployed.
   * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after account creation
   */
  function createAccount(address owner, uint256 salt) public returns (SimpleAccount ret) {
    address addr = getAddress(owner, salt);
    uint codeSize = addr.code.length;
    if (codeSize > 0) {
      return SimpleAccount(payable(addr));
    }
    ret = SimpleAccount(
      payable(
        new ERC1967Proxy{salt: bytes32(salt)}(
          address(simpleAccount),
          abi.encodeCall(SimpleAccount.initialize, (owner))
        )
      )
    );
  }

  function createPasskeyAccount(
    bytes32 credential,
    uint256 x,
    uint256 y,
    uint256 salt
  ) public returns (PasskeyAccount ret) {
    address addr = getPasskeyAccountAddress(credential, x, y, salt);
    uint codeSize = addr.code.length;
    if (codeSize > 0) {
      return PasskeyAccount(payable(addr));
    }
    ret = PasskeyAccount(
      payable(
        new ERC1967Proxy{salt: bytes32(salt)}(
          address(passkeyAccount),
          abi.encodeCall(PasskeyAccount.initialize, (credential, x, y))
        )
      )
    );
  }

  /**
   * calculate the counterfactual address of this account as it would be returned by createAccount()
   */
  function getAddress(address owner, uint256 salt) public view returns (address) {
    return
      Create2.computeAddress(
        bytes32(salt),
        keccak256(
          abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(simpleAccount), abi.encodeCall(SimpleAccount.initialize, (owner)))
          )
        )
      );
  }

  function getPasskeyAccountAddress(
    bytes32 credential,
    uint256 x,
    uint256 y,
    uint256 salt
  ) public view returns (address) {
    return
      Create2.computeAddress(
        bytes32(salt),
        keccak256(
          abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(
              address(passkeyAccount),
              abi.encodeCall(PasskeyAccount.initialize, (credential, x, y))
            )
          )
        )
      );
  }
}
