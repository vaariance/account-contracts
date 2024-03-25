// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

abstract contract RecoverableAccount is UUPSUpgradeable, Initializable {
  address internal recoveryAddress;

  bytes32 private recoveryHash;

  uint256 private recoveryExecutionTime;

  uint256 public constant RECOVERY_DELAY = 2 days;

  mapping(bytes32 hash => bytes signer) private signerOf;

  event RecoveryInitiated(bytes32 recoveryHash, uint256 executionTime);
  event RecoveryCanceled(bytes32 recoveryHash);
  event RecoveryExecuted(bytes32 recoveryHash, bytes newSigner);

  function initializeRecovery(bytes calldata newSigner) public {
    require(msg.sender == recoveryAddress && recoveryAddress != address(0), "unauthorized");
    require(recoveryHash == bytes32(0), "queued recovery exists");

    _initializeRecovery(newSigner);
  }

  function cancelRecovery() public {
    require(msg.sender == address(this) || msg.sender == recoveryAddress, "unauthorized");
    require(recoveryHash != bytes32(0), "no recovery queued");

    _cancelRecovery();
  }

  function _initializeRecovery(bytes calldata newSigner) private {
    bytes32 hash = keccak256(newSigner);
    uint256 eta = block.timestamp + RECOVERY_DELAY;

    recoveryHash = hash;
    signerOf[hash] = newSigner;
    recoveryExecutionTime = eta;

    emit RecoveryInitiated(hash, eta);
  }

  function _cancelRecovery() private {
    bytes32 hash = recoveryHash;

    recoveryHash = bytes32(0);
    recoveryExecutionTime = 0;

    emit RecoveryCanceled(hash);
  }

  function _executeRecovery() internal {
    if (recoveryHash != bytes32(0) && block.timestamp >= recoveryExecutionTime) {
      executeRecovery(recoveryHash);
    }
  }

  function executeRecovery(bytes32 hash) private {
    bytes memory newSigner = signerOf[hash];

    recoveryHash = bytes32(0);
    recoveryExecutionTime = 0;
    _executeRecovery(newSigner);

    emit RecoveryExecuted(hash, newSigner);
  }

  function _executeRecovery(bytes memory signer) internal virtual {}
}
