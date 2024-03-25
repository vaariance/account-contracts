// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@aa/contracts/core/BaseAccount.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "@aa/contracts/core/Helpers.sol";
import "@aa/contracts/samples/callback/TokenCallbackHandler.sol";
import "@~/library/P256.sol";
import "@~/library/B64Encoder.sol";
import "@~/RecoverableAccount.sol";

error IndexOutOfBounds();

struct Signer {
  SignerType signerType;
  bytes32 credential;
  uint256[2] publicKey;
}

enum SignerType {
  HARDWARE,
  PASSKEY
}

/**
 *  light p256 account.
 *  this is sample minimal account.
 *  has execute, eth handling methods
 */
contract P256Account is BaseAccount, TokenCallbackHandler, RecoverableAccount {
  Signer private _signer;

  IEntryPoint private immutable _entryPoint;

  event P256AccountInitialized(IEntryPoint indexed entryPoint, bytes32 indexed credential);

  /// only this account should authorize actions.
  /// use either a 2771 relayer like Gelato (not implemented) or an entrypoint
  modifier onlyThis() {
    _onlyThis();
    _;
  }

  /// @inheritdoc BaseAccount
  function entryPoint() public view virtual override returns (IEntryPoint) {
    return _entryPoint;
  }

  // solhint-disable-next-line no-empty-blocks
  receive() external payable {}

  constructor(IEntryPoint entrypoint) {
    _entryPoint = entrypoint;
    _disableInitializers();
  }

  function _onlyThis() internal view {
    //directly through the account itself (which gets redirected through execute())
    require(msg.sender == address(this), "only this");
  }

  /**
   * execute a transaction (called directly from owner, or by entryPoint)
   */
  function execute(address dest, uint256 value, bytes calldata func) external {
    _requireFromEntryPoint();
    _call(dest, value, func);
  }

  /**
   * execute a sequence of transactions
   * @dev to reduce gas consumption for trivial case (no value), use a zero-length array to mean zero value
   */
  function executeBatch(
    address[] calldata dest,
    uint256[] calldata value,
    bytes[] calldata func
  ) external {
    _requireFromEntryPoint();
    require(
      dest.length == func.length && (value.length == 0 || value.length == func.length),
      "wrong array lengths"
    );
    if (value.length == 0) {
      for (uint256 i = 0; i < dest.length; i++) {
        _call(dest[i], 0, func[i]);
      }
    } else {
      for (uint256 i = 0; i < dest.length; i++) {
        _call(dest[i], value[i], func[i]);
      }
    }
  }

  /**
   * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
   * a new implementation of SimpleAccount must be deployed with the new EntryPoint address, then upgrading
   * the implementation by calling `upgradeTo()`
   */
  function initialize(bytes calldata _creation) public virtual initializer {
    _initialize(_creation);
  }

  function _initialize(bytes calldata _creation) internal virtual {
    (address recovery, bytes32 credential, uint256 x, uint256 y) = abi.decode(
      _creation,
      (address, bytes32, uint256, uint256)
    );

    _signer = Signer({
      signerType: credential == bytes32(0) ? SignerType.HARDWARE : SignerType.PASSKEY,
      credential: credential,
      publicKey: [x, y]
    });
    recoveryAddress = recovery;

    emit P256AccountInitialized(_entryPoint, credential);
  }

  /// implement template method of BaseAccount
  function _validateSignature(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash
  ) internal virtual override returns (uint256 validationData) {
    _executeRecovery();

    bool isPassKey = _signer.signerType == SignerType.PASSKEY;

    if (isPassKey) {
      (
        uint256 r,
        uint256 s,
        bytes memory authenticatorData,
        string memory clientDataJSONPre,
        string memory clientDataJSONPost
      ) = abi.decode(userOp.signature, (uint256, uint256, bytes, string, string));

      string memory execHashBase64 = B64Encoder.encode(bytes.concat(userOpHash));
      string memory clientDataJSON = string.concat(
        clientDataJSONPre,
        execHashBase64,
        clientDataJSONPost
      );
      bytes32 clientHash = sha256(bytes(clientDataJSON));
      bytes32 sigHash = sha256(bytes.concat(authenticatorData, clientHash));

      return P256.verify(sigHash, [r, s], _signer.publicKey);
    }

    (uint256 r1, uint256 s1) = abi.decode(userOp.signature, (uint256, uint256));
    bytes32 sigHash1 = sha256(bytes.concat(userOpHash));
    return P256.verify(sigHash1, [r1, s1], _signer.publicKey);
  }

  function _call(address target, uint256 value, bytes memory data) internal {
    // slither-disable-next-line arbitrary-send-eth
    (bool success, bytes memory result) = target.call{value: value}(data);
    if (!success) {
      assembly {
        revert(add(result, 32), mload(result))
      }
    }
  }

  function getPublicKey() public view returns (uint256[2] memory) {
    return _signer.publicKey;
  }

  /**
   * check current account deposit in the entryPoint
   */
  function getDeposit() public view returns (uint256) {
    return entryPoint().balanceOf(address(this));
  }

  /**
   * deposit more funds for this account in the entryPoint
   */
  function addDeposit() public payable {
    entryPoint().depositTo{value: msg.value}(address(this));
  }

  /**
   * withdraw value from the account's deposit
   * @param withdrawAddress target to send to
   * @param amount to withdrawHardware
   */
  function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyThis {
    entryPoint().withdrawTo(withdrawAddress, amount);
  }

  function changeRecoveryAddress(address newRecoveryAddress) public onlyThis {
    require(newRecoveryAddress != address(0), "zero address");
    recoveryAddress = newRecoveryAddress;
  }

  function _executeRecovery(bytes memory signer) internal override {
    (uint256 x, uint256 y) = abi.decode(signer, (uint256, uint256));

    _signer = Signer({
      signerType: _signer.signerType,
      credential: _signer.credential,
      publicKey: [x, y]
    });
  }

  function _authorizeUpgrade(address newImplementation) internal view override {
    (newImplementation);
    _onlyThis();
  }
}
