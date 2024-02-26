// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@aa/contracts/core/BaseAccount.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "@aa/contracts/core/Helpers.sol";
import "@aa/contracts/samples/callback/TokenCallbackHandler.sol";
import "@~/library/P256.sol";
import "@~/library/B64Encoder.sol";

error IndexOutOfBounds();

struct Signer {
  SignerType signerType;
  bytes32 credential;
  uint256[2] publicKey;
}

enum SignerType {
  P256,
  PASSKEY
}

/**
 *  light p256 account.
 *  this is sample minimal account.
 *  has execute, eth handling methods
 */
contract P256Account is BaseAccount, TokenCallbackHandler, UUPSUpgradeable, Initializable {
  uint256 public signerCount;

  Signer[5] internal signers;

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
    require(_creation.length == 96, "wrong creation length");

    signerCount = 1;

    bytes32 credential = bytes32(_creation[0:32]);
    uint256 x = uint256(bytes32(_creation[32:64]));
    uint256 y = uint256(bytes32(_creation[64:96]));

    Signer memory s = Signer({
      signerType: credential == bytes32(0) ? SignerType.P256 : SignerType.PASSKEY,
      credential: credential,
      publicKey: [x, y]
    });

    signers[0] = s;

    emit P256AccountInitialized(_entryPoint, credential);
  }

  /// implement template method of BaseAccount
  function _validateSignature(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash
  ) internal virtual override returns (uint256 validationData) {
    uint256 index = uint256(bytes32(userOp.signature[0:32]));
    if (index >= signerCount) return SIG_VALIDATION_FAILED;

    Signer memory signer = signers[index];
    bool isP256 = signer.signerType == SignerType.P256;

    if (isP256) {
      (uint256 r1, uint256 s1) = abi.decode(userOp.signature[32:], (uint256, uint256));
      bytes32 sigHash1 = sha256(bytes.concat(userOpHash));
      return P256.verify(sigHash1, [r1, s1], signer.publicKey);
    }

    (
      uint256 r,
      uint256 s,
      bytes memory authenticatorData,
      string memory clientDataJSONPre,
      string memory clientDataJSONPost
    ) = abi.decode(userOp.signature[32:], (uint256, uint256, bytes, string, string));

    string memory execHashBase64 = B64Encoder.encode(bytes.concat(userOpHash));
    string memory clientDataJSON = string.concat(
      clientDataJSONPre,
      execHashBase64,
      clientDataJSONPost
    );
    bytes32 clientHash = sha256(bytes(clientDataJSON));
    bytes32 sigHash = sha256(bytes.concat(authenticatorData, clientHash));

    return P256.verify(sigHash, [r, s], signer.publicKey);
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

  function getSigner(uint256 location) public view returns (uint256[3] memory) {
    uint256[3] memory signer;
    signer[0] = uint256(signers[location].credential);
    signer[1] = signers[location].publicKey[0];
    signer[2] = signers[location].publicKey[1];
    return signer;
  }

  function addPublicKey(uint256 x, uint256 y, bytes32 credential) external onlyThis {
    uint256 location = signerCount;
    if (location >= 5) revert IndexOutOfBounds();

    signerCount++;

    signers[location] = Signer({
      signerType: credential == bytes32(0) ? SignerType.P256 : SignerType.PASSKEY,
      credential: credential,
      publicKey: [x, y]
    });
  }

  function removePublicKey(uint256 index) external onlyThis {
    uint256 location = signerCount - 1;
    if (location == 0 || index > location) revert IndexOutOfBounds();

    signerCount--;

    signers[index] = signers[location];
    delete signers[location];
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
   * @param amount to withdraw
   */
  function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyThis {
    entryPoint().withdrawTo(withdrawAddress, amount);
  }

  function _authorizeUpgrade(address newImplementation) internal view override {
    (newImplementation);
    _onlyThis();
  }
}
