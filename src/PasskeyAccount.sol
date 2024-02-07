// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.21;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@aa/contracts/core/BaseAccount.sol";
import "@~/utils/TokenCallbackHandler.sol";
import "@~/library/P256.sol";
import "@~/library/Base64Url.sol";

error IndexOutOfBounds();

/**
 *  light passkey account.
 *  this is sample minimal account.
 *  has execute, eth handling methods
 */
contract PasskeyAccount is BaseAccount, TokenCallbackHandler, UUPSUpgradeable, Initializable {
  uint256 public publicKeyCount;

  bytes32[5] internal credentials;

  uint256[2][5] internal publicKeys;

  IEntryPoint private immutable _entryPoint;

  event SimpleAccountInitialized(IEntryPoint indexed entryPoint, bytes32 indexed credentialHex);

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
  function initialize(bytes32 credential, uint256 x, uint256 y) public virtual initializer {
    _initialize(credential, x, y);
  }

  function _initialize(bytes32 credential, uint256 x, uint256 y) internal virtual {
    publicKeyCount = 1;
    credentials[0] = credential;
    publicKeys[0][0] = x;
    publicKeys[0][1] = y;
    emit SimpleAccountInitialized(_entryPoint, credential);
  }

  /// implement template method of BaseAccount
  function _validateSignature(
    UserOperation calldata userOp,
    bytes32 userOpHash
  ) internal virtual override returns (uint256 validationData) {
    uint256 index = uint256(bytes32(userOp.signature[0:32]));
    if (index >= publicKeyCount) return SIG_VALIDATION_FAILED;

    (
      uint256 r,
      uint256 s,
      bytes memory authenticatorData,
      string memory clientDataJSONPre,
      string memory clientDataJSONPost
    ) = abi.decode(userOp.signature[32:], (uint256, uint256, bytes, string, string));

    string memory execHashBase64 = Base64URL.encode(bytes.concat(userOpHash));
    string memory clientDataJSON = string.concat(
      clientDataJSONPre,
      execHashBase64,
      clientDataJSONPost
    );
    bytes32 clientHash = sha256(bytes(clientDataJSON));
    bytes32 sigHash = sha256(bytes.concat(authenticatorData, clientHash));

    return P256.verify(sigHash, [r, s], publicKeys[index]);
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

  function getCredentialIdBase64(uint256 location) public view returns (string memory) {
    if (location >= publicKeyCount) revert IndexOutOfBounds();

    bytes32 credentialBytes32 = credentials[location];

    uint256 count = 0;
    while (count < 32 && credentialBytes32[count] == 0x00) {
      count++;
    }

    uint256 length = 32 - count;

    bytes memory credentialBytes = new bytes(length);

    for (uint256 i = 0; i < length; i++) {
      credentialBytes[i] = credentialBytes32[i + count];
    }

    string memory credentialIdBase64 = Base64URL.encode(credentialBytes);
    return credentialIdBase64;
  }

  function getPublicKey(uint256 location) public view returns (uint256[2] memory) {
    return publicKeys[location];
  }

  function addPublicKey(uint256 x, uint256 y, bytes32 credential) external onlyThis {
    uint256 location = publicKeyCount;
    if (location >= 5) revert IndexOutOfBounds();

    publicKeyCount++;
    publicKeys[location][0] = x;
    publicKeys[location][1] = y;
    credentials[location] = credential;
  }

  function removePublicKey(uint256 index) external onlyThis {
    uint256 location = publicKeyCount - 1;
    if (location == 0 || index > location) revert IndexOutOfBounds();

    publicKeyCount--;
    publicKeys[index] = publicKeys[location];
    credentials[index] = credentials[location];

    publicKeys[location] = [0, 0];
    credentials[location] = bytes32(0);
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
