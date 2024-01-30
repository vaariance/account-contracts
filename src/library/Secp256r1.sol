// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

library Secp256r1 {
  address constant VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

  function verify(
    bytes32 hash,
    uint256[2] memory rs,
    uint256[2] memory xy
  ) internal view returns (uint256) {
    (bool success, bytes memory ret) = VERIFIER.staticcall(
      abi.encode(hash, rs[0], rs[1], xy[0], xy[1])
    );

    if (!success || abi.decode(ret, (uint256)) != 1) {
      return 1;
    }
    return 0;
  }
}
