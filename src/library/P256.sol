// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

library P256 {
  address constant VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
  uint256 constant P256_N_DIV_2 =
    57896044605178124381348723474703786764998477612067880171211129530534256022184;

  function verify(
    bytes32 hash,
    uint256[2] memory rs,
    uint256[2] memory xy
  ) internal view returns (uint256) {
    (bool success, bytes memory ret) = VERIFIER.staticcall(
      abi.encode(hash, rs[0], rs[1], xy[0], xy[1])
    );

    return (!success || abi.decode(ret, (uint256)) != 1) ? 1 : 0;
  }

  function verifySignature(
    bytes32 hash,
    uint256[2] memory rs,
    uint256[2] memory xy
  ) internal view returns (uint256) {
    if (rs[1] > P256_N_DIV_2) {
      return 1;
    }
    return verify(hash, rs, xy);
  }
}
