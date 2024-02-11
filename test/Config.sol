// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.21;

contract Config {
  struct NetworkConfig {
    address entrypoint;
    string credentialId;
    bytes32 credentialHex;
    uint256[2] xy;
    uint256[2] rs;
    string clientDataJsonPre;
    string clientDataJsonPost;
    string clientData;
    bytes authenticatorData;
    bytes32 testHash;
    string challenge;
  }

  NetworkConfig activeNetworkConfig;

  mapping(uint256 => NetworkConfig) public chainIdToNetworkConfig;

  constructor() {
    chainIdToNetworkConfig[31337] = getAnvilEthConfig();
    activeNetworkConfig = chainIdToNetworkConfig[block.chainid];
  }

  function getActiveNetworkConfig() external view returns (NetworkConfig memory) {
    return activeNetworkConfig;
  }

  // fails malleability test
  function getAnvilEthConfig() internal pure returns (NetworkConfig memory anvilNetworkConfig) {
    uint256[2] memory q;
    uint256[2] memory rs;
    q[0] = 0xf5dee907a9f28e50eab51b699ff6becf2783fa5f6cf0d83186e6c8a29f84e7a6;
    q[1] = 0x6e5794995bfe01a6166731db5de6caf5a9cf232364cb816ac6626d46abf8d759;
    rs[0] = 0xe017c9b829f0d550c9a0f1d791d460485b774c5e157d2eaabdf690cba2a62726;
    rs[1] = 0xb3e3a3c5022dc5301d272a752c05053941b1ca608bf6bc8ec7c71dfe15d53059;
    anvilNetworkConfig = NetworkConfig({
      entrypoint: 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789,
      credentialId: "EUQ8dgl3CB-p6SewjKsmj25ng2IfKkAQLYzFhube47w",
      credentialHex: 0x11443c760977081fa9e927b08cab268f6e6783621f2a40102d8cc586e6dee3bc,
      xy: q,
      rs: rs,
      clientDataJsonPre: '{"type":"webauthn.get","challenge":"',
      clientDataJsonPost: '","origin":"api.webauthn.io"}',
      clientData: '{"type":"webauthn.get","challenge":"1BWo2FD1icnHUjlcCCurRR6Iltb1GfTUYQmnzAZVq3M","origin":"api.webauthn.io"}',
      authenticatorData: hex"205f5f63c4a6cebdc67844b75186367e6d2e4f19b976ab0affefb4e981c224350500000001",
      testHash: 0xd415a8d850f589c9c752395c082bab451e8896d6f519f4d46109a7cc0655ab73,
      challenge: "1BWo2FD1icnHUjlcCCurRR6Iltb1GfTUYQmnzAZVq3M"
    });
  }

  // passes malleability test
  function getIosTest() external pure returns (NetworkConfig memory) {
    uint256[2] memory q;
    uint256[2] memory rs;
    q[0] = 0xdac9aba50f24fd66b9213fb8ff01459183d18213dd2d81a04ef7f74804daa855;
    q[1] = 0xddf7d419a18b9a8bd9b3a7d9e8db9e37dacaab2242e47c82ed0cac14a4bba8fc;
    rs[0] = 0x707428e93b9b1bed8d55b21a800bd549d6bddd50cb5b756fa755dcb4966731dd;
    rs[1] = 0x7b08aa15dce60563d7897048848ce602786f6fd71afaf09bd9d9e5503906bfed;
    return
      NetworkConfig({
        entrypoint: 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789, // correct
        credentialId: "53vSAl9NraUFyvfuQJ3YUt29cPlQhlbG88tmA-hiDNs", // correct
        credentialHex: 0xe77bd2025f4dada505caf7ee409dd852ddbd70f9508656c6f3cb6603e8620cdb, // correct
        xy: q, // correct
        rs: rs, // done
        clientDataJsonPre: '{"type":"webauthn.get","challenge":"', // correct
        clientDataJsonPost: '","origin":"https://webauthn.io"}', // correct
        clientData: '{"type":"webauthn.get","challenge":"KYn6ZEHl7MMnPmUECA_zDwzMaBgNDDAY2AIn8cD0Mvg","origin":"https://webauthn.io"}', // correct
        authenticatorData: hex"74a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef00500000008", // done
        testHash: 0x2989fa6441e5ecc3273e6504080ff30f0ccc68180d0c3018d80227f1c0f432f8, // correct
        challenge: "KYn6ZEHl7MMnPmUECA_zDwzMaBgNDDAY2AIn8cD0Mvg" // correct
      }); // check rs, testhash, authData
  }

  // fails malleability test
  function getAndroidTest() external pure returns (NetworkConfig memory) {
    uint256[2] memory q;
    uint256[2] memory rs;
    q[0] = 0xd73867c5c6357f7a23843d78b1d325d8cde8cc269ad2c767896657e86c2f9db9;
    q[1] = 0x728bfe811e3c355a80bd96c71c99ae68ca717b1182078a554e73e56574a8a6c9;
    rs[0] = 0x4b97728ef566a4640ce10a5175d36db5cdcd1ab6102f9ac671a712b8fe8aa672;
    rs[1] = 0xeb1da7361f9f9918bf7336e85bcefe413d2b5688d0ee626a8e44e6ebaf03fd13;
    return
      NetworkConfig({
        entrypoint: 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789,
        credentialId: "bcCUiAXUtXlJz9MBBqJ8qA",
        credentialHex: 0x000000000000000000000000000000006dc0948805d4b57949cfd30106a27ca8,
        xy: q,
        rs: rs,
        clientDataJsonPre: '{"type":"webauthn.get","challenge":"',
        clientDataJsonPost: '","origin":"android:apk-key-hash:5--XhhrpNeH_K2aYpxYxOupzRZZkBz1dGUTuwDUaDNI","androidPackageName":"com.example.web3Signers"}',
        clientData: '{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"android:apk-key-hash:5--XhhrpNeH_K2aYpxYxOupzRZZkBz1dGUTuwDUaDNI","androidPackageName":"com.example.web3Signers"}',
        authenticatorData: hex"4e3197cc08995079232626957e440e0c6ad8ee223df4184a44f640e1c617696d1d00000000",
        testHash: 0x0000000000000000000000000000000000000000000000000000000000000000,
        challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      });
  }

  struct p256VerifyStruct {
    bytes32 hash;
    uint256 r;
    uint256 s;
    uint256 x;
    uint256 y;
  }

  function getSecureEnclaveTest() external pure returns (p256VerifyStruct memory) {
    return
      p256VerifyStruct({
        hash: 0x66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925,
        r: 0x44dcb6ead69cff6d51ce5c978db2b8539b55b2190b356afb86fe7f586a58c699,
        s: 0xd0c5fee693d4f7a6dcd638ca35d23954ee8470c807e0f948251c05ff9d989e22,
        x: 0x0ec33bbe2e86e6f38a4f599ae6ddc3a750b72666496e28cff40bcfc354e3ed22,
        y: 0x325624c49471ede3baac05c5c29e35240e8b658fb39e376c5ec3c8e64b76e3a1
      });
  }
}
