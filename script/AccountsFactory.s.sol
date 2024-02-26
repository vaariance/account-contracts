// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import "../src/P256AccountFactory.sol";
import "../test/Config.sol";

contract DeployAccountsFactory is Script {
  Config.NetworkConfig config;

  function setUp() public {
    Config conf = new Config();
    config = conf.getActiveNetworkConfig();
  }

  function run() external {
    vm.startBroadcast();
    new P256AccountFactory{
      salt: 0xd415a8d850f589c9c752395c082bab451e8896d6f519f4d46109a7cc0655ab73
    }(IEntryPoint(0x0000000071727De22E5E9d8BAf0edAc6f37da032));
    vm.stopBroadcast();
  }
}
