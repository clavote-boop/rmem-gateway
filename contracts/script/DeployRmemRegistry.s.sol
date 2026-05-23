// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {RmemMemoryRegistry} from "../src/RmemMemoryRegistry.sol";

/// @notice Deploys RmemMemoryRegistry to whichever --rpc-url is targeted.
///         Run:
///           forge script script/DeployRmemRegistry.s.sol:Deploy \
///             --rpc-url $SEPOLIA_RPC_URL --broadcast --verify
///         Requires env: DEPLOYER_PRIVATE_KEY (or --account flag),
///                       ETHERSCAN_API_KEY (for --verify on Sepolia),
///                       BASESCAN_API_KEY (for --verify on Base Sepolia).
contract Deploy is Script {
    function run() external returns (RmemMemoryRegistry reg) {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);
        reg = new RmemMemoryRegistry();
        vm.stopBroadcast();
        console.log("RmemMemoryRegistry deployed at:", address(reg));
        console.log("Chain ID:", block.chainid);
    }
}
