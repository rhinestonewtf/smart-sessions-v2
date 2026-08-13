// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.30;

import { Script, console2 } from "forge-std/Script.sol";

// Contracts
import { SmartSessionEmissary } from "@contracts/SmartSessionEmissary.sol";
import { SmartSessionLens } from "@core/SmartSessionLens.sol";
import { Permit2ClaimPolicy } from "@policies/claim/permit2/Permit2ClaimPolicy.sol";
import { CompactClaimPolicy } from "@policies/claim/compact/CompactClaimPolicy.sol";
import { NoncePinPolicy } from "@policies/nonce/NoncePinPolicy.sol";

/// @title Deploy
/// @notice Deploys SmartSessionEmissary and related contracts using CREATE2
contract Deploy is Script {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Intent Executor address
    address constant INTENT_EXECUTOR = 0xbF9b5b917a83f8adaC17B0752846D41D8D7b7E17;

    /// @notice Permit2 address (canonical across chains)
    address constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    /// @notice CREATE2 salt for deterministic deployment
    bytes32 constant SALT = bytes32(uint256(0x2));

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    SmartSessionLens public lens;
    SmartSessionEmissary public emissary;
    Permit2ClaimPolicy public permit2Policy;
    CompactClaimPolicy public compactClaimPolicy;
    NoncePinPolicy public noncePinPolicy;

    /*//////////////////////////////////////////////////////////////
                                  RUN
    //////////////////////////////////////////////////////////////*/

    function run() external {
        address deployer = msg.sender;

        console2.log("Deployer:", deployer);
        console2.log("Intent Executor:", INTENT_EXECUTOR);
        console2.log("Salt:", vm.toString(SALT));
        console2.log("");

        vm.startBroadcast();

        // 1. Deploy Lens first (no dependencies)
        lens = new SmartSessionLens{ salt: SALT }();
        console2.log("SmartSessionLens deployed at:", address(lens));

        // 2. Deploy Emissary (depends on Lens)
        emissary = new SmartSessionEmissary{ salt: SALT }(INTENT_EXECUTOR, address(lens));
        console2.log("SmartSessionEmissary deployed at:", address(emissary));

        // 3. Deploy Permit2ClaimPolicy
        permit2Policy = new Permit2ClaimPolicy{ salt: SALT }(PERMIT2);
        console2.log("Permit2ClaimPolicy deployed at:", address(permit2Policy));

        // 4. Deploy CompactClaimPolicy
        compactClaimPolicy = new CompactClaimPolicy{ salt: SALT }();
        console2.log("CompactClaimPolicy deployed at:", address(compactClaimPolicy));

        // 5. Deploy NoncePinPolicy
        noncePinPolicy = new NoncePinPolicy{ salt: SALT }(INTENT_EXECUTOR, PERMIT2);
        console2.log("NoncePinPolicy deployed at:", address(noncePinPolicy));

        vm.stopBroadcast();

        // Log summary
        console2.log("");
        console2.log("=== Deployment Summary ===");
        console2.log("SmartSessionLens:     ", address(lens));
        console2.log("SmartSessionEmissary: ", address(emissary));
        console2.log("Permit2ClaimPolicy:        ", address(permit2Policy));
        console2.log("CompactClaimPolicy:   ", address(compactClaimPolicy));
        console2.log("NoncePinPolicy:       ", address(noncePinPolicy));
    }
}
