// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { SSXLibSet } from "src/lib/SSXLibSet.sol";
import { ConfigBitMapLib, PermissionMode } from "src/lib/SSXLib.sol";

/// @title SSXLibSetTest
/// @notice Test suite demonstrating usage of SSXLibSet helper library
contract SSXLibSetTest is Test {
    using SSXLibSet for bytes32;
    using ConfigBitMapLib for bytes32;

    function test_SetIndividualFlags() public {
        bytes32 config = bytes32(0);

        // Set individual flags
        config = SSXLibSet.setEnabled(config, true);
        assertTrue(config.isEnabled(), "Should be enabled");

        config = SSXLibSet.setAnyTargetChainId(config, true);
        assertTrue(config.isAnyTargetChainId(), "Should allow any chain ID");

        config = SSXLibSet.setPreClaimOps(config, true);
        config = SSXLibSet.setTargetOps(config, true);

        // Set permission modes
        config = SSXLibSet.setRecipientMode(config, PermissionMode.LOCAL_MAPPING);
        config = SSXLibSet.setTokenOutMode(config, PermissionMode.IGNORE);
        config = SSXLibSet.setTokenInMode(config, PermissionMode.COMPARE);

        // Verify the configuration is enabled
        assertTrue(config.isEnabled());
    }

    function test_CreateConfigBatch() public {
        bytes32 config = SSXLibSet.createConfig({
            enabled: true,
            anyChainId: true,
            inspectPreClaimOps: true,
            inspectTargetOps: false,
            recipientMode: PermissionMode.LOCAL_MAPPING,
            tokenOutMode: PermissionMode.IGNORE,
            tokenInMode: PermissionMode.EXTERNAL_POLICY
        });

        assertTrue(config.isEnabled(), "Should be enabled");
        assertTrue(config.isAnyTargetChainId(), "Should allow any chain ID");
    }

    function test_CreateConfigWithExpiry() public {
        bytes32 config = SSXLibSet.createConfigWithExpiry({
            enabled: true,
            anyChainId: false,
            inspectPreClaimOps: true,
            inspectTargetOps: true,
            claimExpiryMode: PermissionMode.COMPARE,
            fillExpiryMode: PermissionMode.COMPARE,
            recipientMode: PermissionMode.LOCAL_MAPPING,
            tokenOutMode: PermissionMode.LOCAL_MAPPING,
            tokenInMode: PermissionMode.IGNORE
        });

        assertTrue(config.isEnabled(), "Should be enabled");
        assertFalse(config.isAnyTargetChainId(), "Should not allow any chain ID");
    }

    function test_CreatePermissiveConfig() public {
        bytes32 config = SSXLibSet.createPermissiveConfig();

        assertTrue(config.isEnabled(), "Should be enabled");
        assertTrue(config.isAnyTargetChainId(), "Should allow any chain ID");
    }

    function test_CreateRestrictiveConfig() public {
        bytes32 config = SSXLibSet.createRestrictiveConfig();

        assertTrue(config.isEnabled(), "Should be enabled");
        assertFalse(config.isAnyTargetChainId(), "Should require specific chain ID");
    }

    function test_CreateDisabledConfig() public {
        bytes32 config = SSXLibSet.createDisabledConfig();

        assertFalse(config.isEnabled(), "Should be disabled");
    }

    function test_ModifyExistingConfig() public {
        // Start with a permissive config
        bytes32 config = SSXLibSet.createPermissiveConfig();
        assertTrue(config.isEnabled());

        // Modify to be more restrictive
        config = SSXLibSet.setAnyTargetChainId(config, false);
        config = SSXLibSet.setRecipientMode(config, PermissionMode.COMPARE);

        assertTrue(config.isEnabled(), "Should still be enabled");
        assertFalse(config.isAnyTargetChainId(), "Should now require specific chain ID");
    }

    function test_ChainedCalls() public {
        // Demonstrate chained calls for fluent API style
        bytes32 config = bytes32(0);
        config = SSXLibSet.setEnabled(config, true);
        config = SSXLibSet.setAnyTargetChainId(config, true);
        config = SSXLibSet.setPreClaimOps(config, true);
        config = SSXLibSet.setTargetOps(config, true);
        config = SSXLibSet.setRecipientMode(config, PermissionMode.LOCAL_MAPPING);

        assertTrue(config.isEnabled());
        assertTrue(config.isAnyTargetChainId());
    }

    function test_ToggleFlags() public {
        bytes32 config = SSXLibSet.createPermissiveConfig();
        assertTrue(config.isEnabled());

        // Disable
        config = SSXLibSet.setEnabled(config, false);
        assertFalse(config.isEnabled());

        // Re-enable
        config = SSXLibSet.setEnabled(config, true);
        assertTrue(config.isEnabled());
    }

    function test_AllPermissionModes() public {
        bytes32 config = bytes32(0);

        // Test all PermissionMode values for recipient
        config = SSXLibSet.setRecipientMode(config, PermissionMode.IGNORE);
        config = SSXLibSet.setRecipientMode(config, PermissionMode.COMPARE);
        config = SSXLibSet.setRecipientMode(config, PermissionMode.LOCAL_MAPPING);
        config = SSXLibSet.setRecipientMode(config, PermissionMode.EXTERNAL_POLICY);

        // Test all PermissionMode values for tokenOut
        config = SSXLibSet.setTokenOutMode(config, PermissionMode.IGNORE);
        config = SSXLibSet.setTokenOutMode(config, PermissionMode.LOCAL_MAPPING);
        config = SSXLibSet.setTokenOutMode(config, PermissionMode.EXTERNAL_POLICY);

        // Test all PermissionMode values for tokenIn
        config = SSXLibSet.setTokenInMode(config, PermissionMode.IGNORE);
        config = SSXLibSet.setTokenInMode(config, PermissionMode.LOCAL_MAPPING);
        config = SSXLibSet.setTokenInMode(config, PermissionMode.EXTERNAL_POLICY);
    }
}
