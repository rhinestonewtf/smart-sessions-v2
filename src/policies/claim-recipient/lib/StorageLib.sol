// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { PolicyConfig } from "@policies/claim-recipient/lib/ConfigLib.sol";
import {
    ParamRules,
    ParamRule,
    TokenAmountConfig,
    MultichainCompact
} from "@policies/claim-recipient/types/DataTypes.sol";

/*//////////////////////////////////////////////////////////////
                             STRUCTS
//////////////////////////////////////////////////////////////*/

struct PolicyStorage {
    // Mapping to store the policy configuration for each account and config ID
    mapping(
        ConfigId id
            => mapping(
                address msgSender => mapping(address userOpSender => PolicyConfig conditionsBitmap)
            )
    ) policyConfig;
    // Mapping to store token amount configurations per chain id
    mapping(
        ConfigId id
            => mapping(
                address msgSender
                    => mapping(
                        address userOpSender
                            => mapping(uint256 chainId => TokenAmountConfig tokenInConfig)
                    )
            )
    ) tokenInConfig;
    // Mapping to store token amount configurations per target chain id
    mapping(
        ConfigId id
            => mapping(
                address msgSender
                    => mapping(
                        address userOpSender
                            => mapping(uint256 targetChainId => TokenAmountConfig tokenOutConfig)
                    )
            )
    ) tokenOutConfig;
    // Mapping to recipient configurations per chain target chain id
    mapping(
        ConfigId id
            => mapping(
                address msgSender
                    => mapping(
                        address userOpSender => mapping(uint256 targetChainId => address recipient)
                    )
            )
    ) recipientConfig;
    // Mapping to store pre-claim operations configurations
    mapping(
        ConfigId id
            => mapping(
                address msgSender => mapping(address userOpSender => ParamRules preClaimOpsConfig)
            )
    ) preClaimOpsConfig;
    // Mapping to store qualification params
    mapping(
        ConfigId id
            => mapping(
                address msgSender
                    => mapping(
                        address userOpSender
                            => mapping(
                                bytes32 qualificationTypehash => ParamRules qualificationConfig
                            )
                    )
            )
    ) qualificationConfig;
}

/// @title Storage Library
/// @notice Library for managing storage of claim recipient data
library StorageLib {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    // TODO: Hardcode and truncate this
    bytes32 internal constant POLICY_STORAGE_POSITION = keccak256("claim.recipient.policy.storage");

    /*//////////////////////////////////////////////////////////////
                               STORAGE ACCESS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the storage slot for the PolicyStorage struct
    function getPolicyStorage() internal pure returns (PolicyStorage storage ps) {
        bytes32 position = POLICY_STORAGE_POSITION;
        assembly {
            ps.slot := position
        }
    }
}
