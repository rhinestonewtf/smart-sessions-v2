// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { IEmissary } from "@compact-utils/interfaces/IEmissary.sol";

interface ISmartSessionEmissary is IEmissary {
    /*//////////////////////////////////////////////////////////////
                                  ERRORS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the Smart Session Emissary configuration for a specific account.
    /// @param account The address of the account for which the configuration is being set.
    /// @param config The Smart Session Emissary configuration.
    /// @param enable The Emissary enable data.
    function setConfig(
        address account,
        SmartSessionEmissaryConfig calldata config,
        EmissaryEnable calldata enable
    )
        external;

    /// @notice Sets the vanilla Emissary configuration for a specific account.
    /// @param account The address of the account for which the configuration is being set.
    /// @param config The Emissary configuration.
    /// @param enable The Emissary enable data.
    function setConfig(
        address account,
        EmissaryConfig calldata config,
        EmissaryEnable calldata enable
    )
        external;
}
