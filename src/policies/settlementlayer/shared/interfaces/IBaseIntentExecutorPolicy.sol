// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title IBaseIntentExecutorPolicy
/// @notice Public surface every IntentExecutor-family policy exposes for inspection.
///         Concrete policies extend this with their own getters.
interface IBaseIntentExecutorPolicy {
    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Data blob shorter than its declared header.
    error DataTruncated(uint256 expected, uint256 got);

    /// @notice First byte of the data blob declares an unsupported variant.
    /// @dev v1 supports only `VARIANT_SINGLE_CHAIN` (= 0).
    error VariantNotSupported(uint8 variant);

    /// @notice The account encoded in the data blob doesn't match the caller argument,
    ///         or the policy was installed with `FLAG_LOCK_ACCOUNT` and a different
    ///         account is now trying to use it.
    error AccountMismatch(address expected, address provided);

    /// @notice Recomputed EIP-712 digest doesn't match the `hash` smart-sessions handed in.
    error DigestMismatch();

    /// @notice Install set `FLAG_REQUIRE_GAS_REFUND` but the data blob carries no
    ///         GasRefund commitment.
    error GasRefundRequired();

    /// @notice Gas-refund token isn't on the install whitelist.
    error GasTokenNotWhitelisted(address token);

    /// @notice GasRefund.exchangeRate exceeds the install-time cap.
    error ExchangeRateOverCap(uint256 provided, uint256 cap);

    /*//////////////////////////////////////////////////////////////
                                VIEWS
    //////////////////////////////////////////////////////////////*/

    function getIntentExecutor(ConfigId configId, address account) external view returns (address);

    function getGasTokenWhitelist(
        ConfigId configId,
        address account
    )
        external
        view
        returns (address[] memory tokens);

    function getMaxExchangeRate(ConfigId configId, address account) external view returns (uint256);
}
