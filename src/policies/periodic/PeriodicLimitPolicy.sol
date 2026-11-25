// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { IPeriodicLimitPolicy } from "@policies/periodic/interfaces/IPeriodicLimitPolicy.sol";
import { IActionPolicy, IPolicy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @title Periodic Limit Policy
/// @author Rhinestone
/// @notice Limits how often an action runs, and how much of one token it moves, per period
///         (e.g. one charge of at most 10 USDC per 30 days).
///
/// @dev A use is recorded when `checkAction` VALIDATES the op, not when it executes, and before
///      the multiplexer checks the session signature. It rolls back only if the validating frame
///      reverts: the executor must revert when verification fails, and where it swallows a failed
///      execution the use is spent without a transfer. Either way a window never admits more than
///      its limits.
///
/// @dev Install requirements:
///      - on exactly ONE action (target + selector), never the fallback action, and not on both
///        `transfer` and `transferFrom`: counters are per (configuration, multiplexer, account),
///        so every action carrying it has its own allowance;
///      - with an amount limit, on `token`'s `transfer` or `transferFrom`; every other op
///        (including `approve`, whose allowance outlives the window) is refused. `transferFrom`
///        counts its amount whatever `from` is; bound the parties with another policy;
///      - tokens the session moves through claims never reach this policy.
contract PeriodicLimitPolicy is IPeriodicLimitPolicy, IActionPolicy {
    /// @dev Length of one ABI-encoded `PeriodicLimitConfig`
    uint256 internal constant CONFIG_LENGTH = 7 * 32;

    mapping(
        ConfigId configId
            => mapping(address multiplexer => mapping(address account => PeriodicLimitConfig))
    ) internal $configs;

    mapping(
        ConfigId configId
            => mapping(address multiplexer => mapping(address account => PeriodicUsage))
    ) internal $usages;

    /*//////////////////////////////////////////////////////////////
                                  INIT
    //////////////////////////////////////////////////////////////*/

    /// @notice Installs the configuration for `account` under the caller (the multiplexer)
    /// @dev Overwrites the configuration but keeps the usage: the multiplexer runs this on every
    ///      enable, and re-enabling the same configuration must not hand out a fresh window
    ///      mid-period. A changed `mode`, `period` or `start` places windows anew, which resets the
    ///      counters.
    /// @param initData One ABI-encoded `PeriodicLimitConfig`
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        override
    {
        if (initData.length != CONFIG_LENGTH) revert InvalidInitDataLength(initData.length);
        PeriodicLimitConfig memory config = abi.decode(initData, (PeriodicLimitConfig));

        if (config.chainId == 0) revert InvalidChainId();
        if (config.period == 0) revert InvalidPeriod();
        if (config.mode == PeriodMode.Fixed && config.start == 0) revert InvalidStart();
        if (config.maxUses == 0 && config.maxAmount == 0) revert NoLimitSet();
        if ((config.token == address(0)) != (config.maxAmount == 0)) {
            revert InvalidToken(config.token, config.maxAmount);
        }

        $configs[configId][msg.sender][account] = config;
        emit IPolicy.PolicySet(configId, msg.sender, account);
    }

    /*//////////////////////////////////////////////////////////////
                                 CHECK
    //////////////////////////////////////////////////////////////*/

    /// @notice Admits the op if the current window has room for one more use and its amount,
    ///         and records both
    /// @return VALIDATION_SUCCESS if admitted, VALIDATION_FAILED otherwise
    function checkAction(
        ConfigId configId,
        address account,
        address target,
        uint256 value,
        bytes calldata data
    )
        external
        override
        returns (uint256)
    {
        PeriodicLimitConfig storage $config = $configs[configId][msg.sender][account];
        if ($config.period == 0 || $config.chainId != block.chainid) return VALIDATION_FAILED;
        if (block.timestamp < $config.start) return VALIDATION_FAILED;

        uint256 maxAmount = $config.maxAmount;
        uint256 amount;
        if (maxAmount != 0) {
            if (target != $config.token || value != 0) return VALIDATION_FAILED;
            bool isTransfer;
            (isTransfer, amount) = _transferAmount(data);
            if (!isTransfer || amount > maxAmount) return VALIDATION_FAILED;
        }

        PeriodicUsage storage $usage = $usages[configId][msg.sender][account];
        uint48 windowStart = _windowStart($config, $usage.windowStart);

        uint256 uses = 1;
        uint256 spent = amount;
        if (windowStart == $usage.windowStart) {
            uses += $usage.uses;
            if (maxAmount != 0) {
                // `amount <= maxAmount` above, so this cannot underflow
                if ($usage.spent > maxAmount - amount) return VALIDATION_FAILED;
                spent += $usage.spent;
            }
        }
        uint256 maxUses = $config.maxUses;
        if (maxUses != 0 && uses > maxUses) return VALIDATION_FAILED;

        $usage.windowStart = windowStart;
        $usage.uses = uint208(uses);
        $usage.spent = spent;

        emit PeriodicLimitUsed(configId, msg.sender, account, windowStart, uses, spent);
        return VALIDATION_SUCCESS;
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPeriodicLimitPolicy
    function getConfig(
        ConfigId configId,
        address multiplexer,
        address account
    )
        external
        view
        override
        returns (PeriodicLimitConfig memory)
    {
        return $configs[configId][multiplexer][account];
    }

    /// @inheritdoc IPeriodicLimitPolicy
    function currentUsage(
        ConfigId configId,
        address multiplexer,
        address account
    )
        external
        view
        override
        returns (uint48 windowStart, uint256 uses, uint256 spent)
    {
        PeriodicLimitConfig storage $config = $configs[configId][multiplexer][account];
        PeriodicUsage storage $usage = $usages[configId][multiplexer][account];
        if (
            $config.period == 0 || $config.chainId != block.chainid
                || block.timestamp < $config.start
        ) {
            return (0, 0, 0);
        }

        windowStart = _windowStart($config, $usage.windowStart);
        if (windowStart == $usage.windowStart) return (windowStart, $usage.uses, $usage.spent);
        // A `FromFirstUse` window opens on its first use; until then there is none.
        if ($config.mode == PeriodMode.FromFirstUse) windowStart = 0;
    }

    /// @notice ERC-165 for the action policy surface and the view surface
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IActionPolicy).interfaceId
            || interfaceId == type(IPolicy).interfaceId
            || interfaceId == type(IPeriodicLimitPolicy).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @dev Start of the window holding `block.timestamp`, given the recorded one.
    ///      Requires `block.timestamp >= config.start`.
    function _windowStart(
        PeriodicLimitConfig storage $config,
        uint48 recorded
    )
        internal
        view
        returns (uint48)
    {
        uint256 period = $config.period;
        if ($config.mode == PeriodMode.Fixed) {
            uint256 start = $config.start;
            return uint48(block.timestamp - (block.timestamp - start) % period);
        }
        if (recorded != 0 && block.timestamp < uint256(recorded) + period) return recorded;
        return uint48(block.timestamp);
    }

    /// @dev The amount an ERC-20 `transfer` or `transferFrom` moves; false for any other call
    function _transferAmount(bytes calldata data) internal pure returns (bool, uint256) {
        if (data.length < 4) return (false, 0);
        bytes4 selector = bytes4(data[0:4]);
        if (selector == IERC20.transfer.selector && data.length >= 68) {
            return (true, uint256(bytes32(data[36:68])));
        }
        if (selector == IERC20.transferFrom.selector && data.length >= 100) {
            return (true, uint256(bytes32(data[68:100])));
        }
        return (false, 0);
    }
}
