// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import {
    SmartSessionEmissaryMock as SmartSessionEmissary
} from "@mocks/SmartSessionEmissaryMock.sol";
import { OwnableValidator } from "@mocks/MockOwnableValidator.sol";
import { EIP712 } from "@solady/utils/EIP712.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Libraries
import { AccountInstance, ModuleKitHelpers } from "@modulekit/ModuleKit.sol";

// Types
import {
    PermissionId,
    PolicyData,
    ActionData,
    ERC7739Data,
    ERC7739Context
} from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";
import { Vm } from "forge-std/Vm.sol";
import {
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { CALLTYPE_STATIC } from "erc7579/lib/ModeLib.sol";

/// @title SmartSessionEmissary Integration Test Base
/// @notice Abstract base contract with shared setup for SmartSessionEmissary integration tests
abstract contract SmartSessionEmissary_Integration_Base_Test is Base_Test {
    using ModuleKitHelpers for *;

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    address internal constant MOCK_INTENT_EXECUTOR =
        address(0x1234567890123456789012345678901234567890);

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice The SmartSessionEmissary contract instance
    SmartSessionEmissary internal smartSessionEmissary;

    /// @notice Ownable validator for real ECDSA signature validation
    OwnableValidator internal ownableValidator;

    /// @notice Default test wallet used when no specific signer is provided
    Vm.Wallet internal testWallet;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();

        // Deploy SmartSessionEmissary with mock intent executor
        smartSessionEmissary = new SmartSessionEmissary(MOCK_INTENT_EXECUTOR);

        // Deploy ownable validator
        ownableValidator = new OwnableValidator();

        // Create default test wallet
        testWallet = vm.createWallet("testSigner");
    }

    /*//////////////////////////////////////////////////////////////
                            ACCOUNT SETUP
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets up a smart account with SmartSessionEmissary as a validator module
    /// @dev Also installs EIP712 domain fallback handler for ERC7739 support
    function setupAccountWithEmissary(AccountInstance memory account) internal {
        // Install SmartSessionEmissary as validator
        account.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR, module: address(smartSessionEmissary), data: ""
        });

        // Install fallback for EIP712 domain queries (needed for ERC7739)
        bytes memory fallbackData = abi.encode(
            bytes4(0x84b0196e), // eip712Domain selector
            CALLTYPE_STATIC,
            ""
        );
        account.installModule({
            moduleTypeId: MODULE_TYPE_FALLBACK, module: address(fallbackModule), data: fallbackData
        });
    }

    /*//////////////////////////////////////////////////////////////
                          SESSION ENABLING
    //////////////////////////////////////////////////////////////*/

    /// @notice Enables a session with the given configuration
    function enableSession(
        AccountInstance memory account,
        Session memory session
    )
        internal
        returns (PermissionId)
    {
        return enableSession(account, session, bytes12(0));
    }

    /// @notice Enables a session with the given configuration and lock tag
    function enableSession(
        AccountInstance memory account,
        Session memory session,
        bytes12 lockTag
    )
        internal
        returns (PermissionId)
    {
        vm.prank(account.account);
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory ids = smartSessionEmissary.enableSessions(sessions, lockTag);
        return ids[0];
    }

    /*//////////////////////////////////////////////////////////////
                         SESSION BUILDERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates session validator init data for OwnableValidator
    function createValidatorInitData(address signer) internal pure returns (bytes memory) {
        address[] memory owners = new address[](1);
        owners[0] = signer;
        return abi.encode(uint256(1), owners);
    }

    /// @notice Creates an EIP-712 domain separator for testing
    function createAppDomainSeparator(
        string memory appName,
        string memory appVersion
    )
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(appName)),
                keccak256(bytes(appVersion)),
                block.chainid,
                address(0xC0FFEE)
            )
        );
    }
}
