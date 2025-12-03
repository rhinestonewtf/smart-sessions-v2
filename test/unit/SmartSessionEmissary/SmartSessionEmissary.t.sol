// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";
import { Solarray } from "solarray/Solarray.sol";

// Contracts
import { SmartSessionEmissaryMock } from "@test/mock/SmartSessionEmissaryMock.sol";

// Interfaces
import { ISmartSessionLens } from "@interfaces/ISmartSessionLens.sol";

// Libraries
import { IntegrationEncodeLib } from "@smartsessions-test/utils/lib/IntegrationEncodeLib.sol";

// Types
import { PermissionId, ChainDigest } from "@smartsessions/DataTypes.sol";
import { Session, EnableSession } from "@types/DataTypes.sol";

contract SmartSessionEmissary_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The SmartSessionEmissary contract instance.
    SmartSessionEmissaryMock internal smartSessionEmissary;

    /// @notice Mock intent executor address.
    address internal MOCK_INTENT_EXECUTOR;

    /*//////////////////////////////////////////////////////////////
                                  SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();
        // Define the mock intent executor address.
        MOCK_INTENT_EXECUTOR = makeAddr("MockIntentExecutor");
        // Deploy the SmartSessionEmissary contract.
        smartSessionEmissary = new SmartSessionEmissaryMock(MOCK_INTENT_EXECUTOR);
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    function makeMultiChainEnableData(
        Session memory session,
        address, /*validator*/
        bytes12 lockTag,
        uint256 expires,
        address,
        address /*allocator*/
    )
        internal
        view
        returns (EnableSession memory enableData)
    {
        bytes32 sessionDigest = ISmartSessionLens(address(smartSessionEmissary))
            .getSessionDigest({
                lockTag: lockTag, account: instance.account, data: session, expires: expires
            });

        ChainDigest[] memory chainDigests = IntegrationEncodeLib.encodeHashesAndChainIds(
            Solarray.uint64s(181_818, uint64(block.chainid), 777),
            Solarray.bytes32s(sessionDigest, sessionDigest, sessionDigest)
        );

        enableData = EnableSession({
            chainDigestIndex: 1, hashesAndChainIds: chainDigests, sessionToEnable: session
        });
    }
}
