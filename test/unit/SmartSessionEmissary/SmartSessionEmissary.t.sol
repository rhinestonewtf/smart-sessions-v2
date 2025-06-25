// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";
import { Solarray } from "solarray/Solarray.sol";

// Contracts
import { SmartSessionEmissaryMock } from "@test/mock/SmartSessionEmissaryMock.sol";

// Libraries
import { IntegrationEncodeLib } from "@smartsessions-test/utils/lib/IntegrationEncodeLib.sol";

// Types
import { SmartSessionMode, PermissionId, ChainDigest } from "@smartsessions/DataTypes.sol";
import { Session, EnableSession } from "@types/DataTypes.sol";

contract SmartSessionEmissary_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The SmartSessionEmissary contract instance.
    SmartSessionEmissaryMock internal smartSessionEmissary;

    /*//////////////////////////////////////////////////////////////
                                  SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();
        // Deploy the SmartSessionEmissary contract.
        smartSessionEmissary = new SmartSessionEmissaryMock();
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    function makeMultiChainEnableData(
        Session memory session,
        address, /*validator*/
        bytes12 lockTag,
        uint256 expires,
        address arbiter,
        address allocator
    )
        internal
        view
        returns (EnableSession memory enableData)
    {
        bytes32 sessionDigest = smartSessionEmissary.getSessionDigest({
            lockTag: lockTag,
            account: instance.account,
            data: session,
            expires: expires,
            allocator: allocator,
            arbiter: arbiter
        });

        ChainDigest[] memory chainDigests = IntegrationEncodeLib.encodeHashesAndChainIds(
            Solarray.uint64s(181_818, uint64(block.chainid), 777),
            Solarray.bytes32s(sessionDigest, sessionDigest, sessionDigest)
        );

        enableData = EnableSession({
            chainDigestIndex: 1,
            hashesAndChainIds: chainDigests,
            sessionToEnable: session
        });
    }
}
