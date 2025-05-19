// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";
import { Solarray } from "solarray/Solarray.sol";

// Contracts
import { SmartSessionExecutionVerifier } from "@contracts/SmartSessionExecutionVerifier.sol";

// Libraries
import { IntegrationEncodeLib } from "@smartsessions-test/utils/lib/IntegrationEncodeLib.sol";

// Types
import {
    SmartSessionMode,
    PermissionId,
    Session,
    EnableSession,
    ChainDigest
} from "@smartsessions/DataTypes.sol";

contract SmartSessionExecutionVerifier_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The SmartSessionExecutionVerifier contract instance.
    SmartSessionExecutionVerifier internal smartSessionExecutionVerifier;

    /*//////////////////////////////////////////////////////////////
                                  SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();
        // Deploy the SmartSessionExecutionVerifier contract.
        smartSessionExecutionVerifier = new SmartSessionExecutionVerifier(admin.addr);
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    function makeMultiChainEnableData(
        PermissionId permissionId,
        Session memory session,
        address validator
    )
        internal
        view
        returns (EnableSession memory enableData)
    {
        bytes32 sessionDigest = smartSessionExecutionVerifier.getSessionDigest({
            permissionId: permissionId,
            account: instance.account,
            data: session,
            mode: SmartSessionMode.ENABLE
        });

        ChainDigest[] memory chainDigests = IntegrationEncodeLib.encodeHashesAndChainIds(
            Solarray.uint64s(181_818, uint64(block.chainid), 777),
            Solarray.bytes32s(sessionDigest, sessionDigest, sessionDigest)
        );

        enableData = EnableSession({
            chainDigestIndex: 1,
            hashesAndChainIds: chainDigests,
            sessionToEnable: session,
            permissionEnableSig: abi.encodePacked(validator, hex"42069420")
        });
    }
}
