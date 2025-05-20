// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionManager_Unit_Test } from
    "@test/unit/SmartSessionManager/SmartSessionManager.t.sol";

// Interfaces
import { ISmartSessionExecutionVerifier } from "@interfaces/ISmartSessionExecutionVerifier.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

contract SmartSessionManager_setWhitelistedSource_Test is SmartSessionManager_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    address testSource;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();

        // Initialize test variables
        testSource = makeAddr("testSource");
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    ///-------------------------------///
    /// 1. When caller is not owner   ///
    ///-------------------------------///

    function test_setWhitelistedSource_RevertWhen_CallerNotOwner() public {
        // Arrange
        address notOwner = makeAddr("notOwner");

        // Act/Assert
        vm.prank(notOwner);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, notOwner)
        );
        smartSessionManager.setWhitelistedSource(testSource, true);
    }

    ///-------------------------------///
    /// 2. When caller is owner       ///
    ///-------------------------------///

    function test_setWhitelistedSource_WhenWhitelistingSource_NotCurrentlyWhitelisted() public {
        // Arrange
        // Verify source is not whitelisted initially
        assertFalse(
            smartSessionManager.$whitelistedSources(testSource),
            "Source should not be whitelisted initially"
        );

        // Act
        vm.prank(admin.addr);
        vm.expectEmit(true, true, false, true);
        emit ISmartSessionExecutionVerifier.WhitelistStatusUpdated(testSource, true);
        smartSessionManager.setWhitelistedSource(testSource, true);

        // Assert
        assertTrue(
            smartSessionManager.$whitelistedSources(testSource), "Source should be whitelisted"
        );
    }

    function test_setWhitelistedSource_WhenWhitelistingSource_AlreadyWhitelisted() public {
        // Arrange
        // First whitelist the source
        vm.prank(admin.addr);
        smartSessionManager.setWhitelistedSource(testSource, true);
        assertTrue(
            smartSessionManager.$whitelistedSources(testSource), "Source should be whitelisted"
        );

        // Act
        vm.prank(admin.addr);
        vm.expectEmit(true, true, false, true);
        emit ISmartSessionExecutionVerifier.WhitelistStatusUpdated(testSource, true);
        smartSessionManager.setWhitelistedSource(testSource, true);

        // Assert
        assertTrue(
            smartSessionManager.$whitelistedSources(testSource), "Source should remain whitelisted"
        );
    }

    function test_setWhitelistedSource_WhenRemovingFromWhitelist_CurrentlyWhitelisted() public {
        // Arrange
        // First whitelist the source
        vm.prank(admin.addr);
        smartSessionManager.setWhitelistedSource(testSource, true);
        assertTrue(
            smartSessionManager.$whitelistedSources(testSource), "Source should be whitelisted"
        );

        // Act
        vm.prank(admin.addr);
        vm.expectEmit(true, true, false, true);
        emit ISmartSessionExecutionVerifier.WhitelistStatusUpdated(testSource, false);
        smartSessionManager.setWhitelistedSource(testSource, false);

        // Assert
        assertFalse(
            smartSessionManager.$whitelistedSources(testSource), "Source should not be whitelisted"
        );
    }

    function test_setWhitelistedSource_WhenRemovingFromWhitelist_NotCurrentlyWhitelisted() public {
        // Arrange
        // Verify source is not whitelisted initially
        assertFalse(
            smartSessionManager.$whitelistedSources(testSource),
            "Source should not be whitelisted initially"
        );

        // Act
        vm.prank(admin.addr);
        vm.expectEmit(true, true, false, true);
        emit ISmartSessionExecutionVerifier.WhitelistStatusUpdated(testSource, false);
        smartSessionManager.setWhitelistedSource(testSource, false);

        // Assert
        assertFalse(
            smartSessionManager.$whitelistedSources(testSource),
            "Source should remain not whitelisted"
        );
    }

    ///-------------------------------///
    /// 3. Edge Cases                 ///
    ///-------------------------------///

    function test_setWhitelistedSource_WithZeroAddress() public {
        // Arrange/Act
        vm.prank(admin.addr);
        vm.expectEmit(true, true, false, true);
        emit ISmartSessionExecutionVerifier.WhitelistStatusUpdated(address(0), true);
        smartSessionManager.setWhitelistedSource(address(0), true);

        // Assert
        assertTrue(
            smartSessionManager.$whitelistedSources(address(0)),
            "Zero address should be whitelisted"
        );
    }

    function test_setWhitelistedSource_MultipleSourcesSequentially() public {
        // Arrange
        address source1 = makeAddr("source1");
        address source2 = makeAddr("source2");
        address source3 = makeAddr("source3");

        // Act & Assert
        vm.startPrank(admin.addr);

        // Whitelist multiple sources
        smartSessionManager.setWhitelistedSource(source1, true);
        smartSessionManager.setWhitelistedSource(source2, true);
        smartSessionManager.setWhitelistedSource(source3, true);

        // Verify all are whitelisted
        assertTrue(
            smartSessionManager.$whitelistedSources(source1), "Source1 should be whitelisted"
        );
        assertTrue(
            smartSessionManager.$whitelistedSources(source2), "Source2 should be whitelisted"
        );
        assertTrue(
            smartSessionManager.$whitelistedSources(source3), "Source3 should be whitelisted"
        );

        // Remove one from whitelist
        smartSessionManager.setWhitelistedSource(source2, false);

        // Verify selective removal
        assertTrue(
            smartSessionManager.$whitelistedSources(source1), "Source1 should remain whitelisted"
        );
        assertFalse(
            smartSessionManager.$whitelistedSources(source2), "Source2 should not be whitelisted"
        );
        assertTrue(
            smartSessionManager.$whitelistedSources(source3), "Source3 should remain whitelisted"
        );

        vm.stopPrank();
    }
}
