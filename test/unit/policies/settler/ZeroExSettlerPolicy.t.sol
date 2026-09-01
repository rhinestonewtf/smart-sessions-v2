// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Testing
import { Test } from "@forge-std/Test.sol";

// Contracts
import { ZeroExSettlerPolicy, IZeroExDeployer } from "@policies/settler/ZeroExSettlerPolicy.sol";

// Interfaces
import { IPolicy, IActionPolicy, I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

// Mocks
import { MockZeroExDeployer } from "@mocks/MockZeroExDeployer.sol";
import { MockViewSource } from "@mocks/MockViewSource.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @notice The 0x AllowanceHolder entrypoint this policy guards
interface IAllowanceHolder {
    function exec(
        address operator,
        address token,
        uint256 amount,
        address target,
        bytes calldata data
    )
        external
        payable
        returns (bytes memory);
}

/// @title ZeroExSettlerPolicy Unit Tests
/// @notice Adversarial unit tests for the 0x Settler action policy
/// @dev The registry address is a constant in the policy, so the mock is etched over it. Etching
///      keeps the address while giving the test control over what the registry returns - including
///      reverting, which is how 0x signals a paused feature. Tests that need a codeless registry
///      simply skip the etch.
contract ZeroExSettlerPolicy_Unit_Test is Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    ZeroExSettlerPolicy internal policy;
    MockZeroExDeployer internal registry;

    ConfigId internal configId;
    address internal account;
    address internal settler;
    address internal token;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mirrors the constant inside the policy
    address internal constant REGISTRY = 0x00000000000004533Fe15556B1E086BB1A72cEae;

    /// @notice 0x feature id for the taker-submitted Settler
    uint256 internal constant FEATURE_TAKER = 2;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        configId = ConfigId.wrap(bytes32(uint256(1)));
        account = makeAddr("account");
        settler = makeAddr("settler");
        token = makeAddr("token");

        _etchRegistry();
        registry.setOwner(FEATURE_TAKER, settler);

        policy = new ZeroExSettlerPolicy();
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Etches the mock registry over the address the policy hardcodes
    function _etchRegistry() internal {
        MockZeroExDeployer mock = new MockZeroExDeployer();
        vm.etch(REGISTRY, address(mock).code);
        registry = MockZeroExDeployer(REGISTRY);
    }

    function _exec(address operator, address target) internal view returns (bytes memory) {
        return abi.encodeCall(IAllowanceHolder.exec, (operator, token, 1 ether, target, hex"1234"));
    }

    function _check(bytes memory data) internal view returns (uint256) {
        return policy.checkAction(configId, account, address(0xA11), 0, data);
    }

    /*//////////////////////////////////////////////////////////////
                             HAPPY PATH
    //////////////////////////////////////////////////////////////*/

    function test_CheckAction_PassesWhenBothFieldsAreTheLiveSettler() public view {
        assertEq(_check(_exec(settler, settler)), VALIDATION_SUCCESS, "live settler");
    }

    /*//////////////////////////////////////////////////////////////
                            THE CORE HOLE
    //////////////////////////////////////////////////////////////*/

    function test_CheckAction_FailsWhenNeitherFieldMatches() public {
        address attacker = makeAddr("attacker");
        assertEq(_check(_exec(attacker, attacker)), VALIDATION_FAILED, "both wrong");
    }

    /// @dev Pinning `operator` alone would let this through, and the token pull would land in an
    ///      attacker-chosen contract
    function test_CheckAction_FailsWhenOnlyOperatorMatches() public {
        address attacker = makeAddr("attacker");
        assertEq(_check(_exec(settler, attacker)), VALIDATION_FAILED, "target redirected");
    }

    /// @dev And pinning `target` alone would let this through
    function test_CheckAction_FailsWhenOnlyTargetMatches() public {
        address attacker = makeAddr("attacker");
        assertEq(_check(_exec(attacker, settler)), VALIDATION_FAILED, "operator redirected");
    }

    function testFuzz_CheckAction_OnlyTheExactPairPasses(
        address operator,
        address targetAddress
    )
        public
        view
    {
        uint256 result = _check(_exec(operator, targetAddress));

        if (operator == settler && targetAddress == settler) {
            assertEq(result, VALIDATION_SUCCESS, "exact pair must pass");
        } else {
            assertEq(result, VALIDATION_FAILED, "anything else must fail");
        }
    }

    /*//////////////////////////////////////////////////////////////
                               ROTATION
    //////////////////////////////////////////////////////////////*/

    /// @dev The reason the policy resolves instead of hardcoding
    function test_CheckAction_PicksUpRotationWithoutReinitialization() public {
        bytes memory oldCall = _exec(settler, settler);
        assertEq(_check(oldCall), VALIDATION_SUCCESS, "passes before rotation");

        address rotated = makeAddr("rotatedSettler");
        registry.setOwner(FEATURE_TAKER, rotated);

        // Nothing was re-initialized, redeployed, or re-signed
        assertEq(_check(oldCall), VALIDATION_FAILED, "retired settler stops passing");
        assertEq(_check(_exec(rotated, rotated)), VALIDATION_SUCCESS, "new settler passes");
    }

    function testFuzz_CheckAction_TracksAnyRotation(address rotated) public {
        vm.assume(rotated != address(0));
        registry.setOwner(FEATURE_TAKER, rotated);

        assertEq(_check(_exec(rotated, rotated)), VALIDATION_SUCCESS, "tracks rotation");
    }

    /// @dev Feature 2 only: the intent Settler must not satisfy this policy
    function test_CheckAction_DoesNotCoverOtherFeatures() public {
        address intentSettler = makeAddr("intentSettler");
        registry.setOwner(4, intentSettler);

        assertEq(_check(_exec(intentSettler, intentSettler)), VALIDATION_FAILED, "feature 4");
    }

    /*//////////////////////////////////////////////////////////////
                             FAIL CLOSED
    //////////////////////////////////////////////////////////////*/

    /// @dev A staticcall to an address with no code SUCCEEDS with empty returndata. Reading that
    ///      as a zero word would compare against zero, so this is the most important fail-closed
    ///      case: it is what happens on a chain where 0x is not deployed.
    function test_CheckAction_FailsWhenRegistryHasNoCode() public {
        vm.etch(REGISTRY, "");
        assertEq(REGISTRY.code.length, 0, "precondition: no code");

        assertEq(_check(_exec(settler, settler)), VALIDATION_FAILED, "must fail closed");
    }

    /// @dev And it must not pass for a call that names address(0) either
    function test_CheckAction_FailsWhenRegistryHasNoCodeAndCalldataIsZero() public {
        vm.etch(REGISTRY, "");

        assertEq(
            _check(_exec(address(0), address(0))),
            VALIDATION_FAILED,
            "zero must not match empty returndata"
        );
    }

    /// @dev 0x pauses a feature by making `ownerOf` revert; a paused Settler must never be used
    function test_CheckAction_FailsWhenRegistryReverts() public {
        registry.setOwnerReverts(FEATURE_TAKER, true);
        assertEq(_check(_exec(settler, settler)), VALIDATION_FAILED, "paused must deny");
    }

    /// @dev A large revert payload must still fail closed rather than bubbling up
    function test_CheckAction_FailsWhenRegistryRevertsWithLargePayload() public {
        registry.setOwnerReverts(FEATURE_TAKER, true);
        registry.setRevertBombWords(20_000);

        assertEq(_check(_exec(settler, settler)), VALIDATION_FAILED, "must fail closed");
    }

    function test_CheckAction_FailsWhenReturndataIsEmpty() public {
        _etchViewSource(0);
        assertEq(_check(_exec(settler, settler)), VALIDATION_FAILED, "0 bytes");
    }

    function test_CheckAction_FailsWhenReturndataIsShort() public {
        _etchViewSource(31);
        assertEq(_check(_exec(settler, settler)), VALIDATION_FAILED, "31 bytes");
    }

    /// @dev Exactly one word is required, so a registry returning another shape is rejected rather
    ///      than having its first word guessed at
    function test_CheckAction_FailsWhenReturndataIsLong() public {
        _etchViewSource(64);
        assertEq(_check(_exec(settler, settler)), VALIDATION_FAILED, "64 bytes");
    }

    function test_CheckAction_PassesWhenReturndataIsExactlyOneWord() public {
        _etchViewSource(32);
        assertEq(_check(_exec(settler, settler)), VALIDATION_SUCCESS, "32 bytes");
    }

    /// @notice Etches a mock returning `size` bytes whose first word is `settler`
    function _etchViewSource(uint256 size) internal {
        MockViewSource source = new MockViewSource();
        source.setValue(bytes32(uint256(uint160(settler))));
        source.setReturnSize(size);

        vm.etch(REGISTRY, address(source).code);
        // Re-apply configuration through the etched code so its storage layout is used
        MockViewSource(payable(REGISTRY)).setValue(bytes32(uint256(uint160(settler))));
        MockViewSource(payable(REGISTRY)).setReturnSize(size);
    }

    /*//////////////////////////////////////////////////////////////
                          MALFORMED CALLDATA
    //////////////////////////////////////////////////////////////*/

    function test_CheckAction_FailsWhenCalldataHasNoSelector() public view {
        assertEq(_check(hex"001122"), VALIDATION_FAILED, "3 bytes");
        assertEq(_check(""), VALIDATION_FAILED, "empty");
    }

    function test_CheckAction_FailsWhenCalldataIsSelectorOnly() public view {
        assertEq(
            _check(abi.encodePacked(IAllowanceHolder.exec.selector)), VALIDATION_FAILED, "no args"
        );
    }

    /// @dev A pinned field that is simply absent must be a mismatch, never a skip. Here `operator`
    ///      matches but the calldata stops before `target`.
    function test_CheckAction_FailsWhenTargetWordIsAbsent() public view {
        bytes memory truncated =
            abi.encodePacked(IAllowanceHolder.exec.selector, bytes32(uint256(uint160(settler))));

        assertEq(_check(truncated), VALIDATION_FAILED, "absent target must not be skipped");
    }

    /// @dev Strict full-word comparison: dirty upper bytes are a false reject, never a false
    ///      accept. Masking would invert that.
    function test_CheckAction_FailsOnDirtyUpperBytes() public view {
        bytes32 dirty = bytes32(uint256(uint160(settler)) | (uint256(1) << 250));

        bytes memory data = abi.encodePacked(
            IAllowanceHolder.exec.selector,
            dirty,
            bytes32(uint256(uint160(token))),
            bytes32(uint256(1 ether)),
            bytes32(uint256(uint160(settler))),
            bytes32(uint256(160))
        );

        assertEq(_check(data), VALIDATION_FAILED, "dirty word must not match");
    }

    /*//////////////////////////////////////////////////////////////
                             STATELESSNESS
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_UsesNoStorageSlots() public view {
        for (uint256 i; i < 8; i++) {
            assertEq(vm.load(address(policy), bytes32(i)), bytes32(0), "unexpected storage");
        }
    }

    function test_CheckAction_WorksWithoutInitialization() public view {
        assertEq(
            _check(_exec(settler, settler)),
            VALIDATION_SUCCESS,
            "uninitialized config must still validate"
        );
    }

    function testFuzz_CheckAction_IsIndependentOfConfigIdAndAccount(
        bytes32 rawConfigId,
        address rawAccount
    )
        public
        view
    {
        uint256 result = policy.checkAction(
            ConfigId.wrap(rawConfigId), rawAccount, address(0xA11), 0, _exec(settler, settler)
        );
        assertEq(result, VALIDATION_SUCCESS, "no per-config state");
    }

    function test_Initialize_IsNoOpAndRepeatable() public {
        vm.expectEmit(true, true, true, true, address(policy));
        emit IPolicy.PolicySet(configId, address(this), account);
        policy.initializeWithMultiplexer(account, configId, "");

        // Re-initialization must not revert; there is nothing to overwrite
        policy.initializeWithMultiplexer(account, configId, hex"deadbeef");

        assertEq(_check(_exec(settler, settler)), VALIDATION_SUCCESS, "unaffected by init");
    }

    /*//////////////////////////////////////////////////////////////
                              INTERFACES
    //////////////////////////////////////////////////////////////*/

    function test_SupportsInterface() public view {
        assertTrue(policy.supportsInterface(type(IERC165).interfaceId), "IERC165");
        assertTrue(policy.supportsInterface(type(IPolicy).interfaceId), "IPolicy");
        assertTrue(policy.supportsInterface(type(IActionPolicy).interfaceId), "IActionPolicy");

        // Not a 1271 policy: that surface's payload is not a function call, so the offsets would
        // pin meaningless words
        assertFalse(policy.supportsInterface(type(I1271Policy).interfaceId), "I1271Policy");
        assertFalse(policy.supportsInterface(0xffffffff), "invalid");
    }
}
