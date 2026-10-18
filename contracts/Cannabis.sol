// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ISemaphore} from "@semaphore-protocol/contracts/interfaces/ISemaphore.sol";
import {ISemaphoreGroups} from "@semaphore-protocol/contracts/interfaces/ISemaphoreGroups.sol";

interface ICannabisSemaphore is ISemaphore, ISemaphoreGroups {}

/// @notice Append-only membership. The registrar must independently verify one commitment per person.
/// @dev No member removal, replacement, group-admin transfer or identity-document storage.
contract CannabisEnrollment {
    uint256 public constant MAX_MEMBERS = 990_000;
    ICannabisSemaphore public immutable semaphore;
    address public immutable registrar;
    uint256 public immutable groupId;
    uint256 public enrolledCount;
    error Unauthorized();
    error InvalidEnrollment();

    constructor(address semaphoreAddress, address registrarAddress) {
        if (semaphoreAddress.code.length == 0 || registrarAddress == address(0)) revert InvalidEnrollment();
        semaphore = ICannabisSemaphore(semaphoreAddress);
        registrar = registrarAddress;
        groupId = semaphore.createGroup(address(this));
    }

    function addVerifiedMembers(uint256[] calldata commitments) external {
        if (msg.sender != registrar) revert Unauthorized();
        if (commitments.length == 0 || commitments.length > 256 || enrolledCount + commitments.length > MAX_MEMBERS)
            revert InvalidEnrollment();
        enrolledCount += commitments.length;
        semaphore.addMembers(groupId, commitments);
    }
}

/// @notice Immutable beneficiary and schedule. No administrator or transferable ownership.
contract FounderVesting {
    using SafeERC20 for IERC20;
    IERC20 public immutable token;
    address public immutable beneficiary;
    uint64 public immutable start;
    uint64 public immutable end;
    uint256 public immutable allocation;
    uint256 public released;

    error NothingToRelease();
    event Released(uint256 amount);

    constructor(address beneficiary_, uint64 start_, uint64 end_, uint256 allocation_) {
        token = IERC20(msg.sender);
        beneficiary = beneficiary_;
        start = start_;
        end = end_;
        allocation = allocation_;
    }

    function vestedAt(uint256 timestamp) public view returns (uint256) {
        if (timestamp <= start) return 0;
        if (timestamp >= end) return allocation;
        return allocation * (timestamp - start) / (end - start);
    }

    /// @notice Anyone may trigger release; funds always go to the fixed beneficiary.
    function release() external {
        uint256 amount = vestedAt(block.timestamp) - released;
        if (amount == 0) revert NothingToRelease();
        released += amount;
        token.safeTransfer(beneficiary, amount);
        emit Released(amount);
    }
}

/// @notice Fixed-cap, anonymous membership claims. The reviewed Cannabis ceremony verifies distinct people.
/// @dev No proof-of-work. Underlying network provides consensus. Independent review remains required.
contract Cannabis is ERC20 {
    uint256 public constant CAP = 420_000_000 ether;
    uint256 public constant FOUNDER_ALLOCATION = CAP / 100;
    uint256 public constant COMMUNITY_ALLOCATION = CAP - FOUNDER_ALLOCATION;
    uint256 public constant CLAIM_AMOUNT = 420 ether;
    uint256 public constant MAX_CLAIMANTS = COMMUNITY_ALLOCATION / CLAIM_AMOUNT;
    uint256 public constant MIN_ANONYMITY_SET = 128;
    uint64 public immutable claimsStartAt;
    ICannabisSemaphore public immutable semaphore;
    CannabisEnrollment public immutable enrollment;
    uint256 public immutable groupId;
    uint256 public immutable claimScope;
    FounderVesting public immutable founderVesting;
    uint256 public communityIssued;
    mapping(uint256 => bool) public nullifierClaimed;
    mapping(address => bool) public walletClaimed;

    error InvalidConfiguration();
    error ClaimsNotOpen();
    error InvalidProof();
    error AnonymitySetTooSmall();
    error MembershipRootChanged();
    error AlreadyClaimed();
    error CommunityExhausted();
    event Claimed(address indexed recipient, uint256 indexed nullifier, uint256 amount);

    constructor(address founder, uint64 start, uint64 vestingEnd, address semaphoreAddress, address registrar)
        ERC20("Cannabis", "CANNABIS")
    {
        if (founder == address(0) || start <= block.timestamp || vestingEnd <= start ||
            semaphoreAddress.code.length == 0 || registrar == address(0)) revert InvalidConfiguration();
        claimsStartAt = start;
        semaphore = ICannabisSemaphore(semaphoreAddress);
        enrollment = new CannabisEnrollment(semaphoreAddress, registrar);
        groupId = enrollment.groupId();
        claimScope = uint256(keccak256(abi.encode("Cannabis community claim v1", block.chainid, address(this))));
        founderVesting = new FounderVesting(founder, start, vestingEnd, FOUNDER_ALLOCATION);
        _mint(address(founderVesting), FOUNDER_ALLOCATION);
    }

    /// @notice A relayer may pay gas; the proof always binds the public receiving address.
    /// @dev Uses view verification and our own nullifier registry to avoid external nullifier-burning attacks.
    function claim(address recipient, ISemaphore.SemaphoreProof calldata proof) external {
        if (block.timestamp < claimsStartAt) revert ClaimsNotOpen();
        if (recipient == address(0) || proof.message != uint256(uint160(recipient)) || proof.scope != claimScope) revert InvalidProof();
        if (nullifierClaimed[proof.nullifier] || walletClaimed[recipient]) revert AlreadyClaimed();
        if (communityIssued + CLAIM_AMOUNT > COMMUNITY_ALLOCATION) revert CommunityExhausted();
        if (enrollment.enrolledCount() < MIN_ANONYMITY_SET) revert AnonymitySetTooSmall();
        if (proof.merkleTreeRoot != semaphore.getMerkleTreeRoot(groupId)) revert MembershipRootChanged();
        if (!semaphore.verifyProof(groupId, proof)) revert InvalidProof();
        nullifierClaimed[proof.nullifier] = true;
        walletClaimed[recipient] = true;
        communityIssued += CLAIM_AMOUNT;
        _mint(recipient, CLAIM_AMOUNT);
        emit Claimed(recipient, proof.nullifier, CLAIM_AMOUNT);
    }
}
