// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

interface ICommunityEnrollment {
    function registrar() external view returns (address);
    function addVerifiedMembers(uint256[] calldata commitments) external;
}

/// @notice Recurring Cannabis ceremonies with a permanent append-only registry.
/// @dev Venue and registry quorums attest human checks; signatures/tags do not prove people.
/// No founder bypass, identity replacement, registry reset or privileged token mint.
/// The registry reviewer set changes only by a quorum of the current reviewers.
contract CommunityRegistrar is EIP712 {
    uint256 public constant FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes32 public constant ROUND_TYPEHASH = keccak256("RoundPolicy(uint64 number,bytes32 policyRoot,uint64 startsAt,uint64 endsAt,uint64 submissionsCloseAt)");
    bytes32 public constant ROSTER_TYPEHASH = keccak256("VenueRoster(uint64 round,bytes32 policyRoot,address enrollment,uint64 startsAt,uint64 endsAt,uint64 submissionsCloseAt,bytes32 venueId,bytes32 commitmentsHash,bytes32 personTagsHash)");
    bytes32 public constant PERSON_TYPEHASH = keccak256("PersonApproval(bytes32 rosterDigest)");
    bytes32 public constant VENUE_TYPEHASH = keccak256("Cannabis venue policy v1");
    bytes32 public constant REVIEWERS_TYPEHASH = keccak256("ReviewerChange(uint64 epoch,bytes32 reviewersHash,uint8 quorum,uint64 deadline)");
    ICommunityEnrollment public immutable enrollment;
    uint8 public registryQuorum;
    uint64 public reviewerEpoch;
    address[] public registryReviewers;
    mapping(address => bool) public isRegistryReviewer;
    uint64 public roundCount;
    uint64 public lastSubmissionCloseAt;
    mapping(uint64 => Round) public rounds;
    mapping(uint64 => mapping(bytes32 => bool)) public venueSubmitted;
    mapping(uint256 => bool) public commitmentEnrolled;
    mapping(bytes32 => uint256) public personCommitment;

    struct Round { uint64 number; bytes32 policyRoot; uint64 startsAt; uint64 endsAt; uint64 submissionsCloseAt; }
    struct Venue { bytes32 id; uint16 capacity; uint8 quorum; address[] witnesses; }
    struct Submission {
        uint64 round; Venue venue; bytes32[] proof; uint256[] commitments; bytes32[] personTags;
        bytes[] witnessApprovals; bytes[] registryApprovals;
    }
    error InvalidPolicy();
    error OutsideSubmissionWindow();
    error InvalidRoster();
    error InvalidApproval();
    event RoundAuthorized(uint64 indexed number, bytes32 policyRoot, uint64 startsAt, uint64 endsAt, uint64 submissionsCloseAt);
    event VenueEnrolled(uint64 indexed round, bytes32 indexed venueId, bytes32 commitmentsHash, bytes32 personTagsHash, uint256 count);
    event ReviewersChanged(uint64 indexed epoch, bytes32 reviewersHash, uint8 quorum, uint256 count);

    constructor(address expectedEnrollment, address[] memory reviewers, uint8 quorum)
        EIP712("Cannabis community registrar", "1")
    {
        if (expectedEnrollment == address(0)) revert InvalidPolicy();
        enrollment = ICommunityEnrollment(expectedEnrollment);
        _setReviewers(reviewers, quorum);
    }

    function registryReviewerCount() external view returns (uint256) {
        return registryReviewers.length;
    }

    function reviewerChangeDigest(address[] calldata reviewers, uint8 quorum, uint64 deadline) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(REVIEWERS_TYPEHASH, reviewerEpoch,
            keccak256(abi.encode(reviewers)), quorum, deadline)));
    }

    /// @notice Replace the reviewer set (adding and/or removing reviewers) with approval of the current quorum.
    /// Each approval is bound to the current epoch, so a completed change cannot be replayed.
    function changeReviewers(address[] calldata reviewers, uint8 quorum, uint64 deadline, bytes[] calldata approvals) external {
        if (deadline < block.timestamp || deadline > block.timestamp + 30 days) revert InvalidApproval();
        _registryApproval(reviewerChangeDigest(reviewers, quorum, deadline), approvals);
        for (uint256 i; i < registryReviewers.length; ++i) isRegistryReviewer[registryReviewers[i]] = false;
        delete registryReviewers;
        ++reviewerEpoch;
        _setReviewers(reviewers, quorum);
    }

    function _setReviewers(address[] memory reviewers, uint8 quorum) private {
        if (reviewers.length < 3 || reviewers.length > 9 ||
            quorum < (2 * reviewers.length + 2) / 3 || quorum > reviewers.length) revert InvalidPolicy();
        address previous;
        for (uint256 i; i < reviewers.length; ++i) {
            if (reviewers[i] <= previous || reviewers[i] == address(enrollment)) revert InvalidPolicy();
            previous = reviewers[i];
            isRegistryReviewer[previous] = true;
        }
        registryReviewers = reviewers;
        registryQuorum = quorum;
        emit ReviewersChanged(reviewerEpoch, keccak256(abi.encode(reviewers)), quorum, reviewers.length);
    }

    function roundDigest(Round calldata round) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(ROUND_TYPEHASH, round.number, round.policyRoot,
            round.startsAt, round.endsAt, round.submissionsCloseAt)));
    }

    function authorizeRound(Round calldata round, bytes[] calldata approvals) external {
        if (round.number != roundCount + 1 || round.policyRoot == bytes32(0) ||
            round.startsAt < block.timestamp + 7 days || round.startsAt <= lastSubmissionCloseAt ||
            round.endsAt < uint256(round.startsAt) + 3600 || round.endsAt > uint256(round.startsAt) + 14400 ||
            round.submissionsCloseAt < uint256(round.endsAt) + 1 days || round.submissionsCloseAt > uint256(round.endsAt) + 30 days) revert InvalidPolicy();
        _registryApproval(roundDigest(round), approvals);
        rounds[round.number] = round;
        roundCount = round.number;
        lastSubmissionCloseAt = round.submissionsCloseAt;
        emit RoundAuthorized(round.number, round.policyRoot, round.startsAt, round.endsAt, round.submissionsCloseAt);
    }

    function venueLeaf(Venue calldata venue) public pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(VENUE_TYPEHASH, venue.id, venue.capacity,
            venue.quorum, keccak256(abi.encode(venue.witnesses))))));
    }

    function rosterDigest(uint64 number, bytes32 venueId, uint256[] calldata commitments, bytes32[] calldata personTags) public view returns (bytes32) {
        Round memory round = rounds[number];
        return _hashTypedDataV4(keccak256(abi.encode(ROSTER_TYPEHASH, number, round.policyRoot,
            address(enrollment), round.startsAt, round.endsAt, round.submissionsCloseAt,
            venueId, keccak256(abi.encode(commitments)), keccak256(abi.encode(personTags)))));
    }

    function personApprovalDigest(bytes32 roster) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(PERSON_TYPEHASH, roster)));
    }

    function registerVenue(Submission calldata submission) external {
        Round memory round = rounds[submission.round];
        if (round.number == 0 || block.timestamp <= round.endsAt || block.timestamp > round.submissionsCloseAt) revert OutsideSubmissionWindow();
        Venue calldata venue = submission.venue;
        if (venue.id == bytes32(0) || venueSubmitted[submission.round][venue.id] || venue.capacity == 0 || venue.capacity > 256 ||
            submission.proof.length > 20 || !MerkleProof.verifyCalldata(submission.proof, round.policyRoot, venueLeaf(venue))) revert InvalidPolicy();
        _consumeRoster(venue.capacity, submission.commitments, submission.personTags);
        bytes32 digest = rosterDigest(submission.round, venue.id, submission.commitments, submission.personTags);
        _witnessApproval(digest, venue, submission.witnessApprovals);
        _registryApproval(personApprovalDigest(digest), submission.registryApprovals);
        if (enrollment.registrar() != address(this)) revert InvalidPolicy();
        venueSubmitted[submission.round][venue.id] = true;
        enrollment.addVerifiedMembers(submission.commitments);
        emit VenueEnrolled(submission.round, venue.id, keccak256(abi.encode(submission.commitments)), keccak256(abi.encode(submission.personTags)), submission.commitments.length);
    }

    function _witnessApproval(bytes32 digest, Venue calldata venue, bytes[] calldata approvals) private view {
        uint256 count = venue.witnesses.length;
        if (count < 3 || count > 9 || venue.quorum < (2 * count + 2) / 3 || venue.quorum > count ||
            approvals.length < venue.quorum || approvals.length > count) revert InvalidApproval();
        address previous;
        for (uint256 i; i < count; ++i) {
            if (venue.witnesses[i] <= previous || isRegistryReviewer[venue.witnesses[i]]) revert InvalidApproval();
            previous = venue.witnesses[i];
        }
        previous = address(0);
        for (uint256 i; i < approvals.length; ++i) {
            address signer = ECDSA.recover(digest, approvals[i]);
            if (signer <= previous) revert InvalidApproval();
            bool approved;
            for (uint256 j; j < count; ++j) if (venue.witnesses[j] == signer) approved = true;
            if (!approved) revert InvalidApproval();
            previous = signer;
        }
    }

    function _consumeRoster(uint256 capacity, uint256[] calldata commitments, bytes32[] calldata personTags) private {
        if (commitments.length == 0 || commitments.length > capacity || commitments.length != personTags.length) revert InvalidRoster();
        uint256 previousCommitment;
        // Mark first, under revert atomicity, so a repeated tag inside this batch
        // fails as well as a tag used in any earlier venue or round.
        for (uint256 i; i < commitments.length; ++i) {
            uint256 commitment = commitments[i]; bytes32 tag = personTags[i];
            if (commitment <= previousCommitment || commitment >= FIELD || commitmentEnrolled[commitment] ||
                tag == bytes32(0) || personCommitment[tag] != 0) revert InvalidRoster();
            previousCommitment = commitment;
            commitmentEnrolled[commitment] = true;
            personCommitment[tag] = commitment;
        }
    }

    function _registryApproval(bytes32 digest, bytes[] calldata approvals) private view {
        if (approvals.length < registryQuorum || approvals.length > registryReviewers.length) revert InvalidApproval();
        address previous;
        for (uint256 i; i < approvals.length; ++i) {
            address signer = ECDSA.recover(digest, approvals[i]);
            if (signer <= previous || !isRegistryReviewer[signer]) revert InvalidApproval();
            previous = signer;
        }
    }
}
