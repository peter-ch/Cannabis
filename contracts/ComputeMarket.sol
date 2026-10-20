// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ComputeEscrow} from "./ComputeEscrow.sol";

/// @notice Permissionless discovery and shared capacity bookings for two immutable escrows.
/// @dev Resource identities/capacities are provider declarations, not hardware admission.
///      No administrator, custody, key release, execution or physical-capacity oracle.
contract ComputeMarket is EIP712 {
    uint256 public constant MAX_BATCH = 64;
    uint256 public constant MAX_RESOURCE_BOOKINGS = 64;
    uint64 public constant MAX_HOLD_SECONDS = 30 minutes;
    uint64 public constant MAX_HORIZON = 90 days;
    bytes32 public constant BOOKING_TYPEHASH = keccak256(
        "Booking(bytes32 reservationId,bytes32 offerId,address requester,bytes32 orderId,bytes32 termsDigest,uint64 start,uint64 end,uint32 units,uint256 gross,uint64 holdUntil)"
    );
    ComputeEscrow public immutable nativeEscrow;
    ComputeEscrow public immutable cannabisEscrow;

    struct Resource { address provider; bytes32 serviceHash; uint32 units; }
    struct Offer {
        bytes32 resource;
        address escrow;
        bytes32 policyHash;
        bytes32 manifestHash;
        uint64 start;
        uint64 end;
        uint64 expiresAt;
        uint32 units;
        uint256 grossPerUnitSecond;
    }
    struct Booking {
        bytes32 reservationId;
        bytes32 offerId;
        address requester;
        bytes32 orderId;
        bytes32 termsDigest;
        uint64 start;
        uint64 end;
        uint32 units;
        uint256 gross;
        uint64 holdUntil;
    }
    struct Record { Booking booking; bool activated; }
    struct Span { uint64 start; uint64 end; uint32 units; bytes32 offerId; }

    mapping(bytes32 => Resource) public resources;
    mapping(bytes32 => Offer) public offers;
    mapping(bytes32 => bool) public withdrawnOffers;
    mapping(bytes32 => Record) public bookings;
    mapping(address => mapping(bytes32 => bool)) public usedReservationIds;
    mapping(bytes32 => bytes32[]) private resourceBookings;
    mapping(address => mapping(bytes32 => bool)) public activatedOrders;

    error InvalidTerms();
    error Unauthorized();
    error AlreadyUsed();
    error Expired();
    error CapacityExceeded();
    error BookingLimit();
    error FundingMismatch();

    event ResourcePublished(bytes32 indexed resource, address indexed provider, bytes32 serviceHash, uint32 units);
    event OfferPublished(bytes32 indexed offerId, bytes32 indexed resource, address indexed escrow, Offer offer);
    event OfferWithdrawn(bytes32 indexed offerId);
    event Reserved(bytes32 indexed bookingId, bytes32 indexed offerId, address indexed requester, Booking booking);
    event Activated(address indexed escrow, bytes32 indexed orderId, address indexed requester, bytes32[] reservationIds);

    constructor(ComputeEscrow native_, ComputeEscrow cannabis_) EIP712("Cannabis compute market", "1") {
        if (address(native_) == address(cannabis_) || address(native_.token()) != address(0) ||
            address(cannabis_.token()) == address(0) || native_.FEE_BPS() != 100 || cannabis_.FEE_BPS() != 100 ||
            native_.founderRecipient() != cannabis_.founderRecipient()) revert InvalidTerms();
        nativeEscrow = native_;
        cannabisEscrow = cannabis_;
    }

    function resourceKey(address provider, bytes32 resourceId) public pure returns (bytes32) {
        return keccak256(abi.encode(provider, resourceId));
    }

    function publishResource(bytes32 resourceId, bytes32 serviceHash, uint32 units) external returns (bytes32 key) {
        if (resourceId == bytes32(0) || serviceHash == bytes32(0) || units == 0) revert InvalidTerms();
        key = resourceKey(msg.sender, resourceId);
        if (resources[key].provider != address(0)) revert AlreadyUsed();
        resources[key] = Resource(msg.sender, serviceHash, units);
        emit ResourcePublished(key, msg.sender, serviceHash, units);
    }

    function publishOffer(bytes32 nonce, Offer calldata offer) external returns (bytes32 id) {
        Resource memory resource = resources[offer.resource];
        if (resource.provider != msg.sender) revert Unauthorized();
        if (nonce == bytes32(0) || (offer.escrow != address(nativeEscrow) && offer.escrow != address(cannabisEscrow)) ||
            offer.policyHash == bytes32(0) || offer.manifestHash == bytes32(0) ||
            offer.start < block.timestamp || offer.end <= offer.start || offer.end > block.timestamp + MAX_HORIZON ||
            offer.expiresAt <= block.timestamp || offer.expiresAt > offer.end ||
            offer.units == 0 || offer.units > resource.units || offer.grossPerUnitSecond == 0 ||
            offer.grossPerUnitSecond % 100 != 0) revert InvalidTerms();
        id = keccak256(abi.encode(msg.sender, nonce));
        if (offers[id].resource != bytes32(0)) revert AlreadyUsed();
        offers[id] = offer;
        emit OfferPublished(id, offer.resource, offer.escrow, offer);
    }

    /// @notice Stops new bookings only. Previously signed, recorded holds are preserved.
    function withdrawOffer(bytes32 id) external {
        if (resources[offers[id].resource].provider != msg.sender) revert Unauthorized();
        withdrawnOffers[id] = true;
        emit OfferWithdrawn(id);
    }

    function bookingDigest(Booking calldata booking) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(BOOKING_TYPEHASH, booking)));
    }

    /// @notice The requester submits; each provider separately authorizes its exact hold.
    ///         All entries succeed together or the transaction leaves no reservations.
    function reserveBatch(Booking[] calldata requests, bytes[] calldata signatures) external {
        if (requests.length == 0 || requests.length > MAX_BATCH || requests.length != signatures.length) revert InvalidTerms();
        for (uint256 i; i < requests.length; ++i) _reserve(requests[i], signatures[i]);
    }

    function _reserve(Booking calldata b, bytes calldata signature) private {
        Offer memory offer = offers[b.offerId];
        address provider = resources[offer.resource].provider;
        if (b.requester != msg.sender || provider == address(0)) revert Unauthorized();
        if (b.reservationId == bytes32(0) || b.orderId == bytes32(0) || b.termsDigest == bytes32(0) ||
            b.start < offer.start || b.end > offer.end || b.end <= b.start || b.units == 0 || b.units > offer.units ||
            b.gross != offer.grossPerUnitSecond * (b.end - b.start) * b.units) revert InvalidTerms();
        if (withdrawnOffers[b.offerId] || offer.expiresAt <= block.timestamp || b.start <= block.timestamp ||
            b.holdUntil <= block.timestamp || b.holdUntil > block.timestamp + MAX_HOLD_SECONDS ||
            b.holdUntil > b.start || b.holdUntil > offer.expiresAt) revert Expired();
        if (usedReservationIds[b.requester][b.reservationId] || activatedOrders[offer.escrow][b.orderId]) revert AlreadyUsed();
        bytes32 id = bookingDigest(b);
        if (!SignatureChecker.isValidSignatureNow(provider, id, signature)) revert Unauthorized();
        _prune(offer.resource);
        bytes32[] storage ids = resourceBookings[offer.resource];
        if (ids.length >= MAX_RESOURCE_BOOKINGS) revert BookingLimit();
        Span[] memory spans = new Span[](ids.length + 1);
        for (uint256 i; i < ids.length; ++i) {
            Booking storage old = bookings[ids[i]].booking;
            spans[i] = Span(old.start, old.end, old.units, old.offerId);
        }
        spans[ids.length] = Span(b.start, b.end, b.units, b.offerId);
        // Occupancy can increase only at an interval start. Half-open intervals
        // release capacity before a new booking at the same instant.
        _checkUsage(spans, b.start, b.offerId, resources[offer.resource].units, offer.units);
        for (uint256 i; i < ids.length; ++i) {
            if (spans[i].start > b.start && spans[i].start < b.end)
                _checkUsage(spans, spans[i].start, b.offerId, resources[offer.resource].units, offer.units);
        }
        usedReservationIds[b.requester][b.reservationId] = true;
        bookings[id] = Record(b, false);
        ids.push(id);
        emit Reserved(id, b.offerId, b.requester, b);
    }

    function _checkUsage(Span[] memory spans, uint64 at, bytes32 offerId, uint32 resourceLimit, uint32 offerLimit) private pure {
        uint256 resourceUsed;
        uint256 offerUsed;
        for (uint256 i; i < spans.length; ++i) if (spans[i].start <= at && at < spans[i].end) {
            resourceUsed += spans[i].units;
            if (spans[i].offerId == offerId) offerUsed += spans[i].units;
        }
        if (resourceUsed > resourceLimit || offerUsed > offerLimit) revert CapacityExceeded();
    }

    function _prune(bytes32 resource) private {
        bytes32[] storage ids = resourceBookings[resource];
        uint256 i;
        while (i < ids.length) {
            Record storage record = bookings[ids[i]];
            if (record.booking.end <= block.timestamp || (!record.activated && record.booking.holdUntil <= block.timestamp)) {
                ids[i] = ids[ids.length - 1];
                ids.pop();
            } else ++i;
        }
    }

    function inventory(bytes32 resource) external view returns (bytes32[] memory) { return resourceBookings[resource]; }

    /// @notice Anyone can activate a complete booked order; no coordinator privilege.
    ///         IDs must be strictly ascending. This preserves capacity until service end.
    function activate(bytes32[] calldata ids) external {
        if (ids.length == 0 || ids.length > MAX_BATCH) revert InvalidTerms();
        Record storage first = bookings[ids[0]];
        address escrowAddress = offers[first.booking.offerId].escrow;
        if (escrowAddress == address(0)) revert InvalidTerms();
        ComputeEscrow escrow = ComputeEscrow(escrowAddress);
        bytes32 orderId = first.booking.orderId;
        if (activatedOrders[escrowAddress][orderId]) revert AlreadyUsed();
        ComputeEscrow.Order memory order = _order(escrow, orderId);
        if (order.state != ComputeEscrow.State.Active || order.workerCount != order.acceptedCount) revert FundingMismatch();
        (address[] memory accounts, uint16[] memory shares) = _workers(escrow, orderId, order.workerCount);
        bytes32 digest = _termsDigest(escrow, order, accounts, shares);
        uint256[] memory grossByWorker = new uint256[](accounts.length);
        uint256 total;
        for (uint256 i; i < ids.length; ++i) {
            if (i != 0 && ids[i] <= ids[i - 1]) revert InvalidTerms();
            Record storage record = bookings[ids[i]];
            Booking storage b = record.booking;
            Offer storage offer = offers[b.offerId];
            if (record.activated || b.requester != order.requester || b.orderId != orderId ||
                offer.escrow != escrowAddress || b.termsDigest != digest ||
                order.terms.acceptBy > b.start || order.terms.deliverBy < b.end) revert FundingMismatch();
            if (b.holdUntil <= block.timestamp || b.start <= block.timestamp) revert Expired();
            address provider = resources[offer.resource].provider;
            bool found;
            for (uint256 j; j < accounts.length; ++j) if (accounts[j] == provider) {
                grossByWorker[j] += b.gross;
                found = true;
                break;
            }
            if (!found) revert FundingMismatch();
            total += b.gross;
        }
        if (total != order.terms.budget) revert FundingMismatch();
        for (uint256 i; i < accounts.length; ++i) {
            if (grossByWorker[i] == 0 || mulmod(total, shares[i], 10000) != 0 ||
                Math.mulDiv(total, shares[i], 10000) != grossByWorker[i]) revert FundingMismatch();
        }
        activatedOrders[escrowAddress][orderId] = true;
        for (uint256 i; i < ids.length; ++i) bookings[ids[i]].activated = true;
        emit Activated(escrowAddress, orderId, order.requester, ids);
    }

    function _order(ComputeEscrow escrow, bytes32 id) private view returns (ComputeEscrow.Order memory) {
        // ComputeEscrow's public getter returns this wholly static struct's fields.
        (bool ok, bytes memory data) = address(escrow).staticcall(abi.encodeWithSignature("orders(bytes32)", id));
        if (!ok) revert FundingMismatch();
        return abi.decode(data, (ComputeEscrow.Order));
    }

    function _workers(ComputeEscrow escrow, bytes32 id, uint16 count) private view returns (address[] memory accounts, uint16[] memory shares) {
        accounts = new address[](count);
        shares = new uint16[](count);
        uint16 previous;
        for (uint256 i; i < count; ++i) {
            ComputeEscrow.Worker memory worker = escrow.workerAt(id, i);
            accounts[i] = worker.account;
            shares[i] = worker.cumulativeBps - previous;
            previous = worker.cumulativeBps;
        }
    }

    function _termsDigest(ComputeEscrow escrow, ComputeEscrow.Order memory order, address[] memory accounts, uint16[] memory shares) private view returns (bytes32) {
        return keccak256(abi.encode("Cannabis compute settlement v1", block.chainid, address(escrow),
            address(escrow.token()), escrow.founderRecipient(), uint16(100), order.requester, order.terms, accounts, shares));
    }
}
