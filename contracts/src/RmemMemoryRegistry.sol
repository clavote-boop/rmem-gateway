// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {IAgentMemoryAccess} from "./IAgentMemoryAccess.sol";

/// @title  RmemMemoryRegistry
/// @author Clavote Research
/// @notice ERC-8264 reference implementation with two extensions:
///
///         1. **Hash-commitment storage.** `writeMemory(subject, recordId, data)` stores
///            `keccak256(data)` only. The on-chain footprint per record is 32 bytes; real
///            payloads live in an off-chain encrypted vault. `readMemory` returns the
///            commitment so an off-chain client can verify its locally-decrypted payload.
///
///         2. **Subject-controlled lease delegation.** A subject can grant a body
///            (any address) a scoped, time-bounded lease via `grantLease`. The leased
///            body can then call `writeMemory` / `readMemory` / `deleteMemory` /
///            `exportMemory` on the subject's behalf within scope. This mirrors the
///            off-chain `rmem-gateway` Body Lease auth path and demonstrates the
///            "the body is a lease; the soul is permanent" model on-chain.
///
///         Anchoring: `anchorMemoryRoot` emits a `MemoryAnchored` event without
///         persisting state — an EVM-side analogue of the OP_RETURN CAMIA anchor.
contract RmemMemoryRegistry is IAgentMemoryAccess {

    // ---------------------------------------------------------------
    // Scope bitmap
    // ---------------------------------------------------------------

    uint64 internal constant SCOPE_READ   = 1;
    uint64 internal constant SCOPE_WRITE  = 2;
    uint64 internal constant SCOPE_DELETE = 4;
    uint64 internal constant SCOPE_EXPORT = 8;

    // ---------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------

    struct Lease {
        uint64 expiresAt;
        uint64 scopes;
    }

    /// subject => recordId => keccak256(data). Zero means absent.
    mapping(address => mapping(bytes32 => bytes32)) private _commit;

    /// subject => ordered list of recordIds (for export). Not pruned on delete.
    mapping(address => bytes32[]) private _index;

    /// subject => body => lease
    mapping(address => mapping(address => Lease)) public leases;

    /// subject => body => timestamp of revocation (0 means not revoked).
    /// Per the spec's Allow_8264 (¬Revoked is a conjunct separate from
    /// WithinTime), revocation must be checkable independently of the lease's
    /// time window. Keeping this as its own mapping — rather than reusing the
    /// zeroed `Lease.expiresAt` left behind by `delete leases[...]` — makes
    /// the conjunct explicit and the audit trail unambiguous.
    mapping(address => mapping(address => uint64)) public revokedAt;

    // ---------------------------------------------------------------
    // Events (in addition to IAgentMemoryAccess.MemoryWritten/Deleted)
    // ---------------------------------------------------------------

    /// @notice A subject granted a body a scoped, time-bounded lease.
    event LeaseGranted(
        address indexed subject,
        address indexed body,
        uint64 scopes,
        uint64 expiresAt
    );

    /// @notice A lease was revoked (by the subject) or auto-expired.
    event LeaseRevoked(address indexed subject, address indexed body);

    /// @notice A Merkle root over off-chain memory state was anchored on-chain.
    /// @param subject     The Soul subject whose state is being anchored.
    /// @param merkleRoot  sha256/keccak256 root over the record payload commitments.
    /// @param commitType  1 = capsule root, 2 = live memory-state root.
    event MemoryAnchored(
        address indexed subject,
        bytes32 indexed merkleRoot,
        uint8 commitType
    );

    // ---------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------

    error NotAuthorized(address subject, address caller, uint64 requiredScope);
    error UnknownRecord(address subject, bytes32 recordId);
    error InvalidCommitType(uint8 commitType);
    error InvalidLease();

    // ---------------------------------------------------------------
    // IAgentMemoryAccess
    // ---------------------------------------------------------------

    function readMemory(address subject, bytes32 recordId)
        external view override returns (bytes memory data)
    {
        if (!_isAuthorized(subject, SCOPE_READ)) {
            revert NotAuthorized(subject, msg.sender, SCOPE_READ);
        }
        bytes32 commitment = _commit[subject][recordId];
        if (commitment == bytes32(0)) {
            revert UnknownRecord(subject, recordId);
        }
        return abi.encodePacked(commitment);
    }

    function writeMemory(address subject, bytes32 recordId, bytes calldata data)
        external override
    {
        if (!_isAuthorized(subject, SCOPE_WRITE)) {
            revert NotAuthorized(subject, msg.sender, SCOPE_WRITE);
        }
        bytes32 commitment = keccak256(data);
        if (_commit[subject][recordId] == bytes32(0)) {
            _index[subject].push(recordId);
        }
        _commit[subject][recordId] = commitment;
        emit MemoryWritten(subject, recordId);
    }

    function deleteMemory(address subject, bytes32 recordId)
        external override
    {
        if (!_isAuthorized(subject, SCOPE_DELETE)) {
            revert NotAuthorized(subject, msg.sender, SCOPE_DELETE);
        }
        if (_commit[subject][recordId] == bytes32(0)) {
            revert UnknownRecord(subject, recordId);
        }
        delete _commit[subject][recordId];
        emit MemoryDeleted(subject, recordId);
    }

    function exportMemory(address subject)
        external view override returns (bytes memory)
    {
        if (!_isAuthorized(subject, SCOPE_EXPORT)) {
            revert NotAuthorized(subject, msg.sender, SCOPE_EXPORT);
        }
        bytes32[] storage ids = _index[subject];
        uint256 n = ids.length;
        bytes32[] memory liveIds = new bytes32[](n);
        bytes[] memory payloads = new bytes[](n);
        uint256 j;
        for (uint256 i; i < n; ++i) {
            bytes32 rid = ids[i];
            bytes32 commitment = _commit[subject][rid];
            if (commitment == bytes32(0)) continue; // tombstoned
            liveIds[j] = rid;
            payloads[j] = abi.encodePacked(commitment);
            unchecked { ++j; }
        }
        // Truncate to live count.
        assembly {
            mstore(liveIds, j)
            mstore(payloads, j)
        }
        return abi.encode(liveIds, payloads);
    }

    // ---------------------------------------------------------------
    // Lease management (subject-only)
    // ---------------------------------------------------------------

    /// @notice Grant a body a scoped, time-bounded lease over the caller's memory.
    ///         Replaces any existing lease for that body and clears any prior
    ///         revocation timestamp (so re-granting after revoke is supported).
    function grantLease(address body, uint64 scopes, uint64 expiresAt) external {
        if (body == address(0) || scopes == 0 || expiresAt <= block.timestamp) {
            revert InvalidLease();
        }
        leases[msg.sender][body] = Lease({ expiresAt: expiresAt, scopes: scopes });
        revokedAt[msg.sender][body] = 0;
        emit LeaseGranted(msg.sender, body, scopes, expiresAt);
    }

    /// @notice Revoke a body's lease over the caller's memory. Sets an explicit
    ///         revocation timestamp checked independently of `expiresAt`.
    function revokeLease(address body) external {
        revokedAt[msg.sender][body] = uint64(block.timestamp);
        delete leases[msg.sender][body];
        emit LeaseRevoked(msg.sender, body);
    }

    // ---------------------------------------------------------------
    // Anchoring (EVM-side analogue of OP_RETURN CAMIA)
    // ---------------------------------------------------------------

    /// @notice Anchor a Merkle root over the subject's off-chain memory state.
    /// @dev    Emits `MemoryAnchored`; no storage write. The event is the proof.
    /// @param  commitType 1 = capsule root, 2 = live memory-state root.
    function anchorMemoryRoot(address subject, bytes32 merkleRoot, uint8 commitType) external {
        if (!_isAuthorized(subject, SCOPE_WRITE)) {
            revert NotAuthorized(subject, msg.sender, SCOPE_WRITE);
        }
        if (commitType != 1 && commitType != 2) {
            revert InvalidCommitType(commitType);
        }
        emit MemoryAnchored(subject, merkleRoot, commitType);
    }

    // ---------------------------------------------------------------
    // Authorization
    // ---------------------------------------------------------------

    function _isAuthorized(address subject, uint64 requiredScope) internal view returns (bool) {
        if (msg.sender == subject) return true;
        // Spec Eq. allow-revoke: ¬Revoked is an independent conjunct from
        // WithinTime. Check it explicitly first so revocation cannot be
        // mistaken for an expired-time false.
        if (revokedAt[subject][msg.sender] != 0) return false;
        Lease memory l = leases[subject][msg.sender];
        if (l.expiresAt <= block.timestamp) return false;
        return (l.scopes & requiredScope) == requiredScope;
    }

    // ---------------------------------------------------------------
    // ERC-165
    // ---------------------------------------------------------------

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IAgentMemoryAccess).interfaceId
            || interfaceId == 0x01ffc9a7; // ERC-165
    }

    // ---------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------

    /// @notice Returns the keccak256 commitment for a record, or bytes32(0) if absent.
    function commitmentOf(address subject, bytes32 recordId) external view returns (bytes32) {
        return _commit[subject][recordId];
    }

    /// @notice Returns the full (possibly tombstoned-inclusive) recordId index for a subject.
    function indexOf(address subject) external view returns (bytes32[] memory) {
        return _index[subject];
    }
}
