// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

/// @title  IERC-8264 AI Agent Memory Access Rights
/// @notice The four-function rights interface a subject holds over the memory
///         an agent stores about them: read, write (rectify), delete (erase),
///         and export (portability).
/// @dev    Implementors MUST also implement ERC-165 and return true for the
///         interfaceId of this interface.
interface IAgentMemoryAccess {

    /// @notice Emitted when a memory record is written for a subject.
    event MemoryWritten(address indexed subject, bytes32 indexed recordId);

    /// @notice Emitted when a memory record is deleted for a subject.
    event MemoryDeleted(address indexed subject, bytes32 indexed recordId);

    /// @notice Read a memory record belonging to `subject`.
    function readMemory(address subject, bytes32 recordId)
        external view returns (bytes memory data);

    /// @notice Write or update a memory record for `subject`.
    function writeMemory(address subject, bytes32 recordId, bytes calldata data)
        external;

    /// @notice Delete a memory record for `subject`.
    function deleteMemory(address subject, bytes32 recordId)
        external;

    /// @notice Export all memory records for `subject` as a single payload.
    function exportMemory(address subject)
        external view returns (bytes memory payload);
}
