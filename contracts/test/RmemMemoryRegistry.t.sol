// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {RmemMemoryRegistry} from "../src/RmemMemoryRegistry.sol";
import {IAgentMemoryAccess} from "../src/IAgentMemoryAccess.sol";

contract RmemMemoryRegistryTest is Test {
    RmemMemoryRegistry reg;

    address subject = address(0xA11CE);
    address body    = address(0xB0DE);
    address stranger = address(0xDEAD);

    bytes32 constant RID_1 = keccak256("mem_ulid_001");
    bytes32 constant RID_2 = keccak256("mem_ulid_002");

    bytes constant PAYLOAD = bytes("encrypted-blob-v1");

    uint64 constant SCOPE_READ   = 1;
    uint64 constant SCOPE_WRITE  = 2;
    uint64 constant SCOPE_DELETE = 4;
    uint64 constant SCOPE_EXPORT = 8;

    function setUp() public {
        reg = new RmemMemoryRegistry();
    }

    // ----- subject write/read/delete -----

    function test_subject_write_emits_event_and_stores_commitment() public {
        vm.prank(subject);
        vm.expectEmit(true, true, false, false);
        emit IAgentMemoryAccess.MemoryWritten(subject, RID_1);
        reg.writeMemory(subject, RID_1, PAYLOAD);

        assertEq(reg.commitmentOf(subject, RID_1), keccak256(PAYLOAD));
    }

    function test_subject_read_returns_commitment() public {
        vm.prank(subject);
        reg.writeMemory(subject, RID_1, PAYLOAD);

        vm.prank(subject);
        bytes memory got = reg.readMemory(subject, RID_1);
        assertEq(got.length, 32);
        assertEq(bytes32(got), keccak256(PAYLOAD));
    }

    function test_subject_delete_clears_commitment() public {
        vm.prank(subject);
        reg.writeMemory(subject, RID_1, PAYLOAD);

        vm.prank(subject);
        vm.expectEmit(true, true, false, false);
        emit IAgentMemoryAccess.MemoryDeleted(subject, RID_1);
        reg.deleteMemory(subject, RID_1);

        assertEq(reg.commitmentOf(subject, RID_1), bytes32(0));
    }

    function test_stranger_read_reverts() public {
        vm.prank(subject);
        reg.writeMemory(subject, RID_1, PAYLOAD);

        vm.prank(stranger);
        vm.expectRevert();
        reg.readMemory(subject, RID_1);
    }

    function test_stranger_write_reverts() public {
        vm.prank(stranger);
        vm.expectRevert();
        reg.writeMemory(subject, RID_1, PAYLOAD);
    }

    function test_delete_unknown_record_reverts() public {
        vm.prank(subject);
        vm.expectRevert();
        reg.deleteMemory(subject, RID_1);
    }

    // ----- export -----

    function test_export_returns_live_records_only() public {
        vm.startPrank(subject);
        reg.writeMemory(subject, RID_1, PAYLOAD);
        reg.writeMemory(subject, RID_2, bytes("second"));
        reg.deleteMemory(subject, RID_1);
        vm.stopPrank();

        vm.prank(subject);
        bytes memory exported = reg.exportMemory(subject);
        (bytes32[] memory ids, bytes[] memory payloads) =
            abi.decode(exported, (bytes32[], bytes[]));
        assertEq(ids.length, 1, "tombstoned record should be filtered out");
        assertEq(ids[0], RID_2);
        assertEq(bytes32(payloads[0]), keccak256(bytes("second")));
    }

    // ----- lease delegation -----

    function test_lease_grant_lets_body_write_within_scope() public {
        vm.prank(subject);
        reg.grantLease(body, SCOPE_READ | SCOPE_WRITE, uint64(block.timestamp + 1 hours));

        // Body can write within scope.
        vm.prank(body);
        reg.writeMemory(subject, RID_1, PAYLOAD);
        assertEq(reg.commitmentOf(subject, RID_1), keccak256(PAYLOAD));

        // Body can read.
        vm.prank(body);
        bytes memory got = reg.readMemory(subject, RID_1);
        assertEq(bytes32(got), keccak256(PAYLOAD));
    }

    function test_lease_without_delete_scope_blocks_delete() public {
        vm.prank(subject);
        reg.grantLease(body, SCOPE_READ | SCOPE_WRITE, uint64(block.timestamp + 1 hours));
        vm.prank(body);
        reg.writeMemory(subject, RID_1, PAYLOAD);

        // Body lacks SCOPE_DELETE.
        vm.prank(body);
        vm.expectRevert();
        reg.deleteMemory(subject, RID_1);
    }

    function test_expired_lease_is_rejected() public {
        vm.prank(subject);
        reg.grantLease(body, SCOPE_WRITE, uint64(block.timestamp + 1 hours));

        vm.warp(block.timestamp + 2 hours);

        vm.prank(body);
        vm.expectRevert();
        reg.writeMemory(subject, RID_1, PAYLOAD);
    }

    function test_revoked_lease_is_rejected() public {
        vm.prank(subject);
        reg.grantLease(body, SCOPE_WRITE, uint64(block.timestamp + 1 hours));
        vm.prank(subject);
        reg.revokeLease(body);

        vm.prank(body);
        vm.expectRevert();
        reg.writeMemory(subject, RID_1, PAYLOAD);
    }

    function test_revocation_sets_explicit_timestamp_independent_of_expiry() public {
        // Lease with a far-future expiresAt so WithinTime cannot mask revocation.
        uint64 farFuture = uint64(block.timestamp + 365 days);
        vm.prank(subject);
        reg.grantLease(body, SCOPE_WRITE, farFuture);

        // Pre-revoke: revokedAt is 0; writeMemory works.
        assertEq(reg.revokedAt(subject, body), 0, "revokedAt should start 0");
        vm.prank(body);
        reg.writeMemory(subject, RID_1, PAYLOAD);

        // Revoke: explicit timestamp is recorded.
        uint64 t = uint64(block.timestamp);
        vm.prank(subject);
        reg.revokeLease(body);
        assertEq(reg.revokedAt(subject, body), t,
                 "revokedAt should equal block.timestamp at revoke");

        // Post-revoke: still well within the original time window, but ¬Revoked
        // fires the auth failure independently.
        vm.prank(body);
        vm.expectRevert();
        reg.writeMemory(subject, RID_2, PAYLOAD);
    }

    function test_regrant_clears_prior_revocation() public {
        vm.prank(subject);
        reg.grantLease(body, SCOPE_WRITE, uint64(block.timestamp + 1 hours));
        vm.prank(subject);
        reg.revokeLease(body);
        assertGt(reg.revokedAt(subject, body), 0, "revokedAt should be set after revoke");

        // Re-grant must clear the revocation timestamp so the new lease is valid.
        vm.prank(subject);
        reg.grantLease(body, SCOPE_WRITE, uint64(block.timestamp + 1 hours));
        assertEq(reg.revokedAt(subject, body), 0,
                 "grantLease should clear prior revokedAt");

        vm.prank(body);
        reg.writeMemory(subject, RID_1, PAYLOAD);
        assertEq(reg.commitmentOf(subject, RID_1), keccak256(PAYLOAD));
    }

    function test_grant_lease_invalid_inputs_revert() public {
        vm.startPrank(subject);
        vm.expectRevert();
        reg.grantLease(address(0), SCOPE_WRITE, uint64(block.timestamp + 1 hours));

        vm.expectRevert();
        reg.grantLease(body, 0, uint64(block.timestamp + 1 hours));

        vm.expectRevert();
        reg.grantLease(body, SCOPE_WRITE, uint64(block.timestamp));
        vm.stopPrank();
    }

    // ----- anchoring -----

    function test_anchor_memory_root_emits_event() public {
        bytes32 root = keccak256("merkle-root");
        vm.prank(subject);
        vm.expectEmit(true, true, false, true);
        emit RmemMemoryRegistry.MemoryAnchored(subject, root, 2);
        reg.anchorMemoryRoot(subject, root, 2);
    }

    function test_anchor_invalid_commit_type_reverts() public {
        vm.prank(subject);
        vm.expectRevert();
        reg.anchorMemoryRoot(subject, keccak256("x"), 9);
    }

    function test_anchor_via_lease_with_write_scope() public {
        vm.prank(subject);
        reg.grantLease(body, SCOPE_WRITE, uint64(block.timestamp + 1 hours));

        vm.prank(body);
        reg.anchorMemoryRoot(subject, keccak256("root"), 1);
    }

    function test_anchor_stranger_reverts() public {
        vm.prank(stranger);
        vm.expectRevert();
        reg.anchorMemoryRoot(subject, keccak256("root"), 1);
    }

    // ----- ERC-165 -----

    function test_supports_erc165() public view {
        assertTrue(reg.supportsInterface(0x01ffc9a7));
    }

    function test_supports_iagent_memory_access() public view {
        assertTrue(reg.supportsInterface(type(IAgentMemoryAccess).interfaceId));
    }

    function test_does_not_support_random_id() public view {
        assertFalse(reg.supportsInterface(0xdeadbeef));
    }
}
