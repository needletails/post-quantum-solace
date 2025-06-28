//
//  FriendshipStateTests.swift
//  post-quantum-solace
//
//  Created by Cole M on 10/19/24.
//
import Testing
@testable import PQSSession
@testable import SessionEvents
@testable import SessionModels

@Suite(.serialized)
struct FriendshipMetadataTests {
    
    // MARK: - Initial State Tests
    
    @Test
    func testInitialState() {
        let friendship = FriendshipMetadata()
        #expect(friendship.myState == .pending)
        #expect(friendship.theirState == .pending)
        #expect(friendship.ourState == .pending)
    }
    
    // MARK: - Friend Request Tests
    
    @Test
    func testSendFriendRequest() {
        var friendship = FriendshipMetadata()
        friendship.synchronizeRequestedState()
        
        #expect(friendship.myState == .requested)
        #expect(friendship.ourState == .pending)
    }
    
    @Test
    func testAcceptFriendRequest() {
        var friendship = FriendshipMetadata(myState: .requested, theirState: .requested)
        friendship.synchronizeAcceptedState()
        
        #expect(friendship.myState == .accepted)
        #expect(friendship.theirState == .accepted)
        #expect(friendship.ourState == .accepted)
    }
    
    @Test
    func testRejectFriendRequest() {
        var friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
        friendship.rejectFriendRequest()
        
        #expect(friendship.myState == .rejectedRequest)
        #expect(friendship.theirState == .rejected)
        #expect(friendship.ourState == .friendshipRejected)
    }
    
    @Test
    func testResetToPendingState() {
        var friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
        friendship.synchronizePendingState()
        
        #expect(friendship.myState == .pending)
        #expect(friendship.theirState == .pending)
        #expect(friendship.ourState == .pending)
    }
    
    // MARK: - Block/Unblock Tests
    
    @Test
    func testBlockUser() {
        var friendship = FriendshipMetadata()
        friendship.synchronizeBlockState(receivedBlock: false)
        
        #expect(friendship.myState == .blockedUser)
        #expect(friendship.theirState == .blocked)
        #expect(friendship.ourState == .pending)
    }
    
    @Test
    func testUnblockUser() {
        var friendship = FriendshipMetadata(myState: .blockedUser, theirState: .blocked)
        friendship.unBlockFriend()
        
        #expect(friendship.myState == .pending)
        #expect(friendship.theirState == .pending)
        #expect(friendship.ourState == .pending)
    }
    
    // MARK: - State Management Tests
    
    @Test
    func testSwitchStates() {
        var friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
        friendship.switchStates()
        
        #expect(friendship.myState == .pending)
        #expect(friendship.theirState == .requested)
    }
    
    @Test
    func testUpdateOurState() {
        // Test accepted state
        var friendship = FriendshipMetadata(myState: .accepted, theirState: .accepted)
        friendship.updateOurState()
        #expect(friendship.ourState == .accepted)
        
        // Test pending state
        friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
        friendship.updateOurState()
        #expect(friendship.ourState == .pending)
        
        // Test rejected state
        friendship = FriendshipMetadata(myState: .rejected, theirState: .rejectedRequest)
        friendship.updateOurState()
        #expect(friendship.ourState == .friendshipRejected)
        
        // Test both requested state
        friendship = FriendshipMetadata(myState: .requested, theirState: .requested)
        friendship.updateOurState()
        #expect(friendship.ourState == .requested)
    }
}
