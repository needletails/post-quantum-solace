//
//  FriendshipStateTests.swift
//  crypto-session
//
//  Created by Cole M on 10/19/24.
//
import Testing
@testable import CryptoSession
@testable import SessionEvents
@testable import SessionModels

struct FriendshipMetadataTests {
    
    @Test
    func testInitialState() {
        let friendship = FriendshipMetadata()
        #expect(friendship.myState == .pending)
        #expect(friendship.theirState == .pending)
        #expect(friendship.ourState == .pending)
    }
    
    @Test
    func testSendFriendRequest() {
        var friendship = FriendshipMetadata()
        friendship.synchronizeAcceptedState()
        
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
    func testFriendRejection() {
        var friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
        friendship.rejectFriendRequest()
        friendship.switchStates()
        #expect(friendship.myState == .rejected)
        #expect(friendship.theirState == .rejectedRequest)
        #expect(friendship.ourState == .friendshipRejected)
    }
    
    @Test
    func testRevokeFriendRequest() {
        var friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
        friendship.rejectFriendRequest()
        
        #expect(friendship.myState == .pending)
        #expect(friendship.theirState == .pending)
        #expect(friendship.ourState == .pending)
    }
    
    @Test
    func testBlockFriend() {
        var friendship = FriendshipMetadata()
        friendship.rejectFriendRequest()
        
        #expect(friendship.myState == .blockedUser)
        #expect(friendship.theirState == .blocked)
        #expect(friendship.ourState == .pending)
    }
    
    @Test
    func testWasBlocked() {
        var friendship = FriendshipMetadata()
        friendship.rejectFriendRequest()
        friendship.switchStates()
        #expect(friendship.myState == .blocked)
        #expect(friendship.theirState == .blockedUser)
        #expect(friendship.ourState == .pending)
    }
    
    @Test
    func testUnblockFriend() {
        var friendship = FriendshipMetadata(myState: .blockedUser, theirState: .blocked)
        friendship.unBlockFriend()

        #expect(friendship.myState == .pending)
        #expect(friendship.theirState == .pending)
        #expect(friendship.ourState == .pending)
    }
    
    @Test
    func testSwitchStates() {
        var friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
        friendship.switchStates()
        
        #expect(friendship.myState == .pending)
        #expect(friendship.theirState == .requested)
    }
    
    @Test
    func testUpdateOurState() {
        var friendship = FriendshipMetadata(myState: .accepted, theirState: .accepted)
        friendship.updateOurState()
        
        #expect(friendship.ourState == .accepted)
        
        friendship = FriendshipMetadata(myState: .requested, theirState: .pending)
        friendship.updateOurState()
        
        #expect(friendship.ourState == .pending)
        
        friendship = FriendshipMetadata(myState: .rejected, theirState: .rejectedRequest)
        friendship.updateOurState()
        
        #expect(friendship.ourState == .friendshipRejected)
    }
}
