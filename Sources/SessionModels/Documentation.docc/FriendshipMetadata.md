# ``FriendshipMetadata``

<!--@START_MENU_TOKEN@-->Summary<!--@END_MENU_TOKEN@-->

## Overview

<!--@START_MENU_TOKEN@-->Text<!--@END_MENU_TOKEN@-->

The `FriendshipMetadata` system manages friendship states between two users, allowing both parties to update their individual states and maintain a combined state that reflects the overall relationship. This system provides a comprehensive API for handling the complete friendship lifecycle from initial requests to blocking and unblocking.

## Topics

### Core Concepts

- ``FriendshipMetadata/State``
- ``FriendshipMetadata/myState``
- ``FriendshipMetadata/theirState``
- ``FriendshipMetadata/ourState``

### State Management

- ``FriendshipMetadata/setRequestedState()``
- ``FriendshipMetadata/setAcceptedState()``
- ``FriendshipMetadata/resetToPendingState()``
- ``FriendshipMetadata/rejectRequest()``
- ``FriendshipMetadata/setBlockState(isBlocking:)``
- ``FriendshipMetadata/unblockUser()``
- ``FriendshipMetadata/updateOurState()``
- ``FriendshipMetadata/swapUserPerspectives()``

## Naming Conventions

The `FriendshipMetadata` system uses consistent naming conventions across all related components:

### Method Naming Pattern

All methods follow a consistent action-based naming pattern:

```swift
func setRequestedState()
func setAcceptedState()
func rejectRequest()
func unblockUser()
func swapUserPerspectives()
```

### Enum Case Names

Enum cases use clear and descriptive names:

```swift
case rejectedByOther = "e"      // Clear who rejected
case mutuallyRejected = "f"     // Describes mutual rejection
case blockedByOther = "h"       // Clear perspective
case unblocked = "i"            // Consistent with other cases
```

### Parameter Names

Parameter names clearly indicate their purpose:

```swift
func setBlockState(isBlocking: Bool)  // Clear meaning
```

## Updated Method Reference

### Core State Management Methods

| Method | Purpose | Example |
|--------|---------|---------|
| `setRequestedState()` | Initiates a friendship request | `friendship.setRequestedState()` |
| `setAcceptedState()` | Accepts a friendship request | `friendship.setAcceptedState()` |
| `resetToPendingState()` | Resets friendship to initial state | `friendship.resetToPendingState()` |
| `rejectRequest()` | Rejects a friendship request | `friendship.rejectRequest()` |
| `setBlockState(isBlocking:)` | Sets blocking state | `friendship.setBlockState(isBlocking: true)` |
| `unblockUser()` | Unblocks a user | `friendship.unblockUser()` |
| `swapUserPerspectives()` | Swaps user perspectives | `friendship.swapUserPerspectives()` |
| `updateOurState()` | Updates combined state | `friendship.updateOurState()` |

### Enum States

| State | Description | Use Case |
|-------|-------------|----------|
| `.pending` | No action taken yet | Initial state, reset state |
| `.requested` | Friend request sent | User initiated request |
| `.accepted` | Friendship accepted | Both parties agreed |
| `.rejected` | Current user rejected request | User rejected incoming request |
| `.rejectedByOther` | Other user rejected request | Other user rejected outgoing request |
| `.mutuallyRejected` | Both users rejected each other | Mutual rejection scenario |
| `.blocked` | Current user blocked other | User blocked contact |
| `.blockedByOther` | Other user blocked current user | Contact blocked user |
| `.unblocked` | User unblocked other | Reset after unblocking |

## Usage Examples

### Basic Friendship Lifecycle

```swift
// 1. Create new friendship
var friendship = FriendshipMetadata()

// 2. Send friend request
friendship.setRequestedState()
// friendship.myState == .requested
// friendship.ourState == .pending

// 3. Accept friend request (from other user's perspective)
friendship.setAcceptedState()
// friendship.myState == .accepted
// friendship.theirState == .accepted
// friendship.ourState == .accepted
```

### Blocking and Unblocking

```swift
// Block the other user
friendship.setBlockState(isBlocking: true)
// friendship.myState == .blocked
// friendship.theirState == .blockedByOther

// Unblock the user
friendship.unblockUser()
// friendship.myState == .pending
// friendship.theirState == .pending
```

### Rejecting Requests

```swift
// Reject an incoming friend request
friendship.rejectRequest()
// friendship.myState == .rejectedByOther
// friendship.theirState == .rejected
// friendship.ourState == .mutuallyRejected
```

## State Transition Logic

The `updateOurState()` method implements the following priority logic:

1. **Blocked State**: If current user is blocked, no state changes are allowed
2. **Accepted State**: If both users have accepted, combined state is `.accepted`
3. **Pending State**: If one user has requested and the other is pending, combined state is `.pending`
4. **Mutual Rejection**: If both users have rejected each other, combined state is `.mutuallyRejected`
5. **Blocked by Other**: If the other user has blocked the current user, combined state is `.blocked`
6. **Default**: Any unhandled combinations default to `.pending`

## Files Updated

The following files were updated to reflect the new naming conventions:

1. **`Sources/SessionModels/FriendshipMetadata.swift`**
   - Updated method names and enum cases
   - Enhanced documentation with examples
   - Improved parameter names

2. **`Sources/SessionEvents/SessionEvents.swift`**
   - Updated method calls to use new names
   - Enhanced documentation for state transitions
   - Improved error handling descriptions

3. **`Tests/PostQuantumSolaceTests/FriendshipStateTests.swift`**
   - Updated test method names
   - Updated test assertions to use new enum cases
   - Enhanced test documentation

## Benefits

### 1. Consistency
- All method names follow the same action-based pattern
- Enum cases have consistent naming conventions
- Parameter names clearly indicate their purpose

### 2. Clarity
- Method names clearly indicate their purpose
- Enum cases are self-documenting
- Parameter names eliminate ambiguity

### 3. Maintainability
- Easier to understand and modify code
- Better adherence to Swift naming conventions
- Improved code readability

### 4. Developer Experience
- More intuitive API design
- Better documentation with examples
- Clearer error messages and state transitions

## Testing

All functionality is thoroughly tested in `FriendshipStateTests.swift`. The test suite validates:

- Initial state creation
- Friend request lifecycle
- Blocking and unblocking functionality
- State synchronization
- Perspective swapping
- Combined state calculation

Run the tests to ensure everything works correctly:

```bash
swift test --filter FriendshipMetadataTests
```

## Conclusion

The `FriendshipMetadata` system provides an intuitive, maintainable, and developer-friendly API for managing friendship relationships. The consistent patterns and clear naming help reduce cognitive load and improve code quality across the entire codebase.
