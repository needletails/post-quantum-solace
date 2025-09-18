//
//  Collections+Extension.swift
//  post-quantum-solace
//
//  Created by Cole M on 2025-04-08.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//
import DequeModule
#if os(Android) || os(Linux)
@preconcurrency import Crypto
#else
import Crypto
#endif

public extension Deque {
    /// Asynchronously finds the index of the first element in the deque that satisfies the given predicate.
    ///
    /// This method iterates through the elements of the deque and evaluates the provided asynchronous
    /// predicate for each element. If the predicate returns `true` for an element, the index of that
    /// element is returned. If no elements satisfy the predicate, `nil` is returned.
    ///
    /// - Parameter predicate: An asynchronous closure that takes an element of the deque and returns
    ///   a Boolean value indicating whether the element satisfies a certain condition. The closure
    ///   is marked as `@Sendable`, meaning it can be safely used across concurrency domains.
    ///
    /// - Returns: The index of the first element that satisfies the predicate, or `nil` if no such
    ///   element is found.
    ///
    /// - Complexity: O(n), where n is the number of elements in the deque. The function may suspend
    ///   while waiting for the predicate to complete, so it should be used in an asynchronous context.
    ///
    /// - Note: This function is designed to work with deques of any type, as long as the type conforms
    ///   to the requirements of the predicate closure. The deque maintains its order during iteration,
    ///   so the first element that satisfies the predicate will be returned regardless of its position
    ///   in the deque.
    ///
    /// ## Example
    ///
    /// ```swift
    /// let numbers = Deque([1, 3, 5, 7, 8, 10])
    ///
    /// // Asynchronous predicate function
    /// func isEven(_ number: Int) async -> Bool {
    ///     return number % 2 == 0
    /// }
    ///
    /// Task {
    ///     if let index = await numbers.firstAsyncIndex(where: isEven) {
    ///         print("The first even number is at index \(index).") // Output: The first even number is at index 4.
    ///     } else {
    ///         print("No even number found.")
    ///     }
    /// }
    /// ```
    func firstAsyncIndex(where predicate: @Sendable (Element) async -> Bool) async -> Int? {
        for (index, element) in enumerated() {
            if await predicate(element) {
                return index
            }
        }
        return nil
    }
}

public extension Array {
    /// Asynchronously finds the first element in the array that satisfies the given predicate.
    ///
    /// This method iterates through the elements of the array and evaluates the provided asynchronous
    /// predicate for each element. If the predicate returns `true` for an element, that element is
    /// returned. If no elements satisfy the predicate, `nil` is returned.
    ///
    /// - Parameter predicate: An asynchronous closure that takes an element of the array and returns
    ///   a Boolean value indicating whether the element satisfies a certain condition. The closure
    ///   is marked as `@Sendable`, meaning it can be safely used across concurrency domains.
    ///
    /// - Returns: The first element that satisfies the predicate, or `nil` if no such element is found.
    ///
    /// - Complexity: O(n), where n is the number of elements in the array. The function may suspend
    ///   while waiting for the predicate to complete, so it should be used in an asynchronous context.
    ///
    /// - Note: This function is designed to work with arrays of any type, as long as the type conforms
    ///   to the requirements of the predicate closure.
    ///
    /// ## Example
    ///
    /// ```swift
    /// let numbers = [1, 3, 5, 7, 8, 10]
    ///
    /// // Asynchronous predicate function
    /// func isEven(_ number: Int) async -> Bool {
    ///     return number % 2 == 0
    /// }
    ///
    /// Task {
    ///     if let firstEven = await numbers.asyncFirst(where: isEven) {
    ///         print("The first even number is \(firstEven).") // Output: The first even number is 8.
    ///     } else {
    ///         print("No even number found.")
    ///     }
    /// }
    /// ```
    func asyncFirst(where predicate: @Sendable (Element) async -> Bool) async -> Element? {
        for element in self {
            if await predicate(element) {
                return element
            }
        }
        return nil
    }

    func asyncMap<T>(transform: @Sendable (Element) async -> T) async -> [T] {
        var results = [T]()
        for element in self {
            let result = await transform(element)
            results.append(result)
        }
        return results
    }

    func asyncCompactMap<T>(transform: @Sendable (Element) async -> T?) async -> [T] {
        var results = [T]()
        for element in self {
            if let result = await transform(element) {
                results.append(result)
            }
        }
        return results
    }

    // Asynchronously finds the index of the first element in the array that satisfies the given predicate.
    ///
    /// This method iterates through the elements of the array and evaluates the provided asynchronous
    /// predicate for each element. If the predicate returns `true` for an element, the index of that
    /// element is returned. If no elements satisfy the predicate, `nil` is returned.
    ///
    /// - Parameter predicate: An asynchronous closure that takes an element of the array and returns
    ///   a Boolean value indicating whether the element satisfies a certain condition. The closure
    ///   is marked as `@Sendable`, meaning it can be safely used across concurrency domains.
    ///
    /// - Returns: The index of the first element that satisfies the predicate, or `nil` if no such
    ///   element is found.
    ///
    /// - Complexity: O(n), where n is the number of elements in the array. The function may suspend
    ///   while waiting for the predicate to complete, so it should be used in an asynchronous context.
    ///
    /// - Note: This function is designed to work with arrays of any type, as long as the type conforms
    ///   to the requirements of the predicate closure.
    ///
    /// ## Example
    ///
    /// ```swift
    /// let numbers = [1, 3, 5, 7, 8, 10]
    ///
    /// // Asynchronous predicate function
    /// func isEven(_ number: Int) async -> Bool {
    ///     return number % 2 == 0
    /// }
    ///
    /// Task {
    ///     if let index = await numbers.firstAsyncIndex(where: isEven) {
    ///         print("The first even number is at index \(index).") // Output: The first even number is at index 4.
    ///     } else {
    ///         print("No even number found.")
    ///     }
    /// }
    /// ```
    func firstAsyncIndex(where predicate: @Sendable (Element) async -> Bool) async -> Int? {
        for (index, element) in enumerated() {
            if await predicate(element) {
                return index
            }
        }
        return nil
    }

    /// Asynchronously filters the array based on the given predicate.
    ///
    /// This method iterates through the elements of the array and evaluates the provided asynchronous
    /// predicate for each element. If the predicate returns `true` for an element, that element is
    /// included in the resulting array. The method returns a new array containing all elements that
    /// satisfy the predicate.
    ///
    /// - Parameter predicate: An asynchronous closure that takes an element of the array and returns
    ///   a Boolean value indicating whether the element should be included in the resulting array.
    ///   The closure is marked as `@Sendable`, meaning it can be safely used across concurrency domains.
    ///
    /// - Returns: An array containing the elements that satisfy the predicate.
    ///
    /// - Complexity: O(n), where n is the number of elements in the array. The function may suspend
    ///   while waiting for the predicate to complete, so it should be used in an asynchronous context.
    ///
    /// - Note: This function is designed to work with arrays of any type, as long as the type conforms
    ///   to the requirements of the predicate closure.
    ///
    /// ## Example
    ///
    /// ```swift
    /// let numbers = [1, 2, 3, 4, 5]
    ///
    /// // Asynchronous predicate function
    /// func isEven(_ number: Int) async -> Bool {
    ///     return number % 2 == 0
    /// }
    ///
    /// Task {
    ///     let evenNumbers = await numbers.asyncFilter(where: isEven)
    ///     print("Even numbers: \(evenNumbers)") // Output: Even numbers: [2, 4]
    /// }
    /// ```
    func asyncFilter(_ predicate: @Sendable (Element) async -> Bool) async -> [Element] {
        var result: [Element] = []
        for element in self {
            if await predicate(element) {
                result.append(element)
            }
        }
        return result
    }

    /// Asynchronously removes all elements that satisfy the given predicate from the current array.
    ///
    /// This method evaluates the provided asynchronous predicate for each element in the array. If the
    /// predicate returns `true` for an element, that element is removed from the array. The method
    /// updates the current array to contain only the elements that do not satisfy the predicate.
    ///
    /// - Parameter predicate: An asynchronous closure that takes an element of the array and returns
    ///   a Boolean value indicating whether the element should be removed from the array. The closure
    ///   is marked as `@Sendable`, meaning it can be safely used across concurrency domains.
    ///
    /// - Returns: This method does not return a value. It modifies the current array in place to
    ///   exclude the elements that satisfy the predicate.
    ///
    /// - Complexity: O(n), where n is the number of elements in the array. The function may suspend
    ///   while waiting for the predicate to complete, so it should be used in an asynchronous context.
    ///
    /// - Note: This function is designed to work with arrays of any type, as long as the type conforms
    ///   to the requirements of the predicate closure.
    ///
    /// ## Example
    ///
    /// ```swift
    /// var numbers = [1, 2, 3, 4, 5]
    ///
    /// // Asynchronous predicate function
    /// func isEven(_ number: Int) async -> Bool {
    ///     return number % 2 == 0
    /// }
    ///
    /// Task {
    ///     await numbers.asyncRemoveAll(where: isEven)
    ///     print("Remaining numbers: \(numbers)") // Output: Remaining numbers: [1, 3, 5]
    /// }
    /// ```
    mutating func asyncRemoveAll(where predicate: @Sendable (Element) async -> Bool) async {
        // Create a new array with elements that should remain
        let filteredArray = await asyncFilter { element in
            await !predicate(element)
        }
        // Update the current array
        self = filteredArray
    }

    /// Asynchronously checks if the array contains an element that satisfies the given predicate.
    ///
    /// This method iterates through the elements of the array and evaluates the provided asynchronous
    /// predicate for each element. If the predicate returns `true` for any element, the method returns
    /// `true`. If no elements satisfy the predicate, the method returns `false`.
    ///
    /// - Parameter predicate: An asynchronous closure that takes an element of the array and returns
    ///   a Boolean value indicating whether the element satisfies a certain condition. The closure
    ///   is marked as `@Sendable`, meaning it can be safely used across concurrency domains.
    ///
    /// - Returns: A Boolean value indicating whether the array contains an element that satisfies the
    ///   predicate.
    ///
    /// - Complexity: O(n), where n is the number of elements in the array. The function may suspend
    ///   while waiting for the predicate to complete, so it should be used in an asynchronous context.
    ///
    /// - Note: This function is designed to work with arrays of any type, as long as the type conforms
    ///   to the requirements of the predicate closure.
    ///
    /// ## Example
    ///
    /// ```swift
    /// let numbers = [1, 2, 3, 4, 5]
    ///
    /// // Asynchronous predicate function
    /// func isEven(_ number: Int) async -> Bool {
    ///     return number % 2 == 0
    /// }
    ///
    /// Task {
    ///     let containsEven = await numbers.asyncContains(where: isEven)
    ///     print("Contains even number: \(containsEven)") // Output: Contains even number: true
    /// }
    /// ```
    func asyncContains(where predicate: @Sendable (Element) async -> Bool) async -> Bool {
        for element in self {
            if await predicate(element) {
                return true
            }
        }
        return false
    }
}

// MARK: - Range<Int> AsyncMap

public extension Range where Bound == Int {
    func asyncMap<T>(transform: @Sendable (Int) async -> T) async -> [T] {
        var results = [T]()
        for element in self {
            let result = await transform(element)
            results.append(result)
        }
        return results
    }
}

// Optionally also for ClosedRange<Int> (for...through)
public extension ClosedRange where Bound == Int {
    func asyncMap<T>(transform: @Sendable (Int) async -> T) async -> [T] {
        var results = [T]()
        for element in self {
            let result = await transform(element)
            results.append(result)
        }
        return results
    }
}
