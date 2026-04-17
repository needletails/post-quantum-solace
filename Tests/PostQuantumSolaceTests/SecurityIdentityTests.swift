//
//  SecurityIdentityTests.swift
//  post-quantum-solace
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//

import Crypto
import Foundation
import SessionModels
import Testing

@Suite("SecurityIdentity safety numbers")
struct SecurityIdentityTests {

    private func identity(secretName: String) -> SecurityIdentity {
        let key = Curve25519.Signing.PrivateKey()
        return SecurityIdentity(
            secretName: secretName,
            signingPublicKey: key.publicKey.rawRepresentation
        )
    }

    @Test("safetyNumber is symmetric across the two parties")
    func safetyNumberIsSymmetric() {
        let alice = identity(secretName: "alice")
        let bob = identity(secretName: "bob")

        // Use a low iteration count to keep tests fast; behaviour is identical at
        // any iteration value because both sides derive identical fingerprints.
        let aFromAlice = SecurityIdentity.safetyNumber(local: alice, remote: bob, iterations: 8)
        let aFromBob = SecurityIdentity.safetyNumber(local: bob, remote: alice, iterations: 8)
        #expect(aFromAlice == aFromBob)
    }

    @Test("safetyNumber is deterministic for fixed inputs")
    func safetyNumberIsDeterministic() {
        let alice = identity(secretName: "alice")
        let bob = identity(secretName: "bob")

        let first = SecurityIdentity.safetyNumber(local: alice, remote: bob, iterations: 8)
        let second = SecurityIdentity.safetyNumber(local: alice, remote: bob, iterations: 8)
        #expect(first == second)
    }

    @Test("safetyNumber renders 60 digits in 12 groups of 5")
    func safetyNumberFormat() {
        let alice = identity(secretName: "alice")
        let bob = identity(secretName: "bob")

        let number = SecurityIdentity.safetyNumber(local: alice, remote: bob, iterations: 8)
        let groups = number.split(separator: " ")
        #expect(groups.count == 12)
        for group in groups {
            #expect(group.count == 5)
            let allDigits = group.allSatisfy(\.isNumber)
            #expect(allDigits)
        }
    }

    @Test("safetyNumber changes when either party's key changes")
    func safetyNumberChangesWithKey() {
        let alice = identity(secretName: "alice")
        let bob = identity(secretName: "bob")
        let aliceRotated = SecurityIdentity(
            secretName: "alice",
            signingPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        )

        let original = SecurityIdentity.safetyNumber(local: alice, remote: bob, iterations: 8)
        let rotated = SecurityIdentity.safetyNumber(local: aliceRotated, remote: bob, iterations: 8)
        #expect(original != rotated)
    }

    @Test("safetyNumber differs when secretName differs even if key matches")
    func safetyNumberBindsToSecretName() {
        let key = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        let alice = SecurityIdentity(secretName: "alice", signingPublicKey: key)
        let alias = SecurityIdentity(secretName: "alice-alias", signingPublicKey: key)
        let bob = identity(secretName: "bob")

        let aBob = SecurityIdentity.safetyNumber(local: alice, remote: bob, iterations: 8)
        let aliasBob = SecurityIdentity.safetyNumber(local: alias, remote: bob, iterations: 8)
        #expect(aBob != aliasBob)
    }

    @Test("shortFingerprintHex is deterministic and changes with the key")
    func shortFingerprintHex() {
        let alice = identity(secretName: "alice")
        let aliceAgain = SecurityIdentity(
            secretName: alice.secretName,
            signingPublicKey: alice.signingPublicKey
        )
        let other = identity(secretName: "alice")

        #expect(alice.shortFingerprintHex() == aliceAgain.shortFingerprintHex())
        #expect(alice.shortFingerprintHex() != other.shortFingerprintHex())
        // 8 bytes → 4 colon-separated 4-char groups.
        let groups = alice.shortFingerprintHex().split(separator: ":")
        #expect(groups.count == 4)
        for group in groups { #expect(group.count == 4) }
    }
}
