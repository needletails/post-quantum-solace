//
//  CanonicalSecretNameTests.swift
//  post-quantum-solace
//
//  Created by Cole M on 2026-04-17.
//
//  Copyright (c) 2026 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//

@testable import SessionModels
import Testing

@Suite(.serialized)
struct CanonicalSecretNameTests {
    @Test("ASCII names match plain lowercased+trim semantics")
    func asciiNamesAreEquivalentToLowercasedTrim() {
        let inputs = [
            "Alice",
            "  bob  ",
            "Charlie\n",
            "MIXEDcase",
        ]

        for input in inputs {
            #expect(
                SecretName(input).rawValue ==
                input.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }
    }

    @Test("IRC-equivalent characters are folded so PQS lookups match transport-stored names")
    func ircEquivalentCharactersAreFolded() {
        #expect(SecretName("Foo[bar]").rawValue == "foo{bar}")
        #expect(SecretName("Back\\Slash").rawValue == "back|slash")
        #expect(SecretName("Tilde~Name").rawValue == "tilde^name")
        #expect(SecretName("[mix]\\Of~All").rawValue == "{mix}|of^all")
    }

    @Test("areEqual folds case and IRC-equivalent characters")
    func areEqualFoldsIdentity() {
        #expect(SecretName.areEqual("Alice", "alice"))
        #expect(SecretName.areEqual("Foo[bar]", "foo{bar}"))
        #expect(!SecretName.areEqual("alice", "bob"))
        #expect(!SecretName.areEqual("", "bob"))
    }

    @Test("Normalization is idempotent")
    func normalizationIsIdempotent() {
        let inputs = [
            "Alice",
            "Foo[bar]",
            "Back\\Slash",
            "Tilde~Name",
            "  [Mixed]Case~  ",
        ]

        for input in inputs {
            let once = SecretName(input).rawValue
            let twice = SecretName(once).rawValue
            #expect(once == twice)
        }
    }
}
