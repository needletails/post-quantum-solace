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
                input.pqsCanonicalSecretName ==
                input.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }
    }

    @Test("IRC-equivalent characters are folded so PQS lookups match transport-stored names")
    func ircEquivalentCharactersAreFolded() {
        #expect("Foo[bar]".pqsCanonicalSecretName == "foo{bar}")
        #expect("Back\\Slash".pqsCanonicalSecretName == "back|slash")
        #expect("Tilde~Name".pqsCanonicalSecretName == "tilde^name")
        #expect("[mix]\\Of~All".pqsCanonicalSecretName == "{mix}|of^all")
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
            let once = input.pqsCanonicalSecretName
            let twice = once.pqsCanonicalSecretName
            #expect(once == twice)
        }
    }
}
