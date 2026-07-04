//
//  String+CanonicalSecretName.swift
//  post-quantum-solace
//
//  Created by Cole M on 2026-04-17.
//
//  Copyright (c) 2026 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//

import Foundation

extension String {
    /// Canonical normalization for any user-facing identifier (a `secretName`)
    /// stored or looked up inside Post-Quantum Solace.
    ///
    /// This intentionally mirrors the IRC nickname normalization used by the
    /// `nudge-kit` transport layer (`String.ircLowercased`):
    ///
    /// - Lowercases the string.
    /// - Substitutes the IRC-equivalent of the four "wall" characters that
    ///   IRC RFC 2812 considers case-equivalent: `[` → `{`, `]` → `}`,
    ///   `\` → `|`, `~` → `^`.
    /// - Trims surrounding whitespace and newlines.
    ///
    /// Keeping PQS's normalization in lock-step with the transport prevents a
    /// class of latent bugs where a contact created via the transport (which
    /// always pre-normalizes) is later looked up directly through PQS APIs and
    /// missed because the local lookup applies a weaker normalization.
    ///
    /// For ASCII-only identifiers the output is identical to
    /// `lowercased().trimmingCharacters(in: .whitespacesAndNewlines)`, so this
    /// is safe to apply to existing data: anything already stored by the
    /// transport-layer flow is already in this canonical form.
    public var pqsCanonicalSecretName: String {
        self.lowercased()
            .replacingOccurrences(of: "[", with: "{")
            .replacingOccurrences(of: "]", with: "}")
            .replacingOccurrences(of: "\\", with: "|")
            .replacingOccurrences(of: "~", with: "^")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
