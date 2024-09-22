//
//  NetworkDelegate.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//
import Foundation

public protocol NetworkDelegate: Sendable {
    var isViable: Bool { get set }
}
