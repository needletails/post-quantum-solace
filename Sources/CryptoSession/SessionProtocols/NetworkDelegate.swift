//
//  NetworkDelegate.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/14/24.
//
import Foundation

public protocol NetworkDelegate: Sendable {
    var isViable: Bool { get set }
}
