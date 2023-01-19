//
//  OIDAuthStateExtensions.swift
//  SingleSignOn
//
//  Created by Scharien, Todd SDPR:EX on 2023-01-18.
//

import Foundation
import AppAuth
import SwiftKeychainWrapper

internal extension OIDAuthState {
    
    static let AuthStateKey = "Serialized.AppAuth.OIDAuthState"
    
    private func saveToStorage(data: Data) {
        KeychainWrapper.standard.set(data, forKey: OIDAuthState.AuthStateKey)
    }
    
    private static func loadFromStorage() -> Data? {
        return KeychainWrapper.standard.data(forKey: OIDAuthState.AuthStateKey)
    }
    
    static func removeFromStorage() {
        KeychainWrapper.standard.remove(key: OIDAuthState.AuthStateKey)
    }
    
    func saveAsSerialized() throws {
        let data = try NSKeyedArchiver.archivedData(withRootObject: self, requiringSecureCoding: true)
        saveToStorage(data: data)
    }
    
    static func loadFromSerialized() throws -> OIDAuthState {
        if let data = loadFromStorage() {
            return try NSKeyedUnarchiver.unarchivedObject(ofClass: OIDAuthState.self, from: data)!
        } else {
            throw AuthenticationError.credentialsUnavailable
        }
    }
    
}
