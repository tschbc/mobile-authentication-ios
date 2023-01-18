//
// SecureImage
//
// Copyright © 2018 Province of British Columbia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at 
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Created by Jason Leach on 2018-02-01.
//

import Foundation
import SwiftKeychainWrapper

public struct Credentials {
    
    public struct Key {
        public static let AccessToken = "access_token"
        public static let TokenType = "token_type"
        public static let RefreshToken = "refresh_token"
        public static let SessionState = "session_state"
        public static let RefreshExpiresIn = "refresh_expires_in"
        public static let RefreshExpiresAt = "refreshExpiresAt"
        public static let NotBeforePolicy = "not-before-policy"
        public static let ExpiresIn = "expires_in"
        public static let ExpiresAt = "expiresAt"
    }
    
    public let accessToken: String
    internal let tokenType: String
    internal let refreshToken: String
    internal let sessionState: String
    internal let refreshExpiresIn: Int // in seconds
    internal let refreshExpiresAt: Date
    internal let notBeforePolicy: Int
    internal let expiresIn: Int // in seconds
    internal let expiresAt: Date
    internal let props: [String : Any]

    static func loadFromStoredCredentials() -> Credentials? {
        
        if let json = Credentials.load() {
            return Credentials(withJSON: json)
        }
        
        return nil
    }
    
    static func dateToString(date: Date) -> String {
        
        let formatter: DateFormatter = DateFormatter()
        formatter.dateFormat = Constants.Defaults.dateFormat
        formatter.timeZone = TimeZone(abbreviation: Constants.Defaults.timeZoneCode)

        return formatter.string(from: date)
    }
    
    static func toDate(string: String) -> Date? {
        
        let formatter: DateFormatter = DateFormatter()
        formatter.dateFormat = Constants.Defaults.dateFormat
        formatter.timeZone = TimeZone(abbreviation: Constants.Defaults.timeZoneCode)
        
        return formatter.date(from: string)
    }
    
    
    init(withJSON data: [String: Any]) {

        tokenType = data[Key.TokenType] as! String
        refreshToken = data[Key.RefreshToken] as! String
        accessToken = data[Key.AccessToken] as! String
        sessionState = data[Key.SessionState] as! String
        refreshExpiresIn = data[Key.RefreshExpiresIn] as! Int
        notBeforePolicy = data[Key.NotBeforePolicy] as! Int
        expiresIn = data[Key.ExpiresIn] as! Int
        
        // If we are loading credentials from the keychain we will have two additional fields representing when the
        // tokens will expire. Otherwise they need to be created
        if let refreshExpiresAtString = data[Key.RefreshExpiresAt] as? String,
           let refreshExpiresAt = Credentials.toDate(string: refreshExpiresAtString),
           let expiresAtString = data[Key.ExpiresAt] as? String,
           let expiresAt = Credentials.toDate(string: expiresAtString) {
            
            self.refreshExpiresAt = refreshExpiresAt
            self.expiresAt = expiresAt
        } else {
            refreshExpiresAt = Date().addingTimeInterval(Double(refreshExpiresIn))
            expiresAt = Date().addingTimeInterval(Double(expiresIn))
        }

        // Used to serialize this object so it can be stored in the keychian
        props = [
            Key.TokenType: tokenType,
            Key.RefreshToken: refreshToken,
            Key.AccessToken: accessToken,
            Key.SessionState: sessionState,
            Key.RefreshExpiresIn: refreshExpiresIn,
            Key.NotBeforePolicy: notBeforePolicy,
            Key.ExpiresIn: expiresIn,
            Key.RefreshExpiresAt: Credentials.dateToString(date: refreshExpiresAt),
            Key.ExpiresAt: Credentials.dateToString(date: expiresAt)
        ]

        save()
    }

    internal func remove() {
        
        KeychainWrapper.standard.removeObject(forKey: Constants.Keychain.KeycloakCredentials)
    }
    
    public func isExpired() -> Bool {

        return isAuthTokenExpired() && isRefreshTokenExpired()
    }
    
    public func canRefresh() -> Bool {
        
        return isAuthTokenExpired() && !isRefreshTokenExpired()
    }
    
    public func isAuthTokenExpired() -> Bool {
        
        return Date() > expiresAt
    }

    public func isRefreshTokenExpired() -> Bool {

        return Date() > refreshExpiresAt
    }

    private static func load() -> [String: Any]? {

        if let value = KeychainWrapper.standard.string(forKey: Constants.Keychain.KeycloakCredentials), let data = Data(base64Encoded: value) {
            do {
                return try JSONSerialization.jsonObject(with: data, options: .allowFragments) as? [String: Any]
            } catch let error {
                print("error converting to json: \(error)")
            }
        }

        return nil
    }
    
    private func save() {

        do {
            let data = try JSONSerialization.data(withJSONObject: props, options: .prettyPrinted)
            // Securley store the credentials
            guard KeychainWrapper.standard.set(data.base64EncodedString(), forKey: Constants.Keychain.KeycloakCredentials) else {
                fatalError("Unalbe to store auth credentials")
            }
        } catch let error {
            print("error converting to json: \(error)")
        }
    }
    
}
