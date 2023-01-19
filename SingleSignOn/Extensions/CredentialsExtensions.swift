//
//  CredentialsExtensions.swift
//  SingleSignOn
//
//  Created by Scharien, Todd SDPR:EX on 2023-01-04.
//  Copyright © 2023 Jason Leach. All rights reserved.
//

import Foundation
import AppAuth

extension OIDTokenResponse {
    
    func toCredentials() -> Credentials {
        let currentDate = Date()
        let expiresIn = accessTokenExpirationDate!.timeIntervalSince(currentDate) // in seconds
        let refreshExpiresIn = additionalParameters?[Credentials.Key.RefreshExpiresIn] as! Double // in seconds
        let refreshExpiresAt = currentDate.addingTimeInterval(refreshExpiresIn)
        
        return Credentials(withJSON: [
            Credentials.Key.TokenType: tokenType!,
            Credentials.Key.RefreshToken: refreshToken!,
            Credentials.Key.AccessToken: accessToken!,
            Credentials.Key.SessionState: String(describing: additionalParameters?[Credentials.Key.SessionState]),
            Credentials.Key.RefreshExpiresIn: Int(refreshExpiresIn),
            Credentials.Key.RefreshExpiresAt: refreshExpiresAt,
            Credentials.Key.NotBeforePolicy: additionalParameters?[Credentials.Key.NotBeforePolicy] as! Int,
            Credentials.Key.ExpiresIn: Int(expiresIn),
            Credentials.Key.ExpiresAt: accessTokenExpirationDate!
        ])
        
    }
    
}
