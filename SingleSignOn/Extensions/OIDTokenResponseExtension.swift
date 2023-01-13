//
//  OIDTokenResponseExtension.swift
//  SingleSignOn
//
//  Created by Scharien, Todd SDPR:EX on 2023-01-04.
//  Copyright © 2023 Jason Leach. All rights reserved.
//

import Foundation
import AppAuth

extension OIDTokenResponse {
    
    func toCredentials() -> Credentials {
        
        return Credentials(withJSON: [
            Credentials.Key.TokenType: tokenType!,
            Credentials.Key.RefreshToken: refreshToken!,
            Credentials.Key.AccessToken: accessToken!,
            Credentials.Key.SessionState: value(forKey: Credentials.Key.SessionState) as Any,
            Credentials.Key.RefreshExpiresIn: value(forKey: Credentials.Key.RefreshExpiresIn) as Any,
            Credentials.Key.RefreshExpiresAt: value(forKey: Credentials.Key.RefreshExpiresAt) as Any,
            Credentials.Key.NotBeforePolicy: value(forKey: Credentials.Key.NotBeforePolicy) as Any,
            Credentials.Key.ExpiresIn: value(forKey: Credentials.Key.ExpiresIn) as Any,
            Credentials.Key.ExpiresAt: accessTokenExpirationDate!
        ])
        
    }
    
}
