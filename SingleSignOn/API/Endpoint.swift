//
//  EndpointInfo.swift
//  SingleSignOn
//
//  Created by Scharien, Todd SDPR:EX on 2023-01-13.
//  Copyright © 2023 Jason Leach. All rights reserved.
//

import Foundation

public struct Endpoint {
    public let realmName: String
    public let clientId: String
    public let redirectUri: String
    public let baseUrl: String
    public let responseType: String
    
    public let hint: String?
    
    var baseOidcUrl: String {
        return baseUrl + "/auth/realms/\(realmName)/protocol/openid-connect"
    }
    
    public var authUrl: String {
        return baseOidcUrl + "/auth"
    }
    
    public var tokenUrl: String {
        return baseOidcUrl + "/token"
    }
    
    public var logoutUrl: String {
        return baseOidcUrl + "/logout"
    }
    
    public var oidcQuery: String {
        var query = "response_type=\(responseType)&client_id=\(clientId)&redirect_uri=\(redirectUri)"
        
        if let hint = hint {
            query += "&kc_idp_hint=\(hint)"
        }
        
        return query
    }
    
    init(realmName: String,
         clientId: String,
         redirectUri: String,
         baseUrl: String,
         responseType: String = Constants.API.authenticationResponseType,
         hint: String? = nil) {
        
        self.realmName = realmName
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.baseUrl = baseUrl
        self.responseType = responseType
        
        self.hint = hint
    }
}
