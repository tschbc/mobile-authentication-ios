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
// Created by Jason Leach on 2018-02-02.
//

import Foundation
import AppAuth

public typealias AuthenticationCompleted = (_ credentials: Credentials?, _ error: Error?) -> Void

public class AuthServices: NSObject {

    private let endpoint: Endpoint
    private let authConfig: OIDServiceConfiguration
    
    private var authRequest: OIDAuthorizationRequest {
        return OIDAuthorizationRequest(
            configuration: authConfig,
            clientId: endpoint.clientId,
            scopes: [OIDScopeOpenID, OIDScopeProfile],
            redirectURL: URL(string: endpoint.redirectUri)!,
            responseType: OIDResponseTypeCode,
            additionalParameters: nil
        )
    }
    
    public private(set) var credentials: Credentials? = {
        return Credentials.loadFromStoredCredentials()
    }()
    
    public var onAuthenticationCompleted: AuthenticationCompleted?
    
    private var _authState: OIDAuthState?
    var authState: OIDAuthState? {
        get {
            if _authState == nil {
                do {
                    _authState = try OIDAuthState.loadFromSerialized()
                } catch {
                    _authState = nil
                }
            }
            return _authState
        }
        set {
            _authState = newValue
        }
    }
    var currentAuthorizationFlow: OIDExternalUserAgentSession?
    
    public init(baseUrl: URL, redirectUri: String, clientId: String, realm: String, idpHint: String? = nil) {
        
        endpoint = Endpoint(
            realmName: realm,
            clientId: clientId,
            redirectUri: redirectUri,
            baseUrl: baseUrl.absoluteString,
            hint: idpHint
        )
        
        authConfig = OIDServiceConfiguration(
            authorizationEndpoint: URL(string: endpoint.authUrl)!,
            tokenEndpoint: URL(string: endpoint.tokenUrl)!
        )
        
        super.init()
    }

    public func isAuthenticated() -> Bool {
        if let credentials {
            return credentials.isValid()
        }
        return false
    }
    
    public func canRefresh() -> Bool {
        if let credentials {
            return credentials.canRefresh() && authState != nil
        }
        return false
    }
    
    public func doWithAuthentication(presenting: UIViewController, completion: @escaping (Credentials?, Error?) -> Void) {
        if isAuthenticated() {
            completion(credentials, nil)
        } else if canRefresh() {
            refreshCredientials(completion: completion)
        } else {
            // no credentials or all tokens expired
            authenticate(presenting: presenting, completion: completion)
        }
    }
    
    private func authenticate(presenting: UIViewController, completion: @escaping (Credentials?, Error?) -> Void) {
        
        OIDAuthState.removeFromStorage()
        
        currentAuthorizationFlow = OIDAuthState.authState(byPresenting: authRequest, presenting: presenting)
        { authState, error in
            
            self.authState = authState ?? nil
            self.credentials = authState?.lastTokenResponse?.toCredentials()
            
            if let authState, error == nil {
                do {
                    try authState.saveAsSerialized()
                } catch let savingError {
                    self.logout()
                    completion(nil, savingError)
                    return
                }
            }
            
            completion(self.credentials, error)
        }
    }
    
    private func refreshCredientials(completion: @escaping (Credentials?, Error?) -> Void) {
        
        guard let credentials else {
            completion(nil, AuthenticationError.credentialsUnavailable)
            return
        }
        
        if credentials.isRefreshTokenExpired() {
            completion(nil, AuthenticationError.expired)
            return
        }
        
        guard let authState else {
            completion(nil, AuthenticationError.credentialsUnavailable)
            return
        }
        
        guard let tokenRefreshRequest = authState.tokenRefreshRequest() else {
            completion(nil, AuthenticationError.unableToCreateTokenRefreshRequest)
            return
        }
        
        OIDAuthorizationService.perform(tokenRefreshRequest) { tokenResponse, error in
            let credentials = tokenResponse?.toCredentials()
            
            if let _ = credentials, error == nil {
                do {
                    try authState.saveAsSerialized()
                } catch let savingError {
                    self.logout()
                    completion(nil, savingError)
                    return
                }
            }
            
            self.credentials = credentials
            completion(credentials, error)
        }
    }
    
    public func logout() {
        
        if let credentials {
            credentials.remove();
            self.credentials = nil
        }

        OIDAuthState.removeFromStorage()
    }
}
