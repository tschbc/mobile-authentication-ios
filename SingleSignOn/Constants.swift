//
// SecureImage
//
// Copyright © 2017 Province of British Columbia
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
// Created by Jason Leach on 2017-02-01.
//

import Foundation

struct Constants {
    
    struct Defaults {
        static let dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZZ"
        static let timeZoneCode = "UTC"
    }
    
    struct Keychain {
        static let KeycloakCredentials = "KeycloakCredentials"
    }

    struct API {
        static let authenticationResponseType = "code"
        static let allowedWebDomain = "gov.bc.ca"
        static let secureScheme = "https"
    }
    
    enum GrantType: String {
        case refreshToken = "refresh_token"
        case authorizationCode = "authorization_code"
    }
}
