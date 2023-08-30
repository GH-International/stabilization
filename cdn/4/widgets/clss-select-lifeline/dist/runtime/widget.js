System.register(["jimu-core","jimu-ui","jimu-core/react","jimu-arcgis"], function(__WEBPACK_DYNAMIC_EXPORT__, __system_context__) {
	var __WEBPACK_EXTERNAL_MODULE_jimu_core__ = {};
	var __WEBPACK_EXTERNAL_MODULE_jimu_ui__ = {};
	var __WEBPACK_EXTERNAL_MODULE_react__ = {};
	var __WEBPACK_EXTERNAL_MODULE_jimu_arcgis__ = {};
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_jimu_core__, "__esModule", { value: true });
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_jimu_ui__, "__esModule", { value: true });
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_react__, "__esModule", { value: true });
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_jimu_arcgis__, "__esModule", { value: true });
	return {
		setters: [
			function(module) {
				Object.keys(module).forEach(function(key) {
					__WEBPACK_EXTERNAL_MODULE_jimu_core__[key] = module[key];
				});
			},
			function(module) {
				Object.keys(module).forEach(function(key) {
					__WEBPACK_EXTERNAL_MODULE_jimu_ui__[key] = module[key];
				});
			},
			function(module) {
				Object.keys(module).forEach(function(key) {
					__WEBPACK_EXTERNAL_MODULE_react__[key] = module[key];
				});
			},
			function(module) {
				Object.keys(module).forEach(function(key) {
					__WEBPACK_EXTERNAL_MODULE_jimu_arcgis__[key] = module[key];
				});
			}
		],
		execute: function() {
			__WEBPACK_DYNAMIC_EXPORT__(
/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ "./node_modules/@esri/arcgis-rest-auth/dist/esm/UserSession.js":
/*!*********************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-auth/dist/esm/UserSession.js ***!
  \*********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "UserSession": () => (/* binding */ UserSession)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-auth/node_modules/tslib/tslib.es6.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-query-string.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/decode-query-string.js");
/* harmony import */ var _generate_token__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./generate-token */ "./node_modules/@esri/arcgis-rest-auth/dist/esm/generate-token.js");
/* harmony import */ var _fetch_token__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./fetch-token */ "./node_modules/@esri/arcgis-rest-auth/dist/esm/fetch-token.js");
/* harmony import */ var _federation_utils__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./federation-utils */ "./node_modules/@esri/arcgis-rest-auth/dist/esm/federation-utils.js");
/* harmony import */ var _validate_app_access__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./validate-app-access */ "./node_modules/@esri/arcgis-rest-auth/dist/esm/validate-app-access.js");
/* Copyright (c) 2017-2019 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */






function defer() {
    var deferred = {
        promise: null,
        resolve: null,
        reject: null,
    };
    deferred.promise = new Promise(function (resolve, reject) {
        deferred.resolve = resolve;
        deferred.reject = reject;
    });
    return deferred;
}
/**
 * ```js
 * import { UserSession } from '@esri/arcgis-rest-auth';
 * UserSession.beginOAuth2({
 *   // register an app of your own to create a unique clientId
 *   clientId: "abc123",
 *   redirectUri: 'https://yourapp.com/authenticate.html'
 * })
 *   .then(session)
 * // or
 * new UserSession({
 *   username: "jsmith",
 *   password: "123456"
 * })
 * // or
 * UserSession.deserialize(cache)
 * ```
 * Used to authenticate both ArcGIS Online and ArcGIS Enterprise users. `UserSession` includes helper methods for [OAuth 2.0](/arcgis-rest-js/guides/browser-authentication/) in both browser and server applications.
 */
var UserSession = /** @class */ (function () {
    function UserSession(options) {
        this.clientId = options.clientId;
        this._refreshToken = options.refreshToken;
        this._refreshTokenExpires = options.refreshTokenExpires;
        this.username = options.username;
        this.password = options.password;
        this._token = options.token;
        this._tokenExpires = options.tokenExpires;
        this.portal = options.portal
            ? (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(options.portal)
            : "https://www.arcgis.com/sharing/rest";
        this.ssl = options.ssl;
        this.provider = options.provider || "arcgis";
        this.tokenDuration = options.tokenDuration || 20160;
        this.redirectUri = options.redirectUri;
        this.refreshTokenTTL = options.refreshTokenTTL || 20160;
        this.server = options.server;
        this.federatedServers = {};
        this.trustedDomains = [];
        // if a non-federated server was passed explicitly, it should be trusted.
        if (options.server) {
            // if the url includes more than '/arcgis/', trim the rest
            var root = this.getServerRootUrl(options.server);
            this.federatedServers[root] = {
                token: options.token,
                expires: options.tokenExpires,
            };
        }
        this._pendingTokenRequests = {};
    }
    Object.defineProperty(UserSession.prototype, "token", {
        /**
         * The current ArcGIS Online or ArcGIS Enterprise `token`.
         */
        get: function () {
            return this._token;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(UserSession.prototype, "tokenExpires", {
        /**
         * The expiration time of the current `token`.
         */
        get: function () {
            return this._tokenExpires;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(UserSession.prototype, "refreshToken", {
        /**
         * The current token to ArcGIS Online or ArcGIS Enterprise.
         */
        get: function () {
            return this._refreshToken;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(UserSession.prototype, "refreshTokenExpires", {
        /**
         * The expiration time of the current `refreshToken`.
         */
        get: function () {
            return this._refreshTokenExpires;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(UserSession.prototype, "trustedServers", {
        /**
         * Deprecated, use `federatedServers` instead.
         *
         * @deprecated
         */
        get: function () {
            console.log("DEPRECATED: use federatedServers instead");
            return this.federatedServers;
        },
        enumerable: false,
        configurable: true
    });
    /**
     * Begins a new browser-based OAuth 2.0 sign in. If `options.popup` is `true` the
     * authentication window will open in a new tab/window and the function will return
     * Promise&lt;UserSession&gt;. Otherwise, the user will be redirected to the
     * authorization page in their current tab/window and the function will return `undefined`.
     *
     * @browserOnly
     */
    /* istanbul ignore next */
    UserSession.beginOAuth2 = function (options, win) {
        if (win === void 0) { win = window; }
        if (options.duration) {
            console.log("DEPRECATED: 'duration' is deprecated - use 'expiration' instead");
        }
        var _a = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({
            portal: "https://www.arcgis.com/sharing/rest",
            provider: "arcgis",
            expiration: 20160,
            popup: true,
            popupWindowFeatures: "height=400,width=600,menubar=no,location=yes,resizable=yes,scrollbars=yes,status=yes",
            state: options.clientId,
            locale: "",
        }, options), portal = _a.portal, provider = _a.provider, clientId = _a.clientId, expiration = _a.expiration, redirectUri = _a.redirectUri, popup = _a.popup, popupWindowFeatures = _a.popupWindowFeatures, state = _a.state, locale = _a.locale, params = _a.params;
        var url;
        if (provider === "arcgis") {
            url = portal + "/oauth2/authorize?client_id=" + clientId + "&response_type=token&expiration=" + (options.duration || expiration) + "&redirect_uri=" + encodeURIComponent(redirectUri) + "&state=" + state + "&locale=" + locale;
        }
        else {
            url = portal + "/oauth2/social/authorize?client_id=" + clientId + "&socialLoginProviderName=" + provider + "&autoAccountCreateForSocial=true&response_type=token&expiration=" + (options.duration || expiration) + "&redirect_uri=" + encodeURIComponent(redirectUri) + "&state=" + state + "&locale=" + locale;
        }
        // append additional params
        if (params) {
            url = url + "&" + (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_2__.encodeQueryString)(params);
        }
        if (!popup) {
            win.location.href = url;
            return undefined;
        }
        var session = defer();
        win["__ESRI_REST_AUTH_HANDLER_" + clientId] = function (errorString, oauthInfoString) {
            if (errorString) {
                var error = JSON.parse(errorString);
                session.reject(new _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.ArcGISAuthError(error.errorMessage, error.error));
                return;
            }
            if (oauthInfoString) {
                var oauthInfo = JSON.parse(oauthInfoString);
                session.resolve(new UserSession({
                    clientId: clientId,
                    portal: portal,
                    ssl: oauthInfo.ssl,
                    token: oauthInfo.token,
                    tokenExpires: new Date(oauthInfo.expires),
                    username: oauthInfo.username,
                }));
            }
        };
        win.open(url, "oauth-window", popupWindowFeatures);
        return session.promise;
    };
    /**
     * Completes a browser-based OAuth 2.0 sign in. If `options.popup` is `true` the user
     * will be returned to the previous window. Otherwise a new `UserSession`
     * will be returned. You must pass the same values for `options.popup` and
     * `options.portal` as you used in `beginOAuth2()`.
     *
     * @browserOnly
     */
    /* istanbul ignore next */
    UserSession.completeOAuth2 = function (options, win) {
        if (win === void 0) { win = window; }
        var _a = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ portal: "https://www.arcgis.com/sharing/rest", popup: true }, options), portal = _a.portal, clientId = _a.clientId, popup = _a.popup;
        function completeSignIn(error, oauthInfo) {
            try {
                var handlerFn = void 0;
                var handlerFnName = "__ESRI_REST_AUTH_HANDLER_" + clientId;
                if (popup) {
                    // Guard b/c IE does not support window.opener
                    if (win.opener) {
                        if (win.opener.parent && win.opener.parent[handlerFnName]) {
                            handlerFn = win.opener.parent[handlerFnName];
                        }
                        else if (win.opener && win.opener[handlerFnName]) {
                            // support pop-out oauth from within an iframe
                            handlerFn = win.opener[handlerFnName];
                        }
                    }
                    else {
                        // IE
                        if (win !== win.parent && win.parent && win.parent[handlerFnName]) {
                            handlerFn = win.parent[handlerFnName];
                        }
                    }
                    // if we have a handler fn, call it and close the window
                    if (handlerFn) {
                        handlerFn(error ? JSON.stringify(error) : undefined, JSON.stringify(oauthInfo));
                        win.close();
                        return undefined;
                    }
                }
            }
            catch (e) {
                throw new _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.ArcGISAuthError("Unable to complete authentication. It's possible you specified popup based oAuth2 but no handler from \"beginOAuth2()\" present. This generally happens because the \"popup\" option differs between \"beginOAuth2()\" and \"completeOAuth2()\".");
            }
            if (error) {
                throw new _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.ArcGISAuthError(error.errorMessage, error.error);
            }
            return new UserSession({
                clientId: clientId,
                portal: portal,
                ssl: oauthInfo.ssl,
                token: oauthInfo.token,
                tokenExpires: oauthInfo.expires,
                username: oauthInfo.username,
            });
        }
        var params = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_4__.decodeQueryString)(win.location.hash);
        if (!params.access_token) {
            var error = void 0;
            var errorMessage = "Unknown error";
            if (params.error) {
                error = params.error;
                errorMessage = params.error_description;
            }
            return completeSignIn({ error: error, errorMessage: errorMessage });
        }
        var token = params.access_token;
        var expires = new Date(Date.now() + parseInt(params.expires_in, 10) * 1000 - 60 * 1000);
        var username = params.username;
        var ssl = params.ssl === "true";
        return completeSignIn(undefined, {
            token: token,
            expires: expires,
            ssl: ssl,
            username: username,
        });
    };
    /**
     * Request session information from the parent application
     *
     * When an application is embedded into another application via an IFrame, the embedded app can
     * use `window.postMessage` to request credentials from the host application. This function wraps
     * that behavior.
     *
     * The ArcGIS API for Javascript has this built into the Identity Manager as of the 4.19 release.
     *
     * Note: The parent application will not respond if the embedded app's origin is not:
     * - the same origin as the parent or *.arcgis.com (JSAPI)
     * - in the list of valid child origins (REST-JS)
     *
     *
     * @param parentOrigin origin of the parent frame. Passed into the embedded application as `parentOrigin` query param
     * @browserOnly
     */
    UserSession.fromParent = function (parentOrigin, win) {
        /* istanbul ignore next: must pass in a mockwindow for tests so we can't cover the other branch */
        if (!win && window) {
            win = window;
        }
        // Declare handler outside of promise scope so we can detach it
        var handler;
        // return a promise that will resolve when the handler receives
        // session information from the correct origin
        return new Promise(function (resolve, reject) {
            // create an event handler that just wraps the parentMessageHandler
            handler = function (event) {
                // ensure we only listen to events from the parent
                if (event.source === win.parent && event.data) {
                    try {
                        return resolve(UserSession.parentMessageHandler(event));
                    }
                    catch (err) {
                        return reject(err);
                    }
                }
            };
            // add listener
            win.addEventListener("message", handler, false);
            win.parent.postMessage({ type: "arcgis:auth:requestCredential" }, parentOrigin);
        }).then(function (session) {
            win.removeEventListener("message", handler, false);
            return session;
        });
    };
    /**
     * Begins a new server-based OAuth 2.0 sign in. This will redirect the user to
     * the ArcGIS Online or ArcGIS Enterprise authorization page.
     *
     * @nodeOnly
     */
    UserSession.authorize = function (options, response) {
        if (options.duration) {
            console.log("DEPRECATED: 'duration' is deprecated - use 'expiration' instead");
        }
        var _a = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ portal: "https://arcgis.com/sharing/rest", expiration: 20160 }, options), portal = _a.portal, clientId = _a.clientId, expiration = _a.expiration, redirectUri = _a.redirectUri;
        response.writeHead(301, {
            Location: portal + "/oauth2/authorize?client_id=" + clientId + "&expiration=" + (options.duration || expiration) + "&response_type=code&redirect_uri=" + encodeURIComponent(redirectUri),
        });
        response.end();
    };
    /**
     * Completes the server-based OAuth 2.0 sign in process by exchanging the `authorizationCode`
     * for a `access_token`.
     *
     * @nodeOnly
     */
    UserSession.exchangeAuthorizationCode = function (options, authorizationCode) {
        var _a = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({
            portal: "https://www.arcgis.com/sharing/rest",
            refreshTokenTTL: 20160,
        }, options), portal = _a.portal, clientId = _a.clientId, redirectUri = _a.redirectUri, refreshTokenTTL = _a.refreshTokenTTL;
        return (0,_fetch_token__WEBPACK_IMPORTED_MODULE_5__.fetchToken)(portal + "/oauth2/token", {
            params: {
                grant_type: "authorization_code",
                client_id: clientId,
                redirect_uri: redirectUri,
                code: authorizationCode,
            },
        }).then(function (response) {
            return new UserSession({
                clientId: clientId,
                portal: portal,
                ssl: response.ssl,
                redirectUri: redirectUri,
                refreshToken: response.refreshToken,
                refreshTokenTTL: refreshTokenTTL,
                refreshTokenExpires: new Date(Date.now() + (refreshTokenTTL - 1) * 60 * 1000),
                token: response.token,
                tokenExpires: response.expires,
                username: response.username,
            });
        });
    };
    UserSession.deserialize = function (str) {
        var options = JSON.parse(str);
        return new UserSession({
            clientId: options.clientId,
            refreshToken: options.refreshToken,
            refreshTokenExpires: new Date(options.refreshTokenExpires),
            username: options.username,
            password: options.password,
            token: options.token,
            tokenExpires: new Date(options.tokenExpires),
            portal: options.portal,
            ssl: options.ssl,
            tokenDuration: options.tokenDuration,
            redirectUri: options.redirectUri,
            refreshTokenTTL: options.refreshTokenTTL,
        });
    };
    /**
     * Translates authentication from the format used in the [ArcGIS API for JavaScript](https://developers.arcgis.com/javascript/).
     *
     * ```js
     * UserSession.fromCredential({
     *   userId: "jsmith",
     *   token: "secret"
     * });
     * ```
     *
     * @returns UserSession
     */
    UserSession.fromCredential = function (credential) {
        // At ArcGIS Online 9.1, credentials no longer include the ssl and expires properties
        // Here, we provide default values for them to cover this condition
        var ssl = typeof credential.ssl !== "undefined" ? credential.ssl : true;
        var expires = credential.expires || Date.now() + 7200000; /* 2 hours */
        return new UserSession({
            portal: credential.server.includes("sharing/rest")
                ? credential.server
                : credential.server + "/sharing/rest",
            ssl: ssl,
            token: credential.token,
            username: credential.userId,
            tokenExpires: new Date(expires),
        });
    };
    /**
     * Handle the response from the parent
     * @param event DOM Event
     */
    UserSession.parentMessageHandler = function (event) {
        if (event.data.type === "arcgis:auth:credential") {
            return UserSession.fromCredential(event.data.credential);
        }
        if (event.data.type === "arcgis:auth:error") {
            var err = new Error(event.data.error.message);
            err.name = event.data.error.name;
            throw err;
        }
        else {
            throw new Error("Unknown message type.");
        }
    };
    /**
     * Returns authentication in a format useable in the [ArcGIS API for JavaScript](https://developers.arcgis.com/javascript/).
     *
     * ```js
     * esriId.registerToken(session.toCredential());
     * ```
     *
     * @returns ICredential
     */
    UserSession.prototype.toCredential = function () {
        return {
            expires: this.tokenExpires.getTime(),
            server: this.portal,
            ssl: this.ssl,
            token: this.token,
            userId: this.username,
        };
    };
    /**
     * Returns information about the currently logged in [user](https://developers.arcgis.com/rest/users-groups-and-items/user.htm). Subsequent calls will *not* result in additional web traffic.
     *
     * ```js
     * session.getUser()
     *   .then(response => {
     *     console.log(response.role); // "org_admin"
     *   })
     * ```
     *
     * @param requestOptions - Options for the request. NOTE: `rawResponse` is not supported by this operation.
     * @returns A Promise that will resolve with the data from the response.
     */
    UserSession.prototype.getUser = function (requestOptions) {
        var _this = this;
        if (this._pendingUserRequest) {
            return this._pendingUserRequest;
        }
        else if (this._user) {
            return Promise.resolve(this._user);
        }
        else {
            var url = this.portal + "/community/self";
            var options = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ httpMethod: "GET", authentication: this }, requestOptions), { rawResponse: false });
            this._pendingUserRequest = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.request)(url, options).then(function (response) {
                _this._user = response;
                _this._pendingUserRequest = null;
                return response;
            });
            return this._pendingUserRequest;
        }
    };
    /**
     * Returns information about the currently logged in user's [portal](https://developers.arcgis.com/rest/users-groups-and-items/portal-self.htm). Subsequent calls will *not* result in additional web traffic.
     *
     * ```js
     * session.getPortal()
     *   .then(response => {
     *     console.log(portal.name); // "City of ..."
     *   })
     * ```
     *
     * @param requestOptions - Options for the request. NOTE: `rawResponse` is not supported by this operation.
     * @returns A Promise that will resolve with the data from the response.
     */
    UserSession.prototype.getPortal = function (requestOptions) {
        var _this = this;
        if (this._pendingPortalRequest) {
            return this._pendingPortalRequest;
        }
        else if (this._portalInfo) {
            return Promise.resolve(this._portalInfo);
        }
        else {
            var url = this.portal + "/portals/self";
            var options = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ httpMethod: "GET", authentication: this }, requestOptions), { rawResponse: false });
            this._pendingPortalRequest = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.request)(url, options).then(function (response) {
                _this._portalInfo = response;
                _this._pendingPortalRequest = null;
                return response;
            });
            return this._pendingPortalRequest;
        }
    };
    /**
     * Returns the username for the currently logged in [user](https://developers.arcgis.com/rest/users-groups-and-items/user.htm). Subsequent calls will *not* result in additional web traffic. This is also used internally when a username is required for some requests but is not present in the options.
     *
     *    * ```js
     * session.getUsername()
     *   .then(response => {
     *     console.log(response); // "casey_jones"
     *   })
     * ```
     */
    UserSession.prototype.getUsername = function () {
        if (this.username) {
            return Promise.resolve(this.username);
        }
        else if (this._user) {
            return Promise.resolve(this._user.username);
        }
        else {
            return this.getUser().then(function (user) {
                return user.username;
            });
        }
    };
    /**
     * Gets an appropriate token for the given URL. If `portal` is ArcGIS Online and
     * the request is to an ArcGIS Online domain `token` will be used. If the request
     * is to the current `portal` the current `token` will also be used. However if
     * the request is to an unknown server we will validate the server with a request
     * to our current `portal`.
     */
    UserSession.prototype.getToken = function (url, requestOptions) {
        if ((0,_federation_utils__WEBPACK_IMPORTED_MODULE_6__.canUseOnlineToken)(this.portal, url)) {
            return this.getFreshToken(requestOptions);
        }
        else if (new RegExp(this.portal, "i").test(url)) {
            return this.getFreshToken(requestOptions);
        }
        else {
            return this.getTokenForServer(url, requestOptions);
        }
    };
    /**
     * Get application access information for the current user
     * see `validateAppAccess` function for details
     *
     * @param clientId application client id
     */
    UserSession.prototype.validateAppAccess = function (clientId) {
        return this.getToken(this.portal).then(function (token) {
            return (0,_validate_app_access__WEBPACK_IMPORTED_MODULE_7__.validateAppAccess)(token, clientId);
        });
    };
    UserSession.prototype.toJSON = function () {
        return {
            clientId: this.clientId,
            refreshToken: this.refreshToken,
            refreshTokenExpires: this.refreshTokenExpires,
            username: this.username,
            password: this.password,
            token: this.token,
            tokenExpires: this.tokenExpires,
            portal: this.portal,
            ssl: this.ssl,
            tokenDuration: this.tokenDuration,
            redirectUri: this.redirectUri,
            refreshTokenTTL: this.refreshTokenTTL,
        };
    };
    UserSession.prototype.serialize = function () {
        return JSON.stringify(this);
    };
    /**
     * For a "Host" app that embeds other platform apps via iframes, after authenticating the user
     * and creating a UserSession, the app can then enable "post message" style authentication by calling
     * this method.
     *
     * Internally this adds an event listener on window for the `message` event
     *
     * @param validChildOrigins Array of origins that are allowed to request authentication from the host app
     */
    UserSession.prototype.enablePostMessageAuth = function (validChildOrigins, win) {
        /* istanbul ignore next: must pass in a mockwindow for tests so we can't cover the other branch */
        if (!win && window) {
            win = window;
        }
        this._hostHandler = this.createPostMessageHandler(validChildOrigins);
        win.addEventListener("message", this._hostHandler, false);
    };
    /**
     * For a "Host" app that has embedded other platform apps via iframes, when the host needs
     * to transition routes, it should call `UserSession.disablePostMessageAuth()` to remove
     * the event listener and prevent memory leaks
     */
    UserSession.prototype.disablePostMessageAuth = function (win) {
        /* istanbul ignore next: must pass in a mockwindow for tests so we can't cover the other branch */
        if (!win && window) {
            win = window;
        }
        win.removeEventListener("message", this._hostHandler, false);
    };
    /**
     * Manually refreshes the current `token` and `tokenExpires`.
     */
    UserSession.prototype.refreshSession = function (requestOptions) {
        // make sure subsequent calls to getUser() don't returned cached metadata
        this._user = null;
        if (this.username && this.password) {
            return this.refreshWithUsernameAndPassword(requestOptions);
        }
        if (this.clientId && this.refreshToken) {
            return this.refreshWithRefreshToken();
        }
        return Promise.reject(new _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.ArcGISAuthError("Unable to refresh token."));
    };
    /**
     * Determines the root of the ArcGIS Server or Portal for a given URL.
     *
     * @param url the URl to determine the root url for.
     */
    UserSession.prototype.getServerRootUrl = function (url) {
        var root = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(url).split(/\/rest(\/admin)?\/services(?:\/|#|\?|$)/)[0];
        var _a = root.match(/(https?:\/\/)(.+)/), match = _a[0], protocol = _a[1], domainAndPath = _a[2];
        var _b = domainAndPath.split("/"), domain = _b[0], path = _b.slice(1);
        // only the domain is lowercased because in some cases an org id might be
        // in the path which cannot be lowercased.
        return "" + protocol + domain.toLowerCase() + "/" + path.join("/");
    };
    /**
     * Returns the proper [`credentials`] option for `fetch` for a given domain.
     * See [trusted server](https://enterprise.arcgis.com/en/portal/latest/administer/windows/configure-security.htm#ESRI_SECTION1_70CC159B3540440AB325BE5D89DBE94A).
     * Used internally by underlying request methods to add support for specific security considerations.
     *
     * @param url The url of the request
     * @returns "include" or "same-origin"
     */
    UserSession.prototype.getDomainCredentials = function (url) {
        if (!this.trustedDomains || !this.trustedDomains.length) {
            return "same-origin";
        }
        return this.trustedDomains.some(function (domainWithProtocol) {
            return url.startsWith(domainWithProtocol);
        })
            ? "include"
            : "same-origin";
    };
    /**
     * Return a function that closes over the validOrigins array and
     * can be used as an event handler for the `message` event
     *
     * @param validOrigins Array of valid origins
     */
    UserSession.prototype.createPostMessageHandler = function (validOrigins) {
        var _this = this;
        // return a function that closes over the validOrigins and
        // has access to the credential
        return function (event) {
            // Verify that the origin is valid
            // Note: do not use regex's here. validOrigins is an array so we're checking that the event's origin
            // is in the array via exact match. More info about avoiding postMessage xss issues here
            // https://jlajara.gitlab.io/web/2020/07/17/Dom_XSS_PostMessage_2.html#tipsbypasses-in-postmessage-vulnerabilities
            var isValidOrigin = validOrigins.indexOf(event.origin) > -1;
            // JSAPI handles this slightly differently - instead of checking a list, it will respond if
            // event.origin === window.location.origin || event.origin.endsWith('.arcgis.com')
            // For Hub, and to enable cross domain debugging with port's in urls, we are opting to
            // use a list of valid origins
            // Ensure the message type is something we want to handle
            var isValidType = event.data.type === "arcgis:auth:requestCredential";
            var isTokenValid = _this.tokenExpires.getTime() > Date.now();
            if (isValidOrigin && isValidType) {
                var msg = {};
                if (isTokenValid) {
                    var credential = _this.toCredential();
                    // arcgis:auth:error with {name: "", message: ""}
                    // the following line allows us to conform to our spec without changing other depended-on functionality
                    // https://github.com/Esri/arcgis-rest-js/blob/master/packages/arcgis-rest-auth/post-message-auth-spec.md#arcgisauthcredential
                    credential.server = credential.server.replace("/sharing/rest", "");
                    msg = { type: "arcgis:auth:credential", credential: credential };
                }
                else {
                    // Return an error
                    msg = {
                        type: "arcgis:auth:error",
                        error: {
                            name: "tokenExpiredError",
                            message: "Session token was expired, and not returned to the child application",
                        },
                    };
                }
                event.source.postMessage(msg, event.origin);
            }
        };
    };
    /**
     * Validates that a given URL is properly federated with our current `portal`.
     * Attempts to use the internal `federatedServers` cache first.
     */
    UserSession.prototype.getTokenForServer = function (url, requestOptions) {
        var _this = this;
        // requests to /rest/services/ and /rest/admin/services/ are both valid
        // Federated servers may have inconsistent casing, so lowerCase it
        var root = this.getServerRootUrl(url);
        var existingToken = this.federatedServers[root];
        if (existingToken &&
            existingToken.expires &&
            existingToken.expires.getTime() > Date.now()) {
            return Promise.resolve(existingToken.token);
        }
        if (this._pendingTokenRequests[root]) {
            return this._pendingTokenRequests[root];
        }
        this._pendingTokenRequests[root] = this.fetchAuthorizedDomains().then(function () {
            return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.request)(root + "/rest/info", {
                credentials: _this.getDomainCredentials(url),
            })
                .then(function (response) {
                if (response.owningSystemUrl) {
                    /**
                     * if this server is not owned by this portal
                     * bail out with an error since we know we wont
                     * be able to generate a token
                     */
                    if (!(0,_federation_utils__WEBPACK_IMPORTED_MODULE_6__.isFederated)(response.owningSystemUrl, _this.portal)) {
                        throw new _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.ArcGISAuthError(url + " is not federated with " + _this.portal + ".", "NOT_FEDERATED");
                    }
                    else {
                        /**
                         * if the server is federated, use the relevant token endpoint.
                         */
                        return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.request)(response.owningSystemUrl + "/sharing/rest/info", requestOptions);
                    }
                }
                else if (response.authInfo &&
                    _this.federatedServers[root] !== undefined) {
                    /**
                     * if its a stand-alone instance of ArcGIS Server that doesn't advertise
                     * federation, but the root server url is recognized, use its built in token endpoint.
                     */
                    return Promise.resolve({
                        authInfo: response.authInfo,
                    });
                }
                else {
                    throw new _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.ArcGISAuthError(url + " is not federated with any portal and is not explicitly trusted.", "NOT_FEDERATED");
                }
            })
                .then(function (response) {
                return response.authInfo.tokenServicesUrl;
            })
                .then(function (tokenServicesUrl) {
                // an expired token cant be used to generate a new token
                if (_this.token && _this.tokenExpires.getTime() > Date.now()) {
                    return (0,_generate_token__WEBPACK_IMPORTED_MODULE_8__.generateToken)(tokenServicesUrl, {
                        params: {
                            token: _this.token,
                            serverUrl: url,
                            expiration: _this.tokenDuration,
                            client: "referer",
                        },
                    });
                    // generate an entirely fresh token if necessary
                }
                else {
                    return (0,_generate_token__WEBPACK_IMPORTED_MODULE_8__.generateToken)(tokenServicesUrl, {
                        params: {
                            username: _this.username,
                            password: _this.password,
                            expiration: _this.tokenDuration,
                            client: "referer",
                        },
                    }).then(function (response) {
                        _this._token = response.token;
                        _this._tokenExpires = new Date(response.expires);
                        return response;
                    });
                }
            })
                .then(function (response) {
                _this.federatedServers[root] = {
                    expires: new Date(response.expires),
                    token: response.token,
                };
                delete _this._pendingTokenRequests[root];
                return response.token;
            });
        });
        return this._pendingTokenRequests[root];
    };
    /**
     * Returns an unexpired token for the current `portal`.
     */
    UserSession.prototype.getFreshToken = function (requestOptions) {
        var _this = this;
        if (this.token && !this.tokenExpires) {
            return Promise.resolve(this.token);
        }
        if (this.token &&
            this.tokenExpires &&
            this.tokenExpires.getTime() > Date.now()) {
            return Promise.resolve(this.token);
        }
        if (!this._pendingTokenRequests[this.portal]) {
            this._pendingTokenRequests[this.portal] = this.refreshSession(requestOptions).then(function (session) {
                _this._pendingTokenRequests[_this.portal] = null;
                return session.token;
            });
        }
        return this._pendingTokenRequests[this.portal];
    };
    /**
     * Refreshes the current `token` and `tokenExpires` with `username` and
     * `password`.
     */
    UserSession.prototype.refreshWithUsernameAndPassword = function (requestOptions) {
        var _this = this;
        var options = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ params: {
                username: this.username,
                password: this.password,
                expiration: this.tokenDuration,
            } }, requestOptions);
        return (0,_generate_token__WEBPACK_IMPORTED_MODULE_8__.generateToken)(this.portal + "/generateToken", options).then(function (response) {
            _this._token = response.token;
            _this._tokenExpires = new Date(response.expires);
            return _this;
        });
    };
    /**
     * Refreshes the current `token` and `tokenExpires` with `refreshToken`.
     */
    UserSession.prototype.refreshWithRefreshToken = function (requestOptions) {
        var _this = this;
        if (this.refreshToken &&
            this.refreshTokenExpires &&
            this.refreshTokenExpires.getTime() < Date.now()) {
            return this.refreshRefreshToken(requestOptions);
        }
        var options = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ params: {
                client_id: this.clientId,
                refresh_token: this.refreshToken,
                grant_type: "refresh_token",
            } }, requestOptions);
        return (0,_fetch_token__WEBPACK_IMPORTED_MODULE_5__.fetchToken)(this.portal + "/oauth2/token", options).then(function (response) {
            _this._token = response.token;
            _this._tokenExpires = response.expires;
            return _this;
        });
    };
    /**
     * Exchanges an unexpired `refreshToken` for a new one, also updates `token` and
     * `tokenExpires`.
     */
    UserSession.prototype.refreshRefreshToken = function (requestOptions) {
        var _this = this;
        var options = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ params: {
                client_id: this.clientId,
                refresh_token: this.refreshToken,
                redirect_uri: this.redirectUri,
                grant_type: "exchange_refresh_token",
            } }, requestOptions);
        return (0,_fetch_token__WEBPACK_IMPORTED_MODULE_5__.fetchToken)(this.portal + "/oauth2/token", options).then(function (response) {
            _this._token = response.token;
            _this._tokenExpires = response.expires;
            _this._refreshToken = response.refreshToken;
            _this._refreshTokenExpires = new Date(Date.now() + (_this.refreshTokenTTL - 1) * 60 * 1000);
            return _this;
        });
    };
    /**
     * ensures that the authorizedCrossOriginDomains are obtained from the portal and cached
     * so we can check them later.
     *
     * @returns this
     */
    UserSession.prototype.fetchAuthorizedDomains = function () {
        var _this = this;
        // if this token is for a specific server or we don't have a portal
        // don't get the portal info because we cant get the authorizedCrossOriginDomains
        if (this.server || !this.portal) {
            return Promise.resolve(this);
        }
        return this.getPortal().then(function (portalInfo) {
            /**
             * Specific domains can be configured as secure.esri.com or https://secure.esri.com this
             * normalizes to https://secure.esri.com so we can use startsWith later.
             */
            if (portalInfo.authorizedCrossOriginDomains &&
                portalInfo.authorizedCrossOriginDomains.length) {
                _this.trustedDomains = portalInfo.authorizedCrossOriginDomains
                    .filter(function (d) { return !d.startsWith("http://"); })
                    .map(function (d) {
                    if (d.startsWith("https://")) {
                        return d;
                    }
                    else {
                        return "https://" + d;
                    }
                });
            }
            return _this;
        });
    };
    return UserSession;
}());

//# sourceMappingURL=UserSession.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-auth/dist/esm/federation-utils.js":
/*!**************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-auth/dist/esm/federation-utils.js ***!
  \**************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "canUseOnlineToken": () => (/* binding */ canUseOnlineToken),
/* harmony export */   "getOnlineEnvironment": () => (/* binding */ getOnlineEnvironment),
/* harmony export */   "isFederated": () => (/* binding */ isFederated),
/* harmony export */   "isOnline": () => (/* binding */ isOnline),
/* harmony export */   "normalizeOnlinePortalUrl": () => (/* binding */ normalizeOnlinePortalUrl)
/* harmony export */ });
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js");

/**
 * Used to test if a URL is an ArcGIS Online URL
 */
var arcgisOnlineUrlRegex = /^https?:\/\/(\S+)\.arcgis\.com.+/;
/**
 * Used to test if a URL is production ArcGIS Online Portal
 */
var arcgisOnlinePortalRegex = /^https?:\/\/(dev|devext|qa|qaext|www)\.arcgis\.com\/sharing\/rest+/;
/**
 * Used to test if a URL is an ArcGIS Online Organization Portal
 */
var arcgisOnlineOrgPortalRegex = /^https?:\/\/(?:[a-z0-9-]+\.maps(dev|devext|qa|qaext)?)?.arcgis\.com\/sharing\/rest/;
function isOnline(url) {
    return arcgisOnlineUrlRegex.test(url);
}
function normalizeOnlinePortalUrl(portalUrl) {
    if (!arcgisOnlineUrlRegex.test(portalUrl)) {
        return portalUrl;
    }
    switch (getOnlineEnvironment(portalUrl)) {
        case "dev":
            return "https://devext.arcgis.com/sharing/rest";
        case "qa":
            return "https://qaext.arcgis.com/sharing/rest";
        default:
            return "https://www.arcgis.com/sharing/rest";
    }
}
function getOnlineEnvironment(url) {
    if (!arcgisOnlineUrlRegex.test(url)) {
        return null;
    }
    var match = url.match(arcgisOnlineUrlRegex);
    var subdomain = match[1].split(".").pop();
    if (subdomain.includes("dev")) {
        return "dev";
    }
    if (subdomain.includes("qa")) {
        return "qa";
    }
    return "production";
}
function isFederated(owningSystemUrl, portalUrl) {
    var normalizedPortalUrl = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(normalizeOnlinePortalUrl(portalUrl)).replace(/https?:\/\//, "");
    var normalizedOwningSystemUrl = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(owningSystemUrl).replace(/https?:\/\//, "");
    return new RegExp(normalizedOwningSystemUrl, "i").test(normalizedPortalUrl);
}
function canUseOnlineToken(portalUrl, requestUrl) {
    var portalIsOnline = isOnline(portalUrl);
    var requestIsOnline = isOnline(requestUrl);
    var portalEnv = getOnlineEnvironment(portalUrl);
    var requestEnv = getOnlineEnvironment(requestUrl);
    if (portalIsOnline && requestIsOnline && portalEnv === requestEnv) {
        return true;
    }
    return false;
}
//# sourceMappingURL=federation-utils.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-auth/dist/esm/fetch-token.js":
/*!*********************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-auth/dist/esm/fetch-token.js ***!
  \*********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "fetchToken": () => (/* binding */ fetchToken)
/* harmony export */ });
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */

function fetchToken(url, requestOptions) {
    var options = requestOptions;
    // we generate a response, so we can't return the raw response
    options.rawResponse = false;
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.request)(url, options).then(function (response) {
        var r = {
            token: response.access_token,
            username: response.username,
            expires: new Date(
            // convert seconds in response to milliseconds and add the value to the current time to calculate a static expiration timestamp
            Date.now() + (response.expires_in * 1000 - 1000)),
            ssl: response.ssl === true
        };
        if (response.refresh_token) {
            r.refreshToken = response.refresh_token;
        }
        return r;
    });
}
//# sourceMappingURL=fetch-token.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-auth/dist/esm/generate-token.js":
/*!************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-auth/dist/esm/generate-token.js ***!
  \************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "generateToken": () => (/* binding */ generateToken)
/* harmony export */ });
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* Copyright (c) 2017-2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */

function generateToken(url, requestOptions) {
    var options = requestOptions;
    /* istanbul ignore else */
    if (typeof window !== "undefined" &&
        window.location &&
        window.location.host) {
        options.params.referer = window.location.host;
    }
    else {
        options.params.referer = _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.NODEJS_DEFAULT_REFERER_HEADER;
    }
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.request)(url, options);
}
//# sourceMappingURL=generate-token.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-auth/dist/esm/validate-app-access.js":
/*!*****************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-auth/dist/esm/validate-app-access.js ***!
  \*****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "validateAppAccess": () => (/* binding */ validateAppAccess)
/* harmony export */ });
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* Copyright (c) 2018-2020 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */

/**
 * Validates that the user has access to the application
 * and if they user should be presented a "View Only" mode
 *
 * This is only needed/valid for Esri applications that are "licensed"
 * and shipped in ArcGIS Online or ArcGIS Enterprise. Most custom applications
 * should not need or use this.
 *
 * ```js
 * import { validateAppAccess } from '@esri/arcgis-rest-auth';
 *
 * return validateAppAccess('your-token', 'theClientId')
 * .then((result) => {
 *    if (!result.value) {
 *      // redirect or show some other ui
 *    } else {
 *      if (result.viewOnlyUserTypeApp) {
 *        // use this to inform your app to show a "View Only" mode
 *      }
 *    }
 * })
 * .catch((err) => {
 *  // two possible errors
 *  // invalid clientId: {"error":{"code":400,"messageCode":"GWM_0007","message":"Invalid request","details":[]}}
 *  // invalid token: {"error":{"code":498,"message":"Invalid token.","details":[]}}
 * })
 * ```
 *
 * Note: This is only usable by Esri applications hosted on *arcgis.com, *esri.com or within
 * an ArcGIS Enterprise installation. Custom applications can not use this.
 *
 * @param token platform token
 * @param clientId application client id
 * @param portal Optional
 */
function validateAppAccess(token, clientId, portal) {
    if (portal === void 0) { portal = "https://www.arcgis.com/sharing/rest"; }
    var url = portal + "/oauth2/validateAppAccess";
    var ro = {
        method: "POST",
        params: {
            f: "json",
            client_id: clientId,
            token: token,
        },
    };
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.request)(url, ro);
}
//# sourceMappingURL=validate-app-access.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-auth/node_modules/tslib/tslib.es6.js":
/*!*****************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-auth/node_modules/tslib/tslib.es6.js ***!
  \*****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "__assign": () => (/* binding */ __assign),
/* harmony export */   "__asyncDelegator": () => (/* binding */ __asyncDelegator),
/* harmony export */   "__asyncGenerator": () => (/* binding */ __asyncGenerator),
/* harmony export */   "__asyncValues": () => (/* binding */ __asyncValues),
/* harmony export */   "__await": () => (/* binding */ __await),
/* harmony export */   "__awaiter": () => (/* binding */ __awaiter),
/* harmony export */   "__classPrivateFieldGet": () => (/* binding */ __classPrivateFieldGet),
/* harmony export */   "__classPrivateFieldSet": () => (/* binding */ __classPrivateFieldSet),
/* harmony export */   "__createBinding": () => (/* binding */ __createBinding),
/* harmony export */   "__decorate": () => (/* binding */ __decorate),
/* harmony export */   "__exportStar": () => (/* binding */ __exportStar),
/* harmony export */   "__extends": () => (/* binding */ __extends),
/* harmony export */   "__generator": () => (/* binding */ __generator),
/* harmony export */   "__importDefault": () => (/* binding */ __importDefault),
/* harmony export */   "__importStar": () => (/* binding */ __importStar),
/* harmony export */   "__makeTemplateObject": () => (/* binding */ __makeTemplateObject),
/* harmony export */   "__metadata": () => (/* binding */ __metadata),
/* harmony export */   "__param": () => (/* binding */ __param),
/* harmony export */   "__read": () => (/* binding */ __read),
/* harmony export */   "__rest": () => (/* binding */ __rest),
/* harmony export */   "__spread": () => (/* binding */ __spread),
/* harmony export */   "__spreadArrays": () => (/* binding */ __spreadArrays),
/* harmony export */   "__values": () => (/* binding */ __values)
/* harmony export */ });
/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return extendStatics(d, b);
};

function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

var __assign = function() {
    __assign = Object.assign || function __assign(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    }
    return __assign.apply(this, arguments);
}

function __rest(s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
}

function __decorate(decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
}

function __param(paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
}

function __metadata(metadataKey, metadataValue) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(metadataKey, metadataValue);
}

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __generator(thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
}

function __createBinding(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}

function __exportStar(m, exports) {
    for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) exports[p] = m[p];
}

function __values(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
}

function __read(o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
}

function __spread() {
    for (var ar = [], i = 0; i < arguments.length; i++)
        ar = ar.concat(__read(arguments[i]));
    return ar;
}

function __spreadArrays() {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
};

function __await(v) {
    return this instanceof __await ? (this.v = v, this) : new __await(v);
}

function __asyncGenerator(thisArg, _arguments, generator) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var g = generator.apply(thisArg, _arguments || []), i, q = [];
    return i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i;
    function verb(n) { if (g[n]) i[n] = function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]) > 1 || resume(n, v); }); }; }
    function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(q[0][3], e); } }
    function step(r) { r.value instanceof __await ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r); }
    function fulfill(value) { resume("next", value); }
    function reject(value) { resume("throw", value); }
    function settle(f, v) { if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]); }
}

function __asyncDelegator(o) {
    var i, p;
    return i = {}, verb("next"), verb("throw", function (e) { throw e; }), verb("return"), i[Symbol.iterator] = function () { return this; }, i;
    function verb(n, f) { i[n] = o[n] ? function (v) { return (p = !p) ? { value: __await(o[n](v)), done: n === "return" } : f ? f(v) : v; } : f; }
}

function __asyncValues(o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
}

function __makeTemplateObject(cooked, raw) {
    if (Object.defineProperty) { Object.defineProperty(cooked, "raw", { value: raw }); } else { cooked.raw = raw; }
    return cooked;
};

function __importStar(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result.default = mod;
    return result;
}

function __importDefault(mod) {
    return (mod && mod.__esModule) ? mod : { default: mod };
}

function __classPrivateFieldGet(receiver, privateMap) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
}

function __classPrivateFieldSet(receiver, privateMap, value) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to set private field on non-instance");
    }
    privateMap.set(receiver, value);
    return value;
}


/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/add.js":
/*!**********************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/add.js ***!
  \**********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "addFeatures": () => (/* binding */ addFeatures)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-feature-layer/node_modules/tslib/tslib.es6.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/append-custom-params.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */


/**
 * ```js
 * import { addFeatures } from '@esri/arcgis-rest-feature-layer';
 * //
 * addFeatures({
 *   url: "https://sampleserver6.arcgisonline.com/arcgis/rest/services/ServiceRequest/FeatureServer/0",
 *   features: [{
 *     geometry: { x: -120, y: 45, spatialReference: { wkid: 4326 } },
 *     attributes: { status: "alive" }
 *   }]
 * })
 *   .then(response)
 * ```
 * Add features request. See the [REST Documentation](https://developers.arcgis.com/rest/services-reference/add-features.htm) for more information.
 *
 * @param requestOptions - Options for the request.
 * @returns A Promise that will resolve with the addFeatures response.
 */
function addFeatures(requestOptions) {
    var url = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(requestOptions.url) + "/addFeatures";
    // edit operations are POST only
    var options = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_1__.appendCustomParams)(requestOptions, ["features", "gdbVersion", "returnEditMoment", "rollbackOnFailure"], { params: (0,tslib__WEBPACK_IMPORTED_MODULE_2__.__assign)({}, requestOptions.params) });
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.request)(url, options);
}
//# sourceMappingURL=add.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/delete.js":
/*!*************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/delete.js ***!
  \*************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "deleteFeatures": () => (/* binding */ deleteFeatures)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-feature-layer/node_modules/tslib/tslib.es6.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/append-custom-params.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */


/**
 * ```js
 * import { deleteFeatures } from '@esri/arcgis-rest-feature-layer';
 * //
 * deleteFeatures({
 *   url: "https://sampleserver6.arcgisonline.com/arcgis/rest/services/ServiceRequest/FeatureServer/0",
 *   objectIds: [1,2,3]
 * });
 * ```
 * Delete features request. See the [REST Documentation](https://developers.arcgis.com/rest/services-reference/delete-features.htm) for more information.
 *
 * @param deleteFeaturesRequestOptions - Options for the request.
 * @returns A Promise that will resolve with the deleteFeatures response.
 */
function deleteFeatures(requestOptions) {
    var url = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(requestOptions.url) + "/deleteFeatures";
    // edit operations POST only
    var options = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_1__.appendCustomParams)(requestOptions, [
        "where",
        "objectIds",
        "gdbVersion",
        "returnEditMoment",
        "rollbackOnFailure"
    ], { params: (0,tslib__WEBPACK_IMPORTED_MODULE_2__.__assign)({}, requestOptions.params) });
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.request)(url, options);
}
//# sourceMappingURL=delete.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/query.js":
/*!************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/query.js ***!
  \************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "getFeature": () => (/* binding */ getFeature),
/* harmony export */   "queryFeatures": () => (/* binding */ queryFeatures)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-feature-layer/node_modules/tslib/tslib.es6.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/append-custom-params.js");
/* Copyright (c) 2017-2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */


/**
 * ```js
 * import { getFeature } from '@esri/arcgis-rest-feature-layer';
 * //
 * const url = "https://services.arcgis.com/V6ZHFr6zdgNZuVG0/arcgis/rest/services/Landscape_Trees/FeatureServer/0";
 * //
 * getFeature({
 *   url,
 *   id: 42
 * }).then(feature => {
 *  console.log(feature.attributes.FID); // 42
 * });
 * ```
 * Get a feature by id.
 *
 * @param requestOptions - Options for the request
 * @returns A Promise that will resolve with the feature or the [response](https://developer.mozilla.org/en-US/docs/Web/API/Response) itself if `rawResponse: true` was passed in.
 */
function getFeature(requestOptions) {
    var url = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(requestOptions.url) + "/" + requestOptions.id;
    // default to a GET request
    var options = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ httpMethod: "GET" }, requestOptions);
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_2__.request)(url, options).then(function (response) {
        if (options.rawResponse) {
            return response;
        }
        return response.feature;
    });
}
/**
 * ```js
 * import { queryFeatures } from '@esri/arcgis-rest-feature-layer';
 * //
 * queryFeatures({
 *   url: "http://sampleserver6.arcgisonline.com/arcgis/rest/services/Census/MapServer/3",
 *   where: "STATE_NAME = 'Alaska'"
 * })
 *   .then(result)
 * ```
 * Query a feature service. See [REST Documentation](https://developers.arcgis.com/rest/services-reference/query-feature-service-layer-.htm) for more information.
 *
 * @param requestOptions - Options for the request
 * @returns A Promise that will resolve with the query response.
 */
function queryFeatures(requestOptions) {
    var queryOptions = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.appendCustomParams)(requestOptions, [
        "where",
        "objectIds",
        "relationParam",
        "time",
        "distance",
        "units",
        "outFields",
        "geometry",
        "geometryType",
        "spatialRel",
        "returnGeometry",
        "maxAllowableOffset",
        "geometryPrecision",
        "inSR",
        "outSR",
        "gdbVersion",
        "returnDistinctValues",
        "returnIdsOnly",
        "returnCountOnly",
        "returnExtentOnly",
        "orderByFields",
        "groupByFieldsForStatistics",
        "outStatistics",
        "returnZ",
        "returnM",
        "multipatchOption",
        "resultOffset",
        "resultRecordCount",
        "quantizationParameters",
        "returnCentroid",
        "resultType",
        "historicMoment",
        "returnTrueCurves",
        "sqlFormat",
        "returnExceededLimitFeatures",
        "f"
    ], {
        httpMethod: "GET",
        params: (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ 
            // set default query parameters
            where: "1=1", outFields: "*" }, requestOptions.params)
    });
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_2__.request)((0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(requestOptions.url) + "/query", queryOptions);
}
//# sourceMappingURL=query.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/queryRelated.js":
/*!*******************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/queryRelated.js ***!
  \*******************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "queryRelated": () => (/* binding */ queryRelated)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-feature-layer/node_modules/tslib/tslib.es6.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/append-custom-params.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js");
/* Copyright (c) 2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */


/**
 *
 * ```js
 * import { queryRelated } from '@esri/arcgis-rest-feature-layer'
 * //
 * queryRelated({
 *  url: "http://services.myserver/OrgID/ArcGIS/rest/services/Petroleum/KSPetro/FeatureServer/0",
 *  relationshipId: 1,
 *  params: { returnCountOnly: true }
 * })
 *  .then(response) // response.relatedRecords
 * ```
 * Query the related records for a feature service. See the [REST Documentation](https://developers.arcgis.com/rest/services-reference/query-related-records-feature-service-.htm) for more information.
 *
 * @param requestOptions
 * @returns A Promise that will resolve with the query response
 */
function queryRelated(requestOptions) {
    var options = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.appendCustomParams)(requestOptions, ["objectIds", "relationshipId", "definitionExpression", "outFields"], {
        httpMethod: "GET",
        params: (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ 
            // set default query parameters
            definitionExpression: "1=1", outFields: "*", relationshipId: 0 }, requestOptions.params)
    });
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_2__.request)((0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.cleanUrl)(requestOptions.url) + "/queryRelatedRecords", options);
}
//# sourceMappingURL=queryRelated.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/update.js":
/*!*************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/update.js ***!
  \*************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "updateFeatures": () => (/* binding */ updateFeatures)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-feature-layer/node_modules/tslib/tslib.es6.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/append-custom-params.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */


/**
 *
 * ```js
 * import { updateFeatures } from '@esri/arcgis-rest-feature-layer';
 * //
 * updateFeatures({
 *   url: "https://sampleserver6.arcgisonline.com/arcgis/rest/services/ServiceRequest/FeatureServer/0",
 *   features: [{
 *     geometry: { x: -120, y: 45, spatialReference: { wkid: 4326 } },
 *     attributes: { status: "alive" }
 *   }]
 * });
 * ```
 * Update features request. See the [REST Documentation](https://developers.arcgis.com/rest/services-reference/update-features.htm) for more information.
 *
 * @param requestOptions - Options for the request.
 * @returns A Promise that will resolve with the updateFeatures response.
 */
function updateFeatures(requestOptions) {
    var url = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(requestOptions.url) + "/updateFeatures";
    // edit operations are POST only
    var options = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_1__.appendCustomParams)(requestOptions, ["features", "gdbVersion", "returnEditMoment", "rollbackOnFailure", "trueCurveClient"], { params: (0,tslib__WEBPACK_IMPORTED_MODULE_2__.__assign)({}, requestOptions.params) });
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.request)(url, options);
}
//# sourceMappingURL=update.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-feature-layer/node_modules/tslib/tslib.es6.js":
/*!**************************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-feature-layer/node_modules/tslib/tslib.es6.js ***!
  \**************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "__assign": () => (/* binding */ __assign),
/* harmony export */   "__asyncDelegator": () => (/* binding */ __asyncDelegator),
/* harmony export */   "__asyncGenerator": () => (/* binding */ __asyncGenerator),
/* harmony export */   "__asyncValues": () => (/* binding */ __asyncValues),
/* harmony export */   "__await": () => (/* binding */ __await),
/* harmony export */   "__awaiter": () => (/* binding */ __awaiter),
/* harmony export */   "__classPrivateFieldGet": () => (/* binding */ __classPrivateFieldGet),
/* harmony export */   "__classPrivateFieldSet": () => (/* binding */ __classPrivateFieldSet),
/* harmony export */   "__createBinding": () => (/* binding */ __createBinding),
/* harmony export */   "__decorate": () => (/* binding */ __decorate),
/* harmony export */   "__exportStar": () => (/* binding */ __exportStar),
/* harmony export */   "__extends": () => (/* binding */ __extends),
/* harmony export */   "__generator": () => (/* binding */ __generator),
/* harmony export */   "__importDefault": () => (/* binding */ __importDefault),
/* harmony export */   "__importStar": () => (/* binding */ __importStar),
/* harmony export */   "__makeTemplateObject": () => (/* binding */ __makeTemplateObject),
/* harmony export */   "__metadata": () => (/* binding */ __metadata),
/* harmony export */   "__param": () => (/* binding */ __param),
/* harmony export */   "__read": () => (/* binding */ __read),
/* harmony export */   "__rest": () => (/* binding */ __rest),
/* harmony export */   "__spread": () => (/* binding */ __spread),
/* harmony export */   "__spreadArrays": () => (/* binding */ __spreadArrays),
/* harmony export */   "__values": () => (/* binding */ __values)
/* harmony export */ });
/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return extendStatics(d, b);
};

function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

var __assign = function() {
    __assign = Object.assign || function __assign(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    }
    return __assign.apply(this, arguments);
}

function __rest(s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
}

function __decorate(decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
}

function __param(paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
}

function __metadata(metadataKey, metadataValue) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(metadataKey, metadataValue);
}

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __generator(thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
}

function __createBinding(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}

function __exportStar(m, exports) {
    for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) exports[p] = m[p];
}

function __values(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
}

function __read(o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
}

function __spread() {
    for (var ar = [], i = 0; i < arguments.length; i++)
        ar = ar.concat(__read(arguments[i]));
    return ar;
}

function __spreadArrays() {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
};

function __await(v) {
    return this instanceof __await ? (this.v = v, this) : new __await(v);
}

function __asyncGenerator(thisArg, _arguments, generator) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var g = generator.apply(thisArg, _arguments || []), i, q = [];
    return i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i;
    function verb(n) { if (g[n]) i[n] = function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]) > 1 || resume(n, v); }); }; }
    function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(q[0][3], e); } }
    function step(r) { r.value instanceof __await ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r); }
    function fulfill(value) { resume("next", value); }
    function reject(value) { resume("throw", value); }
    function settle(f, v) { if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]); }
}

function __asyncDelegator(o) {
    var i, p;
    return i = {}, verb("next"), verb("throw", function (e) { throw e; }), verb("return"), i[Symbol.iterator] = function () { return this; }, i;
    function verb(n, f) { i[n] = o[n] ? function (v) { return (p = !p) ? { value: __await(o[n](v)), done: n === "return" } : f ? f(v) : v; } : f; }
}

function __asyncValues(o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
}

function __makeTemplateObject(cooked, raw) {
    if (Object.defineProperty) { Object.defineProperty(cooked, "raw", { value: raw }); } else { cooked.raw = raw; }
    return cooked;
};

function __importStar(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result.default = mod;
    return result;
}

function __importDefault(mod) {
    return (mod && mod.__esModule) ? mod : { default: mod };
}

function __classPrivateFieldGet(receiver, privateMap) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
}

function __classPrivateFieldSet(receiver, privateMap, value) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to set private field on non-instance");
    }
    privateMap.set(receiver, value);
    return value;
}


/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js":
/*!********************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/request.js ***!
  \********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "ArcGISAuthError": () => (/* binding */ ArcGISAuthError),
/* harmony export */   "NODEJS_DEFAULT_REFERER_HEADER": () => (/* binding */ NODEJS_DEFAULT_REFERER_HEADER),
/* harmony export */   "checkForErrors": () => (/* binding */ checkForErrors),
/* harmony export */   "request": () => (/* binding */ request),
/* harmony export */   "setDefaultRequestOptions": () => (/* binding */ setDefaultRequestOptions)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-request/node_modules/tslib/tslib.es6.js");
/* harmony import */ var _utils_encode_form_data__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./utils/encode-form-data */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-form-data.js");
/* harmony import */ var _utils_encode_query_string__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./utils/encode-query-string */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-query-string.js");
/* harmony import */ var _utils_process_params__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./utils/process-params */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/process-params.js");
/* harmony import */ var _utils_ArcGISRequestError__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./utils/ArcGISRequestError */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/ArcGISRequestError.js");
/* harmony import */ var _utils_warn__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./utils/warn */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/warn.js");
/* Copyright (c) 2017-2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */






var NODEJS_DEFAULT_REFERER_HEADER = "@esri/arcgis-rest-js";
var DEFAULT_ARCGIS_REQUEST_OPTIONS = {
    httpMethod: "POST",
    params: {
        f: "json",
    },
};
/**
 * Sets the default options that will be passed in **all requests across all `@esri/arcgis-rest-js` modules**.
 *
 *
 * ```js
 * import { setDefaultRequestOptions } from "@esri/arcgis-rest-request";
 * setDefaultRequestOptions({
 *   authentication: userSession // all requests will use this session by default
 * })
 * ```
 * You should **never** set a default `authentication` when you are in a server side environment where you may be handling requests for many different authenticated users.
 *
 * @param options The default options to pass with every request. Existing default will be overwritten.
 * @param hideWarnings Silence warnings about setting default `authentication` in shared environments.
 */
function setDefaultRequestOptions(options, hideWarnings) {
    if (options.authentication && !hideWarnings) {
        (0,_utils_warn__WEBPACK_IMPORTED_MODULE_0__.warn)("You should not set `authentication` as a default in a shared environment such as a web server which will process multiple users requests. You can call `setDefaultRequestOptions` with `true` as a second argument to disable this warning.");
    }
    DEFAULT_ARCGIS_REQUEST_OPTIONS = options;
}
var ArcGISAuthError = /** @class */ (function (_super) {
    (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__extends)(ArcGISAuthError, _super);
    /**
     * Create a new `ArcGISAuthError`  object.
     *
     * @param message - The error message from the API
     * @param code - The error code from the API
     * @param response - The original response from the API that caused the error
     * @param url - The original url of the request
     * @param options - The original options of the request
     */
    function ArcGISAuthError(message, code, response, url, options) {
        if (message === void 0) { message = "AUTHENTICATION_ERROR"; }
        if (code === void 0) { code = "AUTHENTICATION_ERROR_CODE"; }
        var _this = _super.call(this, message, code, response, url, options) || this;
        _this.name = "ArcGISAuthError";
        _this.message =
            code === "AUTHENTICATION_ERROR_CODE" ? message : code + ": " + message;
        return _this;
    }
    ArcGISAuthError.prototype.retry = function (getSession, retryLimit) {
        var _this = this;
        if (retryLimit === void 0) { retryLimit = 3; }
        var tries = 0;
        var retryRequest = function (resolve, reject) {
            getSession(_this.url, _this.options)
                .then(function (session) {
                var newOptions = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({}, _this.options), { authentication: session });
                tries = tries + 1;
                return request(_this.url, newOptions);
            })
                .then(function (response) {
                resolve(response);
            })
                .catch(function (e) {
                if (e.name === "ArcGISAuthError" && tries < retryLimit) {
                    retryRequest(resolve, reject);
                }
                else if (e.name === "ArcGISAuthError" && tries >= retryLimit) {
                    reject(_this);
                }
                else {
                    reject(e);
                }
            });
        };
        return new Promise(function (resolve, reject) {
            retryRequest(resolve, reject);
        });
    };
    return ArcGISAuthError;
}(_utils_ArcGISRequestError__WEBPACK_IMPORTED_MODULE_2__.ArcGISRequestError));

/**
 * Checks for errors in a JSON response from the ArcGIS REST API. If there are no errors, it will return the `data` passed in. If there is an error, it will throw an `ArcGISRequestError` or `ArcGISAuthError`.
 *
 * @param data The response JSON to check for errors.
 * @param url The url of the original request
 * @param params The parameters of the original request
 * @param options The options of the original request
 * @returns The data that was passed in the `data` parameter
 */
function checkForErrors(response, url, params, options, originalAuthError) {
    // this is an error message from billing.arcgis.com backend
    if (response.code >= 400) {
        var message = response.message, code = response.code;
        throw new _utils_ArcGISRequestError__WEBPACK_IMPORTED_MODULE_2__.ArcGISRequestError(message, code, response, url, options);
    }
    // error from ArcGIS Online or an ArcGIS Portal or server instance.
    if (response.error) {
        var _a = response.error, message = _a.message, code = _a.code, messageCode = _a.messageCode;
        var errorCode = messageCode || code || "UNKNOWN_ERROR_CODE";
        if (code === 498 ||
            code === 499 ||
            messageCode === "GWM_0003" ||
            (code === 400 && message === "Unable to generate token.")) {
            if (originalAuthError) {
                throw originalAuthError;
            }
            else {
                throw new ArcGISAuthError(message, errorCode, response, url, options);
            }
        }
        throw new _utils_ArcGISRequestError__WEBPACK_IMPORTED_MODULE_2__.ArcGISRequestError(message, errorCode, response, url, options);
    }
    // error from a status check
    if (response.status === "failed" || response.status === "failure") {
        var message = void 0;
        var code = "UNKNOWN_ERROR_CODE";
        try {
            message = JSON.parse(response.statusMessage).message;
            code = JSON.parse(response.statusMessage).code;
        }
        catch (e) {
            message = response.statusMessage || response.message;
        }
        throw new _utils_ArcGISRequestError__WEBPACK_IMPORTED_MODULE_2__.ArcGISRequestError(message, code, response, url, options);
    }
    return response;
}
/**
 * ```js
 * import { request } from '@esri/arcgis-rest-request';
 * //
 * request('https://www.arcgis.com/sharing/rest')
 *   .then(response) // response.currentVersion === 5.2
 * //
 * request('https://www.arcgis.com/sharing/rest', {
 *   httpMethod: "GET"
 * })
 * //
 * request('https://www.arcgis.com/sharing/rest/search', {
 *   params: { q: 'parks' }
 * })
 *   .then(response) // response.total => 78379
 * ```
 * Generic method for making HTTP requests to ArcGIS REST API endpoints.
 *
 * @param url - The URL of the ArcGIS REST API endpoint.
 * @param requestOptions - Options for the request, including parameters relevant to the endpoint.
 * @returns A Promise that will resolve with the data from the response.
 */
function request(url, requestOptions) {
    if (requestOptions === void 0) { requestOptions = { params: { f: "json" } }; }
    var options = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ httpMethod: "POST" }, DEFAULT_ARCGIS_REQUEST_OPTIONS), requestOptions), {
        params: (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({}, DEFAULT_ARCGIS_REQUEST_OPTIONS.params), requestOptions.params),
        headers: (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({}, DEFAULT_ARCGIS_REQUEST_OPTIONS.headers), requestOptions.headers),
    });
    var missingGlobals = [];
    var recommendedPackages = [];
    // don't check for a global fetch if a custom implementation was passed through
    if (!options.fetch && typeof fetch !== "undefined") {
        options.fetch = fetch.bind(Function("return this")());
    }
    else {
        missingGlobals.push("`fetch`");
        recommendedPackages.push("`node-fetch`");
    }
    if (typeof Promise === "undefined") {
        missingGlobals.push("`Promise`");
        recommendedPackages.push("`es6-promise`");
    }
    if (typeof FormData === "undefined") {
        missingGlobals.push("`FormData`");
        recommendedPackages.push("`isomorphic-form-data`");
    }
    if (!options.fetch ||
        typeof Promise === "undefined" ||
        typeof FormData === "undefined") {
        throw new Error("`arcgis-rest-request` requires a `fetch` implementation and global variables for `Promise` and `FormData` to be present in the global scope. You are missing " + missingGlobals.join(", ") + ". We recommend installing the " + recommendedPackages.join(", ") + " modules at the root of your application to add these to the global scope. See https://bit.ly/2KNwWaJ for more info.");
    }
    var httpMethod = options.httpMethod, authentication = options.authentication, rawResponse = options.rawResponse;
    var params = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ f: "json" }, options.params);
    var originalAuthError = null;
    var fetchOptions = {
        method: httpMethod,
        /* ensures behavior mimics XMLHttpRequest.
        needed to support sending IWA cookies */
        credentials: options.credentials || "same-origin",
    };
    // the /oauth2/platformSelf route will add X-Esri-Auth-Client-Id header
    // and that request needs to send cookies cross domain
    // so we need to set the credentials to "include"
    if (options.headers &&
        options.headers["X-Esri-Auth-Client-Id"] &&
        url.indexOf("/oauth2/platformSelf") > -1) {
        fetchOptions.credentials = "include";
    }
    return (authentication
        ? authentication.getToken(url, { fetch: options.fetch }).catch(function (err) {
            /**
             * append original request url and requestOptions
             * to the error thrown by getToken()
             * to assist with retrying
             */
            err.url = url;
            err.options = options;
            /**
             * if an attempt is made to talk to an unfederated server
             * first try the request anonymously. if a 'token required'
             * error is thrown, throw the UNFEDERATED error then.
             */
            originalAuthError = err;
            return Promise.resolve("");
        })
        : Promise.resolve(""))
        .then(function (token) {
        if (token.length) {
            params.token = token;
        }
        if (authentication && authentication.getDomainCredentials) {
            fetchOptions.credentials = authentication.getDomainCredentials(url);
        }
        // Custom headers to add to request. IRequestOptions.headers with merge over requestHeaders.
        var requestHeaders = {};
        if (fetchOptions.method === "GET") {
            // Prevents token from being passed in query params when hideToken option is used.
            /* istanbul ignore if - window is always defined in a browser. Test case is covered by Jasmine in node test */
            if (params.token &&
                options.hideToken &&
                // Sharing API does not support preflight check required by modern browsers https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request
                typeof window === "undefined") {
                requestHeaders["X-Esri-Authorization"] = "Bearer " + params.token;
                delete params.token;
            }
            // encode the parameters into the query string
            var queryParams = (0,_utils_encode_query_string__WEBPACK_IMPORTED_MODULE_3__.encodeQueryString)(params);
            // dont append a '?' unless parameters are actually present
            var urlWithQueryString = queryParams === "" ? url : url + "?" + (0,_utils_encode_query_string__WEBPACK_IMPORTED_MODULE_3__.encodeQueryString)(params);
            if (
            // This would exceed the maximum length for URLs specified by the consumer and requires POST
            (options.maxUrlLength &&
                urlWithQueryString.length > options.maxUrlLength) ||
                // Or if the customer requires the token to be hidden and it has not already been hidden in the header (for browsers)
                (params.token && options.hideToken)) {
                // the consumer specified a maximum length for URLs
                // and this would exceed it, so use post instead
                fetchOptions.method = "POST";
                // If the token was already added as a Auth header, add the token back to body with other params instead of header
                if (token.length && options.hideToken) {
                    params.token = token;
                    // Remove existing header that was added before url query length was checked
                    delete requestHeaders["X-Esri-Authorization"];
                }
            }
            else {
                // just use GET
                url = urlWithQueryString;
            }
        }
        /* updateResources currently requires FormData even when the input parameters dont warrant it.
    https://developers.arcgis.com/rest/users-groups-and-items/update-resources.htm
        see https://github.com/Esri/arcgis-rest-js/pull/500 for more info. */
        var forceFormData = new RegExp("/items/.+/updateResources").test(url);
        if (fetchOptions.method === "POST") {
            fetchOptions.body = (0,_utils_encode_form_data__WEBPACK_IMPORTED_MODULE_4__.encodeFormData)(params, forceFormData);
        }
        // Mixin headers from request options
        fetchOptions.headers = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({}, requestHeaders), options.headers);
        /* istanbul ignore next - karma reports coverage on browser tests only */
        if (typeof window === "undefined" && !fetchOptions.headers.referer) {
            fetchOptions.headers.referer = NODEJS_DEFAULT_REFERER_HEADER;
        }
        /* istanbul ignore else blob responses are difficult to make cross platform we will just have to trust the isomorphic fetch will do its job */
        if (!(0,_utils_process_params__WEBPACK_IMPORTED_MODULE_5__.requiresFormData)(params) && !forceFormData) {
            fetchOptions.headers["Content-Type"] =
                "application/x-www-form-urlencoded";
        }
        return options.fetch(url, fetchOptions);
    })
        .then(function (response) {
        if (!response.ok) {
            // server responded w/ an actual error (404, 500, etc)
            var status_1 = response.status, statusText = response.statusText;
            throw new _utils_ArcGISRequestError__WEBPACK_IMPORTED_MODULE_2__.ArcGISRequestError(statusText, "HTTP " + status_1, response, url, options);
        }
        if (rawResponse) {
            return response;
        }
        switch (params.f) {
            case "json":
                return response.json();
            case "geojson":
                return response.json();
            case "html":
                return response.text();
            case "text":
                return response.text();
            /* istanbul ignore next blob responses are difficult to make cross platform we will just have to trust that isomorphic fetch will do its job */
            default:
                return response.blob();
        }
    })
        .then(function (data) {
        if ((params.f === "json" || params.f === "geojson") && !rawResponse) {
            var response = checkForErrors(data, url, params, options, originalAuthError);
            if (originalAuthError) {
                /* If the request was made to an unfederated service that
                didn't require authentication, add the base url and a dummy token
                to the list of trusted servers to avoid another federation check
                in the event of a repeat request */
                var truncatedUrl = url
                    .toLowerCase()
                    .split(/\/rest(\/admin)?\/services\//)[0];
                options.authentication.federatedServers[truncatedUrl] = {
                    token: [],
                    // default to 24 hours
                    expires: new Date(Date.now() + 86400 * 1000),
                };
                originalAuthError = null;
            }
            return response;
        }
        else {
            return data;
        }
    });
}
//# sourceMappingURL=request.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/ArcGISRequestError.js":
/*!*************************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/ArcGISRequestError.js ***!
  \*************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "ArcGISRequestError": () => (/* binding */ ArcGISRequestError)
/* harmony export */ });
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */
// TypeScript 2.1 no longer allows you to extend built in types. See https://github.com/Microsoft/TypeScript/issues/12790#issuecomment-265981442
// and https://github.com/Microsoft/TypeScript-wiki/blob/master/Breaking-Changes.md#extending-built-ins-like-error-array-and-map-may-no-longer-work
//
// This code is from MDN https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error#Custom_Error_Types.
var ArcGISRequestError = /** @class */ (function () {
    /**
     * Create a new `ArcGISRequestError`  object.
     *
     * @param message - The error message from the API
     * @param code - The error code from the API
     * @param response - The original response from the API that caused the error
     * @param url - The original url of the request
     * @param options - The original options and parameters of the request
     */
    function ArcGISRequestError(message, code, response, url, options) {
        message = message || "UNKNOWN_ERROR";
        code = code || "UNKNOWN_ERROR_CODE";
        this.name = "ArcGISRequestError";
        this.message =
            code === "UNKNOWN_ERROR_CODE" ? message : code + ": " + message;
        this.originalMessage = message;
        this.code = code;
        this.response = response;
        this.url = url;
        this.options = options;
    }
    return ArcGISRequestError;
}());

ArcGISRequestError.prototype = Object.create(Error.prototype);
ArcGISRequestError.prototype.constructor = ArcGISRequestError;
//# sourceMappingURL=ArcGISRequestError.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/append-custom-params.js":
/*!***************************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/append-custom-params.js ***!
  \***************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "appendCustomParams": () => (/* binding */ appendCustomParams)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-request/node_modules/tslib/tslib.es6.js");
/* Copyright (c) 2017-2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */

/**
 * Helper for methods with lots of first order request options to pass through as request parameters.
 */
function appendCustomParams(customOptions, keys, baseOptions) {
    var requestOptionsKeys = [
        "params",
        "httpMethod",
        "rawResponse",
        "authentication",
        "portal",
        "fetch",
        "maxUrlLength",
        "headers"
    ];
    var options = (0,tslib__WEBPACK_IMPORTED_MODULE_0__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_0__.__assign)({ params: {} }, baseOptions), customOptions);
    // merge all keys in customOptions into options.params
    options.params = keys.reduce(function (value, key) {
        if (customOptions[key] || typeof customOptions[key] === "boolean") {
            value[key] = customOptions[key];
        }
        return value;
    }, options.params);
    // now remove all properties in options that don't exist in IRequestOptions
    return requestOptionsKeys.reduce(function (value, key) {
        if (options[key]) {
            value[key] = options[key];
        }
        return value;
    }, {});
}
//# sourceMappingURL=append-custom-params.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js":
/*!****************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js ***!
  \****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "cleanUrl": () => (/* binding */ cleanUrl)
/* harmony export */ });
/* Copyright (c) 2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */
/**
 * Helper method to ensure that user supplied urls don't include whitespace or a trailing slash.
 */
function cleanUrl(url) {
    // Guard so we don't try to trim something that's not a string
    if (typeof url !== "string") {
        return url;
    }
    // trim leading and trailing spaces, but not spaces inside the url
    url = url.trim();
    // remove the trailing slash to the url if one was included
    if (url[url.length - 1] === "/") {
        url = url.slice(0, -1);
    }
    return url;
}
//# sourceMappingURL=clean-url.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/decode-query-string.js":
/*!**************************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/decode-query-string.js ***!
  \**************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "decodeParam": () => (/* binding */ decodeParam),
/* harmony export */   "decodeQueryString": () => (/* binding */ decodeQueryString)
/* harmony export */ });
/* Copyright (c) 2017-2020 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */
function decodeParam(param) {
    var _a = param.split("="), key = _a[0], value = _a[1];
    return { key: decodeURIComponent(key), value: decodeURIComponent(value) };
}
/**
 * Decodes the passed query string as an object.
 *
 * @param query A string to be decoded.
 * @returns A decoded query param object.
 */
function decodeQueryString(query) {
    return query
        .replace(/^#/, "")
        .split("&")
        .reduce(function (acc, entry) {
        var _a = decodeParam(entry), key = _a.key, value = _a.value;
        acc[key] = value;
        return acc;
    }, {});
}
//# sourceMappingURL=decode-query-string.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-form-data.js":
/*!***********************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-form-data.js ***!
  \***********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "encodeFormData": () => (/* binding */ encodeFormData)
/* harmony export */ });
/* harmony import */ var _process_params__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./process-params */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/process-params.js");
/* harmony import */ var _encode_query_string__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./encode-query-string */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-query-string.js");
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */


/**
 * Encodes parameters in a [FormData](https://developer.mozilla.org/en-US/docs/Web/API/FormData) object in browsers or in a [FormData](https://github.com/form-data/form-data) in Node.js
 *
 * @param params An object to be encoded.
 * @returns The complete [FormData](https://developer.mozilla.org/en-US/docs/Web/API/FormData) object.
 */
function encodeFormData(params, forceFormData) {
    // see https://github.com/Esri/arcgis-rest-js/issues/499 for more info.
    var useFormData = (0,_process_params__WEBPACK_IMPORTED_MODULE_0__.requiresFormData)(params) || forceFormData;
    var newParams = (0,_process_params__WEBPACK_IMPORTED_MODULE_0__.processParams)(params);
    if (useFormData) {
        var formData_1 = new FormData();
        Object.keys(newParams).forEach(function (key) {
            if (typeof Blob !== "undefined" && newParams[key] instanceof Blob) {
                /* To name the Blob:
                 1. look to an alternate request parameter called 'fileName'
                 2. see if 'name' has been tacked onto the Blob manually
                 3. if all else fails, use the request parameter
                */
                var filename = newParams["fileName"] || newParams[key].name || key;
                formData_1.append(key, newParams[key], filename);
            }
            else {
                formData_1.append(key, newParams[key]);
            }
        });
        return formData_1;
    }
    else {
        return (0,_encode_query_string__WEBPACK_IMPORTED_MODULE_1__.encodeQueryString)(params);
    }
}
//# sourceMappingURL=encode-form-data.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-query-string.js":
/*!**************************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-query-string.js ***!
  \**************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "encodeParam": () => (/* binding */ encodeParam),
/* harmony export */   "encodeQueryString": () => (/* binding */ encodeQueryString)
/* harmony export */ });
/* harmony import */ var _process_params__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./process-params */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/process-params.js");
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */

/**
 * Encodes keys and parameters for use in a URL's query string.
 *
 * @param key Parameter's key
 * @param value Parameter's value
 * @returns Query string with key and value pairs separated by "&"
 */
function encodeParam(key, value) {
    // For array of arrays, repeat key=value for each element of containing array
    if (Array.isArray(value) && value[0] && Array.isArray(value[0])) {
        return value.map(function (arrayElem) { return encodeParam(key, arrayElem); }).join("&");
    }
    return encodeURIComponent(key) + "=" + encodeURIComponent(value);
}
/**
 * Encodes the passed object as a query string.
 *
 * @param params An object to be encoded.
 * @returns An encoded query string.
 */
function encodeQueryString(params) {
    var newParams = (0,_process_params__WEBPACK_IMPORTED_MODULE_0__.processParams)(params);
    return Object.keys(newParams)
        .map(function (key) {
        return encodeParam(key, newParams[key]);
    })
        .join("&");
}
//# sourceMappingURL=encode-query-string.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/process-params.js":
/*!*********************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/process-params.js ***!
  \*********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "processParams": () => (/* binding */ processParams),
/* harmony export */   "requiresFormData": () => (/* binding */ requiresFormData)
/* harmony export */ });
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */
/**
 * Checks parameters to see if we should use FormData to send the request
 * @param params The object whose keys will be encoded.
 * @return A boolean indicating if FormData will be required.
 */
function requiresFormData(params) {
    return Object.keys(params).some(function (key) {
        var value = params[key];
        if (!value) {
            return false;
        }
        if (value && value.toParam) {
            value = value.toParam();
        }
        var type = value.constructor.name;
        switch (type) {
            case "Array":
                return false;
            case "Object":
                return false;
            case "Date":
                return false;
            case "Function":
                return false;
            case "Boolean":
                return false;
            case "String":
                return false;
            case "Number":
                return false;
            default:
                return true;
        }
    });
}
/**
 * Converts parameters to the proper representation to send to the ArcGIS REST API.
 * @param params The object whose keys will be encoded.
 * @return A new object with properly encoded values.
 */
function processParams(params) {
    var newParams = {};
    Object.keys(params).forEach(function (key) {
        var _a, _b;
        var param = params[key];
        if (param && param.toParam) {
            param = param.toParam();
        }
        if (!param &&
            param !== 0 &&
            typeof param !== "boolean" &&
            typeof param !== "string") {
            return;
        }
        var type = param.constructor.name;
        var value;
        // properly encodes objects, arrays and dates for arcgis.com and other services.
        // ported from https://github.com/Esri/esri-leaflet/blob/master/src/Request.js#L22-L30
        // also see https://github.com/Esri/arcgis-rest-js/issues/18:
        // null, undefined, function are excluded. If you want to send an empty key you need to send an empty string "".
        switch (type) {
            case "Array":
                // Based on the first element of the array, classify array as an array of arrays, an array of objects
                // to be stringified, or an array of non-objects to be comma-separated
                // eslint-disable-next-line no-case-declarations
                var firstElementType = (_b = (_a = param[0]) === null || _a === void 0 ? void 0 : _a.constructor) === null || _b === void 0 ? void 0 : _b.name;
                value =
                    firstElementType === "Array" ? param : // pass thru array of arrays
                        firstElementType === "Object" ? JSON.stringify(param) : // stringify array of objects
                            param.join(","); // join other types of array elements
                break;
            case "Object":
                value = JSON.stringify(param);
                break;
            case "Date":
                value = param.valueOf();
                break;
            case "Function":
                value = null;
                break;
            case "Boolean":
                value = param + "";
                break;
            default:
                value = param;
                break;
        }
        if (value || value === 0 || typeof value === "string" || Array.isArray(value)) {
            newParams[key] = value;
        }
    });
    return newParams;
}
//# sourceMappingURL=process-params.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/warn.js":
/*!***********************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/warn.js ***!
  \***********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "warn": () => (/* binding */ warn)
/* harmony export */ });
/* Copyright (c) 2017-2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */
/**
 * Method used internally to surface messages to developers.
 */
function warn(message) {
    if (console && console.warn) {
        console.warn.apply(console, [message]);
    }
}
//# sourceMappingURL=warn.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/node_modules/tslib/tslib.es6.js":
/*!********************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/node_modules/tslib/tslib.es6.js ***!
  \********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "__assign": () => (/* binding */ __assign),
/* harmony export */   "__asyncDelegator": () => (/* binding */ __asyncDelegator),
/* harmony export */   "__asyncGenerator": () => (/* binding */ __asyncGenerator),
/* harmony export */   "__asyncValues": () => (/* binding */ __asyncValues),
/* harmony export */   "__await": () => (/* binding */ __await),
/* harmony export */   "__awaiter": () => (/* binding */ __awaiter),
/* harmony export */   "__classPrivateFieldGet": () => (/* binding */ __classPrivateFieldGet),
/* harmony export */   "__classPrivateFieldSet": () => (/* binding */ __classPrivateFieldSet),
/* harmony export */   "__createBinding": () => (/* binding */ __createBinding),
/* harmony export */   "__decorate": () => (/* binding */ __decorate),
/* harmony export */   "__exportStar": () => (/* binding */ __exportStar),
/* harmony export */   "__extends": () => (/* binding */ __extends),
/* harmony export */   "__generator": () => (/* binding */ __generator),
/* harmony export */   "__importDefault": () => (/* binding */ __importDefault),
/* harmony export */   "__importStar": () => (/* binding */ __importStar),
/* harmony export */   "__makeTemplateObject": () => (/* binding */ __makeTemplateObject),
/* harmony export */   "__metadata": () => (/* binding */ __metadata),
/* harmony export */   "__param": () => (/* binding */ __param),
/* harmony export */   "__read": () => (/* binding */ __read),
/* harmony export */   "__rest": () => (/* binding */ __rest),
/* harmony export */   "__spread": () => (/* binding */ __spread),
/* harmony export */   "__spreadArrays": () => (/* binding */ __spreadArrays),
/* harmony export */   "__values": () => (/* binding */ __values)
/* harmony export */ });
/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return extendStatics(d, b);
};

function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

var __assign = function() {
    __assign = Object.assign || function __assign(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    }
    return __assign.apply(this, arguments);
}

function __rest(s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
}

function __decorate(decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
}

function __param(paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
}

function __metadata(metadataKey, metadataValue) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(metadataKey, metadataValue);
}

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __generator(thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
}

function __createBinding(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}

function __exportStar(m, exports) {
    for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) exports[p] = m[p];
}

function __values(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
}

function __read(o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
}

function __spread() {
    for (var ar = [], i = 0; i < arguments.length; i++)
        ar = ar.concat(__read(arguments[i]));
    return ar;
}

function __spreadArrays() {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
};

function __await(v) {
    return this instanceof __await ? (this.v = v, this) : new __await(v);
}

function __asyncGenerator(thisArg, _arguments, generator) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var g = generator.apply(thisArg, _arguments || []), i, q = [];
    return i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i;
    function verb(n) { if (g[n]) i[n] = function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]) > 1 || resume(n, v); }); }; }
    function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(q[0][3], e); } }
    function step(r) { r.value instanceof __await ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r); }
    function fulfill(value) { resume("next", value); }
    function reject(value) { resume("throw", value); }
    function settle(f, v) { if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]); }
}

function __asyncDelegator(o) {
    var i, p;
    return i = {}, verb("next"), verb("throw", function (e) { throw e; }), verb("return"), i[Symbol.iterator] = function () { return this; }, i;
    function verb(n, f) { i[n] = o[n] ? function (v) { return (p = !p) ? { value: __await(o[n](v)), done: n === "return" } : f ? f(v) : v; } : f; }
}

function __asyncValues(o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
}

function __makeTemplateObject(cooked, raw) {
    if (Object.defineProperty) { Object.defineProperty(cooked, "raw", { value: raw }); } else { cooked.raw = raw; }
    return cooked;
};

function __importStar(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result.default = mod;
    return result;
}

function __importDefault(mod) {
    return (mod && mod.__esModule) ? mod : { default: mod };
}

function __classPrivateFieldGet(receiver, privateMap) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
}

function __classPrivateFieldSet(receiver, privateMap, value) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to set private field on non-instance");
    }
    privateMap.set(receiver, value);
    return value;
}


/***/ }),

/***/ "./your-extensions/widgets/clss-application/src/extensions/api.ts":
/*!************************************************************************!*\
  !*** ./your-extensions/widgets/clss-application/src/extensions/api.ts ***!
  \************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "archiveTemplate": () => (/* binding */ archiveTemplate),
/* harmony export */   "checkParam": () => (/* binding */ checkParam),
/* harmony export */   "completeAssessment": () => (/* binding */ completeAssessment),
/* harmony export */   "createIncident": () => (/* binding */ createIncident),
/* harmony export */   "createNewIndicator": () => (/* binding */ createNewIndicator),
/* harmony export */   "createNewTemplate": () => (/* binding */ createNewTemplate),
/* harmony export */   "deleteHazard": () => (/* binding */ deleteHazard),
/* harmony export */   "deleteIncident": () => (/* binding */ deleteIncident),
/* harmony export */   "deleteIndicator": () => (/* binding */ deleteIndicator),
/* harmony export */   "deleteOrganization": () => (/* binding */ deleteOrganization),
/* harmony export */   "dispatchAction": () => (/* binding */ dispatchAction),
/* harmony export */   "getAssessmentNames": () => (/* binding */ getAssessmentNames),
/* harmony export */   "getHazards": () => (/* binding */ getHazards),
/* harmony export */   "getIncidents": () => (/* binding */ getIncidents),
/* harmony export */   "getOrganizations": () => (/* binding */ getOrganizations),
/* harmony export */   "getTemplates": () => (/* binding */ getTemplates),
/* harmony export */   "initializeAuth": () => (/* binding */ initializeAuth),
/* harmony export */   "loadAllAssessments": () => (/* binding */ loadAllAssessments),
/* harmony export */   "loadScaleFactors": () => (/* binding */ loadScaleFactors),
/* harmony export */   "passDataIntegrity": () => (/* binding */ passDataIntegrity),
/* harmony export */   "saveHazard": () => (/* binding */ saveHazard),
/* harmony export */   "saveNewAssessment": () => (/* binding */ saveNewAssessment),
/* harmony export */   "saveOrganization": () => (/* binding */ saveOrganization),
/* harmony export */   "selectTemplate": () => (/* binding */ selectTemplate),
/* harmony export */   "templCleanUp": () => (/* binding */ templCleanUp),
/* harmony export */   "updateIndicator": () => (/* binding */ updateIndicator),
/* harmony export */   "updateIndicatorName": () => (/* binding */ updateIndicatorName),
/* harmony export */   "updateLifelineStatus": () => (/* binding */ updateLifelineStatus),
/* harmony export */   "updateTemplateOrganizationAndHazard": () => (/* binding */ updateTemplateOrganizationAndHazard),
/* harmony export */   "useFetchData": () => (/* binding */ useFetchData)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./constants */ "./your-extensions/widgets/clss-application/src/extensions/constants.ts");
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _esri_api__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./esri-api */ "./your-extensions/widgets/clss-application/src/extensions/esri-api.ts");
/* harmony import */ var _logger__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./logger */ "./your-extensions/widgets/clss-application/src/extensions/logger.ts");
/* harmony import */ var _auth__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./auth */ "./your-extensions/widgets/clss-application/src/extensions/auth.ts");
/* harmony import */ var _clss_store__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _utils__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./utils */ "./your-extensions/widgets/clss-application/src/extensions/utils.ts");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};








//========================PUBLIC=============================================================
const initializeAuth = (appId) => __awaiter(void 0, void 0, void 0, function* () {
    console.log('initializeAuth called');
    let cred = yield (0,_auth__WEBPACK_IMPORTED_MODULE_5__.checkCurrentStatus)(appId, _constants__WEBPACK_IMPORTED_MODULE_1__.PORTAL_URL);
    if (!cred) {
        cred = yield (0,_auth__WEBPACK_IMPORTED_MODULE_5__.signIn)(appId, _constants__WEBPACK_IMPORTED_MODULE_1__.PORTAL_URL);
    }
    const credential = {
        expires: cred.expires,
        server: cred.server,
        ssl: cred.ssl,
        token: cred.token,
        userId: cred.userId
    };
    dispatchAction(_clss_store__WEBPACK_IMPORTED_MODULE_6__.CLSSActionKeys.AUTHENTICATE_ACTION, credential);
});
function updateLifelineStatus(lifelineStatus, config, assessmentObjectId, user) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('called updateLifelineStatus');
        checkParam(config.lifelineStatus, 'Lifeline Status URL not provided');
        const attributes = {
            OBJECTID: lifelineStatus.objectId,
            Score: lifelineStatus.score,
            Color: lifelineStatus.color,
            IsOverriden: lifelineStatus.isOverriden,
            OverridenScore: lifelineStatus.overrideScore,
            OverridenColor: lifelineStatus.overridenColor,
            OverridenBy: lifelineStatus.overridenBy,
            OverrideComment: lifelineStatus.overrideComment
        };
        let response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeature)(config.lifelineStatus, attributes, config);
        if (response.updateResults && response.updateResults.every(u => u.success)) {
            const iaFeatures = lifelineStatus.indicatorAssessments.map(i => {
                return {
                    attributes: {
                        OBJECTID: i.objectId,
                        status: i.status,
                        Comments: i.comments && i.comments.length > 0 ? JSON.stringify(i.comments) : ''
                    }
                };
            });
            response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeatures)(config.indicatorAssessments, iaFeatures, config);
            if (response.updateResults && response.updateResults.every(u => u.success)) {
                const assessFeature = {
                    OBJECTID: assessmentObjectId,
                    EditedDate: new Date().getTime(),
                    Editor: user
                };
                response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeature)(config.assessments, assessFeature, config);
                if (response.updateResults && response.updateResults.every(u => u.success)) {
                    return {
                        data: true
                    };
                }
            }
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)('Updating Lifeline score failed', _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'updateLifelineStatus');
        return {
            errors: 'Updating Lifeline score failed'
        };
    });
}
function completeAssessment(assessment, config, userName) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.assessments, 'No Assessment Url provided');
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeature)(config.assessments, {
            OBJECTID: assessment.objectId,
            Editor: userName,
            EditedDate: new Date().getTime(),
            IsCompleted: 1
        }, config);
        console.log(response);
        return {
            data: response.updateResults && response.updateResults.every(u => u.success)
        };
    });
}
const passDataIntegrity = (serviceUrl, fields, config) => __awaiter(void 0, void 0, void 0, function* () {
    checkParam(serviceUrl, 'Service URL not provided');
    // serviceUrl = `${serviceUrl}?f=json&token=${token}`;
    // const response = await fetch(serviceUrl, {
    //   method: "GET",
    //   headers: {
    //     'content-type': 'application/x-www-form-urlencoded'
    //   }
    // }
    // );
    // const json = await response.json();
    // const features = await queryTableFeatures(serviceUrl, '1=1', config);
    // const dataFields = features[0]. as IField[];
    // debugger;
    // if (fields.length > dataFields.length) {
    //   throw new Error('Number of fields do not match for ' + serviceUrl);
    // }
    // const allFieldsGood = fields.every(f => {
    //   const found = dataFields.find(f1 => f1.name === f.name && f1.type.toString() === f.type.toString() && f1.domain == f.domain);
    //   return found;
    // });
    // if (!allFieldsGood) {
    //   throw new Error('Invalid fields in the feature service ' + serviceUrl)
    // }
    return true;
});
function getIndicatorFeatures(query, config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Indicators called');
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.indicators, query, config);
    });
}
function getWeightsFeatures(query, config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Weights called');
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.weights, query, config);
    });
}
function getLifelineFeatures(query, config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Lifeline called');
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.lifelines, query, config);
    });
}
function getComponentFeatures(query, config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Components called');
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.components, query, config);
    });
}
function getTemplateFeatureSet(query, config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Template called');
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatureSet)(config.templates, query, config);
    });
}
function getTemplates(config, templateId, queryString) {
    return __awaiter(this, void 0, void 0, function* () {
        const templateUrl = config.templates;
        const lifelineUrl = config.lifelines;
        const componentUrl = config.components;
        try {
            checkParam(templateUrl, _constants__WEBPACK_IMPORTED_MODULE_1__.TEMPLATE_URL_ERROR);
            checkParam(lifelineUrl, _constants__WEBPACK_IMPORTED_MODULE_1__.LIFELINE_URL_ERROR);
            checkParam(componentUrl, _constants__WEBPACK_IMPORTED_MODULE_1__.COMPONENT_URL_ERROR);
            const tempQuery = templateId ? `GlobalID='${templateId}` : (queryString ? queryString : '1=1');
            const response = yield Promise.all([
                getTemplateFeatureSet(tempQuery, config),
                getLifelineFeatures('1=1', config),
                getComponentFeatures('1=1', config)
            ]);
            const templateFeatureSet = response[0];
            const lifelineFeatures = response[1];
            const componentFeatures = response[2];
            const indicatorFeatures = yield getIndicatorFeatures('1=1', config);
            const weightFeatures = yield getWeightsFeatures('1=1', config);
            const templates = yield Promise.all(templateFeatureSet.features.map((templateFeature) => __awaiter(this, void 0, void 0, function* () {
                const templateIndicatorFeatures = indicatorFeatures.filter(i => i.attributes.TemplateID == templateFeature.attributes.GlobalID);
                return yield getTemplate(templateFeature, lifelineFeatures, componentFeatures, templateIndicatorFeatures, weightFeatures, templateFeatureSet.fields.find(f => f.name === 'Status').domain.codedValues);
            })));
            if (templates.filter(t => t.isSelected).length > 1 || templates.filter(t => t.isSelected).length == 0) {
                return {
                    data: templates.map(t => {
                        return Object.assign(Object.assign({}, t), { isSelected: t.name === _constants__WEBPACK_IMPORTED_MODULE_1__.BASELINE_TEMPLATE_NAME });
                    })
                };
            }
            if (templates.length === 1) {
                return {
                    data: templates.map(t => {
                        return Object.assign(Object.assign({}, t), { isSelected: true });
                    })
                };
            }
            return {
                data: templates
            };
        }
        catch (e) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'getTemplates');
            return {
                errors: 'Templates request failed.'
            };
        }
    });
}
function useFetchData(url, callbackAdapter) {
    const [data, setData] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(null);
    const [loading, setLoading] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(true);
    const [error, setError] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState('');
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        const controller = new AbortController();
        requestData(url, controller)
            .then((data) => {
            if (callbackAdapter) {
                setData(callbackAdapter(data));
            }
            else {
                setData(data);
            }
            setLoading(false);
        })
            .catch((err) => {
            console.log(err);
            setError(err);
        });
        return () => controller.abort();
    }, [url]);
    return [data, setData, loading, error];
}
function dispatchAction(type, val) {
    (0,jimu_core__WEBPACK_IMPORTED_MODULE_2__.getAppStore)().dispatch({
        type,
        val
    });
}
function getIncidents(config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get incidents called.');
        checkParam(config.incidents, _constants__WEBPACK_IMPORTED_MODULE_1__.INCIDENT_URL_ERROR);
        const features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.incidents, '1=1', config);
        const query = `GlobalID IN (${features.map(f => f.attributes.HazardID).map(id => `'${id}'`).join(',')})`;
        const hazardFeatureset = yield getHazardFeatures(config, query, 'getIncidents');
        return features.map((f) => {
            const hf = hazardFeatureset.features.find(h => h.attributes.GlobalID == f.attributes.HazardID);
            return {
                objectId: f.attributes.OBJECTID,
                id: f.attributes.GlobalID,
                name: f.attributes.Name,
                hazard: hf ? {
                    objectId: hf.attributes.OBJECTID,
                    id: hf.attributes.GlobalID,
                    name: hf.attributes.Name,
                    title: hf.attributes.DisplayTitle || hf.attributes.DisplayName || hf.attributes.Name,
                    type: hf.attributes.Type,
                    description: hf.attributes.Description,
                    domains: hazardFeatureset.fields.find(f => f.name === 'Type').domain.codedValues
                } : null,
                description: f.attributes.Description,
                startDate: Number(f.attributes.StartDate),
                endDate: Number(f.attributes.EndDate)
            };
        });
        return [];
    });
}
function getHazardFeatures(config, query, caller) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Hazards called by ' + caller);
        checkParam(config.hazards, _constants__WEBPACK_IMPORTED_MODULE_1__.HAZARD_URL_ERROR);
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatureSet)(config.hazards, query, config);
    });
}
function getHazards(config, queryString, caller) {
    return __awaiter(this, void 0, void 0, function* () {
        const featureSet = yield getHazardFeatures(config, queryString, caller);
        if (!featureSet || featureSet.features.length == 0) {
            return [];
        }
        return featureSet.features.map((f) => {
            return {
                objectId: f.attributes.OBJECTID,
                id: f.attributes.GlobalID,
                name: f.attributes.Name,
                title: f.attributes.DisplayTitle || f.attributes.DisplayName || f.attributes.Name,
                type: f.attributes.Type,
                description: f.attributes.Description,
                domains: featureSet.fields.find(f => f.name === 'Type').domain.codedValues
            };
        });
        return [];
    });
}
function getOrganizations(config, queryString) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Organizations called');
        checkParam(config.organizations, _constants__WEBPACK_IMPORTED_MODULE_1__.ORGANIZATION_URL_ERROR);
        const featureSet = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatureSet)(config.organizations, queryString, config);
        if (featureSet && featureSet.features && featureSet.features.length > 0) {
            return featureSet.features.map((f) => {
                return {
                    objectId: f.attributes.OBJECTID,
                    id: f.attributes.GlobalID,
                    name: f.attributes.Name,
                    title: f.attributes.Name,
                    type: f.attributes.Type,
                    parentId: f.attributes.ParentID,
                    description: f.attributes.Description,
                    domains: featureSet.fields.find(f => f.name === 'Type').domain.codedValues
                };
            });
        }
        return [];
    });
}
function createNewTemplate(config, template, userName, organization, hazard) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.templates, _constants__WEBPACK_IMPORTED_MODULE_1__.TEMPLATE_URL_ERROR);
        checkParam(template, 'Template data not provided');
        const createDate = new Date().getTime();
        const templateName = template.name[0].toLocaleUpperCase() + template.name.substring(1);
        let feature = {
            attributes: {
                OrganizationID: organization ? organization.id : null,
                OrganizationName: organization ? organization.name : null,
                OrganizationType: organization ? (organization.type.code ? organization.type.code : organization.type) : null,
                HazardID: hazard ? hazard.id : null,
                HazardName: hazard ? hazard.name : null,
                HazardType: hazard ? (hazard.type.code ? hazard.type.code : hazard.type) : null,
                Name: templateName,
                Creator: userName,
                CreatedDate: createDate,
                Status: 1,
                IsSelected: 0,
                Editor: userName,
                EditedDate: createDate
            }
        };
        let response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.templates, [feature], config);
        if (response.addResults && response.addResults.every(r => r.success)) {
            const templateId = response.addResults[0].globalId;
            //create new indicators   
            const indicators = getTemplateIndicators(template);
            const indicatorFeatures = indicators.map(indicator => {
                return {
                    attributes: {
                        TemplateID: templateId,
                        ComponentID: indicator.componentId,
                        ComponentName: indicator.componentName,
                        Name: indicator.name,
                        TemplateName: templateName,
                        LifelineName: indicator.lifelineName
                    }
                };
            });
            response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.indicators, indicatorFeatures, config);
            if (response.addResults && response.addResults.every(r => r.success)) {
                const globalIds = `(${response.addResults.map(r => `'${r.globalId}'`).join(',')})`;
                const query = 'GlobalID IN ' + globalIds;
                const addedIndicatorFeatures = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.indicators, query, config);
                let weightsFeatures = [];
                for (let feature of addedIndicatorFeatures) {
                    const incomingIndicator = indicators.find(i => i.name === feature.attributes.Name);
                    if (incomingIndicator) {
                        const weightFeatures = incomingIndicator.weights.map(w => {
                            return {
                                attributes: {
                                    IndicatorID: feature.attributes.GlobalID,
                                    Name: w.name,
                                    Weight: w.weight,
                                    ScaleFactor: 0,
                                    AdjustedWeight: 0,
                                    MaxAdjustedWeight: 0
                                }
                            };
                        });
                        weightsFeatures = weightsFeatures.concat(weightFeatures);
                    }
                }
                response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.weights, weightsFeatures, config);
                if (response.addResults && response.addResults.every(r => r.success)) {
                    return {
                        data: true
                    };
                }
            }
            // const promises = indicators.map(indicator => createNewIndicator(indicator, config, templateId, templateName));
            // const promiseResponse = await Promise.all(promises);
            // if(promiseResponse.every(p => p.data)){
            //   return {
            //     data: true
            //   }
            // }
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(JSON.stringify(response), _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'createNewTemplate');
        return {
            errors: 'Error occurred while creating the new template'
        };
    });
}
function updateTemplateOrganizationAndHazard(config, template, userName) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(template, 'Template not provided');
        checkParam(config.templates, _constants__WEBPACK_IMPORTED_MODULE_1__.TEMPLATE_URL_ERROR);
        const attributes = {
            OBJECTID: template.objectId,
            OrganizationID: template.organizationId,
            HazardID: template.hazardId,
            OrganizationName: template.organizationName,
            OrganizationType: template.organizationType,
            HazardName: template.hazardName,
            HazardType: template.hazardType,
            Name: template.name,
            Editor: userName,
            EditedDate: new Date().getTime(),
            Status: template.status.code,
            IsSelected: template.isSelected ? 1 : 0
        };
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeature)(config.templates, attributes, config);
        if (response.updateResults && response.updateResults.every(u => u.success)) {
            return {
                data: true
            };
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(JSON.stringify(response), _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'updateTemplateOrganizationAndHazard');
        return {
            errors: 'Error occurred while updating template.'
        };
    });
}
function selectTemplate(objectId, objectIds, config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('select Template called');
        try {
            checkParam(config.templates, _constants__WEBPACK_IMPORTED_MODULE_1__.TEMPLATE_URL_ERROR);
            //let features = await getTemplateFeatures('1=1', config)// await queryTableFeatures(config.templates, '1=1', config)
            const features = objectIds.map(oid => {
                return {
                    attributes: {
                        OBJECTID: oid,
                        IsSelected: oid === objectId ? 1 : 0
                    }
                };
            });
            const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeatures)(config.templates, features, config);
            if (response.updateResults && response.updateResults.every(u => u.success)) {
                return {
                    data: response.updateResults[0].globalId
                };
            }
        }
        catch (e) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'selectTemplate');
            return {
                errors: e
            };
        }
    });
}
function loadScaleFactors(config) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.constants, 'Rating Scales url not provided');
        try {
            const features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.constants, '1=1', config);
            if (features && features.length > 0) {
                const scales = features.map(f => {
                    return {
                        name: f.attributes.Name,
                        value: f.attributes.Value
                    };
                });
                return {
                    data: scales
                };
            }
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)('Error occurred while requesting rating scales', _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'loadRatingScales');
            return {
                errors: 'Error occurred while requesting rating scales'
            };
        }
        catch (e) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'loadRatingScales');
        }
    });
}
function createNewIndicator(indicator, config, templateId, templateName) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.indicators, _constants__WEBPACK_IMPORTED_MODULE_1__.INDICATOR_URL_ERROR);
        const indicatorFeature = {
            attributes: {
                TemplateID: templateId,
                ComponentID: indicator.componentId,
                ComponentName: indicator.componentName,
                Name: indicator.name,
                TemplateName: templateName,
                LifelineName: indicator.lifelineName
            }
        };
        let response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.indicators, [indicatorFeature], config);
        if (response.addResults && response.addResults.every(r => r.success)) {
            const weightFeatures = indicator.weights.map(w => {
                return {
                    attributes: {
                        IndicatorID: response.addResults[0].globalId,
                        Name: w.name,
                        Weight: w.weight,
                        ScaleFactor: 0,
                        AdjustedWeight: 0,
                        MaxAdjustedWeight: 0
                    }
                };
            });
            response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.weights, weightFeatures, config);
            if (response.addResults && response.addResults.every(r => r.success)) {
                return {
                    data: true
                };
            }
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(JSON.stringify(response), _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'createNewIndicator');
        return {
            errors: 'Error occurred while saving the indicator.'
        };
    });
}
function updateIndicatorName(config, indicatorTemp) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.indicators, _constants__WEBPACK_IMPORTED_MODULE_1__.INDICATOR_URL_ERROR);
        const attributes = {
            OBJECTID: indicatorTemp.objectId,
            Name: indicatorTemp.name,
            DisplayTitle: indicatorTemp.name,
            IsActive: 1
        };
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeature)(config.indicators, attributes, config);
        if (response.updateResults && response.updateResults.every(u => u.success)) {
            return {
                data: true
            };
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(JSON.stringify(response), _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'updateIndicatorName');
        return {
            errors: 'Error occurred while updating indicator'
        };
    });
}
function updateIndicator(indicator, config) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.indicators, _constants__WEBPACK_IMPORTED_MODULE_1__.INCIDENT_URL_ERROR);
        let features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.indicators, `Name='${indicator.name}' AND TemplateName='${indicator.templateName}'`, config);
        if (features && features.length > 1) {
            return {
                errors: 'An indicator with the same name already exists'
            };
        }
        const response = yield updateIndicatorName(config, indicator);
        if (response.errors) {
            return {
                errors: response.errors
            };
        }
        features = indicator.weights.map(w => {
            return {
                attributes: {
                    OBJECTID: w.objectId,
                    Weight: Number(w.weight),
                    AdjustedWeight: Number(w.weight) * w.scaleFactor
                }
            };
        });
        const updateResponse = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeatures)(config.weights, features, config);
        if (updateResponse.updateResults && updateResponse.updateResults.every(u => u.success)) {
            return {
                data: true
            };
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(JSON.stringify(updateResponse), _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'updateIndicator');
        return {
            errors: 'Error occurred while updating indicator.'
        };
    });
}
function deleteIndicator(indicatorTemplate, config) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.indicators, _constants__WEBPACK_IMPORTED_MODULE_1__.INDICATOR_URL_ERROR);
        checkParam(config.weights, 'Weights URL not provided');
        let resp = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.indicators, [indicatorTemplate.objectId], config);
        if (resp.deleteResults && resp.deleteResults.every(d => d.success)) {
            const weightsObjectIds = indicatorTemplate.weights.map(w => w.objectId);
            resp = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.weights, weightsObjectIds, config);
            if (resp.deleteResults && resp.deleteResults.every(d => d.success)) {
                return {
                    data: true
                };
            }
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(JSON.stringify(resp), _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'deleteIndicator');
        return {
            errors: 'Error occurred while deleting the indicator'
        };
    });
}
function archiveTemplate(objectId, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeature)(config.templates, {
            OBJECTID: objectId,
            IsSelected: 0,
            IsActive: 0
        }, config);
        console.log(response);
        if (response.updateResults && response.updateResults.every(e => e.success)) {
            return {
                data: true
            };
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(JSON.stringify(response), _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'archiveTemplate');
        return {
            errors: 'The template cannot be archived.'
        };
    });
}
function saveOrganization(config, organization) {
    var _a;
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.organizations, _constants__WEBPACK_IMPORTED_MODULE_1__.ORGANIZATION_URL_ERROR);
        checkParam(organization, 'Organization object not provided');
        const feature = {
            attributes: {
                Name: organization.name,
                Type: (_a = organization.type) === null || _a === void 0 ? void 0 : _a.code,
                DisplayTitle: organization.name,
                ParentID: organization === null || organization === void 0 ? void 0 : organization.parentId
            }
        };
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.organizations, [feature], config);
        if (response.addResults && response.addResults.every(r => r.success)) {
            return {
                data: Object.assign({}, organization) // (await getOrganizations(config, `GlobalID='${response.addResults[0].globalId}'`))[0]
            };
        }
        return {
            errors: JSON.stringify(response)
        };
    });
}
function saveHazard(config, hazard) {
    return __awaiter(this, void 0, void 0, function* () {
        const feature = {
            attributes: {
                Name: hazard.name,
                DisplayTitle: hazard.name,
                Type: hazard.type.code,
                Description: hazard.description
            }
        };
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.hazards, [feature], config);
        if (response.addResults && response.addResults.every(r => r.success)) {
            return {
                data: Object.assign(Object.assign({}, hazard), { objectId: response.addResults[0].objectId, id: response.addResults[0].globalId })
            };
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(`Error occurred while saving hazard. Restarting the application may fix this issue.`, _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'saveHazard');
        return {
            errors: 'Error occurred while saving hazard. Restarting the application may fix this issue.'
        };
    });
}
function deleteIncident(incident, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.incidents, [incident.objectId], config);
        if (response.deleteResults && response.deleteResults.every(d => d.success)) {
            return {
                data: true
            };
        }
        return {
            errors: JSON.stringify(response)
        };
    });
}
function deleteHazard(hazard, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.hazards, [hazard.objectId], config);
        if (response.deleteResults && response.deleteResults.every(d => d.success)) {
            return {
                data: true
            };
        }
        return {
            errors: JSON.stringify(response)
        };
    });
}
function deleteOrganization(organization, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.organizations, [organization.objectId], config);
        if (response.deleteResults && response.deleteResults.every(d => d.success)) {
            return {
                data: true
            };
        }
        return {
            errors: JSON.stringify(response)
        };
    });
}
function checkParam(param, error) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!param || param == null || param === '' || param == undefined) {
            throw new Error(error);
        }
    });
}
function templCleanUp(indUrl, aligUrl, token) {
    return __awaiter(this, void 0, void 0, function* () {
    });
}
function saveNewAssessment(newAssessment, template, config, prevAssessment) {
    return __awaiter(this, void 0, void 0, function* () {
        const resp = yield saveAssessment(newAssessment, config);
        if (resp.errors) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)('Unable to create the assessment.', _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'saveNewAssessment');
            return {
                errors: 'Unable to create the assessment.'
            };
        }
        try {
            const indicators = getTemplateIndicators(template);
            if (!indicators || indicators.length === 0) {
                (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)('Template indicators not found', _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'saveNewAssessment');
                throw new Error('Template indicators not found.');
            }
            const lifelineStatusFeatures = template.lifelineTemplates.map(lt => {
                return {
                    attributes: {
                        AssessmentID: resp.data,
                        Score: null,
                        Color: null,
                        LifelineID: lt.id,
                        IsOverriden: 0,
                        OverridenScore: null,
                        OverridenBy: null,
                        OverrideComment: null,
                        LifelineName: lt.title,
                        TemplateName: template.name
                    }
                };
            });
            let response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.lifelineStatus, lifelineStatusFeatures, config);
            if (response && response.addResults && response.addResults.every(r => r.success)) {
                const query = 'GlobalID IN (' + response.addResults.map(r => `'${r.globalId}'`).join(',') + ")";
                const lsFeatures = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.lifelineStatus, query, config);
                const indicatorAssessmentFeatures = indicators.map(i => {
                    var _a, _b, _c, _d, _e;
                    const lifelineStatusFeature = lsFeatures.find(ls => ls.attributes.LifelineName.split(/[' '&_,]+/).join('_') === i.lifelineName);
                    if (!lifelineStatusFeature) {
                        console.log(`${i.lifelineName} not found`);
                        throw new Error(`${i.lifelineName} not found`);
                    }
                    return {
                        attributes: {
                            LifelineStatusID: lifelineStatusFeature ? lifelineStatusFeature.attributes.GlobalID : '',
                            IndicatorID: i.id,
                            TemplateName: i.templateName,
                            LifelineName: i.lifelineName,
                            ComponentName: i.componentName,
                            IndicatorName: i.name,
                            Comments: "",
                            Rank: (_a = i.weights.find(w => w.name === _constants__WEBPACK_IMPORTED_MODULE_1__.RANK)) === null || _a === void 0 ? void 0 : _a.weight,
                            LifeSafety: (_b = i.weights.find(w => w.name === _constants__WEBPACK_IMPORTED_MODULE_1__.LIFE_SAFETY)) === null || _b === void 0 ? void 0 : _b.weight,
                            PropertyProtection: (_c = i.weights.find(w => w.name === _constants__WEBPACK_IMPORTED_MODULE_1__.PROPERTY_PROTECTION)) === null || _c === void 0 ? void 0 : _c.weight,
                            IncidentStabilization: (_d = i.weights.find(w => w.name === _constants__WEBPACK_IMPORTED_MODULE_1__.INCIDENT_STABILIZATION)) === null || _d === void 0 ? void 0 : _d.weight,
                            EnvironmentPreservation: (_e = i.weights.find(w => w.name === _constants__WEBPACK_IMPORTED_MODULE_1__.ENVIRONMENT_PRESERVATION)) === null || _e === void 0 ? void 0 : _e.weight,
                            Status: 4 //unknown
                        }
                    };
                });
                response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.indicatorAssessments, indicatorAssessmentFeatures, config);
                if (response && response.addResults && response.addResults.every(r => r.success)) {
                    return {
                        data: resp.data
                    };
                }
                else {
                    throw new Error('Failed to add indicator assessment features');
                }
            }
            else {
                throw new Error('Failed to add Lifeline Status Features');
            }
        }
        catch (e) {
            yield cleanUpAssessmentFailedData(resp.data, config);
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'saveNewAssessment');
            return {
                errors: 'Error occurred while creating Assessment.'
            };
        }
    });
}
function cleanUpAssessmentFailedData(assessmentGlobalId, config) {
    return __awaiter(this, void 0, void 0, function* () {
        let features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.assessments, `GlobalID='${assessmentGlobalId}'`, config);
        if (features && features.length > 0) {
            yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.assessments, features.map(f => f.attributes.OBJECTID), config);
        }
        features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.lifelineStatus, `AssessmentID='${assessmentGlobalId}'`, config);
        if (features && features.length > 0) {
            yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.lifelineStatus, features.map(f => f.attributes.OBJECTID), config);
            const query = `LifelineStatusID IN (${features.map(f => f.attributes.GlobalID).join(',')})`;
            console.log('delete queries', query);
            features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.indicatorAssessments, query, config);
            if (features && features.length > 0) {
                yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.indicatorAssessments, features.map(f => f.attributes.OBJECTID), config);
            }
        }
    });
}
function getAssessmentNames(config, templateName) {
    return __awaiter(this, void 0, void 0, function* () {
        const features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.assessments, `Template='${templateName}'`, config);
        if (features && features.length === 0) {
            return {
                data: []
            };
        }
        if (features && features.length > 0) {
            const assess = features.map(f => {
                return {
                    name: f.attributes.Name,
                    date: (0,_utils__WEBPACK_IMPORTED_MODULE_7__.parseDate)(Number(f.attributes.CreatedDate))
                };
            });
            return {
                data: assess
            };
        }
        return {
            errors: 'Request for assessment names failed.'
        };
    });
}
function getAssessmentFeatures(config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Assessment Features called.');
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.assessments, `1=1`, config);
    });
}
function loadAllAssessments(config) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const assessmentFeatures = yield getAssessmentFeatures(config);
            if (!assessmentFeatures || assessmentFeatures.length == 0) {
                return {
                    data: []
                };
            }
            const lsFeatures = yield getLifelineStatusFeatures(config, `1=1`);
            const query = `LifelineStatusID IN (${lsFeatures.map(f => `'${f.attributes.GlobalID}'`).join(',')})`;
            const indicatorAssessments = yield getIndicatorAssessments(query, config);
            if (assessmentFeatures && assessmentFeatures.length > 0) {
                const assessments = assessmentFeatures.map((feature) => {
                    const assessmentLsFeatures = lsFeatures.filter(l => l.attributes.AssessmentID == feature.attributes.GlobalID);
                    return loadAssessment(feature, assessmentLsFeatures, indicatorAssessments);
                });
                return {
                    data: assessments
                };
            }
            if (assessmentFeatures && assessmentFeatures.length == 0) {
                return {
                    data: []
                };
            }
        }
        catch (e) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'loadAllAssessments');
            return {
                errors: e
            };
        }
    });
}
function createIncident(config, incident) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            checkParam(config.incidents, _constants__WEBPACK_IMPORTED_MODULE_1__.INCIDENT_URL_ERROR);
            checkParam(incident, 'Incident data not provided');
            const features = [{
                    attributes: {
                        HazardID: incident.hazard.id,
                        Name: incident.name,
                        Description: incident.description,
                        StartDate: String(incident.startDate),
                        EndDate: String(incident.endDate)
                    }
                }];
            const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.incidents, features, config);
            if (response.addResults && response.addResults.length > 0) {
                return {};
            }
            return {
                errors: 'Incident could not be saved.'
            };
        }
        catch (e) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'createIncident');
            return {
                errors: 'Incident could not be saved.'
            };
        }
    });
}
//====================PRIVATE======================================
const requestData = (url, controller) => __awaiter(void 0, void 0, void 0, function* () {
    if (!controller) {
        controller = new AbortController();
    }
    const response = yield fetch(url, {
        method: "GET",
        headers: {
            'content-type': 'application/x-www-form-urlencoded'
        },
        signal: controller.signal
    });
    return response.json();
});
function getTemplate(templateFeature, lifelineFeatures, componentFeatures, indicatorsFeatures, weightsFeatures, templateDomains) {
    return __awaiter(this, void 0, void 0, function* () {
        const indicatorFeatures = indicatorsFeatures.filter(i => i.attributes.TemplateID = `'${templateFeature.attributes.GlobalID}'`); //  await getIndicatorFeatures(`TemplateID='${templateFeature.attributes.GlobalID}'`, config);
        //const query = indicatorFeatures.map(i => `IndicatorID='${i.attributes.GlobalID.toUpperCase()}'`).join(' OR ')
        const indicatorIds = indicatorFeatures.map(i => i.attributes.GlobalID);
        const weightFeatures = weightsFeatures.filter(w => indicatorIds.indexOf(w.attributes.IndicatorID)); //await getWeightsFeatures(query, config);
        const indicatorTemplates = indicatorFeatures.map((feature) => {
            const weights = weightsFeatures
                .filter(w => w.attributes.IndicatorID === feature.attributes.GlobalID)
                .map(w => {
                return {
                    objectId: w.attributes.OBJECTID,
                    name: w.attributes.Name,
                    weight: w.attributes.Weight,
                    scaleFactor: w.attributes.ScaleFactor,
                    adjustedWeight: w.attributes.AdjustedWeight,
                    maxAdjustedWeight: w.attributes.MaxAdjustedWeight
                };
            });
            return {
                objectId: feature.attributes.OBJECTID,
                id: feature.attributes.GlobalID,
                name: feature.attributes.Name,
                templateName: feature.attributes.TemplateName,
                weights,
                componentId: feature.attributes.ComponentID,
                templateId: feature.attributes.TemplateID,
                componentName: feature.attributes.ComponentName,
                lifelineName: feature.attributes.LifelineName
            };
        });
        const componentTemplates = componentFeatures.map((feature) => {
            return {
                id: feature.attributes.GlobalID,
                title: feature.attributes.DisplayName || feature.attributes.DisplayTitle,
                name: feature.attributes.Name,
                lifelineId: feature.attributes.LifelineID,
                indicators: indicatorTemplates.filter(i => i.componentId === feature.attributes.GlobalID).orderBy('name')
            };
        });
        const lifelineTemplates = lifelineFeatures.map((feature) => {
            return {
                id: feature.attributes.GlobalID,
                title: feature.attributes.DisplayName || feature.attributes.DisplayTitle,
                name: feature.attributes.Name,
                componentTemplates: componentTemplates.filter(c => c.lifelineId === feature.attributes.GlobalID).orderBy('title')
            };
        });
        const template = {
            objectId: templateFeature.attributes.OBJECTID,
            id: templateFeature.attributes.GlobalID,
            isSelected: templateFeature.attributes.IsSelected == 1,
            status: {
                code: templateFeature.attributes.Status,
                name: templateFeature.attributes.Status === 1 ? "Active" : 'Archived'
            },
            name: templateFeature.attributes.Name,
            hazardName: templateFeature.attributes.HazardName,
            hazardType: templateFeature.attributes.HazardType,
            organizationName: templateFeature.attributes.OrganizationName,
            organizationType: templateFeature.attributes.OrganizationType,
            creator: templateFeature.attributes.Creator,
            createdDate: Number(templateFeature.attributes.CreatedDate),
            editor: templateFeature.attributes.Editor,
            editedDate: Number(templateFeature.attributes.EditedDate),
            lifelineTemplates: lifelineTemplates.orderBy('title'),
            domains: templateDomains
        };
        return template;
    });
}
function saveAssessment(assessment, config) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const feature = {
                attributes: {
                    Name: assessment.name,
                    Description: assessment.description,
                    AssessmentType: assessment.assessmentType,
                    Organization: assessment.organization,
                    Incident: assessment.incident,
                    Hazard: assessment.hazard,
                    Creator: assessment.creator,
                    CreatedDate: assessment.createdDate,
                    Editor: assessment.editor,
                    EditedDate: assessment.editedDate,
                    IsCompleted: assessment.isCompleted,
                    HazardType: assessment.hazardType,
                    OrganizationType: assessment.organizationType,
                    Template: assessment.template
                }
            };
            const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.assessments, [feature], config);
            if (response.addResults && response.addResults.every(r => r.success)) {
                return { data: response.addResults[0].globalId };
            }
            return {
                errors: JSON.stringify(response)
            };
        }
        catch (e) {
            return {
                errors: e
            };
        }
    });
}
function getIndicatorAssessments(query, config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Indicator Assessments called.');
        const features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.indicatorAssessments, query, config);
        if (features && features.length > 0) {
            return features.map(feature => {
                return {
                    objectId: feature.attributes.OBJECTID,
                    id: feature.attributes.GlobalID,
                    indicatorId: feature.attributes.IndicatorID,
                    indicator: feature.attributes.IndicatorName,
                    template: feature.attributes.TemplateName,
                    lifeline: feature.attributes.LifelineName,
                    component: feature.attributes.ComponentName,
                    comments: parseComment(feature.attributes.Comments),
                    lifelineStatusId: feature.attributes.LifelineStatusID,
                    environmentPreservation: feature.attributes.EnvironmentPreservation,
                    incidentStabilization: feature.attributes.IncidentStabilization,
                    rank: feature.attributes.Rank,
                    lifeSafety: feature.attributes.LifeSafety,
                    propertyProtection: feature.attributes.PropertyProtection,
                    status: feature.attributes.Status
                };
            });
        }
    });
}
function parseComment(comments) {
    if (!comments || comments === "") {
        return [];
    }
    let parsedComments = JSON.parse(comments);
    if (parsedComments && parsedComments.length > 0) {
        parsedComments.map((commentData) => {
            return Object.assign(Object.assign({}, commentData), { datetime: Number(commentData.datetime) });
        });
        parsedComments = parsedComments.orderBy('datetime', true);
    }
    else {
        parsedComments = [];
    }
    return parsedComments;
}
function getLifelineStatusFeatures(config, query) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Lifeline Status called');
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.lifelineStatus, query, config);
    });
}
function loadAssessment(assessmentFeature, lsFeatures, indicatorAssessments) {
    const lifelineStatuses = lsFeatures.map((feature) => {
        return {
            objectId: feature.attributes.OBJECTID,
            id: feature.attributes.GlobalID,
            assessmentId: feature.attributes.AssessmentID,
            lifelineName: feature.attributes.LifelineName,
            indicatorAssessments: indicatorAssessments.filter(i => i.lifelineStatusId === feature.attributes.GlobalID),
            score: feature.attributes.Score,
            color: feature.attributes.Color,
            isOverriden: feature.attributes.IsOverriden,
            overrideScore: feature.attributes.OverridenScore,
            overridenBy: feature.attributes.OverridenBy,
            overridenColor: feature.attributes.OverridenColor,
            overrideComment: feature.attributes.OverrideComment
        };
    });
    const assessment = {
        objectId: assessmentFeature.attributes.OBJECTID,
        id: assessmentFeature.attributes.GlobalID,
        name: assessmentFeature.attributes.Name,
        assessmentType: assessmentFeature.attributes.AssessmentType,
        lifelineStatuses: lifelineStatuses,
        description: assessmentFeature.attributes.Description,
        template: assessmentFeature.attributes.Template,
        organization: assessmentFeature.attributes.Organization,
        organizationType: assessmentFeature.attributes.OrganizationType,
        incident: assessmentFeature.attributes.Incident,
        hazard: assessmentFeature.attributes.Hazard,
        hazardType: assessmentFeature.attributes.HazardType,
        creator: assessmentFeature.attributes.Creator,
        createdDate: Number(assessmentFeature.attributes.CreatedDate),
        editor: assessmentFeature.attributes.Editor,
        editedDate: Number(assessmentFeature.attributes.EditedDate),
        isSelected: false,
        isCompleted: assessmentFeature.attributes.IsCompleted,
    };
    return assessment;
}
function saveLifelineStatus(lifelineStatusFeature, lsIndAssessFeatures, config) {
    return __awaiter(this, void 0, void 0, function* () {
        let response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.lifelineStatus, [lifelineStatusFeature], config);
        if (response.addResults && response.addResults.every(e => e.success)) {
            const globalId = response.addResults[0].globalId;
            const indicatorAssessmentFeatures = lsIndAssessFeatures.map(ind => {
                ind.attributes.LifelineStatusID = globalId;
                return ind;
            });
            response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.indicatorAssessments, indicatorAssessmentFeatures, config);
            if (response.addResults && response.addResults.every(e => e.success)) {
                return true;
            }
        }
    });
}
function getTemplateIndicators(template) {
    return [].concat.apply([], ([].concat.apply([], template.lifelineTemplates.map(l => l.componentTemplates)))
        .map((c) => c.indicators));
}


/***/ }),

/***/ "./your-extensions/widgets/clss-application/src/extensions/auth.ts":
/*!*************************************************************************!*\
  !*** ./your-extensions/widgets/clss-application/src/extensions/auth.ts ***!
  \*************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "checkCurrentStatus": () => (/* binding */ checkCurrentStatus),
/* harmony export */   "signIn": () => (/* binding */ signIn),
/* harmony export */   "signOut": () => (/* binding */ signOut)
/* harmony export */ });
/* harmony import */ var jimu_arcgis__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-arcgis */ "jimu-arcgis");
//Adapted from //https://github.com/odoe/map-vue/blob/master/src/data/auth.ts
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};

/**
 * Attempt to sign in,
 * first check current status
 * if not signed in, then go through
 * steps to get credentials
 */
const signIn = (appId, portalUrl) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        return yield checkCurrentStatus(appId, portalUrl);
    }
    catch (error) {
        console.log(error);
        return yield fetchCredentials(appId, portalUrl);
    }
});
/**
 * Sign the user out, but if we checked credentials
 * manually, make sure they are registered with
 * IdentityManager, so it can destroy them properly
 */
const signOut = (appId, portalUrl) => __awaiter(void 0, void 0, void 0, function* () {
    const IdentityManager = yield loadModules(appId, portalUrl);
    yield signIn(appId, portalUrl);
    delete window['IdentityManager'];
    delete window['OAuthInfo'];
    IdentityManager.destroyCredentials();
});
/**
 * Get the credentials for the provided portal
 */
function fetchCredentials(appId, portalUrl) {
    return __awaiter(this, void 0, void 0, function* () {
        const IdentityManager = yield loadModules(appId, portalUrl);
        const credential = yield IdentityManager.getCredential(`${portalUrl}/sharing`, {
            error: null,
            oAuthPopupConfirmation: false,
            token: null
        });
        return credential;
    });
}
;
/**
 * Import Identity Manager, and OAuthInfo
 */
function loadModules(appId, portalUrl) {
    return __awaiter(this, void 0, void 0, function* () {
        let IdentityManager = window['IdentityManager'];
        if (!IdentityManager) {
            const modules = yield (0,jimu_arcgis__WEBPACK_IMPORTED_MODULE_0__.loadArcGISJSAPIModules)([
                'esri/identity/IdentityManager',
                'esri/identity/OAuthInfo'
            ]);
            window['IdentityManager'] = modules[0];
            window['OAuthInfo'] = modules[1];
            IdentityManager = modules[0];
            const OAuthInfo = modules[1];
            const oauthInfo = new OAuthInfo({
                appId,
                portalUrl,
                popup: false
            });
            IdentityManager.registerOAuthInfos([oauthInfo]);
        }
        return IdentityManager;
    });
}
/**
 * Check current logged in status for current portal
 */
const checkCurrentStatus = (appId, portalUrl) => __awaiter(void 0, void 0, void 0, function* () {
    const IdentityManager = yield loadModules(appId, portalUrl);
    return IdentityManager.checkSignInStatus(`${portalUrl}/sharing`);
});


/***/ }),

/***/ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts":
/*!*******************************************************************************!*\
  !*** ./your-extensions/widgets/clss-application/src/extensions/clss-store.ts ***!
  \*******************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "CLSSActionKeys": () => (/* binding */ CLSSActionKeys),
/* harmony export */   "default": () => (/* binding */ MyReduxStoreExtension)
/* harmony export */ });
var CLSSActionKeys;
(function (CLSSActionKeys) {
    CLSSActionKeys["AUTHENTICATE_ACTION"] = "[CLSS-APPLICATION] authenicate credentials";
    CLSSActionKeys["LOAD_HAZARDS_ACTION"] = "[CLSS-APPLICATION] load hazards";
    CLSSActionKeys["LOAD_HAZARD_TYPES_ACTION"] = "[CLSS-APPLICATION] load hazard types";
    CLSSActionKeys["LOAD_ORGANIZATIONS_ACTION"] = "[CLSS-APPLICATION] load organizations";
    CLSSActionKeys["LOAD_ORGANIZATION_TYPES_ACTION"] = "[CLSS-APPLICATION] load organization types";
    CLSSActionKeys["LOAD_TEMPLATES_ACTION"] = "[CLSS-APPLICATION] load templates";
    CLSSActionKeys["LOAD_PRIORITIES_ACTION"] = "[CLSS-APPLICATION] load priorities";
    CLSSActionKeys["SELECT_TEMPLATE_ACTION"] = "[CLSS-APPLICATION] select template";
    CLSSActionKeys["SEARCH_ACTION"] = "[CLSS-APPLICATION] search for template";
    CLSSActionKeys["SIGN_IN_ACTION"] = "[CLSS-APPLICATION] Sign in";
    CLSSActionKeys["SIGN_OUT_ACTION"] = "[CLSS-APPLICATION] Sign out";
    CLSSActionKeys["SET_USER_ACTION"] = "[CLSS-APPLICATION] Set CLSS User";
    CLSSActionKeys["SET_IDENTITY_ACTION"] = "[CLSS-APPLICATION] Set Identity";
    CLSSActionKeys["SET_ERRORS"] = "[CLSS-APPLICATION] Set global errors";
    CLSSActionKeys["TOGGLE_INDICATOR_EDITING"] = "[CLSS-APPLICATION] Toggle indicator editing";
    CLSSActionKeys["SELECT_LIFELINESTATUS_ACTION"] = "[CLSS-APPLICATION] Select a lifeline status";
    CLSSActionKeys["LOAD_ASSESSMENTS_ACTION"] = "[CLSS-APPLICATION] Load assessments";
    CLSSActionKeys["SELECT_ASSESSMENT_ACTION"] = "[CLSS-APPLICATION] Select assessment";
    CLSSActionKeys["LOAD_RATINGSCALES_ACTION"] = "[CLSS-APPLICATION] Load rating scales";
    CLSSActionKeys["LOAD_SCALEFACTORS_ACTION"] = "[CLSS-APPLICATION] Load constants";
})(CLSSActionKeys || (CLSSActionKeys = {}));
class MyReduxStoreExtension {
    constructor() {
        this.id = 'clss-redux-store-extension';
    }
    getActions() {
        return Object.keys(CLSSActionKeys).map(k => CLSSActionKeys[k]);
    }
    getInitLocalState() {
        return {
            selectedTemplate: null,
            templates: [],
            searchResults: [],
            user: null,
            auth: null,
            identity: null,
            newTemplateModalVisible: false,
            hazards: [],
            organizations: [],
            errors: '',
            isIndicatorEditing: false,
            selectedLifelineStatus: null,
            organizationTypes: [],
            hazardTypes: [],
            priorities: [],
            assessments: [],
            ratingScales: [],
            scaleFactors: [],
            authenticate: null
        };
    }
    getReducer() {
        return (localState, action, appState) => {
            switch (action.type) {
                case CLSSActionKeys.AUTHENTICATE_ACTION:
                    return localState.set('authenticate', action.val);
                case CLSSActionKeys.LOAD_SCALEFACTORS_ACTION:
                    return localState.set('scaleFactors', action.val);
                case CLSSActionKeys.LOAD_RATINGSCALES_ACTION:
                    return localState.set('ratingScales', action.val);
                case CLSSActionKeys.SELECT_ASSESSMENT_ACTION:
                    const assessments = localState.assessments.map(assess => {
                        return Object.assign(Object.assign({}, assess), { isSelected: assess.id === action.val.id.toLowerCase() });
                    });
                    return localState.set('assessments', assessments);
                case CLSSActionKeys.LOAD_ASSESSMENTS_ACTION:
                    return localState.set('assessments', action.val);
                case CLSSActionKeys.LOAD_PRIORITIES_ACTION:
                    return localState.set('priorities', action.val);
                case CLSSActionKeys.SELECT_LIFELINESTATUS_ACTION:
                    return localState.set('selectedLifelineStatus', action.val);
                case CLSSActionKeys.TOGGLE_INDICATOR_EDITING:
                    return localState.set('isIndicatorEditing', action.val);
                case CLSSActionKeys.SET_ERRORS:
                    return localState.set('errors', action.val);
                case CLSSActionKeys.LOAD_HAZARDS_ACTION:
                    return localState.set('hazards', action.val);
                case CLSSActionKeys.LOAD_HAZARD_TYPES_ACTION:
                    return localState.set('hazardTypes', action.val);
                case CLSSActionKeys.LOAD_ORGANIZATION_TYPES_ACTION:
                    return localState.set('organizationTypes', action.val);
                case CLSSActionKeys.LOAD_ORGANIZATIONS_ACTION:
                    return localState.set('organizations', action.val);
                case CLSSActionKeys.SET_IDENTITY_ACTION:
                    return localState.set('identity', action.val);
                case CLSSActionKeys.SET_USER_ACTION:
                    return localState.set('user', action.val);
                case CLSSActionKeys.LOAD_TEMPLATES_ACTION:
                    return localState.set('templates', action.val);
                case CLSSActionKeys.SELECT_TEMPLATE_ACTION:
                    let templates = [...localState.templates].map(t => {
                        return Object.assign(Object.assign({}, t), { isSelected: t.id === action.val });
                    });
                    return localState.set('templates', templates);
                default:
                    return localState;
            }
        };
    }
    getStoreKey() {
        return 'clssState';
    }
}


/***/ }),

/***/ "./your-extensions/widgets/clss-application/src/extensions/constants.ts":
/*!******************************************************************************!*\
  !*** ./your-extensions/widgets/clss-application/src/extensions/constants.ts ***!
  \******************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "ALIGNMENT_URL_ERROR": () => (/* binding */ ALIGNMENT_URL_ERROR),
/* harmony export */   "ANALYSIS_REPORTING_TITLE": () => (/* binding */ ANALYSIS_REPORTING_TITLE),
/* harmony export */   "ASSESSMENT_URL_ERROR": () => (/* binding */ ASSESSMENT_URL_ERROR),
/* harmony export */   "BASELINE_TEMPLATE_NAME": () => (/* binding */ BASELINE_TEMPLATE_NAME),
/* harmony export */   "CLSS_ADMIN": () => (/* binding */ CLSS_ADMIN),
/* harmony export */   "CLSS_ASSESSOR": () => (/* binding */ CLSS_ASSESSOR),
/* harmony export */   "CLSS_EDITOR": () => (/* binding */ CLSS_EDITOR),
/* harmony export */   "CLSS_FOLLOWERS": () => (/* binding */ CLSS_FOLLOWERS),
/* harmony export */   "CLSS_VIEWER": () => (/* binding */ CLSS_VIEWER),
/* harmony export */   "COMMENT": () => (/* binding */ COMMENT),
/* harmony export */   "COMMENT_HELP": () => (/* binding */ COMMENT_HELP),
/* harmony export */   "COMPONENT_URL_ERROR": () => (/* binding */ COMPONENT_URL_ERROR),
/* harmony export */   "CRITICAL": () => (/* binding */ CRITICAL),
/* harmony export */   "CRITICAL_LOWER_BOUNDARY": () => (/* binding */ CRITICAL_LOWER_BOUNDARY),
/* harmony export */   "DATA_LIBRARY_TITLE": () => (/* binding */ DATA_LIBRARY_TITLE),
/* harmony export */   "DEFAULT_LISTITEM": () => (/* binding */ DEFAULT_LISTITEM),
/* harmony export */   "DEFAULT_PRIORITY_LEVELS": () => (/* binding */ DEFAULT_PRIORITY_LEVELS),
/* harmony export */   "DELETE_INDICATOR_CONFIRMATION": () => (/* binding */ DELETE_INDICATOR_CONFIRMATION),
/* harmony export */   "DESTABILIZING_SCALE_FACTOR": () => (/* binding */ DESTABILIZING_SCALE_FACTOR),
/* harmony export */   "ENVIRONMENT_PRESERVATION": () => (/* binding */ ENVIRONMENT_PRESERVATION),
/* harmony export */   "ENVIRONMENT_PRESERVATION_MESSAGE": () => (/* binding */ ENVIRONMENT_PRESERVATION_MESSAGE),
/* harmony export */   "GREEN_COLOR": () => (/* binding */ GREEN_COLOR),
/* harmony export */   "HAZARD_URL_ERROR": () => (/* binding */ HAZARD_URL_ERROR),
/* harmony export */   "INCIDENT_STABILIZATION": () => (/* binding */ INCIDENT_STABILIZATION),
/* harmony export */   "INCIDENT_STABILIZATION_MESSAGE": () => (/* binding */ INCIDENT_STABILIZATION_MESSAGE),
/* harmony export */   "INCIDENT_URL_ERROR": () => (/* binding */ INCIDENT_URL_ERROR),
/* harmony export */   "INCLUDE_INDICATOR": () => (/* binding */ INCLUDE_INDICATOR),
/* harmony export */   "INCLUDE_INDICATOR_HELP": () => (/* binding */ INCLUDE_INDICATOR_HELP),
/* harmony export */   "INDICATOR_COMMENT_LENGTH": () => (/* binding */ INDICATOR_COMMENT_LENGTH),
/* harmony export */   "INDICATOR_STATUS": () => (/* binding */ INDICATOR_STATUS),
/* harmony export */   "INDICATOR_STATUS_HELP": () => (/* binding */ INDICATOR_STATUS_HELP),
/* harmony export */   "INDICATOR_URL_ERROR": () => (/* binding */ INDICATOR_URL_ERROR),
/* harmony export */   "LIFELINE_URL_ERROR": () => (/* binding */ LIFELINE_URL_ERROR),
/* harmony export */   "LIFE_SAFETY": () => (/* binding */ LIFE_SAFETY),
/* harmony export */   "LIFE_SAFETY_MESSAGE": () => (/* binding */ LIFE_SAFETY_MESSAGE),
/* harmony export */   "LIFE_SAFETY_SCALE_FACTOR": () => (/* binding */ LIFE_SAFETY_SCALE_FACTOR),
/* harmony export */   "MAXIMUM_WEIGHT": () => (/* binding */ MAXIMUM_WEIGHT),
/* harmony export */   "MODERATE_LOWER_BOUNDARY": () => (/* binding */ MODERATE_LOWER_BOUNDARY),
/* harmony export */   "NODATA_COLOR": () => (/* binding */ NODATA_COLOR),
/* harmony export */   "NODATA_VALUE": () => (/* binding */ NODATA_VALUE),
/* harmony export */   "ORGANIZATION_URL_ERROR": () => (/* binding */ ORGANIZATION_URL_ERROR),
/* harmony export */   "OTHER_WEIGHTS_SCALE_FACTOR": () => (/* binding */ OTHER_WEIGHTS_SCALE_FACTOR),
/* harmony export */   "OVERWRITE_SCORE_MESSAGE": () => (/* binding */ OVERWRITE_SCORE_MESSAGE),
/* harmony export */   "PORTAL_URL": () => (/* binding */ PORTAL_URL),
/* harmony export */   "PRIORITY_URL_ERROR": () => (/* binding */ PRIORITY_URL_ERROR),
/* harmony export */   "PROPERTY_PROTECTION": () => (/* binding */ PROPERTY_PROTECTION),
/* harmony export */   "PROPERTY_PROTECTION_MESSAGE": () => (/* binding */ PROPERTY_PROTECTION_MESSAGE),
/* harmony export */   "RANK": () => (/* binding */ RANK),
/* harmony export */   "RANK_MESSAGE": () => (/* binding */ RANK_MESSAGE),
/* harmony export */   "RED_COLOR": () => (/* binding */ RED_COLOR),
/* harmony export */   "SAVING_SAME_AS_BASELINE_ERROR": () => (/* binding */ SAVING_SAME_AS_BASELINE_ERROR),
/* harmony export */   "SAVING_TIMER": () => (/* binding */ SAVING_TIMER),
/* harmony export */   "STABILIZING_SCALE_FACTOR": () => (/* binding */ STABILIZING_SCALE_FACTOR),
/* harmony export */   "TEMPLATE_URL_ERROR": () => (/* binding */ TEMPLATE_URL_ERROR),
/* harmony export */   "TOKEN_ERROR": () => (/* binding */ TOKEN_ERROR),
/* harmony export */   "UNCHANGED_SCALE_FACTOR": () => (/* binding */ UNCHANGED_SCALE_FACTOR),
/* harmony export */   "USER_BOX_ELEMENT_ID": () => (/* binding */ USER_BOX_ELEMENT_ID),
/* harmony export */   "UpdateAction": () => (/* binding */ UpdateAction),
/* harmony export */   "YELLOW_COLOR": () => (/* binding */ YELLOW_COLOR)
/* harmony export */ });
const CLSS_ADMIN = 'CLSS_Admin';
const CLSS_EDITOR = 'CLSS_Editor';
const CLSS_ASSESSOR = 'CLSS_Assessor';
const CLSS_VIEWER = 'CLSS_Viewer';
const CLSS_FOLLOWERS = 'CLSS Followers';
const BASELINE_TEMPLATE_NAME = 'Baseline';
const TOKEN_ERROR = 'Token not provided';
const TEMPLATE_URL_ERROR = 'Template FeatureLayer URL not provided';
const ASSESSMENT_URL_ERROR = 'Assessment FeatureLayer URL not provided';
const ORGANIZATION_URL_ERROR = 'Organization FeatureLayer URL not provided';
const HAZARD_URL_ERROR = 'Hazard FeatureLayer URL not provided';
const INDICATOR_URL_ERROR = 'Indicator FeatureLayer URL not provided';
const ALIGNMENT_URL_ERROR = 'Alignments FeatureLayer URL not provided';
const LIFELINE_URL_ERROR = 'Lifeline FeatureLayer URL not provided';
const COMPONENT_URL_ERROR = 'Component FeatureLayer URL not provided';
const PRIORITY_URL_ERROR = 'Priority FeatureLayer URL not provided';
const INCIDENT_URL_ERROR = 'Incident FeatureLayer URL not provided';
const SAVING_SAME_AS_BASELINE_ERROR = 'Baseline template cannot be updated. Change the template name to create a new one.';
const STABILIZING_SCALE_FACTOR = 'Stabilizing_Scale_Factor';
const DESTABILIZING_SCALE_FACTOR = 'Destabilizing_Scale_Factor';
const UNCHANGED_SCALE_FACTOR = 'Unchanged_Indicators';
const DEFAULT_PRIORITY_LEVELS = "Default_Priority_Levels";
const RANK = 'Importance of Indicator';
const LIFE_SAFETY = 'Life Safety';
const INCIDENT_STABILIZATION = 'Incident Stabilization';
const PROPERTY_PROTECTION = 'Property Protection';
const ENVIRONMENT_PRESERVATION = 'Environment Preservation';
const LIFE_SAFETY_SCALE_FACTOR = 200;
const OTHER_WEIGHTS_SCALE_FACTOR = 100;
const MAXIMUM_WEIGHT = 5;
var UpdateAction;
(function (UpdateAction) {
    UpdateAction["HEADER"] = "header";
    UpdateAction["INDICATOR_NAME"] = "Indicator Name";
    UpdateAction["PRIORITIES"] = "Indicator Priorities";
    UpdateAction["NEW_INDICATOR"] = "Create New Indicator";
    UpdateAction["DELETE_INDICATOR"] = "Delete Indicator";
})(UpdateAction || (UpdateAction = {}));
const INCLUDE_INDICATOR = 'Impacted - Yes or No';
const INCLUDE_INDICATOR_HELP = 'Yes: The indicator will be considered in the assessment.\nNo: The indicator will not be considered.\nUnknown: Not sure to include the indicator in assessment.';
const INDICATOR_STATUS = 'Indicator Impact Status';
const INDICATOR_STATUS_HELP = 'Stabilizing: Has the indicator been improved or improving.\nDestabilizing: Is the indicator degrading.\nUnchanged: No significant improvement since the last assessment.';
const COMMENT = 'Comment';
const COMMENT_HELP = 'Provide justification for the selected indicator status.';
const DELETE_INDICATOR_CONFIRMATION = 'Are you sure you want to delete indicator?';
//Cell Weight =  Trend * ( (-1*Rank) + 6
const CRITICAL = 25;
const CRITICAL_LOWER_BOUNDARY = 12.5;
const MODERATE_LOWER_BOUNDARY = 5.5;
const NODATA_COLOR = '#919395';
const NODATA_VALUE = 999999;
const RED_COLOR = '#C52038';
const YELLOW_COLOR = '#FBBA16';
const GREEN_COLOR = '#5E9C42';
const SAVING_TIMER = 1500;
const INDICATOR_COMMENT_LENGTH = 300;
const PORTAL_URL = 'https://www.arcgis.com';
const DEFAULT_LISTITEM = { id: '000', name: '-None-', title: '-None-' };
const RANK_MESSAGE = 'How important is the indicator to your jurisdiction or hazard?';
const LIFE_SAFETY_MESSAGE = 'How important is the indicator to Life Safety?';
const PROPERTY_PROTECTION_MESSAGE = 'How important is the indicator to Property Protection?';
const ENVIRONMENT_PRESERVATION_MESSAGE = 'How important is the indicator to Environment Preservation?';
const INCIDENT_STABILIZATION_MESSAGE = 'How important is the indicator to Incident Stabilization?';
const OVERWRITE_SCORE_MESSAGE = 'A completed assessment cannot be edited. Are you sure you want to complete this assessment?';
const USER_BOX_ELEMENT_ID = 'userBoxElement';
const DATA_LIBRARY_TITLE = 'Data Library';
const ANALYSIS_REPORTING_TITLE = 'Analysis & Reporting';


/***/ }),

/***/ "./your-extensions/widgets/clss-application/src/extensions/esri-api.ts":
/*!*****************************************************************************!*\
  !*** ./your-extensions/widgets/clss-application/src/extensions/esri-api.ts ***!
  \*****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "addTableFeatures": () => (/* binding */ addTableFeatures),
/* harmony export */   "deleteTableFeatures": () => (/* binding */ deleteTableFeatures),
/* harmony export */   "queryRelatedTableFeatures": () => (/* binding */ queryRelatedTableFeatures),
/* harmony export */   "queryTableFeatureSet": () => (/* binding */ queryTableFeatureSet),
/* harmony export */   "queryTableFeatures": () => (/* binding */ queryTableFeatures),
/* harmony export */   "updateTableFeature": () => (/* binding */ updateTableFeature),
/* harmony export */   "updateTableFeatures": () => (/* binding */ updateTableFeatures)
/* harmony export */ });
/* harmony import */ var _esri_arcgis_rest_auth__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @esri/arcgis-rest-auth */ "./node_modules/@esri/arcgis-rest-auth/dist/esm/UserSession.js");
/* harmony import */ var _esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @esri/arcgis-rest-feature-layer */ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/query.js");
/* harmony import */ var _esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @esri/arcgis-rest-feature-layer */ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/queryRelated.js");
/* harmony import */ var _esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @esri/arcgis-rest-feature-layer */ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/update.js");
/* harmony import */ var _esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! @esri/arcgis-rest-feature-layer */ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/add.js");
/* harmony import */ var _esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @esri/arcgis-rest-feature-layer */ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/delete.js");
/* harmony import */ var _logger__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./logger */ "./your-extensions/widgets/clss-application/src/extensions/logger.ts");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};



function getAuthentication(config) {
    return __awaiter(this, void 0, void 0, function* () {
        return _esri_arcgis_rest_auth__WEBPACK_IMPORTED_MODULE_1__.UserSession.fromCredential(config.credential);
    });
}
function queryTableFeatureSet(url, where, config) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const authentication = yield getAuthentication(config);
            return (0,_esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_2__.queryFeatures)({ url, where, authentication, hideToken: true })
                .then((response) => {
                return response;
            });
        }
        catch (e) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_0__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_0__.LogType.ERROR, 'queryTableFeatureSet');
        }
    });
}
function queryTableFeatures(url, where, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const authentication = yield getAuthentication(config);
        try {
            const response = yield (0,_esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_2__.queryFeatures)({ url, where, authentication, httpMethod: 'POST', hideToken: true });
            return response.features;
        }
        catch (e) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_0__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_0__.LogType.ERROR, 'queryTableFeatures');
            (0,_logger__WEBPACK_IMPORTED_MODULE_0__.log)(url, _logger__WEBPACK_IMPORTED_MODULE_0__.LogType.WRN, where);
        }
    });
}
function queryRelatedTableFeatures(objectIds, url, relationshipId, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const authentication = yield getAuthentication(config);
        const response = yield (0,_esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_3__.queryRelated)({
            objectIds,
            url, relationshipId,
            authentication,
            hideToken: true
        });
        return response.relatedRecordGroups;
    });
}
function updateTableFeature(url, attributes, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const authentication = yield getAuthentication(config);
        return (0,_esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_4__.updateFeatures)({
            url,
            authentication,
            features: [{
                    attributes
                }],
            rollbackOnFailure: true
        });
    });
}
function updateTableFeatures(url, features, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const authentication = yield getAuthentication(config);
        return (0,_esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_4__.updateFeatures)({
            url,
            authentication,
            features
        });
    });
}
function addTableFeatures(url, features, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const authentication = yield getAuthentication(config);
        try {
            return (0,_esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_5__.addFeatures)({ url, features, authentication, rollbackOnFailure: true });
        }
        catch (e) {
            console.log(e);
        }
    });
}
function deleteTableFeatures(url, objectIds, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const authentication = yield getAuthentication(config);
        return (0,_esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_6__.deleteFeatures)({ url, objectIds, authentication, rollbackOnFailure: true });
    });
}


/***/ }),

/***/ "./your-extensions/widgets/clss-application/src/extensions/logger.ts":
/*!***************************************************************************!*\
  !*** ./your-extensions/widgets/clss-application/src/extensions/logger.ts ***!
  \***************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "LogType": () => (/* binding */ LogType),
/* harmony export */   "log": () => (/* binding */ log)
/* harmony export */ });
var LogType;
(function (LogType) {
    LogType["INFO"] = "Information";
    LogType["WRN"] = "Warning";
    LogType["ERROR"] = "Error";
})(LogType || (LogType = {}));
function log(message, type, func) {
    if (!type) {
        type = LogType.INFO;
    }
    if (func) {
        func = `(${func})`;
    }
    message = `[${new Date().toLocaleString()}]: ${message} ${func}`;
    switch (type) {
        case LogType.INFO:
            console.log(message);
            break;
        case LogType.WRN:
            console.warn(message);
            break;
        case LogType.ERROR:
            console.error(message);
            break;
        default:
            console.log(message);
    }
}


/***/ }),

/***/ "./your-extensions/widgets/clss-application/src/extensions/utils.ts":
/*!**************************************************************************!*\
  !*** ./your-extensions/widgets/clss-application/src/extensions/utils.ts ***!
  \**************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "createGuid": () => (/* binding */ createGuid),
/* harmony export */   "parseDate": () => (/* binding */ parseDate),
/* harmony export */   "saveDate": () => (/* binding */ saveDate),
/* harmony export */   "sortObject": () => (/* binding */ sortObject)
/* harmony export */ });
const sortObject = (obj, prop, reverse) => {
    return obj.sort((a, b) => {
        if (a[prop] > b[prop]) {
            return reverse ? -1 : 1;
        }
        if (a[prop] < b[prop]) {
            return reverse ? 1 : -1;
        }
        return 0;
    });
};
const createGuid = () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
};
const parseDate = (milliseconds) => {
    if (!milliseconds) {
        return;
    }
    return new Date(milliseconds).toLocaleString();
};
const saveDate = (date) => {
    return new Date(date).getMilliseconds();
};
//Reference: https://stackoverflow.com/questions/6195335/linear-regression-in-javascript
// export const linearRegression = (yValues: number[], xValues: number[]) =>{
//   debugger;
//   const y = yValues;
//   const x = xValues;
//   var lr = {slope: NaN, intercept: NaN, r2: NaN};
//   var n = y.length;
//   var sum_x = 0;
//   var sum_y = 0;
//   var sum_xy = 0;
//   var sum_xx = 0;
//   var sum_yy = 0;
//   for (var i = 0; i < y.length; i++) {
//       sum_x += x[i];
//       sum_y += y[i];
//       sum_xy += (x[i]*y[i]);
//       sum_xx += (x[i]*x[i]);
//       sum_yy += (y[i]*y[i]);
//   } 
//   lr.slope = (n * sum_xy - sum_x * sum_y) / (n*sum_xx - sum_x * sum_x);
//   lr.intercept = (sum_y - lr.slope * sum_x)/n;
//   lr.r2 = Math.pow((n*sum_xy - sum_x*sum_y)/Math.sqrt((n*sum_xx-sum_x*sum_x)*(n*sum_yy-sum_y*sum_y)),2);
//   return lr;
// }
String.prototype.toTitleCase = function () {
    return this.replace(/\w\S*/g, function (txt) { return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase(); });
};
Array.prototype.orderBy = function (prop, reverse) {
    return this.sort((a, b) => {
        if (a[prop] > b[prop]) {
            return reverse ? -1 : 1;
        }
        if (a[prop] < b[prop]) {
            return reverse ? 1 : -1;
        }
        return 0;
    });
};
Array.prototype.groupBy = function (key) {
    return this.reduce(function (rv, x) {
        (rv[x[key]] = rv[x[key]] || []).push(x);
        return rv;
    }, {});
};


/***/ }),

/***/ "jimu-arcgis":
/*!******************************!*\
  !*** external "jimu-arcgis" ***!
  \******************************/
/***/ ((module) => {

"use strict";
module.exports = __WEBPACK_EXTERNAL_MODULE_jimu_arcgis__;

/***/ }),

/***/ "jimu-core":
/*!****************************!*\
  !*** external "jimu-core" ***!
  \****************************/
/***/ ((module) => {

"use strict";
module.exports = __WEBPACK_EXTERNAL_MODULE_jimu_core__;

/***/ }),

/***/ "react":
/*!**********************************!*\
  !*** external "jimu-core/react" ***!
  \**********************************/
/***/ ((module) => {

"use strict";
module.exports = __WEBPACK_EXTERNAL_MODULE_react__;

/***/ }),

/***/ "jimu-ui":
/*!**************************!*\
  !*** external "jimu-ui" ***!
  \**************************/
/***/ ((module) => {

"use strict";
module.exports = __WEBPACK_EXTERNAL_MODULE_jimu_ui__;

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/publicPath */
/******/ 	(() => {
/******/ 		__webpack_require__.p = "";
/******/ 	})();
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other entry modules.
(() => {
/*!******************************************!*\
  !*** ./jimu-core/lib/set-public-path.ts ***!
  \******************************************/
/**
 * Webpack will replace __webpack_public_path__ with __webpack_require__.p to set the public path dynamically.
 * The reason why we can't set the publicPath in webpack config is: we change the publicPath when download.
 * */
// eslint-disable-next-line
// @ts-ignore
__webpack_require__.p = window.jimuConfig.baseUrl;

})();

// This entry need to be wrapped in an IIFE because it need to be in strict mode.
(() => {
"use strict";
/*!*****************************************************************************!*\
  !*** ./your-extensions/widgets/clss-select-lifeline/src/runtime/widget.tsx ***!
  \*****************************************************************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");




const { useSelector } = jimu_core__WEBPACK_IMPORTED_MODULE_0__.ReactRedux;
// function useWindowSize() {
//   const [size, setSize] = React.useState([0, 0]);
//   React.useLayoutEffect(() => {
//     function updateSize() {
//       setSize([window.innerWidth, window.innerHeight]);
//     }
//     window.addEventListener('resize', updateSize);
//     updateSize();
//     return () => window.removeEventListener('resize', updateSize);
//   }, []);
//   return size;
// }
const Widget = (props) => {
    // const [width, height] = useWindowSize();
    const [lifelineStatuses, setLifelineStatuses] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState([]);
    const [selectedLifelineStatus, setSelectedLifelineStatus] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(null);
    const selectedAssessment = useSelector((state) => {
        var _a, _b, _c, _d;
        if (((_a = state.clssState) === null || _a === void 0 ? void 0 : _a.assessments) && ((_b = state.clssState) === null || _b === void 0 ? void 0 : _b.assessments.length) > 0) {
            return (_d = (_c = state.clssState) === null || _c === void 0 ? void 0 : _c.assessments) === null || _d === void 0 ? void 0 : _d.find(a => a.isSelected);
        }
    });
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (selectedAssessment) {
            setLifelineStatuses((selectedAssessment === null || selectedAssessment === void 0 ? void 0 : selectedAssessment.lifelineStatuses).orderBy('lifelineName'));
        }
    }, [selectedAssessment]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (lifelineStatuses) {
            selectLifelineStatus(lifelineStatuses[0]);
        }
    }, [lifelineStatuses]);
    const selectLifelineStatus = (lifelineStatus) => {
        setSelectedLifelineStatus(lifelineStatus);
        (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_2__.CLSSActionKeys.SELECT_LIFELINESTATUS_ACTION, lifelineStatus);
    };
    if (!lifelineStatuses || lifelineStatuses.length == 0) {
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("h5", { style: { position: 'absolute', left: '40%', top: '50%' } }, "No Data");
    }
    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "widget-select-lifelines jimu-widget" },
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("style", null, `
            .widget-select-lifelines{
              width: 100%;
              height: 100%;
              padding: 10px;
            }
            .select-lifeline-container{
               width: 100%;
               height: 100%;
               display: flex;
               flex-direction: column;
               align-items: center;
               border-radius: 10px;
               overflow-y: auto;
               overflow-x: hidden;
            }
            .lifelines-header{
              width: 100%;
              display: flex;
              justify-content: center;
              align-items: center;
              padding: 10px 0;
              font-size: 1.2rem;
              font-weight: bold;              
              border-radius: 10px 10px 0 0;
            }
            .lifeline{
              width: 100%;
              cursor: pointer;            
              text-align: center;
              font-size: 2.5em;
              padding: 0.2em 0
            }
            .lifeline:hover{
              opacity: 0.5;
            }
            .lifeline label{
              cursor: pointer;
            }
            .back-templates-button{    
              position: absolute;
              bottom: 10px;
              left: 0;           
              height: 65px;
              width: 85%;
              font-weight: bold;
              font-size: 1.5em;
              border-radius: 5px;
              line-height: 1.5em;
              margin: 10px 18px 10px 18px;
            }
            .back-templates-button:hover{
               opacity: 0.8
            }
            .selected-assessment{
              display: flex;
              flex-direction: column;
              width: 100%;
              align-items: center;
              margin-top: 5em;
              color: #9a9a9a;
              border-top: 1px solid;
              padding-top: 20px;
            }
            .selected-assessment h2,
            .selected-assessment h3,
            .selected-assessment-top h2,
            .selected-assessment-top h3 {
              color: #9a9a9a;
              margin: 0;
            }
            .selected-assessment-top{
              color: #9a9a9a;
              margin: 0;
              display: flex;
              flex-direction: column;
              width: 100%;
              align-items: center;   
              border-bottom: 1px solid;
              padding-top: 20px;
            }
           `),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "select-lifeline-container", style: {
                backgroundColor: props.config.backgroundColor
            } },
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { check: true, className: 'lifelines-header', style: { backgroundColor: props.config.backgroundColor,
                    color: props.config.fontColor } }, "Assessment"),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("h2", { style: {
                    color: '#b6b6b6',
                    marginTop: '-15px',
                    fontSize: '21px'
                } }, selectedAssessment === null || selectedAssessment === void 0 ? void 0 : selectedAssessment.name),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { check: true, className: 'lifelines-header', style: {
                    color: props.config.fontColor, borderTop: '1px solid white'
                } }, "Lifelines"), lifelineStatuses === null || lifelineStatuses === void 0 ? void 0 :
            lifelineStatuses.map((lifelineStatus) => {
                return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: 'lifeline', key: lifelineStatus.id, style: {
                        backgroundColor: (selectedLifelineStatus === null || selectedLifelineStatus === void 0 ? void 0 : selectedLifelineStatus.id) === lifelineStatus.id ? props.config.selectedBackgroundColor : 'transparent'
                    }, onClick: () => selectLifelineStatus(lifelineStatus) },
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { size: 'lg', style: { color: props.config.fontColor } }, lifelineStatus.lifelineName)));
            }))));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (Widget);

})();

/******/ 	return __webpack_exports__;
/******/ })()

			);
		}
	};
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2lkZ2V0cy9jbHNzLXNlbGVjdC1saWZlbGluZS9kaXN0L3J1bnRpbWUvd2lkZ2V0LmpzIiwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQ0E7QUFDaUM7QUFDcUY7QUFDckU7QUFDTjtBQUN5QjtBQUNWO0FBQzFEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFlBQVksY0FBYztBQUMxQjtBQUNBO0FBQ0E7QUFDQTtBQUNBLElBQUk7QUFDSjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsSUFBSTtBQUNKO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGNBQWMsbUVBQVE7QUFDdEI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBLGtCQUFrQixlQUFlO0FBQ2pDO0FBQ0E7QUFDQTtB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O1lBQ0gsQ0FBQyxDQUFDLENBRUEsQ0FDRixDQUNQO0FBQ0gsQ0FBQztBQUNELGlFQUFlLE1BQU0iLCJzb3VyY2VzIjpbIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgvZGlzdC9lc20vVXNlclNlc3Npb24uanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL2Rpc3QvZXNtL2ZlZGVyYXRpb24tdXRpbHMuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL2Rpc3QvZXNtL2ZldGNoLXRva2VuLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aC9kaXN0L2VzbS9nZW5lcmF0ZS10b2tlbi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgvZGlzdC9lc20vdmFsaWRhdGUtYXBwLWFjY2Vzcy5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgvbm9kZV9tb2R1bGVzL3RzbGliL3RzbGliLmVzNi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXIvZGlzdC9lc20vYWRkLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllci9kaXN0L2VzbS9kZWxldGUuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyL2Rpc3QvZXNtL3F1ZXJ5LmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllci9kaXN0L2VzbS9xdWVyeVJlbGF0ZWQuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyL2Rpc3QvZXNtL3VwZGF0ZS5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXIvbm9kZV9tb2R1bGVzL3RzbGliL3RzbGliLmVzNi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vcmVxdWVzdC5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvQXJjR0lTUmVxdWVzdEVycm9yLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy9hcHBlbmQtY3VzdG9tLXBhcmFtcy5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvY2xlYW4tdXJsLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy9kZWNvZGUtcXVlcnktc3RyaW5nLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy9lbmNvZGUtZm9ybS1kYXRhLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy9lbmNvZGUtcXVlcnktc3RyaW5nLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy9wcm9jZXNzLXBhcmFtcy5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvd2Fybi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3Qvbm9kZV9tb2R1bGVzL3RzbGliL3RzbGliLmVzNi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9hcGkudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXV0aC50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jbHNzLXN0b3JlLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2NvbnN0YW50cy50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9lc3JpLWFwaS50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9sb2dnZXIudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvdXRpbHMudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC9leHRlcm5hbCBzeXN0ZW0gXCJqaW11LWFyY2dpc1wiIiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS1jb3JlXCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC9leHRlcm5hbCBzeXN0ZW0gXCJqaW11LWNvcmUvcmVhY3RcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtdWlcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svYm9vdHN0cmFwIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL2RlZmluZSBwcm9wZXJ0eSBnZXR0ZXJzIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL2hhc093blByb3BlcnR5IHNob3J0aGFuZCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9tYWtlIG5hbWVzcGFjZSBvYmplY3QiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvcHVibGljUGF0aCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1jb3JlL2xpYi9zZXQtcHVibGljLXBhdGgudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3Mtc2VsZWN0LWxpZmVsaW5lL3NyYy9ydW50aW1lL3dpZGdldC50c3giXSwic291cmNlc0NvbnRlbnQiOlsiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTkgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIEFyY0dJU0F1dGhFcnJvciwgY2xlYW5VcmwsIGVuY29kZVF1ZXJ5U3RyaW5nLCBkZWNvZGVRdWVyeVN0cmluZywgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuaW1wb3J0IHsgZ2VuZXJhdGVUb2tlbiB9IGZyb20gXCIuL2dlbmVyYXRlLXRva2VuXCI7XG5pbXBvcnQgeyBmZXRjaFRva2VuIH0gZnJvbSBcIi4vZmV0Y2gtdG9rZW5cIjtcbmltcG9ydCB7IGNhblVzZU9ubGluZVRva2VuLCBpc0ZlZGVyYXRlZCB9IGZyb20gXCIuL2ZlZGVyYXRpb24tdXRpbHNcIjtcbmltcG9ydCB7IHZhbGlkYXRlQXBwQWNjZXNzIH0gZnJvbSBcIi4vdmFsaWRhdGUtYXBwLWFjY2Vzc1wiO1xuZnVuY3Rpb24gZGVmZXIoKSB7XG4gICAgdmFyIGRlZmVycmVkID0ge1xuICAgICAgICBwcm9taXNlOiBudWxsLFxuICAgICAgICByZXNvbHZlOiBudWxsLFxuICAgICAgICByZWplY3Q6IG51bGwsXG4gICAgfTtcbiAgICBkZWZlcnJlZC5wcm9taXNlID0gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlID0gcmVzb2x2ZTtcbiAgICAgICAgZGVmZXJyZWQucmVqZWN0ID0gcmVqZWN0O1xuICAgIH0pO1xuICAgIHJldHVybiBkZWZlcnJlZDtcbn1cbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IFVzZXJTZXNzaW9uIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aCc7XG4gKiBVc2VyU2Vzc2lvbi5iZWdpbk9BdXRoMih7XG4gKiAgIC8vIHJlZ2lzdGVyIGFuIGFwcCBvZiB5b3VyIG93biB0byBjcmVhdGUgYSB1bmlxdWUgY2xpZW50SWRcbiAqICAgY2xpZW50SWQ6IFwiYWJjMTIzXCIsXG4gKiAgIHJlZGlyZWN0VXJpOiAnaHR0cHM6Ly95b3VyYXBwLmNvbS9hdXRoZW50aWNhdGUuaHRtbCdcbiAqIH0pXG4gKiAgIC50aGVuKHNlc3Npb24pXG4gKiAvLyBvclxuICogbmV3IFVzZXJTZXNzaW9uKHtcbiAqICAgdXNlcm5hbWU6IFwianNtaXRoXCIsXG4gKiAgIHBhc3N3b3JkOiBcIjEyMzQ1NlwiXG4gKiB9KVxuICogLy8gb3JcbiAqIFVzZXJTZXNzaW9uLmRlc2VyaWFsaXplKGNhY2hlKVxuICogYGBgXG4gKiBVc2VkIHRvIGF1dGhlbnRpY2F0ZSBib3RoIEFyY0dJUyBPbmxpbmUgYW5kIEFyY0dJUyBFbnRlcnByaXNlIHVzZXJzLiBgVXNlclNlc3Npb25gIGluY2x1ZGVzIGhlbHBlciBtZXRob2RzIGZvciBbT0F1dGggMi4wXSgvYXJjZ2lzLXJlc3QtanMvZ3VpZGVzL2Jyb3dzZXItYXV0aGVudGljYXRpb24vKSBpbiBib3RoIGJyb3dzZXIgYW5kIHNlcnZlciBhcHBsaWNhdGlvbnMuXG4gKi9cbnZhciBVc2VyU2Vzc2lvbiA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBVc2VyU2Vzc2lvbihvcHRpb25zKSB7XG4gICAgICAgIHRoaXMuY2xpZW50SWQgPSBvcHRpb25zLmNsaWVudElkO1xuICAgICAgICB0aGlzLl9yZWZyZXNoVG9rZW4gPSBvcHRpb25zLnJlZnJlc2hUb2tlbjtcbiAgICAgICAgdGhpcy5fcmVmcmVzaFRva2VuRXhwaXJlcyA9IG9wdGlvbnMucmVmcmVzaFRva2VuRXhwaXJlcztcbiAgICAgICAgdGhpcy51c2VybmFtZSA9IG9wdGlvbnMudXNlcm5hbWU7XG4gICAgICAgIHRoaXMucGFzc3dvcmQgPSBvcHRpb25zLnBhc3N3b3JkO1xuICAgICAgICB0aGlzLl90b2tlbiA9IG9wdGlvbnMudG9rZW47XG4gICAgICAgIHRoaXMuX3Rva2VuRXhwaXJlcyA9IG9wdGlvbnMudG9rZW5FeHBpcmVzO1xuICAgICAgICB0aGlzLnBvcnRhbCA9IG9wdGlvbnMucG9ydGFsXG4gICAgICAgICAgICA/IGNsZWFuVXJsKG9wdGlvbnMucG9ydGFsKVxuICAgICAgICAgICAgOiBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCI7XG4gICAgICAgIHRoaXMuc3NsID0gb3B0aW9ucy5zc2w7XG4gICAgICAgIHRoaXMucHJvdmlkZXIgPSBvcHRpb25zLnByb3ZpZGVyIHx8IFwiYXJjZ2lzXCI7XG4gICAgICAgIHRoaXMudG9rZW5EdXJhdGlvbiA9IG9wdGlvbnMudG9rZW5EdXJhdGlvbiB8fCAyMDE2MDtcbiAgICAgICAgdGhpcy5yZWRpcmVjdFVyaSA9IG9wdGlvbnMucmVkaXJlY3RVcmk7XG4gICAgICAgIHRoaXMucmVmcmVzaFRva2VuVFRMID0gb3B0aW9ucy5yZWZyZXNoVG9rZW5UVEwgfHwgMjAxNjA7XG4gICAgICAgIHRoaXMuc2VydmVyID0gb3B0aW9ucy5zZXJ2ZXI7XG4gICAgICAgIHRoaXMuZmVkZXJhdGVkU2VydmVycyA9IHt9O1xuICAgICAgICB0aGlzLnRydXN0ZWREb21haW5zID0gW107XG4gICAgICAgIC8vIGlmIGEgbm9uLWZlZGVyYXRlZCBzZXJ2ZXIgd2FzIHBhc3NlZCBleHBsaWNpdGx5LCBpdCBzaG91bGQgYmUgdHJ1c3RlZC5cbiAgICAgICAgaWYgKG9wdGlvbnMuc2VydmVyKSB7XG4gICAgICAgICAgICAvLyBpZiB0aGUgdXJsIGluY2x1ZGVzIG1vcmUgdGhhbiAnL2FyY2dpcy8nLCB0cmltIHRoZSByZXN0XG4gICAgICAgICAgICB2YXIgcm9vdCA9IHRoaXMuZ2V0U2VydmVyUm9vdFVybChvcHRpb25zLnNlcnZlcik7XG4gICAgICAgICAgICB0aGlzLmZlZGVyYXRlZFNlcnZlcnNbcm9vdF0gPSB7XG4gICAgICAgICAgICAgICAgdG9rZW46IG9wdGlvbnMudG9rZW4sXG4gICAgICAgICAgICAgICAgZXhwaXJlczogb3B0aW9ucy50b2tlbkV4cGlyZXMsXG4gICAgICAgICAgICB9O1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzID0ge307XG4gICAgfVxuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShVc2VyU2Vzc2lvbi5wcm90b3R5cGUsIFwidG9rZW5cIiwge1xuICAgICAgICAvKipcbiAgICAgICAgICogVGhlIGN1cnJlbnQgQXJjR0lTIE9ubGluZSBvciBBcmNHSVMgRW50ZXJwcmlzZSBgdG9rZW5gLlxuICAgICAgICAgKi9cbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fdG9rZW47XG4gICAgICAgIH0sXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KTtcbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoVXNlclNlc3Npb24ucHJvdG90eXBlLCBcInRva2VuRXhwaXJlc1wiLCB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBUaGUgZXhwaXJhdGlvbiB0aW1lIG9mIHRoZSBjdXJyZW50IGB0b2tlbmAuXG4gICAgICAgICAqL1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl90b2tlbkV4cGlyZXM7XG4gICAgICAgIH0sXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KTtcbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoVXNlclNlc3Npb24ucHJvdG90eXBlLCBcInJlZnJlc2hUb2tlblwiLCB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBUaGUgY3VycmVudCB0b2tlbiB0byBBcmNHSVMgT25saW5lIG9yIEFyY0dJUyBFbnRlcnByaXNlLlxuICAgICAgICAgKi9cbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcmVmcmVzaFRva2VuO1xuICAgICAgICB9LFxuICAgICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSk7XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KFVzZXJTZXNzaW9uLnByb3RvdHlwZSwgXCJyZWZyZXNoVG9rZW5FeHBpcmVzXCIsIHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFRoZSBleHBpcmF0aW9uIHRpbWUgb2YgdGhlIGN1cnJlbnQgYHJlZnJlc2hUb2tlbmAuXG4gICAgICAgICAqL1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9yZWZyZXNoVG9rZW5FeHBpcmVzO1xuICAgICAgICB9LFxuICAgICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSk7XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KFVzZXJTZXNzaW9uLnByb3RvdHlwZSwgXCJ0cnVzdGVkU2VydmVyc1wiLCB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBEZXByZWNhdGVkLCB1c2UgYGZlZGVyYXRlZFNlcnZlcnNgIGluc3RlYWQuXG4gICAgICAgICAqXG4gICAgICAgICAqIEBkZXByZWNhdGVkXG4gICAgICAgICAqL1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiREVQUkVDQVRFRDogdXNlIGZlZGVyYXRlZFNlcnZlcnMgaW5zdGVhZFwiKTtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmZlZGVyYXRlZFNlcnZlcnM7XG4gICAgICAgIH0sXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KTtcbiAgICAvKipcbiAgICAgKiBCZWdpbnMgYSBuZXcgYnJvd3Nlci1iYXNlZCBPQXV0aCAyLjAgc2lnbiBpbi4gSWYgYG9wdGlvbnMucG9wdXBgIGlzIGB0cnVlYCB0aGVcbiAgICAgKiBhdXRoZW50aWNhdGlvbiB3aW5kb3cgd2lsbCBvcGVuIGluIGEgbmV3IHRhYi93aW5kb3cgYW5kIHRoZSBmdW5jdGlvbiB3aWxsIHJldHVyblxuICAgICAqIFByb21pc2UmbHQ7VXNlclNlc3Npb24mZ3Q7LiBPdGhlcndpc2UsIHRoZSB1c2VyIHdpbGwgYmUgcmVkaXJlY3RlZCB0byB0aGVcbiAgICAgKiBhdXRob3JpemF0aW9uIHBhZ2UgaW4gdGhlaXIgY3VycmVudCB0YWIvd2luZG93IGFuZCB0aGUgZnVuY3Rpb24gd2lsbCByZXR1cm4gYHVuZGVmaW5lZGAuXG4gICAgICpcbiAgICAgKiBAYnJvd3Nlck9ubHlcbiAgICAgKi9cbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICAgIFVzZXJTZXNzaW9uLmJlZ2luT0F1dGgyID0gZnVuY3Rpb24gKG9wdGlvbnMsIHdpbikge1xuICAgICAgICBpZiAod2luID09PSB2b2lkIDApIHsgd2luID0gd2luZG93OyB9XG4gICAgICAgIGlmIChvcHRpb25zLmR1cmF0aW9uKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkRFUFJFQ0FURUQ6ICdkdXJhdGlvbicgaXMgZGVwcmVjYXRlZCAtIHVzZSAnZXhwaXJhdGlvbicgaW5zdGVhZFwiKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgX2EgPSBfX2Fzc2lnbih7XG4gICAgICAgICAgICBwb3J0YWw6IFwiaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIixcbiAgICAgICAgICAgIHByb3ZpZGVyOiBcImFyY2dpc1wiLFxuICAgICAgICAgICAgZXhwaXJhdGlvbjogMjAxNjAsXG4gICAgICAgICAgICBwb3B1cDogdHJ1ZSxcbiAgICAgICAgICAgIHBvcHVwV2luZG93RmVhdHVyZXM6IFwiaGVpZ2h0PTQwMCx3aWR0aD02MDAsbWVudWJhcj1ubyxsb2NhdGlvbj15ZXMscmVzaXphYmxlPXllcyxzY3JvbGxiYXJzPXllcyxzdGF0dXM9eWVzXCIsXG4gICAgICAgICAgICBzdGF0ZTogb3B0aW9ucy5jbGllbnRJZCxcbiAgICAgICAgICAgIGxvY2FsZTogXCJcIixcbiAgICAgICAgfSwgb3B0aW9ucyksIHBvcnRhbCA9IF9hLnBvcnRhbCwgcHJvdmlkZXIgPSBfYS5wcm92aWRlciwgY2xpZW50SWQgPSBfYS5jbGllbnRJZCwgZXhwaXJhdGlvbiA9IF9hLmV4cGlyYXRpb24sIHJlZGlyZWN0VXJpID0gX2EucmVkaXJlY3RVcmksIHBvcHVwID0gX2EucG9wdXAsIHBvcHVwV2luZG93RmVhdHVyZXMgPSBfYS5wb3B1cFdpbmRvd0ZlYXR1cmVzLCBzdGF0ZSA9IF9hLnN0YXRlLCBsb2NhbGUgPSBfYS5sb2NhbGUsIHBhcmFtcyA9IF9hLnBhcmFtcztcbiAgICAgICAgdmFyIHVybDtcbiAgICAgICAgaWYgKHByb3ZpZGVyID09PSBcImFyY2dpc1wiKSB7XG4gICAgICAgICAgICB1cmwgPSBwb3J0YWwgKyBcIi9vYXV0aDIvYXV0aG9yaXplP2NsaWVudF9pZD1cIiArIGNsaWVudElkICsgXCImcmVzcG9uc2VfdHlwZT10b2tlbiZleHBpcmF0aW9uPVwiICsgKG9wdGlvbnMuZHVyYXRpb24gfHwgZXhwaXJhdGlvbikgKyBcIiZyZWRpcmVjdF91cmk9XCIgKyBlbmNvZGVVUklDb21wb25lbnQocmVkaXJlY3RVcmkpICsgXCImc3RhdGU9XCIgKyBzdGF0ZSArIFwiJmxvY2FsZT1cIiArIGxvY2FsZTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHVybCA9IHBvcnRhbCArIFwiL29hdXRoMi9zb2NpYWwvYXV0aG9yaXplP2NsaWVudF9pZD1cIiArIGNsaWVudElkICsgXCImc29jaWFsTG9naW5Qcm92aWRlck5hbWU9XCIgKyBwcm92aWRlciArIFwiJmF1dG9BY2NvdW50Q3JlYXRlRm9yU29jaWFsPXRydWUmcmVzcG9uc2VfdHlwZT10b2tlbiZleHBpcmF0aW9uPVwiICsgKG9wdGlvbnMuZHVyYXRpb24gfHwgZXhwaXJhdGlvbikgKyBcIiZyZWRpcmVjdF91cmk9XCIgKyBlbmNvZGVVUklDb21wb25lbnQocmVkaXJlY3RVcmkpICsgXCImc3RhdGU9XCIgKyBzdGF0ZSArIFwiJmxvY2FsZT1cIiArIGxvY2FsZTtcbiAgICAgICAgfVxuICAgICAgICAvLyBhcHBlbmQgYWRkaXRpb25hbCBwYXJhbXNcbiAgICAgICAgaWYgKHBhcmFtcykge1xuICAgICAgICAgICAgdXJsID0gdXJsICsgXCImXCIgKyBlbmNvZGVRdWVyeVN0cmluZyhwYXJhbXMpO1xuICAgICAgICB9XG4gICAgICAgIGlmICghcG9wdXApIHtcbiAgICAgICAgICAgIHdpbi5sb2NhdGlvbi5ocmVmID0gdXJsO1xuICAgICAgICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICAgICAgfVxuICAgICAgICB2YXIgc2Vzc2lvbiA9IGRlZmVyKCk7XG4gICAgICAgIHdpbltcIl9fRVNSSV9SRVNUX0FVVEhfSEFORExFUl9cIiArIGNsaWVudElkXSA9IGZ1bmN0aW9uIChlcnJvclN0cmluZywgb2F1dGhJbmZvU3RyaW5nKSB7XG4gICAgICAgICAgICBpZiAoZXJyb3JTdHJpbmcpIHtcbiAgICAgICAgICAgICAgICB2YXIgZXJyb3IgPSBKU09OLnBhcnNlKGVycm9yU3RyaW5nKTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uLnJlamVjdChuZXcgQXJjR0lTQXV0aEVycm9yKGVycm9yLmVycm9yTWVzc2FnZSwgZXJyb3IuZXJyb3IpKTtcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAob2F1dGhJbmZvU3RyaW5nKSB7XG4gICAgICAgICAgICAgICAgdmFyIG9hdXRoSW5mbyA9IEpTT04ucGFyc2Uob2F1dGhJbmZvU3RyaW5nKTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uLnJlc29sdmUobmV3IFVzZXJTZXNzaW9uKHtcbiAgICAgICAgICAgICAgICAgICAgY2xpZW50SWQ6IGNsaWVudElkLFxuICAgICAgICAgICAgICAgICAgICBwb3J0YWw6IHBvcnRhbCxcbiAgICAgICAgICAgICAgICAgICAgc3NsOiBvYXV0aEluZm8uc3NsLFxuICAgICAgICAgICAgICAgICAgICB0b2tlbjogb2F1dGhJbmZvLnRva2VuLFxuICAgICAgICAgICAgICAgICAgICB0b2tlbkV4cGlyZXM6IG5ldyBEYXRlKG9hdXRoSW5mby5leHBpcmVzKSxcbiAgICAgICAgICAgICAgICAgICAgdXNlcm5hbWU6IG9hdXRoSW5mby51c2VybmFtZSxcbiAgICAgICAgICAgICAgICB9KSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgICAgIHdpbi5vcGVuKHVybCwgXCJvYXV0aC13aW5kb3dcIiwgcG9wdXBXaW5kb3dGZWF0dXJlcyk7XG4gICAgICAgIHJldHVybiBzZXNzaW9uLnByb21pc2U7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBDb21wbGV0ZXMgYSBicm93c2VyLWJhc2VkIE9BdXRoIDIuMCBzaWduIGluLiBJZiBgb3B0aW9ucy5wb3B1cGAgaXMgYHRydWVgIHRoZSB1c2VyXG4gICAgICogd2lsbCBiZSByZXR1cm5lZCB0byB0aGUgcHJldmlvdXMgd2luZG93LiBPdGhlcndpc2UgYSBuZXcgYFVzZXJTZXNzaW9uYFxuICAgICAqIHdpbGwgYmUgcmV0dXJuZWQuIFlvdSBtdXN0IHBhc3MgdGhlIHNhbWUgdmFsdWVzIGZvciBgb3B0aW9ucy5wb3B1cGAgYW5kXG4gICAgICogYG9wdGlvbnMucG9ydGFsYCBhcyB5b3UgdXNlZCBpbiBgYmVnaW5PQXV0aDIoKWAuXG4gICAgICpcbiAgICAgKiBAYnJvd3Nlck9ubHlcbiAgICAgKi9cbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICAgIFVzZXJTZXNzaW9uLmNvbXBsZXRlT0F1dGgyID0gZnVuY3Rpb24gKG9wdGlvbnMsIHdpbikge1xuICAgICAgICBpZiAod2luID09PSB2b2lkIDApIHsgd2luID0gd2luZG93OyB9XG4gICAgICAgIHZhciBfYSA9IF9fYXNzaWduKHsgcG9ydGFsOiBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCIsIHBvcHVwOiB0cnVlIH0sIG9wdGlvbnMpLCBwb3J0YWwgPSBfYS5wb3J0YWwsIGNsaWVudElkID0gX2EuY2xpZW50SWQsIHBvcHVwID0gX2EucG9wdXA7XG4gICAgICAgIGZ1bmN0aW9uIGNvbXBsZXRlU2lnbkluKGVycm9yLCBvYXV0aEluZm8pIHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgdmFyIGhhbmRsZXJGbiA9IHZvaWQgMDtcbiAgICAgICAgICAgICAgICB2YXIgaGFuZGxlckZuTmFtZSA9IFwiX19FU1JJX1JFU1RfQVVUSF9IQU5ETEVSX1wiICsgY2xpZW50SWQ7XG4gICAgICAgICAgICAgICAgaWYgKHBvcHVwKSB7XG4gICAgICAgICAgICAgICAgICAgIC8vIEd1YXJkIGIvYyBJRSBkb2VzIG5vdCBzdXBwb3J0IHdpbmRvdy5vcGVuZXJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHdpbi5vcGVuZXIpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICh3aW4ub3BlbmVyLnBhcmVudCAmJiB3aW4ub3BlbmVyLnBhcmVudFtoYW5kbGVyRm5OYW1lXSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhhbmRsZXJGbiA9IHdpbi5vcGVuZXIucGFyZW50W2hhbmRsZXJGbk5hbWVdO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSBpZiAod2luLm9wZW5lciAmJiB3aW4ub3BlbmVyW2hhbmRsZXJGbk5hbWVdKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gc3VwcG9ydCBwb3Atb3V0IG9hdXRoIGZyb20gd2l0aGluIGFuIGlmcmFtZVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhhbmRsZXJGbiA9IHdpbi5vcGVuZXJbaGFuZGxlckZuTmFtZV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBJRVxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHdpbiAhPT0gd2luLnBhcmVudCAmJiB3aW4ucGFyZW50ICYmIHdpbi5wYXJlbnRbaGFuZGxlckZuTmFtZV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVyRm4gPSB3aW4ucGFyZW50W2hhbmRsZXJGbk5hbWVdO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIC8vIGlmIHdlIGhhdmUgYSBoYW5kbGVyIGZuLCBjYWxsIGl0IGFuZCBjbG9zZSB0aGUgd2luZG93XG4gICAgICAgICAgICAgICAgICAgIGlmIChoYW5kbGVyRm4pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGhhbmRsZXJGbihlcnJvciA/IEpTT04uc3RyaW5naWZ5KGVycm9yKSA6IHVuZGVmaW5lZCwgSlNPTi5zdHJpbmdpZnkob2F1dGhJbmZvKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB3aW4uY2xvc2UoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNBdXRoRXJyb3IoXCJVbmFibGUgdG8gY29tcGxldGUgYXV0aGVudGljYXRpb24uIEl0J3MgcG9zc2libGUgeW91IHNwZWNpZmllZCBwb3B1cCBiYXNlZCBvQXV0aDIgYnV0IG5vIGhhbmRsZXIgZnJvbSBcXFwiYmVnaW5PQXV0aDIoKVxcXCIgcHJlc2VudC4gVGhpcyBnZW5lcmFsbHkgaGFwcGVucyBiZWNhdXNlIHRoZSBcXFwicG9wdXBcXFwiIG9wdGlvbiBkaWZmZXJzIGJldHdlZW4gXFxcImJlZ2luT0F1dGgyKClcXFwiIGFuZCBcXFwiY29tcGxldGVPQXV0aDIoKVxcXCIuXCIpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKGVycm9yKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEFyY0dJU0F1dGhFcnJvcihlcnJvci5lcnJvck1lc3NhZ2UsIGVycm9yLmVycm9yKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBuZXcgVXNlclNlc3Npb24oe1xuICAgICAgICAgICAgICAgIGNsaWVudElkOiBjbGllbnRJZCxcbiAgICAgICAgICAgICAgICBwb3J0YWw6IHBvcnRhbCxcbiAgICAgICAgICAgICAgICBzc2w6IG9hdXRoSW5mby5zc2wsXG4gICAgICAgICAgICAgICAgdG9rZW46IG9hdXRoSW5mby50b2tlbixcbiAgICAgICAgICAgICAgICB0b2tlbkV4cGlyZXM6IG9hdXRoSW5mby5leHBpcmVzLFxuICAgICAgICAgICAgICAgIHVzZXJuYW1lOiBvYXV0aEluZm8udXNlcm5hbWUsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgcGFyYW1zID0gZGVjb2RlUXVlcnlTdHJpbmcod2luLmxvY2F0aW9uLmhhc2gpO1xuICAgICAgICBpZiAoIXBhcmFtcy5hY2Nlc3NfdG9rZW4pIHtcbiAgICAgICAgICAgIHZhciBlcnJvciA9IHZvaWQgMDtcbiAgICAgICAgICAgIHZhciBlcnJvck1lc3NhZ2UgPSBcIlVua25vd24gZXJyb3JcIjtcbiAgICAgICAgICAgIGlmIChwYXJhbXMuZXJyb3IpIHtcbiAgICAgICAgICAgICAgICBlcnJvciA9IHBhcmFtcy5lcnJvcjtcbiAgICAgICAgICAgICAgICBlcnJvck1lc3NhZ2UgPSBwYXJhbXMuZXJyb3JfZGVzY3JpcHRpb247XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gY29tcGxldGVTaWduSW4oeyBlcnJvcjogZXJyb3IsIGVycm9yTWVzc2FnZTogZXJyb3JNZXNzYWdlIH0pO1xuICAgICAgICB9XG4gICAgICAgIHZhciB0b2tlbiA9IHBhcmFtcy5hY2Nlc3NfdG9rZW47XG4gICAgICAgIHZhciBleHBpcmVzID0gbmV3IERhdGUoRGF0ZS5ub3coKSArIHBhcnNlSW50KHBhcmFtcy5leHBpcmVzX2luLCAxMCkgKiAxMDAwIC0gNjAgKiAxMDAwKTtcbiAgICAgICAgdmFyIHVzZXJuYW1lID0gcGFyYW1zLnVzZXJuYW1lO1xuICAgICAgICB2YXIgc3NsID0gcGFyYW1zLnNzbCA9PT0gXCJ0cnVlXCI7XG4gICAgICAgIHJldHVybiBjb21wbGV0ZVNpZ25Jbih1bmRlZmluZWQsIHtcbiAgICAgICAgICAgIHRva2VuOiB0b2tlbixcbiAgICAgICAgICAgIGV4cGlyZXM6IGV4cGlyZXMsXG4gICAgICAgICAgICBzc2w6IHNzbCxcbiAgICAgICAgICAgIHVzZXJuYW1lOiB1c2VybmFtZSxcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXF1ZXN0IHNlc3Npb24gaW5mb3JtYXRpb24gZnJvbSB0aGUgcGFyZW50IGFwcGxpY2F0aW9uXG4gICAgICpcbiAgICAgKiBXaGVuIGFuIGFwcGxpY2F0aW9uIGlzIGVtYmVkZGVkIGludG8gYW5vdGhlciBhcHBsaWNhdGlvbiB2aWEgYW4gSUZyYW1lLCB0aGUgZW1iZWRkZWQgYXBwIGNhblxuICAgICAqIHVzZSBgd2luZG93LnBvc3RNZXNzYWdlYCB0byByZXF1ZXN0IGNyZWRlbnRpYWxzIGZyb20gdGhlIGhvc3QgYXBwbGljYXRpb24uIFRoaXMgZnVuY3Rpb24gd3JhcHNcbiAgICAgKiB0aGF0IGJlaGF2aW9yLlxuICAgICAqXG4gICAgICogVGhlIEFyY0dJUyBBUEkgZm9yIEphdmFzY3JpcHQgaGFzIHRoaXMgYnVpbHQgaW50byB0aGUgSWRlbnRpdHkgTWFuYWdlciBhcyBvZiB0aGUgNC4xOSByZWxlYXNlLlxuICAgICAqXG4gICAgICogTm90ZTogVGhlIHBhcmVudCBhcHBsaWNhdGlvbiB3aWxsIG5vdCByZXNwb25kIGlmIHRoZSBlbWJlZGRlZCBhcHAncyBvcmlnaW4gaXMgbm90OlxuICAgICAqIC0gdGhlIHNhbWUgb3JpZ2luIGFzIHRoZSBwYXJlbnQgb3IgKi5hcmNnaXMuY29tIChKU0FQSSlcbiAgICAgKiAtIGluIHRoZSBsaXN0IG9mIHZhbGlkIGNoaWxkIG9yaWdpbnMgKFJFU1QtSlMpXG4gICAgICpcbiAgICAgKlxuICAgICAqIEBwYXJhbSBwYXJlbnRPcmlnaW4gb3JpZ2luIG9mIHRoZSBwYXJlbnQgZnJhbWUuIFBhc3NlZCBpbnRvIHRoZSBlbWJlZGRlZCBhcHBsaWNhdGlvbiBhcyBgcGFyZW50T3JpZ2luYCBxdWVyeSBwYXJhbVxuICAgICAqIEBicm93c2VyT25seVxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLmZyb21QYXJlbnQgPSBmdW5jdGlvbiAocGFyZW50T3JpZ2luLCB3aW4pIHtcbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQ6IG11c3QgcGFzcyBpbiBhIG1vY2t3aW5kb3cgZm9yIHRlc3RzIHNvIHdlIGNhbid0IGNvdmVyIHRoZSBvdGhlciBicmFuY2ggKi9cbiAgICAgICAgaWYgKCF3aW4gJiYgd2luZG93KSB7XG4gICAgICAgICAgICB3aW4gPSB3aW5kb3c7XG4gICAgICAgIH1cbiAgICAgICAgLy8gRGVjbGFyZSBoYW5kbGVyIG91dHNpZGUgb2YgcHJvbWlzZSBzY29wZSBzbyB3ZSBjYW4gZGV0YWNoIGl0XG4gICAgICAgIHZhciBoYW5kbGVyO1xuICAgICAgICAvLyByZXR1cm4gYSBwcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdoZW4gdGhlIGhhbmRsZXIgcmVjZWl2ZXNcbiAgICAgICAgLy8gc2Vzc2lvbiBpbmZvcm1hdGlvbiBmcm9tIHRoZSBjb3JyZWN0IG9yaWdpblxuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xuICAgICAgICAgICAgLy8gY3JlYXRlIGFuIGV2ZW50IGhhbmRsZXIgdGhhdCBqdXN0IHdyYXBzIHRoZSBwYXJlbnRNZXNzYWdlSGFuZGxlclxuICAgICAgICAgICAgaGFuZGxlciA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICAgICAgICAgIC8vIGVuc3VyZSB3ZSBvbmx5IGxpc3RlbiB0byBldmVudHMgZnJvbSB0aGUgcGFyZW50XG4gICAgICAgICAgICAgICAgaWYgKGV2ZW50LnNvdXJjZSA9PT0gd2luLnBhcmVudCAmJiBldmVudC5kYXRhKSB7XG4gICAgICAgICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVzb2x2ZShVc2VyU2Vzc2lvbi5wYXJlbnRNZXNzYWdlSGFuZGxlcihldmVudCkpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGNhdGNoIChlcnIpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICAvLyBhZGQgbGlzdGVuZXJcbiAgICAgICAgICAgIHdpbi5hZGRFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLCBoYW5kbGVyLCBmYWxzZSk7XG4gICAgICAgICAgICB3aW4ucGFyZW50LnBvc3RNZXNzYWdlKHsgdHlwZTogXCJhcmNnaXM6YXV0aDpyZXF1ZXN0Q3JlZGVudGlhbFwiIH0sIHBhcmVudE9yaWdpbik7XG4gICAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKHNlc3Npb24pIHtcbiAgICAgICAgICAgIHdpbi5yZW1vdmVFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLCBoYW5kbGVyLCBmYWxzZSk7XG4gICAgICAgICAgICByZXR1cm4gc2Vzc2lvbjtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBCZWdpbnMgYSBuZXcgc2VydmVyLWJhc2VkIE9BdXRoIDIuMCBzaWduIGluLiBUaGlzIHdpbGwgcmVkaXJlY3QgdGhlIHVzZXIgdG9cbiAgICAgKiB0aGUgQXJjR0lTIE9ubGluZSBvciBBcmNHSVMgRW50ZXJwcmlzZSBhdXRob3JpemF0aW9uIHBhZ2UuXG4gICAgICpcbiAgICAgKiBAbm9kZU9ubHlcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5hdXRob3JpemUgPSBmdW5jdGlvbiAob3B0aW9ucywgcmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKG9wdGlvbnMuZHVyYXRpb24pIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiREVQUkVDQVRFRDogJ2R1cmF0aW9uJyBpcyBkZXByZWNhdGVkIC0gdXNlICdleHBpcmF0aW9uJyBpbnN0ZWFkXCIpO1xuICAgICAgICB9XG4gICAgICAgIHZhciBfYSA9IF9fYXNzaWduKHsgcG9ydGFsOiBcImh0dHBzOi8vYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIiwgZXhwaXJhdGlvbjogMjAxNjAgfSwgb3B0aW9ucyksIHBvcnRhbCA9IF9hLnBvcnRhbCwgY2xpZW50SWQgPSBfYS5jbGllbnRJZCwgZXhwaXJhdGlvbiA9IF9hLmV4cGlyYXRpb24sIHJlZGlyZWN0VXJpID0gX2EucmVkaXJlY3RVcmk7XG4gICAgICAgIHJlc3BvbnNlLndyaXRlSGVhZCgzMDEsIHtcbiAgICAgICAgICAgIExvY2F0aW9uOiBwb3J0YWwgKyBcIi9vYXV0aDIvYXV0aG9yaXplP2NsaWVudF9pZD1cIiArIGNsaWVudElkICsgXCImZXhwaXJhdGlvbj1cIiArIChvcHRpb25zLmR1cmF0aW9uIHx8IGV4cGlyYXRpb24pICsgXCImcmVzcG9uc2VfdHlwZT1jb2RlJnJlZGlyZWN0X3VyaT1cIiArIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSksXG4gICAgICAgIH0pO1xuICAgICAgICByZXNwb25zZS5lbmQoKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIENvbXBsZXRlcyB0aGUgc2VydmVyLWJhc2VkIE9BdXRoIDIuMCBzaWduIGluIHByb2Nlc3MgYnkgZXhjaGFuZ2luZyB0aGUgYGF1dGhvcml6YXRpb25Db2RlYFxuICAgICAqIGZvciBhIGBhY2Nlc3NfdG9rZW5gLlxuICAgICAqXG4gICAgICogQG5vZGVPbmx5XG4gICAgICovXG4gICAgVXNlclNlc3Npb24uZXhjaGFuZ2VBdXRob3JpemF0aW9uQ29kZSA9IGZ1bmN0aW9uIChvcHRpb25zLCBhdXRob3JpemF0aW9uQ29kZSkge1xuICAgICAgICB2YXIgX2EgPSBfX2Fzc2lnbih7XG4gICAgICAgICAgICBwb3J0YWw6IFwiaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIixcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlblRUTDogMjAxNjAsXG4gICAgICAgIH0sIG9wdGlvbnMpLCBwb3J0YWwgPSBfYS5wb3J0YWwsIGNsaWVudElkID0gX2EuY2xpZW50SWQsIHJlZGlyZWN0VXJpID0gX2EucmVkaXJlY3RVcmksIHJlZnJlc2hUb2tlblRUTCA9IF9hLnJlZnJlc2hUb2tlblRUTDtcbiAgICAgICAgcmV0dXJuIGZldGNoVG9rZW4ocG9ydGFsICsgXCIvb2F1dGgyL3Rva2VuXCIsIHtcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgIGdyYW50X3R5cGU6IFwiYXV0aG9yaXphdGlvbl9jb2RlXCIsXG4gICAgICAgICAgICAgICAgY2xpZW50X2lkOiBjbGllbnRJZCxcbiAgICAgICAgICAgICAgICByZWRpcmVjdF91cmk6IHJlZGlyZWN0VXJpLFxuICAgICAgICAgICAgICAgIGNvZGU6IGF1dGhvcml6YXRpb25Db2RlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHJldHVybiBuZXcgVXNlclNlc3Npb24oe1xuICAgICAgICAgICAgICAgIGNsaWVudElkOiBjbGllbnRJZCxcbiAgICAgICAgICAgICAgICBwb3J0YWw6IHBvcnRhbCxcbiAgICAgICAgICAgICAgICBzc2w6IHJlc3BvbnNlLnNzbCxcbiAgICAgICAgICAgICAgICByZWRpcmVjdFVyaTogcmVkaXJlY3RVcmksXG4gICAgICAgICAgICAgICAgcmVmcmVzaFRva2VuOiByZXNwb25zZS5yZWZyZXNoVG9rZW4sXG4gICAgICAgICAgICAgICAgcmVmcmVzaFRva2VuVFRMOiByZWZyZXNoVG9rZW5UVEwsXG4gICAgICAgICAgICAgICAgcmVmcmVzaFRva2VuRXhwaXJlczogbmV3IERhdGUoRGF0ZS5ub3coKSArIChyZWZyZXNoVG9rZW5UVEwgLSAxKSAqIDYwICogMTAwMCksXG4gICAgICAgICAgICAgICAgdG9rZW46IHJlc3BvbnNlLnRva2VuLFxuICAgICAgICAgICAgICAgIHRva2VuRXhwaXJlczogcmVzcG9uc2UuZXhwaXJlcyxcbiAgICAgICAgICAgICAgICB1c2VybmFtZTogcmVzcG9uc2UudXNlcm5hbWUsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICBVc2VyU2Vzc2lvbi5kZXNlcmlhbGl6ZSA9IGZ1bmN0aW9uIChzdHIpIHtcbiAgICAgICAgdmFyIG9wdGlvbnMgPSBKU09OLnBhcnNlKHN0cik7XG4gICAgICAgIHJldHVybiBuZXcgVXNlclNlc3Npb24oe1xuICAgICAgICAgICAgY2xpZW50SWQ6IG9wdGlvbnMuY2xpZW50SWQsXG4gICAgICAgICAgICByZWZyZXNoVG9rZW46IG9wdGlvbnMucmVmcmVzaFRva2VuLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuRXhwaXJlczogbmV3IERhdGUob3B0aW9ucy5yZWZyZXNoVG9rZW5FeHBpcmVzKSxcbiAgICAgICAgICAgIHVzZXJuYW1lOiBvcHRpb25zLnVzZXJuYW1lLFxuICAgICAgICAgICAgcGFzc3dvcmQ6IG9wdGlvbnMucGFzc3dvcmQsXG4gICAgICAgICAgICB0b2tlbjogb3B0aW9ucy50b2tlbixcbiAgICAgICAgICAgIHRva2VuRXhwaXJlczogbmV3IERhdGUob3B0aW9ucy50b2tlbkV4cGlyZXMpLFxuICAgICAgICAgICAgcG9ydGFsOiBvcHRpb25zLnBvcnRhbCxcbiAgICAgICAgICAgIHNzbDogb3B0aW9ucy5zc2wsXG4gICAgICAgICAgICB0b2tlbkR1cmF0aW9uOiBvcHRpb25zLnRva2VuRHVyYXRpb24sXG4gICAgICAgICAgICByZWRpcmVjdFVyaTogb3B0aW9ucy5yZWRpcmVjdFVyaSxcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlblRUTDogb3B0aW9ucy5yZWZyZXNoVG9rZW5UVEwsXG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogVHJhbnNsYXRlcyBhdXRoZW50aWNhdGlvbiBmcm9tIHRoZSBmb3JtYXQgdXNlZCBpbiB0aGUgW0FyY0dJUyBBUEkgZm9yIEphdmFTY3JpcHRdKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL2phdmFzY3JpcHQvKS5cbiAgICAgKlxuICAgICAqIGBgYGpzXG4gICAgICogVXNlclNlc3Npb24uZnJvbUNyZWRlbnRpYWwoe1xuICAgICAqICAgdXNlcklkOiBcImpzbWl0aFwiLFxuICAgICAqICAgdG9rZW46IFwic2VjcmV0XCJcbiAgICAgKiB9KTtcbiAgICAgKiBgYGBcbiAgICAgKlxuICAgICAqIEByZXR1cm5zIFVzZXJTZXNzaW9uXG4gICAgICovXG4gICAgVXNlclNlc3Npb24uZnJvbUNyZWRlbnRpYWwgPSBmdW5jdGlvbiAoY3JlZGVudGlhbCkge1xuICAgICAgICAvLyBBdCBBcmNHSVMgT25saW5lIDkuMSwgY3JlZGVudGlhbHMgbm8gbG9uZ2VyIGluY2x1ZGUgdGhlIHNzbCBhbmQgZXhwaXJlcyBwcm9wZXJ0aWVzXG4gICAgICAgIC8vIEhlcmUsIHdlIHByb3ZpZGUgZGVmYXVsdCB2YWx1ZXMgZm9yIHRoZW0gdG8gY292ZXIgdGhpcyBjb25kaXRpb25cbiAgICAgICAgdmFyIHNzbCA9IHR5cGVvZiBjcmVkZW50aWFsLnNzbCAhPT0gXCJ1bmRlZmluZWRcIiA/IGNyZWRlbnRpYWwuc3NsIDogdHJ1ZTtcbiAgICAgICAgdmFyIGV4cGlyZXMgPSBjcmVkZW50aWFsLmV4cGlyZXMgfHwgRGF0ZS5ub3coKSArIDcyMDAwMDA7IC8qIDIgaG91cnMgKi9cbiAgICAgICAgcmV0dXJuIG5ldyBVc2VyU2Vzc2lvbih7XG4gICAgICAgICAgICBwb3J0YWw6IGNyZWRlbnRpYWwuc2VydmVyLmluY2x1ZGVzKFwic2hhcmluZy9yZXN0XCIpXG4gICAgICAgICAgICAgICAgPyBjcmVkZW50aWFsLnNlcnZlclxuICAgICAgICAgICAgICAgIDogY3JlZGVudGlhbC5zZXJ2ZXIgKyBcIi9zaGFyaW5nL3Jlc3RcIixcbiAgICAgICAgICAgIHNzbDogc3NsLFxuICAgICAgICAgICAgdG9rZW46IGNyZWRlbnRpYWwudG9rZW4sXG4gICAgICAgICAgICB1c2VybmFtZTogY3JlZGVudGlhbC51c2VySWQsXG4gICAgICAgICAgICB0b2tlbkV4cGlyZXM6IG5ldyBEYXRlKGV4cGlyZXMpLFxuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEhhbmRsZSB0aGUgcmVzcG9uc2UgZnJvbSB0aGUgcGFyZW50XG4gICAgICogQHBhcmFtIGV2ZW50IERPTSBFdmVudFxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnBhcmVudE1lc3NhZ2VIYW5kbGVyID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIGlmIChldmVudC5kYXRhLnR5cGUgPT09IFwiYXJjZ2lzOmF1dGg6Y3JlZGVudGlhbFwiKSB7XG4gICAgICAgICAgICByZXR1cm4gVXNlclNlc3Npb24uZnJvbUNyZWRlbnRpYWwoZXZlbnQuZGF0YS5jcmVkZW50aWFsKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoZXZlbnQuZGF0YS50eXBlID09PSBcImFyY2dpczphdXRoOmVycm9yXCIpIHtcbiAgICAgICAgICAgIHZhciBlcnIgPSBuZXcgRXJyb3IoZXZlbnQuZGF0YS5lcnJvci5tZXNzYWdlKTtcbiAgICAgICAgICAgIGVyci5uYW1lID0gZXZlbnQuZGF0YS5lcnJvci5uYW1lO1xuICAgICAgICAgICAgdGhyb3cgZXJyO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiVW5rbm93biBtZXNzYWdlIHR5cGUuXCIpO1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIGF1dGhlbnRpY2F0aW9uIGluIGEgZm9ybWF0IHVzZWFibGUgaW4gdGhlIFtBcmNHSVMgQVBJIGZvciBKYXZhU2NyaXB0XShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9qYXZhc2NyaXB0LykuXG4gICAgICpcbiAgICAgKiBgYGBqc1xuICAgICAqIGVzcmlJZC5yZWdpc3RlclRva2VuKHNlc3Npb24udG9DcmVkZW50aWFsKCkpO1xuICAgICAqIGBgYFxuICAgICAqXG4gICAgICogQHJldHVybnMgSUNyZWRlbnRpYWxcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUudG9DcmVkZW50aWFsID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgZXhwaXJlczogdGhpcy50b2tlbkV4cGlyZXMuZ2V0VGltZSgpLFxuICAgICAgICAgICAgc2VydmVyOiB0aGlzLnBvcnRhbCxcbiAgICAgICAgICAgIHNzbDogdGhpcy5zc2wsXG4gICAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICAgIHVzZXJJZDogdGhpcy51c2VybmFtZSxcbiAgICAgICAgfTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgaW5mb3JtYXRpb24gYWJvdXQgdGhlIGN1cnJlbnRseSBsb2dnZWQgaW4gW3VzZXJdKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3QvdXNlcnMtZ3JvdXBzLWFuZC1pdGVtcy91c2VyLmh0bSkuIFN1YnNlcXVlbnQgY2FsbHMgd2lsbCAqbm90KiByZXN1bHQgaW4gYWRkaXRpb25hbCB3ZWIgdHJhZmZpYy5cbiAgICAgKlxuICAgICAqIGBgYGpzXG4gICAgICogc2Vzc2lvbi5nZXRVc2VyKClcbiAgICAgKiAgIC50aGVuKHJlc3BvbnNlID0+IHtcbiAgICAgKiAgICAgY29uc29sZS5sb2cocmVzcG9uc2Uucm9sZSk7IC8vIFwib3JnX2FkbWluXCJcbiAgICAgKiAgIH0pXG4gICAgICogYGBgXG4gICAgICpcbiAgICAgKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdC4gTk9URTogYHJhd1Jlc3BvbnNlYCBpcyBub3Qgc3VwcG9ydGVkIGJ5IHRoaXMgb3BlcmF0aW9uLlxuICAgICAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBkYXRhIGZyb20gdGhlIHJlc3BvbnNlLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRVc2VyID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIGlmICh0aGlzLl9wZW5kaW5nVXNlclJlcXVlc3QpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nVXNlclJlcXVlc3Q7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAodGhpcy5fdXNlcikge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzLl91c2VyKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHZhciB1cmwgPSB0aGlzLnBvcnRhbCArIFwiL2NvbW11bml0eS9zZWxmXCI7XG4gICAgICAgICAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKF9fYXNzaWduKHsgaHR0cE1ldGhvZDogXCJHRVRcIiwgYXV0aGVudGljYXRpb246IHRoaXMgfSwgcmVxdWVzdE9wdGlvbnMpLCB7IHJhd1Jlc3BvbnNlOiBmYWxzZSB9KTtcbiAgICAgICAgICAgIHRoaXMuX3BlbmRpbmdVc2VyUmVxdWVzdCA9IHJlcXVlc3QodXJsLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIF90aGlzLl91c2VyID0gcmVzcG9uc2U7XG4gICAgICAgICAgICAgICAgX3RoaXMuX3BlbmRpbmdVc2VyUmVxdWVzdCA9IG51bGw7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1VzZXJSZXF1ZXN0O1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIGluZm9ybWF0aW9uIGFib3V0IHRoZSBjdXJyZW50bHkgbG9nZ2VkIGluIHVzZXIncyBbcG9ydGFsXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3VzZXJzLWdyb3Vwcy1hbmQtaXRlbXMvcG9ydGFsLXNlbGYuaHRtKS4gU3Vic2VxdWVudCBjYWxscyB3aWxsICpub3QqIHJlc3VsdCBpbiBhZGRpdGlvbmFsIHdlYiB0cmFmZmljLlxuICAgICAqXG4gICAgICogYGBganNcbiAgICAgKiBzZXNzaW9uLmdldFBvcnRhbCgpXG4gICAgICogICAudGhlbihyZXNwb25zZSA9PiB7XG4gICAgICogICAgIGNvbnNvbGUubG9nKHBvcnRhbC5uYW1lKTsgLy8gXCJDaXR5IG9mIC4uLlwiXG4gICAgICogICB9KVxuICAgICAqIGBgYFxuICAgICAqXG4gICAgICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3QuIE5PVEU6IGByYXdSZXNwb25zZWAgaXMgbm90IHN1cHBvcnRlZCBieSB0aGlzIG9wZXJhdGlvbi5cbiAgICAgKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgZGF0YSBmcm9tIHRoZSByZXNwb25zZS5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0UG9ydGFsID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIGlmICh0aGlzLl9wZW5kaW5nUG9ydGFsUmVxdWVzdCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdQb3J0YWxSZXF1ZXN0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKHRoaXMuX3BvcnRhbEluZm8pIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy5fcG9ydGFsSW5mbyk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICB2YXIgdXJsID0gdGhpcy5wb3J0YWwgKyBcIi9wb3J0YWxzL3NlbGZcIjtcbiAgICAgICAgICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oX19hc3NpZ24oeyBodHRwTWV0aG9kOiBcIkdFVFwiLCBhdXRoZW50aWNhdGlvbjogdGhpcyB9LCByZXF1ZXN0T3B0aW9ucyksIHsgcmF3UmVzcG9uc2U6IGZhbHNlIH0pO1xuICAgICAgICAgICAgdGhpcy5fcGVuZGluZ1BvcnRhbFJlcXVlc3QgPSByZXF1ZXN0KHVybCwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICBfdGhpcy5fcG9ydGFsSW5mbyA9IHJlc3BvbnNlO1xuICAgICAgICAgICAgICAgIF90aGlzLl9wZW5kaW5nUG9ydGFsUmVxdWVzdCA9IG51bGw7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1BvcnRhbFJlcXVlc3Q7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIHVzZXJuYW1lIGZvciB0aGUgY3VycmVudGx5IGxvZ2dlZCBpbiBbdXNlcl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC91c2Vycy1ncm91cHMtYW5kLWl0ZW1zL3VzZXIuaHRtKS4gU3Vic2VxdWVudCBjYWxscyB3aWxsICpub3QqIHJlc3VsdCBpbiBhZGRpdGlvbmFsIHdlYiB0cmFmZmljLiBUaGlzIGlzIGFsc28gdXNlZCBpbnRlcm5hbGx5IHdoZW4gYSB1c2VybmFtZSBpcyByZXF1aXJlZCBmb3Igc29tZSByZXF1ZXN0cyBidXQgaXMgbm90IHByZXNlbnQgaW4gdGhlIG9wdGlvbnMuXG4gICAgICpcbiAgICAgKiAgICAqIGBgYGpzXG4gICAgICogc2Vzc2lvbi5nZXRVc2VybmFtZSgpXG4gICAgICogICAudGhlbihyZXNwb25zZSA9PiB7XG4gICAgICogICAgIGNvbnNvbGUubG9nKHJlc3BvbnNlKTsgLy8gXCJjYXNleV9qb25lc1wiXG4gICAgICogICB9KVxuICAgICAqIGBgYFxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRVc2VybmFtZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKHRoaXMudXNlcm5hbWUpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy51c2VybmFtZSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAodGhpcy5fdXNlcikge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzLl91c2VyLnVzZXJuYW1lKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmdldFVzZXIoKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHVzZXIudXNlcm5hbWU7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgLyoqXG4gICAgICogR2V0cyBhbiBhcHByb3ByaWF0ZSB0b2tlbiBmb3IgdGhlIGdpdmVuIFVSTC4gSWYgYHBvcnRhbGAgaXMgQXJjR0lTIE9ubGluZSBhbmRcbiAgICAgKiB0aGUgcmVxdWVzdCBpcyB0byBhbiBBcmNHSVMgT25saW5lIGRvbWFpbiBgdG9rZW5gIHdpbGwgYmUgdXNlZC4gSWYgdGhlIHJlcXVlc3RcbiAgICAgKiBpcyB0byB0aGUgY3VycmVudCBgcG9ydGFsYCB0aGUgY3VycmVudCBgdG9rZW5gIHdpbGwgYWxzbyBiZSB1c2VkLiBIb3dldmVyIGlmXG4gICAgICogdGhlIHJlcXVlc3QgaXMgdG8gYW4gdW5rbm93biBzZXJ2ZXIgd2Ugd2lsbCB2YWxpZGF0ZSB0aGUgc2VydmVyIHdpdGggYSByZXF1ZXN0XG4gICAgICogdG8gb3VyIGN1cnJlbnQgYHBvcnRhbGAuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFRva2VuID0gZnVuY3Rpb24gKHVybCwgcmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgaWYgKGNhblVzZU9ubGluZVRva2VuKHRoaXMucG9ydGFsLCB1cmwpKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5nZXRGcmVzaFRva2VuKHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChuZXcgUmVnRXhwKHRoaXMucG9ydGFsLCBcImlcIikudGVzdCh1cmwpKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5nZXRGcmVzaFRva2VuKHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmdldFRva2VuRm9yU2VydmVyKHVybCwgcmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBHZXQgYXBwbGljYXRpb24gYWNjZXNzIGluZm9ybWF0aW9uIGZvciB0aGUgY3VycmVudCB1c2VyXG4gICAgICogc2VlIGB2YWxpZGF0ZUFwcEFjY2Vzc2AgZnVuY3Rpb24gZm9yIGRldGFpbHNcbiAgICAgKlxuICAgICAqIEBwYXJhbSBjbGllbnRJZCBhcHBsaWNhdGlvbiBjbGllbnQgaWRcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUudmFsaWRhdGVBcHBBY2Nlc3MgPSBmdW5jdGlvbiAoY2xpZW50SWQpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2V0VG9rZW4odGhpcy5wb3J0YWwpLnRoZW4oZnVuY3Rpb24gKHRva2VuKSB7XG4gICAgICAgICAgICByZXR1cm4gdmFsaWRhdGVBcHBBY2Nlc3ModG9rZW4sIGNsaWVudElkKTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUudG9KU09OID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgY2xpZW50SWQ6IHRoaXMuY2xpZW50SWQsXG4gICAgICAgICAgICByZWZyZXNoVG9rZW46IHRoaXMucmVmcmVzaFRva2VuLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuRXhwaXJlczogdGhpcy5yZWZyZXNoVG9rZW5FeHBpcmVzLFxuICAgICAgICAgICAgdXNlcm5hbWU6IHRoaXMudXNlcm5hbWUsXG4gICAgICAgICAgICBwYXNzd29yZDogdGhpcy5wYXNzd29yZCxcbiAgICAgICAgICAgIHRva2VuOiB0aGlzLnRva2VuLFxuICAgICAgICAgICAgdG9rZW5FeHBpcmVzOiB0aGlzLnRva2VuRXhwaXJlcyxcbiAgICAgICAgICAgIHBvcnRhbDogdGhpcy5wb3J0YWwsXG4gICAgICAgICAgICBzc2w6IHRoaXMuc3NsLFxuICAgICAgICAgICAgdG9rZW5EdXJhdGlvbjogdGhpcy50b2tlbkR1cmF0aW9uLFxuICAgICAgICAgICAgcmVkaXJlY3RVcmk6IHRoaXMucmVkaXJlY3RVcmksXG4gICAgICAgICAgICByZWZyZXNoVG9rZW5UVEw6IHRoaXMucmVmcmVzaFRva2VuVFRMLFxuICAgICAgICB9O1xuICAgIH07XG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnNlcmlhbGl6ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KHRoaXMpO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogRm9yIGEgXCJIb3N0XCIgYXBwIHRoYXQgZW1iZWRzIG90aGVyIHBsYXRmb3JtIGFwcHMgdmlhIGlmcmFtZXMsIGFmdGVyIGF1dGhlbnRpY2F0aW5nIHRoZSB1c2VyXG4gICAgICogYW5kIGNyZWF0aW5nIGEgVXNlclNlc3Npb24sIHRoZSBhcHAgY2FuIHRoZW4gZW5hYmxlIFwicG9zdCBtZXNzYWdlXCIgc3R5bGUgYXV0aGVudGljYXRpb24gYnkgY2FsbGluZ1xuICAgICAqIHRoaXMgbWV0aG9kLlxuICAgICAqXG4gICAgICogSW50ZXJuYWxseSB0aGlzIGFkZHMgYW4gZXZlbnQgbGlzdGVuZXIgb24gd2luZG93IGZvciB0aGUgYG1lc3NhZ2VgIGV2ZW50XG4gICAgICpcbiAgICAgKiBAcGFyYW0gdmFsaWRDaGlsZE9yaWdpbnMgQXJyYXkgb2Ygb3JpZ2lucyB0aGF0IGFyZSBhbGxvd2VkIHRvIHJlcXVlc3QgYXV0aGVudGljYXRpb24gZnJvbSB0aGUgaG9zdCBhcHBcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZW5hYmxlUG9zdE1lc3NhZ2VBdXRoID0gZnVuY3Rpb24gKHZhbGlkQ2hpbGRPcmlnaW5zLCB3aW4pIHtcbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQ6IG11c3QgcGFzcyBpbiBhIG1vY2t3aW5kb3cgZm9yIHRlc3RzIHNvIHdlIGNhbid0IGNvdmVyIHRoZSBvdGhlciBicmFuY2ggKi9cbiAgICAgICAgaWYgKCF3aW4gJiYgd2luZG93KSB7XG4gICAgICAgICAgICB3aW4gPSB3aW5kb3c7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5faG9zdEhhbmRsZXIgPSB0aGlzLmNyZWF0ZVBvc3RNZXNzYWdlSGFuZGxlcih2YWxpZENoaWxkT3JpZ2lucyk7XG4gICAgICAgIHdpbi5hZGRFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLCB0aGlzLl9ob3N0SGFuZGxlciwgZmFsc2UpO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogRm9yIGEgXCJIb3N0XCIgYXBwIHRoYXQgaGFzIGVtYmVkZGVkIG90aGVyIHBsYXRmb3JtIGFwcHMgdmlhIGlmcmFtZXMsIHdoZW4gdGhlIGhvc3QgbmVlZHNcbiAgICAgKiB0byB0cmFuc2l0aW9uIHJvdXRlcywgaXQgc2hvdWxkIGNhbGwgYFVzZXJTZXNzaW9uLmRpc2FibGVQb3N0TWVzc2FnZUF1dGgoKWAgdG8gcmVtb3ZlXG4gICAgICogdGhlIGV2ZW50IGxpc3RlbmVyIGFuZCBwcmV2ZW50IG1lbW9yeSBsZWFrc1xuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5kaXNhYmxlUG9zdE1lc3NhZ2VBdXRoID0gZnVuY3Rpb24gKHdpbikge1xuICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dDogbXVzdCBwYXNzIGluIGEgbW9ja3dpbmRvdyBmb3IgdGVzdHMgc28gd2UgY2FuJ3QgY292ZXIgdGhlIG90aGVyIGJyYW5jaCAqL1xuICAgICAgICBpZiAoIXdpbiAmJiB3aW5kb3cpIHtcbiAgICAgICAgICAgIHdpbiA9IHdpbmRvdztcbiAgICAgICAgfVxuICAgICAgICB3aW4ucmVtb3ZlRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgdGhpcy5faG9zdEhhbmRsZXIsIGZhbHNlKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIE1hbnVhbGx5IHJlZnJlc2hlcyB0aGUgY3VycmVudCBgdG9rZW5gIGFuZCBgdG9rZW5FeHBpcmVzYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUucmVmcmVzaFNlc3Npb24gPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgLy8gbWFrZSBzdXJlIHN1YnNlcXVlbnQgY2FsbHMgdG8gZ2V0VXNlcigpIGRvbid0IHJldHVybmVkIGNhY2hlZCBtZXRhZGF0YVxuICAgICAgICB0aGlzLl91c2VyID0gbnVsbDtcbiAgICAgICAgaWYgKHRoaXMudXNlcm5hbWUgJiYgdGhpcy5wYXNzd29yZCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMucmVmcmVzaFdpdGhVc2VybmFtZUFuZFBhc3N3b3JkKHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5jbGllbnRJZCAmJiB0aGlzLnJlZnJlc2hUb2tlbikge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMucmVmcmVzaFdpdGhSZWZyZXNoVG9rZW4oKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IEFyY0dJU0F1dGhFcnJvcihcIlVuYWJsZSB0byByZWZyZXNoIHRva2VuLlwiKSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBEZXRlcm1pbmVzIHRoZSByb290IG9mIHRoZSBBcmNHSVMgU2VydmVyIG9yIFBvcnRhbCBmb3IgYSBnaXZlbiBVUkwuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gdXJsIHRoZSBVUmwgdG8gZGV0ZXJtaW5lIHRoZSByb290IHVybCBmb3IuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFNlcnZlclJvb3RVcmwgPSBmdW5jdGlvbiAodXJsKSB7XG4gICAgICAgIHZhciByb290ID0gY2xlYW5VcmwodXJsKS5zcGxpdCgvXFwvcmVzdChcXC9hZG1pbik/XFwvc2VydmljZXMoPzpcXC98I3xcXD98JCkvKVswXTtcbiAgICAgICAgdmFyIF9hID0gcm9vdC5tYXRjaCgvKGh0dHBzPzpcXC9cXC8pKC4rKS8pLCBtYXRjaCA9IF9hWzBdLCBwcm90b2NvbCA9IF9hWzFdLCBkb21haW5BbmRQYXRoID0gX2FbMl07XG4gICAgICAgIHZhciBfYiA9IGRvbWFpbkFuZFBhdGguc3BsaXQoXCIvXCIpLCBkb21haW4gPSBfYlswXSwgcGF0aCA9IF9iLnNsaWNlKDEpO1xuICAgICAgICAvLyBvbmx5IHRoZSBkb21haW4gaXMgbG93ZXJjYXNlZCBiZWNhdXNlIGluIHNvbWUgY2FzZXMgYW4gb3JnIGlkIG1pZ2h0IGJlXG4gICAgICAgIC8vIGluIHRoZSBwYXRoIHdoaWNoIGNhbm5vdCBiZSBsb3dlcmNhc2VkLlxuICAgICAgICByZXR1cm4gXCJcIiArIHByb3RvY29sICsgZG9tYWluLnRvTG93ZXJDYXNlKCkgKyBcIi9cIiArIHBhdGguam9pbihcIi9cIik7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSBwcm9wZXIgW2BjcmVkZW50aWFsc2BdIG9wdGlvbiBmb3IgYGZldGNoYCBmb3IgYSBnaXZlbiBkb21haW4uXG4gICAgICogU2VlIFt0cnVzdGVkIHNlcnZlcl0oaHR0cHM6Ly9lbnRlcnByaXNlLmFyY2dpcy5jb20vZW4vcG9ydGFsL2xhdGVzdC9hZG1pbmlzdGVyL3dpbmRvd3MvY29uZmlndXJlLXNlY3VyaXR5Lmh0bSNFU1JJX1NFQ1RJT04xXzcwQ0MxNTlCMzU0MDQ0MEFCMzI1QkU1RDg5REJFOTRBKS5cbiAgICAgKiBVc2VkIGludGVybmFsbHkgYnkgdW5kZXJseWluZyByZXF1ZXN0IG1ldGhvZHMgdG8gYWRkIHN1cHBvcnQgZm9yIHNwZWNpZmljIHNlY3VyaXR5IGNvbnNpZGVyYXRpb25zLlxuICAgICAqXG4gICAgICogQHBhcmFtIHVybCBUaGUgdXJsIG9mIHRoZSByZXF1ZXN0XG4gICAgICogQHJldHVybnMgXCJpbmNsdWRlXCIgb3IgXCJzYW1lLW9yaWdpblwiXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldERvbWFpbkNyZWRlbnRpYWxzID0gZnVuY3Rpb24gKHVybCkge1xuICAgICAgICBpZiAoIXRoaXMudHJ1c3RlZERvbWFpbnMgfHwgIXRoaXMudHJ1c3RlZERvbWFpbnMubGVuZ3RoKSB7XG4gICAgICAgICAgICByZXR1cm4gXCJzYW1lLW9yaWdpblwiO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0aGlzLnRydXN0ZWREb21haW5zLnNvbWUoZnVuY3Rpb24gKGRvbWFpbldpdGhQcm90b2NvbCkge1xuICAgICAgICAgICAgcmV0dXJuIHVybC5zdGFydHNXaXRoKGRvbWFpbldpdGhQcm90b2NvbCk7XG4gICAgICAgIH0pXG4gICAgICAgICAgICA/IFwiaW5jbHVkZVwiXG4gICAgICAgICAgICA6IFwic2FtZS1vcmlnaW5cIjtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybiBhIGZ1bmN0aW9uIHRoYXQgY2xvc2VzIG92ZXIgdGhlIHZhbGlkT3JpZ2lucyBhcnJheSBhbmRcbiAgICAgKiBjYW4gYmUgdXNlZCBhcyBhbiBldmVudCBoYW5kbGVyIGZvciB0aGUgYG1lc3NhZ2VgIGV2ZW50XG4gICAgICpcbiAgICAgKiBAcGFyYW0gdmFsaWRPcmlnaW5zIEFycmF5IG9mIHZhbGlkIG9yaWdpbnNcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuY3JlYXRlUG9zdE1lc3NhZ2VIYW5kbGVyID0gZnVuY3Rpb24gKHZhbGlkT3JpZ2lucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICAvLyByZXR1cm4gYSBmdW5jdGlvbiB0aGF0IGNsb3NlcyBvdmVyIHRoZSB2YWxpZE9yaWdpbnMgYW5kXG4gICAgICAgIC8vIGhhcyBhY2Nlc3MgdG8gdGhlIGNyZWRlbnRpYWxcbiAgICAgICAgcmV0dXJuIGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICAgICAgLy8gVmVyaWZ5IHRoYXQgdGhlIG9yaWdpbiBpcyB2YWxpZFxuICAgICAgICAgICAgLy8gTm90ZTogZG8gbm90IHVzZSByZWdleCdzIGhlcmUuIHZhbGlkT3JpZ2lucyBpcyBhbiBhcnJheSBzbyB3ZSdyZSBjaGVja2luZyB0aGF0IHRoZSBldmVudCdzIG9yaWdpblxuICAgICAgICAgICAgLy8gaXMgaW4gdGhlIGFycmF5IHZpYSBleGFjdCBtYXRjaC4gTW9yZSBpbmZvIGFib3V0IGF2b2lkaW5nIHBvc3RNZXNzYWdlIHhzcyBpc3N1ZXMgaGVyZVxuICAgICAgICAgICAgLy8gaHR0cHM6Ly9qbGFqYXJhLmdpdGxhYi5pby93ZWIvMjAyMC8wNy8xNy9Eb21fWFNTX1Bvc3RNZXNzYWdlXzIuaHRtbCN0aXBzYnlwYXNzZXMtaW4tcG9zdG1lc3NhZ2UtdnVsbmVyYWJpbGl0aWVzXG4gICAgICAgICAgICB2YXIgaXNWYWxpZE9yaWdpbiA9IHZhbGlkT3JpZ2lucy5pbmRleE9mKGV2ZW50Lm9yaWdpbikgPiAtMTtcbiAgICAgICAgICAgIC8vIEpTQVBJIGhhbmRsZXMgdGhpcyBzbGlnaHRseSBkaWZmZXJlbnRseSAtIGluc3RlYWQgb2YgY2hlY2tpbmcgYSBsaXN0LCBpdCB3aWxsIHJlc3BvbmQgaWZcbiAgICAgICAgICAgIC8vIGV2ZW50Lm9yaWdpbiA9PT0gd2luZG93LmxvY2F0aW9uLm9yaWdpbiB8fCBldmVudC5vcmlnaW4uZW5kc1dpdGgoJy5hcmNnaXMuY29tJylcbiAgICAgICAgICAgIC8vIEZvciBIdWIsIGFuZCB0byBlbmFibGUgY3Jvc3MgZG9tYWluIGRlYnVnZ2luZyB3aXRoIHBvcnQncyBpbiB1cmxzLCB3ZSBhcmUgb3B0aW5nIHRvXG4gICAgICAgICAgICAvLyB1c2UgYSBsaXN0IG9mIHZhbGlkIG9yaWdpbnNcbiAgICAgICAgICAgIC8vIEVuc3VyZSB0aGUgbWVzc2FnZSB0eXBlIGlzIHNvbWV0aGluZyB3ZSB3YW50IHRvIGhhbmRsZVxuICAgICAgICAgICAgdmFyIGlzVmFsaWRUeXBlID0gZXZlbnQuZGF0YS50eXBlID09PSBcImFyY2dpczphdXRoOnJlcXVlc3RDcmVkZW50aWFsXCI7XG4gICAgICAgICAgICB2YXIgaXNUb2tlblZhbGlkID0gX3RoaXMudG9rZW5FeHBpcmVzLmdldFRpbWUoKSA+IERhdGUubm93KCk7XG4gICAgICAgICAgICBpZiAoaXNWYWxpZE9yaWdpbiAmJiBpc1ZhbGlkVHlwZSkge1xuICAgICAgICAgICAgICAgIHZhciBtc2cgPSB7fTtcbiAgICAgICAgICAgICAgICBpZiAoaXNUb2tlblZhbGlkKSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjcmVkZW50aWFsID0gX3RoaXMudG9DcmVkZW50aWFsKCk7XG4gICAgICAgICAgICAgICAgICAgIC8vIGFyY2dpczphdXRoOmVycm9yIHdpdGgge25hbWU6IFwiXCIsIG1lc3NhZ2U6IFwiXCJ9XG4gICAgICAgICAgICAgICAgICAgIC8vIHRoZSBmb2xsb3dpbmcgbGluZSBhbGxvd3MgdXMgdG8gY29uZm9ybSB0byBvdXIgc3BlYyB3aXRob3V0IGNoYW5naW5nIG90aGVyIGRlcGVuZGVkLW9uIGZ1bmN0aW9uYWxpdHlcbiAgICAgICAgICAgICAgICAgICAgLy8gaHR0cHM6Ly9naXRodWIuY29tL0VzcmkvYXJjZ2lzLXJlc3QtanMvYmxvYi9tYXN0ZXIvcGFja2FnZXMvYXJjZ2lzLXJlc3QtYXV0aC9wb3N0LW1lc3NhZ2UtYXV0aC1zcGVjLm1kI2FyY2dpc2F1dGhjcmVkZW50aWFsXG4gICAgICAgICAgICAgICAgICAgIGNyZWRlbnRpYWwuc2VydmVyID0gY3JlZGVudGlhbC5zZXJ2ZXIucmVwbGFjZShcIi9zaGFyaW5nL3Jlc3RcIiwgXCJcIik7XG4gICAgICAgICAgICAgICAgICAgIG1zZyA9IHsgdHlwZTogXCJhcmNnaXM6YXV0aDpjcmVkZW50aWFsXCIsIGNyZWRlbnRpYWw6IGNyZWRlbnRpYWwgfTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIC8vIFJldHVybiBhbiBlcnJvclxuICAgICAgICAgICAgICAgICAgICBtc2cgPSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0eXBlOiBcImFyY2dpczphdXRoOmVycm9yXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICBlcnJvcjoge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5hbWU6IFwidG9rZW5FeHBpcmVkRXJyb3JcIixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBtZXNzYWdlOiBcIlNlc3Npb24gdG9rZW4gd2FzIGV4cGlyZWQsIGFuZCBub3QgcmV0dXJuZWQgdG8gdGhlIGNoaWxkIGFwcGxpY2F0aW9uXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBldmVudC5zb3VyY2UucG9zdE1lc3NhZ2UobXNnLCBldmVudC5vcmlnaW4pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuICAgIH07XG4gICAgLyoqXG4gICAgICogVmFsaWRhdGVzIHRoYXQgYSBnaXZlbiBVUkwgaXMgcHJvcGVybHkgZmVkZXJhdGVkIHdpdGggb3VyIGN1cnJlbnQgYHBvcnRhbGAuXG4gICAgICogQXR0ZW1wdHMgdG8gdXNlIHRoZSBpbnRlcm5hbCBgZmVkZXJhdGVkU2VydmVyc2AgY2FjaGUgZmlyc3QuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFRva2VuRm9yU2VydmVyID0gZnVuY3Rpb24gKHVybCwgcmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgLy8gcmVxdWVzdHMgdG8gL3Jlc3Qvc2VydmljZXMvIGFuZCAvcmVzdC9hZG1pbi9zZXJ2aWNlcy8gYXJlIGJvdGggdmFsaWRcbiAgICAgICAgLy8gRmVkZXJhdGVkIHNlcnZlcnMgbWF5IGhhdmUgaW5jb25zaXN0ZW50IGNhc2luZywgc28gbG93ZXJDYXNlIGl0XG4gICAgICAgIHZhciByb290ID0gdGhpcy5nZXRTZXJ2ZXJSb290VXJsKHVybCk7XG4gICAgICAgIHZhciBleGlzdGluZ1Rva2VuID0gdGhpcy5mZWRlcmF0ZWRTZXJ2ZXJzW3Jvb3RdO1xuICAgICAgICBpZiAoZXhpc3RpbmdUb2tlbiAmJlxuICAgICAgICAgICAgZXhpc3RpbmdUb2tlbi5leHBpcmVzICYmXG4gICAgICAgICAgICBleGlzdGluZ1Rva2VuLmV4cGlyZXMuZ2V0VGltZSgpID4gRGF0ZS5ub3coKSkge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShleGlzdGluZ1Rva2VuLnRva2VuKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbcm9vdF0pIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tyb290XTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tyb290XSA9IHRoaXMuZmV0Y2hBdXRob3JpemVkRG9tYWlucygpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIHJlcXVlc3Qocm9vdCArIFwiL3Jlc3QvaW5mb1wiLCB7XG4gICAgICAgICAgICAgICAgY3JlZGVudGlhbHM6IF90aGlzLmdldERvbWFpbkNyZWRlbnRpYWxzKHVybCksXG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZS5vd25pbmdTeXN0ZW1VcmwpIHtcbiAgICAgICAgICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgICAgICAgICAqIGlmIHRoaXMgc2VydmVyIGlzIG5vdCBvd25lZCBieSB0aGlzIHBvcnRhbFxuICAgICAgICAgICAgICAgICAgICAgKiBiYWlsIG91dCB3aXRoIGFuIGVycm9yIHNpbmNlIHdlIGtub3cgd2Ugd29udFxuICAgICAgICAgICAgICAgICAgICAgKiBiZSBhYmxlIHRvIGdlbmVyYXRlIGEgdG9rZW5cbiAgICAgICAgICAgICAgICAgICAgICovXG4gICAgICAgICAgICAgICAgICAgIGlmICghaXNGZWRlcmF0ZWQocmVzcG9uc2Uub3duaW5nU3lzdGVtVXJsLCBfdGhpcy5wb3J0YWwpKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgQXJjR0lTQXV0aEVycm9yKHVybCArIFwiIGlzIG5vdCBmZWRlcmF0ZWQgd2l0aCBcIiArIF90aGlzLnBvcnRhbCArIFwiLlwiLCBcIk5PVF9GRURFUkFURURcIik7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAgICAgICAgICAgICAqIGlmIHRoZSBzZXJ2ZXIgaXMgZmVkZXJhdGVkLCB1c2UgdGhlIHJlbGV2YW50IHRva2VuIGVuZHBvaW50LlxuICAgICAgICAgICAgICAgICAgICAgICAgICovXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVxdWVzdChyZXNwb25zZS5vd25pbmdTeXN0ZW1VcmwgKyBcIi9zaGFyaW5nL3Jlc3QvaW5mb1wiLCByZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAocmVzcG9uc2UuYXV0aEluZm8gJiZcbiAgICAgICAgICAgICAgICAgICAgX3RoaXMuZmVkZXJhdGVkU2VydmVyc1tyb290XSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICAgICAgICAgKiBpZiBpdHMgYSBzdGFuZC1hbG9uZSBpbnN0YW5jZSBvZiBBcmNHSVMgU2VydmVyIHRoYXQgZG9lc24ndCBhZHZlcnRpc2VcbiAgICAgICAgICAgICAgICAgICAgICogZmVkZXJhdGlvbiwgYnV0IHRoZSByb290IHNlcnZlciB1cmwgaXMgcmVjb2duaXplZCwgdXNlIGl0cyBidWlsdCBpbiB0b2tlbiBlbmRwb2ludC5cbiAgICAgICAgICAgICAgICAgICAgICovXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoe1xuICAgICAgICAgICAgICAgICAgICAgICAgYXV0aEluZm86IHJlc3BvbnNlLmF1dGhJbmZvLFxuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNBdXRoRXJyb3IodXJsICsgXCIgaXMgbm90IGZlZGVyYXRlZCB3aXRoIGFueSBwb3J0YWwgYW5kIGlzIG5vdCBleHBsaWNpdGx5IHRydXN0ZWQuXCIsIFwiTk9UX0ZFREVSQVRFRFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5hdXRoSW5mby50b2tlblNlcnZpY2VzVXJsO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAodG9rZW5TZXJ2aWNlc1VybCkge1xuICAgICAgICAgICAgICAgIC8vIGFuIGV4cGlyZWQgdG9rZW4gY2FudCBiZSB1c2VkIHRvIGdlbmVyYXRlIGEgbmV3IHRva2VuXG4gICAgICAgICAgICAgICAgaWYgKF90aGlzLnRva2VuICYmIF90aGlzLnRva2VuRXhwaXJlcy5nZXRUaW1lKCkgPiBEYXRlLm5vdygpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBnZW5lcmF0ZVRva2VuKHRva2VuU2VydmljZXNVcmwsIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuOiBfdGhpcy50b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZXJ2ZXJVcmw6IHVybCxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBleHBpcmF0aW9uOiBfdGhpcy50b2tlbkR1cmF0aW9uLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNsaWVudDogXCJyZWZlcmVyXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgLy8gZ2VuZXJhdGUgYW4gZW50aXJlbHkgZnJlc2ggdG9rZW4gaWYgbmVjZXNzYXJ5XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZ2VuZXJhdGVUb2tlbih0b2tlblNlcnZpY2VzVXJsLCB7XG4gICAgICAgICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB1c2VybmFtZTogX3RoaXMudXNlcm5hbWUsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzc3dvcmQ6IF90aGlzLnBhc3N3b3JkLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4cGlyYXRpb246IF90aGlzLnRva2VuRHVyYXRpb24sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xpZW50OiBcInJlZmVyZXJcIixcbiAgICAgICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5fdG9rZW4gPSByZXNwb25zZS50b2tlbjtcbiAgICAgICAgICAgICAgICAgICAgICAgIF90aGlzLl90b2tlbkV4cGlyZXMgPSBuZXcgRGF0ZShyZXNwb25zZS5leHBpcmVzKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICBfdGhpcy5mZWRlcmF0ZWRTZXJ2ZXJzW3Jvb3RdID0ge1xuICAgICAgICAgICAgICAgICAgICBleHBpcmVzOiBuZXcgRGF0ZShyZXNwb25zZS5leHBpcmVzKSxcbiAgICAgICAgICAgICAgICAgICAgdG9rZW46IHJlc3BvbnNlLnRva2VuLFxuICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgICAgZGVsZXRlIF90aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tyb290XTtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UudG9rZW47XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tyb290XTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgYW4gdW5leHBpcmVkIHRva2VuIGZvciB0aGUgY3VycmVudCBgcG9ydGFsYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0RnJlc2hUb2tlbiA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBpZiAodGhpcy50b2tlbiAmJiAhdGhpcy50b2tlbkV4cGlyZXMpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy50b2tlbik7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMudG9rZW4gJiZcbiAgICAgICAgICAgIHRoaXMudG9rZW5FeHBpcmVzICYmXG4gICAgICAgICAgICB0aGlzLnRva2VuRXhwaXJlcy5nZXRUaW1lKCkgPiBEYXRlLm5vdygpKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMudG9rZW4pO1xuICAgICAgICB9XG4gICAgICAgIGlmICghdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbdGhpcy5wb3J0YWxdKSB7XG4gICAgICAgICAgICB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1t0aGlzLnBvcnRhbF0gPSB0aGlzLnJlZnJlc2hTZXNzaW9uKHJlcXVlc3RPcHRpb25zKS50aGVuKGZ1bmN0aW9uIChzZXNzaW9uKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW190aGlzLnBvcnRhbF0gPSBudWxsO1xuICAgICAgICAgICAgICAgIHJldHVybiBzZXNzaW9uLnRva2VuO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3RoaXMucG9ydGFsXTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJlZnJlc2hlcyB0aGUgY3VycmVudCBgdG9rZW5gIGFuZCBgdG9rZW5FeHBpcmVzYCB3aXRoIGB1c2VybmFtZWAgYW5kXG4gICAgICogYHBhc3N3b3JkYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUucmVmcmVzaFdpdGhVc2VybmFtZUFuZFBhc3N3b3JkID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oeyBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICB1c2VybmFtZTogdGhpcy51c2VybmFtZSxcbiAgICAgICAgICAgICAgICBwYXNzd29yZDogdGhpcy5wYXNzd29yZCxcbiAgICAgICAgICAgICAgICBleHBpcmF0aW9uOiB0aGlzLnRva2VuRHVyYXRpb24sXG4gICAgICAgICAgICB9IH0sIHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgcmV0dXJuIGdlbmVyYXRlVG9rZW4odGhpcy5wb3J0YWwgKyBcIi9nZW5lcmF0ZVRva2VuXCIsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICBfdGhpcy5fdG9rZW4gPSByZXNwb25zZS50b2tlbjtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbkV4cGlyZXMgPSBuZXcgRGF0ZShyZXNwb25zZS5leHBpcmVzKTtcbiAgICAgICAgICAgIHJldHVybiBfdGhpcztcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZWZyZXNoZXMgdGhlIGN1cnJlbnQgYHRva2VuYCBhbmQgYHRva2VuRXhwaXJlc2Agd2l0aCBgcmVmcmVzaFRva2VuYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUucmVmcmVzaFdpdGhSZWZyZXNoVG9rZW4gPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgaWYgKHRoaXMucmVmcmVzaFRva2VuICYmXG4gICAgICAgICAgICB0aGlzLnJlZnJlc2hUb2tlbkV4cGlyZXMgJiZcbiAgICAgICAgICAgIHRoaXMucmVmcmVzaFRva2VuRXhwaXJlcy5nZXRUaW1lKCkgPCBEYXRlLm5vdygpKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5yZWZyZXNoUmVmcmVzaFRva2VuKHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKHsgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgY2xpZW50X2lkOiB0aGlzLmNsaWVudElkLFxuICAgICAgICAgICAgICAgIHJlZnJlc2hfdG9rZW46IHRoaXMucmVmcmVzaFRva2VuLFxuICAgICAgICAgICAgICAgIGdyYW50X3R5cGU6IFwicmVmcmVzaF90b2tlblwiLFxuICAgICAgICAgICAgfSB9LCByZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIHJldHVybiBmZXRjaFRva2VuKHRoaXMucG9ydGFsICsgXCIvb2F1dGgyL3Rva2VuXCIsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICBfdGhpcy5fdG9rZW4gPSByZXNwb25zZS50b2tlbjtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbkV4cGlyZXMgPSByZXNwb25zZS5leHBpcmVzO1xuICAgICAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEV4Y2hhbmdlcyBhbiB1bmV4cGlyZWQgYHJlZnJlc2hUb2tlbmAgZm9yIGEgbmV3IG9uZSwgYWxzbyB1cGRhdGVzIGB0b2tlbmAgYW5kXG4gICAgICogYHRva2VuRXhwaXJlc2AuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnJlZnJlc2hSZWZyZXNoVG9rZW4gPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbih7IHBhcmFtczoge1xuICAgICAgICAgICAgICAgIGNsaWVudF9pZDogdGhpcy5jbGllbnRJZCxcbiAgICAgICAgICAgICAgICByZWZyZXNoX3Rva2VuOiB0aGlzLnJlZnJlc2hUb2tlbixcbiAgICAgICAgICAgICAgICByZWRpcmVjdF91cmk6IHRoaXMucmVkaXJlY3RVcmksXG4gICAgICAgICAgICAgICAgZ3JhbnRfdHlwZTogXCJleGNoYW5nZV9yZWZyZXNoX3Rva2VuXCIsXG4gICAgICAgICAgICB9IH0sIHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgcmV0dXJuIGZldGNoVG9rZW4odGhpcy5wb3J0YWwgKyBcIi9vYXV0aDIvdG9rZW5cIiwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbiA9IHJlc3BvbnNlLnRva2VuO1xuICAgICAgICAgICAgX3RoaXMuX3Rva2VuRXhwaXJlcyA9IHJlc3BvbnNlLmV4cGlyZXM7XG4gICAgICAgICAgICBfdGhpcy5fcmVmcmVzaFRva2VuID0gcmVzcG9uc2UucmVmcmVzaFRva2VuO1xuICAgICAgICAgICAgX3RoaXMuX3JlZnJlc2hUb2tlbkV4cGlyZXMgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgKF90aGlzLnJlZnJlc2hUb2tlblRUTCAtIDEpICogNjAgKiAxMDAwKTtcbiAgICAgICAgICAgIHJldHVybiBfdGhpcztcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBlbnN1cmVzIHRoYXQgdGhlIGF1dGhvcml6ZWRDcm9zc09yaWdpbkRvbWFpbnMgYXJlIG9idGFpbmVkIGZyb20gdGhlIHBvcnRhbCBhbmQgY2FjaGVkXG4gICAgICogc28gd2UgY2FuIGNoZWNrIHRoZW0gbGF0ZXIuXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyB0aGlzXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmZldGNoQXV0aG9yaXplZERvbWFpbnMgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIC8vIGlmIHRoaXMgdG9rZW4gaXMgZm9yIGEgc3BlY2lmaWMgc2VydmVyIG9yIHdlIGRvbid0IGhhdmUgYSBwb3J0YWxcbiAgICAgICAgLy8gZG9uJ3QgZ2V0IHRoZSBwb3J0YWwgaW5mbyBiZWNhdXNlIHdlIGNhbnQgZ2V0IHRoZSBhdXRob3JpemVkQ3Jvc3NPcmlnaW5Eb21haW5zXG4gICAgICAgIGlmICh0aGlzLnNlcnZlciB8fCAhdGhpcy5wb3J0YWwpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcyk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXMuZ2V0UG9ydGFsKCkudGhlbihmdW5jdGlvbiAocG9ydGFsSW5mbykge1xuICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgKiBTcGVjaWZpYyBkb21haW5zIGNhbiBiZSBjb25maWd1cmVkIGFzIHNlY3VyZS5lc3JpLmNvbSBvciBodHRwczovL3NlY3VyZS5lc3JpLmNvbSB0aGlzXG4gICAgICAgICAgICAgKiBub3JtYWxpemVzIHRvIGh0dHBzOi8vc2VjdXJlLmVzcmkuY29tIHNvIHdlIGNhbiB1c2Ugc3RhcnRzV2l0aCBsYXRlci5cbiAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgaWYgKHBvcnRhbEluZm8uYXV0aG9yaXplZENyb3NzT3JpZ2luRG9tYWlucyAmJlxuICAgICAgICAgICAgICAgIHBvcnRhbEluZm8uYXV0aG9yaXplZENyb3NzT3JpZ2luRG9tYWlucy5sZW5ndGgpIHtcbiAgICAgICAgICAgICAgICBfdGhpcy50cnVzdGVkRG9tYWlucyA9IHBvcnRhbEluZm8uYXV0aG9yaXplZENyb3NzT3JpZ2luRG9tYWluc1xuICAgICAgICAgICAgICAgICAgICAuZmlsdGVyKGZ1bmN0aW9uIChkKSB7IHJldHVybiAhZC5zdGFydHNXaXRoKFwiaHR0cDovL1wiKTsgfSlcbiAgICAgICAgICAgICAgICAgICAgLm1hcChmdW5jdGlvbiAoZCkge1xuICAgICAgICAgICAgICAgICAgICBpZiAoZC5zdGFydHNXaXRoKFwiaHR0cHM6Ly9cIikpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaHR0cHM6Ly9cIiArIGQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBfdGhpcztcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICByZXR1cm4gVXNlclNlc3Npb247XG59KCkpO1xuZXhwb3J0IHsgVXNlclNlc3Npb24gfTtcbi8vIyBzb3VyY2VNYXBwaW5nVVJMPVVzZXJTZXNzaW9uLmpzLm1hcCIsImltcG9ydCB7IGNsZWFuVXJsIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICogVXNlZCB0byB0ZXN0IGlmIGEgVVJMIGlzIGFuIEFyY0dJUyBPbmxpbmUgVVJMXG4gKi9cbnZhciBhcmNnaXNPbmxpbmVVcmxSZWdleCA9IC9eaHR0cHM/OlxcL1xcLyhcXFMrKVxcLmFyY2dpc1xcLmNvbS4rLztcbi8qKlxuICogVXNlZCB0byB0ZXN0IGlmIGEgVVJMIGlzIHByb2R1Y3Rpb24gQXJjR0lTIE9ubGluZSBQb3J0YWxcbiAqL1xudmFyIGFyY2dpc09ubGluZVBvcnRhbFJlZ2V4ID0gL15odHRwcz86XFwvXFwvKGRldnxkZXZleHR8cWF8cWFleHR8d3d3KVxcLmFyY2dpc1xcLmNvbVxcL3NoYXJpbmdcXC9yZXN0Ky87XG4vKipcbiAqIFVzZWQgdG8gdGVzdCBpZiBhIFVSTCBpcyBhbiBBcmNHSVMgT25saW5lIE9yZ2FuaXphdGlvbiBQb3J0YWxcbiAqL1xudmFyIGFyY2dpc09ubGluZU9yZ1BvcnRhbFJlZ2V4ID0gL15odHRwcz86XFwvXFwvKD86W2EtejAtOS1dK1xcLm1hcHMoZGV2fGRldmV4dHxxYXxxYWV4dCk/KT8uYXJjZ2lzXFwuY29tXFwvc2hhcmluZ1xcL3Jlc3QvO1xuZXhwb3J0IGZ1bmN0aW9uIGlzT25saW5lKHVybCkge1xuICAgIHJldHVybiBhcmNnaXNPbmxpbmVVcmxSZWdleC50ZXN0KHVybCk7XG59XG5leHBvcnQgZnVuY3Rpb24gbm9ybWFsaXplT25saW5lUG9ydGFsVXJsKHBvcnRhbFVybCkge1xuICAgIGlmICghYXJjZ2lzT25saW5lVXJsUmVnZXgudGVzdChwb3J0YWxVcmwpKSB7XG4gICAgICAgIHJldHVybiBwb3J0YWxVcmw7XG4gICAgfVxuICAgIHN3aXRjaCAoZ2V0T25saW5lRW52aXJvbm1lbnQocG9ydGFsVXJsKSkge1xuICAgICAgICBjYXNlIFwiZGV2XCI6XG4gICAgICAgICAgICByZXR1cm4gXCJodHRwczovL2RldmV4dC5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiO1xuICAgICAgICBjYXNlIFwicWFcIjpcbiAgICAgICAgICAgIHJldHVybiBcImh0dHBzOi8vcWFleHQuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIjtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHJldHVybiBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCI7XG4gICAgfVxufVxuZXhwb3J0IGZ1bmN0aW9uIGdldE9ubGluZUVudmlyb25tZW50KHVybCkge1xuICAgIGlmICghYXJjZ2lzT25saW5lVXJsUmVnZXgudGVzdCh1cmwpKSB7XG4gICAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICB2YXIgbWF0Y2ggPSB1cmwubWF0Y2goYXJjZ2lzT25saW5lVXJsUmVnZXgpO1xuICAgIHZhciBzdWJkb21haW4gPSBtYXRjaFsxXS5zcGxpdChcIi5cIikucG9wKCk7XG4gICAgaWYgKHN1YmRvbWFpbi5pbmNsdWRlcyhcImRldlwiKSkge1xuICAgICAgICByZXR1cm4gXCJkZXZcIjtcbiAgICB9XG4gICAgaWYgKHN1YmRvbWFpbi5pbmNsdWRlcyhcInFhXCIpKSB7XG4gICAgICAgIHJldHVybiBcInFhXCI7XG4gICAgfVxuICAgIHJldHVybiBcInByb2R1Y3Rpb25cIjtcbn1cbmV4cG9ydCBmdW5jdGlvbiBpc0ZlZGVyYXRlZChvd25pbmdTeXN0ZW1VcmwsIHBvcnRhbFVybCkge1xuICAgIHZhciBub3JtYWxpemVkUG9ydGFsVXJsID0gY2xlYW5Vcmwobm9ybWFsaXplT25saW5lUG9ydGFsVXJsKHBvcnRhbFVybCkpLnJlcGxhY2UoL2h0dHBzPzpcXC9cXC8vLCBcIlwiKTtcbiAgICB2YXIgbm9ybWFsaXplZE93bmluZ1N5c3RlbVVybCA9IGNsZWFuVXJsKG93bmluZ1N5c3RlbVVybCkucmVwbGFjZSgvaHR0cHM/OlxcL1xcLy8sIFwiXCIpO1xuICAgIHJldHVybiBuZXcgUmVnRXhwKG5vcm1hbGl6ZWRPd25pbmdTeXN0ZW1VcmwsIFwiaVwiKS50ZXN0KG5vcm1hbGl6ZWRQb3J0YWxVcmwpO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGNhblVzZU9ubGluZVRva2VuKHBvcnRhbFVybCwgcmVxdWVzdFVybCkge1xuICAgIHZhciBwb3J0YWxJc09ubGluZSA9IGlzT25saW5lKHBvcnRhbFVybCk7XG4gICAgdmFyIHJlcXVlc3RJc09ubGluZSA9IGlzT25saW5lKHJlcXVlc3RVcmwpO1xuICAgIHZhciBwb3J0YWxFbnYgPSBnZXRPbmxpbmVFbnZpcm9ubWVudChwb3J0YWxVcmwpO1xuICAgIHZhciByZXF1ZXN0RW52ID0gZ2V0T25saW5lRW52aXJvbm1lbnQocmVxdWVzdFVybCk7XG4gICAgaWYgKHBvcnRhbElzT25saW5lICYmIHJlcXVlc3RJc09ubGluZSAmJiBwb3J0YWxFbnYgPT09IHJlcXVlc3RFbnYpIHtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIHJldHVybiBmYWxzZTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWZlZGVyYXRpb24tdXRpbHMuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IHJlcXVlc3QgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuZXhwb3J0IGZ1bmN0aW9uIGZldGNoVG9rZW4odXJsLCByZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciBvcHRpb25zID0gcmVxdWVzdE9wdGlvbnM7XG4gICAgLy8gd2UgZ2VuZXJhdGUgYSByZXNwb25zZSwgc28gd2UgY2FuJ3QgcmV0dXJuIHRoZSByYXcgcmVzcG9uc2VcbiAgICBvcHRpb25zLnJhd1Jlc3BvbnNlID0gZmFsc2U7XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2YXIgciA9IHtcbiAgICAgICAgICAgIHRva2VuOiByZXNwb25zZS5hY2Nlc3NfdG9rZW4sXG4gICAgICAgICAgICB1c2VybmFtZTogcmVzcG9uc2UudXNlcm5hbWUsXG4gICAgICAgICAgICBleHBpcmVzOiBuZXcgRGF0ZShcbiAgICAgICAgICAgIC8vIGNvbnZlcnQgc2Vjb25kcyBpbiByZXNwb25zZSB0byBtaWxsaXNlY29uZHMgYW5kIGFkZCB0aGUgdmFsdWUgdG8gdGhlIGN1cnJlbnQgdGltZSB0byBjYWxjdWxhdGUgYSBzdGF0aWMgZXhwaXJhdGlvbiB0aW1lc3RhbXBcbiAgICAgICAgICAgIERhdGUubm93KCkgKyAocmVzcG9uc2UuZXhwaXJlc19pbiAqIDEwMDAgLSAxMDAwKSksXG4gICAgICAgICAgICBzc2w6IHJlc3BvbnNlLnNzbCA9PT0gdHJ1ZVxuICAgICAgICB9O1xuICAgICAgICBpZiAocmVzcG9uc2UucmVmcmVzaF90b2tlbikge1xuICAgICAgICAgICAgci5yZWZyZXNoVG9rZW4gPSByZXNwb25zZS5yZWZyZXNoX3Rva2VuO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiByO1xuICAgIH0pO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZmV0Y2gtdG9rZW4uanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgcmVxdWVzdCwgTk9ERUpTX0RFRkFVTFRfUkVGRVJFUl9IRUFERVIsIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbmV4cG9ydCBmdW5jdGlvbiBnZW5lcmF0ZVRva2VuKHVybCwgcmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgb3B0aW9ucyA9IHJlcXVlc3RPcHRpb25zO1xuICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBlbHNlICovXG4gICAgaWYgKHR5cGVvZiB3aW5kb3cgIT09IFwidW5kZWZpbmVkXCIgJiZcbiAgICAgICAgd2luZG93LmxvY2F0aW9uICYmXG4gICAgICAgIHdpbmRvdy5sb2NhdGlvbi5ob3N0KSB7XG4gICAgICAgIG9wdGlvbnMucGFyYW1zLnJlZmVyZXIgPSB3aW5kb3cubG9jYXRpb24uaG9zdDtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIG9wdGlvbnMucGFyYW1zLnJlZmVyZXIgPSBOT0RFSlNfREVGQVVMVF9SRUZFUkVSX0hFQURFUjtcbiAgICB9XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWdlbmVyYXRlLXRva2VuLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxOC0yMDIwIEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IHJlcXVlc3QgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKiBWYWxpZGF0ZXMgdGhhdCB0aGUgdXNlciBoYXMgYWNjZXNzIHRvIHRoZSBhcHBsaWNhdGlvblxuICogYW5kIGlmIHRoZXkgdXNlciBzaG91bGQgYmUgcHJlc2VudGVkIGEgXCJWaWV3IE9ubHlcIiBtb2RlXG4gKlxuICogVGhpcyBpcyBvbmx5IG5lZWRlZC92YWxpZCBmb3IgRXNyaSBhcHBsaWNhdGlvbnMgdGhhdCBhcmUgXCJsaWNlbnNlZFwiXG4gKiBhbmQgc2hpcHBlZCBpbiBBcmNHSVMgT25saW5lIG9yIEFyY0dJUyBFbnRlcnByaXNlLiBNb3N0IGN1c3RvbSBhcHBsaWNhdGlvbnNcbiAqIHNob3VsZCBub3QgbmVlZCBvciB1c2UgdGhpcy5cbiAqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgdmFsaWRhdGVBcHBBY2Nlc3MgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1hdXRoJztcbiAqXG4gKiByZXR1cm4gdmFsaWRhdGVBcHBBY2Nlc3MoJ3lvdXItdG9rZW4nLCAndGhlQ2xpZW50SWQnKVxuICogLnRoZW4oKHJlc3VsdCkgPT4ge1xuICogICAgaWYgKCFyZXN1bHQudmFsdWUpIHtcbiAqICAgICAgLy8gcmVkaXJlY3Qgb3Igc2hvdyBzb21lIG90aGVyIHVpXG4gKiAgICB9IGVsc2Uge1xuICogICAgICBpZiAocmVzdWx0LnZpZXdPbmx5VXNlclR5cGVBcHApIHtcbiAqICAgICAgICAvLyB1c2UgdGhpcyB0byBpbmZvcm0geW91ciBhcHAgdG8gc2hvdyBhIFwiVmlldyBPbmx5XCIgbW9kZVxuICogICAgICB9XG4gKiAgICB9XG4gKiB9KVxuICogLmNhdGNoKChlcnIpID0+IHtcbiAqICAvLyB0d28gcG9zc2libGUgZXJyb3JzXG4gKiAgLy8gaW52YWxpZCBjbGllbnRJZDoge1wiZXJyb3JcIjp7XCJjb2RlXCI6NDAwLFwibWVzc2FnZUNvZGVcIjpcIkdXTV8wMDA3XCIsXCJtZXNzYWdlXCI6XCJJbnZhbGlkIHJlcXVlc3RcIixcImRldGFpbHNcIjpbXX19XG4gKiAgLy8gaW52YWxpZCB0b2tlbjoge1wiZXJyb3JcIjp7XCJjb2RlXCI6NDk4LFwibWVzc2FnZVwiOlwiSW52YWxpZCB0b2tlbi5cIixcImRldGFpbHNcIjpbXX19XG4gKiB9KVxuICogYGBgXG4gKlxuICogTm90ZTogVGhpcyBpcyBvbmx5IHVzYWJsZSBieSBFc3JpIGFwcGxpY2F0aW9ucyBob3N0ZWQgb24gKmFyY2dpcy5jb20sICplc3JpLmNvbSBvciB3aXRoaW5cbiAqIGFuIEFyY0dJUyBFbnRlcnByaXNlIGluc3RhbGxhdGlvbi4gQ3VzdG9tIGFwcGxpY2F0aW9ucyBjYW4gbm90IHVzZSB0aGlzLlxuICpcbiAqIEBwYXJhbSB0b2tlbiBwbGF0Zm9ybSB0b2tlblxuICogQHBhcmFtIGNsaWVudElkIGFwcGxpY2F0aW9uIGNsaWVudCBpZFxuICogQHBhcmFtIHBvcnRhbCBPcHRpb25hbFxuICovXG5leHBvcnQgZnVuY3Rpb24gdmFsaWRhdGVBcHBBY2Nlc3ModG9rZW4sIGNsaWVudElkLCBwb3J0YWwpIHtcbiAgICBpZiAocG9ydGFsID09PSB2b2lkIDApIHsgcG9ydGFsID0gXCJodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiOyB9XG4gICAgdmFyIHVybCA9IHBvcnRhbCArIFwiL29hdXRoMi92YWxpZGF0ZUFwcEFjY2Vzc1wiO1xuICAgIHZhciBybyA9IHtcbiAgICAgICAgbWV0aG9kOiBcIlBPU1RcIixcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICBmOiBcImpzb25cIixcbiAgICAgICAgICAgIGNsaWVudF9pZDogY2xpZW50SWQsXG4gICAgICAgICAgICB0b2tlbjogdG9rZW4sXG4gICAgICAgIH0sXG4gICAgfTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIHJvKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXZhbGlkYXRlLWFwcC1hY2Nlc3MuanMubWFwIiwiLyohICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXHJcbkNvcHlyaWdodCAoYykgTWljcm9zb2Z0IENvcnBvcmF0aW9uLlxyXG5cclxuUGVybWlzc2lvbiB0byB1c2UsIGNvcHksIG1vZGlmeSwgYW5kL29yIGRpc3RyaWJ1dGUgdGhpcyBzb2Z0d2FyZSBmb3IgYW55XHJcbnB1cnBvc2Ugd2l0aCBvciB3aXRob3V0IGZlZSBpcyBoZXJlYnkgZ3JhbnRlZC5cclxuXHJcblRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIgQU5EIFRIRSBBVVRIT1IgRElTQ0xBSU1TIEFMTCBXQVJSQU5USUVTIFdJVEhcclxuUkVHQVJEIFRPIFRISVMgU09GVFdBUkUgSU5DTFVESU5HIEFMTCBJTVBMSUVEIFdBUlJBTlRJRVMgT0YgTUVSQ0hBTlRBQklMSVRZXHJcbkFORCBGSVRORVNTLiBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SIEJFIExJQUJMRSBGT1IgQU5ZIFNQRUNJQUwsIERJUkVDVCxcclxuSU5ESVJFQ1QsIE9SIENPTlNFUVVFTlRJQUwgREFNQUdFUyBPUiBBTlkgREFNQUdFUyBXSEFUU09FVkVSIFJFU1VMVElORyBGUk9NXHJcbkxPU1MgT0YgVVNFLCBEQVRBIE9SIFBST0ZJVFMsIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBORUdMSUdFTkNFIE9SXHJcbk9USEVSIFRPUlRJT1VTIEFDVElPTiwgQVJJU0lORyBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBVU0UgT1JcclxuUEVSRk9STUFOQ0UgT0YgVEhJUyBTT0ZUV0FSRS5cclxuKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiogKi9cclxuLyogZ2xvYmFsIFJlZmxlY3QsIFByb21pc2UgKi9cclxuXHJcbnZhciBleHRlbmRTdGF0aWNzID0gZnVuY3Rpb24oZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyA9IE9iamVjdC5zZXRQcm90b3R5cGVPZiB8fFxyXG4gICAgICAgICh7IF9fcHJvdG9fXzogW10gfSBpbnN0YW5jZW9mIEFycmF5ICYmIGZ1bmN0aW9uIChkLCBiKSB7IGQuX19wcm90b19fID0gYjsgfSkgfHxcclxuICAgICAgICBmdW5jdGlvbiAoZCwgYikgeyBmb3IgKHZhciBwIGluIGIpIGlmIChiLmhhc093blByb3BlcnR5KHApKSBkW3BdID0gYltwXTsgfTtcclxuICAgIHJldHVybiBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXh0ZW5kcyhkLCBiKSB7XHJcbiAgICBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG4gICAgZnVuY3Rpb24gX18oKSB7IHRoaXMuY29uc3RydWN0b3IgPSBkOyB9XHJcbiAgICBkLnByb3RvdHlwZSA9IGIgPT09IG51bGwgPyBPYmplY3QuY3JlYXRlKGIpIDogKF9fLnByb3RvdHlwZSA9IGIucHJvdG90eXBlLCBuZXcgX18oKSk7XHJcbn1cclxuXHJcbmV4cG9ydCB2YXIgX19hc3NpZ24gPSBmdW5jdGlvbigpIHtcclxuICAgIF9fYXNzaWduID0gT2JqZWN0LmFzc2lnbiB8fCBmdW5jdGlvbiBfX2Fzc2lnbih0KSB7XHJcbiAgICAgICAgZm9yICh2YXIgcywgaSA9IDEsIG4gPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgbjsgaSsrKSB7XHJcbiAgICAgICAgICAgIHMgPSBhcmd1bWVudHNbaV07XHJcbiAgICAgICAgICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSkgdFtwXSA9IHNbcF07XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHJldHVybiB0O1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIF9fYXNzaWduLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3Jlc3QocywgZSkge1xyXG4gICAgdmFyIHQgPSB7fTtcclxuICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSAmJiBlLmluZGV4T2YocCkgPCAwKVxyXG4gICAgICAgIHRbcF0gPSBzW3BdO1xyXG4gICAgaWYgKHMgIT0gbnVsbCAmJiB0eXBlb2YgT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyA9PT0gXCJmdW5jdGlvblwiKVxyXG4gICAgICAgIGZvciAodmFyIGkgPSAwLCBwID0gT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyhzKTsgaSA8IHAubGVuZ3RoOyBpKyspIHtcclxuICAgICAgICAgICAgaWYgKGUuaW5kZXhPZihwW2ldKSA8IDAgJiYgT2JqZWN0LnByb3RvdHlwZS5wcm9wZXJ0eUlzRW51bWVyYWJsZS5jYWxsKHMsIHBbaV0pKVxyXG4gICAgICAgICAgICAgICAgdFtwW2ldXSA9IHNbcFtpXV07XHJcbiAgICAgICAgfVxyXG4gICAgcmV0dXJuIHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2RlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKSB7XHJcbiAgICB2YXIgYyA9IGFyZ3VtZW50cy5sZW5ndGgsIHIgPSBjIDwgMyA/IHRhcmdldCA6IGRlc2MgPT09IG51bGwgPyBkZXNjID0gT2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih0YXJnZXQsIGtleSkgOiBkZXNjLCBkO1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0LmRlY29yYXRlID09PSBcImZ1bmN0aW9uXCIpIHIgPSBSZWZsZWN0LmRlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKTtcclxuICAgIGVsc2UgZm9yICh2YXIgaSA9IGRlY29yYXRvcnMubGVuZ3RoIC0gMTsgaSA+PSAwOyBpLS0pIGlmIChkID0gZGVjb3JhdG9yc1tpXSkgciA9IChjIDwgMyA/IGQocikgOiBjID4gMyA/IGQodGFyZ2V0LCBrZXksIHIpIDogZCh0YXJnZXQsIGtleSkpIHx8IHI7XHJcbiAgICByZXR1cm4gYyA+IDMgJiYgciAmJiBPYmplY3QuZGVmaW5lUHJvcGVydHkodGFyZ2V0LCBrZXksIHIpLCByO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19wYXJhbShwYXJhbUluZGV4LCBkZWNvcmF0b3IpIHtcclxuICAgIHJldHVybiBmdW5jdGlvbiAodGFyZ2V0LCBrZXkpIHsgZGVjb3JhdG9yKHRhcmdldCwga2V5LCBwYXJhbUluZGV4KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSkge1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0Lm1ldGFkYXRhID09PSBcImZ1bmN0aW9uXCIpIHJldHVybiBSZWZsZWN0Lm1ldGFkYXRhKG1ldGFkYXRhS2V5LCBtZXRhZGF0YVZhbHVlKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXRlcih0aGlzQXJnLCBfYXJndW1lbnRzLCBQLCBnZW5lcmF0b3IpIHtcclxuICAgIGZ1bmN0aW9uIGFkb3B0KHZhbHVlKSB7IHJldHVybiB2YWx1ZSBpbnN0YW5jZW9mIFAgPyB2YWx1ZSA6IG5ldyBQKGZ1bmN0aW9uIChyZXNvbHZlKSB7IHJlc29sdmUodmFsdWUpOyB9KTsgfVxyXG4gICAgcmV0dXJuIG5ldyAoUCB8fCAoUCA9IFByb21pc2UpKShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XHJcbiAgICAgICAgZnVuY3Rpb24gZnVsZmlsbGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yLm5leHQodmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHJlamVjdGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yW1widGhyb3dcIl0odmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHN0ZXAocmVzdWx0KSB7IHJlc3VsdC5kb25lID8gcmVzb2x2ZShyZXN1bHQudmFsdWUpIDogYWRvcHQocmVzdWx0LnZhbHVlKS50aGVuKGZ1bGZpbGxlZCwgcmVqZWN0ZWQpOyB9XHJcbiAgICAgICAgc3RlcCgoZ2VuZXJhdG9yID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pKS5uZXh0KCkpO1xyXG4gICAgfSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2dlbmVyYXRvcih0aGlzQXJnLCBib2R5KSB7XHJcbiAgICB2YXIgXyA9IHsgbGFiZWw6IDAsIHNlbnQ6IGZ1bmN0aW9uKCkgeyBpZiAodFswXSAmIDEpIHRocm93IHRbMV07IHJldHVybiB0WzFdOyB9LCB0cnlzOiBbXSwgb3BzOiBbXSB9LCBmLCB5LCB0LCBnO1xyXG4gICAgcmV0dXJuIGcgPSB7IG5leHQ6IHZlcmIoMCksIFwidGhyb3dcIjogdmVyYigxKSwgXCJyZXR1cm5cIjogdmVyYigyKSB9LCB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgKGdbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uKCkgeyByZXR1cm4gdGhpczsgfSksIGc7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgcmV0dXJuIGZ1bmN0aW9uICh2KSB7IHJldHVybiBzdGVwKFtuLCB2XSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAob3ApIHtcclxuICAgICAgICBpZiAoZikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIkdlbmVyYXRvciBpcyBhbHJlYWR5IGV4ZWN1dGluZy5cIik7XHJcbiAgICAgICAgd2hpbGUgKF8pIHRyeSB7XHJcbiAgICAgICAgICAgIGlmIChmID0gMSwgeSAmJiAodCA9IG9wWzBdICYgMiA/IHlbXCJyZXR1cm5cIl0gOiBvcFswXSA/IHlbXCJ0aHJvd1wiXSB8fCAoKHQgPSB5W1wicmV0dXJuXCJdKSAmJiB0LmNhbGwoeSksIDApIDogeS5uZXh0KSAmJiAhKHQgPSB0LmNhbGwoeSwgb3BbMV0pKS5kb25lKSByZXR1cm4gdDtcclxuICAgICAgICAgICAgaWYgKHkgPSAwLCB0KSBvcCA9IFtvcFswXSAmIDIsIHQudmFsdWVdO1xyXG4gICAgICAgICAgICBzd2l0Y2ggKG9wWzBdKSB7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDA6IGNhc2UgMTogdCA9IG9wOyBicmVhaztcclxuICAgICAgICAgICAgICAgIGNhc2UgNDogXy5sYWJlbCsrOyByZXR1cm4geyB2YWx1ZTogb3BbMV0sIGRvbmU6IGZhbHNlIH07XHJcbiAgICAgICAgICAgICAgICBjYXNlIDU6IF8ubGFiZWwrKzsgeSA9IG9wWzFdOyBvcCA9IFswXTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDc6IG9wID0gXy5vcHMucG9wKCk7IF8udHJ5cy5wb3AoKTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgICAgICAgICAgIGlmICghKHQgPSBfLnRyeXMsIHQgPSB0Lmxlbmd0aCA+IDAgJiYgdFt0Lmxlbmd0aCAtIDFdKSAmJiAob3BbMF0gPT09IDYgfHwgb3BbMF0gPT09IDIpKSB7IF8gPSAwOyBjb250aW51ZTsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gMyAmJiAoIXQgfHwgKG9wWzFdID4gdFswXSAmJiBvcFsxXSA8IHRbM10pKSkgeyBfLmxhYmVsID0gb3BbMV07IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG9wWzBdID09PSA2ICYmIF8ubGFiZWwgPCB0WzFdKSB7IF8ubGFiZWwgPSB0WzFdOyB0ID0gb3A7IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHQgJiYgXy5sYWJlbCA8IHRbMl0pIHsgXy5sYWJlbCA9IHRbMl07IF8ub3BzLnB1c2gob3ApOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0WzJdKSBfLm9wcy5wb3AoKTtcclxuICAgICAgICAgICAgICAgICAgICBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIG9wID0gYm9keS5jYWxsKHRoaXNBcmcsIF8pO1xyXG4gICAgICAgIH0gY2F0Y2ggKGUpIHsgb3AgPSBbNiwgZV07IHkgPSAwOyB9IGZpbmFsbHkgeyBmID0gdCA9IDA7IH1cclxuICAgICAgICBpZiAob3BbMF0gJiA1KSB0aHJvdyBvcFsxXTsgcmV0dXJuIHsgdmFsdWU6IG9wWzBdID8gb3BbMV0gOiB2b2lkIDAsIGRvbmU6IHRydWUgfTtcclxuICAgIH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY3JlYXRlQmluZGluZyhvLCBtLCBrLCBrMikge1xyXG4gICAgaWYgKGsyID09PSB1bmRlZmluZWQpIGsyID0gaztcclxuICAgIG9bazJdID0gbVtrXTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXhwb3J0U3RhcihtLCBleHBvcnRzKSB7XHJcbiAgICBmb3IgKHZhciBwIGluIG0pIGlmIChwICE9PSBcImRlZmF1bHRcIiAmJiAhZXhwb3J0cy5oYXNPd25Qcm9wZXJ0eShwKSkgZXhwb3J0c1twXSA9IG1bcF07XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3ZhbHVlcyhvKSB7XHJcbiAgICB2YXIgcyA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBTeW1ib2wuaXRlcmF0b3IsIG0gPSBzICYmIG9bc10sIGkgPSAwO1xyXG4gICAgaWYgKG0pIHJldHVybiBtLmNhbGwobyk7XHJcbiAgICBpZiAobyAmJiB0eXBlb2Ygby5sZW5ndGggPT09IFwibnVtYmVyXCIpIHJldHVybiB7XHJcbiAgICAgICAgbmV4dDogZnVuY3Rpb24gKCkge1xyXG4gICAgICAgICAgICBpZiAobyAmJiBpID49IG8ubGVuZ3RoKSBvID0gdm9pZCAwO1xyXG4gICAgICAgICAgICByZXR1cm4geyB2YWx1ZTogbyAmJiBvW2krK10sIGRvbmU6ICFvIH07XHJcbiAgICAgICAgfVxyXG4gICAgfTtcclxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IocyA/IFwiT2JqZWN0IGlzIG5vdCBpdGVyYWJsZS5cIiA6IFwiU3ltYm9sLml0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcmVhZChvLCBuKSB7XHJcbiAgICB2YXIgbSA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBvW1N5bWJvbC5pdGVyYXRvcl07XHJcbiAgICBpZiAoIW0pIHJldHVybiBvO1xyXG4gICAgdmFyIGkgPSBtLmNhbGwobyksIHIsIGFyID0gW10sIGU7XHJcbiAgICB0cnkge1xyXG4gICAgICAgIHdoaWxlICgobiA9PT0gdm9pZCAwIHx8IG4tLSA+IDApICYmICEociA9IGkubmV4dCgpKS5kb25lKSBhci5wdXNoKHIudmFsdWUpO1xyXG4gICAgfVxyXG4gICAgY2F0Y2ggKGVycm9yKSB7IGUgPSB7IGVycm9yOiBlcnJvciB9OyB9XHJcbiAgICBmaW5hbGx5IHtcclxuICAgICAgICB0cnkge1xyXG4gICAgICAgICAgICBpZiAociAmJiAhci5kb25lICYmIChtID0gaVtcInJldHVyblwiXSkpIG0uY2FsbChpKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgZmluYWxseSB7IGlmIChlKSB0aHJvdyBlLmVycm9yOyB9XHJcbiAgICB9XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZCgpIHtcclxuICAgIGZvciAodmFyIGFyID0gW10sIGkgPSAwOyBpIDwgYXJndW1lbnRzLmxlbmd0aDsgaSsrKVxyXG4gICAgICAgIGFyID0gYXIuY29uY2F0KF9fcmVhZChhcmd1bWVudHNbaV0pKTtcclxuICAgIHJldHVybiBhcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fc3ByZWFkQXJyYXlzKCkge1xyXG4gICAgZm9yICh2YXIgcyA9IDAsIGkgPSAwLCBpbCA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBpbDsgaSsrKSBzICs9IGFyZ3VtZW50c1tpXS5sZW5ndGg7XHJcbiAgICBmb3IgKHZhciByID0gQXJyYXkocyksIGsgPSAwLCBpID0gMDsgaSA8IGlsOyBpKyspXHJcbiAgICAgICAgZm9yICh2YXIgYSA9IGFyZ3VtZW50c1tpXSwgaiA9IDAsIGpsID0gYS5sZW5ndGg7IGogPCBqbDsgaisrLCBrKyspXHJcbiAgICAgICAgICAgIHJba10gPSBhW2pdO1xyXG4gICAgcmV0dXJuIHI7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hd2FpdCh2KSB7XHJcbiAgICByZXR1cm4gdGhpcyBpbnN0YW5jZW9mIF9fYXdhaXQgPyAodGhpcy52ID0gdiwgdGhpcykgOiBuZXcgX19hd2FpdCh2KTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNHZW5lcmF0b3IodGhpc0FyZywgX2FyZ3VtZW50cywgZ2VuZXJhdG9yKSB7XHJcbiAgICBpZiAoIVN5bWJvbC5hc3luY0l0ZXJhdG9yKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU3ltYm9sLmFzeW5jSXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgdmFyIGcgPSBnZW5lcmF0b3IuYXBwbHkodGhpc0FyZywgX2FyZ3VtZW50cyB8fCBbXSksIGksIHEgPSBbXTtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyBpZiAoZ1tuXSkgaVtuXSA9IGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAoYSwgYikgeyBxLnB1c2goW24sIHYsIGEsIGJdKSA+IDEgfHwgcmVzdW1lKG4sIHYpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gcmVzdW1lKG4sIHYpIHsgdHJ5IHsgc3RlcChnW25dKHYpKTsgfSBjYXRjaCAoZSkgeyBzZXR0bGUocVswXVszXSwgZSk7IH0gfVxyXG4gICAgZnVuY3Rpb24gc3RlcChyKSB7IHIudmFsdWUgaW5zdGFuY2VvZiBfX2F3YWl0ID8gUHJvbWlzZS5yZXNvbHZlKHIudmFsdWUudikudGhlbihmdWxmaWxsLCByZWplY3QpIDogc2V0dGxlKHFbMF1bMl0sIHIpOyB9XHJcbiAgICBmdW5jdGlvbiBmdWxmaWxsKHZhbHVlKSB7IHJlc3VtZShcIm5leHRcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiByZWplY3QodmFsdWUpIHsgcmVzdW1lKFwidGhyb3dcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUoZiwgdikgeyBpZiAoZih2KSwgcS5zaGlmdCgpLCBxLmxlbmd0aCkgcmVzdW1lKHFbMF1bMF0sIHFbMF1bMV0pOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jRGVsZWdhdG9yKG8pIHtcclxuICAgIHZhciBpLCBwO1xyXG4gICAgcmV0dXJuIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiLCBmdW5jdGlvbiAoZSkgeyB0aHJvdyBlOyB9KSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuaXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobiwgZikgeyBpW25dID0gb1tuXSA/IGZ1bmN0aW9uICh2KSB7IHJldHVybiAocCA9ICFwKSA/IHsgdmFsdWU6IF9fYXdhaXQob1tuXSh2KSksIGRvbmU6IG4gPT09IFwicmV0dXJuXCIgfSA6IGYgPyBmKHYpIDogdjsgfSA6IGY7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNWYWx1ZXMobykge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBtID0gb1tTeW1ib2wuYXN5bmNJdGVyYXRvcl0sIGk7XHJcbiAgICByZXR1cm4gbSA/IG0uY2FsbChvKSA6IChvID0gdHlwZW9mIF9fdmFsdWVzID09PSBcImZ1bmN0aW9uXCIgPyBfX3ZhbHVlcyhvKSA6IG9bU3ltYm9sLml0ZXJhdG9yXSgpLCBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaSk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaVtuXSA9IG9bbl0gJiYgZnVuY3Rpb24gKHYpIHsgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHsgdiA9IG9bbl0odiksIHNldHRsZShyZXNvbHZlLCByZWplY3QsIHYuZG9uZSwgdi52YWx1ZSk7IH0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCBkLCB2KSB7IFByb21pc2UucmVzb2x2ZSh2KS50aGVuKGZ1bmN0aW9uKHYpIHsgcmVzb2x2ZSh7IHZhbHVlOiB2LCBkb25lOiBkIH0pOyB9LCByZWplY3QpOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX21ha2VUZW1wbGF0ZU9iamVjdChjb29rZWQsIHJhdykge1xyXG4gICAgaWYgKE9iamVjdC5kZWZpbmVQcm9wZXJ0eSkgeyBPYmplY3QuZGVmaW5lUHJvcGVydHkoY29va2VkLCBcInJhd1wiLCB7IHZhbHVlOiByYXcgfSk7IH0gZWxzZSB7IGNvb2tlZC5yYXcgPSByYXc7IH1cclxuICAgIHJldHVybiBjb29rZWQ7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnRTdGFyKG1vZCkge1xyXG4gICAgaWYgKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgcmV0dXJuIG1vZDtcclxuICAgIHZhciByZXN1bHQgPSB7fTtcclxuICAgIGlmIChtb2QgIT0gbnVsbCkgZm9yICh2YXIgayBpbiBtb2QpIGlmIChPYmplY3QuaGFzT3duUHJvcGVydHkuY2FsbChtb2QsIGspKSByZXN1bHRba10gPSBtb2Rba107XHJcbiAgICByZXN1bHQuZGVmYXVsdCA9IG1vZDtcclxuICAgIHJldHVybiByZXN1bHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2ltcG9ydERlZmF1bHQobW9kKSB7XHJcbiAgICByZXR1cm4gKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgPyBtb2QgOiB7IGRlZmF1bHQ6IG1vZCB9O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZEdldChyZWNlaXZlciwgcHJpdmF0ZU1hcCkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIGdldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHJldHVybiBwcml2YXRlTWFwLmdldChyZWNlaXZlcik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NsYXNzUHJpdmF0ZUZpZWxkU2V0KHJlY2VpdmVyLCBwcml2YXRlTWFwLCB2YWx1ZSkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIHNldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHByaXZhdGVNYXAuc2V0KHJlY2VpdmVyLCB2YWx1ZSk7XHJcbiAgICByZXR1cm4gdmFsdWU7XHJcbn1cclxuIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyByZXF1ZXN0LCBjbGVhblVybCwgYXBwZW5kQ3VzdG9tUGFyYW1zIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IGFkZEZlYXR1cmVzIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcic7XG4gKiAvL1xuICogYWRkRmVhdHVyZXMoe1xuICogICB1cmw6IFwiaHR0cHM6Ly9zYW1wbGVzZXJ2ZXI2LmFyY2dpc29ubGluZS5jb20vYXJjZ2lzL3Jlc3Qvc2VydmljZXMvU2VydmljZVJlcXVlc3QvRmVhdHVyZVNlcnZlci8wXCIsXG4gKiAgIGZlYXR1cmVzOiBbe1xuICogICAgIGdlb21ldHJ5OiB7IHg6IC0xMjAsIHk6IDQ1LCBzcGF0aWFsUmVmZXJlbmNlOiB7IHdraWQ6IDQzMjYgfSB9LFxuICogICAgIGF0dHJpYnV0ZXM6IHsgc3RhdHVzOiBcImFsaXZlXCIgfVxuICogICB9XVxuICogfSlcbiAqICAgLnRoZW4ocmVzcG9uc2UpXG4gKiBgYGBcbiAqIEFkZCBmZWF0dXJlcyByZXF1ZXN0LiBTZWUgdGhlIFtSRVNUIERvY3VtZW50YXRpb25dKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3Qvc2VydmljZXMtcmVmZXJlbmNlL2FkZC1mZWF0dXJlcy5odG0pIGZvciBtb3JlIGluZm9ybWF0aW9uLlxuICpcbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0LlxuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIGFkZEZlYXR1cmVzIHJlc3BvbnNlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gYWRkRmVhdHVyZXMocmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgdXJsID0gY2xlYW5VcmwocmVxdWVzdE9wdGlvbnMudXJsKSArIFwiL2FkZEZlYXR1cmVzXCI7XG4gICAgLy8gZWRpdCBvcGVyYXRpb25zIGFyZSBQT1NUIG9ubHlcbiAgICB2YXIgb3B0aW9ucyA9IGFwcGVuZEN1c3RvbVBhcmFtcyhyZXF1ZXN0T3B0aW9ucywgW1wiZmVhdHVyZXNcIiwgXCJnZGJWZXJzaW9uXCIsIFwicmV0dXJuRWRpdE1vbWVudFwiLCBcInJvbGxiYWNrT25GYWlsdXJlXCJdLCB7IHBhcmFtczogX19hc3NpZ24oe30sIHJlcXVlc3RPcHRpb25zLnBhcmFtcykgfSk7XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWFkZC5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIGNsZWFuVXJsLCBhcHBlbmRDdXN0b21QYXJhbXMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgZGVsZXRlRmVhdHVyZXMgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyJztcbiAqIC8vXG4gKiBkZWxldGVGZWF0dXJlcyh7XG4gKiAgIHVybDogXCJodHRwczovL3NhbXBsZXNlcnZlcjYuYXJjZ2lzb25saW5lLmNvbS9hcmNnaXMvcmVzdC9zZXJ2aWNlcy9TZXJ2aWNlUmVxdWVzdC9GZWF0dXJlU2VydmVyLzBcIixcbiAqICAgb2JqZWN0SWRzOiBbMSwyLDNdXG4gKiB9KTtcbiAqIGBgYFxuICogRGVsZXRlIGZlYXR1cmVzIHJlcXVlc3QuIFNlZSB0aGUgW1JFU1QgRG9jdW1lbnRhdGlvbl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC9zZXJ2aWNlcy1yZWZlcmVuY2UvZGVsZXRlLWZlYXR1cmVzLmh0bSkgZm9yIG1vcmUgaW5mb3JtYXRpb24uXG4gKlxuICogQHBhcmFtIGRlbGV0ZUZlYXR1cmVzUmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdC5cbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBkZWxldGVGZWF0dXJlcyByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGRlbGV0ZUZlYXR1cmVzKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIHVybCA9IGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi9kZWxldGVGZWF0dXJlc1wiO1xuICAgIC8vIGVkaXQgb3BlcmF0aW9ucyBQT1NUIG9ubHlcbiAgICB2YXIgb3B0aW9ucyA9IGFwcGVuZEN1c3RvbVBhcmFtcyhyZXF1ZXN0T3B0aW9ucywgW1xuICAgICAgICBcIndoZXJlXCIsXG4gICAgICAgIFwib2JqZWN0SWRzXCIsXG4gICAgICAgIFwiZ2RiVmVyc2lvblwiLFxuICAgICAgICBcInJldHVybkVkaXRNb21lbnRcIixcbiAgICAgICAgXCJyb2xsYmFja09uRmFpbHVyZVwiXG4gICAgXSwgeyBwYXJhbXM6IF9fYXNzaWduKHt9LCByZXF1ZXN0T3B0aW9ucy5wYXJhbXMpIH0pO1xuICAgIHJldHVybiByZXF1ZXN0KHVybCwgb3B0aW9ucyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1kZWxldGUuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIGNsZWFuVXJsLCBhcHBlbmRDdXN0b21QYXJhbXMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgZ2V0RmVhdHVyZSB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXInO1xuICogLy9cbiAqIGNvbnN0IHVybCA9IFwiaHR0cHM6Ly9zZXJ2aWNlcy5hcmNnaXMuY29tL1Y2WkhGcjZ6ZGdOWnVWRzAvYXJjZ2lzL3Jlc3Qvc2VydmljZXMvTGFuZHNjYXBlX1RyZWVzL0ZlYXR1cmVTZXJ2ZXIvMFwiO1xuICogLy9cbiAqIGdldEZlYXR1cmUoe1xuICogICB1cmwsXG4gKiAgIGlkOiA0MlxuICogfSkudGhlbihmZWF0dXJlID0+IHtcbiAqICBjb25zb2xlLmxvZyhmZWF0dXJlLmF0dHJpYnV0ZXMuRklEKTsgLy8gNDJcbiAqIH0pO1xuICogYGBgXG4gKiBHZXQgYSBmZWF0dXJlIGJ5IGlkLlxuICpcbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0XG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgZmVhdHVyZSBvciB0aGUgW3Jlc3BvbnNlXShodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL1dlYi9BUEkvUmVzcG9uc2UpIGl0c2VsZiBpZiBgcmF3UmVzcG9uc2U6IHRydWVgIHdhcyBwYXNzZWQgaW4uXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBnZXRGZWF0dXJlKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIHVybCA9IGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi9cIiArIHJlcXVlc3RPcHRpb25zLmlkO1xuICAgIC8vIGRlZmF1bHQgdG8gYSBHRVQgcmVxdWVzdFxuICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oeyBodHRwTWV0aG9kOiBcIkdFVFwiIH0sIHJlcXVlc3RPcHRpb25zKTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGlmIChvcHRpb25zLnJhd1Jlc3BvbnNlKSB7XG4gICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmZlYXR1cmU7XG4gICAgfSk7XG59XG4vKipcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBxdWVyeUZlYXR1cmVzIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcic7XG4gKiAvL1xuICogcXVlcnlGZWF0dXJlcyh7XG4gKiAgIHVybDogXCJodHRwOi8vc2FtcGxlc2VydmVyNi5hcmNnaXNvbmxpbmUuY29tL2FyY2dpcy9yZXN0L3NlcnZpY2VzL0NlbnN1cy9NYXBTZXJ2ZXIvM1wiLFxuICogICB3aGVyZTogXCJTVEFURV9OQU1FID0gJ0FsYXNrYSdcIlxuICogfSlcbiAqICAgLnRoZW4ocmVzdWx0KVxuICogYGBgXG4gKiBRdWVyeSBhIGZlYXR1cmUgc2VydmljZS4gU2VlIFtSRVNUIERvY3VtZW50YXRpb25dKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3Qvc2VydmljZXMtcmVmZXJlbmNlL3F1ZXJ5LWZlYXR1cmUtc2VydmljZS1sYXllci0uaHRtKSBmb3IgbW9yZSBpbmZvcm1hdGlvbi5cbiAqXG4gKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdFxuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIHF1ZXJ5IHJlc3BvbnNlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gcXVlcnlGZWF0dXJlcyhyZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciBxdWVyeU9wdGlvbnMgPSBhcHBlbmRDdXN0b21QYXJhbXMocmVxdWVzdE9wdGlvbnMsIFtcbiAgICAgICAgXCJ3aGVyZVwiLFxuICAgICAgICBcIm9iamVjdElkc1wiLFxuICAgICAgICBcInJlbGF0aW9uUGFyYW1cIixcbiAgICAgICAgXCJ0aW1lXCIsXG4gICAgICAgIFwiZGlzdGFuY2VcIixcbiAgICAgICAgXCJ1bml0c1wiLFxuICAgICAgICBcIm91dEZpZWxkc1wiLFxuICAgICAgICBcImdlb21ldHJ5XCIsXG4gICAgICAgIFwiZ2VvbWV0cnlUeXBlXCIsXG4gICAgICAgIFwic3BhdGlhbFJlbFwiLFxuICAgICAgICBcInJldHVybkdlb21ldHJ5XCIsXG4gICAgICAgIFwibWF4QWxsb3dhYmxlT2Zmc2V0XCIsXG4gICAgICAgIFwiZ2VvbWV0cnlQcmVjaXNpb25cIixcbiAgICAgICAgXCJpblNSXCIsXG4gICAgICAgIFwib3V0U1JcIixcbiAgICAgICAgXCJnZGJWZXJzaW9uXCIsXG4gICAgICAgIFwicmV0dXJuRGlzdGluY3RWYWx1ZXNcIixcbiAgICAgICAgXCJyZXR1cm5JZHNPbmx5XCIsXG4gICAgICAgIFwicmV0dXJuQ291bnRPbmx5XCIsXG4gICAgICAgIFwicmV0dXJuRXh0ZW50T25seVwiLFxuICAgICAgICBcIm9yZGVyQnlGaWVsZHNcIixcbiAgICAgICAgXCJncm91cEJ5RmllbGRzRm9yU3RhdGlzdGljc1wiLFxuICAgICAgICBcIm91dFN0YXRpc3RpY3NcIixcbiAgICAgICAgXCJyZXR1cm5aXCIsXG4gICAgICAgIFwicmV0dXJuTVwiLFxuICAgICAgICBcIm11bHRpcGF0Y2hPcHRpb25cIixcbiAgICAgICAgXCJyZXN1bHRPZmZzZXRcIixcbiAgICAgICAgXCJyZXN1bHRSZWNvcmRDb3VudFwiLFxuICAgICAgICBcInF1YW50aXphdGlvblBhcmFtZXRlcnNcIixcbiAgICAgICAgXCJyZXR1cm5DZW50cm9pZFwiLFxuICAgICAgICBcInJlc3VsdFR5cGVcIixcbiAgICAgICAgXCJoaXN0b3JpY01vbWVudFwiLFxuICAgICAgICBcInJldHVyblRydWVDdXJ2ZXNcIixcbiAgICAgICAgXCJzcWxGb3JtYXRcIixcbiAgICAgICAgXCJyZXR1cm5FeGNlZWRlZExpbWl0RmVhdHVyZXNcIixcbiAgICAgICAgXCJmXCJcbiAgICBdLCB7XG4gICAgICAgIGh0dHBNZXRob2Q6IFwiR0VUXCIsXG4gICAgICAgIHBhcmFtczogX19hc3NpZ24oeyBcbiAgICAgICAgICAgIC8vIHNldCBkZWZhdWx0IHF1ZXJ5IHBhcmFtZXRlcnNcbiAgICAgICAgICAgIHdoZXJlOiBcIjE9MVwiLCBvdXRGaWVsZHM6IFwiKlwiIH0sIHJlcXVlc3RPcHRpb25zLnBhcmFtcylcbiAgICB9KTtcbiAgICByZXR1cm4gcmVxdWVzdChjbGVhblVybChyZXF1ZXN0T3B0aW9ucy51cmwpICsgXCIvcXVlcnlcIiwgcXVlcnlPcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXF1ZXJ5LmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgcmVxdWVzdCwgY2xlYW5VcmwsIGFwcGVuZEN1c3RvbVBhcmFtcyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgcXVlcnlSZWxhdGVkIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcidcbiAqIC8vXG4gKiBxdWVyeVJlbGF0ZWQoe1xuICogIHVybDogXCJodHRwOi8vc2VydmljZXMubXlzZXJ2ZXIvT3JnSUQvQXJjR0lTL3Jlc3Qvc2VydmljZXMvUGV0cm9sZXVtL0tTUGV0cm8vRmVhdHVyZVNlcnZlci8wXCIsXG4gKiAgcmVsYXRpb25zaGlwSWQ6IDEsXG4gKiAgcGFyYW1zOiB7IHJldHVybkNvdW50T25seTogdHJ1ZSB9XG4gKiB9KVxuICogIC50aGVuKHJlc3BvbnNlKSAvLyByZXNwb25zZS5yZWxhdGVkUmVjb3Jkc1xuICogYGBgXG4gKiBRdWVyeSB0aGUgcmVsYXRlZCByZWNvcmRzIGZvciBhIGZlYXR1cmUgc2VydmljZS4gU2VlIHRoZSBbUkVTVCBEb2N1bWVudGF0aW9uXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3NlcnZpY2VzLXJlZmVyZW5jZS9xdWVyeS1yZWxhdGVkLXJlY29yZHMtZmVhdHVyZS1zZXJ2aWNlLS5odG0pIGZvciBtb3JlIGluZm9ybWF0aW9uLlxuICpcbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9uc1xuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIHF1ZXJ5IHJlc3BvbnNlXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBxdWVyeVJlbGF0ZWQocmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgb3B0aW9ucyA9IGFwcGVuZEN1c3RvbVBhcmFtcyhyZXF1ZXN0T3B0aW9ucywgW1wib2JqZWN0SWRzXCIsIFwicmVsYXRpb25zaGlwSWRcIiwgXCJkZWZpbml0aW9uRXhwcmVzc2lvblwiLCBcIm91dEZpZWxkc1wiXSwge1xuICAgICAgICBodHRwTWV0aG9kOiBcIkdFVFwiLFxuICAgICAgICBwYXJhbXM6IF9fYXNzaWduKHsgXG4gICAgICAgICAgICAvLyBzZXQgZGVmYXVsdCBxdWVyeSBwYXJhbWV0ZXJzXG4gICAgICAgICAgICBkZWZpbml0aW9uRXhwcmVzc2lvbjogXCIxPTFcIiwgb3V0RmllbGRzOiBcIipcIiwgcmVsYXRpb25zaGlwSWQ6IDAgfSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKVxuICAgIH0pO1xuICAgIHJldHVybiByZXF1ZXN0KGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi9xdWVyeVJlbGF0ZWRSZWNvcmRzXCIsIG9wdGlvbnMpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9cXVlcnlSZWxhdGVkLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgcmVxdWVzdCwgY2xlYW5VcmwsIGFwcGVuZEN1c3RvbVBhcmFtcyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgdXBkYXRlRmVhdHVyZXMgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyJztcbiAqIC8vXG4gKiB1cGRhdGVGZWF0dXJlcyh7XG4gKiAgIHVybDogXCJodHRwczovL3NhbXBsZXNlcnZlcjYuYXJjZ2lzb25saW5lLmNvbS9hcmNnaXMvcmVzdC9zZXJ2aWNlcy9TZXJ2aWNlUmVxdWVzdC9GZWF0dXJlU2VydmVyLzBcIixcbiAqICAgZmVhdHVyZXM6IFt7XG4gKiAgICAgZ2VvbWV0cnk6IHsgeDogLTEyMCwgeTogNDUsIHNwYXRpYWxSZWZlcmVuY2U6IHsgd2tpZDogNDMyNiB9IH0sXG4gKiAgICAgYXR0cmlidXRlczogeyBzdGF0dXM6IFwiYWxpdmVcIiB9XG4gKiAgIH1dXG4gKiB9KTtcbiAqIGBgYFxuICogVXBkYXRlIGZlYXR1cmVzIHJlcXVlc3QuIFNlZSB0aGUgW1JFU1QgRG9jdW1lbnRhdGlvbl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC9zZXJ2aWNlcy1yZWZlcmVuY2UvdXBkYXRlLWZlYXR1cmVzLmh0bSkgZm9yIG1vcmUgaW5mb3JtYXRpb24uXG4gKlxuICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3QuXG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgdXBkYXRlRmVhdHVyZXMgcmVzcG9uc2UuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB1cGRhdGVGZWF0dXJlcyhyZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciB1cmwgPSBjbGVhblVybChyZXF1ZXN0T3B0aW9ucy51cmwpICsgXCIvdXBkYXRlRmVhdHVyZXNcIjtcbiAgICAvLyBlZGl0IG9wZXJhdGlvbnMgYXJlIFBPU1Qgb25seVxuICAgIHZhciBvcHRpb25zID0gYXBwZW5kQ3VzdG9tUGFyYW1zKHJlcXVlc3RPcHRpb25zLCBbXCJmZWF0dXJlc1wiLCBcImdkYlZlcnNpb25cIiwgXCJyZXR1cm5FZGl0TW9tZW50XCIsIFwicm9sbGJhY2tPbkZhaWx1cmVcIiwgXCJ0cnVlQ3VydmVDbGllbnRcIl0sIHsgcGFyYW1zOiBfX2Fzc2lnbih7fSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKSB9KTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIG9wdGlvbnMpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9dXBkYXRlLmpzLm1hcCIsIi8qISAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxyXG5Db3B5cmlnaHQgKGMpIE1pY3Jvc29mdCBDb3Jwb3JhdGlvbi5cclxuXHJcblBlcm1pc3Npb24gdG8gdXNlLCBjb3B5LCBtb2RpZnksIGFuZC9vciBkaXN0cmlidXRlIHRoaXMgc29mdHdhcmUgZm9yIGFueVxyXG5wdXJwb3NlIHdpdGggb3Igd2l0aG91dCBmZWUgaXMgaGVyZWJ5IGdyYW50ZWQuXHJcblxyXG5USEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiIEFORCBUSEUgQVVUSE9SIERJU0NMQUlNUyBBTEwgV0FSUkFOVElFUyBXSVRIXHJcblJFR0FSRCBUTyBUSElTIFNPRlRXQVJFIElOQ0xVRElORyBBTEwgSU1QTElFRCBXQVJSQU5USUVTIE9GIE1FUkNIQU5UQUJJTElUWVxyXG5BTkQgRklUTkVTUy4gSU4gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUiBCRSBMSUFCTEUgRk9SIEFOWSBTUEVDSUFMLCBESVJFQ1QsXHJcbklORElSRUNULCBPUiBDT05TRVFVRU5USUFMIERBTUFHRVMgT1IgQU5ZIERBTUFHRVMgV0hBVFNPRVZFUiBSRVNVTFRJTkcgRlJPTVxyXG5MT1NTIE9GIFVTRSwgREFUQSBPUiBQUk9GSVRTLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgTkVHTElHRU5DRSBPUlxyXG5PVEhFUiBUT1JUSU9VUyBBQ1RJT04sIEFSSVNJTkcgT1VUIE9GIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgVVNFIE9SXHJcblBFUkZPUk1BTkNFIE9GIFRISVMgU09GVFdBUkUuXHJcbioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqICovXHJcbi8qIGdsb2JhbCBSZWZsZWN0LCBQcm9taXNlICovXHJcblxyXG52YXIgZXh0ZW5kU3RhdGljcyA9IGZ1bmN0aW9uKGQsIGIpIHtcclxuICAgIGV4dGVuZFN0YXRpY3MgPSBPYmplY3Quc2V0UHJvdG90eXBlT2YgfHxcclxuICAgICAgICAoeyBfX3Byb3RvX186IFtdIH0gaW5zdGFuY2VvZiBBcnJheSAmJiBmdW5jdGlvbiAoZCwgYikgeyBkLl9fcHJvdG9fXyA9IGI7IH0pIHx8XHJcbiAgICAgICAgZnVuY3Rpb24gKGQsIGIpIHsgZm9yICh2YXIgcCBpbiBiKSBpZiAoYi5oYXNPd25Qcm9wZXJ0eShwKSkgZFtwXSA9IGJbcF07IH07XHJcbiAgICByZXR1cm4gZXh0ZW5kU3RhdGljcyhkLCBiKTtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2V4dGVuZHMoZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyhkLCBiKTtcclxuICAgIGZ1bmN0aW9uIF9fKCkgeyB0aGlzLmNvbnN0cnVjdG9yID0gZDsgfVxyXG4gICAgZC5wcm90b3R5cGUgPSBiID09PSBudWxsID8gT2JqZWN0LmNyZWF0ZShiKSA6IChfXy5wcm90b3R5cGUgPSBiLnByb3RvdHlwZSwgbmV3IF9fKCkpO1xyXG59XHJcblxyXG5leHBvcnQgdmFyIF9fYXNzaWduID0gZnVuY3Rpb24oKSB7XHJcbiAgICBfX2Fzc2lnbiA9IE9iamVjdC5hc3NpZ24gfHwgZnVuY3Rpb24gX19hc3NpZ24odCkge1xyXG4gICAgICAgIGZvciAodmFyIHMsIGkgPSAxLCBuID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IG47IGkrKykge1xyXG4gICAgICAgICAgICBzID0gYXJndW1lbnRzW2ldO1xyXG4gICAgICAgICAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkpIHRbcF0gPSBzW3BdO1xyXG4gICAgICAgIH1cclxuICAgICAgICByZXR1cm4gdDtcclxuICAgIH1cclxuICAgIHJldHVybiBfX2Fzc2lnbi5hcHBseSh0aGlzLCBhcmd1bWVudHMpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19yZXN0KHMsIGUpIHtcclxuICAgIHZhciB0ID0ge307XHJcbiAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkgJiYgZS5pbmRleE9mKHApIDwgMClcclxuICAgICAgICB0W3BdID0gc1twXTtcclxuICAgIGlmIChzICE9IG51bGwgJiYgdHlwZW9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHMgPT09IFwiZnVuY3Rpb25cIilcclxuICAgICAgICBmb3IgKHZhciBpID0gMCwgcCA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHMocyk7IGkgPCBwLmxlbmd0aDsgaSsrKSB7XHJcbiAgICAgICAgICAgIGlmIChlLmluZGV4T2YocFtpXSkgPCAwICYmIE9iamVjdC5wcm90b3R5cGUucHJvcGVydHlJc0VudW1lcmFibGUuY2FsbChzLCBwW2ldKSlcclxuICAgICAgICAgICAgICAgIHRbcFtpXV0gPSBzW3BbaV1dO1xyXG4gICAgICAgIH1cclxuICAgIHJldHVybiB0O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19kZWNvcmF0ZShkZWNvcmF0b3JzLCB0YXJnZXQsIGtleSwgZGVzYykge1xyXG4gICAgdmFyIGMgPSBhcmd1bWVudHMubGVuZ3RoLCByID0gYyA8IDMgPyB0YXJnZXQgOiBkZXNjID09PSBudWxsID8gZGVzYyA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IodGFyZ2V0LCBrZXkpIDogZGVzYywgZDtcclxuICAgIGlmICh0eXBlb2YgUmVmbGVjdCA9PT0gXCJvYmplY3RcIiAmJiB0eXBlb2YgUmVmbGVjdC5kZWNvcmF0ZSA9PT0gXCJmdW5jdGlvblwiKSByID0gUmVmbGVjdC5kZWNvcmF0ZShkZWNvcmF0b3JzLCB0YXJnZXQsIGtleSwgZGVzYyk7XHJcbiAgICBlbHNlIGZvciAodmFyIGkgPSBkZWNvcmF0b3JzLmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSBpZiAoZCA9IGRlY29yYXRvcnNbaV0pIHIgPSAoYyA8IDMgPyBkKHIpIDogYyA+IDMgPyBkKHRhcmdldCwga2V5LCByKSA6IGQodGFyZ2V0LCBrZXkpKSB8fCByO1xyXG4gICAgcmV0dXJuIGMgPiAzICYmIHIgJiYgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRhcmdldCwga2V5LCByKSwgcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcGFyYW0ocGFyYW1JbmRleCwgZGVjb3JhdG9yKSB7XHJcbiAgICByZXR1cm4gZnVuY3Rpb24gKHRhcmdldCwga2V5KSB7IGRlY29yYXRvcih0YXJnZXQsIGtleSwgcGFyYW1JbmRleCk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fbWV0YWRhdGEobWV0YWRhdGFLZXksIG1ldGFkYXRhVmFsdWUpIHtcclxuICAgIGlmICh0eXBlb2YgUmVmbGVjdCA9PT0gXCJvYmplY3RcIiAmJiB0eXBlb2YgUmVmbGVjdC5tZXRhZGF0YSA9PT0gXCJmdW5jdGlvblwiKSByZXR1cm4gUmVmbGVjdC5tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2F3YWl0ZXIodGhpc0FyZywgX2FyZ3VtZW50cywgUCwgZ2VuZXJhdG9yKSB7XHJcbiAgICBmdW5jdGlvbiBhZG9wdCh2YWx1ZSkgeyByZXR1cm4gdmFsdWUgaW5zdGFuY2VvZiBQID8gdmFsdWUgOiBuZXcgUChmdW5jdGlvbiAocmVzb2x2ZSkgeyByZXNvbHZlKHZhbHVlKTsgfSk7IH1cclxuICAgIHJldHVybiBuZXcgKFAgfHwgKFAgPSBQcm9taXNlKSkoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xyXG4gICAgICAgIGZ1bmN0aW9uIGZ1bGZpbGxlZCh2YWx1ZSkgeyB0cnkgeyBzdGVwKGdlbmVyYXRvci5uZXh0KHZhbHVlKSk7IH0gY2F0Y2ggKGUpIHsgcmVqZWN0KGUpOyB9IH1cclxuICAgICAgICBmdW5jdGlvbiByZWplY3RlZCh2YWx1ZSkgeyB0cnkgeyBzdGVwKGdlbmVyYXRvcltcInRocm93XCJdKHZhbHVlKSk7IH0gY2F0Y2ggKGUpIHsgcmVqZWN0KGUpOyB9IH1cclxuICAgICAgICBmdW5jdGlvbiBzdGVwKHJlc3VsdCkgeyByZXN1bHQuZG9uZSA/IHJlc29sdmUocmVzdWx0LnZhbHVlKSA6IGFkb3B0KHJlc3VsdC52YWx1ZSkudGhlbihmdWxmaWxsZWQsIHJlamVjdGVkKTsgfVxyXG4gICAgICAgIHN0ZXAoKGdlbmVyYXRvciA9IGdlbmVyYXRvci5hcHBseSh0aGlzQXJnLCBfYXJndW1lbnRzIHx8IFtdKSkubmV4dCgpKTtcclxuICAgIH0pO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19nZW5lcmF0b3IodGhpc0FyZywgYm9keSkge1xyXG4gICAgdmFyIF8gPSB7IGxhYmVsOiAwLCBzZW50OiBmdW5jdGlvbigpIHsgaWYgKHRbMF0gJiAxKSB0aHJvdyB0WzFdOyByZXR1cm4gdFsxXTsgfSwgdHJ5czogW10sIG9wczogW10gfSwgZiwgeSwgdCwgZztcclxuICAgIHJldHVybiBnID0geyBuZXh0OiB2ZXJiKDApLCBcInRocm93XCI6IHZlcmIoMSksIFwicmV0dXJuXCI6IHZlcmIoMikgfSwgdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIChnW1N5bWJvbC5pdGVyYXRvcl0gPSBmdW5jdGlvbigpIHsgcmV0dXJuIHRoaXM7IH0pLCBnO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IHJldHVybiBmdW5jdGlvbiAodikgeyByZXR1cm4gc3RlcChbbiwgdl0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzdGVwKG9wKSB7XHJcbiAgICAgICAgaWYgKGYpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJHZW5lcmF0b3IgaXMgYWxyZWFkeSBleGVjdXRpbmcuXCIpO1xyXG4gICAgICAgIHdoaWxlIChfKSB0cnkge1xyXG4gICAgICAgICAgICBpZiAoZiA9IDEsIHkgJiYgKHQgPSBvcFswXSAmIDIgPyB5W1wicmV0dXJuXCJdIDogb3BbMF0gPyB5W1widGhyb3dcIl0gfHwgKCh0ID0geVtcInJldHVyblwiXSkgJiYgdC5jYWxsKHkpLCAwKSA6IHkubmV4dCkgJiYgISh0ID0gdC5jYWxsKHksIG9wWzFdKSkuZG9uZSkgcmV0dXJuIHQ7XHJcbiAgICAgICAgICAgIGlmICh5ID0gMCwgdCkgb3AgPSBbb3BbMF0gJiAyLCB0LnZhbHVlXTtcclxuICAgICAgICAgICAgc3dpdGNoIChvcFswXSkge1xyXG4gICAgICAgICAgICAgICAgY2FzZSAwOiBjYXNlIDE6IHQgPSBvcDsgYnJlYWs7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDQ6IF8ubGFiZWwrKzsgcmV0dXJuIHsgdmFsdWU6IG9wWzFdLCBkb25lOiBmYWxzZSB9O1xyXG4gICAgICAgICAgICAgICAgY2FzZSA1OiBfLmxhYmVsKys7IHkgPSBvcFsxXTsgb3AgPSBbMF07IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICAgICAgY2FzZSA3OiBvcCA9IF8ub3BzLnBvcCgpOyBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgICAgICAgICAgICBpZiAoISh0ID0gXy50cnlzLCB0ID0gdC5sZW5ndGggPiAwICYmIHRbdC5sZW5ndGggLSAxXSkgJiYgKG9wWzBdID09PSA2IHx8IG9wWzBdID09PSAyKSkgeyBfID0gMDsgY29udGludWU7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAob3BbMF0gPT09IDMgJiYgKCF0IHx8IChvcFsxXSA+IHRbMF0gJiYgb3BbMV0gPCB0WzNdKSkpIHsgXy5sYWJlbCA9IG9wWzFdOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gNiAmJiBfLmxhYmVsIDwgdFsxXSkgeyBfLmxhYmVsID0gdFsxXTsgdCA9IG9wOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0ICYmIF8ubGFiZWwgPCB0WzJdKSB7IF8ubGFiZWwgPSB0WzJdOyBfLm9wcy5wdXNoKG9wKTsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAodFsyXSkgXy5vcHMucG9wKCk7XHJcbiAgICAgICAgICAgICAgICAgICAgXy50cnlzLnBvcCgpOyBjb250aW51ZTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBvcCA9IGJvZHkuY2FsbCh0aGlzQXJnLCBfKTtcclxuICAgICAgICB9IGNhdGNoIChlKSB7IG9wID0gWzYsIGVdOyB5ID0gMDsgfSBmaW5hbGx5IHsgZiA9IHQgPSAwOyB9XHJcbiAgICAgICAgaWYgKG9wWzBdICYgNSkgdGhyb3cgb3BbMV07IHJldHVybiB7IHZhbHVlOiBvcFswXSA/IG9wWzFdIDogdm9pZCAwLCBkb25lOiB0cnVlIH07XHJcbiAgICB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NyZWF0ZUJpbmRpbmcobywgbSwgaywgazIpIHtcclxuICAgIGlmIChrMiA9PT0gdW5kZWZpbmVkKSBrMiA9IGs7XHJcbiAgICBvW2syXSA9IG1ba107XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2V4cG9ydFN0YXIobSwgZXhwb3J0cykge1xyXG4gICAgZm9yICh2YXIgcCBpbiBtKSBpZiAocCAhPT0gXCJkZWZhdWx0XCIgJiYgIWV4cG9ydHMuaGFzT3duUHJvcGVydHkocCkpIGV4cG9ydHNbcF0gPSBtW3BdO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX192YWx1ZXMobykge1xyXG4gICAgdmFyIHMgPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgU3ltYm9sLml0ZXJhdG9yLCBtID0gcyAmJiBvW3NdLCBpID0gMDtcclxuICAgIGlmIChtKSByZXR1cm4gbS5jYWxsKG8pO1xyXG4gICAgaWYgKG8gJiYgdHlwZW9mIG8ubGVuZ3RoID09PSBcIm51bWJlclwiKSByZXR1cm4ge1xyXG4gICAgICAgIG5leHQ6IGZ1bmN0aW9uICgpIHtcclxuICAgICAgICAgICAgaWYgKG8gJiYgaSA+PSBvLmxlbmd0aCkgbyA9IHZvaWQgMDtcclxuICAgICAgICAgICAgcmV0dXJuIHsgdmFsdWU6IG8gJiYgb1tpKytdLCBkb25lOiAhbyB9O1xyXG4gICAgICAgIH1cclxuICAgIH07XHJcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKHMgPyBcIk9iamVjdCBpcyBub3QgaXRlcmFibGUuXCIgOiBcIlN5bWJvbC5pdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3JlYWQobywgbikge1xyXG4gICAgdmFyIG0gPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgb1tTeW1ib2wuaXRlcmF0b3JdO1xyXG4gICAgaWYgKCFtKSByZXR1cm4gbztcclxuICAgIHZhciBpID0gbS5jYWxsKG8pLCByLCBhciA9IFtdLCBlO1xyXG4gICAgdHJ5IHtcclxuICAgICAgICB3aGlsZSAoKG4gPT09IHZvaWQgMCB8fCBuLS0gPiAwKSAmJiAhKHIgPSBpLm5leHQoKSkuZG9uZSkgYXIucHVzaChyLnZhbHVlKTtcclxuICAgIH1cclxuICAgIGNhdGNoIChlcnJvcikgeyBlID0geyBlcnJvcjogZXJyb3IgfTsgfVxyXG4gICAgZmluYWxseSB7XHJcbiAgICAgICAgdHJ5IHtcclxuICAgICAgICAgICAgaWYgKHIgJiYgIXIuZG9uZSAmJiAobSA9IGlbXCJyZXR1cm5cIl0pKSBtLmNhbGwoaSk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGZpbmFsbHkgeyBpZiAoZSkgdGhyb3cgZS5lcnJvcjsgfVxyXG4gICAgfVxyXG4gICAgcmV0dXJuIGFyO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19zcHJlYWQoKSB7XHJcbiAgICBmb3IgKHZhciBhciA9IFtdLCBpID0gMDsgaSA8IGFyZ3VtZW50cy5sZW5ndGg7IGkrKylcclxuICAgICAgICBhciA9IGFyLmNvbmNhdChfX3JlYWQoYXJndW1lbnRzW2ldKSk7XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZEFycmF5cygpIHtcclxuICAgIGZvciAodmFyIHMgPSAwLCBpID0gMCwgaWwgPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgaWw7IGkrKykgcyArPSBhcmd1bWVudHNbaV0ubGVuZ3RoO1xyXG4gICAgZm9yICh2YXIgciA9IEFycmF5KHMpLCBrID0gMCwgaSA9IDA7IGkgPCBpbDsgaSsrKVxyXG4gICAgICAgIGZvciAodmFyIGEgPSBhcmd1bWVudHNbaV0sIGogPSAwLCBqbCA9IGEubGVuZ3RoOyBqIDwgamw7IGorKywgaysrKVxyXG4gICAgICAgICAgICByW2tdID0gYVtqXTtcclxuICAgIHJldHVybiByO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXQodikge1xyXG4gICAgcmV0dXJuIHRoaXMgaW5zdGFuY2VvZiBfX2F3YWl0ID8gKHRoaXMudiA9IHYsIHRoaXMpIDogbmV3IF9fYXdhaXQodik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jR2VuZXJhdG9yKHRoaXNBcmcsIF9hcmd1bWVudHMsIGdlbmVyYXRvcikge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBnID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pLCBpLCBxID0gW107XHJcbiAgICByZXR1cm4gaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIpLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaWYgKGdbbl0pIGlbbl0gPSBmdW5jdGlvbiAodikgeyByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKGEsIGIpIHsgcS5wdXNoKFtuLCB2LCBhLCBiXSkgPiAxIHx8IHJlc3VtZShuLCB2KTsgfSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHJlc3VtZShuLCB2KSB7IHRyeSB7IHN0ZXAoZ1tuXSh2KSk7IH0gY2F0Y2ggKGUpIHsgc2V0dGxlKHFbMF1bM10sIGUpOyB9IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAocikgeyByLnZhbHVlIGluc3RhbmNlb2YgX19hd2FpdCA/IFByb21pc2UucmVzb2x2ZShyLnZhbHVlLnYpLnRoZW4oZnVsZmlsbCwgcmVqZWN0KSA6IHNldHRsZShxWzBdWzJdLCByKTsgfVxyXG4gICAgZnVuY3Rpb24gZnVsZmlsbCh2YWx1ZSkgeyByZXN1bWUoXCJuZXh0XCIsIHZhbHVlKTsgfVxyXG4gICAgZnVuY3Rpb24gcmVqZWN0KHZhbHVlKSB7IHJlc3VtZShcInRocm93XCIsIHZhbHVlKTsgfVxyXG4gICAgZnVuY3Rpb24gc2V0dGxlKGYsIHYpIHsgaWYgKGYodiksIHEuc2hpZnQoKSwgcS5sZW5ndGgpIHJlc3VtZShxWzBdWzBdLCBxWzBdWzFdKTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY0RlbGVnYXRvcihvKSB7XHJcbiAgICB2YXIgaSwgcDtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiwgZnVuY3Rpb24gKGUpIHsgdGhyb3cgZTsgfSksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4sIGYpIHsgaVtuXSA9IG9bbl0gPyBmdW5jdGlvbiAodikgeyByZXR1cm4gKHAgPSAhcCkgPyB7IHZhbHVlOiBfX2F3YWl0KG9bbl0odikpLCBkb25lOiBuID09PSBcInJldHVyblwiIH0gOiBmID8gZih2KSA6IHY7IH0gOiBmOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jVmFsdWVzKG8pIHtcclxuICAgIGlmICghU3ltYm9sLmFzeW5jSXRlcmF0b3IpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTeW1ib2wuYXN5bmNJdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbiAgICB2YXIgbSA9IG9bU3ltYm9sLmFzeW5jSXRlcmF0b3JdLCBpO1xyXG4gICAgcmV0dXJuIG0gPyBtLmNhbGwobykgOiAobyA9IHR5cGVvZiBfX3ZhbHVlcyA9PT0gXCJmdW5jdGlvblwiID8gX192YWx1ZXMobykgOiBvW1N5bWJvbC5pdGVyYXRvcl0oKSwgaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIpLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGkpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IGlbbl0gPSBvW25dICYmIGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7IHYgPSBvW25dKHYpLCBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCB2LmRvbmUsIHYudmFsdWUpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gc2V0dGxlKHJlc29sdmUsIHJlamVjdCwgZCwgdikgeyBQcm9taXNlLnJlc29sdmUodikudGhlbihmdW5jdGlvbih2KSB7IHJlc29sdmUoeyB2YWx1ZTogdiwgZG9uZTogZCB9KTsgfSwgcmVqZWN0KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tYWtlVGVtcGxhdGVPYmplY3QoY29va2VkLCByYXcpIHtcclxuICAgIGlmIChPYmplY3QuZGVmaW5lUHJvcGVydHkpIHsgT2JqZWN0LmRlZmluZVByb3BlcnR5KGNvb2tlZCwgXCJyYXdcIiwgeyB2YWx1ZTogcmF3IH0pOyB9IGVsc2UgeyBjb29rZWQucmF3ID0gcmF3OyB9XHJcbiAgICByZXR1cm4gY29va2VkO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9faW1wb3J0U3Rhcihtb2QpIHtcclxuICAgIGlmIChtb2QgJiYgbW9kLl9fZXNNb2R1bGUpIHJldHVybiBtb2Q7XHJcbiAgICB2YXIgcmVzdWx0ID0ge307XHJcbiAgICBpZiAobW9kICE9IG51bGwpIGZvciAodmFyIGsgaW4gbW9kKSBpZiAoT2JqZWN0Lmhhc093blByb3BlcnR5LmNhbGwobW9kLCBrKSkgcmVzdWx0W2tdID0gbW9kW2tdO1xyXG4gICAgcmVzdWx0LmRlZmF1bHQgPSBtb2Q7XHJcbiAgICByZXR1cm4gcmVzdWx0O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnREZWZhdWx0KG1vZCkge1xyXG4gICAgcmV0dXJuIChtb2QgJiYgbW9kLl9fZXNNb2R1bGUpID8gbW9kIDogeyBkZWZhdWx0OiBtb2QgfTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY2xhc3NQcml2YXRlRmllbGRHZXQocmVjZWl2ZXIsIHByaXZhdGVNYXApIHtcclxuICAgIGlmICghcHJpdmF0ZU1hcC5oYXMocmVjZWl2ZXIpKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcImF0dGVtcHRlZCB0byBnZXQgcHJpdmF0ZSBmaWVsZCBvbiBub24taW5zdGFuY2VcIik7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gcHJpdmF0ZU1hcC5nZXQocmVjZWl2ZXIpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZFNldChyZWNlaXZlciwgcHJpdmF0ZU1hcCwgdmFsdWUpIHtcclxuICAgIGlmICghcHJpdmF0ZU1hcC5oYXMocmVjZWl2ZXIpKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcImF0dGVtcHRlZCB0byBzZXQgcHJpdmF0ZSBmaWVsZCBvbiBub24taW5zdGFuY2VcIik7XHJcbiAgICB9XHJcbiAgICBwcml2YXRlTWFwLnNldChyZWNlaXZlciwgdmFsdWUpO1xyXG4gICAgcmV0dXJuIHZhbHVlO1xyXG59XHJcbiIsIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduLCBfX2V4dGVuZHMgfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IGVuY29kZUZvcm1EYXRhIH0gZnJvbSBcIi4vdXRpbHMvZW5jb2RlLWZvcm0tZGF0YVwiO1xuaW1wb3J0IHsgZW5jb2RlUXVlcnlTdHJpbmcgfSBmcm9tIFwiLi91dGlscy9lbmNvZGUtcXVlcnktc3RyaW5nXCI7XG5pbXBvcnQgeyByZXF1aXJlc0Zvcm1EYXRhIH0gZnJvbSBcIi4vdXRpbHMvcHJvY2Vzcy1wYXJhbXNcIjtcbmltcG9ydCB7IEFyY0dJU1JlcXVlc3RFcnJvciB9IGZyb20gXCIuL3V0aWxzL0FyY0dJU1JlcXVlc3RFcnJvclwiO1xuaW1wb3J0IHsgd2FybiB9IGZyb20gXCIuL3V0aWxzL3dhcm5cIjtcbmV4cG9ydCB2YXIgTk9ERUpTX0RFRkFVTFRfUkVGRVJFUl9IRUFERVIgPSBcIkBlc3JpL2FyY2dpcy1yZXN0LWpzXCI7XG52YXIgREVGQVVMVF9BUkNHSVNfUkVRVUVTVF9PUFRJT05TID0ge1xuICAgIGh0dHBNZXRob2Q6IFwiUE9TVFwiLFxuICAgIHBhcmFtczoge1xuICAgICAgICBmOiBcImpzb25cIixcbiAgICB9LFxufTtcbi8qKlxuICogU2V0cyB0aGUgZGVmYXVsdCBvcHRpb25zIHRoYXQgd2lsbCBiZSBwYXNzZWQgaW4gKiphbGwgcmVxdWVzdHMgYWNyb3NzIGFsbCBgQGVzcmkvYXJjZ2lzLXJlc3QtanNgIG1vZHVsZXMqKi5cbiAqXG4gKlxuICogYGBganNcbiAqIGltcG9ydCB7IHNldERlZmF1bHRSZXF1ZXN0T3B0aW9ucyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4gKiBzZXREZWZhdWx0UmVxdWVzdE9wdGlvbnMoe1xuICogICBhdXRoZW50aWNhdGlvbjogdXNlclNlc3Npb24gLy8gYWxsIHJlcXVlc3RzIHdpbGwgdXNlIHRoaXMgc2Vzc2lvbiBieSBkZWZhdWx0XG4gKiB9KVxuICogYGBgXG4gKiBZb3Ugc2hvdWxkICoqbmV2ZXIqKiBzZXQgYSBkZWZhdWx0IGBhdXRoZW50aWNhdGlvbmAgd2hlbiB5b3UgYXJlIGluIGEgc2VydmVyIHNpZGUgZW52aXJvbm1lbnQgd2hlcmUgeW91IG1heSBiZSBoYW5kbGluZyByZXF1ZXN0cyBmb3IgbWFueSBkaWZmZXJlbnQgYXV0aGVudGljYXRlZCB1c2Vycy5cbiAqXG4gKiBAcGFyYW0gb3B0aW9ucyBUaGUgZGVmYXVsdCBvcHRpb25zIHRvIHBhc3Mgd2l0aCBldmVyeSByZXF1ZXN0LiBFeGlzdGluZyBkZWZhdWx0IHdpbGwgYmUgb3ZlcndyaXR0ZW4uXG4gKiBAcGFyYW0gaGlkZVdhcm5pbmdzIFNpbGVuY2Ugd2FybmluZ3MgYWJvdXQgc2V0dGluZyBkZWZhdWx0IGBhdXRoZW50aWNhdGlvbmAgaW4gc2hhcmVkIGVudmlyb25tZW50cy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHNldERlZmF1bHRSZXF1ZXN0T3B0aW9ucyhvcHRpb25zLCBoaWRlV2FybmluZ3MpIHtcbiAgICBpZiAob3B0aW9ucy5hdXRoZW50aWNhdGlvbiAmJiAhaGlkZVdhcm5pbmdzKSB7XG4gICAgICAgIHdhcm4oXCJZb3Ugc2hvdWxkIG5vdCBzZXQgYGF1dGhlbnRpY2F0aW9uYCBhcyBhIGRlZmF1bHQgaW4gYSBzaGFyZWQgZW52aXJvbm1lbnQgc3VjaCBhcyBhIHdlYiBzZXJ2ZXIgd2hpY2ggd2lsbCBwcm9jZXNzIG11bHRpcGxlIHVzZXJzIHJlcXVlc3RzLiBZb3UgY2FuIGNhbGwgYHNldERlZmF1bHRSZXF1ZXN0T3B0aW9uc2Agd2l0aCBgdHJ1ZWAgYXMgYSBzZWNvbmQgYXJndW1lbnQgdG8gZGlzYWJsZSB0aGlzIHdhcm5pbmcuXCIpO1xuICAgIH1cbiAgICBERUZBVUxUX0FSQ0dJU19SRVFVRVNUX09QVElPTlMgPSBvcHRpb25zO1xufVxudmFyIEFyY0dJU0F1dGhFcnJvciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoQXJjR0lTQXV0aEVycm9yLCBfc3VwZXIpO1xuICAgIC8qKlxuICAgICAqIENyZWF0ZSBhIG5ldyBgQXJjR0lTQXV0aEVycm9yYCAgb2JqZWN0LlxuICAgICAqXG4gICAgICogQHBhcmFtIG1lc3NhZ2UgLSBUaGUgZXJyb3IgbWVzc2FnZSBmcm9tIHRoZSBBUElcbiAgICAgKiBAcGFyYW0gY29kZSAtIFRoZSBlcnJvciBjb2RlIGZyb20gdGhlIEFQSVxuICAgICAqIEBwYXJhbSByZXNwb25zZSAtIFRoZSBvcmlnaW5hbCByZXNwb25zZSBmcm9tIHRoZSBBUEkgdGhhdCBjYXVzZWQgdGhlIGVycm9yXG4gICAgICogQHBhcmFtIHVybCAtIFRoZSBvcmlnaW5hbCB1cmwgb2YgdGhlIHJlcXVlc3RcbiAgICAgKiBAcGFyYW0gb3B0aW9ucyAtIFRoZSBvcmlnaW5hbCBvcHRpb25zIG9mIHRoZSByZXF1ZXN0XG4gICAgICovXG4gICAgZnVuY3Rpb24gQXJjR0lTQXV0aEVycm9yKG1lc3NhZ2UsIGNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpIHtcbiAgICAgICAgaWYgKG1lc3NhZ2UgPT09IHZvaWQgMCkgeyBtZXNzYWdlID0gXCJBVVRIRU5USUNBVElPTl9FUlJPUlwiOyB9XG4gICAgICAgIGlmIChjb2RlID09PSB2b2lkIDApIHsgY29kZSA9IFwiQVVUSEVOVElDQVRJT05fRVJST1JfQ09ERVwiOyB9XG4gICAgICAgIHZhciBfdGhpcyA9IF9zdXBlci5jYWxsKHRoaXMsIG1lc3NhZ2UsIGNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpIHx8IHRoaXM7XG4gICAgICAgIF90aGlzLm5hbWUgPSBcIkFyY0dJU0F1dGhFcnJvclwiO1xuICAgICAgICBfdGhpcy5tZXNzYWdlID1cbiAgICAgICAgICAgIGNvZGUgPT09IFwiQVVUSEVOVElDQVRJT05fRVJST1JfQ09ERVwiID8gbWVzc2FnZSA6IGNvZGUgKyBcIjogXCIgKyBtZXNzYWdlO1xuICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgfVxuICAgIEFyY0dJU0F1dGhFcnJvci5wcm90b3R5cGUucmV0cnkgPSBmdW5jdGlvbiAoZ2V0U2Vzc2lvbiwgcmV0cnlMaW1pdCkge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBpZiAocmV0cnlMaW1pdCA9PT0gdm9pZCAwKSB7IHJldHJ5TGltaXQgPSAzOyB9XG4gICAgICAgIHZhciB0cmllcyA9IDA7XG4gICAgICAgIHZhciByZXRyeVJlcXVlc3QgPSBmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XG4gICAgICAgICAgICBnZXRTZXNzaW9uKF90aGlzLnVybCwgX3RoaXMub3B0aW9ucylcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAoc2Vzc2lvbikge1xuICAgICAgICAgICAgICAgIHZhciBuZXdPcHRpb25zID0gX19hc3NpZ24oX19hc3NpZ24oe30sIF90aGlzLm9wdGlvbnMpLCB7IGF1dGhlbnRpY2F0aW9uOiBzZXNzaW9uIH0pO1xuICAgICAgICAgICAgICAgIHRyaWVzID0gdHJpZXMgKyAxO1xuICAgICAgICAgICAgICAgIHJldHVybiByZXF1ZXN0KF90aGlzLnVybCwgbmV3T3B0aW9ucyk7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIHJlc29sdmUocmVzcG9uc2UpO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAuY2F0Y2goZnVuY3Rpb24gKGUpIHtcbiAgICAgICAgICAgICAgICBpZiAoZS5uYW1lID09PSBcIkFyY0dJU0F1dGhFcnJvclwiICYmIHRyaWVzIDwgcmV0cnlMaW1pdCkge1xuICAgICAgICAgICAgICAgICAgICByZXRyeVJlcXVlc3QocmVzb2x2ZSwgcmVqZWN0KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAoZS5uYW1lID09PSBcIkFyY0dJU0F1dGhFcnJvclwiICYmIHRyaWVzID49IHJldHJ5TGltaXQpIHtcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0KF90aGlzKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfTtcbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcbiAgICAgICAgICAgIHJldHJ5UmVxdWVzdChyZXNvbHZlLCByZWplY3QpO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIHJldHVybiBBcmNHSVNBdXRoRXJyb3I7XG59KEFyY0dJU1JlcXVlc3RFcnJvcikpO1xuZXhwb3J0IHsgQXJjR0lTQXV0aEVycm9yIH07XG4vKipcbiAqIENoZWNrcyBmb3IgZXJyb3JzIGluIGEgSlNPTiByZXNwb25zZSBmcm9tIHRoZSBBcmNHSVMgUkVTVCBBUEkuIElmIHRoZXJlIGFyZSBubyBlcnJvcnMsIGl0IHdpbGwgcmV0dXJuIHRoZSBgZGF0YWAgcGFzc2VkIGluLiBJZiB0aGVyZSBpcyBhbiBlcnJvciwgaXQgd2lsbCB0aHJvdyBhbiBgQXJjR0lTUmVxdWVzdEVycm9yYCBvciBgQXJjR0lTQXV0aEVycm9yYC5cbiAqXG4gKiBAcGFyYW0gZGF0YSBUaGUgcmVzcG9uc2UgSlNPTiB0byBjaGVjayBmb3IgZXJyb3JzLlxuICogQHBhcmFtIHVybCBUaGUgdXJsIG9mIHRoZSBvcmlnaW5hbCByZXF1ZXN0XG4gKiBAcGFyYW0gcGFyYW1zIFRoZSBwYXJhbWV0ZXJzIG9mIHRoZSBvcmlnaW5hbCByZXF1ZXN0XG4gKiBAcGFyYW0gb3B0aW9ucyBUaGUgb3B0aW9ucyBvZiB0aGUgb3JpZ2luYWwgcmVxdWVzdFxuICogQHJldHVybnMgVGhlIGRhdGEgdGhhdCB3YXMgcGFzc2VkIGluIHRoZSBgZGF0YWAgcGFyYW1ldGVyXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBjaGVja0ZvckVycm9ycyhyZXNwb25zZSwgdXJsLCBwYXJhbXMsIG9wdGlvbnMsIG9yaWdpbmFsQXV0aEVycm9yKSB7XG4gICAgLy8gdGhpcyBpcyBhbiBlcnJvciBtZXNzYWdlIGZyb20gYmlsbGluZy5hcmNnaXMuY29tIGJhY2tlbmRcbiAgICBpZiAocmVzcG9uc2UuY29kZSA+PSA0MDApIHtcbiAgICAgICAgdmFyIG1lc3NhZ2UgPSByZXNwb25zZS5tZXNzYWdlLCBjb2RlID0gcmVzcG9uc2UuY29kZTtcbiAgICAgICAgdGhyb3cgbmV3IEFyY0dJU1JlcXVlc3RFcnJvcihtZXNzYWdlLCBjb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKTtcbiAgICB9XG4gICAgLy8gZXJyb3IgZnJvbSBBcmNHSVMgT25saW5lIG9yIGFuIEFyY0dJUyBQb3J0YWwgb3Igc2VydmVyIGluc3RhbmNlLlxuICAgIGlmIChyZXNwb25zZS5lcnJvcikge1xuICAgICAgICB2YXIgX2EgPSByZXNwb25zZS5lcnJvciwgbWVzc2FnZSA9IF9hLm1lc3NhZ2UsIGNvZGUgPSBfYS5jb2RlLCBtZXNzYWdlQ29kZSA9IF9hLm1lc3NhZ2VDb2RlO1xuICAgICAgICB2YXIgZXJyb3JDb2RlID0gbWVzc2FnZUNvZGUgfHwgY29kZSB8fCBcIlVOS05PV05fRVJST1JfQ09ERVwiO1xuICAgICAgICBpZiAoY29kZSA9PT0gNDk4IHx8XG4gICAgICAgICAgICBjb2RlID09PSA0OTkgfHxcbiAgICAgICAgICAgIG1lc3NhZ2VDb2RlID09PSBcIkdXTV8wMDAzXCIgfHxcbiAgICAgICAgICAgIChjb2RlID09PSA0MDAgJiYgbWVzc2FnZSA9PT0gXCJVbmFibGUgdG8gZ2VuZXJhdGUgdG9rZW4uXCIpKSB7XG4gICAgICAgICAgICBpZiAob3JpZ2luYWxBdXRoRXJyb3IpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBvcmlnaW5hbEF1dGhFcnJvcjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNBdXRoRXJyb3IobWVzc2FnZSwgZXJyb3JDb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICB0aHJvdyBuZXcgQXJjR0lTUmVxdWVzdEVycm9yKG1lc3NhZ2UsIGVycm9yQ29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucyk7XG4gICAgfVxuICAgIC8vIGVycm9yIGZyb20gYSBzdGF0dXMgY2hlY2tcbiAgICBpZiAocmVzcG9uc2Uuc3RhdHVzID09PSBcImZhaWxlZFwiIHx8IHJlc3BvbnNlLnN0YXR1cyA9PT0gXCJmYWlsdXJlXCIpIHtcbiAgICAgICAgdmFyIG1lc3NhZ2UgPSB2b2lkIDA7XG4gICAgICAgIHZhciBjb2RlID0gXCJVTktOT1dOX0VSUk9SX0NPREVcIjtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIG1lc3NhZ2UgPSBKU09OLnBhcnNlKHJlc3BvbnNlLnN0YXR1c01lc3NhZ2UpLm1lc3NhZ2U7XG4gICAgICAgICAgICBjb2RlID0gSlNPTi5wYXJzZShyZXNwb25zZS5zdGF0dXNNZXNzYWdlKS5jb2RlO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlKSB7XG4gICAgICAgICAgICBtZXNzYWdlID0gcmVzcG9uc2Uuc3RhdHVzTWVzc2FnZSB8fCByZXNwb25zZS5tZXNzYWdlO1xuICAgICAgICB9XG4gICAgICAgIHRocm93IG5ldyBBcmNHSVNSZXF1ZXN0RXJyb3IobWVzc2FnZSwgY29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucyk7XG4gICAgfVxuICAgIHJldHVybiByZXNwb25zZTtcbn1cbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IHJlcXVlc3QgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0JztcbiAqIC8vXG4gKiByZXF1ZXN0KCdodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdCcpXG4gKiAgIC50aGVuKHJlc3BvbnNlKSAvLyByZXNwb25zZS5jdXJyZW50VmVyc2lvbiA9PT0gNS4yXG4gKiAvL1xuICogcmVxdWVzdCgnaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3QnLCB7XG4gKiAgIGh0dHBNZXRob2Q6IFwiR0VUXCJcbiAqIH0pXG4gKiAvL1xuICogcmVxdWVzdCgnaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3Qvc2VhcmNoJywge1xuICogICBwYXJhbXM6IHsgcTogJ3BhcmtzJyB9XG4gKiB9KVxuICogICAudGhlbihyZXNwb25zZSkgLy8gcmVzcG9uc2UudG90YWwgPT4gNzgzNzlcbiAqIGBgYFxuICogR2VuZXJpYyBtZXRob2QgZm9yIG1ha2luZyBIVFRQIHJlcXVlc3RzIHRvIEFyY0dJUyBSRVNUIEFQSSBlbmRwb2ludHMuXG4gKlxuICogQHBhcmFtIHVybCAtIFRoZSBVUkwgb2YgdGhlIEFyY0dJUyBSRVNUIEFQSSBlbmRwb2ludC5cbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0LCBpbmNsdWRpbmcgcGFyYW1ldGVycyByZWxldmFudCB0byB0aGUgZW5kcG9pbnQuXG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgZGF0YSBmcm9tIHRoZSByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHJlcXVlc3QodXJsLCByZXF1ZXN0T3B0aW9ucykge1xuICAgIGlmIChyZXF1ZXN0T3B0aW9ucyA9PT0gdm9pZCAwKSB7IHJlcXVlc3RPcHRpb25zID0geyBwYXJhbXM6IHsgZjogXCJqc29uXCIgfSB9OyB9XG4gICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbihfX2Fzc2lnbihfX2Fzc2lnbih7IGh0dHBNZXRob2Q6IFwiUE9TVFwiIH0sIERFRkFVTFRfQVJDR0lTX1JFUVVFU1RfT1BUSU9OUyksIHJlcXVlc3RPcHRpb25zKSwge1xuICAgICAgICBwYXJhbXM6IF9fYXNzaWduKF9fYXNzaWduKHt9LCBERUZBVUxUX0FSQ0dJU19SRVFVRVNUX09QVElPTlMucGFyYW1zKSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKSxcbiAgICAgICAgaGVhZGVyczogX19hc3NpZ24oX19hc3NpZ24oe30sIERFRkFVTFRfQVJDR0lTX1JFUVVFU1RfT1BUSU9OUy5oZWFkZXJzKSwgcmVxdWVzdE9wdGlvbnMuaGVhZGVycyksXG4gICAgfSk7XG4gICAgdmFyIG1pc3NpbmdHbG9iYWxzID0gW107XG4gICAgdmFyIHJlY29tbWVuZGVkUGFja2FnZXMgPSBbXTtcbiAgICAvLyBkb24ndCBjaGVjayBmb3IgYSBnbG9iYWwgZmV0Y2ggaWYgYSBjdXN0b20gaW1wbGVtZW50YXRpb24gd2FzIHBhc3NlZCB0aHJvdWdoXG4gICAgaWYgKCFvcHRpb25zLmZldGNoICYmIHR5cGVvZiBmZXRjaCAhPT0gXCJ1bmRlZmluZWRcIikge1xuICAgICAgICBvcHRpb25zLmZldGNoID0gZmV0Y2guYmluZChGdW5jdGlvbihcInJldHVybiB0aGlzXCIpKCkpO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgbWlzc2luZ0dsb2JhbHMucHVzaChcImBmZXRjaGBcIik7XG4gICAgICAgIHJlY29tbWVuZGVkUGFja2FnZXMucHVzaChcImBub2RlLWZldGNoYFwiKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBQcm9taXNlID09PSBcInVuZGVmaW5lZFwiKSB7XG4gICAgICAgIG1pc3NpbmdHbG9iYWxzLnB1c2goXCJgUHJvbWlzZWBcIik7XG4gICAgICAgIHJlY29tbWVuZGVkUGFja2FnZXMucHVzaChcImBlczYtcHJvbWlzZWBcIik7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgRm9ybURhdGEgPT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgbWlzc2luZ0dsb2JhbHMucHVzaChcImBGb3JtRGF0YWBcIik7XG4gICAgICAgIHJlY29tbWVuZGVkUGFja2FnZXMucHVzaChcImBpc29tb3JwaGljLWZvcm0tZGF0YWBcIik7XG4gICAgfVxuICAgIGlmICghb3B0aW9ucy5mZXRjaCB8fFxuICAgICAgICB0eXBlb2YgUHJvbWlzZSA9PT0gXCJ1bmRlZmluZWRcIiB8fFxuICAgICAgICB0eXBlb2YgRm9ybURhdGEgPT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiYGFyY2dpcy1yZXN0LXJlcXVlc3RgIHJlcXVpcmVzIGEgYGZldGNoYCBpbXBsZW1lbnRhdGlvbiBhbmQgZ2xvYmFsIHZhcmlhYmxlcyBmb3IgYFByb21pc2VgIGFuZCBgRm9ybURhdGFgIHRvIGJlIHByZXNlbnQgaW4gdGhlIGdsb2JhbCBzY29wZS4gWW91IGFyZSBtaXNzaW5nIFwiICsgbWlzc2luZ0dsb2JhbHMuam9pbihcIiwgXCIpICsgXCIuIFdlIHJlY29tbWVuZCBpbnN0YWxsaW5nIHRoZSBcIiArIHJlY29tbWVuZGVkUGFja2FnZXMuam9pbihcIiwgXCIpICsgXCIgbW9kdWxlcyBhdCB0aGUgcm9vdCBvZiB5b3VyIGFwcGxpY2F0aW9uIHRvIGFkZCB0aGVzZSB0byB0aGUgZ2xvYmFsIHNjb3BlLiBTZWUgaHR0cHM6Ly9iaXQubHkvMktOd1dhSiBmb3IgbW9yZSBpbmZvLlwiKTtcbiAgICB9XG4gICAgdmFyIGh0dHBNZXRob2QgPSBvcHRpb25zLmh0dHBNZXRob2QsIGF1dGhlbnRpY2F0aW9uID0gb3B0aW9ucy5hdXRoZW50aWNhdGlvbiwgcmF3UmVzcG9uc2UgPSBvcHRpb25zLnJhd1Jlc3BvbnNlO1xuICAgIHZhciBwYXJhbXMgPSBfX2Fzc2lnbih7IGY6IFwianNvblwiIH0sIG9wdGlvbnMucGFyYW1zKTtcbiAgICB2YXIgb3JpZ2luYWxBdXRoRXJyb3IgPSBudWxsO1xuICAgIHZhciBmZXRjaE9wdGlvbnMgPSB7XG4gICAgICAgIG1ldGhvZDogaHR0cE1ldGhvZCxcbiAgICAgICAgLyogZW5zdXJlcyBiZWhhdmlvciBtaW1pY3MgWE1MSHR0cFJlcXVlc3QuXG4gICAgICAgIG5lZWRlZCB0byBzdXBwb3J0IHNlbmRpbmcgSVdBIGNvb2tpZXMgKi9cbiAgICAgICAgY3JlZGVudGlhbHM6IG9wdGlvbnMuY3JlZGVudGlhbHMgfHwgXCJzYW1lLW9yaWdpblwiLFxuICAgIH07XG4gICAgLy8gdGhlIC9vYXV0aDIvcGxhdGZvcm1TZWxmIHJvdXRlIHdpbGwgYWRkIFgtRXNyaS1BdXRoLUNsaWVudC1JZCBoZWFkZXJcbiAgICAvLyBhbmQgdGhhdCByZXF1ZXN0IG5lZWRzIHRvIHNlbmQgY29va2llcyBjcm9zcyBkb21haW5cbiAgICAvLyBzbyB3ZSBuZWVkIHRvIHNldCB0aGUgY3JlZGVudGlhbHMgdG8gXCJpbmNsdWRlXCJcbiAgICBpZiAob3B0aW9ucy5oZWFkZXJzICYmXG4gICAgICAgIG9wdGlvbnMuaGVhZGVyc1tcIlgtRXNyaS1BdXRoLUNsaWVudC1JZFwiXSAmJlxuICAgICAgICB1cmwuaW5kZXhPZihcIi9vYXV0aDIvcGxhdGZvcm1TZWxmXCIpID4gLTEpIHtcbiAgICAgICAgZmV0Y2hPcHRpb25zLmNyZWRlbnRpYWxzID0gXCJpbmNsdWRlXCI7XG4gICAgfVxuICAgIHJldHVybiAoYXV0aGVudGljYXRpb25cbiAgICAgICAgPyBhdXRoZW50aWNhdGlvbi5nZXRUb2tlbih1cmwsIHsgZmV0Y2g6IG9wdGlvbnMuZmV0Y2ggfSkuY2F0Y2goZnVuY3Rpb24gKGVycikge1xuICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgKiBhcHBlbmQgb3JpZ2luYWwgcmVxdWVzdCB1cmwgYW5kIHJlcXVlc3RPcHRpb25zXG4gICAgICAgICAgICAgKiB0byB0aGUgZXJyb3IgdGhyb3duIGJ5IGdldFRva2VuKClcbiAgICAgICAgICAgICAqIHRvIGFzc2lzdCB3aXRoIHJldHJ5aW5nXG4gICAgICAgICAgICAgKi9cbiAgICAgICAgICAgIGVyci51cmwgPSB1cmw7XG4gICAgICAgICAgICBlcnIub3B0aW9ucyA9IG9wdGlvbnM7XG4gICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAqIGlmIGFuIGF0dGVtcHQgaXMgbWFkZSB0byB0YWxrIHRvIGFuIHVuZmVkZXJhdGVkIHNlcnZlclxuICAgICAgICAgICAgICogZmlyc3QgdHJ5IHRoZSByZXF1ZXN0IGFub255bW91c2x5LiBpZiBhICd0b2tlbiByZXF1aXJlZCdcbiAgICAgICAgICAgICAqIGVycm9yIGlzIHRocm93biwgdGhyb3cgdGhlIFVORkVERVJBVEVEIGVycm9yIHRoZW4uXG4gICAgICAgICAgICAgKi9cbiAgICAgICAgICAgIG9yaWdpbmFsQXV0aEVycm9yID0gZXJyO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShcIlwiKTtcbiAgICAgICAgfSlcbiAgICAgICAgOiBQcm9taXNlLnJlc29sdmUoXCJcIikpXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uICh0b2tlbikge1xuICAgICAgICBpZiAodG9rZW4ubGVuZ3RoKSB7XG4gICAgICAgICAgICBwYXJhbXMudG9rZW4gPSB0b2tlbjtcbiAgICAgICAgfVxuICAgICAgICBpZiAoYXV0aGVudGljYXRpb24gJiYgYXV0aGVudGljYXRpb24uZ2V0RG9tYWluQ3JlZGVudGlhbHMpIHtcbiAgICAgICAgICAgIGZldGNoT3B0aW9ucy5jcmVkZW50aWFscyA9IGF1dGhlbnRpY2F0aW9uLmdldERvbWFpbkNyZWRlbnRpYWxzKHVybCk7XG4gICAgICAgIH1cbiAgICAgICAgLy8gQ3VzdG9tIGhlYWRlcnMgdG8gYWRkIHRvIHJlcXVlc3QuIElSZXF1ZXN0T3B0aW9ucy5oZWFkZXJzIHdpdGggbWVyZ2Ugb3ZlciByZXF1ZXN0SGVhZGVycy5cbiAgICAgICAgdmFyIHJlcXVlc3RIZWFkZXJzID0ge307XG4gICAgICAgIGlmIChmZXRjaE9wdGlvbnMubWV0aG9kID09PSBcIkdFVFwiKSB7XG4gICAgICAgICAgICAvLyBQcmV2ZW50cyB0b2tlbiBmcm9tIGJlaW5nIHBhc3NlZCBpbiBxdWVyeSBwYXJhbXMgd2hlbiBoaWRlVG9rZW4gb3B0aW9uIGlzIHVzZWQuXG4gICAgICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgaWYgLSB3aW5kb3cgaXMgYWx3YXlzIGRlZmluZWQgaW4gYSBicm93c2VyLiBUZXN0IGNhc2UgaXMgY292ZXJlZCBieSBKYXNtaW5lIGluIG5vZGUgdGVzdCAqL1xuICAgICAgICAgICAgaWYgKHBhcmFtcy50b2tlbiAmJlxuICAgICAgICAgICAgICAgIG9wdGlvbnMuaGlkZVRva2VuICYmXG4gICAgICAgICAgICAgICAgLy8gU2hhcmluZyBBUEkgZG9lcyBub3Qgc3VwcG9ydCBwcmVmbGlnaHQgY2hlY2sgcmVxdWlyZWQgYnkgbW9kZXJuIGJyb3dzZXJzIGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvR2xvc3NhcnkvUHJlZmxpZ2h0X3JlcXVlc3RcbiAgICAgICAgICAgICAgICB0eXBlb2Ygd2luZG93ID09PSBcInVuZGVmaW5lZFwiKSB7XG4gICAgICAgICAgICAgICAgcmVxdWVzdEhlYWRlcnNbXCJYLUVzcmktQXV0aG9yaXphdGlvblwiXSA9IFwiQmVhcmVyIFwiICsgcGFyYW1zLnRva2VuO1xuICAgICAgICAgICAgICAgIGRlbGV0ZSBwYXJhbXMudG9rZW47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAvLyBlbmNvZGUgdGhlIHBhcmFtZXRlcnMgaW50byB0aGUgcXVlcnkgc3RyaW5nXG4gICAgICAgICAgICB2YXIgcXVlcnlQYXJhbXMgPSBlbmNvZGVRdWVyeVN0cmluZyhwYXJhbXMpO1xuICAgICAgICAgICAgLy8gZG9udCBhcHBlbmQgYSAnPycgdW5sZXNzIHBhcmFtZXRlcnMgYXJlIGFjdHVhbGx5IHByZXNlbnRcbiAgICAgICAgICAgIHZhciB1cmxXaXRoUXVlcnlTdHJpbmcgPSBxdWVyeVBhcmFtcyA9PT0gXCJcIiA/IHVybCA6IHVybCArIFwiP1wiICsgZW5jb2RlUXVlcnlTdHJpbmcocGFyYW1zKTtcbiAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgIC8vIFRoaXMgd291bGQgZXhjZWVkIHRoZSBtYXhpbXVtIGxlbmd0aCBmb3IgVVJMcyBzcGVjaWZpZWQgYnkgdGhlIGNvbnN1bWVyIGFuZCByZXF1aXJlcyBQT1NUXG4gICAgICAgICAgICAob3B0aW9ucy5tYXhVcmxMZW5ndGggJiZcbiAgICAgICAgICAgICAgICB1cmxXaXRoUXVlcnlTdHJpbmcubGVuZ3RoID4gb3B0aW9ucy5tYXhVcmxMZW5ndGgpIHx8XG4gICAgICAgICAgICAgICAgLy8gT3IgaWYgdGhlIGN1c3RvbWVyIHJlcXVpcmVzIHRoZSB0b2tlbiB0byBiZSBoaWRkZW4gYW5kIGl0IGhhcyBub3QgYWxyZWFkeSBiZWVuIGhpZGRlbiBpbiB0aGUgaGVhZGVyIChmb3IgYnJvd3NlcnMpXG4gICAgICAgICAgICAgICAgKHBhcmFtcy50b2tlbiAmJiBvcHRpb25zLmhpZGVUb2tlbikpIHtcbiAgICAgICAgICAgICAgICAvLyB0aGUgY29uc3VtZXIgc3BlY2lmaWVkIGEgbWF4aW11bSBsZW5ndGggZm9yIFVSTHNcbiAgICAgICAgICAgICAgICAvLyBhbmQgdGhpcyB3b3VsZCBleGNlZWQgaXQsIHNvIHVzZSBwb3N0IGluc3RlYWRcbiAgICAgICAgICAgICAgICBmZXRjaE9wdGlvbnMubWV0aG9kID0gXCJQT1NUXCI7XG4gICAgICAgICAgICAgICAgLy8gSWYgdGhlIHRva2VuIHdhcyBhbHJlYWR5IGFkZGVkIGFzIGEgQXV0aCBoZWFkZXIsIGFkZCB0aGUgdG9rZW4gYmFjayB0byBib2R5IHdpdGggb3RoZXIgcGFyYW1zIGluc3RlYWQgb2YgaGVhZGVyXG4gICAgICAgICAgICAgICAgaWYgKHRva2VuLmxlbmd0aCAmJiBvcHRpb25zLmhpZGVUb2tlbikge1xuICAgICAgICAgICAgICAgICAgICBwYXJhbXMudG9rZW4gPSB0b2tlbjtcbiAgICAgICAgICAgICAgICAgICAgLy8gUmVtb3ZlIGV4aXN0aW5nIGhlYWRlciB0aGF0IHdhcyBhZGRlZCBiZWZvcmUgdXJsIHF1ZXJ5IGxlbmd0aCB3YXMgY2hlY2tlZFxuICAgICAgICAgICAgICAgICAgICBkZWxldGUgcmVxdWVzdEhlYWRlcnNbXCJYLUVzcmktQXV0aG9yaXphdGlvblwiXTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAvLyBqdXN0IHVzZSBHRVRcbiAgICAgICAgICAgICAgICB1cmwgPSB1cmxXaXRoUXVlcnlTdHJpbmc7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgLyogdXBkYXRlUmVzb3VyY2VzIGN1cnJlbnRseSByZXF1aXJlcyBGb3JtRGF0YSBldmVuIHdoZW4gdGhlIGlucHV0IHBhcmFtZXRlcnMgZG9udCB3YXJyYW50IGl0LlxuICAgIGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3QvdXNlcnMtZ3JvdXBzLWFuZC1pdGVtcy91cGRhdGUtcmVzb3VyY2VzLmh0bVxuICAgICAgICBzZWUgaHR0cHM6Ly9naXRodWIuY29tL0VzcmkvYXJjZ2lzLXJlc3QtanMvcHVsbC81MDAgZm9yIG1vcmUgaW5mby4gKi9cbiAgICAgICAgdmFyIGZvcmNlRm9ybURhdGEgPSBuZXcgUmVnRXhwKFwiL2l0ZW1zLy4rL3VwZGF0ZVJlc291cmNlc1wiKS50ZXN0KHVybCk7XG4gICAgICAgIGlmIChmZXRjaE9wdGlvbnMubWV0aG9kID09PSBcIlBPU1RcIikge1xuICAgICAgICAgICAgZmV0Y2hPcHRpb25zLmJvZHkgPSBlbmNvZGVGb3JtRGF0YShwYXJhbXMsIGZvcmNlRm9ybURhdGEpO1xuICAgICAgICB9XG4gICAgICAgIC8vIE1peGluIGhlYWRlcnMgZnJvbSByZXF1ZXN0IG9wdGlvbnNcbiAgICAgICAgZmV0Y2hPcHRpb25zLmhlYWRlcnMgPSBfX2Fzc2lnbihfX2Fzc2lnbih7fSwgcmVxdWVzdEhlYWRlcnMpLCBvcHRpb25zLmhlYWRlcnMpO1xuICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAtIGthcm1hIHJlcG9ydHMgY292ZXJhZ2Ugb24gYnJvd3NlciB0ZXN0cyBvbmx5ICovXG4gICAgICAgIGlmICh0eXBlb2Ygd2luZG93ID09PSBcInVuZGVmaW5lZFwiICYmICFmZXRjaE9wdGlvbnMuaGVhZGVycy5yZWZlcmVyKSB7XG4gICAgICAgICAgICBmZXRjaE9wdGlvbnMuaGVhZGVycy5yZWZlcmVyID0gTk9ERUpTX0RFRkFVTFRfUkVGRVJFUl9IRUFERVI7XG4gICAgICAgIH1cbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIGVsc2UgYmxvYiByZXNwb25zZXMgYXJlIGRpZmZpY3VsdCB0byBtYWtlIGNyb3NzIHBsYXRmb3JtIHdlIHdpbGwganVzdCBoYXZlIHRvIHRydXN0IHRoZSBpc29tb3JwaGljIGZldGNoIHdpbGwgZG8gaXRzIGpvYiAqL1xuICAgICAgICBpZiAoIXJlcXVpcmVzRm9ybURhdGEocGFyYW1zKSAmJiAhZm9yY2VGb3JtRGF0YSkge1xuICAgICAgICAgICAgZmV0Y2hPcHRpb25zLmhlYWRlcnNbXCJDb250ZW50LVR5cGVcIl0gPVxuICAgICAgICAgICAgICAgIFwiYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkXCI7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIG9wdGlvbnMuZmV0Y2godXJsLCBmZXRjaE9wdGlvbnMpO1xuICAgIH0pXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICBpZiAoIXJlc3BvbnNlLm9rKSB7XG4gICAgICAgICAgICAvLyBzZXJ2ZXIgcmVzcG9uZGVkIHcvIGFuIGFjdHVhbCBlcnJvciAoNDA0LCA1MDAsIGV0YylcbiAgICAgICAgICAgIHZhciBzdGF0dXNfMSA9IHJlc3BvbnNlLnN0YXR1cywgc3RhdHVzVGV4dCA9IHJlc3BvbnNlLnN0YXR1c1RleHQ7XG4gICAgICAgICAgICB0aHJvdyBuZXcgQXJjR0lTUmVxdWVzdEVycm9yKHN0YXR1c1RleHQsIFwiSFRUUCBcIiArIHN0YXR1c18xLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAocmF3UmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgfVxuICAgICAgICBzd2l0Y2ggKHBhcmFtcy5mKSB7XG4gICAgICAgICAgICBjYXNlIFwianNvblwiOlxuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5qc29uKCk7XG4gICAgICAgICAgICBjYXNlIFwiZ2VvanNvblwiOlxuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5qc29uKCk7XG4gICAgICAgICAgICBjYXNlIFwiaHRtbFwiOlxuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS50ZXh0KCk7XG4gICAgICAgICAgICBjYXNlIFwidGV4dFwiOlxuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS50ZXh0KCk7XG4gICAgICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCBibG9iIHJlc3BvbnNlcyBhcmUgZGlmZmljdWx0IHRvIG1ha2UgY3Jvc3MgcGxhdGZvcm0gd2Ugd2lsbCBqdXN0IGhhdmUgdG8gdHJ1c3QgdGhhdCBpc29tb3JwaGljIGZldGNoIHdpbGwgZG8gaXRzIGpvYiAqL1xuICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuYmxvYigpO1xuICAgICAgICB9XG4gICAgfSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgaWYgKChwYXJhbXMuZiA9PT0gXCJqc29uXCIgfHwgcGFyYW1zLmYgPT09IFwiZ2VvanNvblwiKSAmJiAhcmF3UmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHZhciByZXNwb25zZSA9IGNoZWNrRm9yRXJyb3JzKGRhdGEsIHVybCwgcGFyYW1zLCBvcHRpb25zLCBvcmlnaW5hbEF1dGhFcnJvcik7XG4gICAgICAgICAgICBpZiAob3JpZ2luYWxBdXRoRXJyb3IpIHtcbiAgICAgICAgICAgICAgICAvKiBJZiB0aGUgcmVxdWVzdCB3YXMgbWFkZSB0byBhbiB1bmZlZGVyYXRlZCBzZXJ2aWNlIHRoYXRcbiAgICAgICAgICAgICAgICBkaWRuJ3QgcmVxdWlyZSBhdXRoZW50aWNhdGlvbiwgYWRkIHRoZSBiYXNlIHVybCBhbmQgYSBkdW1teSB0b2tlblxuICAgICAgICAgICAgICAgIHRvIHRoZSBsaXN0IG9mIHRydXN0ZWQgc2VydmVycyB0byBhdm9pZCBhbm90aGVyIGZlZGVyYXRpb24gY2hlY2tcbiAgICAgICAgICAgICAgICBpbiB0aGUgZXZlbnQgb2YgYSByZXBlYXQgcmVxdWVzdCAqL1xuICAgICAgICAgICAgICAgIHZhciB0cnVuY2F0ZWRVcmwgPSB1cmxcbiAgICAgICAgICAgICAgICAgICAgLnRvTG93ZXJDYXNlKClcbiAgICAgICAgICAgICAgICAgICAgLnNwbGl0KC9cXC9yZXN0KFxcL2FkbWluKT9cXC9zZXJ2aWNlc1xcLy8pWzBdO1xuICAgICAgICAgICAgICAgIG9wdGlvbnMuYXV0aGVudGljYXRpb24uZmVkZXJhdGVkU2VydmVyc1t0cnVuY2F0ZWRVcmxdID0ge1xuICAgICAgICAgICAgICAgICAgICB0b2tlbjogW10sXG4gICAgICAgICAgICAgICAgICAgIC8vIGRlZmF1bHQgdG8gMjQgaG91cnNcbiAgICAgICAgICAgICAgICAgICAgZXhwaXJlczogbmV3IERhdGUoRGF0ZS5ub3coKSArIDg2NDAwICogMTAwMCksXG4gICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICBvcmlnaW5hbEF1dGhFcnJvciA9IG51bGw7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICByZXR1cm4gZGF0YTtcbiAgICAgICAgfVxuICAgIH0pO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9cmVxdWVzdC5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuLy8gVHlwZVNjcmlwdCAyLjEgbm8gbG9uZ2VyIGFsbG93cyB5b3UgdG8gZXh0ZW5kIGJ1aWx0IGluIHR5cGVzLiBTZWUgaHR0cHM6Ly9naXRodWIuY29tL01pY3Jvc29mdC9UeXBlU2NyaXB0L2lzc3Vlcy8xMjc5MCNpc3N1ZWNvbW1lbnQtMjY1OTgxNDQyXG4vLyBhbmQgaHR0cHM6Ly9naXRodWIuY29tL01pY3Jvc29mdC9UeXBlU2NyaXB0LXdpa2kvYmxvYi9tYXN0ZXIvQnJlYWtpbmctQ2hhbmdlcy5tZCNleHRlbmRpbmctYnVpbHQtaW5zLWxpa2UtZXJyb3ItYXJyYXktYW5kLW1hcC1tYXktbm8tbG9uZ2VyLXdvcmtcbi8vXG4vLyBUaGlzIGNvZGUgaXMgZnJvbSBNRE4gaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvSmF2YVNjcmlwdC9SZWZlcmVuY2UvR2xvYmFsX09iamVjdHMvRXJyb3IjQ3VzdG9tX0Vycm9yX1R5cGVzLlxudmFyIEFyY0dJU1JlcXVlc3RFcnJvciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICAvKipcbiAgICAgKiBDcmVhdGUgYSBuZXcgYEFyY0dJU1JlcXVlc3RFcnJvcmAgIG9iamVjdC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBtZXNzYWdlIC0gVGhlIGVycm9yIG1lc3NhZ2UgZnJvbSB0aGUgQVBJXG4gICAgICogQHBhcmFtIGNvZGUgLSBUaGUgZXJyb3IgY29kZSBmcm9tIHRoZSBBUElcbiAgICAgKiBAcGFyYW0gcmVzcG9uc2UgLSBUaGUgb3JpZ2luYWwgcmVzcG9uc2UgZnJvbSB0aGUgQVBJIHRoYXQgY2F1c2VkIHRoZSBlcnJvclxuICAgICAqIEBwYXJhbSB1cmwgLSBUaGUgb3JpZ2luYWwgdXJsIG9mIHRoZSByZXF1ZXN0XG4gICAgICogQHBhcmFtIG9wdGlvbnMgLSBUaGUgb3JpZ2luYWwgb3B0aW9ucyBhbmQgcGFyYW1ldGVycyBvZiB0aGUgcmVxdWVzdFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIEFyY0dJU1JlcXVlc3RFcnJvcihtZXNzYWdlLCBjb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKSB7XG4gICAgICAgIG1lc3NhZ2UgPSBtZXNzYWdlIHx8IFwiVU5LTk9XTl9FUlJPUlwiO1xuICAgICAgICBjb2RlID0gY29kZSB8fCBcIlVOS05PV05fRVJST1JfQ09ERVwiO1xuICAgICAgICB0aGlzLm5hbWUgPSBcIkFyY0dJU1JlcXVlc3RFcnJvclwiO1xuICAgICAgICB0aGlzLm1lc3NhZ2UgPVxuICAgICAgICAgICAgY29kZSA9PT0gXCJVTktOT1dOX0VSUk9SX0NPREVcIiA/IG1lc3NhZ2UgOiBjb2RlICsgXCI6IFwiICsgbWVzc2FnZTtcbiAgICAgICAgdGhpcy5vcmlnaW5hbE1lc3NhZ2UgPSBtZXNzYWdlO1xuICAgICAgICB0aGlzLmNvZGUgPSBjb2RlO1xuICAgICAgICB0aGlzLnJlc3BvbnNlID0gcmVzcG9uc2U7XG4gICAgICAgIHRoaXMudXJsID0gdXJsO1xuICAgICAgICB0aGlzLm9wdGlvbnMgPSBvcHRpb25zO1xuICAgIH1cbiAgICByZXR1cm4gQXJjR0lTUmVxdWVzdEVycm9yO1xufSgpKTtcbmV4cG9ydCB7IEFyY0dJU1JlcXVlc3RFcnJvciB9O1xuQXJjR0lTUmVxdWVzdEVycm9yLnByb3RvdHlwZSA9IE9iamVjdC5jcmVhdGUoRXJyb3IucHJvdG90eXBlKTtcbkFyY0dJU1JlcXVlc3RFcnJvci5wcm90b3R5cGUuY29uc3RydWN0b3IgPSBBcmNHSVNSZXF1ZXN0RXJyb3I7XG4vLyMgc291cmNlTWFwcGluZ1VSTD1BcmNHSVNSZXF1ZXN0RXJyb3IuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbi8qKlxuICogSGVscGVyIGZvciBtZXRob2RzIHdpdGggbG90cyBvZiBmaXJzdCBvcmRlciByZXF1ZXN0IG9wdGlvbnMgdG8gcGFzcyB0aHJvdWdoIGFzIHJlcXVlc3QgcGFyYW1ldGVycy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGFwcGVuZEN1c3RvbVBhcmFtcyhjdXN0b21PcHRpb25zLCBrZXlzLCBiYXNlT3B0aW9ucykge1xuICAgIHZhciByZXF1ZXN0T3B0aW9uc0tleXMgPSBbXG4gICAgICAgIFwicGFyYW1zXCIsXG4gICAgICAgIFwiaHR0cE1ldGhvZFwiLFxuICAgICAgICBcInJhd1Jlc3BvbnNlXCIsXG4gICAgICAgIFwiYXV0aGVudGljYXRpb25cIixcbiAgICAgICAgXCJwb3J0YWxcIixcbiAgICAgICAgXCJmZXRjaFwiLFxuICAgICAgICBcIm1heFVybExlbmd0aFwiLFxuICAgICAgICBcImhlYWRlcnNcIlxuICAgIF07XG4gICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbihfX2Fzc2lnbih7IHBhcmFtczoge30gfSwgYmFzZU9wdGlvbnMpLCBjdXN0b21PcHRpb25zKTtcbiAgICAvLyBtZXJnZSBhbGwga2V5cyBpbiBjdXN0b21PcHRpb25zIGludG8gb3B0aW9ucy5wYXJhbXNcbiAgICBvcHRpb25zLnBhcmFtcyA9IGtleXMucmVkdWNlKGZ1bmN0aW9uICh2YWx1ZSwga2V5KSB7XG4gICAgICAgIGlmIChjdXN0b21PcHRpb25zW2tleV0gfHwgdHlwZW9mIGN1c3RvbU9wdGlvbnNba2V5XSA9PT0gXCJib29sZWFuXCIpIHtcbiAgICAgICAgICAgIHZhbHVlW2tleV0gPSBjdXN0b21PcHRpb25zW2tleV07XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHZhbHVlO1xuICAgIH0sIG9wdGlvbnMucGFyYW1zKTtcbiAgICAvLyBub3cgcmVtb3ZlIGFsbCBwcm9wZXJ0aWVzIGluIG9wdGlvbnMgdGhhdCBkb24ndCBleGlzdCBpbiBJUmVxdWVzdE9wdGlvbnNcbiAgICByZXR1cm4gcmVxdWVzdE9wdGlvbnNLZXlzLnJlZHVjZShmdW5jdGlvbiAodmFsdWUsIGtleSkge1xuICAgICAgICBpZiAob3B0aW9uc1trZXldKSB7XG4gICAgICAgICAgICB2YWx1ZVtrZXldID0gb3B0aW9uc1trZXldO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9LCB7fSk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1hcHBlbmQtY3VzdG9tLXBhcmFtcy5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuLyoqXG4gKiBIZWxwZXIgbWV0aG9kIHRvIGVuc3VyZSB0aGF0IHVzZXIgc3VwcGxpZWQgdXJscyBkb24ndCBpbmNsdWRlIHdoaXRlc3BhY2Ugb3IgYSB0cmFpbGluZyBzbGFzaC5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNsZWFuVXJsKHVybCkge1xuICAgIC8vIEd1YXJkIHNvIHdlIGRvbid0IHRyeSB0byB0cmltIHNvbWV0aGluZyB0aGF0J3Mgbm90IGEgc3RyaW5nXG4gICAgaWYgKHR5cGVvZiB1cmwgIT09IFwic3RyaW5nXCIpIHtcbiAgICAgICAgcmV0dXJuIHVybDtcbiAgICB9XG4gICAgLy8gdHJpbSBsZWFkaW5nIGFuZCB0cmFpbGluZyBzcGFjZXMsIGJ1dCBub3Qgc3BhY2VzIGluc2lkZSB0aGUgdXJsXG4gICAgdXJsID0gdXJsLnRyaW0oKTtcbiAgICAvLyByZW1vdmUgdGhlIHRyYWlsaW5nIHNsYXNoIHRvIHRoZSB1cmwgaWYgb25lIHdhcyBpbmNsdWRlZFxuICAgIGlmICh1cmxbdXJsLmxlbmd0aCAtIDFdID09PSBcIi9cIikge1xuICAgICAgICB1cmwgPSB1cmwuc2xpY2UoMCwgLTEpO1xuICAgIH1cbiAgICByZXR1cm4gdXJsO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9Y2xlYW4tdXJsLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDIwIEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmV4cG9ydCBmdW5jdGlvbiBkZWNvZGVQYXJhbShwYXJhbSkge1xuICAgIHZhciBfYSA9IHBhcmFtLnNwbGl0KFwiPVwiKSwga2V5ID0gX2FbMF0sIHZhbHVlID0gX2FbMV07XG4gICAgcmV0dXJuIHsga2V5OiBkZWNvZGVVUklDb21wb25lbnQoa2V5KSwgdmFsdWU6IGRlY29kZVVSSUNvbXBvbmVudCh2YWx1ZSkgfTtcbn1cbi8qKlxuICogRGVjb2RlcyB0aGUgcGFzc2VkIHF1ZXJ5IHN0cmluZyBhcyBhbiBvYmplY3QuXG4gKlxuICogQHBhcmFtIHF1ZXJ5IEEgc3RyaW5nIHRvIGJlIGRlY29kZWQuXG4gKiBAcmV0dXJucyBBIGRlY29kZWQgcXVlcnkgcGFyYW0gb2JqZWN0LlxuICovXG5leHBvcnQgZnVuY3Rpb24gZGVjb2RlUXVlcnlTdHJpbmcocXVlcnkpIHtcbiAgICByZXR1cm4gcXVlcnlcbiAgICAgICAgLnJlcGxhY2UoL14jLywgXCJcIilcbiAgICAgICAgLnNwbGl0KFwiJlwiKVxuICAgICAgICAucmVkdWNlKGZ1bmN0aW9uIChhY2MsIGVudHJ5KSB7XG4gICAgICAgIHZhciBfYSA9IGRlY29kZVBhcmFtKGVudHJ5KSwga2V5ID0gX2Eua2V5LCB2YWx1ZSA9IF9hLnZhbHVlO1xuICAgICAgICBhY2Nba2V5XSA9IHZhbHVlO1xuICAgICAgICByZXR1cm4gYWNjO1xuICAgIH0sIHt9KTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRlY29kZS1xdWVyeS1zdHJpbmcuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IHByb2Nlc3NQYXJhbXMsIHJlcXVpcmVzRm9ybURhdGEgfSBmcm9tIFwiLi9wcm9jZXNzLXBhcmFtc1wiO1xuaW1wb3J0IHsgZW5jb2RlUXVlcnlTdHJpbmcgfSBmcm9tIFwiLi9lbmNvZGUtcXVlcnktc3RyaW5nXCI7XG4vKipcbiAqIEVuY29kZXMgcGFyYW1ldGVycyBpbiBhIFtGb3JtRGF0YV0oaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvQVBJL0Zvcm1EYXRhKSBvYmplY3QgaW4gYnJvd3NlcnMgb3IgaW4gYSBbRm9ybURhdGFdKGh0dHBzOi8vZ2l0aHViLmNvbS9mb3JtLWRhdGEvZm9ybS1kYXRhKSBpbiBOb2RlLmpzXG4gKlxuICogQHBhcmFtIHBhcmFtcyBBbiBvYmplY3QgdG8gYmUgZW5jb2RlZC5cbiAqIEByZXR1cm5zIFRoZSBjb21wbGV0ZSBbRm9ybURhdGFdKGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0FQSS9Gb3JtRGF0YSkgb2JqZWN0LlxuICovXG5leHBvcnQgZnVuY3Rpb24gZW5jb2RlRm9ybURhdGEocGFyYW1zLCBmb3JjZUZvcm1EYXRhKSB7XG4gICAgLy8gc2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9Fc3JpL2FyY2dpcy1yZXN0LWpzL2lzc3Vlcy80OTkgZm9yIG1vcmUgaW5mby5cbiAgICB2YXIgdXNlRm9ybURhdGEgPSByZXF1aXJlc0Zvcm1EYXRhKHBhcmFtcykgfHwgZm9yY2VGb3JtRGF0YTtcbiAgICB2YXIgbmV3UGFyYW1zID0gcHJvY2Vzc1BhcmFtcyhwYXJhbXMpO1xuICAgIGlmICh1c2VGb3JtRGF0YSkge1xuICAgICAgICB2YXIgZm9ybURhdGFfMSA9IG5ldyBGb3JtRGF0YSgpO1xuICAgICAgICBPYmplY3Qua2V5cyhuZXdQYXJhbXMpLmZvckVhY2goZnVuY3Rpb24gKGtleSkge1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBCbG9iICE9PSBcInVuZGVmaW5lZFwiICYmIG5ld1BhcmFtc1trZXldIGluc3RhbmNlb2YgQmxvYikge1xuICAgICAgICAgICAgICAgIC8qIFRvIG5hbWUgdGhlIEJsb2I6XG4gICAgICAgICAgICAgICAgIDEuIGxvb2sgdG8gYW4gYWx0ZXJuYXRlIHJlcXVlc3QgcGFyYW1ldGVyIGNhbGxlZCAnZmlsZU5hbWUnXG4gICAgICAgICAgICAgICAgIDIuIHNlZSBpZiAnbmFtZScgaGFzIGJlZW4gdGFja2VkIG9udG8gdGhlIEJsb2IgbWFudWFsbHlcbiAgICAgICAgICAgICAgICAgMy4gaWYgYWxsIGVsc2UgZmFpbHMsIHVzZSB0aGUgcmVxdWVzdCBwYXJhbWV0ZXJcbiAgICAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgICAgIHZhciBmaWxlbmFtZSA9IG5ld1BhcmFtc1tcImZpbGVOYW1lXCJdIHx8IG5ld1BhcmFtc1trZXldLm5hbWUgfHwga2V5O1xuICAgICAgICAgICAgICAgIGZvcm1EYXRhXzEuYXBwZW5kKGtleSwgbmV3UGFyYW1zW2tleV0sIGZpbGVuYW1lKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgIGZvcm1EYXRhXzEuYXBwZW5kKGtleSwgbmV3UGFyYW1zW2tleV0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIGZvcm1EYXRhXzE7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICByZXR1cm4gZW5jb2RlUXVlcnlTdHJpbmcocGFyYW1zKTtcbiAgICB9XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1lbmNvZGUtZm9ybS1kYXRhLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBwcm9jZXNzUGFyYW1zIH0gZnJvbSBcIi4vcHJvY2Vzcy1wYXJhbXNcIjtcbi8qKlxuICogRW5jb2RlcyBrZXlzIGFuZCBwYXJhbWV0ZXJzIGZvciB1c2UgaW4gYSBVUkwncyBxdWVyeSBzdHJpbmcuXG4gKlxuICogQHBhcmFtIGtleSBQYXJhbWV0ZXIncyBrZXlcbiAqIEBwYXJhbSB2YWx1ZSBQYXJhbWV0ZXIncyB2YWx1ZVxuICogQHJldHVybnMgUXVlcnkgc3RyaW5nIHdpdGgga2V5IGFuZCB2YWx1ZSBwYWlycyBzZXBhcmF0ZWQgYnkgXCImXCJcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGVuY29kZVBhcmFtKGtleSwgdmFsdWUpIHtcbiAgICAvLyBGb3IgYXJyYXkgb2YgYXJyYXlzLCByZXBlYXQga2V5PXZhbHVlIGZvciBlYWNoIGVsZW1lbnQgb2YgY29udGFpbmluZyBhcnJheVxuICAgIGlmIChBcnJheS5pc0FycmF5KHZhbHVlKSAmJiB2YWx1ZVswXSAmJiBBcnJheS5pc0FycmF5KHZhbHVlWzBdKSkge1xuICAgICAgICByZXR1cm4gdmFsdWUubWFwKGZ1bmN0aW9uIChhcnJheUVsZW0pIHsgcmV0dXJuIGVuY29kZVBhcmFtKGtleSwgYXJyYXlFbGVtKTsgfSkuam9pbihcIiZcIik7XG4gICAgfVxuICAgIHJldHVybiBlbmNvZGVVUklDb21wb25lbnQoa2V5KSArIFwiPVwiICsgZW5jb2RlVVJJQ29tcG9uZW50KHZhbHVlKTtcbn1cbi8qKlxuICogRW5jb2RlcyB0aGUgcGFzc2VkIG9iamVjdCBhcyBhIHF1ZXJ5IHN0cmluZy5cbiAqXG4gKiBAcGFyYW0gcGFyYW1zIEFuIG9iamVjdCB0byBiZSBlbmNvZGVkLlxuICogQHJldHVybnMgQW4gZW5jb2RlZCBxdWVyeSBzdHJpbmcuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBlbmNvZGVRdWVyeVN0cmluZyhwYXJhbXMpIHtcbiAgICB2YXIgbmV3UGFyYW1zID0gcHJvY2Vzc1BhcmFtcyhwYXJhbXMpO1xuICAgIHJldHVybiBPYmplY3Qua2V5cyhuZXdQYXJhbXMpXG4gICAgICAgIC5tYXAoZnVuY3Rpb24gKGtleSkge1xuICAgICAgICByZXR1cm4gZW5jb2RlUGFyYW0oa2V5LCBuZXdQYXJhbXNba2V5XSk7XG4gICAgfSlcbiAgICAgICAgLmpvaW4oXCImXCIpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZW5jb2RlLXF1ZXJ5LXN0cmluZy5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuLyoqXG4gKiBDaGVja3MgcGFyYW1ldGVycyB0byBzZWUgaWYgd2Ugc2hvdWxkIHVzZSBGb3JtRGF0YSB0byBzZW5kIHRoZSByZXF1ZXN0XG4gKiBAcGFyYW0gcGFyYW1zIFRoZSBvYmplY3Qgd2hvc2Uga2V5cyB3aWxsIGJlIGVuY29kZWQuXG4gKiBAcmV0dXJuIEEgYm9vbGVhbiBpbmRpY2F0aW5nIGlmIEZvcm1EYXRhIHdpbGwgYmUgcmVxdWlyZWQuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiByZXF1aXJlc0Zvcm1EYXRhKHBhcmFtcykge1xuICAgIHJldHVybiBPYmplY3Qua2V5cyhwYXJhbXMpLnNvbWUoZnVuY3Rpb24gKGtleSkge1xuICAgICAgICB2YXIgdmFsdWUgPSBwYXJhbXNba2V5XTtcbiAgICAgICAgaWYgKCF2YWx1ZSkge1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG4gICAgICAgIGlmICh2YWx1ZSAmJiB2YWx1ZS50b1BhcmFtKSB7XG4gICAgICAgICAgICB2YWx1ZSA9IHZhbHVlLnRvUGFyYW0oKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgdHlwZSA9IHZhbHVlLmNvbnN0cnVjdG9yLm5hbWU7XG4gICAgICAgIHN3aXRjaCAodHlwZSkge1xuICAgICAgICAgICAgY2FzZSBcIkFycmF5XCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIk9iamVjdFwiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGNhc2UgXCJEYXRlXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIkZ1bmN0aW9uXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIkJvb2xlYW5cIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBjYXNlIFwiU3RyaW5nXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIk51bWJlclwiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICB9KTtcbn1cbi8qKlxuICogQ29udmVydHMgcGFyYW1ldGVycyB0byB0aGUgcHJvcGVyIHJlcHJlc2VudGF0aW9uIHRvIHNlbmQgdG8gdGhlIEFyY0dJUyBSRVNUIEFQSS5cbiAqIEBwYXJhbSBwYXJhbXMgVGhlIG9iamVjdCB3aG9zZSBrZXlzIHdpbGwgYmUgZW5jb2RlZC5cbiAqIEByZXR1cm4gQSBuZXcgb2JqZWN0IHdpdGggcHJvcGVybHkgZW5jb2RlZCB2YWx1ZXMuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBwcm9jZXNzUGFyYW1zKHBhcmFtcykge1xuICAgIHZhciBuZXdQYXJhbXMgPSB7fTtcbiAgICBPYmplY3Qua2V5cyhwYXJhbXMpLmZvckVhY2goZnVuY3Rpb24gKGtleSkge1xuICAgICAgICB2YXIgX2EsIF9iO1xuICAgICAgICB2YXIgcGFyYW0gPSBwYXJhbXNba2V5XTtcbiAgICAgICAgaWYgKHBhcmFtICYmIHBhcmFtLnRvUGFyYW0pIHtcbiAgICAgICAgICAgIHBhcmFtID0gcGFyYW0udG9QYXJhbSgpO1xuICAgICAgICB9XG4gICAgICAgIGlmICghcGFyYW0gJiZcbiAgICAgICAgICAgIHBhcmFtICE9PSAwICYmXG4gICAgICAgICAgICB0eXBlb2YgcGFyYW0gIT09IFwiYm9vbGVhblwiICYmXG4gICAgICAgICAgICB0eXBlb2YgcGFyYW0gIT09IFwic3RyaW5nXCIpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICB2YXIgdHlwZSA9IHBhcmFtLmNvbnN0cnVjdG9yLm5hbWU7XG4gICAgICAgIHZhciB2YWx1ZTtcbiAgICAgICAgLy8gcHJvcGVybHkgZW5jb2RlcyBvYmplY3RzLCBhcnJheXMgYW5kIGRhdGVzIGZvciBhcmNnaXMuY29tIGFuZCBvdGhlciBzZXJ2aWNlcy5cbiAgICAgICAgLy8gcG9ydGVkIGZyb20gaHR0cHM6Ly9naXRodWIuY29tL0VzcmkvZXNyaS1sZWFmbGV0L2Jsb2IvbWFzdGVyL3NyYy9SZXF1ZXN0LmpzI0wyMi1MMzBcbiAgICAgICAgLy8gYWxzbyBzZWUgaHR0cHM6Ly9naXRodWIuY29tL0VzcmkvYXJjZ2lzLXJlc3QtanMvaXNzdWVzLzE4OlxuICAgICAgICAvLyBudWxsLCB1bmRlZmluZWQsIGZ1bmN0aW9uIGFyZSBleGNsdWRlZC4gSWYgeW91IHdhbnQgdG8gc2VuZCBhbiBlbXB0eSBrZXkgeW91IG5lZWQgdG8gc2VuZCBhbiBlbXB0eSBzdHJpbmcgXCJcIi5cbiAgICAgICAgc3dpdGNoICh0eXBlKSB7XG4gICAgICAgICAgICBjYXNlIFwiQXJyYXlcIjpcbiAgICAgICAgICAgICAgICAvLyBCYXNlZCBvbiB0aGUgZmlyc3QgZWxlbWVudCBvZiB0aGUgYXJyYXksIGNsYXNzaWZ5IGFycmF5IGFzIGFuIGFycmF5IG9mIGFycmF5cywgYW4gYXJyYXkgb2Ygb2JqZWN0c1xuICAgICAgICAgICAgICAgIC8vIHRvIGJlIHN0cmluZ2lmaWVkLCBvciBhbiBhcnJheSBvZiBub24tb2JqZWN0cyB0byBiZSBjb21tYS1zZXBhcmF0ZWRcbiAgICAgICAgICAgICAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm8tY2FzZS1kZWNsYXJhdGlvbnNcbiAgICAgICAgICAgICAgICB2YXIgZmlyc3RFbGVtZW50VHlwZSA9IChfYiA9IChfYSA9IHBhcmFtWzBdKSA9PT0gbnVsbCB8fCBfYSA9PT0gdm9pZCAwID8gdm9pZCAwIDogX2EuY29uc3RydWN0b3IpID09PSBudWxsIHx8IF9iID09PSB2b2lkIDAgPyB2b2lkIDAgOiBfYi5uYW1lO1xuICAgICAgICAgICAgICAgIHZhbHVlID1cbiAgICAgICAgICAgICAgICAgICAgZmlyc3RFbGVtZW50VHlwZSA9PT0gXCJBcnJheVwiID8gcGFyYW0gOiAvLyBwYXNzIHRocnUgYXJyYXkgb2YgYXJyYXlzXG4gICAgICAgICAgICAgICAgICAgICAgICBmaXJzdEVsZW1lbnRUeXBlID09PSBcIk9iamVjdFwiID8gSlNPTi5zdHJpbmdpZnkocGFyYW0pIDogLy8gc3RyaW5naWZ5IGFycmF5IG9mIG9iamVjdHNcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXJhbS5qb2luKFwiLFwiKTsgLy8gam9pbiBvdGhlciB0eXBlcyBvZiBhcnJheSBlbGVtZW50c1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgY2FzZSBcIk9iamVjdFwiOlxuICAgICAgICAgICAgICAgIHZhbHVlID0gSlNPTi5zdHJpbmdpZnkocGFyYW0pO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgY2FzZSBcIkRhdGVcIjpcbiAgICAgICAgICAgICAgICB2YWx1ZSA9IHBhcmFtLnZhbHVlT2YoKTtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIGNhc2UgXCJGdW5jdGlvblwiOlxuICAgICAgICAgICAgICAgIHZhbHVlID0gbnVsbDtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIGNhc2UgXCJCb29sZWFuXCI6XG4gICAgICAgICAgICAgICAgdmFsdWUgPSBwYXJhbSArIFwiXCI7XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgIHZhbHVlID0gcGFyYW07XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHZhbHVlIHx8IHZhbHVlID09PSAwIHx8IHR5cGVvZiB2YWx1ZSA9PT0gXCJzdHJpbmdcIiB8fCBBcnJheS5pc0FycmF5KHZhbHVlKSkge1xuICAgICAgICAgICAgbmV3UGFyYW1zW2tleV0gPSB2YWx1ZTtcbiAgICAgICAgfVxuICAgIH0pO1xuICAgIHJldHVybiBuZXdQYXJhbXM7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1wcm9jZXNzLXBhcmFtcy5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG4vKipcbiAqIE1ldGhvZCB1c2VkIGludGVybmFsbHkgdG8gc3VyZmFjZSBtZXNzYWdlcyB0byBkZXZlbG9wZXJzLlxuICovXG5leHBvcnQgZnVuY3Rpb24gd2FybihtZXNzYWdlKSB7XG4gICAgaWYgKGNvbnNvbGUgJiYgY29uc29sZS53YXJuKSB7XG4gICAgICAgIGNvbnNvbGUud2Fybi5hcHBseShjb25zb2xlLCBbbWVzc2FnZV0pO1xuICAgIH1cbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXdhcm4uanMubWFwIiwiLyohICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXHJcbkNvcHlyaWdodCAoYykgTWljcm9zb2Z0IENvcnBvcmF0aW9uLlxyXG5cclxuUGVybWlzc2lvbiB0byB1c2UsIGNvcHksIG1vZGlmeSwgYW5kL29yIGRpc3RyaWJ1dGUgdGhpcyBzb2Z0d2FyZSBmb3IgYW55XHJcbnB1cnBvc2Ugd2l0aCBvciB3aXRob3V0IGZlZSBpcyBoZXJlYnkgZ3JhbnRlZC5cclxuXHJcblRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIgQU5EIFRIRSBBVVRIT1IgRElTQ0xBSU1TIEFMTCBXQVJSQU5USUVTIFdJVEhcclxuUkVHQVJEIFRPIFRISVMgU09GVFdBUkUgSU5DTFVESU5HIEFMTCBJTVBMSUVEIFdBUlJBTlRJRVMgT0YgTUVSQ0hBTlRBQklMSVRZXHJcbkFORCBGSVRORVNTLiBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SIEJFIExJQUJMRSBGT1IgQU5ZIFNQRUNJQUwsIERJUkVDVCxcclxuSU5ESVJFQ1QsIE9SIENPTlNFUVVFTlRJQUwgREFNQUdFUyBPUiBBTlkgREFNQUdFUyBXSEFUU09FVkVSIFJFU1VMVElORyBGUk9NXHJcbkxPU1MgT0YgVVNFLCBEQVRBIE9SIFBST0ZJVFMsIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBORUdMSUdFTkNFIE9SXHJcbk9USEVSIFRPUlRJT1VTIEFDVElPTiwgQVJJU0lORyBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBVU0UgT1JcclxuUEVSRk9STUFOQ0UgT0YgVEhJUyBTT0ZUV0FSRS5cclxuKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiogKi9cclxuLyogZ2xvYmFsIFJlZmxlY3QsIFByb21pc2UgKi9cclxuXHJcbnZhciBleHRlbmRTdGF0aWNzID0gZnVuY3Rpb24oZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyA9IE9iamVjdC5zZXRQcm90b3R5cGVPZiB8fFxyXG4gICAgICAgICh7IF9fcHJvdG9fXzogW10gfSBpbnN0YW5jZW9mIEFycmF5ICYmIGZ1bmN0aW9uIChkLCBiKSB7IGQuX19wcm90b19fID0gYjsgfSkgfHxcclxuICAgICAgICBmdW5jdGlvbiAoZCwgYikgeyBmb3IgKHZhciBwIGluIGIpIGlmIChiLmhhc093blByb3BlcnR5KHApKSBkW3BdID0gYltwXTsgfTtcclxuICAgIHJldHVybiBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXh0ZW5kcyhkLCBiKSB7XHJcbiAgICBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG4gICAgZnVuY3Rpb24gX18oKSB7IHRoaXMuY29uc3RydWN0b3IgPSBkOyB9XHJcbiAgICBkLnByb3RvdHlwZSA9IGIgPT09IG51bGwgPyBPYmplY3QuY3JlYXRlKGIpIDogKF9fLnByb3RvdHlwZSA9IGIucHJvdG90eXBlLCBuZXcgX18oKSk7XHJcbn1cclxuXHJcbmV4cG9ydCB2YXIgX19hc3NpZ24gPSBmdW5jdGlvbigpIHtcclxuICAgIF9fYXNzaWduID0gT2JqZWN0LmFzc2lnbiB8fCBmdW5jdGlvbiBfX2Fzc2lnbih0KSB7XHJcbiAgICAgICAgZm9yICh2YXIgcywgaSA9IDEsIG4gPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgbjsgaSsrKSB7XHJcbiAgICAgICAgICAgIHMgPSBhcmd1bWVudHNbaV07XHJcbiAgICAgICAgICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSkgdFtwXSA9IHNbcF07XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHJldHVybiB0O1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIF9fYXNzaWduLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3Jlc3QocywgZSkge1xyXG4gICAgdmFyIHQgPSB7fTtcclxuICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSAmJiBlLmluZGV4T2YocCkgPCAwKVxyXG4gICAgICAgIHRbcF0gPSBzW3BdO1xyXG4gICAgaWYgKHMgIT0gbnVsbCAmJiB0eXBlb2YgT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyA9PT0gXCJmdW5jdGlvblwiKVxyXG4gICAgICAgIGZvciAodmFyIGkgPSAwLCBwID0gT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyhzKTsgaSA8IHAubGVuZ3RoOyBpKyspIHtcclxuICAgICAgICAgICAgaWYgKGUuaW5kZXhPZihwW2ldKSA8IDAgJiYgT2JqZWN0LnByb3RvdHlwZS5wcm9wZXJ0eUlzRW51bWVyYWJsZS5jYWxsKHMsIHBbaV0pKVxyXG4gICAgICAgICAgICAgICAgdFtwW2ldXSA9IHNbcFtpXV07XHJcbiAgICAgICAgfVxyXG4gICAgcmV0dXJuIHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2RlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKSB7XHJcbiAgICB2YXIgYyA9IGFyZ3VtZW50cy5sZW5ndGgsIHIgPSBjIDwgMyA/IHRhcmdldCA6IGRlc2MgPT09IG51bGwgPyBkZXNjID0gT2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih0YXJnZXQsIGtleSkgOiBkZXNjLCBkO1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0LmRlY29yYXRlID09PSBcImZ1bmN0aW9uXCIpIHIgPSBSZWZsZWN0LmRlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKTtcclxuICAgIGVsc2UgZm9yICh2YXIgaSA9IGRlY29yYXRvcnMubGVuZ3RoIC0gMTsgaSA+PSAwOyBpLS0pIGlmIChkID0gZGVjb3JhdG9yc1tpXSkgciA9IChjIDwgMyA/IGQocikgOiBjID4gMyA/IGQodGFyZ2V0LCBrZXksIHIpIDogZCh0YXJnZXQsIGtleSkpIHx8IHI7XHJcbiAgICByZXR1cm4gYyA+IDMgJiYgciAmJiBPYmplY3QuZGVmaW5lUHJvcGVydHkodGFyZ2V0LCBrZXksIHIpLCByO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19wYXJhbShwYXJhbUluZGV4LCBkZWNvcmF0b3IpIHtcclxuICAgIHJldHVybiBmdW5jdGlvbiAodGFyZ2V0LCBrZXkpIHsgZGVjb3JhdG9yKHRhcmdldCwga2V5LCBwYXJhbUluZGV4KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSkge1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0Lm1ldGFkYXRhID09PSBcImZ1bmN0aW9uXCIpIHJldHVybiBSZWZsZWN0Lm1ldGFkYXRhKG1ldGFkYXRhS2V5LCBtZXRhZGF0YVZhbHVlKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXRlcih0aGlzQXJnLCBfYXJndW1lbnRzLCBQLCBnZW5lcmF0b3IpIHtcclxuICAgIGZ1bmN0aW9uIGFkb3B0KHZhbHVlKSB7IHJldHVybiB2YWx1ZSBpbnN0YW5jZW9mIFAgPyB2YWx1ZSA6IG5ldyBQKGZ1bmN0aW9uIChyZXNvbHZlKSB7IHJlc29sdmUodmFsdWUpOyB9KTsgfVxyXG4gICAgcmV0dXJuIG5ldyAoUCB8fCAoUCA9IFByb21pc2UpKShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XHJcbiAgICAgICAgZnVuY3Rpb24gZnVsZmlsbGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yLm5leHQodmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHJlamVjdGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yW1widGhyb3dcIl0odmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHN0ZXAocmVzdWx0KSB7IHJlc3VsdC5kb25lID8gcmVzb2x2ZShyZXN1bHQudmFsdWUpIDogYWRvcHQocmVzdWx0LnZhbHVlKS50aGVuKGZ1bGZpbGxlZCwgcmVqZWN0ZWQpOyB9XHJcbiAgICAgICAgc3RlcCgoZ2VuZXJhdG9yID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pKS5uZXh0KCkpO1xyXG4gICAgfSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2dlbmVyYXRvcih0aGlzQXJnLCBib2R5KSB7XHJcbiAgICB2YXIgXyA9IHsgbGFiZWw6IDAsIHNlbnQ6IGZ1bmN0aW9uKCkgeyBpZiAodFswXSAmIDEpIHRocm93IHRbMV07IHJldHVybiB0WzFdOyB9LCB0cnlzOiBbXSwgb3BzOiBbXSB9LCBmLCB5LCB0LCBnO1xyXG4gICAgcmV0dXJuIGcgPSB7IG5leHQ6IHZlcmIoMCksIFwidGhyb3dcIjogdmVyYigxKSwgXCJyZXR1cm5cIjogdmVyYigyKSB9LCB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgKGdbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uKCkgeyByZXR1cm4gdGhpczsgfSksIGc7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgcmV0dXJuIGZ1bmN0aW9uICh2KSB7IHJldHVybiBzdGVwKFtuLCB2XSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAob3ApIHtcclxuICAgICAgICBpZiAoZikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIkdlbmVyYXRvciBpcyBhbHJlYWR5IGV4ZWN1dGluZy5cIik7XHJcbiAgICAgICAgd2hpbGUgKF8pIHRyeSB7XHJcbiAgICAgICAgICAgIGlmIChmID0gMSwgeSAmJiAodCA9IG9wWzBdICYgMiA/IHlbXCJyZXR1cm5cIl0gOiBvcFswXSA/IHlbXCJ0aHJvd1wiXSB8fCAoKHQgPSB5W1wicmV0dXJuXCJdKSAmJiB0LmNhbGwoeSksIDApIDogeS5uZXh0KSAmJiAhKHQgPSB0LmNhbGwoeSwgb3BbMV0pKS5kb25lKSByZXR1cm4gdDtcclxuICAgICAgICAgICAgaWYgKHkgPSAwLCB0KSBvcCA9IFtvcFswXSAmIDIsIHQudmFsdWVdO1xyXG4gICAgICAgICAgICBzd2l0Y2ggKG9wWzBdKSB7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDA6IGNhc2UgMTogdCA9IG9wOyBicmVhaztcclxuICAgICAgICAgICAgICAgIGNhc2UgNDogXy5sYWJlbCsrOyByZXR1cm4geyB2YWx1ZTogb3BbMV0sIGRvbmU6IGZhbHNlIH07XHJcbiAgICAgICAgICAgICAgICBjYXNlIDU6IF8ubGFiZWwrKzsgeSA9IG9wWzFdOyBvcCA9IFswXTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDc6IG9wID0gXy5vcHMucG9wKCk7IF8udHJ5cy5wb3AoKTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgICAgICAgICAgIGlmICghKHQgPSBfLnRyeXMsIHQgPSB0Lmxlbmd0aCA+IDAgJiYgdFt0Lmxlbmd0aCAtIDFdKSAmJiAob3BbMF0gPT09IDYgfHwgb3BbMF0gPT09IDIpKSB7IF8gPSAwOyBjb250aW51ZTsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gMyAmJiAoIXQgfHwgKG9wWzFdID4gdFswXSAmJiBvcFsxXSA8IHRbM10pKSkgeyBfLmxhYmVsID0gb3BbMV07IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG9wWzBdID09PSA2ICYmIF8ubGFiZWwgPCB0WzFdKSB7IF8ubGFiZWwgPSB0WzFdOyB0ID0gb3A7IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHQgJiYgXy5sYWJlbCA8IHRbMl0pIHsgXy5sYWJlbCA9IHRbMl07IF8ub3BzLnB1c2gob3ApOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0WzJdKSBfLm9wcy5wb3AoKTtcclxuICAgICAgICAgICAgICAgICAgICBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIG9wID0gYm9keS5jYWxsKHRoaXNBcmcsIF8pO1xyXG4gICAgICAgIH0gY2F0Y2ggKGUpIHsgb3AgPSBbNiwgZV07IHkgPSAwOyB9IGZpbmFsbHkgeyBmID0gdCA9IDA7IH1cclxuICAgICAgICBpZiAob3BbMF0gJiA1KSB0aHJvdyBvcFsxXTsgcmV0dXJuIHsgdmFsdWU6IG9wWzBdID8gb3BbMV0gOiB2b2lkIDAsIGRvbmU6IHRydWUgfTtcclxuICAgIH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY3JlYXRlQmluZGluZyhvLCBtLCBrLCBrMikge1xyXG4gICAgaWYgKGsyID09PSB1bmRlZmluZWQpIGsyID0gaztcclxuICAgIG9bazJdID0gbVtrXTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXhwb3J0U3RhcihtLCBleHBvcnRzKSB7XHJcbiAgICBmb3IgKHZhciBwIGluIG0pIGlmIChwICE9PSBcImRlZmF1bHRcIiAmJiAhZXhwb3J0cy5oYXNPd25Qcm9wZXJ0eShwKSkgZXhwb3J0c1twXSA9IG1bcF07XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3ZhbHVlcyhvKSB7XHJcbiAgICB2YXIgcyA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBTeW1ib2wuaXRlcmF0b3IsIG0gPSBzICYmIG9bc10sIGkgPSAwO1xyXG4gICAgaWYgKG0pIHJldHVybiBtLmNhbGwobyk7XHJcbiAgICBpZiAobyAmJiB0eXBlb2Ygby5sZW5ndGggPT09IFwibnVtYmVyXCIpIHJldHVybiB7XHJcbiAgICAgICAgbmV4dDogZnVuY3Rpb24gKCkge1xyXG4gICAgICAgICAgICBpZiAobyAmJiBpID49IG8ubGVuZ3RoKSBvID0gdm9pZCAwO1xyXG4gICAgICAgICAgICByZXR1cm4geyB2YWx1ZTogbyAmJiBvW2krK10sIGRvbmU6ICFvIH07XHJcbiAgICAgICAgfVxyXG4gICAgfTtcclxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IocyA/IFwiT2JqZWN0IGlzIG5vdCBpdGVyYWJsZS5cIiA6IFwiU3ltYm9sLml0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcmVhZChvLCBuKSB7XHJcbiAgICB2YXIgbSA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBvW1N5bWJvbC5pdGVyYXRvcl07XHJcbiAgICBpZiAoIW0pIHJldHVybiBvO1xyXG4gICAgdmFyIGkgPSBtLmNhbGwobyksIHIsIGFyID0gW10sIGU7XHJcbiAgICB0cnkge1xyXG4gICAgICAgIHdoaWxlICgobiA9PT0gdm9pZCAwIHx8IG4tLSA+IDApICYmICEociA9IGkubmV4dCgpKS5kb25lKSBhci5wdXNoKHIudmFsdWUpO1xyXG4gICAgfVxyXG4gICAgY2F0Y2ggKGVycm9yKSB7IGUgPSB7IGVycm9yOiBlcnJvciB9OyB9XHJcbiAgICBmaW5hbGx5IHtcclxuICAgICAgICB0cnkge1xyXG4gICAgICAgICAgICBpZiAociAmJiAhci5kb25lICYmIChtID0gaVtcInJldHVyblwiXSkpIG0uY2FsbChpKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgZmluYWxseSB7IGlmIChlKSB0aHJvdyBlLmVycm9yOyB9XHJcbiAgICB9XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZCgpIHtcclxuICAgIGZvciAodmFyIGFyID0gW10sIGkgPSAwOyBpIDwgYXJndW1lbnRzLmxlbmd0aDsgaSsrKVxyXG4gICAgICAgIGFyID0gYXIuY29uY2F0KF9fcmVhZChhcmd1bWVudHNbaV0pKTtcclxuICAgIHJldHVybiBhcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fc3ByZWFkQXJyYXlzKCkge1xyXG4gICAgZm9yICh2YXIgcyA9IDAsIGkgPSAwLCBpbCA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBpbDsgaSsrKSBzICs9IGFyZ3VtZW50c1tpXS5sZW5ndGg7XHJcbiAgICBmb3IgKHZhciByID0gQXJyYXkocyksIGsgPSAwLCBpID0gMDsgaSA8IGlsOyBpKyspXHJcbiAgICAgICAgZm9yICh2YXIgYSA9IGFyZ3VtZW50c1tpXSwgaiA9IDAsIGpsID0gYS5sZW5ndGg7IGogPCBqbDsgaisrLCBrKyspXHJcbiAgICAgICAgICAgIHJba10gPSBhW2pdO1xyXG4gICAgcmV0dXJuIHI7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hd2FpdCh2KSB7XHJcbiAgICByZXR1cm4gdGhpcyBpbnN0YW5jZW9mIF9fYXdhaXQgPyAodGhpcy52ID0gdiwgdGhpcykgOiBuZXcgX19hd2FpdCh2KTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNHZW5lcmF0b3IodGhpc0FyZywgX2FyZ3VtZW50cywgZ2VuZXJhdG9yKSB7XHJcbiAgICBpZiAoIVN5bWJvbC5hc3luY0l0ZXJhdG9yKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU3ltYm9sLmFzeW5jSXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgdmFyIGcgPSBnZW5lcmF0b3IuYXBwbHkodGhpc0FyZywgX2FyZ3VtZW50cyB8fCBbXSksIGksIHEgPSBbXTtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyBpZiAoZ1tuXSkgaVtuXSA9IGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAoYSwgYikgeyBxLnB1c2goW24sIHYsIGEsIGJdKSA+IDEgfHwgcmVzdW1lKG4sIHYpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gcmVzdW1lKG4sIHYpIHsgdHJ5IHsgc3RlcChnW25dKHYpKTsgfSBjYXRjaCAoZSkgeyBzZXR0bGUocVswXVszXSwgZSk7IH0gfVxyXG4gICAgZnVuY3Rpb24gc3RlcChyKSB7IHIudmFsdWUgaW5zdGFuY2VvZiBfX2F3YWl0ID8gUHJvbWlzZS5yZXNvbHZlKHIudmFsdWUudikudGhlbihmdWxmaWxsLCByZWplY3QpIDogc2V0dGxlKHFbMF1bMl0sIHIpOyB9XHJcbiAgICBmdW5jdGlvbiBmdWxmaWxsKHZhbHVlKSB7IHJlc3VtZShcIm5leHRcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiByZWplY3QodmFsdWUpIHsgcmVzdW1lKFwidGhyb3dcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUoZiwgdikgeyBpZiAoZih2KSwgcS5zaGlmdCgpLCBxLmxlbmd0aCkgcmVzdW1lKHFbMF1bMF0sIHFbMF1bMV0pOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jRGVsZWdhdG9yKG8pIHtcclxuICAgIHZhciBpLCBwO1xyXG4gICAgcmV0dXJuIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiLCBmdW5jdGlvbiAoZSkgeyB0aHJvdyBlOyB9KSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuaXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobiwgZikgeyBpW25dID0gb1tuXSA/IGZ1bmN0aW9uICh2KSB7IHJldHVybiAocCA9ICFwKSA/IHsgdmFsdWU6IF9fYXdhaXQob1tuXSh2KSksIGRvbmU6IG4gPT09IFwicmV0dXJuXCIgfSA6IGYgPyBmKHYpIDogdjsgfSA6IGY7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNWYWx1ZXMobykge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBtID0gb1tTeW1ib2wuYXN5bmNJdGVyYXRvcl0sIGk7XHJcbiAgICByZXR1cm4gbSA/IG0uY2FsbChvKSA6IChvID0gdHlwZW9mIF9fdmFsdWVzID09PSBcImZ1bmN0aW9uXCIgPyBfX3ZhbHVlcyhvKSA6IG9bU3ltYm9sLml0ZXJhdG9yXSgpLCBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaSk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaVtuXSA9IG9bbl0gJiYgZnVuY3Rpb24gKHYpIHsgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHsgdiA9IG9bbl0odiksIHNldHRsZShyZXNvbHZlLCByZWplY3QsIHYuZG9uZSwgdi52YWx1ZSk7IH0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCBkLCB2KSB7IFByb21pc2UucmVzb2x2ZSh2KS50aGVuKGZ1bmN0aW9uKHYpIHsgcmVzb2x2ZSh7IHZhbHVlOiB2LCBkb25lOiBkIH0pOyB9LCByZWplY3QpOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX21ha2VUZW1wbGF0ZU9iamVjdChjb29rZWQsIHJhdykge1xyXG4gICAgaWYgKE9iamVjdC5kZWZpbmVQcm9wZXJ0eSkgeyBPYmplY3QuZGVmaW5lUHJvcGVydHkoY29va2VkLCBcInJhd1wiLCB7IHZhbHVlOiByYXcgfSk7IH0gZWxzZSB7IGNvb2tlZC5yYXcgPSByYXc7IH1cclxuICAgIHJldHVybiBjb29rZWQ7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnRTdGFyKG1vZCkge1xyXG4gICAgaWYgKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgcmV0dXJuIG1vZDtcclxuICAgIHZhciByZXN1bHQgPSB7fTtcclxuICAgIGlmIChtb2QgIT0gbnVsbCkgZm9yICh2YXIgayBpbiBtb2QpIGlmIChPYmplY3QuaGFzT3duUHJvcGVydHkuY2FsbChtb2QsIGspKSByZXN1bHRba10gPSBtb2Rba107XHJcbiAgICByZXN1bHQuZGVmYXVsdCA9IG1vZDtcclxuICAgIHJldHVybiByZXN1bHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2ltcG9ydERlZmF1bHQobW9kKSB7XHJcbiAgICByZXR1cm4gKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgPyBtb2QgOiB7IGRlZmF1bHQ6IG1vZCB9O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZEdldChyZWNlaXZlciwgcHJpdmF0ZU1hcCkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIGdldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHJldHVybiBwcml2YXRlTWFwLmdldChyZWNlaXZlcik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NsYXNzUHJpdmF0ZUZpZWxkU2V0KHJlY2VpdmVyLCBwcml2YXRlTWFwLCB2YWx1ZSkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIHNldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHByaXZhdGVNYXAuc2V0KHJlY2VpdmVyLCB2YWx1ZSk7XHJcbiAgICByZXR1cm4gdmFsdWU7XHJcbn1cclxuIiwiaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiO1xyXG5pbXBvcnQge1xyXG4gIEFwcFdpZGdldENvbmZpZywgQXNzZXNzbWVudCwgXHJcbiAgQ2xzc1Jlc3BvbnNlLFxyXG4gIENMU1NUZW1wbGF0ZSwgXHJcbiAgQ29tcG9uZW50VGVtcGxhdGUsIFxyXG4gIEhhemFyZCxcclxuICBJbmNpZGVudCxcclxuICBJbkNvbW1lbnQsXHJcbiAgSW5kaWNhdG9yQXNzZXNzbWVudCxcclxuICBJbmRpY2F0b3JUZW1wbGF0ZSwgSW5kaWNhdG9yV2VpZ2h0LCBMaWZlbGluZVN0YXR1cywgTGlmZUxpbmVUZW1wbGF0ZSxcclxuICBPcmdhbml6YXRpb24sIFNjYWxlRmFjdG9yXHJcbn0gZnJvbSBcIi4vZGF0YS1kZWZpbml0aW9uc1wiO1xyXG5pbXBvcnQge1xyXG4gIEFTU0VTU01FTlRfVVJMX0VSUk9SLCBcclxuICBCQVNFTElORV9URU1QTEFURV9OQU1FLCBcclxuICBDT01QT05FTlRfVVJMX0VSUk9SLCBFTlZJUk9OTUVOVF9QUkVTRVJWQVRJT04sIEhBWkFSRF9VUkxfRVJST1IsIElOQ0lERU5UX1NUQUJJTElaQVRJT04sIElOQ0lERU5UX1VSTF9FUlJPUiwgSU5ESUNBVE9SX1VSTF9FUlJPUixcclxuICBMSUZFX1NBRkVUWSxcclxuICBMSUZFX1NBRkVUWV9TQ0FMRV9GQUNUT1IsXHJcbiAgTElGRUxJTkVfVVJMX0VSUk9SLCBNQVhJTVVNX1dFSUdIVCwgT1JHQU5JWkFUSU9OX1VSTF9FUlJPUiwgT1RIRVJfV0VJR0hUU19TQ0FMRV9GQUNUT1IsIFxyXG4gIFBPUlRBTF9VUkwsIFxyXG4gIFBST1BFUlRZX1BST1RFQ1RJT04sIFxyXG4gIFJBTkssIFxyXG4gIFRFTVBMQVRFX1VSTF9FUlJPUn0gZnJvbSBcIi4vY29uc3RhbnRzXCI7XHJcbmltcG9ydCB7IGdldEFwcFN0b3JlIH0gZnJvbSBcImppbXUtY29yZVwiO1xyXG5pbXBvcnQge1xyXG4gIElGZWF0dXJlLCBJRmVhdHVyZVNldCwgSUZpZWxkfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllclwiO1xyXG5pbXBvcnQgeyBxdWVyeVRhYmxlRmVhdHVyZXMsIFxyXG4gICB1cGRhdGVUYWJsZUZlYXR1cmUsIGRlbGV0ZVRhYmxlRmVhdHVyZXMsIFxyXG4gICAgYWRkVGFibGVGZWF0dXJlcywgdXBkYXRlVGFibGVGZWF0dXJlcywgcXVlcnlUYWJsZUZlYXR1cmVTZXQgfSBmcm9tIFwiLi9lc3JpLWFwaVwiO1xyXG5pbXBvcnQgeyBsb2csIExvZ1R5cGUgfSBmcm9tIFwiLi9sb2dnZXJcIjtcclxuaW1wb3J0IHsgSUNvZGVkVmFsdWUgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtdHlwZXNcIjtcclxuaW1wb3J0IHsgY2hlY2tDdXJyZW50U3RhdHVzLCBzaWduSW4gfSBmcm9tIFwiLi9hdXRoXCI7XHJcbmltcG9ydCB7IENMU1NBY3Rpb25LZXlzIH0gZnJvbSBcIi4vY2xzcy1zdG9yZVwiO1xyXG5pbXBvcnQgeyBJQ3JlZGVudGlhbCB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1hdXRoXCI7XHJcbmltcG9ydCB7IHBhcnNlRGF0ZSB9IGZyb20gXCIuL3V0aWxzXCI7XHJcblxyXG5cclxuLy89PT09PT09PT09PT09PT09PT09PT09PT1QVUJMSUM9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XHJcblxyXG5leHBvcnQgY29uc3QgaW5pdGlhbGl6ZUF1dGggPSBhc3luYyhhcHBJZDogc3RyaW5nKSA9PnsgICBcclxuICBjb25zb2xlLmxvZygnaW5pdGlhbGl6ZUF1dGggY2FsbGVkJylcclxuICBsZXQgY3JlZCA9IGF3YWl0IGNoZWNrQ3VycmVudFN0YXR1cyhhcHBJZCwgUE9SVEFMX1VSTCk7XHJcblxyXG4gIGlmKCFjcmVkKXtcclxuICAgIGNyZWQgPSBhd2FpdCBzaWduSW4oYXBwSWQsIFBPUlRBTF9VUkwpOyAgICBcclxuICB9XHJcblxyXG4gIGNvbnN0IGNyZWRlbnRpYWwgPSB7XHJcbiAgICBleHBpcmVzOiBjcmVkLmV4cGlyZXMsXHJcbiAgICBzZXJ2ZXI6IGNyZWQuc2VydmVyLFxyXG4gICAgc3NsOiBjcmVkLnNzbCxcclxuICAgIHRva2VuOiBjcmVkLnRva2VuLFxyXG4gICAgdXNlcklkOiBjcmVkLnVzZXJJZFxyXG4gIH0gYXMgSUNyZWRlbnRpYWxcclxuXHJcbiAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuQVVUSEVOVElDQVRFX0FDVElPTiwgY3JlZGVudGlhbCk7IFxyXG59XHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB1cGRhdGVMaWZlbGluZVN0YXR1cyhsaWZlbGluZVN0YXR1czogTGlmZWxpbmVTdGF0dXMsIFxyXG4gIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBhc3Nlc3NtZW50T2JqZWN0SWQ6IG51bWJlciwgIHVzZXI6IHN0cmluZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICBcclxuICBjb25zb2xlLmxvZygnY2FsbGVkIHVwZGF0ZUxpZmVsaW5lU3RhdHVzJylcclxuICBjaGVja1BhcmFtKGNvbmZpZy5saWZlbGluZVN0YXR1cywgJ0xpZmVsaW5lIFN0YXR1cyBVUkwgbm90IHByb3ZpZGVkJyk7XHJcblxyXG4gIGNvbnN0IGF0dHJpYnV0ZXMgPSB7XHJcbiAgICBPQkpFQ1RJRDogbGlmZWxpbmVTdGF0dXMub2JqZWN0SWQsXHJcbiAgICBTY29yZTogbGlmZWxpbmVTdGF0dXMuc2NvcmUsIFxyXG4gICAgQ29sb3I6IGxpZmVsaW5lU3RhdHVzLmNvbG9yLCBcclxuICAgIElzT3ZlcnJpZGVuOiBsaWZlbGluZVN0YXR1cy5pc092ZXJyaWRlbiwgXHJcbiAgICBPdmVycmlkZW5TY29yZTogbGlmZWxpbmVTdGF0dXMub3ZlcnJpZGVTY29yZSwgIFxyXG4gICAgT3ZlcnJpZGVuQ29sb3I6IGxpZmVsaW5lU3RhdHVzLm92ZXJyaWRlbkNvbG9yLFxyXG4gICAgT3ZlcnJpZGVuQnk6IGxpZmVsaW5lU3RhdHVzLm92ZXJyaWRlbkJ5LCAgXHJcbiAgICBPdmVycmlkZUNvbW1lbnQ6IGxpZmVsaW5lU3RhdHVzLm92ZXJyaWRlQ29tbWVudCBcclxuICB9XHJcbiAgbGV0IHJlc3BvbnNlICA9IGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZShjb25maWcubGlmZWxpbmVTdGF0dXMsIGF0dHJpYnV0ZXMsIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcblxyXG4gICAgY29uc3QgaWFGZWF0dXJlcyA9IGxpZmVsaW5lU3RhdHVzLmluZGljYXRvckFzc2Vzc21lbnRzLm1hcChpID0+IHtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICBPQkpFQ1RJRDogaS5vYmplY3RJZCxcclxuICAgICAgICAgIHN0YXR1czogaS5zdGF0dXMsXHJcbiAgICAgICAgICBDb21tZW50czogaS5jb21tZW50cyAmJiBpLmNvbW1lbnRzLmxlbmd0aCA+IDAgPyBKU09OLnN0cmluZ2lmeShpLmNvbW1lbnRzKTogJydcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuICAgIH0pXHJcblxyXG4gICAgcmVzcG9uc2UgPSBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JBc3Nlc3NtZW50cywgaWFGZWF0dXJlcywgY29uZmlnKTtcclxuICAgIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG5cclxuICAgICAgY29uc3QgYXNzZXNzRmVhdHVyZSA9IHtcclxuICAgICAgICBPQkpFQ1RJRDogYXNzZXNzbWVudE9iamVjdElkLFxyXG4gICAgICAgIEVkaXRlZERhdGU6IG5ldyBEYXRlKCkuZ2V0VGltZSgpLFxyXG4gICAgICAgIEVkaXRvcjogdXNlclxyXG4gICAgICB9XHJcbiAgICAgIHJlc3BvbnNlID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy5hc3Nlc3NtZW50cywgYXNzZXNzRmVhdHVyZSwgY29uZmlnKVxyXG4gICAgICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG4gICAgfSAgICBcclxuICB9XHJcbiAgbG9nKCdVcGRhdGluZyBMaWZlbGluZSBzY29yZSBmYWlsZWQnLCBMb2dUeXBlLkVSUk9SLCAndXBkYXRlTGlmZWxpbmVTdGF0dXMnKTtcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnVXBkYXRpbmcgTGlmZWxpbmUgc2NvcmUgZmFpbGVkJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNvbXBsZXRlQXNzZXNzbWVudChhc3Nlc3NtZW50OiBBc3Nlc3NtZW50LCBcclxuICBjb25maWc6IEFwcFdpZGdldENvbmZpZywgdXNlck5hbWU6IHN0cmluZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICAgY2hlY2tQYXJhbShjb25maWcuYXNzZXNzbWVudHMsICdObyBBc3Nlc3NtZW50IFVybCBwcm92aWRlZCcpO1xyXG5cclxuICAgY29uc3QgcmVzcG9uc2UgPSAgYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy5hc3Nlc3NtZW50cywge1xyXG4gICAgICBPQkpFQ1RJRDogYXNzZXNzbWVudC5vYmplY3RJZCxcclxuICAgICAgRWRpdG9yOiB1c2VyTmFtZSxcclxuICAgICAgRWRpdGVkRGF0ZTogbmV3IERhdGUoKS5nZXRUaW1lKCksXHJcbiAgICAgIElzQ29tcGxldGVkOiAxXHJcbiAgIH0sIGNvbmZpZyk7XHJcbiAgIGNvbnNvbGUubG9nKHJlc3BvbnNlKTtcclxuICAgcmV0dXJue1xyXG4gICAgIGRhdGE6IHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2VzcylcclxuICAgfVxyXG59XHJcblxyXG5leHBvcnQgY29uc3QgcGFzc0RhdGFJbnRlZ3JpdHkgPSBhc3luYyAoc2VydmljZVVybDogc3RyaW5nLCBmaWVsZHM6IElGaWVsZFtdLCBjb25maWc6IEFwcFdpZGdldENvbmZpZykgPT4ge1xyXG5cclxuICBjaGVja1BhcmFtKHNlcnZpY2VVcmwsICdTZXJ2aWNlIFVSTCBub3QgcHJvdmlkZWQnKTtcclxuXHJcbiAgLy8gc2VydmljZVVybCA9IGAke3NlcnZpY2VVcmx9P2Y9anNvbiZ0b2tlbj0ke3Rva2VufWA7XHJcbiAgLy8gY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaChzZXJ2aWNlVXJsLCB7XHJcbiAgLy8gICBtZXRob2Q6IFwiR0VUXCIsXHJcbiAgLy8gICBoZWFkZXJzOiB7XHJcbiAgLy8gICAgICdjb250ZW50LXR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xyXG4gIC8vICAgfVxyXG4gIC8vIH1cclxuICAvLyApO1xyXG4gIC8vIGNvbnN0IGpzb24gPSBhd2FpdCByZXNwb25zZS5qc29uKCk7XHJcblxyXG4gIC8vIGNvbnN0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKHNlcnZpY2VVcmwsICcxPTEnLCBjb25maWcpO1xyXG5cclxuICAvLyBjb25zdCBkYXRhRmllbGRzID0gZmVhdHVyZXNbMF0uIGFzIElGaWVsZFtdO1xyXG5cclxuICAvLyBkZWJ1Z2dlcjtcclxuICAvLyBpZiAoZmllbGRzLmxlbmd0aCA+IGRhdGFGaWVsZHMubGVuZ3RoKSB7XHJcbiAgLy8gICB0aHJvdyBuZXcgRXJyb3IoJ051bWJlciBvZiBmaWVsZHMgZG8gbm90IG1hdGNoIGZvciAnICsgc2VydmljZVVybCk7XHJcbiAgLy8gfVxyXG5cclxuICAvLyBjb25zdCBhbGxGaWVsZHNHb29kID0gZmllbGRzLmV2ZXJ5KGYgPT4ge1xyXG4gIC8vICAgY29uc3QgZm91bmQgPSBkYXRhRmllbGRzLmZpbmQoZjEgPT4gZjEubmFtZSA9PT0gZi5uYW1lICYmIGYxLnR5cGUudG9TdHJpbmcoKSA9PT0gZi50eXBlLnRvU3RyaW5nKCkgJiYgZjEuZG9tYWluID09IGYuZG9tYWluKTtcclxuICAvLyAgIHJldHVybiBmb3VuZDtcclxuICAvLyB9KTtcclxuXHJcbiAgLy8gaWYgKCFhbGxGaWVsZHNHb29kKSB7XHJcbiAgLy8gICB0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgZmllbGRzIGluIHRoZSBmZWF0dXJlIHNlcnZpY2UgJyArIHNlcnZpY2VVcmwpXHJcbiAgLy8gfVxyXG4gIHJldHVybiB0cnVlO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRJbmRpY2F0b3JGZWF0dXJlcyhxdWVyeTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVbXT57XHJcbiAgY29uc29sZS5sb2coJ2dldCBJbmRpY2F0b3JzIGNhbGxlZCcpO1xyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvcnMsIHF1ZXJ5LCBjb25maWcpO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRXZWlnaHRzRmVhdHVyZXMocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlW10+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgV2VpZ2h0cyBjYWxsZWQnKTtcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy53ZWlnaHRzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0TGlmZWxpbmVGZWF0dXJlcyhxdWVyeTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVbXT57XHJcbiAgY29uc29sZS5sb2coJ2dldCBMaWZlbGluZSBjYWxsZWQnKTtcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZXMsIHF1ZXJ5LCBjb25maWcpO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRDb21wb25lbnRGZWF0dXJlcyhxdWVyeTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVbXT57XHJcbiAgY29uc29sZS5sb2coJ2dldCBDb21wb25lbnRzIGNhbGxlZCcpO1xyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmNvbXBvbmVudHMsIHF1ZXJ5LCBjb25maWcpO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRUZW1wbGF0ZUZlYXR1cmVTZXQocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlU2V0PntcclxuICBjb25zb2xlLmxvZygnZ2V0IFRlbXBsYXRlIGNhbGxlZCcpO1xyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZVNldChjb25maWcudGVtcGxhdGVzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldFRlbXBsYXRlcyhjb25maWc6IEFwcFdpZGdldENvbmZpZywgdGVtcGxhdGVJZD86IHN0cmluZywgcXVlcnlTdHJpbmc/OnN0cmluZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPENMU1NUZW1wbGF0ZVtdPj4ge1xyXG5cclxuICBjb25zdCB0ZW1wbGF0ZVVybCA9IGNvbmZpZy50ZW1wbGF0ZXM7XHJcbiAgY29uc3QgbGlmZWxpbmVVcmwgPSBjb25maWcubGlmZWxpbmVzO1xyXG4gIGNvbnN0IGNvbXBvbmVudFVybCA9IGNvbmZpZy5jb21wb25lbnRzO1xyXG5cclxuICB0cnl7XHJcbiAgICBjaGVja1BhcmFtKHRlbXBsYXRlVXJsLCBURU1QTEFURV9VUkxfRVJST1IpO1xyXG4gICAgY2hlY2tQYXJhbShsaWZlbGluZVVybCwgTElGRUxJTkVfVVJMX0VSUk9SKTtcclxuICAgIGNoZWNrUGFyYW0oY29tcG9uZW50VXJsLCBDT01QT05FTlRfVVJMX0VSUk9SKTtcclxuXHJcbiAgICBjb25zdCB0ZW1wUXVlcnkgPSB0ZW1wbGF0ZUlkID8gYEdsb2JhbElEPScke3RlbXBsYXRlSWR9YCA6KHF1ZXJ5U3RyaW5nID8gcXVlcnlTdHJpbmcgOiAnMT0xJyApO1xyXG5cclxuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgUHJvbWlzZS5hbGwoW1xyXG4gICAgICBnZXRUZW1wbGF0ZUZlYXR1cmVTZXQodGVtcFF1ZXJ5LCBjb25maWcpLFxyXG4gICAgICBnZXRMaWZlbGluZUZlYXR1cmVzKCcxPTEnLCBjb25maWcpLCBcclxuICAgICAgZ2V0Q29tcG9uZW50RmVhdHVyZXMoJzE9MScsIGNvbmZpZyldKTtcclxuICAgIFxyXG4gICAgY29uc3QgdGVtcGxhdGVGZWF0dXJlU2V0ID0gcmVzcG9uc2VbMF07XHJcbiAgICBjb25zdCBsaWZlbGluZUZlYXR1cmVzID0gcmVzcG9uc2VbMV07XHJcbiAgICBjb25zdCBjb21wb25lbnRGZWF0dXJlcyA9IHJlc3BvbnNlWzJdO1xyXG5cclxuICAgIGNvbnN0IGluZGljYXRvckZlYXR1cmVzID0gYXdhaXQgZ2V0SW5kaWNhdG9yRmVhdHVyZXMoJzE9MScsIGNvbmZpZyk7XHJcbiAgICBjb25zdCB3ZWlnaHRGZWF0dXJlcyA9IGF3YWl0IGdldFdlaWdodHNGZWF0dXJlcygnMT0xJywgY29uZmlnKTtcclxuXHJcbiAgICBjb25zdCB0ZW1wbGF0ZXMgPSBhd2FpdCBQcm9taXNlLmFsbCh0ZW1wbGF0ZUZlYXR1cmVTZXQuZmVhdHVyZXMubWFwKGFzeW5jICh0ZW1wbGF0ZUZlYXR1cmU6IElGZWF0dXJlKSA9PiB7XHJcbiAgICAgIGNvbnN0IHRlbXBsYXRlSW5kaWNhdG9yRmVhdHVyZXMgPSBpbmRpY2F0b3JGZWF0dXJlcy5maWx0ZXIoaSA9PmkuYXR0cmlidXRlcy5UZW1wbGF0ZUlEID09IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEKSAgICAgIFxyXG4gICAgICByZXR1cm4gYXdhaXQgZ2V0VGVtcGxhdGUodGVtcGxhdGVGZWF0dXJlLCBsaWZlbGluZUZlYXR1cmVzLCBjb21wb25lbnRGZWF0dXJlcywgXHJcbiAgICAgICAgdGVtcGxhdGVJbmRpY2F0b3JGZWF0dXJlcywgd2VpZ2h0RmVhdHVyZXMsIFxyXG4gICAgICAgIHRlbXBsYXRlRmVhdHVyZVNldC5maWVsZHMuZmluZChmID0+IGYubmFtZSA9PT0gJ1N0YXR1cycpLmRvbWFpbi5jb2RlZFZhbHVlcylcclxuICAgIH0pKTtcclxuXHJcbiAgICBpZih0ZW1wbGF0ZXMuZmlsdGVyKHQgPT4gdC5pc1NlbGVjdGVkKS5sZW5ndGggPiAxIHx8IHRlbXBsYXRlcy5maWx0ZXIodCA9PiB0LmlzU2VsZWN0ZWQpLmxlbmd0aCA9PSAwKXtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiB0ZW1wbGF0ZXMubWFwKHQgPT4ge1xyXG4gICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgLi4udCxcclxuICAgICAgICAgICAgaXNTZWxlY3RlZDogdC5uYW1lID09PSBCQVNFTElORV9URU1QTEFURV9OQU1FXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgfSlcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGlmKHRlbXBsYXRlcy5sZW5ndGggPT09IDEpe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IHRlbXBsYXRlcy5tYXAodCA9PiB7XHJcbiAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAuLi50LFxyXG4gICAgICAgICAgICBpc1NlbGVjdGVkOiB0cnVlXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgfSlcclxuICAgICAgfVxyXG4gICAgfVxyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogdGVtcGxhdGVzXHJcbiAgICB9XHJcbiAgfVxyXG4gIGNhdGNoKGUpeyBcclxuICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAnZ2V0VGVtcGxhdGVzJyk7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBlcnJvcnM6ICdUZW1wbGF0ZXMgcmVxdWVzdCBmYWlsZWQuJ1xyXG4gICAgfVxyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIHVzZUZldGNoRGF0YTxUPih1cmw6IHN0cmluZywgY2FsbGJhY2tBZGFwdGVyPzogRnVuY3Rpb24pOiBbVCwgRnVuY3Rpb24sIGJvb2xlYW4sIHN0cmluZ10ge1xyXG4gIGNvbnN0IFtkYXRhLCBzZXREYXRhXSA9IFJlYWN0LnVzZVN0YXRlKG51bGwpO1xyXG4gIGNvbnN0IFtsb2FkaW5nLCBzZXRMb2FkaW5nXSA9IFJlYWN0LnVzZVN0YXRlKHRydWUpO1xyXG4gIGNvbnN0IFtlcnJvciwgc2V0RXJyb3JdID0gUmVhY3QudXNlU3RhdGUoJycpO1xyXG5cclxuICBSZWFjdC51c2VFZmZlY3QoKCkgPT4ge1xyXG4gICAgY29uc3QgY29udHJvbGxlciA9IG5ldyBBYm9ydENvbnRyb2xsZXIoKTtcclxuICAgIHJlcXVlc3REYXRhKHVybCwgY29udHJvbGxlcilcclxuICAgICAgLnRoZW4oKGRhdGEpID0+IHtcclxuICAgICAgICBpZiAoY2FsbGJhY2tBZGFwdGVyKSB7XHJcbiAgICAgICAgICBzZXREYXRhKGNhbGxiYWNrQWRhcHRlcihkYXRhKSk7XHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgIHNldERhdGEoZGF0YSk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xyXG4gICAgICB9KVxyXG4gICAgICAuY2F0Y2goKGVycikgPT4ge1xyXG4gICAgICAgIGNvbnNvbGUubG9nKGVycik7XHJcbiAgICAgICAgc2V0RXJyb3IoZXJyKTtcclxuICAgICAgfSlcclxuICAgIHJldHVybiAoKSA9PiBjb250cm9sbGVyLmFib3J0KCk7XHJcbiAgfSwgW3VybF0pXHJcblxyXG4gIHJldHVybiBbZGF0YSwgc2V0RGF0YSwgbG9hZGluZywgZXJyb3JdXHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBkaXNwYXRjaEFjdGlvbih0eXBlOiBhbnksIHZhbDogYW55KSB7XHJcbiAgZ2V0QXBwU3RvcmUoKS5kaXNwYXRjaCh7XHJcbiAgICB0eXBlLFxyXG4gICAgdmFsXHJcbiAgfSk7XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRJbmNpZGVudHMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPEluY2lkZW50W10+IHtcclxuICAgXHJcbiAgY29uc29sZS5sb2coJ2dldCBpbmNpZGVudHMgY2FsbGVkLicpXHJcbiAgY2hlY2tQYXJhbShjb25maWcuaW5jaWRlbnRzLCBJTkNJREVOVF9VUkxfRVJST1IpO1xyXG5cclxuICBjb25zdCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuaW5jaWRlbnRzLCAnMT0xJywgY29uZmlnKTtcclxuXHJcbiAgY29uc3QgcXVlcnkgPSBgR2xvYmFsSUQgSU4gKCR7ZmVhdHVyZXMubWFwKGYgPT4gZi5hdHRyaWJ1dGVzLkhhemFyZElEKS5tYXAoaWQgPT4gYCcke2lkfSdgKS5qb2luKCcsJyl9KWA7XHJcbiAgXHJcbiAgY29uc3QgaGF6YXJkRmVhdHVyZXNldCA9IGF3YWl0IGdldEhhemFyZEZlYXR1cmVzKGNvbmZpZywgcXVlcnksICdnZXRJbmNpZGVudHMnKTtcclxuXHJcbiAgcmV0dXJuIGZlYXR1cmVzLm1hcCgoZjogSUZlYXR1cmUpID0+e1xyXG4gICAgICBjb25zdCBoZiA9IGhhemFyZEZlYXR1cmVzZXQuZmVhdHVyZXMuZmluZChoID0+IGguYXR0cmlidXRlcy5HbG9iYWxJRCA9PSBmLmF0dHJpYnV0ZXMuSGF6YXJkSUQpXHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgb2JqZWN0SWQ6IGYuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgICBpZDogZi5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICAgIG5hbWU6IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgIGhhemFyZDogaGYgPyB7XHJcbiAgICAgICAgICBvYmplY3RJZDogaGYuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgICAgIGlkOiBoZi5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICAgICAgbmFtZTogaGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgICAgdGl0bGU6IGhmLmF0dHJpYnV0ZXMuRGlzcGxheVRpdGxlIHx8IGhmLmF0dHJpYnV0ZXMuRGlzcGxheU5hbWUgfHwgaGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgICAgdHlwZTogaGYuYXR0cmlidXRlcy5UeXBlLFxyXG4gICAgICAgICAgZGVzY3JpcHRpb246IGhmLmF0dHJpYnV0ZXMuRGVzY3JpcHRpb24sXHJcbiAgICAgICAgICBkb21haW5zOiBoYXphcmRGZWF0dXJlc2V0LmZpZWxkcy5maW5kKGYgPT4gZi5uYW1lID09PSAnVHlwZScpLmRvbWFpbi5jb2RlZFZhbHVlc1xyXG4gICAgICAgIH0gOiBudWxsLFxyXG4gICAgICAgIGRlc2NyaXB0aW9uOiBmLmF0dHJpYnV0ZXMuRGVzY3JpcHRpb24sXHJcbiAgICAgICAgc3RhcnREYXRlOiBOdW1iZXIoZi5hdHRyaWJ1dGVzLlN0YXJ0RGF0ZSksXHJcbiAgICAgICAgZW5kRGF0ZTogTnVtYmVyKGYuYXR0cmlidXRlcy5FbmREYXRlKVxyXG4gICAgICB9IGFzIEluY2lkZW50O1xyXG4gIH0pO1xyXG4gIHJldHVybiBbXTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0SGF6YXJkRmVhdHVyZXMgKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBxdWVyeTogc3RyaW5nLCBjYWxsZXI6IHN0cmluZyk6IFByb21pc2U8SUZlYXR1cmVTZXQ+IHtcclxuICBjb25zb2xlLmxvZygnZ2V0IEhhemFyZHMgY2FsbGVkIGJ5ICcrY2FsbGVyKVxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmhhemFyZHMsIEhBWkFSRF9VUkxfRVJST1IpOyAgXHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlU2V0KGNvbmZpZy5oYXphcmRzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldEhhemFyZHMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHF1ZXJ5U3RyaW5nOiBzdHJpbmcsIGNhbGxlcjogc3RyaW5nKTogUHJvbWlzZTxIYXphcmRbXT4ge1xyXG4gIFxyXG4gIGNvbnN0IGZlYXR1cmVTZXQgPSBhd2FpdCBnZXRIYXphcmRGZWF0dXJlcyhjb25maWcsIHF1ZXJ5U3RyaW5nLCBjYWxsZXIpO1xyXG4gIGlmKCFmZWF0dXJlU2V0IHx8IGZlYXR1cmVTZXQuZmVhdHVyZXMubGVuZ3RoID09IDApe1xyXG4gICAgcmV0dXJuIFtdO1xyXG4gIH1cclxuICByZXR1cm4gZmVhdHVyZVNldC5mZWF0dXJlcy5tYXAoKGY6IElGZWF0dXJlKSA9PiB7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBvYmplY3RJZDogZi5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICBpZDogZi5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICBuYW1lOiBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgdGl0bGU6IGYuYXR0cmlidXRlcy5EaXNwbGF5VGl0bGUgfHwgZi5hdHRyaWJ1dGVzLkRpc3BsYXlOYW1lIHx8IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICB0eXBlOiBmLmF0dHJpYnV0ZXMuVHlwZSxcclxuICAgICAgZGVzY3JpcHRpb246IGYuYXR0cmlidXRlcy5EZXNjcmlwdGlvbixcclxuICAgICAgZG9tYWluczogZmVhdHVyZVNldC5maWVsZHMuZmluZChmID0+IGYubmFtZSA9PT0gJ1R5cGUnKS5kb21haW4uY29kZWRWYWx1ZXNcclxuICAgIH0gYXMgSGF6YXJkXHJcbiAgfSlcclxuICByZXR1cm4gW107XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRPcmdhbml6YXRpb25zKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBxdWVyeVN0cmluZzogc3RyaW5nKTogUHJvbWlzZTxPcmdhbml6YXRpb25bXT4ge1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgT3JnYW5pemF0aW9ucyBjYWxsZWQnKVxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLm9yZ2FuaXphdGlvbnMsIE9SR0FOSVpBVElPTl9VUkxfRVJST1IpO1xyXG5cclxuICBjb25zdCBmZWF0dXJlU2V0ID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVTZXQoY29uZmlnLm9yZ2FuaXphdGlvbnMsIHF1ZXJ5U3RyaW5nLCBjb25maWcpO1xyXG4gXHJcbiAgaWYoZmVhdHVyZVNldCAmJiBmZWF0dXJlU2V0LmZlYXR1cmVzICYmIGZlYXR1cmVTZXQuZmVhdHVyZXMubGVuZ3RoID4gMCl7XHJcbiAgICByZXR1cm4gZmVhdHVyZVNldC5mZWF0dXJlcy5tYXAoKGY6IElGZWF0dXJlKSA9PiB7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgb2JqZWN0SWQ6IGYuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgICBpZDogZi5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICAgIG5hbWU6IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgIHRpdGxlOiBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICB0eXBlOiBmLmF0dHJpYnV0ZXMuVHlwZSxcclxuICAgICAgICBwYXJlbnRJZDogZi5hdHRyaWJ1dGVzLlBhcmVudElELFxyXG4gICAgICAgIGRlc2NyaXB0aW9uOiBmLmF0dHJpYnV0ZXMuRGVzY3JpcHRpb24sXHJcbiAgICAgICAgZG9tYWluczogZmVhdHVyZVNldC5maWVsZHMuZmluZChmID0+IGYubmFtZSA9PT0gJ1R5cGUnKS5kb21haW4uY29kZWRWYWx1ZXNcclxuICAgICAgfSBhcyBPcmdhbml6YXRpb25cclxuICAgIH0pXHJcbiAgfVxyXG4gIHJldHVybiBbXTtcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNyZWF0ZU5ld1RlbXBsYXRlKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCB0ZW1wbGF0ZTogQ0xTU1RlbXBsYXRlLCBcclxuIHVzZXJOYW1lOiBzdHJpbmcsIG9yZ2FuaXphdGlvbjogT3JnYW5pemF0aW9uLCBoYXphcmQ6IEhhemFyZCk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PiB7XHJcbiBcclxuICBjaGVja1BhcmFtKGNvbmZpZy50ZW1wbGF0ZXMsIFRFTVBMQVRFX1VSTF9FUlJPUik7XHJcbiAgY2hlY2tQYXJhbSh0ZW1wbGF0ZSwgJ1RlbXBsYXRlIGRhdGEgbm90IHByb3ZpZGVkJyk7XHJcblxyXG4gIGNvbnN0IGNyZWF0ZURhdGUgPSBuZXcgRGF0ZSgpLmdldFRpbWUoKTtcclxuICBjb25zdCB0ZW1wbGF0ZU5hbWUgPSB0ZW1wbGF0ZS5uYW1lWzBdLnRvTG9jYWxlVXBwZXJDYXNlKCkrdGVtcGxhdGUubmFtZS5zdWJzdHJpbmcoMSk7XHJcbiBcclxuICBsZXQgZmVhdHVyZSA9IHtcclxuICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgT3JnYW5pemF0aW9uSUQ6IG9yZ2FuaXphdGlvbiA/IG9yZ2FuaXphdGlvbi5pZCA6ICBudWxsLFxyXG4gICAgICBPcmdhbml6YXRpb25OYW1lOiBvcmdhbml6YXRpb24gPyBvcmdhbml6YXRpb24ubmFtZTogbnVsbCxcclxuICAgICAgT3JnYW5pemF0aW9uVHlwZTogb3JnYW5pemF0aW9uID8gKG9yZ2FuaXphdGlvbi50eXBlLmNvZGUgPyBvcmdhbml6YXRpb24udHlwZS5jb2RlOiBvcmdhbml6YXRpb24udHlwZSApOiBudWxsLFxyXG4gICAgICBIYXphcmRJRDogIGhhemFyZCA/IGhhemFyZC5pZCA6IG51bGwsXHJcbiAgICAgIEhhemFyZE5hbWU6ICBoYXphcmQgPyBoYXphcmQubmFtZSA6IG51bGwsXHJcbiAgICAgIEhhemFyZFR5cGU6ICBoYXphcmQgPyAoaGF6YXJkLnR5cGUuY29kZSA/IGhhemFyZC50eXBlLmNvZGUgOiBoYXphcmQudHlwZSkgOiBudWxsLFxyXG4gICAgICBOYW1lOiB0ZW1wbGF0ZU5hbWUgLFxyXG4gICAgICBDcmVhdG9yOiB1c2VyTmFtZSxcclxuICAgICAgQ3JlYXRlZERhdGU6IGNyZWF0ZURhdGUsICAgICAgXHJcbiAgICAgIFN0YXR1czogMSxcclxuICAgICAgSXNTZWxlY3RlZDogMCxcclxuICAgICAgRWRpdG9yOiB1c2VyTmFtZSxcclxuICAgICAgRWRpdGVkRGF0ZTogY3JlYXRlRGF0ZSAgICAgXHJcbiAgICB9XHJcbiAgfVxyXG4gIGxldCByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLnRlbXBsYXRlcywgW2ZlYXR1cmVdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgXHJcbiAgICBjb25zdCB0ZW1wbGF0ZUlkID0gcmVzcG9uc2UuYWRkUmVzdWx0c1swXS5nbG9iYWxJZDtcclxuICAgIC8vY3JlYXRlIG5ldyBpbmRpY2F0b3JzICAgXHJcbiAgICBjb25zdCBpbmRpY2F0b3JzID0gZ2V0VGVtcGxhdGVJbmRpY2F0b3JzKHRlbXBsYXRlKTtcclxuICAgIGNvbnN0IGluZGljYXRvckZlYXR1cmVzID0gaW5kaWNhdG9ycy5tYXAoaW5kaWNhdG9yID0+IHtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICBUZW1wbGF0ZUlEOiB0ZW1wbGF0ZUlkLCAgXHJcbiAgICAgICAgICBDb21wb25lbnRJRDogaW5kaWNhdG9yLmNvbXBvbmVudElkLFxyXG4gICAgICAgICAgQ29tcG9uZW50TmFtZTogaW5kaWNhdG9yLmNvbXBvbmVudE5hbWUsICBcclxuICAgICAgICAgIE5hbWU6IGluZGljYXRvci5uYW1lLCAgIFxyXG4gICAgICAgICAgVGVtcGxhdGVOYW1lOiB0ZW1wbGF0ZU5hbWUsIFxyXG4gICAgICAgICAgTGlmZWxpbmVOYW1lOiBpbmRpY2F0b3IubGlmZWxpbmVOYW1lICAgICAgXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcbiAgICB9KVxyXG4gICAgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLCBpbmRpY2F0b3JGZWF0dXJlcywgY29uZmlnKTtcclxuICAgIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG5cclxuICAgICAgY29uc3QgZ2xvYmFsSWRzID0gYCgke3Jlc3BvbnNlLmFkZFJlc3VsdHMubWFwKHIgPT4gYCcke3IuZ2xvYmFsSWR9J2ApLmpvaW4oJywnKX0pYDtcclxuICAgICAgY29uc3QgcXVlcnkgPSAnR2xvYmFsSUQgSU4gJytnbG9iYWxJZHM7ICAgICBcclxuICAgICAgY29uc3QgYWRkZWRJbmRpY2F0b3JGZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9ycyxxdWVyeSAsIGNvbmZpZyk7XHJcblxyXG4gICAgICAgbGV0IHdlaWdodHNGZWF0dXJlcyA9IFtdO1xyXG4gICAgICAgZm9yKGxldCBmZWF0dXJlIG9mIGFkZGVkSW5kaWNhdG9yRmVhdHVyZXMpeyAgIFxyXG4gICAgICAgICBjb25zdCBpbmNvbWluZ0luZGljYXRvciA9IGluZGljYXRvcnMuZmluZChpID0+IGkubmFtZSA9PT0gZmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUpO1xyXG4gICAgICAgICBpZihpbmNvbWluZ0luZGljYXRvcil7XHJcbiAgICAgICAgICBjb25zdCB3ZWlnaHRGZWF0dXJlcyA9IGluY29taW5nSW5kaWNhdG9yLndlaWdodHMubWFwKHcgPT4geyAgICAgICAgXHJcbiAgICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgICAgICAgSW5kaWNhdG9ySUQ6IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCwgIFxyXG4gICAgICAgICAgICAgICAgTmFtZTogdy5uYW1lICxcclxuICAgICAgICAgICAgICAgIFdlaWdodDogdy53ZWlnaHQsIFxyXG4gICAgICAgICAgICAgICAgU2NhbGVGYWN0b3I6IDAsICBcclxuICAgICAgICAgICAgICAgIEFkanVzdGVkV2VpZ2h0IDogMCxcclxuICAgICAgICAgICAgICAgIE1heEFkanVzdGVkV2VpZ2h0OjBcclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgIH0pO1xyXG4gICAgICAgICAgd2VpZ2h0c0ZlYXR1cmVzID0gd2VpZ2h0c0ZlYXR1cmVzLmNvbmNhdCh3ZWlnaHRGZWF0dXJlcylcclxuICAgICAgICAgfSAgICAgICAgICAgIFxyXG4gICAgICAgfVxyXG5cclxuICAgICAgIHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcud2VpZ2h0cywgd2VpZ2h0c0ZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgICAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGRhdGE6IHRydWVcclxuICAgICAgICB9XHJcbiAgICAgICB9XHJcbiAgICB9XHJcbiAgICAvLyBjb25zdCBwcm9taXNlcyA9IGluZGljYXRvcnMubWFwKGluZGljYXRvciA9PiBjcmVhdGVOZXdJbmRpY2F0b3IoaW5kaWNhdG9yLCBjb25maWcsIHRlbXBsYXRlSWQsIHRlbXBsYXRlTmFtZSkpO1xyXG5cclxuICAgIC8vIGNvbnN0IHByb21pc2VSZXNwb25zZSA9IGF3YWl0IFByb21pc2UuYWxsKHByb21pc2VzKTtcclxuICAgIC8vIGlmKHByb21pc2VSZXNwb25zZS5ldmVyeShwID0+IHAuZGF0YSkpe1xyXG4gICAgLy8gICByZXR1cm4ge1xyXG4gICAgLy8gICAgIGRhdGE6IHRydWVcclxuICAgIC8vICAgfVxyXG4gICAgLy8gfVxyXG4gIH0gXHJcblxyXG4gIGxvZyhKU09OLnN0cmluZ2lmeShyZXNwb25zZSksIExvZ1R5cGUuRVJST1IsICdjcmVhdGVOZXdUZW1wbGF0ZScpXHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIGNyZWF0aW5nIHRoZSBuZXcgdGVtcGxhdGUnXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdXBkYXRlVGVtcGxhdGVPcmdhbml6YXRpb25BbmRIYXphcmQoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIFxyXG4gIHRlbXBsYXRlOiBDTFNTVGVtcGxhdGUsIHVzZXJOYW1lOiBzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj4ge1xyXG5cclxuICBjaGVja1BhcmFtKHRlbXBsYXRlLCAnVGVtcGxhdGUgbm90IHByb3ZpZGVkJyk7XHJcbiAgY2hlY2tQYXJhbShjb25maWcudGVtcGxhdGVzLCBURU1QTEFURV9VUkxfRVJST1IpOyBcclxuXHJcbiAgY29uc3QgYXR0cmlidXRlcyA9IHtcclxuICAgIE9CSkVDVElEOiB0ZW1wbGF0ZS5vYmplY3RJZCxcclxuICAgIE9yZ2FuaXphdGlvbklEOiB0ZW1wbGF0ZS5vcmdhbml6YXRpb25JZCxcclxuICAgIEhhemFyZElEOiB0ZW1wbGF0ZS5oYXphcmRJZCxcclxuICAgIE9yZ2FuaXphdGlvbk5hbWU6IHRlbXBsYXRlLm9yZ2FuaXphdGlvbk5hbWUsXHJcbiAgICBPcmdhbml6YXRpb25UeXBlOiB0ZW1wbGF0ZS5vcmdhbml6YXRpb25UeXBlLFxyXG4gICAgSGF6YXJkTmFtZTogdGVtcGxhdGUuaGF6YXJkTmFtZSxcclxuICAgIEhhemFyZFR5cGU6IHRlbXBsYXRlLmhhemFyZFR5cGUsXHJcbiAgICBOYW1lOiB0ZW1wbGF0ZS5uYW1lLFxyXG4gICAgRWRpdG9yOiB1c2VyTmFtZSxcclxuICAgIEVkaXRlZERhdGU6IG5ldyBEYXRlKCkuZ2V0VGltZSgpLFxyXG4gICAgU3RhdHVzOiB0ZW1wbGF0ZS5zdGF0dXMuY29kZSxcclxuICAgIElzU2VsZWN0ZWQ6IHRlbXBsYXRlLmlzU2VsZWN0ZWQgPyAxOiAwXHJcbiAgfSBcclxuICBjb25zdCByZXNwb25zZSA9ICBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmUoY29uZmlnLnRlbXBsYXRlcywgYXR0cmlidXRlcywgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHRydWVcclxuICAgIH1cclxuICB9XHJcbiAgbG9nKEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKSwgTG9nVHlwZS5FUlJPUiwgJ3VwZGF0ZVRlbXBsYXRlT3JnYW5pemF0aW9uQW5kSGF6YXJkJylcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgdXBkYXRpbmcgdGVtcGxhdGUuJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHNlbGVjdFRlbXBsYXRlKG9iamVjdElkOiBudW1iZXIsIG9iamVjdElkczogbnVtYmVyW10sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8U3RyaW5nPj4ge1xyXG4gIFxyXG4gICAgY29uc29sZS5sb2coJ3NlbGVjdCBUZW1wbGF0ZSBjYWxsZWQnKVxyXG4gICAgdHJ5e1xyXG4gICAgICBjaGVja1BhcmFtKGNvbmZpZy50ZW1wbGF0ZXMsIFRFTVBMQVRFX1VSTF9FUlJPUik7XHJcblxyXG4gICAgICAvL2xldCBmZWF0dXJlcyA9IGF3YWl0IGdldFRlbXBsYXRlRmVhdHVyZXMoJzE9MScsIGNvbmZpZykvLyBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLnRlbXBsYXRlcywgJzE9MScsIGNvbmZpZylcclxuICAgIFxyXG4gICAgICBjb25zdCBmZWF0dXJlcyA9ICBvYmplY3RJZHMubWFwKG9pZCA9PiB7XHJcbiAgICAgICAgcmV0dXJuIHsgICAgICAgICAgXHJcbiAgICAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICAgIE9CSkVDVElEOiBvaWQsXHJcbiAgICAgICAgICAgIElzU2VsZWN0ZWQ6IG9pZCA9PT0gb2JqZWN0SWQgPyAxIDogMFxyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgICAgfSlcclxuICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmVzKGNvbmZpZy50ZW1wbGF0ZXMsIGZlYXR1cmVzLCBjb25maWcpXHJcbiAgICAgIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG4gICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgZGF0YTogcmVzcG9uc2UudXBkYXRlUmVzdWx0c1swXS5nbG9iYWxJZFxyXG4gICAgICAgICB9IGFzIENsc3NSZXNwb25zZTxTdHJpbmc+O1xyXG4gICAgICB9XHJcbiAgICB9Y2F0Y2goZSkge1xyXG4gICAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ3NlbGVjdFRlbXBsYXRlJyk7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZXJyb3JzOiBlXHJcbiAgICAgIH1cclxuICAgIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGxvYWRTY2FsZUZhY3RvcnMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxTY2FsZUZhY3RvcltdPj57XHJcblxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmNvbnN0YW50cywgJ1JhdGluZyBTY2FsZXMgdXJsIG5vdCBwcm92aWRlZCcpO1xyXG5cclxuICB0cnl7XHJcblxyXG4gICBjb25zdCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuY29uc3RhbnRzLCAnMT0xJywgY29uZmlnKTtcclxuICAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMCl7XHJcbiAgICAgY29uc3Qgc2NhbGVzID0gIGZlYXR1cmVzLm1hcChmID0+e1xyXG4gICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgbmFtZTogZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgIHZhbHVlOiBmLmF0dHJpYnV0ZXMuVmFsdWVcclxuICAgICAgIH0gYXMgU2NhbGVGYWN0b3I7ICAgICAgIFxyXG4gICAgIH0pXHJcblxyXG4gICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHNjYWxlc1xyXG4gICAgfSBhcyBDbHNzUmVzcG9uc2U8U2NhbGVGYWN0b3JbXT5cclxuICAgfVxyXG5cclxuICAgbG9nKCdFcnJvciBvY2N1cnJlZCB3aGlsZSByZXF1ZXN0aW5nIHJhdGluZyBzY2FsZXMnLCBMb2dUeXBlLkVSUk9SLCAnbG9hZFJhdGluZ1NjYWxlcycpXHJcbiAgIHJldHVybiB7XHJcbiAgICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgcmVxdWVzdGluZyByYXRpbmcgc2NhbGVzJ1xyXG4gICB9XHJcbiAgfSBjYXRjaChlKXtcclxuICAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ2xvYWRSYXRpbmdTY2FsZXMnKTsgICAgXHJcbiAgfSAgXHJcbiAgIFxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY3JlYXRlTmV3SW5kaWNhdG9yKGluZGljYXRvcjogSW5kaWNhdG9yVGVtcGxhdGUsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCB0ZW1wbGF0ZUlkOiBzdHJpbmcsIHRlbXBsYXRlTmFtZTogc3RyaW5nKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+IHtcclxuXHJcbiAgY2hlY2tQYXJhbShjb25maWcuaW5kaWNhdG9ycywgSU5ESUNBVE9SX1VSTF9FUlJPUik7XHJcblxyXG4gIGNvbnN0IGluZGljYXRvckZlYXR1cmUgPSB7XHJcbiAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgIFRlbXBsYXRlSUQ6IHRlbXBsYXRlSWQsICBcclxuICAgICAgQ29tcG9uZW50SUQ6IGluZGljYXRvci5jb21wb25lbnRJZCxcclxuICAgICAgQ29tcG9uZW50TmFtZTogaW5kaWNhdG9yLmNvbXBvbmVudE5hbWUsICBcclxuICAgICAgTmFtZTogaW5kaWNhdG9yLm5hbWUsICAgXHJcbiAgICAgIFRlbXBsYXRlTmFtZTogdGVtcGxhdGVOYW1lLCBcclxuICAgICAgTGlmZWxpbmVOYW1lOiBpbmRpY2F0b3IubGlmZWxpbmVOYW1lICAgICAgXHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBsZXQgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLCBbaW5kaWNhdG9yRmVhdHVyZV0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcblxyXG4gICAgY29uc3Qgd2VpZ2h0RmVhdHVyZXMgPSBpbmRpY2F0b3Iud2VpZ2h0cy5tYXAodyA9PiB7XHJcbiAgICAgICBcclxuICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgSW5kaWNhdG9ySUQ6IHJlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWQsICBcclxuICAgICAgICAgIE5hbWU6IHcubmFtZSAsXHJcbiAgICAgICAgICBXZWlnaHQ6IHcud2VpZ2h0LCBcclxuICAgICAgICAgIFNjYWxlRmFjdG9yOiAwLCAgXHJcbiAgICAgICAgICBBZGp1c3RlZFdlaWdodCA6IDAsXHJcbiAgICAgICAgICBNYXhBZGp1c3RlZFdlaWdodDowXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcbiAgICB9KTtcclxuXHJcbiAgICByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLndlaWdodHMsIHdlaWdodEZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcbiAgICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IHRydWVcclxuICAgICAgIH1cclxuICAgIH1cclxuICB9XHJcblxyXG4gIGxvZyhKU09OLnN0cmluZ2lmeShyZXNwb25zZSksIExvZ1R5cGUuRVJST1IsICdjcmVhdGVOZXdJbmRpY2F0b3InKTtcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgc2F2aW5nIHRoZSBpbmRpY2F0b3IuJ1xyXG4gIH1cclxuXHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB1cGRhdGVJbmRpY2F0b3JOYW1lKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBpbmRpY2F0b3JUZW1wOkluZGljYXRvclRlbXBsYXRlKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gICBcclxuICBjaGVja1BhcmFtKGNvbmZpZy5pbmRpY2F0b3JzLCBJTkRJQ0FUT1JfVVJMX0VSUk9SKTtcclxuXHJcbiAgY29uc3QgYXR0cmlidXRlcyA9IHtcclxuICAgIE9CSkVDVElEOiBpbmRpY2F0b3JUZW1wLm9iamVjdElkLFxyXG4gICAgTmFtZTogaW5kaWNhdG9yVGVtcC5uYW1lLFxyXG4gICAgRGlzcGxheVRpdGxlOiBpbmRpY2F0b3JUZW1wLm5hbWUsXHJcbiAgICBJc0FjdGl2ZTogMVxyXG4gIH1cclxuICBjb25zdCByZXNwb25zZSA9ICBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmUoY29uZmlnLmluZGljYXRvcnMsIGF0dHJpYnV0ZXMsIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgIH1cclxuICB9XHJcbiAgbG9nKEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKSwgTG9nVHlwZS5FUlJPUiwgJ3VwZGF0ZUluZGljYXRvck5hbWUnKVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSB1cGRhdGluZyBpbmRpY2F0b3InXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdXBkYXRlSW5kaWNhdG9yKGluZGljYXRvcjogSW5kaWNhdG9yVGVtcGxhdGUsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gICBcclxuICBjaGVja1BhcmFtKGNvbmZpZy5pbmRpY2F0b3JzLCBJTkNJREVOVF9VUkxfRVJST1IpO1xyXG5cclxuICBsZXQgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvcnMsIGBOYW1lPScke2luZGljYXRvci5uYW1lfScgQU5EIFRlbXBsYXRlTmFtZT0nJHtpbmRpY2F0b3IudGVtcGxhdGVOYW1lfSdgLCBjb25maWcpXHJcbiBcclxuICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAxKXtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGVycm9yczogJ0FuIGluZGljYXRvciB3aXRoIHRoZSBzYW1lIG5hbWUgYWxyZWFkeSBleGlzdHMnXHJcbiAgICB9XHJcbiAgfVxyXG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgdXBkYXRlSW5kaWNhdG9yTmFtZShjb25maWcsIGluZGljYXRvcik7XHJcblxyXG4gIGlmKHJlc3BvbnNlLmVycm9ycyl7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBlcnJvcnM6IHJlc3BvbnNlLmVycm9yc1xyXG4gICAgfVxyXG4gIH1cclxuIFxyXG4gICBmZWF0dXJlcyA9IGluZGljYXRvci53ZWlnaHRzLm1hcCh3ID0+IHtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgT0JKRUNUSUQ6IHcub2JqZWN0SWQsXHJcbiAgICAgICAgICBXZWlnaHQ6IE51bWJlcih3LndlaWdodCksIFxyXG4gICAgICAgICAgQWRqdXN0ZWRXZWlnaHQ6IE51bWJlcih3LndlaWdodCkgKiB3LnNjYWxlRmFjdG9yXHJcbiAgICAgICB9XHJcbiAgICAgfVxyXG4gICB9KTtcclxuXHJcbiAgIGNvbnN0IHVwZGF0ZVJlc3BvbnNlID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlcyhjb25maWcud2VpZ2h0cywgZmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgIGlmKHVwZGF0ZVJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgdXBkYXRlUmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHRydWVcclxuICAgICB9XHJcbiAgIH1cclxuXHJcbiAgIGxvZyhKU09OLnN0cmluZ2lmeSh1cGRhdGVSZXNwb25zZSksIExvZ1R5cGUuRVJST1IsICd1cGRhdGVJbmRpY2F0b3InKTtcclxuICAgcmV0dXJuIHtcclxuICAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSB1cGRhdGluZyBpbmRpY2F0b3IuJ1xyXG4gICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWxldGVJbmRpY2F0b3IoaW5kaWNhdG9yVGVtcGxhdGU6IEluZGljYXRvclRlbXBsYXRlLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PiB7XHJcblxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmluZGljYXRvcnMsIElORElDQVRPUl9VUkxfRVJST1IpO1xyXG4gIGNoZWNrUGFyYW0oY29uZmlnLndlaWdodHMsICdXZWlnaHRzIFVSTCBub3QgcHJvdmlkZWQnKTtcclxuICBcclxuICBsZXQgcmVzcCA9IGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvcnMsIFtpbmRpY2F0b3JUZW1wbGF0ZS5vYmplY3RJZF0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcC5kZWxldGVSZXN1bHRzICYmIHJlc3AuZGVsZXRlUmVzdWx0cy5ldmVyeShkID0+IGQuc3VjY2Vzcykpe1xyXG4gICAgIGNvbnN0IHdlaWdodHNPYmplY3RJZHMgPSBpbmRpY2F0b3JUZW1wbGF0ZS53ZWlnaHRzLm1hcCh3ID0+IHcub2JqZWN0SWQpO1xyXG4gICAgIHJlc3AgPSBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy53ZWlnaHRzLCB3ZWlnaHRzT2JqZWN0SWRzLCBjb25maWcpO1xyXG4gICAgIGlmKHJlc3AuZGVsZXRlUmVzdWx0cyAmJiByZXNwLmRlbGV0ZVJlc3VsdHMuZXZlcnkoZCA9PiBkLnN1Y2Nlc3MpKXtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgIH1cclxuICAgICB9XHJcbiAgfVxyXG5cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcCksIExvZ1R5cGUuRVJST1IsICdkZWxldGVJbmRpY2F0b3InKVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSBkZWxldGluZyB0aGUgaW5kaWNhdG9yJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGFyY2hpdmVUZW1wbGF0ZShvYmplY3RJZDogbnVtYmVyLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PiB7XHJcbiBcclxuICBjb25zdCByZXNwb25zZSAgPSBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmUoY29uZmlnLnRlbXBsYXRlcywge1xyXG4gICAgT0JKRUNUSUQ6IG9iamVjdElkLFxyXG4gICAgSXNTZWxlY3RlZDogMCxcclxuICAgIElzQWN0aXZlOiAwXHJcbiAgfSwgY29uZmlnKTtcclxuICBjb25zb2xlLmxvZyhyZXNwb25zZSk7XHJcbiAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KGUgPT4gZS5zdWNjZXNzKSl7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB0cnVlXHJcbiAgICB9XHJcbiAgfVxyXG4gIGxvZyhKU09OLnN0cmluZ2lmeShyZXNwb25zZSksIExvZ1R5cGUuRVJST1IsICdhcmNoaXZlVGVtcGxhdGUnKTtcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnVGhlIHRlbXBsYXRlIGNhbm5vdCBiZSBhcmNoaXZlZC4nXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc2F2ZU9yZ2FuaXphdGlvbihjb25maWc6IEFwcFdpZGdldENvbmZpZywgb3JnYW5pemF0aW9uOiBPcmdhbml6YXRpb24pOiBQcm9taXNlPENsc3NSZXNwb25zZTxPcmdhbml6YXRpb24+PiB7XHJcblxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLm9yZ2FuaXphdGlvbnMsIE9SR0FOSVpBVElPTl9VUkxfRVJST1IpO1xyXG4gIGNoZWNrUGFyYW0ob3JnYW5pemF0aW9uLCAnT3JnYW5pemF0aW9uIG9iamVjdCBub3QgcHJvdmlkZWQnKTtcclxuIFxyXG4gIGNvbnN0IGZlYXR1cmUgPSB7XHJcbiAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgIE5hbWU6IG9yZ2FuaXphdGlvbi5uYW1lLFxyXG4gICAgICBUeXBlOiBvcmdhbml6YXRpb24udHlwZT8uY29kZSxcclxuICAgICAgRGlzcGxheVRpdGxlOiBvcmdhbml6YXRpb24ubmFtZSxcclxuICAgICAgUGFyZW50SUQ6IG9yZ2FuaXphdGlvbj8ucGFyZW50SWRcclxuICAgIH1cclxuICB9XHJcbiAgY29uc3QgcmVzcG9uc2UgPSAgYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcub3JnYW5pemF0aW9ucywgW2ZlYXR1cmVdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2VzcykpeyBcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHtcclxuICAgICAgICAuLi5vcmdhbml6YXRpb25cclxuICAgICAgfSBhcyBPcmdhbml6YXRpb24gLy8gKGF3YWl0IGdldE9yZ2FuaXphdGlvbnMoY29uZmlnLCBgR2xvYmFsSUQ9JyR7cmVzcG9uc2UuYWRkUmVzdWx0c1swXS5nbG9iYWxJZH0nYCkpWzBdXHJcbiAgICB9XHJcbiAgfVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6IEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKVxyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHNhdmVIYXphcmQoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIGhhemFyZDogSGF6YXJkKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8SGF6YXJkPj4ge1xyXG4gIFxyXG4gIGNvbnN0IGZlYXR1cmUgPSB7XHJcbiAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgIE5hbWU6IGhhemFyZC5uYW1lLFxyXG4gICAgICBEaXNwbGF5VGl0bGU6IGhhemFyZC5uYW1lLFxyXG4gICAgICBUeXBlOiBoYXphcmQudHlwZS5jb2RlLFxyXG4gICAgICBEZXNjcmlwdGlvbjogaGF6YXJkLmRlc2NyaXB0aW9uXHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBjb25zdCByZXNwb25zZSA9ICBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5oYXphcmRzLCBbZmVhdHVyZV0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7ICAgXHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YToge1xyXG4gICAgICAgICAgLi4uaGF6YXJkLFxyXG4gICAgICAgICAgb2JqZWN0SWQ6IHJlc3BvbnNlLmFkZFJlc3VsdHNbMF0ub2JqZWN0SWQsXHJcbiAgICAgICAgICBpZDogcmVzcG9uc2UuYWRkUmVzdWx0c1swXS5nbG9iYWxJZFxyXG4gICAgICAgIH0gYXMgSGF6YXJkICBcclxuICAgICAgfVxyXG4gIH1cclxuXHJcbiAgbG9nKGBFcnJvciBvY2N1cnJlZCB3aGlsZSBzYXZpbmcgaGF6YXJkLiBSZXN0YXJ0aW5nIHRoZSBhcHBsaWNhdGlvbiBtYXkgZml4IHRoaXMgaXNzdWUuYCwgTG9nVHlwZS5FUlJPUiwgJ3NhdmVIYXphcmQnKVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSBzYXZpbmcgaGF6YXJkLiBSZXN0YXJ0aW5nIHRoZSBhcHBsaWNhdGlvbiBtYXkgZml4IHRoaXMgaXNzdWUuJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZUluY2lkZW50KGluY2lkZW50OiBJbmNpZGVudCwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmNpZGVudHMsIFtpbmNpZGVudC5vYmplY3RJZF0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UuZGVsZXRlUmVzdWx0cyAmJiByZXNwb25zZS5kZWxldGVSZXN1bHRzLmV2ZXJ5KGQgPT4gZC5zdWNjZXNzKSl7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgIGRhdGE6IHRydWVcclxuICAgICB9XHJcbiAgfVxyXG4gIHJldHVybiB7XHJcbiAgIGVycm9yczogSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVsZXRlSGF6YXJkKGhhemFyZDogSGF6YXJkLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5oYXphcmRzLCBbaGF6YXJkLm9iamVjdElkXSwgY29uZmlnKTtcclxuICAgaWYocmVzcG9uc2UuZGVsZXRlUmVzdWx0cyAmJiByZXNwb25zZS5kZWxldGVSZXN1bHRzLmV2ZXJ5KGQgPT4gZC5zdWNjZXNzKSl7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgICB9XHJcbiAgIH1cclxuICAgcmV0dXJuIHtcclxuICAgIGVycm9yczogSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpXHJcbiAgIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZU9yZ2FuaXphdGlvbihvcmdhbml6YXRpb246IE9yZ2FuaXphdGlvbiwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5vcmdhbml6YXRpb25zLCBbb3JnYW5pemF0aW9uLm9iamVjdElkXSwgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS5kZWxldGVSZXN1bHRzICYmIHJlc3BvbnNlLmRlbGV0ZVJlc3VsdHMuZXZlcnkoZCA9PiBkLnN1Y2Nlc3MpKXtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgIH1cclxuICB9XHJcbiAgcmV0dXJuIHtcclxuICAgZXJyb3JzOiBKU09OLnN0cmluZ2lmeShyZXNwb25zZSlcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjaGVja1BhcmFtKHBhcmFtOiBhbnksIGVycm9yOiBzdHJpbmcpIHtcclxuICBpZiAoIXBhcmFtIHx8IHBhcmFtID09IG51bGwgfHwgcGFyYW0gPT09ICcnIHx8IHBhcmFtID09IHVuZGVmaW5lZCkge1xyXG4gICAgdGhyb3cgbmV3IEVycm9yKGVycm9yKVxyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHRlbXBsQ2xlYW5VcChpbmRVcmw6IHN0cmluZywgYWxpZ1VybDogc3RyaW5nLCB0b2tlbjogc3RyaW5nKSB7XHJcblxyXG5cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHNhdmVOZXdBc3Nlc3NtZW50KG5ld0Fzc2Vzc21lbnQ6IEFzc2Vzc21lbnQsIHRlbXBsYXRlOiBDTFNTVGVtcGxhdGUsIFxyXG4gICAgICAgICAgICAgICAgICBjb25maWc6IEFwcFdpZGdldENvbmZpZywgcHJldkFzc2Vzc21lbnQ/OiBBc3Nlc3NtZW50KTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8c3RyaW5nPj57ICAgIFxyXG4gICAgICBcclxuICAgICAgY29uc3QgcmVzcCA9IGF3YWl0IHNhdmVBc3Nlc3NtZW50KG5ld0Fzc2Vzc21lbnQsIGNvbmZpZyk7XHJcbiAgICAgIGlmKHJlc3AuZXJyb3JzKXtcclxuICAgICAgICBsb2coJ1VuYWJsZSB0byBjcmVhdGUgdGhlIGFzc2Vzc21lbnQuJywgTG9nVHlwZS5FUlJPUiwgJ3NhdmVOZXdBc3Nlc3NtZW50Jyk7XHJcblxyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBlcnJvcnM6ICdVbmFibGUgdG8gY3JlYXRlIHRoZSBhc3Nlc3NtZW50LidcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuICAgICBcclxuICAgICAgdHJ5e1xyXG5cclxuICAgICAgICBjb25zdCBpbmRpY2F0b3JzID0gZ2V0VGVtcGxhdGVJbmRpY2F0b3JzKHRlbXBsYXRlKTtcclxuICAgICAgICBpZighaW5kaWNhdG9ycyB8fCBpbmRpY2F0b3JzLmxlbmd0aCA9PT0gMCl7XHJcbiAgICAgICAgICBsb2coJ1RlbXBsYXRlIGluZGljYXRvcnMgbm90IGZvdW5kJywgTG9nVHlwZS5FUlJPUiwgJ3NhdmVOZXdBc3Nlc3NtZW50Jyk7ICBcclxuICAgICAgICAgIHRocm93IG5ldyBFcnJvcignVGVtcGxhdGUgaW5kaWNhdG9ycyBub3QgZm91bmQuJylcclxuICAgICAgICB9ICAgICAgXHJcbiAgXHJcbiAgICAgICAgY29uc3QgbGlmZWxpbmVTdGF0dXNGZWF0dXJlcyA9IHRlbXBsYXRlLmxpZmVsaW5lVGVtcGxhdGVzLm1hcChsdCA9PiB7XHJcbiAgICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgYXR0cmlidXRlczogeyBcclxuICAgICAgICAgICAgICBBc3Nlc3NtZW50SUQgOiByZXNwLmRhdGEsXHJcbiAgICAgICAgICAgICAgU2NvcmU6IG51bGwsIFxyXG4gICAgICAgICAgICAgIENvbG9yOiBudWxsLCBcclxuICAgICAgICAgICAgICBMaWZlbGluZUlEOiBsdC5pZCwgXHJcbiAgICAgICAgICAgICAgSXNPdmVycmlkZW46IDAsIFxyXG4gICAgICAgICAgICAgIE92ZXJyaWRlblNjb3JlOiBudWxsLCBcclxuICAgICAgICAgICAgICBPdmVycmlkZW5CeTogbnVsbCwgXHJcbiAgICAgICAgICAgICAgT3ZlcnJpZGVDb21tZW50OiBudWxsLCBcclxuICAgICAgICAgICAgICBMaWZlbGluZU5hbWU6IGx0LnRpdGxlLCBcclxuICAgICAgICAgICAgICBUZW1wbGF0ZU5hbWU6IHRlbXBsYXRlLm5hbWVcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH0pXHJcbiAgICAgICAgbGV0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIGxpZmVsaW5lU3RhdHVzRmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICAgICAgaWYocmVzcG9uc2UgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcbiAgICAgICAgICAgY29uc3QgcXVlcnkgPSAnR2xvYmFsSUQgSU4gKCcrIHJlc3BvbnNlLmFkZFJlc3VsdHMubWFwKHIgPT4gYCcke3IuZ2xvYmFsSWR9J2ApLmpvaW4oJywnKStcIilcIjtcclxuICAgICAgICAgICBjb25zdCBsc0ZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZVN0YXR1cywgcXVlcnksIGNvbmZpZyk7XHJcbiAgICAgICAgICAgXHJcbiAgICAgICAgICAgY29uc3QgaW5kaWNhdG9yQXNzZXNzbWVudEZlYXR1cmVzID0gaW5kaWNhdG9ycy5tYXAoaSA9PiB7XHJcbiAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICBjb25zdCBsaWZlbGluZVN0YXR1c0ZlYXR1cmUgPSBsc0ZlYXR1cmVzLmZpbmQobHMgPT4gXHJcbiAgICAgICAgICAgICAgICBscy5hdHRyaWJ1dGVzLkxpZmVsaW5lTmFtZS5zcGxpdCgvWycgJyZfLF0rLykuam9pbignXycpICA9PT0gaS5saWZlbGluZU5hbWUpO1xyXG4gICAgICAgICAgICBpZighbGlmZWxpbmVTdGF0dXNGZWF0dXJlKXtcclxuICAgICAgICAgICAgICBjb25zb2xlLmxvZyhgJHtpLmxpZmVsaW5lTmFtZX0gbm90IGZvdW5kYCk7XHJcbiAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGAke2kubGlmZWxpbmVOYW1lfSBub3QgZm91bmRgKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgICAgICAgIExpZmVsaW5lU3RhdHVzSUQgOiBsaWZlbGluZVN0YXR1c0ZlYXR1cmU/IGxpZmVsaW5lU3RhdHVzRmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEIDogJycsXHJcbiAgICAgICAgICAgICAgICBJbmRpY2F0b3JJRDogaS5pZCwgIFxyXG4gICAgICAgICAgICAgICAgVGVtcGxhdGVOYW1lOiBpLnRlbXBsYXRlTmFtZSwgIFxyXG4gICAgICAgICAgICAgICAgTGlmZWxpbmVOYW1lOiBpLmxpZmVsaW5lTmFtZSwgIFxyXG4gICAgICAgICAgICAgICAgQ29tcG9uZW50TmFtZTogaS5jb21wb25lbnROYW1lLCAgXHJcbiAgICAgICAgICAgICAgICBJbmRpY2F0b3JOYW1lOiBpLm5hbWUsXHJcbiAgICAgICAgICAgICAgICBDb21tZW50czogXCJcIixcclxuICAgICAgICAgICAgICAgIFJhbms6IGkud2VpZ2h0cy5maW5kKHcgPT4gdy5uYW1lID09PSBSQU5LKT8ud2VpZ2h0LFxyXG4gICAgICAgICAgICAgICAgTGlmZVNhZmV0eTogaS53ZWlnaHRzLmZpbmQodyA9PiB3Lm5hbWUgPT09IExJRkVfU0FGRVRZKT8ud2VpZ2h0LFxyXG4gICAgICAgICAgICAgICAgUHJvcGVydHlQcm90ZWN0aW9uOiBpLndlaWdodHMuZmluZCh3ID0+IHcubmFtZSA9PT0gUFJPUEVSVFlfUFJPVEVDVElPTik/LndlaWdodCxcclxuICAgICAgICAgICAgICAgIEluY2lkZW50U3RhYmlsaXphdGlvbjogaS53ZWlnaHRzLmZpbmQodyA9PiB3Lm5hbWUgPT09IElOQ0lERU5UX1NUQUJJTElaQVRJT04pPy53ZWlnaHQsXHJcbiAgICAgICAgICAgICAgICBFbnZpcm9ubWVudFByZXNlcnZhdGlvbjogaS53ZWlnaHRzLmZpbmQodyA9PiB3Lm5hbWUgPT09IEVOVklST05NRU5UX1BSRVNFUlZBVElPTik/LndlaWdodCxcclxuICAgICAgICAgICAgICAgIFN0YXR1czogNCAvL3Vua25vd25cclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICB9KVxyXG4gIFxyXG4gICAgICAgICAgIHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9yQXNzZXNzbWVudHMsIGluZGljYXRvckFzc2Vzc21lbnRGZWF0dXJlcywgY29uZmlnKTtcclxuICAgICAgICAgICBpZihyZXNwb25zZSAmJiByZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuICAgICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgICBkYXRhOiByZXNwLmRhdGFcclxuICAgICAgICAgICAgfSBcclxuICAgICAgICAgICB9ZWxzZXtcclxuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdGYWlsZWQgdG8gYWRkIGluZGljYXRvciBhc3Nlc3NtZW50IGZlYXR1cmVzJyk7XHJcbiAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgICAgICBlbHNle1xyXG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdGYWlsZWQgdG8gYWRkIExpZmVsaW5lIFN0YXR1cyBGZWF0dXJlcycpO1xyXG4gICAgICAgIH0gXHJcblxyXG4gICAgICB9Y2F0Y2goZSl7XHJcbiAgICAgICAgYXdhaXQgY2xlYW5VcEFzc2Vzc21lbnRGYWlsZWREYXRhKHJlc3AuZGF0YSwgY29uZmlnKTtcclxuICAgICAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ3NhdmVOZXdBc3Nlc3NtZW50JylcclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgZXJyb3JzOidFcnJvciBvY2N1cnJlZCB3aGlsZSBjcmVhdGluZyBBc3Nlc3NtZW50LidcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuXHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGNsZWFuVXBBc3Nlc3NtZW50RmFpbGVkRGF0YShhc3Nlc3NtZW50R2xvYmFsSWQ6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpe1xyXG4gICBcclxuICAgbGV0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5hc3Nlc3NtZW50cywgYEdsb2JhbElEPScke2Fzc2Vzc21lbnRHbG9iYWxJZH0nYCwgY29uZmlnKTtcclxuICAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMCl7XHJcbiAgICAgYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcuYXNzZXNzbWVudHMsIGZlYXR1cmVzLm1hcChmID0+IGYuYXR0cmlidXRlcy5PQkpFQ1RJRCksIGNvbmZpZyk7XHJcbiAgIH1cclxuXHJcbiAgIGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZVN0YXR1cywgYEFzc2Vzc21lbnRJRD0nJHthc3Nlc3NtZW50R2xvYmFsSWR9J2AsIGNvbmZpZyk7XHJcbiAgIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIGZlYXR1cmVzLm1hcChmID0+IGYuYXR0cmlidXRlcy5PQkpFQ1RJRCksIGNvbmZpZyk7XHJcblxyXG4gICAgY29uc3QgcXVlcnkgPSBgTGlmZWxpbmVTdGF0dXNJRCBJTiAoJHtmZWF0dXJlcy5tYXAoZiA9PiBmLmF0dHJpYnV0ZXMuR2xvYmFsSUQpLmpvaW4oJywnKX0pYDtcclxuICAgIGNvbnNvbGUubG9nKCdkZWxldGUgcXVlcmllcycsIHF1ZXJ5KVxyXG4gICAgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBxdWVyeSwgY29uZmlnKTtcclxuICAgIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgICBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JBc3Nlc3NtZW50cywgZmVhdHVyZXMubWFwKGYgPT4gZi5hdHRyaWJ1dGVzLk9CSkVDVElEKSwgY29uZmlnKTtcclxuICAgIH1cclxuICAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0QXNzZXNzbWVudE5hbWVzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCB0ZW1wbGF0ZU5hbWU6IHN0cmluZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPHtuYW1lOiBzdHJpbmcsIGRhdGU6IHN0cmluZ31bXT4+e1xyXG4gIFxyXG4gIGNvbnN0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5hc3Nlc3NtZW50cywgYFRlbXBsYXRlPScke3RlbXBsYXRlTmFtZX0nYCwgY29uZmlnKTtcclxuICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPT09IDApe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogW11cclxuICAgIH1cclxuICB9XHJcbiAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMCl7XHJcbiAgIFxyXG4gICAgIGNvbnN0IGFzc2VzcyA9ICBmZWF0dXJlcy5tYXAoZiA9PiB7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgbmFtZTogZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgZGF0ZTogcGFyc2VEYXRlKE51bWJlcihmLmF0dHJpYnV0ZXMuQ3JlYXRlZERhdGUpKVxyXG4gICAgICB9XHJcbiAgICAgfSk7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgIGRhdGE6IGFzc2Vzc1xyXG4gICAgIH1cclxuICB9XHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ1JlcXVlc3QgZm9yIGFzc2Vzc21lbnQgbmFtZXMgZmFpbGVkLidcclxuICB9XHJcblxyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRBc3Nlc3NtZW50RmVhdHVyZXMoY29uZmlnKSB7XHJcbiAgIGNvbnNvbGUubG9nKCdnZXQgQXNzZXNzbWVudCBGZWF0dXJlcyBjYWxsZWQuJyk7XHJcbiAgIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmFzc2Vzc21lbnRzLCBgMT0xYCwgY29uZmlnKTtcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGxvYWRBbGxBc3Nlc3NtZW50cyhjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPEFzc2Vzc21lbnRbXT4+e1xyXG5cclxuICAgdHJ5e1xyXG4gICAgY29uc3QgYXNzZXNzbWVudEZlYXR1cmVzID0gYXdhaXQgZ2V0QXNzZXNzbWVudEZlYXR1cmVzKGNvbmZpZyk7XHJcbiAgICBpZighYXNzZXNzbWVudEZlYXR1cmVzIHx8IGFzc2Vzc21lbnRGZWF0dXJlcy5sZW5ndGggPT0gMCl7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogW11cclxuICAgICAgfVxyXG4gICAgfVxyXG4gICAgXHJcbiAgICBjb25zdCBsc0ZlYXR1cmVzID0gYXdhaXQgZ2V0TGlmZWxpbmVTdGF0dXNGZWF0dXJlcyhjb25maWcsIGAxPTFgKTtcclxuXHJcbiAgICBjb25zdCBxdWVyeSA9IGBMaWZlbGluZVN0YXR1c0lEIElOICgke2xzRmVhdHVyZXMubWFwKGYgPT4gYCcke2YuYXR0cmlidXRlcy5HbG9iYWxJRH0nYCkuam9pbignLCcpfSlgXHJcbiAgICBcclxuICAgIGNvbnN0IGluZGljYXRvckFzc2Vzc21lbnRzID0gYXdhaXQgZ2V0SW5kaWNhdG9yQXNzZXNzbWVudHMocXVlcnksIGNvbmZpZyk7XHJcblxyXG4gICAgaWYoYXNzZXNzbWVudEZlYXR1cmVzICYmIGFzc2Vzc21lbnRGZWF0dXJlcy5sZW5ndGggPiAwKXsgICBcclxuICAgICAgY29uc3QgYXNzZXNzbWVudHMgPSBhc3Nlc3NtZW50RmVhdHVyZXMubWFwKChmZWF0dXJlOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgICAgIGNvbnN0IGFzc2Vzc21lbnRMc0ZlYXR1cmVzID0gbHNGZWF0dXJlcy5maWx0ZXIobCA9PmwuYXR0cmlidXRlcy5Bc3Nlc3NtZW50SUQgPT0gZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEKSAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIGxvYWRBc3Nlc3NtZW50KGZlYXR1cmUsIGFzc2Vzc21lbnRMc0ZlYXR1cmVzLCBpbmRpY2F0b3JBc3Nlc3NtZW50cyk7XHJcbiAgICAgIH0pO1xyXG5cclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiBhc3Nlc3NtZW50c1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgaWYoYXNzZXNzbWVudEZlYXR1cmVzICYmIGFzc2Vzc21lbnRGZWF0dXJlcy5sZW5ndGggPT0gMCl7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogW11cclxuICAgICAgfSAgXHJcbiAgICB9XHJcbiAgIH1jYXRjaChlKXtcclxuICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAnbG9hZEFsbEFzc2Vzc21lbnRzJyk7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBlcnJvcnM6IGVcclxuICAgIH1cclxuICAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY3JlYXRlSW5jaWRlbnQoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIGluY2lkZW50OiBJbmNpZGVudCk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPHZvaWQ+PntcclxuICAgXHJcbiAgICB0cnl7XHJcbiAgICAgIGNoZWNrUGFyYW0oY29uZmlnLmluY2lkZW50cywgSU5DSURFTlRfVVJMX0VSUk9SKTtcclxuICAgICAgY2hlY2tQYXJhbShpbmNpZGVudCwgJ0luY2lkZW50IGRhdGEgbm90IHByb3ZpZGVkJyk7XHJcblxyXG4gICAgICBjb25zdCBmZWF0dXJlcyA9IFt7XHJcbiAgICAgICAgYXR0cmlidXRlcyA6IHtcclxuICAgICAgICAgIEhhemFyZElEOiBpbmNpZGVudC5oYXphcmQuaWQsXHJcbiAgICAgICAgICBOYW1lIDogaW5jaWRlbnQubmFtZSxcclxuICAgICAgICAgIERlc2NyaXB0aW9uOiBpbmNpZGVudC5kZXNjcmlwdGlvbixcclxuICAgICAgICAgIFN0YXJ0RGF0ZSA6IFN0cmluZyhpbmNpZGVudC5zdGFydERhdGUpLFxyXG4gICAgICAgICAgRW5kRGF0ZSA6IFN0cmluZyhpbmNpZGVudC5lbmREYXRlKVxyXG4gICAgICAgIH1cclxuICAgICAgfV1cclxuXHJcbiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaW5jaWRlbnRzLCBmZWF0dXJlcywgY29uZmlnKTtcclxuXHJcbiAgICAgIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5sZW5ndGggPiAwKXtcclxuICAgICAgICByZXR1cm57fSBcclxuICAgICAgfVxyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGVycm9yczogJ0luY2lkZW50IGNvdWxkIG5vdCBiZSBzYXZlZC4nXHJcbiAgICAgIH1cclxuICAgIH1jYXRjaChlKSB7XHJcbiAgICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAnY3JlYXRlSW5jaWRlbnQnKTtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBlcnJvcnM6ICdJbmNpZGVudCBjb3VsZCBub3QgYmUgc2F2ZWQuJ1xyXG4gICAgICB9XHJcbiAgICB9XHJcbn1cclxuXHJcbi8vPT09PT09PT09PT09PT09PT09PT1QUklWQVRFPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cclxuXHJcbmNvbnN0IHJlcXVlc3REYXRhID0gYXN5bmMgKHVybDogc3RyaW5nLCBjb250cm9sbGVyPzogYW55KTogUHJvbWlzZTxJRmVhdHVyZVNldD4gPT4ge1xyXG4gIGlmICghY29udHJvbGxlcikge1xyXG4gICAgY29udHJvbGxlciA9IG5ldyBBYm9ydENvbnRyb2xsZXIoKTtcclxuICB9XHJcbiAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaCh1cmwsIHtcclxuICAgIG1ldGhvZDogXCJHRVRcIixcclxuICAgIGhlYWRlcnM6IHtcclxuICAgICAgJ2NvbnRlbnQtdHlwZSc6ICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbiAgICB9LFxyXG4gICAgc2lnbmFsOiBjb250cm9sbGVyLnNpZ25hbFxyXG4gIH1cclxuICApO1xyXG4gIHJldHVybiByZXNwb25zZS5qc29uKCk7XHJcbn1cclxuXHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRUZW1wbGF0ZShcclxuICB0ZW1wbGF0ZUZlYXR1cmU6IElGZWF0dXJlLCBcclxuICBsaWZlbGluZUZlYXR1cmVzOiBJRmVhdHVyZVtdLCBcclxuICBjb21wb25lbnRGZWF0dXJlczogSUZlYXR1cmVbXSwgXHJcbiAgaW5kaWNhdG9yc0ZlYXR1cmVzOiBJRmVhdHVyZVtdLCBcclxuICB3ZWlnaHRzRmVhdHVyZXM6IElGZWF0dXJlW10sIFxyXG4gIHRlbXBsYXRlRG9tYWluczogSUNvZGVkVmFsdWVbXSk6IFByb21pc2U8Q0xTU1RlbXBsYXRlPntcclxuXHJcbiAgY29uc3QgaW5kaWNhdG9yRmVhdHVyZXMgPSBpbmRpY2F0b3JzRmVhdHVyZXMuZmlsdGVyKGkgPT4gaS5hdHRyaWJ1dGVzLlRlbXBsYXRlSUQgPSBgJyR7dGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUR9J2ApLy8gIGF3YWl0IGdldEluZGljYXRvckZlYXR1cmVzKGBUZW1wbGF0ZUlEPScke3RlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEfSdgLCBjb25maWcpO1xyXG4gIFxyXG4gIC8vY29uc3QgcXVlcnkgPSBpbmRpY2F0b3JGZWF0dXJlcy5tYXAoaSA9PiBgSW5kaWNhdG9ySUQ9JyR7aS5hdHRyaWJ1dGVzLkdsb2JhbElELnRvVXBwZXJDYXNlKCl9J2ApLmpvaW4oJyBPUiAnKVxyXG4gIFxyXG4gIGNvbnN0IGluZGljYXRvcklkcyA9IGluZGljYXRvckZlYXR1cmVzLm1hcChpID0+IGkuYXR0cmlidXRlcy5HbG9iYWxJRCk7XHJcbiAgY29uc3Qgd2VpZ2h0RmVhdHVyZXMgPSB3ZWlnaHRzRmVhdHVyZXMuZmlsdGVyKHcgPT4gaW5kaWNhdG9ySWRzLmluZGV4T2Yody5hdHRyaWJ1dGVzLkluZGljYXRvcklEKSkgLy9hd2FpdCBnZXRXZWlnaHRzRmVhdHVyZXMocXVlcnksIGNvbmZpZyk7XHJcbiAgXHJcbiAgY29uc3QgaW5kaWNhdG9yVGVtcGxhdGVzID0gaW5kaWNhdG9yRmVhdHVyZXMubWFwKChmZWF0dXJlOiBJRmVhdHVyZSkgPT4ge1xyXG5cclxuICAgICBjb25zdCB3ZWlnaHRzID0gd2VpZ2h0c0ZlYXR1cmVzXHJcbiAgICAgIC5maWx0ZXIodyA9PiB3LmF0dHJpYnV0ZXMuSW5kaWNhdG9ySUQ9PT1mZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQpXHJcbiAgICAgIC5tYXAodyA9PiB7XHJcbiAgICAgICByZXR1cm4geyBcclxuICAgICAgICBvYmplY3RJZDogdy5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICAgIG5hbWU6IHcuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgIHdlaWdodDogdy5hdHRyaWJ1dGVzLldlaWdodCxcclxuICAgICAgICBzY2FsZUZhY3RvciA6IHcuYXR0cmlidXRlcy5TY2FsZUZhY3RvciwgXHJcbiAgICAgICAgYWRqdXN0ZWRXZWlnaHQ6IHcuYXR0cmlidXRlcy5BZGp1c3RlZFdlaWdodCxcclxuICAgICAgICBtYXhBZGp1c3RlZFdlaWdodDogdy5hdHRyaWJ1dGVzLk1heEFkanVzdGVkV2VpZ2h0XHJcbiAgICAgICB9IGFzIEluZGljYXRvcldlaWdodFxyXG4gICAgIH0pXHJcblxyXG4gICAgIHJldHVybiB7XHJcbiAgICAgIG9iamVjdElkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgIGlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsIFxyXG4gICAgICBuYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgdGVtcGxhdGVOYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuVGVtcGxhdGVOYW1lLFxyXG4gICAgICB3ZWlnaHRzLFxyXG4gICAgICBjb21wb25lbnRJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkNvbXBvbmVudElELFxyXG4gICAgICB0ZW1wbGF0ZUlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuVGVtcGxhdGVJRCwgIFxyXG4gICAgICBjb21wb25lbnROYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuQ29tcG9uZW50TmFtZSxcclxuICAgICAgbGlmZWxpbmVOYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZWxpbmVOYW1lXHJcbiAgICAgfSBhcyBJbmRpY2F0b3JUZW1wbGF0ZVxyXG4gIH0pO1xyXG5cclxuICBjb25zdCBjb21wb25lbnRUZW1wbGF0ZXMgPSBjb21wb25lbnRGZWF0dXJlcy5tYXAoKGZlYXR1cmU6IElGZWF0dXJlKSA9PiB7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgICBpZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICAgIHRpdGxlOiBmZWF0dXJlLmF0dHJpYnV0ZXMuRGlzcGxheU5hbWUgfHwgZmVhdHVyZS5hdHRyaWJ1dGVzLkRpc3BsYXlUaXRsZSxcclxuICAgICAgICBuYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICBsaWZlbGluZUlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZWxpbmVJRCxcclxuICAgICAgICBpbmRpY2F0b3JzOiAoaW5kaWNhdG9yVGVtcGxhdGVzLmZpbHRlcihpID0+IGkuY29tcG9uZW50SWQgPT09IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCkgYXMgYW55KS5vcmRlckJ5KCduYW1lJylcclxuICAgICB9XHJcbiAgfSk7XHJcblxyXG4gIGNvbnN0IGxpZmVsaW5lVGVtcGxhdGVzID0gbGlmZWxpbmVGZWF0dXJlcy5tYXAoKGZlYXR1cmU6IElGZWF0dXJlKSA9PiB7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBpZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICB0aXRsZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkRpc3BsYXlOYW1lIHx8IGZlYXR1cmUuYXR0cmlidXRlcy5EaXNwbGF5VGl0bGUsXHJcbiAgICAgIG5hbWU6IGZlYXR1cmUuYXR0cmlidXRlcy5OYW1lLCAgICAgIFxyXG4gICAgICBjb21wb25lbnRUZW1wbGF0ZXM6IChjb21wb25lbnRUZW1wbGF0ZXMuZmlsdGVyKGMgPT4gYy5saWZlbGluZUlkID09PSBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQpIGFzIGFueSkub3JkZXJCeSgndGl0bGUnKVxyXG4gICAgfSBhcyBMaWZlTGluZVRlbXBsYXRlO1xyXG4gIH0pO1xyXG5cclxuICBjb25zdCB0ZW1wbGF0ZSA9IHtcclxuICAgICAgb2JqZWN0SWQ6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICBpZDogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgIGlzU2VsZWN0ZWQ6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLklzU2VsZWN0ZWQgPT0gMSxcclxuICAgICAgc3RhdHVzOiB7XHJcbiAgICAgICAgY29kZTogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuU3RhdHVzLFxyXG4gICAgICAgIG5hbWU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLlN0YXR1cyA9PT0gMSA/IFwiQWN0aXZlXCI6ICdBcmNoaXZlZCdcclxuICAgICAgfSBhcyBJQ29kZWRWYWx1ZSxcclxuICAgICAgbmFtZTogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgaGF6YXJkTmFtZTogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuSGF6YXJkTmFtZSxcclxuICAgICAgaGF6YXJkVHlwZTogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuSGF6YXJkVHlwZSxcclxuICAgICAgb3JnYW5pemF0aW9uTmFtZTogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuT3JnYW5pemF0aW9uTmFtZSxcclxuICAgICAgb3JnYW5pemF0aW9uVHlwZTogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuT3JnYW5pemF0aW9uVHlwZSwgXHJcbiAgICAgIGNyZWF0b3I6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkNyZWF0b3IsXHJcbiAgICAgIGNyZWF0ZWREYXRlOiBOdW1iZXIodGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuQ3JlYXRlZERhdGUpLFxyXG4gICAgICBlZGl0b3I6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkVkaXRvcixcclxuICAgICAgZWRpdGVkRGF0ZTogTnVtYmVyKHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkVkaXRlZERhdGUpLFxyXG4gICAgICBsaWZlbGluZVRlbXBsYXRlczogIChsaWZlbGluZVRlbXBsYXRlcyBhcyBhbnkpLm9yZGVyQnkoJ3RpdGxlJyksXHJcbiAgICAgIGRvbWFpbnM6IHRlbXBsYXRlRG9tYWluc1xyXG4gIH0gYXMgQ0xTU1RlbXBsYXRlO1xyXG5cclxuICByZXR1cm4gdGVtcGxhdGU7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIHNhdmVBc3Nlc3NtZW50KGFzc2Vzc21lbnQ6IEFzc2Vzc21lbnQsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8c3RyaW5nPj57XHJcblxyXG4gIHRyeXtcclxuICAgIGNvbnN0IGZlYXR1cmUgPSB7XHJcbiAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICBOYW1lIDphc3Nlc3NtZW50Lm5hbWUsXHJcbiAgICAgICAgRGVzY3JpcHRpb246IGFzc2Vzc21lbnQuZGVzY3JpcHRpb24sXHJcbiAgICAgICAgQXNzZXNzbWVudFR5cGU6IGFzc2Vzc21lbnQuYXNzZXNzbWVudFR5cGUsIFxyXG4gICAgICAgIE9yZ2FuaXphdGlvbjogYXNzZXNzbWVudC5vcmdhbml6YXRpb24sIFxyXG4gICAgICAgIEluY2lkZW50OiBhc3Nlc3NtZW50LmluY2lkZW50LCBcclxuICAgICAgICBIYXphcmQ6IGFzc2Vzc21lbnQuaGF6YXJkLCBcclxuICAgICAgICBDcmVhdG9yOiBhc3Nlc3NtZW50LmNyZWF0b3IsIFxyXG4gICAgICAgIENyZWF0ZWREYXRlOiBhc3Nlc3NtZW50LmNyZWF0ZWREYXRlLCBcclxuICAgICAgICBFZGl0b3I6IGFzc2Vzc21lbnQuZWRpdG9yLCBcclxuICAgICAgICBFZGl0ZWREYXRlOiBhc3Nlc3NtZW50LmVkaXRlZERhdGUsIFxyXG4gICAgICAgIElzQ29tcGxldGVkOiBhc3Nlc3NtZW50LmlzQ29tcGxldGVkLCBcclxuICAgICAgICBIYXphcmRUeXBlOiBhc3Nlc3NtZW50LmhhemFyZFR5cGUsXHJcbiAgICAgICAgT3JnYW5pemF0aW9uVHlwZTphc3Nlc3NtZW50Lm9yZ2FuaXphdGlvblR5cGUsXHJcbiAgICAgICAgVGVtcGxhdGU6IGFzc2Vzc21lbnQudGVtcGxhdGVcclxuICAgICAgfVxyXG4gICAgfVxyXG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5hc3Nlc3NtZW50cyxbZmVhdHVyZV0sIGNvbmZpZyk7XHJcbiAgICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuICAgICAgcmV0dXJueyBkYXRhOiByZXNwb25zZS5hZGRSZXN1bHRzWzBdLmdsb2JhbElkfVxyXG4gICAgfVxyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiAgSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpICAgIFxyXG4gICAgfVxyXG5cclxuICB9Y2F0Y2goZSl7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBlcnJvcnM6IGVcclxuICAgIH1cclxuICB9XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldEluZGljYXRvckFzc2Vzc21lbnRzKHF1ZXJ5OiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJbmRpY2F0b3JBc3Nlc3NtZW50W10+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgSW5kaWNhdG9yIEFzc2Vzc21lbnRzIGNhbGxlZC4nKVxyXG5cclxuICBjb25zdCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9yQXNzZXNzbWVudHMsIHF1ZXJ5LCBjb25maWcpO1xyXG4gIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgIHJldHVybiBmZWF0dXJlcy5tYXAoZmVhdHVyZSA9PiB7ICAgICAgICBcclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgb2JqZWN0SWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgICAgIGlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgICAgICBpbmRpY2F0b3JJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkluZGljYXRvcklELFxyXG4gICAgICAgICAgaW5kaWNhdG9yOiBmZWF0dXJlLmF0dHJpYnV0ZXMuSW5kaWNhdG9yTmFtZSxcclxuICAgICAgICAgIHRlbXBsYXRlOiBmZWF0dXJlLmF0dHJpYnV0ZXMuVGVtcGxhdGVOYW1lLFxyXG4gICAgICAgICAgbGlmZWxpbmU6IGZlYXR1cmUuYXR0cmlidXRlcy5MaWZlbGluZU5hbWUsXHJcbiAgICAgICAgICBjb21wb25lbnQ6IGZlYXR1cmUuYXR0cmlidXRlcy5Db21wb25lbnROYW1lLCAgICAgICAgICBcclxuICAgICAgICAgIGNvbW1lbnRzOiBwYXJzZUNvbW1lbnQoZmVhdHVyZS5hdHRyaWJ1dGVzLkNvbW1lbnRzKSwgICAgICAgICAgXHJcbiAgICAgICAgICBsaWZlbGluZVN0YXR1c0lkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZWxpbmVTdGF0dXNJRCxcclxuICAgICAgICAgIGVudmlyb25tZW50UHJlc2VydmF0aW9uOiBmZWF0dXJlLmF0dHJpYnV0ZXMuRW52aXJvbm1lbnRQcmVzZXJ2YXRpb24sXHJcbiAgICAgICAgICBpbmNpZGVudFN0YWJpbGl6YXRpb246IGZlYXR1cmUuYXR0cmlidXRlcy5JbmNpZGVudFN0YWJpbGl6YXRpb24sXHJcbiAgICAgICAgICByYW5rOiBmZWF0dXJlLmF0dHJpYnV0ZXMuUmFuayxcclxuICAgICAgICAgIGxpZmVTYWZldHk6IGZlYXR1cmUuYXR0cmlidXRlcy5MaWZlU2FmZXR5LFxyXG4gICAgICAgICAgcHJvcGVydHlQcm90ZWN0aW9uOiBmZWF0dXJlLmF0dHJpYnV0ZXMuUHJvcGVydHlQcm90ZWN0aW9uLFxyXG4gICAgICAgICAgc3RhdHVzOiBmZWF0dXJlLmF0dHJpYnV0ZXMuU3RhdHVzXHJcbiAgICAgICAgfSBhcyBJbmRpY2F0b3JBc3Nlc3NtZW50O1xyXG4gICAgIH0pXHJcbiAgfVxyXG5cclxufVxyXG5cclxuZnVuY3Rpb24gcGFyc2VDb21tZW50KGNvbW1lbnRzOiBzdHJpbmcpe1xyXG4gIGlmKCFjb21tZW50cyB8fCBjb21tZW50cyA9PT0gXCJcIil7XHJcbiAgICByZXR1cm4gW107XHJcbiAgfVxyXG4gIGxldCBwYXJzZWRDb21tZW50cyA9IEpTT04ucGFyc2UoY29tbWVudHMpIGFzIEluQ29tbWVudFtdO1xyXG4gIFxyXG4gIGlmKHBhcnNlZENvbW1lbnRzICYmIHBhcnNlZENvbW1lbnRzLmxlbmd0aCA+IDApe1xyXG4gICAgcGFyc2VkQ29tbWVudHMubWFwKChjb21tZW50RGF0YTogSW5Db21tZW50KSA9PiB7XHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgLi4uY29tbWVudERhdGEsXHJcbiAgICAgICAgICAgIGRhdGV0aW1lOiBOdW1iZXIoY29tbWVudERhdGEuZGF0ZXRpbWUpXHJcbiAgICAgICAgfSBhcyBJbkNvbW1lbnRcclxuICAgIH0pO1xyXG4gICAgcGFyc2VkQ29tbWVudHMgPSAocGFyc2VkQ29tbWVudHMgYXMgYW55KS5vcmRlckJ5KCdkYXRldGltZScsIHRydWUpO1xyXG4gIH1lbHNle1xyXG4gICAgcGFyc2VkQ29tbWVudHMgPSBbXTtcclxuICB9XHJcbiAgXHJcbiAgcmV0dXJuIHBhcnNlZENvbW1lbnRzO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRMaWZlbGluZVN0YXR1c0ZlYXR1cmVzKGNvbmZpZywgcXVlcnkpIHtcclxuICBjb25zb2xlLmxvZygnZ2V0IExpZmVsaW5lIFN0YXR1cyBjYWxsZWQnKVxyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuZnVuY3Rpb24gbG9hZEFzc2Vzc21lbnQoYXNzZXNzbWVudEZlYXR1cmU6IElGZWF0dXJlLCBsc0ZlYXR1cmVzOiBJRmVhdHVyZVtdLCBcclxuICBpbmRpY2F0b3JBc3Nlc3NtZW50czogSW5kaWNhdG9yQXNzZXNzbWVudFtdKTogQXNzZXNzbWVudHsgICBcclxuXHJcbiAgY29uc3QgbGlmZWxpbmVTdGF0dXNlcyA9IGxzRmVhdHVyZXMubWFwKChmZWF0dXJlKSA9PiB7IFxyXG4gICAgcmV0dXJuIHtcclxuICAgICAgb2JqZWN0SWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgaWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgYXNzZXNzbWVudElkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuQXNzZXNzbWVudElELFxyXG4gICAgICBsaWZlbGluZU5hbWU6IGZlYXR1cmUuYXR0cmlidXRlcy5MaWZlbGluZU5hbWUsXHJcbiAgICAgIGluZGljYXRvckFzc2Vzc21lbnRzOiBpbmRpY2F0b3JBc3Nlc3NtZW50cy5maWx0ZXIoaSA9PiBpLmxpZmVsaW5lU3RhdHVzSWQgPT09IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCksICAgICAgXHJcbiAgICAgIHNjb3JlOiBmZWF0dXJlLmF0dHJpYnV0ZXMuU2NvcmUsXHJcbiAgICAgIGNvbG9yOiBmZWF0dXJlLmF0dHJpYnV0ZXMuQ29sb3IsXHJcbiAgICAgIGlzT3ZlcnJpZGVuOiBmZWF0dXJlLmF0dHJpYnV0ZXMuSXNPdmVycmlkZW4sXHJcbiAgICAgIG92ZXJyaWRlU2NvcmU6ZmVhdHVyZS5hdHRyaWJ1dGVzLk92ZXJyaWRlblNjb3JlLFxyXG4gICAgICBvdmVycmlkZW5CeTogZmVhdHVyZS5hdHRyaWJ1dGVzLk92ZXJyaWRlbkJ5LFxyXG4gICAgICBvdmVycmlkZW5Db2xvcjogZmVhdHVyZS5hdHRyaWJ1dGVzLk92ZXJyaWRlbkNvbG9yLCAgICAgXHJcbiAgICAgIG92ZXJyaWRlQ29tbWVudDogZmVhdHVyZS5hdHRyaWJ1dGVzLk92ZXJyaWRlQ29tbWVudCAgICAgIFxyXG4gICAgfSBhcyBMaWZlbGluZVN0YXR1cztcclxuICB9KTtcclxuXHJcbiAgY29uc3QgYXNzZXNzbWVudCA9IHtcclxuICAgIG9iamVjdElkOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgaWQ6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICBuYW1lOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICBhc3Nlc3NtZW50VHlwZTogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5Bc3Nlc3NtZW50VHlwZSxcclxuICAgIGxpZmVsaW5lU3RhdHVzZXM6IGxpZmVsaW5lU3RhdHVzZXMsXHJcbiAgICBkZXNjcmlwdGlvbjogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5EZXNjcmlwdGlvbixcclxuICAgIHRlbXBsYXRlOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLlRlbXBsYXRlLFxyXG4gICAgb3JnYW5pemF0aW9uOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLk9yZ2FuaXphdGlvbixcclxuICAgIG9yZ2FuaXphdGlvblR5cGU6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuT3JnYW5pemF0aW9uVHlwZSxcclxuICAgIGluY2lkZW50OiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkluY2lkZW50LFxyXG4gICAgaGF6YXJkOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkhhemFyZCxcclxuICAgIGhhemFyZFR5cGU6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuSGF6YXJkVHlwZSxcclxuICAgIGNyZWF0b3I6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuQ3JlYXRvcixcclxuICAgIGNyZWF0ZWREYXRlOiBOdW1iZXIoYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5DcmVhdGVkRGF0ZSksXHJcbiAgICBlZGl0b3I6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuRWRpdG9yLFxyXG4gICAgZWRpdGVkRGF0ZTogTnVtYmVyKGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuRWRpdGVkRGF0ZSksXHJcbiAgICBpc1NlbGVjdGVkOiBmYWxzZSxcclxuICAgIGlzQ29tcGxldGVkOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLklzQ29tcGxldGVkLFxyXG4gIH0gYXMgQXNzZXNzbWVudFxyXG5cclxuICByZXR1cm4gYXNzZXNzbWVudDsgIFxyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBzYXZlTGlmZWxpbmVTdGF0dXMobGlmZWxpbmVTdGF0dXNGZWF0dXJlOiBJRmVhdHVyZSwgbHNJbmRBc3Nlc3NGZWF0dXJlczogSUZlYXR1cmVbXSwgY29uZmlnKTogUHJvbWlzZTxib29sZWFuPntcclxuICBsZXQgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZVN0YXR1cywgW2xpZmVsaW5lU3RhdHVzRmVhdHVyZV0sIGNvbmZpZylcclxuICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkoZSA9PiBlLnN1Y2Nlc3MpKXtcclxuICAgICBjb25zdCBnbG9iYWxJZCA9IHJlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWQ7XHJcblxyXG4gICAgIGNvbnN0IGluZGljYXRvckFzc2Vzc21lbnRGZWF0dXJlcyA9IGxzSW5kQXNzZXNzRmVhdHVyZXMubWFwKGluZCA9PiB7XHJcbiAgICAgICAgaW5kLmF0dHJpYnV0ZXMuTGlmZWxpbmVTdGF0dXNJRCA9IGdsb2JhbElkXHJcbiAgICAgICAgcmV0dXJuIGluZDtcclxuICAgICB9KVxyXG4gICAgIHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9yQXNzZXNzbWVudHMsIGluZGljYXRvckFzc2Vzc21lbnRGZWF0dXJlcywgY29uZmlnKTtcclxuICAgICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkoZSA9PiBlLnN1Y2Nlc3MpKXtcclxuICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgIH1cclxuICB9XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGdldFRlbXBsYXRlSW5kaWNhdG9ycyh0ZW1wbGF0ZTogQ0xTU1RlbXBsYXRlKTogSW5kaWNhdG9yVGVtcGxhdGVbXSB7XHJcbiAgcmV0dXJuIFtdLmNvbmNhdC5hcHBseShbXSwgKFtdLmNvbmNhdC5hcHBseShbXSwgXHJcbiAgIHRlbXBsYXRlLmxpZmVsaW5lVGVtcGxhdGVzLm1hcChsID0+IGwuY29tcG9uZW50VGVtcGxhdGVzKSkpXHJcbiAgIC5tYXAoKGM6IENvbXBvbmVudFRlbXBsYXRlKSA9PiBjLmluZGljYXRvcnMpKTtcclxufSIsIi8vQWRhcHRlZCBmcm9tIC8vaHR0cHM6Ly9naXRodWIuY29tL29kb2UvbWFwLXZ1ZS9ibG9iL21hc3Rlci9zcmMvZGF0YS9hdXRoLnRzXHJcblxyXG5pbXBvcnQgeyBsb2FkQXJjR0lTSlNBUElNb2R1bGVzIH0gZnJvbSBcImppbXUtYXJjZ2lzXCI7XHJcblxyXG4vKipcclxuICogQXR0ZW1wdCB0byBzaWduIGluLFxyXG4gKiBmaXJzdCBjaGVjayBjdXJyZW50IHN0YXR1c1xyXG4gKiBpZiBub3Qgc2lnbmVkIGluLCB0aGVuIGdvIHRocm91Z2hcclxuICogc3RlcHMgdG8gZ2V0IGNyZWRlbnRpYWxzXHJcbiAqL1xyXG5leHBvcnQgY29uc3Qgc2lnbkluID0gYXN5bmMgKGFwcElkOiBzdHJpbmcsIHBvcnRhbFVybDogc3RyaW5nKSA9PiB7XHJcbiAgICB0cnkge1xyXG4gICAgICAgIHJldHVybiBhd2FpdCBjaGVja0N1cnJlbnRTdGF0dXMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICB9IGNhdGNoIChlcnJvcikge1xyXG4gICAgICAgIGNvbnNvbGUubG9nKGVycm9yKTtcclxuICAgICAgICByZXR1cm4gYXdhaXQgZmV0Y2hDcmVkZW50aWFscyhhcHBJZCwgcG9ydGFsVXJsKTtcclxuICAgIH1cclxufTtcclxuXHJcbi8qKlxyXG4gKiBTaWduIHRoZSB1c2VyIG91dCwgYnV0IGlmIHdlIGNoZWNrZWQgY3JlZGVudGlhbHNcclxuICogbWFudWFsbHksIG1ha2Ugc3VyZSB0aGV5IGFyZSByZWdpc3RlcmVkIHdpdGhcclxuICogSWRlbnRpdHlNYW5hZ2VyLCBzbyBpdCBjYW4gZGVzdHJveSB0aGVtIHByb3Blcmx5XHJcbiAqL1xyXG5leHBvcnQgY29uc3Qgc2lnbk91dCA9IGFzeW5jIChhcHBJZDogc3RyaW5nLCBwb3J0YWxVcmw6IHN0cmluZykgPT4ge1xyXG4gICAgY29uc3QgSWRlbnRpdHlNYW5hZ2VyID0gYXdhaXQgbG9hZE1vZHVsZXMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICBhd2FpdCBzaWduSW4oYXBwSWQsIHBvcnRhbFVybCk7XHJcblxyXG4gICAgZGVsZXRlIHdpbmRvd1snSWRlbnRpdHlNYW5hZ2VyJ107XHJcbiAgICBkZWxldGUgd2luZG93WydPQXV0aEluZm8nXTtcclxuICAgIElkZW50aXR5TWFuYWdlci5kZXN0cm95Q3JlZGVudGlhbHMoKTtcclxuICAgIFxyXG59O1xyXG5cclxuLyoqXHJcbiAqIEdldCB0aGUgY3JlZGVudGlhbHMgZm9yIHRoZSBwcm92aWRlZCBwb3J0YWxcclxuICovXHJcbmFzeW5jIGZ1bmN0aW9uIGZldGNoQ3JlZGVudGlhbHMoYXBwSWQ6IHN0cmluZywgcG9ydGFsVXJsOiBzdHJpbmcpe1xyXG4gICAgY29uc3QgSWRlbnRpdHlNYW5hZ2VyID0gYXdhaXQgbG9hZE1vZHVsZXMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICBjb25zdCBjcmVkZW50aWFsID0gYXdhaXQgSWRlbnRpdHlNYW5hZ2VyLmdldENyZWRlbnRpYWwoYCR7cG9ydGFsVXJsfS9zaGFyaW5nYCwge1xyXG4gICAgICAgIGVycm9yOiBudWxsIGFzIGFueSxcclxuICAgICAgICBvQXV0aFBvcHVwQ29uZmlybWF0aW9uOiBmYWxzZSxcclxuICAgICAgICB0b2tlbjogbnVsbCBhcyBhbnlcclxuICAgIH0pO1xyXG4gICAgcmV0dXJuIGNyZWRlbnRpYWw7XHJcbn07XHJcblxyXG4vKipcclxuICogSW1wb3J0IElkZW50aXR5IE1hbmFnZXIsIGFuZCBPQXV0aEluZm9cclxuICovXHJcbmFzeW5jIGZ1bmN0aW9uIGxvYWRNb2R1bGVzKGFwcElkOiBzdHJpbmcsIHBvcnRhbFVybDogc3RyaW5nKSB7XHJcbiAgICBsZXQgSWRlbnRpdHlNYW5hZ2VyID0gd2luZG93WydJZGVudGl0eU1hbmFnZXInXVxyXG4gICAgaWYoIUlkZW50aXR5TWFuYWdlcil7XHJcbiAgICAgICAgY29uc3QgbW9kdWxlcyA9IGF3YWl0IGxvYWRBcmNHSVNKU0FQSU1vZHVsZXMoW1xyXG4gICAgICAgICAgICAnZXNyaS9pZGVudGl0eS9JZGVudGl0eU1hbmFnZXInLFxyXG4gICAgICAgICAgICAnZXNyaS9pZGVudGl0eS9PQXV0aEluZm8nXSk7XHJcblxyXG4gICAgICAgICAgICB3aW5kb3dbJ0lkZW50aXR5TWFuYWdlciddID0gbW9kdWxlc1swXTtcclxuICAgICAgICAgICAgd2luZG93WydPQXV0aEluZm8nXSA9IG1vZHVsZXNbMV07XHJcbiAgICAgICAgICAgIFxyXG4gICAgICAgIElkZW50aXR5TWFuYWdlciA9IG1vZHVsZXNbMF07XHJcbiAgICAgICAgY29uc3QgT0F1dGhJbmZvID0gbW9kdWxlc1sxXTtcclxuXHJcbiAgICAgICAgY29uc3Qgb2F1dGhJbmZvID0gbmV3IE9BdXRoSW5mbyh7XHJcbiAgICAgICAgICAgIGFwcElkLFxyXG4gICAgICAgICAgICBwb3J0YWxVcmwsXHJcbiAgICAgICAgICAgIHBvcHVwOiBmYWxzZVxyXG4gICAgICAgIH0pO1xyXG4gICAgICAgIElkZW50aXR5TWFuYWdlci5yZWdpc3Rlck9BdXRoSW5mb3MoW29hdXRoSW5mb10pOyAgICAgICAgXHJcbiAgICB9XHJcbiAgICByZXR1cm4gSWRlbnRpdHlNYW5hZ2VyO1xyXG59XHJcblxyXG4vKipcclxuICogQ2hlY2sgY3VycmVudCBsb2dnZWQgaW4gc3RhdHVzIGZvciBjdXJyZW50IHBvcnRhbFxyXG4gKi9cclxuZXhwb3J0IGNvbnN0IGNoZWNrQ3VycmVudFN0YXR1cyA9IGFzeW5jIChhcHBJZDogc3RyaW5nLCBwb3J0YWxVcmw6IHN0cmluZykgPT4ge1xyXG4gICAgY29uc3QgSWRlbnRpdHlNYW5hZ2VyID0gYXdhaXQgbG9hZE1vZHVsZXMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICByZXR1cm4gSWRlbnRpdHlNYW5hZ2VyLmNoZWNrU2lnbkluU3RhdHVzKGAke3BvcnRhbFVybH0vc2hhcmluZ2ApO1xyXG59OyIsImltcG9ydCB7IGV4dGVuc2lvblNwZWMsIEltbXV0YWJsZU9iamVjdCwgSU1TdGF0ZSB9IGZyb20gJ2ppbXUtY29yZSc7XHJcbmltcG9ydCB7IEFzc2Vzc21lbnQsIENMU1NfU3RhdGUsIFxyXG4gIENMU1NUZW1wbGF0ZSwgQ2xzc1VzZXIsIEhhemFyZCwgXHJcbiAgTGlmZWxpbmVTdGF0dXMsIE9yZ2FuaXphdGlvbiwgXHJcbiAgUmF0aW5nU2NhbGUsIFNjYWxlRmFjdG9yIH0gZnJvbSAnLi9kYXRhLWRlZmluaXRpb25zJztcclxuaW1wb3J0IHsgSUNvZGVkVmFsdWUgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC10eXBlcyc7XHJcbmltcG9ydCB7IElDcmVkZW50aWFsIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aCc7XHJcblxyXG5cclxuZXhwb3J0IGVudW0gQ0xTU0FjdGlvbktleXMge1xyXG4gIEFVVEhFTlRJQ0FURV9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGF1dGhlbmljYXRlIGNyZWRlbnRpYWxzJyxcclxuICBMT0FEX0hBWkFSRFNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBsb2FkIGhhemFyZHMnLFxyXG4gIExPQURfSEFaQVJEX1RZUEVTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCBoYXphcmQgdHlwZXMnLFxyXG4gIExPQURfT1JHQU5JWkFUSU9OU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGxvYWQgb3JnYW5pemF0aW9ucycsXHJcbiAgTE9BRF9PUkdBTklaQVRJT05fVFlQRVNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBsb2FkIG9yZ2FuaXphdGlvbiB0eXBlcycsXHJcbiAgTE9BRF9URU1QTEFURVNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBsb2FkIHRlbXBsYXRlcycsXHJcbiAgTE9BRF9QUklPUklUSUVTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCBwcmlvcml0aWVzJyxcclxuICBTRUxFQ1RfVEVNUExBVEVfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBzZWxlY3QgdGVtcGxhdGUnLFxyXG4gIFNFQVJDSF9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIHNlYXJjaCBmb3IgdGVtcGxhdGUnLFxyXG4gIFNJR05fSU5fQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTaWduIGluJyxcclxuICBTSUdOX09VVF9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIFNpZ24gb3V0JyxcclxuICBTRVRfVVNFUl9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIFNldCBDTFNTIFVzZXInLFxyXG4gIFNFVF9JREVOVElUWV9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIFNldCBJZGVudGl0eScsXHJcbiAgU0VUX0VSUk9SUyA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2V0IGdsb2JhbCBlcnJvcnMnLFxyXG4gIFRPR0dMRV9JTkRJQ0FUT1JfRURJVElORyA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gVG9nZ2xlIGluZGljYXRvciBlZGl0aW5nJywgIFxyXG4gIFNFTEVDVF9MSUZFTElORVNUQVRVU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIFNlbGVjdCBhIGxpZmVsaW5lIHN0YXR1cycsXHJcbiAgTE9BRF9BU1NFU1NNRU5UU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIExvYWQgYXNzZXNzbWVudHMnLFxyXG4gIFNFTEVDVF9BU1NFU1NNRU5UX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2VsZWN0IGFzc2Vzc21lbnQnLFxyXG4gIExPQURfUkFUSU5HU0NBTEVTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gTG9hZCByYXRpbmcgc2NhbGVzJyxcclxuICBMT0FEX1NDQUxFRkFDVE9SU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIExvYWQgY29uc3RhbnRzJ1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfU2NhbGVGYWN0b3JzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfU0NBTEVGQUNUT1JTX0FDVElPTixcclxuICB2YWw6IFNjYWxlRmFjdG9yW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX1JhdGluZ19TY2FsZXNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9SQVRJTkdTQ0FMRVNfQUNUSU9OLFxyXG4gIHZhbDogUmF0aW5nU2NhbGVbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNlbGVjdF9Bc3Nlc3NtZW50X0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFTEVDVF9BU1NFU1NNRU5UX0FDVElPTixcclxuICB2YWw6IEFzc2Vzc21lbnRcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX0Fzc2Vzc21lbnRzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfQVNTRVNTTUVOVFNfQUNUSU9OLFxyXG4gIHZhbDogQXNzZXNzbWVudFtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9Qcmlvcml0aWVzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfUFJJT1JJVElFU19BQ1RJT04sXHJcbiAgdmFsOiBhbnlbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfSGF6YXJkX1R5cGVzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfSEFaQVJEX1RZUEVTX0FDVElPTixcclxuICB2YWw6IElDb2RlZFZhbHVlW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX09yZ2FuaXphdGlvbl9UeXBlc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX09SR0FOSVpBVElPTl9UWVBFU19BQ1RJT04sXHJcbiAgdmFsOiBJQ29kZWRWYWx1ZVtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2VsZWN0X0xpZmVsaW5lU3RhdHVzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFTEVDVF9MSUZFTElORVNUQVRVU19BQ1RJT04sXHJcbiAgdmFsOiBMaWZlbGluZVN0YXR1c1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNldF9Ub2dnbGVfSW5kaWNhdG9yX0VkaXRpbmdfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuVE9HR0xFX0lORElDQVRPUl9FRElUSU5HLFxyXG4gIHZhbDogc3RyaW5nXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2V0X0Vycm9yc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLFxyXG4gIHZhbDogc3RyaW5nXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9IYXphcmRzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfSEFaQVJEU19BQ1RJT04sXHJcbiAgdmFsOiBIYXphcmRbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfT3JnYW5pemF0aW9uc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX09SR0FOSVpBVElPTlNfQUNUSU9OLFxyXG4gIHZhbDogT3JnYW5pemF0aW9uW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZXRJZGVudGl0eV9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRVRfSURFTlRJVFlfQUNUSU9OLFxyXG4gIHZhbDogQ2xzc1VzZXJcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZXRVc2VyX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFVF9VU0VSX0FDVElPTixcclxuICB2YWw6IENsc3NVc2VyXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2lnbmluX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNJR05fSU5fQUNUSU9OXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2lnbm91dF9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TSUdOX09VVF9BQ1RJT05cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZWxlY3RfVGVtcGxhdGVfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VMRUNUX1RFTVBMQVRFX0FDVElPTixcclxuICB2YWw6IHN0cmluZ1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfVGVtcGxhdGVzX0FjdGlvbl9UeXBlIHtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX1RFTVBMQVRFU19BQ1RJT04sXHJcbiAgdmFsOiBDTFNTVGVtcGxhdGVbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNlYXJjaF9UZW1wbGF0ZXNfQWN0aW9uX1R5cGUge1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFQVJDSF9BQ1RJT04sXHJcbiAgdmFsOiBzdHJpbmdcclxufSAgXHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIEF1dGhlbnRpY2F0ZV9BY3Rpb25fVHlwZSB7XHJcbiAgIHR5cGU6IENMU1NBY3Rpb25LZXlzLkFVVEhFTlRJQ0FURV9BQ1RJT04sXHJcbiAgIHZhbDogSUNyZWRlbnRpYWw7XHJcbn1cclxuXHJcblxyXG50eXBlIEFjdGlvblR5cGVzID0gXHJcbiBTZWxlY3RfVGVtcGxhdGVfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9UZW1wbGF0ZXNfQWN0aW9uX1R5cGUgfCBcclxuIFNlYXJjaF9UZW1wbGF0ZXNfQWN0aW9uX1R5cGUgfCBcclxuIFNpZ25pbl9BY3Rpb25fVHlwZSB8XHJcbiBTaWdub3V0X0FjdGlvbl9UeXBlIHxcclxuIFNldFVzZXJfQWN0aW9uX1R5cGUgfCBcclxuIFNldElkZW50aXR5X0FjdGlvbl9UeXBlIHxcclxuIExvYWRfSGF6YXJkc19BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX09yZ2FuaXphdGlvbnNfQWN0aW9uX1R5cGUgfFxyXG4gU2V0X0Vycm9yc19BY3Rpb25fVHlwZSB8XHJcbiBTZXRfVG9nZ2xlX0luZGljYXRvcl9FZGl0aW5nX0FjdGlvbl9UeXBlIHxcclxuIFNlbGVjdF9MaWZlbGluZVN0YXR1c19BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX0hhemFyZF9UeXBlc19BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX09yZ2FuaXphdGlvbl9UeXBlc19BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX1ByaW9yaXRpZXNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9Bc3Nlc3NtZW50c19BY3Rpb25fVHlwZSB8XHJcbiBTZWxlY3RfQXNzZXNzbWVudF9BY3Rpb25fVHlwZXwgXHJcbiBMb2FkX1JhdGluZ19TY2FsZXNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9TY2FsZUZhY3RvcnNfQWN0aW9uX1R5cGUgfFxyXG4gQXV0aGVudGljYXRlX0FjdGlvbl9UeXBlIDtcclxuXHJcbnR5cGUgSU1NeVN0YXRlID0gSW1tdXRhYmxlT2JqZWN0PENMU1NfU3RhdGU+O1xyXG5cclxuZGVjbGFyZSBtb2R1bGUgJ2ppbXUtY29yZS9saWIvdHlwZXMvc3RhdGUne1xyXG4gIGludGVyZmFjZSBTdGF0ZXtcclxuICAgIGNsc3NTdGF0ZT86IElNTXlTdGF0ZVxyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgTXlSZWR1eFN0b3JlRXh0ZW5zaW9uIGltcGxlbWVudHMgZXh0ZW5zaW9uU3BlYy5SZWR1eFN0b3JlRXh0ZW5zaW9uIHtcclxuICBpZCA9ICdjbHNzLXJlZHV4LXN0b3JlLWV4dGVuc2lvbic7XHJcbiBcclxuICBnZXRBY3Rpb25zKCkge1xyXG4gICAgcmV0dXJuIE9iamVjdC5rZXlzKENMU1NBY3Rpb25LZXlzKS5tYXAoayA9PiBDTFNTQWN0aW9uS2V5c1trXSk7XHJcbiAgfVxyXG5cclxuICBnZXRJbml0TG9jYWxTdGF0ZSgpIHtcclxuICAgIHJldHVybiB7XHJcbiAgICAgICBzZWxlY3RlZFRlbXBsYXRlOiBudWxsLFxyXG4gICAgICAgdGVtcGxhdGVzOiBbXSxcclxuICAgICAgIHNlYXJjaFJlc3VsdHM6IFtdLFxyXG4gICAgICAgdXNlcjogbnVsbCxcclxuICAgICAgIGF1dGg6IG51bGwsXHJcbiAgICAgICBpZGVudGl0eTogbnVsbCwgICAgICAgXHJcbiAgICAgICBuZXdUZW1wbGF0ZU1vZGFsVmlzaWJsZTogZmFsc2UsXHJcbiAgICAgICBoYXphcmRzOiBbXSxcclxuICAgICAgIG9yZ2FuaXphdGlvbnM6IFtdLFxyXG4gICAgICAgZXJyb3JzOiAnJyxcclxuICAgICAgIGlzSW5kaWNhdG9yRWRpdGluZzogZmFsc2UsXHJcbiAgICAgICBzZWxlY3RlZExpZmVsaW5lU3RhdHVzOiBudWxsLFxyXG4gICAgICAgb3JnYW5pemF0aW9uVHlwZXM6IFtdLFxyXG4gICAgICAgaGF6YXJkVHlwZXM6IFtdLFxyXG4gICAgICAgcHJpb3JpdGllczogW10sXHJcbiAgICAgICBhc3Nlc3NtZW50czogW10sXHJcbiAgICAgICByYXRpbmdTY2FsZXM6IFtdLFxyXG4gICAgICAgc2NhbGVGYWN0b3JzOiBbXSxcclxuICAgICAgIGF1dGhlbnRpY2F0ZTogbnVsbFxyXG4gICAgfSBhcyBDTFNTX1N0YXRlO1xyXG4gIH1cclxuXHJcbiAgZ2V0UmVkdWNlcigpIHtcclxuICAgIHJldHVybiAobG9jYWxTdGF0ZTogSU1NeVN0YXRlLCBhY3Rpb246IEFjdGlvblR5cGVzLCBhcHBTdGF0ZTogSU1TdGF0ZSk6IElNTXlTdGF0ZSA9PiB7ICAgICAgXHJcbiAgICAgIFxyXG4gICAgICBzd2l0Y2ggKGFjdGlvbi50eXBlKSB7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuQVVUSEVOVElDQVRFX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnYXV0aGVudGljYXRlJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9TQ0FMRUZBQ1RPUlNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdzY2FsZUZhY3RvcnMnLCBhY3Rpb24udmFsKTtcclxuICAgICAgICBcclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfUkFUSU5HU0NBTEVTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgncmF0aW5nU2NhbGVzJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VMRUNUX0FTU0VTU01FTlRfQUNUSU9OOlxyXG4gICAgICAgICAgY29uc3QgYXNzZXNzbWVudHMgPSBsb2NhbFN0YXRlLmFzc2Vzc21lbnRzLm1hcChhc3Nlc3MgPT4ge1xyXG4gICAgICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgICAuLi5hc3Nlc3MsXHJcbiAgICAgICAgICAgICAgaXNTZWxlY3RlZDogYXNzZXNzLmlkID09PSBhY3Rpb24udmFsLmlkLnRvTG93ZXJDYXNlKClcclxuICAgICAgICAgICAgIH1cclxuICAgICAgICAgIH0pXHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2Fzc2Vzc21lbnRzJywgYXNzZXNzbWVudHMpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfQVNTRVNTTUVOVFNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdhc3Nlc3NtZW50cycsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfUFJJT1JJVElFU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3ByaW9yaXRpZXMnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfTElGRUxJTkVTVEFUVVNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdzZWxlY3RlZExpZmVsaW5lU3RhdHVzJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuVE9HR0xFX0lORElDQVRPUl9FRElUSU5HOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdpc0luZGljYXRvckVkaXRpbmcnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdlcnJvcnMnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX0hBWkFSRFNfQUNUSU9OOiAgXHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2hhemFyZHMnLCBhY3Rpb24udmFsKVxyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfSEFaQVJEX1RZUEVTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnaGF6YXJkVHlwZXMnLCBhY3Rpb24udmFsKVxyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfT1JHQU5JWkFUSU9OX1RZUEVTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnb3JnYW5pemF0aW9uVHlwZXMnLCBhY3Rpb24udmFsKVxyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfT1JHQU5JWkFUSU9OU19BQ1RJT046XHJcbiAgICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnb3JnYW5pemF0aW9ucycsIGFjdGlvbi52YWwpXHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VUX0lERU5USVRZX0FDVElPTjogIFxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdpZGVudGl0eScsIGFjdGlvbi52YWwpO1xyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VUX1VTRVJfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCd1c2VyJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9URU1QTEFURVNfQUNUSU9OOiAgICAgICAgICBcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgndGVtcGxhdGVzJywgYWN0aW9uLnZhbCk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfVEVNUExBVEVfQUNUSU9OOlxyXG4gICAgICAgICAgbGV0IHRlbXBsYXRlcyA9IFsuLi5sb2NhbFN0YXRlLnRlbXBsYXRlc10ubWFwKHQgPT4ge1xyXG4gICAgICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgICAuLi50LFxyXG4gICAgICAgICAgICAgIGlzU2VsZWN0ZWQ6IHQuaWQgPT09IGFjdGlvbi52YWxcclxuICAgICAgICAgICAgIH0gXHJcbiAgICAgICAgICB9KVxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCd0ZW1wbGF0ZXMnLCB0ZW1wbGF0ZXMpICAgICAgICAgICAgXHJcbiAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlO1xyXG4gICAgICB9XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBnZXRTdG9yZUtleSgpIHtcclxuICAgIHJldHVybiAnY2xzc1N0YXRlJztcclxuICB9XHJcbn0iLCJleHBvcnQgY29uc3QgQ0xTU19BRE1JTiA9ICdDTFNTX0FkbWluJztcclxuZXhwb3J0IGNvbnN0IENMU1NfRURJVE9SID0gJ0NMU1NfRWRpdG9yJztcclxuZXhwb3J0IGNvbnN0IENMU1NfQVNTRVNTT1IgPSAnQ0xTU19Bc3Nlc3Nvcic7XHJcbmV4cG9ydCBjb25zdCBDTFNTX1ZJRVdFUiA9ICdDTFNTX1ZpZXdlcic7XHJcbmV4cG9ydCBjb25zdCBDTFNTX0ZPTExPV0VSUyA9ICdDTFNTIEZvbGxvd2Vycyc7XHJcblxyXG5leHBvcnQgY29uc3QgQkFTRUxJTkVfVEVNUExBVEVfTkFNRSA9ICdCYXNlbGluZSc7XHJcbmV4cG9ydCBjb25zdCBUT0tFTl9FUlJPUiA9ICdUb2tlbiBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgVEVNUExBVEVfVVJMX0VSUk9SID0gJ1RlbXBsYXRlIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IEFTU0VTU01FTlRfVVJMX0VSUk9SID0gJ0Fzc2Vzc21lbnQgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgT1JHQU5JWkFUSU9OX1VSTF9FUlJPUiA9ICdPcmdhbml6YXRpb24gRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgSEFaQVJEX1VSTF9FUlJPUiA9ICdIYXphcmQgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgSU5ESUNBVE9SX1VSTF9FUlJPUiA9ICdJbmRpY2F0b3IgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgQUxJR05NRU5UX1VSTF9FUlJPUiA9ICdBbGlnbm1lbnRzIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IExJRkVMSU5FX1VSTF9FUlJPUiA9ICdMaWZlbGluZSBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBDT01QT05FTlRfVVJMX0VSUk9SID0gJ0NvbXBvbmVudCBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBQUklPUklUWV9VUkxfRVJST1IgPSAnUHJpb3JpdHkgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgSU5DSURFTlRfVVJMX0VSUk9SID0gJ0luY2lkZW50IEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IFNBVklOR19TQU1FX0FTX0JBU0VMSU5FX0VSUk9SID0gJ0Jhc2VsaW5lIHRlbXBsYXRlIGNhbm5vdCBiZSB1cGRhdGVkLiBDaGFuZ2UgdGhlIHRlbXBsYXRlIG5hbWUgdG8gY3JlYXRlIGEgbmV3IG9uZS4nXHJcblxyXG5leHBvcnQgY29uc3QgU1RBQklMSVpJTkdfU0NBTEVfRkFDVE9SID0gJ1N0YWJpbGl6aW5nX1NjYWxlX0ZhY3Rvcic7XHJcbmV4cG9ydCBjb25zdCBERVNUQUJJTElaSU5HX1NDQUxFX0ZBQ1RPUiA9ICdEZXN0YWJpbGl6aW5nX1NjYWxlX0ZhY3Rvcic7XHJcbmV4cG9ydCBjb25zdCBVTkNIQU5HRURfU0NBTEVfRkFDVE9SID0gJ1VuY2hhbmdlZF9JbmRpY2F0b3JzJztcclxuZXhwb3J0IGNvbnN0IERFRkFVTFRfUFJJT1JJVFlfTEVWRUxTID0gXCJEZWZhdWx0X1ByaW9yaXR5X0xldmVsc1wiO1xyXG5leHBvcnQgY29uc3QgUkFOSyA9ICdJbXBvcnRhbmNlIG9mIEluZGljYXRvcic7XHJcbmV4cG9ydCBjb25zdCBMSUZFX1NBRkVUWSA9ICdMaWZlIFNhZmV0eSc7XHJcbmV4cG9ydCBjb25zdCBJTkNJREVOVF9TVEFCSUxJWkFUSU9OID0gJ0luY2lkZW50IFN0YWJpbGl6YXRpb24nO1xyXG5leHBvcnQgY29uc3QgUFJPUEVSVFlfUFJPVEVDVElPTiA9ICdQcm9wZXJ0eSBQcm90ZWN0aW9uJztcclxuZXhwb3J0IGNvbnN0IEVOVklST05NRU5UX1BSRVNFUlZBVElPTiA9ICdFbnZpcm9ubWVudCBQcmVzZXJ2YXRpb24nO1xyXG5cclxuZXhwb3J0IGNvbnN0IExJRkVfU0FGRVRZX1NDQUxFX0ZBQ1RPUiA9IDIwMDtcclxuZXhwb3J0IGNvbnN0IE9USEVSX1dFSUdIVFNfU0NBTEVfRkFDVE9SID0gMTAwO1xyXG5leHBvcnQgY29uc3QgTUFYSU1VTV9XRUlHSFQgPSA1O1xyXG5cclxuZXhwb3J0IGVudW0gVXBkYXRlQWN0aW9uIHtcclxuICAgIEhFQURFUiA9ICdoZWFkZXInLFxyXG4gICAgSU5ESUNBVE9SX05BTUUgPSAnSW5kaWNhdG9yIE5hbWUnLFxyXG4gICAgUFJJT1JJVElFUyA9ICdJbmRpY2F0b3IgUHJpb3JpdGllcycsXHJcbiAgICBORVdfSU5ESUNBVE9SID0gJ0NyZWF0ZSBOZXcgSW5kaWNhdG9yJyxcclxuICAgIERFTEVURV9JTkRJQ0FUT1IgPSAnRGVsZXRlIEluZGljYXRvcidcclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IElOQ0xVREVfSU5ESUNBVE9SID0gJ0ltcGFjdGVkIC0gWWVzIG9yIE5vJztcclxuZXhwb3J0IGNvbnN0IElOQ0xVREVfSU5ESUNBVE9SX0hFTFAgPSAnWWVzOiBUaGUgaW5kaWNhdG9yIHdpbGwgYmUgY29uc2lkZXJlZCBpbiB0aGUgYXNzZXNzbWVudC5cXG5ObzogVGhlIGluZGljYXRvciB3aWxsIG5vdCBiZSBjb25zaWRlcmVkLlxcblVua25vd246IE5vdCBzdXJlIHRvIGluY2x1ZGUgdGhlIGluZGljYXRvciBpbiBhc3Nlc3NtZW50Lic7XHJcblxyXG5leHBvcnQgY29uc3QgSU5ESUNBVE9SX1NUQVRVUyA9ICdJbmRpY2F0b3IgSW1wYWN0IFN0YXR1cyc7XHJcbmV4cG9ydCBjb25zdCBJTkRJQ0FUT1JfU1RBVFVTX0hFTFAgPSAnU3RhYmlsaXppbmc6IEhhcyB0aGUgaW5kaWNhdG9yIGJlZW4gaW1wcm92ZWQgb3IgaW1wcm92aW5nLlxcbkRlc3RhYmlsaXppbmc6IElzIHRoZSBpbmRpY2F0b3IgZGVncmFkaW5nLlxcblVuY2hhbmdlZDogTm8gc2lnbmlmaWNhbnQgaW1wcm92ZW1lbnQgc2luY2UgdGhlIGxhc3QgYXNzZXNzbWVudC4nO1xyXG5cclxuZXhwb3J0IGNvbnN0IENPTU1FTlQgPSAnQ29tbWVudCc7XHJcbmV4cG9ydCBjb25zdCBDT01NRU5UX0hFTFAgPSAnUHJvdmlkZSBqdXN0aWZpY2F0aW9uIGZvciB0aGUgc2VsZWN0ZWQgaW5kaWNhdG9yIHN0YXR1cy4nO1xyXG5cclxuZXhwb3J0IGNvbnN0IERFTEVURV9JTkRJQ0FUT1JfQ09ORklSTUFUSU9OID0gJ0FyZSB5b3Ugc3VyZSB5b3Ugd2FudCB0byBkZWxldGUgaW5kaWNhdG9yPyc7XHJcblxyXG4vL0NlbGwgV2VpZ2h0ID0gIFRyZW5kICogKCAoLTEqUmFuaykgKyA2XHJcbmV4cG9ydCBjb25zdCBDUklUSUNBTCA9IDI1O1xyXG5leHBvcnQgY29uc3QgQ1JJVElDQUxfTE9XRVJfQk9VTkRBUlkgPSAxMi41O1xyXG5leHBvcnQgY29uc3QgTU9ERVJBVEVfTE9XRVJfQk9VTkRBUlkgPSA1LjU7XHJcbmV4cG9ydCBjb25zdCBOT0RBVEFfQ09MT1IgPSAnIzkxOTM5NSc7XHJcbmV4cG9ydCBjb25zdCBOT0RBVEFfVkFMVUUgPSA5OTk5OTk7XHJcbmV4cG9ydCBjb25zdCBSRURfQ09MT1IgPSAnI0M1MjAzOCc7XHJcbmV4cG9ydCBjb25zdCBZRUxMT1dfQ09MT1IgPSAnI0ZCQkExNic7XHJcbmV4cG9ydCBjb25zdCBHUkVFTl9DT0xPUiA9ICcjNUU5QzQyJztcclxuZXhwb3J0IGNvbnN0IFNBVklOR19USU1FUiA9IDE1MDA7XHJcbmV4cG9ydCBjb25zdCBJTkRJQ0FUT1JfQ09NTUVOVF9MRU5HVEggPSAzMDA7XHJcblxyXG5leHBvcnQgY29uc3QgUE9SVEFMX1VSTCA9ICdodHRwczovL3d3dy5hcmNnaXMuY29tJztcclxuXHJcbmV4cG9ydCBjb25zdCBERUZBVUxUX0xJU1RJVEVNID0ge2lkOiAnMDAwJywgbmFtZTogJy1Ob25lLScsIHRpdGxlOiAnLU5vbmUtJ30gYXMgYW55O1xyXG5cclxuZXhwb3J0IGNvbnN0IFJBTktfTUVTU0FHRSA9ICdIb3cgaW1wb3J0YW50IGlzIHRoZSBpbmRpY2F0b3IgdG8geW91ciBqdXJpc2RpY3Rpb24gb3IgaGF6YXJkPyc7XHJcbmV4cG9ydCBjb25zdCBMSUZFX1NBRkVUWV9NRVNTQUdFID0gJ0hvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byBMaWZlIFNhZmV0eT8nO1xyXG5leHBvcnQgY29uc3QgUFJPUEVSVFlfUFJPVEVDVElPTl9NRVNTQUdFID0gJ0hvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byBQcm9wZXJ0eSBQcm90ZWN0aW9uPyc7XHJcbmV4cG9ydCBjb25zdCBFTlZJUk9OTUVOVF9QUkVTRVJWQVRJT05fTUVTU0FHRSA9ICdIb3cgaW1wb3J0YW50IGlzIHRoZSBpbmRpY2F0b3IgdG8gRW52aXJvbm1lbnQgUHJlc2VydmF0aW9uPyc7XHJcbmV4cG9ydCBjb25zdCBJTkNJREVOVF9TVEFCSUxJWkFUSU9OX01FU1NBR0UgPSAnSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIEluY2lkZW50IFN0YWJpbGl6YXRpb24/JztcclxuXHJcbmV4cG9ydCBjb25zdCBPVkVSV1JJVEVfU0NPUkVfTUVTU0FHRSA9ICdBIGNvbXBsZXRlZCBhc3Nlc3NtZW50IGNhbm5vdCBiZSBlZGl0ZWQuIEFyZSB5b3Ugc3VyZSB5b3Ugd2FudCB0byBjb21wbGV0ZSB0aGlzIGFzc2Vzc21lbnQ/JztcclxuXHJcbmV4cG9ydCBjb25zdCBVU0VSX0JPWF9FTEVNRU5UX0lEID0gJ3VzZXJCb3hFbGVtZW50JztcclxuXHJcbmV4cG9ydCBjb25zdCBEQVRBX0xJQlJBUllfVElUTEUgPSAnRGF0YSBMaWJyYXJ5JztcclxuZXhwb3J0IGNvbnN0IEFOQUxZU0lTX1JFUE9SVElOR19USVRMRSA9ICdBbmFseXNpcyAmIFJlcG9ydGluZyc7XHJcblxyXG4iLCJpbXBvcnQgeyBVc2VyU2Vzc2lvbiB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1hdXRoXCI7XHJcbmltcG9ydCB7IHF1ZXJ5RmVhdHVyZXMsIElRdWVyeUZlYXR1cmVzUmVzcG9uc2UsIFxyXG4gICAgSVJlbGF0ZWRSZWNvcmRHcm91cCwgcXVlcnlSZWxhdGVkLCB1cGRhdGVGZWF0dXJlcywgXHJcbiAgICBhZGRGZWF0dXJlcywgZGVsZXRlRmVhdHVyZXMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllclwiO1xyXG5pbXBvcnQgeyBJRmVhdHVyZVNldCwgSUZlYXR1cmUgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtdHlwZXNcIjtcclxuaW1wb3J0IHsgQXBwV2lkZ2V0Q29uZmlnIH0gZnJvbSBcIi4vZGF0YS1kZWZpbml0aW9uc1wiO1xyXG5pbXBvcnQgeyBsb2csIExvZ1R5cGUgfSBmcm9tIFwiLi9sb2dnZXJcIjtcclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKSB7XHJcbiAgcmV0dXJuIFVzZXJTZXNzaW9uLmZyb21DcmVkZW50aWFsKGNvbmZpZy5jcmVkZW50aWFsKTtcclxufVxyXG4gIFxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcXVlcnlUYWJsZUZlYXR1cmVTZXQodXJsOiBzdHJpbmcsIHdoZXJlOiBzdHJpbmcsIFxyXG4gIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVNldD4ge1xyXG4gIFxyXG4gICAgdHJ5e1xyXG5cclxuICAgICAgY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG4gICAgICByZXR1cm4gcXVlcnlGZWF0dXJlcyh7IHVybCwgd2hlcmUsIGF1dGhlbnRpY2F0aW9uLCBoaWRlVG9rZW46IHRydWUgfSlcclxuICAgICAgLnRoZW4oKHJlc3BvbnNlOiBJUXVlcnlGZWF0dXJlc1Jlc3BvbnNlKSA9PiB7XHJcbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlXHJcbiAgICAgIH0pXHJcblxyXG4gICAgfWNhdGNoKGUpe1xyXG4gICAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ3F1ZXJ5VGFibGVGZWF0dXJlU2V0JylcclxuICAgIH0gICAgXHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBxdWVyeVRhYmxlRmVhdHVyZXModXJsOiBzdHJpbmcsIHdoZXJlOiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVtdPiB7XHJcblxyXG4gY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG5cclxuICB0cnl7XHJcbiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgcXVlcnlGZWF0dXJlcyh7IHVybCwgd2hlcmUsIGF1dGhlbnRpY2F0aW9uLCAgaHR0cE1ldGhvZDonUE9TVCcsIGhpZGVUb2tlbjogdHJ1ZSB9KVxyXG4gICAgICByZXR1cm4gKHJlc3BvbnNlIGFzIElRdWVyeUZlYXR1cmVzUmVzcG9uc2UpLmZlYXR1cmVzO1xyXG4gIH1jYXRjaChlKXtcclxuICAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdxdWVyeVRhYmxlRmVhdHVyZXMnKVxyXG4gICAgICBsb2codXJsLCBMb2dUeXBlLldSTiwgd2hlcmUpO1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0ICBhc3luYyBmdW5jdGlvbiBxdWVyeVJlbGF0ZWRUYWJsZUZlYXR1cmVzKG9iamVjdElkczogbnVtYmVyW10sXHJcbnVybDogc3RyaW5nLCByZWxhdGlvbnNoaXBJZDogbnVtYmVyLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SVJlbGF0ZWRSZWNvcmRHcm91cFtdPiB7XHJcblxyXG5jb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7XHJcblxyXG5jb25zdCByZXNwb25zZSA9IGF3YWl0IHF1ZXJ5UmVsYXRlZCh7XHJcbiAgICBvYmplY3RJZHMsXHJcbiAgICB1cmwsIHJlbGF0aW9uc2hpcElkLFxyXG4gICAgYXV0aGVudGljYXRpb24sXHJcbiAgICBoaWRlVG9rZW46IHRydWVcclxufSk7XHJcbnJldHVybiByZXNwb25zZS5yZWxhdGVkUmVjb3JkR3JvdXBzO1xyXG59XHJcblxyXG5leHBvcnQgIGFzeW5jIGZ1bmN0aW9uIHVwZGF0ZVRhYmxlRmVhdHVyZSh1cmw6IHN0cmluZywgYXR0cmlidXRlczogYW55LCBjb25maWc6IEFwcFdpZGdldENvbmZpZykge1xyXG4gIGNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTtcclxuXHJcbiAgcmV0dXJuIHVwZGF0ZUZlYXR1cmVzKHtcclxuICAgICAgdXJsLFxyXG4gICAgICBhdXRoZW50aWNhdGlvbixcclxuICAgICAgZmVhdHVyZXM6IFt7XHJcbiAgICAgIGF0dHJpYnV0ZXNcclxuICAgICAgfV0sXHJcbiAgICAgIHJvbGxiYWNrT25GYWlsdXJlOiB0cnVlXHJcbiAgfSlcclxufVxyXG5cclxuZXhwb3J0ICBhc3luYyBmdW5jdGlvbiB1cGRhdGVUYWJsZUZlYXR1cmVzKHVybDogc3RyaW5nLCBmZWF0dXJlczogSUZlYXR1cmVbXSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpIHtcclxuICBjb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7ICBcclxuICByZXR1cm4gdXBkYXRlRmVhdHVyZXMoe1xyXG4gICAgICB1cmwsXHJcbiAgICAgIGF1dGhlbnRpY2F0aW9uLFxyXG4gICAgICBmZWF0dXJlc1xyXG4gIH0pXHJcbn1cclxuXHJcbmV4cG9ydCAgYXN5bmMgZnVuY3Rpb24gYWRkVGFibGVGZWF0dXJlcyh1cmw6IHN0cmluZywgZmVhdHVyZXM6IGFueVtdLCBjb25maWc6IEFwcFdpZGdldENvbmZpZykge1xyXG5cclxuICBjb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7XHJcblxyXG4gIHRyeXtcclxuICAgIHJldHVybiBhZGRGZWF0dXJlcyh7IHVybCwgZmVhdHVyZXMsIGF1dGhlbnRpY2F0aW9uLCByb2xsYmFja09uRmFpbHVyZTogdHJ1ZSB9KTtcclxuICB9Y2F0Y2goZSl7XHJcbiAgICBjb25zb2xlLmxvZyhlKTtcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlVGFibGVGZWF0dXJlcyh1cmw6IHN0cmluZywgb2JqZWN0SWRzOiBudW1iZXJbXSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpIHtcclxuXHJcbiAgICBjb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7XHJcbiAgICByZXR1cm4gZGVsZXRlRmVhdHVyZXMoeyB1cmwsIG9iamVjdElkcywgYXV0aGVudGljYXRpb24sIHJvbGxiYWNrT25GYWlsdXJlOiB0cnVlIH0pO1xyXG59IiwiZXhwb3J0IGVudW0gTG9nVHlwZSB7XHJcbiAgICBJTkZPID0gJ0luZm9ybWF0aW9uJyxcclxuICAgIFdSTiA9ICdXYXJuaW5nJyxcclxuICAgIEVSUk9SID0gJ0Vycm9yJ1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gbG9nKG1lc3NhZ2U6IHN0cmluZywgdHlwZT86IExvZ1R5cGUsIGZ1bmM/OiBzdHJpbmcpe1xyXG4gICAgaWYoIXR5cGUpe1xyXG4gICAgICAgIHR5cGUgPSBMb2dUeXBlLklORk9cclxuICAgIH1cclxuXHJcbiAgICBpZihmdW5jKXtcclxuICAgICAgICBmdW5jID0gYCgke2Z1bmN9KWA7XHJcbiAgICB9XHJcblxyXG4gICAgbWVzc2FnZSA9IGBbJHtuZXcgRGF0ZSgpLnRvTG9jYWxlU3RyaW5nKCl9XTogJHttZXNzYWdlfSAke2Z1bmN9YDtcclxuXHJcbiAgICBzd2l0Y2godHlwZSl7XHJcbiAgICAgICAgY2FzZSBMb2dUeXBlLklORk86XHJcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKG1lc3NhZ2UpO1xyXG4gICAgICAgICAgICBicmVhaztcclxuICAgICAgICBjYXNlIExvZ1R5cGUuV1JOOlxyXG4gICAgICAgICAgICBjb25zb2xlLndhcm4obWVzc2FnZSk7XHJcbiAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIGNhc2UgTG9nVHlwZS5FUlJPUjpcclxuICAgICAgICAgICAgY29uc29sZS5lcnJvcihtZXNzYWdlKTtcclxuICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgICAgY29uc29sZS5sb2cobWVzc2FnZSk7XHJcbiAgICB9XHJcbn0iLCJcclxuZXhwb3J0IGNvbnN0IHNvcnRPYmplY3QgPSA8VD4ob2JqOiBUW10sIHByb3A6IHN0cmluZywgcmV2ZXJzZT86Ym9vbGVhbik6IFRbXSA9PiB7XHJcbiAgIHJldHVybiBvYmouc29ydCgoYTpULCBiOlQpID0+IHtcclxuICAgICAgaWYoYVtwcm9wXSA+IGJbcHJvcF0pe1xyXG4gICAgICAgIHJldHVybiByZXZlcnNlID8gLTEgOiAxXHJcbiAgICAgIH1cclxuICAgICAgaWYoYVtwcm9wXSA8IGJbcHJvcF0pe1xyXG4gICAgICAgIHJldHVybiByZXZlcnNlID8gMSA6IC0xXHJcbiAgICAgIH1cclxuICAgICAgcmV0dXJuIDA7XHJcbiAgfSk7XHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBjcmVhdGVHdWlkID0gKCkgPT57XHJcbiAgcmV0dXJuICd4eHh4eHh4eC14eHh4LTR4eHgteXh4eC14eHh4eHh4eHh4eHgnLnJlcGxhY2UoL1t4eV0vZywgZnVuY3Rpb24oYykge1xyXG4gICAgdmFyIHIgPSBNYXRoLnJhbmRvbSgpICogMTYgfCAwLCB2ID0gYyA9PSAneCcgPyByIDogKHIgJiAweDMgfCAweDgpO1xyXG4gICAgcmV0dXJuIHYudG9TdHJpbmcoMTYpO1xyXG4gIH0pO1xyXG59XHJcblxyXG5leHBvcnQgY29uc3QgcGFyc2VEYXRlID0gKG1pbGxpc2Vjb25kczogbnVtYmVyKTogc3RyaW5nID0+IHtcclxuICBpZighbWlsbGlzZWNvbmRzKXtcclxuICAgIHJldHVyblxyXG4gIH1cclxuICAgcmV0dXJuIG5ldyBEYXRlKG1pbGxpc2Vjb25kcykudG9Mb2NhbGVTdHJpbmcoKTtcclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IHNhdmVEYXRlID0gKGRhdGU6IHN0cmluZyk6IG51bWJlciA9PiB7XHJcbiAgIHJldHVybiBuZXcgRGF0ZShkYXRlKS5nZXRNaWxsaXNlY29uZHMoKTtcclxufVxyXG5cclxuXHJcbi8vUmVmZXJlbmNlOiBodHRwczovL3N0YWNrb3ZlcmZsb3cuY29tL3F1ZXN0aW9ucy82MTk1MzM1L2xpbmVhci1yZWdyZXNzaW9uLWluLWphdmFzY3JpcHRcclxuLy8gZXhwb3J0IGNvbnN0IGxpbmVhclJlZ3Jlc3Npb24gPSAoeVZhbHVlczogbnVtYmVyW10sIHhWYWx1ZXM6IG51bWJlcltdKSA9PntcclxuLy8gICBkZWJ1Z2dlcjtcclxuLy8gICBjb25zdCB5ID0geVZhbHVlcztcclxuLy8gICBjb25zdCB4ID0geFZhbHVlcztcclxuXHJcbi8vICAgdmFyIGxyID0ge3Nsb3BlOiBOYU4sIGludGVyY2VwdDogTmFOLCByMjogTmFOfTtcclxuLy8gICB2YXIgbiA9IHkubGVuZ3RoO1xyXG4vLyAgIHZhciBzdW1feCA9IDA7XHJcbi8vICAgdmFyIHN1bV95ID0gMDtcclxuLy8gICB2YXIgc3VtX3h5ID0gMDtcclxuLy8gICB2YXIgc3VtX3h4ID0gMDtcclxuLy8gICB2YXIgc3VtX3l5ID0gMDtcclxuXHJcbi8vICAgZm9yICh2YXIgaSA9IDA7IGkgPCB5Lmxlbmd0aDsgaSsrKSB7XHJcblxyXG4vLyAgICAgICBzdW1feCArPSB4W2ldO1xyXG4vLyAgICAgICBzdW1feSArPSB5W2ldO1xyXG4vLyAgICAgICBzdW1feHkgKz0gKHhbaV0qeVtpXSk7XHJcbi8vICAgICAgIHN1bV94eCArPSAoeFtpXSp4W2ldKTtcclxuLy8gICAgICAgc3VtX3l5ICs9ICh5W2ldKnlbaV0pO1xyXG4vLyAgIH0gXHJcblxyXG4vLyAgIGxyLnNsb3BlID0gKG4gKiBzdW1feHkgLSBzdW1feCAqIHN1bV95KSAvIChuKnN1bV94eCAtIHN1bV94ICogc3VtX3gpO1xyXG4vLyAgIGxyLmludGVyY2VwdCA9IChzdW1feSAtIGxyLnNsb3BlICogc3VtX3gpL247XHJcbi8vICAgbHIucjIgPSBNYXRoLnBvdygobipzdW1feHkgLSBzdW1feCpzdW1feSkvTWF0aC5zcXJ0KChuKnN1bV94eC1zdW1feCpzdW1feCkqKG4qc3VtX3l5LXN1bV95KnN1bV95KSksMik7XHJcbi8vICAgcmV0dXJuIGxyO1xyXG4vLyB9XHJcblxyXG5TdHJpbmcucHJvdG90eXBlLnRvVGl0bGVDYXNlID0gZnVuY3Rpb24gKCkge1xyXG4gIHJldHVybiB0aGlzLnJlcGxhY2UoL1xcd1xcUyovZywgZnVuY3Rpb24odHh0KXtyZXR1cm4gdHh0LmNoYXJBdCgwKS50b1VwcGVyQ2FzZSgpICsgdHh0LnN1YnN0cigxKS50b0xvd2VyQ2FzZSgpO30pO1xyXG59O1xyXG5cclxuQXJyYXkucHJvdG90eXBlLm9yZGVyQnkgPSBmdW5jdGlvbjxUPihwcm9wLCByZXZlcnNlKSB7XHJcbiAgcmV0dXJuIHRoaXMuc29ydCgoYTpULCBiOlQpID0+IHtcclxuICAgIGlmKGFbcHJvcF0gPiBiW3Byb3BdKXtcclxuICAgICAgcmV0dXJuIHJldmVyc2UgPyAtMSA6IDFcclxuICAgIH1cclxuICAgIGlmKGFbcHJvcF0gPCBiW3Byb3BdKXtcclxuICAgICAgcmV0dXJuIHJldmVyc2UgPyAxIDogLTFcclxuICAgIH1cclxuICAgIHJldHVybiAwO1xyXG4gIH0pO1xyXG59XHJcblxyXG5BcnJheS5wcm90b3R5cGUuZ3JvdXBCeSA9IGZ1bmN0aW9uKGtleSkge1xyXG4gIHJldHVybiB0aGlzLnJlZHVjZShmdW5jdGlvbihydiwgeCkge1xyXG4gICAgKHJ2W3hba2V5XV0gPSBydlt4W2tleV1dIHx8IFtdKS5wdXNoKHgpO1xyXG4gICAgcmV0dXJuIHJ2O1xyXG4gIH0sIHt9KTtcclxufTtcclxuIiwibW9kdWxlLmV4cG9ydHMgPSBfX1dFQlBBQ0tfRVhURVJOQUxfTU9EVUxFX2ppbXVfYXJjZ2lzX187IiwibW9kdWxlLmV4cG9ydHMgPSBfX1dFQlBBQ0tfRVhURVJOQUxfTU9EVUxFX2ppbXVfY29yZV9fOyIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9yZWFjdF9fOyIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X3VpX187IiwiLy8gVGhlIG1vZHVsZSBjYWNoZVxudmFyIF9fd2VicGFja19tb2R1bGVfY2FjaGVfXyA9IHt9O1xuXG4vLyBUaGUgcmVxdWlyZSBmdW5jdGlvblxuZnVuY3Rpb24gX193ZWJwYWNrX3JlcXVpcmVfXyhtb2R1bGVJZCkge1xuXHQvLyBDaGVjayBpZiBtb2R1bGUgaXMgaW4gY2FjaGVcblx0dmFyIGNhY2hlZE1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF07XG5cdGlmIChjYWNoZWRNb2R1bGUgIT09IHVuZGVmaW5lZCkge1xuXHRcdHJldHVybiBjYWNoZWRNb2R1bGUuZXhwb3J0cztcblx0fVxuXHQvLyBDcmVhdGUgYSBuZXcgbW9kdWxlIChhbmQgcHV0IGl0IGludG8gdGhlIGNhY2hlKVxuXHR2YXIgbW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXSA9IHtcblx0XHQvLyBubyBtb2R1bGUuaWQgbmVlZGVkXG5cdFx0Ly8gbm8gbW9kdWxlLmxvYWRlZCBuZWVkZWRcblx0XHRleHBvcnRzOiB7fVxuXHR9O1xuXG5cdC8vIEV4ZWN1dGUgdGhlIG1vZHVsZSBmdW5jdGlvblxuXHRfX3dlYnBhY2tfbW9kdWxlc19fW21vZHVsZUlkXShtb2R1bGUsIG1vZHVsZS5leHBvcnRzLCBfX3dlYnBhY2tfcmVxdWlyZV9fKTtcblxuXHQvLyBSZXR1cm4gdGhlIGV4cG9ydHMgb2YgdGhlIG1vZHVsZVxuXHRyZXR1cm4gbW9kdWxlLmV4cG9ydHM7XG59XG5cbiIsIi8vIGRlZmluZSBnZXR0ZXIgZnVuY3Rpb25zIGZvciBoYXJtb255IGV4cG9ydHNcbl9fd2VicGFja19yZXF1aXJlX18uZCA9IChleHBvcnRzLCBkZWZpbml0aW9uKSA9PiB7XG5cdGZvcih2YXIga2V5IGluIGRlZmluaXRpb24pIHtcblx0XHRpZihfX3dlYnBhY2tfcmVxdWlyZV9fLm8oZGVmaW5pdGlvbiwga2V5KSAmJiAhX193ZWJwYWNrX3JlcXVpcmVfXy5vKGV4cG9ydHMsIGtleSkpIHtcblx0XHRcdE9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBrZXksIHsgZW51bWVyYWJsZTogdHJ1ZSwgZ2V0OiBkZWZpbml0aW9uW2tleV0gfSk7XG5cdFx0fVxuXHR9XG59OyIsIl9fd2VicGFja19yZXF1aXJlX18ubyA9IChvYmosIHByb3ApID0+IChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwob2JqLCBwcm9wKSkiLCIvLyBkZWZpbmUgX19lc01vZHVsZSBvbiBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLnIgPSAoZXhwb3J0cykgPT4ge1xuXHRpZih0eXBlb2YgU3ltYm9sICE9PSAndW5kZWZpbmVkJyAmJiBTeW1ib2wudG9TdHJpbmdUYWcpIHtcblx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgU3ltYm9sLnRvU3RyaW5nVGFnLCB7IHZhbHVlOiAnTW9kdWxlJyB9KTtcblx0fVxuXHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgJ19fZXNNb2R1bGUnLCB7IHZhbHVlOiB0cnVlIH0pO1xufTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLnAgPSBcIlwiOyIsIi8qKlxyXG4gKiBXZWJwYWNrIHdpbGwgcmVwbGFjZSBfX3dlYnBhY2tfcHVibGljX3BhdGhfXyB3aXRoIF9fd2VicGFja19yZXF1aXJlX18ucCB0byBzZXQgdGhlIHB1YmxpYyBwYXRoIGR5bmFtaWNhbGx5LlxyXG4gKiBUaGUgcmVhc29uIHdoeSB3ZSBjYW4ndCBzZXQgdGhlIHB1YmxpY1BhdGggaW4gd2VicGFjayBjb25maWcgaXM6IHdlIGNoYW5nZSB0aGUgcHVibGljUGF0aCB3aGVuIGRvd25sb2FkLlxyXG4gKiAqL1xyXG4vLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmVcclxuLy8gQHRzLWlnbm9yZVxyXG5fX3dlYnBhY2tfcHVibGljX3BhdGhfXyA9IHdpbmRvdy5qaW11Q29uZmlnLmJhc2VVcmxcclxuIiwiaW1wb3J0IHsgUmVhY3QsIEFsbFdpZGdldFByb3BzLCBSZWFjdFJlZHV4IH0gZnJvbSAnamltdS1jb3JlJ1xyXG5pbXBvcnQgeyBJTUNvbmZpZyB9IGZyb20gJy4uL2NvbmZpZydcclxuaW1wb3J0IHsgTGFiZWwgfSBmcm9tICdqaW11LXVpJztcclxuaW1wb3J0IHsgQXNzZXNzbWVudCwgTGlmZWxpbmVTdGF0dXMgfSBmcm9tICcuLi8uLi8uLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2RhdGEtZGVmaW5pdGlvbnMnO1xyXG5pbXBvcnQgeyBDTFNTQWN0aW9uS2V5cyB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY2xzcy1zdG9yZSc7XHJcbmltcG9ydCB7IGRpc3BhdGNoQWN0aW9uIH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9hcGknO1xyXG5jb25zdCB7IHVzZVNlbGVjdG9yIH0gPSBSZWFjdFJlZHV4O1xyXG5cclxuLy8gZnVuY3Rpb24gdXNlV2luZG93U2l6ZSgpIHtcclxuLy8gICBjb25zdCBbc2l6ZSwgc2V0U2l6ZV0gPSBSZWFjdC51c2VTdGF0ZShbMCwgMF0pO1xyXG4vLyAgIFJlYWN0LnVzZUxheW91dEVmZmVjdCgoKSA9PiB7XHJcbi8vICAgICBmdW5jdGlvbiB1cGRhdGVTaXplKCkge1xyXG4vLyAgICAgICBzZXRTaXplKFt3aW5kb3cuaW5uZXJXaWR0aCwgd2luZG93LmlubmVySGVpZ2h0XSk7XHJcbi8vICAgICB9XHJcbi8vICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigncmVzaXplJywgdXBkYXRlU2l6ZSk7XHJcbi8vICAgICB1cGRhdGVTaXplKCk7XHJcbi8vICAgICByZXR1cm4gKCkgPT4gd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ3Jlc2l6ZScsIHVwZGF0ZVNpemUpO1xyXG4vLyAgIH0sIFtdKTtcclxuLy8gICByZXR1cm4gc2l6ZTtcclxuLy8gfVxyXG5cclxuY29uc3QgV2lkZ2V0ID0gKHByb3BzOiBBbGxXaWRnZXRQcm9wczxJTUNvbmZpZz4pID0+IHtcclxuICAvLyBjb25zdCBbd2lkdGgsIGhlaWdodF0gPSB1c2VXaW5kb3dTaXplKCk7XHJcbiAgY29uc3QgW2xpZmVsaW5lU3RhdHVzZXMsIHNldExpZmVsaW5lU3RhdHVzZXNdID0gUmVhY3QudXNlU3RhdGU8TGlmZWxpbmVTdGF0dXNbXT4oW10pO1xyXG4gIGNvbnN0IFtzZWxlY3RlZExpZmVsaW5lU3RhdHVzLCBzZXRTZWxlY3RlZExpZmVsaW5lU3RhdHVzXSA9IFJlYWN0LnVzZVN0YXRlPExpZmVsaW5lU3RhdHVzPihudWxsKVxyXG5cclxuICBjb25zdCBzZWxlY3RlZEFzc2Vzc21lbnQgPSB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSk9PiB7XHJcbiAgICBpZihzdGF0ZS5jbHNzU3RhdGU/LmFzc2Vzc21lbnRzICYmIHN0YXRlLmNsc3NTdGF0ZT8uYXNzZXNzbWVudHMubGVuZ3RoID4gMCl7ICAgICBcclxuICAgICAgcmV0dXJuIChzdGF0ZS5jbHNzU3RhdGU/LmFzc2Vzc21lbnRzIGFzIEFzc2Vzc21lbnRbXSk/LmZpbmQoYSA9PiBhLmlzU2VsZWN0ZWQpXHJcbiAgICB9XHJcbiAgfSlcclxuXHJcbiAgUmVhY3QudXNlRWZmZWN0KCgpPT57XHJcbiAgICBpZihzZWxlY3RlZEFzc2Vzc21lbnQpeyAgICAgXHJcbiAgICAgIHNldExpZmVsaW5lU3RhdHVzZXMoKHNlbGVjdGVkQXNzZXNzbWVudD8ubGlmZWxpbmVTdGF0dXNlcyBhcyBhbnkpLm9yZGVyQnkoJ2xpZmVsaW5lTmFtZScpKTtcclxuICAgIH1cclxuICB9LCBbc2VsZWN0ZWRBc3Nlc3NtZW50XSlcclxuXHJcbiAgUmVhY3QudXNlRWZmZWN0KCgpPT57XHJcbiAgICBpZihsaWZlbGluZVN0YXR1c2VzKXtcclxuICAgICAgc2VsZWN0TGlmZWxpbmVTdGF0dXMobGlmZWxpbmVTdGF0dXNlc1swXSk7XHJcbiAgICB9XHJcbiAgfSwgW2xpZmVsaW5lU3RhdHVzZXNdKVxyXG5cclxuICBjb25zdCBzZWxlY3RMaWZlbGluZVN0YXR1cyA9IChsaWZlbGluZVN0YXR1czogTGlmZWxpbmVTdGF0dXMpID0+e1xyXG4gICAgc2V0U2VsZWN0ZWRMaWZlbGluZVN0YXR1cyhsaWZlbGluZVN0YXR1cyk7XHJcbiAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfTElGRUxJTkVTVEFUVVNfQUNUSU9OLCBsaWZlbGluZVN0YXR1cyk7XHJcbiAgfVxyXG5cclxuICBpZighbGlmZWxpbmVTdGF0dXNlcyB8fCBsaWZlbGluZVN0YXR1c2VzLmxlbmd0aCA9PSAwKXsgICBcclxuICAgIHJldHVybiA8aDUgc3R5bGU9e3twb3NpdGlvbjogJ2Fic29sdXRlJywgbGVmdDogJzQwJScsIHRvcDogJzUwJSd9fT5ObyBEYXRhPC9oNT5cclxuICB9XHJcbiAgcmV0dXJuIChcclxuICAgIDxkaXYgY2xhc3NOYW1lPVwid2lkZ2V0LXNlbGVjdC1saWZlbGluZXMgamltdS13aWRnZXRcIj5cclxuICAgICAgPHN0eWxlPlxyXG4gICAgICAgIHtcclxuICAgICAgICAgICBgXHJcbiAgICAgICAgICAgIC53aWRnZXQtc2VsZWN0LWxpZmVsaW5lc3tcclxuICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgICBoZWlnaHQ6IDEwMCU7XHJcbiAgICAgICAgICAgICAgcGFkZGluZzogMTBweDtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAuc2VsZWN0LWxpZmVsaW5lLWNvbnRhaW5lcntcclxuICAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgIGhlaWdodDogMTAwJTtcclxuICAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjtcclxuICAgICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjtcclxuICAgICAgICAgICAgICAgYm9yZGVyLXJhZGl1czogMTBweDtcclxuICAgICAgICAgICAgICAgb3ZlcmZsb3cteTogYXV0bztcclxuICAgICAgICAgICAgICAgb3ZlcmZsb3cteDogaGlkZGVuO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIC5saWZlbGluZXMtaGVhZGVye1xyXG4gICAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7XHJcbiAgICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjtcclxuICAgICAgICAgICAgICBwYWRkaW5nOiAxMHB4IDA7XHJcbiAgICAgICAgICAgICAgZm9udC1zaXplOiAxLjJyZW07XHJcbiAgICAgICAgICAgICAgZm9udC13ZWlnaHQ6IGJvbGQ7ICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICBib3JkZXItcmFkaXVzOiAxMHB4IDEwcHggMCAwO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIC5saWZlbGluZXtcclxuICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgICBjdXJzb3I6IHBvaW50ZXI7ICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgdGV4dC1hbGlnbjogY2VudGVyO1xyXG4gICAgICAgICAgICAgIGZvbnQtc2l6ZTogMi41ZW07XHJcbiAgICAgICAgICAgICAgcGFkZGluZzogMC4yZW0gMFxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIC5saWZlbGluZTpob3ZlcntcclxuICAgICAgICAgICAgICBvcGFjaXR5OiAwLjU7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgLmxpZmVsaW5lIGxhYmVse1xyXG4gICAgICAgICAgICAgIGN1cnNvcjogcG9pbnRlcjtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAuYmFjay10ZW1wbGF0ZXMtYnV0dG9ueyAgICBcclxuICAgICAgICAgICAgICBwb3NpdGlvbjogYWJzb2x1dGU7XHJcbiAgICAgICAgICAgICAgYm90dG9tOiAxMHB4O1xyXG4gICAgICAgICAgICAgIGxlZnQ6IDA7ICAgICAgICAgICBcclxuICAgICAgICAgICAgICBoZWlnaHQ6IDY1cHg7XHJcbiAgICAgICAgICAgICAgd2lkdGg6IDg1JTtcclxuICAgICAgICAgICAgICBmb250LXdlaWdodDogYm9sZDtcclxuICAgICAgICAgICAgICBmb250LXNpemU6IDEuNWVtO1xyXG4gICAgICAgICAgICAgIGJvcmRlci1yYWRpdXM6IDVweDtcclxuICAgICAgICAgICAgICBsaW5lLWhlaWdodDogMS41ZW07XHJcbiAgICAgICAgICAgICAgbWFyZ2luOiAxMHB4IDE4cHggMTBweCAxOHB4O1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIC5iYWNrLXRlbXBsYXRlcy1idXR0b246aG92ZXJ7XHJcbiAgICAgICAgICAgICAgIG9wYWNpdHk6IDAuOFxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIC5zZWxlY3RlZC1hc3Nlc3NtZW50e1xyXG4gICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjtcclxuICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgICBhbGlnbi1pdGVtczogY2VudGVyO1xyXG4gICAgICAgICAgICAgIG1hcmdpbi10b3A6IDVlbTtcclxuICAgICAgICAgICAgICBjb2xvcjogIzlhOWE5YTtcclxuICAgICAgICAgICAgICBib3JkZXItdG9wOiAxcHggc29saWQ7XHJcbiAgICAgICAgICAgICAgcGFkZGluZy10b3A6IDIwcHg7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgLnNlbGVjdGVkLWFzc2Vzc21lbnQgaDIsXHJcbiAgICAgICAgICAgIC5zZWxlY3RlZC1hc3Nlc3NtZW50IGgzLFxyXG4gICAgICAgICAgICAuc2VsZWN0ZWQtYXNzZXNzbWVudC10b3AgaDIsXHJcbiAgICAgICAgICAgIC5zZWxlY3RlZC1hc3Nlc3NtZW50LXRvcCBoMyB7XHJcbiAgICAgICAgICAgICAgY29sb3I6ICM5YTlhOWE7XHJcbiAgICAgICAgICAgICAgbWFyZ2luOiAwO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIC5zZWxlY3RlZC1hc3Nlc3NtZW50LXRvcHtcclxuICAgICAgICAgICAgICBjb2xvcjogIzlhOWE5YTtcclxuICAgICAgICAgICAgICBtYXJnaW46IDA7XHJcbiAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uO1xyXG4gICAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7ICAgXHJcbiAgICAgICAgICAgICAgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkO1xyXG4gICAgICAgICAgICAgIHBhZGRpbmctdG9wOiAyMHB4O1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgYFxyXG4gICAgICAgIH1cclxuICAgICAgPC9zdHlsZT5cclxuICAgICAgPGRpdiBjbGFzc05hbWU9XCJzZWxlY3QtbGlmZWxpbmUtY29udGFpbmVyXCIgc3R5bGU9e3tcclxuICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICBwcm9wcy5jb25maWcuYmFja2dyb3VuZENvbG9yfX0+XHJcbiAgICAgICAgXHJcbiAgICAgICAgPExhYmVsIGNoZWNrIGNsYXNzTmFtZT0nbGlmZWxpbmVzLWhlYWRlcidcclxuICAgICAgICAgIHN0eWxlPXt7YmFja2dyb3VuZENvbG9yOiBwcm9wcy5jb25maWcuYmFja2dyb3VuZENvbG9yLFxyXG4gICAgICAgICAgY29sb3I6IHByb3BzLmNvbmZpZy5mb250Q29sb3J9fT5cclxuICAgICAgICAgICBBc3Nlc3NtZW50XHJcbiAgICAgICAgPC9MYWJlbD5cclxuICAgICAgICA8aDIgc3R5bGU9e3tcclxuICAgICAgICAgIGNvbG9yOiAnI2I2YjZiNicsXHJcbiAgICAgICAgICBtYXJnaW5Ub3A6ICctMTVweCcsXHJcbiAgICAgICAgICBmb250U2l6ZTogJzIxcHgnXHJcbiAgICAgICAgICB9fT57c2VsZWN0ZWRBc3Nlc3NtZW50Py5uYW1lfTwvaDI+XHJcblxyXG4gICAgICAgIHsvKiA8TGFiZWwgY2hlY2sgY2xhc3NOYW1lPSdsaWZlbGluZXMtaGVhZGVyJ1xyXG4gICAgICAgICAgc3R5bGU9e3tiYWNrZ3JvdW5kQ29sb3I6IHByb3BzLmNvbmZpZy5iYWNrZ3JvdW5kQ29sb3IsXHJcbiAgICAgICAgICBjb2xvcjogcHJvcHMuY29uZmlnLmZvbnRDb2xvcixcclxuICAgICAgICAgIG1hcmdpblRvcDogJy0xNXB4J319PlxyXG4gICAgICAgICAgIEFzc2Vzc21lbnQgU3RhdHVzXHJcbiAgICAgICAgPC9MYWJlbD5cclxuICAgICAgICA8aDIgc3R5bGU9e3tcclxuICAgICAgICAgIGNvbG9yOiAncmdiKDEzOSwgMTM5LCAxMzkpJyxcclxuICAgICAgICAgIG1hcmdpblRvcDogJy0xNXB4JyxcclxuICAgICAgICAgIGZvbnRTaXplOiAnMjFweCcsICAgICAgICAgICBcclxuICAgICAgICAgIH19PntzZWxlY3RlZEFzc2Vzc21lbnQ/LmlzQ29tcGxldGVkID8gJ0NvbXBsZXRlZCc6ICdJbiBQcm9ncmVzcyd9PC9oMj4gKi99XHJcblxyXG4gICAgICAgIDxMYWJlbCBjaGVjayBjbGFzc05hbWU9J2xpZmVsaW5lcy1oZWFkZXInXHJcbiAgICAgICAgICBzdHlsZT17e1xyXG4gICAgICAgICAgY29sb3I6IHByb3BzLmNvbmZpZy5mb250Q29sb3IsIGJvcmRlclRvcDogJzFweCBzb2xpZCB3aGl0ZSd9fT5cclxuICAgICAgICAgICBMaWZlbGluZXNcclxuICAgICAgICA8L0xhYmVsPlxyXG4gICAgICAgIHtcclxuICAgICAgICAgIGxpZmVsaW5lU3RhdHVzZXM/Lm1hcCgobGlmZWxpbmVTdGF0dXM6IExpZmVsaW5lU3RhdHVzKSA9PiB7XHJcbiAgICAgICAgICAgIHJldHVybiAoXHJcbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT0nbGlmZWxpbmUnIGtleT17bGlmZWxpbmVTdGF0dXMuaWR9IHN0eWxlPXt7XHJcbiAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6IHNlbGVjdGVkTGlmZWxpbmVTdGF0dXM/LmlkID09PSBsaWZlbGluZVN0YXR1cy5pZCA/IHByb3BzLmNvbmZpZy5zZWxlY3RlZEJhY2tncm91bmRDb2xvciA6ICd0cmFuc3BhcmVudCdcclxuICAgICAgICAgICAgICAgIH19IG9uQ2xpY2s9eygpID0+IHNlbGVjdExpZmVsaW5lU3RhdHVzKGxpZmVsaW5lU3RhdHVzKX0+XHJcbiAgICAgICAgICAgICAgICAgICAgPExhYmVsIHNpemU9J2xnJyBzdHlsZT17e2NvbG9yOiBwcm9wcy5jb25maWcuZm9udENvbG9yfX0+XHJcbiAgICAgICAgICAgICAgICAgICAgICB7bGlmZWxpbmVTdGF0dXMubGlmZWxpbmVOYW1lfVxyXG4gICAgICAgICAgICAgICAgICAgIDwvTGFiZWw+XHJcbiAgICAgICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICAgICAgKVxyXG4gICAgICAgICAgfSlcclxuICAgICAgICB9ICAgICAgICAgICAgICBcclxuICAgICAgPC9kaXY+ICAgICBcclxuICAgIDwvZGl2PlxyXG4gIClcclxufVxyXG5leHBvcnQgZGVmYXVsdCBXaWRnZXRcclxuIl0sIm5hbWVzIjpbXSwic291cmNlUm9vdCI6IiJ9