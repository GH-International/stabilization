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

/***/ "./jimu-icons/svg/filled/application/check.svg":
/*!*****************************************************!*\
  !*** ./jimu-icons/svg/filled/application/check.svg ***!
  \*****************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M16 2.443 5.851 14 0 8.115l1.45-1.538 4.31 4.334L14.463 1 16 2.443Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/filled/editor/close-circle.svg":
/*!*******************************************************!*\
  !*** ./jimu-icons/svg/filled/editor/close-circle.svg ***!
  \*******************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0Zm-5.737-3.394a.8.8 0 0 1 1.131 1.131L9.132 8l2.262 2.263a.8.8 0 0 1-1.131 1.131L8 9.131l-2.263 2.263a.8.8 0 0 1-1.13-1.131L6.868 8 4.606 5.737a.8.8 0 1 1 1.131-1.131L8 6.869l2.263-2.263Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/filled/editor/edit.svg":
/*!***********************************************!*\
  !*** ./jimu-icons/svg/filled/editor/edit.svg ***!
  \***********************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M9.795 1.282c.387-.387 1.028-.374 1.431.03l1.462 1.462c.404.403.417 1.044.03 1.431L5.413 11.51l-2.674.48a.637.637 0 0 1-.73-.73l.48-2.673 7.306-7.305ZM2 13a1 1 0 1 0 0 2h12a1 1 0 1 0 0-2H2Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/filled/editor/save.svg":
/*!***********************************************!*\
  !*** ./jimu-icons/svg/filled/editor/save.svg ***!
  \***********************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M1 3a2 2 0 0 1 2-2h8.086a1 1 0 0 1 .707.293l2.914 2.914a1 1 0 0 1 .293.707V13a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V3Zm1.75.75a1 1 0 0 1 1-1h5.875a1 1 0 0 1 1 1v1.5a1 1 0 0 1-1 1H3.75a1 1 0 0 1-1-1v-1.5Zm7.875 6.875a2.625 2.625 0 1 1-5.25 0 2.625 2.625 0 0 1 5.25 0Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/filled/suggested/help.svg":
/*!**************************************************!*\
  !*** ./jimu-icons/svg/filled/suggested/help.svg ***!
  \**************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M1 8c0-3.85 3.15-7 7-7s7 3.15 7 7-3.15 7-7 7-7-3.15-7-7Zm7.875 4.375a.875.875 0 1 1-1.75 0 .875.875 0 0 1 1.75 0Zm-.063-2.656c.132-.571.415-.916.848-1.299.433-.383.701-.709.701-.709.39-.472.701-1.102.701-1.811 0-1.732-1.402-3.15-3.117-3.15-1.357 0-2.52.928-2.946 2.157-.06.152-.06.299-.06.299a.648.648 0 0 0 .668.694l.1-.006c.4-.046.679-.275.829-.65.078-.164.108-.208.122-.229.281-.416.754-.69 1.287-.69.858 0 1.559.709 1.559 1.575 0 .472-.156.866-.468 1.103l-.935 1.023c-.505.447-.806 1.049-.901 1.722a.614.614 0 0 0-.005.064v.117a.748.748 0 0 0 .75.696l.092-.005c.393-.043.714-.358.743-.74l.032-.161Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/outlined/editor/close.svg":
/*!**************************************************!*\
  !*** ./jimu-icons/svg/outlined/editor/close.svg ***!
  \**************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"m8.745 8 6.1 6.1a.527.527 0 1 1-.745.746L8 8.746l-6.1 6.1a.527.527 0 1 1-.746-.746l6.1-6.1-6.1-6.1a.527.527 0 0 1 .746-.746l6.1 6.1 6.1-6.1a.527.527 0 0 1 .746.746L8.746 8Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/outlined/editor/edit.svg":
/*!*************************************************!*\
  !*** ./jimu-icons/svg/outlined/editor/edit.svg ***!
  \*************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M11.226 1.312c-.403-.404-1.044-.417-1.431-.03L2.49 8.587l-.48 2.674a.637.637 0 0 0 .73.73l2.673-.48 7.305-7.306c.387-.387.374-1.028-.03-1.431l-1.462-1.462Zm-8.113 9.575.32-1.781 4.991-4.992 1.462 1.462-4.992 4.991-1.781.32Zm7.473-6.012 1.402-1.4-1.462-1.463-1.401 1.402 1.461 1.461Z\" fill=\"#000\"></path><path d=\"M1.5 14a.5.5 0 0 0 0 1h13a.5.5 0 0 0 0-1h-13Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/outlined/editor/plus-circle.svg":
/*!********************************************************!*\
  !*** ./jimu-icons/svg/outlined/editor/plus-circle.svg ***!
  \********************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M14 8A6 6 0 1 1 2 8a6 6 0 0 1 12 0Zm1 0A7 7 0 1 1 1 8a7 7 0 0 1 14 0ZM7.5 4.5a.5.5 0 0 1 1 0v3h3a.5.5 0 0 1 0 1h-3v3a.5.5 0 0 1-1 0v-3h-3a.5.5 0 0 1 0-1h3v-3Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/outlined/editor/trash.svg":
/*!**************************************************!*\
  !*** ./jimu-icons/svg/outlined/editor/trash.svg ***!
  \**************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M6 6.5a.5.5 0 0 1 1 0v6a.5.5 0 0 1-1 0v-6ZM9.5 6a.5.5 0 0 0-.5.5v6a.5.5 0 0 0 1 0v-6a.5.5 0 0 0-.5-.5Z\" fill=\"#000\"></path><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M11 0H5a1 1 0 0 0-1 1v2H.5a.5.5 0 0 0 0 1h1.6l.81 11.1a1 1 0 0 0 .995.9h8.19a1 1 0 0 0 .995-.9L13.9 4h1.6a.5.5 0 0 0 0-1H12V1a1 1 0 0 0-1-1Zm0 3V1H5v2h6Zm1.895 1h-9.79l.8 11h8.19l.8-11Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/filled/application/check.tsx":
/*!*************************************************!*\
  !*** ./jimu-icons/filled/application/check.tsx ***!
  \*************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "CheckFilled": () => (/* binding */ CheckFilled)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_filled_application_check_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/filled/application/check.svg */ "./jimu-icons/svg/filled/application/check.svg");
/* harmony import */ var _svg_filled_application_check_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_filled_application_check_svg__WEBPACK_IMPORTED_MODULE_1__);
var __rest = (undefined && undefined.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};


const CheckFilled = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_filled_application_check_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/filled/editor/close-circle.tsx":
/*!***************************************************!*\
  !*** ./jimu-icons/filled/editor/close-circle.tsx ***!
  \***************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "CloseCircleFilled": () => (/* binding */ CloseCircleFilled)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_filled_editor_close_circle_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/filled/editor/close-circle.svg */ "./jimu-icons/svg/filled/editor/close-circle.svg");
/* harmony import */ var _svg_filled_editor_close_circle_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_filled_editor_close_circle_svg__WEBPACK_IMPORTED_MODULE_1__);
var __rest = (undefined && undefined.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};


const CloseCircleFilled = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_filled_editor_close_circle_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/filled/editor/edit.tsx":
/*!*******************************************!*\
  !*** ./jimu-icons/filled/editor/edit.tsx ***!
  \*******************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "EditFilled": () => (/* binding */ EditFilled)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_filled_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/filled/editor/edit.svg */ "./jimu-icons/svg/filled/editor/edit.svg");
/* harmony import */ var _svg_filled_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_filled_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1__);
var __rest = (undefined && undefined.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};


const EditFilled = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_filled_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/filled/editor/save.tsx":
/*!*******************************************!*\
  !*** ./jimu-icons/filled/editor/save.tsx ***!
  \*******************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "SaveFilled": () => (/* binding */ SaveFilled)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_filled_editor_save_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/filled/editor/save.svg */ "./jimu-icons/svg/filled/editor/save.svg");
/* harmony import */ var _svg_filled_editor_save_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_filled_editor_save_svg__WEBPACK_IMPORTED_MODULE_1__);
var __rest = (undefined && undefined.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};


const SaveFilled = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_filled_editor_save_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/filled/suggested/help.tsx":
/*!**********************************************!*\
  !*** ./jimu-icons/filled/suggested/help.tsx ***!
  \**********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "HelpFilled": () => (/* binding */ HelpFilled)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_filled_suggested_help_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/filled/suggested/help.svg */ "./jimu-icons/svg/filled/suggested/help.svg");
/* harmony import */ var _svg_filled_suggested_help_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_filled_suggested_help_svg__WEBPACK_IMPORTED_MODULE_1__);
var __rest = (undefined && undefined.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};


const HelpFilled = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_filled_suggested_help_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/outlined/editor/close.tsx":
/*!**********************************************!*\
  !*** ./jimu-icons/outlined/editor/close.tsx ***!
  \**********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "CloseOutlined": () => (/* binding */ CloseOutlined)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_outlined_editor_close_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/outlined/editor/close.svg */ "./jimu-icons/svg/outlined/editor/close.svg");
/* harmony import */ var _svg_outlined_editor_close_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_outlined_editor_close_svg__WEBPACK_IMPORTED_MODULE_1__);
var __rest = (undefined && undefined.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};


const CloseOutlined = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_outlined_editor_close_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/outlined/editor/edit.tsx":
/*!*********************************************!*\
  !*** ./jimu-icons/outlined/editor/edit.tsx ***!
  \*********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "EditOutlined": () => (/* binding */ EditOutlined)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_outlined_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/outlined/editor/edit.svg */ "./jimu-icons/svg/outlined/editor/edit.svg");
/* harmony import */ var _svg_outlined_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_outlined_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1__);
var __rest = (undefined && undefined.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};


const EditOutlined = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_outlined_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/outlined/editor/plus-circle.tsx":
/*!****************************************************!*\
  !*** ./jimu-icons/outlined/editor/plus-circle.tsx ***!
  \****************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "PlusCircleOutlined": () => (/* binding */ PlusCircleOutlined)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_outlined_editor_plus_circle_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/outlined/editor/plus-circle.svg */ "./jimu-icons/svg/outlined/editor/plus-circle.svg");
/* harmony import */ var _svg_outlined_editor_plus_circle_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_outlined_editor_plus_circle_svg__WEBPACK_IMPORTED_MODULE_1__);
var __rest = (undefined && undefined.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};


const PlusCircleOutlined = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_outlined_editor_plus_circle_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/outlined/editor/trash.tsx":
/*!**********************************************!*\
  !*** ./jimu-icons/outlined/editor/trash.tsx ***!
  \**********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "TrashOutlined": () => (/* binding */ TrashOutlined)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_outlined_editor_trash_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/outlined/editor/trash.svg */ "./jimu-icons/svg/outlined/editor/trash.svg");
/* harmony import */ var _svg_outlined_editor_trash_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_outlined_editor_trash_svg__WEBPACK_IMPORTED_MODULE_1__);
var __rest = (undefined && undefined.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};


const TrashOutlined = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_outlined_editor_trash_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


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

/***/ "./your-extensions/widgets/clss-custom-components/clss-add-hazard.tsx":
/*!****************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-add-hazard.tsx ***!
  \****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "AddHazardWidget": () => (/* binding */ AddHazardWidget)
/* harmony export */ });
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _clss_dropdown__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./clss-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx");
/* harmony import */ var _clss_modal__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./clss-modal */ "./your-extensions/widgets/clss-custom-components/clss-modal.tsx");
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! jimu-core */ "jimu-core");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};








const { useSelector } = jimu_core__WEBPACK_IMPORTED_MODULE_6__.ReactRedux;
const AddHazardWidget = ({ props, visible, toggle, setHazard }) => {
    const [loading, setLoading] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(false);
    const [isVisible, setVisible] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(false);
    const [name, setName] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState('');
    const [description, setDescription] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState('');
    const [hazardTypes, setHazardTypes] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState([]);
    const [selectedHazardType, setSelectedHazardType] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(null);
    const [config, setConfig] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(null);
    const credential = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.authenticate;
    });
    const hazards = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.hazards;
    });
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        if (credential) {
            setConfig(Object.assign(Object.assign({}, props.config), { credential: credential }));
        }
    }, [credential]);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        if (hazards && hazards.length > 0) {
            const types = hazards[1].domains;
            types.orderBy('name');
            setHazardTypes(types);
        }
    }, [hazards]);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        setVisible(visible);
        setName('');
        setDescription('');
        setSelectedHazardType(null);
    }, [visible]);
    const saveNewHazard = () => __awaiter(void 0, void 0, void 0, function* () {
        const exist = hazards.find(h => h.name.toLowerCase() === name.toLowerCase().trim());
        if (exist) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__.CLSSActionKeys.SET_ERRORS, `Hazard: ${name} already exists`);
            return;
        }
        setLoading(true);
        try {
            let newHazard = {
                name,
                title: name,
                type: selectedHazardType,
                description
            };
            const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.saveHazard)(config, newHazard);
            console.log(response);
            if (response.errors) {
                throw new Error(String(response.errors));
            }
            newHazard = response.data;
            newHazard.domains = hazards[1].domains;
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__.CLSSActionKeys.LOAD_HAZARDS_ACTION, [...hazards, newHazard]);
            setHazard(newHazard);
            toggle(false);
        }
        catch (err) {
            console.log(err);
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__.CLSSActionKeys.SET_ERRORS, err.message);
        }
        finally {
            setLoading(false);
        }
    });
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_modal__WEBPACK_IMPORTED_MODULE_5__.ClssModal, { title: "Add New Hazard", disable: !(name && selectedHazardType), save: saveNewHazard, toggleVisibility: toggle, visible: isVisible, loading: loading },
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "hazards" },
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true },
                    "Hazard Name",
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("span", { style: { color: 'red' } }, "*")),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.TextInput, { onChange: (e) => setName(e.target.value), value: name })),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true },
                    "Hazard Type",
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("span", { style: { color: 'red' } }, "*")),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_dropdown__WEBPACK_IMPORTED_MODULE_4__.ClssDropdown, { items: hazardTypes, item: selectedHazardType, deletable: false, setItem: setSelectedHazardType })),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true }, "Description of Hazard (Optional)"),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.TextArea, { value: description, onChange: (e) => setDescription(e.target.value) })))));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-add-organization.tsx":
/*!**********************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-add-organization.tsx ***!
  \**********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "AddOrganizatonWidget": () => (/* binding */ AddOrganizatonWidget)
/* harmony export */ });
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _clss_dropdown__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./clss-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx");
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _clss_modal__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./clss-modal */ "./your-extensions/widgets/clss-custom-components/clss-modal.tsx");
/* harmony import */ var _clss_organizations_dropdown__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./clss-organizations-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-organizations-dropdown.tsx");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};









const { useSelector } = jimu_core__WEBPACK_IMPORTED_MODULE_5__.ReactRedux;
const AddOrganizatonWidget = ({ propsConfig, visible, toggle, setOrganization }) => {
    const [loading, setLoading] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(false);
    const [isVisible, setVisible] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(false);
    const [organizationName, setOrganizationName] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState('');
    const [organizationTypes, setOrganizationTypes] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState([]);
    const [selectedOrganizationType, setSelectedOrganizationType] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(null);
    const [selectedParentOrganization, setSelectedParentOrganization] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(null);
    const [config, setConfig] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(null);
    const organizations = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.organizations;
    });
    const credential = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.authenticate;
    });
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        setVisible(visible);
        setOrganizationName('');
        setSelectedOrganizationType(null);
    }, [visible]);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        if (credential) {
            setConfig(Object.assign(Object.assign({}, propsConfig), { credential }));
        }
    }, [credential]);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        if (organizations && organizations.length > 0) {
            const types = organizations[1].domains;
            types === null || types === void 0 ? void 0 : types.orderBy('name');
            setOrganizationTypes(types);
        }
    }, [organizations]);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        setSelectedParentOrganization(organizations[0]);
    }, [organizations]);
    const save = () => __awaiter(void 0, void 0, void 0, function* () {
        const exists = organizations.find(o => o.name === organizationName);
        if (exists) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__.CLSSActionKeys.SET_ERRORS, `Organization: ${organizationName} already exists`);
            return;
        }
        setLoading(true);
        try {
            let newOrganization = {
                name: organizationName,
                title: organizationName,
                type: selectedOrganizationType,
                parentId: selectedParentOrganization.id !== '000' ? selectedParentOrganization.id : null
            };
            const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.saveOrganization)(config, newOrganization);
            console.log(response);
            if (response.errors) {
                throw new Error(String(response.errors));
            }
            newOrganization = response.data;
            newOrganization.domains = organizations[1].domains;
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__.CLSSActionKeys.LOAD_ORGANIZATIONS_ACTION, [...organizations, newOrganization]);
            setOrganization(response.data);
            toggle(false);
        }
        catch (err) {
            console.log(err);
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__.CLSSActionKeys.SET_ERRORS, err.message);
        }
        finally {
            setLoading(false);
        }
    });
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_modal__WEBPACK_IMPORTED_MODULE_6__.ClssModal, { title: "Add New Organization", disable: !(organizationName && selectedOrganizationType), save: save, loading: loading, toggleVisibility: toggle, visible: isVisible },
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "add-organization" },
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("style", null, `
                        .add-organization{
                           display: flex;
                           flex-direction: column
                         }                         
                     `),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true },
                    "Organization Name",
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("span", { style: { color: 'red' } }, "*")),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.TextInput, { "data-testid": "txtOrganizationName", size: "default", onChange: (e) => setOrganizationName(e.target.value), value: organizationName })),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true },
                    "Organization Type",
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("span", { style: { color: 'red' } }, "*")),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_dropdown__WEBPACK_IMPORTED_MODULE_4__.ClssDropdown, { items: organizationTypes, item: selectedOrganizationType, deletable: false, setItem: setSelectedOrganizationType })),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true }, "Organization's Parent (Optional)"),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_organizations_dropdown__WEBPACK_IMPORTED_MODULE_7__.OrganizationsDropdown, { config: config, toggleNewOrganizationModal: null, organizations: organizations, selectedOrganization: selectedParentOrganization, setOrganization: setSelectedParentOrganization, vertical: false })))));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-assessments-list.tsx":
/*!**********************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-assessments-list.tsx ***!
  \**********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "TemplateAssessmentView": () => (/* binding */ TemplateAssessmentView)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var _clss_modal__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./clss-modal */ "./your-extensions/widgets/clss-custom-components/clss-modal.tsx");


const TemplateAssessmentView = ({ assessments, toggle, isVisible }) => {
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_modal__WEBPACK_IMPORTED_MODULE_1__.ClssModal, { title: "Assessments created with this template", toggleVisibility: toggle, visible: isVisible, hideFooter: true },
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", null,
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("style", null, `
                     .assessment-list tr:nth-child(2n+2){
                        background:#efefef;
                     }       
                     .assessment-list td{
                         line-height: 50px;
                     }     
                    `),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("table", { className: "assessment-list", style: { width: '100%' } }, assessments === null || assessments === void 0 ? void 0 : assessments.map((a, i) => {
                return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                        i + 1 + ") ",
                        a.name,
                        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("span", { style: { color: 'gray', marginLeft: '.2em' } }, "   (" + a.date + ")"))));
            })))));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx":
/*!**************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx ***!
  \**************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "ClssDropdown": () => (/* binding */ ClssDropdown)
/* harmony export */ });
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var jimu_icons_outlined_editor_trash__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-icons/outlined/editor/trash */ "./jimu-icons/outlined/editor/trash.tsx");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! react */ "react");



const ClssDropdown = ({ items, item, deletable, setItem, deleteItem, menuWidth }) => {
    const buttonElement = react__WEBPACK_IMPORTED_MODULE_2__["default"].useRef();
    react__WEBPACK_IMPORTED_MODULE_2__["default"].useEffect(() => {
        if (items && items.length > 0) {
            if (!item) {
                setItem(items[0]);
            }
            else {
                setItem(item);
            }
        }
    }, [items]);
    const itemClick = (item) => {
        setItem(item);
        if (buttonElement && buttonElement.current) {
            buttonElement.current.click();
        }
    };
    const removeItem = (item) => {
        if (confirm('Remove ' + (item.title || item.name))) {
            deleteItem(item);
        }
    };
    return (react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement("div", { className: "clss-dropdown-container", style: { width: '100%' } },
        react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement("style", null, `
                  .dropdown-item-container{
                    height: 45px;
                    border-bottom: 1px solid rgb(227, 227, 227);
                    width: 100%;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                  }
                  .dropdown-item-container:hover{
                    background-color: rgb(227, 227, 227);
                  }
                  .jimu-dropdown-menu{
                    width: 35%;
                    max-height: 500px;
                    overflow: auto;
                  }
                  .jimu-dropdown-menu .dropdown-item-container:last-child{
                    border-bottom: none;
                  }
                  .modal-content .clss-dropdown-container button{
                    width: 100%;
                  }
                  .clss-dropdown-container .jimu-dropdown{
                    width: 100%;
                  }
                  .close-button{
                    margin: 10px;
                    color: gray;
                  }

                  .modal-content .clss-dropdown-container button span{
                     line-height: 30px !important;
                  }
                 
                  .dropdown-item-container label{
                    width: 100%;
                    height: 100%;
                    display: flex;
                    align-items: center;
                    font-size: 1.2em;
                    margin-left: 1em;
                    cursor: pointer;
                  }
                 `),
        react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Dropdown, { activeIcon: "true", size: "lg" },
            react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.DropdownButton, { className: "dropdownButton", ref: buttonElement, size: "lg", style: { textAlign: 'left' } }, (item === null || item === void 0 ? void 0 : item.title) || (item === null || item === void 0 ? void 0 : item.name)),
            react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.DropdownMenu, { style: { width: menuWidth || "30%" } }, items === null || items === void 0 ? void 0 : items.map((item, idx) => {
                return (react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement("div", { id: (item === null || item === void 0 ? void 0 : item.name) || (item === null || item === void 0 ? void 0 : item.title), className: "dropdown-item-container" },
                    react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true, onClick: () => itemClick(item) }, (item === null || item === void 0 ? void 0 : item.title) || (item === null || item === void 0 ? void 0 : item.name)),
                    (((item === null || item === void 0 ? void 0 : item.title) || (item === null || item === void 0 ? void 0 : item.name)) !== '-None-') && deletable ?
                        (react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement(jimu_icons_outlined_editor_trash__WEBPACK_IMPORTED_MODULE_1__.TrashOutlined, { title: 'Remove', className: "close-button", size: 20, onClick: () => removeItem(item) }))
                        : null));
            })))));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-error.tsx":
/*!***********************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-error.tsx ***!
  \***********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");

const ClssError = ({ error }) => {
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("h2", { style: { color: 'red', fontSize: '15px' } }, error));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (ClssError);


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-errors-panel.tsx":
/*!******************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-errors-panel.tsx ***!
  \******************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var jimu_icons_filled_editor_close_circle__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-icons/filled/editor/close-circle */ "./jimu-icons/filled/editor/close-circle.tsx");



//const use
const ClssErrorsPanel = ({ close, errors }) => {
    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: 'jimu-widget widget-error-container' },
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("style", null, `
          .widget-error-container{
            display: flex;
            justify-content: center;
            align-items: center;
            background-color: #ffc6cd;
            border: 1px solid red;
            box-shadow: 1px 1px 12px 4px #5d5c5c;
            padding: 10px 20px;
            border-radius: 0 10px 0 0;
          }     
          .close-button{
             position: absolute;
             top: 0;
             right: 0;
             color: red;
             cursor: pointer;
          }     
        `),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_icons_filled_editor_close_circle__WEBPACK_IMPORTED_MODULE_2__.CloseCircleFilled, { className: 'close-button', "data-testid": "btnCloseError", size: 30, onClick: () => close(), style: { color: 'red' }, title: 'Close' }),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { style: { color: '#a50000',
                fontSize: '20px' }, check: true, size: 'lg' }, errors)));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (ClssErrorsPanel);


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-hazards-dropdown.tsx":
/*!**********************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-hazards-dropdown.tsx ***!
  \**********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "HazardsDropdown": () => (/* binding */ HazardsDropdown)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var _clss_dropdown__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./clss-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var jimu_icons_outlined_editor_plus_circle__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! jimu-icons/outlined/editor/plus-circle */ "./jimu-icons/outlined/editor/plus-circle.tsx");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};






const HazardsDropdown = ({ config, hazards, selectedHazard, setHazard, vertical, toggleNewHazardModal }) => {
    const [localHazards, setLocalHazards] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState([]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (hazards) {
            setLocalHazards([...hazards]);
        }
    }, [hazards]);
    const removeHazard = (hazard) => __awaiter(void 0, void 0, void 0, function* () {
        const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_4__.deleteHazard)(hazard, config);
        if (response.errors) {
            console.log(response.errors);
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_4__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.SET_ERRORS, response.errors);
            return;
        }
        console.log(`${hazard.title} deleted`);
        setLocalHazards([...localHazards.filter(h => h.id !== hazard.id)]);
    });
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { style: { display: vertical ? 'block' : 'flex',
            alignItems: 'center' } },
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("style", null, `
                     .action-icon {
                        color: gray;
                        cursor: pointer;
                      }
                    `),
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_dropdown__WEBPACK_IMPORTED_MODULE_1__.ClssDropdown, { items: localHazards, item: selectedHazard, deletable: true, setItem: setHazard, deleteItem: removeHazard }),
        vertical ? (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_2__.Button, { "data-testid": "btnShowAddOrganization", className: " add-link", type: "link", style: { textAlign: 'left' }, onClick: () => toggleNewHazardModal(true) }, "Add New Hazard")) : (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_icons_outlined_editor_plus_circle__WEBPACK_IMPORTED_MODULE_3__.PlusCircleOutlined, { className: "action-icon", "data-testid": "btnAddNewHazard", title: "Add New Hazard", size: 30, color: 'gray', onClick: () => toggleNewHazardModal(true) }))));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-lifeline-component.tsx":
/*!************************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-lifeline-component.tsx ***!
  \************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "LifelineComponent": () => (/* binding */ LifelineComponent)
/* harmony export */ });
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var jimu_icons_outlined_editor_trash__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-icons/outlined/editor/trash */ "./jimu-icons/outlined/editor/trash.tsx");
/* harmony import */ var jimu_icons_filled_editor_edit__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! jimu-icons/filled/editor/edit */ "./jimu-icons/filled/editor/edit.tsx");
/* harmony import */ var jimu_icons_filled_suggested_help__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! jimu-icons/filled/suggested/help */ "./jimu-icons/filled/suggested/help.tsx");
/* harmony import */ var jimu_icons_outlined_editor_close__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! jimu-icons/outlined/editor/close */ "./jimu-icons/outlined/editor/close.tsx");
/* harmony import */ var _clss_loading__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./clss-loading */ "./your-extensions/widgets/clss-custom-components/clss-loading.tsx");
/* harmony import */ var jimu_icons_filled_application_check__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! jimu-icons/filled/application/check */ "./jimu-icons/filled/application/check.tsx");
/* harmony import */ var _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../clss-application/src/extensions/constants */ "./your-extensions/widgets/clss-application/src/extensions/constants.ts");
/* harmony import */ var _clss_error__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ./clss-error */ "./your-extensions/widgets/clss-custom-components/clss-error.tsx");
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(/*! ../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};













const { useSelector } = jimu_core__WEBPACK_IMPORTED_MODULE_10__.ReactRedux;
const TableRowCommand = ({ isInEditMode, onEdit, onDelete, onSave, onCancel, canSave }) => {
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" },
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "command-container" },
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("style", null, `
                        .command-container{
                            display: flex;
                            justify-content: space-between;
                            align-items: center;
                        }
                        .command{
                            flex: 1
                        }
                        .edit-delete, .save-cancel{
                            display: flex;
                            align-items: center;
                            flex-wrap: nowrap;
                        }
                        `),
            isInEditMode ?
                (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "edit-delete" },
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_filled_application_check__WEBPACK_IMPORTED_MODULE_7__.CheckFilled, { style: { pointerEvents: !canSave ? 'none' : 'all' }, size: 20, className: "command", title: "Save Edits", onClick: () => onSave() }),
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_outlined_editor_close__WEBPACK_IMPORTED_MODULE_5__.CloseOutlined, { size: 20, className: "command", title: "Cancel Edits", onClick: () => onCancel() })))
                : (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "edit-delete" },
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_filled_editor_edit__WEBPACK_IMPORTED_MODULE_3__.EditFilled, { size: 20, className: "command", title: "Edit", onClick: () => onEdit() }),
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_outlined_editor_trash__WEBPACK_IMPORTED_MODULE_2__.TrashOutlined, { size: 20, className: "command", title: "Delete", onClick: () => onDelete() }))))));
};
const EditableTableRow = ({ indicator, isEditable, component, template, config, setError, onActionComplete, onCancel }) => {
    const [isEditing, setEditing] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(indicator.isBeingEdited);
    const [loading, setLoading] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(false);
    const [name, setName] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState('');
    const [rank, setRank] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState();
    const [lifeSafety, setLifeSafety] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState();
    const [incidentStab, setIncidentStab] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState();
    const [propertyProt, setPropProt] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState();
    const [envPres, setEnvPres] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState();
    const [canCommit, setCanCommit] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(true);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        var _a, _b, _c, _d, _e;
        if (indicator) {
            try {
                setName(indicator === null || indicator === void 0 ? void 0 : indicator.name);
                setRank((_a = indicator === null || indicator === void 0 ? void 0 : indicator.weights) === null || _a === void 0 ? void 0 : _a.find(w => w.name === _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.RANK).weight);
                setLifeSafety((_b = indicator === null || indicator === void 0 ? void 0 : indicator.weights) === null || _b === void 0 ? void 0 : _b.find(w => w.name === _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.LIFE_SAFETY).weight);
                setIncidentStab((_c = indicator === null || indicator === void 0 ? void 0 : indicator.weights) === null || _c === void 0 ? void 0 : _c.find(w => w.name === _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.INCIDENT_STABILIZATION).weight);
                setPropProt((_d = indicator === null || indicator === void 0 ? void 0 : indicator.weights) === null || _d === void 0 ? void 0 : _d.find(w => w.name === _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.PROPERTY_PROTECTION).weight);
                setEnvPres((_e = indicator === null || indicator === void 0 ? void 0 : indicator.weights) === null || _e === void 0 ? void 0 : _e.find(w => w.name === _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.ENVIRONMENT_PRESERVATION).weight);
            }
            catch (e) {
            }
        }
    }, [indicator]);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        setCanCommit(true);
        setError('');
        if (name) {
            const indicatorsNames = component.indicators.map(i => i.name.toLocaleLowerCase());
            if (indicator.isNew && indicatorsNames.includes(name.toLocaleLowerCase())) {
                setError(`Indicator: ${name} already exists`);
                setCanCommit(false);
                return;
            }
        }
    }, [name]);
    const getWeightByName = (w) => {
        switch (w.name) {
            case _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.RANK:
                return rank;
            case _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.LIFE_SAFETY:
                return lifeSafety;
            case _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.INCIDENT_STABILIZATION:
                return incidentStab;
            case _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.PROPERTY_PROTECTION:
                return propertyProt;
            case _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.ENVIRONMENT_PRESERVATION:
                return envPres;
        }
    };
    const onSaveEdits = () => __awaiter(void 0, void 0, void 0, function* () {
        setLoading(true);
        const updatedIndicator = Object.assign(Object.assign({}, indicator), { name: name, title: name, weights: indicator === null || indicator === void 0 ? void 0 : indicator.weights.map(w => {
                return Object.assign(Object.assign({}, w), { weight: getWeightByName(w) });
            }) });
        if (indicator.isNew) {
            const resp = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_11__.createNewIndicator)(updatedIndicator, config, template.id, template.name);
            if (resp.errors) {
                setLoading(false);
                (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_11__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_12__.CLSSActionKeys.SET_ERRORS, resp.errors);
                return;
            }
        }
        else {
            const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_11__.updateIndicator)(updatedIndicator, config);
            if (response.errors) {
                setLoading(false);
                (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_11__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_12__.CLSSActionKeys.SET_ERRORS, response.errors);
                return;
            }
        }
        setEditing(false);
        setLoading(false);
        onActionComplete(true);
    });
    const onCancelEdits = () => {
        setError('');
        setCanCommit(true);
        setEditing(false);
        onActionComplete(false);
        if (indicator.isNew) {
            onCancel();
        }
    };
    const onDeleteIndicator = () => __awaiter(void 0, void 0, void 0, function* () {
        if (confirm(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.DELETE_INDICATOR_CONFIRMATION) == true) {
            setLoading(true);
            const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_11__.deleteIndicator)(indicator, config);
            if (response.errors) {
                (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_11__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_12__.CLSSActionKeys.SET_ERRORS, response.errors);
                return;
            }
            setLoading(false);
            onActionComplete(true);
        }
    });
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("tr", { style: { position: 'relative' } },
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("style", null, `
                    .lifeline-component-table .indicator-name input {
                        font-size: 12px !important
                     }   
                     .jimu-numeric-input input{
                        min-width: 160px;
                     }                  
                    `),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data indicator-name", style: { textAlign: 'left' } }, isEditing ?
            (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("label", { style: { width: '100%' } },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.TextInput, { className: "indicator-name", title: name, value: name, onChange: (e) => setName(e.target.value), allowClear: true, type: "text" }))) :
            name),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" }, isEditing ?
            (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("label", null,
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.NumericInput, { max: 5, min: 1, onChange: (v) => setRank(v), value: rank }))) : rank),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" }, 'N/A'
        //    !isEditing ? (lifeSafety?.value): (<label><NumericInput onChange={onLifeSafetyChange} value={lifeSafety?.value}/></label>)
        ),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" }, 'N/A'
        //    !isEditing ? (incidentStab?.value): (<label><NumericInput onChange={onIncidentStabilizationChange} value={incidentStab?.value}/></label>)
        ),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" }, 'N/A'
        //    !isEditing ? (propertyProt?.value): (<label><NumericInput onChange={onPropertyProtectionChange} value={propertyProt?.value}/></label>)
        ),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" }, 'N/A'
        //    !isEditing ? (envPres?.value): (<label><NumericInput onChange={onEnvironmentalPreservationChange} value={envPres?.value}/></label>)
        ),
        isEditable ?
            (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(TableRowCommand, { isInEditMode: isEditing, canSave: canCommit, onEdit: () => setEditing(true), onSave: onSaveEdits, onCancel: onCancelEdits, onDelete: onDeleteIndicator }))) : null,
        loading ? react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_loading__WEBPACK_IMPORTED_MODULE_6__["default"], null) : null));
};
const LifelineComponent = ({ lifeline, component, template, config, onActionComplete }) => {
    const [indicators, setIndicators] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState([]);
    const [error, setError] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState('');
    const [isEditable, setEditable] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(false);
    const user = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.user;
    });
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        var _a, _b, _c;
        if (user) {
            if ((_a = user === null || user === void 0 ? void 0 : user.groups) === null || _a === void 0 ? void 0 : _a.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.CLSS_ADMIN)) {
                setEditable(true);
                return;
            }
            if (((_b = user === null || user === void 0 ? void 0 : user.groups) === null || _b === void 0 ? void 0 : _b.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.CLSS_EDITOR)) &&
                (template === null || template === void 0 ? void 0 : template.name) !== _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.BASELINE_TEMPLATE_NAME) {
                setEditable(true);
                return;
            }
            if (((_c = user === null || user === void 0 ? void 0 : user.groups) === null || _c === void 0 ? void 0 : _c.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.CLSS_FOLLOWERS)) &&
                (template === null || template === void 0 ? void 0 : template.name) !== _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.BASELINE_TEMPLATE_NAME) {
                setEditable(true);
                return;
            }
        }
        setEditable(false);
    }, [template, user]);
    // React.useEffect(() => {        
    //     if(user && template){
    //         if(!template.isActive){
    //            setEditable(false);
    //            return;
    //         }
    //         const isTemplateEditable = 
    //         (user?.groups?.includes(CLSS_ADMIN)) || 
    //         (template.name !== BASELINE_TEMPLATE_NAME && 
    //             user.groups?.includes(CLSS_EDITOR));
    //         setEditable(isTemplateEditable);
    //     }
    // }, [template, user])
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        setIndicators(component.indicators.orderBy('name'));
    }, [component]);
    const createNewIndicator = () => __awaiter(void 0, void 0, void 0, function* () {
        const weights = [
            {
                name: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.RANK,
                adjustedWeight: 0,
                indicatorId: '',
                scaleFactor: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.OTHER_WEIGHTS_SCALE_FACTOR,
                weight: 1
            },
            {
                name: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.LIFE_SAFETY,
                adjustedWeight: 0,
                indicatorId: '',
                scaleFactor: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.LIFE_SAFETY_SCALE_FACTOR,
                weight: 1
            },
            {
                name: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.PROPERTY_PROTECTION,
                adjustedWeight: 0,
                indicatorId: '',
                scaleFactor: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.OTHER_WEIGHTS_SCALE_FACTOR,
                weight: 1
            },
            {
                name: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.INCIDENT_STABILIZATION,
                adjustedWeight: 0,
                indicatorId: '',
                scaleFactor: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.OTHER_WEIGHTS_SCALE_FACTOR,
                weight: 1
            },
            {
                name: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.ENVIRONMENT_PRESERVATION,
                adjustedWeight: 0,
                indicatorId: '',
                scaleFactor: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.OTHER_WEIGHTS_SCALE_FACTOR,
                weight: 1
            }
        ];
        const existingIndicators = indicators || [];
        const newIndicator = {
            name: '',
            isBeingEdited: true,
            isNew: true,
            templateName: template.name,
            weights: weights,
            componentId: component.id,
            templateId: template.id,
            componentName: component.name,
            lifelineName: lifeline.name,
        };
        setIndicators([...existingIndicators, newIndicator]);
    });
    const onCancelIndicatorCreate = () => {
        setIndicators(indicators.filter(i => !i.isNew));
    };
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "lifeline-component-container", style: {
            marginTop: isEditable ? '0.5em' : '1.8em'
        } },
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("style", null, `
               .lifeline-component-container{
                  display: flex;
                  flex-direction: column;
                  width: 100%;
                  margin-bottom: 0.5em;
               } 
               .component-label{
                font-size: 18px;
                color: #534c4c;
                font-weight: bold;
                padding: 0 0 0 1.2em;
                text-decoration: underline;
               }                     
               .component-details{
                 background-color: white;
                 width: 100%;
                 padding: 15px 0 0 0;
               }
               .lifeline-component-table{
                width: 100%;
               }    
               .lifeline-component-table .table-header-data{
                 display: flex;
                 width: 10em;
                 align-items: center;
                 flex-wrap:nowrap;
                 justify-content: center;
               } 
               .lifeline-component-table .table-header-data svg{
                 width: 40px;
               }         
               .lifeline-component-table .command{
                color: gray;
                cursor: pointer;
                width: 40px !important;
              }
              .lifeline-component-table td.data{
                font-size: 13px;               
                color: #534c4c;
                text-align: center;
                border-right: 1px solid white
              }
              .lifeline-component-table .tableBody td{
                color: #534c4c;
                text-align: center;
                font-size: 0.8rem;
                padding: .8em;
                font-weight: bold;
              }
              .lifeline-component-table .tableBody tr:nth-child(odd){
                background-color: #f0f0f0;
              }
              .add-new{
                text-align: right;
                margin: 10px 5px 0 0;
                font-weight: bold;
              }
              .add-new button{
                 font-weight: normal;
                 padding: 0.5em;
              }
              .table-header-data h6{
                margin: 0;
              }
            `),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true, className: "component-label" }, component.title),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "component-details" },
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("table", { className: "lifeline-component-table table" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("thead", { style: { backgroundColor: '#c5c5c5' } },
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("tr", null,
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data", style: { width: '400px' } },
                            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h6", null, "Indicator")),
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" },
                            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "table-header-data" },
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h6", null, "Rank"),
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_filled_suggested_help__WEBPACK_IMPORTED_MODULE_4__.HelpFilled, { size: 20, title: "How important is the indicator to your jurisdiction or hazard?(1=Most Important, 5=Least Important)" }))),
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" },
                            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "table-header-data" },
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h6", null, "Life Safety"),
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_filled_suggested_help__WEBPACK_IMPORTED_MODULE_4__.HelpFilled, { size: 20, title: "How important is the indicator to Life Safety?" }))),
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" },
                            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "table-header-data" },
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h6", null, "Incident Stabilization"),
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_filled_suggested_help__WEBPACK_IMPORTED_MODULE_4__.HelpFilled, { size: 20, title: "How important is the indicator to Incident Stabilization?" }))),
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" },
                            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "table-header-data" },
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h6", null, "Property Protection"),
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_filled_suggested_help__WEBPACK_IMPORTED_MODULE_4__.HelpFilled, { size: 20, title: "How important is the indicator to Property Protection?" }))),
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" },
                            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "table-header-data" },
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h6", null, "Environmental Preservation"),
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_filled_suggested_help__WEBPACK_IMPORTED_MODULE_4__.HelpFilled, { size: 20, title: "How important is the indicator to Environmental Preservation?" }))),
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" }))),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("tbody", { className: "tableBody" }, indicators.map((indicator) => {
                    return react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(EditableTableRow, { key: indicator.id, indicator: indicator, isEditable: isEditable, component: component, config: config, template: template, setError: setError, onCancel: onCancelIndicatorCreate, onActionComplete: onActionComplete });
                })),
                (!isEditable) ? null
                    : (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("tfoot", null,
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("tr", null,
                            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { colSpan: 8 },
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "add-new" },
                                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Button, { disabled: indicators === null || indicators === void 0 ? void 0 : indicators.some(i => i.isNew), onClick: () => createNewIndicator(), title: "Add new indicator", size: "default" },
                                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Icon, { icon: "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M7.5 0a.5.5 0 0 0-.5.5V7H.5a.5.5 0 0 0 0 1H7v6.5a.5.5 0 0 0 1 0V8h6.5a.5.5 0 0 0 0-1H8V.5a.5.5 0 0 0-.5-.5Z\" fill=\"#000\"></path></svg>", size: "m" }),
                                        "Add New Indicator"))))))),
            error ? (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_error__WEBPACK_IMPORTED_MODULE_9__["default"], { error: error })) : null)));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-loading.tsx":
/*!*************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-loading.tsx ***!
  \*************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! react */ "react");


const ClssLoading = ({ message }) => {
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { style: {
            height: '100%',
            width: '100%',
            position: 'absolute',
            background: 'rgb(0 0 0 / 13%)',
            top: 0,
            left: 0,
            zIndex: 999999,
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center'
        } },
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Loading, { className: "", type: "SECONDARY" }),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h3", null, message)));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (ClssLoading);


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-modal.tsx":
/*!***********************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-modal.tsx ***!
  \***********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "ClssModal": () => (/* binding */ ClssModal)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var _clss_loading__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./clss-loading */ "./your-extensions/widgets/clss-custom-components/clss-loading.tsx");



// export interface ModalProps {
//     title: string;
//     visible: boolean;
//     disable: boolean;
//     children: any;
//     toggleVisibility: Function;
//     save: Function;
//     cancel: Function;
// }
const ClssModal = (props) => {
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Modal, { isOpen: props.visible, centered: true, className: "clss-modal" },
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("style", null, `
                        .clss-modal .modal-content{
                          font-size: 1.3rem;
                          display: flex;
                          flex-direction: column
                        }              
                        .clss-modal .modal-title{
                            font-size: 1.1em;
                        }         
                        .clss-modal input{
                            padding-left: 0px;
                        }                   
                        .clss-modal .jimu-input span{
                            height: 40px;
                            font-size: .9em;
                        }                         
                        .clss-modal label{
                            color: gray;
                        }    
                        .clss-modal .jimu-dropdown-button{
                            font-size: 1em;
                        }    
                        .clss-modal .modal-item{
                            margin: 10px 0;
                        }   
                        .clss-modal textarea{
                            font-size: 0.8em;
                        }  
                        .clss-modal .spacer{
                            width: 1em;
                        }
                    `),
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.ModalHeader, { toggle: () => props.toggleVisibility(false) }, props.title),
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.ModalBody, null, props.children),
        props.hideFooter && props.hideFooter == true ? null :
            (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.ModalFooter, null,
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Button, { onClick: () => (props.cancel ? props.cancel() : props.toggleVisibility(false)) }, props.noButtonTitle || 'Cancel'),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { className: "spacer" }),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Button, { "data-testid": "btnSave", disabled: props.disable, onClick: () => props.save() }, props.yesButtonTitle || 'Save'))),
        (props.loading) ? react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_loading__WEBPACK_IMPORTED_MODULE_2__["default"], null) : null));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-no-data.tsx":
/*!*************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-no-data.tsx ***!
  \*************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");

const ClssNoData = ({ message }) => {
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { style: {
            height: '100%',
            width: '100%',
            position: 'absolute',
            background: 'rgb(0 0 0 / 13%)',
            top: 0,
            left: 0,
            zIndex: 999999,
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center'
        } },
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("h3", null, message)));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (ClssNoData);


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-organizations-dropdown.tsx":
/*!****************************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-organizations-dropdown.tsx ***!
  \****************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "OrganizationsDropdown": () => (/* binding */ OrganizationsDropdown)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var _clss_dropdown__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./clss-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var jimu_icons_outlined_editor_plus_circle__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! jimu-icons/outlined/editor/plus-circle */ "./jimu-icons/outlined/editor/plus-circle.tsx");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};






const OrganizationsDropdown = ({ config, organizations, selectedOrganization, setOrganization, vertical, toggleNewOrganizationModal }) => {
    const [localOrganizations, setLocalOrganizations] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState([]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (organizations) {
            setLocalOrganizations([...organizations]);
        }
    }, [organizations]);
    const removeOrganization = (organization) => __awaiter(void 0, void 0, void 0, function* () {
        const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_4__.deleteOrganization)(organization, config);
        if (response.errors) {
            console.log(response.errors);
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_4__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.SET_ERRORS, response.errors);
            return;
        }
        console.log(`${organization.title} deleted`);
        setLocalOrganizations([...localOrganizations.filter(o => o.id !== organization.id)]);
    });
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { style: { display: vertical ? 'block' : 'flex',
            alignItems: 'center' } },
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_dropdown__WEBPACK_IMPORTED_MODULE_1__.ClssDropdown, { items: localOrganizations, item: selectedOrganization, deletable: true, setItem: setOrganization, deleteItem: removeOrganization }),
        toggleNewOrganizationModal ? (vertical ? (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_2__.Button, { "data-testid": "btnShowAddOrganization", className: " add-link", type: "link", style: { textAlign: 'left' }, onClick: () => toggleNewOrganizationModal(true) }, "Add New Organization")) : (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_icons_outlined_editor_plus_circle__WEBPACK_IMPORTED_MODULE_3__.PlusCircleOutlined, { className: "action-icon", "data-testid": "btnAddNewOrganization", title: "Add New Organization", size: 30, color: 'gray', onClick: () => toggleNewOrganizationModal(true) }))) : null));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-template-detail/src/runtime/header.tsx":
/*!*****************************************************************************!*\
  !*** ./your-extensions/widgets/clss-template-detail/src/runtime/header.tsx ***!
  \*****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "DetailHeaderWidget": () => (/* binding */ DetailHeaderWidget)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var jimu_icons_outlined_editor_close__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-icons/outlined/editor/close */ "./jimu-icons/outlined/editor/close.tsx");
/* harmony import */ var jimu_icons_outlined_editor_edit__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-icons/outlined/editor/edit */ "./jimu-icons/outlined/editor/edit.tsx");
/* harmony import */ var jimu_icons_filled_editor_save__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! jimu-icons/filled/editor/save */ "./jimu-icons/filled/editor/save.tsx");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var _clss_custom_components_clss_loading__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../clss-custom-components/clss-loading */ "./your-extensions/widgets/clss-custom-components/clss-loading.tsx");
/* harmony import */ var _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../../../clss-application/src/extensions/constants */ "./your-extensions/widgets/clss-application/src/extensions/constants.ts");
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../../../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../../../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ../../../clss-application/src/extensions/utils */ "./your-extensions/widgets/clss-application/src/extensions/utils.ts");
/* harmony import */ var _clss_custom_components_clss_dropdown__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ../../../clss-custom-components/clss-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx");
/* harmony import */ var _clss_custom_components_clss_organizations_dropdown__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(/*! ../../../clss-custom-components/clss-organizations-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-organizations-dropdown.tsx");
/* harmony import */ var _clss_custom_components_clss_hazards_dropdown__WEBPACK_IMPORTED_MODULE_13__ = __webpack_require__(/*! ../../../clss-custom-components/clss-hazards-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-hazards-dropdown.tsx");
/* harmony import */ var _clss_custom_components_clss_assessments_list__WEBPACK_IMPORTED_MODULE_14__ = __webpack_require__(/*! ../../../clss-custom-components/clss-assessments-list */ "./your-extensions/widgets/clss-custom-components/clss-assessments-list.tsx");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};















const { useSelector } = jimu_core__WEBPACK_IMPORTED_MODULE_7__.ReactRedux;
const DetailHeaderWidget = ({ template, config, organizations, hazards, onActionComplete, selectedNewHazard, selectedNewOrganization, toggleHazardModalVisibility, toggleOrganizationModalVisibility }) => {
    const [loading, setLoading] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(false);
    const [isEditing, setEditing] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(false);
    const [templateName, setTemplateName] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState('');
    const [selectedHazard, setSelectedHazard] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(null);
    const [selectedOrganization, setSelectedOrganization] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(null);
    const [allowToEdit, setAllowToEdit] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(false);
    const [status, setStatus] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState();
    const [statuses, setStatuses] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState([]);
    const [assessments, setAssessments] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState([]);
    const [isAssessmentsVisibility, setToggleAssessmentVisibility] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(false);
    const user = useSelector((state) => {
        return state.clssState.user;
    });
    const templates = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.templates;
    });
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (selectedNewHazard) {
            setSelectedHazard(selectedNewHazard);
        }
    }, [selectedNewHazard]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (selectedNewOrganization) {
            setSelectedOrganization(selectedNewOrganization);
        }
    }, [selectedNewOrganization]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (config) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_8__.getAssessmentNames)(config, template === null || template === void 0 ? void 0 : template.name)
                .then((response) => {
                if (response.data) {
                    setAssessments(response.data);
                }
            });
        }
    }, [template]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (template) {
            const statusDomains = template.domains;
            setStatuses(statusDomains);
        }
    }, [template]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (template && statuses && statuses.length > 0) {
            const s = statuses.find(s => s.name === (template === null || template === void 0 ? void 0 : template.status.name));
            try {
                setStatus(s);
            }
            catch (e) {
                console.log(e);
            }
        }
    }, [template, statuses]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        var _a, _b, _c;
        if (user) {
            if ((_a = user === null || user === void 0 ? void 0 : user.groups) === null || _a === void 0 ? void 0 : _a.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_6__.CLSS_ADMIN)) {
                setAllowToEdit(true);
                return;
            }
            if (((_b = user === null || user === void 0 ? void 0 : user.groups) === null || _b === void 0 ? void 0 : _b.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_6__.CLSS_EDITOR)) &&
                (template === null || template === void 0 ? void 0 : template.name) !== _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_6__.BASELINE_TEMPLATE_NAME) {
                setAllowToEdit(true);
                return;
            }
            if (((_c = user === null || user === void 0 ? void 0 : user.groups) === null || _c === void 0 ? void 0 : _c.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_6__.CLSS_FOLLOWERS)) &&
                (template === null || template === void 0 ? void 0 : template.name) !== _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_6__.BASELINE_TEMPLATE_NAME) {
                setAllowToEdit(true);
                return;
            }
        }
        setAllowToEdit(false);
    }, [template, user]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (template) {
            setTemplateName(template === null || template === void 0 ? void 0 : template.name);
        }
    }, [template]);
    const onCancel = () => {
        setTemplateName(template.name);
        setSelectedHazard(hazards.find(h => h.name === template.hazardName));
        setSelectedOrganization(organizations.find(o => o.name === template.organizationName));
        setEditing(false);
        onActionComplete(false);
    };
    const getSelectedHazardData = () => {
        if (selectedHazard && selectedHazard.title !== '-None-') {
            return selectedHazard;
        }
    };
    const getSelectedOrgData = () => {
        if (selectedOrganization && selectedOrganization.title !== '-None-') {
            return selectedOrganization;
        }
    };
    const onSaveTemplateHeaderEdits = () => __awaiter(void 0, void 0, void 0, function* () {
        var _a;
        const _templates = templates.filter(t => t.id != template.id);
        if (_templates.some(t => t.name.toLowerCase() === templateName.toLowerCase().trim())) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_8__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_9__.CLSSActionKeys.SET_ERRORS, `Template: ${templateName} already exists`);
            return;
        }
        setLoading(true);
        const hazardData = getSelectedHazardData();
        const orgData = getSelectedOrgData();
        const updatedTemplate = Object.assign(Object.assign({}, template), { name: templateName, isSelected: template.isSelected, status: status, hazardId: hazardData ? hazardData.id : null, hazardName: hazardData ? hazardData.name : null, hazardType: hazardData ? (_a = hazardData.type) === null || _a === void 0 ? void 0 : _a.code : null, organizationType: orgData ? orgData.type : null, organizationName: orgData ? orgData.name : null, organizationId: orgData ? orgData.id : null });
        const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_8__.updateTemplateOrganizationAndHazard)(config, updatedTemplate, user.userName);
        setLoading(false);
        if (response.errors) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_8__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_9__.CLSSActionKeys.SET_ERRORS, response.errors);
            return;
        }
        setEditing(false);
        onActionComplete(true);
    });
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { className: "details-content-header", style: {
            backgroundColor: config === null || config === void 0 ? void 0 : config.headerBackgroundColor
        } },
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("style", null, `      
                  .details-content-header{
                    display: flex;                    
                    flex-wrap: wrap;
                  }            
                  .editor-icon{                    
                    color: #534c4c;
                    cursor: pointer;
                    margin: 10px;
                  }
                  .details-content-header .editor-icon: hover{
                    opacity: .8
                  }
                  .details-content-header .save-cancel, 
                  .details-content-header .save-icon{
                    position: absolute;
                    right: 10px;
                    top: 10px;
                  }
                  .details-content-header .data-dropdown, 
                  .details-content-header .data-input{
                    width: 100%;
                    display: flex;
                    align-items: center;
                  }
                  .details-content-header .data-dropdown .jimu-dropdown{
                      width: 300px;
                  }
                  .details-content-header .data-dropdown-menu{
                    width: 300px;
                  }
                  .details-content-header .error{
                    color: red;
                    font-size: 15px;
                  }
                  .details-content-header .dropdown-item{
                      font-size: 1.3em;
                  }
                  .details-content-header .organization{
                    display: flex;
                    flex-direction: column;
                  }
                  .details-content-header .end-widget{
                      margin-bottom: 15px;
                  }
                  .details-content-header .data-input{
                      width: 30.7%
                  }
                  .details-content-header .title.template{
                    width: 142px;
                  }

                  .details-content-header td label,
                  .details-content-header td input{ 
                    font-size: 1.5em;
                  }
                  .details-content-header td label{
                    width: 165px;
                  }
                  .details-content-header td label.value{
                      font-weight: bold;
                      width: auto;
                  }
                  .details-content-header tr.td-under>td{
                    padding-bottom: 1em;
                  }
                  .details-content-header .template-input input{
                    padding-left: 10px;
                    height: 40px;
                    font-size: 16px;
                  }
                  .details-content-header .template-input span{
                      height: 40px !important;
                      width: 300px;
                  }
                  .action-icon {
                    color: gray;
                    cursor: pointer;
                  }
                `),
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("table", { className: "template-detail-header-table", style: { marginRight: '10em' } },
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    " ",
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { check: true }, "Template Name: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null, isEditing ? (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.TextInput, { className: "template-input", onChange: (e) => setTemplateName(e.target.value), value: templateName })) :
                    (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { "data-testid": "lblTemplateName", className: "value", check: true },
                        templateName,
                        " ")))),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "title", check: true }, "Organization: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null, isEditing ? (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { className: 'data-dropdown' },
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_custom_components_clss_organizations_dropdown__WEBPACK_IMPORTED_MODULE_12__.OrganizationsDropdown, { config: config, organizations: organizations, selectedOrganization: selectedOrganization, setOrganization: setSelectedOrganization, toggleNewOrganizationModal: toggleOrganizationModalVisibility, vertical: false }))) :
                    (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { "data-testid": "txtOrganizationName", className: "value", check: true }, selectedOrganization ? selectedOrganization === null || selectedOrganization === void 0 ? void 0 : selectedOrganization.name : '-None-')))),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    " ",
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "title", check: true }, "Hazard: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null, isEditing ? (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { className: 'data-dropdown' },
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_custom_components_clss_hazards_dropdown__WEBPACK_IMPORTED_MODULE_13__.HazardsDropdown, { config: config, hazards: hazards, selectedHazard: selectedHazard, setHazard: setSelectedHazard, toggleNewHazardModal: toggleHazardModalVisibility, vertical: false }))) : (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "value", check: true }, selectedHazard && (selectedHazard === null || selectedHazard === void 0 ? void 0 : selectedHazard.title) !== '-None-' ? (selectedHazard.title + ` (${selectedHazard.type})`) : '-None-')))),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "title", check: true }, "Status: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null, isEditing ? (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { className: 'data-dropdown' },
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_custom_components_clss_dropdown__WEBPACK_IMPORTED_MODULE_11__.ClssDropdown, { items: statuses, item: status, menuWidth: '300px', deletable: false, setItem: setStatus }))) : (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "value", check: true }, status === null || status === void 0 ? void 0 : status.name))))),
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("table", { className: "template-detail-header-table" },
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    " ",
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { check: true }, "Author: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { "data-testid": "lblTemplateName", className: "value", check: true }, template === null || template === void 0 ? void 0 :
                        template.creator,
                        " "))),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "title", check: true }, "Date Created: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { "data-testid": "lblTemplateName", className: "value", check: true },
                        (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_10__.parseDate)(template === null || template === void 0 ? void 0 : template.createdDate),
                        " "))),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "title", check: true }, "Last Updated: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { "data-testid": "lblTemplateName", className: "value", check: true },
                        (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_10__.parseDate)(template === null || template === void 0 ? void 0 : template.editedDate),
                        " ",
                        template.editor ? ' by ' + template.editor : '-'))),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    " ",
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "title", check: true }, "Assessments: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null, assessments && assessments.length > 0 ?
                    (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Button, { onClick: () => setToggleAssessmentVisibility(true), style: { fontSize: '1.5em',
                            padding: 0, fontWeight: 'bold' }, type: "link" },
                        "Click here to view the assessments (", assessments === null || assessments === void 0 ? void 0 :
                        assessments.length,
                        ")")) : react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { "data-testid": "lblTemplateName", className: "value", check: true }, "-None-")))),
        allowToEdit && isEditing ? (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { className: "save-cancel", style: { display: 'flex', flexDirection: 'column' } },
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_icons_outlined_editor_close__WEBPACK_IMPORTED_MODULE_1__.CloseOutlined, { "data-testid": "btnCancelEdits", size: 25, className: 'editor-icon', style: { color: '#534c4c', fontWeight: 'bold' }, title: "Cancel Edits", onClick: () => onCancel() }),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_icons_filled_editor_save__WEBPACK_IMPORTED_MODULE_3__.SaveFilled, { size: 25, "data-testid": "btnSaveEdits", className: 'editor-icon', onClick: () => onSaveTemplateHeaderEdits(), style: { color: '#534c4c', fontWeight: 'bold' }, title: 'Save' }))) :
            (allowToEdit ?
                (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_icons_outlined_editor_edit__WEBPACK_IMPORTED_MODULE_2__.EditOutlined, { "data-testid": "btnStartEditing", size: 30, className: 'editor-icon save-icon', onClick: () => setEditing(true), style: { color: '#534c4c' }, title: 'Edit' })) : null),
        (!template || loading) ? react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_custom_components_clss_loading__WEBPACK_IMPORTED_MODULE_5__["default"], null) : null,
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_custom_components_clss_assessments_list__WEBPACK_IMPORTED_MODULE_14__.TemplateAssessmentView, { isVisible: isAssessmentsVisibility, toggle: setToggleAssessmentVisibility, assessments: assessments })));
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
/******/ 	/* webpack/runtime/compat get default export */
/******/ 	(() => {
/******/ 		// getDefaultExport function for compatibility with non-harmony modules
/******/ 		__webpack_require__.n = (module) => {
/******/ 			var getter = module && module.__esModule ?
/******/ 				() => (module['default']) :
/******/ 				() => (module);
/******/ 			__webpack_require__.d(getter, { a: getter });
/******/ 			return getter;
/******/ 		};
/******/ 	})();
/******/ 	
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
  !*** ./your-extensions/widgets/clss-template-detail/src/runtime/widget.tsx ***!
  \*****************************************************************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _clss_custom_components_clss_loading__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../clss-custom-components/clss-loading */ "./your-extensions/widgets/clss-custom-components/clss-loading.tsx");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_custom_components_clss_errors_panel__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../../../clss-custom-components/clss-errors-panel */ "./your-extensions/widgets/clss-custom-components/clss-errors-panel.tsx");
/* harmony import */ var _header__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./header */ "./your-extensions/widgets/clss-template-detail/src/runtime/header.tsx");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var _clss_custom_components_clss_lifeline_component__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../clss-custom-components/clss-lifeline-component */ "./your-extensions/widgets/clss-custom-components/clss-lifeline-component.tsx");
/* harmony import */ var _clss_custom_components_clss_add_organization__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../../../clss-custom-components/clss-add-organization */ "./your-extensions/widgets/clss-custom-components/clss-add-organization.tsx");
/* harmony import */ var _clss_custom_components_clss_add_hazard__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../../../clss-custom-components/clss-add-hazard */ "./your-extensions/widgets/clss-custom-components/clss-add-hazard.tsx");
/* harmony import */ var _clss_custom_components_clss_no_data__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ../../../clss-custom-components/clss-no-data */ "./your-extensions/widgets/clss-custom-components/clss-no-data.tsx");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};











const { useSelector } = jimu_core__WEBPACK_IMPORTED_MODULE_0__.ReactRedux;
const Widget = (props) => {
    const [loading, setLoading] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    const [config, setConfig] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(null);
    const [isAddOrganizationModalVisible, setAddOrganizationModalVisibility] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    const [isAddHazardModalVisible, setAddHazardModalVisibility] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    const [selectedHazard, setSelectedHazard] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(null);
    const [selectedOrganization, setSelectedOrganization] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(null);
    const errors = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.errors;
    });
    const template = useSelector((state) => {
        var _a;
        return (_a = state === null || state === void 0 ? void 0 : state.clssState) === null || _a === void 0 ? void 0 : _a.templates.find(t => t.isSelected);
    });
    const credential = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.authenticate;
    });
    const hazards = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.hazards;
    });
    const organizations = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.organizations;
    });
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (credential) {
            setConfig(Object.assign(Object.assign({}, props.config), { credential: credential }));
        }
    }, [credential]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (template && organizations && organizations.length > 0) {
            setSelectedOrganization(organizations.find(o => o.name === template.organizationName));
        }
    }, [template, organizations]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (template && hazards && hazards.length > 0) {
            setSelectedHazard(hazards.find(h => h.name === template.hazardName));
        }
    }, [template, hazards]);
    const closeError = () => {
        (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.getAppStore)().dispatch({
            type: _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_2__.CLSSActionKeys.SET_ERRORS,
            val: ''
        });
    };
    const loadTemplates = () => __awaiter(void 0, void 0, void 0, function* () {
        const selectedTemplate = template ? Object.assign({}, template) : null;
        const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__.getTemplates)(config);
        let fetchData = response.data;
        if (response.data) {
            if (selectedTemplate) {
                fetchData = response.data.map(t => {
                    return Object.assign(Object.assign({}, t), { isSelected: t.id === selectedTemplate.id });
                });
            }
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_2__.CLSSActionKeys.LOAD_TEMPLATES_ACTION, fetchData);
        }
        return response;
    });
    const onIndicatorActionComplete = (reload) => __awaiter(void 0, void 0, void 0, function* () {
        if (reload) {
            yield loadTemplates();
        }
    });
    if (loading) {
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_loading__WEBPACK_IMPORTED_MODULE_1__["default"], null);
    }
    if (template == null) {
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_no_data__WEBPACK_IMPORTED_MODULE_10__["default"], { message: 'Select a template to view details' });
    }
    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "widget-template-detail", style: {
            backgroundColor: props.config.backgoundColor
        } },
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("style", null, `
          .widget-template-detail {
            width: 100%;
            height: 100%;
            padding: 20px;
            overflow: auto;
            position: relative;            
          }

          .error-panel {
            position: absolute;
            left: 0;
            top: 0;
            width: 100%;
            z-index: 999
          }
          
          .details-content{
            width: 100%;
            height: 100%; 
            display: flex;
            flex-direction: column;
            align-items: center;   
          }
         
          .details-content-header{
            border-radius: 10px 10px 0 0;
            padding: 30px 50px;
            width: 100%;
            position:relative;              
            margin-bottom: 10px;
          }
          
          .header-row{
            display: flex;   
            margin-bottom: 10px;           
          }
          .header-row label{
            font-size: 1.6em;
            color: #4d4949;
          }
          .header-row .value{
            font-weight: bold;
          }
          .header-row .title{
             width: 165px;
          }
          .details-content-data{
            height: 100%;
            margin-top: 20px;
            padding: 0;
          }
          .details-content-data-header{             
            height: 75px;
            width: 100%;
            background: #534c4c80;
            border-radius: 10px 10px 0 0;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 0 10px;
            text-align: center;
          }
          .details-content-data-header label{
            font-size: 1.6em;
            color: white;
          }
          .lifelines-tabs{
            width: 100%;             
          }
          .lifelines-tabs .tab-title{
            font-size: 15px;
            font-weight: bold;
            padding: 10px;
          }
          .lifelines-tabs .nav-item{
            height: 40px;
          }
          .lifeline-tab-content{
            padding: 10px;
            background-color: white;
          }
        `),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "details-content" },
            errors && !loading ? (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: 'error-panel' },
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_errors_panel__WEBPACK_IMPORTED_MODULE_4__["default"], { close: closeError, errors: errors }))) : null,
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_header__WEBPACK_IMPORTED_MODULE_5__.DetailHeaderWidget, { template: template, organizations: organizations, hazards: hazards, onActionComplete: onIndicatorActionComplete, config: config, selectedNewHazard: selectedHazard, selectedNewOrganization: selectedOrganization, toggleHazardModalVisibility: setAddHazardModalVisibility, toggleOrganizationModalVisibility: setAddOrganizationModalVisibility }),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: 'lifelines-tabs' },
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_6__.Tabs, { defaultValue: "tab-1", fill: true, type: "tabs" }, template === null || template === void 0 ? void 0 : template.lifelineTemplates.map(((lifeline) => {
                    var _a;
                    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_6__.Tab, { id: lifeline === null || lifeline === void 0 ? void 0 : lifeline.id, key: lifeline === null || lifeline === void 0 ? void 0 : lifeline.id, title: lifeline.title },
                        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "lifeline-tab-content" }, (_a = lifeline === null || lifeline === void 0 ? void 0 : lifeline.componentTemplates) === null || _a === void 0 ? void 0 : _a.map(((lifelineComp) => {
                            return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_lifeline_component__WEBPACK_IMPORTED_MODULE_7__.LifelineComponent, { key: lifelineComp.id, lifeline: lifeline, component: lifelineComp, template: template, config: config, onActionComplete: onIndicatorActionComplete }));
                        })))));
                }))))),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_add_organization__WEBPACK_IMPORTED_MODULE_8__.AddOrganizatonWidget, { propsConfig: props === null || props === void 0 ? void 0 : props.config, visible: isAddOrganizationModalVisible, setOrganization: setSelectedOrganization, toggle: setAddOrganizationModalVisibility }),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_add_hazard__WEBPACK_IMPORTED_MODULE_9__.AddHazardWidget, { props: props, visible: isAddHazardModalVisible, setHazard: setSelectedHazard, toggle: setAddHazardModalVisibility })));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (Widget);

})();

/******/ 	return __webpack_exports__;
/******/ })()

			);
		}
	};
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2lkZ2V0cy9jbHNzLXRlbXBsYXRlLWRldGFpbC9kaXN0L3J1bnRpbWUvd2lkZ2V0LmpzIiwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQ0E7QUFDaUM7QUFDcUY7QUFDckU7QUFDTjtBQUN5QjtBQUNWO0FBQzFEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFlBQVksY0FBYztBQUMxQjtBQUNBO0FBQ0E7QUFDQTtBQUNBLElBQUk7QUFDSjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsSUFBSTtBQUNKO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGNBQWMsbUVBQVE7QUFDdEI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBLGtCQUFrQixlQUFlO0FBQ2pDO0FBQ0E7QUFDQTtB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LDZCQUE2QixFQUN0QyxlQUFlLEVBQUUsdUJBQXVCLEVBQ3hDLE1BQU0sRUFBRSxpQ0FBaUMsR0FBRztRQUVoRCwyREFBQyxvRkFBZSxJQUNkLEtBQUssRUFBRSxLQUFLLEVBQ1osT0FBTyxFQUFFLHVCQUF1QixFQUNoQyxTQUFTLEVBQUUsaUJBQWlCLEVBQzVCLE1BQU0sRUFBRSwyQkFBMkIsR0FBRyxDQUNwQyxDQUNQO0FBQ0gsQ0FBQztBQUNELGlFQUFlLE1BQU0iLCJzb3VyY2VzIjpbIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgvZGlzdC9lc20vVXNlclNlc3Npb24uanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL2Rpc3QvZXNtL2ZlZGVyYXRpb24tdXRpbHMuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL2Rpc3QvZXNtL2ZldGNoLXRva2VuLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aC9kaXN0L2VzbS9nZW5lcmF0ZS10b2tlbi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgvZGlzdC9lc20vdmFsaWRhdGUtYXBwLWFjY2Vzcy5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgvbm9kZV9tb2R1bGVzL3RzbGliL3RzbGliLmVzNi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXIvZGlzdC9lc20vYWRkLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllci9kaXN0L2VzbS9kZWxldGUuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyL2Rpc3QvZXNtL3F1ZXJ5LmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllci9kaXN0L2VzbS9xdWVyeVJlbGF0ZWQuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyL2Rpc3QvZXNtL3VwZGF0ZS5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXIvbm9kZV9tb2R1bGVzL3RzbGliL3RzbGliLmVzNi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vcmVxdWVzdC5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvQXJjR0lTUmVxdWVzdEVycm9yLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy9hcHBlbmQtY3VzdG9tLXBhcmFtcy5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvY2xlYW4tdXJsLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy9kZWNvZGUtcXVlcnktc3RyaW5nLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy9lbmNvZGUtZm9ybS1kYXRhLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy9lbmNvZGUtcXVlcnktc3RyaW5nLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy9wcm9jZXNzLXBhcmFtcy5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvd2Fybi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3Qvbm9kZV9tb2R1bGVzL3RzbGliL3RzbGliLmVzNi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9zdmcvZmlsbGVkL2FwcGxpY2F0aW9uL2NoZWNrLnN2ZyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9zdmcvZmlsbGVkL2VkaXRvci9jbG9zZS1jaXJjbGUuc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL3N2Zy9maWxsZWQvZWRpdG9yL2VkaXQuc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL3N2Zy9maWxsZWQvZWRpdG9yL3NhdmUuc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL3N2Zy9maWxsZWQvc3VnZ2VzdGVkL2hlbHAuc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL3N2Zy9vdXRsaW5lZC9lZGl0b3IvY2xvc2Uuc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL3N2Zy9vdXRsaW5lZC9lZGl0b3IvZWRpdC5zdmciLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvc3ZnL291dGxpbmVkL2VkaXRvci9wbHVzLWNpcmNsZS5zdmciLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvc3ZnL291dGxpbmVkL2VkaXRvci90cmFzaC5zdmciLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvZmlsbGVkL2FwcGxpY2F0aW9uL2NoZWNrLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9maWxsZWQvZWRpdG9yL2Nsb3NlLWNpcmNsZS50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvZmlsbGVkL2VkaXRvci9lZGl0LnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9maWxsZWQvZWRpdG9yL3NhdmUudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL2ZpbGxlZC9zdWdnZXN0ZWQvaGVscC50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvb3V0bGluZWQvZWRpdG9yL2Nsb3NlLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9vdXRsaW5lZC9lZGl0b3IvZWRpdC50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvb3V0bGluZWQvZWRpdG9yL3BsdXMtY2lyY2xlLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9vdXRsaW5lZC9lZGl0b3IvdHJhc2gudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2FwaS50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9hdXRoLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2Nsc3Mtc3RvcmUudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY29uc3RhbnRzLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2VzcmktYXBpLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2xvZ2dlci50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy91dGlscy50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWFkZC1oYXphcmQudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtYWRkLW9yZ2FuaXphdGlvbi50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1hc3Nlc3NtZW50cy1saXN0LnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWRyb3Bkb3duLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWVycm9yLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWVycm9ycy1wYW5lbC50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1oYXphcmRzLWRyb3Bkb3duLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWxpZmVsaW5lLWNvbXBvbmVudC50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1sb2FkaW5nLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLW1vZGFsLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLW5vLWRhdGEudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3Mtb3JnYW5pemF0aW9ucy1kcm9wZG93bi50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtdGVtcGxhdGUtZGV0YWlsL3NyYy9ydW50aW1lL2hlYWRlci50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC9leHRlcm5hbCBzeXN0ZW0gXCJqaW11LWFyY2dpc1wiIiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS1jb3JlXCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC9leHRlcm5hbCBzeXN0ZW0gXCJqaW11LWNvcmUvcmVhY3RcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtdWlcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svYm9vdHN0cmFwIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL2NvbXBhdCBnZXQgZGVmYXVsdCBleHBvcnQiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvZGVmaW5lIHByb3BlcnR5IGdldHRlcnMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvaGFzT3duUHJvcGVydHkgc2hvcnRoYW5kIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL21ha2UgbmFtZXNwYWNlIG9iamVjdCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9wdWJsaWNQYXRoIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWNvcmUvbGliL3NldC1wdWJsaWMtcGF0aC50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy10ZW1wbGF0ZS1kZXRhaWwvc3JjL3J1bnRpbWUvd2lkZ2V0LnRzeCJdLCJzb3VyY2VzQ29udGVudCI6WyIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAxOSBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgcmVxdWVzdCwgQXJjR0lTQXV0aEVycm9yLCBjbGVhblVybCwgZW5jb2RlUXVlcnlTdHJpbmcsIGRlY29kZVF1ZXJ5U3RyaW5nLCB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG5pbXBvcnQgeyBnZW5lcmF0ZVRva2VuIH0gZnJvbSBcIi4vZ2VuZXJhdGUtdG9rZW5cIjtcbmltcG9ydCB7IGZldGNoVG9rZW4gfSBmcm9tIFwiLi9mZXRjaC10b2tlblwiO1xuaW1wb3J0IHsgY2FuVXNlT25saW5lVG9rZW4sIGlzRmVkZXJhdGVkIH0gZnJvbSBcIi4vZmVkZXJhdGlvbi11dGlsc1wiO1xuaW1wb3J0IHsgdmFsaWRhdGVBcHBBY2Nlc3MgfSBmcm9tIFwiLi92YWxpZGF0ZS1hcHAtYWNjZXNzXCI7XG5mdW5jdGlvbiBkZWZlcigpIHtcbiAgICB2YXIgZGVmZXJyZWQgPSB7XG4gICAgICAgIHByb21pc2U6IG51bGwsXG4gICAgICAgIHJlc29sdmU6IG51bGwsXG4gICAgICAgIHJlamVjdDogbnVsbCxcbiAgICB9O1xuICAgIGRlZmVycmVkLnByb21pc2UgPSBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUgPSByZXNvbHZlO1xuICAgICAgICBkZWZlcnJlZC5yZWplY3QgPSByZWplY3Q7XG4gICAgfSk7XG4gICAgcmV0dXJuIGRlZmVycmVkO1xufVxuLyoqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgVXNlclNlc3Npb24gfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1hdXRoJztcbiAqIFVzZXJTZXNzaW9uLmJlZ2luT0F1dGgyKHtcbiAqICAgLy8gcmVnaXN0ZXIgYW4gYXBwIG9mIHlvdXIgb3duIHRvIGNyZWF0ZSBhIHVuaXF1ZSBjbGllbnRJZFxuICogICBjbGllbnRJZDogXCJhYmMxMjNcIixcbiAqICAgcmVkaXJlY3RVcmk6ICdodHRwczovL3lvdXJhcHAuY29tL2F1dGhlbnRpY2F0ZS5odG1sJ1xuICogfSlcbiAqICAgLnRoZW4oc2Vzc2lvbilcbiAqIC8vIG9yXG4gKiBuZXcgVXNlclNlc3Npb24oe1xuICogICB1c2VybmFtZTogXCJqc21pdGhcIixcbiAqICAgcGFzc3dvcmQ6IFwiMTIzNDU2XCJcbiAqIH0pXG4gKiAvLyBvclxuICogVXNlclNlc3Npb24uZGVzZXJpYWxpemUoY2FjaGUpXG4gKiBgYGBcbiAqIFVzZWQgdG8gYXV0aGVudGljYXRlIGJvdGggQXJjR0lTIE9ubGluZSBhbmQgQXJjR0lTIEVudGVycHJpc2UgdXNlcnMuIGBVc2VyU2Vzc2lvbmAgaW5jbHVkZXMgaGVscGVyIG1ldGhvZHMgZm9yIFtPQXV0aCAyLjBdKC9hcmNnaXMtcmVzdC1qcy9ndWlkZXMvYnJvd3Nlci1hdXRoZW50aWNhdGlvbi8pIGluIGJvdGggYnJvd3NlciBhbmQgc2VydmVyIGFwcGxpY2F0aW9ucy5cbiAqL1xudmFyIFVzZXJTZXNzaW9uID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIFVzZXJTZXNzaW9uKG9wdGlvbnMpIHtcbiAgICAgICAgdGhpcy5jbGllbnRJZCA9IG9wdGlvbnMuY2xpZW50SWQ7XG4gICAgICAgIHRoaXMuX3JlZnJlc2hUb2tlbiA9IG9wdGlvbnMucmVmcmVzaFRva2VuO1xuICAgICAgICB0aGlzLl9yZWZyZXNoVG9rZW5FeHBpcmVzID0gb3B0aW9ucy5yZWZyZXNoVG9rZW5FeHBpcmVzO1xuICAgICAgICB0aGlzLnVzZXJuYW1lID0gb3B0aW9ucy51c2VybmFtZTtcbiAgICAgICAgdGhpcy5wYXNzd29yZCA9IG9wdGlvbnMucGFzc3dvcmQ7XG4gICAgICAgIHRoaXMuX3Rva2VuID0gb3B0aW9ucy50b2tlbjtcbiAgICAgICAgdGhpcy5fdG9rZW5FeHBpcmVzID0gb3B0aW9ucy50b2tlbkV4cGlyZXM7XG4gICAgICAgIHRoaXMucG9ydGFsID0gb3B0aW9ucy5wb3J0YWxcbiAgICAgICAgICAgID8gY2xlYW5Vcmwob3B0aW9ucy5wb3J0YWwpXG4gICAgICAgICAgICA6IFwiaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIjtcbiAgICAgICAgdGhpcy5zc2wgPSBvcHRpb25zLnNzbDtcbiAgICAgICAgdGhpcy5wcm92aWRlciA9IG9wdGlvbnMucHJvdmlkZXIgfHwgXCJhcmNnaXNcIjtcbiAgICAgICAgdGhpcy50b2tlbkR1cmF0aW9uID0gb3B0aW9ucy50b2tlbkR1cmF0aW9uIHx8IDIwMTYwO1xuICAgICAgICB0aGlzLnJlZGlyZWN0VXJpID0gb3B0aW9ucy5yZWRpcmVjdFVyaTtcbiAgICAgICAgdGhpcy5yZWZyZXNoVG9rZW5UVEwgPSBvcHRpb25zLnJlZnJlc2hUb2tlblRUTCB8fCAyMDE2MDtcbiAgICAgICAgdGhpcy5zZXJ2ZXIgPSBvcHRpb25zLnNlcnZlcjtcbiAgICAgICAgdGhpcy5mZWRlcmF0ZWRTZXJ2ZXJzID0ge307XG4gICAgICAgIHRoaXMudHJ1c3RlZERvbWFpbnMgPSBbXTtcbiAgICAgICAgLy8gaWYgYSBub24tZmVkZXJhdGVkIHNlcnZlciB3YXMgcGFzc2VkIGV4cGxpY2l0bHksIGl0IHNob3VsZCBiZSB0cnVzdGVkLlxuICAgICAgICBpZiAob3B0aW9ucy5zZXJ2ZXIpIHtcbiAgICAgICAgICAgIC8vIGlmIHRoZSB1cmwgaW5jbHVkZXMgbW9yZSB0aGFuICcvYXJjZ2lzLycsIHRyaW0gdGhlIHJlc3RcbiAgICAgICAgICAgIHZhciByb290ID0gdGhpcy5nZXRTZXJ2ZXJSb290VXJsKG9wdGlvbnMuc2VydmVyKTtcbiAgICAgICAgICAgIHRoaXMuZmVkZXJhdGVkU2VydmVyc1tyb290XSA9IHtcbiAgICAgICAgICAgICAgICB0b2tlbjogb3B0aW9ucy50b2tlbixcbiAgICAgICAgICAgICAgICBleHBpcmVzOiBvcHRpb25zLnRva2VuRXhwaXJlcyxcbiAgICAgICAgICAgIH07XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHMgPSB7fTtcbiAgICB9XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KFVzZXJTZXNzaW9uLnByb3RvdHlwZSwgXCJ0b2tlblwiLCB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBUaGUgY3VycmVudCBBcmNHSVMgT25saW5lIG9yIEFyY0dJUyBFbnRlcnByaXNlIGB0b2tlbmAuXG4gICAgICAgICAqL1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl90b2tlbjtcbiAgICAgICAgfSxcbiAgICAgICAgZW51bWVyYWJsZTogZmFsc2UsXG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZVxuICAgIH0pO1xuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShVc2VyU2Vzc2lvbi5wcm90b3R5cGUsIFwidG9rZW5FeHBpcmVzXCIsIHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFRoZSBleHBpcmF0aW9uIHRpbWUgb2YgdGhlIGN1cnJlbnQgYHRva2VuYC5cbiAgICAgICAgICovXG4gICAgICAgIGdldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3Rva2VuRXhwaXJlcztcbiAgICAgICAgfSxcbiAgICAgICAgZW51bWVyYWJsZTogZmFsc2UsXG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZVxuICAgIH0pO1xuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShVc2VyU2Vzc2lvbi5wcm90b3R5cGUsIFwicmVmcmVzaFRva2VuXCIsIHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFRoZSBjdXJyZW50IHRva2VuIHRvIEFyY0dJUyBPbmxpbmUgb3IgQXJjR0lTIEVudGVycHJpc2UuXG4gICAgICAgICAqL1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9yZWZyZXNoVG9rZW47XG4gICAgICAgIH0sXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KTtcbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoVXNlclNlc3Npb24ucHJvdG90eXBlLCBcInJlZnJlc2hUb2tlbkV4cGlyZXNcIiwge1xuICAgICAgICAvKipcbiAgICAgICAgICogVGhlIGV4cGlyYXRpb24gdGltZSBvZiB0aGUgY3VycmVudCBgcmVmcmVzaFRva2VuYC5cbiAgICAgICAgICovXG4gICAgICAgIGdldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3JlZnJlc2hUb2tlbkV4cGlyZXM7XG4gICAgICAgIH0sXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KTtcbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoVXNlclNlc3Npb24ucHJvdG90eXBlLCBcInRydXN0ZWRTZXJ2ZXJzXCIsIHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIERlcHJlY2F0ZWQsIHVzZSBgZmVkZXJhdGVkU2VydmVyc2AgaW5zdGVhZC5cbiAgICAgICAgICpcbiAgICAgICAgICogQGRlcHJlY2F0ZWRcbiAgICAgICAgICovXG4gICAgICAgIGdldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJERVBSRUNBVEVEOiB1c2UgZmVkZXJhdGVkU2VydmVycyBpbnN0ZWFkXCIpO1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuZmVkZXJhdGVkU2VydmVycztcbiAgICAgICAgfSxcbiAgICAgICAgZW51bWVyYWJsZTogZmFsc2UsXG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZVxuICAgIH0pO1xuICAgIC8qKlxuICAgICAqIEJlZ2lucyBhIG5ldyBicm93c2VyLWJhc2VkIE9BdXRoIDIuMCBzaWduIGluLiBJZiBgb3B0aW9ucy5wb3B1cGAgaXMgYHRydWVgIHRoZVxuICAgICAqIGF1dGhlbnRpY2F0aW9uIHdpbmRvdyB3aWxsIG9wZW4gaW4gYSBuZXcgdGFiL3dpbmRvdyBhbmQgdGhlIGZ1bmN0aW9uIHdpbGwgcmV0dXJuXG4gICAgICogUHJvbWlzZSZsdDtVc2VyU2Vzc2lvbiZndDsuIE90aGVyd2lzZSwgdGhlIHVzZXIgd2lsbCBiZSByZWRpcmVjdGVkIHRvIHRoZVxuICAgICAqIGF1dGhvcml6YXRpb24gcGFnZSBpbiB0aGVpciBjdXJyZW50IHRhYi93aW5kb3cgYW5kIHRoZSBmdW5jdGlvbiB3aWxsIHJldHVybiBgdW5kZWZpbmVkYC5cbiAgICAgKlxuICAgICAqIEBicm93c2VyT25seVxuICAgICAqL1xuICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gICAgVXNlclNlc3Npb24uYmVnaW5PQXV0aDIgPSBmdW5jdGlvbiAob3B0aW9ucywgd2luKSB7XG4gICAgICAgIGlmICh3aW4gPT09IHZvaWQgMCkgeyB3aW4gPSB3aW5kb3c7IH1cbiAgICAgICAgaWYgKG9wdGlvbnMuZHVyYXRpb24pIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiREVQUkVDQVRFRDogJ2R1cmF0aW9uJyBpcyBkZXByZWNhdGVkIC0gdXNlICdleHBpcmF0aW9uJyBpbnN0ZWFkXCIpO1xuICAgICAgICB9XG4gICAgICAgIHZhciBfYSA9IF9fYXNzaWduKHtcbiAgICAgICAgICAgIHBvcnRhbDogXCJodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiLFxuICAgICAgICAgICAgcHJvdmlkZXI6IFwiYXJjZ2lzXCIsXG4gICAgICAgICAgICBleHBpcmF0aW9uOiAyMDE2MCxcbiAgICAgICAgICAgIHBvcHVwOiB0cnVlLFxuICAgICAgICAgICAgcG9wdXBXaW5kb3dGZWF0dXJlczogXCJoZWlnaHQ9NDAwLHdpZHRoPTYwMCxtZW51YmFyPW5vLGxvY2F0aW9uPXllcyxyZXNpemFibGU9eWVzLHNjcm9sbGJhcnM9eWVzLHN0YXR1cz15ZXNcIixcbiAgICAgICAgICAgIHN0YXRlOiBvcHRpb25zLmNsaWVudElkLFxuICAgICAgICAgICAgbG9jYWxlOiBcIlwiLFxuICAgICAgICB9LCBvcHRpb25zKSwgcG9ydGFsID0gX2EucG9ydGFsLCBwcm92aWRlciA9IF9hLnByb3ZpZGVyLCBjbGllbnRJZCA9IF9hLmNsaWVudElkLCBleHBpcmF0aW9uID0gX2EuZXhwaXJhdGlvbiwgcmVkaXJlY3RVcmkgPSBfYS5yZWRpcmVjdFVyaSwgcG9wdXAgPSBfYS5wb3B1cCwgcG9wdXBXaW5kb3dGZWF0dXJlcyA9IF9hLnBvcHVwV2luZG93RmVhdHVyZXMsIHN0YXRlID0gX2Euc3RhdGUsIGxvY2FsZSA9IF9hLmxvY2FsZSwgcGFyYW1zID0gX2EucGFyYW1zO1xuICAgICAgICB2YXIgdXJsO1xuICAgICAgICBpZiAocHJvdmlkZXIgPT09IFwiYXJjZ2lzXCIpIHtcbiAgICAgICAgICAgIHVybCA9IHBvcnRhbCArIFwiL29hdXRoMi9hdXRob3JpemU/Y2xpZW50X2lkPVwiICsgY2xpZW50SWQgKyBcIiZyZXNwb25zZV90eXBlPXRva2VuJmV4cGlyYXRpb249XCIgKyAob3B0aW9ucy5kdXJhdGlvbiB8fCBleHBpcmF0aW9uKSArIFwiJnJlZGlyZWN0X3VyaT1cIiArIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSkgKyBcIiZzdGF0ZT1cIiArIHN0YXRlICsgXCImbG9jYWxlPVwiICsgbG9jYWxlO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgdXJsID0gcG9ydGFsICsgXCIvb2F1dGgyL3NvY2lhbC9hdXRob3JpemU/Y2xpZW50X2lkPVwiICsgY2xpZW50SWQgKyBcIiZzb2NpYWxMb2dpblByb3ZpZGVyTmFtZT1cIiArIHByb3ZpZGVyICsgXCImYXV0b0FjY291bnRDcmVhdGVGb3JTb2NpYWw9dHJ1ZSZyZXNwb25zZV90eXBlPXRva2VuJmV4cGlyYXRpb249XCIgKyAob3B0aW9ucy5kdXJhdGlvbiB8fCBleHBpcmF0aW9uKSArIFwiJnJlZGlyZWN0X3VyaT1cIiArIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSkgKyBcIiZzdGF0ZT1cIiArIHN0YXRlICsgXCImbG9jYWxlPVwiICsgbG9jYWxlO1xuICAgICAgICB9XG4gICAgICAgIC8vIGFwcGVuZCBhZGRpdGlvbmFsIHBhcmFtc1xuICAgICAgICBpZiAocGFyYW1zKSB7XG4gICAgICAgICAgICB1cmwgPSB1cmwgKyBcIiZcIiArIGVuY29kZVF1ZXJ5U3RyaW5nKHBhcmFtcyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCFwb3B1cCkge1xuICAgICAgICAgICAgd2luLmxvY2F0aW9uLmhyZWYgPSB1cmw7XG4gICAgICAgICAgICByZXR1cm4gdW5kZWZpbmVkO1xuICAgICAgICB9XG4gICAgICAgIHZhciBzZXNzaW9uID0gZGVmZXIoKTtcbiAgICAgICAgd2luW1wiX19FU1JJX1JFU1RfQVVUSF9IQU5ETEVSX1wiICsgY2xpZW50SWRdID0gZnVuY3Rpb24gKGVycm9yU3RyaW5nLCBvYXV0aEluZm9TdHJpbmcpIHtcbiAgICAgICAgICAgIGlmIChlcnJvclN0cmluZykge1xuICAgICAgICAgICAgICAgIHZhciBlcnJvciA9IEpTT04ucGFyc2UoZXJyb3JTdHJpbmcpO1xuICAgICAgICAgICAgICAgIHNlc3Npb24ucmVqZWN0KG5ldyBBcmNHSVNBdXRoRXJyb3IoZXJyb3IuZXJyb3JNZXNzYWdlLCBlcnJvci5lcnJvcikpO1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmIChvYXV0aEluZm9TdHJpbmcpIHtcbiAgICAgICAgICAgICAgICB2YXIgb2F1dGhJbmZvID0gSlNPTi5wYXJzZShvYXV0aEluZm9TdHJpbmcpO1xuICAgICAgICAgICAgICAgIHNlc3Npb24ucmVzb2x2ZShuZXcgVXNlclNlc3Npb24oe1xuICAgICAgICAgICAgICAgICAgICBjbGllbnRJZDogY2xpZW50SWQsXG4gICAgICAgICAgICAgICAgICAgIHBvcnRhbDogcG9ydGFsLFxuICAgICAgICAgICAgICAgICAgICBzc2w6IG9hdXRoSW5mby5zc2wsXG4gICAgICAgICAgICAgICAgICAgIHRva2VuOiBvYXV0aEluZm8udG9rZW4sXG4gICAgICAgICAgICAgICAgICAgIHRva2VuRXhwaXJlczogbmV3IERhdGUob2F1dGhJbmZvLmV4cGlyZXMpLFxuICAgICAgICAgICAgICAgICAgICB1c2VybmFtZTogb2F1dGhJbmZvLnVzZXJuYW1lLFxuICAgICAgICAgICAgICAgIH0pKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICAgICAgd2luLm9wZW4odXJsLCBcIm9hdXRoLXdpbmRvd1wiLCBwb3B1cFdpbmRvd0ZlYXR1cmVzKTtcbiAgICAgICAgcmV0dXJuIHNlc3Npb24ucHJvbWlzZTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIENvbXBsZXRlcyBhIGJyb3dzZXItYmFzZWQgT0F1dGggMi4wIHNpZ24gaW4uIElmIGBvcHRpb25zLnBvcHVwYCBpcyBgdHJ1ZWAgdGhlIHVzZXJcbiAgICAgKiB3aWxsIGJlIHJldHVybmVkIHRvIHRoZSBwcmV2aW91cyB3aW5kb3cuIE90aGVyd2lzZSBhIG5ldyBgVXNlclNlc3Npb25gXG4gICAgICogd2lsbCBiZSByZXR1cm5lZC4gWW91IG11c3QgcGFzcyB0aGUgc2FtZSB2YWx1ZXMgZm9yIGBvcHRpb25zLnBvcHVwYCBhbmRcbiAgICAgKiBgb3B0aW9ucy5wb3J0YWxgIGFzIHlvdSB1c2VkIGluIGBiZWdpbk9BdXRoMigpYC5cbiAgICAgKlxuICAgICAqIEBicm93c2VyT25seVxuICAgICAqL1xuICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gICAgVXNlclNlc3Npb24uY29tcGxldGVPQXV0aDIgPSBmdW5jdGlvbiAob3B0aW9ucywgd2luKSB7XG4gICAgICAgIGlmICh3aW4gPT09IHZvaWQgMCkgeyB3aW4gPSB3aW5kb3c7IH1cbiAgICAgICAgdmFyIF9hID0gX19hc3NpZ24oeyBwb3J0YWw6IFwiaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIiwgcG9wdXA6IHRydWUgfSwgb3B0aW9ucyksIHBvcnRhbCA9IF9hLnBvcnRhbCwgY2xpZW50SWQgPSBfYS5jbGllbnRJZCwgcG9wdXAgPSBfYS5wb3B1cDtcbiAgICAgICAgZnVuY3Rpb24gY29tcGxldGVTaWduSW4oZXJyb3IsIG9hdXRoSW5mbykge1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICB2YXIgaGFuZGxlckZuID0gdm9pZCAwO1xuICAgICAgICAgICAgICAgIHZhciBoYW5kbGVyRm5OYW1lID0gXCJfX0VTUklfUkVTVF9BVVRIX0hBTkRMRVJfXCIgKyBjbGllbnRJZDtcbiAgICAgICAgICAgICAgICBpZiAocG9wdXApIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gR3VhcmQgYi9jIElFIGRvZXMgbm90IHN1cHBvcnQgd2luZG93Lm9wZW5lclxuICAgICAgICAgICAgICAgICAgICBpZiAod2luLm9wZW5lcikge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHdpbi5vcGVuZXIucGFyZW50ICYmIHdpbi5vcGVuZXIucGFyZW50W2hhbmRsZXJGbk5hbWVdKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaGFuZGxlckZuID0gd2luLm9wZW5lci5wYXJlbnRbaGFuZGxlckZuTmFtZV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlIGlmICh3aW4ub3BlbmVyICYmIHdpbi5vcGVuZXJbaGFuZGxlckZuTmFtZV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBzdXBwb3J0IHBvcC1vdXQgb2F1dGggZnJvbSB3aXRoaW4gYW4gaWZyYW1lXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaGFuZGxlckZuID0gd2luLm9wZW5lcltoYW5kbGVyRm5OYW1lXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIElFXG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAod2luICE9PSB3aW4ucGFyZW50ICYmIHdpbi5wYXJlbnQgJiYgd2luLnBhcmVudFtoYW5kbGVyRm5OYW1lXSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhhbmRsZXJGbiA9IHdpbi5wYXJlbnRbaGFuZGxlckZuTmFtZV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgLy8gaWYgd2UgaGF2ZSBhIGhhbmRsZXIgZm4sIGNhbGwgaXQgYW5kIGNsb3NlIHRoZSB3aW5kb3dcbiAgICAgICAgICAgICAgICAgICAgaWYgKGhhbmRsZXJGbikge1xuICAgICAgICAgICAgICAgICAgICAgICAgaGFuZGxlckZuKGVycm9yID8gSlNPTi5zdHJpbmdpZnkoZXJyb3IpIDogdW5kZWZpbmVkLCBKU09OLnN0cmluZ2lmeShvYXV0aEluZm8pKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHdpbi5jbG9zZSgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEFyY0dJU0F1dGhFcnJvcihcIlVuYWJsZSB0byBjb21wbGV0ZSBhdXRoZW50aWNhdGlvbi4gSXQncyBwb3NzaWJsZSB5b3Ugc3BlY2lmaWVkIHBvcHVwIGJhc2VkIG9BdXRoMiBidXQgbm8gaGFuZGxlciBmcm9tIFxcXCJiZWdpbk9BdXRoMigpXFxcIiBwcmVzZW50LiBUaGlzIGdlbmVyYWxseSBoYXBwZW5zIGJlY2F1c2UgdGhlIFxcXCJwb3B1cFxcXCIgb3B0aW9uIGRpZmZlcnMgYmV0d2VlbiBcXFwiYmVnaW5PQXV0aDIoKVxcXCIgYW5kIFxcXCJjb21wbGV0ZU9BdXRoMigpXFxcIi5cIik7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoZXJyb3IpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgQXJjR0lTQXV0aEVycm9yKGVycm9yLmVycm9yTWVzc2FnZSwgZXJyb3IuZXJyb3IpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIG5ldyBVc2VyU2Vzc2lvbih7XG4gICAgICAgICAgICAgICAgY2xpZW50SWQ6IGNsaWVudElkLFxuICAgICAgICAgICAgICAgIHBvcnRhbDogcG9ydGFsLFxuICAgICAgICAgICAgICAgIHNzbDogb2F1dGhJbmZvLnNzbCxcbiAgICAgICAgICAgICAgICB0b2tlbjogb2F1dGhJbmZvLnRva2VuLFxuICAgICAgICAgICAgICAgIHRva2VuRXhwaXJlczogb2F1dGhJbmZvLmV4cGlyZXMsXG4gICAgICAgICAgICAgICAgdXNlcm5hbWU6IG9hdXRoSW5mby51c2VybmFtZSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICAgIHZhciBwYXJhbXMgPSBkZWNvZGVRdWVyeVN0cmluZyh3aW4ubG9jYXRpb24uaGFzaCk7XG4gICAgICAgIGlmICghcGFyYW1zLmFjY2Vzc190b2tlbikge1xuICAgICAgICAgICAgdmFyIGVycm9yID0gdm9pZCAwO1xuICAgICAgICAgICAgdmFyIGVycm9yTWVzc2FnZSA9IFwiVW5rbm93biBlcnJvclwiO1xuICAgICAgICAgICAgaWYgKHBhcmFtcy5lcnJvcikge1xuICAgICAgICAgICAgICAgIGVycm9yID0gcGFyYW1zLmVycm9yO1xuICAgICAgICAgICAgICAgIGVycm9yTWVzc2FnZSA9IHBhcmFtcy5lcnJvcl9kZXNjcmlwdGlvbjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBjb21wbGV0ZVNpZ25Jbih7IGVycm9yOiBlcnJvciwgZXJyb3JNZXNzYWdlOiBlcnJvck1lc3NhZ2UgfSk7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIHRva2VuID0gcGFyYW1zLmFjY2Vzc190b2tlbjtcbiAgICAgICAgdmFyIGV4cGlyZXMgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgcGFyc2VJbnQocGFyYW1zLmV4cGlyZXNfaW4sIDEwKSAqIDEwMDAgLSA2MCAqIDEwMDApO1xuICAgICAgICB2YXIgdXNlcm5hbWUgPSBwYXJhbXMudXNlcm5hbWU7XG4gICAgICAgIHZhciBzc2wgPSBwYXJhbXMuc3NsID09PSBcInRydWVcIjtcbiAgICAgICAgcmV0dXJuIGNvbXBsZXRlU2lnbkluKHVuZGVmaW5lZCwge1xuICAgICAgICAgICAgdG9rZW46IHRva2VuLFxuICAgICAgICAgICAgZXhwaXJlczogZXhwaXJlcyxcbiAgICAgICAgICAgIHNzbDogc3NsLFxuICAgICAgICAgICAgdXNlcm5hbWU6IHVzZXJuYW1lLFxuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJlcXVlc3Qgc2Vzc2lvbiBpbmZvcm1hdGlvbiBmcm9tIHRoZSBwYXJlbnQgYXBwbGljYXRpb25cbiAgICAgKlxuICAgICAqIFdoZW4gYW4gYXBwbGljYXRpb24gaXMgZW1iZWRkZWQgaW50byBhbm90aGVyIGFwcGxpY2F0aW9uIHZpYSBhbiBJRnJhbWUsIHRoZSBlbWJlZGRlZCBhcHAgY2FuXG4gICAgICogdXNlIGB3aW5kb3cucG9zdE1lc3NhZ2VgIHRvIHJlcXVlc3QgY3JlZGVudGlhbHMgZnJvbSB0aGUgaG9zdCBhcHBsaWNhdGlvbi4gVGhpcyBmdW5jdGlvbiB3cmFwc1xuICAgICAqIHRoYXQgYmVoYXZpb3IuXG4gICAgICpcbiAgICAgKiBUaGUgQXJjR0lTIEFQSSBmb3IgSmF2YXNjcmlwdCBoYXMgdGhpcyBidWlsdCBpbnRvIHRoZSBJZGVudGl0eSBNYW5hZ2VyIGFzIG9mIHRoZSA0LjE5IHJlbGVhc2UuXG4gICAgICpcbiAgICAgKiBOb3RlOiBUaGUgcGFyZW50IGFwcGxpY2F0aW9uIHdpbGwgbm90IHJlc3BvbmQgaWYgdGhlIGVtYmVkZGVkIGFwcCdzIG9yaWdpbiBpcyBub3Q6XG4gICAgICogLSB0aGUgc2FtZSBvcmlnaW4gYXMgdGhlIHBhcmVudCBvciAqLmFyY2dpcy5jb20gKEpTQVBJKVxuICAgICAqIC0gaW4gdGhlIGxpc3Qgb2YgdmFsaWQgY2hpbGQgb3JpZ2lucyAoUkVTVC1KUylcbiAgICAgKlxuICAgICAqXG4gICAgICogQHBhcmFtIHBhcmVudE9yaWdpbiBvcmlnaW4gb2YgdGhlIHBhcmVudCBmcmFtZS4gUGFzc2VkIGludG8gdGhlIGVtYmVkZGVkIGFwcGxpY2F0aW9uIGFzIGBwYXJlbnRPcmlnaW5gIHF1ZXJ5IHBhcmFtXG4gICAgICogQGJyb3dzZXJPbmx5XG4gICAgICovXG4gICAgVXNlclNlc3Npb24uZnJvbVBhcmVudCA9IGZ1bmN0aW9uIChwYXJlbnRPcmlnaW4sIHdpbikge1xuICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dDogbXVzdCBwYXNzIGluIGEgbW9ja3dpbmRvdyBmb3IgdGVzdHMgc28gd2UgY2FuJ3QgY292ZXIgdGhlIG90aGVyIGJyYW5jaCAqL1xuICAgICAgICBpZiAoIXdpbiAmJiB3aW5kb3cpIHtcbiAgICAgICAgICAgIHdpbiA9IHdpbmRvdztcbiAgICAgICAgfVxuICAgICAgICAvLyBEZWNsYXJlIGhhbmRsZXIgb3V0c2lkZSBvZiBwcm9taXNlIHNjb3BlIHNvIHdlIGNhbiBkZXRhY2ggaXRcbiAgICAgICAgdmFyIGhhbmRsZXI7XG4gICAgICAgIC8vIHJldHVybiBhIHByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2hlbiB0aGUgaGFuZGxlciByZWNlaXZlc1xuICAgICAgICAvLyBzZXNzaW9uIGluZm9ybWF0aW9uIGZyb20gdGhlIGNvcnJlY3Qgb3JpZ2luXG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XG4gICAgICAgICAgICAvLyBjcmVhdGUgYW4gZXZlbnQgaGFuZGxlciB0aGF0IGp1c3Qgd3JhcHMgdGhlIHBhcmVudE1lc3NhZ2VIYW5kbGVyXG4gICAgICAgICAgICBoYW5kbGVyID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgICAgICAgICAgLy8gZW5zdXJlIHdlIG9ubHkgbGlzdGVuIHRvIGV2ZW50cyBmcm9tIHRoZSBwYXJlbnRcbiAgICAgICAgICAgICAgICBpZiAoZXZlbnQuc291cmNlID09PSB3aW4ucGFyZW50ICYmIGV2ZW50LmRhdGEpIHtcbiAgICAgICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZXNvbHZlKFVzZXJTZXNzaW9uLnBhcmVudE1lc3NhZ2VIYW5kbGVyKGV2ZW50KSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGVycikge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIC8vIGFkZCBsaXN0ZW5lclxuICAgICAgICAgICAgd2luLmFkZEV2ZW50TGlzdGVuZXIoXCJtZXNzYWdlXCIsIGhhbmRsZXIsIGZhbHNlKTtcbiAgICAgICAgICAgIHdpbi5wYXJlbnQucG9zdE1lc3NhZ2UoeyB0eXBlOiBcImFyY2dpczphdXRoOnJlcXVlc3RDcmVkZW50aWFsXCIgfSwgcGFyZW50T3JpZ2luKTtcbiAgICAgICAgfSkudGhlbihmdW5jdGlvbiAoc2Vzc2lvbikge1xuICAgICAgICAgICAgd2luLnJlbW92ZUV2ZW50TGlzdGVuZXIoXCJtZXNzYWdlXCIsIGhhbmRsZXIsIGZhbHNlKTtcbiAgICAgICAgICAgIHJldHVybiBzZXNzaW9uO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEJlZ2lucyBhIG5ldyBzZXJ2ZXItYmFzZWQgT0F1dGggMi4wIHNpZ24gaW4uIFRoaXMgd2lsbCByZWRpcmVjdCB0aGUgdXNlciB0b1xuICAgICAqIHRoZSBBcmNHSVMgT25saW5lIG9yIEFyY0dJUyBFbnRlcnByaXNlIGF1dGhvcml6YXRpb24gcGFnZS5cbiAgICAgKlxuICAgICAqIEBub2RlT25seVxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLmF1dGhvcml6ZSA9IGZ1bmN0aW9uIChvcHRpb25zLCByZXNwb25zZSkge1xuICAgICAgICBpZiAob3B0aW9ucy5kdXJhdGlvbikge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJERVBSRUNBVEVEOiAnZHVyYXRpb24nIGlzIGRlcHJlY2F0ZWQgLSB1c2UgJ2V4cGlyYXRpb24nIGluc3RlYWRcIik7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIF9hID0gX19hc3NpZ24oeyBwb3J0YWw6IFwiaHR0cHM6Ly9hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiLCBleHBpcmF0aW9uOiAyMDE2MCB9LCBvcHRpb25zKSwgcG9ydGFsID0gX2EucG9ydGFsLCBjbGllbnRJZCA9IF9hLmNsaWVudElkLCBleHBpcmF0aW9uID0gX2EuZXhwaXJhdGlvbiwgcmVkaXJlY3RVcmkgPSBfYS5yZWRpcmVjdFVyaTtcbiAgICAgICAgcmVzcG9uc2Uud3JpdGVIZWFkKDMwMSwge1xuICAgICAgICAgICAgTG9jYXRpb246IHBvcnRhbCArIFwiL29hdXRoMi9hdXRob3JpemU/Y2xpZW50X2lkPVwiICsgY2xpZW50SWQgKyBcIiZleHBpcmF0aW9uPVwiICsgKG9wdGlvbnMuZHVyYXRpb24gfHwgZXhwaXJhdGlvbikgKyBcIiZyZXNwb25zZV90eXBlPWNvZGUmcmVkaXJlY3RfdXJpPVwiICsgZW5jb2RlVVJJQ29tcG9uZW50KHJlZGlyZWN0VXJpKSxcbiAgICAgICAgfSk7XG4gICAgICAgIHJlc3BvbnNlLmVuZCgpO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogQ29tcGxldGVzIHRoZSBzZXJ2ZXItYmFzZWQgT0F1dGggMi4wIHNpZ24gaW4gcHJvY2VzcyBieSBleGNoYW5naW5nIHRoZSBgYXV0aG9yaXphdGlvbkNvZGVgXG4gICAgICogZm9yIGEgYGFjY2Vzc190b2tlbmAuXG4gICAgICpcbiAgICAgKiBAbm9kZU9ubHlcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5leGNoYW5nZUF1dGhvcml6YXRpb25Db2RlID0gZnVuY3Rpb24gKG9wdGlvbnMsIGF1dGhvcml6YXRpb25Db2RlKSB7XG4gICAgICAgIHZhciBfYSA9IF9fYXNzaWduKHtcbiAgICAgICAgICAgIHBvcnRhbDogXCJodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuVFRMOiAyMDE2MCxcbiAgICAgICAgfSwgb3B0aW9ucyksIHBvcnRhbCA9IF9hLnBvcnRhbCwgY2xpZW50SWQgPSBfYS5jbGllbnRJZCwgcmVkaXJlY3RVcmkgPSBfYS5yZWRpcmVjdFVyaSwgcmVmcmVzaFRva2VuVFRMID0gX2EucmVmcmVzaFRva2VuVFRMO1xuICAgICAgICByZXR1cm4gZmV0Y2hUb2tlbihwb3J0YWwgKyBcIi9vYXV0aDIvdG9rZW5cIiwge1xuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgZ3JhbnRfdHlwZTogXCJhdXRob3JpemF0aW9uX2NvZGVcIixcbiAgICAgICAgICAgICAgICBjbGllbnRfaWQ6IGNsaWVudElkLFxuICAgICAgICAgICAgICAgIHJlZGlyZWN0X3VyaTogcmVkaXJlY3RVcmksXG4gICAgICAgICAgICAgICAgY29kZTogYXV0aG9yaXphdGlvbkNvZGUsXG4gICAgICAgICAgICB9LFxuICAgICAgICB9KS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBVc2VyU2Vzc2lvbih7XG4gICAgICAgICAgICAgICAgY2xpZW50SWQ6IGNsaWVudElkLFxuICAgICAgICAgICAgICAgIHBvcnRhbDogcG9ydGFsLFxuICAgICAgICAgICAgICAgIHNzbDogcmVzcG9uc2Uuc3NsLFxuICAgICAgICAgICAgICAgIHJlZGlyZWN0VXJpOiByZWRpcmVjdFVyaSxcbiAgICAgICAgICAgICAgICByZWZyZXNoVG9rZW46IHJlc3BvbnNlLnJlZnJlc2hUb2tlbixcbiAgICAgICAgICAgICAgICByZWZyZXNoVG9rZW5UVEw6IHJlZnJlc2hUb2tlblRUTCxcbiAgICAgICAgICAgICAgICByZWZyZXNoVG9rZW5FeHBpcmVzOiBuZXcgRGF0ZShEYXRlLm5vdygpICsgKHJlZnJlc2hUb2tlblRUTCAtIDEpICogNjAgKiAxMDAwKSxcbiAgICAgICAgICAgICAgICB0b2tlbjogcmVzcG9uc2UudG9rZW4sXG4gICAgICAgICAgICAgICAgdG9rZW5FeHBpcmVzOiByZXNwb25zZS5leHBpcmVzLFxuICAgICAgICAgICAgICAgIHVzZXJuYW1lOiByZXNwb25zZS51c2VybmFtZSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIFVzZXJTZXNzaW9uLmRlc2VyaWFsaXplID0gZnVuY3Rpb24gKHN0cikge1xuICAgICAgICB2YXIgb3B0aW9ucyA9IEpTT04ucGFyc2Uoc3RyKTtcbiAgICAgICAgcmV0dXJuIG5ldyBVc2VyU2Vzc2lvbih7XG4gICAgICAgICAgICBjbGllbnRJZDogb3B0aW9ucy5jbGllbnRJZCxcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlbjogb3B0aW9ucy5yZWZyZXNoVG9rZW4sXG4gICAgICAgICAgICByZWZyZXNoVG9rZW5FeHBpcmVzOiBuZXcgRGF0ZShvcHRpb25zLnJlZnJlc2hUb2tlbkV4cGlyZXMpLFxuICAgICAgICAgICAgdXNlcm5hbWU6IG9wdGlvbnMudXNlcm5hbWUsXG4gICAgICAgICAgICBwYXNzd29yZDogb3B0aW9ucy5wYXNzd29yZCxcbiAgICAgICAgICAgIHRva2VuOiBvcHRpb25zLnRva2VuLFxuICAgICAgICAgICAgdG9rZW5FeHBpcmVzOiBuZXcgRGF0ZShvcHRpb25zLnRva2VuRXhwaXJlcyksXG4gICAgICAgICAgICBwb3J0YWw6IG9wdGlvbnMucG9ydGFsLFxuICAgICAgICAgICAgc3NsOiBvcHRpb25zLnNzbCxcbiAgICAgICAgICAgIHRva2VuRHVyYXRpb246IG9wdGlvbnMudG9rZW5EdXJhdGlvbixcbiAgICAgICAgICAgIHJlZGlyZWN0VXJpOiBvcHRpb25zLnJlZGlyZWN0VXJpLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuVFRMOiBvcHRpb25zLnJlZnJlc2hUb2tlblRUTCxcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBUcmFuc2xhdGVzIGF1dGhlbnRpY2F0aW9uIGZyb20gdGhlIGZvcm1hdCB1c2VkIGluIHRoZSBbQXJjR0lTIEFQSSBmb3IgSmF2YVNjcmlwdF0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vamF2YXNjcmlwdC8pLlxuICAgICAqXG4gICAgICogYGBganNcbiAgICAgKiBVc2VyU2Vzc2lvbi5mcm9tQ3JlZGVudGlhbCh7XG4gICAgICogICB1c2VySWQ6IFwianNtaXRoXCIsXG4gICAgICogICB0b2tlbjogXCJzZWNyZXRcIlxuICAgICAqIH0pO1xuICAgICAqIGBgYFxuICAgICAqXG4gICAgICogQHJldHVybnMgVXNlclNlc3Npb25cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5mcm9tQ3JlZGVudGlhbCA9IGZ1bmN0aW9uIChjcmVkZW50aWFsKSB7XG4gICAgICAgIC8vIEF0IEFyY0dJUyBPbmxpbmUgOS4xLCBjcmVkZW50aWFscyBubyBsb25nZXIgaW5jbHVkZSB0aGUgc3NsIGFuZCBleHBpcmVzIHByb3BlcnRpZXNcbiAgICAgICAgLy8gSGVyZSwgd2UgcHJvdmlkZSBkZWZhdWx0IHZhbHVlcyBmb3IgdGhlbSB0byBjb3ZlciB0aGlzIGNvbmRpdGlvblxuICAgICAgICB2YXIgc3NsID0gdHlwZW9mIGNyZWRlbnRpYWwuc3NsICE9PSBcInVuZGVmaW5lZFwiID8gY3JlZGVudGlhbC5zc2wgOiB0cnVlO1xuICAgICAgICB2YXIgZXhwaXJlcyA9IGNyZWRlbnRpYWwuZXhwaXJlcyB8fCBEYXRlLm5vdygpICsgNzIwMDAwMDsgLyogMiBob3VycyAqL1xuICAgICAgICByZXR1cm4gbmV3IFVzZXJTZXNzaW9uKHtcbiAgICAgICAgICAgIHBvcnRhbDogY3JlZGVudGlhbC5zZXJ2ZXIuaW5jbHVkZXMoXCJzaGFyaW5nL3Jlc3RcIilcbiAgICAgICAgICAgICAgICA/IGNyZWRlbnRpYWwuc2VydmVyXG4gICAgICAgICAgICAgICAgOiBjcmVkZW50aWFsLnNlcnZlciArIFwiL3NoYXJpbmcvcmVzdFwiLFxuICAgICAgICAgICAgc3NsOiBzc2wsXG4gICAgICAgICAgICB0b2tlbjogY3JlZGVudGlhbC50b2tlbixcbiAgICAgICAgICAgIHVzZXJuYW1lOiBjcmVkZW50aWFsLnVzZXJJZCxcbiAgICAgICAgICAgIHRva2VuRXhwaXJlczogbmV3IERhdGUoZXhwaXJlcyksXG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogSGFuZGxlIHRoZSByZXNwb25zZSBmcm9tIHRoZSBwYXJlbnRcbiAgICAgKiBAcGFyYW0gZXZlbnQgRE9NIEV2ZW50XG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucGFyZW50TWVzc2FnZUhhbmRsZXIgPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgaWYgKGV2ZW50LmRhdGEudHlwZSA9PT0gXCJhcmNnaXM6YXV0aDpjcmVkZW50aWFsXCIpIHtcbiAgICAgICAgICAgIHJldHVybiBVc2VyU2Vzc2lvbi5mcm9tQ3JlZGVudGlhbChldmVudC5kYXRhLmNyZWRlbnRpYWwpO1xuICAgICAgICB9XG4gICAgICAgIGlmIChldmVudC5kYXRhLnR5cGUgPT09IFwiYXJjZ2lzOmF1dGg6ZXJyb3JcIikge1xuICAgICAgICAgICAgdmFyIGVyciA9IG5ldyBFcnJvcihldmVudC5kYXRhLmVycm9yLm1lc3NhZ2UpO1xuICAgICAgICAgICAgZXJyLm5hbWUgPSBldmVudC5kYXRhLmVycm9yLm5hbWU7XG4gICAgICAgICAgICB0aHJvdyBlcnI7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJVbmtub3duIG1lc3NhZ2UgdHlwZS5cIik7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgYXV0aGVudGljYXRpb24gaW4gYSBmb3JtYXQgdXNlYWJsZSBpbiB0aGUgW0FyY0dJUyBBUEkgZm9yIEphdmFTY3JpcHRdKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL2phdmFzY3JpcHQvKS5cbiAgICAgKlxuICAgICAqIGBgYGpzXG4gICAgICogZXNyaUlkLnJlZ2lzdGVyVG9rZW4oc2Vzc2lvbi50b0NyZWRlbnRpYWwoKSk7XG4gICAgICogYGBgXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyBJQ3JlZGVudGlhbFxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS50b0NyZWRlbnRpYWwgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBleHBpcmVzOiB0aGlzLnRva2VuRXhwaXJlcy5nZXRUaW1lKCksXG4gICAgICAgICAgICBzZXJ2ZXI6IHRoaXMucG9ydGFsLFxuICAgICAgICAgICAgc3NsOiB0aGlzLnNzbCxcbiAgICAgICAgICAgIHRva2VuOiB0aGlzLnRva2VuLFxuICAgICAgICAgICAgdXNlcklkOiB0aGlzLnVzZXJuYW1lLFxuICAgICAgICB9O1xuICAgIH07XG4gICAgLyoqXG4gICAgICogUmV0dXJucyBpbmZvcm1hdGlvbiBhYm91dCB0aGUgY3VycmVudGx5IGxvZ2dlZCBpbiBbdXNlcl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC91c2Vycy1ncm91cHMtYW5kLWl0ZW1zL3VzZXIuaHRtKS4gU3Vic2VxdWVudCBjYWxscyB3aWxsICpub3QqIHJlc3VsdCBpbiBhZGRpdGlvbmFsIHdlYiB0cmFmZmljLlxuICAgICAqXG4gICAgICogYGBganNcbiAgICAgKiBzZXNzaW9uLmdldFVzZXIoKVxuICAgICAqICAgLnRoZW4ocmVzcG9uc2UgPT4ge1xuICAgICAqICAgICBjb25zb2xlLmxvZyhyZXNwb25zZS5yb2xlKTsgLy8gXCJvcmdfYWRtaW5cIlxuICAgICAqICAgfSlcbiAgICAgKiBgYGBcbiAgICAgKlxuICAgICAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0LiBOT1RFOiBgcmF3UmVzcG9uc2VgIGlzIG5vdCBzdXBwb3J0ZWQgYnkgdGhpcyBvcGVyYXRpb24uXG4gICAgICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIGRhdGEgZnJvbSB0aGUgcmVzcG9uc2UuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFVzZXIgPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgaWYgKHRoaXMuX3BlbmRpbmdVc2VyUmVxdWVzdCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdVc2VyUmVxdWVzdDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICh0aGlzLl91c2VyKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMuX3VzZXIpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgdmFyIHVybCA9IHRoaXMucG9ydGFsICsgXCIvY29tbXVuaXR5L3NlbGZcIjtcbiAgICAgICAgICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oX19hc3NpZ24oeyBodHRwTWV0aG9kOiBcIkdFVFwiLCBhdXRoZW50aWNhdGlvbjogdGhpcyB9LCByZXF1ZXN0T3B0aW9ucyksIHsgcmF3UmVzcG9uc2U6IGZhbHNlIH0pO1xuICAgICAgICAgICAgdGhpcy5fcGVuZGluZ1VzZXJSZXF1ZXN0ID0gcmVxdWVzdCh1cmwsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMuX3VzZXIgPSByZXNwb25zZTtcbiAgICAgICAgICAgICAgICBfdGhpcy5fcGVuZGluZ1VzZXJSZXF1ZXN0ID0gbnVsbDtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nVXNlclJlcXVlc3Q7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgaW5mb3JtYXRpb24gYWJvdXQgdGhlIGN1cnJlbnRseSBsb2dnZWQgaW4gdXNlcidzIFtwb3J0YWxdKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3QvdXNlcnMtZ3JvdXBzLWFuZC1pdGVtcy9wb3J0YWwtc2VsZi5odG0pLiBTdWJzZXF1ZW50IGNhbGxzIHdpbGwgKm5vdCogcmVzdWx0IGluIGFkZGl0aW9uYWwgd2ViIHRyYWZmaWMuXG4gICAgICpcbiAgICAgKiBgYGBqc1xuICAgICAqIHNlc3Npb24uZ2V0UG9ydGFsKClcbiAgICAgKiAgIC50aGVuKHJlc3BvbnNlID0+IHtcbiAgICAgKiAgICAgY29uc29sZS5sb2cocG9ydGFsLm5hbWUpOyAvLyBcIkNpdHkgb2YgLi4uXCJcbiAgICAgKiAgIH0pXG4gICAgICogYGBgXG4gICAgICpcbiAgICAgKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdC4gTk9URTogYHJhd1Jlc3BvbnNlYCBpcyBub3Qgc3VwcG9ydGVkIGJ5IHRoaXMgb3BlcmF0aW9uLlxuICAgICAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBkYXRhIGZyb20gdGhlIHJlc3BvbnNlLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRQb3J0YWwgPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgaWYgKHRoaXMuX3BlbmRpbmdQb3J0YWxSZXF1ZXN0KSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1BvcnRhbFJlcXVlc3Q7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAodGhpcy5fcG9ydGFsSW5mbykge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzLl9wb3J0YWxJbmZvKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHZhciB1cmwgPSB0aGlzLnBvcnRhbCArIFwiL3BvcnRhbHMvc2VsZlwiO1xuICAgICAgICAgICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbihfX2Fzc2lnbih7IGh0dHBNZXRob2Q6IFwiR0VUXCIsIGF1dGhlbnRpY2F0aW9uOiB0aGlzIH0sIHJlcXVlc3RPcHRpb25zKSwgeyByYXdSZXNwb25zZTogZmFsc2UgfSk7XG4gICAgICAgICAgICB0aGlzLl9wZW5kaW5nUG9ydGFsUmVxdWVzdCA9IHJlcXVlc3QodXJsLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIF90aGlzLl9wb3J0YWxJbmZvID0gcmVzcG9uc2U7XG4gICAgICAgICAgICAgICAgX3RoaXMuX3BlbmRpbmdQb3J0YWxSZXF1ZXN0ID0gbnVsbDtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nUG9ydGFsUmVxdWVzdDtcbiAgICAgICAgfVxuICAgIH07XG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgdXNlcm5hbWUgZm9yIHRoZSBjdXJyZW50bHkgbG9nZ2VkIGluIFt1c2VyXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3VzZXJzLWdyb3Vwcy1hbmQtaXRlbXMvdXNlci5odG0pLiBTdWJzZXF1ZW50IGNhbGxzIHdpbGwgKm5vdCogcmVzdWx0IGluIGFkZGl0aW9uYWwgd2ViIHRyYWZmaWMuIFRoaXMgaXMgYWxzbyB1c2VkIGludGVybmFsbHkgd2hlbiBhIHVzZXJuYW1lIGlzIHJlcXVpcmVkIGZvciBzb21lIHJlcXVlc3RzIGJ1dCBpcyBub3QgcHJlc2VudCBpbiB0aGUgb3B0aW9ucy5cbiAgICAgKlxuICAgICAqICAgICogYGBganNcbiAgICAgKiBzZXNzaW9uLmdldFVzZXJuYW1lKClcbiAgICAgKiAgIC50aGVuKHJlc3BvbnNlID0+IHtcbiAgICAgKiAgICAgY29uc29sZS5sb2cocmVzcG9uc2UpOyAvLyBcImNhc2V5X2pvbmVzXCJcbiAgICAgKiAgIH0pXG4gICAgICogYGBgXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFVzZXJuYW1lID0gZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAodGhpcy51c2VybmFtZSkge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzLnVzZXJuYW1lKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICh0aGlzLl91c2VyKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMuX3VzZXIudXNlcm5hbWUpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuZ2V0VXNlcigpLnRoZW4oZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gdXNlci51c2VybmFtZTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBHZXRzIGFuIGFwcHJvcHJpYXRlIHRva2VuIGZvciB0aGUgZ2l2ZW4gVVJMLiBJZiBgcG9ydGFsYCBpcyBBcmNHSVMgT25saW5lIGFuZFxuICAgICAqIHRoZSByZXF1ZXN0IGlzIHRvIGFuIEFyY0dJUyBPbmxpbmUgZG9tYWluIGB0b2tlbmAgd2lsbCBiZSB1c2VkLiBJZiB0aGUgcmVxdWVzdFxuICAgICAqIGlzIHRvIHRoZSBjdXJyZW50IGBwb3J0YWxgIHRoZSBjdXJyZW50IGB0b2tlbmAgd2lsbCBhbHNvIGJlIHVzZWQuIEhvd2V2ZXIgaWZcbiAgICAgKiB0aGUgcmVxdWVzdCBpcyB0byBhbiB1bmtub3duIHNlcnZlciB3ZSB3aWxsIHZhbGlkYXRlIHRoZSBzZXJ2ZXIgd2l0aCBhIHJlcXVlc3RcbiAgICAgKiB0byBvdXIgY3VycmVudCBgcG9ydGFsYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0VG9rZW4gPSBmdW5jdGlvbiAodXJsLCByZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICBpZiAoY2FuVXNlT25saW5lVG9rZW4odGhpcy5wb3J0YWwsIHVybCkpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmdldEZyZXNoVG9rZW4ocmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKG5ldyBSZWdFeHAodGhpcy5wb3J0YWwsIFwiaVwiKS50ZXN0KHVybCkpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmdldEZyZXNoVG9rZW4ocmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuZ2V0VG9rZW5Gb3JTZXJ2ZXIodXJsLCByZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEdldCBhcHBsaWNhdGlvbiBhY2Nlc3MgaW5mb3JtYXRpb24gZm9yIHRoZSBjdXJyZW50IHVzZXJcbiAgICAgKiBzZWUgYHZhbGlkYXRlQXBwQWNjZXNzYCBmdW5jdGlvbiBmb3IgZGV0YWlsc1xuICAgICAqXG4gICAgICogQHBhcmFtIGNsaWVudElkIGFwcGxpY2F0aW9uIGNsaWVudCBpZFxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS52YWxpZGF0ZUFwcEFjY2VzcyA9IGZ1bmN0aW9uIChjbGllbnRJZCkge1xuICAgICAgICByZXR1cm4gdGhpcy5nZXRUb2tlbih0aGlzLnBvcnRhbCkudGhlbihmdW5jdGlvbiAodG9rZW4pIHtcbiAgICAgICAgICAgIHJldHVybiB2YWxpZGF0ZUFwcEFjY2Vzcyh0b2tlbiwgY2xpZW50SWQpO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS50b0pTT04gPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBjbGllbnRJZDogdGhpcy5jbGllbnRJZCxcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlbjogdGhpcy5yZWZyZXNoVG9rZW4sXG4gICAgICAgICAgICByZWZyZXNoVG9rZW5FeHBpcmVzOiB0aGlzLnJlZnJlc2hUb2tlbkV4cGlyZXMsXG4gICAgICAgICAgICB1c2VybmFtZTogdGhpcy51c2VybmFtZSxcbiAgICAgICAgICAgIHBhc3N3b3JkOiB0aGlzLnBhc3N3b3JkLFxuICAgICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgICB0b2tlbkV4cGlyZXM6IHRoaXMudG9rZW5FeHBpcmVzLFxuICAgICAgICAgICAgcG9ydGFsOiB0aGlzLnBvcnRhbCxcbiAgICAgICAgICAgIHNzbDogdGhpcy5zc2wsXG4gICAgICAgICAgICB0b2tlbkR1cmF0aW9uOiB0aGlzLnRva2VuRHVyYXRpb24sXG4gICAgICAgICAgICByZWRpcmVjdFVyaTogdGhpcy5yZWRpcmVjdFVyaSxcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlblRUTDogdGhpcy5yZWZyZXNoVG9rZW5UVEwsXG4gICAgICAgIH07XG4gICAgfTtcbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuc2VyaWFsaXplID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkodGhpcyk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBGb3IgYSBcIkhvc3RcIiBhcHAgdGhhdCBlbWJlZHMgb3RoZXIgcGxhdGZvcm0gYXBwcyB2aWEgaWZyYW1lcywgYWZ0ZXIgYXV0aGVudGljYXRpbmcgdGhlIHVzZXJcbiAgICAgKiBhbmQgY3JlYXRpbmcgYSBVc2VyU2Vzc2lvbiwgdGhlIGFwcCBjYW4gdGhlbiBlbmFibGUgXCJwb3N0IG1lc3NhZ2VcIiBzdHlsZSBhdXRoZW50aWNhdGlvbiBieSBjYWxsaW5nXG4gICAgICogdGhpcyBtZXRob2QuXG4gICAgICpcbiAgICAgKiBJbnRlcm5hbGx5IHRoaXMgYWRkcyBhbiBldmVudCBsaXN0ZW5lciBvbiB3aW5kb3cgZm9yIHRoZSBgbWVzc2FnZWAgZXZlbnRcbiAgICAgKlxuICAgICAqIEBwYXJhbSB2YWxpZENoaWxkT3JpZ2lucyBBcnJheSBvZiBvcmlnaW5zIHRoYXQgYXJlIGFsbG93ZWQgdG8gcmVxdWVzdCBhdXRoZW50aWNhdGlvbiBmcm9tIHRoZSBob3N0IGFwcFxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5lbmFibGVQb3N0TWVzc2FnZUF1dGggPSBmdW5jdGlvbiAodmFsaWRDaGlsZE9yaWdpbnMsIHdpbikge1xuICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dDogbXVzdCBwYXNzIGluIGEgbW9ja3dpbmRvdyBmb3IgdGVzdHMgc28gd2UgY2FuJ3QgY292ZXIgdGhlIG90aGVyIGJyYW5jaCAqL1xuICAgICAgICBpZiAoIXdpbiAmJiB3aW5kb3cpIHtcbiAgICAgICAgICAgIHdpbiA9IHdpbmRvdztcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9ob3N0SGFuZGxlciA9IHRoaXMuY3JlYXRlUG9zdE1lc3NhZ2VIYW5kbGVyKHZhbGlkQ2hpbGRPcmlnaW5zKTtcbiAgICAgICAgd2luLmFkZEV2ZW50TGlzdGVuZXIoXCJtZXNzYWdlXCIsIHRoaXMuX2hvc3RIYW5kbGVyLCBmYWxzZSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBGb3IgYSBcIkhvc3RcIiBhcHAgdGhhdCBoYXMgZW1iZWRkZWQgb3RoZXIgcGxhdGZvcm0gYXBwcyB2aWEgaWZyYW1lcywgd2hlbiB0aGUgaG9zdCBuZWVkc1xuICAgICAqIHRvIHRyYW5zaXRpb24gcm91dGVzLCBpdCBzaG91bGQgY2FsbCBgVXNlclNlc3Npb24uZGlzYWJsZVBvc3RNZXNzYWdlQXV0aCgpYCB0byByZW1vdmVcbiAgICAgKiB0aGUgZXZlbnQgbGlzdGVuZXIgYW5kIHByZXZlbnQgbWVtb3J5IGxlYWtzXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmRpc2FibGVQb3N0TWVzc2FnZUF1dGggPSBmdW5jdGlvbiAod2luKSB7XG4gICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0OiBtdXN0IHBhc3MgaW4gYSBtb2Nrd2luZG93IGZvciB0ZXN0cyBzbyB3ZSBjYW4ndCBjb3ZlciB0aGUgb3RoZXIgYnJhbmNoICovXG4gICAgICAgIGlmICghd2luICYmIHdpbmRvdykge1xuICAgICAgICAgICAgd2luID0gd2luZG93O1xuICAgICAgICB9XG4gICAgICAgIHdpbi5yZW1vdmVFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLCB0aGlzLl9ob3N0SGFuZGxlciwgZmFsc2UpO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogTWFudWFsbHkgcmVmcmVzaGVzIHRoZSBjdXJyZW50IGB0b2tlbmAgYW5kIGB0b2tlbkV4cGlyZXNgLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5yZWZyZXNoU2Vzc2lvbiA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICAvLyBtYWtlIHN1cmUgc3Vic2VxdWVudCBjYWxscyB0byBnZXRVc2VyKCkgZG9uJ3QgcmV0dXJuZWQgY2FjaGVkIG1ldGFkYXRhXG4gICAgICAgIHRoaXMuX3VzZXIgPSBudWxsO1xuICAgICAgICBpZiAodGhpcy51c2VybmFtZSAmJiB0aGlzLnBhc3N3b3JkKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5yZWZyZXNoV2l0aFVzZXJuYW1lQW5kUGFzc3dvcmQocmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLmNsaWVudElkICYmIHRoaXMucmVmcmVzaFRva2VuKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5yZWZyZXNoV2l0aFJlZnJlc2hUb2tlbigpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgQXJjR0lTQXV0aEVycm9yKFwiVW5hYmxlIHRvIHJlZnJlc2ggdG9rZW4uXCIpKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIERldGVybWluZXMgdGhlIHJvb3Qgb2YgdGhlIEFyY0dJUyBTZXJ2ZXIgb3IgUG9ydGFsIGZvciBhIGdpdmVuIFVSTC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB1cmwgdGhlIFVSbCB0byBkZXRlcm1pbmUgdGhlIHJvb3QgdXJsIGZvci5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0U2VydmVyUm9vdFVybCA9IGZ1bmN0aW9uICh1cmwpIHtcbiAgICAgICAgdmFyIHJvb3QgPSBjbGVhblVybCh1cmwpLnNwbGl0KC9cXC9yZXN0KFxcL2FkbWluKT9cXC9zZXJ2aWNlcyg/OlxcL3wjfFxcP3wkKS8pWzBdO1xuICAgICAgICB2YXIgX2EgPSByb290Lm1hdGNoKC8oaHR0cHM/OlxcL1xcLykoLispLyksIG1hdGNoID0gX2FbMF0sIHByb3RvY29sID0gX2FbMV0sIGRvbWFpbkFuZFBhdGggPSBfYVsyXTtcbiAgICAgICAgdmFyIF9iID0gZG9tYWluQW5kUGF0aC5zcGxpdChcIi9cIiksIGRvbWFpbiA9IF9iWzBdLCBwYXRoID0gX2Iuc2xpY2UoMSk7XG4gICAgICAgIC8vIG9ubHkgdGhlIGRvbWFpbiBpcyBsb3dlcmNhc2VkIGJlY2F1c2UgaW4gc29tZSBjYXNlcyBhbiBvcmcgaWQgbWlnaHQgYmVcbiAgICAgICAgLy8gaW4gdGhlIHBhdGggd2hpY2ggY2Fubm90IGJlIGxvd2VyY2FzZWQuXG4gICAgICAgIHJldHVybiBcIlwiICsgcHJvdG9jb2wgKyBkb21haW4udG9Mb3dlckNhc2UoKSArIFwiL1wiICsgcGF0aC5qb2luKFwiL1wiKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIHByb3BlciBbYGNyZWRlbnRpYWxzYF0gb3B0aW9uIGZvciBgZmV0Y2hgIGZvciBhIGdpdmVuIGRvbWFpbi5cbiAgICAgKiBTZWUgW3RydXN0ZWQgc2VydmVyXShodHRwczovL2VudGVycHJpc2UuYXJjZ2lzLmNvbS9lbi9wb3J0YWwvbGF0ZXN0L2FkbWluaXN0ZXIvd2luZG93cy9jb25maWd1cmUtc2VjdXJpdHkuaHRtI0VTUklfU0VDVElPTjFfNzBDQzE1OUIzNTQwNDQwQUIzMjVCRTVEODlEQkU5NEEpLlxuICAgICAqIFVzZWQgaW50ZXJuYWxseSBieSB1bmRlcmx5aW5nIHJlcXVlc3QgbWV0aG9kcyB0byBhZGQgc3VwcG9ydCBmb3Igc3BlY2lmaWMgc2VjdXJpdHkgY29uc2lkZXJhdGlvbnMuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gdXJsIFRoZSB1cmwgb2YgdGhlIHJlcXVlc3RcbiAgICAgKiBAcmV0dXJucyBcImluY2x1ZGVcIiBvciBcInNhbWUtb3JpZ2luXCJcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0RG9tYWluQ3JlZGVudGlhbHMgPSBmdW5jdGlvbiAodXJsKSB7XG4gICAgICAgIGlmICghdGhpcy50cnVzdGVkRG9tYWlucyB8fCAhdGhpcy50cnVzdGVkRG9tYWlucy5sZW5ndGgpIHtcbiAgICAgICAgICAgIHJldHVybiBcInNhbWUtb3JpZ2luXCI7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXMudHJ1c3RlZERvbWFpbnMuc29tZShmdW5jdGlvbiAoZG9tYWluV2l0aFByb3RvY29sKSB7XG4gICAgICAgICAgICByZXR1cm4gdXJsLnN0YXJ0c1dpdGgoZG9tYWluV2l0aFByb3RvY29sKTtcbiAgICAgICAgfSlcbiAgICAgICAgICAgID8gXCJpbmNsdWRlXCJcbiAgICAgICAgICAgIDogXCJzYW1lLW9yaWdpblwiO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogUmV0dXJuIGEgZnVuY3Rpb24gdGhhdCBjbG9zZXMgb3ZlciB0aGUgdmFsaWRPcmlnaW5zIGFycmF5IGFuZFxuICAgICAqIGNhbiBiZSB1c2VkIGFzIGFuIGV2ZW50IGhhbmRsZXIgZm9yIHRoZSBgbWVzc2FnZWAgZXZlbnRcbiAgICAgKlxuICAgICAqIEBwYXJhbSB2YWxpZE9yaWdpbnMgQXJyYXkgb2YgdmFsaWQgb3JpZ2luc1xuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5jcmVhdGVQb3N0TWVzc2FnZUhhbmRsZXIgPSBmdW5jdGlvbiAodmFsaWRPcmlnaW5zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIC8vIHJldHVybiBhIGZ1bmN0aW9uIHRoYXQgY2xvc2VzIG92ZXIgdGhlIHZhbGlkT3JpZ2lucyBhbmRcbiAgICAgICAgLy8gaGFzIGFjY2VzcyB0byB0aGUgY3JlZGVudGlhbFxuICAgICAgICByZXR1cm4gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgICAgICAvLyBWZXJpZnkgdGhhdCB0aGUgb3JpZ2luIGlzIHZhbGlkXG4gICAgICAgICAgICAvLyBOb3RlOiBkbyBub3QgdXNlIHJlZ2V4J3MgaGVyZS4gdmFsaWRPcmlnaW5zIGlzIGFuIGFycmF5IHNvIHdlJ3JlIGNoZWNraW5nIHRoYXQgdGhlIGV2ZW50J3Mgb3JpZ2luXG4gICAgICAgICAgICAvLyBpcyBpbiB0aGUgYXJyYXkgdmlhIGV4YWN0IG1hdGNoLiBNb3JlIGluZm8gYWJvdXQgYXZvaWRpbmcgcG9zdE1lc3NhZ2UgeHNzIGlzc3VlcyBoZXJlXG4gICAgICAgICAgICAvLyBodHRwczovL2psYWphcmEuZ2l0bGFiLmlvL3dlYi8yMDIwLzA3LzE3L0RvbV9YU1NfUG9zdE1lc3NhZ2VfMi5odG1sI3RpcHNieXBhc3Nlcy1pbi1wb3N0bWVzc2FnZS12dWxuZXJhYmlsaXRpZXNcbiAgICAgICAgICAgIHZhciBpc1ZhbGlkT3JpZ2luID0gdmFsaWRPcmlnaW5zLmluZGV4T2YoZXZlbnQub3JpZ2luKSA+IC0xO1xuICAgICAgICAgICAgLy8gSlNBUEkgaGFuZGxlcyB0aGlzIHNsaWdodGx5IGRpZmZlcmVudGx5IC0gaW5zdGVhZCBvZiBjaGVja2luZyBhIGxpc3QsIGl0IHdpbGwgcmVzcG9uZCBpZlxuICAgICAgICAgICAgLy8gZXZlbnQub3JpZ2luID09PSB3aW5kb3cubG9jYXRpb24ub3JpZ2luIHx8IGV2ZW50Lm9yaWdpbi5lbmRzV2l0aCgnLmFyY2dpcy5jb20nKVxuICAgICAgICAgICAgLy8gRm9yIEh1YiwgYW5kIHRvIGVuYWJsZSBjcm9zcyBkb21haW4gZGVidWdnaW5nIHdpdGggcG9ydCdzIGluIHVybHMsIHdlIGFyZSBvcHRpbmcgdG9cbiAgICAgICAgICAgIC8vIHVzZSBhIGxpc3Qgb2YgdmFsaWQgb3JpZ2luc1xuICAgICAgICAgICAgLy8gRW5zdXJlIHRoZSBtZXNzYWdlIHR5cGUgaXMgc29tZXRoaW5nIHdlIHdhbnQgdG8gaGFuZGxlXG4gICAgICAgICAgICB2YXIgaXNWYWxpZFR5cGUgPSBldmVudC5kYXRhLnR5cGUgPT09IFwiYXJjZ2lzOmF1dGg6cmVxdWVzdENyZWRlbnRpYWxcIjtcbiAgICAgICAgICAgIHZhciBpc1Rva2VuVmFsaWQgPSBfdGhpcy50b2tlbkV4cGlyZXMuZ2V0VGltZSgpID4gRGF0ZS5ub3coKTtcbiAgICAgICAgICAgIGlmIChpc1ZhbGlkT3JpZ2luICYmIGlzVmFsaWRUeXBlKSB7XG4gICAgICAgICAgICAgICAgdmFyIG1zZyA9IHt9O1xuICAgICAgICAgICAgICAgIGlmIChpc1Rva2VuVmFsaWQpIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGNyZWRlbnRpYWwgPSBfdGhpcy50b0NyZWRlbnRpYWwoKTtcbiAgICAgICAgICAgICAgICAgICAgLy8gYXJjZ2lzOmF1dGg6ZXJyb3Igd2l0aCB7bmFtZTogXCJcIiwgbWVzc2FnZTogXCJcIn1cbiAgICAgICAgICAgICAgICAgICAgLy8gdGhlIGZvbGxvd2luZyBsaW5lIGFsbG93cyB1cyB0byBjb25mb3JtIHRvIG91ciBzcGVjIHdpdGhvdXQgY2hhbmdpbmcgb3RoZXIgZGVwZW5kZWQtb24gZnVuY3Rpb25hbGl0eVxuICAgICAgICAgICAgICAgICAgICAvLyBodHRwczovL2dpdGh1Yi5jb20vRXNyaS9hcmNnaXMtcmVzdC1qcy9ibG9iL21hc3Rlci9wYWNrYWdlcy9hcmNnaXMtcmVzdC1hdXRoL3Bvc3QtbWVzc2FnZS1hdXRoLXNwZWMubWQjYXJjZ2lzYXV0aGNyZWRlbnRpYWxcbiAgICAgICAgICAgICAgICAgICAgY3JlZGVudGlhbC5zZXJ2ZXIgPSBjcmVkZW50aWFsLnNlcnZlci5yZXBsYWNlKFwiL3NoYXJpbmcvcmVzdFwiLCBcIlwiKTtcbiAgICAgICAgICAgICAgICAgICAgbXNnID0geyB0eXBlOiBcImFyY2dpczphdXRoOmNyZWRlbnRpYWxcIiwgY3JlZGVudGlhbDogY3JlZGVudGlhbCB9O1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gUmV0dXJuIGFuIGVycm9yXG4gICAgICAgICAgICAgICAgICAgIG1zZyA9IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHR5cGU6IFwiYXJjZ2lzOmF1dGg6ZXJyb3JcIixcbiAgICAgICAgICAgICAgICAgICAgICAgIGVycm9yOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbmFtZTogXCJ0b2tlbkV4cGlyZWRFcnJvclwiLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1lc3NhZ2U6IFwiU2Vzc2lvbiB0b2tlbiB3YXMgZXhwaXJlZCwgYW5kIG5vdCByZXR1cm5lZCB0byB0aGUgY2hpbGQgYXBwbGljYXRpb25cIixcbiAgICAgICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGV2ZW50LnNvdXJjZS5wb3N0TWVzc2FnZShtc2csIGV2ZW50Lm9yaWdpbik7XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBWYWxpZGF0ZXMgdGhhdCBhIGdpdmVuIFVSTCBpcyBwcm9wZXJseSBmZWRlcmF0ZWQgd2l0aCBvdXIgY3VycmVudCBgcG9ydGFsYC5cbiAgICAgKiBBdHRlbXB0cyB0byB1c2UgdGhlIGludGVybmFsIGBmZWRlcmF0ZWRTZXJ2ZXJzYCBjYWNoZSBmaXJzdC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0VG9rZW5Gb3JTZXJ2ZXIgPSBmdW5jdGlvbiAodXJsLCByZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICAvLyByZXF1ZXN0cyB0byAvcmVzdC9zZXJ2aWNlcy8gYW5kIC9yZXN0L2FkbWluL3NlcnZpY2VzLyBhcmUgYm90aCB2YWxpZFxuICAgICAgICAvLyBGZWRlcmF0ZWQgc2VydmVycyBtYXkgaGF2ZSBpbmNvbnNpc3RlbnQgY2FzaW5nLCBzbyBsb3dlckNhc2UgaXRcbiAgICAgICAgdmFyIHJvb3QgPSB0aGlzLmdldFNlcnZlclJvb3RVcmwodXJsKTtcbiAgICAgICAgdmFyIGV4aXN0aW5nVG9rZW4gPSB0aGlzLmZlZGVyYXRlZFNlcnZlcnNbcm9vdF07XG4gICAgICAgIGlmIChleGlzdGluZ1Rva2VuICYmXG4gICAgICAgICAgICBleGlzdGluZ1Rva2VuLmV4cGlyZXMgJiZcbiAgICAgICAgICAgIGV4aXN0aW5nVG9rZW4uZXhwaXJlcy5nZXRUaW1lKCkgPiBEYXRlLm5vdygpKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGV4aXN0aW5nVG9rZW4udG9rZW4pO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tyb290XSkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3Jvb3RdO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3Jvb3RdID0gdGhpcy5mZXRjaEF1dGhvcml6ZWREb21haW5zKCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gcmVxdWVzdChyb290ICsgXCIvcmVzdC9pbmZvXCIsIHtcbiAgICAgICAgICAgICAgICBjcmVkZW50aWFsczogX3RoaXMuZ2V0RG9tYWluQ3JlZGVudGlhbHModXJsKSxcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlLm93bmluZ1N5c3RlbVVybCkge1xuICAgICAgICAgICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAgICAgICAgICogaWYgdGhpcyBzZXJ2ZXIgaXMgbm90IG93bmVkIGJ5IHRoaXMgcG9ydGFsXG4gICAgICAgICAgICAgICAgICAgICAqIGJhaWwgb3V0IHdpdGggYW4gZXJyb3Igc2luY2Ugd2Uga25vdyB3ZSB3b250XG4gICAgICAgICAgICAgICAgICAgICAqIGJlIGFibGUgdG8gZ2VuZXJhdGUgYSB0b2tlblxuICAgICAgICAgICAgICAgICAgICAgKi9cbiAgICAgICAgICAgICAgICAgICAgaWYgKCFpc0ZlZGVyYXRlZChyZXNwb25zZS5vd25pbmdTeXN0ZW1VcmwsIF90aGlzLnBvcnRhbCkpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNBdXRoRXJyb3IodXJsICsgXCIgaXMgbm90IGZlZGVyYXRlZCB3aXRoIFwiICsgX3RoaXMucG9ydGFsICsgXCIuXCIsIFwiTk9UX0ZFREVSQVRFRFwiKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICAgICAgICAgICAgICogaWYgdGhlIHNlcnZlciBpcyBmZWRlcmF0ZWQsIHVzZSB0aGUgcmVsZXZhbnQgdG9rZW4gZW5kcG9pbnQuXG4gICAgICAgICAgICAgICAgICAgICAgICAgKi9cbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZXF1ZXN0KHJlc3BvbnNlLm93bmluZ1N5c3RlbVVybCArIFwiL3NoYXJpbmcvcmVzdC9pbmZvXCIsIHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmIChyZXNwb25zZS5hdXRoSW5mbyAmJlxuICAgICAgICAgICAgICAgICAgICBfdGhpcy5mZWRlcmF0ZWRTZXJ2ZXJzW3Jvb3RdICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgICAgICAgICAqIGlmIGl0cyBhIHN0YW5kLWFsb25lIGluc3RhbmNlIG9mIEFyY0dJUyBTZXJ2ZXIgdGhhdCBkb2Vzbid0IGFkdmVydGlzZVxuICAgICAgICAgICAgICAgICAgICAgKiBmZWRlcmF0aW9uLCBidXQgdGhlIHJvb3Qgc2VydmVyIHVybCBpcyByZWNvZ25pemVkLCB1c2UgaXRzIGJ1aWx0IGluIHRva2VuIGVuZHBvaW50LlxuICAgICAgICAgICAgICAgICAgICAgKi9cbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh7XG4gICAgICAgICAgICAgICAgICAgICAgICBhdXRoSW5mbzogcmVzcG9uc2UuYXV0aEluZm8sXG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEFyY0dJU0F1dGhFcnJvcih1cmwgKyBcIiBpcyBub3QgZmVkZXJhdGVkIHdpdGggYW55IHBvcnRhbCBhbmQgaXMgbm90IGV4cGxpY2l0bHkgdHJ1c3RlZC5cIiwgXCJOT1RfRkVERVJBVEVEXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmF1dGhJbmZvLnRva2VuU2VydmljZXNVcmw7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uICh0b2tlblNlcnZpY2VzVXJsKSB7XG4gICAgICAgICAgICAgICAgLy8gYW4gZXhwaXJlZCB0b2tlbiBjYW50IGJlIHVzZWQgdG8gZ2VuZXJhdGUgYSBuZXcgdG9rZW5cbiAgICAgICAgICAgICAgICBpZiAoX3RoaXMudG9rZW4gJiYgX3RoaXMudG9rZW5FeHBpcmVzLmdldFRpbWUoKSA+IERhdGUubm93KCkpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGdlbmVyYXRlVG9rZW4odG9rZW5TZXJ2aWNlc1VybCwge1xuICAgICAgICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW46IF90aGlzLnRva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNlcnZlclVybDogdXJsLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4cGlyYXRpb246IF90aGlzLnRva2VuRHVyYXRpb24sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xpZW50OiBcInJlZmVyZXJcIixcbiAgICAgICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAvLyBnZW5lcmF0ZSBhbiBlbnRpcmVseSBmcmVzaCB0b2tlbiBpZiBuZWNlc3NhcnlcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBnZW5lcmF0ZVRva2VuKHRva2VuU2VydmljZXNVcmwsIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVzZXJuYW1lOiBfdGhpcy51c2VybmFtZSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzd29yZDogX3RoaXMucGFzc3dvcmQsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhwaXJhdGlvbjogX3RoaXMudG9rZW5EdXJhdGlvbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjbGllbnQ6IFwicmVmZXJlclwiLFxuICAgICAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIF90aGlzLl90b2tlbiA9IHJlc3BvbnNlLnRva2VuO1xuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuX3Rva2VuRXhwaXJlcyA9IG5ldyBEYXRlKHJlc3BvbnNlLmV4cGlyZXMpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIF90aGlzLmZlZGVyYXRlZFNlcnZlcnNbcm9vdF0gPSB7XG4gICAgICAgICAgICAgICAgICAgIGV4cGlyZXM6IG5ldyBEYXRlKHJlc3BvbnNlLmV4cGlyZXMpLFxuICAgICAgICAgICAgICAgICAgICB0b2tlbjogcmVzcG9uc2UudG9rZW4sXG4gICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICBkZWxldGUgX3RoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3Jvb3RdO1xuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS50b2tlbjtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3Jvb3RdO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogUmV0dXJucyBhbiB1bmV4cGlyZWQgdG9rZW4gZm9yIHRoZSBjdXJyZW50IGBwb3J0YWxgLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRGcmVzaFRva2VuID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIGlmICh0aGlzLnRva2VuICYmICF0aGlzLnRva2VuRXhwaXJlcykge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzLnRva2VuKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy50b2tlbiAmJlxuICAgICAgICAgICAgdGhpcy50b2tlbkV4cGlyZXMgJiZcbiAgICAgICAgICAgIHRoaXMudG9rZW5FeHBpcmVzLmdldFRpbWUoKSA+IERhdGUubm93KCkpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy50b2tlbik7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCF0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1t0aGlzLnBvcnRhbF0pIHtcbiAgICAgICAgICAgIHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3RoaXMucG9ydGFsXSA9IHRoaXMucmVmcmVzaFNlc3Npb24ocmVxdWVzdE9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHNlc3Npb24pIHtcbiAgICAgICAgICAgICAgICBfdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbX3RoaXMucG9ydGFsXSA9IG51bGw7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHNlc3Npb24udG9rZW47XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbdGhpcy5wb3J0YWxdO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogUmVmcmVzaGVzIHRoZSBjdXJyZW50IGB0b2tlbmAgYW5kIGB0b2tlbkV4cGlyZXNgIHdpdGggYHVzZXJuYW1lYCBhbmRcbiAgICAgKiBgcGFzc3dvcmRgLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5yZWZyZXNoV2l0aFVzZXJuYW1lQW5kUGFzc3dvcmQgPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbih7IHBhcmFtczoge1xuICAgICAgICAgICAgICAgIHVzZXJuYW1lOiB0aGlzLnVzZXJuYW1lLFxuICAgICAgICAgICAgICAgIHBhc3N3b3JkOiB0aGlzLnBhc3N3b3JkLFxuICAgICAgICAgICAgICAgIGV4cGlyYXRpb246IHRoaXMudG9rZW5EdXJhdGlvbixcbiAgICAgICAgICAgIH0gfSwgcmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICByZXR1cm4gZ2VuZXJhdGVUb2tlbih0aGlzLnBvcnRhbCArIFwiL2dlbmVyYXRlVG9rZW5cIiwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbiA9IHJlc3BvbnNlLnRva2VuO1xuICAgICAgICAgICAgX3RoaXMuX3Rva2VuRXhwaXJlcyA9IG5ldyBEYXRlKHJlc3BvbnNlLmV4cGlyZXMpO1xuICAgICAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJlZnJlc2hlcyB0aGUgY3VycmVudCBgdG9rZW5gIGFuZCBgdG9rZW5FeHBpcmVzYCB3aXRoIGByZWZyZXNoVG9rZW5gLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5yZWZyZXNoV2l0aFJlZnJlc2hUb2tlbiA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBpZiAodGhpcy5yZWZyZXNoVG9rZW4gJiZcbiAgICAgICAgICAgIHRoaXMucmVmcmVzaFRva2VuRXhwaXJlcyAmJlxuICAgICAgICAgICAgdGhpcy5yZWZyZXNoVG9rZW5FeHBpcmVzLmdldFRpbWUoKSA8IERhdGUubm93KCkpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnJlZnJlc2hSZWZyZXNoVG9rZW4ocmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oeyBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICBjbGllbnRfaWQ6IHRoaXMuY2xpZW50SWQsXG4gICAgICAgICAgICAgICAgcmVmcmVzaF90b2tlbjogdGhpcy5yZWZyZXNoVG9rZW4sXG4gICAgICAgICAgICAgICAgZ3JhbnRfdHlwZTogXCJyZWZyZXNoX3Rva2VuXCIsXG4gICAgICAgICAgICB9IH0sIHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgcmV0dXJuIGZldGNoVG9rZW4odGhpcy5wb3J0YWwgKyBcIi9vYXV0aDIvdG9rZW5cIiwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbiA9IHJlc3BvbnNlLnRva2VuO1xuICAgICAgICAgICAgX3RoaXMuX3Rva2VuRXhwaXJlcyA9IHJlc3BvbnNlLmV4cGlyZXM7XG4gICAgICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogRXhjaGFuZ2VzIGFuIHVuZXhwaXJlZCBgcmVmcmVzaFRva2VuYCBmb3IgYSBuZXcgb25lLCBhbHNvIHVwZGF0ZXMgYHRva2VuYCBhbmRcbiAgICAgKiBgdG9rZW5FeHBpcmVzYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUucmVmcmVzaFJlZnJlc2hUb2tlbiA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKHsgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgY2xpZW50X2lkOiB0aGlzLmNsaWVudElkLFxuICAgICAgICAgICAgICAgIHJlZnJlc2hfdG9rZW46IHRoaXMucmVmcmVzaFRva2VuLFxuICAgICAgICAgICAgICAgIHJlZGlyZWN0X3VyaTogdGhpcy5yZWRpcmVjdFVyaSxcbiAgICAgICAgICAgICAgICBncmFudF90eXBlOiBcImV4Y2hhbmdlX3JlZnJlc2hfdG9rZW5cIixcbiAgICAgICAgICAgIH0gfSwgcmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICByZXR1cm4gZmV0Y2hUb2tlbih0aGlzLnBvcnRhbCArIFwiL29hdXRoMi90b2tlblwiLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgX3RoaXMuX3Rva2VuID0gcmVzcG9uc2UudG9rZW47XG4gICAgICAgICAgICBfdGhpcy5fdG9rZW5FeHBpcmVzID0gcmVzcG9uc2UuZXhwaXJlcztcbiAgICAgICAgICAgIF90aGlzLl9yZWZyZXNoVG9rZW4gPSByZXNwb25zZS5yZWZyZXNoVG9rZW47XG4gICAgICAgICAgICBfdGhpcy5fcmVmcmVzaFRva2VuRXhwaXJlcyA9IG5ldyBEYXRlKERhdGUubm93KCkgKyAoX3RoaXMucmVmcmVzaFRva2VuVFRMIC0gMSkgKiA2MCAqIDEwMDApO1xuICAgICAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIGVuc3VyZXMgdGhhdCB0aGUgYXV0aG9yaXplZENyb3NzT3JpZ2luRG9tYWlucyBhcmUgb2J0YWluZWQgZnJvbSB0aGUgcG9ydGFsIGFuZCBjYWNoZWRcbiAgICAgKiBzbyB3ZSBjYW4gY2hlY2sgdGhlbSBsYXRlci5cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHRoaXNcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZmV0Y2hBdXRob3JpemVkRG9tYWlucyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgLy8gaWYgdGhpcyB0b2tlbiBpcyBmb3IgYSBzcGVjaWZpYyBzZXJ2ZXIgb3Igd2UgZG9uJ3QgaGF2ZSBhIHBvcnRhbFxuICAgICAgICAvLyBkb24ndCBnZXQgdGhlIHBvcnRhbCBpbmZvIGJlY2F1c2Ugd2UgY2FudCBnZXQgdGhlIGF1dGhvcml6ZWRDcm9zc09yaWdpbkRvbWFpbnNcbiAgICAgICAgaWYgKHRoaXMuc2VydmVyIHx8ICF0aGlzLnBvcnRhbCkge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdGhpcy5nZXRQb3J0YWwoKS50aGVuKGZ1bmN0aW9uIChwb3J0YWxJbmZvKSB7XG4gICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAqIFNwZWNpZmljIGRvbWFpbnMgY2FuIGJlIGNvbmZpZ3VyZWQgYXMgc2VjdXJlLmVzcmkuY29tIG9yIGh0dHBzOi8vc2VjdXJlLmVzcmkuY29tIHRoaXNcbiAgICAgICAgICAgICAqIG5vcm1hbGl6ZXMgdG8gaHR0cHM6Ly9zZWN1cmUuZXNyaS5jb20gc28gd2UgY2FuIHVzZSBzdGFydHNXaXRoIGxhdGVyLlxuICAgICAgICAgICAgICovXG4gICAgICAgICAgICBpZiAocG9ydGFsSW5mby5hdXRob3JpemVkQ3Jvc3NPcmlnaW5Eb21haW5zICYmXG4gICAgICAgICAgICAgICAgcG9ydGFsSW5mby5hdXRob3JpemVkQ3Jvc3NPcmlnaW5Eb21haW5zLmxlbmd0aCkge1xuICAgICAgICAgICAgICAgIF90aGlzLnRydXN0ZWREb21haW5zID0gcG9ydGFsSW5mby5hdXRob3JpemVkQ3Jvc3NPcmlnaW5Eb21haW5zXG4gICAgICAgICAgICAgICAgICAgIC5maWx0ZXIoZnVuY3Rpb24gKGQpIHsgcmV0dXJuICFkLnN0YXJ0c1dpdGgoXCJodHRwOi8vXCIpOyB9KVxuICAgICAgICAgICAgICAgICAgICAubWFwKGZ1bmN0aW9uIChkKSB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChkLnN0YXJ0c1dpdGgoXCJodHRwczovL1wiKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJodHRwczovL1wiICsgZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIHJldHVybiBVc2VyU2Vzc2lvbjtcbn0oKSk7XG5leHBvcnQgeyBVc2VyU2Vzc2lvbiB9O1xuLy8jIHNvdXJjZU1hcHBpbmdVUkw9VXNlclNlc3Npb24uanMubWFwIiwiaW1wb3J0IHsgY2xlYW5VcmwgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKiBVc2VkIHRvIHRlc3QgaWYgYSBVUkwgaXMgYW4gQXJjR0lTIE9ubGluZSBVUkxcbiAqL1xudmFyIGFyY2dpc09ubGluZVVybFJlZ2V4ID0gL15odHRwcz86XFwvXFwvKFxcUyspXFwuYXJjZ2lzXFwuY29tLisvO1xuLyoqXG4gKiBVc2VkIHRvIHRlc3QgaWYgYSBVUkwgaXMgcHJvZHVjdGlvbiBBcmNHSVMgT25saW5lIFBvcnRhbFxuICovXG52YXIgYXJjZ2lzT25saW5lUG9ydGFsUmVnZXggPSAvXmh0dHBzPzpcXC9cXC8oZGV2fGRldmV4dHxxYXxxYWV4dHx3d3cpXFwuYXJjZ2lzXFwuY29tXFwvc2hhcmluZ1xcL3Jlc3QrLztcbi8qKlxuICogVXNlZCB0byB0ZXN0IGlmIGEgVVJMIGlzIGFuIEFyY0dJUyBPbmxpbmUgT3JnYW5pemF0aW9uIFBvcnRhbFxuICovXG52YXIgYXJjZ2lzT25saW5lT3JnUG9ydGFsUmVnZXggPSAvXmh0dHBzPzpcXC9cXC8oPzpbYS16MC05LV0rXFwubWFwcyhkZXZ8ZGV2ZXh0fHFhfHFhZXh0KT8pPy5hcmNnaXNcXC5jb21cXC9zaGFyaW5nXFwvcmVzdC87XG5leHBvcnQgZnVuY3Rpb24gaXNPbmxpbmUodXJsKSB7XG4gICAgcmV0dXJuIGFyY2dpc09ubGluZVVybFJlZ2V4LnRlc3QodXJsKTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBub3JtYWxpemVPbmxpbmVQb3J0YWxVcmwocG9ydGFsVXJsKSB7XG4gICAgaWYgKCFhcmNnaXNPbmxpbmVVcmxSZWdleC50ZXN0KHBvcnRhbFVybCkpIHtcbiAgICAgICAgcmV0dXJuIHBvcnRhbFVybDtcbiAgICB9XG4gICAgc3dpdGNoIChnZXRPbmxpbmVFbnZpcm9ubWVudChwb3J0YWxVcmwpKSB7XG4gICAgICAgIGNhc2UgXCJkZXZcIjpcbiAgICAgICAgICAgIHJldHVybiBcImh0dHBzOi8vZGV2ZXh0LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCI7XG4gICAgICAgIGNhc2UgXCJxYVwiOlxuICAgICAgICAgICAgcmV0dXJuIFwiaHR0cHM6Ly9xYWV4dC5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgcmV0dXJuIFwiaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIjtcbiAgICB9XG59XG5leHBvcnQgZnVuY3Rpb24gZ2V0T25saW5lRW52aXJvbm1lbnQodXJsKSB7XG4gICAgaWYgKCFhcmNnaXNPbmxpbmVVcmxSZWdleC50ZXN0KHVybCkpIHtcbiAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIHZhciBtYXRjaCA9IHVybC5tYXRjaChhcmNnaXNPbmxpbmVVcmxSZWdleCk7XG4gICAgdmFyIHN1YmRvbWFpbiA9IG1hdGNoWzFdLnNwbGl0KFwiLlwiKS5wb3AoKTtcbiAgICBpZiAoc3ViZG9tYWluLmluY2x1ZGVzKFwiZGV2XCIpKSB7XG4gICAgICAgIHJldHVybiBcImRldlwiO1xuICAgIH1cbiAgICBpZiAoc3ViZG9tYWluLmluY2x1ZGVzKFwicWFcIikpIHtcbiAgICAgICAgcmV0dXJuIFwicWFcIjtcbiAgICB9XG4gICAgcmV0dXJuIFwicHJvZHVjdGlvblwiO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGlzRmVkZXJhdGVkKG93bmluZ1N5c3RlbVVybCwgcG9ydGFsVXJsKSB7XG4gICAgdmFyIG5vcm1hbGl6ZWRQb3J0YWxVcmwgPSBjbGVhblVybChub3JtYWxpemVPbmxpbmVQb3J0YWxVcmwocG9ydGFsVXJsKSkucmVwbGFjZSgvaHR0cHM/OlxcL1xcLy8sIFwiXCIpO1xuICAgIHZhciBub3JtYWxpemVkT3duaW5nU3lzdGVtVXJsID0gY2xlYW5Vcmwob3duaW5nU3lzdGVtVXJsKS5yZXBsYWNlKC9odHRwcz86XFwvXFwvLywgXCJcIik7XG4gICAgcmV0dXJuIG5ldyBSZWdFeHAobm9ybWFsaXplZE93bmluZ1N5c3RlbVVybCwgXCJpXCIpLnRlc3Qobm9ybWFsaXplZFBvcnRhbFVybCk7XG59XG5leHBvcnQgZnVuY3Rpb24gY2FuVXNlT25saW5lVG9rZW4ocG9ydGFsVXJsLCByZXF1ZXN0VXJsKSB7XG4gICAgdmFyIHBvcnRhbElzT25saW5lID0gaXNPbmxpbmUocG9ydGFsVXJsKTtcbiAgICB2YXIgcmVxdWVzdElzT25saW5lID0gaXNPbmxpbmUocmVxdWVzdFVybCk7XG4gICAgdmFyIHBvcnRhbEVudiA9IGdldE9ubGluZUVudmlyb25tZW50KHBvcnRhbFVybCk7XG4gICAgdmFyIHJlcXVlc3RFbnYgPSBnZXRPbmxpbmVFbnZpcm9ubWVudChyZXF1ZXN0VXJsKTtcbiAgICBpZiAocG9ydGFsSXNPbmxpbmUgJiYgcmVxdWVzdElzT25saW5lICYmIHBvcnRhbEVudiA9PT0gcmVxdWVzdEVudikge1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG4gICAgcmV0dXJuIGZhbHNlO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZmVkZXJhdGlvbi11dGlscy5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgcmVxdWVzdCB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG5leHBvcnQgZnVuY3Rpb24gZmV0Y2hUb2tlbih1cmwsIHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIG9wdGlvbnMgPSByZXF1ZXN0T3B0aW9ucztcbiAgICAvLyB3ZSBnZW5lcmF0ZSBhIHJlc3BvbnNlLCBzbyB3ZSBjYW4ndCByZXR1cm4gdGhlIHJhdyByZXNwb25zZVxuICAgIG9wdGlvbnMucmF3UmVzcG9uc2UgPSBmYWxzZTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZhciByID0ge1xuICAgICAgICAgICAgdG9rZW46IHJlc3BvbnNlLmFjY2Vzc190b2tlbixcbiAgICAgICAgICAgIHVzZXJuYW1lOiByZXNwb25zZS51c2VybmFtZSxcbiAgICAgICAgICAgIGV4cGlyZXM6IG5ldyBEYXRlKFxuICAgICAgICAgICAgLy8gY29udmVydCBzZWNvbmRzIGluIHJlc3BvbnNlIHRvIG1pbGxpc2Vjb25kcyBhbmQgYWRkIHRoZSB2YWx1ZSB0byB0aGUgY3VycmVudCB0aW1lIHRvIGNhbGN1bGF0ZSBhIHN0YXRpYyBleHBpcmF0aW9uIHRpbWVzdGFtcFxuICAgICAgICAgICAgRGF0ZS5ub3coKSArIChyZXNwb25zZS5leHBpcmVzX2luICogMTAwMCAtIDEwMDApKSxcbiAgICAgICAgICAgIHNzbDogcmVzcG9uc2Uuc3NsID09PSB0cnVlXG4gICAgICAgIH07XG4gICAgICAgIGlmIChyZXNwb25zZS5yZWZyZXNoX3Rva2VuKSB7XG4gICAgICAgICAgICByLnJlZnJlc2hUb2tlbiA9IHJlc3BvbnNlLnJlZnJlc2hfdG9rZW47XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHI7XG4gICAgfSk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1mZXRjaC10b2tlbi5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyByZXF1ZXN0LCBOT0RFSlNfREVGQVVMVF9SRUZFUkVSX0hFQURFUiwgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuZXhwb3J0IGZ1bmN0aW9uIGdlbmVyYXRlVG9rZW4odXJsLCByZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciBvcHRpb25zID0gcmVxdWVzdE9wdGlvbnM7XG4gICAgLyogaXN0YW5idWwgaWdub3JlIGVsc2UgKi9cbiAgICBpZiAodHlwZW9mIHdpbmRvdyAhPT0gXCJ1bmRlZmluZWRcIiAmJlxuICAgICAgICB3aW5kb3cubG9jYXRpb24gJiZcbiAgICAgICAgd2luZG93LmxvY2F0aW9uLmhvc3QpIHtcbiAgICAgICAgb3B0aW9ucy5wYXJhbXMucmVmZXJlciA9IHdpbmRvdy5sb2NhdGlvbi5ob3N0O1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgb3B0aW9ucy5wYXJhbXMucmVmZXJlciA9IE5PREVKU19ERUZBVUxUX1JFRkVSRVJfSEVBREVSO1xuICAgIH1cbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIG9wdGlvbnMpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9Z2VuZXJhdGUtdG9rZW4uanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE4LTIwMjAgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgcmVxdWVzdCB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqIFZhbGlkYXRlcyB0aGF0IHRoZSB1c2VyIGhhcyBhY2Nlc3MgdG8gdGhlIGFwcGxpY2F0aW9uXG4gKiBhbmQgaWYgdGhleSB1c2VyIHNob3VsZCBiZSBwcmVzZW50ZWQgYSBcIlZpZXcgT25seVwiIG1vZGVcbiAqXG4gKiBUaGlzIGlzIG9ubHkgbmVlZGVkL3ZhbGlkIGZvciBFc3JpIGFwcGxpY2F0aW9ucyB0aGF0IGFyZSBcImxpY2Vuc2VkXCJcbiAqIGFuZCBzaGlwcGVkIGluIEFyY0dJUyBPbmxpbmUgb3IgQXJjR0lTIEVudGVycHJpc2UuIE1vc3QgY3VzdG9tIGFwcGxpY2F0aW9uc1xuICogc2hvdWxkIG5vdCBuZWVkIG9yIHVzZSB0aGlzLlxuICpcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyB2YWxpZGF0ZUFwcEFjY2VzcyB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgnO1xuICpcbiAqIHJldHVybiB2YWxpZGF0ZUFwcEFjY2VzcygneW91ci10b2tlbicsICd0aGVDbGllbnRJZCcpXG4gKiAudGhlbigocmVzdWx0KSA9PiB7XG4gKiAgICBpZiAoIXJlc3VsdC52YWx1ZSkge1xuICogICAgICAvLyByZWRpcmVjdCBvciBzaG93IHNvbWUgb3RoZXIgdWlcbiAqICAgIH0gZWxzZSB7XG4gKiAgICAgIGlmIChyZXN1bHQudmlld09ubHlVc2VyVHlwZUFwcCkge1xuICogICAgICAgIC8vIHVzZSB0aGlzIHRvIGluZm9ybSB5b3VyIGFwcCB0byBzaG93IGEgXCJWaWV3IE9ubHlcIiBtb2RlXG4gKiAgICAgIH1cbiAqICAgIH1cbiAqIH0pXG4gKiAuY2F0Y2goKGVycikgPT4ge1xuICogIC8vIHR3byBwb3NzaWJsZSBlcnJvcnNcbiAqICAvLyBpbnZhbGlkIGNsaWVudElkOiB7XCJlcnJvclwiOntcImNvZGVcIjo0MDAsXCJtZXNzYWdlQ29kZVwiOlwiR1dNXzAwMDdcIixcIm1lc3NhZ2VcIjpcIkludmFsaWQgcmVxdWVzdFwiLFwiZGV0YWlsc1wiOltdfX1cbiAqICAvLyBpbnZhbGlkIHRva2VuOiB7XCJlcnJvclwiOntcImNvZGVcIjo0OTgsXCJtZXNzYWdlXCI6XCJJbnZhbGlkIHRva2VuLlwiLFwiZGV0YWlsc1wiOltdfX1cbiAqIH0pXG4gKiBgYGBcbiAqXG4gKiBOb3RlOiBUaGlzIGlzIG9ubHkgdXNhYmxlIGJ5IEVzcmkgYXBwbGljYXRpb25zIGhvc3RlZCBvbiAqYXJjZ2lzLmNvbSwgKmVzcmkuY29tIG9yIHdpdGhpblxuICogYW4gQXJjR0lTIEVudGVycHJpc2UgaW5zdGFsbGF0aW9uLiBDdXN0b20gYXBwbGljYXRpb25zIGNhbiBub3QgdXNlIHRoaXMuXG4gKlxuICogQHBhcmFtIHRva2VuIHBsYXRmb3JtIHRva2VuXG4gKiBAcGFyYW0gY2xpZW50SWQgYXBwbGljYXRpb24gY2xpZW50IGlkXG4gKiBAcGFyYW0gcG9ydGFsIE9wdGlvbmFsXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB2YWxpZGF0ZUFwcEFjY2Vzcyh0b2tlbiwgY2xpZW50SWQsIHBvcnRhbCkge1xuICAgIGlmIChwb3J0YWwgPT09IHZvaWQgMCkgeyBwb3J0YWwgPSBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCI7IH1cbiAgICB2YXIgdXJsID0gcG9ydGFsICsgXCIvb2F1dGgyL3ZhbGlkYXRlQXBwQWNjZXNzXCI7XG4gICAgdmFyIHJvID0ge1xuICAgICAgICBtZXRob2Q6IFwiUE9TVFwiLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgIGY6IFwianNvblwiLFxuICAgICAgICAgICAgY2xpZW50X2lkOiBjbGllbnRJZCxcbiAgICAgICAgICAgIHRva2VuOiB0b2tlbixcbiAgICAgICAgfSxcbiAgICB9O1xuICAgIHJldHVybiByZXF1ZXN0KHVybCwgcm8pO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9dmFsaWRhdGUtYXBwLWFjY2Vzcy5qcy5tYXAiLCIvKiEgKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcclxuQ29weXJpZ2h0IChjKSBNaWNyb3NvZnQgQ29ycG9yYXRpb24uXHJcblxyXG5QZXJtaXNzaW9uIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBhbmQvb3IgZGlzdHJpYnV0ZSB0aGlzIHNvZnR3YXJlIGZvciBhbnlcclxucHVycG9zZSB3aXRoIG9yIHdpdGhvdXQgZmVlIGlzIGhlcmVieSBncmFudGVkLlxyXG5cclxuVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiBBTkQgVEhFIEFVVEhPUiBESVNDTEFJTVMgQUxMIFdBUlJBTlRJRVMgV0lUSFxyXG5SRUdBUkQgVE8gVEhJUyBTT0ZUV0FSRSBJTkNMVURJTkcgQUxMIElNUExJRUQgV0FSUkFOVElFUyBPRiBNRVJDSEFOVEFCSUxJVFlcclxuQU5EIEZJVE5FU1MuIElOIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1IgQkUgTElBQkxFIEZPUiBBTlkgU1BFQ0lBTCwgRElSRUNULFxyXG5JTkRJUkVDVCwgT1IgQ09OU0VRVUVOVElBTCBEQU1BR0VTIE9SIEFOWSBEQU1BR0VTIFdIQVRTT0VWRVIgUkVTVUxUSU5HIEZST01cclxuTE9TUyBPRiBVU0UsIERBVEEgT1IgUFJPRklUUywgV0hFVEhFUiBJTiBBTiBBQ1RJT04gT0YgQ09OVFJBQ1QsIE5FR0xJR0VOQ0UgT1JcclxuT1RIRVIgVE9SVElPVVMgQUNUSU9OLCBBUklTSU5HIE9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFVTRSBPUlxyXG5QRVJGT1JNQU5DRSBPRiBUSElTIFNPRlRXQVJFLlxyXG4qKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiAqL1xyXG4vKiBnbG9iYWwgUmVmbGVjdCwgUHJvbWlzZSAqL1xyXG5cclxudmFyIGV4dGVuZFN0YXRpY3MgPSBmdW5jdGlvbihkLCBiKSB7XHJcbiAgICBleHRlbmRTdGF0aWNzID0gT2JqZWN0LnNldFByb3RvdHlwZU9mIHx8XHJcbiAgICAgICAgKHsgX19wcm90b19fOiBbXSB9IGluc3RhbmNlb2YgQXJyYXkgJiYgZnVuY3Rpb24gKGQsIGIpIHsgZC5fX3Byb3RvX18gPSBiOyB9KSB8fFxyXG4gICAgICAgIGZ1bmN0aW9uIChkLCBiKSB7IGZvciAodmFyIHAgaW4gYikgaWYgKGIuaGFzT3duUHJvcGVydHkocCkpIGRbcF0gPSBiW3BdOyB9O1xyXG4gICAgcmV0dXJuIGV4dGVuZFN0YXRpY3MoZCwgYik7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19leHRlbmRzKGQsIGIpIHtcclxuICAgIGV4dGVuZFN0YXRpY3MoZCwgYik7XHJcbiAgICBmdW5jdGlvbiBfXygpIHsgdGhpcy5jb25zdHJ1Y3RvciA9IGQ7IH1cclxuICAgIGQucHJvdG90eXBlID0gYiA9PT0gbnVsbCA/IE9iamVjdC5jcmVhdGUoYikgOiAoX18ucHJvdG90eXBlID0gYi5wcm90b3R5cGUsIG5ldyBfXygpKTtcclxufVxyXG5cclxuZXhwb3J0IHZhciBfX2Fzc2lnbiA9IGZ1bmN0aW9uKCkge1xyXG4gICAgX19hc3NpZ24gPSBPYmplY3QuYXNzaWduIHx8IGZ1bmN0aW9uIF9fYXNzaWduKHQpIHtcclxuICAgICAgICBmb3IgKHZhciBzLCBpID0gMSwgbiA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBuOyBpKyspIHtcclxuICAgICAgICAgICAgcyA9IGFyZ3VtZW50c1tpXTtcclxuICAgICAgICAgICAgZm9yICh2YXIgcCBpbiBzKSBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHMsIHApKSB0W3BdID0gc1twXTtcclxuICAgICAgICB9XHJcbiAgICAgICAgcmV0dXJuIHQ7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gX19hc3NpZ24uYXBwbHkodGhpcywgYXJndW1lbnRzKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcmVzdChzLCBlKSB7XHJcbiAgICB2YXIgdCA9IHt9O1xyXG4gICAgZm9yICh2YXIgcCBpbiBzKSBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHMsIHApICYmIGUuaW5kZXhPZihwKSA8IDApXHJcbiAgICAgICAgdFtwXSA9IHNbcF07XHJcbiAgICBpZiAocyAhPSBudWxsICYmIHR5cGVvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlTeW1ib2xzID09PSBcImZ1bmN0aW9uXCIpXHJcbiAgICAgICAgZm9yICh2YXIgaSA9IDAsIHAgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlTeW1ib2xzKHMpOyBpIDwgcC5sZW5ndGg7IGkrKykge1xyXG4gICAgICAgICAgICBpZiAoZS5pbmRleE9mKHBbaV0pIDwgMCAmJiBPYmplY3QucHJvdG90eXBlLnByb3BlcnR5SXNFbnVtZXJhYmxlLmNhbGwocywgcFtpXSkpXHJcbiAgICAgICAgICAgICAgICB0W3BbaV1dID0gc1twW2ldXTtcclxuICAgICAgICB9XHJcbiAgICByZXR1cm4gdDtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZGVjb3JhdGUoZGVjb3JhdG9ycywgdGFyZ2V0LCBrZXksIGRlc2MpIHtcclxuICAgIHZhciBjID0gYXJndW1lbnRzLmxlbmd0aCwgciA9IGMgPCAzID8gdGFyZ2V0IDogZGVzYyA9PT0gbnVsbCA/IGRlc2MgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKHRhcmdldCwga2V5KSA6IGRlc2MsIGQ7XHJcbiAgICBpZiAodHlwZW9mIFJlZmxlY3QgPT09IFwib2JqZWN0XCIgJiYgdHlwZW9mIFJlZmxlY3QuZGVjb3JhdGUgPT09IFwiZnVuY3Rpb25cIikgciA9IFJlZmxlY3QuZGVjb3JhdGUoZGVjb3JhdG9ycywgdGFyZ2V0LCBrZXksIGRlc2MpO1xyXG4gICAgZWxzZSBmb3IgKHZhciBpID0gZGVjb3JhdG9ycy5sZW5ndGggLSAxOyBpID49IDA7IGktLSkgaWYgKGQgPSBkZWNvcmF0b3JzW2ldKSByID0gKGMgPCAzID8gZChyKSA6IGMgPiAzID8gZCh0YXJnZXQsIGtleSwgcikgOiBkKHRhcmdldCwga2V5KSkgfHwgcjtcclxuICAgIHJldHVybiBjID4gMyAmJiByICYmIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0YXJnZXQsIGtleSwgciksIHI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3BhcmFtKHBhcmFtSW5kZXgsIGRlY29yYXRvcikge1xyXG4gICAgcmV0dXJuIGZ1bmN0aW9uICh0YXJnZXQsIGtleSkgeyBkZWNvcmF0b3IodGFyZ2V0LCBrZXksIHBhcmFtSW5kZXgpOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX21ldGFkYXRhKG1ldGFkYXRhS2V5LCBtZXRhZGF0YVZhbHVlKSB7XHJcbiAgICBpZiAodHlwZW9mIFJlZmxlY3QgPT09IFwib2JqZWN0XCIgJiYgdHlwZW9mIFJlZmxlY3QubWV0YWRhdGEgPT09IFwiZnVuY3Rpb25cIikgcmV0dXJuIFJlZmxlY3QubWV0YWRhdGEobWV0YWRhdGFLZXksIG1ldGFkYXRhVmFsdWUpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hd2FpdGVyKHRoaXNBcmcsIF9hcmd1bWVudHMsIFAsIGdlbmVyYXRvcikge1xyXG4gICAgZnVuY3Rpb24gYWRvcHQodmFsdWUpIHsgcmV0dXJuIHZhbHVlIGluc3RhbmNlb2YgUCA/IHZhbHVlIDogbmV3IFAoZnVuY3Rpb24gKHJlc29sdmUpIHsgcmVzb2x2ZSh2YWx1ZSk7IH0pOyB9XHJcbiAgICByZXR1cm4gbmV3IChQIHx8IChQID0gUHJvbWlzZSkpKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcclxuICAgICAgICBmdW5jdGlvbiBmdWxmaWxsZWQodmFsdWUpIHsgdHJ5IHsgc3RlcChnZW5lcmF0b3IubmV4dCh2YWx1ZSkpOyB9IGNhdGNoIChlKSB7IHJlamVjdChlKTsgfSB9XHJcbiAgICAgICAgZnVuY3Rpb24gcmVqZWN0ZWQodmFsdWUpIHsgdHJ5IHsgc3RlcChnZW5lcmF0b3JbXCJ0aHJvd1wiXSh2YWx1ZSkpOyB9IGNhdGNoIChlKSB7IHJlamVjdChlKTsgfSB9XHJcbiAgICAgICAgZnVuY3Rpb24gc3RlcChyZXN1bHQpIHsgcmVzdWx0LmRvbmUgPyByZXNvbHZlKHJlc3VsdC52YWx1ZSkgOiBhZG9wdChyZXN1bHQudmFsdWUpLnRoZW4oZnVsZmlsbGVkLCByZWplY3RlZCk7IH1cclxuICAgICAgICBzdGVwKChnZW5lcmF0b3IgPSBnZW5lcmF0b3IuYXBwbHkodGhpc0FyZywgX2FyZ3VtZW50cyB8fCBbXSkpLm5leHQoKSk7XHJcbiAgICB9KTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZ2VuZXJhdG9yKHRoaXNBcmcsIGJvZHkpIHtcclxuICAgIHZhciBfID0geyBsYWJlbDogMCwgc2VudDogZnVuY3Rpb24oKSB7IGlmICh0WzBdICYgMSkgdGhyb3cgdFsxXTsgcmV0dXJuIHRbMV07IH0sIHRyeXM6IFtdLCBvcHM6IFtdIH0sIGYsIHksIHQsIGc7XHJcbiAgICByZXR1cm4gZyA9IHsgbmV4dDogdmVyYigwKSwgXCJ0aHJvd1wiOiB2ZXJiKDEpLCBcInJldHVyblwiOiB2ZXJiKDIpIH0sIHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiAoZ1tTeW1ib2wuaXRlcmF0b3JdID0gZnVuY3Rpb24oKSB7IHJldHVybiB0aGlzOyB9KSwgZztcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyByZXR1cm4gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIHN0ZXAoW24sIHZdKTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gc3RlcChvcCkge1xyXG4gICAgICAgIGlmIChmKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiR2VuZXJhdG9yIGlzIGFscmVhZHkgZXhlY3V0aW5nLlwiKTtcclxuICAgICAgICB3aGlsZSAoXykgdHJ5IHtcclxuICAgICAgICAgICAgaWYgKGYgPSAxLCB5ICYmICh0ID0gb3BbMF0gJiAyID8geVtcInJldHVyblwiXSA6IG9wWzBdID8geVtcInRocm93XCJdIHx8ICgodCA9IHlbXCJyZXR1cm5cIl0pICYmIHQuY2FsbCh5KSwgMCkgOiB5Lm5leHQpICYmICEodCA9IHQuY2FsbCh5LCBvcFsxXSkpLmRvbmUpIHJldHVybiB0O1xyXG4gICAgICAgICAgICBpZiAoeSA9IDAsIHQpIG9wID0gW29wWzBdICYgMiwgdC52YWx1ZV07XHJcbiAgICAgICAgICAgIHN3aXRjaCAob3BbMF0pIHtcclxuICAgICAgICAgICAgICAgIGNhc2UgMDogY2FzZSAxOiB0ID0gb3A7IGJyZWFrO1xyXG4gICAgICAgICAgICAgICAgY2FzZSA0OiBfLmxhYmVsKys7IHJldHVybiB7IHZhbHVlOiBvcFsxXSwgZG9uZTogZmFsc2UgfTtcclxuICAgICAgICAgICAgICAgIGNhc2UgNTogXy5sYWJlbCsrOyB5ID0gb3BbMV07IG9wID0gWzBdOyBjb250aW51ZTtcclxuICAgICAgICAgICAgICAgIGNhc2UgNzogb3AgPSBfLm9wcy5wb3AoKTsgXy50cnlzLnBvcCgpOyBjb250aW51ZTtcclxuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKCEodCA9IF8udHJ5cywgdCA9IHQubGVuZ3RoID4gMCAmJiB0W3QubGVuZ3RoIC0gMV0pICYmIChvcFswXSA9PT0gNiB8fCBvcFswXSA9PT0gMikpIHsgXyA9IDA7IGNvbnRpbnVlOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG9wWzBdID09PSAzICYmICghdCB8fCAob3BbMV0gPiB0WzBdICYmIG9wWzFdIDwgdFszXSkpKSB7IF8ubGFiZWwgPSBvcFsxXTsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAob3BbMF0gPT09IDYgJiYgXy5sYWJlbCA8IHRbMV0pIHsgXy5sYWJlbCA9IHRbMV07IHQgPSBvcDsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAodCAmJiBfLmxhYmVsIDwgdFsyXSkgeyBfLmxhYmVsID0gdFsyXTsgXy5vcHMucHVzaChvcCk7IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHRbMl0pIF8ub3BzLnBvcCgpO1xyXG4gICAgICAgICAgICAgICAgICAgIF8udHJ5cy5wb3AoKTsgY29udGludWU7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgb3AgPSBib2R5LmNhbGwodGhpc0FyZywgXyk7XHJcbiAgICAgICAgfSBjYXRjaCAoZSkgeyBvcCA9IFs2LCBlXTsgeSA9IDA7IH0gZmluYWxseSB7IGYgPSB0ID0gMDsgfVxyXG4gICAgICAgIGlmIChvcFswXSAmIDUpIHRocm93IG9wWzFdOyByZXR1cm4geyB2YWx1ZTogb3BbMF0gPyBvcFsxXSA6IHZvaWQgMCwgZG9uZTogdHJ1ZSB9O1xyXG4gICAgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jcmVhdGVCaW5kaW5nKG8sIG0sIGssIGsyKSB7XHJcbiAgICBpZiAoazIgPT09IHVuZGVmaW5lZCkgazIgPSBrO1xyXG4gICAgb1trMl0gPSBtW2tdO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19leHBvcnRTdGFyKG0sIGV4cG9ydHMpIHtcclxuICAgIGZvciAodmFyIHAgaW4gbSkgaWYgKHAgIT09IFwiZGVmYXVsdFwiICYmICFleHBvcnRzLmhhc093blByb3BlcnR5KHApKSBleHBvcnRzW3BdID0gbVtwXTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fdmFsdWVzKG8pIHtcclxuICAgIHZhciBzID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIFN5bWJvbC5pdGVyYXRvciwgbSA9IHMgJiYgb1tzXSwgaSA9IDA7XHJcbiAgICBpZiAobSkgcmV0dXJuIG0uY2FsbChvKTtcclxuICAgIGlmIChvICYmIHR5cGVvZiBvLmxlbmd0aCA9PT0gXCJudW1iZXJcIikgcmV0dXJuIHtcclxuICAgICAgICBuZXh0OiBmdW5jdGlvbiAoKSB7XHJcbiAgICAgICAgICAgIGlmIChvICYmIGkgPj0gby5sZW5ndGgpIG8gPSB2b2lkIDA7XHJcbiAgICAgICAgICAgIHJldHVybiB7IHZhbHVlOiBvICYmIG9baSsrXSwgZG9uZTogIW8gfTtcclxuICAgICAgICB9XHJcbiAgICB9O1xyXG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihzID8gXCJPYmplY3QgaXMgbm90IGl0ZXJhYmxlLlwiIDogXCJTeW1ib2wuaXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19yZWFkKG8sIG4pIHtcclxuICAgIHZhciBtID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIG9bU3ltYm9sLml0ZXJhdG9yXTtcclxuICAgIGlmICghbSkgcmV0dXJuIG87XHJcbiAgICB2YXIgaSA9IG0uY2FsbChvKSwgciwgYXIgPSBbXSwgZTtcclxuICAgIHRyeSB7XHJcbiAgICAgICAgd2hpbGUgKChuID09PSB2b2lkIDAgfHwgbi0tID4gMCkgJiYgIShyID0gaS5uZXh0KCkpLmRvbmUpIGFyLnB1c2goci52YWx1ZSk7XHJcbiAgICB9XHJcbiAgICBjYXRjaCAoZXJyb3IpIHsgZSA9IHsgZXJyb3I6IGVycm9yIH07IH1cclxuICAgIGZpbmFsbHkge1xyXG4gICAgICAgIHRyeSB7XHJcbiAgICAgICAgICAgIGlmIChyICYmICFyLmRvbmUgJiYgKG0gPSBpW1wicmV0dXJuXCJdKSkgbS5jYWxsKGkpO1xyXG4gICAgICAgIH1cclxuICAgICAgICBmaW5hbGx5IHsgaWYgKGUpIHRocm93IGUuZXJyb3I7IH1cclxuICAgIH1cclxuICAgIHJldHVybiBhcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fc3ByZWFkKCkge1xyXG4gICAgZm9yICh2YXIgYXIgPSBbXSwgaSA9IDA7IGkgPCBhcmd1bWVudHMubGVuZ3RoOyBpKyspXHJcbiAgICAgICAgYXIgPSBhci5jb25jYXQoX19yZWFkKGFyZ3VtZW50c1tpXSkpO1xyXG4gICAgcmV0dXJuIGFyO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19zcHJlYWRBcnJheXMoKSB7XHJcbiAgICBmb3IgKHZhciBzID0gMCwgaSA9IDAsIGlsID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IGlsOyBpKyspIHMgKz0gYXJndW1lbnRzW2ldLmxlbmd0aDtcclxuICAgIGZvciAodmFyIHIgPSBBcnJheShzKSwgayA9IDAsIGkgPSAwOyBpIDwgaWw7IGkrKylcclxuICAgICAgICBmb3IgKHZhciBhID0gYXJndW1lbnRzW2ldLCBqID0gMCwgamwgPSBhLmxlbmd0aDsgaiA8IGpsOyBqKyssIGsrKylcclxuICAgICAgICAgICAgcltrXSA9IGFbal07XHJcbiAgICByZXR1cm4gcjtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2F3YWl0KHYpIHtcclxuICAgIHJldHVybiB0aGlzIGluc3RhbmNlb2YgX19hd2FpdCA/ICh0aGlzLnYgPSB2LCB0aGlzKSA6IG5ldyBfX2F3YWl0KHYpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY0dlbmVyYXRvcih0aGlzQXJnLCBfYXJndW1lbnRzLCBnZW5lcmF0b3IpIHtcclxuICAgIGlmICghU3ltYm9sLmFzeW5jSXRlcmF0b3IpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTeW1ib2wuYXN5bmNJdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbiAgICB2YXIgZyA9IGdlbmVyYXRvci5hcHBseSh0aGlzQXJnLCBfYXJndW1lbnRzIHx8IFtdKSwgaSwgcSA9IFtdO1xyXG4gICAgcmV0dXJuIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiKSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuYXN5bmNJdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IGlmIChnW25dKSBpW25dID0gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChhLCBiKSB7IHEucHVzaChbbiwgdiwgYSwgYl0pID4gMSB8fCByZXN1bWUobiwgdik7IH0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiByZXN1bWUobiwgdikgeyB0cnkgeyBzdGVwKGdbbl0odikpOyB9IGNhdGNoIChlKSB7IHNldHRsZShxWzBdWzNdLCBlKTsgfSB9XHJcbiAgICBmdW5jdGlvbiBzdGVwKHIpIHsgci52YWx1ZSBpbnN0YW5jZW9mIF9fYXdhaXQgPyBQcm9taXNlLnJlc29sdmUoci52YWx1ZS52KS50aGVuKGZ1bGZpbGwsIHJlamVjdCkgOiBzZXR0bGUocVswXVsyXSwgcik7IH1cclxuICAgIGZ1bmN0aW9uIGZ1bGZpbGwodmFsdWUpIHsgcmVzdW1lKFwibmV4dFwiLCB2YWx1ZSk7IH1cclxuICAgIGZ1bmN0aW9uIHJlamVjdCh2YWx1ZSkgeyByZXN1bWUoXCJ0aHJvd1wiLCB2YWx1ZSk7IH1cclxuICAgIGZ1bmN0aW9uIHNldHRsZShmLCB2KSB7IGlmIChmKHYpLCBxLnNoaWZ0KCksIHEubGVuZ3RoKSByZXN1bWUocVswXVswXSwgcVswXVsxXSk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNEZWxlZ2F0b3Iobykge1xyXG4gICAgdmFyIGksIHA7XHJcbiAgICByZXR1cm4gaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIsIGZ1bmN0aW9uIChlKSB7IHRocm93IGU7IH0pLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5pdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuLCBmKSB7IGlbbl0gPSBvW25dID8gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIChwID0gIXApID8geyB2YWx1ZTogX19hd2FpdChvW25dKHYpKSwgZG9uZTogbiA9PT0gXCJyZXR1cm5cIiB9IDogZiA/IGYodikgOiB2OyB9IDogZjsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY1ZhbHVlcyhvKSB7XHJcbiAgICBpZiAoIVN5bWJvbC5hc3luY0l0ZXJhdG9yKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU3ltYm9sLmFzeW5jSXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgdmFyIG0gPSBvW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSwgaTtcclxuICAgIHJldHVybiBtID8gbS5jYWxsKG8pIDogKG8gPSB0eXBlb2YgX192YWx1ZXMgPT09IFwiZnVuY3Rpb25cIiA/IF9fdmFsdWVzKG8pIDogb1tTeW1ib2wuaXRlcmF0b3JdKCksIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiKSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuYXN5bmNJdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpKTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyBpW25dID0gb1tuXSAmJiBmdW5jdGlvbiAodikgeyByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkgeyB2ID0gb1tuXSh2KSwgc2V0dGxlKHJlc29sdmUsIHJlamVjdCwgdi5kb25lLCB2LnZhbHVlKTsgfSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHNldHRsZShyZXNvbHZlLCByZWplY3QsIGQsIHYpIHsgUHJvbWlzZS5yZXNvbHZlKHYpLnRoZW4oZnVuY3Rpb24odikgeyByZXNvbHZlKHsgdmFsdWU6IHYsIGRvbmU6IGQgfSk7IH0sIHJlamVjdCk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fbWFrZVRlbXBsYXRlT2JqZWN0KGNvb2tlZCwgcmF3KSB7XHJcbiAgICBpZiAoT2JqZWN0LmRlZmluZVByb3BlcnR5KSB7IE9iamVjdC5kZWZpbmVQcm9wZXJ0eShjb29rZWQsIFwicmF3XCIsIHsgdmFsdWU6IHJhdyB9KTsgfSBlbHNlIHsgY29va2VkLnJhdyA9IHJhdzsgfVxyXG4gICAgcmV0dXJuIGNvb2tlZDtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2ltcG9ydFN0YXIobW9kKSB7XHJcbiAgICBpZiAobW9kICYmIG1vZC5fX2VzTW9kdWxlKSByZXR1cm4gbW9kO1xyXG4gICAgdmFyIHJlc3VsdCA9IHt9O1xyXG4gICAgaWYgKG1vZCAhPSBudWxsKSBmb3IgKHZhciBrIGluIG1vZCkgaWYgKE9iamVjdC5oYXNPd25Qcm9wZXJ0eS5jYWxsKG1vZCwgaykpIHJlc3VsdFtrXSA9IG1vZFtrXTtcclxuICAgIHJlc3VsdC5kZWZhdWx0ID0gbW9kO1xyXG4gICAgcmV0dXJuIHJlc3VsdDtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9faW1wb3J0RGVmYXVsdChtb2QpIHtcclxuICAgIHJldHVybiAobW9kICYmIG1vZC5fX2VzTW9kdWxlKSA/IG1vZCA6IHsgZGVmYXVsdDogbW9kIH07XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NsYXNzUHJpdmF0ZUZpZWxkR2V0KHJlY2VpdmVyLCBwcml2YXRlTWFwKSB7XHJcbiAgICBpZiAoIXByaXZhdGVNYXAuaGFzKHJlY2VpdmVyKSkge1xyXG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJhdHRlbXB0ZWQgdG8gZ2V0IHByaXZhdGUgZmllbGQgb24gbm9uLWluc3RhbmNlXCIpO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHByaXZhdGVNYXAuZ2V0KHJlY2VpdmVyKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY2xhc3NQcml2YXRlRmllbGRTZXQocmVjZWl2ZXIsIHByaXZhdGVNYXAsIHZhbHVlKSB7XHJcbiAgICBpZiAoIXByaXZhdGVNYXAuaGFzKHJlY2VpdmVyKSkge1xyXG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJhdHRlbXB0ZWQgdG8gc2V0IHByaXZhdGUgZmllbGQgb24gbm9uLWluc3RhbmNlXCIpO1xyXG4gICAgfVxyXG4gICAgcHJpdmF0ZU1hcC5zZXQocmVjZWl2ZXIsIHZhbHVlKTtcclxuICAgIHJldHVybiB2YWx1ZTtcclxufVxyXG4iLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIGNsZWFuVXJsLCBhcHBlbmRDdXN0b21QYXJhbXMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgYWRkRmVhdHVyZXMgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyJztcbiAqIC8vXG4gKiBhZGRGZWF0dXJlcyh7XG4gKiAgIHVybDogXCJodHRwczovL3NhbXBsZXNlcnZlcjYuYXJjZ2lzb25saW5lLmNvbS9hcmNnaXMvcmVzdC9zZXJ2aWNlcy9TZXJ2aWNlUmVxdWVzdC9GZWF0dXJlU2VydmVyLzBcIixcbiAqICAgZmVhdHVyZXM6IFt7XG4gKiAgICAgZ2VvbWV0cnk6IHsgeDogLTEyMCwgeTogNDUsIHNwYXRpYWxSZWZlcmVuY2U6IHsgd2tpZDogNDMyNiB9IH0sXG4gKiAgICAgYXR0cmlidXRlczogeyBzdGF0dXM6IFwiYWxpdmVcIiB9XG4gKiAgIH1dXG4gKiB9KVxuICogICAudGhlbihyZXNwb25zZSlcbiAqIGBgYFxuICogQWRkIGZlYXR1cmVzIHJlcXVlc3QuIFNlZSB0aGUgW1JFU1QgRG9jdW1lbnRhdGlvbl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC9zZXJ2aWNlcy1yZWZlcmVuY2UvYWRkLWZlYXR1cmVzLmh0bSkgZm9yIG1vcmUgaW5mb3JtYXRpb24uXG4gKlxuICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3QuXG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgYWRkRmVhdHVyZXMgcmVzcG9uc2UuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBhZGRGZWF0dXJlcyhyZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciB1cmwgPSBjbGVhblVybChyZXF1ZXN0T3B0aW9ucy51cmwpICsgXCIvYWRkRmVhdHVyZXNcIjtcbiAgICAvLyBlZGl0IG9wZXJhdGlvbnMgYXJlIFBPU1Qgb25seVxuICAgIHZhciBvcHRpb25zID0gYXBwZW5kQ3VzdG9tUGFyYW1zKHJlcXVlc3RPcHRpb25zLCBbXCJmZWF0dXJlc1wiLCBcImdkYlZlcnNpb25cIiwgXCJyZXR1cm5FZGl0TW9tZW50XCIsIFwicm9sbGJhY2tPbkZhaWx1cmVcIl0sIHsgcGFyYW1zOiBfX2Fzc2lnbih7fSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKSB9KTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIG9wdGlvbnMpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9YWRkLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgcmVxdWVzdCwgY2xlYW5VcmwsIGFwcGVuZEN1c3RvbVBhcmFtcyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBkZWxldGVGZWF0dXJlcyB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXInO1xuICogLy9cbiAqIGRlbGV0ZUZlYXR1cmVzKHtcbiAqICAgdXJsOiBcImh0dHBzOi8vc2FtcGxlc2VydmVyNi5hcmNnaXNvbmxpbmUuY29tL2FyY2dpcy9yZXN0L3NlcnZpY2VzL1NlcnZpY2VSZXF1ZXN0L0ZlYXR1cmVTZXJ2ZXIvMFwiLFxuICogICBvYmplY3RJZHM6IFsxLDIsM11cbiAqIH0pO1xuICogYGBgXG4gKiBEZWxldGUgZmVhdHVyZXMgcmVxdWVzdC4gU2VlIHRoZSBbUkVTVCBEb2N1bWVudGF0aW9uXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3NlcnZpY2VzLXJlZmVyZW5jZS9kZWxldGUtZmVhdHVyZXMuaHRtKSBmb3IgbW9yZSBpbmZvcm1hdGlvbi5cbiAqXG4gKiBAcGFyYW0gZGVsZXRlRmVhdHVyZXNSZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0LlxuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIGRlbGV0ZUZlYXR1cmVzIHJlc3BvbnNlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gZGVsZXRlRmVhdHVyZXMocmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgdXJsID0gY2xlYW5VcmwocmVxdWVzdE9wdGlvbnMudXJsKSArIFwiL2RlbGV0ZUZlYXR1cmVzXCI7XG4gICAgLy8gZWRpdCBvcGVyYXRpb25zIFBPU1Qgb25seVxuICAgIHZhciBvcHRpb25zID0gYXBwZW5kQ3VzdG9tUGFyYW1zKHJlcXVlc3RPcHRpb25zLCBbXG4gICAgICAgIFwid2hlcmVcIixcbiAgICAgICAgXCJvYmplY3RJZHNcIixcbiAgICAgICAgXCJnZGJWZXJzaW9uXCIsXG4gICAgICAgIFwicmV0dXJuRWRpdE1vbWVudFwiLFxuICAgICAgICBcInJvbGxiYWNrT25GYWlsdXJlXCJcbiAgICBdLCB7IHBhcmFtczogX19hc3NpZ24oe30sIHJlcXVlc3RPcHRpb25zLnBhcmFtcykgfSk7XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRlbGV0ZS5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgcmVxdWVzdCwgY2xlYW5VcmwsIGFwcGVuZEN1c3RvbVBhcmFtcyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBnZXRGZWF0dXJlIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcic7XG4gKiAvL1xuICogY29uc3QgdXJsID0gXCJodHRwczovL3NlcnZpY2VzLmFyY2dpcy5jb20vVjZaSEZyNnpkZ05adVZHMC9hcmNnaXMvcmVzdC9zZXJ2aWNlcy9MYW5kc2NhcGVfVHJlZXMvRmVhdHVyZVNlcnZlci8wXCI7XG4gKiAvL1xuICogZ2V0RmVhdHVyZSh7XG4gKiAgIHVybCxcbiAqICAgaWQ6IDQyXG4gKiB9KS50aGVuKGZlYXR1cmUgPT4ge1xuICogIGNvbnNvbGUubG9nKGZlYXR1cmUuYXR0cmlidXRlcy5GSUQpOyAvLyA0MlxuICogfSk7XG4gKiBgYGBcbiAqIEdldCBhIGZlYXR1cmUgYnkgaWQuXG4gKlxuICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3RcbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBmZWF0dXJlIG9yIHRoZSBbcmVzcG9uc2VdKGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0FQSS9SZXNwb25zZSkgaXRzZWxmIGlmIGByYXdSZXNwb25zZTogdHJ1ZWAgd2FzIHBhc3NlZCBpbi5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGdldEZlYXR1cmUocmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgdXJsID0gY2xlYW5VcmwocmVxdWVzdE9wdGlvbnMudXJsKSArIFwiL1wiICsgcmVxdWVzdE9wdGlvbnMuaWQ7XG4gICAgLy8gZGVmYXVsdCB0byBhIEdFVCByZXF1ZXN0XG4gICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbih7IGh0dHBNZXRob2Q6IFwiR0VUXCIgfSwgcmVxdWVzdE9wdGlvbnMpO1xuICAgIHJldHVybiByZXF1ZXN0KHVybCwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKG9wdGlvbnMucmF3UmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcmVzcG9uc2UuZmVhdHVyZTtcbiAgICB9KTtcbn1cbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IHF1ZXJ5RmVhdHVyZXMgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyJztcbiAqIC8vXG4gKiBxdWVyeUZlYXR1cmVzKHtcbiAqICAgdXJsOiBcImh0dHA6Ly9zYW1wbGVzZXJ2ZXI2LmFyY2dpc29ubGluZS5jb20vYXJjZ2lzL3Jlc3Qvc2VydmljZXMvQ2Vuc3VzL01hcFNlcnZlci8zXCIsXG4gKiAgIHdoZXJlOiBcIlNUQVRFX05BTUUgPSAnQWxhc2thJ1wiXG4gKiB9KVxuICogICAudGhlbihyZXN1bHQpXG4gKiBgYGBcbiAqIFF1ZXJ5IGEgZmVhdHVyZSBzZXJ2aWNlLiBTZWUgW1JFU1QgRG9jdW1lbnRhdGlvbl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC9zZXJ2aWNlcy1yZWZlcmVuY2UvcXVlcnktZmVhdHVyZS1zZXJ2aWNlLWxheWVyLS5odG0pIGZvciBtb3JlIGluZm9ybWF0aW9uLlxuICpcbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0XG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgcXVlcnkgcmVzcG9uc2UuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBxdWVyeUZlYXR1cmVzKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIHF1ZXJ5T3B0aW9ucyA9IGFwcGVuZEN1c3RvbVBhcmFtcyhyZXF1ZXN0T3B0aW9ucywgW1xuICAgICAgICBcIndoZXJlXCIsXG4gICAgICAgIFwib2JqZWN0SWRzXCIsXG4gICAgICAgIFwicmVsYXRpb25QYXJhbVwiLFxuICAgICAgICBcInRpbWVcIixcbiAgICAgICAgXCJkaXN0YW5jZVwiLFxuICAgICAgICBcInVuaXRzXCIsXG4gICAgICAgIFwib3V0RmllbGRzXCIsXG4gICAgICAgIFwiZ2VvbWV0cnlcIixcbiAgICAgICAgXCJnZW9tZXRyeVR5cGVcIixcbiAgICAgICAgXCJzcGF0aWFsUmVsXCIsXG4gICAgICAgIFwicmV0dXJuR2VvbWV0cnlcIixcbiAgICAgICAgXCJtYXhBbGxvd2FibGVPZmZzZXRcIixcbiAgICAgICAgXCJnZW9tZXRyeVByZWNpc2lvblwiLFxuICAgICAgICBcImluU1JcIixcbiAgICAgICAgXCJvdXRTUlwiLFxuICAgICAgICBcImdkYlZlcnNpb25cIixcbiAgICAgICAgXCJyZXR1cm5EaXN0aW5jdFZhbHVlc1wiLFxuICAgICAgICBcInJldHVybklkc09ubHlcIixcbiAgICAgICAgXCJyZXR1cm5Db3VudE9ubHlcIixcbiAgICAgICAgXCJyZXR1cm5FeHRlbnRPbmx5XCIsXG4gICAgICAgIFwib3JkZXJCeUZpZWxkc1wiLFxuICAgICAgICBcImdyb3VwQnlGaWVsZHNGb3JTdGF0aXN0aWNzXCIsXG4gICAgICAgIFwib3V0U3RhdGlzdGljc1wiLFxuICAgICAgICBcInJldHVyblpcIixcbiAgICAgICAgXCJyZXR1cm5NXCIsXG4gICAgICAgIFwibXVsdGlwYXRjaE9wdGlvblwiLFxuICAgICAgICBcInJlc3VsdE9mZnNldFwiLFxuICAgICAgICBcInJlc3VsdFJlY29yZENvdW50XCIsXG4gICAgICAgIFwicXVhbnRpemF0aW9uUGFyYW1ldGVyc1wiLFxuICAgICAgICBcInJldHVybkNlbnRyb2lkXCIsXG4gICAgICAgIFwicmVzdWx0VHlwZVwiLFxuICAgICAgICBcImhpc3RvcmljTW9tZW50XCIsXG4gICAgICAgIFwicmV0dXJuVHJ1ZUN1cnZlc1wiLFxuICAgICAgICBcInNxbEZvcm1hdFwiLFxuICAgICAgICBcInJldHVybkV4Y2VlZGVkTGltaXRGZWF0dXJlc1wiLFxuICAgICAgICBcImZcIlxuICAgIF0sIHtcbiAgICAgICAgaHR0cE1ldGhvZDogXCJHRVRcIixcbiAgICAgICAgcGFyYW1zOiBfX2Fzc2lnbih7IFxuICAgICAgICAgICAgLy8gc2V0IGRlZmF1bHQgcXVlcnkgcGFyYW1ldGVyc1xuICAgICAgICAgICAgd2hlcmU6IFwiMT0xXCIsIG91dEZpZWxkczogXCIqXCIgfSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKVxuICAgIH0pO1xuICAgIHJldHVybiByZXF1ZXN0KGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi9xdWVyeVwiLCBxdWVyeU9wdGlvbnMpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9cXVlcnkuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyByZXF1ZXN0LCBjbGVhblVybCwgYXBwZW5kQ3VzdG9tUGFyYW1zIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICpcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBxdWVyeVJlbGF0ZWQgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyJ1xuICogLy9cbiAqIHF1ZXJ5UmVsYXRlZCh7XG4gKiAgdXJsOiBcImh0dHA6Ly9zZXJ2aWNlcy5teXNlcnZlci9PcmdJRC9BcmNHSVMvcmVzdC9zZXJ2aWNlcy9QZXRyb2xldW0vS1NQZXRyby9GZWF0dXJlU2VydmVyLzBcIixcbiAqICByZWxhdGlvbnNoaXBJZDogMSxcbiAqICBwYXJhbXM6IHsgcmV0dXJuQ291bnRPbmx5OiB0cnVlIH1cbiAqIH0pXG4gKiAgLnRoZW4ocmVzcG9uc2UpIC8vIHJlc3BvbnNlLnJlbGF0ZWRSZWNvcmRzXG4gKiBgYGBcbiAqIFF1ZXJ5IHRoZSByZWxhdGVkIHJlY29yZHMgZm9yIGEgZmVhdHVyZSBzZXJ2aWNlLiBTZWUgdGhlIFtSRVNUIERvY3VtZW50YXRpb25dKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3Qvc2VydmljZXMtcmVmZXJlbmNlL3F1ZXJ5LXJlbGF0ZWQtcmVjb3Jkcy1mZWF0dXJlLXNlcnZpY2UtLmh0bSkgZm9yIG1vcmUgaW5mb3JtYXRpb24uXG4gKlxuICogQHBhcmFtIHJlcXVlc3RPcHRpb25zXG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgcXVlcnkgcmVzcG9uc2VcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHF1ZXJ5UmVsYXRlZChyZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciBvcHRpb25zID0gYXBwZW5kQ3VzdG9tUGFyYW1zKHJlcXVlc3RPcHRpb25zLCBbXCJvYmplY3RJZHNcIiwgXCJyZWxhdGlvbnNoaXBJZFwiLCBcImRlZmluaXRpb25FeHByZXNzaW9uXCIsIFwib3V0RmllbGRzXCJdLCB7XG4gICAgICAgIGh0dHBNZXRob2Q6IFwiR0VUXCIsXG4gICAgICAgIHBhcmFtczogX19hc3NpZ24oeyBcbiAgICAgICAgICAgIC8vIHNldCBkZWZhdWx0IHF1ZXJ5IHBhcmFtZXRlcnNcbiAgICAgICAgICAgIGRlZmluaXRpb25FeHByZXNzaW9uOiBcIjE9MVwiLCBvdXRGaWVsZHM6IFwiKlwiLCByZWxhdGlvbnNoaXBJZDogMCB9LCByZXF1ZXN0T3B0aW9ucy5wYXJhbXMpXG4gICAgfSk7XG4gICAgcmV0dXJuIHJlcXVlc3QoY2xlYW5VcmwocmVxdWVzdE9wdGlvbnMudXJsKSArIFwiL3F1ZXJ5UmVsYXRlZFJlY29yZHNcIiwgb3B0aW9ucyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1xdWVyeVJlbGF0ZWQuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyByZXF1ZXN0LCBjbGVhblVybCwgYXBwZW5kQ3VzdG9tUGFyYW1zIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICpcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyB1cGRhdGVGZWF0dXJlcyB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXInO1xuICogLy9cbiAqIHVwZGF0ZUZlYXR1cmVzKHtcbiAqICAgdXJsOiBcImh0dHBzOi8vc2FtcGxlc2VydmVyNi5hcmNnaXNvbmxpbmUuY29tL2FyY2dpcy9yZXN0L3NlcnZpY2VzL1NlcnZpY2VSZXF1ZXN0L0ZlYXR1cmVTZXJ2ZXIvMFwiLFxuICogICBmZWF0dXJlczogW3tcbiAqICAgICBnZW9tZXRyeTogeyB4OiAtMTIwLCB5OiA0NSwgc3BhdGlhbFJlZmVyZW5jZTogeyB3a2lkOiA0MzI2IH0gfSxcbiAqICAgICBhdHRyaWJ1dGVzOiB7IHN0YXR1czogXCJhbGl2ZVwiIH1cbiAqICAgfV1cbiAqIH0pO1xuICogYGBgXG4gKiBVcGRhdGUgZmVhdHVyZXMgcmVxdWVzdC4gU2VlIHRoZSBbUkVTVCBEb2N1bWVudGF0aW9uXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3NlcnZpY2VzLXJlZmVyZW5jZS91cGRhdGUtZmVhdHVyZXMuaHRtKSBmb3IgbW9yZSBpbmZvcm1hdGlvbi5cbiAqXG4gKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdC5cbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSB1cGRhdGVGZWF0dXJlcyByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHVwZGF0ZUZlYXR1cmVzKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIHVybCA9IGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi91cGRhdGVGZWF0dXJlc1wiO1xuICAgIC8vIGVkaXQgb3BlcmF0aW9ucyBhcmUgUE9TVCBvbmx5XG4gICAgdmFyIG9wdGlvbnMgPSBhcHBlbmRDdXN0b21QYXJhbXMocmVxdWVzdE9wdGlvbnMsIFtcImZlYXR1cmVzXCIsIFwiZ2RiVmVyc2lvblwiLCBcInJldHVybkVkaXRNb21lbnRcIiwgXCJyb2xsYmFja09uRmFpbHVyZVwiLCBcInRydWVDdXJ2ZUNsaWVudFwiXSwgeyBwYXJhbXM6IF9fYXNzaWduKHt9LCByZXF1ZXN0T3B0aW9ucy5wYXJhbXMpIH0pO1xuICAgIHJldHVybiByZXF1ZXN0KHVybCwgb3B0aW9ucyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD11cGRhdGUuanMubWFwIiwiLyohICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXHJcbkNvcHlyaWdodCAoYykgTWljcm9zb2Z0IENvcnBvcmF0aW9uLlxyXG5cclxuUGVybWlzc2lvbiB0byB1c2UsIGNvcHksIG1vZGlmeSwgYW5kL29yIGRpc3RyaWJ1dGUgdGhpcyBzb2Z0d2FyZSBmb3IgYW55XHJcbnB1cnBvc2Ugd2l0aCBvciB3aXRob3V0IGZlZSBpcyBoZXJlYnkgZ3JhbnRlZC5cclxuXHJcblRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIgQU5EIFRIRSBBVVRIT1IgRElTQ0xBSU1TIEFMTCBXQVJSQU5USUVTIFdJVEhcclxuUkVHQVJEIFRPIFRISVMgU09GVFdBUkUgSU5DTFVESU5HIEFMTCBJTVBMSUVEIFdBUlJBTlRJRVMgT0YgTUVSQ0hBTlRBQklMSVRZXHJcbkFORCBGSVRORVNTLiBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SIEJFIExJQUJMRSBGT1IgQU5ZIFNQRUNJQUwsIERJUkVDVCxcclxuSU5ESVJFQ1QsIE9SIENPTlNFUVVFTlRJQUwgREFNQUdFUyBPUiBBTlkgREFNQUdFUyBXSEFUU09FVkVSIFJFU1VMVElORyBGUk9NXHJcbkxPU1MgT0YgVVNFLCBEQVRBIE9SIFBST0ZJVFMsIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBORUdMSUdFTkNFIE9SXHJcbk9USEVSIFRPUlRJT1VTIEFDVElPTiwgQVJJU0lORyBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBVU0UgT1JcclxuUEVSRk9STUFOQ0UgT0YgVEhJUyBTT0ZUV0FSRS5cclxuKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiogKi9cclxuLyogZ2xvYmFsIFJlZmxlY3QsIFByb21pc2UgKi9cclxuXHJcbnZhciBleHRlbmRTdGF0aWNzID0gZnVuY3Rpb24oZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyA9IE9iamVjdC5zZXRQcm90b3R5cGVPZiB8fFxyXG4gICAgICAgICh7IF9fcHJvdG9fXzogW10gfSBpbnN0YW5jZW9mIEFycmF5ICYmIGZ1bmN0aW9uIChkLCBiKSB7IGQuX19wcm90b19fID0gYjsgfSkgfHxcclxuICAgICAgICBmdW5jdGlvbiAoZCwgYikgeyBmb3IgKHZhciBwIGluIGIpIGlmIChiLmhhc093blByb3BlcnR5KHApKSBkW3BdID0gYltwXTsgfTtcclxuICAgIHJldHVybiBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXh0ZW5kcyhkLCBiKSB7XHJcbiAgICBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG4gICAgZnVuY3Rpb24gX18oKSB7IHRoaXMuY29uc3RydWN0b3IgPSBkOyB9XHJcbiAgICBkLnByb3RvdHlwZSA9IGIgPT09IG51bGwgPyBPYmplY3QuY3JlYXRlKGIpIDogKF9fLnByb3RvdHlwZSA9IGIucHJvdG90eXBlLCBuZXcgX18oKSk7XHJcbn1cclxuXHJcbmV4cG9ydCB2YXIgX19hc3NpZ24gPSBmdW5jdGlvbigpIHtcclxuICAgIF9fYXNzaWduID0gT2JqZWN0LmFzc2lnbiB8fCBmdW5jdGlvbiBfX2Fzc2lnbih0KSB7XHJcbiAgICAgICAgZm9yICh2YXIgcywgaSA9IDEsIG4gPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgbjsgaSsrKSB7XHJcbiAgICAgICAgICAgIHMgPSBhcmd1bWVudHNbaV07XHJcbiAgICAgICAgICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSkgdFtwXSA9IHNbcF07XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHJldHVybiB0O1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIF9fYXNzaWduLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3Jlc3QocywgZSkge1xyXG4gICAgdmFyIHQgPSB7fTtcclxuICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSAmJiBlLmluZGV4T2YocCkgPCAwKVxyXG4gICAgICAgIHRbcF0gPSBzW3BdO1xyXG4gICAgaWYgKHMgIT0gbnVsbCAmJiB0eXBlb2YgT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyA9PT0gXCJmdW5jdGlvblwiKVxyXG4gICAgICAgIGZvciAodmFyIGkgPSAwLCBwID0gT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyhzKTsgaSA8IHAubGVuZ3RoOyBpKyspIHtcclxuICAgICAgICAgICAgaWYgKGUuaW5kZXhPZihwW2ldKSA8IDAgJiYgT2JqZWN0LnByb3RvdHlwZS5wcm9wZXJ0eUlzRW51bWVyYWJsZS5jYWxsKHMsIHBbaV0pKVxyXG4gICAgICAgICAgICAgICAgdFtwW2ldXSA9IHNbcFtpXV07XHJcbiAgICAgICAgfVxyXG4gICAgcmV0dXJuIHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2RlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKSB7XHJcbiAgICB2YXIgYyA9IGFyZ3VtZW50cy5sZW5ndGgsIHIgPSBjIDwgMyA/IHRhcmdldCA6IGRlc2MgPT09IG51bGwgPyBkZXNjID0gT2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih0YXJnZXQsIGtleSkgOiBkZXNjLCBkO1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0LmRlY29yYXRlID09PSBcImZ1bmN0aW9uXCIpIHIgPSBSZWZsZWN0LmRlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKTtcclxuICAgIGVsc2UgZm9yICh2YXIgaSA9IGRlY29yYXRvcnMubGVuZ3RoIC0gMTsgaSA+PSAwOyBpLS0pIGlmIChkID0gZGVjb3JhdG9yc1tpXSkgciA9IChjIDwgMyA/IGQocikgOiBjID4gMyA/IGQodGFyZ2V0LCBrZXksIHIpIDogZCh0YXJnZXQsIGtleSkpIHx8IHI7XHJcbiAgICByZXR1cm4gYyA+IDMgJiYgciAmJiBPYmplY3QuZGVmaW5lUHJvcGVydHkodGFyZ2V0LCBrZXksIHIpLCByO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19wYXJhbShwYXJhbUluZGV4LCBkZWNvcmF0b3IpIHtcclxuICAgIHJldHVybiBmdW5jdGlvbiAodGFyZ2V0LCBrZXkpIHsgZGVjb3JhdG9yKHRhcmdldCwga2V5LCBwYXJhbUluZGV4KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSkge1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0Lm1ldGFkYXRhID09PSBcImZ1bmN0aW9uXCIpIHJldHVybiBSZWZsZWN0Lm1ldGFkYXRhKG1ldGFkYXRhS2V5LCBtZXRhZGF0YVZhbHVlKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXRlcih0aGlzQXJnLCBfYXJndW1lbnRzLCBQLCBnZW5lcmF0b3IpIHtcclxuICAgIGZ1bmN0aW9uIGFkb3B0KHZhbHVlKSB7IHJldHVybiB2YWx1ZSBpbnN0YW5jZW9mIFAgPyB2YWx1ZSA6IG5ldyBQKGZ1bmN0aW9uIChyZXNvbHZlKSB7IHJlc29sdmUodmFsdWUpOyB9KTsgfVxyXG4gICAgcmV0dXJuIG5ldyAoUCB8fCAoUCA9IFByb21pc2UpKShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XHJcbiAgICAgICAgZnVuY3Rpb24gZnVsZmlsbGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yLm5leHQodmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHJlamVjdGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yW1widGhyb3dcIl0odmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHN0ZXAocmVzdWx0KSB7IHJlc3VsdC5kb25lID8gcmVzb2x2ZShyZXN1bHQudmFsdWUpIDogYWRvcHQocmVzdWx0LnZhbHVlKS50aGVuKGZ1bGZpbGxlZCwgcmVqZWN0ZWQpOyB9XHJcbiAgICAgICAgc3RlcCgoZ2VuZXJhdG9yID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pKS5uZXh0KCkpO1xyXG4gICAgfSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2dlbmVyYXRvcih0aGlzQXJnLCBib2R5KSB7XHJcbiAgICB2YXIgXyA9IHsgbGFiZWw6IDAsIHNlbnQ6IGZ1bmN0aW9uKCkgeyBpZiAodFswXSAmIDEpIHRocm93IHRbMV07IHJldHVybiB0WzFdOyB9LCB0cnlzOiBbXSwgb3BzOiBbXSB9LCBmLCB5LCB0LCBnO1xyXG4gICAgcmV0dXJuIGcgPSB7IG5leHQ6IHZlcmIoMCksIFwidGhyb3dcIjogdmVyYigxKSwgXCJyZXR1cm5cIjogdmVyYigyKSB9LCB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgKGdbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uKCkgeyByZXR1cm4gdGhpczsgfSksIGc7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgcmV0dXJuIGZ1bmN0aW9uICh2KSB7IHJldHVybiBzdGVwKFtuLCB2XSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAob3ApIHtcclxuICAgICAgICBpZiAoZikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIkdlbmVyYXRvciBpcyBhbHJlYWR5IGV4ZWN1dGluZy5cIik7XHJcbiAgICAgICAgd2hpbGUgKF8pIHRyeSB7XHJcbiAgICAgICAgICAgIGlmIChmID0gMSwgeSAmJiAodCA9IG9wWzBdICYgMiA/IHlbXCJyZXR1cm5cIl0gOiBvcFswXSA/IHlbXCJ0aHJvd1wiXSB8fCAoKHQgPSB5W1wicmV0dXJuXCJdKSAmJiB0LmNhbGwoeSksIDApIDogeS5uZXh0KSAmJiAhKHQgPSB0LmNhbGwoeSwgb3BbMV0pKS5kb25lKSByZXR1cm4gdDtcclxuICAgICAgICAgICAgaWYgKHkgPSAwLCB0KSBvcCA9IFtvcFswXSAmIDIsIHQudmFsdWVdO1xyXG4gICAgICAgICAgICBzd2l0Y2ggKG9wWzBdKSB7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDA6IGNhc2UgMTogdCA9IG9wOyBicmVhaztcclxuICAgICAgICAgICAgICAgIGNhc2UgNDogXy5sYWJlbCsrOyByZXR1cm4geyB2YWx1ZTogb3BbMV0sIGRvbmU6IGZhbHNlIH07XHJcbiAgICAgICAgICAgICAgICBjYXNlIDU6IF8ubGFiZWwrKzsgeSA9IG9wWzFdOyBvcCA9IFswXTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDc6IG9wID0gXy5vcHMucG9wKCk7IF8udHJ5cy5wb3AoKTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgICAgICAgICAgIGlmICghKHQgPSBfLnRyeXMsIHQgPSB0Lmxlbmd0aCA+IDAgJiYgdFt0Lmxlbmd0aCAtIDFdKSAmJiAob3BbMF0gPT09IDYgfHwgb3BbMF0gPT09IDIpKSB7IF8gPSAwOyBjb250aW51ZTsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gMyAmJiAoIXQgfHwgKG9wWzFdID4gdFswXSAmJiBvcFsxXSA8IHRbM10pKSkgeyBfLmxhYmVsID0gb3BbMV07IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG9wWzBdID09PSA2ICYmIF8ubGFiZWwgPCB0WzFdKSB7IF8ubGFiZWwgPSB0WzFdOyB0ID0gb3A7IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHQgJiYgXy5sYWJlbCA8IHRbMl0pIHsgXy5sYWJlbCA9IHRbMl07IF8ub3BzLnB1c2gob3ApOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0WzJdKSBfLm9wcy5wb3AoKTtcclxuICAgICAgICAgICAgICAgICAgICBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIG9wID0gYm9keS5jYWxsKHRoaXNBcmcsIF8pO1xyXG4gICAgICAgIH0gY2F0Y2ggKGUpIHsgb3AgPSBbNiwgZV07IHkgPSAwOyB9IGZpbmFsbHkgeyBmID0gdCA9IDA7IH1cclxuICAgICAgICBpZiAob3BbMF0gJiA1KSB0aHJvdyBvcFsxXTsgcmV0dXJuIHsgdmFsdWU6IG9wWzBdID8gb3BbMV0gOiB2b2lkIDAsIGRvbmU6IHRydWUgfTtcclxuICAgIH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY3JlYXRlQmluZGluZyhvLCBtLCBrLCBrMikge1xyXG4gICAgaWYgKGsyID09PSB1bmRlZmluZWQpIGsyID0gaztcclxuICAgIG9bazJdID0gbVtrXTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXhwb3J0U3RhcihtLCBleHBvcnRzKSB7XHJcbiAgICBmb3IgKHZhciBwIGluIG0pIGlmIChwICE9PSBcImRlZmF1bHRcIiAmJiAhZXhwb3J0cy5oYXNPd25Qcm9wZXJ0eShwKSkgZXhwb3J0c1twXSA9IG1bcF07XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3ZhbHVlcyhvKSB7XHJcbiAgICB2YXIgcyA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBTeW1ib2wuaXRlcmF0b3IsIG0gPSBzICYmIG9bc10sIGkgPSAwO1xyXG4gICAgaWYgKG0pIHJldHVybiBtLmNhbGwobyk7XHJcbiAgICBpZiAobyAmJiB0eXBlb2Ygby5sZW5ndGggPT09IFwibnVtYmVyXCIpIHJldHVybiB7XHJcbiAgICAgICAgbmV4dDogZnVuY3Rpb24gKCkge1xyXG4gICAgICAgICAgICBpZiAobyAmJiBpID49IG8ubGVuZ3RoKSBvID0gdm9pZCAwO1xyXG4gICAgICAgICAgICByZXR1cm4geyB2YWx1ZTogbyAmJiBvW2krK10sIGRvbmU6ICFvIH07XHJcbiAgICAgICAgfVxyXG4gICAgfTtcclxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IocyA/IFwiT2JqZWN0IGlzIG5vdCBpdGVyYWJsZS5cIiA6IFwiU3ltYm9sLml0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcmVhZChvLCBuKSB7XHJcbiAgICB2YXIgbSA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBvW1N5bWJvbC5pdGVyYXRvcl07XHJcbiAgICBpZiAoIW0pIHJldHVybiBvO1xyXG4gICAgdmFyIGkgPSBtLmNhbGwobyksIHIsIGFyID0gW10sIGU7XHJcbiAgICB0cnkge1xyXG4gICAgICAgIHdoaWxlICgobiA9PT0gdm9pZCAwIHx8IG4tLSA+IDApICYmICEociA9IGkubmV4dCgpKS5kb25lKSBhci5wdXNoKHIudmFsdWUpO1xyXG4gICAgfVxyXG4gICAgY2F0Y2ggKGVycm9yKSB7IGUgPSB7IGVycm9yOiBlcnJvciB9OyB9XHJcbiAgICBmaW5hbGx5IHtcclxuICAgICAgICB0cnkge1xyXG4gICAgICAgICAgICBpZiAociAmJiAhci5kb25lICYmIChtID0gaVtcInJldHVyblwiXSkpIG0uY2FsbChpKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgZmluYWxseSB7IGlmIChlKSB0aHJvdyBlLmVycm9yOyB9XHJcbiAgICB9XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZCgpIHtcclxuICAgIGZvciAodmFyIGFyID0gW10sIGkgPSAwOyBpIDwgYXJndW1lbnRzLmxlbmd0aDsgaSsrKVxyXG4gICAgICAgIGFyID0gYXIuY29uY2F0KF9fcmVhZChhcmd1bWVudHNbaV0pKTtcclxuICAgIHJldHVybiBhcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fc3ByZWFkQXJyYXlzKCkge1xyXG4gICAgZm9yICh2YXIgcyA9IDAsIGkgPSAwLCBpbCA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBpbDsgaSsrKSBzICs9IGFyZ3VtZW50c1tpXS5sZW5ndGg7XHJcbiAgICBmb3IgKHZhciByID0gQXJyYXkocyksIGsgPSAwLCBpID0gMDsgaSA8IGlsOyBpKyspXHJcbiAgICAgICAgZm9yICh2YXIgYSA9IGFyZ3VtZW50c1tpXSwgaiA9IDAsIGpsID0gYS5sZW5ndGg7IGogPCBqbDsgaisrLCBrKyspXHJcbiAgICAgICAgICAgIHJba10gPSBhW2pdO1xyXG4gICAgcmV0dXJuIHI7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hd2FpdCh2KSB7XHJcbiAgICByZXR1cm4gdGhpcyBpbnN0YW5jZW9mIF9fYXdhaXQgPyAodGhpcy52ID0gdiwgdGhpcykgOiBuZXcgX19hd2FpdCh2KTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNHZW5lcmF0b3IodGhpc0FyZywgX2FyZ3VtZW50cywgZ2VuZXJhdG9yKSB7XHJcbiAgICBpZiAoIVN5bWJvbC5hc3luY0l0ZXJhdG9yKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU3ltYm9sLmFzeW5jSXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgdmFyIGcgPSBnZW5lcmF0b3IuYXBwbHkodGhpc0FyZywgX2FyZ3VtZW50cyB8fCBbXSksIGksIHEgPSBbXTtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyBpZiAoZ1tuXSkgaVtuXSA9IGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAoYSwgYikgeyBxLnB1c2goW24sIHYsIGEsIGJdKSA+IDEgfHwgcmVzdW1lKG4sIHYpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gcmVzdW1lKG4sIHYpIHsgdHJ5IHsgc3RlcChnW25dKHYpKTsgfSBjYXRjaCAoZSkgeyBzZXR0bGUocVswXVszXSwgZSk7IH0gfVxyXG4gICAgZnVuY3Rpb24gc3RlcChyKSB7IHIudmFsdWUgaW5zdGFuY2VvZiBfX2F3YWl0ID8gUHJvbWlzZS5yZXNvbHZlKHIudmFsdWUudikudGhlbihmdWxmaWxsLCByZWplY3QpIDogc2V0dGxlKHFbMF1bMl0sIHIpOyB9XHJcbiAgICBmdW5jdGlvbiBmdWxmaWxsKHZhbHVlKSB7IHJlc3VtZShcIm5leHRcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiByZWplY3QodmFsdWUpIHsgcmVzdW1lKFwidGhyb3dcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUoZiwgdikgeyBpZiAoZih2KSwgcS5zaGlmdCgpLCBxLmxlbmd0aCkgcmVzdW1lKHFbMF1bMF0sIHFbMF1bMV0pOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jRGVsZWdhdG9yKG8pIHtcclxuICAgIHZhciBpLCBwO1xyXG4gICAgcmV0dXJuIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiLCBmdW5jdGlvbiAoZSkgeyB0aHJvdyBlOyB9KSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuaXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobiwgZikgeyBpW25dID0gb1tuXSA/IGZ1bmN0aW9uICh2KSB7IHJldHVybiAocCA9ICFwKSA/IHsgdmFsdWU6IF9fYXdhaXQob1tuXSh2KSksIGRvbmU6IG4gPT09IFwicmV0dXJuXCIgfSA6IGYgPyBmKHYpIDogdjsgfSA6IGY7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNWYWx1ZXMobykge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBtID0gb1tTeW1ib2wuYXN5bmNJdGVyYXRvcl0sIGk7XHJcbiAgICByZXR1cm4gbSA/IG0uY2FsbChvKSA6IChvID0gdHlwZW9mIF9fdmFsdWVzID09PSBcImZ1bmN0aW9uXCIgPyBfX3ZhbHVlcyhvKSA6IG9bU3ltYm9sLml0ZXJhdG9yXSgpLCBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaSk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaVtuXSA9IG9bbl0gJiYgZnVuY3Rpb24gKHYpIHsgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHsgdiA9IG9bbl0odiksIHNldHRsZShyZXNvbHZlLCByZWplY3QsIHYuZG9uZSwgdi52YWx1ZSk7IH0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCBkLCB2KSB7IFByb21pc2UucmVzb2x2ZSh2KS50aGVuKGZ1bmN0aW9uKHYpIHsgcmVzb2x2ZSh7IHZhbHVlOiB2LCBkb25lOiBkIH0pOyB9LCByZWplY3QpOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX21ha2VUZW1wbGF0ZU9iamVjdChjb29rZWQsIHJhdykge1xyXG4gICAgaWYgKE9iamVjdC5kZWZpbmVQcm9wZXJ0eSkgeyBPYmplY3QuZGVmaW5lUHJvcGVydHkoY29va2VkLCBcInJhd1wiLCB7IHZhbHVlOiByYXcgfSk7IH0gZWxzZSB7IGNvb2tlZC5yYXcgPSByYXc7IH1cclxuICAgIHJldHVybiBjb29rZWQ7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnRTdGFyKG1vZCkge1xyXG4gICAgaWYgKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgcmV0dXJuIG1vZDtcclxuICAgIHZhciByZXN1bHQgPSB7fTtcclxuICAgIGlmIChtb2QgIT0gbnVsbCkgZm9yICh2YXIgayBpbiBtb2QpIGlmIChPYmplY3QuaGFzT3duUHJvcGVydHkuY2FsbChtb2QsIGspKSByZXN1bHRba10gPSBtb2Rba107XHJcbiAgICByZXN1bHQuZGVmYXVsdCA9IG1vZDtcclxuICAgIHJldHVybiByZXN1bHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2ltcG9ydERlZmF1bHQobW9kKSB7XHJcbiAgICByZXR1cm4gKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgPyBtb2QgOiB7IGRlZmF1bHQ6IG1vZCB9O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZEdldChyZWNlaXZlciwgcHJpdmF0ZU1hcCkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIGdldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHJldHVybiBwcml2YXRlTWFwLmdldChyZWNlaXZlcik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NsYXNzUHJpdmF0ZUZpZWxkU2V0KHJlY2VpdmVyLCBwcml2YXRlTWFwLCB2YWx1ZSkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIHNldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHByaXZhdGVNYXAuc2V0KHJlY2VpdmVyLCB2YWx1ZSk7XHJcbiAgICByZXR1cm4gdmFsdWU7XHJcbn1cclxuIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24sIF9fZXh0ZW5kcyB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgZW5jb2RlRm9ybURhdGEgfSBmcm9tIFwiLi91dGlscy9lbmNvZGUtZm9ybS1kYXRhXCI7XG5pbXBvcnQgeyBlbmNvZGVRdWVyeVN0cmluZyB9IGZyb20gXCIuL3V0aWxzL2VuY29kZS1xdWVyeS1zdHJpbmdcIjtcbmltcG9ydCB7IHJlcXVpcmVzRm9ybURhdGEgfSBmcm9tIFwiLi91dGlscy9wcm9jZXNzLXBhcmFtc1wiO1xuaW1wb3J0IHsgQXJjR0lTUmVxdWVzdEVycm9yIH0gZnJvbSBcIi4vdXRpbHMvQXJjR0lTUmVxdWVzdEVycm9yXCI7XG5pbXBvcnQgeyB3YXJuIH0gZnJvbSBcIi4vdXRpbHMvd2FyblwiO1xuZXhwb3J0IHZhciBOT0RFSlNfREVGQVVMVF9SRUZFUkVSX0hFQURFUiA9IFwiQGVzcmkvYXJjZ2lzLXJlc3QtanNcIjtcbnZhciBERUZBVUxUX0FSQ0dJU19SRVFVRVNUX09QVElPTlMgPSB7XG4gICAgaHR0cE1ldGhvZDogXCJQT1NUXCIsXG4gICAgcGFyYW1zOiB7XG4gICAgICAgIGY6IFwianNvblwiLFxuICAgIH0sXG59O1xuLyoqXG4gKiBTZXRzIHRoZSBkZWZhdWx0IG9wdGlvbnMgdGhhdCB3aWxsIGJlIHBhc3NlZCBpbiAqKmFsbCByZXF1ZXN0cyBhY3Jvc3MgYWxsIGBAZXNyaS9hcmNnaXMtcmVzdC1qc2AgbW9kdWxlcyoqLlxuICpcbiAqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgc2V0RGVmYXVsdFJlcXVlc3RPcHRpb25zIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbiAqIHNldERlZmF1bHRSZXF1ZXN0T3B0aW9ucyh7XG4gKiAgIGF1dGhlbnRpY2F0aW9uOiB1c2VyU2Vzc2lvbiAvLyBhbGwgcmVxdWVzdHMgd2lsbCB1c2UgdGhpcyBzZXNzaW9uIGJ5IGRlZmF1bHRcbiAqIH0pXG4gKiBgYGBcbiAqIFlvdSBzaG91bGQgKipuZXZlcioqIHNldCBhIGRlZmF1bHQgYGF1dGhlbnRpY2F0aW9uYCB3aGVuIHlvdSBhcmUgaW4gYSBzZXJ2ZXIgc2lkZSBlbnZpcm9ubWVudCB3aGVyZSB5b3UgbWF5IGJlIGhhbmRsaW5nIHJlcXVlc3RzIGZvciBtYW55IGRpZmZlcmVudCBhdXRoZW50aWNhdGVkIHVzZXJzLlxuICpcbiAqIEBwYXJhbSBvcHRpb25zIFRoZSBkZWZhdWx0IG9wdGlvbnMgdG8gcGFzcyB3aXRoIGV2ZXJ5IHJlcXVlc3QuIEV4aXN0aW5nIGRlZmF1bHQgd2lsbCBiZSBvdmVyd3JpdHRlbi5cbiAqIEBwYXJhbSBoaWRlV2FybmluZ3MgU2lsZW5jZSB3YXJuaW5ncyBhYm91dCBzZXR0aW5nIGRlZmF1bHQgYGF1dGhlbnRpY2F0aW9uYCBpbiBzaGFyZWQgZW52aXJvbm1lbnRzLlxuICovXG5leHBvcnQgZnVuY3Rpb24gc2V0RGVmYXVsdFJlcXVlc3RPcHRpb25zKG9wdGlvbnMsIGhpZGVXYXJuaW5ncykge1xuICAgIGlmIChvcHRpb25zLmF1dGhlbnRpY2F0aW9uICYmICFoaWRlV2FybmluZ3MpIHtcbiAgICAgICAgd2FybihcIllvdSBzaG91bGQgbm90IHNldCBgYXV0aGVudGljYXRpb25gIGFzIGEgZGVmYXVsdCBpbiBhIHNoYXJlZCBlbnZpcm9ubWVudCBzdWNoIGFzIGEgd2ViIHNlcnZlciB3aGljaCB3aWxsIHByb2Nlc3MgbXVsdGlwbGUgdXNlcnMgcmVxdWVzdHMuIFlvdSBjYW4gY2FsbCBgc2V0RGVmYXVsdFJlcXVlc3RPcHRpb25zYCB3aXRoIGB0cnVlYCBhcyBhIHNlY29uZCBhcmd1bWVudCB0byBkaXNhYmxlIHRoaXMgd2FybmluZy5cIik7XG4gICAgfVxuICAgIERFRkFVTFRfQVJDR0lTX1JFUVVFU1RfT1BUSU9OUyA9IG9wdGlvbnM7XG59XG52YXIgQXJjR0lTQXV0aEVycm9yID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhBcmNHSVNBdXRoRXJyb3IsIF9zdXBlcik7XG4gICAgLyoqXG4gICAgICogQ3JlYXRlIGEgbmV3IGBBcmNHSVNBdXRoRXJyb3JgICBvYmplY3QuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gbWVzc2FnZSAtIFRoZSBlcnJvciBtZXNzYWdlIGZyb20gdGhlIEFQSVxuICAgICAqIEBwYXJhbSBjb2RlIC0gVGhlIGVycm9yIGNvZGUgZnJvbSB0aGUgQVBJXG4gICAgICogQHBhcmFtIHJlc3BvbnNlIC0gVGhlIG9yaWdpbmFsIHJlc3BvbnNlIGZyb20gdGhlIEFQSSB0aGF0IGNhdXNlZCB0aGUgZXJyb3JcbiAgICAgKiBAcGFyYW0gdXJsIC0gVGhlIG9yaWdpbmFsIHVybCBvZiB0aGUgcmVxdWVzdFxuICAgICAqIEBwYXJhbSBvcHRpb25zIC0gVGhlIG9yaWdpbmFsIG9wdGlvbnMgb2YgdGhlIHJlcXVlc3RcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBBcmNHSVNBdXRoRXJyb3IobWVzc2FnZSwgY29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucykge1xuICAgICAgICBpZiAobWVzc2FnZSA9PT0gdm9pZCAwKSB7IG1lc3NhZ2UgPSBcIkFVVEhFTlRJQ0FUSU9OX0VSUk9SXCI7IH1cbiAgICAgICAgaWYgKGNvZGUgPT09IHZvaWQgMCkgeyBjb2RlID0gXCJBVVRIRU5USUNBVElPTl9FUlJPUl9DT0RFXCI7IH1cbiAgICAgICAgdmFyIF90aGlzID0gX3N1cGVyLmNhbGwodGhpcywgbWVzc2FnZSwgY29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucykgfHwgdGhpcztcbiAgICAgICAgX3RoaXMubmFtZSA9IFwiQXJjR0lTQXV0aEVycm9yXCI7XG4gICAgICAgIF90aGlzLm1lc3NhZ2UgPVxuICAgICAgICAgICAgY29kZSA9PT0gXCJBVVRIRU5USUNBVElPTl9FUlJPUl9DT0RFXCIgPyBtZXNzYWdlIDogY29kZSArIFwiOiBcIiArIG1lc3NhZ2U7XG4gICAgICAgIHJldHVybiBfdGhpcztcbiAgICB9XG4gICAgQXJjR0lTQXV0aEVycm9yLnByb3RvdHlwZS5yZXRyeSA9IGZ1bmN0aW9uIChnZXRTZXNzaW9uLCByZXRyeUxpbWl0KSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIGlmIChyZXRyeUxpbWl0ID09PSB2b2lkIDApIHsgcmV0cnlMaW1pdCA9IDM7IH1cbiAgICAgICAgdmFyIHRyaWVzID0gMDtcbiAgICAgICAgdmFyIHJldHJ5UmVxdWVzdCA9IGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcbiAgICAgICAgICAgIGdldFNlc3Npb24oX3RoaXMudXJsLCBfdGhpcy5vcHRpb25zKVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChzZXNzaW9uKSB7XG4gICAgICAgICAgICAgICAgdmFyIG5ld09wdGlvbnMgPSBfX2Fzc2lnbihfX2Fzc2lnbih7fSwgX3RoaXMub3B0aW9ucyksIHsgYXV0aGVudGljYXRpb246IHNlc3Npb24gfSk7XG4gICAgICAgICAgICAgICAgdHJpZXMgPSB0cmllcyArIDE7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlcXVlc3QoX3RoaXMudXJsLCBuZXdPcHRpb25zKTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgcmVzb2x2ZShyZXNwb25zZSk7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoZSkge1xuICAgICAgICAgICAgICAgIGlmIChlLm5hbWUgPT09IFwiQXJjR0lTQXV0aEVycm9yXCIgJiYgdHJpZXMgPCByZXRyeUxpbWl0KSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHJ5UmVxdWVzdChyZXNvbHZlLCByZWplY3QpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmIChlLm5hbWUgPT09IFwiQXJjR0lTQXV0aEVycm9yXCIgJiYgdHJpZXMgPj0gcmV0cnlMaW1pdCkge1xuICAgICAgICAgICAgICAgICAgICByZWplY3QoX3RoaXMpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xuICAgICAgICAgICAgcmV0cnlSZXF1ZXN0KHJlc29sdmUsIHJlamVjdCk7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgcmV0dXJuIEFyY0dJU0F1dGhFcnJvcjtcbn0oQXJjR0lTUmVxdWVzdEVycm9yKSk7XG5leHBvcnQgeyBBcmNHSVNBdXRoRXJyb3IgfTtcbi8qKlxuICogQ2hlY2tzIGZvciBlcnJvcnMgaW4gYSBKU09OIHJlc3BvbnNlIGZyb20gdGhlIEFyY0dJUyBSRVNUIEFQSS4gSWYgdGhlcmUgYXJlIG5vIGVycm9ycywgaXQgd2lsbCByZXR1cm4gdGhlIGBkYXRhYCBwYXNzZWQgaW4uIElmIHRoZXJlIGlzIGFuIGVycm9yLCBpdCB3aWxsIHRocm93IGFuIGBBcmNHSVNSZXF1ZXN0RXJyb3JgIG9yIGBBcmNHSVNBdXRoRXJyb3JgLlxuICpcbiAqIEBwYXJhbSBkYXRhIFRoZSByZXNwb25zZSBKU09OIHRvIGNoZWNrIGZvciBlcnJvcnMuXG4gKiBAcGFyYW0gdXJsIFRoZSB1cmwgb2YgdGhlIG9yaWdpbmFsIHJlcXVlc3RcbiAqIEBwYXJhbSBwYXJhbXMgVGhlIHBhcmFtZXRlcnMgb2YgdGhlIG9yaWdpbmFsIHJlcXVlc3RcbiAqIEBwYXJhbSBvcHRpb25zIFRoZSBvcHRpb25zIG9mIHRoZSBvcmlnaW5hbCByZXF1ZXN0XG4gKiBAcmV0dXJucyBUaGUgZGF0YSB0aGF0IHdhcyBwYXNzZWQgaW4gdGhlIGBkYXRhYCBwYXJhbWV0ZXJcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNoZWNrRm9yRXJyb3JzKHJlc3BvbnNlLCB1cmwsIHBhcmFtcywgb3B0aW9ucywgb3JpZ2luYWxBdXRoRXJyb3IpIHtcbiAgICAvLyB0aGlzIGlzIGFuIGVycm9yIG1lc3NhZ2UgZnJvbSBiaWxsaW5nLmFyY2dpcy5jb20gYmFja2VuZFxuICAgIGlmIChyZXNwb25zZS5jb2RlID49IDQwMCkge1xuICAgICAgICB2YXIgbWVzc2FnZSA9IHJlc3BvbnNlLm1lc3NhZ2UsIGNvZGUgPSByZXNwb25zZS5jb2RlO1xuICAgICAgICB0aHJvdyBuZXcgQXJjR0lTUmVxdWVzdEVycm9yKG1lc3NhZ2UsIGNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpO1xuICAgIH1cbiAgICAvLyBlcnJvciBmcm9tIEFyY0dJUyBPbmxpbmUgb3IgYW4gQXJjR0lTIFBvcnRhbCBvciBzZXJ2ZXIgaW5zdGFuY2UuXG4gICAgaWYgKHJlc3BvbnNlLmVycm9yKSB7XG4gICAgICAgIHZhciBfYSA9IHJlc3BvbnNlLmVycm9yLCBtZXNzYWdlID0gX2EubWVzc2FnZSwgY29kZSA9IF9hLmNvZGUsIG1lc3NhZ2VDb2RlID0gX2EubWVzc2FnZUNvZGU7XG4gICAgICAgIHZhciBlcnJvckNvZGUgPSBtZXNzYWdlQ29kZSB8fCBjb2RlIHx8IFwiVU5LTk9XTl9FUlJPUl9DT0RFXCI7XG4gICAgICAgIGlmIChjb2RlID09PSA0OTggfHxcbiAgICAgICAgICAgIGNvZGUgPT09IDQ5OSB8fFxuICAgICAgICAgICAgbWVzc2FnZUNvZGUgPT09IFwiR1dNXzAwMDNcIiB8fFxuICAgICAgICAgICAgKGNvZGUgPT09IDQwMCAmJiBtZXNzYWdlID09PSBcIlVuYWJsZSB0byBnZW5lcmF0ZSB0b2tlbi5cIikpIHtcbiAgICAgICAgICAgIGlmIChvcmlnaW5hbEF1dGhFcnJvcikge1xuICAgICAgICAgICAgICAgIHRocm93IG9yaWdpbmFsQXV0aEVycm9yO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEFyY0dJU0F1dGhFcnJvcihtZXNzYWdlLCBlcnJvckNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHRocm93IG5ldyBBcmNHSVNSZXF1ZXN0RXJyb3IobWVzc2FnZSwgZXJyb3JDb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKTtcbiAgICB9XG4gICAgLy8gZXJyb3IgZnJvbSBhIHN0YXR1cyBjaGVja1xuICAgIGlmIChyZXNwb25zZS5zdGF0dXMgPT09IFwiZmFpbGVkXCIgfHwgcmVzcG9uc2Uuc3RhdHVzID09PSBcImZhaWx1cmVcIikge1xuICAgICAgICB2YXIgbWVzc2FnZSA9IHZvaWQgMDtcbiAgICAgICAgdmFyIGNvZGUgPSBcIlVOS05PV05fRVJST1JfQ09ERVwiO1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgbWVzc2FnZSA9IEpTT04ucGFyc2UocmVzcG9uc2Uuc3RhdHVzTWVzc2FnZSkubWVzc2FnZTtcbiAgICAgICAgICAgIGNvZGUgPSBKU09OLnBhcnNlKHJlc3BvbnNlLnN0YXR1c01lc3NhZ2UpLmNvZGU7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgIG1lc3NhZ2UgPSByZXNwb25zZS5zdGF0dXNNZXNzYWdlIHx8IHJlc3BvbnNlLm1lc3NhZ2U7XG4gICAgICAgIH1cbiAgICAgICAgdGhyb3cgbmV3IEFyY0dJU1JlcXVlc3RFcnJvcihtZXNzYWdlLCBjb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3BvbnNlO1xufVxuLyoqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgcmVxdWVzdCB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QnO1xuICogLy9cbiAqIHJlcXVlc3QoJ2h0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0JylcbiAqICAgLnRoZW4ocmVzcG9uc2UpIC8vIHJlc3BvbnNlLmN1cnJlbnRWZXJzaW9uID09PSA1LjJcbiAqIC8vXG4gKiByZXF1ZXN0KCdodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdCcsIHtcbiAqICAgaHR0cE1ldGhvZDogXCJHRVRcIlxuICogfSlcbiAqIC8vXG4gKiByZXF1ZXN0KCdodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdC9zZWFyY2gnLCB7XG4gKiAgIHBhcmFtczogeyBxOiAncGFya3MnIH1cbiAqIH0pXG4gKiAgIC50aGVuKHJlc3BvbnNlKSAvLyByZXNwb25zZS50b3RhbCA9PiA3ODM3OVxuICogYGBgXG4gKiBHZW5lcmljIG1ldGhvZCBmb3IgbWFraW5nIEhUVFAgcmVxdWVzdHMgdG8gQXJjR0lTIFJFU1QgQVBJIGVuZHBvaW50cy5cbiAqXG4gKiBAcGFyYW0gdXJsIC0gVGhlIFVSTCBvZiB0aGUgQXJjR0lTIFJFU1QgQVBJIGVuZHBvaW50LlxuICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3QsIGluY2x1ZGluZyBwYXJhbWV0ZXJzIHJlbGV2YW50IHRvIHRoZSBlbmRwb2ludC5cbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBkYXRhIGZyb20gdGhlIHJlc3BvbnNlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gcmVxdWVzdCh1cmwsIHJlcXVlc3RPcHRpb25zKSB7XG4gICAgaWYgKHJlcXVlc3RPcHRpb25zID09PSB2b2lkIDApIHsgcmVxdWVzdE9wdGlvbnMgPSB7IHBhcmFtczogeyBmOiBcImpzb25cIiB9IH07IH1cbiAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKF9fYXNzaWduKF9fYXNzaWduKHsgaHR0cE1ldGhvZDogXCJQT1NUXCIgfSwgREVGQVVMVF9BUkNHSVNfUkVRVUVTVF9PUFRJT05TKSwgcmVxdWVzdE9wdGlvbnMpLCB7XG4gICAgICAgIHBhcmFtczogX19hc3NpZ24oX19hc3NpZ24oe30sIERFRkFVTFRfQVJDR0lTX1JFUVVFU1RfT1BUSU9OUy5wYXJhbXMpLCByZXF1ZXN0T3B0aW9ucy5wYXJhbXMpLFxuICAgICAgICBoZWFkZXJzOiBfX2Fzc2lnbihfX2Fzc2lnbih7fSwgREVGQVVMVF9BUkNHSVNfUkVRVUVTVF9PUFRJT05TLmhlYWRlcnMpLCByZXF1ZXN0T3B0aW9ucy5oZWFkZXJzKSxcbiAgICB9KTtcbiAgICB2YXIgbWlzc2luZ0dsb2JhbHMgPSBbXTtcbiAgICB2YXIgcmVjb21tZW5kZWRQYWNrYWdlcyA9IFtdO1xuICAgIC8vIGRvbid0IGNoZWNrIGZvciBhIGdsb2JhbCBmZXRjaCBpZiBhIGN1c3RvbSBpbXBsZW1lbnRhdGlvbiB3YXMgcGFzc2VkIHRocm91Z2hcbiAgICBpZiAoIW9wdGlvbnMuZmV0Y2ggJiYgdHlwZW9mIGZldGNoICE9PSBcInVuZGVmaW5lZFwiKSB7XG4gICAgICAgIG9wdGlvbnMuZmV0Y2ggPSBmZXRjaC5iaW5kKEZ1bmN0aW9uKFwicmV0dXJuIHRoaXNcIikoKSk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBtaXNzaW5nR2xvYmFscy5wdXNoKFwiYGZldGNoYFwiKTtcbiAgICAgICAgcmVjb21tZW5kZWRQYWNrYWdlcy5wdXNoKFwiYG5vZGUtZmV0Y2hgXCIpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIFByb21pc2UgPT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgbWlzc2luZ0dsb2JhbHMucHVzaChcImBQcm9taXNlYFwiKTtcbiAgICAgICAgcmVjb21tZW5kZWRQYWNrYWdlcy5wdXNoKFwiYGVzNi1wcm9taXNlYFwiKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBGb3JtRGF0YSA9PT0gXCJ1bmRlZmluZWRcIikge1xuICAgICAgICBtaXNzaW5nR2xvYmFscy5wdXNoKFwiYEZvcm1EYXRhYFwiKTtcbiAgICAgICAgcmVjb21tZW5kZWRQYWNrYWdlcy5wdXNoKFwiYGlzb21vcnBoaWMtZm9ybS1kYXRhYFwiKTtcbiAgICB9XG4gICAgaWYgKCFvcHRpb25zLmZldGNoIHx8XG4gICAgICAgIHR5cGVvZiBQcm9taXNlID09PSBcInVuZGVmaW5lZFwiIHx8XG4gICAgICAgIHR5cGVvZiBGb3JtRGF0YSA9PT0gXCJ1bmRlZmluZWRcIikge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJgYXJjZ2lzLXJlc3QtcmVxdWVzdGAgcmVxdWlyZXMgYSBgZmV0Y2hgIGltcGxlbWVudGF0aW9uIGFuZCBnbG9iYWwgdmFyaWFibGVzIGZvciBgUHJvbWlzZWAgYW5kIGBGb3JtRGF0YWAgdG8gYmUgcHJlc2VudCBpbiB0aGUgZ2xvYmFsIHNjb3BlLiBZb3UgYXJlIG1pc3NpbmcgXCIgKyBtaXNzaW5nR2xvYmFscy5qb2luKFwiLCBcIikgKyBcIi4gV2UgcmVjb21tZW5kIGluc3RhbGxpbmcgdGhlIFwiICsgcmVjb21tZW5kZWRQYWNrYWdlcy5qb2luKFwiLCBcIikgKyBcIiBtb2R1bGVzIGF0IHRoZSByb290IG9mIHlvdXIgYXBwbGljYXRpb24gdG8gYWRkIHRoZXNlIHRvIHRoZSBnbG9iYWwgc2NvcGUuIFNlZSBodHRwczovL2JpdC5seS8yS053V2FKIGZvciBtb3JlIGluZm8uXCIpO1xuICAgIH1cbiAgICB2YXIgaHR0cE1ldGhvZCA9IG9wdGlvbnMuaHR0cE1ldGhvZCwgYXV0aGVudGljYXRpb24gPSBvcHRpb25zLmF1dGhlbnRpY2F0aW9uLCByYXdSZXNwb25zZSA9IG9wdGlvbnMucmF3UmVzcG9uc2U7XG4gICAgdmFyIHBhcmFtcyA9IF9fYXNzaWduKHsgZjogXCJqc29uXCIgfSwgb3B0aW9ucy5wYXJhbXMpO1xuICAgIHZhciBvcmlnaW5hbEF1dGhFcnJvciA9IG51bGw7XG4gICAgdmFyIGZldGNoT3B0aW9ucyA9IHtcbiAgICAgICAgbWV0aG9kOiBodHRwTWV0aG9kLFxuICAgICAgICAvKiBlbnN1cmVzIGJlaGF2aW9yIG1pbWljcyBYTUxIdHRwUmVxdWVzdC5cbiAgICAgICAgbmVlZGVkIHRvIHN1cHBvcnQgc2VuZGluZyBJV0EgY29va2llcyAqL1xuICAgICAgICBjcmVkZW50aWFsczogb3B0aW9ucy5jcmVkZW50aWFscyB8fCBcInNhbWUtb3JpZ2luXCIsXG4gICAgfTtcbiAgICAvLyB0aGUgL29hdXRoMi9wbGF0Zm9ybVNlbGYgcm91dGUgd2lsbCBhZGQgWC1Fc3JpLUF1dGgtQ2xpZW50LUlkIGhlYWRlclxuICAgIC8vIGFuZCB0aGF0IHJlcXVlc3QgbmVlZHMgdG8gc2VuZCBjb29raWVzIGNyb3NzIGRvbWFpblxuICAgIC8vIHNvIHdlIG5lZWQgdG8gc2V0IHRoZSBjcmVkZW50aWFscyB0byBcImluY2x1ZGVcIlxuICAgIGlmIChvcHRpb25zLmhlYWRlcnMgJiZcbiAgICAgICAgb3B0aW9ucy5oZWFkZXJzW1wiWC1Fc3JpLUF1dGgtQ2xpZW50LUlkXCJdICYmXG4gICAgICAgIHVybC5pbmRleE9mKFwiL29hdXRoMi9wbGF0Zm9ybVNlbGZcIikgPiAtMSkge1xuICAgICAgICBmZXRjaE9wdGlvbnMuY3JlZGVudGlhbHMgPSBcImluY2x1ZGVcIjtcbiAgICB9XG4gICAgcmV0dXJuIChhdXRoZW50aWNhdGlvblxuICAgICAgICA/IGF1dGhlbnRpY2F0aW9uLmdldFRva2VuKHVybCwgeyBmZXRjaDogb3B0aW9ucy5mZXRjaCB9KS5jYXRjaChmdW5jdGlvbiAoZXJyKSB7XG4gICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAqIGFwcGVuZCBvcmlnaW5hbCByZXF1ZXN0IHVybCBhbmQgcmVxdWVzdE9wdGlvbnNcbiAgICAgICAgICAgICAqIHRvIHRoZSBlcnJvciB0aHJvd24gYnkgZ2V0VG9rZW4oKVxuICAgICAgICAgICAgICogdG8gYXNzaXN0IHdpdGggcmV0cnlpbmdcbiAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgZXJyLnVybCA9IHVybDtcbiAgICAgICAgICAgIGVyci5vcHRpb25zID0gb3B0aW9ucztcbiAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICogaWYgYW4gYXR0ZW1wdCBpcyBtYWRlIHRvIHRhbGsgdG8gYW4gdW5mZWRlcmF0ZWQgc2VydmVyXG4gICAgICAgICAgICAgKiBmaXJzdCB0cnkgdGhlIHJlcXVlc3QgYW5vbnltb3VzbHkuIGlmIGEgJ3Rva2VuIHJlcXVpcmVkJ1xuICAgICAgICAgICAgICogZXJyb3IgaXMgdGhyb3duLCB0aHJvdyB0aGUgVU5GRURFUkFURUQgZXJyb3IgdGhlbi5cbiAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgb3JpZ2luYWxBdXRoRXJyb3IgPSBlcnI7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKFwiXCIpO1xuICAgICAgICB9KVxuICAgICAgICA6IFByb21pc2UucmVzb2x2ZShcIlwiKSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHRva2VuKSB7XG4gICAgICAgIGlmICh0b2tlbi5sZW5ndGgpIHtcbiAgICAgICAgICAgIHBhcmFtcy50b2tlbiA9IHRva2VuO1xuICAgICAgICB9XG4gICAgICAgIGlmIChhdXRoZW50aWNhdGlvbiAmJiBhdXRoZW50aWNhdGlvbi5nZXREb21haW5DcmVkZW50aWFscykge1xuICAgICAgICAgICAgZmV0Y2hPcHRpb25zLmNyZWRlbnRpYWxzID0gYXV0aGVudGljYXRpb24uZ2V0RG9tYWluQ3JlZGVudGlhbHModXJsKTtcbiAgICAgICAgfVxuICAgICAgICAvLyBDdXN0b20gaGVhZGVycyB0byBhZGQgdG8gcmVxdWVzdC4gSVJlcXVlc3RPcHRpb25zLmhlYWRlcnMgd2l0aCBtZXJnZSBvdmVyIHJlcXVlc3RIZWFkZXJzLlxuICAgICAgICB2YXIgcmVxdWVzdEhlYWRlcnMgPSB7fTtcbiAgICAgICAgaWYgKGZldGNoT3B0aW9ucy5tZXRob2QgPT09IFwiR0VUXCIpIHtcbiAgICAgICAgICAgIC8vIFByZXZlbnRzIHRva2VuIGZyb20gYmVpbmcgcGFzc2VkIGluIHF1ZXJ5IHBhcmFtcyB3aGVuIGhpZGVUb2tlbiBvcHRpb24gaXMgdXNlZC5cbiAgICAgICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBpZiAtIHdpbmRvdyBpcyBhbHdheXMgZGVmaW5lZCBpbiBhIGJyb3dzZXIuIFRlc3QgY2FzZSBpcyBjb3ZlcmVkIGJ5IEphc21pbmUgaW4gbm9kZSB0ZXN0ICovXG4gICAgICAgICAgICBpZiAocGFyYW1zLnRva2VuICYmXG4gICAgICAgICAgICAgICAgb3B0aW9ucy5oaWRlVG9rZW4gJiZcbiAgICAgICAgICAgICAgICAvLyBTaGFyaW5nIEFQSSBkb2VzIG5vdCBzdXBwb3J0IHByZWZsaWdodCBjaGVjayByZXF1aXJlZCBieSBtb2Rlcm4gYnJvd3NlcnMgaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9HbG9zc2FyeS9QcmVmbGlnaHRfcmVxdWVzdFxuICAgICAgICAgICAgICAgIHR5cGVvZiB3aW5kb3cgPT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgICAgICAgICByZXF1ZXN0SGVhZGVyc1tcIlgtRXNyaS1BdXRob3JpemF0aW9uXCJdID0gXCJCZWFyZXIgXCIgKyBwYXJhbXMudG9rZW47XG4gICAgICAgICAgICAgICAgZGVsZXRlIHBhcmFtcy50b2tlbjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIC8vIGVuY29kZSB0aGUgcGFyYW1ldGVycyBpbnRvIHRoZSBxdWVyeSBzdHJpbmdcbiAgICAgICAgICAgIHZhciBxdWVyeVBhcmFtcyA9IGVuY29kZVF1ZXJ5U3RyaW5nKHBhcmFtcyk7XG4gICAgICAgICAgICAvLyBkb250IGFwcGVuZCBhICc/JyB1bmxlc3MgcGFyYW1ldGVycyBhcmUgYWN0dWFsbHkgcHJlc2VudFxuICAgICAgICAgICAgdmFyIHVybFdpdGhRdWVyeVN0cmluZyA9IHF1ZXJ5UGFyYW1zID09PSBcIlwiID8gdXJsIDogdXJsICsgXCI/XCIgKyBlbmNvZGVRdWVyeVN0cmluZyhwYXJhbXMpO1xuICAgICAgICAgICAgaWYgKFxuICAgICAgICAgICAgLy8gVGhpcyB3b3VsZCBleGNlZWQgdGhlIG1heGltdW0gbGVuZ3RoIGZvciBVUkxzIHNwZWNpZmllZCBieSB0aGUgY29uc3VtZXIgYW5kIHJlcXVpcmVzIFBPU1RcbiAgICAgICAgICAgIChvcHRpb25zLm1heFVybExlbmd0aCAmJlxuICAgICAgICAgICAgICAgIHVybFdpdGhRdWVyeVN0cmluZy5sZW5ndGggPiBvcHRpb25zLm1heFVybExlbmd0aCkgfHxcbiAgICAgICAgICAgICAgICAvLyBPciBpZiB0aGUgY3VzdG9tZXIgcmVxdWlyZXMgdGhlIHRva2VuIHRvIGJlIGhpZGRlbiBhbmQgaXQgaGFzIG5vdCBhbHJlYWR5IGJlZW4gaGlkZGVuIGluIHRoZSBoZWFkZXIgKGZvciBicm93c2VycylcbiAgICAgICAgICAgICAgICAocGFyYW1zLnRva2VuICYmIG9wdGlvbnMuaGlkZVRva2VuKSkge1xuICAgICAgICAgICAgICAgIC8vIHRoZSBjb25zdW1lciBzcGVjaWZpZWQgYSBtYXhpbXVtIGxlbmd0aCBmb3IgVVJMc1xuICAgICAgICAgICAgICAgIC8vIGFuZCB0aGlzIHdvdWxkIGV4Y2VlZCBpdCwgc28gdXNlIHBvc3QgaW5zdGVhZFxuICAgICAgICAgICAgICAgIGZldGNoT3B0aW9ucy5tZXRob2QgPSBcIlBPU1RcIjtcbiAgICAgICAgICAgICAgICAvLyBJZiB0aGUgdG9rZW4gd2FzIGFscmVhZHkgYWRkZWQgYXMgYSBBdXRoIGhlYWRlciwgYWRkIHRoZSB0b2tlbiBiYWNrIHRvIGJvZHkgd2l0aCBvdGhlciBwYXJhbXMgaW5zdGVhZCBvZiBoZWFkZXJcbiAgICAgICAgICAgICAgICBpZiAodG9rZW4ubGVuZ3RoICYmIG9wdGlvbnMuaGlkZVRva2VuKSB7XG4gICAgICAgICAgICAgICAgICAgIHBhcmFtcy50b2tlbiA9IHRva2VuO1xuICAgICAgICAgICAgICAgICAgICAvLyBSZW1vdmUgZXhpc3RpbmcgaGVhZGVyIHRoYXQgd2FzIGFkZGVkIGJlZm9yZSB1cmwgcXVlcnkgbGVuZ3RoIHdhcyBjaGVja2VkXG4gICAgICAgICAgICAgICAgICAgIGRlbGV0ZSByZXF1ZXN0SGVhZGVyc1tcIlgtRXNyaS1BdXRob3JpemF0aW9uXCJdO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgIC8vIGp1c3QgdXNlIEdFVFxuICAgICAgICAgICAgICAgIHVybCA9IHVybFdpdGhRdWVyeVN0cmluZztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICAvKiB1cGRhdGVSZXNvdXJjZXMgY3VycmVudGx5IHJlcXVpcmVzIEZvcm1EYXRhIGV2ZW4gd2hlbiB0aGUgaW5wdXQgcGFyYW1ldGVycyBkb250IHdhcnJhbnQgaXQuXG4gICAgaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC91c2Vycy1ncm91cHMtYW5kLWl0ZW1zL3VwZGF0ZS1yZXNvdXJjZXMuaHRtXG4gICAgICAgIHNlZSBodHRwczovL2dpdGh1Yi5jb20vRXNyaS9hcmNnaXMtcmVzdC1qcy9wdWxsLzUwMCBmb3IgbW9yZSBpbmZvLiAqL1xuICAgICAgICB2YXIgZm9yY2VGb3JtRGF0YSA9IG5ldyBSZWdFeHAoXCIvaXRlbXMvLisvdXBkYXRlUmVzb3VyY2VzXCIpLnRlc3QodXJsKTtcbiAgICAgICAgaWYgKGZldGNoT3B0aW9ucy5tZXRob2QgPT09IFwiUE9TVFwiKSB7XG4gICAgICAgICAgICBmZXRjaE9wdGlvbnMuYm9keSA9IGVuY29kZUZvcm1EYXRhKHBhcmFtcywgZm9yY2VGb3JtRGF0YSk7XG4gICAgICAgIH1cbiAgICAgICAgLy8gTWl4aW4gaGVhZGVycyBmcm9tIHJlcXVlc3Qgb3B0aW9uc1xuICAgICAgICBmZXRjaE9wdGlvbnMuaGVhZGVycyA9IF9fYXNzaWduKF9fYXNzaWduKHt9LCByZXF1ZXN0SGVhZGVycyksIG9wdGlvbnMuaGVhZGVycyk7XG4gICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0IC0ga2FybWEgcmVwb3J0cyBjb3ZlcmFnZSBvbiBicm93c2VyIHRlc3RzIG9ubHkgKi9cbiAgICAgICAgaWYgKHR5cGVvZiB3aW5kb3cgPT09IFwidW5kZWZpbmVkXCIgJiYgIWZldGNoT3B0aW9ucy5oZWFkZXJzLnJlZmVyZXIpIHtcbiAgICAgICAgICAgIGZldGNoT3B0aW9ucy5oZWFkZXJzLnJlZmVyZXIgPSBOT0RFSlNfREVGQVVMVF9SRUZFUkVSX0hFQURFUjtcbiAgICAgICAgfVxuICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgZWxzZSBibG9iIHJlc3BvbnNlcyBhcmUgZGlmZmljdWx0IHRvIG1ha2UgY3Jvc3MgcGxhdGZvcm0gd2Ugd2lsbCBqdXN0IGhhdmUgdG8gdHJ1c3QgdGhlIGlzb21vcnBoaWMgZmV0Y2ggd2lsbCBkbyBpdHMgam9iICovXG4gICAgICAgIGlmICghcmVxdWlyZXNGb3JtRGF0YShwYXJhbXMpICYmICFmb3JjZUZvcm1EYXRhKSB7XG4gICAgICAgICAgICBmZXRjaE9wdGlvbnMuaGVhZGVyc1tcIkNvbnRlbnQtVHlwZVwiXSA9XG4gICAgICAgICAgICAgICAgXCJhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWRcIjtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gb3B0aW9ucy5mZXRjaCh1cmwsIGZldGNoT3B0aW9ucyk7XG4gICAgfSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGlmICghcmVzcG9uc2Uub2spIHtcbiAgICAgICAgICAgIC8vIHNlcnZlciByZXNwb25kZWQgdy8gYW4gYWN0dWFsIGVycm9yICg0MDQsIDUwMCwgZXRjKVxuICAgICAgICAgICAgdmFyIHN0YXR1c18xID0gcmVzcG9uc2Uuc3RhdHVzLCBzdGF0dXNUZXh0ID0gcmVzcG9uc2Uuc3RhdHVzVGV4dDtcbiAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNSZXF1ZXN0RXJyb3Ioc3RhdHVzVGV4dCwgXCJIVFRQIFwiICsgc3RhdHVzXzEsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgICAgIGlmIChyYXdSZXNwb25zZSkge1xuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICB9XG4gICAgICAgIHN3aXRjaCAocGFyYW1zLmYpIHtcbiAgICAgICAgICAgIGNhc2UgXCJqc29uXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmpzb24oKTtcbiAgICAgICAgICAgIGNhc2UgXCJnZW9qc29uXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmpzb24oKTtcbiAgICAgICAgICAgIGNhc2UgXCJodG1sXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLnRleHQoKTtcbiAgICAgICAgICAgIGNhc2UgXCJ0ZXh0XCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLnRleHQoKTtcbiAgICAgICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0IGJsb2IgcmVzcG9uc2VzIGFyZSBkaWZmaWN1bHQgdG8gbWFrZSBjcm9zcyBwbGF0Zm9ybSB3ZSB3aWxsIGp1c3QgaGF2ZSB0byB0cnVzdCB0aGF0IGlzb21vcnBoaWMgZmV0Y2ggd2lsbCBkbyBpdHMgam9iICovXG4gICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5ibG9iKCk7XG4gICAgICAgIH1cbiAgICB9KVxuICAgICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICBpZiAoKHBhcmFtcy5mID09PSBcImpzb25cIiB8fCBwYXJhbXMuZiA9PT0gXCJnZW9qc29uXCIpICYmICFyYXdSZXNwb25zZSkge1xuICAgICAgICAgICAgdmFyIHJlc3BvbnNlID0gY2hlY2tGb3JFcnJvcnMoZGF0YSwgdXJsLCBwYXJhbXMsIG9wdGlvbnMsIG9yaWdpbmFsQXV0aEVycm9yKTtcbiAgICAgICAgICAgIGlmIChvcmlnaW5hbEF1dGhFcnJvcikge1xuICAgICAgICAgICAgICAgIC8qIElmIHRoZSByZXF1ZXN0IHdhcyBtYWRlIHRvIGFuIHVuZmVkZXJhdGVkIHNlcnZpY2UgdGhhdFxuICAgICAgICAgICAgICAgIGRpZG4ndCByZXF1aXJlIGF1dGhlbnRpY2F0aW9uLCBhZGQgdGhlIGJhc2UgdXJsIGFuZCBhIGR1bW15IHRva2VuXG4gICAgICAgICAgICAgICAgdG8gdGhlIGxpc3Qgb2YgdHJ1c3RlZCBzZXJ2ZXJzIHRvIGF2b2lkIGFub3RoZXIgZmVkZXJhdGlvbiBjaGVja1xuICAgICAgICAgICAgICAgIGluIHRoZSBldmVudCBvZiBhIHJlcGVhdCByZXF1ZXN0ICovXG4gICAgICAgICAgICAgICAgdmFyIHRydW5jYXRlZFVybCA9IHVybFxuICAgICAgICAgICAgICAgICAgICAudG9Mb3dlckNhc2UoKVxuICAgICAgICAgICAgICAgICAgICAuc3BsaXQoL1xcL3Jlc3QoXFwvYWRtaW4pP1xcL3NlcnZpY2VzXFwvLylbMF07XG4gICAgICAgICAgICAgICAgb3B0aW9ucy5hdXRoZW50aWNhdGlvbi5mZWRlcmF0ZWRTZXJ2ZXJzW3RydW5jYXRlZFVybF0gPSB7XG4gICAgICAgICAgICAgICAgICAgIHRva2VuOiBbXSxcbiAgICAgICAgICAgICAgICAgICAgLy8gZGVmYXVsdCB0byAyNCBob3Vyc1xuICAgICAgICAgICAgICAgICAgICBleHBpcmVzOiBuZXcgRGF0ZShEYXRlLm5vdygpICsgODY0MDAgKiAxMDAwKSxcbiAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICAgIG9yaWdpbmFsQXV0aEVycm9yID0gbnVsbDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiBkYXRhO1xuICAgICAgICB9XG4gICAgfSk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1yZXF1ZXN0LmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG4vLyBUeXBlU2NyaXB0IDIuMSBubyBsb25nZXIgYWxsb3dzIHlvdSB0byBleHRlbmQgYnVpbHQgaW4gdHlwZXMuIFNlZSBodHRwczovL2dpdGh1Yi5jb20vTWljcm9zb2Z0L1R5cGVTY3JpcHQvaXNzdWVzLzEyNzkwI2lzc3VlY29tbWVudC0yNjU5ODE0NDJcbi8vIGFuZCBodHRwczovL2dpdGh1Yi5jb20vTWljcm9zb2Z0L1R5cGVTY3JpcHQtd2lraS9ibG9iL21hc3Rlci9CcmVha2luZy1DaGFuZ2VzLm1kI2V4dGVuZGluZy1idWlsdC1pbnMtbGlrZS1lcnJvci1hcnJheS1hbmQtbWFwLW1heS1uby1sb25nZXItd29ya1xuLy9cbi8vIFRoaXMgY29kZSBpcyBmcm9tIE1ETiBodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL1dlYi9KYXZhU2NyaXB0L1JlZmVyZW5jZS9HbG9iYWxfT2JqZWN0cy9FcnJvciNDdXN0b21fRXJyb3JfVHlwZXMuXG52YXIgQXJjR0lTUmVxdWVzdEVycm9yID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIC8qKlxuICAgICAqIENyZWF0ZSBhIG5ldyBgQXJjR0lTUmVxdWVzdEVycm9yYCAgb2JqZWN0LlxuICAgICAqXG4gICAgICogQHBhcmFtIG1lc3NhZ2UgLSBUaGUgZXJyb3IgbWVzc2FnZSBmcm9tIHRoZSBBUElcbiAgICAgKiBAcGFyYW0gY29kZSAtIFRoZSBlcnJvciBjb2RlIGZyb20gdGhlIEFQSVxuICAgICAqIEBwYXJhbSByZXNwb25zZSAtIFRoZSBvcmlnaW5hbCByZXNwb25zZSBmcm9tIHRoZSBBUEkgdGhhdCBjYXVzZWQgdGhlIGVycm9yXG4gICAgICogQHBhcmFtIHVybCAtIFRoZSBvcmlnaW5hbCB1cmwgb2YgdGhlIHJlcXVlc3RcbiAgICAgKiBAcGFyYW0gb3B0aW9ucyAtIFRoZSBvcmlnaW5hbCBvcHRpb25zIGFuZCBwYXJhbWV0ZXJzIG9mIHRoZSByZXF1ZXN0XG4gICAgICovXG4gICAgZnVuY3Rpb24gQXJjR0lTUmVxdWVzdEVycm9yKG1lc3NhZ2UsIGNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpIHtcbiAgICAgICAgbWVzc2FnZSA9IG1lc3NhZ2UgfHwgXCJVTktOT1dOX0VSUk9SXCI7XG4gICAgICAgIGNvZGUgPSBjb2RlIHx8IFwiVU5LTk9XTl9FUlJPUl9DT0RFXCI7XG4gICAgICAgIHRoaXMubmFtZSA9IFwiQXJjR0lTUmVxdWVzdEVycm9yXCI7XG4gICAgICAgIHRoaXMubWVzc2FnZSA9XG4gICAgICAgICAgICBjb2RlID09PSBcIlVOS05PV05fRVJST1JfQ09ERVwiID8gbWVzc2FnZSA6IGNvZGUgKyBcIjogXCIgKyBtZXNzYWdlO1xuICAgICAgICB0aGlzLm9yaWdpbmFsTWVzc2FnZSA9IG1lc3NhZ2U7XG4gICAgICAgIHRoaXMuY29kZSA9IGNvZGU7XG4gICAgICAgIHRoaXMucmVzcG9uc2UgPSByZXNwb25zZTtcbiAgICAgICAgdGhpcy51cmwgPSB1cmw7XG4gICAgICAgIHRoaXMub3B0aW9ucyA9IG9wdGlvbnM7XG4gICAgfVxuICAgIHJldHVybiBBcmNHSVNSZXF1ZXN0RXJyb3I7XG59KCkpO1xuZXhwb3J0IHsgQXJjR0lTUmVxdWVzdEVycm9yIH07XG5BcmNHSVNSZXF1ZXN0RXJyb3IucHJvdG90eXBlID0gT2JqZWN0LmNyZWF0ZShFcnJvci5wcm90b3R5cGUpO1xuQXJjR0lTUmVxdWVzdEVycm9yLnByb3RvdHlwZS5jb25zdHJ1Y3RvciA9IEFyY0dJU1JlcXVlc3RFcnJvcjtcbi8vIyBzb3VyY2VNYXBwaW5nVVJMPUFyY0dJU1JlcXVlc3RFcnJvci5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuLyoqXG4gKiBIZWxwZXIgZm9yIG1ldGhvZHMgd2l0aCBsb3RzIG9mIGZpcnN0IG9yZGVyIHJlcXVlc3Qgb3B0aW9ucyB0byBwYXNzIHRocm91Z2ggYXMgcmVxdWVzdCBwYXJhbWV0ZXJzLlxuICovXG5leHBvcnQgZnVuY3Rpb24gYXBwZW5kQ3VzdG9tUGFyYW1zKGN1c3RvbU9wdGlvbnMsIGtleXMsIGJhc2VPcHRpb25zKSB7XG4gICAgdmFyIHJlcXVlc3RPcHRpb25zS2V5cyA9IFtcbiAgICAgICAgXCJwYXJhbXNcIixcbiAgICAgICAgXCJodHRwTWV0aG9kXCIsXG4gICAgICAgIFwicmF3UmVzcG9uc2VcIixcbiAgICAgICAgXCJhdXRoZW50aWNhdGlvblwiLFxuICAgICAgICBcInBvcnRhbFwiLFxuICAgICAgICBcImZldGNoXCIsXG4gICAgICAgIFwibWF4VXJsTGVuZ3RoXCIsXG4gICAgICAgIFwiaGVhZGVyc1wiXG4gICAgXTtcbiAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKF9fYXNzaWduKHsgcGFyYW1zOiB7fSB9LCBiYXNlT3B0aW9ucyksIGN1c3RvbU9wdGlvbnMpO1xuICAgIC8vIG1lcmdlIGFsbCBrZXlzIGluIGN1c3RvbU9wdGlvbnMgaW50byBvcHRpb25zLnBhcmFtc1xuICAgIG9wdGlvbnMucGFyYW1zID0ga2V5cy5yZWR1Y2UoZnVuY3Rpb24gKHZhbHVlLCBrZXkpIHtcbiAgICAgICAgaWYgKGN1c3RvbU9wdGlvbnNba2V5XSB8fCB0eXBlb2YgY3VzdG9tT3B0aW9uc1trZXldID09PSBcImJvb2xlYW5cIikge1xuICAgICAgICAgICAgdmFsdWVba2V5XSA9IGN1c3RvbU9wdGlvbnNba2V5XTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdmFsdWU7XG4gICAgfSwgb3B0aW9ucy5wYXJhbXMpO1xuICAgIC8vIG5vdyByZW1vdmUgYWxsIHByb3BlcnRpZXMgaW4gb3B0aW9ucyB0aGF0IGRvbid0IGV4aXN0IGluIElSZXF1ZXN0T3B0aW9uc1xuICAgIHJldHVybiByZXF1ZXN0T3B0aW9uc0tleXMucmVkdWNlKGZ1bmN0aW9uICh2YWx1ZSwga2V5KSB7XG4gICAgICAgIGlmIChvcHRpb25zW2tleV0pIHtcbiAgICAgICAgICAgIHZhbHVlW2tleV0gPSBvcHRpb25zW2tleV07XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHZhbHVlO1xuICAgIH0sIHt9KTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWFwcGVuZC1jdXN0b20tcGFyYW1zLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG4vKipcbiAqIEhlbHBlciBtZXRob2QgdG8gZW5zdXJlIHRoYXQgdXNlciBzdXBwbGllZCB1cmxzIGRvbid0IGluY2x1ZGUgd2hpdGVzcGFjZSBvciBhIHRyYWlsaW5nIHNsYXNoLlxuICovXG5leHBvcnQgZnVuY3Rpb24gY2xlYW5VcmwodXJsKSB7XG4gICAgLy8gR3VhcmQgc28gd2UgZG9uJ3QgdHJ5IHRvIHRyaW0gc29tZXRoaW5nIHRoYXQncyBub3QgYSBzdHJpbmdcbiAgICBpZiAodHlwZW9mIHVybCAhPT0gXCJzdHJpbmdcIikge1xuICAgICAgICByZXR1cm4gdXJsO1xuICAgIH1cbiAgICAvLyB0cmltIGxlYWRpbmcgYW5kIHRyYWlsaW5nIHNwYWNlcywgYnV0IG5vdCBzcGFjZXMgaW5zaWRlIHRoZSB1cmxcbiAgICB1cmwgPSB1cmwudHJpbSgpO1xuICAgIC8vIHJlbW92ZSB0aGUgdHJhaWxpbmcgc2xhc2ggdG8gdGhlIHVybCBpZiBvbmUgd2FzIGluY2x1ZGVkXG4gICAgaWYgKHVybFt1cmwubGVuZ3RoIC0gMV0gPT09IFwiL1wiKSB7XG4gICAgICAgIHVybCA9IHVybC5zbGljZSgwLCAtMSk7XG4gICAgfVxuICAgIHJldHVybiB1cmw7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1jbGVhbi11cmwuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMjAgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuZXhwb3J0IGZ1bmN0aW9uIGRlY29kZVBhcmFtKHBhcmFtKSB7XG4gICAgdmFyIF9hID0gcGFyYW0uc3BsaXQoXCI9XCIpLCBrZXkgPSBfYVswXSwgdmFsdWUgPSBfYVsxXTtcbiAgICByZXR1cm4geyBrZXk6IGRlY29kZVVSSUNvbXBvbmVudChrZXkpLCB2YWx1ZTogZGVjb2RlVVJJQ29tcG9uZW50KHZhbHVlKSB9O1xufVxuLyoqXG4gKiBEZWNvZGVzIHRoZSBwYXNzZWQgcXVlcnkgc3RyaW5nIGFzIGFuIG9iamVjdC5cbiAqXG4gKiBAcGFyYW0gcXVlcnkgQSBzdHJpbmcgdG8gYmUgZGVjb2RlZC5cbiAqIEByZXR1cm5zIEEgZGVjb2RlZCBxdWVyeSBwYXJhbSBvYmplY3QuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBkZWNvZGVRdWVyeVN0cmluZyhxdWVyeSkge1xuICAgIHJldHVybiBxdWVyeVxuICAgICAgICAucmVwbGFjZSgvXiMvLCBcIlwiKVxuICAgICAgICAuc3BsaXQoXCImXCIpXG4gICAgICAgIC5yZWR1Y2UoZnVuY3Rpb24gKGFjYywgZW50cnkpIHtcbiAgICAgICAgdmFyIF9hID0gZGVjb2RlUGFyYW0oZW50cnkpLCBrZXkgPSBfYS5rZXksIHZhbHVlID0gX2EudmFsdWU7XG4gICAgICAgIGFjY1trZXldID0gdmFsdWU7XG4gICAgICAgIHJldHVybiBhY2M7XG4gICAgfSwge30pO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGVjb2RlLXF1ZXJ5LXN0cmluZy5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgcHJvY2Vzc1BhcmFtcywgcmVxdWlyZXNGb3JtRGF0YSB9IGZyb20gXCIuL3Byb2Nlc3MtcGFyYW1zXCI7XG5pbXBvcnQgeyBlbmNvZGVRdWVyeVN0cmluZyB9IGZyb20gXCIuL2VuY29kZS1xdWVyeS1zdHJpbmdcIjtcbi8qKlxuICogRW5jb2RlcyBwYXJhbWV0ZXJzIGluIGEgW0Zvcm1EYXRhXShodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL1dlYi9BUEkvRm9ybURhdGEpIG9iamVjdCBpbiBicm93c2VycyBvciBpbiBhIFtGb3JtRGF0YV0oaHR0cHM6Ly9naXRodWIuY29tL2Zvcm0tZGF0YS9mb3JtLWRhdGEpIGluIE5vZGUuanNcbiAqXG4gKiBAcGFyYW0gcGFyYW1zIEFuIG9iamVjdCB0byBiZSBlbmNvZGVkLlxuICogQHJldHVybnMgVGhlIGNvbXBsZXRlIFtGb3JtRGF0YV0oaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvQVBJL0Zvcm1EYXRhKSBvYmplY3QuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBlbmNvZGVGb3JtRGF0YShwYXJhbXMsIGZvcmNlRm9ybURhdGEpIHtcbiAgICAvLyBzZWUgaHR0cHM6Ly9naXRodWIuY29tL0VzcmkvYXJjZ2lzLXJlc3QtanMvaXNzdWVzLzQ5OSBmb3IgbW9yZSBpbmZvLlxuICAgIHZhciB1c2VGb3JtRGF0YSA9IHJlcXVpcmVzRm9ybURhdGEocGFyYW1zKSB8fCBmb3JjZUZvcm1EYXRhO1xuICAgIHZhciBuZXdQYXJhbXMgPSBwcm9jZXNzUGFyYW1zKHBhcmFtcyk7XG4gICAgaWYgKHVzZUZvcm1EYXRhKSB7XG4gICAgICAgIHZhciBmb3JtRGF0YV8xID0gbmV3IEZvcm1EYXRhKCk7XG4gICAgICAgIE9iamVjdC5rZXlzKG5ld1BhcmFtcykuZm9yRWFjaChmdW5jdGlvbiAoa2V5KSB7XG4gICAgICAgICAgICBpZiAodHlwZW9mIEJsb2IgIT09IFwidW5kZWZpbmVkXCIgJiYgbmV3UGFyYW1zW2tleV0gaW5zdGFuY2VvZiBCbG9iKSB7XG4gICAgICAgICAgICAgICAgLyogVG8gbmFtZSB0aGUgQmxvYjpcbiAgICAgICAgICAgICAgICAgMS4gbG9vayB0byBhbiBhbHRlcm5hdGUgcmVxdWVzdCBwYXJhbWV0ZXIgY2FsbGVkICdmaWxlTmFtZSdcbiAgICAgICAgICAgICAgICAgMi4gc2VlIGlmICduYW1lJyBoYXMgYmVlbiB0YWNrZWQgb250byB0aGUgQmxvYiBtYW51YWxseVxuICAgICAgICAgICAgICAgICAzLiBpZiBhbGwgZWxzZSBmYWlscywgdXNlIHRoZSByZXF1ZXN0IHBhcmFtZXRlclxuICAgICAgICAgICAgICAgICovXG4gICAgICAgICAgICAgICAgdmFyIGZpbGVuYW1lID0gbmV3UGFyYW1zW1wiZmlsZU5hbWVcIl0gfHwgbmV3UGFyYW1zW2tleV0ubmFtZSB8fCBrZXk7XG4gICAgICAgICAgICAgICAgZm9ybURhdGFfMS5hcHBlbmQoa2V5LCBuZXdQYXJhbXNba2V5XSwgZmlsZW5hbWUpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgZm9ybURhdGFfMS5hcHBlbmQoa2V5LCBuZXdQYXJhbXNba2V5XSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm4gZm9ybURhdGFfMTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIHJldHVybiBlbmNvZGVRdWVyeVN0cmluZyhwYXJhbXMpO1xuICAgIH1cbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWVuY29kZS1mb3JtLWRhdGEuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IHByb2Nlc3NQYXJhbXMgfSBmcm9tIFwiLi9wcm9jZXNzLXBhcmFtc1wiO1xuLyoqXG4gKiBFbmNvZGVzIGtleXMgYW5kIHBhcmFtZXRlcnMgZm9yIHVzZSBpbiBhIFVSTCdzIHF1ZXJ5IHN0cmluZy5cbiAqXG4gKiBAcGFyYW0ga2V5IFBhcmFtZXRlcidzIGtleVxuICogQHBhcmFtIHZhbHVlIFBhcmFtZXRlcidzIHZhbHVlXG4gKiBAcmV0dXJucyBRdWVyeSBzdHJpbmcgd2l0aCBrZXkgYW5kIHZhbHVlIHBhaXJzIHNlcGFyYXRlZCBieSBcIiZcIlxuICovXG5leHBvcnQgZnVuY3Rpb24gZW5jb2RlUGFyYW0oa2V5LCB2YWx1ZSkge1xuICAgIC8vIEZvciBhcnJheSBvZiBhcnJheXMsIHJlcGVhdCBrZXk9dmFsdWUgZm9yIGVhY2ggZWxlbWVudCBvZiBjb250YWluaW5nIGFycmF5XG4gICAgaWYgKEFycmF5LmlzQXJyYXkodmFsdWUpICYmIHZhbHVlWzBdICYmIEFycmF5LmlzQXJyYXkodmFsdWVbMF0pKSB7XG4gICAgICAgIHJldHVybiB2YWx1ZS5tYXAoZnVuY3Rpb24gKGFycmF5RWxlbSkgeyByZXR1cm4gZW5jb2RlUGFyYW0oa2V5LCBhcnJheUVsZW0pOyB9KS5qb2luKFwiJlwiKTtcbiAgICB9XG4gICAgcmV0dXJuIGVuY29kZVVSSUNvbXBvbmVudChrZXkpICsgXCI9XCIgKyBlbmNvZGVVUklDb21wb25lbnQodmFsdWUpO1xufVxuLyoqXG4gKiBFbmNvZGVzIHRoZSBwYXNzZWQgb2JqZWN0IGFzIGEgcXVlcnkgc3RyaW5nLlxuICpcbiAqIEBwYXJhbSBwYXJhbXMgQW4gb2JqZWN0IHRvIGJlIGVuY29kZWQuXG4gKiBAcmV0dXJucyBBbiBlbmNvZGVkIHF1ZXJ5IHN0cmluZy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGVuY29kZVF1ZXJ5U3RyaW5nKHBhcmFtcykge1xuICAgIHZhciBuZXdQYXJhbXMgPSBwcm9jZXNzUGFyYW1zKHBhcmFtcyk7XG4gICAgcmV0dXJuIE9iamVjdC5rZXlzKG5ld1BhcmFtcylcbiAgICAgICAgLm1hcChmdW5jdGlvbiAoa2V5KSB7XG4gICAgICAgIHJldHVybiBlbmNvZGVQYXJhbShrZXksIG5ld1BhcmFtc1trZXldKTtcbiAgICB9KVxuICAgICAgICAuam9pbihcIiZcIik7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1lbmNvZGUtcXVlcnktc3RyaW5nLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG4vKipcbiAqIENoZWNrcyBwYXJhbWV0ZXJzIHRvIHNlZSBpZiB3ZSBzaG91bGQgdXNlIEZvcm1EYXRhIHRvIHNlbmQgdGhlIHJlcXVlc3RcbiAqIEBwYXJhbSBwYXJhbXMgVGhlIG9iamVjdCB3aG9zZSBrZXlzIHdpbGwgYmUgZW5jb2RlZC5cbiAqIEByZXR1cm4gQSBib29sZWFuIGluZGljYXRpbmcgaWYgRm9ybURhdGEgd2lsbCBiZSByZXF1aXJlZC5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHJlcXVpcmVzRm9ybURhdGEocGFyYW1zKSB7XG4gICAgcmV0dXJuIE9iamVjdC5rZXlzKHBhcmFtcykuc29tZShmdW5jdGlvbiAoa2V5KSB7XG4gICAgICAgIHZhciB2YWx1ZSA9IHBhcmFtc1trZXldO1xuICAgICAgICBpZiAoIXZhbHVlKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHZhbHVlICYmIHZhbHVlLnRvUGFyYW0pIHtcbiAgICAgICAgICAgIHZhbHVlID0gdmFsdWUudG9QYXJhbSgpO1xuICAgICAgICB9XG4gICAgICAgIHZhciB0eXBlID0gdmFsdWUuY29uc3RydWN0b3IubmFtZTtcbiAgICAgICAgc3dpdGNoICh0eXBlKSB7XG4gICAgICAgICAgICBjYXNlIFwiQXJyYXlcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBjYXNlIFwiT2JqZWN0XCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIkRhdGVcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBjYXNlIFwiRnVuY3Rpb25cIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBjYXNlIFwiQm9vbGVhblwiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGNhc2UgXCJTdHJpbmdcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBjYXNlIFwiTnVtYmVyXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuICAgIH0pO1xufVxuLyoqXG4gKiBDb252ZXJ0cyBwYXJhbWV0ZXJzIHRvIHRoZSBwcm9wZXIgcmVwcmVzZW50YXRpb24gdG8gc2VuZCB0byB0aGUgQXJjR0lTIFJFU1QgQVBJLlxuICogQHBhcmFtIHBhcmFtcyBUaGUgb2JqZWN0IHdob3NlIGtleXMgd2lsbCBiZSBlbmNvZGVkLlxuICogQHJldHVybiBBIG5ldyBvYmplY3Qgd2l0aCBwcm9wZXJseSBlbmNvZGVkIHZhbHVlcy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHByb2Nlc3NQYXJhbXMocGFyYW1zKSB7XG4gICAgdmFyIG5ld1BhcmFtcyA9IHt9O1xuICAgIE9iamVjdC5rZXlzKHBhcmFtcykuZm9yRWFjaChmdW5jdGlvbiAoa2V5KSB7XG4gICAgICAgIHZhciBfYSwgX2I7XG4gICAgICAgIHZhciBwYXJhbSA9IHBhcmFtc1trZXldO1xuICAgICAgICBpZiAocGFyYW0gJiYgcGFyYW0udG9QYXJhbSkge1xuICAgICAgICAgICAgcGFyYW0gPSBwYXJhbS50b1BhcmFtKCk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCFwYXJhbSAmJlxuICAgICAgICAgICAgcGFyYW0gIT09IDAgJiZcbiAgICAgICAgICAgIHR5cGVvZiBwYXJhbSAhPT0gXCJib29sZWFuXCIgJiZcbiAgICAgICAgICAgIHR5cGVvZiBwYXJhbSAhPT0gXCJzdHJpbmdcIikge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIHZhciB0eXBlID0gcGFyYW0uY29uc3RydWN0b3IubmFtZTtcbiAgICAgICAgdmFyIHZhbHVlO1xuICAgICAgICAvLyBwcm9wZXJseSBlbmNvZGVzIG9iamVjdHMsIGFycmF5cyBhbmQgZGF0ZXMgZm9yIGFyY2dpcy5jb20gYW5kIG90aGVyIHNlcnZpY2VzLlxuICAgICAgICAvLyBwb3J0ZWQgZnJvbSBodHRwczovL2dpdGh1Yi5jb20vRXNyaS9lc3JpLWxlYWZsZXQvYmxvYi9tYXN0ZXIvc3JjL1JlcXVlc3QuanMjTDIyLUwzMFxuICAgICAgICAvLyBhbHNvIHNlZSBodHRwczovL2dpdGh1Yi5jb20vRXNyaS9hcmNnaXMtcmVzdC1qcy9pc3N1ZXMvMTg6XG4gICAgICAgIC8vIG51bGwsIHVuZGVmaW5lZCwgZnVuY3Rpb24gYXJlIGV4Y2x1ZGVkLiBJZiB5b3Ugd2FudCB0byBzZW5kIGFuIGVtcHR5IGtleSB5b3UgbmVlZCB0byBzZW5kIGFuIGVtcHR5IHN0cmluZyBcIlwiLlxuICAgICAgICBzd2l0Y2ggKHR5cGUpIHtcbiAgICAgICAgICAgIGNhc2UgXCJBcnJheVwiOlxuICAgICAgICAgICAgICAgIC8vIEJhc2VkIG9uIHRoZSBmaXJzdCBlbGVtZW50IG9mIHRoZSBhcnJheSwgY2xhc3NpZnkgYXJyYXkgYXMgYW4gYXJyYXkgb2YgYXJyYXlzLCBhbiBhcnJheSBvZiBvYmplY3RzXG4gICAgICAgICAgICAgICAgLy8gdG8gYmUgc3RyaW5naWZpZWQsIG9yIGFuIGFycmF5IG9mIG5vbi1vYmplY3RzIHRvIGJlIGNvbW1hLXNlcGFyYXRlZFxuICAgICAgICAgICAgICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby1jYXNlLWRlY2xhcmF0aW9uc1xuICAgICAgICAgICAgICAgIHZhciBmaXJzdEVsZW1lbnRUeXBlID0gKF9iID0gKF9hID0gcGFyYW1bMF0pID09PSBudWxsIHx8IF9hID09PSB2b2lkIDAgPyB2b2lkIDAgOiBfYS5jb25zdHJ1Y3RvcikgPT09IG51bGwgfHwgX2IgPT09IHZvaWQgMCA/IHZvaWQgMCA6IF9iLm5hbWU7XG4gICAgICAgICAgICAgICAgdmFsdWUgPVxuICAgICAgICAgICAgICAgICAgICBmaXJzdEVsZW1lbnRUeXBlID09PSBcIkFycmF5XCIgPyBwYXJhbSA6IC8vIHBhc3MgdGhydSBhcnJheSBvZiBhcnJheXNcbiAgICAgICAgICAgICAgICAgICAgICAgIGZpcnN0RWxlbWVudFR5cGUgPT09IFwiT2JqZWN0XCIgPyBKU09OLnN0cmluZ2lmeShwYXJhbSkgOiAvLyBzdHJpbmdpZnkgYXJyYXkgb2Ygb2JqZWN0c1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhcmFtLmpvaW4oXCIsXCIpOyAvLyBqb2luIG90aGVyIHR5cGVzIG9mIGFycmF5IGVsZW1lbnRzXG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICBjYXNlIFwiT2JqZWN0XCI6XG4gICAgICAgICAgICAgICAgdmFsdWUgPSBKU09OLnN0cmluZ2lmeShwYXJhbSk7XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICBjYXNlIFwiRGF0ZVwiOlxuICAgICAgICAgICAgICAgIHZhbHVlID0gcGFyYW0udmFsdWVPZigpO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgY2FzZSBcIkZ1bmN0aW9uXCI6XG4gICAgICAgICAgICAgICAgdmFsdWUgPSBudWxsO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgY2FzZSBcIkJvb2xlYW5cIjpcbiAgICAgICAgICAgICAgICB2YWx1ZSA9IHBhcmFtICsgXCJcIjtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgdmFsdWUgPSBwYXJhbTtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBpZiAodmFsdWUgfHwgdmFsdWUgPT09IDAgfHwgdHlwZW9mIHZhbHVlID09PSBcInN0cmluZ1wiIHx8IEFycmF5LmlzQXJyYXkodmFsdWUpKSB7XG4gICAgICAgICAgICBuZXdQYXJhbXNba2V5XSA9IHZhbHVlO1xuICAgICAgICB9XG4gICAgfSk7XG4gICAgcmV0dXJuIG5ld1BhcmFtcztcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXByb2Nlc3MtcGFyYW1zLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbi8qKlxuICogTWV0aG9kIHVzZWQgaW50ZXJuYWxseSB0byBzdXJmYWNlIG1lc3NhZ2VzIHRvIGRldmVsb3BlcnMuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB3YXJuKG1lc3NhZ2UpIHtcbiAgICBpZiAoY29uc29sZSAmJiBjb25zb2xlLndhcm4pIHtcbiAgICAgICAgY29uc29sZS53YXJuLmFwcGx5KGNvbnNvbGUsIFttZXNzYWdlXSk7XG4gICAgfVxufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9d2Fybi5qcy5tYXAiLCIvKiEgKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcclxuQ29weXJpZ2h0IChjKSBNaWNyb3NvZnQgQ29ycG9yYXRpb24uXHJcblxyXG5QZXJtaXNzaW9uIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBhbmQvb3IgZGlzdHJpYnV0ZSB0aGlzIHNvZnR3YXJlIGZvciBhbnlcclxucHVycG9zZSB3aXRoIG9yIHdpdGhvdXQgZmVlIGlzIGhlcmVieSBncmFudGVkLlxyXG5cclxuVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiBBTkQgVEhFIEFVVEhPUiBESVNDTEFJTVMgQUxMIFdBUlJBTlRJRVMgV0lUSFxyXG5SRUdBUkQgVE8gVEhJUyBTT0ZUV0FSRSBJTkNMVURJTkcgQUxMIElNUExJRUQgV0FSUkFOVElFUyBPRiBNRVJDSEFOVEFCSUxJVFlcclxuQU5EIEZJVE5FU1MuIElOIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1IgQkUgTElBQkxFIEZPUiBBTlkgU1BFQ0lBTCwgRElSRUNULFxyXG5JTkRJUkVDVCwgT1IgQ09OU0VRVUVOVElBTCBEQU1BR0VTIE9SIEFOWSBEQU1BR0VTIFdIQVRTT0VWRVIgUkVTVUxUSU5HIEZST01cclxuTE9TUyBPRiBVU0UsIERBVEEgT1IgUFJPRklUUywgV0hFVEhFUiBJTiBBTiBBQ1RJT04gT0YgQ09OVFJBQ1QsIE5FR0xJR0VOQ0UgT1JcclxuT1RIRVIgVE9SVElPVVMgQUNUSU9OLCBBUklTSU5HIE9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFVTRSBPUlxyXG5QRVJGT1JNQU5DRSBPRiBUSElTIFNPRlRXQVJFLlxyXG4qKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiAqL1xyXG4vKiBnbG9iYWwgUmVmbGVjdCwgUHJvbWlzZSAqL1xyXG5cclxudmFyIGV4dGVuZFN0YXRpY3MgPSBmdW5jdGlvbihkLCBiKSB7XHJcbiAgICBleHRlbmRTdGF0aWNzID0gT2JqZWN0LnNldFByb3RvdHlwZU9mIHx8XHJcbiAgICAgICAgKHsgX19wcm90b19fOiBbXSB9IGluc3RhbmNlb2YgQXJyYXkgJiYgZnVuY3Rpb24gKGQsIGIpIHsgZC5fX3Byb3RvX18gPSBiOyB9KSB8fFxyXG4gICAgICAgIGZ1bmN0aW9uIChkLCBiKSB7IGZvciAodmFyIHAgaW4gYikgaWYgKGIuaGFzT3duUHJvcGVydHkocCkpIGRbcF0gPSBiW3BdOyB9O1xyXG4gICAgcmV0dXJuIGV4dGVuZFN0YXRpY3MoZCwgYik7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19leHRlbmRzKGQsIGIpIHtcclxuICAgIGV4dGVuZFN0YXRpY3MoZCwgYik7XHJcbiAgICBmdW5jdGlvbiBfXygpIHsgdGhpcy5jb25zdHJ1Y3RvciA9IGQ7IH1cclxuICAgIGQucHJvdG90eXBlID0gYiA9PT0gbnVsbCA/IE9iamVjdC5jcmVhdGUoYikgOiAoX18ucHJvdG90eXBlID0gYi5wcm90b3R5cGUsIG5ldyBfXygpKTtcclxufVxyXG5cclxuZXhwb3J0IHZhciBfX2Fzc2lnbiA9IGZ1bmN0aW9uKCkge1xyXG4gICAgX19hc3NpZ24gPSBPYmplY3QuYXNzaWduIHx8IGZ1bmN0aW9uIF9fYXNzaWduKHQpIHtcclxuICAgICAgICBmb3IgKHZhciBzLCBpID0gMSwgbiA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBuOyBpKyspIHtcclxuICAgICAgICAgICAgcyA9IGFyZ3VtZW50c1tpXTtcclxuICAgICAgICAgICAgZm9yICh2YXIgcCBpbiBzKSBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHMsIHApKSB0W3BdID0gc1twXTtcclxuICAgICAgICB9XHJcbiAgICAgICAgcmV0dXJuIHQ7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gX19hc3NpZ24uYXBwbHkodGhpcywgYXJndW1lbnRzKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcmVzdChzLCBlKSB7XHJcbiAgICB2YXIgdCA9IHt9O1xyXG4gICAgZm9yICh2YXIgcCBpbiBzKSBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHMsIHApICYmIGUuaW5kZXhPZihwKSA8IDApXHJcbiAgICAgICAgdFtwXSA9IHNbcF07XHJcbiAgICBpZiAocyAhPSBudWxsICYmIHR5cGVvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlTeW1ib2xzID09PSBcImZ1bmN0aW9uXCIpXHJcbiAgICAgICAgZm9yICh2YXIgaSA9IDAsIHAgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlTeW1ib2xzKHMpOyBpIDwgcC5sZW5ndGg7IGkrKykge1xyXG4gICAgICAgICAgICBpZiAoZS5pbmRleE9mKHBbaV0pIDwgMCAmJiBPYmplY3QucHJvdG90eXBlLnByb3BlcnR5SXNFbnVtZXJhYmxlLmNhbGwocywgcFtpXSkpXHJcbiAgICAgICAgICAgICAgICB0W3BbaV1dID0gc1twW2ldXTtcclxuICAgICAgICB9XHJcbiAgICByZXR1cm4gdDtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZGVjb3JhdGUoZGVjb3JhdG9ycywgdGFyZ2V0LCBrZXksIGRlc2MpIHtcclxuICAgIHZhciBjID0gYXJndW1lbnRzLmxlbmd0aCwgciA9IGMgPCAzID8gdGFyZ2V0IDogZGVzYyA9PT0gbnVsbCA/IGRlc2MgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKHRhcmdldCwga2V5KSA6IGRlc2MsIGQ7XHJcbiAgICBpZiAodHlwZW9mIFJlZmxlY3QgPT09IFwib2JqZWN0XCIgJiYgdHlwZW9mIFJlZmxlY3QuZGVjb3JhdGUgPT09IFwiZnVuY3Rpb25cIikgciA9IFJlZmxlY3QuZGVjb3JhdGUoZGVjb3JhdG9ycywgdGFyZ2V0LCBrZXksIGRlc2MpO1xyXG4gICAgZWxzZSBmb3IgKHZhciBpID0gZGVjb3JhdG9ycy5sZW5ndGggLSAxOyBpID49IDA7IGktLSkgaWYgKGQgPSBkZWNvcmF0b3JzW2ldKSByID0gKGMgPCAzID8gZChyKSA6IGMgPiAzID8gZCh0YXJnZXQsIGtleSwgcikgOiBkKHRhcmdldCwga2V5KSkgfHwgcjtcclxuICAgIHJldHVybiBjID4gMyAmJiByICYmIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0YXJnZXQsIGtleSwgciksIHI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3BhcmFtKHBhcmFtSW5kZXgsIGRlY29yYXRvcikge1xyXG4gICAgcmV0dXJuIGZ1bmN0aW9uICh0YXJnZXQsIGtleSkgeyBkZWNvcmF0b3IodGFyZ2V0LCBrZXksIHBhcmFtSW5kZXgpOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX21ldGFkYXRhKG1ldGFkYXRhS2V5LCBtZXRhZGF0YVZhbHVlKSB7XHJcbiAgICBpZiAodHlwZW9mIFJlZmxlY3QgPT09IFwib2JqZWN0XCIgJiYgdHlwZW9mIFJlZmxlY3QubWV0YWRhdGEgPT09IFwiZnVuY3Rpb25cIikgcmV0dXJuIFJlZmxlY3QubWV0YWRhdGEobWV0YWRhdGFLZXksIG1ldGFkYXRhVmFsdWUpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hd2FpdGVyKHRoaXNBcmcsIF9hcmd1bWVudHMsIFAsIGdlbmVyYXRvcikge1xyXG4gICAgZnVuY3Rpb24gYWRvcHQodmFsdWUpIHsgcmV0dXJuIHZhbHVlIGluc3RhbmNlb2YgUCA/IHZhbHVlIDogbmV3IFAoZnVuY3Rpb24gKHJlc29sdmUpIHsgcmVzb2x2ZSh2YWx1ZSk7IH0pOyB9XHJcbiAgICByZXR1cm4gbmV3IChQIHx8IChQID0gUHJvbWlzZSkpKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcclxuICAgICAgICBmdW5jdGlvbiBmdWxmaWxsZWQodmFsdWUpIHsgdHJ5IHsgc3RlcChnZW5lcmF0b3IubmV4dCh2YWx1ZSkpOyB9IGNhdGNoIChlKSB7IHJlamVjdChlKTsgfSB9XHJcbiAgICAgICAgZnVuY3Rpb24gcmVqZWN0ZWQodmFsdWUpIHsgdHJ5IHsgc3RlcChnZW5lcmF0b3JbXCJ0aHJvd1wiXSh2YWx1ZSkpOyB9IGNhdGNoIChlKSB7IHJlamVjdChlKTsgfSB9XHJcbiAgICAgICAgZnVuY3Rpb24gc3RlcChyZXN1bHQpIHsgcmVzdWx0LmRvbmUgPyByZXNvbHZlKHJlc3VsdC52YWx1ZSkgOiBhZG9wdChyZXN1bHQudmFsdWUpLnRoZW4oZnVsZmlsbGVkLCByZWplY3RlZCk7IH1cclxuICAgICAgICBzdGVwKChnZW5lcmF0b3IgPSBnZW5lcmF0b3IuYXBwbHkodGhpc0FyZywgX2FyZ3VtZW50cyB8fCBbXSkpLm5leHQoKSk7XHJcbiAgICB9KTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZ2VuZXJhdG9yKHRoaXNBcmcsIGJvZHkpIHtcclxuICAgIHZhciBfID0geyBsYWJlbDogMCwgc2VudDogZnVuY3Rpb24oKSB7IGlmICh0WzBdICYgMSkgdGhyb3cgdFsxXTsgcmV0dXJuIHRbMV07IH0sIHRyeXM6IFtdLCBvcHM6IFtdIH0sIGYsIHksIHQsIGc7XHJcbiAgICByZXR1cm4gZyA9IHsgbmV4dDogdmVyYigwKSwgXCJ0aHJvd1wiOiB2ZXJiKDEpLCBcInJldHVyblwiOiB2ZXJiKDIpIH0sIHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiAoZ1tTeW1ib2wuaXRlcmF0b3JdID0gZnVuY3Rpb24oKSB7IHJldHVybiB0aGlzOyB9KSwgZztcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyByZXR1cm4gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIHN0ZXAoW24sIHZdKTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gc3RlcChvcCkge1xyXG4gICAgICAgIGlmIChmKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiR2VuZXJhdG9yIGlzIGFscmVhZHkgZXhlY3V0aW5nLlwiKTtcclxuICAgICAgICB3aGlsZSAoXykgdHJ5IHtcclxuICAgICAgICAgICAgaWYgKGYgPSAxLCB5ICYmICh0ID0gb3BbMF0gJiAyID8geVtcInJldHVyblwiXSA6IG9wWzBdID8geVtcInRocm93XCJdIHx8ICgodCA9IHlbXCJyZXR1cm5cIl0pICYmIHQuY2FsbCh5KSwgMCkgOiB5Lm5leHQpICYmICEodCA9IHQuY2FsbCh5LCBvcFsxXSkpLmRvbmUpIHJldHVybiB0O1xyXG4gICAgICAgICAgICBpZiAoeSA9IDAsIHQpIG9wID0gW29wWzBdICYgMiwgdC52YWx1ZV07XHJcbiAgICAgICAgICAgIHN3aXRjaCAob3BbMF0pIHtcclxuICAgICAgICAgICAgICAgIGNhc2UgMDogY2FzZSAxOiB0ID0gb3A7IGJyZWFrO1xyXG4gICAgICAgICAgICAgICAgY2FzZSA0OiBfLmxhYmVsKys7IHJldHVybiB7IHZhbHVlOiBvcFsxXSwgZG9uZTogZmFsc2UgfTtcclxuICAgICAgICAgICAgICAgIGNhc2UgNTogXy5sYWJlbCsrOyB5ID0gb3BbMV07IG9wID0gWzBdOyBjb250aW51ZTtcclxuICAgICAgICAgICAgICAgIGNhc2UgNzogb3AgPSBfLm9wcy5wb3AoKTsgXy50cnlzLnBvcCgpOyBjb250aW51ZTtcclxuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKCEodCA9IF8udHJ5cywgdCA9IHQubGVuZ3RoID4gMCAmJiB0W3QubGVuZ3RoIC0gMV0pICYmIChvcFswXSA9PT0gNiB8fCBvcFswXSA9PT0gMikpIHsgXyA9IDA7IGNvbnRpbnVlOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG9wWzBdID09PSAzICYmICghdCB8fCAob3BbMV0gPiB0WzBdICYmIG9wWzFdIDwgdFszXSkpKSB7IF8ubGFiZWwgPSBvcFsxXTsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAob3BbMF0gPT09IDYgJiYgXy5sYWJlbCA8IHRbMV0pIHsgXy5sYWJlbCA9IHRbMV07IHQgPSBvcDsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAodCAmJiBfLmxhYmVsIDwgdFsyXSkgeyBfLmxhYmVsID0gdFsyXTsgXy5vcHMucHVzaChvcCk7IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHRbMl0pIF8ub3BzLnBvcCgpO1xyXG4gICAgICAgICAgICAgICAgICAgIF8udHJ5cy5wb3AoKTsgY29udGludWU7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgb3AgPSBib2R5LmNhbGwodGhpc0FyZywgXyk7XHJcbiAgICAgICAgfSBjYXRjaCAoZSkgeyBvcCA9IFs2LCBlXTsgeSA9IDA7IH0gZmluYWxseSB7IGYgPSB0ID0gMDsgfVxyXG4gICAgICAgIGlmIChvcFswXSAmIDUpIHRocm93IG9wWzFdOyByZXR1cm4geyB2YWx1ZTogb3BbMF0gPyBvcFsxXSA6IHZvaWQgMCwgZG9uZTogdHJ1ZSB9O1xyXG4gICAgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jcmVhdGVCaW5kaW5nKG8sIG0sIGssIGsyKSB7XHJcbiAgICBpZiAoazIgPT09IHVuZGVmaW5lZCkgazIgPSBrO1xyXG4gICAgb1trMl0gPSBtW2tdO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19leHBvcnRTdGFyKG0sIGV4cG9ydHMpIHtcclxuICAgIGZvciAodmFyIHAgaW4gbSkgaWYgKHAgIT09IFwiZGVmYXVsdFwiICYmICFleHBvcnRzLmhhc093blByb3BlcnR5KHApKSBleHBvcnRzW3BdID0gbVtwXTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fdmFsdWVzKG8pIHtcclxuICAgIHZhciBzID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIFN5bWJvbC5pdGVyYXRvciwgbSA9IHMgJiYgb1tzXSwgaSA9IDA7XHJcbiAgICBpZiAobSkgcmV0dXJuIG0uY2FsbChvKTtcclxuICAgIGlmIChvICYmIHR5cGVvZiBvLmxlbmd0aCA9PT0gXCJudW1iZXJcIikgcmV0dXJuIHtcclxuICAgICAgICBuZXh0OiBmdW5jdGlvbiAoKSB7XHJcbiAgICAgICAgICAgIGlmIChvICYmIGkgPj0gby5sZW5ndGgpIG8gPSB2b2lkIDA7XHJcbiAgICAgICAgICAgIHJldHVybiB7IHZhbHVlOiBvICYmIG9baSsrXSwgZG9uZTogIW8gfTtcclxuICAgICAgICB9XHJcbiAgICB9O1xyXG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihzID8gXCJPYmplY3QgaXMgbm90IGl0ZXJhYmxlLlwiIDogXCJTeW1ib2wuaXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19yZWFkKG8sIG4pIHtcclxuICAgIHZhciBtID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIG9bU3ltYm9sLml0ZXJhdG9yXTtcclxuICAgIGlmICghbSkgcmV0dXJuIG87XHJcbiAgICB2YXIgaSA9IG0uY2FsbChvKSwgciwgYXIgPSBbXSwgZTtcclxuICAgIHRyeSB7XHJcbiAgICAgICAgd2hpbGUgKChuID09PSB2b2lkIDAgfHwgbi0tID4gMCkgJiYgIShyID0gaS5uZXh0KCkpLmRvbmUpIGFyLnB1c2goci52YWx1ZSk7XHJcbiAgICB9XHJcbiAgICBjYXRjaCAoZXJyb3IpIHsgZSA9IHsgZXJyb3I6IGVycm9yIH07IH1cclxuICAgIGZpbmFsbHkge1xyXG4gICAgICAgIHRyeSB7XHJcbiAgICAgICAgICAgIGlmIChyICYmICFyLmRvbmUgJiYgKG0gPSBpW1wicmV0dXJuXCJdKSkgbS5jYWxsKGkpO1xyXG4gICAgICAgIH1cclxuICAgICAgICBmaW5hbGx5IHsgaWYgKGUpIHRocm93IGUuZXJyb3I7IH1cclxuICAgIH1cclxuICAgIHJldHVybiBhcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fc3ByZWFkKCkge1xyXG4gICAgZm9yICh2YXIgYXIgPSBbXSwgaSA9IDA7IGkgPCBhcmd1bWVudHMubGVuZ3RoOyBpKyspXHJcbiAgICAgICAgYXIgPSBhci5jb25jYXQoX19yZWFkKGFyZ3VtZW50c1tpXSkpO1xyXG4gICAgcmV0dXJuIGFyO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19zcHJlYWRBcnJheXMoKSB7XHJcbiAgICBmb3IgKHZhciBzID0gMCwgaSA9IDAsIGlsID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IGlsOyBpKyspIHMgKz0gYXJndW1lbnRzW2ldLmxlbmd0aDtcclxuICAgIGZvciAodmFyIHIgPSBBcnJheShzKSwgayA9IDAsIGkgPSAwOyBpIDwgaWw7IGkrKylcclxuICAgICAgICBmb3IgKHZhciBhID0gYXJndW1lbnRzW2ldLCBqID0gMCwgamwgPSBhLmxlbmd0aDsgaiA8IGpsOyBqKyssIGsrKylcclxuICAgICAgICAgICAgcltrXSA9IGFbal07XHJcbiAgICByZXR1cm4gcjtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2F3YWl0KHYpIHtcclxuICAgIHJldHVybiB0aGlzIGluc3RhbmNlb2YgX19hd2FpdCA/ICh0aGlzLnYgPSB2LCB0aGlzKSA6IG5ldyBfX2F3YWl0KHYpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY0dlbmVyYXRvcih0aGlzQXJnLCBfYXJndW1lbnRzLCBnZW5lcmF0b3IpIHtcclxuICAgIGlmICghU3ltYm9sLmFzeW5jSXRlcmF0b3IpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTeW1ib2wuYXN5bmNJdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbiAgICB2YXIgZyA9IGdlbmVyYXRvci5hcHBseSh0aGlzQXJnLCBfYXJndW1lbnRzIHx8IFtdKSwgaSwgcSA9IFtdO1xyXG4gICAgcmV0dXJuIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiKSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuYXN5bmNJdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IGlmIChnW25dKSBpW25dID0gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChhLCBiKSB7IHEucHVzaChbbiwgdiwgYSwgYl0pID4gMSB8fCByZXN1bWUobiwgdik7IH0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiByZXN1bWUobiwgdikgeyB0cnkgeyBzdGVwKGdbbl0odikpOyB9IGNhdGNoIChlKSB7IHNldHRsZShxWzBdWzNdLCBlKTsgfSB9XHJcbiAgICBmdW5jdGlvbiBzdGVwKHIpIHsgci52YWx1ZSBpbnN0YW5jZW9mIF9fYXdhaXQgPyBQcm9taXNlLnJlc29sdmUoci52YWx1ZS52KS50aGVuKGZ1bGZpbGwsIHJlamVjdCkgOiBzZXR0bGUocVswXVsyXSwgcik7IH1cclxuICAgIGZ1bmN0aW9uIGZ1bGZpbGwodmFsdWUpIHsgcmVzdW1lKFwibmV4dFwiLCB2YWx1ZSk7IH1cclxuICAgIGZ1bmN0aW9uIHJlamVjdCh2YWx1ZSkgeyByZXN1bWUoXCJ0aHJvd1wiLCB2YWx1ZSk7IH1cclxuICAgIGZ1bmN0aW9uIHNldHRsZShmLCB2KSB7IGlmIChmKHYpLCBxLnNoaWZ0KCksIHEubGVuZ3RoKSByZXN1bWUocVswXVswXSwgcVswXVsxXSk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNEZWxlZ2F0b3Iobykge1xyXG4gICAgdmFyIGksIHA7XHJcbiAgICByZXR1cm4gaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIsIGZ1bmN0aW9uIChlKSB7IHRocm93IGU7IH0pLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5pdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuLCBmKSB7IGlbbl0gPSBvW25dID8gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIChwID0gIXApID8geyB2YWx1ZTogX19hd2FpdChvW25dKHYpKSwgZG9uZTogbiA9PT0gXCJyZXR1cm5cIiB9IDogZiA/IGYodikgOiB2OyB9IDogZjsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY1ZhbHVlcyhvKSB7XHJcbiAgICBpZiAoIVN5bWJvbC5hc3luY0l0ZXJhdG9yKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU3ltYm9sLmFzeW5jSXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgdmFyIG0gPSBvW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSwgaTtcclxuICAgIHJldHVybiBtID8gbS5jYWxsKG8pIDogKG8gPSB0eXBlb2YgX192YWx1ZXMgPT09IFwiZnVuY3Rpb25cIiA/IF9fdmFsdWVzKG8pIDogb1tTeW1ib2wuaXRlcmF0b3JdKCksIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiKSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuYXN5bmNJdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpKTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyBpW25dID0gb1tuXSAmJiBmdW5jdGlvbiAodikgeyByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkgeyB2ID0gb1tuXSh2KSwgc2V0dGxlKHJlc29sdmUsIHJlamVjdCwgdi5kb25lLCB2LnZhbHVlKTsgfSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHNldHRsZShyZXNvbHZlLCByZWplY3QsIGQsIHYpIHsgUHJvbWlzZS5yZXNvbHZlKHYpLnRoZW4oZnVuY3Rpb24odikgeyByZXNvbHZlKHsgdmFsdWU6IHYsIGRvbmU6IGQgfSk7IH0sIHJlamVjdCk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fbWFrZVRlbXBsYXRlT2JqZWN0KGNvb2tlZCwgcmF3KSB7XHJcbiAgICBpZiAoT2JqZWN0LmRlZmluZVByb3BlcnR5KSB7IE9iamVjdC5kZWZpbmVQcm9wZXJ0eShjb29rZWQsIFwicmF3XCIsIHsgdmFsdWU6IHJhdyB9KTsgfSBlbHNlIHsgY29va2VkLnJhdyA9IHJhdzsgfVxyXG4gICAgcmV0dXJuIGNvb2tlZDtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2ltcG9ydFN0YXIobW9kKSB7XHJcbiAgICBpZiAobW9kICYmIG1vZC5fX2VzTW9kdWxlKSByZXR1cm4gbW9kO1xyXG4gICAgdmFyIHJlc3VsdCA9IHt9O1xyXG4gICAgaWYgKG1vZCAhPSBudWxsKSBmb3IgKHZhciBrIGluIG1vZCkgaWYgKE9iamVjdC5oYXNPd25Qcm9wZXJ0eS5jYWxsKG1vZCwgaykpIHJlc3VsdFtrXSA9IG1vZFtrXTtcclxuICAgIHJlc3VsdC5kZWZhdWx0ID0gbW9kO1xyXG4gICAgcmV0dXJuIHJlc3VsdDtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9faW1wb3J0RGVmYXVsdChtb2QpIHtcclxuICAgIHJldHVybiAobW9kICYmIG1vZC5fX2VzTW9kdWxlKSA/IG1vZCA6IHsgZGVmYXVsdDogbW9kIH07XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NsYXNzUHJpdmF0ZUZpZWxkR2V0KHJlY2VpdmVyLCBwcml2YXRlTWFwKSB7XHJcbiAgICBpZiAoIXByaXZhdGVNYXAuaGFzKHJlY2VpdmVyKSkge1xyXG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJhdHRlbXB0ZWQgdG8gZ2V0IHByaXZhdGUgZmllbGQgb24gbm9uLWluc3RhbmNlXCIpO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHByaXZhdGVNYXAuZ2V0KHJlY2VpdmVyKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY2xhc3NQcml2YXRlRmllbGRTZXQocmVjZWl2ZXIsIHByaXZhdGVNYXAsIHZhbHVlKSB7XHJcbiAgICBpZiAoIXByaXZhdGVNYXAuaGFzKHJlY2VpdmVyKSkge1xyXG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJhdHRlbXB0ZWQgdG8gc2V0IHByaXZhdGUgZmllbGQgb24gbm9uLWluc3RhbmNlXCIpO1xyXG4gICAgfVxyXG4gICAgcHJpdmF0ZU1hcC5zZXQocmVjZWl2ZXIsIHZhbHVlKTtcclxuICAgIHJldHVybiB2YWx1ZTtcclxufVxyXG4iLCJtb2R1bGUuZXhwb3J0cyA9IFwiPHN2ZyB2aWV3Qm94PVxcXCIwIDAgMTYgMTZcXFwiIGZpbGw9XFxcIm5vbmVcXFwiIHhtbG5zPVxcXCJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2Z1xcXCI+PHBhdGggZmlsbC1ydWxlPVxcXCJldmVub2RkXFxcIiBjbGlwLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGQ9XFxcIk0xNiAyLjQ0MyA1Ljg1MSAxNCAwIDguMTE1bDEuNDUtMS41MzggNC4zMSA0LjMzNEwxNC40NjMgMSAxNiAyLjQ0M1pcXFwiIGZpbGw9XFxcIiMwMDBcXFwiPjwvcGF0aD48L3N2Zz5cIiIsIm1vZHVsZS5leHBvcnRzID0gXCI8c3ZnIHZpZXdCb3g9XFxcIjAgMCAxNiAxNlxcXCIgZmlsbD1cXFwibm9uZVxcXCIgeG1sbnM9XFxcImh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnXFxcIj48cGF0aCBmaWxsLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGNsaXAtcnVsZT1cXFwiZXZlbm9kZFxcXCIgZD1cXFwiTTE2IDhBOCA4IDAgMSAxIDAgOGE4IDggMCAwIDEgMTYgMFptLTUuNzM3LTMuMzk0YS44LjggMCAwIDEgMS4xMzEgMS4xMzFMOS4xMzIgOGwyLjI2MiAyLjI2M2EuOC44IDAgMCAxLTEuMTMxIDEuMTMxTDggOS4xMzFsLTIuMjYzIDIuMjYzYS44LjggMCAwIDEtMS4xMy0xLjEzMUw2Ljg2OCA4IDQuNjA2IDUuNzM3YS44LjggMCAxIDEgMS4xMzEtMS4xMzFMOCA2Ljg2OWwyLjI2My0yLjI2M1pcXFwiIGZpbGw9XFxcIiMwMDBcXFwiPjwvcGF0aD48L3N2Zz5cIiIsIm1vZHVsZS5leHBvcnRzID0gXCI8c3ZnIHZpZXdCb3g9XFxcIjAgMCAxNiAxNlxcXCIgZmlsbD1cXFwibm9uZVxcXCIgeG1sbnM9XFxcImh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnXFxcIj48cGF0aCBmaWxsLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGNsaXAtcnVsZT1cXFwiZXZlbm9kZFxcXCIgZD1cXFwiTTkuNzk1IDEuMjgyYy4zODctLjM4NyAxLjAyOC0uMzc0IDEuNDMxLjAzbDEuNDYyIDEuNDYyYy40MDQuNDAzLjQxNyAxLjA0NC4wMyAxLjQzMUw1LjQxMyAxMS41MWwtMi42NzQuNDhhLjYzNy42MzcgMCAwIDEtLjczLS43M2wuNDgtMi42NzMgNy4zMDYtNy4zMDVaTTIgMTNhMSAxIDAgMSAwIDAgMmgxMmExIDEgMCAxIDAgMC0ySDJaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PC9zdmc+XCIiLCJtb2R1bGUuZXhwb3J0cyA9IFwiPHN2ZyB2aWV3Qm94PVxcXCIwIDAgMTYgMTZcXFwiIGZpbGw9XFxcIm5vbmVcXFwiIHhtbG5zPVxcXCJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2Z1xcXCI+PHBhdGggZmlsbC1ydWxlPVxcXCJldmVub2RkXFxcIiBjbGlwLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGQ9XFxcIk0xIDNhMiAyIDAgMCAxIDItMmg4LjA4NmExIDEgMCAwIDEgLjcwNy4yOTNsMi45MTQgMi45MTRhMSAxIDAgMCAxIC4yOTMuNzA3VjEzYTIgMiAwIDAgMS0yIDJIM2EyIDIgMCAwIDEtMi0yVjNabTEuNzUuNzVhMSAxIDAgMCAxIDEtMWg1Ljg3NWExIDEgMCAwIDEgMSAxdjEuNWExIDEgMCAwIDEtMSAxSDMuNzVhMSAxIDAgMCAxLTEtMXYtMS41Wm03Ljg3NSA2Ljg3NWEyLjYyNSAyLjYyNSAwIDEgMS01LjI1IDAgMi42MjUgMi42MjUgMCAwIDEgNS4yNSAwWlxcXCIgZmlsbD1cXFwiIzAwMFxcXCI+PC9wYXRoPjwvc3ZnPlwiIiwibW9kdWxlLmV4cG9ydHMgPSBcIjxzdmcgdmlld0JveD1cXFwiMCAwIDE2IDE2XFxcIiBmaWxsPVxcXCJub25lXFxcIiB4bWxucz1cXFwiaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmdcXFwiPjxwYXRoIGZpbGwtcnVsZT1cXFwiZXZlbm9kZFxcXCIgY2xpcC1ydWxlPVxcXCJldmVub2RkXFxcIiBkPVxcXCJNMSA4YzAtMy44NSAzLjE1LTcgNy03czcgMy4xNSA3IDctMy4xNSA3LTcgNy03LTMuMTUtNy03Wm03Ljg3NSA0LjM3NWEuODc1Ljg3NSAwIDEgMS0xLjc1IDAgLjg3NS44NzUgMCAwIDEgMS43NSAwWm0tLjA2My0yLjY1NmMuMTMyLS41NzEuNDE1LS45MTYuODQ4LTEuMjk5LjQzMy0uMzgzLjcwMS0uNzA5LjcwMS0uNzA5LjM5LS40NzIuNzAxLTEuMTAyLjcwMS0xLjgxMSAwLTEuNzMyLTEuNDAyLTMuMTUtMy4xMTctMy4xNS0xLjM1NyAwLTIuNTIuOTI4LTIuOTQ2IDIuMTU3LS4wNi4xNTItLjA2LjI5OS0uMDYuMjk5YS42NDguNjQ4IDAgMCAwIC42NjguNjk0bC4xLS4wMDZjLjQtLjA0Ni42NzktLjI3NS44MjktLjY1LjA3OC0uMTY0LjEwOC0uMjA4LjEyMi0uMjI5LjI4MS0uNDE2Ljc1NC0uNjkgMS4yODctLjY5Ljg1OCAwIDEuNTU5LjcwOSAxLjU1OSAxLjU3NSAwIC40NzItLjE1Ni44NjYtLjQ2OCAxLjEwM2wtLjkzNSAxLjAyM2MtLjUwNS40NDctLjgwNiAxLjA0OS0uOTAxIDEuNzIyYS42MTQuNjE0IDAgMCAwLS4wMDUuMDY0di4xMTdhLjc0OC43NDggMCAwIDAgLjc1LjY5NmwuMDkyLS4wMDVjLjM5My0uMDQzLjcxNC0uMzU4Ljc0My0uNzRsLjAzMi0uMTYxWlxcXCIgZmlsbD1cXFwiIzAwMFxcXCI+PC9wYXRoPjwvc3ZnPlwiIiwibW9kdWxlLmV4cG9ydHMgPSBcIjxzdmcgdmlld0JveD1cXFwiMCAwIDE2IDE2XFxcIiBmaWxsPVxcXCJub25lXFxcIiB4bWxucz1cXFwiaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmdcXFwiPjxwYXRoIGQ9XFxcIm04Ljc0NSA4IDYuMSA2LjFhLjUyNy41MjcgMCAxIDEtLjc0NS43NDZMOCA4Ljc0NmwtNi4xIDYuMWEuNTI3LjUyNyAwIDEgMS0uNzQ2LS43NDZsNi4xLTYuMS02LjEtNi4xYS41MjcuNTI3IDAgMCAxIC43NDYtLjc0Nmw2LjEgNi4xIDYuMS02LjFhLjUyNy41MjcgMCAwIDEgLjc0Ni43NDZMOC43NDYgOFpcXFwiIGZpbGw9XFxcIiMwMDBcXFwiPjwvcGF0aD48L3N2Zz5cIiIsIm1vZHVsZS5leHBvcnRzID0gXCI8c3ZnIHZpZXdCb3g9XFxcIjAgMCAxNiAxNlxcXCIgZmlsbD1cXFwibm9uZVxcXCIgeG1sbnM9XFxcImh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnXFxcIj48cGF0aCBmaWxsLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGNsaXAtcnVsZT1cXFwiZXZlbm9kZFxcXCIgZD1cXFwiTTExLjIyNiAxLjMxMmMtLjQwMy0uNDA0LTEuMDQ0LS40MTctMS40MzEtLjAzTDIuNDkgOC41ODdsLS40OCAyLjY3NGEuNjM3LjYzNyAwIDAgMCAuNzMuNzNsMi42NzMtLjQ4IDcuMzA1LTcuMzA2Yy4zODctLjM4Ny4zNzQtMS4wMjgtLjAzLTEuNDMxbC0xLjQ2Mi0xLjQ2MlptLTguMTEzIDkuNTc1LjMyLTEuNzgxIDQuOTkxLTQuOTkyIDEuNDYyIDEuNDYyLTQuOTkyIDQuOTkxLTEuNzgxLjMyWm03LjQ3My02LjAxMiAxLjQwMi0xLjQtMS40NjItMS40NjMtMS40MDEgMS40MDIgMS40NjEgMS40NjFaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PHBhdGggZD1cXFwiTTEuNSAxNGEuNS41IDAgMCAwIDAgMWgxM2EuNS41IDAgMCAwIDAtMWgtMTNaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PC9zdmc+XCIiLCJtb2R1bGUuZXhwb3J0cyA9IFwiPHN2ZyB2aWV3Qm94PVxcXCIwIDAgMTYgMTZcXFwiIGZpbGw9XFxcIm5vbmVcXFwiIHhtbG5zPVxcXCJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2Z1xcXCI+PHBhdGggZmlsbC1ydWxlPVxcXCJldmVub2RkXFxcIiBjbGlwLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGQ9XFxcIk0xNCA4QTYgNiAwIDEgMSAyIDhhNiA2IDAgMCAxIDEyIDBabTEgMEE3IDcgMCAxIDEgMSA4YTcgNyAwIDAgMSAxNCAwWk03LjUgNC41YS41LjUgMCAwIDEgMSAwdjNoM2EuNS41IDAgMCAxIDAgMWgtM3YzYS41LjUgMCAwIDEtMSAwdi0zaC0zYS41LjUgMCAwIDEgMC0xaDN2LTNaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PC9zdmc+XCIiLCJtb2R1bGUuZXhwb3J0cyA9IFwiPHN2ZyB2aWV3Qm94PVxcXCIwIDAgMTYgMTZcXFwiIGZpbGw9XFxcIm5vbmVcXFwiIHhtbG5zPVxcXCJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2Z1xcXCI+PHBhdGggZD1cXFwiTTYgNi41YS41LjUgMCAwIDEgMSAwdjZhLjUuNSAwIDAgMS0xIDB2LTZaTTkuNSA2YS41LjUgMCAwIDAtLjUuNXY2YS41LjUgMCAwIDAgMSAwdi02YS41LjUgMCAwIDAtLjUtLjVaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PHBhdGggZmlsbC1ydWxlPVxcXCJldmVub2RkXFxcIiBjbGlwLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGQ9XFxcIk0xMSAwSDVhMSAxIDAgMCAwLTEgMXYySC41YS41LjUgMCAwIDAgMCAxaDEuNmwuODEgMTEuMWExIDEgMCAwIDAgLjk5NS45aDguMTlhMSAxIDAgMCAwIC45OTUtLjlMMTMuOSA0aDEuNmEuNS41IDAgMCAwIDAtMUgxMlYxYTEgMSAwIDAgMC0xLTFabTAgM1YxSDV2Mmg2Wm0xLjg5NSAxaC05Ljc5bC44IDExaDguMTlsLjgtMTFaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PC9zdmc+XCIiLCJpbXBvcnQgeyBSZWFjdCwgY2xhc3NOYW1lcyB9IGZyb20gJ2ppbXUtY29yZSdcclxuaW1wb3J0IHsgdHlwZSBTVkdDb21wb25lbnRQcm9wcyB9IGZyb20gJ2ppbXUtdWknXHJcbmltcG9ydCBzcmMgZnJvbSAnLi4vLi4vc3ZnL2ZpbGxlZC9hcHBsaWNhdGlvbi9jaGVjay5zdmcnXHJcblxyXG5leHBvcnQgY29uc3QgQ2hlY2tGaWxsZWQgPSAocHJvcHM6IFNWR0NvbXBvbmVudFByb3BzKSA9PiB7XHJcbiAgY29uc3QgU1ZHID0gd2luZG93LlNWR1xyXG4gIGNvbnN0IHsgY2xhc3NOYW1lLCAuLi5vdGhlcnMgfSA9IHByb3BzXHJcblxyXG4gIGNvbnN0IGNsYXNzZXMgPSBjbGFzc05hbWVzKCdqaW11LWljb24gamltdS1pY29uLWNvbXBvbmVudCcsIGNsYXNzTmFtZSlcclxuICBpZiAoIVNWRykgcmV0dXJuIDxzdmcgY2xhc3NOYW1lPXtjbGFzc2VzfSB7Li4ub3RoZXJzIGFzIGFueX0gLz5cclxuICByZXR1cm4gPFNWRyBjbGFzc05hbWU9e2NsYXNzZXN9IHNyYz17c3JjfSB7Li4ub3RoZXJzfSAvPlxyXG59XHJcbiIsImltcG9ydCB7IFJlYWN0LCBjbGFzc05hbWVzIH0gZnJvbSAnamltdS1jb3JlJ1xyXG5pbXBvcnQgeyB0eXBlIFNWR0NvbXBvbmVudFByb3BzIH0gZnJvbSAnamltdS11aSdcclxuaW1wb3J0IHNyYyBmcm9tICcuLi8uLi9zdmcvZmlsbGVkL2VkaXRvci9jbG9zZS1jaXJjbGUuc3ZnJ1xyXG5cclxuZXhwb3J0IGNvbnN0IENsb3NlQ2lyY2xlRmlsbGVkID0gKHByb3BzOiBTVkdDb21wb25lbnRQcm9wcykgPT4ge1xyXG4gIGNvbnN0IFNWRyA9IHdpbmRvdy5TVkdcclxuICBjb25zdCB7IGNsYXNzTmFtZSwgLi4ub3RoZXJzIH0gPSBwcm9wc1xyXG5cclxuICBjb25zdCBjbGFzc2VzID0gY2xhc3NOYW1lcygnamltdS1pY29uIGppbXUtaWNvbi1jb21wb25lbnQnLCBjbGFzc05hbWUpXHJcbiAgaWYgKCFTVkcpIHJldHVybiA8c3ZnIGNsYXNzTmFtZT17Y2xhc3Nlc30gey4uLm90aGVycyBhcyBhbnl9IC8+XHJcbiAgcmV0dXJuIDxTVkcgY2xhc3NOYW1lPXtjbGFzc2VzfSBzcmM9e3NyY30gey4uLm90aGVyc30gLz5cclxufVxyXG4iLCJpbXBvcnQgeyBSZWFjdCwgY2xhc3NOYW1lcyB9IGZyb20gJ2ppbXUtY29yZSdcclxuaW1wb3J0IHsgdHlwZSBTVkdDb21wb25lbnRQcm9wcyB9IGZyb20gJ2ppbXUtdWknXHJcbmltcG9ydCBzcmMgZnJvbSAnLi4vLi4vc3ZnL2ZpbGxlZC9lZGl0b3IvZWRpdC5zdmcnXHJcblxyXG5leHBvcnQgY29uc3QgRWRpdEZpbGxlZCA9IChwcm9wczogU1ZHQ29tcG9uZW50UHJvcHMpID0+IHtcclxuICBjb25zdCBTVkcgPSB3aW5kb3cuU1ZHXHJcbiAgY29uc3QgeyBjbGFzc05hbWUsIC4uLm90aGVycyB9ID0gcHJvcHNcclxuXHJcbiAgY29uc3QgY2xhc3NlcyA9IGNsYXNzTmFtZXMoJ2ppbXUtaWNvbiBqaW11LWljb24tY29tcG9uZW50JywgY2xhc3NOYW1lKVxyXG4gIGlmICghU1ZHKSByZXR1cm4gPHN2ZyBjbGFzc05hbWU9e2NsYXNzZXN9IHsuLi5vdGhlcnMgYXMgYW55fSAvPlxyXG4gIHJldHVybiA8U1ZHIGNsYXNzTmFtZT17Y2xhc3Nlc30gc3JjPXtzcmN9IHsuLi5vdGhlcnN9IC8+XHJcbn1cclxuIiwiaW1wb3J0IHsgUmVhY3QsIGNsYXNzTmFtZXMgfSBmcm9tICdqaW11LWNvcmUnXHJcbmltcG9ydCB7IHR5cGUgU1ZHQ29tcG9uZW50UHJvcHMgfSBmcm9tICdqaW11LXVpJ1xyXG5pbXBvcnQgc3JjIGZyb20gJy4uLy4uL3N2Zy9maWxsZWQvZWRpdG9yL3NhdmUuc3ZnJ1xyXG5cclxuZXhwb3J0IGNvbnN0IFNhdmVGaWxsZWQgPSAocHJvcHM6IFNWR0NvbXBvbmVudFByb3BzKSA9PiB7XHJcbiAgY29uc3QgU1ZHID0gd2luZG93LlNWR1xyXG4gIGNvbnN0IHsgY2xhc3NOYW1lLCAuLi5vdGhlcnMgfSA9IHByb3BzXHJcblxyXG4gIGNvbnN0IGNsYXNzZXMgPSBjbGFzc05hbWVzKCdqaW11LWljb24gamltdS1pY29uLWNvbXBvbmVudCcsIGNsYXNzTmFtZSlcclxuICBpZiAoIVNWRykgcmV0dXJuIDxzdmcgY2xhc3NOYW1lPXtjbGFzc2VzfSB7Li4ub3RoZXJzIGFzIGFueX0gLz5cclxuICByZXR1cm4gPFNWRyBjbGFzc05hbWU9e2NsYXNzZXN9IHNyYz17c3JjfSB7Li4ub3RoZXJzfSAvPlxyXG59XHJcbiIsImltcG9ydCB7IFJlYWN0LCBjbGFzc05hbWVzIH0gZnJvbSAnamltdS1jb3JlJ1xyXG5pbXBvcnQgeyB0eXBlIFNWR0NvbXBvbmVudFByb3BzIH0gZnJvbSAnamltdS11aSdcclxuaW1wb3J0IHNyYyBmcm9tICcuLi8uLi9zdmcvZmlsbGVkL3N1Z2dlc3RlZC9oZWxwLnN2ZydcclxuXHJcbmV4cG9ydCBjb25zdCBIZWxwRmlsbGVkID0gKHByb3BzOiBTVkdDb21wb25lbnRQcm9wcykgPT4ge1xyXG4gIGNvbnN0IFNWRyA9IHdpbmRvdy5TVkdcclxuICBjb25zdCB7IGNsYXNzTmFtZSwgLi4ub3RoZXJzIH0gPSBwcm9wc1xyXG5cclxuICBjb25zdCBjbGFzc2VzID0gY2xhc3NOYW1lcygnamltdS1pY29uIGppbXUtaWNvbi1jb21wb25lbnQnLCBjbGFzc05hbWUpXHJcbiAgaWYgKCFTVkcpIHJldHVybiA8c3ZnIGNsYXNzTmFtZT17Y2xhc3Nlc30gey4uLm90aGVycyBhcyBhbnl9IC8+XHJcbiAgcmV0dXJuIDxTVkcgY2xhc3NOYW1lPXtjbGFzc2VzfSBzcmM9e3NyY30gey4uLm90aGVyc30gLz5cclxufVxyXG4iLCJpbXBvcnQgeyBSZWFjdCwgY2xhc3NOYW1lcyB9IGZyb20gJ2ppbXUtY29yZSdcclxuaW1wb3J0IHsgdHlwZSBTVkdDb21wb25lbnRQcm9wcyB9IGZyb20gJ2ppbXUtdWknXHJcbmltcG9ydCBzcmMgZnJvbSAnLi4vLi4vc3ZnL291dGxpbmVkL2VkaXRvci9jbG9zZS5zdmcnXHJcblxyXG5leHBvcnQgY29uc3QgQ2xvc2VPdXRsaW5lZCA9IChwcm9wczogU1ZHQ29tcG9uZW50UHJvcHMpID0+IHtcclxuICBjb25zdCBTVkcgPSB3aW5kb3cuU1ZHXHJcbiAgY29uc3QgeyBjbGFzc05hbWUsIC4uLm90aGVycyB9ID0gcHJvcHNcclxuXHJcbiAgY29uc3QgY2xhc3NlcyA9IGNsYXNzTmFtZXMoJ2ppbXUtaWNvbiBqaW11LWljb24tY29tcG9uZW50JywgY2xhc3NOYW1lKVxyXG4gIGlmICghU1ZHKSByZXR1cm4gPHN2ZyBjbGFzc05hbWU9e2NsYXNzZXN9IHsuLi5vdGhlcnMgYXMgYW55fSAvPlxyXG4gIHJldHVybiA8U1ZHIGNsYXNzTmFtZT17Y2xhc3Nlc30gc3JjPXtzcmN9IHsuLi5vdGhlcnN9IC8+XHJcbn1cclxuIiwiaW1wb3J0IHsgUmVhY3QsIGNsYXNzTmFtZXMgfSBmcm9tICdqaW11LWNvcmUnXHJcbmltcG9ydCB7IHR5cGUgU1ZHQ29tcG9uZW50UHJvcHMgfSBmcm9tICdqaW11LXVpJ1xyXG5pbXBvcnQgc3JjIGZyb20gJy4uLy4uL3N2Zy9vdXRsaW5lZC9lZGl0b3IvZWRpdC5zdmcnXHJcblxyXG5leHBvcnQgY29uc3QgRWRpdE91dGxpbmVkID0gKHByb3BzOiBTVkdDb21wb25lbnRQcm9wcykgPT4ge1xyXG4gIGNvbnN0IFNWRyA9IHdpbmRvdy5TVkdcclxuICBjb25zdCB7IGNsYXNzTmFtZSwgLi4ub3RoZXJzIH0gPSBwcm9wc1xyXG5cclxuICBjb25zdCBjbGFzc2VzID0gY2xhc3NOYW1lcygnamltdS1pY29uIGppbXUtaWNvbi1jb21wb25lbnQnLCBjbGFzc05hbWUpXHJcbiAgaWYgKCFTVkcpIHJldHVybiA8c3ZnIGNsYXNzTmFtZT17Y2xhc3Nlc30gey4uLm90aGVycyBhcyBhbnl9IC8+XHJcbiAgcmV0dXJuIDxTVkcgY2xhc3NOYW1lPXtjbGFzc2VzfSBzcmM9e3NyY30gey4uLm90aGVyc30gLz5cclxufVxyXG4iLCJpbXBvcnQgeyBSZWFjdCwgY2xhc3NOYW1lcyB9IGZyb20gJ2ppbXUtY29yZSdcclxuaW1wb3J0IHsgdHlwZSBTVkdDb21wb25lbnRQcm9wcyB9IGZyb20gJ2ppbXUtdWknXHJcbmltcG9ydCBzcmMgZnJvbSAnLi4vLi4vc3ZnL291dGxpbmVkL2VkaXRvci9wbHVzLWNpcmNsZS5zdmcnXHJcblxyXG5leHBvcnQgY29uc3QgUGx1c0NpcmNsZU91dGxpbmVkID0gKHByb3BzOiBTVkdDb21wb25lbnRQcm9wcykgPT4ge1xyXG4gIGNvbnN0IFNWRyA9IHdpbmRvdy5TVkdcclxuICBjb25zdCB7IGNsYXNzTmFtZSwgLi4ub3RoZXJzIH0gPSBwcm9wc1xyXG5cclxuICBjb25zdCBjbGFzc2VzID0gY2xhc3NOYW1lcygnamltdS1pY29uIGppbXUtaWNvbi1jb21wb25lbnQnLCBjbGFzc05hbWUpXHJcbiAgaWYgKCFTVkcpIHJldHVybiA8c3ZnIGNsYXNzTmFtZT17Y2xhc3Nlc30gey4uLm90aGVycyBhcyBhbnl9IC8+XHJcbiAgcmV0dXJuIDxTVkcgY2xhc3NOYW1lPXtjbGFzc2VzfSBzcmM9e3NyY30gey4uLm90aGVyc30gLz5cclxufVxyXG4iLCJpbXBvcnQgeyBSZWFjdCwgY2xhc3NOYW1lcyB9IGZyb20gJ2ppbXUtY29yZSdcclxuaW1wb3J0IHsgdHlwZSBTVkdDb21wb25lbnRQcm9wcyB9IGZyb20gJ2ppbXUtdWknXHJcbmltcG9ydCBzcmMgZnJvbSAnLi4vLi4vc3ZnL291dGxpbmVkL2VkaXRvci90cmFzaC5zdmcnXHJcblxyXG5leHBvcnQgY29uc3QgVHJhc2hPdXRsaW5lZCA9IChwcm9wczogU1ZHQ29tcG9uZW50UHJvcHMpID0+IHtcclxuICBjb25zdCBTVkcgPSB3aW5kb3cuU1ZHXHJcbiAgY29uc3QgeyBjbGFzc05hbWUsIC4uLm90aGVycyB9ID0gcHJvcHNcclxuXHJcbiAgY29uc3QgY2xhc3NlcyA9IGNsYXNzTmFtZXMoJ2ppbXUtaWNvbiBqaW11LWljb24tY29tcG9uZW50JywgY2xhc3NOYW1lKVxyXG4gIGlmICghU1ZHKSByZXR1cm4gPHN2ZyBjbGFzc05hbWU9e2NsYXNzZXN9IHsuLi5vdGhlcnMgYXMgYW55fSAvPlxyXG4gIHJldHVybiA8U1ZHIGNsYXNzTmFtZT17Y2xhc3Nlc30gc3JjPXtzcmN9IHsuLi5vdGhlcnN9IC8+XHJcbn1cclxuIiwiaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiO1xyXG5pbXBvcnQge1xyXG4gIEFwcFdpZGdldENvbmZpZywgQXNzZXNzbWVudCwgXHJcbiAgQ2xzc1Jlc3BvbnNlLFxyXG4gIENMU1NUZW1wbGF0ZSwgXHJcbiAgQ29tcG9uZW50VGVtcGxhdGUsIFxyXG4gIEhhemFyZCxcclxuICBJbmNpZGVudCxcclxuICBJbkNvbW1lbnQsXHJcbiAgSW5kaWNhdG9yQXNzZXNzbWVudCxcclxuICBJbmRpY2F0b3JUZW1wbGF0ZSwgSW5kaWNhdG9yV2VpZ2h0LCBMaWZlbGluZVN0YXR1cywgTGlmZUxpbmVUZW1wbGF0ZSxcclxuICBPcmdhbml6YXRpb24sIFNjYWxlRmFjdG9yXHJcbn0gZnJvbSBcIi4vZGF0YS1kZWZpbml0aW9uc1wiO1xyXG5pbXBvcnQge1xyXG4gIEFTU0VTU01FTlRfVVJMX0VSUk9SLCBcclxuICBCQVNFTElORV9URU1QTEFURV9OQU1FLCBcclxuICBDT01QT05FTlRfVVJMX0VSUk9SLCBFTlZJUk9OTUVOVF9QUkVTRVJWQVRJT04sIEhBWkFSRF9VUkxfRVJST1IsIElOQ0lERU5UX1NUQUJJTElaQVRJT04sIElOQ0lERU5UX1VSTF9FUlJPUiwgSU5ESUNBVE9SX1VSTF9FUlJPUixcclxuICBMSUZFX1NBRkVUWSxcclxuICBMSUZFX1NBRkVUWV9TQ0FMRV9GQUNUT1IsXHJcbiAgTElGRUxJTkVfVVJMX0VSUk9SLCBNQVhJTVVNX1dFSUdIVCwgT1JHQU5JWkFUSU9OX1VSTF9FUlJPUiwgT1RIRVJfV0VJR0hUU19TQ0FMRV9GQUNUT1IsIFxyXG4gIFBPUlRBTF9VUkwsIFxyXG4gIFBST1BFUlRZX1BST1RFQ1RJT04sIFxyXG4gIFJBTkssIFxyXG4gIFRFTVBMQVRFX1VSTF9FUlJPUn0gZnJvbSBcIi4vY29uc3RhbnRzXCI7XHJcbmltcG9ydCB7IGdldEFwcFN0b3JlIH0gZnJvbSBcImppbXUtY29yZVwiO1xyXG5pbXBvcnQge1xyXG4gIElGZWF0dXJlLCBJRmVhdHVyZVNldCwgSUZpZWxkfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllclwiO1xyXG5pbXBvcnQgeyBxdWVyeVRhYmxlRmVhdHVyZXMsIFxyXG4gICB1cGRhdGVUYWJsZUZlYXR1cmUsIGRlbGV0ZVRhYmxlRmVhdHVyZXMsIFxyXG4gICAgYWRkVGFibGVGZWF0dXJlcywgdXBkYXRlVGFibGVGZWF0dXJlcywgcXVlcnlUYWJsZUZlYXR1cmVTZXQgfSBmcm9tIFwiLi9lc3JpLWFwaVwiO1xyXG5pbXBvcnQgeyBsb2csIExvZ1R5cGUgfSBmcm9tIFwiLi9sb2dnZXJcIjtcclxuaW1wb3J0IHsgSUNvZGVkVmFsdWUgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtdHlwZXNcIjtcclxuaW1wb3J0IHsgY2hlY2tDdXJyZW50U3RhdHVzLCBzaWduSW4gfSBmcm9tIFwiLi9hdXRoXCI7XHJcbmltcG9ydCB7IENMU1NBY3Rpb25LZXlzIH0gZnJvbSBcIi4vY2xzcy1zdG9yZVwiO1xyXG5pbXBvcnQgeyBJQ3JlZGVudGlhbCB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1hdXRoXCI7XHJcbmltcG9ydCB7IHBhcnNlRGF0ZSB9IGZyb20gXCIuL3V0aWxzXCI7XHJcblxyXG5cclxuLy89PT09PT09PT09PT09PT09PT09PT09PT1QVUJMSUM9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XHJcblxyXG5leHBvcnQgY29uc3QgaW5pdGlhbGl6ZUF1dGggPSBhc3luYyhhcHBJZDogc3RyaW5nKSA9PnsgICBcclxuICBjb25zb2xlLmxvZygnaW5pdGlhbGl6ZUF1dGggY2FsbGVkJylcclxuICBsZXQgY3JlZCA9IGF3YWl0IGNoZWNrQ3VycmVudFN0YXR1cyhhcHBJZCwgUE9SVEFMX1VSTCk7XHJcblxyXG4gIGlmKCFjcmVkKXtcclxuICAgIGNyZWQgPSBhd2FpdCBzaWduSW4oYXBwSWQsIFBPUlRBTF9VUkwpOyAgICBcclxuICB9XHJcblxyXG4gIGNvbnN0IGNyZWRlbnRpYWwgPSB7XHJcbiAgICBleHBpcmVzOiBjcmVkLmV4cGlyZXMsXHJcbiAgICBzZXJ2ZXI6IGNyZWQuc2VydmVyLFxyXG4gICAgc3NsOiBjcmVkLnNzbCxcclxuICAgIHRva2VuOiBjcmVkLnRva2VuLFxyXG4gICAgdXNlcklkOiBjcmVkLnVzZXJJZFxyXG4gIH0gYXMgSUNyZWRlbnRpYWxcclxuXHJcbiAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuQVVUSEVOVElDQVRFX0FDVElPTiwgY3JlZGVudGlhbCk7IFxyXG59XHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB1cGRhdGVMaWZlbGluZVN0YXR1cyhsaWZlbGluZVN0YXR1czogTGlmZWxpbmVTdGF0dXMsIFxyXG4gIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBhc3Nlc3NtZW50T2JqZWN0SWQ6IG51bWJlciwgIHVzZXI6IHN0cmluZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICBcclxuICBjb25zb2xlLmxvZygnY2FsbGVkIHVwZGF0ZUxpZmVsaW5lU3RhdHVzJylcclxuICBjaGVja1BhcmFtKGNvbmZpZy5saWZlbGluZVN0YXR1cywgJ0xpZmVsaW5lIFN0YXR1cyBVUkwgbm90IHByb3ZpZGVkJyk7XHJcblxyXG4gIGNvbnN0IGF0dHJpYnV0ZXMgPSB7XHJcbiAgICBPQkpFQ1RJRDogbGlmZWxpbmVTdGF0dXMub2JqZWN0SWQsXHJcbiAgICBTY29yZTogbGlmZWxpbmVTdGF0dXMuc2NvcmUsIFxyXG4gICAgQ29sb3I6IGxpZmVsaW5lU3RhdHVzLmNvbG9yLCBcclxuICAgIElzT3ZlcnJpZGVuOiBsaWZlbGluZVN0YXR1cy5pc092ZXJyaWRlbiwgXHJcbiAgICBPdmVycmlkZW5TY29yZTogbGlmZWxpbmVTdGF0dXMub3ZlcnJpZGVTY29yZSwgIFxyXG4gICAgT3ZlcnJpZGVuQ29sb3I6IGxpZmVsaW5lU3RhdHVzLm92ZXJyaWRlbkNvbG9yLFxyXG4gICAgT3ZlcnJpZGVuQnk6IGxpZmVsaW5lU3RhdHVzLm92ZXJyaWRlbkJ5LCAgXHJcbiAgICBPdmVycmlkZUNvbW1lbnQ6IGxpZmVsaW5lU3RhdHVzLm92ZXJyaWRlQ29tbWVudCBcclxuICB9XHJcbiAgbGV0IHJlc3BvbnNlICA9IGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZShjb25maWcubGlmZWxpbmVTdGF0dXMsIGF0dHJpYnV0ZXMsIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcblxyXG4gICAgY29uc3QgaWFGZWF0dXJlcyA9IGxpZmVsaW5lU3RhdHVzLmluZGljYXRvckFzc2Vzc21lbnRzLm1hcChpID0+IHtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICBPQkpFQ1RJRDogaS5vYmplY3RJZCxcclxuICAgICAgICAgIHN0YXR1czogaS5zdGF0dXMsXHJcbiAgICAgICAgICBDb21tZW50czogaS5jb21tZW50cyAmJiBpLmNvbW1lbnRzLmxlbmd0aCA+IDAgPyBKU09OLnN0cmluZ2lmeShpLmNvbW1lbnRzKTogJydcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuICAgIH0pXHJcblxyXG4gICAgcmVzcG9uc2UgPSBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JBc3Nlc3NtZW50cywgaWFGZWF0dXJlcywgY29uZmlnKTtcclxuICAgIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG5cclxuICAgICAgY29uc3QgYXNzZXNzRmVhdHVyZSA9IHtcclxuICAgICAgICBPQkpFQ1RJRDogYXNzZXNzbWVudE9iamVjdElkLFxyXG4gICAgICAgIEVkaXRlZERhdGU6IG5ldyBEYXRlKCkuZ2V0VGltZSgpLFxyXG4gICAgICAgIEVkaXRvcjogdXNlclxyXG4gICAgICB9XHJcbiAgICAgIHJlc3BvbnNlID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy5hc3Nlc3NtZW50cywgYXNzZXNzRmVhdHVyZSwgY29uZmlnKVxyXG4gICAgICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG4gICAgfSAgICBcclxuICB9XHJcbiAgbG9nKCdVcGRhdGluZyBMaWZlbGluZSBzY29yZSBmYWlsZWQnLCBMb2dUeXBlLkVSUk9SLCAndXBkYXRlTGlmZWxpbmVTdGF0dXMnKTtcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnVXBkYXRpbmcgTGlmZWxpbmUgc2NvcmUgZmFpbGVkJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNvbXBsZXRlQXNzZXNzbWVudChhc3Nlc3NtZW50OiBBc3Nlc3NtZW50LCBcclxuICBjb25maWc6IEFwcFdpZGdldENvbmZpZywgdXNlck5hbWU6IHN0cmluZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICAgY2hlY2tQYXJhbShjb25maWcuYXNzZXNzbWVudHMsICdObyBBc3Nlc3NtZW50IFVybCBwcm92aWRlZCcpO1xyXG5cclxuICAgY29uc3QgcmVzcG9uc2UgPSAgYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy5hc3Nlc3NtZW50cywge1xyXG4gICAgICBPQkpFQ1RJRDogYXNzZXNzbWVudC5vYmplY3RJZCxcclxuICAgICAgRWRpdG9yOiB1c2VyTmFtZSxcclxuICAgICAgRWRpdGVkRGF0ZTogbmV3IERhdGUoKS5nZXRUaW1lKCksXHJcbiAgICAgIElzQ29tcGxldGVkOiAxXHJcbiAgIH0sIGNvbmZpZyk7XHJcbiAgIGNvbnNvbGUubG9nKHJlc3BvbnNlKTtcclxuICAgcmV0dXJue1xyXG4gICAgIGRhdGE6IHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2VzcylcclxuICAgfVxyXG59XHJcblxyXG5leHBvcnQgY29uc3QgcGFzc0RhdGFJbnRlZ3JpdHkgPSBhc3luYyAoc2VydmljZVVybDogc3RyaW5nLCBmaWVsZHM6IElGaWVsZFtdLCBjb25maWc6IEFwcFdpZGdldENvbmZpZykgPT4ge1xyXG5cclxuICBjaGVja1BhcmFtKHNlcnZpY2VVcmwsICdTZXJ2aWNlIFVSTCBub3QgcHJvdmlkZWQnKTtcclxuXHJcbiAgLy8gc2VydmljZVVybCA9IGAke3NlcnZpY2VVcmx9P2Y9anNvbiZ0b2tlbj0ke3Rva2VufWA7XHJcbiAgLy8gY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaChzZXJ2aWNlVXJsLCB7XHJcbiAgLy8gICBtZXRob2Q6IFwiR0VUXCIsXHJcbiAgLy8gICBoZWFkZXJzOiB7XHJcbiAgLy8gICAgICdjb250ZW50LXR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xyXG4gIC8vICAgfVxyXG4gIC8vIH1cclxuICAvLyApO1xyXG4gIC8vIGNvbnN0IGpzb24gPSBhd2FpdCByZXNwb25zZS5qc29uKCk7XHJcblxyXG4gIC8vIGNvbnN0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKHNlcnZpY2VVcmwsICcxPTEnLCBjb25maWcpO1xyXG5cclxuICAvLyBjb25zdCBkYXRhRmllbGRzID0gZmVhdHVyZXNbMF0uIGFzIElGaWVsZFtdO1xyXG5cclxuICAvLyBkZWJ1Z2dlcjtcclxuICAvLyBpZiAoZmllbGRzLmxlbmd0aCA+IGRhdGFGaWVsZHMubGVuZ3RoKSB7XHJcbiAgLy8gICB0aHJvdyBuZXcgRXJyb3IoJ051bWJlciBvZiBmaWVsZHMgZG8gbm90IG1hdGNoIGZvciAnICsgc2VydmljZVVybCk7XHJcbiAgLy8gfVxyXG5cclxuICAvLyBjb25zdCBhbGxGaWVsZHNHb29kID0gZmllbGRzLmV2ZXJ5KGYgPT4ge1xyXG4gIC8vICAgY29uc3QgZm91bmQgPSBkYXRhRmllbGRzLmZpbmQoZjEgPT4gZjEubmFtZSA9PT0gZi5uYW1lICYmIGYxLnR5cGUudG9TdHJpbmcoKSA9PT0gZi50eXBlLnRvU3RyaW5nKCkgJiYgZjEuZG9tYWluID09IGYuZG9tYWluKTtcclxuICAvLyAgIHJldHVybiBmb3VuZDtcclxuICAvLyB9KTtcclxuXHJcbiAgLy8gaWYgKCFhbGxGaWVsZHNHb29kKSB7XHJcbiAgLy8gICB0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgZmllbGRzIGluIHRoZSBmZWF0dXJlIHNlcnZpY2UgJyArIHNlcnZpY2VVcmwpXHJcbiAgLy8gfVxyXG4gIHJldHVybiB0cnVlO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRJbmRpY2F0b3JGZWF0dXJlcyhxdWVyeTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVbXT57XHJcbiAgY29uc29sZS5sb2coJ2dldCBJbmRpY2F0b3JzIGNhbGxlZCcpO1xyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvcnMsIHF1ZXJ5LCBjb25maWcpO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRXZWlnaHRzRmVhdHVyZXMocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlW10+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgV2VpZ2h0cyBjYWxsZWQnKTtcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy53ZWlnaHRzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0TGlmZWxpbmVGZWF0dXJlcyhxdWVyeTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVbXT57XHJcbiAgY29uc29sZS5sb2coJ2dldCBMaWZlbGluZSBjYWxsZWQnKTtcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZXMsIHF1ZXJ5LCBjb25maWcpO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRDb21wb25lbnRGZWF0dXJlcyhxdWVyeTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVbXT57XHJcbiAgY29uc29sZS5sb2coJ2dldCBDb21wb25lbnRzIGNhbGxlZCcpO1xyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmNvbXBvbmVudHMsIHF1ZXJ5LCBjb25maWcpO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRUZW1wbGF0ZUZlYXR1cmVTZXQocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlU2V0PntcclxuICBjb25zb2xlLmxvZygnZ2V0IFRlbXBsYXRlIGNhbGxlZCcpO1xyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZVNldChjb25maWcudGVtcGxhdGVzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldFRlbXBsYXRlcyhjb25maWc6IEFwcFdpZGdldENvbmZpZywgdGVtcGxhdGVJZD86IHN0cmluZywgcXVlcnlTdHJpbmc/OnN0cmluZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPENMU1NUZW1wbGF0ZVtdPj4ge1xyXG5cclxuICBjb25zdCB0ZW1wbGF0ZVVybCA9IGNvbmZpZy50ZW1wbGF0ZXM7XHJcbiAgY29uc3QgbGlmZWxpbmVVcmwgPSBjb25maWcubGlmZWxpbmVzO1xyXG4gIGNvbnN0IGNvbXBvbmVudFVybCA9IGNvbmZpZy5jb21wb25lbnRzO1xyXG5cclxuICB0cnl7XHJcbiAgICBjaGVja1BhcmFtKHRlbXBsYXRlVXJsLCBURU1QTEFURV9VUkxfRVJST1IpO1xyXG4gICAgY2hlY2tQYXJhbShsaWZlbGluZVVybCwgTElGRUxJTkVfVVJMX0VSUk9SKTtcclxuICAgIGNoZWNrUGFyYW0oY29tcG9uZW50VXJsLCBDT01QT05FTlRfVVJMX0VSUk9SKTtcclxuXHJcbiAgICBjb25zdCB0ZW1wUXVlcnkgPSB0ZW1wbGF0ZUlkID8gYEdsb2JhbElEPScke3RlbXBsYXRlSWR9YCA6KHF1ZXJ5U3RyaW5nID8gcXVlcnlTdHJpbmcgOiAnMT0xJyApO1xyXG5cclxuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgUHJvbWlzZS5hbGwoW1xyXG4gICAgICBnZXRUZW1wbGF0ZUZlYXR1cmVTZXQodGVtcFF1ZXJ5LCBjb25maWcpLFxyXG4gICAgICBnZXRMaWZlbGluZUZlYXR1cmVzKCcxPTEnLCBjb25maWcpLCBcclxuICAgICAgZ2V0Q29tcG9uZW50RmVhdHVyZXMoJzE9MScsIGNvbmZpZyldKTtcclxuICAgIFxyXG4gICAgY29uc3QgdGVtcGxhdGVGZWF0dXJlU2V0ID0gcmVzcG9uc2VbMF07XHJcbiAgICBjb25zdCBsaWZlbGluZUZlYXR1cmVzID0gcmVzcG9uc2VbMV07XHJcbiAgICBjb25zdCBjb21wb25lbnRGZWF0dXJlcyA9IHJlc3BvbnNlWzJdO1xyXG5cclxuICAgIGNvbnN0IGluZGljYXRvckZlYXR1cmVzID0gYXdhaXQgZ2V0SW5kaWNhdG9yRmVhdHVyZXMoJzE9MScsIGNvbmZpZyk7XHJcbiAgICBjb25zdCB3ZWlnaHRGZWF0dXJlcyA9IGF3YWl0IGdldFdlaWdodHNGZWF0dXJlcygnMT0xJywgY29uZmlnKTtcclxuXHJcbiAgICBjb25zdCB0ZW1wbGF0ZXMgPSBhd2FpdCBQcm9taXNlLmFsbCh0ZW1wbGF0ZUZlYXR1cmVTZXQuZmVhdHVyZXMubWFwKGFzeW5jICh0ZW1wbGF0ZUZlYXR1cmU6IElGZWF0dXJlKSA9PiB7XHJcbiAgICAgIGNvbnN0IHRlbXBsYXRlSW5kaWNhdG9yRmVhdHVyZXMgPSBpbmRpY2F0b3JGZWF0dXJlcy5maWx0ZXIoaSA9PmkuYXR0cmlidXRlcy5UZW1wbGF0ZUlEID09IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEKSAgICAgIFxyXG4gICAgICByZXR1cm4gYXdhaXQgZ2V0VGVtcGxhdGUodGVtcGxhdGVGZWF0dXJlLCBsaWZlbGluZUZlYXR1cmVzLCBjb21wb25lbnRGZWF0dXJlcywgXHJcbiAgICAgICAgdGVtcGxhdGVJbmRpY2F0b3JGZWF0dXJlcywgd2VpZ2h0RmVhdHVyZXMsIFxyXG4gICAgICAgIHRlbXBsYXRlRmVhdHVyZVNldC5maWVsZHMuZmluZChmID0+IGYubmFtZSA9PT0gJ1N0YXR1cycpLmRvbWFpbi5jb2RlZFZhbHVlcylcclxuICAgIH0pKTtcclxuXHJcbiAgICBpZih0ZW1wbGF0ZXMuZmlsdGVyKHQgPT4gdC5pc1NlbGVjdGVkKS5sZW5ndGggPiAxIHx8IHRlbXBsYXRlcy5maWx0ZXIodCA9PiB0LmlzU2VsZWN0ZWQpLmxlbmd0aCA9PSAwKXtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiB0ZW1wbGF0ZXMubWFwKHQgPT4ge1xyXG4gICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgLi4udCxcclxuICAgICAgICAgICAgaXNTZWxlY3RlZDogdC5uYW1lID09PSBCQVNFTElORV9URU1QTEFURV9OQU1FXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgfSlcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGlmKHRlbXBsYXRlcy5sZW5ndGggPT09IDEpe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IHRlbXBsYXRlcy5tYXAodCA9PiB7XHJcbiAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAuLi50LFxyXG4gICAgICAgICAgICBpc1NlbGVjdGVkOiB0cnVlXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgfSlcclxuICAgICAgfVxyXG4gICAgfVxyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogdGVtcGxhdGVzXHJcbiAgICB9XHJcbiAgfVxyXG4gIGNhdGNoKGUpeyBcclxuICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAnZ2V0VGVtcGxhdGVzJyk7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBlcnJvcnM6ICdUZW1wbGF0ZXMgcmVxdWVzdCBmYWlsZWQuJ1xyXG4gICAgfVxyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIHVzZUZldGNoRGF0YTxUPih1cmw6IHN0cmluZywgY2FsbGJhY2tBZGFwdGVyPzogRnVuY3Rpb24pOiBbVCwgRnVuY3Rpb24sIGJvb2xlYW4sIHN0cmluZ10ge1xyXG4gIGNvbnN0IFtkYXRhLCBzZXREYXRhXSA9IFJlYWN0LnVzZVN0YXRlKG51bGwpO1xyXG4gIGNvbnN0IFtsb2FkaW5nLCBzZXRMb2FkaW5nXSA9IFJlYWN0LnVzZVN0YXRlKHRydWUpO1xyXG4gIGNvbnN0IFtlcnJvciwgc2V0RXJyb3JdID0gUmVhY3QudXNlU3RhdGUoJycpO1xyXG5cclxuICBSZWFjdC51c2VFZmZlY3QoKCkgPT4ge1xyXG4gICAgY29uc3QgY29udHJvbGxlciA9IG5ldyBBYm9ydENvbnRyb2xsZXIoKTtcclxuICAgIHJlcXVlc3REYXRhKHVybCwgY29udHJvbGxlcilcclxuICAgICAgLnRoZW4oKGRhdGEpID0+IHtcclxuICAgICAgICBpZiAoY2FsbGJhY2tBZGFwdGVyKSB7XHJcbiAgICAgICAgICBzZXREYXRhKGNhbGxiYWNrQWRhcHRlcihkYXRhKSk7XHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgIHNldERhdGEoZGF0YSk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xyXG4gICAgICB9KVxyXG4gICAgICAuY2F0Y2goKGVycikgPT4ge1xyXG4gICAgICAgIGNvbnNvbGUubG9nKGVycik7XHJcbiAgICAgICAgc2V0RXJyb3IoZXJyKTtcclxuICAgICAgfSlcclxuICAgIHJldHVybiAoKSA9PiBjb250cm9sbGVyLmFib3J0KCk7XHJcbiAgfSwgW3VybF0pXHJcblxyXG4gIHJldHVybiBbZGF0YSwgc2V0RGF0YSwgbG9hZGluZywgZXJyb3JdXHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBkaXNwYXRjaEFjdGlvbih0eXBlOiBhbnksIHZhbDogYW55KSB7XHJcbiAgZ2V0QXBwU3RvcmUoKS5kaXNwYXRjaCh7XHJcbiAgICB0eXBlLFxyXG4gICAgdmFsXHJcbiAgfSk7XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRJbmNpZGVudHMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPEluY2lkZW50W10+IHtcclxuICAgXHJcbiAgY29uc29sZS5sb2coJ2dldCBpbmNpZGVudHMgY2FsbGVkLicpXHJcbiAgY2hlY2tQYXJhbShjb25maWcuaW5jaWRlbnRzLCBJTkNJREVOVF9VUkxfRVJST1IpO1xyXG5cclxuICBjb25zdCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuaW5jaWRlbnRzLCAnMT0xJywgY29uZmlnKTtcclxuXHJcbiAgY29uc3QgcXVlcnkgPSBgR2xvYmFsSUQgSU4gKCR7ZmVhdHVyZXMubWFwKGYgPT4gZi5hdHRyaWJ1dGVzLkhhemFyZElEKS5tYXAoaWQgPT4gYCcke2lkfSdgKS5qb2luKCcsJyl9KWA7XHJcbiAgXHJcbiAgY29uc3QgaGF6YXJkRmVhdHVyZXNldCA9IGF3YWl0IGdldEhhemFyZEZlYXR1cmVzKGNvbmZpZywgcXVlcnksICdnZXRJbmNpZGVudHMnKTtcclxuXHJcbiAgcmV0dXJuIGZlYXR1cmVzLm1hcCgoZjogSUZlYXR1cmUpID0+e1xyXG4gICAgICBjb25zdCBoZiA9IGhhemFyZEZlYXR1cmVzZXQuZmVhdHVyZXMuZmluZChoID0+IGguYXR0cmlidXRlcy5HbG9iYWxJRCA9PSBmLmF0dHJpYnV0ZXMuSGF6YXJkSUQpXHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgb2JqZWN0SWQ6IGYuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgICBpZDogZi5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICAgIG5hbWU6IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgIGhhemFyZDogaGYgPyB7XHJcbiAgICAgICAgICBvYmplY3RJZDogaGYuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgICAgIGlkOiBoZi5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICAgICAgbmFtZTogaGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgICAgdGl0bGU6IGhmLmF0dHJpYnV0ZXMuRGlzcGxheVRpdGxlIHx8IGhmLmF0dHJpYnV0ZXMuRGlzcGxheU5hbWUgfHwgaGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgICAgdHlwZTogaGYuYXR0cmlidXRlcy5UeXBlLFxyXG4gICAgICAgICAgZGVzY3JpcHRpb246IGhmLmF0dHJpYnV0ZXMuRGVzY3JpcHRpb24sXHJcbiAgICAgICAgICBkb21haW5zOiBoYXphcmRGZWF0dXJlc2V0LmZpZWxkcy5maW5kKGYgPT4gZi5uYW1lID09PSAnVHlwZScpLmRvbWFpbi5jb2RlZFZhbHVlc1xyXG4gICAgICAgIH0gOiBudWxsLFxyXG4gICAgICAgIGRlc2NyaXB0aW9uOiBmLmF0dHJpYnV0ZXMuRGVzY3JpcHRpb24sXHJcbiAgICAgICAgc3RhcnREYXRlOiBOdW1iZXIoZi5hdHRyaWJ1dGVzLlN0YXJ0RGF0ZSksXHJcbiAgICAgICAgZW5kRGF0ZTogTnVtYmVyKGYuYXR0cmlidXRlcy5FbmREYXRlKVxyXG4gICAgICB9IGFzIEluY2lkZW50O1xyXG4gIH0pO1xyXG4gIHJldHVybiBbXTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0SGF6YXJkRmVhdHVyZXMgKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBxdWVyeTogc3RyaW5nLCBjYWxsZXI6IHN0cmluZyk6IFByb21pc2U8SUZlYXR1cmVTZXQ+IHtcclxuICBjb25zb2xlLmxvZygnZ2V0IEhhemFyZHMgY2FsbGVkIGJ5ICcrY2FsbGVyKVxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmhhemFyZHMsIEhBWkFSRF9VUkxfRVJST1IpOyAgXHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlU2V0KGNvbmZpZy5oYXphcmRzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldEhhemFyZHMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHF1ZXJ5U3RyaW5nOiBzdHJpbmcsIGNhbGxlcjogc3RyaW5nKTogUHJvbWlzZTxIYXphcmRbXT4ge1xyXG4gIFxyXG4gIGNvbnN0IGZlYXR1cmVTZXQgPSBhd2FpdCBnZXRIYXphcmRGZWF0dXJlcyhjb25maWcsIHF1ZXJ5U3RyaW5nLCBjYWxsZXIpO1xyXG4gIGlmKCFmZWF0dXJlU2V0IHx8IGZlYXR1cmVTZXQuZmVhdHVyZXMubGVuZ3RoID09IDApe1xyXG4gICAgcmV0dXJuIFtdO1xyXG4gIH1cclxuICByZXR1cm4gZmVhdHVyZVNldC5mZWF0dXJlcy5tYXAoKGY6IElGZWF0dXJlKSA9PiB7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBvYmplY3RJZDogZi5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICBpZDogZi5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICBuYW1lOiBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgdGl0bGU6IGYuYXR0cmlidXRlcy5EaXNwbGF5VGl0bGUgfHwgZi5hdHRyaWJ1dGVzLkRpc3BsYXlOYW1lIHx8IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICB0eXBlOiBmLmF0dHJpYnV0ZXMuVHlwZSxcclxuICAgICAgZGVzY3JpcHRpb246IGYuYXR0cmlidXRlcy5EZXNjcmlwdGlvbixcclxuICAgICAgZG9tYWluczogZmVhdHVyZVNldC5maWVsZHMuZmluZChmID0+IGYubmFtZSA9PT0gJ1R5cGUnKS5kb21haW4uY29kZWRWYWx1ZXNcclxuICAgIH0gYXMgSGF6YXJkXHJcbiAgfSlcclxuICByZXR1cm4gW107XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRPcmdhbml6YXRpb25zKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBxdWVyeVN0cmluZzogc3RyaW5nKTogUHJvbWlzZTxPcmdhbml6YXRpb25bXT4ge1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgT3JnYW5pemF0aW9ucyBjYWxsZWQnKVxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLm9yZ2FuaXphdGlvbnMsIE9SR0FOSVpBVElPTl9VUkxfRVJST1IpO1xyXG5cclxuICBjb25zdCBmZWF0dXJlU2V0ID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVTZXQoY29uZmlnLm9yZ2FuaXphdGlvbnMsIHF1ZXJ5U3RyaW5nLCBjb25maWcpO1xyXG4gXHJcbiAgaWYoZmVhdHVyZVNldCAmJiBmZWF0dXJlU2V0LmZlYXR1cmVzICYmIGZlYXR1cmVTZXQuZmVhdHVyZXMubGVuZ3RoID4gMCl7XHJcbiAgICByZXR1cm4gZmVhdHVyZVNldC5mZWF0dXJlcy5tYXAoKGY6IElGZWF0dXJlKSA9PiB7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgb2JqZWN0SWQ6IGYuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgICBpZDogZi5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICAgIG5hbWU6IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgIHRpdGxlOiBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICB0eXBlOiBmLmF0dHJpYnV0ZXMuVHlwZSxcclxuICAgICAgICBwYXJlbnRJZDogZi5hdHRyaWJ1dGVzLlBhcmVudElELFxyXG4gICAgICAgIGRlc2NyaXB0aW9uOiBmLmF0dHJpYnV0ZXMuRGVzY3JpcHRpb24sXHJcbiAgICAgICAgZG9tYWluczogZmVhdHVyZVNldC5maWVsZHMuZmluZChmID0+IGYubmFtZSA9PT0gJ1R5cGUnKS5kb21haW4uY29kZWRWYWx1ZXNcclxuICAgICAgfSBhcyBPcmdhbml6YXRpb25cclxuICAgIH0pXHJcbiAgfVxyXG4gIHJldHVybiBbXTtcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNyZWF0ZU5ld1RlbXBsYXRlKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCB0ZW1wbGF0ZTogQ0xTU1RlbXBsYXRlLCBcclxuIHVzZXJOYW1lOiBzdHJpbmcsIG9yZ2FuaXphdGlvbjogT3JnYW5pemF0aW9uLCBoYXphcmQ6IEhhemFyZCk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PiB7XHJcbiBcclxuICBjaGVja1BhcmFtKGNvbmZpZy50ZW1wbGF0ZXMsIFRFTVBMQVRFX1VSTF9FUlJPUik7XHJcbiAgY2hlY2tQYXJhbSh0ZW1wbGF0ZSwgJ1RlbXBsYXRlIGRhdGEgbm90IHByb3ZpZGVkJyk7XHJcblxyXG4gIGNvbnN0IGNyZWF0ZURhdGUgPSBuZXcgRGF0ZSgpLmdldFRpbWUoKTtcclxuICBjb25zdCB0ZW1wbGF0ZU5hbWUgPSB0ZW1wbGF0ZS5uYW1lWzBdLnRvTG9jYWxlVXBwZXJDYXNlKCkrdGVtcGxhdGUubmFtZS5zdWJzdHJpbmcoMSk7XHJcbiBcclxuICBsZXQgZmVhdHVyZSA9IHtcclxuICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgT3JnYW5pemF0aW9uSUQ6IG9yZ2FuaXphdGlvbiA/IG9yZ2FuaXphdGlvbi5pZCA6ICBudWxsLFxyXG4gICAgICBPcmdhbml6YXRpb25OYW1lOiBvcmdhbml6YXRpb24gPyBvcmdhbml6YXRpb24ubmFtZTogbnVsbCxcclxuICAgICAgT3JnYW5pemF0aW9uVHlwZTogb3JnYW5pemF0aW9uID8gKG9yZ2FuaXphdGlvbi50eXBlLmNvZGUgPyBvcmdhbml6YXRpb24udHlwZS5jb2RlOiBvcmdhbml6YXRpb24udHlwZSApOiBudWxsLFxyXG4gICAgICBIYXphcmRJRDogIGhhemFyZCA/IGhhemFyZC5pZCA6IG51bGwsXHJcbiAgICAgIEhhemFyZE5hbWU6ICBoYXphcmQgPyBoYXphcmQubmFtZSA6IG51bGwsXHJcbiAgICAgIEhhemFyZFR5cGU6ICBoYXphcmQgPyAoaGF6YXJkLnR5cGUuY29kZSA/IGhhemFyZC50eXBlLmNvZGUgOiBoYXphcmQudHlwZSkgOiBudWxsLFxyXG4gICAgICBOYW1lOiB0ZW1wbGF0ZU5hbWUgLFxyXG4gICAgICBDcmVhdG9yOiB1c2VyTmFtZSxcclxuICAgICAgQ3JlYXRlZERhdGU6IGNyZWF0ZURhdGUsICAgICAgXHJcbiAgICAgIFN0YXR1czogMSxcclxuICAgICAgSXNTZWxlY3RlZDogMCxcclxuICAgICAgRWRpdG9yOiB1c2VyTmFtZSxcclxuICAgICAgRWRpdGVkRGF0ZTogY3JlYXRlRGF0ZSAgICAgXHJcbiAgICB9XHJcbiAgfVxyXG4gIGxldCByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLnRlbXBsYXRlcywgW2ZlYXR1cmVdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgXHJcbiAgICBjb25zdCB0ZW1wbGF0ZUlkID0gcmVzcG9uc2UuYWRkUmVzdWx0c1swXS5nbG9iYWxJZDtcclxuICAgIC8vY3JlYXRlIG5ldyBpbmRpY2F0b3JzICAgXHJcbiAgICBjb25zdCBpbmRpY2F0b3JzID0gZ2V0VGVtcGxhdGVJbmRpY2F0b3JzKHRlbXBsYXRlKTtcclxuICAgIGNvbnN0IGluZGljYXRvckZlYXR1cmVzID0gaW5kaWNhdG9ycy5tYXAoaW5kaWNhdG9yID0+IHtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICBUZW1wbGF0ZUlEOiB0ZW1wbGF0ZUlkLCAgXHJcbiAgICAgICAgICBDb21wb25lbnRJRDogaW5kaWNhdG9yLmNvbXBvbmVudElkLFxyXG4gICAgICAgICAgQ29tcG9uZW50TmFtZTogaW5kaWNhdG9yLmNvbXBvbmVudE5hbWUsICBcclxuICAgICAgICAgIE5hbWU6IGluZGljYXRvci5uYW1lLCAgIFxyXG4gICAgICAgICAgVGVtcGxhdGVOYW1lOiB0ZW1wbGF0ZU5hbWUsIFxyXG4gICAgICAgICAgTGlmZWxpbmVOYW1lOiBpbmRpY2F0b3IubGlmZWxpbmVOYW1lICAgICAgXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcbiAgICB9KVxyXG4gICAgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLCBpbmRpY2F0b3JGZWF0dXJlcywgY29uZmlnKTtcclxuICAgIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG5cclxuICAgICAgY29uc3QgZ2xvYmFsSWRzID0gYCgke3Jlc3BvbnNlLmFkZFJlc3VsdHMubWFwKHIgPT4gYCcke3IuZ2xvYmFsSWR9J2ApLmpvaW4oJywnKX0pYDtcclxuICAgICAgY29uc3QgcXVlcnkgPSAnR2xvYmFsSUQgSU4gJytnbG9iYWxJZHM7ICAgICBcclxuICAgICAgY29uc3QgYWRkZWRJbmRpY2F0b3JGZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9ycyxxdWVyeSAsIGNvbmZpZyk7XHJcblxyXG4gICAgICAgbGV0IHdlaWdodHNGZWF0dXJlcyA9IFtdO1xyXG4gICAgICAgZm9yKGxldCBmZWF0dXJlIG9mIGFkZGVkSW5kaWNhdG9yRmVhdHVyZXMpeyAgIFxyXG4gICAgICAgICBjb25zdCBpbmNvbWluZ0luZGljYXRvciA9IGluZGljYXRvcnMuZmluZChpID0+IGkubmFtZSA9PT0gZmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUpO1xyXG4gICAgICAgICBpZihpbmNvbWluZ0luZGljYXRvcil7XHJcbiAgICAgICAgICBjb25zdCB3ZWlnaHRGZWF0dXJlcyA9IGluY29taW5nSW5kaWNhdG9yLndlaWdodHMubWFwKHcgPT4geyAgICAgICAgXHJcbiAgICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgICAgICAgSW5kaWNhdG9ySUQ6IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCwgIFxyXG4gICAgICAgICAgICAgICAgTmFtZTogdy5uYW1lICxcclxuICAgICAgICAgICAgICAgIFdlaWdodDogdy53ZWlnaHQsIFxyXG4gICAgICAgICAgICAgICAgU2NhbGVGYWN0b3I6IDAsICBcclxuICAgICAgICAgICAgICAgIEFkanVzdGVkV2VpZ2h0IDogMCxcclxuICAgICAgICAgICAgICAgIE1heEFkanVzdGVkV2VpZ2h0OjBcclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgIH0pO1xyXG4gICAgICAgICAgd2VpZ2h0c0ZlYXR1cmVzID0gd2VpZ2h0c0ZlYXR1cmVzLmNvbmNhdCh3ZWlnaHRGZWF0dXJlcylcclxuICAgICAgICAgfSAgICAgICAgICAgIFxyXG4gICAgICAgfVxyXG5cclxuICAgICAgIHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcud2VpZ2h0cywgd2VpZ2h0c0ZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgICAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGRhdGE6IHRydWVcclxuICAgICAgICB9XHJcbiAgICAgICB9XHJcbiAgICB9XHJcbiAgICAvLyBjb25zdCBwcm9taXNlcyA9IGluZGljYXRvcnMubWFwKGluZGljYXRvciA9PiBjcmVhdGVOZXdJbmRpY2F0b3IoaW5kaWNhdG9yLCBjb25maWcsIHRlbXBsYXRlSWQsIHRlbXBsYXRlTmFtZSkpO1xyXG5cclxuICAgIC8vIGNvbnN0IHByb21pc2VSZXNwb25zZSA9IGF3YWl0IFByb21pc2UuYWxsKHByb21pc2VzKTtcclxuICAgIC8vIGlmKHByb21pc2VSZXNwb25zZS5ldmVyeShwID0+IHAuZGF0YSkpe1xyXG4gICAgLy8gICByZXR1cm4ge1xyXG4gICAgLy8gICAgIGRhdGE6IHRydWVcclxuICAgIC8vICAgfVxyXG4gICAgLy8gfVxyXG4gIH0gXHJcblxyXG4gIGxvZyhKU09OLnN0cmluZ2lmeShyZXNwb25zZSksIExvZ1R5cGUuRVJST1IsICdjcmVhdGVOZXdUZW1wbGF0ZScpXHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIGNyZWF0aW5nIHRoZSBuZXcgdGVtcGxhdGUnXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdXBkYXRlVGVtcGxhdGVPcmdhbml6YXRpb25BbmRIYXphcmQoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIFxyXG4gIHRlbXBsYXRlOiBDTFNTVGVtcGxhdGUsIHVzZXJOYW1lOiBzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj4ge1xyXG5cclxuICBjaGVja1BhcmFtKHRlbXBsYXRlLCAnVGVtcGxhdGUgbm90IHByb3ZpZGVkJyk7XHJcbiAgY2hlY2tQYXJhbShjb25maWcudGVtcGxhdGVzLCBURU1QTEFURV9VUkxfRVJST1IpOyBcclxuXHJcbiAgY29uc3QgYXR0cmlidXRlcyA9IHtcclxuICAgIE9CSkVDVElEOiB0ZW1wbGF0ZS5vYmplY3RJZCxcclxuICAgIE9yZ2FuaXphdGlvbklEOiB0ZW1wbGF0ZS5vcmdhbml6YXRpb25JZCxcclxuICAgIEhhemFyZElEOiB0ZW1wbGF0ZS5oYXphcmRJZCxcclxuICAgIE9yZ2FuaXphdGlvbk5hbWU6IHRlbXBsYXRlLm9yZ2FuaXphdGlvbk5hbWUsXHJcbiAgICBPcmdhbml6YXRpb25UeXBlOiB0ZW1wbGF0ZS5vcmdhbml6YXRpb25UeXBlLFxyXG4gICAgSGF6YXJkTmFtZTogdGVtcGxhdGUuaGF6YXJkTmFtZSxcclxuICAgIEhhemFyZFR5cGU6IHRlbXBsYXRlLmhhemFyZFR5cGUsXHJcbiAgICBOYW1lOiB0ZW1wbGF0ZS5uYW1lLFxyXG4gICAgRWRpdG9yOiB1c2VyTmFtZSxcclxuICAgIEVkaXRlZERhdGU6IG5ldyBEYXRlKCkuZ2V0VGltZSgpLFxyXG4gICAgU3RhdHVzOiB0ZW1wbGF0ZS5zdGF0dXMuY29kZSxcclxuICAgIElzU2VsZWN0ZWQ6IHRlbXBsYXRlLmlzU2VsZWN0ZWQgPyAxOiAwXHJcbiAgfSBcclxuICBjb25zdCByZXNwb25zZSA9ICBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmUoY29uZmlnLnRlbXBsYXRlcywgYXR0cmlidXRlcywgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHRydWVcclxuICAgIH1cclxuICB9XHJcbiAgbG9nKEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKSwgTG9nVHlwZS5FUlJPUiwgJ3VwZGF0ZVRlbXBsYXRlT3JnYW5pemF0aW9uQW5kSGF6YXJkJylcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgdXBkYXRpbmcgdGVtcGxhdGUuJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHNlbGVjdFRlbXBsYXRlKG9iamVjdElkOiBudW1iZXIsIG9iamVjdElkczogbnVtYmVyW10sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8U3RyaW5nPj4ge1xyXG4gIFxyXG4gICAgY29uc29sZS5sb2coJ3NlbGVjdCBUZW1wbGF0ZSBjYWxsZWQnKVxyXG4gICAgdHJ5e1xyXG4gICAgICBjaGVja1BhcmFtKGNvbmZpZy50ZW1wbGF0ZXMsIFRFTVBMQVRFX1VSTF9FUlJPUik7XHJcblxyXG4gICAgICAvL2xldCBmZWF0dXJlcyA9IGF3YWl0IGdldFRlbXBsYXRlRmVhdHVyZXMoJzE9MScsIGNvbmZpZykvLyBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLnRlbXBsYXRlcywgJzE9MScsIGNvbmZpZylcclxuICAgIFxyXG4gICAgICBjb25zdCBmZWF0dXJlcyA9ICBvYmplY3RJZHMubWFwKG9pZCA9PiB7XHJcbiAgICAgICAgcmV0dXJuIHsgICAgICAgICAgXHJcbiAgICAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICAgIE9CSkVDVElEOiBvaWQsXHJcbiAgICAgICAgICAgIElzU2VsZWN0ZWQ6IG9pZCA9PT0gb2JqZWN0SWQgPyAxIDogMFxyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgICAgfSlcclxuICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmVzKGNvbmZpZy50ZW1wbGF0ZXMsIGZlYXR1cmVzLCBjb25maWcpXHJcbiAgICAgIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG4gICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgZGF0YTogcmVzcG9uc2UudXBkYXRlUmVzdWx0c1swXS5nbG9iYWxJZFxyXG4gICAgICAgICB9IGFzIENsc3NSZXNwb25zZTxTdHJpbmc+O1xyXG4gICAgICB9XHJcbiAgICB9Y2F0Y2goZSkge1xyXG4gICAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ3NlbGVjdFRlbXBsYXRlJyk7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZXJyb3JzOiBlXHJcbiAgICAgIH1cclxuICAgIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGxvYWRTY2FsZUZhY3RvcnMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxTY2FsZUZhY3RvcltdPj57XHJcblxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmNvbnN0YW50cywgJ1JhdGluZyBTY2FsZXMgdXJsIG5vdCBwcm92aWRlZCcpO1xyXG5cclxuICB0cnl7XHJcblxyXG4gICBjb25zdCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuY29uc3RhbnRzLCAnMT0xJywgY29uZmlnKTtcclxuICAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMCl7XHJcbiAgICAgY29uc3Qgc2NhbGVzID0gIGZlYXR1cmVzLm1hcChmID0+e1xyXG4gICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgbmFtZTogZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgIHZhbHVlOiBmLmF0dHJpYnV0ZXMuVmFsdWVcclxuICAgICAgIH0gYXMgU2NhbGVGYWN0b3I7ICAgICAgIFxyXG4gICAgIH0pXHJcblxyXG4gICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHNjYWxlc1xyXG4gICAgfSBhcyBDbHNzUmVzcG9uc2U8U2NhbGVGYWN0b3JbXT5cclxuICAgfVxyXG5cclxuICAgbG9nKCdFcnJvciBvY2N1cnJlZCB3aGlsZSByZXF1ZXN0aW5nIHJhdGluZyBzY2FsZXMnLCBMb2dUeXBlLkVSUk9SLCAnbG9hZFJhdGluZ1NjYWxlcycpXHJcbiAgIHJldHVybiB7XHJcbiAgICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgcmVxdWVzdGluZyByYXRpbmcgc2NhbGVzJ1xyXG4gICB9XHJcbiAgfSBjYXRjaChlKXtcclxuICAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ2xvYWRSYXRpbmdTY2FsZXMnKTsgICAgXHJcbiAgfSAgXHJcbiAgIFxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY3JlYXRlTmV3SW5kaWNhdG9yKGluZGljYXRvcjogSW5kaWNhdG9yVGVtcGxhdGUsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCB0ZW1wbGF0ZUlkOiBzdHJpbmcsIHRlbXBsYXRlTmFtZTogc3RyaW5nKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+IHtcclxuXHJcbiAgY2hlY2tQYXJhbShjb25maWcuaW5kaWNhdG9ycywgSU5ESUNBVE9SX1VSTF9FUlJPUik7XHJcblxyXG4gIGNvbnN0IGluZGljYXRvckZlYXR1cmUgPSB7XHJcbiAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgIFRlbXBsYXRlSUQ6IHRlbXBsYXRlSWQsICBcclxuICAgICAgQ29tcG9uZW50SUQ6IGluZGljYXRvci5jb21wb25lbnRJZCxcclxuICAgICAgQ29tcG9uZW50TmFtZTogaW5kaWNhdG9yLmNvbXBvbmVudE5hbWUsICBcclxuICAgICAgTmFtZTogaW5kaWNhdG9yLm5hbWUsICAgXHJcbiAgICAgIFRlbXBsYXRlTmFtZTogdGVtcGxhdGVOYW1lLCBcclxuICAgICAgTGlmZWxpbmVOYW1lOiBpbmRpY2F0b3IubGlmZWxpbmVOYW1lICAgICAgXHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBsZXQgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLCBbaW5kaWNhdG9yRmVhdHVyZV0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcblxyXG4gICAgY29uc3Qgd2VpZ2h0RmVhdHVyZXMgPSBpbmRpY2F0b3Iud2VpZ2h0cy5tYXAodyA9PiB7XHJcbiAgICAgICBcclxuICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgSW5kaWNhdG9ySUQ6IHJlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWQsICBcclxuICAgICAgICAgIE5hbWU6IHcubmFtZSAsXHJcbiAgICAgICAgICBXZWlnaHQ6IHcud2VpZ2h0LCBcclxuICAgICAgICAgIFNjYWxlRmFjdG9yOiAwLCAgXHJcbiAgICAgICAgICBBZGp1c3RlZFdlaWdodCA6IDAsXHJcbiAgICAgICAgICBNYXhBZGp1c3RlZFdlaWdodDowXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcbiAgICB9KTtcclxuXHJcbiAgICByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLndlaWdodHMsIHdlaWdodEZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcbiAgICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IHRydWVcclxuICAgICAgIH1cclxuICAgIH1cclxuICB9XHJcblxyXG4gIGxvZyhKU09OLnN0cmluZ2lmeShyZXNwb25zZSksIExvZ1R5cGUuRVJST1IsICdjcmVhdGVOZXdJbmRpY2F0b3InKTtcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgc2F2aW5nIHRoZSBpbmRpY2F0b3IuJ1xyXG4gIH1cclxuXHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB1cGRhdGVJbmRpY2F0b3JOYW1lKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBpbmRpY2F0b3JUZW1wOkluZGljYXRvclRlbXBsYXRlKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gICBcclxuICBjaGVja1BhcmFtKGNvbmZpZy5pbmRpY2F0b3JzLCBJTkRJQ0FUT1JfVVJMX0VSUk9SKTtcclxuXHJcbiAgY29uc3QgYXR0cmlidXRlcyA9IHtcclxuICAgIE9CSkVDVElEOiBpbmRpY2F0b3JUZW1wLm9iamVjdElkLFxyXG4gICAgTmFtZTogaW5kaWNhdG9yVGVtcC5uYW1lLFxyXG4gICAgRGlzcGxheVRpdGxlOiBpbmRpY2F0b3JUZW1wLm5hbWUsXHJcbiAgICBJc0FjdGl2ZTogMVxyXG4gIH1cclxuICBjb25zdCByZXNwb25zZSA9ICBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmUoY29uZmlnLmluZGljYXRvcnMsIGF0dHJpYnV0ZXMsIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgIH1cclxuICB9XHJcbiAgbG9nKEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKSwgTG9nVHlwZS5FUlJPUiwgJ3VwZGF0ZUluZGljYXRvck5hbWUnKVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSB1cGRhdGluZyBpbmRpY2F0b3InXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdXBkYXRlSW5kaWNhdG9yKGluZGljYXRvcjogSW5kaWNhdG9yVGVtcGxhdGUsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gICBcclxuICBjaGVja1BhcmFtKGNvbmZpZy5pbmRpY2F0b3JzLCBJTkNJREVOVF9VUkxfRVJST1IpO1xyXG5cclxuICBsZXQgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvcnMsIGBOYW1lPScke2luZGljYXRvci5uYW1lfScgQU5EIFRlbXBsYXRlTmFtZT0nJHtpbmRpY2F0b3IudGVtcGxhdGVOYW1lfSdgLCBjb25maWcpXHJcbiBcclxuICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAxKXtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGVycm9yczogJ0FuIGluZGljYXRvciB3aXRoIHRoZSBzYW1lIG5hbWUgYWxyZWFkeSBleGlzdHMnXHJcbiAgICB9XHJcbiAgfVxyXG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgdXBkYXRlSW5kaWNhdG9yTmFtZShjb25maWcsIGluZGljYXRvcik7XHJcblxyXG4gIGlmKHJlc3BvbnNlLmVycm9ycyl7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBlcnJvcnM6IHJlc3BvbnNlLmVycm9yc1xyXG4gICAgfVxyXG4gIH1cclxuIFxyXG4gICBmZWF0dXJlcyA9IGluZGljYXRvci53ZWlnaHRzLm1hcCh3ID0+IHtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgT0JKRUNUSUQ6IHcub2JqZWN0SWQsXHJcbiAgICAgICAgICBXZWlnaHQ6IE51bWJlcih3LndlaWdodCksIFxyXG4gICAgICAgICAgQWRqdXN0ZWRXZWlnaHQ6IE51bWJlcih3LndlaWdodCkgKiB3LnNjYWxlRmFjdG9yXHJcbiAgICAgICB9XHJcbiAgICAgfVxyXG4gICB9KTtcclxuXHJcbiAgIGNvbnN0IHVwZGF0ZVJlc3BvbnNlID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlcyhjb25maWcud2VpZ2h0cywgZmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgIGlmKHVwZGF0ZVJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgdXBkYXRlUmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHRydWVcclxuICAgICB9XHJcbiAgIH1cclxuXHJcbiAgIGxvZyhKU09OLnN0cmluZ2lmeSh1cGRhdGVSZXNwb25zZSksIExvZ1R5cGUuRVJST1IsICd1cGRhdGVJbmRpY2F0b3InKTtcclxuICAgcmV0dXJuIHtcclxuICAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSB1cGRhdGluZyBpbmRpY2F0b3IuJ1xyXG4gICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWxldGVJbmRpY2F0b3IoaW5kaWNhdG9yVGVtcGxhdGU6IEluZGljYXRvclRlbXBsYXRlLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PiB7XHJcblxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmluZGljYXRvcnMsIElORElDQVRPUl9VUkxfRVJST1IpO1xyXG4gIGNoZWNrUGFyYW0oY29uZmlnLndlaWdodHMsICdXZWlnaHRzIFVSTCBub3QgcHJvdmlkZWQnKTtcclxuICBcclxuICBsZXQgcmVzcCA9IGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvcnMsIFtpbmRpY2F0b3JUZW1wbGF0ZS5vYmplY3RJZF0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcC5kZWxldGVSZXN1bHRzICYmIHJlc3AuZGVsZXRlUmVzdWx0cy5ldmVyeShkID0+IGQuc3VjY2Vzcykpe1xyXG4gICAgIGNvbnN0IHdlaWdodHNPYmplY3RJZHMgPSBpbmRpY2F0b3JUZW1wbGF0ZS53ZWlnaHRzLm1hcCh3ID0+IHcub2JqZWN0SWQpO1xyXG4gICAgIHJlc3AgPSBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy53ZWlnaHRzLCB3ZWlnaHRzT2JqZWN0SWRzLCBjb25maWcpO1xyXG4gICAgIGlmKHJlc3AuZGVsZXRlUmVzdWx0cyAmJiByZXNwLmRlbGV0ZVJlc3VsdHMuZXZlcnkoZCA9PiBkLnN1Y2Nlc3MpKXtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgIH1cclxuICAgICB9XHJcbiAgfVxyXG5cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcCksIExvZ1R5cGUuRVJST1IsICdkZWxldGVJbmRpY2F0b3InKVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSBkZWxldGluZyB0aGUgaW5kaWNhdG9yJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGFyY2hpdmVUZW1wbGF0ZShvYmplY3RJZDogbnVtYmVyLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PiB7XHJcbiBcclxuICBjb25zdCByZXNwb25zZSAgPSBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmUoY29uZmlnLnRlbXBsYXRlcywge1xyXG4gICAgT0JKRUNUSUQ6IG9iamVjdElkLFxyXG4gICAgSXNTZWxlY3RlZDogMCxcclxuICAgIElzQWN0aXZlOiAwXHJcbiAgfSwgY29uZmlnKTtcclxuICBjb25zb2xlLmxvZyhyZXNwb25zZSk7XHJcbiAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KGUgPT4gZS5zdWNjZXNzKSl7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB0cnVlXHJcbiAgICB9XHJcbiAgfVxyXG4gIGxvZyhKU09OLnN0cmluZ2lmeShyZXNwb25zZSksIExvZ1R5cGUuRVJST1IsICdhcmNoaXZlVGVtcGxhdGUnKTtcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnVGhlIHRlbXBsYXRlIGNhbm5vdCBiZSBhcmNoaXZlZC4nXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc2F2ZU9yZ2FuaXphdGlvbihjb25maWc6IEFwcFdpZGdldENvbmZpZywgb3JnYW5pemF0aW9uOiBPcmdhbml6YXRpb24pOiBQcm9taXNlPENsc3NSZXNwb25zZTxPcmdhbml6YXRpb24+PiB7XHJcblxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLm9yZ2FuaXphdGlvbnMsIE9SR0FOSVpBVElPTl9VUkxfRVJST1IpO1xyXG4gIGNoZWNrUGFyYW0ob3JnYW5pemF0aW9uLCAnT3JnYW5pemF0aW9uIG9iamVjdCBub3QgcHJvdmlkZWQnKTtcclxuIFxyXG4gIGNvbnN0IGZlYXR1cmUgPSB7XHJcbiAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgIE5hbWU6IG9yZ2FuaXphdGlvbi5uYW1lLFxyXG4gICAgICBUeXBlOiBvcmdhbml6YXRpb24udHlwZT8uY29kZSxcclxuICAgICAgRGlzcGxheVRpdGxlOiBvcmdhbml6YXRpb24ubmFtZSxcclxuICAgICAgUGFyZW50SUQ6IG9yZ2FuaXphdGlvbj8ucGFyZW50SWRcclxuICAgIH1cclxuICB9XHJcbiAgY29uc3QgcmVzcG9uc2UgPSAgYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcub3JnYW5pemF0aW9ucywgW2ZlYXR1cmVdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2VzcykpeyBcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHtcclxuICAgICAgICAuLi5vcmdhbml6YXRpb25cclxuICAgICAgfSBhcyBPcmdhbml6YXRpb24gLy8gKGF3YWl0IGdldE9yZ2FuaXphdGlvbnMoY29uZmlnLCBgR2xvYmFsSUQ9JyR7cmVzcG9uc2UuYWRkUmVzdWx0c1swXS5nbG9iYWxJZH0nYCkpWzBdXHJcbiAgICB9XHJcbiAgfVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6IEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKVxyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHNhdmVIYXphcmQoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIGhhemFyZDogSGF6YXJkKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8SGF6YXJkPj4ge1xyXG4gIFxyXG4gIGNvbnN0IGZlYXR1cmUgPSB7XHJcbiAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgIE5hbWU6IGhhemFyZC5uYW1lLFxyXG4gICAgICBEaXNwbGF5VGl0bGU6IGhhemFyZC5uYW1lLFxyXG4gICAgICBUeXBlOiBoYXphcmQudHlwZS5jb2RlLFxyXG4gICAgICBEZXNjcmlwdGlvbjogaGF6YXJkLmRlc2NyaXB0aW9uXHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBjb25zdCByZXNwb25zZSA9ICBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5oYXphcmRzLCBbZmVhdHVyZV0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7ICAgXHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YToge1xyXG4gICAgICAgICAgLi4uaGF6YXJkLFxyXG4gICAgICAgICAgb2JqZWN0SWQ6IHJlc3BvbnNlLmFkZFJlc3VsdHNbMF0ub2JqZWN0SWQsXHJcbiAgICAgICAgICBpZDogcmVzcG9uc2UuYWRkUmVzdWx0c1swXS5nbG9iYWxJZFxyXG4gICAgICAgIH0gYXMgSGF6YXJkICBcclxuICAgICAgfVxyXG4gIH1cclxuXHJcbiAgbG9nKGBFcnJvciBvY2N1cnJlZCB3aGlsZSBzYXZpbmcgaGF6YXJkLiBSZXN0YXJ0aW5nIHRoZSBhcHBsaWNhdGlvbiBtYXkgZml4IHRoaXMgaXNzdWUuYCwgTG9nVHlwZS5FUlJPUiwgJ3NhdmVIYXphcmQnKVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSBzYXZpbmcgaGF6YXJkLiBSZXN0YXJ0aW5nIHRoZSBhcHBsaWNhdGlvbiBtYXkgZml4IHRoaXMgaXNzdWUuJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZUluY2lkZW50KGluY2lkZW50OiBJbmNpZGVudCwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmNpZGVudHMsIFtpbmNpZGVudC5vYmplY3RJZF0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UuZGVsZXRlUmVzdWx0cyAmJiByZXNwb25zZS5kZWxldGVSZXN1bHRzLmV2ZXJ5KGQgPT4gZC5zdWNjZXNzKSl7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgIGRhdGE6IHRydWVcclxuICAgICB9XHJcbiAgfVxyXG4gIHJldHVybiB7XHJcbiAgIGVycm9yczogSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVsZXRlSGF6YXJkKGhhemFyZDogSGF6YXJkLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5oYXphcmRzLCBbaGF6YXJkLm9iamVjdElkXSwgY29uZmlnKTtcclxuICAgaWYocmVzcG9uc2UuZGVsZXRlUmVzdWx0cyAmJiByZXNwb25zZS5kZWxldGVSZXN1bHRzLmV2ZXJ5KGQgPT4gZC5zdWNjZXNzKSl7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgICB9XHJcbiAgIH1cclxuICAgcmV0dXJuIHtcclxuICAgIGVycm9yczogSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpXHJcbiAgIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZU9yZ2FuaXphdGlvbihvcmdhbml6YXRpb246IE9yZ2FuaXphdGlvbiwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5vcmdhbml6YXRpb25zLCBbb3JnYW5pemF0aW9uLm9iamVjdElkXSwgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS5kZWxldGVSZXN1bHRzICYmIHJlc3BvbnNlLmRlbGV0ZVJlc3VsdHMuZXZlcnkoZCA9PiBkLnN1Y2Nlc3MpKXtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgIH1cclxuICB9XHJcbiAgcmV0dXJuIHtcclxuICAgZXJyb3JzOiBKU09OLnN0cmluZ2lmeShyZXNwb25zZSlcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjaGVja1BhcmFtKHBhcmFtOiBhbnksIGVycm9yOiBzdHJpbmcpIHtcclxuICBpZiAoIXBhcmFtIHx8IHBhcmFtID09IG51bGwgfHwgcGFyYW0gPT09ICcnIHx8IHBhcmFtID09IHVuZGVmaW5lZCkge1xyXG4gICAgdGhyb3cgbmV3IEVycm9yKGVycm9yKVxyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHRlbXBsQ2xlYW5VcChpbmRVcmw6IHN0cmluZywgYWxpZ1VybDogc3RyaW5nLCB0b2tlbjogc3RyaW5nKSB7XHJcblxyXG5cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHNhdmVOZXdBc3Nlc3NtZW50KG5ld0Fzc2Vzc21lbnQ6IEFzc2Vzc21lbnQsIHRlbXBsYXRlOiBDTFNTVGVtcGxhdGUsIFxyXG4gICAgICAgICAgICAgICAgICBjb25maWc6IEFwcFdpZGdldENvbmZpZywgcHJldkFzc2Vzc21lbnQ/OiBBc3Nlc3NtZW50KTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8c3RyaW5nPj57ICAgIFxyXG4gICAgICBcclxuICAgICAgY29uc3QgcmVzcCA9IGF3YWl0IHNhdmVBc3Nlc3NtZW50KG5ld0Fzc2Vzc21lbnQsIGNvbmZpZyk7XHJcbiAgICAgIGlmKHJlc3AuZXJyb3JzKXtcclxuICAgICAgICBsb2coJ1VuYWJsZSB0byBjcmVhdGUgdGhlIGFzc2Vzc21lbnQuJywgTG9nVHlwZS5FUlJPUiwgJ3NhdmVOZXdBc3Nlc3NtZW50Jyk7XHJcblxyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBlcnJvcnM6ICdVbmFibGUgdG8gY3JlYXRlIHRoZSBhc3Nlc3NtZW50LidcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuICAgICBcclxuICAgICAgdHJ5e1xyXG5cclxuICAgICAgICBjb25zdCBpbmRpY2F0b3JzID0gZ2V0VGVtcGxhdGVJbmRpY2F0b3JzKHRlbXBsYXRlKTtcclxuICAgICAgICBpZighaW5kaWNhdG9ycyB8fCBpbmRpY2F0b3JzLmxlbmd0aCA9PT0gMCl7XHJcbiAgICAgICAgICBsb2coJ1RlbXBsYXRlIGluZGljYXRvcnMgbm90IGZvdW5kJywgTG9nVHlwZS5FUlJPUiwgJ3NhdmVOZXdBc3Nlc3NtZW50Jyk7ICBcclxuICAgICAgICAgIHRocm93IG5ldyBFcnJvcignVGVtcGxhdGUgaW5kaWNhdG9ycyBub3QgZm91bmQuJylcclxuICAgICAgICB9ICAgICAgXHJcbiAgXHJcbiAgICAgICAgY29uc3QgbGlmZWxpbmVTdGF0dXNGZWF0dXJlcyA9IHRlbXBsYXRlLmxpZmVsaW5lVGVtcGxhdGVzLm1hcChsdCA9PiB7XHJcbiAgICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgYXR0cmlidXRlczogeyBcclxuICAgICAgICAgICAgICBBc3Nlc3NtZW50SUQgOiByZXNwLmRhdGEsXHJcbiAgICAgICAgICAgICAgU2NvcmU6IG51bGwsIFxyXG4gICAgICAgICAgICAgIENvbG9yOiBudWxsLCBcclxuICAgICAgICAgICAgICBMaWZlbGluZUlEOiBsdC5pZCwgXHJcbiAgICAgICAgICAgICAgSXNPdmVycmlkZW46IDAsIFxyXG4gICAgICAgICAgICAgIE92ZXJyaWRlblNjb3JlOiBudWxsLCBcclxuICAgICAgICAgICAgICBPdmVycmlkZW5CeTogbnVsbCwgXHJcbiAgICAgICAgICAgICAgT3ZlcnJpZGVDb21tZW50OiBudWxsLCBcclxuICAgICAgICAgICAgICBMaWZlbGluZU5hbWU6IGx0LnRpdGxlLCBcclxuICAgICAgICAgICAgICBUZW1wbGF0ZU5hbWU6IHRlbXBsYXRlLm5hbWVcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH0pXHJcbiAgICAgICAgbGV0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIGxpZmVsaW5lU3RhdHVzRmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICAgICAgaWYocmVzcG9uc2UgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcbiAgICAgICAgICAgY29uc3QgcXVlcnkgPSAnR2xvYmFsSUQgSU4gKCcrIHJlc3BvbnNlLmFkZFJlc3VsdHMubWFwKHIgPT4gYCcke3IuZ2xvYmFsSWR9J2ApLmpvaW4oJywnKStcIilcIjtcclxuICAgICAgICAgICBjb25zdCBsc0ZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZVN0YXR1cywgcXVlcnksIGNvbmZpZyk7XHJcbiAgICAgICAgICAgXHJcbiAgICAgICAgICAgY29uc3QgaW5kaWNhdG9yQXNzZXNzbWVudEZlYXR1cmVzID0gaW5kaWNhdG9ycy5tYXAoaSA9PiB7XHJcbiAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICBjb25zdCBsaWZlbGluZVN0YXR1c0ZlYXR1cmUgPSBsc0ZlYXR1cmVzLmZpbmQobHMgPT4gXHJcbiAgICAgICAgICAgICAgICBscy5hdHRyaWJ1dGVzLkxpZmVsaW5lTmFtZS5zcGxpdCgvWycgJyZfLF0rLykuam9pbignXycpICA9PT0gaS5saWZlbGluZU5hbWUpO1xyXG4gICAgICAgICAgICBpZighbGlmZWxpbmVTdGF0dXNGZWF0dXJlKXtcclxuICAgICAgICAgICAgICBjb25zb2xlLmxvZyhgJHtpLmxpZmVsaW5lTmFtZX0gbm90IGZvdW5kYCk7XHJcbiAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGAke2kubGlmZWxpbmVOYW1lfSBub3QgZm91bmRgKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgICAgICAgIExpZmVsaW5lU3RhdHVzSUQgOiBsaWZlbGluZVN0YXR1c0ZlYXR1cmU/IGxpZmVsaW5lU3RhdHVzRmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEIDogJycsXHJcbiAgICAgICAgICAgICAgICBJbmRpY2F0b3JJRDogaS5pZCwgIFxyXG4gICAgICAgICAgICAgICAgVGVtcGxhdGVOYW1lOiBpLnRlbXBsYXRlTmFtZSwgIFxyXG4gICAgICAgICAgICAgICAgTGlmZWxpbmVOYW1lOiBpLmxpZmVsaW5lTmFtZSwgIFxyXG4gICAgICAgICAgICAgICAgQ29tcG9uZW50TmFtZTogaS5jb21wb25lbnROYW1lLCAgXHJcbiAgICAgICAgICAgICAgICBJbmRpY2F0b3JOYW1lOiBpLm5hbWUsXHJcbiAgICAgICAgICAgICAgICBDb21tZW50czogXCJcIixcclxuICAgICAgICAgICAgICAgIFJhbms6IGkud2VpZ2h0cy5maW5kKHcgPT4gdy5uYW1lID09PSBSQU5LKT8ud2VpZ2h0LFxyXG4gICAgICAgICAgICAgICAgTGlmZVNhZmV0eTogaS53ZWlnaHRzLmZpbmQodyA9PiB3Lm5hbWUgPT09IExJRkVfU0FGRVRZKT8ud2VpZ2h0LFxyXG4gICAgICAgICAgICAgICAgUHJvcGVydHlQcm90ZWN0aW9uOiBpLndlaWdodHMuZmluZCh3ID0+IHcubmFtZSA9PT0gUFJPUEVSVFlfUFJPVEVDVElPTik/LndlaWdodCxcclxuICAgICAgICAgICAgICAgIEluY2lkZW50U3RhYmlsaXphdGlvbjogaS53ZWlnaHRzLmZpbmQodyA9PiB3Lm5hbWUgPT09IElOQ0lERU5UX1NUQUJJTElaQVRJT04pPy53ZWlnaHQsXHJcbiAgICAgICAgICAgICAgICBFbnZpcm9ubWVudFByZXNlcnZhdGlvbjogaS53ZWlnaHRzLmZpbmQodyA9PiB3Lm5hbWUgPT09IEVOVklST05NRU5UX1BSRVNFUlZBVElPTik/LndlaWdodCxcclxuICAgICAgICAgICAgICAgIFN0YXR1czogNCAvL3Vua25vd25cclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICB9KVxyXG4gIFxyXG4gICAgICAgICAgIHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9yQXNzZXNzbWVudHMsIGluZGljYXRvckFzc2Vzc21lbnRGZWF0dXJlcywgY29uZmlnKTtcclxuICAgICAgICAgICBpZihyZXNwb25zZSAmJiByZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuICAgICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgICBkYXRhOiByZXNwLmRhdGFcclxuICAgICAgICAgICAgfSBcclxuICAgICAgICAgICB9ZWxzZXtcclxuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdGYWlsZWQgdG8gYWRkIGluZGljYXRvciBhc3Nlc3NtZW50IGZlYXR1cmVzJyk7XHJcbiAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgICAgICBlbHNle1xyXG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdGYWlsZWQgdG8gYWRkIExpZmVsaW5lIFN0YXR1cyBGZWF0dXJlcycpO1xyXG4gICAgICAgIH0gXHJcblxyXG4gICAgICB9Y2F0Y2goZSl7XHJcbiAgICAgICAgYXdhaXQgY2xlYW5VcEFzc2Vzc21lbnRGYWlsZWREYXRhKHJlc3AuZGF0YSwgY29uZmlnKTtcclxuICAgICAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ3NhdmVOZXdBc3Nlc3NtZW50JylcclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgZXJyb3JzOidFcnJvciBvY2N1cnJlZCB3aGlsZSBjcmVhdGluZyBBc3Nlc3NtZW50LidcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuXHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGNsZWFuVXBBc3Nlc3NtZW50RmFpbGVkRGF0YShhc3Nlc3NtZW50R2xvYmFsSWQ6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpe1xyXG4gICBcclxuICAgbGV0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5hc3Nlc3NtZW50cywgYEdsb2JhbElEPScke2Fzc2Vzc21lbnRHbG9iYWxJZH0nYCwgY29uZmlnKTtcclxuICAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMCl7XHJcbiAgICAgYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcuYXNzZXNzbWVudHMsIGZlYXR1cmVzLm1hcChmID0+IGYuYXR0cmlidXRlcy5PQkpFQ1RJRCksIGNvbmZpZyk7XHJcbiAgIH1cclxuXHJcbiAgIGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZVN0YXR1cywgYEFzc2Vzc21lbnRJRD0nJHthc3Nlc3NtZW50R2xvYmFsSWR9J2AsIGNvbmZpZyk7XHJcbiAgIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIGZlYXR1cmVzLm1hcChmID0+IGYuYXR0cmlidXRlcy5PQkpFQ1RJRCksIGNvbmZpZyk7XHJcblxyXG4gICAgY29uc3QgcXVlcnkgPSBgTGlmZWxpbmVTdGF0dXNJRCBJTiAoJHtmZWF0dXJlcy5tYXAoZiA9PiBmLmF0dHJpYnV0ZXMuR2xvYmFsSUQpLmpvaW4oJywnKX0pYDtcclxuICAgIGNvbnNvbGUubG9nKCdkZWxldGUgcXVlcmllcycsIHF1ZXJ5KVxyXG4gICAgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBxdWVyeSwgY29uZmlnKTtcclxuICAgIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgICBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JBc3Nlc3NtZW50cywgZmVhdHVyZXMubWFwKGYgPT4gZi5hdHRyaWJ1dGVzLk9CSkVDVElEKSwgY29uZmlnKTtcclxuICAgIH1cclxuICAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0QXNzZXNzbWVudE5hbWVzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCB0ZW1wbGF0ZU5hbWU6IHN0cmluZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPHtuYW1lOiBzdHJpbmcsIGRhdGU6IHN0cmluZ31bXT4+e1xyXG4gIFxyXG4gIGNvbnN0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5hc3Nlc3NtZW50cywgYFRlbXBsYXRlPScke3RlbXBsYXRlTmFtZX0nYCwgY29uZmlnKTtcclxuICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPT09IDApe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogW11cclxuICAgIH1cclxuICB9XHJcbiAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMCl7XHJcbiAgIFxyXG4gICAgIGNvbnN0IGFzc2VzcyA9ICBmZWF0dXJlcy5tYXAoZiA9PiB7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgbmFtZTogZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgZGF0ZTogcGFyc2VEYXRlKE51bWJlcihmLmF0dHJpYnV0ZXMuQ3JlYXRlZERhdGUpKVxyXG4gICAgICB9XHJcbiAgICAgfSk7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgIGRhdGE6IGFzc2Vzc1xyXG4gICAgIH1cclxuICB9XHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ1JlcXVlc3QgZm9yIGFzc2Vzc21lbnQgbmFtZXMgZmFpbGVkLidcclxuICB9XHJcblxyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRBc3Nlc3NtZW50RmVhdHVyZXMoY29uZmlnKSB7XHJcbiAgIGNvbnNvbGUubG9nKCdnZXQgQXNzZXNzbWVudCBGZWF0dXJlcyBjYWxsZWQuJyk7XHJcbiAgIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmFzc2Vzc21lbnRzLCBgMT0xYCwgY29uZmlnKTtcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGxvYWRBbGxBc3Nlc3NtZW50cyhjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPEFzc2Vzc21lbnRbXT4+e1xyXG5cclxuICAgdHJ5e1xyXG4gICAgY29uc3QgYXNzZXNzbWVudEZlYXR1cmVzID0gYXdhaXQgZ2V0QXNzZXNzbWVudEZlYXR1cmVzKGNvbmZpZyk7XHJcbiAgICBpZighYXNzZXNzbWVudEZlYXR1cmVzIHx8IGFzc2Vzc21lbnRGZWF0dXJlcy5sZW5ndGggPT0gMCl7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogW11cclxuICAgICAgfVxyXG4gICAgfVxyXG4gICAgXHJcbiAgICBjb25zdCBsc0ZlYXR1cmVzID0gYXdhaXQgZ2V0TGlmZWxpbmVTdGF0dXNGZWF0dXJlcyhjb25maWcsIGAxPTFgKTtcclxuXHJcbiAgICBjb25zdCBxdWVyeSA9IGBMaWZlbGluZVN0YXR1c0lEIElOICgke2xzRmVhdHVyZXMubWFwKGYgPT4gYCcke2YuYXR0cmlidXRlcy5HbG9iYWxJRH0nYCkuam9pbignLCcpfSlgXHJcbiAgICBcclxuICAgIGNvbnN0IGluZGljYXRvckFzc2Vzc21lbnRzID0gYXdhaXQgZ2V0SW5kaWNhdG9yQXNzZXNzbWVudHMocXVlcnksIGNvbmZpZyk7XHJcblxyXG4gICAgaWYoYXNzZXNzbWVudEZlYXR1cmVzICYmIGFzc2Vzc21lbnRGZWF0dXJlcy5sZW5ndGggPiAwKXsgICBcclxuICAgICAgY29uc3QgYXNzZXNzbWVudHMgPSBhc3Nlc3NtZW50RmVhdHVyZXMubWFwKChmZWF0dXJlOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgICAgIGNvbnN0IGFzc2Vzc21lbnRMc0ZlYXR1cmVzID0gbHNGZWF0dXJlcy5maWx0ZXIobCA9PmwuYXR0cmlidXRlcy5Bc3Nlc3NtZW50SUQgPT0gZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEKSAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIGxvYWRBc3Nlc3NtZW50KGZlYXR1cmUsIGFzc2Vzc21lbnRMc0ZlYXR1cmVzLCBpbmRpY2F0b3JBc3Nlc3NtZW50cyk7XHJcbiAgICAgIH0pO1xyXG5cclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiBhc3Nlc3NtZW50c1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgaWYoYXNzZXNzbWVudEZlYXR1cmVzICYmIGFzc2Vzc21lbnRGZWF0dXJlcy5sZW5ndGggPT0gMCl7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogW11cclxuICAgICAgfSAgXHJcbiAgICB9XHJcbiAgIH1jYXRjaChlKXtcclxuICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAnbG9hZEFsbEFzc2Vzc21lbnRzJyk7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBlcnJvcnM6IGVcclxuICAgIH1cclxuICAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY3JlYXRlSW5jaWRlbnQoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIGluY2lkZW50OiBJbmNpZGVudCk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPHZvaWQ+PntcclxuICAgXHJcbiAgICB0cnl7XHJcbiAgICAgIGNoZWNrUGFyYW0oY29uZmlnLmluY2lkZW50cywgSU5DSURFTlRfVVJMX0VSUk9SKTtcclxuICAgICAgY2hlY2tQYXJhbShpbmNpZGVudCwgJ0luY2lkZW50IGRhdGEgbm90IHByb3ZpZGVkJyk7XHJcblxyXG4gICAgICBjb25zdCBmZWF0dXJlcyA9IFt7XHJcbiAgICAgICAgYXR0cmlidXRlcyA6IHtcclxuICAgICAgICAgIEhhemFyZElEOiBpbmNpZGVudC5oYXphcmQuaWQsXHJcbiAgICAgICAgICBOYW1lIDogaW5jaWRlbnQubmFtZSxcclxuICAgICAgICAgIERlc2NyaXB0aW9uOiBpbmNpZGVudC5kZXNjcmlwdGlvbixcclxuICAgICAgICAgIFN0YXJ0RGF0ZSA6IFN0cmluZyhpbmNpZGVudC5zdGFydERhdGUpLFxyXG4gICAgICAgICAgRW5kRGF0ZSA6IFN0cmluZyhpbmNpZGVudC5lbmREYXRlKVxyXG4gICAgICAgIH1cclxuICAgICAgfV1cclxuXHJcbiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaW5jaWRlbnRzLCBmZWF0dXJlcywgY29uZmlnKTtcclxuXHJcbiAgICAgIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5sZW5ndGggPiAwKXtcclxuICAgICAgICByZXR1cm57fSBcclxuICAgICAgfVxyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGVycm9yczogJ0luY2lkZW50IGNvdWxkIG5vdCBiZSBzYXZlZC4nXHJcbiAgICAgIH1cclxuICAgIH1jYXRjaChlKSB7XHJcbiAgICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAnY3JlYXRlSW5jaWRlbnQnKTtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBlcnJvcnM6ICdJbmNpZGVudCBjb3VsZCBub3QgYmUgc2F2ZWQuJ1xyXG4gICAgICB9XHJcbiAgICB9XHJcbn1cclxuXHJcbi8vPT09PT09PT09PT09PT09PT09PT1QUklWQVRFPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cclxuXHJcbmNvbnN0IHJlcXVlc3REYXRhID0gYXN5bmMgKHVybDogc3RyaW5nLCBjb250cm9sbGVyPzogYW55KTogUHJvbWlzZTxJRmVhdHVyZVNldD4gPT4ge1xyXG4gIGlmICghY29udHJvbGxlcikge1xyXG4gICAgY29udHJvbGxlciA9IG5ldyBBYm9ydENvbnRyb2xsZXIoKTtcclxuICB9XHJcbiAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaCh1cmwsIHtcclxuICAgIG1ldGhvZDogXCJHRVRcIixcclxuICAgIGhlYWRlcnM6IHtcclxuICAgICAgJ2NvbnRlbnQtdHlwZSc6ICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbiAgICB9LFxyXG4gICAgc2lnbmFsOiBjb250cm9sbGVyLnNpZ25hbFxyXG4gIH1cclxuICApO1xyXG4gIHJldHVybiByZXNwb25zZS5qc29uKCk7XHJcbn1cclxuXHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRUZW1wbGF0ZShcclxuICB0ZW1wbGF0ZUZlYXR1cmU6IElGZWF0dXJlLCBcclxuICBsaWZlbGluZUZlYXR1cmVzOiBJRmVhdHVyZVtdLCBcclxuICBjb21wb25lbnRGZWF0dXJlczogSUZlYXR1cmVbXSwgXHJcbiAgaW5kaWNhdG9yc0ZlYXR1cmVzOiBJRmVhdHVyZVtdLCBcclxuICB3ZWlnaHRzRmVhdHVyZXM6IElGZWF0dXJlW10sIFxyXG4gIHRlbXBsYXRlRG9tYWluczogSUNvZGVkVmFsdWVbXSk6IFByb21pc2U8Q0xTU1RlbXBsYXRlPntcclxuXHJcbiAgY29uc3QgaW5kaWNhdG9yRmVhdHVyZXMgPSBpbmRpY2F0b3JzRmVhdHVyZXMuZmlsdGVyKGkgPT4gaS5hdHRyaWJ1dGVzLlRlbXBsYXRlSUQgPSBgJyR7dGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUR9J2ApLy8gIGF3YWl0IGdldEluZGljYXRvckZlYXR1cmVzKGBUZW1wbGF0ZUlEPScke3RlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEfSdgLCBjb25maWcpO1xyXG4gIFxyXG4gIC8vY29uc3QgcXVlcnkgPSBpbmRpY2F0b3JGZWF0dXJlcy5tYXAoaSA9PiBgSW5kaWNhdG9ySUQ9JyR7aS5hdHRyaWJ1dGVzLkdsb2JhbElELnRvVXBwZXJDYXNlKCl9J2ApLmpvaW4oJyBPUiAnKVxyXG4gIFxyXG4gIGNvbnN0IGluZGljYXRvcklkcyA9IGluZGljYXRvckZlYXR1cmVzLm1hcChpID0+IGkuYXR0cmlidXRlcy5HbG9iYWxJRCk7XHJcbiAgY29uc3Qgd2VpZ2h0RmVhdHVyZXMgPSB3ZWlnaHRzRmVhdHVyZXMuZmlsdGVyKHcgPT4gaW5kaWNhdG9ySWRzLmluZGV4T2Yody5hdHRyaWJ1dGVzLkluZGljYXRvcklEKSkgLy9hd2FpdCBnZXRXZWlnaHRzRmVhdHVyZXMocXVlcnksIGNvbmZpZyk7XHJcbiAgXHJcbiAgY29uc3QgaW5kaWNhdG9yVGVtcGxhdGVzID0gaW5kaWNhdG9yRmVhdHVyZXMubWFwKChmZWF0dXJlOiBJRmVhdHVyZSkgPT4ge1xyXG5cclxuICAgICBjb25zdCB3ZWlnaHRzID0gd2VpZ2h0c0ZlYXR1cmVzXHJcbiAgICAgIC5maWx0ZXIodyA9PiB3LmF0dHJpYnV0ZXMuSW5kaWNhdG9ySUQ9PT1mZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQpXHJcbiAgICAgIC5tYXAodyA9PiB7XHJcbiAgICAgICByZXR1cm4geyBcclxuICAgICAgICBvYmplY3RJZDogdy5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICAgIG5hbWU6IHcuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgIHdlaWdodDogdy5hdHRyaWJ1dGVzLldlaWdodCxcclxuICAgICAgICBzY2FsZUZhY3RvciA6IHcuYXR0cmlidXRlcy5TY2FsZUZhY3RvciwgXHJcbiAgICAgICAgYWRqdXN0ZWRXZWlnaHQ6IHcuYXR0cmlidXRlcy5BZGp1c3RlZFdlaWdodCxcclxuICAgICAgICBtYXhBZGp1c3RlZFdlaWdodDogdy5hdHRyaWJ1dGVzLk1heEFkanVzdGVkV2VpZ2h0XHJcbiAgICAgICB9IGFzIEluZGljYXRvcldlaWdodFxyXG4gICAgIH0pXHJcblxyXG4gICAgIHJldHVybiB7XHJcbiAgICAgIG9iamVjdElkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgIGlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsIFxyXG4gICAgICBuYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgdGVtcGxhdGVOYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuVGVtcGxhdGVOYW1lLFxyXG4gICAgICB3ZWlnaHRzLFxyXG4gICAgICBjb21wb25lbnRJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkNvbXBvbmVudElELFxyXG4gICAgICB0ZW1wbGF0ZUlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuVGVtcGxhdGVJRCwgIFxyXG4gICAgICBjb21wb25lbnROYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuQ29tcG9uZW50TmFtZSxcclxuICAgICAgbGlmZWxpbmVOYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZWxpbmVOYW1lXHJcbiAgICAgfSBhcyBJbmRpY2F0b3JUZW1wbGF0ZVxyXG4gIH0pO1xyXG5cclxuICBjb25zdCBjb21wb25lbnRUZW1wbGF0ZXMgPSBjb21wb25lbnRGZWF0dXJlcy5tYXAoKGZlYXR1cmU6IElGZWF0dXJlKSA9PiB7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgICBpZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICAgIHRpdGxlOiBmZWF0dXJlLmF0dHJpYnV0ZXMuRGlzcGxheU5hbWUgfHwgZmVhdHVyZS5hdHRyaWJ1dGVzLkRpc3BsYXlUaXRsZSxcclxuICAgICAgICBuYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICBsaWZlbGluZUlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZWxpbmVJRCxcclxuICAgICAgICBpbmRpY2F0b3JzOiAoaW5kaWNhdG9yVGVtcGxhdGVzLmZpbHRlcihpID0+IGkuY29tcG9uZW50SWQgPT09IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCkgYXMgYW55KS5vcmRlckJ5KCduYW1lJylcclxuICAgICB9XHJcbiAgfSk7XHJcblxyXG4gIGNvbnN0IGxpZmVsaW5lVGVtcGxhdGVzID0gbGlmZWxpbmVGZWF0dXJlcy5tYXAoKGZlYXR1cmU6IElGZWF0dXJlKSA9PiB7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBpZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICB0aXRsZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkRpc3BsYXlOYW1lIHx8IGZlYXR1cmUuYXR0cmlidXRlcy5EaXNwbGF5VGl0bGUsXHJcbiAgICAgIG5hbWU6IGZlYXR1cmUuYXR0cmlidXRlcy5OYW1lLCAgICAgIFxyXG4gICAgICBjb21wb25lbnRUZW1wbGF0ZXM6IChjb21wb25lbnRUZW1wbGF0ZXMuZmlsdGVyKGMgPT4gYy5saWZlbGluZUlkID09PSBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQpIGFzIGFueSkub3JkZXJCeSgndGl0bGUnKVxyXG4gICAgfSBhcyBMaWZlTGluZVRlbXBsYXRlO1xyXG4gIH0pO1xyXG5cclxuICBjb25zdCB0ZW1wbGF0ZSA9IHtcclxuICAgICAgb2JqZWN0SWQ6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICBpZDogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgIGlzU2VsZWN0ZWQ6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLklzU2VsZWN0ZWQgPT0gMSxcclxuICAgICAgc3RhdHVzOiB7XHJcbiAgICAgICAgY29kZTogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuU3RhdHVzLFxyXG4gICAgICAgIG5hbWU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLlN0YXR1cyA9PT0gMSA/IFwiQWN0aXZlXCI6ICdBcmNoaXZlZCdcclxuICAgICAgfSBhcyBJQ29kZWRWYWx1ZSxcclxuICAgICAgbmFtZTogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgaGF6YXJkTmFtZTogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuSGF6YXJkTmFtZSxcclxuICAgICAgaGF6YXJkVHlwZTogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuSGF6YXJkVHlwZSxcclxuICAgICAgb3JnYW5pemF0aW9uTmFtZTogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuT3JnYW5pemF0aW9uTmFtZSxcclxuICAgICAgb3JnYW5pemF0aW9uVHlwZTogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuT3JnYW5pemF0aW9uVHlwZSwgXHJcbiAgICAgIGNyZWF0b3I6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkNyZWF0b3IsXHJcbiAgICAgIGNyZWF0ZWREYXRlOiBOdW1iZXIodGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuQ3JlYXRlZERhdGUpLFxyXG4gICAgICBlZGl0b3I6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkVkaXRvcixcclxuICAgICAgZWRpdGVkRGF0ZTogTnVtYmVyKHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkVkaXRlZERhdGUpLFxyXG4gICAgICBsaWZlbGluZVRlbXBsYXRlczogIChsaWZlbGluZVRlbXBsYXRlcyBhcyBhbnkpLm9yZGVyQnkoJ3RpdGxlJyksXHJcbiAgICAgIGRvbWFpbnM6IHRlbXBsYXRlRG9tYWluc1xyXG4gIH0gYXMgQ0xTU1RlbXBsYXRlO1xyXG5cclxuICByZXR1cm4gdGVtcGxhdGU7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIHNhdmVBc3Nlc3NtZW50KGFzc2Vzc21lbnQ6IEFzc2Vzc21lbnQsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8c3RyaW5nPj57XHJcblxyXG4gIHRyeXtcclxuICAgIGNvbnN0IGZlYXR1cmUgPSB7XHJcbiAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICBOYW1lIDphc3Nlc3NtZW50Lm5hbWUsXHJcbiAgICAgICAgRGVzY3JpcHRpb246IGFzc2Vzc21lbnQuZGVzY3JpcHRpb24sXHJcbiAgICAgICAgQXNzZXNzbWVudFR5cGU6IGFzc2Vzc21lbnQuYXNzZXNzbWVudFR5cGUsIFxyXG4gICAgICAgIE9yZ2FuaXphdGlvbjogYXNzZXNzbWVudC5vcmdhbml6YXRpb24sIFxyXG4gICAgICAgIEluY2lkZW50OiBhc3Nlc3NtZW50LmluY2lkZW50LCBcclxuICAgICAgICBIYXphcmQ6IGFzc2Vzc21lbnQuaGF6YXJkLCBcclxuICAgICAgICBDcmVhdG9yOiBhc3Nlc3NtZW50LmNyZWF0b3IsIFxyXG4gICAgICAgIENyZWF0ZWREYXRlOiBhc3Nlc3NtZW50LmNyZWF0ZWREYXRlLCBcclxuICAgICAgICBFZGl0b3I6IGFzc2Vzc21lbnQuZWRpdG9yLCBcclxuICAgICAgICBFZGl0ZWREYXRlOiBhc3Nlc3NtZW50LmVkaXRlZERhdGUsIFxyXG4gICAgICAgIElzQ29tcGxldGVkOiBhc3Nlc3NtZW50LmlzQ29tcGxldGVkLCBcclxuICAgICAgICBIYXphcmRUeXBlOiBhc3Nlc3NtZW50LmhhemFyZFR5cGUsXHJcbiAgICAgICAgT3JnYW5pemF0aW9uVHlwZTphc3Nlc3NtZW50Lm9yZ2FuaXphdGlvblR5cGUsXHJcbiAgICAgICAgVGVtcGxhdGU6IGFzc2Vzc21lbnQudGVtcGxhdGVcclxuICAgICAgfVxyXG4gICAgfVxyXG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5hc3Nlc3NtZW50cyxbZmVhdHVyZV0sIGNvbmZpZyk7XHJcbiAgICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuICAgICAgcmV0dXJueyBkYXRhOiByZXNwb25zZS5hZGRSZXN1bHRzWzBdLmdsb2JhbElkfVxyXG4gICAgfVxyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiAgSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpICAgIFxyXG4gICAgfVxyXG5cclxuICB9Y2F0Y2goZSl7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBlcnJvcnM6IGVcclxuICAgIH1cclxuICB9XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldEluZGljYXRvckFzc2Vzc21lbnRzKHF1ZXJ5OiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJbmRpY2F0b3JBc3Nlc3NtZW50W10+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgSW5kaWNhdG9yIEFzc2Vzc21lbnRzIGNhbGxlZC4nKVxyXG5cclxuICBjb25zdCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9yQXNzZXNzbWVudHMsIHF1ZXJ5LCBjb25maWcpO1xyXG4gIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgIHJldHVybiBmZWF0dXJlcy5tYXAoZmVhdHVyZSA9PiB7ICAgICAgICBcclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgb2JqZWN0SWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgICAgIGlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgICAgICBpbmRpY2F0b3JJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkluZGljYXRvcklELFxyXG4gICAgICAgICAgaW5kaWNhdG9yOiBmZWF0dXJlLmF0dHJpYnV0ZXMuSW5kaWNhdG9yTmFtZSxcclxuICAgICAgICAgIHRlbXBsYXRlOiBmZWF0dXJlLmF0dHJpYnV0ZXMuVGVtcGxhdGVOYW1lLFxyXG4gICAgICAgICAgbGlmZWxpbmU6IGZlYXR1cmUuYXR0cmlidXRlcy5MaWZlbGluZU5hbWUsXHJcbiAgICAgICAgICBjb21wb25lbnQ6IGZlYXR1cmUuYXR0cmlidXRlcy5Db21wb25lbnROYW1lLCAgICAgICAgICBcclxuICAgICAgICAgIGNvbW1lbnRzOiBwYXJzZUNvbW1lbnQoZmVhdHVyZS5hdHRyaWJ1dGVzLkNvbW1lbnRzKSwgICAgICAgICAgXHJcbiAgICAgICAgICBsaWZlbGluZVN0YXR1c0lkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZWxpbmVTdGF0dXNJRCxcclxuICAgICAgICAgIGVudmlyb25tZW50UHJlc2VydmF0aW9uOiBmZWF0dXJlLmF0dHJpYnV0ZXMuRW52aXJvbm1lbnRQcmVzZXJ2YXRpb24sXHJcbiAgICAgICAgICBpbmNpZGVudFN0YWJpbGl6YXRpb246IGZlYXR1cmUuYXR0cmlidXRlcy5JbmNpZGVudFN0YWJpbGl6YXRpb24sXHJcbiAgICAgICAgICByYW5rOiBmZWF0dXJlLmF0dHJpYnV0ZXMuUmFuayxcclxuICAgICAgICAgIGxpZmVTYWZldHk6IGZlYXR1cmUuYXR0cmlidXRlcy5MaWZlU2FmZXR5LFxyXG4gICAgICAgICAgcHJvcGVydHlQcm90ZWN0aW9uOiBmZWF0dXJlLmF0dHJpYnV0ZXMuUHJvcGVydHlQcm90ZWN0aW9uLFxyXG4gICAgICAgICAgc3RhdHVzOiBmZWF0dXJlLmF0dHJpYnV0ZXMuU3RhdHVzXHJcbiAgICAgICAgfSBhcyBJbmRpY2F0b3JBc3Nlc3NtZW50O1xyXG4gICAgIH0pXHJcbiAgfVxyXG5cclxufVxyXG5cclxuZnVuY3Rpb24gcGFyc2VDb21tZW50KGNvbW1lbnRzOiBzdHJpbmcpe1xyXG4gIGlmKCFjb21tZW50cyB8fCBjb21tZW50cyA9PT0gXCJcIil7XHJcbiAgICByZXR1cm4gW107XHJcbiAgfVxyXG4gIGxldCBwYXJzZWRDb21tZW50cyA9IEpTT04ucGFyc2UoY29tbWVudHMpIGFzIEluQ29tbWVudFtdO1xyXG4gIFxyXG4gIGlmKHBhcnNlZENvbW1lbnRzICYmIHBhcnNlZENvbW1lbnRzLmxlbmd0aCA+IDApe1xyXG4gICAgcGFyc2VkQ29tbWVudHMubWFwKChjb21tZW50RGF0YTogSW5Db21tZW50KSA9PiB7XHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgLi4uY29tbWVudERhdGEsXHJcbiAgICAgICAgICAgIGRhdGV0aW1lOiBOdW1iZXIoY29tbWVudERhdGEuZGF0ZXRpbWUpXHJcbiAgICAgICAgfSBhcyBJbkNvbW1lbnRcclxuICAgIH0pO1xyXG4gICAgcGFyc2VkQ29tbWVudHMgPSAocGFyc2VkQ29tbWVudHMgYXMgYW55KS5vcmRlckJ5KCdkYXRldGltZScsIHRydWUpO1xyXG4gIH1lbHNle1xyXG4gICAgcGFyc2VkQ29tbWVudHMgPSBbXTtcclxuICB9XHJcbiAgXHJcbiAgcmV0dXJuIHBhcnNlZENvbW1lbnRzO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRMaWZlbGluZVN0YXR1c0ZlYXR1cmVzKGNvbmZpZywgcXVlcnkpIHtcclxuICBjb25zb2xlLmxvZygnZ2V0IExpZmVsaW5lIFN0YXR1cyBjYWxsZWQnKVxyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuZnVuY3Rpb24gbG9hZEFzc2Vzc21lbnQoYXNzZXNzbWVudEZlYXR1cmU6IElGZWF0dXJlLCBsc0ZlYXR1cmVzOiBJRmVhdHVyZVtdLCBcclxuICBpbmRpY2F0b3JBc3Nlc3NtZW50czogSW5kaWNhdG9yQXNzZXNzbWVudFtdKTogQXNzZXNzbWVudHsgICBcclxuXHJcbiAgY29uc3QgbGlmZWxpbmVTdGF0dXNlcyA9IGxzRmVhdHVyZXMubWFwKChmZWF0dXJlKSA9PiB7IFxyXG4gICAgcmV0dXJuIHtcclxuICAgICAgb2JqZWN0SWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgaWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgYXNzZXNzbWVudElkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuQXNzZXNzbWVudElELFxyXG4gICAgICBsaWZlbGluZU5hbWU6IGZlYXR1cmUuYXR0cmlidXRlcy5MaWZlbGluZU5hbWUsXHJcbiAgICAgIGluZGljYXRvckFzc2Vzc21lbnRzOiBpbmRpY2F0b3JBc3Nlc3NtZW50cy5maWx0ZXIoaSA9PiBpLmxpZmVsaW5lU3RhdHVzSWQgPT09IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCksICAgICAgXHJcbiAgICAgIHNjb3JlOiBmZWF0dXJlLmF0dHJpYnV0ZXMuU2NvcmUsXHJcbiAgICAgIGNvbG9yOiBmZWF0dXJlLmF0dHJpYnV0ZXMuQ29sb3IsXHJcbiAgICAgIGlzT3ZlcnJpZGVuOiBmZWF0dXJlLmF0dHJpYnV0ZXMuSXNPdmVycmlkZW4sXHJcbiAgICAgIG92ZXJyaWRlU2NvcmU6ZmVhdHVyZS5hdHRyaWJ1dGVzLk92ZXJyaWRlblNjb3JlLFxyXG4gICAgICBvdmVycmlkZW5CeTogZmVhdHVyZS5hdHRyaWJ1dGVzLk92ZXJyaWRlbkJ5LFxyXG4gICAgICBvdmVycmlkZW5Db2xvcjogZmVhdHVyZS5hdHRyaWJ1dGVzLk92ZXJyaWRlbkNvbG9yLCAgICAgXHJcbiAgICAgIG92ZXJyaWRlQ29tbWVudDogZmVhdHVyZS5hdHRyaWJ1dGVzLk92ZXJyaWRlQ29tbWVudCAgICAgIFxyXG4gICAgfSBhcyBMaWZlbGluZVN0YXR1cztcclxuICB9KTtcclxuXHJcbiAgY29uc3QgYXNzZXNzbWVudCA9IHtcclxuICAgIG9iamVjdElkOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgaWQ6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICBuYW1lOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICBhc3Nlc3NtZW50VHlwZTogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5Bc3Nlc3NtZW50VHlwZSxcclxuICAgIGxpZmVsaW5lU3RhdHVzZXM6IGxpZmVsaW5lU3RhdHVzZXMsXHJcbiAgICBkZXNjcmlwdGlvbjogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5EZXNjcmlwdGlvbixcclxuICAgIHRlbXBsYXRlOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLlRlbXBsYXRlLFxyXG4gICAgb3JnYW5pemF0aW9uOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLk9yZ2FuaXphdGlvbixcclxuICAgIG9yZ2FuaXphdGlvblR5cGU6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuT3JnYW5pemF0aW9uVHlwZSxcclxuICAgIGluY2lkZW50OiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkluY2lkZW50LFxyXG4gICAgaGF6YXJkOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkhhemFyZCxcclxuICAgIGhhemFyZFR5cGU6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuSGF6YXJkVHlwZSxcclxuICAgIGNyZWF0b3I6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuQ3JlYXRvcixcclxuICAgIGNyZWF0ZWREYXRlOiBOdW1iZXIoYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5DcmVhdGVkRGF0ZSksXHJcbiAgICBlZGl0b3I6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuRWRpdG9yLFxyXG4gICAgZWRpdGVkRGF0ZTogTnVtYmVyKGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuRWRpdGVkRGF0ZSksXHJcbiAgICBpc1NlbGVjdGVkOiBmYWxzZSxcclxuICAgIGlzQ29tcGxldGVkOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLklzQ29tcGxldGVkLFxyXG4gIH0gYXMgQXNzZXNzbWVudFxyXG5cclxuICByZXR1cm4gYXNzZXNzbWVudDsgIFxyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBzYXZlTGlmZWxpbmVTdGF0dXMobGlmZWxpbmVTdGF0dXNGZWF0dXJlOiBJRmVhdHVyZSwgbHNJbmRBc3Nlc3NGZWF0dXJlczogSUZlYXR1cmVbXSwgY29uZmlnKTogUHJvbWlzZTxib29sZWFuPntcclxuICBsZXQgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZVN0YXR1cywgW2xpZmVsaW5lU3RhdHVzRmVhdHVyZV0sIGNvbmZpZylcclxuICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkoZSA9PiBlLnN1Y2Nlc3MpKXtcclxuICAgICBjb25zdCBnbG9iYWxJZCA9IHJlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWQ7XHJcblxyXG4gICAgIGNvbnN0IGluZGljYXRvckFzc2Vzc21lbnRGZWF0dXJlcyA9IGxzSW5kQXNzZXNzRmVhdHVyZXMubWFwKGluZCA9PiB7XHJcbiAgICAgICAgaW5kLmF0dHJpYnV0ZXMuTGlmZWxpbmVTdGF0dXNJRCA9IGdsb2JhbElkXHJcbiAgICAgICAgcmV0dXJuIGluZDtcclxuICAgICB9KVxyXG4gICAgIHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9yQXNzZXNzbWVudHMsIGluZGljYXRvckFzc2Vzc21lbnRGZWF0dXJlcywgY29uZmlnKTtcclxuICAgICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkoZSA9PiBlLnN1Y2Nlc3MpKXtcclxuICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgIH1cclxuICB9XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGdldFRlbXBsYXRlSW5kaWNhdG9ycyh0ZW1wbGF0ZTogQ0xTU1RlbXBsYXRlKTogSW5kaWNhdG9yVGVtcGxhdGVbXSB7XHJcbiAgcmV0dXJuIFtdLmNvbmNhdC5hcHBseShbXSwgKFtdLmNvbmNhdC5hcHBseShbXSwgXHJcbiAgIHRlbXBsYXRlLmxpZmVsaW5lVGVtcGxhdGVzLm1hcChsID0+IGwuY29tcG9uZW50VGVtcGxhdGVzKSkpXHJcbiAgIC5tYXAoKGM6IENvbXBvbmVudFRlbXBsYXRlKSA9PiBjLmluZGljYXRvcnMpKTtcclxufSIsIi8vQWRhcHRlZCBmcm9tIC8vaHR0cHM6Ly9naXRodWIuY29tL29kb2UvbWFwLXZ1ZS9ibG9iL21hc3Rlci9zcmMvZGF0YS9hdXRoLnRzXHJcblxyXG5pbXBvcnQgeyBsb2FkQXJjR0lTSlNBUElNb2R1bGVzIH0gZnJvbSBcImppbXUtYXJjZ2lzXCI7XHJcblxyXG4vKipcclxuICogQXR0ZW1wdCB0byBzaWduIGluLFxyXG4gKiBmaXJzdCBjaGVjayBjdXJyZW50IHN0YXR1c1xyXG4gKiBpZiBub3Qgc2lnbmVkIGluLCB0aGVuIGdvIHRocm91Z2hcclxuICogc3RlcHMgdG8gZ2V0IGNyZWRlbnRpYWxzXHJcbiAqL1xyXG5leHBvcnQgY29uc3Qgc2lnbkluID0gYXN5bmMgKGFwcElkOiBzdHJpbmcsIHBvcnRhbFVybDogc3RyaW5nKSA9PiB7XHJcbiAgICB0cnkge1xyXG4gICAgICAgIHJldHVybiBhd2FpdCBjaGVja0N1cnJlbnRTdGF0dXMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICB9IGNhdGNoIChlcnJvcikge1xyXG4gICAgICAgIGNvbnNvbGUubG9nKGVycm9yKTtcclxuICAgICAgICByZXR1cm4gYXdhaXQgZmV0Y2hDcmVkZW50aWFscyhhcHBJZCwgcG9ydGFsVXJsKTtcclxuICAgIH1cclxufTtcclxuXHJcbi8qKlxyXG4gKiBTaWduIHRoZSB1c2VyIG91dCwgYnV0IGlmIHdlIGNoZWNrZWQgY3JlZGVudGlhbHNcclxuICogbWFudWFsbHksIG1ha2Ugc3VyZSB0aGV5IGFyZSByZWdpc3RlcmVkIHdpdGhcclxuICogSWRlbnRpdHlNYW5hZ2VyLCBzbyBpdCBjYW4gZGVzdHJveSB0aGVtIHByb3Blcmx5XHJcbiAqL1xyXG5leHBvcnQgY29uc3Qgc2lnbk91dCA9IGFzeW5jIChhcHBJZDogc3RyaW5nLCBwb3J0YWxVcmw6IHN0cmluZykgPT4ge1xyXG4gICAgY29uc3QgSWRlbnRpdHlNYW5hZ2VyID0gYXdhaXQgbG9hZE1vZHVsZXMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICBhd2FpdCBzaWduSW4oYXBwSWQsIHBvcnRhbFVybCk7XHJcblxyXG4gICAgZGVsZXRlIHdpbmRvd1snSWRlbnRpdHlNYW5hZ2VyJ107XHJcbiAgICBkZWxldGUgd2luZG93WydPQXV0aEluZm8nXTtcclxuICAgIElkZW50aXR5TWFuYWdlci5kZXN0cm95Q3JlZGVudGlhbHMoKTtcclxuICAgIFxyXG59O1xyXG5cclxuLyoqXHJcbiAqIEdldCB0aGUgY3JlZGVudGlhbHMgZm9yIHRoZSBwcm92aWRlZCBwb3J0YWxcclxuICovXHJcbmFzeW5jIGZ1bmN0aW9uIGZldGNoQ3JlZGVudGlhbHMoYXBwSWQ6IHN0cmluZywgcG9ydGFsVXJsOiBzdHJpbmcpe1xyXG4gICAgY29uc3QgSWRlbnRpdHlNYW5hZ2VyID0gYXdhaXQgbG9hZE1vZHVsZXMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICBjb25zdCBjcmVkZW50aWFsID0gYXdhaXQgSWRlbnRpdHlNYW5hZ2VyLmdldENyZWRlbnRpYWwoYCR7cG9ydGFsVXJsfS9zaGFyaW5nYCwge1xyXG4gICAgICAgIGVycm9yOiBudWxsIGFzIGFueSxcclxuICAgICAgICBvQXV0aFBvcHVwQ29uZmlybWF0aW9uOiBmYWxzZSxcclxuICAgICAgICB0b2tlbjogbnVsbCBhcyBhbnlcclxuICAgIH0pO1xyXG4gICAgcmV0dXJuIGNyZWRlbnRpYWw7XHJcbn07XHJcblxyXG4vKipcclxuICogSW1wb3J0IElkZW50aXR5IE1hbmFnZXIsIGFuZCBPQXV0aEluZm9cclxuICovXHJcbmFzeW5jIGZ1bmN0aW9uIGxvYWRNb2R1bGVzKGFwcElkOiBzdHJpbmcsIHBvcnRhbFVybDogc3RyaW5nKSB7XHJcbiAgICBsZXQgSWRlbnRpdHlNYW5hZ2VyID0gd2luZG93WydJZGVudGl0eU1hbmFnZXInXVxyXG4gICAgaWYoIUlkZW50aXR5TWFuYWdlcil7XHJcbiAgICAgICAgY29uc3QgbW9kdWxlcyA9IGF3YWl0IGxvYWRBcmNHSVNKU0FQSU1vZHVsZXMoW1xyXG4gICAgICAgICAgICAnZXNyaS9pZGVudGl0eS9JZGVudGl0eU1hbmFnZXInLFxyXG4gICAgICAgICAgICAnZXNyaS9pZGVudGl0eS9PQXV0aEluZm8nXSk7XHJcblxyXG4gICAgICAgICAgICB3aW5kb3dbJ0lkZW50aXR5TWFuYWdlciddID0gbW9kdWxlc1swXTtcclxuICAgICAgICAgICAgd2luZG93WydPQXV0aEluZm8nXSA9IG1vZHVsZXNbMV07XHJcbiAgICAgICAgICAgIFxyXG4gICAgICAgIElkZW50aXR5TWFuYWdlciA9IG1vZHVsZXNbMF07XHJcbiAgICAgICAgY29uc3QgT0F1dGhJbmZvID0gbW9kdWxlc1sxXTtcclxuXHJcbiAgICAgICAgY29uc3Qgb2F1dGhJbmZvID0gbmV3IE9BdXRoSW5mbyh7XHJcbiAgICAgICAgICAgIGFwcElkLFxyXG4gICAgICAgICAgICBwb3J0YWxVcmwsXHJcbiAgICAgICAgICAgIHBvcHVwOiBmYWxzZVxyXG4gICAgICAgIH0pO1xyXG4gICAgICAgIElkZW50aXR5TWFuYWdlci5yZWdpc3Rlck9BdXRoSW5mb3MoW29hdXRoSW5mb10pOyAgICAgICAgXHJcbiAgICB9XHJcbiAgICByZXR1cm4gSWRlbnRpdHlNYW5hZ2VyO1xyXG59XHJcblxyXG4vKipcclxuICogQ2hlY2sgY3VycmVudCBsb2dnZWQgaW4gc3RhdHVzIGZvciBjdXJyZW50IHBvcnRhbFxyXG4gKi9cclxuZXhwb3J0IGNvbnN0IGNoZWNrQ3VycmVudFN0YXR1cyA9IGFzeW5jIChhcHBJZDogc3RyaW5nLCBwb3J0YWxVcmw6IHN0cmluZykgPT4ge1xyXG4gICAgY29uc3QgSWRlbnRpdHlNYW5hZ2VyID0gYXdhaXQgbG9hZE1vZHVsZXMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICByZXR1cm4gSWRlbnRpdHlNYW5hZ2VyLmNoZWNrU2lnbkluU3RhdHVzKGAke3BvcnRhbFVybH0vc2hhcmluZ2ApO1xyXG59OyIsImltcG9ydCB7IGV4dGVuc2lvblNwZWMsIEltbXV0YWJsZU9iamVjdCwgSU1TdGF0ZSB9IGZyb20gJ2ppbXUtY29yZSc7XHJcbmltcG9ydCB7IEFzc2Vzc21lbnQsIENMU1NfU3RhdGUsIFxyXG4gIENMU1NUZW1wbGF0ZSwgQ2xzc1VzZXIsIEhhemFyZCwgXHJcbiAgTGlmZWxpbmVTdGF0dXMsIE9yZ2FuaXphdGlvbiwgXHJcbiAgUmF0aW5nU2NhbGUsIFNjYWxlRmFjdG9yIH0gZnJvbSAnLi9kYXRhLWRlZmluaXRpb25zJztcclxuaW1wb3J0IHsgSUNvZGVkVmFsdWUgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC10eXBlcyc7XHJcbmltcG9ydCB7IElDcmVkZW50aWFsIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aCc7XHJcblxyXG5cclxuZXhwb3J0IGVudW0gQ0xTU0FjdGlvbktleXMge1xyXG4gIEFVVEhFTlRJQ0FURV9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGF1dGhlbmljYXRlIGNyZWRlbnRpYWxzJyxcclxuICBMT0FEX0hBWkFSRFNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBsb2FkIGhhemFyZHMnLFxyXG4gIExPQURfSEFaQVJEX1RZUEVTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCBoYXphcmQgdHlwZXMnLFxyXG4gIExPQURfT1JHQU5JWkFUSU9OU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGxvYWQgb3JnYW5pemF0aW9ucycsXHJcbiAgTE9BRF9PUkdBTklaQVRJT05fVFlQRVNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBsb2FkIG9yZ2FuaXphdGlvbiB0eXBlcycsXHJcbiAgTE9BRF9URU1QTEFURVNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBsb2FkIHRlbXBsYXRlcycsXHJcbiAgTE9BRF9QUklPUklUSUVTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCBwcmlvcml0aWVzJyxcclxuICBTRUxFQ1RfVEVNUExBVEVfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBzZWxlY3QgdGVtcGxhdGUnLFxyXG4gIFNFQVJDSF9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIHNlYXJjaCBmb3IgdGVtcGxhdGUnLFxyXG4gIFNJR05fSU5fQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTaWduIGluJyxcclxuICBTSUdOX09VVF9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIFNpZ24gb3V0JyxcclxuICBTRVRfVVNFUl9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIFNldCBDTFNTIFVzZXInLFxyXG4gIFNFVF9JREVOVElUWV9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIFNldCBJZGVudGl0eScsXHJcbiAgU0VUX0VSUk9SUyA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2V0IGdsb2JhbCBlcnJvcnMnLFxyXG4gIFRPR0dMRV9JTkRJQ0FUT1JfRURJVElORyA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gVG9nZ2xlIGluZGljYXRvciBlZGl0aW5nJywgIFxyXG4gIFNFTEVDVF9MSUZFTElORVNUQVRVU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIFNlbGVjdCBhIGxpZmVsaW5lIHN0YXR1cycsXHJcbiAgTE9BRF9BU1NFU1NNRU5UU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIExvYWQgYXNzZXNzbWVudHMnLFxyXG4gIFNFTEVDVF9BU1NFU1NNRU5UX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2VsZWN0IGFzc2Vzc21lbnQnLFxyXG4gIExPQURfUkFUSU5HU0NBTEVTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gTG9hZCByYXRpbmcgc2NhbGVzJyxcclxuICBMT0FEX1NDQUxFRkFDVE9SU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIExvYWQgY29uc3RhbnRzJ1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfU2NhbGVGYWN0b3JzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfU0NBTEVGQUNUT1JTX0FDVElPTixcclxuICB2YWw6IFNjYWxlRmFjdG9yW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX1JhdGluZ19TY2FsZXNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9SQVRJTkdTQ0FMRVNfQUNUSU9OLFxyXG4gIHZhbDogUmF0aW5nU2NhbGVbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNlbGVjdF9Bc3Nlc3NtZW50X0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFTEVDVF9BU1NFU1NNRU5UX0FDVElPTixcclxuICB2YWw6IEFzc2Vzc21lbnRcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX0Fzc2Vzc21lbnRzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfQVNTRVNTTUVOVFNfQUNUSU9OLFxyXG4gIHZhbDogQXNzZXNzbWVudFtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9Qcmlvcml0aWVzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfUFJJT1JJVElFU19BQ1RJT04sXHJcbiAgdmFsOiBhbnlbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfSGF6YXJkX1R5cGVzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfSEFaQVJEX1RZUEVTX0FDVElPTixcclxuICB2YWw6IElDb2RlZFZhbHVlW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX09yZ2FuaXphdGlvbl9UeXBlc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX09SR0FOSVpBVElPTl9UWVBFU19BQ1RJT04sXHJcbiAgdmFsOiBJQ29kZWRWYWx1ZVtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2VsZWN0X0xpZmVsaW5lU3RhdHVzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFTEVDVF9MSUZFTElORVNUQVRVU19BQ1RJT04sXHJcbiAgdmFsOiBMaWZlbGluZVN0YXR1c1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNldF9Ub2dnbGVfSW5kaWNhdG9yX0VkaXRpbmdfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuVE9HR0xFX0lORElDQVRPUl9FRElUSU5HLFxyXG4gIHZhbDogc3RyaW5nXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2V0X0Vycm9yc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLFxyXG4gIHZhbDogc3RyaW5nXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9IYXphcmRzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfSEFaQVJEU19BQ1RJT04sXHJcbiAgdmFsOiBIYXphcmRbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfT3JnYW5pemF0aW9uc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX09SR0FOSVpBVElPTlNfQUNUSU9OLFxyXG4gIHZhbDogT3JnYW5pemF0aW9uW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZXRJZGVudGl0eV9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRVRfSURFTlRJVFlfQUNUSU9OLFxyXG4gIHZhbDogQ2xzc1VzZXJcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZXRVc2VyX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFVF9VU0VSX0FDVElPTixcclxuICB2YWw6IENsc3NVc2VyXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2lnbmluX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNJR05fSU5fQUNUSU9OXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2lnbm91dF9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TSUdOX09VVF9BQ1RJT05cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZWxlY3RfVGVtcGxhdGVfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VMRUNUX1RFTVBMQVRFX0FDVElPTixcclxuICB2YWw6IHN0cmluZ1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfVGVtcGxhdGVzX0FjdGlvbl9UeXBlIHtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX1RFTVBMQVRFU19BQ1RJT04sXHJcbiAgdmFsOiBDTFNTVGVtcGxhdGVbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNlYXJjaF9UZW1wbGF0ZXNfQWN0aW9uX1R5cGUge1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFQVJDSF9BQ1RJT04sXHJcbiAgdmFsOiBzdHJpbmdcclxufSAgXHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIEF1dGhlbnRpY2F0ZV9BY3Rpb25fVHlwZSB7XHJcbiAgIHR5cGU6IENMU1NBY3Rpb25LZXlzLkFVVEhFTlRJQ0FURV9BQ1RJT04sXHJcbiAgIHZhbDogSUNyZWRlbnRpYWw7XHJcbn1cclxuXHJcblxyXG50eXBlIEFjdGlvblR5cGVzID0gXHJcbiBTZWxlY3RfVGVtcGxhdGVfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9UZW1wbGF0ZXNfQWN0aW9uX1R5cGUgfCBcclxuIFNlYXJjaF9UZW1wbGF0ZXNfQWN0aW9uX1R5cGUgfCBcclxuIFNpZ25pbl9BY3Rpb25fVHlwZSB8XHJcbiBTaWdub3V0X0FjdGlvbl9UeXBlIHxcclxuIFNldFVzZXJfQWN0aW9uX1R5cGUgfCBcclxuIFNldElkZW50aXR5X0FjdGlvbl9UeXBlIHxcclxuIExvYWRfSGF6YXJkc19BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX09yZ2FuaXphdGlvbnNfQWN0aW9uX1R5cGUgfFxyXG4gU2V0X0Vycm9yc19BY3Rpb25fVHlwZSB8XHJcbiBTZXRfVG9nZ2xlX0luZGljYXRvcl9FZGl0aW5nX0FjdGlvbl9UeXBlIHxcclxuIFNlbGVjdF9MaWZlbGluZVN0YXR1c19BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX0hhemFyZF9UeXBlc19BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX09yZ2FuaXphdGlvbl9UeXBlc19BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX1ByaW9yaXRpZXNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9Bc3Nlc3NtZW50c19BY3Rpb25fVHlwZSB8XHJcbiBTZWxlY3RfQXNzZXNzbWVudF9BY3Rpb25fVHlwZXwgXHJcbiBMb2FkX1JhdGluZ19TY2FsZXNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9TY2FsZUZhY3RvcnNfQWN0aW9uX1R5cGUgfFxyXG4gQXV0aGVudGljYXRlX0FjdGlvbl9UeXBlIDtcclxuXHJcbnR5cGUgSU1NeVN0YXRlID0gSW1tdXRhYmxlT2JqZWN0PENMU1NfU3RhdGU+O1xyXG5cclxuZGVjbGFyZSBtb2R1bGUgJ2ppbXUtY29yZS9saWIvdHlwZXMvc3RhdGUne1xyXG4gIGludGVyZmFjZSBTdGF0ZXtcclxuICAgIGNsc3NTdGF0ZT86IElNTXlTdGF0ZVxyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgTXlSZWR1eFN0b3JlRXh0ZW5zaW9uIGltcGxlbWVudHMgZXh0ZW5zaW9uU3BlYy5SZWR1eFN0b3JlRXh0ZW5zaW9uIHtcclxuICBpZCA9ICdjbHNzLXJlZHV4LXN0b3JlLWV4dGVuc2lvbic7XHJcbiBcclxuICBnZXRBY3Rpb25zKCkge1xyXG4gICAgcmV0dXJuIE9iamVjdC5rZXlzKENMU1NBY3Rpb25LZXlzKS5tYXAoayA9PiBDTFNTQWN0aW9uS2V5c1trXSk7XHJcbiAgfVxyXG5cclxuICBnZXRJbml0TG9jYWxTdGF0ZSgpIHtcclxuICAgIHJldHVybiB7XHJcbiAgICAgICBzZWxlY3RlZFRlbXBsYXRlOiBudWxsLFxyXG4gICAgICAgdGVtcGxhdGVzOiBbXSxcclxuICAgICAgIHNlYXJjaFJlc3VsdHM6IFtdLFxyXG4gICAgICAgdXNlcjogbnVsbCxcclxuICAgICAgIGF1dGg6IG51bGwsXHJcbiAgICAgICBpZGVudGl0eTogbnVsbCwgICAgICAgXHJcbiAgICAgICBuZXdUZW1wbGF0ZU1vZGFsVmlzaWJsZTogZmFsc2UsXHJcbiAgICAgICBoYXphcmRzOiBbXSxcclxuICAgICAgIG9yZ2FuaXphdGlvbnM6IFtdLFxyXG4gICAgICAgZXJyb3JzOiAnJyxcclxuICAgICAgIGlzSW5kaWNhdG9yRWRpdGluZzogZmFsc2UsXHJcbiAgICAgICBzZWxlY3RlZExpZmVsaW5lU3RhdHVzOiBudWxsLFxyXG4gICAgICAgb3JnYW5pemF0aW9uVHlwZXM6IFtdLFxyXG4gICAgICAgaGF6YXJkVHlwZXM6IFtdLFxyXG4gICAgICAgcHJpb3JpdGllczogW10sXHJcbiAgICAgICBhc3Nlc3NtZW50czogW10sXHJcbiAgICAgICByYXRpbmdTY2FsZXM6IFtdLFxyXG4gICAgICAgc2NhbGVGYWN0b3JzOiBbXSxcclxuICAgICAgIGF1dGhlbnRpY2F0ZTogbnVsbFxyXG4gICAgfSBhcyBDTFNTX1N0YXRlO1xyXG4gIH1cclxuXHJcbiAgZ2V0UmVkdWNlcigpIHtcclxuICAgIHJldHVybiAobG9jYWxTdGF0ZTogSU1NeVN0YXRlLCBhY3Rpb246IEFjdGlvblR5cGVzLCBhcHBTdGF0ZTogSU1TdGF0ZSk6IElNTXlTdGF0ZSA9PiB7ICAgICAgXHJcbiAgICAgIFxyXG4gICAgICBzd2l0Y2ggKGFjdGlvbi50eXBlKSB7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuQVVUSEVOVElDQVRFX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnYXV0aGVudGljYXRlJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9TQ0FMRUZBQ1RPUlNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdzY2FsZUZhY3RvcnMnLCBhY3Rpb24udmFsKTtcclxuICAgICAgICBcclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfUkFUSU5HU0NBTEVTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgncmF0aW5nU2NhbGVzJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VMRUNUX0FTU0VTU01FTlRfQUNUSU9OOlxyXG4gICAgICAgICAgY29uc3QgYXNzZXNzbWVudHMgPSBsb2NhbFN0YXRlLmFzc2Vzc21lbnRzLm1hcChhc3Nlc3MgPT4ge1xyXG4gICAgICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgICAuLi5hc3Nlc3MsXHJcbiAgICAgICAgICAgICAgaXNTZWxlY3RlZDogYXNzZXNzLmlkID09PSBhY3Rpb24udmFsLmlkLnRvTG93ZXJDYXNlKClcclxuICAgICAgICAgICAgIH1cclxuICAgICAgICAgIH0pXHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2Fzc2Vzc21lbnRzJywgYXNzZXNzbWVudHMpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfQVNTRVNTTUVOVFNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdhc3Nlc3NtZW50cycsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfUFJJT1JJVElFU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3ByaW9yaXRpZXMnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfTElGRUxJTkVTVEFUVVNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdzZWxlY3RlZExpZmVsaW5lU3RhdHVzJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuVE9HR0xFX0lORElDQVRPUl9FRElUSU5HOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdpc0luZGljYXRvckVkaXRpbmcnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdlcnJvcnMnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX0hBWkFSRFNfQUNUSU9OOiAgXHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2hhemFyZHMnLCBhY3Rpb24udmFsKVxyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfSEFaQVJEX1RZUEVTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnaGF6YXJkVHlwZXMnLCBhY3Rpb24udmFsKVxyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfT1JHQU5JWkFUSU9OX1RZUEVTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnb3JnYW5pemF0aW9uVHlwZXMnLCBhY3Rpb24udmFsKVxyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfT1JHQU5JWkFUSU9OU19BQ1RJT046XHJcbiAgICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnb3JnYW5pemF0aW9ucycsIGFjdGlvbi52YWwpXHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VUX0lERU5USVRZX0FDVElPTjogIFxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdpZGVudGl0eScsIGFjdGlvbi52YWwpO1xyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VUX1VTRVJfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCd1c2VyJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9URU1QTEFURVNfQUNUSU9OOiAgICAgICAgICBcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgndGVtcGxhdGVzJywgYWN0aW9uLnZhbCk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfVEVNUExBVEVfQUNUSU9OOlxyXG4gICAgICAgICAgbGV0IHRlbXBsYXRlcyA9IFsuLi5sb2NhbFN0YXRlLnRlbXBsYXRlc10ubWFwKHQgPT4ge1xyXG4gICAgICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgICAuLi50LFxyXG4gICAgICAgICAgICAgIGlzU2VsZWN0ZWQ6IHQuaWQgPT09IGFjdGlvbi52YWxcclxuICAgICAgICAgICAgIH0gXHJcbiAgICAgICAgICB9KVxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCd0ZW1wbGF0ZXMnLCB0ZW1wbGF0ZXMpICAgICAgICAgICAgXHJcbiAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlO1xyXG4gICAgICB9XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBnZXRTdG9yZUtleSgpIHtcclxuICAgIHJldHVybiAnY2xzc1N0YXRlJztcclxuICB9XHJcbn0iLCJleHBvcnQgY29uc3QgQ0xTU19BRE1JTiA9ICdDTFNTX0FkbWluJztcclxuZXhwb3J0IGNvbnN0IENMU1NfRURJVE9SID0gJ0NMU1NfRWRpdG9yJztcclxuZXhwb3J0IGNvbnN0IENMU1NfQVNTRVNTT1IgPSAnQ0xTU19Bc3Nlc3Nvcic7XHJcbmV4cG9ydCBjb25zdCBDTFNTX1ZJRVdFUiA9ICdDTFNTX1ZpZXdlcic7XHJcbmV4cG9ydCBjb25zdCBDTFNTX0ZPTExPV0VSUyA9ICdDTFNTIEZvbGxvd2Vycyc7XHJcblxyXG5leHBvcnQgY29uc3QgQkFTRUxJTkVfVEVNUExBVEVfTkFNRSA9ICdCYXNlbGluZSc7XHJcbmV4cG9ydCBjb25zdCBUT0tFTl9FUlJPUiA9ICdUb2tlbiBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgVEVNUExBVEVfVVJMX0VSUk9SID0gJ1RlbXBsYXRlIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IEFTU0VTU01FTlRfVVJMX0VSUk9SID0gJ0Fzc2Vzc21lbnQgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgT1JHQU5JWkFUSU9OX1VSTF9FUlJPUiA9ICdPcmdhbml6YXRpb24gRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgSEFaQVJEX1VSTF9FUlJPUiA9ICdIYXphcmQgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgSU5ESUNBVE9SX1VSTF9FUlJPUiA9ICdJbmRpY2F0b3IgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgQUxJR05NRU5UX1VSTF9FUlJPUiA9ICdBbGlnbm1lbnRzIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IExJRkVMSU5FX1VSTF9FUlJPUiA9ICdMaWZlbGluZSBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBDT01QT05FTlRfVVJMX0VSUk9SID0gJ0NvbXBvbmVudCBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBQUklPUklUWV9VUkxfRVJST1IgPSAnUHJpb3JpdHkgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgSU5DSURFTlRfVVJMX0VSUk9SID0gJ0luY2lkZW50IEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IFNBVklOR19TQU1FX0FTX0JBU0VMSU5FX0VSUk9SID0gJ0Jhc2VsaW5lIHRlbXBsYXRlIGNhbm5vdCBiZSB1cGRhdGVkLiBDaGFuZ2UgdGhlIHRlbXBsYXRlIG5hbWUgdG8gY3JlYXRlIGEgbmV3IG9uZS4nXHJcblxyXG5leHBvcnQgY29uc3QgU1RBQklMSVpJTkdfU0NBTEVfRkFDVE9SID0gJ1N0YWJpbGl6aW5nX1NjYWxlX0ZhY3Rvcic7XHJcbmV4cG9ydCBjb25zdCBERVNUQUJJTElaSU5HX1NDQUxFX0ZBQ1RPUiA9ICdEZXN0YWJpbGl6aW5nX1NjYWxlX0ZhY3Rvcic7XHJcbmV4cG9ydCBjb25zdCBVTkNIQU5HRURfU0NBTEVfRkFDVE9SID0gJ1VuY2hhbmdlZF9JbmRpY2F0b3JzJztcclxuZXhwb3J0IGNvbnN0IERFRkFVTFRfUFJJT1JJVFlfTEVWRUxTID0gXCJEZWZhdWx0X1ByaW9yaXR5X0xldmVsc1wiO1xyXG5leHBvcnQgY29uc3QgUkFOSyA9ICdJbXBvcnRhbmNlIG9mIEluZGljYXRvcic7XHJcbmV4cG9ydCBjb25zdCBMSUZFX1NBRkVUWSA9ICdMaWZlIFNhZmV0eSc7XHJcbmV4cG9ydCBjb25zdCBJTkNJREVOVF9TVEFCSUxJWkFUSU9OID0gJ0luY2lkZW50IFN0YWJpbGl6YXRpb24nO1xyXG5leHBvcnQgY29uc3QgUFJPUEVSVFlfUFJPVEVDVElPTiA9ICdQcm9wZXJ0eSBQcm90ZWN0aW9uJztcclxuZXhwb3J0IGNvbnN0IEVOVklST05NRU5UX1BSRVNFUlZBVElPTiA9ICdFbnZpcm9ubWVudCBQcmVzZXJ2YXRpb24nO1xyXG5cclxuZXhwb3J0IGNvbnN0IExJRkVfU0FGRVRZX1NDQUxFX0ZBQ1RPUiA9IDIwMDtcclxuZXhwb3J0IGNvbnN0IE9USEVSX1dFSUdIVFNfU0NBTEVfRkFDVE9SID0gMTAwO1xyXG5leHBvcnQgY29uc3QgTUFYSU1VTV9XRUlHSFQgPSA1O1xyXG5cclxuZXhwb3J0IGVudW0gVXBkYXRlQWN0aW9uIHtcclxuICAgIEhFQURFUiA9ICdoZWFkZXInLFxyXG4gICAgSU5ESUNBVE9SX05BTUUgPSAnSW5kaWNhdG9yIE5hbWUnLFxyXG4gICAgUFJJT1JJVElFUyA9ICdJbmRpY2F0b3IgUHJpb3JpdGllcycsXHJcbiAgICBORVdfSU5ESUNBVE9SID0gJ0NyZWF0ZSBOZXcgSW5kaWNhdG9yJyxcclxuICAgIERFTEVURV9JTkRJQ0FUT1IgPSAnRGVsZXRlIEluZGljYXRvcidcclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IElOQ0xVREVfSU5ESUNBVE9SID0gJ0ltcGFjdGVkIC0gWWVzIG9yIE5vJztcclxuZXhwb3J0IGNvbnN0IElOQ0xVREVfSU5ESUNBVE9SX0hFTFAgPSAnWWVzOiBUaGUgaW5kaWNhdG9yIHdpbGwgYmUgY29uc2lkZXJlZCBpbiB0aGUgYXNzZXNzbWVudC5cXG5ObzogVGhlIGluZGljYXRvciB3aWxsIG5vdCBiZSBjb25zaWRlcmVkLlxcblVua25vd246IE5vdCBzdXJlIHRvIGluY2x1ZGUgdGhlIGluZGljYXRvciBpbiBhc3Nlc3NtZW50Lic7XHJcblxyXG5leHBvcnQgY29uc3QgSU5ESUNBVE9SX1NUQVRVUyA9ICdJbmRpY2F0b3IgSW1wYWN0IFN0YXR1cyc7XHJcbmV4cG9ydCBjb25zdCBJTkRJQ0FUT1JfU1RBVFVTX0hFTFAgPSAnU3RhYmlsaXppbmc6IEhhcyB0aGUgaW5kaWNhdG9yIGJlZW4gaW1wcm92ZWQgb3IgaW1wcm92aW5nLlxcbkRlc3RhYmlsaXppbmc6IElzIHRoZSBpbmRpY2F0b3IgZGVncmFkaW5nLlxcblVuY2hhbmdlZDogTm8gc2lnbmlmaWNhbnQgaW1wcm92ZW1lbnQgc2luY2UgdGhlIGxhc3QgYXNzZXNzbWVudC4nO1xyXG5cclxuZXhwb3J0IGNvbnN0IENPTU1FTlQgPSAnQ29tbWVudCc7XHJcbmV4cG9ydCBjb25zdCBDT01NRU5UX0hFTFAgPSAnUHJvdmlkZSBqdXN0aWZpY2F0aW9uIGZvciB0aGUgc2VsZWN0ZWQgaW5kaWNhdG9yIHN0YXR1cy4nO1xyXG5cclxuZXhwb3J0IGNvbnN0IERFTEVURV9JTkRJQ0FUT1JfQ09ORklSTUFUSU9OID0gJ0FyZSB5b3Ugc3VyZSB5b3Ugd2FudCB0byBkZWxldGUgaW5kaWNhdG9yPyc7XHJcblxyXG4vL0NlbGwgV2VpZ2h0ID0gIFRyZW5kICogKCAoLTEqUmFuaykgKyA2XHJcbmV4cG9ydCBjb25zdCBDUklUSUNBTCA9IDI1O1xyXG5leHBvcnQgY29uc3QgQ1JJVElDQUxfTE9XRVJfQk9VTkRBUlkgPSAxMi41O1xyXG5leHBvcnQgY29uc3QgTU9ERVJBVEVfTE9XRVJfQk9VTkRBUlkgPSA1LjU7XHJcbmV4cG9ydCBjb25zdCBOT0RBVEFfQ09MT1IgPSAnIzkxOTM5NSc7XHJcbmV4cG9ydCBjb25zdCBOT0RBVEFfVkFMVUUgPSA5OTk5OTk7XHJcbmV4cG9ydCBjb25zdCBSRURfQ09MT1IgPSAnI0M1MjAzOCc7XHJcbmV4cG9ydCBjb25zdCBZRUxMT1dfQ09MT1IgPSAnI0ZCQkExNic7XHJcbmV4cG9ydCBjb25zdCBHUkVFTl9DT0xPUiA9ICcjNUU5QzQyJztcclxuZXhwb3J0IGNvbnN0IFNBVklOR19USU1FUiA9IDE1MDA7XHJcbmV4cG9ydCBjb25zdCBJTkRJQ0FUT1JfQ09NTUVOVF9MRU5HVEggPSAzMDA7XHJcblxyXG5leHBvcnQgY29uc3QgUE9SVEFMX1VSTCA9ICdodHRwczovL3d3dy5hcmNnaXMuY29tJztcclxuXHJcbmV4cG9ydCBjb25zdCBERUZBVUxUX0xJU1RJVEVNID0ge2lkOiAnMDAwJywgbmFtZTogJy1Ob25lLScsIHRpdGxlOiAnLU5vbmUtJ30gYXMgYW55O1xyXG5cclxuZXhwb3J0IGNvbnN0IFJBTktfTUVTU0FHRSA9ICdIb3cgaW1wb3J0YW50IGlzIHRoZSBpbmRpY2F0b3IgdG8geW91ciBqdXJpc2RpY3Rpb24gb3IgaGF6YXJkPyc7XHJcbmV4cG9ydCBjb25zdCBMSUZFX1NBRkVUWV9NRVNTQUdFID0gJ0hvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byBMaWZlIFNhZmV0eT8nO1xyXG5leHBvcnQgY29uc3QgUFJPUEVSVFlfUFJPVEVDVElPTl9NRVNTQUdFID0gJ0hvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byBQcm9wZXJ0eSBQcm90ZWN0aW9uPyc7XHJcbmV4cG9ydCBjb25zdCBFTlZJUk9OTUVOVF9QUkVTRVJWQVRJT05fTUVTU0FHRSA9ICdIb3cgaW1wb3J0YW50IGlzIHRoZSBpbmRpY2F0b3IgdG8gRW52aXJvbm1lbnQgUHJlc2VydmF0aW9uPyc7XHJcbmV4cG9ydCBjb25zdCBJTkNJREVOVF9TVEFCSUxJWkFUSU9OX01FU1NBR0UgPSAnSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIEluY2lkZW50IFN0YWJpbGl6YXRpb24/JztcclxuXHJcbmV4cG9ydCBjb25zdCBPVkVSV1JJVEVfU0NPUkVfTUVTU0FHRSA9ICdBIGNvbXBsZXRlZCBhc3Nlc3NtZW50IGNhbm5vdCBiZSBlZGl0ZWQuIEFyZSB5b3Ugc3VyZSB5b3Ugd2FudCB0byBjb21wbGV0ZSB0aGlzIGFzc2Vzc21lbnQ/JztcclxuXHJcbmV4cG9ydCBjb25zdCBVU0VSX0JPWF9FTEVNRU5UX0lEID0gJ3VzZXJCb3hFbGVtZW50JztcclxuXHJcbmV4cG9ydCBjb25zdCBEQVRBX0xJQlJBUllfVElUTEUgPSAnRGF0YSBMaWJyYXJ5JztcclxuZXhwb3J0IGNvbnN0IEFOQUxZU0lTX1JFUE9SVElOR19USVRMRSA9ICdBbmFseXNpcyAmIFJlcG9ydGluZyc7XHJcblxyXG4iLCJpbXBvcnQgeyBVc2VyU2Vzc2lvbiB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1hdXRoXCI7XHJcbmltcG9ydCB7IHF1ZXJ5RmVhdHVyZXMsIElRdWVyeUZlYXR1cmVzUmVzcG9uc2UsIFxyXG4gICAgSVJlbGF0ZWRSZWNvcmRHcm91cCwgcXVlcnlSZWxhdGVkLCB1cGRhdGVGZWF0dXJlcywgXHJcbiAgICBhZGRGZWF0dXJlcywgZGVsZXRlRmVhdHVyZXMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllclwiO1xyXG5pbXBvcnQgeyBJRmVhdHVyZVNldCwgSUZlYXR1cmUgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtdHlwZXNcIjtcclxuaW1wb3J0IHsgQXBwV2lkZ2V0Q29uZmlnIH0gZnJvbSBcIi4vZGF0YS1kZWZpbml0aW9uc1wiO1xyXG5pbXBvcnQgeyBsb2csIExvZ1R5cGUgfSBmcm9tIFwiLi9sb2dnZXJcIjtcclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKSB7XHJcbiAgcmV0dXJuIFVzZXJTZXNzaW9uLmZyb21DcmVkZW50aWFsKGNvbmZpZy5jcmVkZW50aWFsKTtcclxufVxyXG4gIFxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcXVlcnlUYWJsZUZlYXR1cmVTZXQodXJsOiBzdHJpbmcsIHdoZXJlOiBzdHJpbmcsIFxyXG4gIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVNldD4ge1xyXG4gIFxyXG4gICAgdHJ5e1xyXG5cclxuICAgICAgY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG4gICAgICByZXR1cm4gcXVlcnlGZWF0dXJlcyh7IHVybCwgd2hlcmUsIGF1dGhlbnRpY2F0aW9uLCBoaWRlVG9rZW46IHRydWUgfSlcclxuICAgICAgLnRoZW4oKHJlc3BvbnNlOiBJUXVlcnlGZWF0dXJlc1Jlc3BvbnNlKSA9PiB7XHJcbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlXHJcbiAgICAgIH0pXHJcblxyXG4gICAgfWNhdGNoKGUpe1xyXG4gICAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ3F1ZXJ5VGFibGVGZWF0dXJlU2V0JylcclxuICAgIH0gICAgXHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBxdWVyeVRhYmxlRmVhdHVyZXModXJsOiBzdHJpbmcsIHdoZXJlOiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVtdPiB7XHJcblxyXG4gY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG5cclxuICB0cnl7XHJcbiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgcXVlcnlGZWF0dXJlcyh7IHVybCwgd2hlcmUsIGF1dGhlbnRpY2F0aW9uLCAgaHR0cE1ldGhvZDonUE9TVCcsIGhpZGVUb2tlbjogdHJ1ZSB9KVxyXG4gICAgICByZXR1cm4gKHJlc3BvbnNlIGFzIElRdWVyeUZlYXR1cmVzUmVzcG9uc2UpLmZlYXR1cmVzO1xyXG4gIH1jYXRjaChlKXtcclxuICAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdxdWVyeVRhYmxlRmVhdHVyZXMnKVxyXG4gICAgICBsb2codXJsLCBMb2dUeXBlLldSTiwgd2hlcmUpO1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0ICBhc3luYyBmdW5jdGlvbiBxdWVyeVJlbGF0ZWRUYWJsZUZlYXR1cmVzKG9iamVjdElkczogbnVtYmVyW10sXHJcbnVybDogc3RyaW5nLCByZWxhdGlvbnNoaXBJZDogbnVtYmVyLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SVJlbGF0ZWRSZWNvcmRHcm91cFtdPiB7XHJcblxyXG5jb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7XHJcblxyXG5jb25zdCByZXNwb25zZSA9IGF3YWl0IHF1ZXJ5UmVsYXRlZCh7XHJcbiAgICBvYmplY3RJZHMsXHJcbiAgICB1cmwsIHJlbGF0aW9uc2hpcElkLFxyXG4gICAgYXV0aGVudGljYXRpb24sXHJcbiAgICBoaWRlVG9rZW46IHRydWVcclxufSk7XHJcbnJldHVybiByZXNwb25zZS5yZWxhdGVkUmVjb3JkR3JvdXBzO1xyXG59XHJcblxyXG5leHBvcnQgIGFzeW5jIGZ1bmN0aW9uIHVwZGF0ZVRhYmxlRmVhdHVyZSh1cmw6IHN0cmluZywgYXR0cmlidXRlczogYW55LCBjb25maWc6IEFwcFdpZGdldENvbmZpZykge1xyXG4gIGNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTtcclxuXHJcbiAgcmV0dXJuIHVwZGF0ZUZlYXR1cmVzKHtcclxuICAgICAgdXJsLFxyXG4gICAgICBhdXRoZW50aWNhdGlvbixcclxuICAgICAgZmVhdHVyZXM6IFt7XHJcbiAgICAgIGF0dHJpYnV0ZXNcclxuICAgICAgfV0sXHJcbiAgICAgIHJvbGxiYWNrT25GYWlsdXJlOiB0cnVlXHJcbiAgfSlcclxufVxyXG5cclxuZXhwb3J0ICBhc3luYyBmdW5jdGlvbiB1cGRhdGVUYWJsZUZlYXR1cmVzKHVybDogc3RyaW5nLCBmZWF0dXJlczogSUZlYXR1cmVbXSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpIHtcclxuICBjb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7ICBcclxuICByZXR1cm4gdXBkYXRlRmVhdHVyZXMoe1xyXG4gICAgICB1cmwsXHJcbiAgICAgIGF1dGhlbnRpY2F0aW9uLFxyXG4gICAgICBmZWF0dXJlc1xyXG4gIH0pXHJcbn1cclxuXHJcbmV4cG9ydCAgYXN5bmMgZnVuY3Rpb24gYWRkVGFibGVGZWF0dXJlcyh1cmw6IHN0cmluZywgZmVhdHVyZXM6IGFueVtdLCBjb25maWc6IEFwcFdpZGdldENvbmZpZykge1xyXG5cclxuICBjb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7XHJcblxyXG4gIHRyeXtcclxuICAgIHJldHVybiBhZGRGZWF0dXJlcyh7IHVybCwgZmVhdHVyZXMsIGF1dGhlbnRpY2F0aW9uLCByb2xsYmFja09uRmFpbHVyZTogdHJ1ZSB9KTtcclxuICB9Y2F0Y2goZSl7XHJcbiAgICBjb25zb2xlLmxvZyhlKTtcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlVGFibGVGZWF0dXJlcyh1cmw6IHN0cmluZywgb2JqZWN0SWRzOiBudW1iZXJbXSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpIHtcclxuXHJcbiAgICBjb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7XHJcbiAgICByZXR1cm4gZGVsZXRlRmVhdHVyZXMoeyB1cmwsIG9iamVjdElkcywgYXV0aGVudGljYXRpb24sIHJvbGxiYWNrT25GYWlsdXJlOiB0cnVlIH0pO1xyXG59IiwiZXhwb3J0IGVudW0gTG9nVHlwZSB7XHJcbiAgICBJTkZPID0gJ0luZm9ybWF0aW9uJyxcclxuICAgIFdSTiA9ICdXYXJuaW5nJyxcclxuICAgIEVSUk9SID0gJ0Vycm9yJ1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gbG9nKG1lc3NhZ2U6IHN0cmluZywgdHlwZT86IExvZ1R5cGUsIGZ1bmM/OiBzdHJpbmcpe1xyXG4gICAgaWYoIXR5cGUpe1xyXG4gICAgICAgIHR5cGUgPSBMb2dUeXBlLklORk9cclxuICAgIH1cclxuXHJcbiAgICBpZihmdW5jKXtcclxuICAgICAgICBmdW5jID0gYCgke2Z1bmN9KWA7XHJcbiAgICB9XHJcblxyXG4gICAgbWVzc2FnZSA9IGBbJHtuZXcgRGF0ZSgpLnRvTG9jYWxlU3RyaW5nKCl9XTogJHttZXNzYWdlfSAke2Z1bmN9YDtcclxuXHJcbiAgICBzd2l0Y2godHlwZSl7XHJcbiAgICAgICAgY2FzZSBMb2dUeXBlLklORk86XHJcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKG1lc3NhZ2UpO1xyXG4gICAgICAgICAgICBicmVhaztcclxuICAgICAgICBjYXNlIExvZ1R5cGUuV1JOOlxyXG4gICAgICAgICAgICBjb25zb2xlLndhcm4obWVzc2FnZSk7XHJcbiAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIGNhc2UgTG9nVHlwZS5FUlJPUjpcclxuICAgICAgICAgICAgY29uc29sZS5lcnJvcihtZXNzYWdlKTtcclxuICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgICAgY29uc29sZS5sb2cobWVzc2FnZSk7XHJcbiAgICB9XHJcbn0iLCJcclxuZXhwb3J0IGNvbnN0IHNvcnRPYmplY3QgPSA8VD4ob2JqOiBUW10sIHByb3A6IHN0cmluZywgcmV2ZXJzZT86Ym9vbGVhbik6IFRbXSA9PiB7XHJcbiAgIHJldHVybiBvYmouc29ydCgoYTpULCBiOlQpID0+IHtcclxuICAgICAgaWYoYVtwcm9wXSA+IGJbcHJvcF0pe1xyXG4gICAgICAgIHJldHVybiByZXZlcnNlID8gLTEgOiAxXHJcbiAgICAgIH1cclxuICAgICAgaWYoYVtwcm9wXSA8IGJbcHJvcF0pe1xyXG4gICAgICAgIHJldHVybiByZXZlcnNlID8gMSA6IC0xXHJcbiAgICAgIH1cclxuICAgICAgcmV0dXJuIDA7XHJcbiAgfSk7XHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBjcmVhdGVHdWlkID0gKCkgPT57XHJcbiAgcmV0dXJuICd4eHh4eHh4eC14eHh4LTR4eHgteXh4eC14eHh4eHh4eHh4eHgnLnJlcGxhY2UoL1t4eV0vZywgZnVuY3Rpb24oYykge1xyXG4gICAgdmFyIHIgPSBNYXRoLnJhbmRvbSgpICogMTYgfCAwLCB2ID0gYyA9PSAneCcgPyByIDogKHIgJiAweDMgfCAweDgpO1xyXG4gICAgcmV0dXJuIHYudG9TdHJpbmcoMTYpO1xyXG4gIH0pO1xyXG59XHJcblxyXG5leHBvcnQgY29uc3QgcGFyc2VEYXRlID0gKG1pbGxpc2Vjb25kczogbnVtYmVyKTogc3RyaW5nID0+IHtcclxuICBpZighbWlsbGlzZWNvbmRzKXtcclxuICAgIHJldHVyblxyXG4gIH1cclxuICAgcmV0dXJuIG5ldyBEYXRlKG1pbGxpc2Vjb25kcykudG9Mb2NhbGVTdHJpbmcoKTtcclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IHNhdmVEYXRlID0gKGRhdGU6IHN0cmluZyk6IG51bWJlciA9PiB7XHJcbiAgIHJldHVybiBuZXcgRGF0ZShkYXRlKS5nZXRNaWxsaXNlY29uZHMoKTtcclxufVxyXG5cclxuXHJcbi8vUmVmZXJlbmNlOiBodHRwczovL3N0YWNrb3ZlcmZsb3cuY29tL3F1ZXN0aW9ucy82MTk1MzM1L2xpbmVhci1yZWdyZXNzaW9uLWluLWphdmFzY3JpcHRcclxuLy8gZXhwb3J0IGNvbnN0IGxpbmVhclJlZ3Jlc3Npb24gPSAoeVZhbHVlczogbnVtYmVyW10sIHhWYWx1ZXM6IG51bWJlcltdKSA9PntcclxuLy8gICBkZWJ1Z2dlcjtcclxuLy8gICBjb25zdCB5ID0geVZhbHVlcztcclxuLy8gICBjb25zdCB4ID0geFZhbHVlcztcclxuXHJcbi8vICAgdmFyIGxyID0ge3Nsb3BlOiBOYU4sIGludGVyY2VwdDogTmFOLCByMjogTmFOfTtcclxuLy8gICB2YXIgbiA9IHkubGVuZ3RoO1xyXG4vLyAgIHZhciBzdW1feCA9IDA7XHJcbi8vICAgdmFyIHN1bV95ID0gMDtcclxuLy8gICB2YXIgc3VtX3h5ID0gMDtcclxuLy8gICB2YXIgc3VtX3h4ID0gMDtcclxuLy8gICB2YXIgc3VtX3l5ID0gMDtcclxuXHJcbi8vICAgZm9yICh2YXIgaSA9IDA7IGkgPCB5Lmxlbmd0aDsgaSsrKSB7XHJcblxyXG4vLyAgICAgICBzdW1feCArPSB4W2ldO1xyXG4vLyAgICAgICBzdW1feSArPSB5W2ldO1xyXG4vLyAgICAgICBzdW1feHkgKz0gKHhbaV0qeVtpXSk7XHJcbi8vICAgICAgIHN1bV94eCArPSAoeFtpXSp4W2ldKTtcclxuLy8gICAgICAgc3VtX3l5ICs9ICh5W2ldKnlbaV0pO1xyXG4vLyAgIH0gXHJcblxyXG4vLyAgIGxyLnNsb3BlID0gKG4gKiBzdW1feHkgLSBzdW1feCAqIHN1bV95KSAvIChuKnN1bV94eCAtIHN1bV94ICogc3VtX3gpO1xyXG4vLyAgIGxyLmludGVyY2VwdCA9IChzdW1feSAtIGxyLnNsb3BlICogc3VtX3gpL247XHJcbi8vICAgbHIucjIgPSBNYXRoLnBvdygobipzdW1feHkgLSBzdW1feCpzdW1feSkvTWF0aC5zcXJ0KChuKnN1bV94eC1zdW1feCpzdW1feCkqKG4qc3VtX3l5LXN1bV95KnN1bV95KSksMik7XHJcbi8vICAgcmV0dXJuIGxyO1xyXG4vLyB9XHJcblxyXG5TdHJpbmcucHJvdG90eXBlLnRvVGl0bGVDYXNlID0gZnVuY3Rpb24gKCkge1xyXG4gIHJldHVybiB0aGlzLnJlcGxhY2UoL1xcd1xcUyovZywgZnVuY3Rpb24odHh0KXtyZXR1cm4gdHh0LmNoYXJBdCgwKS50b1VwcGVyQ2FzZSgpICsgdHh0LnN1YnN0cigxKS50b0xvd2VyQ2FzZSgpO30pO1xyXG59O1xyXG5cclxuQXJyYXkucHJvdG90eXBlLm9yZGVyQnkgPSBmdW5jdGlvbjxUPihwcm9wLCByZXZlcnNlKSB7XHJcbiAgcmV0dXJuIHRoaXMuc29ydCgoYTpULCBiOlQpID0+IHtcclxuICAgIGlmKGFbcHJvcF0gPiBiW3Byb3BdKXtcclxuICAgICAgcmV0dXJuIHJldmVyc2UgPyAtMSA6IDFcclxuICAgIH1cclxuICAgIGlmKGFbcHJvcF0gPCBiW3Byb3BdKXtcclxuICAgICAgcmV0dXJuIHJldmVyc2UgPyAxIDogLTFcclxuICAgIH1cclxuICAgIHJldHVybiAwO1xyXG4gIH0pO1xyXG59XHJcblxyXG5BcnJheS5wcm90b3R5cGUuZ3JvdXBCeSA9IGZ1bmN0aW9uKGtleSkge1xyXG4gIHJldHVybiB0aGlzLnJlZHVjZShmdW5jdGlvbihydiwgeCkge1xyXG4gICAgKHJ2W3hba2V5XV0gPSBydlt4W2tleV1dIHx8IFtdKS5wdXNoKHgpO1xyXG4gICAgcmV0dXJuIHJ2O1xyXG4gIH0sIHt9KTtcclxufTtcclxuIiwiaW1wb3J0IHsgVGV4dElucHV0LCBUZXh0QXJlYSB9IGZyb20gXCJqaW11LXVpXCJcclxuaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiXHJcbmltcG9ydCB7IExhYmVsXHJcbiAgICAgIH0gZnJvbSBcImppbXUtdWlcIlxyXG5pbXBvcnQgeyBJQ29kZWRWYWx1ZSB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC10eXBlc1wiXHJcbmltcG9ydCB7IGRpc3BhdGNoQWN0aW9uLCAgc2F2ZUhhemFyZCB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2FwaVwiXHJcbmltcG9ydCB7IEhhemFyZCB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2RhdGEtZGVmaW5pdGlvbnNcIlxyXG5pbXBvcnQgeyBDTFNTQWN0aW9uS2V5cyB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2Nsc3Mtc3RvcmVcIlxyXG5pbXBvcnQgeyBDbHNzRHJvcGRvd24gfSBmcm9tIFwiLi9jbHNzLWRyb3Bkb3duXCJcclxuaW1wb3J0IHsgQ2xzc01vZGFsIH0gZnJvbSBcIi4vY2xzcy1tb2RhbFwiO1xyXG5pbXBvcnQgeyBSZWFjdFJlZHV4IH0gZnJvbSBcImppbXUtY29yZVwiXHJcbmNvbnN0IHsgdXNlU2VsZWN0b3IgfSA9IFJlYWN0UmVkdXg7XHJcblxyXG5leHBvcnQgY29uc3QgQWRkSGF6YXJkV2lkZ2V0PSh7cHJvcHMsIHZpc2libGUsIHRvZ2dsZSwgc2V0SGF6YXJkfTpcclxuICAgIHtwcm9wczogYW55LCB2aXNpYmxlOiBib29sZWFuLCB0b2dnbGU6IGFueSwgc2V0SGF6YXJkPzogYW55fSkgPT57XHJcblxyXG4gICAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpOyAgICBcclxuICAgIGNvbnN0IFtpc1Zpc2libGUsIHNldFZpc2libGVdID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpOyBcclxuICAgIGNvbnN0IFtuYW1lLCBzZXROYW1lXSA9IFJlYWN0LnVzZVN0YXRlKCcnKTsgICBcclxuICAgIGNvbnN0IFtkZXNjcmlwdGlvbiwgc2V0RGVzY3JpcHRpb25dID0gUmVhY3QudXNlU3RhdGUoJycpOyBcclxuICAgIGNvbnN0IFtoYXphcmRUeXBlcywgc2V0SGF6YXJkVHlwZXNdID0gUmVhY3QudXNlU3RhdGU8SUNvZGVkVmFsdWVbXT4oW10pO1xyXG4gICAgY29uc3QgW3NlbGVjdGVkSGF6YXJkVHlwZSwgc2V0U2VsZWN0ZWRIYXphcmRUeXBlXSA9IFJlYWN0LnVzZVN0YXRlPElDb2RlZFZhbHVlPihudWxsKTtcclxuICAgIGNvbnN0IFtjb25maWcsIHNldENvbmZpZ10gPSBSZWFjdC51c2VTdGF0ZShudWxsKVxyXG5cclxuICAgIGNvbnN0IGNyZWRlbnRpYWwgPSB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4ge1xyXG4gICAgICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGU/LmF1dGhlbnRpY2F0ZTtcclxuICAgIH0pXHJcblxyXG4gICAgY29uc3QgaGF6YXJkcyA9IHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KSA9PiB7XHJcbiAgICAgICAgcmV0dXJuIHN0YXRlLmNsc3NTdGF0ZT8uaGF6YXJkcyBhcyBIYXphcmRbXTtcclxuICAgICB9KVxyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICAgICAgaWYoY3JlZGVudGlhbCl7XHJcbiAgICAgICAgICAgc2V0Q29uZmlnKHsuLi4gcHJvcHMuY29uZmlnLCBjcmVkZW50aWFsOmNyZWRlbnRpYWx9KTsgICAgICAgICAgICBcclxuICAgICAgICB9XHJcbiAgICB9LCBbY3JlZGVudGlhbF0pXHJcblxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpID0+IHtcclxuICAgICAgICBpZihoYXphcmRzICYmIGhhemFyZHMubGVuZ3RoID4gMCl7XHJcbiAgICAgICAgICAgIGNvbnN0IHR5cGVzID0gaGF6YXJkc1sxXS5kb21haW5zO1xyXG4gICAgICAgICAgICAodHlwZXMgYXMgYW55KS5vcmRlckJ5KCduYW1lJyk7XHJcbiAgICAgICAgICAgICBzZXRIYXphcmRUeXBlcyh0eXBlcylcclxuOyAgICAgICAgfVxyXG4gICAgfSwgW2hhemFyZHNdKVxyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKT0+e1xyXG4gICAgICAgIHNldFZpc2libGUodmlzaWJsZSk7XHJcbiAgICAgICAgc2V0TmFtZSgnJyk7XHJcbiAgICAgICAgc2V0RGVzY3JpcHRpb24oJycpO1xyXG4gICAgICAgIHNldFNlbGVjdGVkSGF6YXJkVHlwZShudWxsKTtcclxuICAgIH0sIFt2aXNpYmxlXSkgICBcclxuXHJcbiAgICBjb25zdCBzYXZlTmV3SGF6YXJkPWFzeW5jICgpPT57XHJcblxyXG4gICAgICAgIGNvbnN0IGV4aXN0ID0gaGF6YXJkcy5maW5kKGggPT4gaC5uYW1lLnRvTG93ZXJDYXNlKCkgPT09IG5hbWUudG9Mb3dlckNhc2UoKS50cmltKCkpO1xyXG4gICAgICAgIGlmKGV4aXN0KXtcclxuICAgICAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgYEhhemFyZDogJHtuYW1lfSBhbHJlYWR5IGV4aXN0c2ApO1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBzZXRMb2FkaW5nKHRydWUpO1xyXG5cclxuICAgICAgICB0cnl7XHJcbiAgICAgICAgICAgIGxldCBuZXdIYXphcmQgPSB7XHJcbiAgICAgICAgICAgICAgICBuYW1lLFxyXG4gICAgICAgICAgICAgICAgdGl0bGU6IG5hbWUsXHJcbiAgICAgICAgICAgICAgICB0eXBlOiBzZWxlY3RlZEhhemFyZFR5cGUsXHJcbiAgICAgICAgICAgICAgICBkZXNjcmlwdGlvblxyXG4gICAgICAgICAgICB9IGFzIEhhemFyZDtcclxuICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBzYXZlSGF6YXJkKGNvbmZpZywgbmV3SGF6YXJkKTtcclxuICAgICAgICAgICAgY29uc29sZS5sb2cocmVzcG9uc2UpO1xyXG4gICAgICAgICAgICBpZihyZXNwb25zZS5lcnJvcnMpe1xyXG4gICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoU3RyaW5nKHJlc3BvbnNlLmVycm9ycykpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIFxyXG4gICAgICAgICAgICBuZXdIYXphcmQgPSByZXNwb25zZS5kYXRhO1xyXG4gICAgICAgICAgICBuZXdIYXphcmQuZG9tYWlucyA9IGhhemFyZHNbMV0uZG9tYWlucztcclxuXHJcbiAgICAgICAgICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLkxPQURfSEFaQVJEU19BQ1RJT04sXHJcbiAgICAgICAgICAgICAgIFsuLi5oYXphcmRzLCBuZXdIYXphcmRdKVxyXG5cclxuICAgICAgICAgICAgc2V0SGF6YXJkKG5ld0hhemFyZCk7XHJcbiAgICAgICAgICAgIHRvZ2dsZShmYWxzZSk7XHJcbiAgICAgICAgfWNhdGNoKGVycil7XHJcbiAgICAgICAgICAgY29uc29sZS5sb2coZXJyKTtcclxuICAgICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCBlcnIubWVzc2FnZSk7XHJcbiAgICAgICAgfWZpbmFsbHl7XHJcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gKFxyXG4gICAgICAgIDxDbHNzTW9kYWwgdGl0bGU9XCJBZGQgTmV3IEhhemFyZFwiXHJcbiAgICAgICAgICAgIGRpc2FibGU9eyEobmFtZSAmJiBzZWxlY3RlZEhhemFyZFR5cGUpfSAgc2F2ZT17c2F2ZU5ld0hhemFyZH0gXHJcbiAgICAgICAgICAgIHRvZ2dsZVZpc2liaWxpdHk9e3RvZ2dsZX0gdmlzaWJsZT17aXNWaXNpYmxlfVxyXG4gICAgICAgICAgICBsb2FkaW5nPXtsb2FkaW5nfT5cclxuICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwiaGF6YXJkc1wiPlxyXG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJtb2RhbC1pdGVtXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgPExhYmVsIGNoZWNrPkhhemFyZCBOYW1lPHNwYW4gc3R5bGU9e3tjb2xvcjogJ3JlZCd9fT4qPC9zcGFuPjwvTGFiZWw+XHJcbiAgICAgICAgICAgICAgICAgICAgPFRleHRJbnB1dCBvbkNoYW5nZT17KGUpPT4gc2V0TmFtZShlLnRhcmdldC52YWx1ZSl9IFxyXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlPXtuYW1lfT48L1RleHRJbnB1dD5cclxuICAgICAgICAgICAgICAgIDwvZGl2PlxyXG5cclxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibW9kYWwtaXRlbVwiPlxyXG4gICAgICAgICAgICAgICAgICAgIDxMYWJlbCBjaGVjaz5IYXphcmQgVHlwZTxzcGFuIHN0eWxlPXt7Y29sb3I6ICdyZWQnfX0+Kjwvc3Bhbj48L0xhYmVsPlxyXG4gICAgICAgICAgICAgICAgICAgIDxDbHNzRHJvcGRvd24gaXRlbXM9e2hhemFyZFR5cGVzfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaXRlbT17c2VsZWN0ZWRIYXphcmRUeXBlfSBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGV0YWJsZT17ZmFsc2V9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZXRJdGVtPXtzZXRTZWxlY3RlZEhhemFyZFR5cGV9IC8+IFxyXG4gICAgICAgICAgICAgICAgPC9kaXY+ICAgICAgIFxyXG5cclxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibW9kYWwtaXRlbVwiPlxyXG4gICAgICAgICAgICAgICAgICAgIDxMYWJlbCBjaGVjaz5EZXNjcmlwdGlvbiBvZiBIYXphcmQgKE9wdGlvbmFsKTwvTGFiZWw+XHJcbiAgICAgICAgICAgICAgICAgICAgPFRleHRBcmVhXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbHVlPXtkZXNjcmlwdGlvbn1cclxuICAgICAgICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhlKSA9PiBzZXREZXNjcmlwdGlvbihlLnRhcmdldC52YWx1ZSl9XHJcbiAgICAgICAgICAgICAgICAgICAgLz5cclxuICAgICAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgICAgICA8L2Rpdj4gIFxyXG4gICAgICAgIDwvQ2xzc01vZGFsPlxyXG4gICAgKVxyXG59IiwiaW1wb3J0IHsgVGV4dElucHV0LCBCdXR0b24sIE1vZGFsLCBNb2RhbEJvZHksIE1vZGFsRm9vdGVyLCBNb2RhbEhlYWRlciB9IGZyb20gXCJqaW11LXVpXCJcclxuaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiXHJcbmltcG9ydCB7IExhYmVsIH0gZnJvbSBcImppbXUtdWlcIlxyXG5pbXBvcnQgeyBPcmdhbml6YXRpb24gfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9kYXRhLWRlZmluaXRpb25zXCJcclxuaW1wb3J0IHsgZGlzcGF0Y2hBY3Rpb24sIHNhdmVPcmdhbml6YXRpb24gfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9hcGlcIlxyXG5pbXBvcnQgeyBDTFNTQWN0aW9uS2V5cyB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2Nsc3Mtc3RvcmVcIlxyXG5pbXBvcnQgeyBJQ29kZWRWYWx1ZSB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC10eXBlc1wiXHJcbmltcG9ydCBDbHNzTG9hZGluZyBmcm9tIFwiLi9jbHNzLWxvYWRpbmdcIlxyXG5pbXBvcnQgeyBDbHNzRHJvcGRvd24gfSBmcm9tIFwiLi9jbHNzLWRyb3Bkb3duXCI7XHJcbmltcG9ydCB7IFJlYWN0UmVkdXggfSBmcm9tIFwiamltdS1jb3JlXCJcclxuaW1wb3J0IHsgQ2xzc01vZGFsIH0gZnJvbSBcIi4vY2xzcy1tb2RhbFwiXHJcbmltcG9ydCB7IE9yZ2FuaXphdGlvbnNEcm9wZG93biB9IGZyb20gXCIuL2Nsc3Mtb3JnYW5pemF0aW9ucy1kcm9wZG93blwiXHJcbmNvbnN0IHsgdXNlU2VsZWN0b3IgfSA9IFJlYWN0UmVkdXg7XHJcblxyXG5leHBvcnQgY29uc3QgQWRkT3JnYW5pemF0b25XaWRnZXQ9KHtwcm9wc0NvbmZpZywgdmlzaWJsZSwgdG9nZ2xlLCBzZXRPcmdhbml6YXRpb259KSA9PntcclxuXHJcbiAgICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSBSZWFjdC51c2VTdGF0ZShmYWxzZSk7ICAgIFxyXG4gICAgY29uc3QgW2lzVmlzaWJsZSwgc2V0VmlzaWJsZV0gPSBSZWFjdC51c2VTdGF0ZShmYWxzZSk7IFxyXG4gICAgY29uc3QgW29yZ2FuaXphdGlvbk5hbWUsIHNldE9yZ2FuaXphdGlvbk5hbWVdID0gUmVhY3QudXNlU3RhdGUoJycpOyAgICBcclxuICAgIGNvbnN0IFtvcmdhbml6YXRpb25UeXBlcywgc2V0T3JnYW5pemF0aW9uVHlwZXNdID0gUmVhY3QudXNlU3RhdGU8SUNvZGVkVmFsdWVbXT4oW10pO1xyXG4gICAgY29uc3QgW3NlbGVjdGVkT3JnYW5pemF0aW9uVHlwZSwgc2V0U2VsZWN0ZWRPcmdhbml6YXRpb25UeXBlXSA9IFJlYWN0LnVzZVN0YXRlPElDb2RlZFZhbHVlPihudWxsKTtcclxuICAgIGNvbnN0IFtzZWxlY3RlZFBhcmVudE9yZ2FuaXphdGlvbiwgc2V0U2VsZWN0ZWRQYXJlbnRPcmdhbml6YXRpb25dID0gUmVhY3QudXNlU3RhdGU8T3JnYW5pemF0aW9uPihudWxsKTtcclxuICAgIGNvbnN0IFtjb25maWcsIHNldENvbmZpZ10gPSBSZWFjdC51c2VTdGF0ZShudWxsKTtcclxuXHJcbiAgICBjb25zdCBvcmdhbml6YXRpb25zID0gdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgICAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy5vcmdhbml6YXRpb25zIGFzIE9yZ2FuaXphdGlvbltdO1xyXG4gICAgIH0pXHJcblxyXG4gICAgIGNvbnN0IGNyZWRlbnRpYWwgPSB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4ge1xyXG4gICAgICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGU/LmF1dGhlbnRpY2F0ZTtcclxuICAgIH0pXHJcbiAgICAgXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCk9PnsgXHJcbiAgICAgICAgc2V0VmlzaWJsZSh2aXNpYmxlKTtcclxuICAgICAgICBzZXRPcmdhbml6YXRpb25OYW1lKCcnKTtcclxuICAgICAgICBzZXRTZWxlY3RlZE9yZ2FuaXphdGlvblR5cGUobnVsbCk7XHJcbiAgICB9LCBbdmlzaWJsZV0pICAgXHJcblxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpID0+IHtcclxuICAgICAgICBpZihjcmVkZW50aWFsKXtcclxuICAgICAgICAgICBzZXRDb25maWcoey4uLnByb3BzQ29uZmlnLCBjcmVkZW50aWFsfSk7ICAgICAgICAgICAgXHJcbiAgICAgICAgfVxyXG4gICAgfSwgW2NyZWRlbnRpYWxdKVxyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICAgIGlmKG9yZ2FuaXphdGlvbnMgJiYgb3JnYW5pemF0aW9ucy5sZW5ndGggPiAwKXtcclxuICAgICAgICBjb25zdCB0eXBlcyA9IG9yZ2FuaXphdGlvbnNbMV0uZG9tYWlucztcclxuICAgICAgICAodHlwZXMgYXMgYW55KT8ub3JkZXJCeSgnbmFtZScpO1xyXG4gICAgICAgIHNldE9yZ2FuaXphdGlvblR5cGVzKHR5cGVzKTtcclxuICAgICAgfVxyXG4gICAgfSwgW29yZ2FuaXphdGlvbnNdKVxyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKT0+e1xyXG4gICAgICAgIHNldFNlbGVjdGVkUGFyZW50T3JnYW5pemF0aW9uKG9yZ2FuaXphdGlvbnNbMF0pO1xyXG4gICAgfSwgW29yZ2FuaXphdGlvbnNdKVxyXG5cclxuICAgIGNvbnN0IHNhdmUgPSBhc3luYyAoKSA9PiB7XHJcbiAgICAgICAgY29uc3QgZXhpc3RzID0gb3JnYW5pemF0aW9ucy5maW5kKG8gPT4gby5uYW1lID09PSBvcmdhbml6YXRpb25OYW1lKTtcclxuICAgICAgICBpZihleGlzdHMpe1xyXG4gICAgICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCBgT3JnYW5pemF0aW9uOiAke29yZ2FuaXphdGlvbk5hbWV9IGFscmVhZHkgZXhpc3RzYCk7XHJcbiAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICB9XHJcbiAgICAgICAgc2V0TG9hZGluZyh0cnVlKTtcclxuICAgICAgICB0cnl7XHJcbiAgICAgICAgICAgIGxldCBuZXdPcmdhbml6YXRpb24gPSB7XHJcbiAgICAgICAgICAgICAgICBuYW1lOiBvcmdhbml6YXRpb25OYW1lLFxyXG4gICAgICAgICAgICAgICAgdGl0bGU6IG9yZ2FuaXphdGlvbk5hbWUsXHJcbiAgICAgICAgICAgICAgICB0eXBlOiBzZWxlY3RlZE9yZ2FuaXphdGlvblR5cGUsXHJcbiAgICAgICAgICAgICAgICBwYXJlbnRJZDogc2VsZWN0ZWRQYXJlbnRPcmdhbml6YXRpb24uaWQgIT09ICcwMDAnID8gc2VsZWN0ZWRQYXJlbnRPcmdhbml6YXRpb24uaWQgOiBudWxsXHJcbiAgICAgICAgICAgIH0gYXMgT3JnYW5pemF0aW9uXHJcblxyXG4gICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IHNhdmVPcmdhbml6YXRpb24oY29uZmlnLCBuZXdPcmdhbml6YXRpb24pOyAgICAgICAgICAgIFxyXG4gICAgICAgICAgICBjb25zb2xlLmxvZyhyZXNwb25zZSk7XHJcbiAgICAgICAgICAgIGlmKHJlc3BvbnNlLmVycm9ycyl7XHJcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoU3RyaW5nKHJlc3BvbnNlLmVycm9ycykpXHJcbiAgICAgICAgICAgIH0gICAgICAgICAgICBcclxuXHJcbiAgICAgICAgICAgIG5ld09yZ2FuaXphdGlvbiA9IHJlc3BvbnNlLmRhdGE7XHJcbiAgICAgICAgICAgIG5ld09yZ2FuaXphdGlvbi5kb21haW5zID0gb3JnYW5pemF0aW9uc1sxXS5kb21haW5zO1xyXG5cclxuICAgICAgICAgICAgZGlzcGF0Y2hBY3Rpb24oXHJcbiAgICAgICAgICAgICAgICBDTFNTQWN0aW9uS2V5cy5MT0FEX09SR0FOSVpBVElPTlNfQUNUSU9OLFxyXG4gICAgICAgICAgICAgICBbLi4ub3JnYW5pemF0aW9ucywgbmV3T3JnYW5pemF0aW9uXSk7XHJcbiAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICBzZXRPcmdhbml6YXRpb24ocmVzcG9uc2UuZGF0YSlcclxuICAgICAgICAgICAgdG9nZ2xlKGZhbHNlKTtcclxuICAgICAgICB9Y2F0Y2goZXJyKXtcclxuICAgICAgICAgICBjb25zb2xlLmxvZyhlcnIpO1xyXG4gICAgICAgICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlMsIGVyci5tZXNzYWdlKTtcclxuICAgICAgICB9ZmluYWxseXtcclxuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiggICAgICAgICAgIFxyXG4gICAgICA8Q2xzc01vZGFsIHRpdGxlPVwiQWRkIE5ldyBPcmdhbml6YXRpb25cIlxyXG4gICAgICAgIGRpc2FibGU9eyEob3JnYW5pemF0aW9uTmFtZSAmJiBzZWxlY3RlZE9yZ2FuaXphdGlvblR5cGUpfSAgXHJcbiAgICAgICAgc2F2ZT17c2F2ZX0gXHJcbiAgICAgICAgbG9hZGluZz17bG9hZGluZ31cclxuICAgICAgICB0b2dnbGVWaXNpYmlsaXR5PXt0b2dnbGV9IHZpc2libGU9e2lzVmlzaWJsZX0+XHJcbiAgICAgICAgIFxyXG4gICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cImFkZC1vcmdhbml6YXRpb25cIj4gXHJcbiAgICAgICAgICAgICA8c3R5bGU+XHJcbiAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5hZGQtb3JnYW5pemF0aW9ue1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICB9ICAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgPC9zdHlsZT5cclxuICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibW9kYWwtaXRlbVwiPiAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICA8TGFiZWwgY2hlY2s+T3JnYW5pemF0aW9uIE5hbWU8c3BhbiBzdHlsZT17e2NvbG9yOiAncmVkJ319Pio8L3NwYW4+PC9MYWJlbD5cclxuICAgICAgICAgICAgICAgIDxUZXh0SW5wdXQgZGF0YS10ZXN0aWQ9XCJ0eHRPcmdhbml6YXRpb25OYW1lXCIgc2l6ZT1cImRlZmF1bHRcIlxyXG4gICAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsoZSk9PiBzZXRPcmdhbml6YXRpb25OYW1lKGUudGFyZ2V0LnZhbHVlKX0gXHJcbiAgICAgICAgICAgICAgICAgICAgdmFsdWU9e29yZ2FuaXphdGlvbk5hbWV9PlxyXG4gICAgICAgICAgICAgICAgPC9UZXh0SW5wdXQ+XHJcbiAgICAgICAgICAgIDwvZGl2PlxyXG5cclxuICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJtb2RhbC1pdGVtXCI+XHJcbiAgICAgICAgICAgICAgICA8TGFiZWwgY2hlY2s+T3JnYW5pemF0aW9uIFR5cGU8c3BhbiBzdHlsZT17e2NvbG9yOiAncmVkJ319Pio8L3NwYW4+PC9MYWJlbD4gICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgIDxDbHNzRHJvcGRvd24gaXRlbXM9e29yZ2FuaXphdGlvblR5cGVzfSBcclxuICAgICAgICAgICAgICAgICAgICBpdGVtPXtzZWxlY3RlZE9yZ2FuaXphdGlvblR5cGV9IFxyXG4gICAgICAgICAgICAgICAgICAgIGRlbGV0YWJsZT17ZmFsc2V9XHJcbiAgICAgICAgICAgICAgICAgICAgc2V0SXRlbT17c2V0U2VsZWN0ZWRPcmdhbml6YXRpb25UeXBlfS8+XHJcbiAgICAgICAgICAgIDwvZGl2PlxyXG5cclxuICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJtb2RhbC1pdGVtXCI+XHJcbiAgICAgICAgICAgICAgICA8TGFiZWwgY2hlY2s+T3JnYW5pemF0aW9uJ3MgUGFyZW50IChPcHRpb25hbCk8L0xhYmVsPlxyXG4gICAgICAgICAgICAgICAgPE9yZ2FuaXphdGlvbnNEcm9wZG93biBcclxuICAgICAgICAgICAgICAgICAgICBjb25maWc9e2NvbmZpZ31cclxuICAgICAgICAgICAgICAgICAgICB0b2dnbGVOZXdPcmdhbml6YXRpb25Nb2RhbD17bnVsbH0gICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgIG9yZ2FuaXphdGlvbnM9e29yZ2FuaXphdGlvbnN9IFxyXG4gICAgICAgICAgICAgICAgICAgIHNlbGVjdGVkT3JnYW5pemF0aW9uPXtzZWxlY3RlZFBhcmVudE9yZ2FuaXphdGlvbn0gXHJcbiAgICAgICAgICAgICAgICAgICAgc2V0T3JnYW5pemF0aW9uPXtzZXRTZWxlY3RlZFBhcmVudE9yZ2FuaXphdGlvbn1cclxuICAgICAgICAgICAgICAgICAgICB2ZXJ0aWNhbD17ZmFsc2V9Lz4gIFxyXG4gICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICAgPC9kaXY+ICAgICAgICAgICAgICAgIFxyXG4gICAgXHJcbiAgICAgIDwvQ2xzc01vZGFsPlxyXG4gICAgKVxyXG59IiwiaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiXHJcbmltcG9ydCB7IENsc3NNb2RhbCB9IGZyb20gXCIuL2Nsc3MtbW9kYWxcIlxyXG5cclxuZXhwb3J0IGNvbnN0IFRlbXBsYXRlQXNzZXNzbWVudFZpZXcgPSh7YXNzZXNzbWVudHMsIHRvZ2dsZSwgaXNWaXNpYmxlfSk9PiB7XHJcbiAgICByZXR1cm4gKFxyXG4gICAgICAgIDxDbHNzTW9kYWwgdGl0bGU9XCJBc3Nlc3NtZW50cyBjcmVhdGVkIHdpdGggdGhpcyB0ZW1wbGF0ZVwiICBcclxuICAgICAgICB0b2dnbGVWaXNpYmlsaXR5PXt0b2dnbGV9IFxyXG4gICAgICAgIHZpc2libGU9e2lzVmlzaWJsZX1cclxuICAgICAgICBoaWRlRm9vdGVyPXt0cnVlfT5cclxuICAgICAgICA8ZGl2PlxyXG4gICAgICAgICAgICA8c3R5bGU+XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgICAgICAuYXNzZXNzbWVudC1saXN0IHRyOm50aC1jaGlsZCgybisyKXtcclxuICAgICAgICAgICAgICAgICAgICAgICAgYmFja2dyb3VuZDojZWZlZmVmO1xyXG4gICAgICAgICAgICAgICAgICAgICB9ICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAuYXNzZXNzbWVudC1saXN0IHRke1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgbGluZS1oZWlnaHQ6IDUwcHg7XHJcbiAgICAgICAgICAgICAgICAgICAgIH0gICAgIFxyXG4gICAgICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgPC9zdHlsZT5cclxuICAgICAgICAgICAgIDx0YWJsZSBjbGFzc05hbWU9XCJhc3Nlc3NtZW50LWxpc3RcIiBzdHlsZT17e3dpZHRoOiAnMTAwJSd9fT4gICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBhc3Nlc3NtZW50cz8ubWFwKChhLCBpKSA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAoXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8dHI+PHRkPntpKzErXCIpIFwifXthLm5hbWV9PHNwYW4gc3R5bGU9e3tjb2xvcjogJ2dyYXknLCBtYXJnaW5MZWZ0OiAnLjJlbSd9fT57IFwiICAgKFwiK2EuZGF0ZStcIilcIn08L3NwYW4+PC90ZD48L3RyPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgICAgICAgICAgfSlcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICA8L3RhYmxlPiBcclxuICAgICAgICA8L2Rpdj5cclxuICAgICAgICA8L0Nsc3NNb2RhbD5cclxuICAgICAgIFxyXG4gICAgKVxyXG59IiwiaW1wb3J0IHsgRHJvcGRvd24sIERyb3Bkb3duQnV0dG9uLCBEcm9wZG93bk1lbnUsIExhYmVsIH0gZnJvbSBcImppbXUtdWlcIjtcclxuaW1wb3J0IHsgVHJhc2hPdXRsaW5lZCB9IGZyb20gJ2ppbXUtaWNvbnMvb3V0bGluZWQvZWRpdG9yL3RyYXNoJztcclxuaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiXHJcblxyXG5leHBvcnQgY29uc3QgQ2xzc0Ryb3Bkb3duID0gKHtpdGVtcywgaXRlbSwgZGVsZXRhYmxlLCBzZXRJdGVtLCBkZWxldGVJdGVtLCBtZW51V2lkdGh9OlxyXG4gICAge2l0ZW1zOiBhbnlbXSwgaXRlbTogYW55LCBkZWxldGFibGU6IGJvb2xlYW4sIHNldEl0ZW06IEZ1bmN0aW9uLCBcclxuICAgICAgZGVsZXRlSXRlbT86IEZ1bmN0aW9uLCBtZW51V2lkdGg/OiBzdHJpbmd9KT0+IHtcclxuXHJcbiAgICBjb25zdCBidXR0b25FbGVtZW50ID0gUmVhY3QudXNlUmVmPEhUTUxFbGVtZW50PigpO1xyXG4gICAgXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCkgPT57XHJcbiAgICAgICBpZihpdGVtcyAmJiBpdGVtcy5sZW5ndGggPiAwKXtcclxuICAgICAgICAgIGlmKCFpdGVtKXtcclxuICAgICAgICAgICAgc2V0SXRlbShpdGVtc1swXSkgXHJcbiAgICAgICAgICB9ZWxzZXtcclxuICAgICAgICAgICAgc2V0SXRlbShpdGVtKTtcclxuICAgICAgICAgIH0gICAgICBcclxuICAgICAgIH1cclxuICAgIH0sIFtpdGVtc10pXHJcblxyXG4gICAgY29uc3QgaXRlbUNsaWNrID0gKGl0ZW0pPT57ICAgICBcclxuICAgICAgICBzZXRJdGVtKGl0ZW0pOyAgICAgICAgXHJcbiAgICAgICAgaWYoYnV0dG9uRWxlbWVudCAmJiBidXR0b25FbGVtZW50LmN1cnJlbnQpe1xyXG4gICAgICAgICAgICBidXR0b25FbGVtZW50LmN1cnJlbnQuY2xpY2soKTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgcmVtb3ZlSXRlbSA9KGl0ZW0pID0+e1xyXG4gICAgICAgIGlmKGNvbmZpcm0oJ1JlbW92ZSAnKyhpdGVtLnRpdGxlIHx8IGl0ZW0ubmFtZSkpKXtcclxuICAgICAgICAgICAgZGVsZXRlSXRlbShpdGVtKTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIChcclxuICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cImNsc3MtZHJvcGRvd24tY29udGFpbmVyXCIgc3R5bGU9e3t3aWR0aDogJzEwMCUnfX0+XHJcbiAgICAgICAgICAgIDxzdHlsZT5cclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICAgIC5kcm9wZG93bi1pdGVtLWNvbnRhaW5lcntcclxuICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDQ1cHg7XHJcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHJnYigyMjcsIDIyNywgMjI3KTtcclxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgICAgICAgICBjdXJzb3I6IHBvaW50ZXI7XHJcbiAgICAgICAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICAgICAgICBhbGlnbi1pdGVtczogY2VudGVyO1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5kcm9wZG93bi1pdGVtLWNvbnRhaW5lcjpob3ZlcntcclxuICAgICAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kLWNvbG9yOiByZ2IoMjI3LCAyMjcsIDIyNyk7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmppbXUtZHJvcGRvd24tbWVudXtcclxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogMzUlO1xyXG4gICAgICAgICAgICAgICAgICAgIG1heC1oZWlnaHQ6IDUwMHB4O1xyXG4gICAgICAgICAgICAgICAgICAgIG92ZXJmbG93OiBhdXRvO1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5qaW11LWRyb3Bkb3duLW1lbnUgLmRyb3Bkb3duLWl0ZW0tY29udGFpbmVyOmxhc3QtY2hpbGR7XHJcbiAgICAgICAgICAgICAgICAgICAgYm9yZGVyLWJvdHRvbTogbm9uZTtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAubW9kYWwtY29udGVudCAuY2xzcy1kcm9wZG93bi1jb250YWluZXIgYnV0dG9ue1xyXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5jbHNzLWRyb3Bkb3duLWNvbnRhaW5lciAuamltdS1kcm9wZG93bntcclxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuY2xvc2UtYnV0dG9ue1xyXG4gICAgICAgICAgICAgICAgICAgIG1hcmdpbjogMTBweDtcclxuICAgICAgICAgICAgICAgICAgICBjb2xvcjogZ3JheTtcclxuICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgLm1vZGFsLWNvbnRlbnQgLmNsc3MtZHJvcGRvd24tY29udGFpbmVyIGJ1dHRvbiBzcGFue1xyXG4gICAgICAgICAgICAgICAgICAgICBsaW5lLWhlaWdodDogMzBweCAhaW1wb3J0YW50O1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgIC5kcm9wZG93bi1pdGVtLWNvbnRhaW5lciBsYWJlbHtcclxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDEwMCU7XHJcbiAgICAgICAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICAgICAgICBhbGlnbi1pdGVtczogY2VudGVyO1xyXG4gICAgICAgICAgICAgICAgICAgIGZvbnQtc2l6ZTogMS4yZW07XHJcbiAgICAgICAgICAgICAgICAgICAgbWFyZ2luLWxlZnQ6IDFlbTtcclxuICAgICAgICAgICAgICAgICAgICBjdXJzb3I6IHBvaW50ZXI7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIDwvc3R5bGU+XHJcbiAgICAgICAgICAgIDxEcm9wZG93biAgYWN0aXZlSWNvbj1cInRydWVcIiBzaXplPVwibGdcIj5cclxuICAgICAgICAgICAgICAgIDxEcm9wZG93bkJ1dHRvbiBjbGFzc05hbWU9XCJkcm9wZG93bkJ1dHRvblwiIHJlZj17YnV0dG9uRWxlbWVudH0gIHNpemU9XCJsZ1wiIHN0eWxlPXt7dGV4dEFsaWduOiAnbGVmdCd9fT5cclxuICAgICAgICAgICAgICAgICAgICB7aXRlbT8udGl0bGUgfHwgaXRlbT8ubmFtZX1cclxuICAgICAgICAgICAgICAgIDwvRHJvcGRvd25CdXR0b24+XHJcbiAgICAgICAgICAgICAgICA8RHJvcGRvd25NZW51IHN0eWxlPXt7d2lkdGg6IG1lbnVXaWR0aCB8fCBcIjMwJVwifX0+XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgaXRlbXM/Lm1hcCgoaXRlbSwgaWR4KSA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAoXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGlkPXtpdGVtPy5uYW1lIHx8IGl0ZW0/LnRpdGxlfSBjbGFzc05hbWU9XCJkcm9wZG93bi1pdGVtLWNvbnRhaW5lclwiPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxMYWJlbCBjaGVjayBvbkNsaWNrPXsoKSA9PiBpdGVtQ2xpY2soaXRlbSl9PntpdGVtPy50aXRsZSB8fCBpdGVtPy5uYW1lfTwvTGFiZWw+ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKChpdGVtPy50aXRsZSB8fCBpdGVtPy5uYW1lKSAhPT0gJy1Ob25lLScpICYmIGRlbGV0YWJsZSA/IFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAoPFRyYXNoT3V0bGluZWQgdGl0bGU9J1JlbW92ZScgY2xhc3NOYW1lPVwiY2xvc2UtYnV0dG9uXCIgc2l6ZT17MjB9IG9uQ2xpY2s9eygpID0+IHJlbW92ZUl0ZW0oaXRlbSl9Lz4pXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogbnVsbFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PiAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICAgICAgIH0pXHJcbiAgICAgICAgICAgICAgICB9ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgPC9Ecm9wZG93bk1lbnU+XHJcbiAgICAgICAgICAgIDwvRHJvcGRvd24+XHJcbiAgICAgICAgPC9kaXY+XHJcbiAgICApXHJcbn0iLCJpbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCI7XHJcblxyXG5jb25zdCBDbHNzRXJyb3IgPSAoe2Vycm9yfSkgPT4ge1xyXG4gICAgcmV0dXJuIChcclxuICAgICAgICA8aDIgc3R5bGU9e3tjb2xvcjogJ3JlZCcsIGZvbnRTaXplOiAnMTVweCd9fT57ZXJyb3J9PC9oMj5cclxuICAgIClcclxufVxyXG5leHBvcnQgZGVmYXVsdCBDbHNzRXJyb3I7IiwiaW1wb3J0IHsgUmVhY3QgfSBmcm9tICdqaW11LWNvcmUnXHJcbmltcG9ydCB7QnV0dG9uLCBMYWJlbH0gZnJvbSAnamltdS11aSc7XHJcbmltcG9ydCB7IENsb3NlQ2lyY2xlRmlsbGVkIH0gZnJvbSAnamltdS1pY29ucy9maWxsZWQvZWRpdG9yL2Nsb3NlLWNpcmNsZSdcclxuLy9jb25zdCB1c2VcclxuXHJcbmNvbnN0IENsc3NFcnJvcnNQYW5lbCA9ICh7Y2xvc2UsIGVycm9yc30pID0+IHsgIFxyXG4gIHJldHVybiAoIFxyXG4gICAgPGRpdiBjbGFzc05hbWU9J2ppbXUtd2lkZ2V0IHdpZGdldC1lcnJvci1jb250YWluZXInPlxyXG4gICAgICAgPHN0eWxlPlxyXG4gICAgICAgIHtgXHJcbiAgICAgICAgICAud2lkZ2V0LWVycm9yLWNvbnRhaW5lcntcclxuICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7XHJcbiAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7XHJcbiAgICAgICAgICAgIGJhY2tncm91bmQtY29sb3I6ICNmZmM2Y2Q7XHJcbiAgICAgICAgICAgIGJvcmRlcjogMXB4IHNvbGlkIHJlZDtcclxuICAgICAgICAgICAgYm94LXNoYWRvdzogMXB4IDFweCAxMnB4IDRweCAjNWQ1YzVjO1xyXG4gICAgICAgICAgICBwYWRkaW5nOiAxMHB4IDIwcHg7XHJcbiAgICAgICAgICAgIGJvcmRlci1yYWRpdXM6IDAgMTBweCAwIDA7XHJcbiAgICAgICAgICB9ICAgICBcclxuICAgICAgICAgIC5jbG9zZS1idXR0b257XHJcbiAgICAgICAgICAgICBwb3NpdGlvbjogYWJzb2x1dGU7XHJcbiAgICAgICAgICAgICB0b3A6IDA7XHJcbiAgICAgICAgICAgICByaWdodDogMDtcclxuICAgICAgICAgICAgIGNvbG9yOiByZWQ7XHJcbiAgICAgICAgICAgICBjdXJzb3I6IHBvaW50ZXI7XHJcbiAgICAgICAgICB9ICAgICBcclxuICAgICAgICBgfVxyXG4gICAgICA8L3N0eWxlPlxyXG4gICAgICA8Q2xvc2VDaXJjbGVGaWxsZWQgY2xhc3NOYW1lPSdjbG9zZS1idXR0b24nIGRhdGEtdGVzdGlkPVwiYnRuQ2xvc2VFcnJvclwiIHNpemU9ezMwfVxyXG4gICAgICAgICAgICAgICAgICAgIG9uQ2xpY2s9eygpID0+IGNsb3NlKCl9IHN0eWxlPXt7Y29sb3I6ICdyZWQnfX0gdGl0bGU9J0Nsb3NlJy8+XHJcbiAgICA8TGFiZWwgc3R5bGU9e3tjb2xvcjogJyNhNTAwMDAnLCBcclxuICAgICAgICBmb250U2l6ZTogJzIwcHgnfX0gY2hlY2sgc2l6ZT0nbGcnPntlcnJvcnN9PC9MYWJlbD5cclxuICAgICA8L2Rpdj5cclxuICApXHJcbn1cclxuXHJcbmV4cG9ydCBkZWZhdWx0IENsc3NFcnJvcnNQYW5lbDtcclxuXHJcbiIsImltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5pbXBvcnQgeyBDbHNzRHJvcGRvd24gfSBmcm9tIFwiLi9jbHNzLWRyb3Bkb3duXCJcclxuaW1wb3J0IHsgSGF6YXJkIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvZGF0YS1kZWZpbml0aW9uc1wiXHJcbmltcG9ydCB7IEJ1dHRvbiB9IGZyb20gXCJqaW11LXVpXCI7XHJcbmltcG9ydCB7IFBsdXNDaXJjbGVPdXRsaW5lZCB9IGZyb20gXCJqaW11LWljb25zL291dGxpbmVkL2VkaXRvci9wbHVzLWNpcmNsZVwiO1xyXG5pbXBvcnQgeyBkZWxldGVIYXphcmQsIGRpc3BhdGNoQWN0aW9uIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXBpXCI7XHJcbmltcG9ydCB7IENMU1NBY3Rpb25LZXlzIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY2xzcy1zdG9yZVwiO1xyXG5cclxuXHJcbmV4cG9ydCBjb25zdCBIYXphcmRzRHJvcGRvd24gPSh7Y29uZmlnLCBoYXphcmRzLCBzZWxlY3RlZEhhemFyZCwgc2V0SGF6YXJkLCB2ZXJ0aWNhbCwgdG9nZ2xlTmV3SGF6YXJkTW9kYWx9KT0+e1xyXG5cclxuICAgIGNvbnN0IFtsb2NhbEhhemFyZHMsIHNldExvY2FsSGF6YXJkc10gPSBSZWFjdC51c2VTdGF0ZTxIYXphcmRbXT4oW10pO1xyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKT0+e1xyXG4gICAgICAgIGlmKGhhemFyZHMpeyAgICAgICAgICAgIFxyXG4gICAgICAgICAgICBzZXRMb2NhbEhhemFyZHMoWy4uLmhhemFyZHNdIGFzIEhhemFyZFtdKVxyXG4gICAgICAgIH1cclxuICAgIH0sIFtoYXphcmRzXSlcclxuXHJcbiAgICBjb25zdCByZW1vdmVIYXphcmQgPWFzeW5jIChoYXphcmQ6IEhhemFyZCk9PnsgICAgICAgXHJcbiAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBkZWxldGVIYXphcmQoaGF6YXJkLCBjb25maWcpO1xyXG4gICAgICAgaWYocmVzcG9uc2UuZXJyb3JzKXtcclxuICAgICAgICBjb25zb2xlLmxvZyhyZXNwb25zZS5lcnJvcnMpO1xyXG4gICAgICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlMsIHJlc3BvbnNlLmVycm9ycyk7XHJcbiAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgfVxyXG4gICAgICAgY29uc29sZS5sb2coYCR7aGF6YXJkLnRpdGxlfSBkZWxldGVkYCk7XHJcbiAgICAgICBzZXRMb2NhbEhhemFyZHMoWy4uLmxvY2FsSGF6YXJkcy5maWx0ZXIoaCA9PiBoLmlkICE9PSBoYXphcmQuaWQpXSk7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHJldHVybiAoXHJcbiAgICAgICAgPGRpdiBzdHlsZT17e2Rpc3BsYXk6IHZlcnRpY2FsID8gJ2Jsb2NrJzogJ2ZsZXgnLFxyXG4gICAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJ319PlxyXG4gICAgICAgICAgICA8c3R5bGU+XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgICAgICAuYWN0aW9uLWljb24ge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogZ3JheTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgY3Vyc29yOiBwb2ludGVyO1xyXG4gICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgPC9zdHlsZT5cclxuICAgICAgICAgICAgPENsc3NEcm9wZG93biBpdGVtcz17bG9jYWxIYXphcmRzfVxyXG4gICAgICAgICAgICAgICAgaXRlbT17c2VsZWN0ZWRIYXphcmR9IFxyXG4gICAgICAgICAgICAgICAgZGVsZXRhYmxlPXt0cnVlfVxyXG4gICAgICAgICAgICAgICAgc2V0SXRlbT17c2V0SGF6YXJkfSBcclxuICAgICAgICAgICAgICAgIGRlbGV0ZUl0ZW09e3JlbW92ZUhhemFyZH0vPiBcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICB2ZXJ0aWNhbD8gKFxyXG4gICAgICAgICAgICAgICAgPEJ1dHRvbiBkYXRhLXRlc3RpZD1cImJ0blNob3dBZGRPcmdhbml6YXRpb25cIiAgY2xhc3NOYW1lPVwiIGFkZC1saW5rXCJcclxuICAgICAgICAgICAgICAgICAgICAgdHlwZT1cImxpbmtcIiBzdHlsZT17e3RleHRBbGlnbjogJ2xlZnQnfX1cclxuICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKT0+IHRvZ2dsZU5ld0hhemFyZE1vZGFsKHRydWUpfT5cclxuICAgICAgICAgICAgICAgICAgICBBZGQgTmV3IEhhemFyZFxyXG4gICAgICAgICAgICAgICAgPC9CdXR0b24+XHJcbiAgICAgICAgICAgICAgICk6KFxyXG4gICAgICAgICAgICAgICAgPFBsdXNDaXJjbGVPdXRsaW5lZCBjbGFzc05hbWU9XCJhY3Rpb24taWNvblwiIFxyXG4gICAgICAgICAgICAgICAgICAgIGRhdGEtdGVzdGlkPVwiYnRuQWRkTmV3SGF6YXJkXCIgXHJcbiAgICAgICAgICAgICAgICAgICAgdGl0bGU9XCJBZGQgTmV3IEhhemFyZFwiIHNpemU9ezMwfSBjb2xvcj17J2dyYXknfVxyXG4gICAgICAgICAgICAgICAgICAgIG9uQ2xpY2s9eygpPT4gdG9nZ2xlTmV3SGF6YXJkTW9kYWwodHJ1ZSl9Lz4gXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgIH0gICBcclxuICAgICAgICAgICAgey8qIDxwPntzZWxlY3RlZEhhemFyZD8uZGVzY3JpcHRpb259PC9wPiAqL31cclxuICAgICAgICA8L2Rpdj5cclxuICAgIClcclxufSIsImltcG9ydCB7IEJ1dHRvbiwgSWNvbiwgTGFiZWwsIE51bWVyaWNJbnB1dCwgVGV4dElucHV0IH0gZnJvbSBcImppbXUtdWlcIlxyXG5pbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCI7XHJcbmltcG9ydCB7IFRyYXNoT3V0bGluZWQgfSBmcm9tICdqaW11LWljb25zL291dGxpbmVkL2VkaXRvci90cmFzaCc7XHJcbmltcG9ydCB7IEVkaXRGaWxsZWQgfSBmcm9tICdqaW11LWljb25zL2ZpbGxlZC9lZGl0b3IvZWRpdCc7XHJcbmltcG9ydCB7IEhlbHBGaWxsZWQgfSBmcm9tICdqaW11LWljb25zL2ZpbGxlZC9zdWdnZXN0ZWQvaGVscCdcclxuaW1wb3J0IHsgQ2xvc2VPdXRsaW5lZCB9IGZyb20gJ2ppbXUtaWNvbnMvb3V0bGluZWQvZWRpdG9yL2Nsb3NlJztcclxuaW1wb3J0IENsc3NMb2FkaW5nIGZyb20gXCIuL2Nsc3MtbG9hZGluZ1wiO1xyXG5pbXBvcnQgeyBDaGVja0ZpbGxlZCB9IGZyb20gJ2ppbXUtaWNvbnMvZmlsbGVkL2FwcGxpY2F0aW9uL2NoZWNrJztcclxuaW1wb3J0IHsgQ0xTU1RlbXBsYXRlLCBDbHNzVXNlciwgQ29tcG9uZW50VGVtcGxhdGUsIEluZGljYXRvclRlbXBsYXRlLCBJbmRpY2F0b3JXZWlnaHQsIExpZmVMaW5lVGVtcGxhdGUgfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9kYXRhLWRlZmluaXRpb25zXCI7XHJcbmltcG9ydCB7IFJBTkssIExJRkVfU0FGRVRZLCBJTkNJREVOVF9TVEFCSUxJWkFUSU9OLCBQUk9QRVJUWV9QUk9URUNUSU9OLCBcclxuICAgIEVOVklST05NRU5UX1BSRVNFUlZBVElPTiwgXHJcbiAgICBCQVNFTElORV9URU1QTEFURV9OQU1FLFxyXG4gICAgQ0xTU19BRE1JTixcclxuICAgIENMU1NfRURJVE9SLFxyXG4gICAgREVMRVRFX0lORElDQVRPUl9DT05GSVJNQVRJT04sXHJcbiAgICBPVEhFUl9XRUlHSFRTX1NDQUxFX0ZBQ1RPUixcclxuICAgIExJRkVfU0FGRVRZX1NDQUxFX0ZBQ1RPUixcclxuICAgIENMU1NfRk9MTE9XRVJTfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jb25zdGFudHNcIjtcclxuaW1wb3J0IENsc3NFcnJvciBmcm9tIFwiLi9jbHNzLWVycm9yXCI7XHJcbmltcG9ydCB7IFJlYWN0UmVkdXggfSBmcm9tIFwiamltdS1jb3JlXCI7XHJcbmltcG9ydCB7IGNyZWF0ZU5ld0luZGljYXRvciwgZGVsZXRlSW5kaWNhdG9yLCBkaXNwYXRjaEFjdGlvbiwgdXBkYXRlSW5kaWNhdG9yIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXBpXCI7XHJcbmltcG9ydCB7IENMU1NBY3Rpb25LZXlzIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY2xzcy1zdG9yZVwiO1xyXG5jb25zdCB7IHVzZVNlbGVjdG9yIH0gPSBSZWFjdFJlZHV4O1xyXG5cclxuY29uc3QgVGFibGVSb3dDb21tYW5kPSh7aXNJbkVkaXRNb2RlLCBvbkVkaXQsIG9uRGVsZXRlLCBvblNhdmUsIG9uQ2FuY2VsLCBjYW5TYXZlfTogXHJcbiAgICB7aXNJbkVkaXRNb2RlOiBib29sZWFuLCBcclxuICAgICAgICBvbkVkaXQ6IEZ1bmN0aW9uLCBvbkRlbGV0ZTogRnVuY3Rpb24sIG9uU2F2ZTogRnVuY3Rpb24sIFxyXG4gICAgICAgIG9uQ2FuY2VsOiBGdW5jdGlvbiwgY2FuU2F2ZTogYm9vbGVhbn0pPT57XHJcblxyXG4gICAgcmV0dXJuKFxyXG4gICAgICAgIDx0ZCBjbGFzc05hbWU9XCJkYXRhXCI+XHJcbiAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwiY29tbWFuZC1jb250YWluZXJcIj5cclxuICAgICAgICAgICAgICAgIDxzdHlsZT5cclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNvbW1hbmQtY29udGFpbmVye1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNvbW1hbmR7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmbGV4OiAxXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgLmVkaXQtZGVsZXRlLCAuc2F2ZS1jYW5jZWx7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZsZXgtd3JhcDogbm93cmFwO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICA8L3N0eWxlPlxyXG4gICAgICAgICAgICAgICAgeyAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgaXNJbkVkaXRNb2RlID9cclxuICAgICAgICAgICAgICAgICAgICAoXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwiZWRpdC1kZWxldGVcIj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxDaGVja0ZpbGxlZCBzdHlsZT17e3BvaW50ZXJFdmVudHM6ICFjYW5TYXZlID8gJ25vbmUnIDogJ2FsbCd9fSBzaXplPXsyMH0gY2xhc3NOYW1lPVwiY29tbWFuZFwiIHRpdGxlPVwiU2F2ZSBFZGl0c1wiIG9uQ2xpY2s9eygpID0+IG9uU2F2ZSgpfS8+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8Q2xvc2VPdXRsaW5lZCBzaXplPXsyMH0gY2xhc3NOYW1lPVwiY29tbWFuZFwiIHRpdGxlPVwiQ2FuY2VsIEVkaXRzXCIgb25DbGljaz17KCkgPT4gb25DYW5jZWwoKX0vPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgICAgICAgICAgOiAoXHJcbiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJlZGl0LWRlbGV0ZVwiPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8RWRpdEZpbGxlZCBzaXplPXsyMH0gY2xhc3NOYW1lPVwiY29tbWFuZFwiIHRpdGxlPVwiRWRpdFwiIG9uQ2xpY2s9eygpID0+IG9uRWRpdCgpfS8+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDxUcmFzaE91dGxpbmVkIHNpemU9ezIwfSBjbGFzc05hbWU9XCJjb21tYW5kXCIgdGl0bGU9XCJEZWxldGVcIiBvbkNsaWNrPXsoKSA9PiBvbkRlbGV0ZSgpfS8+XHJcbiAgICAgICAgICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICAgfSAgIFxyXG4gICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgIDwvdGQ+ICAgICAgIFxyXG4gICAgKVxyXG59XHJcblxyXG5jb25zdCBFZGl0YWJsZVRhYmxlUm93PSh7aW5kaWNhdG9yLCBpc0VkaXRhYmxlLCBjb21wb25lbnQsIFxyXG4gICAgdGVtcGxhdGUsIGNvbmZpZywgc2V0RXJyb3IsIG9uQWN0aW9uQ29tcGxldGUsIG9uQ2FuY2VsfTp7XHJcbiAgICBpbmRpY2F0b3I6IEluZGljYXRvclRlbXBsYXRlLCBpc0VkaXRhYmxlOiBib29sZWFuLCBcclxuICAgIGNvbXBvbmVudDogQ29tcG9uZW50VGVtcGxhdGUsIHRlbXBsYXRlOiBDTFNTVGVtcGxhdGUsIFxyXG4gICAgY29uZmlnOiBhbnksIHNldEVycm9yOiBGdW5jdGlvbiwgb25BY3Rpb25Db21wbGV0ZTogRnVuY3Rpb24sIG9uQ2FuY2VsOiBGdW5jdGlvbn0pPT4ge1xyXG5cclxuICAgIGNvbnN0IFtpc0VkaXRpbmcsIHNldEVkaXRpbmddID0gUmVhY3QudXNlU3RhdGUoaW5kaWNhdG9yLmlzQmVpbmdFZGl0ZWQpO1xyXG4gICAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpO1xyXG4gICAgY29uc3QgW25hbWUsIHNldE5hbWVdID0gUmVhY3QudXNlU3RhdGUoJycpXHJcbiAgICBjb25zdCBbcmFuaywgc2V0UmFua10gPSBSZWFjdC51c2VTdGF0ZTxudW1iZXI+KCk7ICAgIFxyXG4gICAgY29uc3QgW2xpZmVTYWZldHksIHNldExpZmVTYWZldHldID0gUmVhY3QudXNlU3RhdGU8bnVtYmVyPigpO1xyXG4gICAgY29uc3QgW2luY2lkZW50U3RhYiwgc2V0SW5jaWRlbnRTdGFiXSA9IFJlYWN0LnVzZVN0YXRlPG51bWJlcj4oKTtcclxuICAgIGNvbnN0IFtwcm9wZXJ0eVByb3QsIHNldFByb3BQcm90XSA9IFJlYWN0LnVzZVN0YXRlPG51bWJlcj4oKTtcclxuICAgIGNvbnN0IFtlbnZQcmVzLCBzZXRFbnZQcmVzXSA9IFJlYWN0LnVzZVN0YXRlPG51bWJlcj4oKTsgXHJcbiAgICBjb25zdCBbY2FuQ29tbWl0LCBzZXRDYW5Db21taXRdID0gUmVhY3QudXNlU3RhdGUodHJ1ZSk7XHJcbiAgICAgIFxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpID0+IHtcclxuICAgICAgICBpZihpbmRpY2F0b3Ipe1xyXG4gICAgICAgICAgICB0cnl7XHJcbiAgICAgICAgICAgICAgICBzZXROYW1lKGluZGljYXRvcj8ubmFtZSk7XHJcbiAgICAgICAgICAgICAgICBzZXRSYW5rKGluZGljYXRvcj8ud2VpZ2h0cz8uZmluZCh3ID0+IHcubmFtZSA9PT0gUkFOSykud2VpZ2h0KTtcclxuICAgICAgICAgICAgICAgIHNldExpZmVTYWZldHkoaW5kaWNhdG9yPy53ZWlnaHRzPy5maW5kKHcgPT4gdy5uYW1lID09PSBMSUZFX1NBRkVUWSkud2VpZ2h0KVxyXG4gICAgICAgICAgICAgICAgc2V0SW5jaWRlbnRTdGFiKGluZGljYXRvcj8ud2VpZ2h0cz8uZmluZCh3ID0+IHcubmFtZSA9PT0gSU5DSURFTlRfU1RBQklMSVpBVElPTikud2VpZ2h0KVxyXG4gICAgICAgICAgICAgICAgc2V0UHJvcFByb3QoaW5kaWNhdG9yPy53ZWlnaHRzPy5maW5kKHcgPT4gdy5uYW1lID09PSBQUk9QRVJUWV9QUk9URUNUSU9OKS53ZWlnaHQpXHJcbiAgICAgICAgICAgICAgICBzZXRFbnZQcmVzKGluZGljYXRvcj8ud2VpZ2h0cz8uZmluZCh3ID0+IHcubmFtZSA9PT0gRU5WSVJPTk1FTlRfUFJFU0VSVkFUSU9OKS53ZWlnaHQpXHJcbiAgICAgICAgICAgIH1jYXRjaChlKXtcclxuICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgfSwgW2luZGljYXRvcl0pXHJcblxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpPT57XHJcbiAgICAgICAgc2V0Q2FuQ29tbWl0KHRydWUpO1xyXG4gICAgICAgIHNldEVycm9yKCcnKVxyXG4gICAgICAgIGlmKG5hbWUpe1xyXG4gICAgICAgICAgICBjb25zdCBpbmRpY2F0b3JzTmFtZXMgPSBjb21wb25lbnQuaW5kaWNhdG9ycy5tYXAoaSA9PiBpLm5hbWUudG9Mb2NhbGVMb3dlckNhc2UoKSk7XHJcbiAgICAgICAgICAgIGlmKGluZGljYXRvci5pc05ldyAmJiBpbmRpY2F0b3JzTmFtZXMuaW5jbHVkZXMobmFtZS50b0xvY2FsZUxvd2VyQ2FzZSgpKSl7XHJcbiAgICAgICAgICAgICAgIHNldEVycm9yKGBJbmRpY2F0b3I6ICR7bmFtZX0gYWxyZWFkeSBleGlzdHNgKTtcclxuICAgICAgICAgICAgICAgc2V0Q2FuQ29tbWl0KGZhbHNlKTtcclxuICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgfSwgW25hbWVdKVxyXG5cclxuICAgIGNvbnN0IGdldFdlaWdodEJ5TmFtZT0odzogSW5kaWNhdG9yV2VpZ2h0KT0+e1xyXG4gICAgICAgIHN3aXRjaCh3Lm5hbWUpe1xyXG4gICAgICAgICAgICBjYXNlIFJBTks6XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gcmFuaztcclxuICAgICAgICAgICAgY2FzZSBMSUZFX1NBRkVUWTpcclxuICAgICAgICAgICAgICAgIHJldHVybiBsaWZlU2FmZXR5XHJcbiAgICAgICAgICAgIGNhc2UgSU5DSURFTlRfU1RBQklMSVpBVElPTjpcclxuICAgICAgICAgICAgICAgIHJldHVybiBpbmNpZGVudFN0YWI7XHJcbiAgICAgICAgICAgIGNhc2UgUFJPUEVSVFlfUFJPVEVDVElPTjpcclxuICAgICAgICAgICAgICAgIHJldHVybiBwcm9wZXJ0eVByb3Q7XHJcbiAgICAgICAgICAgIGNhc2UgRU5WSVJPTk1FTlRfUFJFU0VSVkFUSU9OOlxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIGVudlByZXM7XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG4gICAgXHJcbiAgICBjb25zdCBvblNhdmVFZGl0cz1hc3luYyAoKT0+e1xyXG4gICAgICAgIHNldExvYWRpbmcodHJ1ZSk7XHJcbiAgICAgICAgY29uc3QgdXBkYXRlZEluZGljYXRvciA9IHtcclxuICAgICAgICAgICAgLi4uaW5kaWNhdG9yLFxyXG4gICAgICAgICAgICBuYW1lOiBuYW1lLFxyXG4gICAgICAgICAgICB0aXRsZTogbmFtZSxcclxuICAgICAgICAgICAgd2VpZ2h0czogaW5kaWNhdG9yPy53ZWlnaHRzLm1hcCh3ID0+IHtcclxuICAgICAgICAgICAgICAgIHJldHVybntcclxuICAgICAgICAgICAgICAgICAgICAuLi53LFxyXG4gICAgICAgICAgICAgICAgICAgIHdlaWdodDogZ2V0V2VpZ2h0QnlOYW1lKHcpXHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICB9KVxyXG4gICAgICAgIH1cclxuICAgICAgIGlmKGluZGljYXRvci5pc05ldyl7IFxyXG4gICAgICAgICAgY29uc3QgcmVzcCA9IGF3YWl0IGNyZWF0ZU5ld0luZGljYXRvcih1cGRhdGVkSW5kaWNhdG9yLCBcclxuICAgICAgICAgICAgY29uZmlnLCB0ZW1wbGF0ZS5pZCwgdGVtcGxhdGUubmFtZSk7XHJcbiAgICAgICAgICBpZihyZXNwLmVycm9ycyl7XHJcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpXHJcbiAgICAgICAgICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlMsIHJlc3AuZXJyb3JzKTtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgfWVsc2V7ICAgICAgIFxyXG4gICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IHVwZGF0ZUluZGljYXRvcih1cGRhdGVkSW5kaWNhdG9yLCBjb25maWcpO1xyXG4gICAgICAgICAgICBpZihyZXNwb25zZS5lcnJvcnMpe1xyXG4gICAgICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSlcclxuICAgICAgICAgICAgICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlMsIHJlc3BvbnNlLmVycm9ycyk7XHJcbiAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICAgICAgc2V0RWRpdGluZyhmYWxzZSk7XHJcbiAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XHJcbiAgICAgICAgb25BY3Rpb25Db21wbGV0ZSh0cnVlKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBvbkNhbmNlbEVkaXRzPSgpPT57ICAgIFxyXG4gICAgICAgICBzZXRFcnJvcignJyk7XHJcbiAgICAgICAgIHNldENhbkNvbW1pdCh0cnVlKTsgICBcclxuICAgICAgICAgc2V0RWRpdGluZyhmYWxzZSlcclxuICAgICAgICAgb25BY3Rpb25Db21wbGV0ZShmYWxzZSk7XHJcbiAgICAgICAgIGlmKGluZGljYXRvci5pc05ldyl7XHJcbiAgICAgICAgICAgIG9uQ2FuY2VsKClcclxuICAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IG9uRGVsZXRlSW5kaWNhdG9yPWFzeW5jICgpPT57XHJcblxyXG4gICAgICAgIGlmIChjb25maXJtKERFTEVURV9JTkRJQ0FUT1JfQ09ORklSTUFUSU9OKSA9PSB0cnVlKSB7XHJcbiAgICAgICAgICAgIFxyXG4gICAgICAgICAgICBzZXRMb2FkaW5nKHRydWUpO1xyXG5cclxuICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBkZWxldGVJbmRpY2F0b3IoaW5kaWNhdG9yLCBjb25maWcpO1xyXG4gICAgICAgICAgICBpZihyZXNwb25zZS5lcnJvcnMpe1xyXG4gICAgICAgICAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgcmVzcG9uc2UuZXJyb3JzKTtcclxuICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcclxuICAgICAgICAgICAgb25BY3Rpb25Db21wbGV0ZSh0cnVlKTsgICAgICAgICAgIFxyXG4gICAgICAgIH0gICAgICAgIFxyXG4gICAgfSBcclxuICAgIFxyXG4gICAgcmV0dXJuIChcclxuICAgICAgICA8dHIgc3R5bGU9e3twb3NpdGlvbjogJ3JlbGF0aXZlJ319PlxyXG4gICAgICAgICAgICA8c3R5bGU+XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgICAgIC5saWZlbGluZS1jb21wb25lbnQtdGFibGUgLmluZGljYXRvci1uYW1lIGlucHV0IHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgZm9udC1zaXplOiAxMnB4ICFpbXBvcnRhbnRcclxuICAgICAgICAgICAgICAgICAgICAgfSAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAuamltdS1udW1lcmljLWlucHV0IGlucHV0e1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBtaW4td2lkdGg6IDE2MHB4O1xyXG4gICAgICAgICAgICAgICAgICAgICB9ICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICA8L3N0eWxlPlxyXG4gICAgICAgICAgICA8dGQgY2xhc3NOYW1lPVwiZGF0YSBpbmRpY2F0b3ItbmFtZVwiIHN0eWxlPXt7dGV4dEFsaWduOiAnbGVmdCd9fT5cclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBpc0VkaXRpbmcgPyBcclxuICAgICAgICAgICAgICAgICAgICAoPGxhYmVsIHN0eWxlPXt7d2lkdGg6ICcxMDAlJ319PjxUZXh0SW5wdXQgY2xhc3NOYW1lPVwiaW5kaWNhdG9yLW5hbWVcIiBcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGl0bGU9e25hbWV9IHZhbHVlPXtuYW1lfSBvbkNoYW5nZT17KGUpPT4gc2V0TmFtZShlLnRhcmdldC52YWx1ZSl9IFxyXG4gICAgICAgICAgICAgICAgICAgICAgICBhbGxvd0NsZWFyIHR5cGU9XCJ0ZXh0XCIvPjwvbGFiZWw+KTpcclxuICAgICAgICAgICAgICAgICAgICBuYW1lXHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIDwvdGQ+XHJcbiAgICAgICAgICAgIDx0ZCBjbGFzc05hbWU9XCJkYXRhXCI+XHJcbiAgICAgICAgICAgICAgICB7ICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgaXNFZGl0aW5nID8gXHJcbiAgICAgICAgICAgICAgICAgICAoPGxhYmVsPjxOdW1lcmljSW5wdXQgXHJcbiAgICAgICAgICAgICAgICAgICAgbWF4PXs1fSBtaW49ezF9IFxyXG4gICAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsodikgPT4gc2V0UmFuayh2KX0gdmFsdWU9e3Jhbmt9XHJcbiAgICAgICAgICAgICAgICAgICAgLz48L2xhYmVsPik6cmFua1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICA8dGQgY2xhc3NOYW1lPVwiZGF0YVwiPlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICdOL0EnXHJcbiAgICAgICAgICAgICAgICAvLyAgICAhaXNFZGl0aW5nID8gKGxpZmVTYWZldHk/LnZhbHVlKTogKDxsYWJlbD48TnVtZXJpY0lucHV0IG9uQ2hhbmdlPXtvbkxpZmVTYWZldHlDaGFuZ2V9IHZhbHVlPXtsaWZlU2FmZXR5Py52YWx1ZX0vPjwvbGFiZWw+KVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICA8dGQgY2xhc3NOYW1lPVwiZGF0YVwiPlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICdOL0EnXHJcbiAgICAgICAgICAgICAgICAvLyAgICAhaXNFZGl0aW5nID8gKGluY2lkZW50U3RhYj8udmFsdWUpOiAoPGxhYmVsPjxOdW1lcmljSW5wdXQgb25DaGFuZ2U9e29uSW5jaWRlbnRTdGFiaWxpemF0aW9uQ2hhbmdlfSB2YWx1ZT17aW5jaWRlbnRTdGFiPy52YWx1ZX0vPjwvbGFiZWw+KVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICA8dGQgY2xhc3NOYW1lPVwiZGF0YVwiPlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICdOL0EnXHJcbiAgICAgICAgICAgICAgICAvLyAgICAhaXNFZGl0aW5nID8gKHByb3BlcnR5UHJvdD8udmFsdWUpOiAoPGxhYmVsPjxOdW1lcmljSW5wdXQgb25DaGFuZ2U9e29uUHJvcGVydHlQcm90ZWN0aW9uQ2hhbmdlfSB2YWx1ZT17cHJvcGVydHlQcm90Py52YWx1ZX0vPjwvbGFiZWw+KVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICA8dGQgY2xhc3NOYW1lPVwiZGF0YVwiPlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICdOL0EnXHJcbiAgICAgICAgICAgICAgICAvLyAgICAhaXNFZGl0aW5nID8gKGVudlByZXM/LnZhbHVlKTogKDxsYWJlbD48TnVtZXJpY0lucHV0IG9uQ2hhbmdlPXtvbkVudmlyb25tZW50YWxQcmVzZXJ2YXRpb25DaGFuZ2V9IHZhbHVlPXtlbnZQcmVzPy52YWx1ZX0vPjwvbGFiZWw+KVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgIGlzRWRpdGFibGU/IFxyXG4gICAgICAgICAgICAgICAgKFxyXG4gICAgICAgICAgICAgICAgICAgIDx0ZCBjbGFzc05hbWU9XCJkYXRhXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDxUYWJsZVJvd0NvbW1hbmRcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlzSW5FZGl0TW9kZT17aXNFZGl0aW5nfSBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhblNhdmU9e2NhbkNvbW1pdH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uRWRpdD17KCkgPT5zZXRFZGl0aW5nKHRydWUpfSAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBvblNhdmU9e29uU2F2ZUVkaXRzfSBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2FuY2VsPXtvbkNhbmNlbEVkaXRzfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgb25EZWxldGU9e29uRGVsZXRlSW5kaWNhdG9yfS8+ICBcclxuICAgICAgICAgICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICAgICAgKTogbnVsbFxyXG4gICAgICAgICAgICB9ICAgXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgbG9hZGluZyA/IDxDbHNzTG9hZGluZy8+IDogbnVsbCAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgfSAgICAgIFxyXG4gICAgICAgIDwvdHI+XHJcbiAgICApXHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBMaWZlbGluZUNvbXBvbmVudCA9IChcclxuICAgIHtsaWZlbGluZSwgY29tcG9uZW50LCB0ZW1wbGF0ZSwgY29uZmlnLCBvbkFjdGlvbkNvbXBsZXRlfTpcclxuICAgIHtsaWZlbGluZTogTGlmZUxpbmVUZW1wbGF0ZSwgY29tcG9uZW50OiBDb21wb25lbnRUZW1wbGF0ZSwgdGVtcGxhdGU6IENMU1NUZW1wbGF0ZSwgXHJcbiAgICAgICAgY29uZmlnOiBhbnksIG9uQWN0aW9uQ29tcGxldGU6IEZ1bmN0aW9ufSkgPT4ge1xyXG5cclxuICAgIGNvbnN0IFtpbmRpY2F0b3JzLCBzZXRJbmRpY2F0b3JzXT0gUmVhY3QudXNlU3RhdGU8SW5kaWNhdG9yVGVtcGxhdGVbXT4oW10pO1xyXG4gICAgY29uc3QgW2Vycm9yLCBzZXRFcnJvcl0gPSBSZWFjdC51c2VTdGF0ZSgnJykgICAgXHJcbiAgICBjb25zdCBbaXNFZGl0YWJsZSwgc2V0RWRpdGFibGVdID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpXHJcbiAgICAgIFxyXG4gICAgY29uc3QgdXNlciA9ICB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4geyAgIFxyXG4gICAgICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGU/LnVzZXIgYXMgQ2xzc1VzZXI7XHJcbiAgICB9KTsgXHJcblxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpID0+IHtcclxuICAgICAgICBpZih1c2VyKXsgXHJcbiAgICAgICAgICBpZih1c2VyPy5ncm91cHM/LmluY2x1ZGVzKENMU1NfQURNSU4pKXtcclxuICAgICAgICAgICAgc2V0RWRpdGFibGUodHJ1ZSk7XHJcbiAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgIH1cclxuICAgIFxyXG4gICAgICAgICAgaWYodXNlcj8uZ3JvdXBzPy5pbmNsdWRlcyhDTFNTX0VESVRPUikgJiYgXHJcbiAgICAgICAgICAgICAgdGVtcGxhdGU/Lm5hbWUgIT09IEJBU0VMSU5FX1RFTVBMQVRFX05BTUUpe1xyXG4gICAgICAgICAgICAgICAgc2V0RWRpdGFibGUodHJ1ZSk7XHJcbiAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIGlmKHVzZXI/Lmdyb3Vwcz8uaW5jbHVkZXMoQ0xTU19GT0xMT1dFUlMpICYmIFxyXG4gICAgICAgICAgICAgICAgdGVtcGxhdGU/Lm5hbWUgIT09IEJBU0VMSU5FX1RFTVBMQVRFX05BTUUpe1xyXG4gICAgICAgICAgICAgICAgc2V0RWRpdGFibGUodHJ1ZSk7XHJcbiAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgICAgICBzZXRFZGl0YWJsZShmYWxzZSk7ICAgICAgXHJcbiAgICAgIH0sIFt0ZW1wbGF0ZSwgdXNlcl0pXHJcbiAgIFxyXG4gICAgLy8gUmVhY3QudXNlRWZmZWN0KCgpID0+IHsgICAgICAgIFxyXG4gICAgLy8gICAgIGlmKHVzZXIgJiYgdGVtcGxhdGUpe1xyXG5cclxuICAgIC8vICAgICAgICAgaWYoIXRlbXBsYXRlLmlzQWN0aXZlKXtcclxuICAgIC8vICAgICAgICAgICAgc2V0RWRpdGFibGUoZmFsc2UpO1xyXG4gICAgLy8gICAgICAgICAgICByZXR1cm47XHJcbiAgICAvLyAgICAgICAgIH1cclxuXHJcbiAgICAvLyAgICAgICAgIGNvbnN0IGlzVGVtcGxhdGVFZGl0YWJsZSA9IFxyXG4gICAgLy8gICAgICAgICAodXNlcj8uZ3JvdXBzPy5pbmNsdWRlcyhDTFNTX0FETUlOKSkgfHwgXHJcbiAgICAvLyAgICAgICAgICh0ZW1wbGF0ZS5uYW1lICE9PSBCQVNFTElORV9URU1QTEFURV9OQU1FICYmIFxyXG4gICAgLy8gICAgICAgICAgICAgdXNlci5ncm91cHM/LmluY2x1ZGVzKENMU1NfRURJVE9SKSk7XHJcbiAgICAvLyAgICAgICAgIHNldEVkaXRhYmxlKGlzVGVtcGxhdGVFZGl0YWJsZSk7XHJcbiAgICAvLyAgICAgfVxyXG4gICAgLy8gfSwgW3RlbXBsYXRlLCB1c2VyXSlcclxuICAgIFxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpPT4geyBcclxuICAgICAgICBzZXRJbmRpY2F0b3JzKChjb21wb25lbnQuaW5kaWNhdG9ycyBhcyBhbnkpLm9yZGVyQnkoJ25hbWUnKSlcclxuICAgIH0sW2NvbXBvbmVudF0pOyAgXHJcbiAgICAgICBcclxuICAgIGNvbnN0IGNyZWF0ZU5ld0luZGljYXRvcj0gYXN5bmMgKCk9PntcclxuXHJcbiAgICAgICAgY29uc3Qgd2VpZ2h0cyA9IFtcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgbmFtZTogUkFOSyxcclxuICAgICAgICAgICAgICAgIGFkanVzdGVkV2VpZ2h0OiAwLFxyXG4gICAgICAgICAgICAgICAgaW5kaWNhdG9ySWQ6ICcnLFxyXG4gICAgICAgICAgICAgICAgc2NhbGVGYWN0b3I6IE9USEVSX1dFSUdIVFNfU0NBTEVfRkFDVE9SLFxyXG4gICAgICAgICAgICAgICAgd2VpZ2h0OiAxICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIH0gYXMgSW5kaWNhdG9yV2VpZ2h0LFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBuYW1lOiBMSUZFX1NBRkVUWSxcclxuICAgICAgICAgICAgICAgIGFkanVzdGVkV2VpZ2h0OiAwLFxyXG4gICAgICAgICAgICAgICAgaW5kaWNhdG9ySWQ6ICcnLFxyXG4gICAgICAgICAgICAgICAgc2NhbGVGYWN0b3I6IExJRkVfU0FGRVRZX1NDQUxFX0ZBQ1RPUixcclxuICAgICAgICAgICAgICAgIHdlaWdodDogMSAgICAgICAgICAgIFxyXG4gICAgICAgICAgICB9IGFzIEluZGljYXRvcldlaWdodCxcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgbmFtZTogUFJPUEVSVFlfUFJPVEVDVElPTixcclxuICAgICAgICAgICAgICAgIGFkanVzdGVkV2VpZ2h0OiAwLFxyXG4gICAgICAgICAgICAgICAgaW5kaWNhdG9ySWQ6ICcnLFxyXG4gICAgICAgICAgICAgICAgc2NhbGVGYWN0b3I6IE9USEVSX1dFSUdIVFNfU0NBTEVfRkFDVE9SLFxyXG4gICAgICAgICAgICAgICAgd2VpZ2h0OiAxICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIH0gYXMgSW5kaWNhdG9yV2VpZ2h0LFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBuYW1lOiBJTkNJREVOVF9TVEFCSUxJWkFUSU9OLFxyXG4gICAgICAgICAgICAgICAgYWRqdXN0ZWRXZWlnaHQ6IDAsXHJcbiAgICAgICAgICAgICAgICBpbmRpY2F0b3JJZDogJycsXHJcbiAgICAgICAgICAgICAgICBzY2FsZUZhY3RvcjogT1RIRVJfV0VJR0hUU19TQ0FMRV9GQUNUT1IsXHJcbiAgICAgICAgICAgICAgICB3ZWlnaHQ6IDEgICAgICAgICAgICBcclxuICAgICAgICAgICAgfSBhcyBJbmRpY2F0b3JXZWlnaHQsXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIG5hbWU6IEVOVklST05NRU5UX1BSRVNFUlZBVElPTixcclxuICAgICAgICAgICAgICAgIGFkanVzdGVkV2VpZ2h0OiAwLFxyXG4gICAgICAgICAgICAgICAgaW5kaWNhdG9ySWQ6ICcnLFxyXG4gICAgICAgICAgICAgICAgc2NhbGVGYWN0b3I6IE9USEVSX1dFSUdIVFNfU0NBTEVfRkFDVE9SLFxyXG4gICAgICAgICAgICAgICAgd2VpZ2h0OiAxICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIH0gYXMgSW5kaWNhdG9yV2VpZ2h0XHJcbiAgICAgICAgXVxyXG5cclxuICAgICAgICBjb25zdCBleGlzdGluZ0luZGljYXRvcnMgPSBpbmRpY2F0b3JzICB8fCBbXSBhcyBJbmRpY2F0b3JUZW1wbGF0ZVtdXHJcblxyXG4gICAgICAgIGNvbnN0IG5ld0luZGljYXRvciA9IHtcclxuICAgICAgICAgICAgbmFtZTogJycsXHJcbiAgICAgICAgICAgIGlzQmVpbmdFZGl0ZWQ6IHRydWUsXHJcbiAgICAgICAgICAgIGlzTmV3OiB0cnVlLFxyXG4gICAgICAgICAgICB0ZW1wbGF0ZU5hbWU6IHRlbXBsYXRlLm5hbWUsXHJcbiAgICAgICAgICAgIHdlaWdodHM6IHdlaWdodHMsICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIGNvbXBvbmVudElkOiBjb21wb25lbnQuaWQsXHJcbiAgICAgICAgICAgIHRlbXBsYXRlSWQ6IHRlbXBsYXRlLmlkLFxyXG4gICAgICAgICAgICBjb21wb25lbnROYW1lOiBjb21wb25lbnQubmFtZSxcclxuICAgICAgICAgICAgbGlmZWxpbmVOYW1lOiBsaWZlbGluZS5uYW1lLFxyXG4gICAgICAgIH0gYXMgSW5kaWNhdG9yVGVtcGxhdGU7XHJcbiAgICAgICAgXHJcbiAgICAgICAgc2V0SW5kaWNhdG9ycyhbLi4uZXhpc3RpbmdJbmRpY2F0b3JzLCBuZXdJbmRpY2F0b3JdKTsgXHJcbiAgICB9XHJcblxyXG4gICAgY29uc3Qgb25DYW5jZWxJbmRpY2F0b3JDcmVhdGUgPSgpPT57XHJcbiAgICAgICAgc2V0SW5kaWNhdG9ycyhpbmRpY2F0b3JzLmZpbHRlcihpID0+ICFpLmlzTmV3KSk7ICAgICAgICAgXHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIChcclxuICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cImxpZmVsaW5lLWNvbXBvbmVudC1jb250YWluZXJcIlxyXG4gICAgICAgICAgc3R5bGU9e3tcclxuICAgICAgICAgICAgbWFyZ2luVG9wOiBpc0VkaXRhYmxlID8gJzAuNWVtJyA6ICcxLjhlbSdcclxuICAgICAgICAgIH19PlxyXG4gICAgICAgICAgICA8c3R5bGU+e1xyXG4gICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgIC5saWZlbGluZS1jb21wb25lbnQtY29udGFpbmVye1xyXG4gICAgICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICAgICAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uO1xyXG4gICAgICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgICAgICAgbWFyZ2luLWJvdHRvbTogMC41ZW07XHJcbiAgICAgICAgICAgICAgIH0gXHJcbiAgICAgICAgICAgICAgIC5jb21wb25lbnQtbGFiZWx7XHJcbiAgICAgICAgICAgICAgICBmb250LXNpemU6IDE4cHg7XHJcbiAgICAgICAgICAgICAgICBjb2xvcjogIzUzNGM0YztcclxuICAgICAgICAgICAgICAgIGZvbnQtd2VpZ2h0OiBib2xkO1xyXG4gICAgICAgICAgICAgICAgcGFkZGluZzogMCAwIDAgMS4yZW07XHJcbiAgICAgICAgICAgICAgICB0ZXh0LWRlY29yYXRpb246IHVuZGVybGluZTtcclxuICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAuY29tcG9uZW50LWRldGFpbHN7XHJcbiAgICAgICAgICAgICAgICAgYmFja2dyb3VuZC1jb2xvcjogd2hpdGU7XHJcbiAgICAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgICAgcGFkZGluZzogMTVweCAwIDAgMDtcclxuICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAubGlmZWxpbmUtY29tcG9uZW50LXRhYmxle1xyXG4gICAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgIH0gICAgXHJcbiAgICAgICAgICAgICAgIC5saWZlbGluZS1jb21wb25lbnQtdGFibGUgLnRhYmxlLWhlYWRlci1kYXRhe1xyXG4gICAgICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgICAgd2lkdGg6IDEwZW07XHJcbiAgICAgICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjtcclxuICAgICAgICAgICAgICAgICBmbGV4LXdyYXA6bm93cmFwO1xyXG4gICAgICAgICAgICAgICAgIGp1c3RpZnktY29udGVudDogY2VudGVyO1xyXG4gICAgICAgICAgICAgICB9IFxyXG4gICAgICAgICAgICAgICAubGlmZWxpbmUtY29tcG9uZW50LXRhYmxlIC50YWJsZS1oZWFkZXItZGF0YSBzdmd7XHJcbiAgICAgICAgICAgICAgICAgd2lkdGg6IDQwcHg7XHJcbiAgICAgICAgICAgICAgIH0gICAgICAgICBcclxuICAgICAgICAgICAgICAgLmxpZmVsaW5lLWNvbXBvbmVudC10YWJsZSAuY29tbWFuZHtcclxuICAgICAgICAgICAgICAgIGNvbG9yOiBncmF5O1xyXG4gICAgICAgICAgICAgICAgY3Vyc29yOiBwb2ludGVyO1xyXG4gICAgICAgICAgICAgICAgd2lkdGg6IDQwcHggIWltcG9ydGFudDtcclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgLmxpZmVsaW5lLWNvbXBvbmVudC10YWJsZSB0ZC5kYXRhe1xyXG4gICAgICAgICAgICAgICAgZm9udC1zaXplOiAxM3B4OyAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgY29sb3I6ICM1MzRjNGM7XHJcbiAgICAgICAgICAgICAgICB0ZXh0LWFsaWduOiBjZW50ZXI7XHJcbiAgICAgICAgICAgICAgICBib3JkZXItcmlnaHQ6IDFweCBzb2xpZCB3aGl0ZVxyXG4gICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAubGlmZWxpbmUtY29tcG9uZW50LXRhYmxlIC50YWJsZUJvZHkgdGR7XHJcbiAgICAgICAgICAgICAgICBjb2xvcjogIzUzNGM0YztcclxuICAgICAgICAgICAgICAgIHRleHQtYWxpZ246IGNlbnRlcjtcclxuICAgICAgICAgICAgICAgIGZvbnQtc2l6ZTogMC44cmVtO1xyXG4gICAgICAgICAgICAgICAgcGFkZGluZzogLjhlbTtcclxuICAgICAgICAgICAgICAgIGZvbnQtd2VpZ2h0OiBib2xkO1xyXG4gICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAubGlmZWxpbmUtY29tcG9uZW50LXRhYmxlIC50YWJsZUJvZHkgdHI6bnRoLWNoaWxkKG9kZCl7XHJcbiAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kLWNvbG9yOiAjZjBmMGYwO1xyXG4gICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAuYWRkLW5ld3tcclxuICAgICAgICAgICAgICAgIHRleHQtYWxpZ246IHJpZ2h0O1xyXG4gICAgICAgICAgICAgICAgbWFyZ2luOiAxMHB4IDVweCAwIDA7XHJcbiAgICAgICAgICAgICAgICBmb250LXdlaWdodDogYm9sZDtcclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgLmFkZC1uZXcgYnV0dG9ue1xyXG4gICAgICAgICAgICAgICAgIGZvbnQtd2VpZ2h0OiBub3JtYWw7XHJcbiAgICAgICAgICAgICAgICAgcGFkZGluZzogMC41ZW07XHJcbiAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgIC50YWJsZS1oZWFkZXItZGF0YSBoNntcclxuICAgICAgICAgICAgICAgIG1hcmdpbjogMDtcclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgfTwvc3R5bGU+XHJcbiAgICAgICAgICAgIDxMYWJlbCBjaGVjayBjbGFzc05hbWU9XCJjb21wb25lbnQtbGFiZWxcIj5cclxuICAgICAgICAgICAgICAge2NvbXBvbmVudC50aXRsZX1cclxuICAgICAgICAgICAgPC9MYWJlbD5cclxuICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJjb21wb25lbnQtZGV0YWlsc1wiPlxyXG4gICAgICAgICAgICAgICAgPHRhYmxlIGNsYXNzTmFtZT1cImxpZmVsaW5lLWNvbXBvbmVudC10YWJsZSB0YWJsZVwiPlxyXG4gICAgICAgICAgICAgICAgICAgIDx0aGVhZCBzdHlsZT17e2JhY2tncm91bmRDb2xvcjogJyNjNWM1YzUnfX0+ICAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDx0cj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBjbGFzc05hbWU9XCJkYXRhXCIgc3R5bGU9e3t3aWR0aDogJzQwMHB4J319PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxoNj5JbmRpY2F0b3I8L2g2PjwvdGQ+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8dGQgY2xhc3NOYW1lPVwiZGF0YVwiPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwidGFibGUtaGVhZGVyLWRhdGFcIj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPGg2PlJhbms8L2g2PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8SGVscEZpbGxlZCBzaXplPXsyMH0gdGl0bGU9XCJIb3cgaW1wb3J0YW50IGlzIHRoZSBpbmRpY2F0b3IgdG8geW91ciBqdXJpc2RpY3Rpb24gb3IgaGF6YXJkPygxPU1vc3QgSW1wb3J0YW50LCA1PUxlYXN0IEltcG9ydGFudClcIi8+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPHRkIGNsYXNzTmFtZT1cImRhdGFcIj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cInRhYmxlLWhlYWRlci1kYXRhXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8aDY+TGlmZSBTYWZldHk8L2g2PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPEhlbHBGaWxsZWQgc2l6ZT17MjB9IHRpdGxlPVwiSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIExpZmUgU2FmZXR5P1wiLz5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPHRkIGNsYXNzTmFtZT1cImRhdGFcIj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cInRhYmxlLWhlYWRlci1kYXRhXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxoNj5JbmNpZGVudCBTdGFiaWxpemF0aW9uPC9oNj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPEhlbHBGaWxsZWQgc2l6ZT17MjB9IHRpdGxlPVwiSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIEluY2lkZW50IFN0YWJpbGl6YXRpb24/XCIvPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPHRkIGNsYXNzTmFtZT1cImRhdGFcIj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwidGFibGUtaGVhZGVyLWRhdGFcIj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8aDY+UHJvcGVydHkgUHJvdGVjdGlvbjwvaDY+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPEhlbHBGaWxsZWQgc2l6ZT17MjB9IHRpdGxlPVwiSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIFByb3BlcnR5IFByb3RlY3Rpb24/XCIvPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPHRkIGNsYXNzTmFtZT1cImRhdGFcIj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cInRhYmxlLWhlYWRlci1kYXRhXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxoNj5FbnZpcm9ubWVudGFsIFByZXNlcnZhdGlvbjwvaDY+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxIZWxwRmlsbGVkIHNpemU9ezIwfSB0aXRsZT1cIkhvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byBFbnZpcm9ubWVudGFsIFByZXNlcnZhdGlvbj9cIi8+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPHRkIGNsYXNzTmFtZT1cImRhdGFcIj48L3RkPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxyXG4gICAgICAgICAgICAgICAgICAgIDwvdGhlYWQ+XHJcbiAgICAgICAgICAgICAgICAgICAgPHRib2R5IGNsYXNzTmFtZT1cInRhYmxlQm9keVwiPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7ICAgICAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICBpbmRpY2F0b3JzLm1hcCgoaW5kaWNhdG9yOiBJbmRpY2F0b3JUZW1wbGF0ZSkgPT57XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIDxFZGl0YWJsZVRhYmxlUm93IFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBrZXk9e2luZGljYXRvci5pZH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaW5kaWNhdG9yPXtpbmRpY2F0b3J9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlzRWRpdGFibGU9e2lzRWRpdGFibGV9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbXBvbmVudD17Y29tcG9uZW50fVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25maWc9e2NvbmZpZ31cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGVtcGxhdGU9e3RlbXBsYXRlfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZXRFcnJvcj17c2V0RXJyb3J9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2FuY2VsPXtvbkNhbmNlbEluZGljYXRvckNyZWF0ZX1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25BY3Rpb25Db21wbGV0ZT17b25BY3Rpb25Db21wbGV0ZX1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvPiBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgfSlcclxuICAgICAgICAgICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgPC90Ym9keT5cclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICghaXNFZGl0YWJsZSkgPyBudWxsXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDogKFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPHRmb290PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0cj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPHRkIGNvbFNwYW49ezh9PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJhZGQtbmV3XCI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8QnV0dG9uIGRpc2FibGVkPXtpbmRpY2F0b3JzPy5zb21lKGkgPT5pLmlzTmV3KX1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKT0+Y3JlYXRlTmV3SW5kaWNhdG9yKCl9IFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRpdGxlPVwiQWRkIG5ldyBpbmRpY2F0b3JcIlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNpemU9XCJkZWZhdWx0XCI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPEljb24gaWNvbj1cIjxzdmcgdmlld0JveD0mcXVvdDswIDAgMTYgMTYmcXVvdDsgZmlsbD0mcXVvdDtub25lJnF1b3Q7IHhtbG5zPSZxdW90O2h0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnJnF1b3Q7PjxwYXRoIGQ9JnF1b3Q7TTcuNSAwYS41LjUgMCAwIDAtLjUuNVY3SC41YS41LjUgMCAwIDAgMCAxSDd2Ni41YS41LjUgMCAwIDAgMSAwVjhoNi41YS41LjUgMCAwIDAgMC0xSDhWLjVhLjUuNSAwIDAgMC0uNS0uNVomcXVvdDsgZmlsbD0mcXVvdDsjMDAwJnF1b3Q7PjwvcGF0aD48L3N2Zz5cIlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzaXplPVwibVwiLz5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBBZGQgTmV3IEluZGljYXRvclxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9CdXR0b24+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPC90Zm9vdD5cclxuICAgICAgICAgICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICAgICAgIH0gICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgPC90YWJsZT5cclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgIGVycm9yID8gKDxDbHNzRXJyb3IgZXJyb3I9e2Vycm9yfS8+KTogbnVsbFxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICA8L2Rpdj5cclxuICAgIClcclxufSIsImltcG9ydCB7IExvYWRpbmcgfSBmcm9tIFwiamltdS11aVwiXHJcbmltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5cclxuY29uc3QgQ2xzc0xvYWRpbmcgPSh7bWVzc2FnZX06e21lc3NhZ2U/OnN0cmluZ30pID0+e1xyXG4gICAgcmV0dXJuKCAgICAgICAgXHJcbiAgICAgICAgPGRpdlxyXG4gICAgICAgICAgICBzdHlsZT17e1xyXG4gICAgICAgICAgICAgICAgaGVpZ2h0OiAnMTAwJScsXHJcbiAgICAgICAgICAgICAgICB3aWR0aDogJzEwMCUnLFxyXG4gICAgICAgICAgICAgICAgcG9zaXRpb246ICdhYnNvbHV0ZScsXHJcbiAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kOiAncmdiKDAgMCAwIC8gMTMlKScsXHJcbiAgICAgICAgICAgICAgICB0b3A6IDAsICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgIGxlZnQ6IDAsXHJcbiAgICAgICAgICAgICAgICB6SW5kZXg6IDk5OTk5OSxcclxuICAgICAgICAgICAgICAgIGRpc3BsYXk6ICdmbGV4JyxcclxuICAgICAgICAgICAgICAgIGp1c3RpZnlDb250ZW50OiAnY2VudGVyJyxcclxuICAgICAgICAgICAgICAgIGFsaWduSXRlbXM6ICdjZW50ZXInXHJcbiAgICAgICAgICAgIH19XHJcbiAgICAgICAgICAgID5cclxuICAgICAgICAgICAgPExvYWRpbmdcclxuICAgICAgICAgICAgICAgIGNsYXNzTmFtZT1cIlwiXHJcbiAgICAgICAgICAgICAgICB0eXBlPVwiU0VDT05EQVJZXCJcclxuICAgICAgICAgICAgLz5cclxuICAgICAgICAgICAgPGgzPnttZXNzYWdlfTwvaDM+XHJcbiAgICAgICAgPC9kaXY+XHJcbiAgICApXHJcbn1cclxuZXhwb3J0IGRlZmF1bHQgQ2xzc0xvYWRpbmc7IiwiXHJcbmltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5pbXBvcnQgeyBNb2RhbCwgTW9kYWxIZWFkZXIsIE1vZGFsQm9keSwgTW9kYWxGb290ZXIsIEJ1dHRvbiB9IGZyb20gXCJqaW11LXVpXCJcclxuaW1wb3J0IENsc3NMb2FkaW5nIGZyb20gXCIuL2Nsc3MtbG9hZGluZ1wiXHJcblxyXG4vLyBleHBvcnQgaW50ZXJmYWNlIE1vZGFsUHJvcHMge1xyXG4vLyAgICAgdGl0bGU6IHN0cmluZztcclxuLy8gICAgIHZpc2libGU6IGJvb2xlYW47XHJcbi8vICAgICBkaXNhYmxlOiBib29sZWFuO1xyXG4vLyAgICAgY2hpbGRyZW46IGFueTtcclxuLy8gICAgIHRvZ2dsZVZpc2liaWxpdHk6IEZ1bmN0aW9uO1xyXG4vLyAgICAgc2F2ZTogRnVuY3Rpb247XHJcbi8vICAgICBjYW5jZWw6IEZ1bmN0aW9uO1xyXG4vLyB9XHJcblxyXG5leHBvcnQgY29uc3QgQ2xzc01vZGFsID0ocHJvcHMpPT57XHJcbiAgICByZXR1cm4gKFxyXG4gICAgICAgIDxNb2RhbCBpc09wZW49e3Byb3BzLnZpc2libGV9IGNlbnRlcmVkPXt0cnVlfSBjbGFzc05hbWU9XCJjbHNzLW1vZGFsXCI+XHJcbiAgICAgICAgICAgIDxzdHlsZT5cclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jbHNzLW1vZGFsIC5tb2RhbC1jb250ZW50e1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQtc2l6ZTogMS4zcmVtO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgZmxleC1kaXJlY3Rpb246IGNvbHVtblxyXG4gICAgICAgICAgICAgICAgICAgICAgICB9ICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgLm1vZGFsLXRpdGxle1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC1zaXplOiAxLjFlbTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfSAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAuY2xzcy1tb2RhbCBpbnB1dHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhZGRpbmctbGVmdDogMHB4O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9ICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAuY2xzcy1tb2RhbCAuamltdS1pbnB1dCBzcGFue1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiA0MHB4O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC1zaXplOiAuOWVtO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9ICAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAuY2xzcy1tb2RhbCBsYWJlbHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiBncmF5O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9ICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAuY2xzcy1tb2RhbCAuamltdS1kcm9wZG93bi1idXR0b257XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LXNpemU6IDFlbTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfSAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgLm1vZGFsLWl0ZW17XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBtYXJnaW46IDEwcHggMDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfSAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAuY2xzcy1tb2RhbCB0ZXh0YXJlYXtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQtc2l6ZTogMC44ZW07XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH0gIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAuY2xzcy1tb2RhbCAuc3BhY2Vye1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDFlbTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgPC9zdHlsZT5cclxuICAgICAgICAgICAgPE1vZGFsSGVhZGVyIHRvZ2dsZT17KCk9PnByb3BzLnRvZ2dsZVZpc2liaWxpdHkoZmFsc2UpfT5cclxuICAgICAgICAgICAgICAgIHtwcm9wcy50aXRsZX1cclxuICAgICAgICAgICAgPC9Nb2RhbEhlYWRlcj5cclxuICAgICAgICAgICAgPE1vZGFsQm9keT5cclxuICAgICAgICAgICAgICAgIHtwcm9wcy5jaGlsZHJlbn0gICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICA8L01vZGFsQm9keT5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcHJvcHMuaGlkZUZvb3RlciAmJiBwcm9wcy5oaWRlRm9vdGVyID09IHRydWUgPyBudWxsIDpcclxuICAgICAgICAgICAgICAgIChcclxuICAgICAgICAgICAgICAgICAgICA8TW9kYWxGb290ZXIgPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8QnV0dG9uIG9uQ2xpY2s9eygpID0+IChwcm9wcy5jYW5jZWwgPyBwcm9wcy5jYW5jZWwoKSA6IHByb3BzLnRvZ2dsZVZpc2liaWxpdHkoZmFsc2UpKX0+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7cHJvcHMubm9CdXR0b25UaXRsZSB8fCAnQ2FuY2VsJ31cclxuICAgICAgICAgICAgICAgICAgICAgICAgPC9CdXR0b24+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwic3BhY2VyXCIvPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8QnV0dG9uIGRhdGEtdGVzdGlkPVwiYnRuU2F2ZVwiIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZGlzYWJsZWQ9e3Byb3BzLmRpc2FibGV9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiBwcm9wcy5zYXZlKCl9PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge3Byb3BzLnllc0J1dHRvblRpdGxlIHx8ICdTYXZlJ31cclxuICAgICAgICAgICAgICAgICAgICAgICAgPC9CdXR0b24+XHJcbiAgICAgICAgICAgICAgICAgICAgPC9Nb2RhbEZvb3Rlcj5cclxuICAgICAgICAgICAgICAgIClcclxuICAgICAgICAgICAgfSAgICAgICAgICAgIFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAocHJvcHMubG9hZGluZykgPyA8Q2xzc0xvYWRpbmcvPiA6IG51bGwgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICA8L01vZGFsPiBcclxuICAgIClcclxufSIsImltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5cclxuY29uc3QgQ2xzc05vRGF0YSA9KHttZXNzYWdlfTp7bWVzc2FnZTpzdHJpbmd9KSA9PntcclxuICAgIHJldHVybiggICAgICAgIFxyXG4gICAgICAgIDxkaXZcclxuICAgICAgICAgICAgc3R5bGU9e3tcclxuICAgICAgICAgICAgICAgIGhlaWdodDogJzEwMCUnLFxyXG4gICAgICAgICAgICAgICAgd2lkdGg6ICcxMDAlJyxcclxuICAgICAgICAgICAgICAgIHBvc2l0aW9uOiAnYWJzb2x1dGUnLFxyXG4gICAgICAgICAgICAgICAgYmFja2dyb3VuZDogJ3JnYigwIDAgMCAvIDEzJSknLFxyXG4gICAgICAgICAgICAgICAgdG9wOiAwLCAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICBsZWZ0OiAwLFxyXG4gICAgICAgICAgICAgICAgekluZGV4OiA5OTk5OTksXHJcbiAgICAgICAgICAgICAgICBkaXNwbGF5OiAnZmxleCcsXHJcbiAgICAgICAgICAgICAgICBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicsXHJcbiAgICAgICAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJ1xyXG4gICAgICAgICAgICB9fVxyXG4gICAgICAgICAgICA+ICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIDxoMz57bWVzc2FnZX08L2gzPlxyXG4gICAgICAgIDwvZGl2PlxyXG4gICAgKVxyXG59XHJcbmV4cG9ydCBkZWZhdWx0IENsc3NOb0RhdGE7IiwiaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiXHJcbmltcG9ydCB7IENsc3NEcm9wZG93biB9IGZyb20gXCIuL2Nsc3MtZHJvcGRvd25cIlxyXG5pbXBvcnQgeyBCdXR0b24gfSBmcm9tIFwiamltdS11aVwiXHJcbmltcG9ydCB7IFBsdXNDaXJjbGVPdXRsaW5lZCB9IGZyb20gXCJqaW11LWljb25zL291dGxpbmVkL2VkaXRvci9wbHVzLWNpcmNsZVwiXHJcbmltcG9ydCB7IGRlbGV0ZU9yZ2FuaXphdGlvbiwgZGlzcGF0Y2hBY3Rpb24gfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9hcGlcIlxyXG5pbXBvcnQgeyBPcmdhbml6YXRpb24gfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9kYXRhLWRlZmluaXRpb25zXCJcclxuaW1wb3J0IHsgQ0xTU0FjdGlvbktleXMgfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jbHNzLXN0b3JlXCJcclxuXHJcblxyXG5leHBvcnQgY29uc3QgT3JnYW5pemF0aW9uc0Ryb3Bkb3duID0oe2NvbmZpZywgb3JnYW5pemF0aW9ucywgc2VsZWN0ZWRPcmdhbml6YXRpb24sIFxyXG4gICAgc2V0T3JnYW5pemF0aW9uLCB2ZXJ0aWNhbCwgdG9nZ2xlTmV3T3JnYW5pemF0aW9uTW9kYWx9KT0+e1xyXG5cclxuICAgIGNvbnN0IFtsb2NhbE9yZ2FuaXphdGlvbnMsIHNldExvY2FsT3JnYW5pemF0aW9uc10gPSBSZWFjdC51c2VTdGF0ZTxPcmdhbml6YXRpb25bXT4oW10pO1xyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKT0+e1xyXG4gICAgICAgIGlmKG9yZ2FuaXphdGlvbnMpeyBcclxuICAgICAgICAgICAgc2V0TG9jYWxPcmdhbml6YXRpb25zKFsuLi5vcmdhbml6YXRpb25zXSBhcyBPcmdhbml6YXRpb25bXSlcclxuICAgICAgICB9XHJcbiAgICB9LCBbb3JnYW5pemF0aW9uc10pXHJcbiAgICBcclxuICAgIGNvbnN0IHJlbW92ZU9yZ2FuaXphdGlvbiA9YXN5bmMgKG9yZ2FuaXphdGlvbjogT3JnYW5pemF0aW9uKT0+e1xyXG4gICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGRlbGV0ZU9yZ2FuaXphdGlvbihvcmdhbml6YXRpb24sIGNvbmZpZyk7XHJcbiAgICAgIGlmKHJlc3BvbnNlLmVycm9ycyl7XHJcbiAgICAgICBjb25zb2xlLmxvZyhyZXNwb25zZS5lcnJvcnMpO1xyXG4gICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgcmVzcG9uc2UuZXJyb3JzKTtcclxuICAgICAgIHJldHVybjtcclxuICAgICAgfVxyXG4gICAgICBjb25zb2xlLmxvZyhgJHtvcmdhbml6YXRpb24udGl0bGV9IGRlbGV0ZWRgKVxyXG4gICAgICBzZXRMb2NhbE9yZ2FuaXphdGlvbnMoWy4uLmxvY2FsT3JnYW5pemF0aW9ucy5maWx0ZXIobyA9PiBvLmlkICE9PSBvcmdhbml6YXRpb24uaWQpXSk7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gKFxyXG4gICAgICAgIDxkaXYgc3R5bGU9e3tkaXNwbGF5OiB2ZXJ0aWNhbCA/ICdibG9jayc6ICdmbGV4JyxcclxuICAgICAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcid9fT5cclxuICAgICAgICAgICAgIDxDbHNzRHJvcGRvd24gaXRlbXM9e2xvY2FsT3JnYW5pemF0aW9uc31cclxuICAgICAgICAgICAgICAgIGl0ZW09e3NlbGVjdGVkT3JnYW5pemF0aW9ufSBcclxuICAgICAgICAgICAgICAgIGRlbGV0YWJsZT17dHJ1ZX1cclxuICAgICAgICAgICAgICAgIHNldEl0ZW09e3NldE9yZ2FuaXphdGlvbn0gXHJcbiAgICAgICAgICAgICAgICBkZWxldGVJdGVtPXtyZW1vdmVPcmdhbml6YXRpb259Lz5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICB0b2dnbGVOZXdPcmdhbml6YXRpb25Nb2RhbCA/IChcclxuICAgICAgICAgICAgICAgIHZlcnRpY2FsPyAoXHJcbiAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiBkYXRhLXRlc3RpZD1cImJ0blNob3dBZGRPcmdhbml6YXRpb25cIiAgY2xhc3NOYW1lPVwiIGFkZC1saW5rXCJcclxuICAgICAgICAgICAgICAgICAgICAgICAgIHR5cGU9XCJsaW5rXCIgc3R5bGU9e3t0ZXh0QWxpZ246ICdsZWZ0J319XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2s9eygpPT4gdG9nZ2xlTmV3T3JnYW5pemF0aW9uTW9kYWwodHJ1ZSl9PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICBBZGQgTmV3IE9yZ2FuaXphdGlvblxyXG4gICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxyXG4gICAgICAgICAgICAgICAgICAgKTooXHJcbiAgICAgICAgICAgICAgICAgICAgPFBsdXNDaXJjbGVPdXRsaW5lZCBjbGFzc05hbWU9XCJhY3Rpb24taWNvblwiIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICBkYXRhLXRlc3RpZD1cImJ0bkFkZE5ld09yZ2FuaXphdGlvblwiIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICB0aXRsZT1cIkFkZCBOZXcgT3JnYW5pemF0aW9uXCIgc2l6ZT17MzB9IGNvbG9yPXsnZ3JheSd9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2s9eygpPT4gdG9nZ2xlTmV3T3JnYW5pemF0aW9uTW9kYWwodHJ1ZSl9Lz4gICAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgICAgICk6IG51bGxcclxuICAgICAgICAgICAgfSAgIFxyXG4gICAgICAgIDwvZGl2PlxyXG4gICAgKVxyXG59IiwiaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiO1xyXG5pbXBvcnQgeyBDbG9zZU91dGxpbmVkIH0gZnJvbSBcImppbXUtaWNvbnMvb3V0bGluZWQvZWRpdG9yL2Nsb3NlXCI7XHJcbmltcG9ydCB7IEVkaXRPdXRsaW5lZCB9IGZyb20gXCJqaW11LWljb25zL291dGxpbmVkL2VkaXRvci9lZGl0XCI7XHJcbmltcG9ydCB7IFNhdmVGaWxsZWQgfSBmcm9tICdqaW11LWljb25zL2ZpbGxlZC9lZGl0b3Ivc2F2ZSdcclxuaW1wb3J0IHsgXHJcbiAgQnV0dG9uLFxyXG4gIExhYmVsLFRleHRJbnB1dFxyXG4gICB9IGZyb20gXCJqaW11LXVpXCI7XHJcbmltcG9ydCBDbHNzTG9hZGluZyBmcm9tIFwiLi4vLi4vLi4vY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWxvYWRpbmdcIjtcclxuaW1wb3J0IHsgQ0xTU1RlbXBsYXRlLCBcclxuICBDbHNzVXNlciwgSGF6YXJkLCBcclxuICBPcmdhbml6YXRpb24gfSBmcm9tIFwiLi4vLi4vLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9kYXRhLWRlZmluaXRpb25zXCI7XHJcbmltcG9ydCB7IEJBU0VMSU5FX1RFTVBMQVRFX05BTUUsIFxyXG4gIENMU1NfQURNSU4sIENMU1NfRURJVE9SLCBDTFNTX0ZPTExPV0VSUyB9IGZyb20gXCIuLi8uLi8uLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2NvbnN0YW50c1wiO1xyXG5pbXBvcnQgeyBSZWFjdFJlZHV4IH0gZnJvbSBcImppbXUtY29yZVwiO1xyXG5pbXBvcnQgeyBkaXNwYXRjaEFjdGlvbiwgXHJcbiAgZ2V0QXNzZXNzbWVudE5hbWVzLFxyXG4gIHVwZGF0ZVRlbXBsYXRlT3JnYW5pemF0aW9uQW5kSGF6YXJkIH0gZnJvbSBcIi4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXBpXCI7XHJcbmltcG9ydCB7IENMU1NBY3Rpb25LZXlzIH0gZnJvbSBcIi4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY2xzcy1zdG9yZVwiO1xyXG5pbXBvcnQgeyBwYXJzZURhdGUgfSBmcm9tIFwiLi4vLi4vLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy91dGlsc1wiO1xyXG5pbXBvcnQgeyBJQ29kZWRWYWx1ZSB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC10eXBlc1wiO1xyXG5pbXBvcnQgeyBDbHNzRHJvcGRvd24gfSBmcm9tIFwiLi4vLi4vLi4vY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWRyb3Bkb3duXCI7XHJcbmltcG9ydCB7IE9yZ2FuaXphdGlvbnNEcm9wZG93biB9IGZyb20gXCIuLi8uLi8uLi9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3Mtb3JnYW5pemF0aW9ucy1kcm9wZG93blwiO1xyXG5pbXBvcnQgeyBIYXphcmRzRHJvcGRvd24gfSBmcm9tIFwiLi4vLi4vLi4vY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWhhemFyZHMtZHJvcGRvd25cIjtcclxuaW1wb3J0IHsgVGVtcGxhdGVBc3Nlc3NtZW50VmlldyB9IGZyb20gXCIuLi8uLi8uLi9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtYXNzZXNzbWVudHMtbGlzdFwiO1xyXG5jb25zdCB7IHVzZVNlbGVjdG9yIH0gPSBSZWFjdFJlZHV4O1xyXG5cclxuZXhwb3J0IGNvbnN0IERldGFpbEhlYWRlcldpZGdldCA9KFxyXG4gIHt0ZW1wbGF0ZSwgY29uZmlnLCBvcmdhbml6YXRpb25zLCBoYXphcmRzLCBvbkFjdGlvbkNvbXBsZXRlLCBcclxuICAgIHNlbGVjdGVkTmV3SGF6YXJkLCBzZWxlY3RlZE5ld09yZ2FuaXphdGlvbixcclxuICAgIHRvZ2dsZUhhemFyZE1vZGFsVmlzaWJpbGl0eSwgXHJcbiAgICB0b2dnbGVPcmdhbml6YXRpb25Nb2RhbFZpc2liaWxpdHl9KT0+e1xyXG5cclxuICAgIGNvbnN0IFtsb2FkaW5nLCBzZXRMb2FkaW5nXSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKTtcclxuICAgIGNvbnN0IFtpc0VkaXRpbmcsIHNldEVkaXRpbmddID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpO1xyXG4gICAgY29uc3QgW3RlbXBsYXRlTmFtZSwgc2V0VGVtcGxhdGVOYW1lXSA9IFJlYWN0LnVzZVN0YXRlKCcnKTtcclxuICAgIGNvbnN0IFtzZWxlY3RlZEhhemFyZCwgc2V0U2VsZWN0ZWRIYXphcmRdPSBSZWFjdC51c2VTdGF0ZTxIYXphcmQ+KG51bGwpO1xyXG4gICAgY29uc3QgW3NlbGVjdGVkT3JnYW5pemF0aW9uLCBzZXRTZWxlY3RlZE9yZ2FuaXphdGlvbl09UmVhY3QudXNlU3RhdGU8T3JnYW5pemF0aW9uPihudWxsKTtcclxuICAgIGNvbnN0IFthbGxvd1RvRWRpdCwgc2V0QWxsb3dUb0VkaXRdID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpO1xyXG4gICAgY29uc3QgW3N0YXR1cywgc2V0U3RhdHVzXT1SZWFjdC51c2VTdGF0ZTxhbnk+KCk7XHJcbiAgICBjb25zdCBbc3RhdHVzZXMsIHNldFN0YXR1c2VzXSA9IFJlYWN0LnVzZVN0YXRlPElDb2RlZFZhbHVlW10+KFtdKVxyXG4gICAgY29uc3QgW2Fzc2Vzc21lbnRzLCBzZXRBc3Nlc3NtZW50c109UmVhY3QudXNlU3RhdGU8YW55W10+KFtdKVxyXG4gICAgY29uc3QgW2lzQXNzZXNzbWVudHNWaXNpYmlsaXR5LCBzZXRUb2dnbGVBc3Nlc3NtZW50VmlzaWJpbGl0eV09UmVhY3QudXNlU3RhdGUoZmFsc2UpO1xyXG4gICBcclxuICAgIGNvbnN0IHVzZXIgPSB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4ge1xyXG4gICAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlLnVzZXIgYXMgQ2xzc1VzZXI7XHJcbiAgICB9KVxyXG5cclxuICAgIGNvbnN0IHRlbXBsYXRlcyA9IHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KSA9PiB7XHJcbiAgICAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy50ZW1wbGF0ZXMgYXMgQ0xTU1RlbXBsYXRlW107XHJcbiAgICB9KVxyXG4gICAgXHJcbiAgICBcclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICAgIGlmKHNlbGVjdGVkTmV3SGF6YXJkKXsgICAgICAgIFxyXG4gICAgICAgIHNldFNlbGVjdGVkSGF6YXJkKHNlbGVjdGVkTmV3SGF6YXJkKVxyXG4gICAgICB9XHJcbiAgICB9LCBbc2VsZWN0ZWROZXdIYXphcmRdKVxyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICAgIGlmKHNlbGVjdGVkTmV3T3JnYW5pemF0aW9uKXtcclxuICAgICAgICBzZXRTZWxlY3RlZE9yZ2FuaXphdGlvbihzZWxlY3RlZE5ld09yZ2FuaXphdGlvbilcclxuICAgICAgfVxyXG4gICAgfSwgW3NlbGVjdGVkTmV3T3JnYW5pemF0aW9uXSlcclxuICAgICBcclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKT0+e1xyXG4gICAgICBpZihjb25maWcpe1xyXG4gICAgICAgIGdldEFzc2Vzc21lbnROYW1lcyhjb25maWcsIHRlbXBsYXRlPy5uYW1lKVxyXG4gICAgICAgIC50aGVuKChyZXNwb25zZSkgPT4ge1xyXG4gICAgICAgICAgaWYocmVzcG9uc2UuZGF0YSl7XHJcbiAgICAgICAgICAgIHNldEFzc2Vzc21lbnRzKHJlc3BvbnNlLmRhdGEpXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgfSlcclxuICAgICAgfVxyXG4gICAgfSwgW3RlbXBsYXRlXSlcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgICAgaWYodGVtcGxhdGUpe1xyXG4gICAgICAgIGNvbnN0IHN0YXR1c0RvbWFpbnMgPSAgKHRlbXBsYXRlIGFzIENMU1NUZW1wbGF0ZSkuZG9tYWlucztcclxuICAgICAgICBzZXRTdGF0dXNlcyhzdGF0dXNEb21haW5zKTtcclxuICAgICAgfVxyXG4gICAgfSwgW3RlbXBsYXRlXSkgIFxyXG4gICAgXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCk9PiB7XHJcbiAgICAgIGlmKHRlbXBsYXRlICYmIHN0YXR1c2VzICYmIHN0YXR1c2VzLmxlbmd0aCA+IDApeyAgIFxyXG4gICAgICAgIGNvbnN0IHMgPSBzdGF0dXNlcy5maW5kKHMgPT4gcy5uYW1lID09PSB0ZW1wbGF0ZT8uc3RhdHVzLm5hbWUpO1xyXG4gICAgICAgIHRyeXtcclxuICAgICAgICAgIHNldFN0YXR1cyhzKTtcclxuICAgICAgICB9Y2F0Y2goZSl7XHJcbiAgICAgICAgICBjb25zb2xlLmxvZyhlKTtcclxuICAgICAgICB9XHJcbiAgICAgIH0gICAgIFxyXG4gICAgfSwgW3RlbXBsYXRlLCBzdGF0dXNlc10pXHJcblxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpID0+IHtcclxuICAgICAgaWYodXNlcil7IFxyXG4gICAgICAgIGlmKHVzZXI/Lmdyb3Vwcz8uaW5jbHVkZXMoQ0xTU19BRE1JTikpe1xyXG4gICAgICAgICAgc2V0QWxsb3dUb0VkaXQodHJ1ZSk7XHJcbiAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG4gIFxyXG4gICAgICAgIGlmKHVzZXI/Lmdyb3Vwcz8uaW5jbHVkZXMoQ0xTU19FRElUT1IpICYmIFxyXG4gICAgICAgICAgICB0ZW1wbGF0ZT8ubmFtZSAhPT0gQkFTRUxJTkVfVEVNUExBVEVfTkFNRSl7XHJcbiAgICAgICAgICBzZXRBbGxvd1RvRWRpdCh0cnVlKTtcclxuICAgICAgICAgIHJldHVybjtcclxuICAgICAgICB9XHJcbiAgICAgICAgXHJcbiAgICAgICAgaWYodXNlcj8uZ3JvdXBzPy5pbmNsdWRlcyhDTFNTX0ZPTExPV0VSUykgJiYgXHJcbiAgICAgICAgICAgIHRlbXBsYXRlPy5uYW1lICE9PSBCQVNFTElORV9URU1QTEFURV9OQU1FKXtcclxuICAgICAgICAgICBzZXRBbGxvd1RvRWRpdCh0cnVlKTtcclxuICAgICAgICAgIHJldHVybjtcclxuICAgICAgICB9XHJcblxyXG4gICAgICB9XHJcbiAgICAgIHNldEFsbG93VG9FZGl0KGZhbHNlKTsgICAgICBcclxuICAgIH0sIFt0ZW1wbGF0ZSwgdXNlcl0pXHJcblxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpPT57XHJcbiAgICAgIGlmKHRlbXBsYXRlKXtcclxuICAgICAgICBzZXRUZW1wbGF0ZU5hbWUodGVtcGxhdGU/Lm5hbWUpO1xyXG4gICAgICB9XHJcbiAgICB9LCBbdGVtcGxhdGVdKSAgIFxyXG4gICAgXHJcbiAgICBjb25zdCBvbkNhbmNlbCA9KCkgPT57XHJcbiAgICAgIHNldFRlbXBsYXRlTmFtZSh0ZW1wbGF0ZS5uYW1lKTsgXHJcbiAgICAgIHNldFNlbGVjdGVkSGF6YXJkKGhhemFyZHMuZmluZChoID0+IGgubmFtZSA9PT0gdGVtcGxhdGUuaGF6YXJkTmFtZSkpO1xyXG4gICAgICBzZXRTZWxlY3RlZE9yZ2FuaXphdGlvbihvcmdhbml6YXRpb25zLmZpbmQobyA9PiBvLm5hbWUgPT09IHRlbXBsYXRlLm9yZ2FuaXphdGlvbk5hbWUpKTsgXHJcbiAgICAgIHNldEVkaXRpbmcoZmFsc2UpO1xyXG4gICAgICBvbkFjdGlvbkNvbXBsZXRlKGZhbHNlKTtcclxuICAgIH1cclxuICAgXHJcbiAgICBjb25zdCBnZXRTZWxlY3RlZEhhemFyZERhdGEgPSgpID0+IHtcclxuICAgICAgaWYoc2VsZWN0ZWRIYXphcmQgJiYgc2VsZWN0ZWRIYXphcmQudGl0bGUgIT09ICctTm9uZS0nKXtcclxuICAgICAgICByZXR1cm4gc2VsZWN0ZWRIYXphcmRcclxuICAgICAgfSAgICAgICBcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBnZXRTZWxlY3RlZE9yZ0RhdGEgPSAoKT0+IHtcclxuICAgICAgaWYoc2VsZWN0ZWRPcmdhbml6YXRpb24gJiYgc2VsZWN0ZWRPcmdhbml6YXRpb24udGl0bGUgIT09ICctTm9uZS0nKXtcclxuICAgICAgICByZXR1cm4gc2VsZWN0ZWRPcmdhbml6YXRpb25cclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IG9uU2F2ZVRlbXBsYXRlSGVhZGVyRWRpdHM9IGFzeW5jKCk9PnsgIFxyXG5cclxuICAgICAgY29uc3QgX3RlbXBsYXRlcyA9IHRlbXBsYXRlcy5maWx0ZXIodCA9PiB0LmlkICE9IHRlbXBsYXRlLmlkKTtcclxuXHJcbiAgICAgIGlmKF90ZW1wbGF0ZXMuc29tZSh0ID0+IHQubmFtZS50b0xvd2VyQ2FzZSgpID09PSB0ZW1wbGF0ZU5hbWUudG9Mb3dlckNhc2UoKS50cmltKCkpKXtcclxuICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCBgVGVtcGxhdGU6ICR7dGVtcGxhdGVOYW1lfSBhbHJlYWR5IGV4aXN0c2ApO1xyXG4gICAgICAgIHJldHVybjtcclxuICAgICAgfVxyXG4gICAgIFxyXG4gICAgICBzZXRMb2FkaW5nKHRydWUpO1xyXG5cclxuICAgICAgY29uc3QgaGF6YXJkRGF0YSA9IGdldFNlbGVjdGVkSGF6YXJkRGF0YSgpO1xyXG4gICAgICBjb25zdCBvcmdEYXRhID0gZ2V0U2VsZWN0ZWRPcmdEYXRhKCk7XHJcblxyXG4gICAgICBjb25zdCB1cGRhdGVkVGVtcGxhdGUgPSB7XHJcbiAgICAgICAgLi4udGVtcGxhdGUsXHJcbiAgICAgICAgbmFtZTogdGVtcGxhdGVOYW1lLFxyXG4gICAgICAgIGlzU2VsZWN0ZWQ6IHRlbXBsYXRlLmlzU2VsZWN0ZWQsXHJcbiAgICAgICAgc3RhdHVzOiBzdGF0dXMsXHJcbiAgICAgICAgaGF6YXJkSWQ6IGhhemFyZERhdGE/IGhhemFyZERhdGEuaWQ6IG51bGwsXHJcbiAgICAgICAgaGF6YXJkTmFtZTogaGF6YXJkRGF0YT8gaGF6YXJkRGF0YS5uYW1lOiBudWxsLFxyXG4gICAgICAgIGhhemFyZFR5cGU6IGhhemFyZERhdGE/IGhhemFyZERhdGEudHlwZT8uY29kZTogbnVsbCxcclxuICAgICAgICBvcmdhbml6YXRpb25UeXBlOiBvcmdEYXRhPyBvcmdEYXRhLnR5cGU6IG51bGwsXHJcbiAgICAgICAgb3JnYW5pemF0aW9uTmFtZTogb3JnRGF0YT8gb3JnRGF0YS5uYW1lOiAgbnVsbCwgICAgICAgIFxyXG4gICAgICAgIG9yZ2FuaXphdGlvbklkOiBvcmdEYXRhPyBvcmdEYXRhLmlkOiAgbnVsbCxcclxuICAgICAgfSBhcyBDTFNTVGVtcGxhdGU7XHJcblxyXG4gICAgICBjb25zdCByZXNwb25zZSA9ICBhd2FpdCB1cGRhdGVUZW1wbGF0ZU9yZ2FuaXphdGlvbkFuZEhhemFyZChcclxuICAgICAgICBjb25maWcsIHVwZGF0ZWRUZW1wbGF0ZSwgdXNlci51c2VyTmFtZVxyXG4gICAgICApOyAgXHJcblxyXG4gICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcclxuICAgICAgaWYocmVzcG9uc2UuZXJyb3JzKXtcclxuICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCByZXNwb25zZS5lcnJvcnMpOyAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuO1xyXG4gICAgICB9XHJcbiAgICAgIHNldEVkaXRpbmcoZmFsc2UpO1xyXG4gICAgICBvbkFjdGlvbkNvbXBsZXRlKHRydWUpICAgXHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuICggICAgXHJcbiAgICAgIDxkaXYgY2xhc3NOYW1lPVwiZGV0YWlscy1jb250ZW50LWhlYWRlclwiIHN0eWxlPXt7XHJcbiAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6IGNvbmZpZz8uaGVhZGVyQmFja2dyb3VuZENvbG9yXHJcbiAgICAgICAgfX0+XHJcbiAgICAgICAgICAgIDxzdHlsZT5cclxuICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVye1xyXG4gICAgICAgICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7ICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICBmbGV4LXdyYXA6IHdyYXA7XHJcbiAgICAgICAgICAgICAgICAgIH0gICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgLmVkaXRvci1pY29ueyAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgY29sb3I6ICM1MzRjNGM7XHJcbiAgICAgICAgICAgICAgICAgICAgY3Vyc29yOiBwb2ludGVyO1xyXG4gICAgICAgICAgICAgICAgICAgIG1hcmdpbjogMTBweDtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuZGV0YWlscy1jb250ZW50LWhlYWRlciAuZWRpdG9yLWljb246IGhvdmVye1xyXG4gICAgICAgICAgICAgICAgICAgIG9wYWNpdHk6IC44XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmRldGFpbHMtY29udGVudC1oZWFkZXIgLnNhdmUtY2FuY2VsLCBcclxuICAgICAgICAgICAgICAgICAgLmRldGFpbHMtY29udGVudC1oZWFkZXIgLnNhdmUtaWNvbntcclxuICAgICAgICAgICAgICAgICAgICBwb3NpdGlvbjogYWJzb2x1dGU7XHJcbiAgICAgICAgICAgICAgICAgICAgcmlnaHQ6IDEwcHg7XHJcbiAgICAgICAgICAgICAgICAgICAgdG9wOiAxMHB4O1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIC5kYXRhLWRyb3Bkb3duLCBcclxuICAgICAgICAgICAgICAgICAgLmRldGFpbHMtY29udGVudC1oZWFkZXIgLmRhdGEtaW5wdXR7XHJcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICAgICAgICBhbGlnbi1pdGVtczogY2VudGVyO1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIC5kYXRhLWRyb3Bkb3duIC5qaW11LWRyb3Bkb3due1xyXG4gICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDMwMHB4O1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIC5kYXRhLWRyb3Bkb3duLW1lbnV7XHJcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDMwMHB4O1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIC5lcnJvcntcclxuICAgICAgICAgICAgICAgICAgICBjb2xvcjogcmVkO1xyXG4gICAgICAgICAgICAgICAgICAgIGZvbnQtc2l6ZTogMTVweDtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuZGV0YWlscy1jb250ZW50LWhlYWRlciAuZHJvcGRvd24taXRlbXtcclxuICAgICAgICAgICAgICAgICAgICAgIGZvbnQtc2l6ZTogMS4zZW07XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmRldGFpbHMtY29udGVudC1oZWFkZXIgLm9yZ2FuaXphdGlvbntcclxuICAgICAgICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICAgICAgICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmRldGFpbHMtY29udGVudC1oZWFkZXIgLmVuZC13aWRnZXR7XHJcbiAgICAgICAgICAgICAgICAgICAgICBtYXJnaW4tYm90dG9tOiAxNXB4O1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIC5kYXRhLWlucHV0e1xyXG4gICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDMwLjclXHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmRldGFpbHMtY29udGVudC1oZWFkZXIgLnRpdGxlLnRlbXBsYXRle1xyXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiAxNDJweDtcclxuICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgLmRldGFpbHMtY29udGVudC1oZWFkZXIgdGQgbGFiZWwsXHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIHRkIGlucHV0eyBcclxuICAgICAgICAgICAgICAgICAgICBmb250LXNpemU6IDEuNWVtO1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIHRkIGxhYmVse1xyXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiAxNjVweDtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuZGV0YWlscy1jb250ZW50LWhlYWRlciB0ZCBsYWJlbC52YWx1ZXtcclxuICAgICAgICAgICAgICAgICAgICAgIGZvbnQtd2VpZ2h0OiBib2xkO1xyXG4gICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IGF1dG87XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmRldGFpbHMtY29udGVudC1oZWFkZXIgdHIudGQtdW5kZXI+dGR7XHJcbiAgICAgICAgICAgICAgICAgICAgcGFkZGluZy1ib3R0b206IDFlbTtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuZGV0YWlscy1jb250ZW50LWhlYWRlciAudGVtcGxhdGUtaW5wdXQgaW5wdXR7XHJcbiAgICAgICAgICAgICAgICAgICAgcGFkZGluZy1sZWZ0OiAxMHB4O1xyXG4gICAgICAgICAgICAgICAgICAgIGhlaWdodDogNDBweDtcclxuICAgICAgICAgICAgICAgICAgICBmb250LXNpemU6IDE2cHg7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmRldGFpbHMtY29udGVudC1oZWFkZXIgLnRlbXBsYXRlLWlucHV0IHNwYW57XHJcbiAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDQwcHggIWltcG9ydGFudDtcclxuICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiAzMDBweDtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuYWN0aW9uLWljb24ge1xyXG4gICAgICAgICAgICAgICAgICAgIGNvbG9yOiBncmF5O1xyXG4gICAgICAgICAgICAgICAgICAgIGN1cnNvcjogcG9pbnRlcjtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgPC9zdHlsZT4gXHJcblxyXG4gICAgICAgICAgICA8dGFibGUgY2xhc3NOYW1lPVwidGVtcGxhdGUtZGV0YWlsLWhlYWRlci10YWJsZVwiIFxyXG4gICAgICAgICAgICBzdHlsZT17e21hcmdpblJpZ2h0OiAnMTBlbSd9fT5cclxuICAgICAgICAgICAgICA8dHIgY2xhc3NOYW1lPVwidGQtdW5kZXJcIj5cclxuICAgICAgICAgICAgICAgIDx0ZD4gPExhYmVsIGNoZWNrPlRlbXBsYXRlIE5hbWU6IDwvTGFiZWw+PC90ZD5cclxuICAgICAgICAgICAgICAgIDx0ZD5cclxuICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgaXNFZGl0aW5nID8gKFxyXG4gICAgICAgICAgICAgICAgICAgICAgPFRleHRJbnB1dCBjbGFzc05hbWU9XCJ0ZW1wbGF0ZS1pbnB1dFwiXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhlKT0+IHNldFRlbXBsYXRlTmFtZShlLnRhcmdldC52YWx1ZSl9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgdmFsdWU9e3RlbXBsYXRlTmFtZX0+PC9UZXh0SW5wdXQ+XHJcbiAgICAgICAgICAgICAgICAgICAgICApIDpcclxuICAgICAgICAgICAgICAgICAgICAgICg8TGFiZWwgZGF0YS10ZXN0aWQ9XCJsYmxUZW1wbGF0ZU5hbWVcIiBjbGFzc05hbWU9XCJ2YWx1ZVwiIGNoZWNrPnt0ZW1wbGF0ZU5hbWV9IDwvTGFiZWw+KVxyXG4gICAgICAgICAgICAgICAgICB9ICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICAgIDwvdHI+XHJcbiAgICAgICAgICAgICAgPHRyIGNsYXNzTmFtZT1cInRkLXVuZGVyXCI+XHJcbiAgICAgICAgICAgICAgICA8dGQ+PExhYmVsIGNsYXNzTmFtZT1cInRpdGxlXCIgY2hlY2s+T3JnYW5pemF0aW9uOiA8L0xhYmVsPjwvdGQ+XHJcbiAgICAgICAgICAgICAgICA8dGQ+XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgaXNFZGl0aW5nID8gKFxyXG4gICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9J2RhdGEtZHJvcGRvd24nPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8T3JnYW5pemF0aW9uc0Ryb3Bkb3duXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgY29uZmlnPXtjb25maWd9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgb3JnYW5pemF0aW9ucz17b3JnYW5pemF0aW9uc31cclxuICAgICAgICAgICAgICAgICAgICAgICAgICBzZWxlY3RlZE9yZ2FuaXphdGlvbj17c2VsZWN0ZWRPcmdhbml6YXRpb259XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgc2V0T3JnYW5pemF0aW9uPXtzZXRTZWxlY3RlZE9yZ2FuaXphdGlvbn1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICB0b2dnbGVOZXdPcmdhbml6YXRpb25Nb2RhbD17dG9nZ2xlT3JnYW5pemF0aW9uTW9kYWxWaXNpYmlsaXR5fVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgIHZlcnRpY2FsPXtmYWxzZX0vPlxyXG4gICAgICAgICAgICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgICAgICAgICAgICAgKTpcclxuICAgICAgICAgICAgICAgICAgKCAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICA8TGFiZWwgZGF0YS10ZXN0aWQ9XCJ0eHRPcmdhbml6YXRpb25OYW1lXCIgY2xhc3NOYW1lPVwidmFsdWVcIiBjaGVjaz57XHJcbiAgICAgICAgICAgICAgICAgICAgICBzZWxlY3RlZE9yZ2FuaXphdGlvbiA/IHNlbGVjdGVkT3JnYW5pemF0aW9uPy5uYW1lIDogICctTm9uZS0nXHJcbiAgICAgICAgICAgICAgICAgICAgfTwvTGFiZWw+XHJcbiAgICAgICAgICAgICAgICAgIClcclxuICAgICAgICAgICAgICAgIH0gXHJcbiAgICAgICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICAgIDwvdHI+XHJcbiAgICAgICAgICAgICAgPHRyIGNsYXNzTmFtZT1cInRkLXVuZGVyXCI+XHJcbiAgICAgICAgICAgICAgICA8dGQ+IDxMYWJlbCBjbGFzc05hbWU9XCJ0aXRsZVwiIGNoZWNrPkhhemFyZDogPC9MYWJlbD48L3RkPlxyXG4gICAgICAgICAgICAgICAgPHRkPlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICBpc0VkaXRpbmcgPyAoXHJcbiAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT0nZGF0YS1kcm9wZG93bic+ICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgIDxIYXphcmRzRHJvcGRvd25cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uZmlnPXtjb25maWd9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICBoYXphcmRzPXtoYXphcmRzfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0ZWRIYXphcmQ9e3NlbGVjdGVkSGF6YXJkfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgc2V0SGF6YXJkPXtzZXRTZWxlY3RlZEhhemFyZH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgIHRvZ2dsZU5ld0hhemFyZE1vZGFsPXt0b2dnbGVIYXphcmRNb2RhbFZpc2liaWxpdHl9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICB2ZXJ0aWNhbD17ZmFsc2V9Lz4gICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgICAgICAgICAgICAgKTogKFxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8TGFiZWwgY2xhc3NOYW1lPVwidmFsdWVcIiBjaGVjaz5cclxuICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0ZWRIYXphcmQgJiYgc2VsZWN0ZWRIYXphcmQ/LnRpdGxlICE9PSAnLU5vbmUtJyA/IChzZWxlY3RlZEhhemFyZC50aXRsZSsgYCAoJHtzZWxlY3RlZEhhemFyZC50eXBlfSlgKTogJy1Ob25lLSdcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgPC9MYWJlbD5cclxuICAgICAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgICAgfSAgXHJcbiAgICAgICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICAgIDwvdHI+XHJcbiAgICAgICAgICAgICAgPHRyIGNsYXNzTmFtZT1cInRkLXVuZGVyXCI+ICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgPHRkPjxMYWJlbCBjbGFzc05hbWU9XCJ0aXRsZVwiIGNoZWNrPlN0YXR1czogPC9MYWJlbD48L3RkPlxyXG4gICAgICAgICAgICAgICAgPHRkPlxyXG4gICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgaXNFZGl0aW5nID8gKFxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT0nZGF0YS1kcm9wZG93bic+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgPENsc3NEcm9wZG93biBpdGVtcz17c3RhdHVzZXN9IFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaXRlbT17c3RhdHVzfSBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1lbnVXaWR0aD17JzMwMHB4J31cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGV0YWJsZT17ZmFsc2V9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZXRJdGVtPXtzZXRTdGF0dXN9Lz4gICAgICAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgICAgICAgICAgICAgICk6IChcclxuICAgICAgICAgICAgICAgICAgICAgIDxMYWJlbCBjbGFzc05hbWU9XCJ2YWx1ZVwiIGNoZWNrPntzdGF0dXM/Lm5hbWV9PC9MYWJlbD5cclxuICAgICAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgICAgICAgIH0gIFxyXG4gICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICA8L3RyPlxyXG4gICAgICAgICAgICA8L3RhYmxlPiAgICAgICAgIFxyXG5cclxuICAgICAgICAgICAgPHRhYmxlIGNsYXNzTmFtZT1cInRlbXBsYXRlLWRldGFpbC1oZWFkZXItdGFibGVcIj5cclxuICAgICAgICAgICAgICA8dHIgY2xhc3NOYW1lPVwidGQtdW5kZXJcIj5cclxuICAgICAgICAgICAgICAgIDx0ZD4gPExhYmVsIGNoZWNrPkF1dGhvcjogPC9MYWJlbD48L3RkPlxyXG4gICAgICAgICAgICAgICAgPHRkPlxyXG4gICAgICAgICAgICAgICAgICAgIDxMYWJlbCBkYXRhLXRlc3RpZD1cImxibFRlbXBsYXRlTmFtZVwiIFxyXG4gICAgICAgICAgICAgICAgICAgIGNsYXNzTmFtZT1cInZhbHVlXCIgY2hlY2s+e3RlbXBsYXRlPy5jcmVhdG9yfSA8L0xhYmVsPiAgICAgXHJcbiAgICAgICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICAgIDwvdHI+XHJcbiAgICAgICAgICAgICAgPHRyIGNsYXNzTmFtZT1cInRkLXVuZGVyXCI+XHJcbiAgICAgICAgICAgICAgICA8dGQ+PExhYmVsIGNsYXNzTmFtZT1cInRpdGxlXCIgY2hlY2s+RGF0ZSBDcmVhdGVkOiA8L0xhYmVsPjwvdGQ+XHJcbiAgICAgICAgICAgICAgICA8dGQ+XHJcbiAgICAgICAgICAgICAgICAgICA8TGFiZWwgZGF0YS10ZXN0aWQ9XCJsYmxUZW1wbGF0ZU5hbWVcIiBcclxuICAgICAgICAgICAgICAgICAgIGNsYXNzTmFtZT1cInZhbHVlXCIgY2hlY2s+e3BhcnNlRGF0ZSh0ZW1wbGF0ZT8uY3JlYXRlZERhdGUpfSA8L0xhYmVsPiAgICAgXHJcbiAgICAgICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICAgIDwvdHI+XHJcbiAgICAgICAgICAgICAgPHRyIGNsYXNzTmFtZT1cInRkLXVuZGVyXCI+XHJcbiAgICAgICAgICAgICAgICA8dGQ+PExhYmVsIGNsYXNzTmFtZT1cInRpdGxlXCIgY2hlY2s+TGFzdCBVcGRhdGVkOiA8L0xhYmVsPjwvdGQ+XHJcbiAgICAgICAgICAgICAgICA8dGQ+XHJcbiAgICAgICAgICAgICAgICAgICA8TGFiZWwgZGF0YS10ZXN0aWQ9XCJsYmxUZW1wbGF0ZU5hbWVcIiBcclxuICAgICAgICAgICAgICAgICAgIGNsYXNzTmFtZT1cInZhbHVlXCIgY2hlY2s+e3BhcnNlRGF0ZSh0ZW1wbGF0ZT8uZWRpdGVkRGF0ZSl9IHt0ZW1wbGF0ZS5lZGl0b3IgPyAnIGJ5ICcgKyB0ZW1wbGF0ZS5lZGl0b3I6ICctJ308L0xhYmVsPiAgICAgXHJcbiAgICAgICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICAgIDwvdHI+XHJcbiAgICAgICAgICAgICAgPHRyIGNsYXNzTmFtZT1cInRkLXVuZGVyXCI+XHJcbiAgICAgICAgICAgICAgICA8dGQ+IDxMYWJlbCBjbGFzc05hbWU9XCJ0aXRsZVwiIGNoZWNrPkFzc2Vzc21lbnRzOiA8L0xhYmVsPjwvdGQ+XHJcbiAgICAgICAgICAgICAgICA8dGQ+IFxyXG4gICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgIGFzc2Vzc21lbnRzICYmIGFzc2Vzc21lbnRzLmxlbmd0aCA+IDAgP1xyXG4gICAgICAgICAgICAgICAgICAgICAoXHJcbiAgICAgICAgICAgICAgICAgICAgICA8QnV0dG9uIG9uQ2xpY2s9eygpPT4gc2V0VG9nZ2xlQXNzZXNzbWVudFZpc2liaWxpdHkodHJ1ZSl9IHN0eWxlPXt7Zm9udFNpemU6ICcxLjVlbScsIFxyXG4gICAgICAgICAgICAgICAgcGFkZGluZzowLCBmb250V2VpZ2h0OiAnYm9sZCd9fSB0eXBlPVwibGlua1wiPkNsaWNrIGhlcmUgdG8gdmlldyB0aGUgYXNzZXNzbWVudHMgKHthc3Nlc3NtZW50cz8ubGVuZ3RofSk8L0J1dHRvbj5cclxuICAgICAgICAgICAgICAgICAgICAgKTogPExhYmVsIGRhdGEtdGVzdGlkPVwibGJsVGVtcGxhdGVOYW1lXCIgXHJcbiAgICAgICAgICAgICAgICAgICAgIGNsYXNzTmFtZT1cInZhbHVlXCIgY2hlY2s+LU5vbmUtPC9MYWJlbD4gICBcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICAgIDwvdHI+XHJcbiAgICAgICAgICAgIDwvdGFibGU+IFxyXG5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgIGFsbG93VG9FZGl0ICYmIGlzRWRpdGluZyA/IChcclxuICAgICAgICAgICAgICAgIDxkaXYgIGNsYXNzTmFtZT1cInNhdmUtY2FuY2VsXCIgc3R5bGU9e3tkaXNwbGF5OiAnZmxleCcsIGZsZXhEaXJlY3Rpb246ICdjb2x1bW4nfX0+XHJcbiAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICA8Q2xvc2VPdXRsaW5lZCBkYXRhLXRlc3RpZD1cImJ0bkNhbmNlbEVkaXRzXCIgc2l6ZT17MjV9IGNsYXNzTmFtZT0nZWRpdG9yLWljb24nIFxyXG4gICAgICAgICAgICAgICAgICAgIHN0eWxlPXt7Y29sb3I6ICcjNTM0YzRjJywgZm9udFdlaWdodDogJ2JvbGQnfX0gXHJcbiAgICAgICAgICAgICAgICAgICAgdGl0bGU9XCJDYW5jZWwgRWRpdHNcIiBvbkNsaWNrPXsoKSA9PiBvbkNhbmNlbCgpfS8+XHJcblxyXG4gICAgICAgICAgICAgICAgICA8U2F2ZUZpbGxlZCBzaXplPXsyNX0gZGF0YS10ZXN0aWQ9XCJidG5TYXZlRWRpdHNcIiBjbGFzc05hbWU9J2VkaXRvci1pY29uJyAgXHJcbiAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiBvblNhdmVUZW1wbGF0ZUhlYWRlckVkaXRzKCl9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgc3R5bGU9e3tjb2xvcjogJyM1MzRjNGMnLCBmb250V2VpZ2h0OiAnYm9sZCd9fSB0aXRsZT0nU2F2ZScvPlxyXG4gICAgICAgICAgICAgICAgPC9kaXY+ICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICApIDpcclxuICAgICAgICAgICAgICAoXHJcbiAgICAgICAgICAgICAgICBhbGxvd1RvRWRpdCA/XHJcbiAgICAgICAgICAgICAgICAoXHJcbiAgICAgICAgICAgICAgICAgIDxFZGl0T3V0bGluZWQgZGF0YS10ZXN0aWQ9XCJidG5TdGFydEVkaXRpbmdcIiBzaXplPXszMH0gY2xhc3NOYW1lPSdlZGl0b3ItaWNvbiBzYXZlLWljb24nIFxyXG4gICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiBzZXRFZGl0aW5nKHRydWUpfVxyXG4gICAgICAgICAgICAgICAgICBzdHlsZT17e2NvbG9yOiAnIzUzNGM0Yyd9fSB0aXRsZT0nRWRpdCcvPlxyXG4gICAgICAgICAgICAgICAgKTogbnVsbFxyXG4gICAgICAgICAgICAgICkgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICB9ICBcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICghdGVtcGxhdGUgfHwgbG9hZGluZykgPyA8Q2xzc0xvYWRpbmcvPiA6IG51bGwgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIDxUZW1wbGF0ZUFzc2Vzc21lbnRWaWV3XHJcbiAgICAgICAgICAgICAgaXNWaXNpYmxlPXtpc0Fzc2Vzc21lbnRzVmlzaWJpbGl0eX1cclxuICAgICAgICAgICAgICB0b2dnbGU9e3NldFRvZ2dsZUFzc2Vzc21lbnRWaXNpYmlsaXR5fVxyXG4gICAgICAgICAgICAgIGFzc2Vzc21lbnRzPXthc3Nlc3NtZW50c30vPlxyXG4gICAgICA8L2Rpdj4gICAgICBcclxuICAgIClcclxufSIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X2FyY2dpc19fOyIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X2NvcmVfXzsiLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfcmVhY3RfXzsiLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfamltdV91aV9fOyIsIi8vIFRoZSBtb2R1bGUgY2FjaGVcbnZhciBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX18gPSB7fTtcblxuLy8gVGhlIHJlcXVpcmUgZnVuY3Rpb25cbmZ1bmN0aW9uIF9fd2VicGFja19yZXF1aXJlX18obW9kdWxlSWQpIHtcblx0Ly8gQ2hlY2sgaWYgbW9kdWxlIGlzIGluIGNhY2hlXG5cdHZhciBjYWNoZWRNb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdO1xuXHRpZiAoY2FjaGVkTW9kdWxlICE9PSB1bmRlZmluZWQpIHtcblx0XHRyZXR1cm4gY2FjaGVkTW9kdWxlLmV4cG9ydHM7XG5cdH1cblx0Ly8gQ3JlYXRlIGEgbmV3IG1vZHVsZSAoYW5kIHB1dCBpdCBpbnRvIHRoZSBjYWNoZSlcblx0dmFyIG1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF0gPSB7XG5cdFx0Ly8gbm8gbW9kdWxlLmlkIG5lZWRlZFxuXHRcdC8vIG5vIG1vZHVsZS5sb2FkZWQgbmVlZGVkXG5cdFx0ZXhwb3J0czoge31cblx0fTtcblxuXHQvLyBFeGVjdXRlIHRoZSBtb2R1bGUgZnVuY3Rpb25cblx0X193ZWJwYWNrX21vZHVsZXNfX1ttb2R1bGVJZF0obW9kdWxlLCBtb2R1bGUuZXhwb3J0cywgX193ZWJwYWNrX3JlcXVpcmVfXyk7XG5cblx0Ly8gUmV0dXJuIHRoZSBleHBvcnRzIG9mIHRoZSBtb2R1bGVcblx0cmV0dXJuIG1vZHVsZS5leHBvcnRzO1xufVxuXG4iLCIvLyBnZXREZWZhdWx0RXhwb3J0IGZ1bmN0aW9uIGZvciBjb21wYXRpYmlsaXR5IHdpdGggbm9uLWhhcm1vbnkgbW9kdWxlc1xuX193ZWJwYWNrX3JlcXVpcmVfXy5uID0gKG1vZHVsZSkgPT4ge1xuXHR2YXIgZ2V0dGVyID0gbW9kdWxlICYmIG1vZHVsZS5fX2VzTW9kdWxlID9cblx0XHQoKSA9PiAobW9kdWxlWydkZWZhdWx0J10pIDpcblx0XHQoKSA9PiAobW9kdWxlKTtcblx0X193ZWJwYWNrX3JlcXVpcmVfXy5kKGdldHRlciwgeyBhOiBnZXR0ZXIgfSk7XG5cdHJldHVybiBnZXR0ZXI7XG59OyIsIi8vIGRlZmluZSBnZXR0ZXIgZnVuY3Rpb25zIGZvciBoYXJtb255IGV4cG9ydHNcbl9fd2VicGFja19yZXF1aXJlX18uZCA9IChleHBvcnRzLCBkZWZpbml0aW9uKSA9PiB7XG5cdGZvcih2YXIga2V5IGluIGRlZmluaXRpb24pIHtcblx0XHRpZihfX3dlYnBhY2tfcmVxdWlyZV9fLm8oZGVmaW5pdGlvbiwga2V5KSAmJiAhX193ZWJwYWNrX3JlcXVpcmVfXy5vKGV4cG9ydHMsIGtleSkpIHtcblx0XHRcdE9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBrZXksIHsgZW51bWVyYWJsZTogdHJ1ZSwgZ2V0OiBkZWZpbml0aW9uW2tleV0gfSk7XG5cdFx0fVxuXHR9XG59OyIsIl9fd2VicGFja19yZXF1aXJlX18ubyA9IChvYmosIHByb3ApID0+IChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwob2JqLCBwcm9wKSkiLCIvLyBkZWZpbmUgX19lc01vZHVsZSBvbiBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLnIgPSAoZXhwb3J0cykgPT4ge1xuXHRpZih0eXBlb2YgU3ltYm9sICE9PSAndW5kZWZpbmVkJyAmJiBTeW1ib2wudG9TdHJpbmdUYWcpIHtcblx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgU3ltYm9sLnRvU3RyaW5nVGFnLCB7IHZhbHVlOiAnTW9kdWxlJyB9KTtcblx0fVxuXHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgJ19fZXNNb2R1bGUnLCB7IHZhbHVlOiB0cnVlIH0pO1xufTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLnAgPSBcIlwiOyIsIi8qKlxyXG4gKiBXZWJwYWNrIHdpbGwgcmVwbGFjZSBfX3dlYnBhY2tfcHVibGljX3BhdGhfXyB3aXRoIF9fd2VicGFja19yZXF1aXJlX18ucCB0byBzZXQgdGhlIHB1YmxpYyBwYXRoIGR5bmFtaWNhbGx5LlxyXG4gKiBUaGUgcmVhc29uIHdoeSB3ZSBjYW4ndCBzZXQgdGhlIHB1YmxpY1BhdGggaW4gd2VicGFjayBjb25maWcgaXM6IHdlIGNoYW5nZSB0aGUgcHVibGljUGF0aCB3aGVuIGRvd25sb2FkLlxyXG4gKiAqL1xyXG4vLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmVcclxuLy8gQHRzLWlnbm9yZVxyXG5fX3dlYnBhY2tfcHVibGljX3BhdGhfXyA9IHdpbmRvdy5qaW11Q29uZmlnLmJhc2VVcmxcclxuIiwiaW1wb3J0IHsgUmVhY3QsIEFsbFdpZGdldFByb3BzLCBSZWFjdFJlZHV4LCBnZXRBcHBTdG9yZSB9IGZyb20gJ2ppbXUtY29yZSc7XHJcbmltcG9ydCB7IElNQ29uZmlnIH0gZnJvbSAnLi4vY29uZmlnJztcclxuaW1wb3J0IHsgQ0xTU1RlbXBsYXRlLCBcclxuICBDb21wb25lbnRUZW1wbGF0ZSxcclxuICAgSGF6YXJkLFxyXG4gICBMaWZlTGluZVRlbXBsYXRlLFxyXG4gICBPcmdhbml6YXRpb259IGZyb20gJy4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvZGF0YS1kZWZpbml0aW9ucyc7XHJcbmltcG9ydCBDbHNzTG9hZGluZyBmcm9tICcuLi8uLi8uLi9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtbG9hZGluZyc7XHJcbmltcG9ydCB7IENMU1NBY3Rpb25LZXlzIH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jbHNzLXN0b3JlJztcclxuaW1wb3J0IHsgZGlzcGF0Y2hBY3Rpb24sIFxyXG4gIGdldFRlbXBsYXRlc1xyXG4gIH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9hcGknO1xyXG5pbXBvcnQgQ2xzc0Vycm9yc1BhbmVsIGZyb20gJy4uLy4uLy4uL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1lcnJvcnMtcGFuZWwnO1xyXG5pbXBvcnQgeyBEZXRhaWxIZWFkZXJXaWRnZXQgfSBmcm9tICcuL2hlYWRlcic7XHJcbmltcG9ydCB7IFRhYiwgVGFicyB9IGZyb20gJ2ppbXUtdWknO1xyXG5pbXBvcnQgeyBMaWZlbGluZUNvbXBvbmVudCB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1saWZlbGluZS1jb21wb25lbnQnO1xyXG5pbXBvcnQgeyBBZGRPcmdhbml6YXRvbldpZGdldCB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1hZGQtb3JnYW5pemF0aW9uJztcclxuaW1wb3J0IHsgQWRkSGF6YXJkV2lkZ2V0IH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWFkZC1oYXphcmQnO1xyXG5pbXBvcnQgQ2xzc05vRGF0YSBmcm9tICcuLi8uLi8uLi9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3Mtbm8tZGF0YSc7XHJcbmNvbnN0IHsgdXNlU2VsZWN0b3IgfSA9IFJlYWN0UmVkdXg7XHJcblxyXG5jb25zdCBXaWRnZXQgPSAocHJvcHM6IEFsbFdpZGdldFByb3BzPElNQ29uZmlnPikgPT4ge1xyXG4gXHJcbiAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gUmVhY3QudXNlU3RhdGU8Ym9vbGVhbj4oZmFsc2UpO1xyXG4gIGNvbnN0IFtjb25maWcsIHNldENvbmZpZ10gPSBSZWFjdC51c2VTdGF0ZShudWxsKTtcclxuICBjb25zdCBbaXNBZGRPcmdhbml6YXRpb25Nb2RhbFZpc2libGUsIHNldEFkZE9yZ2FuaXphdGlvbk1vZGFsVmlzaWJpbGl0eV0gPSBSZWFjdC51c2VTdGF0ZShmYWxzZSk7XHJcbiAgY29uc3QgW2lzQWRkSGF6YXJkTW9kYWxWaXNpYmxlLCBzZXRBZGRIYXphcmRNb2RhbFZpc2liaWxpdHldID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpO1xyXG4gIGNvbnN0IFtzZWxlY3RlZEhhemFyZCwgc2V0U2VsZWN0ZWRIYXphcmRdPVJlYWN0LnVzZVN0YXRlPEhhemFyZD4obnVsbCk7XHJcbiAgY29uc3QgW3NlbGVjdGVkT3JnYW5pemF0aW9uLCBzZXRTZWxlY3RlZE9yZ2FuaXphdGlvbl09UmVhY3QudXNlU3RhdGU8T3JnYW5pemF0aW9uPihudWxsKTtcclxuICAgXHJcbiAgY29uc3QgZXJyb3JzID0gdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGU/LmVycm9ycztcclxuICB9KVxyXG5cclxuICBjb25zdCB0ZW1wbGF0ZSA9IHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KSA9PiB7XHJcbiAgICByZXR1cm4gc3RhdGU/LmNsc3NTdGF0ZT8udGVtcGxhdGVzLmZpbmQodCA9PiB0LmlzU2VsZWN0ZWQpIGFzIENMU1NUZW1wbGF0ZTtcclxuICB9KVxyXG5cclxuICBjb25zdCBjcmVkZW50aWFsID0gdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGU/LmF1dGhlbnRpY2F0ZTtcclxuICB9KVxyXG5cclxuICBjb25zdCBoYXphcmRzID0gdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGU/LmhhemFyZHMgYXMgSGF6YXJkW107XHJcbiAgfSlcclxuXHJcbiAgY29uc3Qgb3JnYW5pemF0aW9ucyA9IHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KSA9PiB7XHJcbiAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy5vcmdhbml6YXRpb25zIGFzIE9yZ2FuaXphdGlvbltdO1xyXG4gIH0pXHJcblxyXG4gIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICBpZihjcmVkZW50aWFsKXtcclxuICAgICAgIHNldENvbmZpZyh7Li4ucHJvcHMuY29uZmlnLCBjcmVkZW50aWFsOiBjcmVkZW50aWFsfSlcclxuICAgIH1cclxuICB9LCBbY3JlZGVudGlhbF0pXHJcblxyXG4gIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICBpZih0ZW1wbGF0ZSAmJiBvcmdhbml6YXRpb25zICYmIG9yZ2FuaXphdGlvbnMubGVuZ3RoID4gMCl7ICAgICBcclxuICAgICAgIHNldFNlbGVjdGVkT3JnYW5pemF0aW9uKG9yZ2FuaXphdGlvbnMuZmluZChvID0+IG8ubmFtZSA9PT0gdGVtcGxhdGUub3JnYW5pemF0aW9uTmFtZSkpXHJcbiAgICB9XHJcbiAgfSwgW3RlbXBsYXRlLCBvcmdhbml6YXRpb25zXSlcclxuXHJcbiAgUmVhY3QudXNlRWZmZWN0KCgpID0+IHtcclxuICAgIGlmKHRlbXBsYXRlICYmIGhhemFyZHMgJiYgaGF6YXJkcy5sZW5ndGggPiAwKXtcclxuICAgICAgIHNldFNlbGVjdGVkSGF6YXJkKGhhemFyZHMuZmluZChoID0+IGgubmFtZSA9PT0gdGVtcGxhdGUuaGF6YXJkTmFtZSkpXHJcbiAgICB9XHJcbiAgfSwgW3RlbXBsYXRlLCBoYXphcmRzXSlcclxuXHJcbiAgY29uc3QgY2xvc2VFcnJvcj0oKT0+IHtcclxuICAgIGdldEFwcFN0b3JlKCkuZGlzcGF0Y2goe1xyXG4gICAgICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLFxyXG4gICAgICB2YWw6ICcnXHJcbiAgICB9KVxyXG4gIH1cclxuXHJcbiAgY29uc3QgbG9hZFRlbXBsYXRlcyA9YXN5bmMgKCk9PntcclxuICAgIGNvbnN0IHNlbGVjdGVkVGVtcGxhdGUgPSB0ZW1wbGF0ZSA/IHsuLi50ZW1wbGF0ZX0gOiBudWxsO1xyXG5cclxuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZ2V0VGVtcGxhdGVzKGNvbmZpZyk7XHJcblxyXG4gICAgbGV0IGZldGNoRGF0YSA9IHJlc3BvbnNlLmRhdGE7XHJcbiAgICBpZihyZXNwb25zZS5kYXRhKXtcclxuICAgICAgaWYoc2VsZWN0ZWRUZW1wbGF0ZSl7XHJcbiAgICAgICAgZmV0Y2hEYXRhID0gcmVzcG9uc2UuZGF0YS5tYXAodCA9PiB7XHJcbiAgICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgLi4udCxcclxuICAgICAgICAgICAgaXNTZWxlY3RlZDogdC5pZCA9PT0gc2VsZWN0ZWRUZW1wbGF0ZS5pZFxyXG4gICAgICAgICAgIH1cclxuICAgICAgICB9KVxyXG4gICAgICB9XHJcbiAgICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLkxPQURfVEVNUExBVEVTX0FDVElPTiwgZmV0Y2hEYXRhKTtcclxuICAgIH1cclxuICAgIHJldHVybiByZXNwb25zZTtcclxuICB9XHJcblxyXG4gIGNvbnN0IG9uSW5kaWNhdG9yQWN0aW9uQ29tcGxldGU9YXN5bmMocmVsb2FkPzpib29sZWFuKT0+eyAgICBcclxuICAgIGlmKHJlbG9hZCl7XHJcbiAgICAgIGF3YWl0IGxvYWRUZW1wbGF0ZXMoKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIGlmKGxvYWRpbmcpeyAgICBcclxuICAgIHJldHVybiA8Q2xzc0xvYWRpbmcvPlxyXG4gIH0gXHJcblxyXG4gIGlmKHRlbXBsYXRlID09IG51bGwpeyAgICBcclxuICAgIHJldHVybiA8Q2xzc05vRGF0YSBtZXNzYWdlPSdTZWxlY3QgYSB0ZW1wbGF0ZSB0byB2aWV3IGRldGFpbHMnLz5cclxuICB9IFxyXG4gXHJcbiAgcmV0dXJuIChcclxuICAgIDxkaXYgY2xhc3NOYW1lPVwid2lkZ2V0LXRlbXBsYXRlLWRldGFpbFwiXHJcbiAgICAgIHN0eWxlPXtcclxuICAgICAgICB7XHJcbiAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6IHByb3BzLmNvbmZpZy5iYWNrZ291bmRDb2xvclxyXG4gICAgICB9fT5cclxuICAgICAgPHN0eWxlPlxyXG4gICAgICAgIHtgXHJcbiAgICAgICAgICAud2lkZ2V0LXRlbXBsYXRlLWRldGFpbCB7XHJcbiAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICBoZWlnaHQ6IDEwMCU7XHJcbiAgICAgICAgICAgIHBhZGRpbmc6IDIwcHg7XHJcbiAgICAgICAgICAgIG92ZXJmbG93OiBhdXRvO1xyXG4gICAgICAgICAgICBwb3NpdGlvbjogcmVsYXRpdmU7ICAgICAgICAgICAgXHJcbiAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgLmVycm9yLXBhbmVsIHtcclxuICAgICAgICAgICAgcG9zaXRpb246IGFic29sdXRlO1xyXG4gICAgICAgICAgICBsZWZ0OiAwO1xyXG4gICAgICAgICAgICB0b3A6IDA7XHJcbiAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICB6LWluZGV4OiA5OTlcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIFxyXG4gICAgICAgICAgLmRldGFpbHMtY29udGVudHtcclxuICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgIGhlaWdodDogMTAwJTsgXHJcbiAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47XHJcbiAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7ICAgXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgIFxyXG4gICAgICAgICAgLmRldGFpbHMtY29udGVudC1oZWFkZXJ7XHJcbiAgICAgICAgICAgIGJvcmRlci1yYWRpdXM6IDEwcHggMTBweCAwIDA7XHJcbiAgICAgICAgICAgIHBhZGRpbmc6IDMwcHggNTBweDtcclxuICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgIHBvc2l0aW9uOnJlbGF0aXZlOyAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIG1hcmdpbi1ib3R0b206IDEwcHg7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBcclxuICAgICAgICAgIC5oZWFkZXItcm93e1xyXG4gICAgICAgICAgICBkaXNwbGF5OiBmbGV4OyAgIFxyXG4gICAgICAgICAgICBtYXJnaW4tYm90dG9tOiAxMHB4OyAgICAgICAgICAgXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAuaGVhZGVyLXJvdyBsYWJlbHtcclxuICAgICAgICAgICAgZm9udC1zaXplOiAxLjZlbTtcclxuICAgICAgICAgICAgY29sb3I6ICM0ZDQ5NDk7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAuaGVhZGVyLXJvdyAudmFsdWV7XHJcbiAgICAgICAgICAgIGZvbnQtd2VpZ2h0OiBib2xkO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLmhlYWRlci1yb3cgLnRpdGxle1xyXG4gICAgICAgICAgICAgd2lkdGg6IDE2NXB4O1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLmRldGFpbHMtY29udGVudC1kYXRhe1xyXG4gICAgICAgICAgICBoZWlnaHQ6IDEwMCU7XHJcbiAgICAgICAgICAgIG1hcmdpbi10b3A6IDIwcHg7XHJcbiAgICAgICAgICAgIHBhZGRpbmc6IDA7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAuZGV0YWlscy1jb250ZW50LWRhdGEtaGVhZGVyeyAgICAgICAgICAgICBcclxuICAgICAgICAgICAgaGVpZ2h0OiA3NXB4O1xyXG4gICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgYmFja2dyb3VuZDogIzUzNGM0YzgwO1xyXG4gICAgICAgICAgICBib3JkZXItcmFkaXVzOiAxMHB4IDEwcHggMCAwO1xyXG4gICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjtcclxuICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjtcclxuICAgICAgICAgICAgcGFkZGluZzogMCAxMHB4O1xyXG4gICAgICAgICAgICB0ZXh0LWFsaWduOiBjZW50ZXI7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAuZGV0YWlscy1jb250ZW50LWRhdGEtaGVhZGVyIGxhYmVse1xyXG4gICAgICAgICAgICBmb250LXNpemU6IDEuNmVtO1xyXG4gICAgICAgICAgICBjb2xvcjogd2hpdGU7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAubGlmZWxpbmVzLXRhYnN7XHJcbiAgICAgICAgICAgIHdpZHRoOiAxMDAlOyAgICAgICAgICAgICBcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC5saWZlbGluZXMtdGFicyAudGFiLXRpdGxle1xyXG4gICAgICAgICAgICBmb250LXNpemU6IDE1cHg7XHJcbiAgICAgICAgICAgIGZvbnQtd2VpZ2h0OiBib2xkO1xyXG4gICAgICAgICAgICBwYWRkaW5nOiAxMHB4O1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLmxpZmVsaW5lcy10YWJzIC5uYXYtaXRlbXtcclxuICAgICAgICAgICAgaGVpZ2h0OiA0MHB4O1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLmxpZmVsaW5lLXRhYi1jb250ZW50e1xyXG4gICAgICAgICAgICBwYWRkaW5nOiAxMHB4O1xyXG4gICAgICAgICAgICBiYWNrZ3JvdW5kLWNvbG9yOiB3aGl0ZTtcclxuICAgICAgICAgIH1cclxuICAgICAgICBgfVxyXG4gICAgICA8L3N0eWxlPlxyXG4gICAgICA8ZGl2IGNsYXNzTmFtZT1cImRldGFpbHMtY29udGVudFwiPlxyXG4gICAgICAgIHtcclxuICAgICAgICAgIGVycm9ycyAmJiAhbG9hZGluZyA/IChcclxuICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9J2Vycm9yLXBhbmVsJz5cclxuICAgICAgICAgICAgICA8Q2xzc0Vycm9yc1BhbmVsIGNsb3NlPXtjbG9zZUVycm9yfSBlcnJvcnM9e2Vycm9yc30vPlxyXG4gICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICAgICk6IG51bGxcclxuICAgICAgICB9ICAgICAgXHJcbiAgICAgICAgXHJcbiAgICAgICAgPERldGFpbEhlYWRlcldpZGdldCBcclxuICAgICAgICAgIHRlbXBsYXRlPXt0ZW1wbGF0ZX0gXHJcbiAgICAgICAgICBvcmdhbml6YXRpb25zPXtvcmdhbml6YXRpb25zfVxyXG4gICAgICAgICAgaGF6YXJkcz17aGF6YXJkc31cclxuICAgICAgICAgIG9uQWN0aW9uQ29tcGxldGU9e29uSW5kaWNhdG9yQWN0aW9uQ29tcGxldGV9XHJcbiAgICAgICAgICBjb25maWc9e2NvbmZpZ31cclxuICAgICAgICAgIHNlbGVjdGVkTmV3SGF6YXJkPXtzZWxlY3RlZEhhemFyZH1cclxuICAgICAgICAgIHNlbGVjdGVkTmV3T3JnYW5pemF0aW9uPXtzZWxlY3RlZE9yZ2FuaXphdGlvbn0gXHJcbiAgICAgICAgICB0b2dnbGVIYXphcmRNb2RhbFZpc2liaWxpdHk9e3NldEFkZEhhemFyZE1vZGFsVmlzaWJpbGl0eX1cclxuICAgICAgICAgIHRvZ2dsZU9yZ2FuaXphdGlvbk1vZGFsVmlzaWJpbGl0eT17c2V0QWRkT3JnYW5pemF0aW9uTW9kYWxWaXNpYmlsaXR5fS8+IFxyXG5cclxuICAgICAgICA8ZGl2IGNsYXNzTmFtZT0nbGlmZWxpbmVzLXRhYnMnPlxyXG4gICAgICAgICAgPFRhYnMgZGVmYXVsdFZhbHVlPVwidGFiLTFcIiBmaWxsIHR5cGU9XCJ0YWJzXCI+ICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB0ZW1wbGF0ZT8ubGlmZWxpbmVUZW1wbGF0ZXMubWFwKCgobGlmZWxpbmU6IExpZmVMaW5lVGVtcGxhdGUpID0+IHtcclxuICAgICAgICAgICAgICAgICAgcmV0dXJuIChcclxuICAgICAgICAgICAgICAgICAgICA8VGFiIGlkPSB7bGlmZWxpbmU/LmlkfSBrZXk9e2xpZmVsaW5lPy5pZH0gdGl0bGU9e2xpZmVsaW5lLnRpdGxlfT5cclxuICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibGlmZWxpbmUtdGFiLWNvbnRlbnRcIj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgeyAgICAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgbGlmZWxpbmU/LmNvbXBvbmVudFRlbXBsYXRlcz8ubWFwKCgobGlmZWxpbmVDb21wOiBDb21wb25lbnRUZW1wbGF0ZSkgPT4geyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKDxMaWZlbGluZUNvbXBvbmVudCAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBrZXk9e2xpZmVsaW5lQ29tcC5pZH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxpZmVsaW5lPXtsaWZlbGluZX1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbXBvbmVudD0ge2xpZmVsaW5lQ29tcH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRlbXBsYXRlPXt0ZW1wbGF0ZX0gIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uZmlnPXtjb25maWd9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkFjdGlvbkNvbXBsZXRlPXtvbkluZGljYXRvckFjdGlvbkNvbXBsZXRlfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8+KVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgIH0pKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB9ICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgICAgICAgICAgICAgIDwvVGFiPlxyXG4gICAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgICAgICB9KSlcclxuICAgICAgICAgICAgICB9ICAgICAgICAgICAgICBcclxuICAgICAgICAgIDwvVGFicz5cclxuICAgICAgICA8L2Rpdj5cclxuICAgICAgPC9kaXY+ICBcclxuXHJcbiAgICAgIDxBZGRPcmdhbml6YXRvbldpZGdldCBcclxuICAgICAgICAgIHByb3BzQ29uZmlnPXtwcm9wcz8uY29uZmlnfVxyXG4gICAgICAgICAgdmlzaWJsZT17aXNBZGRPcmdhbml6YXRpb25Nb2RhbFZpc2libGV9XHJcbiAgICAgICAgICBzZXRPcmdhbml6YXRpb249e3NldFNlbGVjdGVkT3JnYW5pemF0aW9ufVxyXG4gICAgICAgICAgdG9nZ2xlPXtzZXRBZGRPcmdhbml6YXRpb25Nb2RhbFZpc2liaWxpdHl9Lz4gXHJcblxyXG4gICAgICA8QWRkSGF6YXJkV2lkZ2V0IFxyXG4gICAgICAgIHByb3BzPXtwcm9wc31cclxuICAgICAgICB2aXNpYmxlPXtpc0FkZEhhemFyZE1vZGFsVmlzaWJsZX1cclxuICAgICAgICBzZXRIYXphcmQ9e3NldFNlbGVjdGVkSGF6YXJkfVxyXG4gICAgICAgIHRvZ2dsZT17c2V0QWRkSGF6YXJkTW9kYWxWaXNpYmlsaXR5fS8+ICAgIFxyXG4gICAgPC9kaXY+XHJcbiAgKSAgXHJcbn1cclxuZXhwb3J0IGRlZmF1bHQgV2lkZ2V0XHJcblxyXG5cclxuIl0sIm5hbWVzIjpbXSwic291cmNlUm9vdCI6IiJ9