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

/***/ "./jimu-icons/svg/outlined/application/folder.svg":
/*!********************************************************!*\
  !*** ./jimu-icons/svg/outlined/application/folder.svg ***!
  \********************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M1.333 0h4c.737 0 1.334.597 1.334 1.333v1.334h8C15.403 2.667 16 3.264 16 4v10.667c0 .736-.597 1.333-1.333 1.333H1.333A1.333 1.333 0 0 1 0 14.667V1.333C0 .597.597 0 1.333 0Zm0 7.333v7.334h13.334V7.333H1.334Zm0-1.333h13.334V4H5.334V1.335h-4V6Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/outlined/application/setting.svg":
/*!*********************************************************!*\
  !*** ./jimu-icons/svg/outlined/application/setting.svg ***!
  \*********************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M9.438.994c.213 0 .397.146.44.35.151.722.257 1.34.316 1.852.374.16.725.362 1.048.599l1.728-.676a.455.455 0 0 1 .556.188l1.42 2.394a.43.43 0 0 1-.091.547 21.98 21.98 0 0 1-1.49 1.194 5.17 5.17 0 0 1-.007 1.183l1.464 1.119a.43.43 0 0 1 .111.563l-1.42 2.394a.454.454 0 0 1-.53.197 22.445 22.445 0 0 1-1.807-.66c-.325.233-.679.43-1.055.586l-.263 1.794a.446.446 0 0 1-.445.376H6.574a.446.446 0 0 1-.44-.35 21.019 21.019 0 0 1-.317-1.853 5.34 5.34 0 0 1-1.047-.598l-1.728.675a.455.455 0 0 1-.556-.187l-1.42-2.395a.43.43 0 0 1 .091-.546c.567-.49 1.063-.888 1.49-1.194a5.167 5.167 0 0 1 .008-1.183L1.19 6.243a.43.43 0 0 1-.112-.562l1.42-2.395a.455.455 0 0 1 .531-.196c.719.233 1.321.453 1.807.66.324-.233.679-.43 1.056-.587l.262-1.794A.446.446 0 0 1 6.6.994h2.839Zm-.365 1H6.985l-.28 1.866-.467.19c-.235.095-.46.21-.672.34l-.207.136-.42.293-.476-.197c-.328-.137-.718-.281-1.169-.433l-.221-.074-1.045 1.719L3.59 6.999l-.06.479a4.127 4.127 0 0 0-.021.816l.014.144.058.492-.419.294c-.288.203-.615.451-.979.746l-.177.145 1.043 1.72 1.845-.703.406.29c.204.146.42.274.645.384l.228.103.474.199.059.49c.04.338.103.731.19 1.177l.043.219h2.088l.282-1.867.466-.19c.236-.095.46-.21.672-.34l.207-.136.419-.293.476.198c.33.136.72.28 1.17.433l.22.072 1.044-1.718-1.56-1.165.06-.479a4.131 4.131 0 0 0 .02-.815l-.013-.144-.06-.492.42-.295a18.1 18.1 0 0 0 .98-.746l.176-.146-1.043-1.72-1.844.705-.406-.29a4.496 4.496 0 0 0-.646-.385l-.228-.103-.474-.199-.058-.49c-.032-.27-.08-.576-.14-.916l-.094-.48Zm-1.067 3a3 3 0 1 1 0 6 3 3 0 0 1 0-6Zm0 1a2 2 0 1 0 0 4 2 2 0 0 0 0-4Z\" fill=\"#000\"></path></svg>"

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

/***/ "./jimu-icons/svg/outlined/suggested/success.svg":
/*!*******************************************************!*\
  !*** ./jimu-icons/svg/outlined/suggested/success.svg ***!
  \*******************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"m7 11.5 5.354-5.354-.708-.707L7 10.086 4.354 7.439l-.708.707L7 11.5Z\" fill=\"#000\"></path><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M0 8a8 8 0 1 0 16 0A8 8 0 0 0 0 8Zm15 0A7 7 0 1 1 1 8a7 7 0 0 1 14 0Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/outlined/application/folder.tsx":
/*!****************************************************!*\
  !*** ./jimu-icons/outlined/application/folder.tsx ***!
  \****************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "FolderOutlined": () => (/* binding */ FolderOutlined)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_outlined_application_folder_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/outlined/application/folder.svg */ "./jimu-icons/svg/outlined/application/folder.svg");
/* harmony import */ var _svg_outlined_application_folder_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_outlined_application_folder_svg__WEBPACK_IMPORTED_MODULE_1__);
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


const FolderOutlined = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_outlined_application_folder_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/outlined/application/setting.tsx":
/*!*****************************************************!*\
  !*** ./jimu-icons/outlined/application/setting.tsx ***!
  \*****************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "SettingOutlined": () => (/* binding */ SettingOutlined)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_outlined_application_setting_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/outlined/application/setting.svg */ "./jimu-icons/svg/outlined/application/setting.svg");
/* harmony import */ var _svg_outlined_application_setting_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_outlined_application_setting_svg__WEBPACK_IMPORTED_MODULE_1__);
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


const SettingOutlined = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_outlined_application_setting_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
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

/***/ "./jimu-icons/outlined/suggested/success.tsx":
/*!***************************************************!*\
  !*** ./jimu-icons/outlined/suggested/success.tsx ***!
  \***************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "SuccessOutlined": () => (/* binding */ SuccessOutlined)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_outlined_suggested_success_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/outlined/suggested/success.svg */ "./jimu-icons/svg/outlined/suggested/success.svg");
/* harmony import */ var _svg_outlined_suggested_success_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_outlined_suggested_success_svg__WEBPACK_IMPORTED_MODULE_1__);
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


const SuccessOutlined = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_outlined_suggested_success_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
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

/***/ "./your-extensions/widgets/clss-custom-components/clss-add-template.tsx":
/*!******************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-add-template.tsx ***!
  \******************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "AddTemplateWidget": () => (/* binding */ AddTemplateWidget)
/* harmony export */ });
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _clss_templates_dropdown__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./clss-templates-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-templates-dropdown.tsx");
/* harmony import */ var _clss_hazards_dropdown__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./clss-hazards-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-hazards-dropdown.tsx");
/* harmony import */ var _clss_organizations_dropdown__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./clss-organizations-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-organizations-dropdown.tsx");
/* harmony import */ var _clss_modal__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./clss-modal */ "./your-extensions/widgets/clss-custom-components/clss-modal.tsx");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};










const { useSelector } = jimu_core__WEBPACK_IMPORTED_MODULE_2__.ReactRedux;
const AddTemplateWidget = (props) => {
    const [error, setError] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState('');
    const [loading, setLoading] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(false);
    const [isVisible, setVisibility] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(props.visible);
    const [templateName, setTemplateName] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState('');
    const [selectedBasedOnTemplate, setSelectedBasedOnTemplate] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(null);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        setVisibility(props.visible);
    }, [props]);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        if (props.templates && props.templates.length === 1) {
            setSelectedBasedOnTemplate(props.templates[0]);
        }
    }, [props]);
    const saveNewTemplate = () => __awaiter(void 0, void 0, void 0, function* () {
        var _a;
        const exist = props.templates.find(t => t.name.toLowerCase().trim() === templateName.toLowerCase().trim());
        if (exist) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_4__.CLSSActionKeys.SET_ERRORS, `Template: ${templateName} already exists`);
            return;
        }
        setLoading(true);
        let newTemplate = Object.assign(Object.assign({}, selectedBasedOnTemplate), { name: templateName, title: templateName });
        let organization = null;
        if (props.selectedOrganization &&
            props.selectedOrganization.title !== '-None-') {
            organization = props.selectedOrganization;
        }
        let hazard = null;
        if (props.selectedHazard && props.selectedHazard.title !== '-None-') {
            hazard = props.selectedHazard;
        }
        const start = new Date().getTime();
        const resp = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__.createNewTemplate)(props.config, newTemplate, (_a = props.user) === null || _a === void 0 ? void 0 : _a.userName, organization, hazard);
        console.log('Create Template Took', new Date().getTime() - start);
        setLoading(false);
        if (resp.errors) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_4__.CLSSActionKeys.SET_ERRORS, resp.errors);
            return;
        }
        props.saveTemplateCompleteCallback();
        setLoading(false);
        props.toggleVisibility(false);
    });
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_modal__WEBPACK_IMPORTED_MODULE_8__.ClssModal, { title: "Add New Template", disable: !(templateName && selectedBasedOnTemplate && !error), save: saveNewTemplate, loading: loading, toggleVisibility: props.toggleVisibility, visible: isVisible },
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "new-template" },
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("style", null, `                    
                      .new-template{
                        display: flex;
                        flex-direction: column;
                      }                      
                      .new-template .add-link {
                        width: 207px;
                        margin-left: -16px;
                      }
                    `),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true },
                    "Template Name",
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("span", { style: { color: 'red' } }, "*")),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.TextInput, { "data-testid": "txtTemplateName", className: "template-input", size: "default", onChange: (e) => setTemplateName(e.target.value), value: templateName })),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true },
                    "Base Template On",
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("span", { style: { color: 'red' } }, "*")),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_templates_dropdown__WEBPACK_IMPORTED_MODULE_5__.TemplatesDropdown, { templates: props.templates, selectedTemplate: selectedBasedOnTemplate, setTemplate: setSelectedBasedOnTemplate })),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true }, "Template Hazard (optional)"),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_hazards_dropdown__WEBPACK_IMPORTED_MODULE_6__.HazardsDropdown, { config: props.config, hazards: props.hazards, selectedHazard: props.selectedHazard, setHazard: props.setHazard, vertical: true, toggleNewHazardModal: props.toggleNewHazardModal })),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true }, "Template Organization (optional)"),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_organizations_dropdown__WEBPACK_IMPORTED_MODULE_7__.OrganizationsDropdown, { config: props.config, vertical: true, organizations: props.organizations, selectedOrganization: props.selectedOrganization, setOrganization: props.setOrganization, toggleNewOrganizationModal: props.toggleNewOrganizationModal })))));
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
            react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.DropdownButton, { ref: buttonElement, size: "lg", style: { textAlign: 'left' } }, (item === null || item === void 0 ? void 0 : item.title) || (item === null || item === void 0 ? void 0 : item.name)),
            react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.DropdownMenu, { style: { width: menuWidth || "30%" } }, items === null || items === void 0 ? void 0 : items.map((item, idx) => {
                return (react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement("div", { id: (item === null || item === void 0 ? void 0 : item.name) || (item === null || item === void 0 ? void 0 : item.title), className: "dropdown-item-container" },
                    react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true, onClick: () => itemClick(item) }, (item === null || item === void 0 ? void 0 : item.title) || (item === null || item === void 0 ? void 0 : item.name)),
                    (((item === null || item === void 0 ? void 0 : item.title) || (item === null || item === void 0 ? void 0 : item.name)) !== '-None-') && deletable ?
                        (react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement(jimu_icons_outlined_editor_trash__WEBPACK_IMPORTED_MODULE_1__.TrashOutlined, { title: 'Remove', className: "close-button", size: 20, onClick: () => removeItem(item) }))
                        : null));
            })))));
};


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

/***/ "./your-extensions/widgets/clss-custom-components/clss-search-template.tsx":
/*!*********************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-search-template.tsx ***!
  \*********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "CLSSSearchInput": () => (/* binding */ CLSSSearchInput)
/* harmony export */ });
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! react */ "react");


const CLSSSearchInput = ({ title, onChange, defaultValue, props }) => {
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h4", { style: {
            width: '100%'
        } },
        title,
        ":",
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.TextInput, Object.assign({ style: { fontSize: props.theme.typography.sizes.display4 }, "data-testid": 'templateSearchInput', placeholder: 'Search...', size: 'lg', allowClear: true, type: "text", value: defaultValue, onChange: (e) => onChange(e.target.value) }, props))));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-template-button.tsx":
/*!*********************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-template-button.tsx ***!
  \*********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "TemplateButton": () => (/* binding */ TemplateButton)
/* harmony export */ });
/* harmony import */ var jimu_icons_outlined_application_setting__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-icons/outlined/application/setting */ "./jimu-icons/outlined/application/setting.tsx");
/* harmony import */ var jimu_icons_outlined_suggested_success__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-icons/outlined/suggested/success */ "./jimu-icons/outlined/suggested/success.tsx");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var jimu_icons_outlined_application_folder__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! jimu-icons/outlined/application/folder */ "./jimu-icons/outlined/application/folder.tsx");





const TemplateButton = ({ template, onClick, onDblClick, props }) => {
    var _a;
    const onDoubleClick = () => {
        // if(props.user.groups.find(g => g.title === CLSS_ADMIN) &&
        // template.name !== BASELINE_TEMPLATE_NAME){
        //     if(confirm('Archive the template?') == true){
        //         onDblClick(template.objectId);
        //     }
        // }
    };
    return (react__WEBPACK_IMPORTED_MODULE_3__["default"].createElement("div", { "data-testid": "templateButton", className: "button-wrapper", onDoubleClick: onDoubleClick, onClick: () => onClick(template.objectId), style: {
            backgroundColor: (template.isSelected
                ? props.config.selectedButtonBackgroundColor
                : props.config.defaultButtonBackgroundColor)
        } },
        react__WEBPACK_IMPORTED_MODULE_3__["default"].createElement("style", null, `
                    .button-wrapper{
                        display: flex;
                        border-radius: 10px;
                        width: 100%;
                        align-items: center;
                        font-size: 15px;
                        padding: 10px;
                        cursor: pointer;
                        justify-content: space-between;
                        margin: 5px 0;
                    }
                    .button-wrapper:hover{
                        opacity: 0.5;
                    }
                    .button-content{
                        display: flex;
                        justify-content:space-between;
                        align-items: center;
                    }
                    .button-label{
                        cursor: pointer;                        
                        width: 180px;
                        white-space: nowrap;
                        overflow: hidden;
                        text-overflow: ellipsis;
                        margin-bottom: 0 !important;
                    }
                    .pre-icon{
                        margin-right: 10px;
                    }
                `),
        react__WEBPACK_IMPORTED_MODULE_3__["default"].createElement("div", { className: "button-content" },
            ((_a = template === null || template === void 0 ? void 0 : template.status) === null || _a === void 0 ? void 0 : _a.code) === 1 ? (react__WEBPACK_IMPORTED_MODULE_3__["default"].createElement(jimu_icons_outlined_application_setting__WEBPACK_IMPORTED_MODULE_0__.SettingOutlined, { className: 'pre-icon', size: 20, color: template.isSelected
                    ? props.config.selectedButtonColor
                    : 'gray' })) :
                (react__WEBPACK_IMPORTED_MODULE_3__["default"].createElement(jimu_icons_outlined_application_folder__WEBPACK_IMPORTED_MODULE_4__.FolderOutlined, { className: 'pre-icon', size: 15, color: template.isSelected
                        ? props.config.selectedButtonColor
                        : 'gray' })),
            react__WEBPACK_IMPORTED_MODULE_3__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_2__.Label, { style: {
                    color: template.isSelected
                        ? props.config.selectedButtonColor
                        : props.config.defaultTemplateButtonColor
                }, className: 'button-label' }, template.name)),
        template.isSelected ? react__WEBPACK_IMPORTED_MODULE_3__["default"].createElement(jimu_icons_outlined_suggested_success__WEBPACK_IMPORTED_MODULE_1__.SuccessOutlined, { className: 'post-icon', size: 20, color: props.config.selectedButtonColor }) : null));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-templates-dropdown.tsx":
/*!************************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-templates-dropdown.tsx ***!
  \************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "TemplatesDropdown": () => (/* binding */ TemplatesDropdown)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var _clss_dropdown__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./clss-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx");


const TemplatesDropdown = ({ templates, selectedTemplate, setTemplate }) => {
    const deleteTemplate = () => {
    };
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_dropdown__WEBPACK_IMPORTED_MODULE_1__.ClssDropdown, { items: templates, item: selectedTemplate, deletable: true, setItem: setTemplate, deleteItem: deleteTemplate }));
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
/*!***********************************************************************!*\
  !*** ./your-extensions/widgets/clss-templates/src/runtime/widget.tsx ***!
  \***********************************************************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var _clss_custom_components_clss_search_template__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../clss-custom-components/clss-search-template */ "./your-extensions/widgets/clss-custom-components/clss-search-template.tsx");
/* harmony import */ var _clss_custom_components_clss_template_button__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../clss-custom-components/clss-template-button */ "./your-extensions/widgets/clss-custom-components/clss-template-button.tsx");
/* harmony import */ var _clss_custom_components_clss_loading__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../../../clss-custom-components/clss-loading */ "./your-extensions/widgets/clss-custom-components/clss-loading.tsx");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../../../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../clss-application/src/extensions/constants */ "./your-extensions/widgets/clss-application/src/extensions/constants.ts");
/* harmony import */ var _clss_custom_components_clss_add_template__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../../../clss-custom-components/clss-add-template */ "./your-extensions/widgets/clss-custom-components/clss-add-template.tsx");
/* harmony import */ var _clss_custom_components_clss_add_organization__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../../../clss-custom-components/clss-add-organization */ "./your-extensions/widgets/clss-custom-components/clss-add-organization.tsx");
/* harmony import */ var _clss_custom_components_clss_add_hazard__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ../../../clss-custom-components/clss-add-hazard */ "./your-extensions/widgets/clss-custom-components/clss-add-hazard.tsx");
/* harmony import */ var _clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ../../../clss-application/src/extensions/utils */ "./your-extensions/widgets/clss-application/src/extensions/utils.ts");
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
    var _a, _b, _c;
    const [loading, setLoading] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    const [isAddTemplateModalVisible, setAddTemplateModalVisibility] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    const [isAddOrganizationModalVisible, setAddOrganizationModalVisibility] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    const [isAddHazardModalVisible, setAddHazardModalVisibility] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    const [selectedHazard, setSelectedHazard] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(null);
    const [selectedOrganization, setSelectedOrganization] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(null);
    const [searchResult, setSearchResults] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState([]);
    const [config, setConfig] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(null);
    const [selectedFilter, setSelectedFilter] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState('All');
    const [searchText, setSearchText] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState('');
    const state = useSelector((state) => {
        return state.clssState;
    });
    const user = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.user;
    });
    const credential = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.authenticate;
    });
    const errors = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.errors;
    });
    const templates = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.templates;
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
        (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.initializeAuth)(props.config.appId);
    }, []);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (config) {
            if (!hazards || hazards.length === 0) {
                const start = new Date().getTime();
                (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.getHazards)(config, '1=1', 'clss-templates')
                    .then((hazards) => {
                    if (hazards && hazards.length > 0) {
                        hazards.orderBy('name');
                        hazards.unshift(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_7__.DEFAULT_LISTITEM);
                        (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.LOAD_HAZARDS_ACTION, hazards);
                    }
                    console.log('Hazards took: ' + (new Date().getTime() - start) + " ms");
                });
            }
        }
    }, [config]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (config) {
            if (!organizations || organizations.length === 0) {
                const start = new Date().getTime();
                (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.getOrganizations)(config, '1=1')
                    .then((organizations) => {
                    if (organizations && organizations.length > 0) {
                        organizations.orderBy('name');
                        organizations.unshift(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_7__.DEFAULT_LISTITEM);
                        (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.LOAD_ORGANIZATIONS_ACTION, organizations);
                    }
                    console.log('Organizations took: ' + (new Date().getTime() - start) + " ms");
                });
            }
        }
    }, [config]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (credential) {
            setConfig(Object.assign(Object.assign({}, props.config), { credential: credential }));
        }
    }, [credential]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (config) {
            loadTemplates();
        }
    }, [config]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (errors) {
            alert(errors);
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.SET_ERRORS, '');
        }
    }, [errors]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        var _a, _b, _c, _d, _e;
        (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.SET_USER_ACTION, {
            userName: (_a = props.user) === null || _a === void 0 ? void 0 : _a.username,
            firstName: (_b = props.user) === null || _b === void 0 ? void 0 : _b.firstName,
            lastName: (_c = props.user) === null || _c === void 0 ? void 0 : _c.lastName,
            groups: (_e = (_d = props.user) === null || _d === void 0 ? void 0 : _d.groups) === null || _e === void 0 ? void 0 : _e.map(g => g.title)
        });
    }, [props.user]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (templates && templates.length > 0) {
            filterSelectionChange(selectedFilter, templates);
        }
    }, [templates]);
    const loadTemplates = () => __awaiter(void 0, void 0, void 0, function* () {
        setLoading(true);
        const start = new Date().getTime();
        const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.getTemplates)(config, null, null);
        console.log('Templates Took', new Date().getTime() - start);
        setLoading(false);
        if (response.errors) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.SET_ERRORS, response.errors);
            return;
        }
        (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.LOAD_TEMPLATES_ACTION, response.data);
        yield filterSelectionChange(selectedFilter, response.data);
    });
    const performSearch = (text) => {
        setSearchText(text);
        let copiedTemplates = [...templates];
        if (!text || text === '' || text === null) {
            return (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_11__.sortObject)(copiedTemplates, 'createdDate');
        }
        let searchResults = copiedTemplates.filter(t => {
            var _a, _b, _c, _d, _e, _f, _g, _h;
            return ((_a = t.name) === null || _a === void 0 ? void 0 : _a.toLocaleLowerCase().includes(text.toLocaleLowerCase())) ||
                ((_b = t.organizationName) === null || _b === void 0 ? void 0 : _b.toLocaleLowerCase().includes(text.toLocaleLowerCase())) ||
                ((_c = t.hazardName) === null || _c === void 0 ? void 0 : _c.toLocaleLowerCase().includes(text.toLocaleLowerCase())) ||
                ((_d = t.hazardType) === null || _d === void 0 ? void 0 : _d.toLocaleLowerCase().includes(text.toLocaleLowerCase())) ||
                ((_e = (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_11__.parseDate)(t.createdDate)) === null || _e === void 0 ? void 0 : _e.split(',')[0].trim()) == text ||
                ((_f = (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_11__.parseDate)(t.createdDate)) === null || _f === void 0 ? void 0 : _f.includes(text)) ||
                ((_g = (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_11__.parseDate)(t.editedDate)) === null || _g === void 0 ? void 0 : _g.includes(text)) ||
                ((_h = (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_11__.parseDate)(t.editedDate)) === null || _h === void 0 ? void 0 : _h.split(',')[0].trim()) == text;
        });
        return (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_11__.sortObject)(searchResults, 'createdDate');
    };
    const onSearchTemplates = (text) => {
        filterSelectionChange(selectedFilter, performSearch(text));
    };
    const onSelectTemplate = (objectId) => __awaiter(void 0, void 0, void 0, function* () {
        (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.LOAD_TEMPLATES_ACTION, templates.map(t => {
            return Object.assign(Object.assign({}, t), { isSelected: t.objectId === objectId });
        }));
        if (templates.find(t => t.objectId === objectId).status.code !== 1) {
            return;
        }
        //await selectTemplate(objectId, templates.map(t => t.objectId), config); 
    });
    const onArchiveTemplate = (objectId) => __awaiter(void 0, void 0, void 0, function* () {
        // setLoading(true);
        // const res = await archiveTemplate(objectId, props.config);
        // if(!res.errors && res.data){
        //   await loadTemplates();
        // }  
        // setLoading(false);
    });
    const saveTemplate = () => __awaiter(void 0, void 0, void 0, function* () {
        yield loadTemplates();
        setAddTemplateModalVisibility(false);
    });
    const selectFilter = (id) => {
        filterSelectionChange(id, performSearch(searchText));
    };
    const filterSelectionChange = (id, _templates) => __awaiter(void 0, void 0, void 0, function* () {
        if (_templates == null) {
            return;
        }
        setSelectedFilter(id);
        switch (id) {
            case 'All':
                setSearchResults([..._templates]);
                break;
            case 'Selected':
                setSearchResults(_templates.filter(t => t.isSelected));
                break;
            case 'Active':
                setSearchResults(_templates.filter(t => t.status.code === 1));
                break;
            case 'Archived':
                setSearchResults(_templates.filter(t => t.status.code === 0));
                break;
        }
    });
    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "widget-clss-templates-container jimu-widget", style: {
            backgroundColor: props.theme.surfaces[2].bg
        } },
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("style", null, `
          .widget-clss-templates-container{       
            overflow: hidden; 
          }
          .search-templates{
              width: 100%;
              flex: 1;
              padding-bottom: 10px;
              overflow-y: auto;
              overflow-x: hidden;
          }
          .clss-templates-header{
            height: 50px;
            display: flex;
            justify-content: center;
            align-items: center;               
          }
          .template-buttons-content{
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            padding: 20px 10px;
            height: calc(100% - 50px);
            
          }
          .create-assessment-button{               
            height: 65px;
            width: 100%;
            font-weight: bold;
            font-size: 1.5em;
            border-radius: 5px;
            line-height: 1.5em;
          }
          .create-assessment-button:hover{
              opacity: 0.8
          }
          .create-new-template{
            height: 50px;
            font-weight: bold;
          }
          .create-new-template:hover{
            opacity: .8
          }          
          .widget-clss-templates-container .editor-icon{                    
            color: #534c4c;
            cursor: pointer;
            margin: 10px;
          }
          .widget-clss-templates-container .editor-icon:hover{
            opacity: .8
          }
          .widget-clss-templates-container .save-cancel, 
          .widget-clss-templates-container .save-icon{
            position: absolute;
            right: 10px;
            top: 10px;
          }
          .widget-clss-templates-container .data-dropdown, 
          .widget-clss-templates-container .data-input{
            width: 100%;
            display: flex;
          }
          .widget-clss-templates-container .data-dropdown 
          .widget-clss-templates-container .jimu-dropdown{
            width: 300px;
          }
          .widget-clss-templates-container .data-dropdown-menu{
            width: 300px;
          }
          .widget-clss-templates-container .error{
            color: red;
            font-size: 15px;
          }
          .widget-clss-templates-container .dropdown-item{
              font-size: 1.3em;
          }
          .widget-clss-templates-container .organization{
            display: flex;
            flex-direction: column;
          }
          .widget-clss-templates-container .end-widget{
            margin-bottom: 15px;
          }
          .widget-clss-templates-container .data-input{
            width: 30.7%
          }
          .widget-clss-templates-container .title.template{
            width: 142px;
          }

          .widget-clss-templates-container td label, 
          .widget-clss-templates-container td input{ 
            font-size: 1.5em;
          }
          .widget-clss-templates-container td label{
            width: 128px;
          }
          .widget-clss-templates-container td label.value{
            font-weight: bold;
            width: auto;
          }
          .widget-clss-templates-container tr.td-under>td{
            padding-bottom: 1em;
          }
          .widget-clss-templates-container  .template-input input{
            padding-left: 20px;
            height: 40px;
            font-size: 16px;
          }
          .widget-clss-templates-container  .template-input span{
            height: 40px !important;
          }
          .template-filter-actions .actions{
            display: flex;
            justify-content: space-around;
            align-items: center;
          }
          .template-filter-actions .jimu-checkbox{
            margin-right: 10px;
          }
        `),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "clss-templates-header", style: {
                backgroundColor: props.config.headerBackgroundColor || props.theme.colors.secondary,
                color: props.config.headerTextColor || props.theme.colors.palette.primary[900],
                boxShadow: props.theme.boxShadows.default,
                fontSize: props.theme.typography.sizes.display3,
                fontWeight: props.theme.typography.weights.bold
            } },
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { check: true }, "Templates")),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: 'template-buttons-content' },
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "template-filter-actions" },
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("h4", null, "Filter templates by:"),
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "actions", "aria-label": "Filter templates by", role: "group" },
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { centric: true },
                        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Checkbox, { id: 'All', "aria-label": "Checkbox", checked: selectedFilter === 'All', onChange: (e) => selectFilter(e.target.id) }),
                        "All"),
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { centric: true },
                        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Checkbox, { id: 'Active', "aria-label": "Checkbox", checked: selectedFilter === 'Active', onChange: (e) => selectFilter(e.target.id) }),
                        "Active"),
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { centric: true, check: true },
                        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Checkbox, { id: 'Archived', "aria-label": "Checkbox", checked: selectedFilter === 'Archived', onChange: (e) => selectFilter(e.target.id) }),
                        "Archived"))),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: 'search-templates' },
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_search_template__WEBPACK_IMPORTED_MODULE_2__.CLSSSearchInput, { title: 'Search Templates', onChange: onSearchTemplates, props: props }), searchResult === null || searchResult === void 0 ? void 0 :
                searchResult.map((temp) => {
                    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_template_button__WEBPACK_IMPORTED_MODULE_3__.TemplateButton, { key: temp.id, props: props, template: temp, onClick: () => onSelectTemplate(temp.objectId), onDblClick: onArchiveTemplate }));
                })),
            (user && ((_a = user.groups) === null || _a === void 0 ? void 0 : _a.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_7__.CLSS_ADMIN)) ||
                user && ((_b = user.groups) === null || _b === void 0 ? void 0 : _b.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_7__.CLSS_EDITOR)) ||
                user && ((_c = user.groups) === null || _c === void 0 ? void 0 : _c.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_7__.CLSS_FOLLOWERS))) ?
                (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Button, { "data-testid": "btnCreateNewTemplate", className: 'create-new-template', style: { background: props.config.headerBackgroundColor }, size: 'lg', onClick: () => setAddTemplateModalVisibility(true) }, "Create Template")) : null,
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_add_template__WEBPACK_IMPORTED_MODULE_8__.AddTemplateWidget, { config: config, hazards: hazards, selectedHazard: selectedHazard, setHazard: setSelectedHazard, selectedOrganization: selectedOrganization, organizations: organizations, setOrganization: setSelectedOrganization, templates: templates, user: user, visible: isAddTemplateModalVisible, toggleVisibility: setAddTemplateModalVisibility, saveTemplateCompleteCallback: saveTemplate, toggleNewHazardModal: setAddHazardModalVisibility, toggleNewOrganizationModal: setAddOrganizationModalVisibility }),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_add_organization__WEBPACK_IMPORTED_MODULE_9__.AddOrganizatonWidget, { propsConfig: props === null || props === void 0 ? void 0 : props.config, visible: isAddOrganizationModalVisible, setOrganization: setSelectedOrganization, toggle: setAddOrganizationModalVisibility }),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_add_hazard__WEBPACK_IMPORTED_MODULE_10__.AddHazardWidget, { props: props, visible: isAddHazardModalVisible, setHazard: setSelectedHazard, toggle: setAddHazardModalVisibility })),
        loading ? jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_loading__WEBPACK_IMPORTED_MODULE_4__["default"], null) : null));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (Widget);

})();

/******/ 	return __webpack_exports__;
/******/ })()

			);
		}
	};
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2lkZ2V0cy9jbHNzLXRlbXBsYXRlcy9kaXN0L3J1bnRpbWUvd2lkZ2V0LmpzIiwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQ0E7QUFDaUM7QUFDcUY7QUFDckU7QUFDTjtBQUN5QjtBQUNWO0FBQzFEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFlBQVksY0FBYztBQUMxQjtBQUNBO0FBQ0E7QUFDQTtBQUNBLElBQUk7QUFDSjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsSUFBSTtBQUNKO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGNBQWMsbUVBQVE7QUFDdEI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBLGtCQUFrQixlQUFlO0FBQ2pDO0FBQ0E7QUFDQTtBQUNBO0FB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Z0IsRUFBRSw2QkFBNkIsRUFDL0MsNEJBQTRCLEVBQUUsWUFBWSxFQUMxQyxvQkFBb0IsRUFBRSwyQkFBMkIsRUFDakQsMEJBQTBCLEVBQUUsaUNBQWlDLEdBQUc7WUFFbEUsMkRBQUMsK0ZBQW9CLElBQ25CLFdBQVcsRUFBRSxLQUFLLGFBQUwsS0FBSyx1QkFBTCxLQUFLLENBQUUsTUFBTSxFQUMxQixPQUFPLEVBQUUsNkJBQTZCLEVBQ3RDLGVBQWUsRUFBRSx1QkFBdUIsRUFDeEMsTUFBTSxFQUFFLGlDQUFpQyxHQUFHO1lBRTlDLDJEQUFDLHFGQUFlLElBQ2QsS0FBSyxFQUFFLEtBQUssRUFDWixPQUFPLEVBQUUsdUJBQXVCLEVBQ2hDLFNBQVMsRUFBRSxpQkFBaUIsRUFDNUIsTUFBTSxFQUFFLDJCQUEyQixHQUFHLENBQ3BDO1FBRUosT0FBTyxDQUFDLENBQUMsQ0FBQywyREFBQyw0RUFBVyxPQUFFLEVBQUMsQ0FBQyxJQUFJLENBRTVCLENBQ1A7QUFDSCxDQUFDO0FBQ0QsaUVBQWUsTUFBTSIsInNvdXJjZXMiOlsid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aC9kaXN0L2VzbS9Vc2VyU2Vzc2lvbi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgvZGlzdC9lc20vZmVkZXJhdGlvbi11dGlscy5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgvZGlzdC9lc20vZmV0Y2gtdG9rZW4uanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL2Rpc3QvZXNtL2dlbmVyYXRlLXRva2VuLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aC9kaXN0L2VzbS92YWxpZGF0ZS1hcHAtYWNjZXNzLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aC9ub2RlX21vZHVsZXMvdHNsaWIvdHNsaWIuZXM2LmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllci9kaXN0L2VzbS9hZGQuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyL2Rpc3QvZXNtL2RlbGV0ZS5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXIvZGlzdC9lc20vcXVlcnkuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyL2Rpc3QvZXNtL3F1ZXJ5UmVsYXRlZC5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXIvZGlzdC9lc20vdXBkYXRlLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllci9ub2RlX21vZHVsZXMvdHNsaWIvdHNsaWIuZXM2LmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS9yZXF1ZXN0LmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy9BcmNHSVNSZXF1ZXN0RXJyb3IuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL2FwcGVuZC1jdXN0b20tcGFyYW1zLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy9jbGVhbi11cmwuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL2RlY29kZS1xdWVyeS1zdHJpbmcuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL2VuY29kZS1mb3JtLWRhdGEuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL2VuY29kZS1xdWVyeS1zdHJpbmcuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL3Byb2Nlc3MtcGFyYW1zLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy93YXJuLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9ub2RlX21vZHVsZXMvdHNsaWIvdHNsaWIuZXM2LmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL3N2Zy9vdXRsaW5lZC9hcHBsaWNhdGlvbi9mb2xkZXIuc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL3N2Zy9vdXRsaW5lZC9hcHBsaWNhdGlvbi9zZXR0aW5nLnN2ZyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9zdmcvb3V0bGluZWQvZWRpdG9yL3BsdXMtY2lyY2xlLnN2ZyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9zdmcvb3V0bGluZWQvZWRpdG9yL3RyYXNoLnN2ZyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9zdmcvb3V0bGluZWQvc3VnZ2VzdGVkL3N1Y2Nlc3Muc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL291dGxpbmVkL2FwcGxpY2F0aW9uL2ZvbGRlci50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvb3V0bGluZWQvYXBwbGljYXRpb24vc2V0dGluZy50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvb3V0bGluZWQvZWRpdG9yL3BsdXMtY2lyY2xlLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9vdXRsaW5lZC9lZGl0b3IvdHJhc2gudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL291dGxpbmVkL3N1Z2dlc3RlZC9zdWNjZXNzLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9hcGkudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXV0aC50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jbHNzLXN0b3JlLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2NvbnN0YW50cy50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9lc3JpLWFwaS50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9sb2dnZXIudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvdXRpbHMudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1hZGQtaGF6YXJkLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWFkZC1vcmdhbml6YXRpb24udHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtYWRkLXRlbXBsYXRlLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWRyb3Bkb3duLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWhhemFyZHMtZHJvcGRvd24udHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtbG9hZGluZy50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1tb2RhbC50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1vcmdhbml6YXRpb25zLWRyb3Bkb3duLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLXNlYXJjaC10ZW1wbGF0ZS50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy10ZW1wbGF0ZS1idXR0b24udHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtdGVtcGxhdGVzLWRyb3Bkb3duLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtYXJjZ2lzXCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC9leHRlcm5hbCBzeXN0ZW0gXCJqaW11LWNvcmVcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtY29yZS9yZWFjdFwiIiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS11aVwiIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ib290c3RyYXAiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvY29tcGF0IGdldCBkZWZhdWx0IGV4cG9ydCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9kZWZpbmUgcHJvcGVydHkgZ2V0dGVycyIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9oYXNPd25Qcm9wZXJ0eSBzaG9ydGhhbmQiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvbWFrZSBuYW1lc3BhY2Ugb2JqZWN0Iiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL3B1YmxpY1BhdGgiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtY29yZS9saWIvc2V0LXB1YmxpYy1wYXRoLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLXRlbXBsYXRlcy9zcmMvcnVudGltZS93aWRnZXQudHN4Il0sInNvdXJjZXNDb250ZW50IjpbIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDE5IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyByZXF1ZXN0LCBBcmNHSVNBdXRoRXJyb3IsIGNsZWFuVXJsLCBlbmNvZGVRdWVyeVN0cmluZywgZGVjb2RlUXVlcnlTdHJpbmcsIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbmltcG9ydCB7IGdlbmVyYXRlVG9rZW4gfSBmcm9tIFwiLi9nZW5lcmF0ZS10b2tlblwiO1xuaW1wb3J0IHsgZmV0Y2hUb2tlbiB9IGZyb20gXCIuL2ZldGNoLXRva2VuXCI7XG5pbXBvcnQgeyBjYW5Vc2VPbmxpbmVUb2tlbiwgaXNGZWRlcmF0ZWQgfSBmcm9tIFwiLi9mZWRlcmF0aW9uLXV0aWxzXCI7XG5pbXBvcnQgeyB2YWxpZGF0ZUFwcEFjY2VzcyB9IGZyb20gXCIuL3ZhbGlkYXRlLWFwcC1hY2Nlc3NcIjtcbmZ1bmN0aW9uIGRlZmVyKCkge1xuICAgIHZhciBkZWZlcnJlZCA9IHtcbiAgICAgICAgcHJvbWlzZTogbnVsbCxcbiAgICAgICAgcmVzb2x2ZTogbnVsbCxcbiAgICAgICAgcmVqZWN0OiBudWxsLFxuICAgIH07XG4gICAgZGVmZXJyZWQucHJvbWlzZSA9IG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSA9IHJlc29sdmU7XG4gICAgICAgIGRlZmVycmVkLnJlamVjdCA9IHJlamVjdDtcbiAgICB9KTtcbiAgICByZXR1cm4gZGVmZXJyZWQ7XG59XG4vKipcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBVc2VyU2Vzc2lvbiB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgnO1xuICogVXNlclNlc3Npb24uYmVnaW5PQXV0aDIoe1xuICogICAvLyByZWdpc3RlciBhbiBhcHAgb2YgeW91ciBvd24gdG8gY3JlYXRlIGEgdW5pcXVlIGNsaWVudElkXG4gKiAgIGNsaWVudElkOiBcImFiYzEyM1wiLFxuICogICByZWRpcmVjdFVyaTogJ2h0dHBzOi8veW91cmFwcC5jb20vYXV0aGVudGljYXRlLmh0bWwnXG4gKiB9KVxuICogICAudGhlbihzZXNzaW9uKVxuICogLy8gb3JcbiAqIG5ldyBVc2VyU2Vzc2lvbih7XG4gKiAgIHVzZXJuYW1lOiBcImpzbWl0aFwiLFxuICogICBwYXNzd29yZDogXCIxMjM0NTZcIlxuICogfSlcbiAqIC8vIG9yXG4gKiBVc2VyU2Vzc2lvbi5kZXNlcmlhbGl6ZShjYWNoZSlcbiAqIGBgYFxuICogVXNlZCB0byBhdXRoZW50aWNhdGUgYm90aCBBcmNHSVMgT25saW5lIGFuZCBBcmNHSVMgRW50ZXJwcmlzZSB1c2Vycy4gYFVzZXJTZXNzaW9uYCBpbmNsdWRlcyBoZWxwZXIgbWV0aG9kcyBmb3IgW09BdXRoIDIuMF0oL2FyY2dpcy1yZXN0LWpzL2d1aWRlcy9icm93c2VyLWF1dGhlbnRpY2F0aW9uLykgaW4gYm90aCBicm93c2VyIGFuZCBzZXJ2ZXIgYXBwbGljYXRpb25zLlxuICovXG52YXIgVXNlclNlc3Npb24gPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgZnVuY3Rpb24gVXNlclNlc3Npb24ob3B0aW9ucykge1xuICAgICAgICB0aGlzLmNsaWVudElkID0gb3B0aW9ucy5jbGllbnRJZDtcbiAgICAgICAgdGhpcy5fcmVmcmVzaFRva2VuID0gb3B0aW9ucy5yZWZyZXNoVG9rZW47XG4gICAgICAgIHRoaXMuX3JlZnJlc2hUb2tlbkV4cGlyZXMgPSBvcHRpb25zLnJlZnJlc2hUb2tlbkV4cGlyZXM7XG4gICAgICAgIHRoaXMudXNlcm5hbWUgPSBvcHRpb25zLnVzZXJuYW1lO1xuICAgICAgICB0aGlzLnBhc3N3b3JkID0gb3B0aW9ucy5wYXNzd29yZDtcbiAgICAgICAgdGhpcy5fdG9rZW4gPSBvcHRpb25zLnRva2VuO1xuICAgICAgICB0aGlzLl90b2tlbkV4cGlyZXMgPSBvcHRpb25zLnRva2VuRXhwaXJlcztcbiAgICAgICAgdGhpcy5wb3J0YWwgPSBvcHRpb25zLnBvcnRhbFxuICAgICAgICAgICAgPyBjbGVhblVybChvcHRpb25zLnBvcnRhbClcbiAgICAgICAgICAgIDogXCJodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiO1xuICAgICAgICB0aGlzLnNzbCA9IG9wdGlvbnMuc3NsO1xuICAgICAgICB0aGlzLnByb3ZpZGVyID0gb3B0aW9ucy5wcm92aWRlciB8fCBcImFyY2dpc1wiO1xuICAgICAgICB0aGlzLnRva2VuRHVyYXRpb24gPSBvcHRpb25zLnRva2VuRHVyYXRpb24gfHwgMjAxNjA7XG4gICAgICAgIHRoaXMucmVkaXJlY3RVcmkgPSBvcHRpb25zLnJlZGlyZWN0VXJpO1xuICAgICAgICB0aGlzLnJlZnJlc2hUb2tlblRUTCA9IG9wdGlvbnMucmVmcmVzaFRva2VuVFRMIHx8IDIwMTYwO1xuICAgICAgICB0aGlzLnNlcnZlciA9IG9wdGlvbnMuc2VydmVyO1xuICAgICAgICB0aGlzLmZlZGVyYXRlZFNlcnZlcnMgPSB7fTtcbiAgICAgICAgdGhpcy50cnVzdGVkRG9tYWlucyA9IFtdO1xuICAgICAgICAvLyBpZiBhIG5vbi1mZWRlcmF0ZWQgc2VydmVyIHdhcyBwYXNzZWQgZXhwbGljaXRseSwgaXQgc2hvdWxkIGJlIHRydXN0ZWQuXG4gICAgICAgIGlmIChvcHRpb25zLnNlcnZlcikge1xuICAgICAgICAgICAgLy8gaWYgdGhlIHVybCBpbmNsdWRlcyBtb3JlIHRoYW4gJy9hcmNnaXMvJywgdHJpbSB0aGUgcmVzdFxuICAgICAgICAgICAgdmFyIHJvb3QgPSB0aGlzLmdldFNlcnZlclJvb3RVcmwob3B0aW9ucy5zZXJ2ZXIpO1xuICAgICAgICAgICAgdGhpcy5mZWRlcmF0ZWRTZXJ2ZXJzW3Jvb3RdID0ge1xuICAgICAgICAgICAgICAgIHRva2VuOiBvcHRpb25zLnRva2VuLFxuICAgICAgICAgICAgICAgIGV4cGlyZXM6IG9wdGlvbnMudG9rZW5FeHBpcmVzLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0cyA9IHt9O1xuICAgIH1cbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoVXNlclNlc3Npb24ucHJvdG90eXBlLCBcInRva2VuXCIsIHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFRoZSBjdXJyZW50IEFyY0dJUyBPbmxpbmUgb3IgQXJjR0lTIEVudGVycHJpc2UgYHRva2VuYC5cbiAgICAgICAgICovXG4gICAgICAgIGdldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3Rva2VuO1xuICAgICAgICB9LFxuICAgICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSk7XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KFVzZXJTZXNzaW9uLnByb3RvdHlwZSwgXCJ0b2tlbkV4cGlyZXNcIiwge1xuICAgICAgICAvKipcbiAgICAgICAgICogVGhlIGV4cGlyYXRpb24gdGltZSBvZiB0aGUgY3VycmVudCBgdG9rZW5gLlxuICAgICAgICAgKi9cbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fdG9rZW5FeHBpcmVzO1xuICAgICAgICB9LFxuICAgICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSk7XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KFVzZXJTZXNzaW9uLnByb3RvdHlwZSwgXCJyZWZyZXNoVG9rZW5cIiwge1xuICAgICAgICAvKipcbiAgICAgICAgICogVGhlIGN1cnJlbnQgdG9rZW4gdG8gQXJjR0lTIE9ubGluZSBvciBBcmNHSVMgRW50ZXJwcmlzZS5cbiAgICAgICAgICovXG4gICAgICAgIGdldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3JlZnJlc2hUb2tlbjtcbiAgICAgICAgfSxcbiAgICAgICAgZW51bWVyYWJsZTogZmFsc2UsXG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZVxuICAgIH0pO1xuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShVc2VyU2Vzc2lvbi5wcm90b3R5cGUsIFwicmVmcmVzaFRva2VuRXhwaXJlc1wiLCB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBUaGUgZXhwaXJhdGlvbiB0aW1lIG9mIHRoZSBjdXJyZW50IGByZWZyZXNoVG9rZW5gLlxuICAgICAgICAgKi9cbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcmVmcmVzaFRva2VuRXhwaXJlcztcbiAgICAgICAgfSxcbiAgICAgICAgZW51bWVyYWJsZTogZmFsc2UsXG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZVxuICAgIH0pO1xuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShVc2VyU2Vzc2lvbi5wcm90b3R5cGUsIFwidHJ1c3RlZFNlcnZlcnNcIiwge1xuICAgICAgICAvKipcbiAgICAgICAgICogRGVwcmVjYXRlZCwgdXNlIGBmZWRlcmF0ZWRTZXJ2ZXJzYCBpbnN0ZWFkLlxuICAgICAgICAgKlxuICAgICAgICAgKiBAZGVwcmVjYXRlZFxuICAgICAgICAgKi9cbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkRFUFJFQ0FURUQ6IHVzZSBmZWRlcmF0ZWRTZXJ2ZXJzIGluc3RlYWRcIik7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5mZWRlcmF0ZWRTZXJ2ZXJzO1xuICAgICAgICB9LFxuICAgICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSk7XG4gICAgLyoqXG4gICAgICogQmVnaW5zIGEgbmV3IGJyb3dzZXItYmFzZWQgT0F1dGggMi4wIHNpZ24gaW4uIElmIGBvcHRpb25zLnBvcHVwYCBpcyBgdHJ1ZWAgdGhlXG4gICAgICogYXV0aGVudGljYXRpb24gd2luZG93IHdpbGwgb3BlbiBpbiBhIG5ldyB0YWIvd2luZG93IGFuZCB0aGUgZnVuY3Rpb24gd2lsbCByZXR1cm5cbiAgICAgKiBQcm9taXNlJmx0O1VzZXJTZXNzaW9uJmd0Oy4gT3RoZXJ3aXNlLCB0aGUgdXNlciB3aWxsIGJlIHJlZGlyZWN0ZWQgdG8gdGhlXG4gICAgICogYXV0aG9yaXphdGlvbiBwYWdlIGluIHRoZWlyIGN1cnJlbnQgdGFiL3dpbmRvdyBhbmQgdGhlIGZ1bmN0aW9uIHdpbGwgcmV0dXJuIGB1bmRlZmluZWRgLlxuICAgICAqXG4gICAgICogQGJyb3dzZXJPbmx5XG4gICAgICovXG4gICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgICBVc2VyU2Vzc2lvbi5iZWdpbk9BdXRoMiA9IGZ1bmN0aW9uIChvcHRpb25zLCB3aW4pIHtcbiAgICAgICAgaWYgKHdpbiA9PT0gdm9pZCAwKSB7IHdpbiA9IHdpbmRvdzsgfVxuICAgICAgICBpZiAob3B0aW9ucy5kdXJhdGlvbikge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJERVBSRUNBVEVEOiAnZHVyYXRpb24nIGlzIGRlcHJlY2F0ZWQgLSB1c2UgJ2V4cGlyYXRpb24nIGluc3RlYWRcIik7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIF9hID0gX19hc3NpZ24oe1xuICAgICAgICAgICAgcG9ydGFsOiBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCIsXG4gICAgICAgICAgICBwcm92aWRlcjogXCJhcmNnaXNcIixcbiAgICAgICAgICAgIGV4cGlyYXRpb246IDIwMTYwLFxuICAgICAgICAgICAgcG9wdXA6IHRydWUsXG4gICAgICAgICAgICBwb3B1cFdpbmRvd0ZlYXR1cmVzOiBcImhlaWdodD00MDAsd2lkdGg9NjAwLG1lbnViYXI9bm8sbG9jYXRpb249eWVzLHJlc2l6YWJsZT15ZXMsc2Nyb2xsYmFycz15ZXMsc3RhdHVzPXllc1wiLFxuICAgICAgICAgICAgc3RhdGU6IG9wdGlvbnMuY2xpZW50SWQsXG4gICAgICAgICAgICBsb2NhbGU6IFwiXCIsXG4gICAgICAgIH0sIG9wdGlvbnMpLCBwb3J0YWwgPSBfYS5wb3J0YWwsIHByb3ZpZGVyID0gX2EucHJvdmlkZXIsIGNsaWVudElkID0gX2EuY2xpZW50SWQsIGV4cGlyYXRpb24gPSBfYS5leHBpcmF0aW9uLCByZWRpcmVjdFVyaSA9IF9hLnJlZGlyZWN0VXJpLCBwb3B1cCA9IF9hLnBvcHVwLCBwb3B1cFdpbmRvd0ZlYXR1cmVzID0gX2EucG9wdXBXaW5kb3dGZWF0dXJlcywgc3RhdGUgPSBfYS5zdGF0ZSwgbG9jYWxlID0gX2EubG9jYWxlLCBwYXJhbXMgPSBfYS5wYXJhbXM7XG4gICAgICAgIHZhciB1cmw7XG4gICAgICAgIGlmIChwcm92aWRlciA9PT0gXCJhcmNnaXNcIikge1xuICAgICAgICAgICAgdXJsID0gcG9ydGFsICsgXCIvb2F1dGgyL2F1dGhvcml6ZT9jbGllbnRfaWQ9XCIgKyBjbGllbnRJZCArIFwiJnJlc3BvbnNlX3R5cGU9dG9rZW4mZXhwaXJhdGlvbj1cIiArIChvcHRpb25zLmR1cmF0aW9uIHx8IGV4cGlyYXRpb24pICsgXCImcmVkaXJlY3RfdXJpPVwiICsgZW5jb2RlVVJJQ29tcG9uZW50KHJlZGlyZWN0VXJpKSArIFwiJnN0YXRlPVwiICsgc3RhdGUgKyBcIiZsb2NhbGU9XCIgKyBsb2NhbGU7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICB1cmwgPSBwb3J0YWwgKyBcIi9vYXV0aDIvc29jaWFsL2F1dGhvcml6ZT9jbGllbnRfaWQ9XCIgKyBjbGllbnRJZCArIFwiJnNvY2lhbExvZ2luUHJvdmlkZXJOYW1lPVwiICsgcHJvdmlkZXIgKyBcIiZhdXRvQWNjb3VudENyZWF0ZUZvclNvY2lhbD10cnVlJnJlc3BvbnNlX3R5cGU9dG9rZW4mZXhwaXJhdGlvbj1cIiArIChvcHRpb25zLmR1cmF0aW9uIHx8IGV4cGlyYXRpb24pICsgXCImcmVkaXJlY3RfdXJpPVwiICsgZW5jb2RlVVJJQ29tcG9uZW50KHJlZGlyZWN0VXJpKSArIFwiJnN0YXRlPVwiICsgc3RhdGUgKyBcIiZsb2NhbGU9XCIgKyBsb2NhbGU7XG4gICAgICAgIH1cbiAgICAgICAgLy8gYXBwZW5kIGFkZGl0aW9uYWwgcGFyYW1zXG4gICAgICAgIGlmIChwYXJhbXMpIHtcbiAgICAgICAgICAgIHVybCA9IHVybCArIFwiJlwiICsgZW5jb2RlUXVlcnlTdHJpbmcocGFyYW1zKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXBvcHVwKSB7XG4gICAgICAgICAgICB3aW4ubG9jYXRpb24uaHJlZiA9IHVybDtcbiAgICAgICAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIHNlc3Npb24gPSBkZWZlcigpO1xuICAgICAgICB3aW5bXCJfX0VTUklfUkVTVF9BVVRIX0hBTkRMRVJfXCIgKyBjbGllbnRJZF0gPSBmdW5jdGlvbiAoZXJyb3JTdHJpbmcsIG9hdXRoSW5mb1N0cmluZykge1xuICAgICAgICAgICAgaWYgKGVycm9yU3RyaW5nKSB7XG4gICAgICAgICAgICAgICAgdmFyIGVycm9yID0gSlNPTi5wYXJzZShlcnJvclN0cmluZyk7XG4gICAgICAgICAgICAgICAgc2Vzc2lvbi5yZWplY3QobmV3IEFyY0dJU0F1dGhFcnJvcihlcnJvci5lcnJvck1lc3NhZ2UsIGVycm9yLmVycm9yKSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKG9hdXRoSW5mb1N0cmluZykge1xuICAgICAgICAgICAgICAgIHZhciBvYXV0aEluZm8gPSBKU09OLnBhcnNlKG9hdXRoSW5mb1N0cmluZyk7XG4gICAgICAgICAgICAgICAgc2Vzc2lvbi5yZXNvbHZlKG5ldyBVc2VyU2Vzc2lvbih7XG4gICAgICAgICAgICAgICAgICAgIGNsaWVudElkOiBjbGllbnRJZCxcbiAgICAgICAgICAgICAgICAgICAgcG9ydGFsOiBwb3J0YWwsXG4gICAgICAgICAgICAgICAgICAgIHNzbDogb2F1dGhJbmZvLnNzbCxcbiAgICAgICAgICAgICAgICAgICAgdG9rZW46IG9hdXRoSW5mby50b2tlbixcbiAgICAgICAgICAgICAgICAgICAgdG9rZW5FeHBpcmVzOiBuZXcgRGF0ZShvYXV0aEluZm8uZXhwaXJlcyksXG4gICAgICAgICAgICAgICAgICAgIHVzZXJuYW1lOiBvYXV0aEluZm8udXNlcm5hbWUsXG4gICAgICAgICAgICAgICAgfSkpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuICAgICAgICB3aW4ub3Blbih1cmwsIFwib2F1dGgtd2luZG93XCIsIHBvcHVwV2luZG93RmVhdHVyZXMpO1xuICAgICAgICByZXR1cm4gc2Vzc2lvbi5wcm9taXNlO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogQ29tcGxldGVzIGEgYnJvd3Nlci1iYXNlZCBPQXV0aCAyLjAgc2lnbiBpbi4gSWYgYG9wdGlvbnMucG9wdXBgIGlzIGB0cnVlYCB0aGUgdXNlclxuICAgICAqIHdpbGwgYmUgcmV0dXJuZWQgdG8gdGhlIHByZXZpb3VzIHdpbmRvdy4gT3RoZXJ3aXNlIGEgbmV3IGBVc2VyU2Vzc2lvbmBcbiAgICAgKiB3aWxsIGJlIHJldHVybmVkLiBZb3UgbXVzdCBwYXNzIHRoZSBzYW1lIHZhbHVlcyBmb3IgYG9wdGlvbnMucG9wdXBgIGFuZFxuICAgICAqIGBvcHRpb25zLnBvcnRhbGAgYXMgeW91IHVzZWQgaW4gYGJlZ2luT0F1dGgyKClgLlxuICAgICAqXG4gICAgICogQGJyb3dzZXJPbmx5XG4gICAgICovXG4gICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgICBVc2VyU2Vzc2lvbi5jb21wbGV0ZU9BdXRoMiA9IGZ1bmN0aW9uIChvcHRpb25zLCB3aW4pIHtcbiAgICAgICAgaWYgKHdpbiA9PT0gdm9pZCAwKSB7IHdpbiA9IHdpbmRvdzsgfVxuICAgICAgICB2YXIgX2EgPSBfX2Fzc2lnbih7IHBvcnRhbDogXCJodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiLCBwb3B1cDogdHJ1ZSB9LCBvcHRpb25zKSwgcG9ydGFsID0gX2EucG9ydGFsLCBjbGllbnRJZCA9IF9hLmNsaWVudElkLCBwb3B1cCA9IF9hLnBvcHVwO1xuICAgICAgICBmdW5jdGlvbiBjb21wbGV0ZVNpZ25JbihlcnJvciwgb2F1dGhJbmZvKSB7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIHZhciBoYW5kbGVyRm4gPSB2b2lkIDA7XG4gICAgICAgICAgICAgICAgdmFyIGhhbmRsZXJGbk5hbWUgPSBcIl9fRVNSSV9SRVNUX0FVVEhfSEFORExFUl9cIiArIGNsaWVudElkO1xuICAgICAgICAgICAgICAgIGlmIChwb3B1cCkge1xuICAgICAgICAgICAgICAgICAgICAvLyBHdWFyZCBiL2MgSUUgZG9lcyBub3Qgc3VwcG9ydCB3aW5kb3cub3BlbmVyXG4gICAgICAgICAgICAgICAgICAgIGlmICh3aW4ub3BlbmVyKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAod2luLm9wZW5lci5wYXJlbnQgJiYgd2luLm9wZW5lci5wYXJlbnRbaGFuZGxlckZuTmFtZV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVyRm4gPSB3aW4ub3BlbmVyLnBhcmVudFtoYW5kbGVyRm5OYW1lXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgaWYgKHdpbi5vcGVuZXIgJiYgd2luLm9wZW5lcltoYW5kbGVyRm5OYW1lXSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIHN1cHBvcnQgcG9wLW91dCBvYXV0aCBmcm9tIHdpdGhpbiBhbiBpZnJhbWVcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVyRm4gPSB3aW4ub3BlbmVyW2hhbmRsZXJGbk5hbWVdO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gSUVcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICh3aW4gIT09IHdpbi5wYXJlbnQgJiYgd2luLnBhcmVudCAmJiB3aW4ucGFyZW50W2hhbmRsZXJGbk5hbWVdKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaGFuZGxlckZuID0gd2luLnBhcmVudFtoYW5kbGVyRm5OYW1lXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAvLyBpZiB3ZSBoYXZlIGEgaGFuZGxlciBmbiwgY2FsbCBpdCBhbmQgY2xvc2UgdGhlIHdpbmRvd1xuICAgICAgICAgICAgICAgICAgICBpZiAoaGFuZGxlckZuKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVyRm4oZXJyb3IgPyBKU09OLnN0cmluZ2lmeShlcnJvcikgOiB1bmRlZmluZWQsIEpTT04uc3RyaW5naWZ5KG9hdXRoSW5mbykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgd2luLmNsb3NlKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gdW5kZWZpbmVkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgQXJjR0lTQXV0aEVycm9yKFwiVW5hYmxlIHRvIGNvbXBsZXRlIGF1dGhlbnRpY2F0aW9uLiBJdCdzIHBvc3NpYmxlIHlvdSBzcGVjaWZpZWQgcG9wdXAgYmFzZWQgb0F1dGgyIGJ1dCBubyBoYW5kbGVyIGZyb20gXFxcImJlZ2luT0F1dGgyKClcXFwiIHByZXNlbnQuIFRoaXMgZ2VuZXJhbGx5IGhhcHBlbnMgYmVjYXVzZSB0aGUgXFxcInBvcHVwXFxcIiBvcHRpb24gZGlmZmVycyBiZXR3ZWVuIFxcXCJiZWdpbk9BdXRoMigpXFxcIiBhbmQgXFxcImNvbXBsZXRlT0F1dGgyKClcXFwiLlwiKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmIChlcnJvcikge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNBdXRoRXJyb3IoZXJyb3IuZXJyb3JNZXNzYWdlLCBlcnJvci5lcnJvcik7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gbmV3IFVzZXJTZXNzaW9uKHtcbiAgICAgICAgICAgICAgICBjbGllbnRJZDogY2xpZW50SWQsXG4gICAgICAgICAgICAgICAgcG9ydGFsOiBwb3J0YWwsXG4gICAgICAgICAgICAgICAgc3NsOiBvYXV0aEluZm8uc3NsLFxuICAgICAgICAgICAgICAgIHRva2VuOiBvYXV0aEluZm8udG9rZW4sXG4gICAgICAgICAgICAgICAgdG9rZW5FeHBpcmVzOiBvYXV0aEluZm8uZXhwaXJlcyxcbiAgICAgICAgICAgICAgICB1c2VybmFtZTogb2F1dGhJbmZvLnVzZXJuYW1lLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIHBhcmFtcyA9IGRlY29kZVF1ZXJ5U3RyaW5nKHdpbi5sb2NhdGlvbi5oYXNoKTtcbiAgICAgICAgaWYgKCFwYXJhbXMuYWNjZXNzX3Rva2VuKSB7XG4gICAgICAgICAgICB2YXIgZXJyb3IgPSB2b2lkIDA7XG4gICAgICAgICAgICB2YXIgZXJyb3JNZXNzYWdlID0gXCJVbmtub3duIGVycm9yXCI7XG4gICAgICAgICAgICBpZiAocGFyYW1zLmVycm9yKSB7XG4gICAgICAgICAgICAgICAgZXJyb3IgPSBwYXJhbXMuZXJyb3I7XG4gICAgICAgICAgICAgICAgZXJyb3JNZXNzYWdlID0gcGFyYW1zLmVycm9yX2Rlc2NyaXB0aW9uO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIGNvbXBsZXRlU2lnbkluKHsgZXJyb3I6IGVycm9yLCBlcnJvck1lc3NhZ2U6IGVycm9yTWVzc2FnZSB9KTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgdG9rZW4gPSBwYXJhbXMuYWNjZXNzX3Rva2VuO1xuICAgICAgICB2YXIgZXhwaXJlcyA9IG5ldyBEYXRlKERhdGUubm93KCkgKyBwYXJzZUludChwYXJhbXMuZXhwaXJlc19pbiwgMTApICogMTAwMCAtIDYwICogMTAwMCk7XG4gICAgICAgIHZhciB1c2VybmFtZSA9IHBhcmFtcy51c2VybmFtZTtcbiAgICAgICAgdmFyIHNzbCA9IHBhcmFtcy5zc2wgPT09IFwidHJ1ZVwiO1xuICAgICAgICByZXR1cm4gY29tcGxldGVTaWduSW4odW5kZWZpbmVkLCB7XG4gICAgICAgICAgICB0b2tlbjogdG9rZW4sXG4gICAgICAgICAgICBleHBpcmVzOiBleHBpcmVzLFxuICAgICAgICAgICAgc3NsOiBzc2wsXG4gICAgICAgICAgICB1c2VybmFtZTogdXNlcm5hbWUsXG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogUmVxdWVzdCBzZXNzaW9uIGluZm9ybWF0aW9uIGZyb20gdGhlIHBhcmVudCBhcHBsaWNhdGlvblxuICAgICAqXG4gICAgICogV2hlbiBhbiBhcHBsaWNhdGlvbiBpcyBlbWJlZGRlZCBpbnRvIGFub3RoZXIgYXBwbGljYXRpb24gdmlhIGFuIElGcmFtZSwgdGhlIGVtYmVkZGVkIGFwcCBjYW5cbiAgICAgKiB1c2UgYHdpbmRvdy5wb3N0TWVzc2FnZWAgdG8gcmVxdWVzdCBjcmVkZW50aWFscyBmcm9tIHRoZSBob3N0IGFwcGxpY2F0aW9uLiBUaGlzIGZ1bmN0aW9uIHdyYXBzXG4gICAgICogdGhhdCBiZWhhdmlvci5cbiAgICAgKlxuICAgICAqIFRoZSBBcmNHSVMgQVBJIGZvciBKYXZhc2NyaXB0IGhhcyB0aGlzIGJ1aWx0IGludG8gdGhlIElkZW50aXR5IE1hbmFnZXIgYXMgb2YgdGhlIDQuMTkgcmVsZWFzZS5cbiAgICAgKlxuICAgICAqIE5vdGU6IFRoZSBwYXJlbnQgYXBwbGljYXRpb24gd2lsbCBub3QgcmVzcG9uZCBpZiB0aGUgZW1iZWRkZWQgYXBwJ3Mgb3JpZ2luIGlzIG5vdDpcbiAgICAgKiAtIHRoZSBzYW1lIG9yaWdpbiBhcyB0aGUgcGFyZW50IG9yICouYXJjZ2lzLmNvbSAoSlNBUEkpXG4gICAgICogLSBpbiB0aGUgbGlzdCBvZiB2YWxpZCBjaGlsZCBvcmlnaW5zIChSRVNULUpTKVxuICAgICAqXG4gICAgICpcbiAgICAgKiBAcGFyYW0gcGFyZW50T3JpZ2luIG9yaWdpbiBvZiB0aGUgcGFyZW50IGZyYW1lLiBQYXNzZWQgaW50byB0aGUgZW1iZWRkZWQgYXBwbGljYXRpb24gYXMgYHBhcmVudE9yaWdpbmAgcXVlcnkgcGFyYW1cbiAgICAgKiBAYnJvd3Nlck9ubHlcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5mcm9tUGFyZW50ID0gZnVuY3Rpb24gKHBhcmVudE9yaWdpbiwgd2luKSB7XG4gICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0OiBtdXN0IHBhc3MgaW4gYSBtb2Nrd2luZG93IGZvciB0ZXN0cyBzbyB3ZSBjYW4ndCBjb3ZlciB0aGUgb3RoZXIgYnJhbmNoICovXG4gICAgICAgIGlmICghd2luICYmIHdpbmRvdykge1xuICAgICAgICAgICAgd2luID0gd2luZG93O1xuICAgICAgICB9XG4gICAgICAgIC8vIERlY2xhcmUgaGFuZGxlciBvdXRzaWRlIG9mIHByb21pc2Ugc2NvcGUgc28gd2UgY2FuIGRldGFjaCBpdFxuICAgICAgICB2YXIgaGFuZGxlcjtcbiAgICAgICAgLy8gcmV0dXJuIGEgcHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aGVuIHRoZSBoYW5kbGVyIHJlY2VpdmVzXG4gICAgICAgIC8vIHNlc3Npb24gaW5mb3JtYXRpb24gZnJvbSB0aGUgY29ycmVjdCBvcmlnaW5cbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcbiAgICAgICAgICAgIC8vIGNyZWF0ZSBhbiBldmVudCBoYW5kbGVyIHRoYXQganVzdCB3cmFwcyB0aGUgcGFyZW50TWVzc2FnZUhhbmRsZXJcbiAgICAgICAgICAgIGhhbmRsZXIgPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgICAgICAgICAvLyBlbnN1cmUgd2Ugb25seSBsaXN0ZW4gdG8gZXZlbnRzIGZyb20gdGhlIHBhcmVudFxuICAgICAgICAgICAgICAgIGlmIChldmVudC5zb3VyY2UgPT09IHdpbi5wYXJlbnQgJiYgZXZlbnQuZGF0YSkge1xuICAgICAgICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJlc29sdmUoVXNlclNlc3Npb24ucGFyZW50TWVzc2FnZUhhbmRsZXIoZXZlbnQpKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgLy8gYWRkIGxpc3RlbmVyXG4gICAgICAgICAgICB3aW4uYWRkRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgaGFuZGxlciwgZmFsc2UpO1xuICAgICAgICAgICAgd2luLnBhcmVudC5wb3N0TWVzc2FnZSh7IHR5cGU6IFwiYXJjZ2lzOmF1dGg6cmVxdWVzdENyZWRlbnRpYWxcIiB9LCBwYXJlbnRPcmlnaW4pO1xuICAgICAgICB9KS50aGVuKGZ1bmN0aW9uIChzZXNzaW9uKSB7XG4gICAgICAgICAgICB3aW4ucmVtb3ZlRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgaGFuZGxlciwgZmFsc2UpO1xuICAgICAgICAgICAgcmV0dXJuIHNlc3Npb247XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogQmVnaW5zIGEgbmV3IHNlcnZlci1iYXNlZCBPQXV0aCAyLjAgc2lnbiBpbi4gVGhpcyB3aWxsIHJlZGlyZWN0IHRoZSB1c2VyIHRvXG4gICAgICogdGhlIEFyY0dJUyBPbmxpbmUgb3IgQXJjR0lTIEVudGVycHJpc2UgYXV0aG9yaXphdGlvbiBwYWdlLlxuICAgICAqXG4gICAgICogQG5vZGVPbmx5XG4gICAgICovXG4gICAgVXNlclNlc3Npb24uYXV0aG9yaXplID0gZnVuY3Rpb24gKG9wdGlvbnMsIHJlc3BvbnNlKSB7XG4gICAgICAgIGlmIChvcHRpb25zLmR1cmF0aW9uKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkRFUFJFQ0FURUQ6ICdkdXJhdGlvbicgaXMgZGVwcmVjYXRlZCAtIHVzZSAnZXhwaXJhdGlvbicgaW5zdGVhZFwiKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgX2EgPSBfX2Fzc2lnbih7IHBvcnRhbDogXCJodHRwczovL2FyY2dpcy5jb20vc2hhcmluZy9yZXN0XCIsIGV4cGlyYXRpb246IDIwMTYwIH0sIG9wdGlvbnMpLCBwb3J0YWwgPSBfYS5wb3J0YWwsIGNsaWVudElkID0gX2EuY2xpZW50SWQsIGV4cGlyYXRpb24gPSBfYS5leHBpcmF0aW9uLCByZWRpcmVjdFVyaSA9IF9hLnJlZGlyZWN0VXJpO1xuICAgICAgICByZXNwb25zZS53cml0ZUhlYWQoMzAxLCB7XG4gICAgICAgICAgICBMb2NhdGlvbjogcG9ydGFsICsgXCIvb2F1dGgyL2F1dGhvcml6ZT9jbGllbnRfaWQ9XCIgKyBjbGllbnRJZCArIFwiJmV4cGlyYXRpb249XCIgKyAob3B0aW9ucy5kdXJhdGlvbiB8fCBleHBpcmF0aW9uKSArIFwiJnJlc3BvbnNlX3R5cGU9Y29kZSZyZWRpcmVjdF91cmk9XCIgKyBlbmNvZGVVUklDb21wb25lbnQocmVkaXJlY3RVcmkpLFxuICAgICAgICB9KTtcbiAgICAgICAgcmVzcG9uc2UuZW5kKCk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBDb21wbGV0ZXMgdGhlIHNlcnZlci1iYXNlZCBPQXV0aCAyLjAgc2lnbiBpbiBwcm9jZXNzIGJ5IGV4Y2hhbmdpbmcgdGhlIGBhdXRob3JpemF0aW9uQ29kZWBcbiAgICAgKiBmb3IgYSBgYWNjZXNzX3Rva2VuYC5cbiAgICAgKlxuICAgICAqIEBub2RlT25seVxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLmV4Y2hhbmdlQXV0aG9yaXphdGlvbkNvZGUgPSBmdW5jdGlvbiAob3B0aW9ucywgYXV0aG9yaXphdGlvbkNvZGUpIHtcbiAgICAgICAgdmFyIF9hID0gX19hc3NpZ24oe1xuICAgICAgICAgICAgcG9ydGFsOiBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCIsXG4gICAgICAgICAgICByZWZyZXNoVG9rZW5UVEw6IDIwMTYwLFxuICAgICAgICB9LCBvcHRpb25zKSwgcG9ydGFsID0gX2EucG9ydGFsLCBjbGllbnRJZCA9IF9hLmNsaWVudElkLCByZWRpcmVjdFVyaSA9IF9hLnJlZGlyZWN0VXJpLCByZWZyZXNoVG9rZW5UVEwgPSBfYS5yZWZyZXNoVG9rZW5UVEw7XG4gICAgICAgIHJldHVybiBmZXRjaFRva2VuKHBvcnRhbCArIFwiL29hdXRoMi90b2tlblwiLCB7XG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICBncmFudF90eXBlOiBcImF1dGhvcml6YXRpb25fY29kZVwiLFxuICAgICAgICAgICAgICAgIGNsaWVudF9pZDogY2xpZW50SWQsXG4gICAgICAgICAgICAgICAgcmVkaXJlY3RfdXJpOiByZWRpcmVjdFVyaSxcbiAgICAgICAgICAgICAgICBjb2RlOiBhdXRob3JpemF0aW9uQ29kZSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICByZXR1cm4gbmV3IFVzZXJTZXNzaW9uKHtcbiAgICAgICAgICAgICAgICBjbGllbnRJZDogY2xpZW50SWQsXG4gICAgICAgICAgICAgICAgcG9ydGFsOiBwb3J0YWwsXG4gICAgICAgICAgICAgICAgc3NsOiByZXNwb25zZS5zc2wsXG4gICAgICAgICAgICAgICAgcmVkaXJlY3RVcmk6IHJlZGlyZWN0VXJpLFxuICAgICAgICAgICAgICAgIHJlZnJlc2hUb2tlbjogcmVzcG9uc2UucmVmcmVzaFRva2VuLFxuICAgICAgICAgICAgICAgIHJlZnJlc2hUb2tlblRUTDogcmVmcmVzaFRva2VuVFRMLFxuICAgICAgICAgICAgICAgIHJlZnJlc2hUb2tlbkV4cGlyZXM6IG5ldyBEYXRlKERhdGUubm93KCkgKyAocmVmcmVzaFRva2VuVFRMIC0gMSkgKiA2MCAqIDEwMDApLFxuICAgICAgICAgICAgICAgIHRva2VuOiByZXNwb25zZS50b2tlbixcbiAgICAgICAgICAgICAgICB0b2tlbkV4cGlyZXM6IHJlc3BvbnNlLmV4cGlyZXMsXG4gICAgICAgICAgICAgICAgdXNlcm5hbWU6IHJlc3BvbnNlLnVzZXJuYW1lLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgVXNlclNlc3Npb24uZGVzZXJpYWxpemUgPSBmdW5jdGlvbiAoc3RyKSB7XG4gICAgICAgIHZhciBvcHRpb25zID0gSlNPTi5wYXJzZShzdHIpO1xuICAgICAgICByZXR1cm4gbmV3IFVzZXJTZXNzaW9uKHtcbiAgICAgICAgICAgIGNsaWVudElkOiBvcHRpb25zLmNsaWVudElkLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuOiBvcHRpb25zLnJlZnJlc2hUb2tlbixcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlbkV4cGlyZXM6IG5ldyBEYXRlKG9wdGlvbnMucmVmcmVzaFRva2VuRXhwaXJlcyksXG4gICAgICAgICAgICB1c2VybmFtZTogb3B0aW9ucy51c2VybmFtZSxcbiAgICAgICAgICAgIHBhc3N3b3JkOiBvcHRpb25zLnBhc3N3b3JkLFxuICAgICAgICAgICAgdG9rZW46IG9wdGlvbnMudG9rZW4sXG4gICAgICAgICAgICB0b2tlbkV4cGlyZXM6IG5ldyBEYXRlKG9wdGlvbnMudG9rZW5FeHBpcmVzKSxcbiAgICAgICAgICAgIHBvcnRhbDogb3B0aW9ucy5wb3J0YWwsXG4gICAgICAgICAgICBzc2w6IG9wdGlvbnMuc3NsLFxuICAgICAgICAgICAgdG9rZW5EdXJhdGlvbjogb3B0aW9ucy50b2tlbkR1cmF0aW9uLFxuICAgICAgICAgICAgcmVkaXJlY3RVcmk6IG9wdGlvbnMucmVkaXJlY3RVcmksXG4gICAgICAgICAgICByZWZyZXNoVG9rZW5UVEw6IG9wdGlvbnMucmVmcmVzaFRva2VuVFRMLFxuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFRyYW5zbGF0ZXMgYXV0aGVudGljYXRpb24gZnJvbSB0aGUgZm9ybWF0IHVzZWQgaW4gdGhlIFtBcmNHSVMgQVBJIGZvciBKYXZhU2NyaXB0XShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9qYXZhc2NyaXB0LykuXG4gICAgICpcbiAgICAgKiBgYGBqc1xuICAgICAqIFVzZXJTZXNzaW9uLmZyb21DcmVkZW50aWFsKHtcbiAgICAgKiAgIHVzZXJJZDogXCJqc21pdGhcIixcbiAgICAgKiAgIHRva2VuOiBcInNlY3JldFwiXG4gICAgICogfSk7XG4gICAgICogYGBgXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyBVc2VyU2Vzc2lvblxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLmZyb21DcmVkZW50aWFsID0gZnVuY3Rpb24gKGNyZWRlbnRpYWwpIHtcbiAgICAgICAgLy8gQXQgQXJjR0lTIE9ubGluZSA5LjEsIGNyZWRlbnRpYWxzIG5vIGxvbmdlciBpbmNsdWRlIHRoZSBzc2wgYW5kIGV4cGlyZXMgcHJvcGVydGllc1xuICAgICAgICAvLyBIZXJlLCB3ZSBwcm92aWRlIGRlZmF1bHQgdmFsdWVzIGZvciB0aGVtIHRvIGNvdmVyIHRoaXMgY29uZGl0aW9uXG4gICAgICAgIHZhciBzc2wgPSB0eXBlb2YgY3JlZGVudGlhbC5zc2wgIT09IFwidW5kZWZpbmVkXCIgPyBjcmVkZW50aWFsLnNzbCA6IHRydWU7XG4gICAgICAgIHZhciBleHBpcmVzID0gY3JlZGVudGlhbC5leHBpcmVzIHx8IERhdGUubm93KCkgKyA3MjAwMDAwOyAvKiAyIGhvdXJzICovXG4gICAgICAgIHJldHVybiBuZXcgVXNlclNlc3Npb24oe1xuICAgICAgICAgICAgcG9ydGFsOiBjcmVkZW50aWFsLnNlcnZlci5pbmNsdWRlcyhcInNoYXJpbmcvcmVzdFwiKVxuICAgICAgICAgICAgICAgID8gY3JlZGVudGlhbC5zZXJ2ZXJcbiAgICAgICAgICAgICAgICA6IGNyZWRlbnRpYWwuc2VydmVyICsgXCIvc2hhcmluZy9yZXN0XCIsXG4gICAgICAgICAgICBzc2w6IHNzbCxcbiAgICAgICAgICAgIHRva2VuOiBjcmVkZW50aWFsLnRva2VuLFxuICAgICAgICAgICAgdXNlcm5hbWU6IGNyZWRlbnRpYWwudXNlcklkLFxuICAgICAgICAgICAgdG9rZW5FeHBpcmVzOiBuZXcgRGF0ZShleHBpcmVzKSxcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBIYW5kbGUgdGhlIHJlc3BvbnNlIGZyb20gdGhlIHBhcmVudFxuICAgICAqIEBwYXJhbSBldmVudCBET00gRXZlbnRcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wYXJlbnRNZXNzYWdlSGFuZGxlciA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICBpZiAoZXZlbnQuZGF0YS50eXBlID09PSBcImFyY2dpczphdXRoOmNyZWRlbnRpYWxcIikge1xuICAgICAgICAgICAgcmV0dXJuIFVzZXJTZXNzaW9uLmZyb21DcmVkZW50aWFsKGV2ZW50LmRhdGEuY3JlZGVudGlhbCk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGV2ZW50LmRhdGEudHlwZSA9PT0gXCJhcmNnaXM6YXV0aDplcnJvclwiKSB7XG4gICAgICAgICAgICB2YXIgZXJyID0gbmV3IEVycm9yKGV2ZW50LmRhdGEuZXJyb3IubWVzc2FnZSk7XG4gICAgICAgICAgICBlcnIubmFtZSA9IGV2ZW50LmRhdGEuZXJyb3IubmFtZTtcbiAgICAgICAgICAgIHRocm93IGVycjtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcIlVua25vd24gbWVzc2FnZSB0eXBlLlwiKTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgLyoqXG4gICAgICogUmV0dXJucyBhdXRoZW50aWNhdGlvbiBpbiBhIGZvcm1hdCB1c2VhYmxlIGluIHRoZSBbQXJjR0lTIEFQSSBmb3IgSmF2YVNjcmlwdF0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vamF2YXNjcmlwdC8pLlxuICAgICAqXG4gICAgICogYGBganNcbiAgICAgKiBlc3JpSWQucmVnaXN0ZXJUb2tlbihzZXNzaW9uLnRvQ3JlZGVudGlhbCgpKTtcbiAgICAgKiBgYGBcbiAgICAgKlxuICAgICAqIEByZXR1cm5zIElDcmVkZW50aWFsXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnRvQ3JlZGVudGlhbCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIGV4cGlyZXM6IHRoaXMudG9rZW5FeHBpcmVzLmdldFRpbWUoKSxcbiAgICAgICAgICAgIHNlcnZlcjogdGhpcy5wb3J0YWwsXG4gICAgICAgICAgICBzc2w6IHRoaXMuc3NsLFxuICAgICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgICB1c2VySWQ6IHRoaXMudXNlcm5hbWUsXG4gICAgICAgIH07XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIGluZm9ybWF0aW9uIGFib3V0IHRoZSBjdXJyZW50bHkgbG9nZ2VkIGluIFt1c2VyXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3VzZXJzLWdyb3Vwcy1hbmQtaXRlbXMvdXNlci5odG0pLiBTdWJzZXF1ZW50IGNhbGxzIHdpbGwgKm5vdCogcmVzdWx0IGluIGFkZGl0aW9uYWwgd2ViIHRyYWZmaWMuXG4gICAgICpcbiAgICAgKiBgYGBqc1xuICAgICAqIHNlc3Npb24uZ2V0VXNlcigpXG4gICAgICogICAudGhlbihyZXNwb25zZSA9PiB7XG4gICAgICogICAgIGNvbnNvbGUubG9nKHJlc3BvbnNlLnJvbGUpOyAvLyBcIm9yZ19hZG1pblwiXG4gICAgICogICB9KVxuICAgICAqIGBgYFxuICAgICAqXG4gICAgICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3QuIE5PVEU6IGByYXdSZXNwb25zZWAgaXMgbm90IHN1cHBvcnRlZCBieSB0aGlzIG9wZXJhdGlvbi5cbiAgICAgKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgZGF0YSBmcm9tIHRoZSByZXNwb25zZS5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0VXNlciA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBpZiAodGhpcy5fcGVuZGluZ1VzZXJSZXF1ZXN0KSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1VzZXJSZXF1ZXN0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKHRoaXMuX3VzZXIpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy5fdXNlcik7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICB2YXIgdXJsID0gdGhpcy5wb3J0YWwgKyBcIi9jb21tdW5pdHkvc2VsZlwiO1xuICAgICAgICAgICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbihfX2Fzc2lnbih7IGh0dHBNZXRob2Q6IFwiR0VUXCIsIGF1dGhlbnRpY2F0aW9uOiB0aGlzIH0sIHJlcXVlc3RPcHRpb25zKSwgeyByYXdSZXNwb25zZTogZmFsc2UgfSk7XG4gICAgICAgICAgICB0aGlzLl9wZW5kaW5nVXNlclJlcXVlc3QgPSByZXF1ZXN0KHVybCwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICBfdGhpcy5fdXNlciA9IHJlc3BvbnNlO1xuICAgICAgICAgICAgICAgIF90aGlzLl9wZW5kaW5nVXNlclJlcXVlc3QgPSBudWxsO1xuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdVc2VyUmVxdWVzdDtcbiAgICAgICAgfVxuICAgIH07XG4gICAgLyoqXG4gICAgICogUmV0dXJucyBpbmZvcm1hdGlvbiBhYm91dCB0aGUgY3VycmVudGx5IGxvZ2dlZCBpbiB1c2VyJ3MgW3BvcnRhbF0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC91c2Vycy1ncm91cHMtYW5kLWl0ZW1zL3BvcnRhbC1zZWxmLmh0bSkuIFN1YnNlcXVlbnQgY2FsbHMgd2lsbCAqbm90KiByZXN1bHQgaW4gYWRkaXRpb25hbCB3ZWIgdHJhZmZpYy5cbiAgICAgKlxuICAgICAqIGBgYGpzXG4gICAgICogc2Vzc2lvbi5nZXRQb3J0YWwoKVxuICAgICAqICAgLnRoZW4ocmVzcG9uc2UgPT4ge1xuICAgICAqICAgICBjb25zb2xlLmxvZyhwb3J0YWwubmFtZSk7IC8vIFwiQ2l0eSBvZiAuLi5cIlxuICAgICAqICAgfSlcbiAgICAgKiBgYGBcbiAgICAgKlxuICAgICAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0LiBOT1RFOiBgcmF3UmVzcG9uc2VgIGlzIG5vdCBzdXBwb3J0ZWQgYnkgdGhpcyBvcGVyYXRpb24uXG4gICAgICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIGRhdGEgZnJvbSB0aGUgcmVzcG9uc2UuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFBvcnRhbCA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBpZiAodGhpcy5fcGVuZGluZ1BvcnRhbFJlcXVlc3QpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nUG9ydGFsUmVxdWVzdDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICh0aGlzLl9wb3J0YWxJbmZvKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMuX3BvcnRhbEluZm8pO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgdmFyIHVybCA9IHRoaXMucG9ydGFsICsgXCIvcG9ydGFscy9zZWxmXCI7XG4gICAgICAgICAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKF9fYXNzaWduKHsgaHR0cE1ldGhvZDogXCJHRVRcIiwgYXV0aGVudGljYXRpb246IHRoaXMgfSwgcmVxdWVzdE9wdGlvbnMpLCB7IHJhd1Jlc3BvbnNlOiBmYWxzZSB9KTtcbiAgICAgICAgICAgIHRoaXMuX3BlbmRpbmdQb3J0YWxSZXF1ZXN0ID0gcmVxdWVzdCh1cmwsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMuX3BvcnRhbEluZm8gPSByZXNwb25zZTtcbiAgICAgICAgICAgICAgICBfdGhpcy5fcGVuZGluZ1BvcnRhbFJlcXVlc3QgPSBudWxsO1xuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdQb3J0YWxSZXF1ZXN0O1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSB1c2VybmFtZSBmb3IgdGhlIGN1cnJlbnRseSBsb2dnZWQgaW4gW3VzZXJdKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3QvdXNlcnMtZ3JvdXBzLWFuZC1pdGVtcy91c2VyLmh0bSkuIFN1YnNlcXVlbnQgY2FsbHMgd2lsbCAqbm90KiByZXN1bHQgaW4gYWRkaXRpb25hbCB3ZWIgdHJhZmZpYy4gVGhpcyBpcyBhbHNvIHVzZWQgaW50ZXJuYWxseSB3aGVuIGEgdXNlcm5hbWUgaXMgcmVxdWlyZWQgZm9yIHNvbWUgcmVxdWVzdHMgYnV0IGlzIG5vdCBwcmVzZW50IGluIHRoZSBvcHRpb25zLlxuICAgICAqXG4gICAgICogICAgKiBgYGBqc1xuICAgICAqIHNlc3Npb24uZ2V0VXNlcm5hbWUoKVxuICAgICAqICAgLnRoZW4ocmVzcG9uc2UgPT4ge1xuICAgICAqICAgICBjb25zb2xlLmxvZyhyZXNwb25zZSk7IC8vIFwiY2FzZXlfam9uZXNcIlxuICAgICAqICAgfSlcbiAgICAgKiBgYGBcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0VXNlcm5hbWUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmICh0aGlzLnVzZXJuYW1lKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMudXNlcm5hbWUpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKHRoaXMuX3VzZXIpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy5fdXNlci51c2VybmFtZSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5nZXRVc2VyKCkudGhlbihmdW5jdGlvbiAodXNlcikge1xuICAgICAgICAgICAgICAgIHJldHVybiB1c2VyLnVzZXJuYW1lO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEdldHMgYW4gYXBwcm9wcmlhdGUgdG9rZW4gZm9yIHRoZSBnaXZlbiBVUkwuIElmIGBwb3J0YWxgIGlzIEFyY0dJUyBPbmxpbmUgYW5kXG4gICAgICogdGhlIHJlcXVlc3QgaXMgdG8gYW4gQXJjR0lTIE9ubGluZSBkb21haW4gYHRva2VuYCB3aWxsIGJlIHVzZWQuIElmIHRoZSByZXF1ZXN0XG4gICAgICogaXMgdG8gdGhlIGN1cnJlbnQgYHBvcnRhbGAgdGhlIGN1cnJlbnQgYHRva2VuYCB3aWxsIGFsc28gYmUgdXNlZC4gSG93ZXZlciBpZlxuICAgICAqIHRoZSByZXF1ZXN0IGlzIHRvIGFuIHVua25vd24gc2VydmVyIHdlIHdpbGwgdmFsaWRhdGUgdGhlIHNlcnZlciB3aXRoIGEgcmVxdWVzdFxuICAgICAqIHRvIG91ciBjdXJyZW50IGBwb3J0YWxgLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRUb2tlbiA9IGZ1bmN0aW9uICh1cmwsIHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIGlmIChjYW5Vc2VPbmxpbmVUb2tlbih0aGlzLnBvcnRhbCwgdXJsKSkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuZ2V0RnJlc2hUb2tlbihyZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAobmV3IFJlZ0V4cCh0aGlzLnBvcnRhbCwgXCJpXCIpLnRlc3QodXJsKSkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuZ2V0RnJlc2hUb2tlbihyZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5nZXRUb2tlbkZvclNlcnZlcih1cmwsIHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgLyoqXG4gICAgICogR2V0IGFwcGxpY2F0aW9uIGFjY2VzcyBpbmZvcm1hdGlvbiBmb3IgdGhlIGN1cnJlbnQgdXNlclxuICAgICAqIHNlZSBgdmFsaWRhdGVBcHBBY2Nlc3NgIGZ1bmN0aW9uIGZvciBkZXRhaWxzXG4gICAgICpcbiAgICAgKiBAcGFyYW0gY2xpZW50SWQgYXBwbGljYXRpb24gY2xpZW50IGlkXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnZhbGlkYXRlQXBwQWNjZXNzID0gZnVuY3Rpb24gKGNsaWVudElkKSB7XG4gICAgICAgIHJldHVybiB0aGlzLmdldFRva2VuKHRoaXMucG9ydGFsKS50aGVuKGZ1bmN0aW9uICh0b2tlbikge1xuICAgICAgICAgICAgcmV0dXJuIHZhbGlkYXRlQXBwQWNjZXNzKHRva2VuLCBjbGllbnRJZCk7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnRvSlNPTiA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIGNsaWVudElkOiB0aGlzLmNsaWVudElkLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuOiB0aGlzLnJlZnJlc2hUb2tlbixcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlbkV4cGlyZXM6IHRoaXMucmVmcmVzaFRva2VuRXhwaXJlcyxcbiAgICAgICAgICAgIHVzZXJuYW1lOiB0aGlzLnVzZXJuYW1lLFxuICAgICAgICAgICAgcGFzc3dvcmQ6IHRoaXMucGFzc3dvcmQsXG4gICAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICAgIHRva2VuRXhwaXJlczogdGhpcy50b2tlbkV4cGlyZXMsXG4gICAgICAgICAgICBwb3J0YWw6IHRoaXMucG9ydGFsLFxuICAgICAgICAgICAgc3NsOiB0aGlzLnNzbCxcbiAgICAgICAgICAgIHRva2VuRHVyYXRpb246IHRoaXMudG9rZW5EdXJhdGlvbixcbiAgICAgICAgICAgIHJlZGlyZWN0VXJpOiB0aGlzLnJlZGlyZWN0VXJpLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuVFRMOiB0aGlzLnJlZnJlc2hUb2tlblRUTCxcbiAgICAgICAgfTtcbiAgICB9O1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5zZXJpYWxpemUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeSh0aGlzKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEZvciBhIFwiSG9zdFwiIGFwcCB0aGF0IGVtYmVkcyBvdGhlciBwbGF0Zm9ybSBhcHBzIHZpYSBpZnJhbWVzLCBhZnRlciBhdXRoZW50aWNhdGluZyB0aGUgdXNlclxuICAgICAqIGFuZCBjcmVhdGluZyBhIFVzZXJTZXNzaW9uLCB0aGUgYXBwIGNhbiB0aGVuIGVuYWJsZSBcInBvc3QgbWVzc2FnZVwiIHN0eWxlIGF1dGhlbnRpY2F0aW9uIGJ5IGNhbGxpbmdcbiAgICAgKiB0aGlzIG1ldGhvZC5cbiAgICAgKlxuICAgICAqIEludGVybmFsbHkgdGhpcyBhZGRzIGFuIGV2ZW50IGxpc3RlbmVyIG9uIHdpbmRvdyBmb3IgdGhlIGBtZXNzYWdlYCBldmVudFxuICAgICAqXG4gICAgICogQHBhcmFtIHZhbGlkQ2hpbGRPcmlnaW5zIEFycmF5IG9mIG9yaWdpbnMgdGhhdCBhcmUgYWxsb3dlZCB0byByZXF1ZXN0IGF1dGhlbnRpY2F0aW9uIGZyb20gdGhlIGhvc3QgYXBwXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmVuYWJsZVBvc3RNZXNzYWdlQXV0aCA9IGZ1bmN0aW9uICh2YWxpZENoaWxkT3JpZ2lucywgd2luKSB7XG4gICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0OiBtdXN0IHBhc3MgaW4gYSBtb2Nrd2luZG93IGZvciB0ZXN0cyBzbyB3ZSBjYW4ndCBjb3ZlciB0aGUgb3RoZXIgYnJhbmNoICovXG4gICAgICAgIGlmICghd2luICYmIHdpbmRvdykge1xuICAgICAgICAgICAgd2luID0gd2luZG93O1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX2hvc3RIYW5kbGVyID0gdGhpcy5jcmVhdGVQb3N0TWVzc2FnZUhhbmRsZXIodmFsaWRDaGlsZE9yaWdpbnMpO1xuICAgICAgICB3aW4uYWRkRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgdGhpcy5faG9zdEhhbmRsZXIsIGZhbHNlKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEZvciBhIFwiSG9zdFwiIGFwcCB0aGF0IGhhcyBlbWJlZGRlZCBvdGhlciBwbGF0Zm9ybSBhcHBzIHZpYSBpZnJhbWVzLCB3aGVuIHRoZSBob3N0IG5lZWRzXG4gICAgICogdG8gdHJhbnNpdGlvbiByb3V0ZXMsIGl0IHNob3VsZCBjYWxsIGBVc2VyU2Vzc2lvbi5kaXNhYmxlUG9zdE1lc3NhZ2VBdXRoKClgIHRvIHJlbW92ZVxuICAgICAqIHRoZSBldmVudCBsaXN0ZW5lciBhbmQgcHJldmVudCBtZW1vcnkgbGVha3NcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZGlzYWJsZVBvc3RNZXNzYWdlQXV0aCA9IGZ1bmN0aW9uICh3aW4pIHtcbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQ6IG11c3QgcGFzcyBpbiBhIG1vY2t3aW5kb3cgZm9yIHRlc3RzIHNvIHdlIGNhbid0IGNvdmVyIHRoZSBvdGhlciBicmFuY2ggKi9cbiAgICAgICAgaWYgKCF3aW4gJiYgd2luZG93KSB7XG4gICAgICAgICAgICB3aW4gPSB3aW5kb3c7XG4gICAgICAgIH1cbiAgICAgICAgd2luLnJlbW92ZUV2ZW50TGlzdGVuZXIoXCJtZXNzYWdlXCIsIHRoaXMuX2hvc3RIYW5kbGVyLCBmYWxzZSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBNYW51YWxseSByZWZyZXNoZXMgdGhlIGN1cnJlbnQgYHRva2VuYCBhbmQgYHRva2VuRXhwaXJlc2AuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnJlZnJlc2hTZXNzaW9uID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIC8vIG1ha2Ugc3VyZSBzdWJzZXF1ZW50IGNhbGxzIHRvIGdldFVzZXIoKSBkb24ndCByZXR1cm5lZCBjYWNoZWQgbWV0YWRhdGFcbiAgICAgICAgdGhpcy5fdXNlciA9IG51bGw7XG4gICAgICAgIGlmICh0aGlzLnVzZXJuYW1lICYmIHRoaXMucGFzc3dvcmQpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnJlZnJlc2hXaXRoVXNlcm5hbWVBbmRQYXNzd29yZChyZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuY2xpZW50SWQgJiYgdGhpcy5yZWZyZXNoVG9rZW4pIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnJlZnJlc2hXaXRoUmVmcmVzaFRva2VuKCk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBBcmNHSVNBdXRoRXJyb3IoXCJVbmFibGUgdG8gcmVmcmVzaCB0b2tlbi5cIikpO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogRGV0ZXJtaW5lcyB0aGUgcm9vdCBvZiB0aGUgQXJjR0lTIFNlcnZlciBvciBQb3J0YWwgZm9yIGEgZ2l2ZW4gVVJMLlxuICAgICAqXG4gICAgICogQHBhcmFtIHVybCB0aGUgVVJsIHRvIGRldGVybWluZSB0aGUgcm9vdCB1cmwgZm9yLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRTZXJ2ZXJSb290VXJsID0gZnVuY3Rpb24gKHVybCkge1xuICAgICAgICB2YXIgcm9vdCA9IGNsZWFuVXJsKHVybCkuc3BsaXQoL1xcL3Jlc3QoXFwvYWRtaW4pP1xcL3NlcnZpY2VzKD86XFwvfCN8XFw/fCQpLylbMF07XG4gICAgICAgIHZhciBfYSA9IHJvb3QubWF0Y2goLyhodHRwcz86XFwvXFwvKSguKykvKSwgbWF0Y2ggPSBfYVswXSwgcHJvdG9jb2wgPSBfYVsxXSwgZG9tYWluQW5kUGF0aCA9IF9hWzJdO1xuICAgICAgICB2YXIgX2IgPSBkb21haW5BbmRQYXRoLnNwbGl0KFwiL1wiKSwgZG9tYWluID0gX2JbMF0sIHBhdGggPSBfYi5zbGljZSgxKTtcbiAgICAgICAgLy8gb25seSB0aGUgZG9tYWluIGlzIGxvd2VyY2FzZWQgYmVjYXVzZSBpbiBzb21lIGNhc2VzIGFuIG9yZyBpZCBtaWdodCBiZVxuICAgICAgICAvLyBpbiB0aGUgcGF0aCB3aGljaCBjYW5ub3QgYmUgbG93ZXJjYXNlZC5cbiAgICAgICAgcmV0dXJuIFwiXCIgKyBwcm90b2NvbCArIGRvbWFpbi50b0xvd2VyQ2FzZSgpICsgXCIvXCIgKyBwYXRoLmpvaW4oXCIvXCIpO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgcHJvcGVyIFtgY3JlZGVudGlhbHNgXSBvcHRpb24gZm9yIGBmZXRjaGAgZm9yIGEgZ2l2ZW4gZG9tYWluLlxuICAgICAqIFNlZSBbdHJ1c3RlZCBzZXJ2ZXJdKGh0dHBzOi8vZW50ZXJwcmlzZS5hcmNnaXMuY29tL2VuL3BvcnRhbC9sYXRlc3QvYWRtaW5pc3Rlci93aW5kb3dzL2NvbmZpZ3VyZS1zZWN1cml0eS5odG0jRVNSSV9TRUNUSU9OMV83MENDMTU5QjM1NDA0NDBBQjMyNUJFNUQ4OURCRTk0QSkuXG4gICAgICogVXNlZCBpbnRlcm5hbGx5IGJ5IHVuZGVybHlpbmcgcmVxdWVzdCBtZXRob2RzIHRvIGFkZCBzdXBwb3J0IGZvciBzcGVjaWZpYyBzZWN1cml0eSBjb25zaWRlcmF0aW9ucy5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB1cmwgVGhlIHVybCBvZiB0aGUgcmVxdWVzdFxuICAgICAqIEByZXR1cm5zIFwiaW5jbHVkZVwiIG9yIFwic2FtZS1vcmlnaW5cIlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXREb21haW5DcmVkZW50aWFscyA9IGZ1bmN0aW9uICh1cmwpIHtcbiAgICAgICAgaWYgKCF0aGlzLnRydXN0ZWREb21haW5zIHx8ICF0aGlzLnRydXN0ZWREb21haW5zLmxlbmd0aCkge1xuICAgICAgICAgICAgcmV0dXJuIFwic2FtZS1vcmlnaW5cIjtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdGhpcy50cnVzdGVkRG9tYWlucy5zb21lKGZ1bmN0aW9uIChkb21haW5XaXRoUHJvdG9jb2wpIHtcbiAgICAgICAgICAgIHJldHVybiB1cmwuc3RhcnRzV2l0aChkb21haW5XaXRoUHJvdG9jb2wpO1xuICAgICAgICB9KVxuICAgICAgICAgICAgPyBcImluY2x1ZGVcIlxuICAgICAgICAgICAgOiBcInNhbWUtb3JpZ2luXCI7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm4gYSBmdW5jdGlvbiB0aGF0IGNsb3NlcyBvdmVyIHRoZSB2YWxpZE9yaWdpbnMgYXJyYXkgYW5kXG4gICAgICogY2FuIGJlIHVzZWQgYXMgYW4gZXZlbnQgaGFuZGxlciBmb3IgdGhlIGBtZXNzYWdlYCBldmVudFxuICAgICAqXG4gICAgICogQHBhcmFtIHZhbGlkT3JpZ2lucyBBcnJheSBvZiB2YWxpZCBvcmlnaW5zXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmNyZWF0ZVBvc3RNZXNzYWdlSGFuZGxlciA9IGZ1bmN0aW9uICh2YWxpZE9yaWdpbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgLy8gcmV0dXJuIGEgZnVuY3Rpb24gdGhhdCBjbG9zZXMgb3ZlciB0aGUgdmFsaWRPcmlnaW5zIGFuZFxuICAgICAgICAvLyBoYXMgYWNjZXNzIHRvIHRoZSBjcmVkZW50aWFsXG4gICAgICAgIHJldHVybiBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgICAgIC8vIFZlcmlmeSB0aGF0IHRoZSBvcmlnaW4gaXMgdmFsaWRcbiAgICAgICAgICAgIC8vIE5vdGU6IGRvIG5vdCB1c2UgcmVnZXgncyBoZXJlLiB2YWxpZE9yaWdpbnMgaXMgYW4gYXJyYXkgc28gd2UncmUgY2hlY2tpbmcgdGhhdCB0aGUgZXZlbnQncyBvcmlnaW5cbiAgICAgICAgICAgIC8vIGlzIGluIHRoZSBhcnJheSB2aWEgZXhhY3QgbWF0Y2guIE1vcmUgaW5mbyBhYm91dCBhdm9pZGluZyBwb3N0TWVzc2FnZSB4c3MgaXNzdWVzIGhlcmVcbiAgICAgICAgICAgIC8vIGh0dHBzOi8vamxhamFyYS5naXRsYWIuaW8vd2ViLzIwMjAvMDcvMTcvRG9tX1hTU19Qb3N0TWVzc2FnZV8yLmh0bWwjdGlwc2J5cGFzc2VzLWluLXBvc3RtZXNzYWdlLXZ1bG5lcmFiaWxpdGllc1xuICAgICAgICAgICAgdmFyIGlzVmFsaWRPcmlnaW4gPSB2YWxpZE9yaWdpbnMuaW5kZXhPZihldmVudC5vcmlnaW4pID4gLTE7XG4gICAgICAgICAgICAvLyBKU0FQSSBoYW5kbGVzIHRoaXMgc2xpZ2h0bHkgZGlmZmVyZW50bHkgLSBpbnN0ZWFkIG9mIGNoZWNraW5nIGEgbGlzdCwgaXQgd2lsbCByZXNwb25kIGlmXG4gICAgICAgICAgICAvLyBldmVudC5vcmlnaW4gPT09IHdpbmRvdy5sb2NhdGlvbi5vcmlnaW4gfHwgZXZlbnQub3JpZ2luLmVuZHNXaXRoKCcuYXJjZ2lzLmNvbScpXG4gICAgICAgICAgICAvLyBGb3IgSHViLCBhbmQgdG8gZW5hYmxlIGNyb3NzIGRvbWFpbiBkZWJ1Z2dpbmcgd2l0aCBwb3J0J3MgaW4gdXJscywgd2UgYXJlIG9wdGluZyB0b1xuICAgICAgICAgICAgLy8gdXNlIGEgbGlzdCBvZiB2YWxpZCBvcmlnaW5zXG4gICAgICAgICAgICAvLyBFbnN1cmUgdGhlIG1lc3NhZ2UgdHlwZSBpcyBzb21ldGhpbmcgd2Ugd2FudCB0byBoYW5kbGVcbiAgICAgICAgICAgIHZhciBpc1ZhbGlkVHlwZSA9IGV2ZW50LmRhdGEudHlwZSA9PT0gXCJhcmNnaXM6YXV0aDpyZXF1ZXN0Q3JlZGVudGlhbFwiO1xuICAgICAgICAgICAgdmFyIGlzVG9rZW5WYWxpZCA9IF90aGlzLnRva2VuRXhwaXJlcy5nZXRUaW1lKCkgPiBEYXRlLm5vdygpO1xuICAgICAgICAgICAgaWYgKGlzVmFsaWRPcmlnaW4gJiYgaXNWYWxpZFR5cGUpIHtcbiAgICAgICAgICAgICAgICB2YXIgbXNnID0ge307XG4gICAgICAgICAgICAgICAgaWYgKGlzVG9rZW5WYWxpZCkge1xuICAgICAgICAgICAgICAgICAgICB2YXIgY3JlZGVudGlhbCA9IF90aGlzLnRvQ3JlZGVudGlhbCgpO1xuICAgICAgICAgICAgICAgICAgICAvLyBhcmNnaXM6YXV0aDplcnJvciB3aXRoIHtuYW1lOiBcIlwiLCBtZXNzYWdlOiBcIlwifVxuICAgICAgICAgICAgICAgICAgICAvLyB0aGUgZm9sbG93aW5nIGxpbmUgYWxsb3dzIHVzIHRvIGNvbmZvcm0gdG8gb3VyIHNwZWMgd2l0aG91dCBjaGFuZ2luZyBvdGhlciBkZXBlbmRlZC1vbiBmdW5jdGlvbmFsaXR5XG4gICAgICAgICAgICAgICAgICAgIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9Fc3JpL2FyY2dpcy1yZXN0LWpzL2Jsb2IvbWFzdGVyL3BhY2thZ2VzL2FyY2dpcy1yZXN0LWF1dGgvcG9zdC1tZXNzYWdlLWF1dGgtc3BlYy5tZCNhcmNnaXNhdXRoY3JlZGVudGlhbFxuICAgICAgICAgICAgICAgICAgICBjcmVkZW50aWFsLnNlcnZlciA9IGNyZWRlbnRpYWwuc2VydmVyLnJlcGxhY2UoXCIvc2hhcmluZy9yZXN0XCIsIFwiXCIpO1xuICAgICAgICAgICAgICAgICAgICBtc2cgPSB7IHR5cGU6IFwiYXJjZ2lzOmF1dGg6Y3JlZGVudGlhbFwiLCBjcmVkZW50aWFsOiBjcmVkZW50aWFsIH07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAvLyBSZXR1cm4gYW4gZXJyb3JcbiAgICAgICAgICAgICAgICAgICAgbXNnID0ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdHlwZTogXCJhcmNnaXM6YXV0aDplcnJvclwiLFxuICAgICAgICAgICAgICAgICAgICAgICAgZXJyb3I6IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBuYW1lOiBcInRva2VuRXhwaXJlZEVycm9yXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbWVzc2FnZTogXCJTZXNzaW9uIHRva2VuIHdhcyBleHBpcmVkLCBhbmQgbm90IHJldHVybmVkIHRvIHRoZSBjaGlsZCBhcHBsaWNhdGlvblwiLFxuICAgICAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZXZlbnQuc291cmNlLnBvc3RNZXNzYWdlKG1zZywgZXZlbnQub3JpZ2luKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFZhbGlkYXRlcyB0aGF0IGEgZ2l2ZW4gVVJMIGlzIHByb3Blcmx5IGZlZGVyYXRlZCB3aXRoIG91ciBjdXJyZW50IGBwb3J0YWxgLlxuICAgICAqIEF0dGVtcHRzIHRvIHVzZSB0aGUgaW50ZXJuYWwgYGZlZGVyYXRlZFNlcnZlcnNgIGNhY2hlIGZpcnN0LlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRUb2tlbkZvclNlcnZlciA9IGZ1bmN0aW9uICh1cmwsIHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIC8vIHJlcXVlc3RzIHRvIC9yZXN0L3NlcnZpY2VzLyBhbmQgL3Jlc3QvYWRtaW4vc2VydmljZXMvIGFyZSBib3RoIHZhbGlkXG4gICAgICAgIC8vIEZlZGVyYXRlZCBzZXJ2ZXJzIG1heSBoYXZlIGluY29uc2lzdGVudCBjYXNpbmcsIHNvIGxvd2VyQ2FzZSBpdFxuICAgICAgICB2YXIgcm9vdCA9IHRoaXMuZ2V0U2VydmVyUm9vdFVybCh1cmwpO1xuICAgICAgICB2YXIgZXhpc3RpbmdUb2tlbiA9IHRoaXMuZmVkZXJhdGVkU2VydmVyc1tyb290XTtcbiAgICAgICAgaWYgKGV4aXN0aW5nVG9rZW4gJiZcbiAgICAgICAgICAgIGV4aXN0aW5nVG9rZW4uZXhwaXJlcyAmJlxuICAgICAgICAgICAgZXhpc3RpbmdUb2tlbi5leHBpcmVzLmdldFRpbWUoKSA+IERhdGUubm93KCkpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoZXhpc3RpbmdUb2tlbi50b2tlbik7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3Jvb3RdKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbcm9vdF07XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbcm9vdF0gPSB0aGlzLmZldGNoQXV0aG9yaXplZERvbWFpbnMoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiByZXF1ZXN0KHJvb3QgKyBcIi9yZXN0L2luZm9cIiwge1xuICAgICAgICAgICAgICAgIGNyZWRlbnRpYWxzOiBfdGhpcy5nZXREb21haW5DcmVkZW50aWFscyh1cmwpLFxuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2Uub3duaW5nU3lzdGVtVXJsKSB7XG4gICAgICAgICAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICAgICAgICAgKiBpZiB0aGlzIHNlcnZlciBpcyBub3Qgb3duZWQgYnkgdGhpcyBwb3J0YWxcbiAgICAgICAgICAgICAgICAgICAgICogYmFpbCBvdXQgd2l0aCBhbiBlcnJvciBzaW5jZSB3ZSBrbm93IHdlIHdvbnRcbiAgICAgICAgICAgICAgICAgICAgICogYmUgYWJsZSB0byBnZW5lcmF0ZSBhIHRva2VuXG4gICAgICAgICAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgICAgICAgICBpZiAoIWlzRmVkZXJhdGVkKHJlc3BvbnNlLm93bmluZ1N5c3RlbVVybCwgX3RoaXMucG9ydGFsKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEFyY0dJU0F1dGhFcnJvcih1cmwgKyBcIiBpcyBub3QgZmVkZXJhdGVkIHdpdGggXCIgKyBfdGhpcy5wb3J0YWwgKyBcIi5cIiwgXCJOT1RfRkVERVJBVEVEXCIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgICAgICAgICAgICAgKiBpZiB0aGUgc2VydmVyIGlzIGZlZGVyYXRlZCwgdXNlIHRoZSByZWxldmFudCB0b2tlbiBlbmRwb2ludC5cbiAgICAgICAgICAgICAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJlcXVlc3QocmVzcG9uc2Uub3duaW5nU3lzdGVtVXJsICsgXCIvc2hhcmluZy9yZXN0L2luZm9cIiwgcmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYgKHJlc3BvbnNlLmF1dGhJbmZvICYmXG4gICAgICAgICAgICAgICAgICAgIF90aGlzLmZlZGVyYXRlZFNlcnZlcnNbcm9vdF0gIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAgICAgICAgICogaWYgaXRzIGEgc3RhbmQtYWxvbmUgaW5zdGFuY2Ugb2YgQXJjR0lTIFNlcnZlciB0aGF0IGRvZXNuJ3QgYWR2ZXJ0aXNlXG4gICAgICAgICAgICAgICAgICAgICAqIGZlZGVyYXRpb24sIGJ1dCB0aGUgcm9vdCBzZXJ2ZXIgdXJsIGlzIHJlY29nbml6ZWQsIHVzZSBpdHMgYnVpbHQgaW4gdG9rZW4gZW5kcG9pbnQuXG4gICAgICAgICAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGF1dGhJbmZvOiByZXNwb25zZS5hdXRoSW5mbyxcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgQXJjR0lTQXV0aEVycm9yKHVybCArIFwiIGlzIG5vdCBmZWRlcmF0ZWQgd2l0aCBhbnkgcG9ydGFsIGFuZCBpcyBub3QgZXhwbGljaXRseSB0cnVzdGVkLlwiLCBcIk5PVF9GRURFUkFURURcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuYXV0aEluZm8udG9rZW5TZXJ2aWNlc1VybDtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHRva2VuU2VydmljZXNVcmwpIHtcbiAgICAgICAgICAgICAgICAvLyBhbiBleHBpcmVkIHRva2VuIGNhbnQgYmUgdXNlZCB0byBnZW5lcmF0ZSBhIG5ldyB0b2tlblxuICAgICAgICAgICAgICAgIGlmIChfdGhpcy50b2tlbiAmJiBfdGhpcy50b2tlbkV4cGlyZXMuZ2V0VGltZSgpID4gRGF0ZS5ub3coKSkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZ2VuZXJhdGVUb2tlbih0b2tlblNlcnZpY2VzVXJsLCB7XG4gICAgICAgICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlbjogX3RoaXMudG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc2VydmVyVXJsOiB1cmwsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhwaXJhdGlvbjogX3RoaXMudG9rZW5EdXJhdGlvbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjbGllbnQ6IFwicmVmZXJlclwiLFxuICAgICAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIC8vIGdlbmVyYXRlIGFuIGVudGlyZWx5IGZyZXNoIHRva2VuIGlmIG5lY2Vzc2FyeVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGdlbmVyYXRlVG9rZW4odG9rZW5TZXJ2aWNlc1VybCwge1xuICAgICAgICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdXNlcm5hbWU6IF90aGlzLnVzZXJuYW1lLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhc3N3b3JkOiBfdGhpcy5wYXNzd29yZCxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBleHBpcmF0aW9uOiBfdGhpcy50b2tlbkR1cmF0aW9uLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNsaWVudDogXCJyZWZlcmVyXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICB9KS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuX3Rva2VuID0gcmVzcG9uc2UudG9rZW47XG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5fdG9rZW5FeHBpcmVzID0gbmV3IERhdGUocmVzcG9uc2UuZXhwaXJlcyk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMuZmVkZXJhdGVkU2VydmVyc1tyb290XSA9IHtcbiAgICAgICAgICAgICAgICAgICAgZXhwaXJlczogbmV3IERhdGUocmVzcG9uc2UuZXhwaXJlcyksXG4gICAgICAgICAgICAgICAgICAgIHRva2VuOiByZXNwb25zZS50b2tlbixcbiAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICAgIGRlbGV0ZSBfdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbcm9vdF07XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLnRva2VuO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbcm9vdF07XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIGFuIHVuZXhwaXJlZCB0b2tlbiBmb3IgdGhlIGN1cnJlbnQgYHBvcnRhbGAuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldEZyZXNoVG9rZW4gPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgaWYgKHRoaXMudG9rZW4gJiYgIXRoaXMudG9rZW5FeHBpcmVzKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMudG9rZW4pO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLnRva2VuICYmXG4gICAgICAgICAgICB0aGlzLnRva2VuRXhwaXJlcyAmJlxuICAgICAgICAgICAgdGhpcy50b2tlbkV4cGlyZXMuZ2V0VGltZSgpID4gRGF0ZS5ub3coKSkge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzLnRva2VuKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3RoaXMucG9ydGFsXSkge1xuICAgICAgICAgICAgdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbdGhpcy5wb3J0YWxdID0gdGhpcy5yZWZyZXNoU2Vzc2lvbihyZXF1ZXN0T3B0aW9ucykudGhlbihmdW5jdGlvbiAoc2Vzc2lvbikge1xuICAgICAgICAgICAgICAgIF90aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tfdGhpcy5wb3J0YWxdID0gbnVsbDtcbiAgICAgICAgICAgICAgICByZXR1cm4gc2Vzc2lvbi50b2tlbjtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1t0aGlzLnBvcnRhbF07XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZWZyZXNoZXMgdGhlIGN1cnJlbnQgYHRva2VuYCBhbmQgYHRva2VuRXhwaXJlc2Agd2l0aCBgdXNlcm5hbWVgIGFuZFxuICAgICAqIGBwYXNzd29yZGAuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnJlZnJlc2hXaXRoVXNlcm5hbWVBbmRQYXNzd29yZCA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKHsgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgdXNlcm5hbWU6IHRoaXMudXNlcm5hbWUsXG4gICAgICAgICAgICAgICAgcGFzc3dvcmQ6IHRoaXMucGFzc3dvcmQsXG4gICAgICAgICAgICAgICAgZXhwaXJhdGlvbjogdGhpcy50b2tlbkR1cmF0aW9uLFxuICAgICAgICAgICAgfSB9LCByZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIHJldHVybiBnZW5lcmF0ZVRva2VuKHRoaXMucG9ydGFsICsgXCIvZ2VuZXJhdGVUb2tlblwiLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgX3RoaXMuX3Rva2VuID0gcmVzcG9uc2UudG9rZW47XG4gICAgICAgICAgICBfdGhpcy5fdG9rZW5FeHBpcmVzID0gbmV3IERhdGUocmVzcG9uc2UuZXhwaXJlcyk7XG4gICAgICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogUmVmcmVzaGVzIHRoZSBjdXJyZW50IGB0b2tlbmAgYW5kIGB0b2tlbkV4cGlyZXNgIHdpdGggYHJlZnJlc2hUb2tlbmAuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnJlZnJlc2hXaXRoUmVmcmVzaFRva2VuID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIGlmICh0aGlzLnJlZnJlc2hUb2tlbiAmJlxuICAgICAgICAgICAgdGhpcy5yZWZyZXNoVG9rZW5FeHBpcmVzICYmXG4gICAgICAgICAgICB0aGlzLnJlZnJlc2hUb2tlbkV4cGlyZXMuZ2V0VGltZSgpIDwgRGF0ZS5ub3coKSkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMucmVmcmVzaFJlZnJlc2hUb2tlbihyZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbih7IHBhcmFtczoge1xuICAgICAgICAgICAgICAgIGNsaWVudF9pZDogdGhpcy5jbGllbnRJZCxcbiAgICAgICAgICAgICAgICByZWZyZXNoX3Rva2VuOiB0aGlzLnJlZnJlc2hUb2tlbixcbiAgICAgICAgICAgICAgICBncmFudF90eXBlOiBcInJlZnJlc2hfdG9rZW5cIixcbiAgICAgICAgICAgIH0gfSwgcmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICByZXR1cm4gZmV0Y2hUb2tlbih0aGlzLnBvcnRhbCArIFwiL29hdXRoMi90b2tlblwiLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgX3RoaXMuX3Rva2VuID0gcmVzcG9uc2UudG9rZW47XG4gICAgICAgICAgICBfdGhpcy5fdG9rZW5FeHBpcmVzID0gcmVzcG9uc2UuZXhwaXJlcztcbiAgICAgICAgICAgIHJldHVybiBfdGhpcztcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBFeGNoYW5nZXMgYW4gdW5leHBpcmVkIGByZWZyZXNoVG9rZW5gIGZvciBhIG5ldyBvbmUsIGFsc28gdXBkYXRlcyBgdG9rZW5gIGFuZFxuICAgICAqIGB0b2tlbkV4cGlyZXNgLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5yZWZyZXNoUmVmcmVzaFRva2VuID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oeyBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICBjbGllbnRfaWQ6IHRoaXMuY2xpZW50SWQsXG4gICAgICAgICAgICAgICAgcmVmcmVzaF90b2tlbjogdGhpcy5yZWZyZXNoVG9rZW4sXG4gICAgICAgICAgICAgICAgcmVkaXJlY3RfdXJpOiB0aGlzLnJlZGlyZWN0VXJpLFxuICAgICAgICAgICAgICAgIGdyYW50X3R5cGU6IFwiZXhjaGFuZ2VfcmVmcmVzaF90b2tlblwiLFxuICAgICAgICAgICAgfSB9LCByZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIHJldHVybiBmZXRjaFRva2VuKHRoaXMucG9ydGFsICsgXCIvb2F1dGgyL3Rva2VuXCIsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICBfdGhpcy5fdG9rZW4gPSByZXNwb25zZS50b2tlbjtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbkV4cGlyZXMgPSByZXNwb25zZS5leHBpcmVzO1xuICAgICAgICAgICAgX3RoaXMuX3JlZnJlc2hUb2tlbiA9IHJlc3BvbnNlLnJlZnJlc2hUb2tlbjtcbiAgICAgICAgICAgIF90aGlzLl9yZWZyZXNoVG9rZW5FeHBpcmVzID0gbmV3IERhdGUoRGF0ZS5ub3coKSArIChfdGhpcy5yZWZyZXNoVG9rZW5UVEwgLSAxKSAqIDYwICogMTAwMCk7XG4gICAgICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogZW5zdXJlcyB0aGF0IHRoZSBhdXRob3JpemVkQ3Jvc3NPcmlnaW5Eb21haW5zIGFyZSBvYnRhaW5lZCBmcm9tIHRoZSBwb3J0YWwgYW5kIGNhY2hlZFxuICAgICAqIHNvIHdlIGNhbiBjaGVjayB0aGVtIGxhdGVyLlxuICAgICAqXG4gICAgICogQHJldHVybnMgdGhpc1xuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5mZXRjaEF1dGhvcml6ZWREb21haW5zID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICAvLyBpZiB0aGlzIHRva2VuIGlzIGZvciBhIHNwZWNpZmljIHNlcnZlciBvciB3ZSBkb24ndCBoYXZlIGEgcG9ydGFsXG4gICAgICAgIC8vIGRvbid0IGdldCB0aGUgcG9ydGFsIGluZm8gYmVjYXVzZSB3ZSBjYW50IGdldCB0aGUgYXV0aG9yaXplZENyb3NzT3JpZ2luRG9tYWluc1xuICAgICAgICBpZiAodGhpcy5zZXJ2ZXIgfHwgIXRoaXMucG9ydGFsKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0aGlzLmdldFBvcnRhbCgpLnRoZW4oZnVuY3Rpb24gKHBvcnRhbEluZm8pIHtcbiAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICogU3BlY2lmaWMgZG9tYWlucyBjYW4gYmUgY29uZmlndXJlZCBhcyBzZWN1cmUuZXNyaS5jb20gb3IgaHR0cHM6Ly9zZWN1cmUuZXNyaS5jb20gdGhpc1xuICAgICAgICAgICAgICogbm9ybWFsaXplcyB0byBodHRwczovL3NlY3VyZS5lc3JpLmNvbSBzbyB3ZSBjYW4gdXNlIHN0YXJ0c1dpdGggbGF0ZXIuXG4gICAgICAgICAgICAgKi9cbiAgICAgICAgICAgIGlmIChwb3J0YWxJbmZvLmF1dGhvcml6ZWRDcm9zc09yaWdpbkRvbWFpbnMgJiZcbiAgICAgICAgICAgICAgICBwb3J0YWxJbmZvLmF1dGhvcml6ZWRDcm9zc09yaWdpbkRvbWFpbnMubGVuZ3RoKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMudHJ1c3RlZERvbWFpbnMgPSBwb3J0YWxJbmZvLmF1dGhvcml6ZWRDcm9zc09yaWdpbkRvbWFpbnNcbiAgICAgICAgICAgICAgICAgICAgLmZpbHRlcihmdW5jdGlvbiAoZCkgeyByZXR1cm4gIWQuc3RhcnRzV2l0aChcImh0dHA6Ly9cIik7IH0pXG4gICAgICAgICAgICAgICAgICAgIC5tYXAoZnVuY3Rpb24gKGQpIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGQuc3RhcnRzV2l0aChcImh0dHBzOi8vXCIpKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImh0dHBzOi8vXCIgKyBkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgcmV0dXJuIFVzZXJTZXNzaW9uO1xufSgpKTtcbmV4cG9ydCB7IFVzZXJTZXNzaW9uIH07XG4vLyMgc291cmNlTWFwcGluZ1VSTD1Vc2VyU2Vzc2lvbi5qcy5tYXAiLCJpbXBvcnQgeyBjbGVhblVybCB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqIFVzZWQgdG8gdGVzdCBpZiBhIFVSTCBpcyBhbiBBcmNHSVMgT25saW5lIFVSTFxuICovXG52YXIgYXJjZ2lzT25saW5lVXJsUmVnZXggPSAvXmh0dHBzPzpcXC9cXC8oXFxTKylcXC5hcmNnaXNcXC5jb20uKy87XG4vKipcbiAqIFVzZWQgdG8gdGVzdCBpZiBhIFVSTCBpcyBwcm9kdWN0aW9uIEFyY0dJUyBPbmxpbmUgUG9ydGFsXG4gKi9cbnZhciBhcmNnaXNPbmxpbmVQb3J0YWxSZWdleCA9IC9eaHR0cHM/OlxcL1xcLyhkZXZ8ZGV2ZXh0fHFhfHFhZXh0fHd3dylcXC5hcmNnaXNcXC5jb21cXC9zaGFyaW5nXFwvcmVzdCsvO1xuLyoqXG4gKiBVc2VkIHRvIHRlc3QgaWYgYSBVUkwgaXMgYW4gQXJjR0lTIE9ubGluZSBPcmdhbml6YXRpb24gUG9ydGFsXG4gKi9cbnZhciBhcmNnaXNPbmxpbmVPcmdQb3J0YWxSZWdleCA9IC9eaHR0cHM/OlxcL1xcLyg/OlthLXowLTktXStcXC5tYXBzKGRldnxkZXZleHR8cWF8cWFleHQpPyk/LmFyY2dpc1xcLmNvbVxcL3NoYXJpbmdcXC9yZXN0LztcbmV4cG9ydCBmdW5jdGlvbiBpc09ubGluZSh1cmwpIHtcbiAgICByZXR1cm4gYXJjZ2lzT25saW5lVXJsUmVnZXgudGVzdCh1cmwpO1xufVxuZXhwb3J0IGZ1bmN0aW9uIG5vcm1hbGl6ZU9ubGluZVBvcnRhbFVybChwb3J0YWxVcmwpIHtcbiAgICBpZiAoIWFyY2dpc09ubGluZVVybFJlZ2V4LnRlc3QocG9ydGFsVXJsKSkge1xuICAgICAgICByZXR1cm4gcG9ydGFsVXJsO1xuICAgIH1cbiAgICBzd2l0Y2ggKGdldE9ubGluZUVudmlyb25tZW50KHBvcnRhbFVybCkpIHtcbiAgICAgICAgY2FzZSBcImRldlwiOlxuICAgICAgICAgICAgcmV0dXJuIFwiaHR0cHM6Ly9kZXZleHQuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIjtcbiAgICAgICAgY2FzZSBcInFhXCI6XG4gICAgICAgICAgICByZXR1cm4gXCJodHRwczovL3FhZXh0LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCI7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICByZXR1cm4gXCJodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiO1xuICAgIH1cbn1cbmV4cG9ydCBmdW5jdGlvbiBnZXRPbmxpbmVFbnZpcm9ubWVudCh1cmwpIHtcbiAgICBpZiAoIWFyY2dpc09ubGluZVVybFJlZ2V4LnRlc3QodXJsKSkge1xuICAgICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG4gICAgdmFyIG1hdGNoID0gdXJsLm1hdGNoKGFyY2dpc09ubGluZVVybFJlZ2V4KTtcbiAgICB2YXIgc3ViZG9tYWluID0gbWF0Y2hbMV0uc3BsaXQoXCIuXCIpLnBvcCgpO1xuICAgIGlmIChzdWJkb21haW4uaW5jbHVkZXMoXCJkZXZcIikpIHtcbiAgICAgICAgcmV0dXJuIFwiZGV2XCI7XG4gICAgfVxuICAgIGlmIChzdWJkb21haW4uaW5jbHVkZXMoXCJxYVwiKSkge1xuICAgICAgICByZXR1cm4gXCJxYVwiO1xuICAgIH1cbiAgICByZXR1cm4gXCJwcm9kdWN0aW9uXCI7XG59XG5leHBvcnQgZnVuY3Rpb24gaXNGZWRlcmF0ZWQob3duaW5nU3lzdGVtVXJsLCBwb3J0YWxVcmwpIHtcbiAgICB2YXIgbm9ybWFsaXplZFBvcnRhbFVybCA9IGNsZWFuVXJsKG5vcm1hbGl6ZU9ubGluZVBvcnRhbFVybChwb3J0YWxVcmwpKS5yZXBsYWNlKC9odHRwcz86XFwvXFwvLywgXCJcIik7XG4gICAgdmFyIG5vcm1hbGl6ZWRPd25pbmdTeXN0ZW1VcmwgPSBjbGVhblVybChvd25pbmdTeXN0ZW1VcmwpLnJlcGxhY2UoL2h0dHBzPzpcXC9cXC8vLCBcIlwiKTtcbiAgICByZXR1cm4gbmV3IFJlZ0V4cChub3JtYWxpemVkT3duaW5nU3lzdGVtVXJsLCBcImlcIikudGVzdChub3JtYWxpemVkUG9ydGFsVXJsKTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBjYW5Vc2VPbmxpbmVUb2tlbihwb3J0YWxVcmwsIHJlcXVlc3RVcmwpIHtcbiAgICB2YXIgcG9ydGFsSXNPbmxpbmUgPSBpc09ubGluZShwb3J0YWxVcmwpO1xuICAgIHZhciByZXF1ZXN0SXNPbmxpbmUgPSBpc09ubGluZShyZXF1ZXN0VXJsKTtcbiAgICB2YXIgcG9ydGFsRW52ID0gZ2V0T25saW5lRW52aXJvbm1lbnQocG9ydGFsVXJsKTtcbiAgICB2YXIgcmVxdWVzdEVudiA9IGdldE9ubGluZUVudmlyb25tZW50KHJlcXVlc3RVcmwpO1xuICAgIGlmIChwb3J0YWxJc09ubGluZSAmJiByZXF1ZXN0SXNPbmxpbmUgJiYgcG9ydGFsRW52ID09PSByZXF1ZXN0RW52KSB7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cbiAgICByZXR1cm4gZmFsc2U7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1mZWRlcmF0aW9uLXV0aWxzLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyByZXF1ZXN0IH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbmV4cG9ydCBmdW5jdGlvbiBmZXRjaFRva2VuKHVybCwgcmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgb3B0aW9ucyA9IHJlcXVlc3RPcHRpb25zO1xuICAgIC8vIHdlIGdlbmVyYXRlIGEgcmVzcG9uc2UsIHNvIHdlIGNhbid0IHJldHVybiB0aGUgcmF3IHJlc3BvbnNlXG4gICAgb3B0aW9ucy5yYXdSZXNwb25zZSA9IGZhbHNlO1xuICAgIHJldHVybiByZXF1ZXN0KHVybCwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdmFyIHIgPSB7XG4gICAgICAgICAgICB0b2tlbjogcmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxuICAgICAgICAgICAgdXNlcm5hbWU6IHJlc3BvbnNlLnVzZXJuYW1lLFxuICAgICAgICAgICAgZXhwaXJlczogbmV3IERhdGUoXG4gICAgICAgICAgICAvLyBjb252ZXJ0IHNlY29uZHMgaW4gcmVzcG9uc2UgdG8gbWlsbGlzZWNvbmRzIGFuZCBhZGQgdGhlIHZhbHVlIHRvIHRoZSBjdXJyZW50IHRpbWUgdG8gY2FsY3VsYXRlIGEgc3RhdGljIGV4cGlyYXRpb24gdGltZXN0YW1wXG4gICAgICAgICAgICBEYXRlLm5vdygpICsgKHJlc3BvbnNlLmV4cGlyZXNfaW4gKiAxMDAwIC0gMTAwMCkpLFxuICAgICAgICAgICAgc3NsOiByZXNwb25zZS5zc2wgPT09IHRydWVcbiAgICAgICAgfTtcbiAgICAgICAgaWYgKHJlc3BvbnNlLnJlZnJlc2hfdG9rZW4pIHtcbiAgICAgICAgICAgIHIucmVmcmVzaFRva2VuID0gcmVzcG9uc2UucmVmcmVzaF90b2tlbjtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcjtcbiAgICB9KTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWZldGNoLXRva2VuLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IHJlcXVlc3QsIE5PREVKU19ERUZBVUxUX1JFRkVSRVJfSEVBREVSLCB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG5leHBvcnQgZnVuY3Rpb24gZ2VuZXJhdGVUb2tlbih1cmwsIHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIG9wdGlvbnMgPSByZXF1ZXN0T3B0aW9ucztcbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgZWxzZSAqL1xuICAgIGlmICh0eXBlb2Ygd2luZG93ICE9PSBcInVuZGVmaW5lZFwiICYmXG4gICAgICAgIHdpbmRvdy5sb2NhdGlvbiAmJlxuICAgICAgICB3aW5kb3cubG9jYXRpb24uaG9zdCkge1xuICAgICAgICBvcHRpb25zLnBhcmFtcy5yZWZlcmVyID0gd2luZG93LmxvY2F0aW9uLmhvc3Q7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBvcHRpb25zLnBhcmFtcy5yZWZlcmVyID0gTk9ERUpTX0RFRkFVTFRfUkVGRVJFUl9IRUFERVI7XG4gICAgfVxuICAgIHJldHVybiByZXF1ZXN0KHVybCwgb3B0aW9ucyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1nZW5lcmF0ZS10b2tlbi5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTgtMjAyMCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyByZXF1ZXN0IH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICogVmFsaWRhdGVzIHRoYXQgdGhlIHVzZXIgaGFzIGFjY2VzcyB0byB0aGUgYXBwbGljYXRpb25cbiAqIGFuZCBpZiB0aGV5IHVzZXIgc2hvdWxkIGJlIHByZXNlbnRlZCBhIFwiVmlldyBPbmx5XCIgbW9kZVxuICpcbiAqIFRoaXMgaXMgb25seSBuZWVkZWQvdmFsaWQgZm9yIEVzcmkgYXBwbGljYXRpb25zIHRoYXQgYXJlIFwibGljZW5zZWRcIlxuICogYW5kIHNoaXBwZWQgaW4gQXJjR0lTIE9ubGluZSBvciBBcmNHSVMgRW50ZXJwcmlzZS4gTW9zdCBjdXN0b20gYXBwbGljYXRpb25zXG4gKiBzaG91bGQgbm90IG5lZWQgb3IgdXNlIHRoaXMuXG4gKlxuICogYGBganNcbiAqIGltcG9ydCB7IHZhbGlkYXRlQXBwQWNjZXNzIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aCc7XG4gKlxuICogcmV0dXJuIHZhbGlkYXRlQXBwQWNjZXNzKCd5b3VyLXRva2VuJywgJ3RoZUNsaWVudElkJylcbiAqIC50aGVuKChyZXN1bHQpID0+IHtcbiAqICAgIGlmICghcmVzdWx0LnZhbHVlKSB7XG4gKiAgICAgIC8vIHJlZGlyZWN0IG9yIHNob3cgc29tZSBvdGhlciB1aVxuICogICAgfSBlbHNlIHtcbiAqICAgICAgaWYgKHJlc3VsdC52aWV3T25seVVzZXJUeXBlQXBwKSB7XG4gKiAgICAgICAgLy8gdXNlIHRoaXMgdG8gaW5mb3JtIHlvdXIgYXBwIHRvIHNob3cgYSBcIlZpZXcgT25seVwiIG1vZGVcbiAqICAgICAgfVxuICogICAgfVxuICogfSlcbiAqIC5jYXRjaCgoZXJyKSA9PiB7XG4gKiAgLy8gdHdvIHBvc3NpYmxlIGVycm9yc1xuICogIC8vIGludmFsaWQgY2xpZW50SWQ6IHtcImVycm9yXCI6e1wiY29kZVwiOjQwMCxcIm1lc3NhZ2VDb2RlXCI6XCJHV01fMDAwN1wiLFwibWVzc2FnZVwiOlwiSW52YWxpZCByZXF1ZXN0XCIsXCJkZXRhaWxzXCI6W119fVxuICogIC8vIGludmFsaWQgdG9rZW46IHtcImVycm9yXCI6e1wiY29kZVwiOjQ5OCxcIm1lc3NhZ2VcIjpcIkludmFsaWQgdG9rZW4uXCIsXCJkZXRhaWxzXCI6W119fVxuICogfSlcbiAqIGBgYFxuICpcbiAqIE5vdGU6IFRoaXMgaXMgb25seSB1c2FibGUgYnkgRXNyaSBhcHBsaWNhdGlvbnMgaG9zdGVkIG9uICphcmNnaXMuY29tLCAqZXNyaS5jb20gb3Igd2l0aGluXG4gKiBhbiBBcmNHSVMgRW50ZXJwcmlzZSBpbnN0YWxsYXRpb24uIEN1c3RvbSBhcHBsaWNhdGlvbnMgY2FuIG5vdCB1c2UgdGhpcy5cbiAqXG4gKiBAcGFyYW0gdG9rZW4gcGxhdGZvcm0gdG9rZW5cbiAqIEBwYXJhbSBjbGllbnRJZCBhcHBsaWNhdGlvbiBjbGllbnQgaWRcbiAqIEBwYXJhbSBwb3J0YWwgT3B0aW9uYWxcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHZhbGlkYXRlQXBwQWNjZXNzKHRva2VuLCBjbGllbnRJZCwgcG9ydGFsKSB7XG4gICAgaWYgKHBvcnRhbCA9PT0gdm9pZCAwKSB7IHBvcnRhbCA9IFwiaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIjsgfVxuICAgIHZhciB1cmwgPSBwb3J0YWwgKyBcIi9vYXV0aDIvdmFsaWRhdGVBcHBBY2Nlc3NcIjtcbiAgICB2YXIgcm8gPSB7XG4gICAgICAgIG1ldGhvZDogXCJQT1NUXCIsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgZjogXCJqc29uXCIsXG4gICAgICAgICAgICBjbGllbnRfaWQ6IGNsaWVudElkLFxuICAgICAgICAgICAgdG9rZW46IHRva2VuLFxuICAgICAgICB9LFxuICAgIH07XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBybyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD12YWxpZGF0ZS1hcHAtYWNjZXNzLmpzLm1hcCIsIi8qISAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxyXG5Db3B5cmlnaHQgKGMpIE1pY3Jvc29mdCBDb3Jwb3JhdGlvbi5cclxuXHJcblBlcm1pc3Npb24gdG8gdXNlLCBjb3B5LCBtb2RpZnksIGFuZC9vciBkaXN0cmlidXRlIHRoaXMgc29mdHdhcmUgZm9yIGFueVxyXG5wdXJwb3NlIHdpdGggb3Igd2l0aG91dCBmZWUgaXMgaGVyZWJ5IGdyYW50ZWQuXHJcblxyXG5USEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiIEFORCBUSEUgQVVUSE9SIERJU0NMQUlNUyBBTEwgV0FSUkFOVElFUyBXSVRIXHJcblJFR0FSRCBUTyBUSElTIFNPRlRXQVJFIElOQ0xVRElORyBBTEwgSU1QTElFRCBXQVJSQU5USUVTIE9GIE1FUkNIQU5UQUJJTElUWVxyXG5BTkQgRklUTkVTUy4gSU4gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUiBCRSBMSUFCTEUgRk9SIEFOWSBTUEVDSUFMLCBESVJFQ1QsXHJcbklORElSRUNULCBPUiBDT05TRVFVRU5USUFMIERBTUFHRVMgT1IgQU5ZIERBTUFHRVMgV0hBVFNPRVZFUiBSRVNVTFRJTkcgRlJPTVxyXG5MT1NTIE9GIFVTRSwgREFUQSBPUiBQUk9GSVRTLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgTkVHTElHRU5DRSBPUlxyXG5PVEhFUiBUT1JUSU9VUyBBQ1RJT04sIEFSSVNJTkcgT1VUIE9GIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgVVNFIE9SXHJcblBFUkZPUk1BTkNFIE9GIFRISVMgU09GVFdBUkUuXHJcbioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqICovXHJcbi8qIGdsb2JhbCBSZWZsZWN0LCBQcm9taXNlICovXHJcblxyXG52YXIgZXh0ZW5kU3RhdGljcyA9IGZ1bmN0aW9uKGQsIGIpIHtcclxuICAgIGV4dGVuZFN0YXRpY3MgPSBPYmplY3Quc2V0UHJvdG90eXBlT2YgfHxcclxuICAgICAgICAoeyBfX3Byb3RvX186IFtdIH0gaW5zdGFuY2VvZiBBcnJheSAmJiBmdW5jdGlvbiAoZCwgYikgeyBkLl9fcHJvdG9fXyA9IGI7IH0pIHx8XHJcbiAgICAgICAgZnVuY3Rpb24gKGQsIGIpIHsgZm9yICh2YXIgcCBpbiBiKSBpZiAoYi5oYXNPd25Qcm9wZXJ0eShwKSkgZFtwXSA9IGJbcF07IH07XHJcbiAgICByZXR1cm4gZXh0ZW5kU3RhdGljcyhkLCBiKTtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2V4dGVuZHMoZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyhkLCBiKTtcclxuICAgIGZ1bmN0aW9uIF9fKCkgeyB0aGlzLmNvbnN0cnVjdG9yID0gZDsgfVxyXG4gICAgZC5wcm90b3R5cGUgPSBiID09PSBudWxsID8gT2JqZWN0LmNyZWF0ZShiKSA6IChfXy5wcm90b3R5cGUgPSBiLnByb3RvdHlwZSwgbmV3IF9fKCkpO1xyXG59XHJcblxyXG5leHBvcnQgdmFyIF9fYXNzaWduID0gZnVuY3Rpb24oKSB7XHJcbiAgICBfX2Fzc2lnbiA9IE9iamVjdC5hc3NpZ24gfHwgZnVuY3Rpb24gX19hc3NpZ24odCkge1xyXG4gICAgICAgIGZvciAodmFyIHMsIGkgPSAxLCBuID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IG47IGkrKykge1xyXG4gICAgICAgICAgICBzID0gYXJndW1lbnRzW2ldO1xyXG4gICAgICAgICAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkpIHRbcF0gPSBzW3BdO1xyXG4gICAgICAgIH1cclxuICAgICAgICByZXR1cm4gdDtcclxuICAgIH1cclxuICAgIHJldHVybiBfX2Fzc2lnbi5hcHBseSh0aGlzLCBhcmd1bWVudHMpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19yZXN0KHMsIGUpIHtcclxuICAgIHZhciB0ID0ge307XHJcbiAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkgJiYgZS5pbmRleE9mKHApIDwgMClcclxuICAgICAgICB0W3BdID0gc1twXTtcclxuICAgIGlmIChzICE9IG51bGwgJiYgdHlwZW9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHMgPT09IFwiZnVuY3Rpb25cIilcclxuICAgICAgICBmb3IgKHZhciBpID0gMCwgcCA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHMocyk7IGkgPCBwLmxlbmd0aDsgaSsrKSB7XHJcbiAgICAgICAgICAgIGlmIChlLmluZGV4T2YocFtpXSkgPCAwICYmIE9iamVjdC5wcm90b3R5cGUucHJvcGVydHlJc0VudW1lcmFibGUuY2FsbChzLCBwW2ldKSlcclxuICAgICAgICAgICAgICAgIHRbcFtpXV0gPSBzW3BbaV1dO1xyXG4gICAgICAgIH1cclxuICAgIHJldHVybiB0O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19kZWNvcmF0ZShkZWNvcmF0b3JzLCB0YXJnZXQsIGtleSwgZGVzYykge1xyXG4gICAgdmFyIGMgPSBhcmd1bWVudHMubGVuZ3RoLCByID0gYyA8IDMgPyB0YXJnZXQgOiBkZXNjID09PSBudWxsID8gZGVzYyA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IodGFyZ2V0LCBrZXkpIDogZGVzYywgZDtcclxuICAgIGlmICh0eXBlb2YgUmVmbGVjdCA9PT0gXCJvYmplY3RcIiAmJiB0eXBlb2YgUmVmbGVjdC5kZWNvcmF0ZSA9PT0gXCJmdW5jdGlvblwiKSByID0gUmVmbGVjdC5kZWNvcmF0ZShkZWNvcmF0b3JzLCB0YXJnZXQsIGtleSwgZGVzYyk7XHJcbiAgICBlbHNlIGZvciAodmFyIGkgPSBkZWNvcmF0b3JzLmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSBpZiAoZCA9IGRlY29yYXRvcnNbaV0pIHIgPSAoYyA8IDMgPyBkKHIpIDogYyA+IDMgPyBkKHRhcmdldCwga2V5LCByKSA6IGQodGFyZ2V0LCBrZXkpKSB8fCByO1xyXG4gICAgcmV0dXJuIGMgPiAzICYmIHIgJiYgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRhcmdldCwga2V5LCByKSwgcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcGFyYW0ocGFyYW1JbmRleCwgZGVjb3JhdG9yKSB7XHJcbiAgICByZXR1cm4gZnVuY3Rpb24gKHRhcmdldCwga2V5KSB7IGRlY29yYXRvcih0YXJnZXQsIGtleSwgcGFyYW1JbmRleCk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fbWV0YWRhdGEobWV0YWRhdGFLZXksIG1ldGFkYXRhVmFsdWUpIHtcclxuICAgIGlmICh0eXBlb2YgUmVmbGVjdCA9PT0gXCJvYmplY3RcIiAmJiB0eXBlb2YgUmVmbGVjdC5tZXRhZGF0YSA9PT0gXCJmdW5jdGlvblwiKSByZXR1cm4gUmVmbGVjdC5tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2F3YWl0ZXIodGhpc0FyZywgX2FyZ3VtZW50cywgUCwgZ2VuZXJhdG9yKSB7XHJcbiAgICBmdW5jdGlvbiBhZG9wdCh2YWx1ZSkgeyByZXR1cm4gdmFsdWUgaW5zdGFuY2VvZiBQID8gdmFsdWUgOiBuZXcgUChmdW5jdGlvbiAocmVzb2x2ZSkgeyByZXNvbHZlKHZhbHVlKTsgfSk7IH1cclxuICAgIHJldHVybiBuZXcgKFAgfHwgKFAgPSBQcm9taXNlKSkoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xyXG4gICAgICAgIGZ1bmN0aW9uIGZ1bGZpbGxlZCh2YWx1ZSkgeyB0cnkgeyBzdGVwKGdlbmVyYXRvci5uZXh0KHZhbHVlKSk7IH0gY2F0Y2ggKGUpIHsgcmVqZWN0KGUpOyB9IH1cclxuICAgICAgICBmdW5jdGlvbiByZWplY3RlZCh2YWx1ZSkgeyB0cnkgeyBzdGVwKGdlbmVyYXRvcltcInRocm93XCJdKHZhbHVlKSk7IH0gY2F0Y2ggKGUpIHsgcmVqZWN0KGUpOyB9IH1cclxuICAgICAgICBmdW5jdGlvbiBzdGVwKHJlc3VsdCkgeyByZXN1bHQuZG9uZSA/IHJlc29sdmUocmVzdWx0LnZhbHVlKSA6IGFkb3B0KHJlc3VsdC52YWx1ZSkudGhlbihmdWxmaWxsZWQsIHJlamVjdGVkKTsgfVxyXG4gICAgICAgIHN0ZXAoKGdlbmVyYXRvciA9IGdlbmVyYXRvci5hcHBseSh0aGlzQXJnLCBfYXJndW1lbnRzIHx8IFtdKSkubmV4dCgpKTtcclxuICAgIH0pO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19nZW5lcmF0b3IodGhpc0FyZywgYm9keSkge1xyXG4gICAgdmFyIF8gPSB7IGxhYmVsOiAwLCBzZW50OiBmdW5jdGlvbigpIHsgaWYgKHRbMF0gJiAxKSB0aHJvdyB0WzFdOyByZXR1cm4gdFsxXTsgfSwgdHJ5czogW10sIG9wczogW10gfSwgZiwgeSwgdCwgZztcclxuICAgIHJldHVybiBnID0geyBuZXh0OiB2ZXJiKDApLCBcInRocm93XCI6IHZlcmIoMSksIFwicmV0dXJuXCI6IHZlcmIoMikgfSwgdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIChnW1N5bWJvbC5pdGVyYXRvcl0gPSBmdW5jdGlvbigpIHsgcmV0dXJuIHRoaXM7IH0pLCBnO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IHJldHVybiBmdW5jdGlvbiAodikgeyByZXR1cm4gc3RlcChbbiwgdl0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzdGVwKG9wKSB7XHJcbiAgICAgICAgaWYgKGYpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJHZW5lcmF0b3IgaXMgYWxyZWFkeSBleGVjdXRpbmcuXCIpO1xyXG4gICAgICAgIHdoaWxlIChfKSB0cnkge1xyXG4gICAgICAgICAgICBpZiAoZiA9IDEsIHkgJiYgKHQgPSBvcFswXSAmIDIgPyB5W1wicmV0dXJuXCJdIDogb3BbMF0gPyB5W1widGhyb3dcIl0gfHwgKCh0ID0geVtcInJldHVyblwiXSkgJiYgdC5jYWxsKHkpLCAwKSA6IHkubmV4dCkgJiYgISh0ID0gdC5jYWxsKHksIG9wWzFdKSkuZG9uZSkgcmV0dXJuIHQ7XHJcbiAgICAgICAgICAgIGlmICh5ID0gMCwgdCkgb3AgPSBbb3BbMF0gJiAyLCB0LnZhbHVlXTtcclxuICAgICAgICAgICAgc3dpdGNoIChvcFswXSkge1xyXG4gICAgICAgICAgICAgICAgY2FzZSAwOiBjYXNlIDE6IHQgPSBvcDsgYnJlYWs7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDQ6IF8ubGFiZWwrKzsgcmV0dXJuIHsgdmFsdWU6IG9wWzFdLCBkb25lOiBmYWxzZSB9O1xyXG4gICAgICAgICAgICAgICAgY2FzZSA1OiBfLmxhYmVsKys7IHkgPSBvcFsxXTsgb3AgPSBbMF07IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICAgICAgY2FzZSA3OiBvcCA9IF8ub3BzLnBvcCgpOyBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgICAgICAgICAgICBpZiAoISh0ID0gXy50cnlzLCB0ID0gdC5sZW5ndGggPiAwICYmIHRbdC5sZW5ndGggLSAxXSkgJiYgKG9wWzBdID09PSA2IHx8IG9wWzBdID09PSAyKSkgeyBfID0gMDsgY29udGludWU7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAob3BbMF0gPT09IDMgJiYgKCF0IHx8IChvcFsxXSA+IHRbMF0gJiYgb3BbMV0gPCB0WzNdKSkpIHsgXy5sYWJlbCA9IG9wWzFdOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gNiAmJiBfLmxhYmVsIDwgdFsxXSkgeyBfLmxhYmVsID0gdFsxXTsgdCA9IG9wOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0ICYmIF8ubGFiZWwgPCB0WzJdKSB7IF8ubGFiZWwgPSB0WzJdOyBfLm9wcy5wdXNoKG9wKTsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAodFsyXSkgXy5vcHMucG9wKCk7XHJcbiAgICAgICAgICAgICAgICAgICAgXy50cnlzLnBvcCgpOyBjb250aW51ZTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBvcCA9IGJvZHkuY2FsbCh0aGlzQXJnLCBfKTtcclxuICAgICAgICB9IGNhdGNoIChlKSB7IG9wID0gWzYsIGVdOyB5ID0gMDsgfSBmaW5hbGx5IHsgZiA9IHQgPSAwOyB9XHJcbiAgICAgICAgaWYgKG9wWzBdICYgNSkgdGhyb3cgb3BbMV07IHJldHVybiB7IHZhbHVlOiBvcFswXSA/IG9wWzFdIDogdm9pZCAwLCBkb25lOiB0cnVlIH07XHJcbiAgICB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NyZWF0ZUJpbmRpbmcobywgbSwgaywgazIpIHtcclxuICAgIGlmIChrMiA9PT0gdW5kZWZpbmVkKSBrMiA9IGs7XHJcbiAgICBvW2syXSA9IG1ba107XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2V4cG9ydFN0YXIobSwgZXhwb3J0cykge1xyXG4gICAgZm9yICh2YXIgcCBpbiBtKSBpZiAocCAhPT0gXCJkZWZhdWx0XCIgJiYgIWV4cG9ydHMuaGFzT3duUHJvcGVydHkocCkpIGV4cG9ydHNbcF0gPSBtW3BdO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX192YWx1ZXMobykge1xyXG4gICAgdmFyIHMgPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgU3ltYm9sLml0ZXJhdG9yLCBtID0gcyAmJiBvW3NdLCBpID0gMDtcclxuICAgIGlmIChtKSByZXR1cm4gbS5jYWxsKG8pO1xyXG4gICAgaWYgKG8gJiYgdHlwZW9mIG8ubGVuZ3RoID09PSBcIm51bWJlclwiKSByZXR1cm4ge1xyXG4gICAgICAgIG5leHQ6IGZ1bmN0aW9uICgpIHtcclxuICAgICAgICAgICAgaWYgKG8gJiYgaSA+PSBvLmxlbmd0aCkgbyA9IHZvaWQgMDtcclxuICAgICAgICAgICAgcmV0dXJuIHsgdmFsdWU6IG8gJiYgb1tpKytdLCBkb25lOiAhbyB9O1xyXG4gICAgICAgIH1cclxuICAgIH07XHJcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKHMgPyBcIk9iamVjdCBpcyBub3QgaXRlcmFibGUuXCIgOiBcIlN5bWJvbC5pdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3JlYWQobywgbikge1xyXG4gICAgdmFyIG0gPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgb1tTeW1ib2wuaXRlcmF0b3JdO1xyXG4gICAgaWYgKCFtKSByZXR1cm4gbztcclxuICAgIHZhciBpID0gbS5jYWxsKG8pLCByLCBhciA9IFtdLCBlO1xyXG4gICAgdHJ5IHtcclxuICAgICAgICB3aGlsZSAoKG4gPT09IHZvaWQgMCB8fCBuLS0gPiAwKSAmJiAhKHIgPSBpLm5leHQoKSkuZG9uZSkgYXIucHVzaChyLnZhbHVlKTtcclxuICAgIH1cclxuICAgIGNhdGNoIChlcnJvcikgeyBlID0geyBlcnJvcjogZXJyb3IgfTsgfVxyXG4gICAgZmluYWxseSB7XHJcbiAgICAgICAgdHJ5IHtcclxuICAgICAgICAgICAgaWYgKHIgJiYgIXIuZG9uZSAmJiAobSA9IGlbXCJyZXR1cm5cIl0pKSBtLmNhbGwoaSk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGZpbmFsbHkgeyBpZiAoZSkgdGhyb3cgZS5lcnJvcjsgfVxyXG4gICAgfVxyXG4gICAgcmV0dXJuIGFyO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19zcHJlYWQoKSB7XHJcbiAgICBmb3IgKHZhciBhciA9IFtdLCBpID0gMDsgaSA8IGFyZ3VtZW50cy5sZW5ndGg7IGkrKylcclxuICAgICAgICBhciA9IGFyLmNvbmNhdChfX3JlYWQoYXJndW1lbnRzW2ldKSk7XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZEFycmF5cygpIHtcclxuICAgIGZvciAodmFyIHMgPSAwLCBpID0gMCwgaWwgPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgaWw7IGkrKykgcyArPSBhcmd1bWVudHNbaV0ubGVuZ3RoO1xyXG4gICAgZm9yICh2YXIgciA9IEFycmF5KHMpLCBrID0gMCwgaSA9IDA7IGkgPCBpbDsgaSsrKVxyXG4gICAgICAgIGZvciAodmFyIGEgPSBhcmd1bWVudHNbaV0sIGogPSAwLCBqbCA9IGEubGVuZ3RoOyBqIDwgamw7IGorKywgaysrKVxyXG4gICAgICAgICAgICByW2tdID0gYVtqXTtcclxuICAgIHJldHVybiByO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXQodikge1xyXG4gICAgcmV0dXJuIHRoaXMgaW5zdGFuY2VvZiBfX2F3YWl0ID8gKHRoaXMudiA9IHYsIHRoaXMpIDogbmV3IF9fYXdhaXQodik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jR2VuZXJhdG9yKHRoaXNBcmcsIF9hcmd1bWVudHMsIGdlbmVyYXRvcikge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBnID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pLCBpLCBxID0gW107XHJcbiAgICByZXR1cm4gaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIpLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaWYgKGdbbl0pIGlbbl0gPSBmdW5jdGlvbiAodikgeyByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKGEsIGIpIHsgcS5wdXNoKFtuLCB2LCBhLCBiXSkgPiAxIHx8IHJlc3VtZShuLCB2KTsgfSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHJlc3VtZShuLCB2KSB7IHRyeSB7IHN0ZXAoZ1tuXSh2KSk7IH0gY2F0Y2ggKGUpIHsgc2V0dGxlKHFbMF1bM10sIGUpOyB9IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAocikgeyByLnZhbHVlIGluc3RhbmNlb2YgX19hd2FpdCA/IFByb21pc2UucmVzb2x2ZShyLnZhbHVlLnYpLnRoZW4oZnVsZmlsbCwgcmVqZWN0KSA6IHNldHRsZShxWzBdWzJdLCByKTsgfVxyXG4gICAgZnVuY3Rpb24gZnVsZmlsbCh2YWx1ZSkgeyByZXN1bWUoXCJuZXh0XCIsIHZhbHVlKTsgfVxyXG4gICAgZnVuY3Rpb24gcmVqZWN0KHZhbHVlKSB7IHJlc3VtZShcInRocm93XCIsIHZhbHVlKTsgfVxyXG4gICAgZnVuY3Rpb24gc2V0dGxlKGYsIHYpIHsgaWYgKGYodiksIHEuc2hpZnQoKSwgcS5sZW5ndGgpIHJlc3VtZShxWzBdWzBdLCBxWzBdWzFdKTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY0RlbGVnYXRvcihvKSB7XHJcbiAgICB2YXIgaSwgcDtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiwgZnVuY3Rpb24gKGUpIHsgdGhyb3cgZTsgfSksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4sIGYpIHsgaVtuXSA9IG9bbl0gPyBmdW5jdGlvbiAodikgeyByZXR1cm4gKHAgPSAhcCkgPyB7IHZhbHVlOiBfX2F3YWl0KG9bbl0odikpLCBkb25lOiBuID09PSBcInJldHVyblwiIH0gOiBmID8gZih2KSA6IHY7IH0gOiBmOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jVmFsdWVzKG8pIHtcclxuICAgIGlmICghU3ltYm9sLmFzeW5jSXRlcmF0b3IpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTeW1ib2wuYXN5bmNJdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbiAgICB2YXIgbSA9IG9bU3ltYm9sLmFzeW5jSXRlcmF0b3JdLCBpO1xyXG4gICAgcmV0dXJuIG0gPyBtLmNhbGwobykgOiAobyA9IHR5cGVvZiBfX3ZhbHVlcyA9PT0gXCJmdW5jdGlvblwiID8gX192YWx1ZXMobykgOiBvW1N5bWJvbC5pdGVyYXRvcl0oKSwgaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIpLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGkpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IGlbbl0gPSBvW25dICYmIGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7IHYgPSBvW25dKHYpLCBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCB2LmRvbmUsIHYudmFsdWUpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gc2V0dGxlKHJlc29sdmUsIHJlamVjdCwgZCwgdikgeyBQcm9taXNlLnJlc29sdmUodikudGhlbihmdW5jdGlvbih2KSB7IHJlc29sdmUoeyB2YWx1ZTogdiwgZG9uZTogZCB9KTsgfSwgcmVqZWN0KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tYWtlVGVtcGxhdGVPYmplY3QoY29va2VkLCByYXcpIHtcclxuICAgIGlmIChPYmplY3QuZGVmaW5lUHJvcGVydHkpIHsgT2JqZWN0LmRlZmluZVByb3BlcnR5KGNvb2tlZCwgXCJyYXdcIiwgeyB2YWx1ZTogcmF3IH0pOyB9IGVsc2UgeyBjb29rZWQucmF3ID0gcmF3OyB9XHJcbiAgICByZXR1cm4gY29va2VkO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9faW1wb3J0U3Rhcihtb2QpIHtcclxuICAgIGlmIChtb2QgJiYgbW9kLl9fZXNNb2R1bGUpIHJldHVybiBtb2Q7XHJcbiAgICB2YXIgcmVzdWx0ID0ge307XHJcbiAgICBpZiAobW9kICE9IG51bGwpIGZvciAodmFyIGsgaW4gbW9kKSBpZiAoT2JqZWN0Lmhhc093blByb3BlcnR5LmNhbGwobW9kLCBrKSkgcmVzdWx0W2tdID0gbW9kW2tdO1xyXG4gICAgcmVzdWx0LmRlZmF1bHQgPSBtb2Q7XHJcbiAgICByZXR1cm4gcmVzdWx0O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnREZWZhdWx0KG1vZCkge1xyXG4gICAgcmV0dXJuIChtb2QgJiYgbW9kLl9fZXNNb2R1bGUpID8gbW9kIDogeyBkZWZhdWx0OiBtb2QgfTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY2xhc3NQcml2YXRlRmllbGRHZXQocmVjZWl2ZXIsIHByaXZhdGVNYXApIHtcclxuICAgIGlmICghcHJpdmF0ZU1hcC5oYXMocmVjZWl2ZXIpKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcImF0dGVtcHRlZCB0byBnZXQgcHJpdmF0ZSBmaWVsZCBvbiBub24taW5zdGFuY2VcIik7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gcHJpdmF0ZU1hcC5nZXQocmVjZWl2ZXIpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZFNldChyZWNlaXZlciwgcHJpdmF0ZU1hcCwgdmFsdWUpIHtcclxuICAgIGlmICghcHJpdmF0ZU1hcC5oYXMocmVjZWl2ZXIpKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcImF0dGVtcHRlZCB0byBzZXQgcHJpdmF0ZSBmaWVsZCBvbiBub24taW5zdGFuY2VcIik7XHJcbiAgICB9XHJcbiAgICBwcml2YXRlTWFwLnNldChyZWNlaXZlciwgdmFsdWUpO1xyXG4gICAgcmV0dXJuIHZhbHVlO1xyXG59XHJcbiIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgcmVxdWVzdCwgY2xlYW5VcmwsIGFwcGVuZEN1c3RvbVBhcmFtcyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBhZGRGZWF0dXJlcyB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXInO1xuICogLy9cbiAqIGFkZEZlYXR1cmVzKHtcbiAqICAgdXJsOiBcImh0dHBzOi8vc2FtcGxlc2VydmVyNi5hcmNnaXNvbmxpbmUuY29tL2FyY2dpcy9yZXN0L3NlcnZpY2VzL1NlcnZpY2VSZXF1ZXN0L0ZlYXR1cmVTZXJ2ZXIvMFwiLFxuICogICBmZWF0dXJlczogW3tcbiAqICAgICBnZW9tZXRyeTogeyB4OiAtMTIwLCB5OiA0NSwgc3BhdGlhbFJlZmVyZW5jZTogeyB3a2lkOiA0MzI2IH0gfSxcbiAqICAgICBhdHRyaWJ1dGVzOiB7IHN0YXR1czogXCJhbGl2ZVwiIH1cbiAqICAgfV1cbiAqIH0pXG4gKiAgIC50aGVuKHJlc3BvbnNlKVxuICogYGBgXG4gKiBBZGQgZmVhdHVyZXMgcmVxdWVzdC4gU2VlIHRoZSBbUkVTVCBEb2N1bWVudGF0aW9uXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3NlcnZpY2VzLXJlZmVyZW5jZS9hZGQtZmVhdHVyZXMuaHRtKSBmb3IgbW9yZSBpbmZvcm1hdGlvbi5cbiAqXG4gKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdC5cbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBhZGRGZWF0dXJlcyByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGFkZEZlYXR1cmVzKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIHVybCA9IGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi9hZGRGZWF0dXJlc1wiO1xuICAgIC8vIGVkaXQgb3BlcmF0aW9ucyBhcmUgUE9TVCBvbmx5XG4gICAgdmFyIG9wdGlvbnMgPSBhcHBlbmRDdXN0b21QYXJhbXMocmVxdWVzdE9wdGlvbnMsIFtcImZlYXR1cmVzXCIsIFwiZ2RiVmVyc2lvblwiLCBcInJldHVybkVkaXRNb21lbnRcIiwgXCJyb2xsYmFja09uRmFpbHVyZVwiXSwgeyBwYXJhbXM6IF9fYXNzaWduKHt9LCByZXF1ZXN0T3B0aW9ucy5wYXJhbXMpIH0pO1xuICAgIHJldHVybiByZXF1ZXN0KHVybCwgb3B0aW9ucyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1hZGQuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyByZXF1ZXN0LCBjbGVhblVybCwgYXBwZW5kQ3VzdG9tUGFyYW1zIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IGRlbGV0ZUZlYXR1cmVzIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcic7XG4gKiAvL1xuICogZGVsZXRlRmVhdHVyZXMoe1xuICogICB1cmw6IFwiaHR0cHM6Ly9zYW1wbGVzZXJ2ZXI2LmFyY2dpc29ubGluZS5jb20vYXJjZ2lzL3Jlc3Qvc2VydmljZXMvU2VydmljZVJlcXVlc3QvRmVhdHVyZVNlcnZlci8wXCIsXG4gKiAgIG9iamVjdElkczogWzEsMiwzXVxuICogfSk7XG4gKiBgYGBcbiAqIERlbGV0ZSBmZWF0dXJlcyByZXF1ZXN0LiBTZWUgdGhlIFtSRVNUIERvY3VtZW50YXRpb25dKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3Qvc2VydmljZXMtcmVmZXJlbmNlL2RlbGV0ZS1mZWF0dXJlcy5odG0pIGZvciBtb3JlIGluZm9ybWF0aW9uLlxuICpcbiAqIEBwYXJhbSBkZWxldGVGZWF0dXJlc1JlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3QuXG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgZGVsZXRlRmVhdHVyZXMgcmVzcG9uc2UuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBkZWxldGVGZWF0dXJlcyhyZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciB1cmwgPSBjbGVhblVybChyZXF1ZXN0T3B0aW9ucy51cmwpICsgXCIvZGVsZXRlRmVhdHVyZXNcIjtcbiAgICAvLyBlZGl0IG9wZXJhdGlvbnMgUE9TVCBvbmx5XG4gICAgdmFyIG9wdGlvbnMgPSBhcHBlbmRDdXN0b21QYXJhbXMocmVxdWVzdE9wdGlvbnMsIFtcbiAgICAgICAgXCJ3aGVyZVwiLFxuICAgICAgICBcIm9iamVjdElkc1wiLFxuICAgICAgICBcImdkYlZlcnNpb25cIixcbiAgICAgICAgXCJyZXR1cm5FZGl0TW9tZW50XCIsXG4gICAgICAgIFwicm9sbGJhY2tPbkZhaWx1cmVcIlxuICAgIF0sIHsgcGFyYW1zOiBfX2Fzc2lnbih7fSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKSB9KTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIG9wdGlvbnMpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGVsZXRlLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyByZXF1ZXN0LCBjbGVhblVybCwgYXBwZW5kQ3VzdG9tUGFyYW1zIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IGdldEZlYXR1cmUgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyJztcbiAqIC8vXG4gKiBjb25zdCB1cmwgPSBcImh0dHBzOi8vc2VydmljZXMuYXJjZ2lzLmNvbS9WNlpIRnI2emRnTlp1VkcwL2FyY2dpcy9yZXN0L3NlcnZpY2VzL0xhbmRzY2FwZV9UcmVlcy9GZWF0dXJlU2VydmVyLzBcIjtcbiAqIC8vXG4gKiBnZXRGZWF0dXJlKHtcbiAqICAgdXJsLFxuICogICBpZDogNDJcbiAqIH0pLnRoZW4oZmVhdHVyZSA9PiB7XG4gKiAgY29uc29sZS5sb2coZmVhdHVyZS5hdHRyaWJ1dGVzLkZJRCk7IC8vIDQyXG4gKiB9KTtcbiAqIGBgYFxuICogR2V0IGEgZmVhdHVyZSBieSBpZC5cbiAqXG4gKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdFxuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIGZlYXR1cmUgb3IgdGhlIFtyZXNwb25zZV0oaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvQVBJL1Jlc3BvbnNlKSBpdHNlbGYgaWYgYHJhd1Jlc3BvbnNlOiB0cnVlYCB3YXMgcGFzc2VkIGluLlxuICovXG5leHBvcnQgZnVuY3Rpb24gZ2V0RmVhdHVyZShyZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciB1cmwgPSBjbGVhblVybChyZXF1ZXN0T3B0aW9ucy51cmwpICsgXCIvXCIgKyByZXF1ZXN0T3B0aW9ucy5pZDtcbiAgICAvLyBkZWZhdWx0IHRvIGEgR0VUIHJlcXVlc3RcbiAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKHsgaHR0cE1ldGhvZDogXCJHRVRcIiB9LCByZXF1ZXN0T3B0aW9ucyk7XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICBpZiAob3B0aW9ucy5yYXdSZXNwb25zZSkge1xuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiByZXNwb25zZS5mZWF0dXJlO1xuICAgIH0pO1xufVxuLyoqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgcXVlcnlGZWF0dXJlcyB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXInO1xuICogLy9cbiAqIHF1ZXJ5RmVhdHVyZXMoe1xuICogICB1cmw6IFwiaHR0cDovL3NhbXBsZXNlcnZlcjYuYXJjZ2lzb25saW5lLmNvbS9hcmNnaXMvcmVzdC9zZXJ2aWNlcy9DZW5zdXMvTWFwU2VydmVyLzNcIixcbiAqICAgd2hlcmU6IFwiU1RBVEVfTkFNRSA9ICdBbGFza2EnXCJcbiAqIH0pXG4gKiAgIC50aGVuKHJlc3VsdClcbiAqIGBgYFxuICogUXVlcnkgYSBmZWF0dXJlIHNlcnZpY2UuIFNlZSBbUkVTVCBEb2N1bWVudGF0aW9uXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3NlcnZpY2VzLXJlZmVyZW5jZS9xdWVyeS1mZWF0dXJlLXNlcnZpY2UtbGF5ZXItLmh0bSkgZm9yIG1vcmUgaW5mb3JtYXRpb24uXG4gKlxuICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3RcbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBxdWVyeSByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHF1ZXJ5RmVhdHVyZXMocmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgcXVlcnlPcHRpb25zID0gYXBwZW5kQ3VzdG9tUGFyYW1zKHJlcXVlc3RPcHRpb25zLCBbXG4gICAgICAgIFwid2hlcmVcIixcbiAgICAgICAgXCJvYmplY3RJZHNcIixcbiAgICAgICAgXCJyZWxhdGlvblBhcmFtXCIsXG4gICAgICAgIFwidGltZVwiLFxuICAgICAgICBcImRpc3RhbmNlXCIsXG4gICAgICAgIFwidW5pdHNcIixcbiAgICAgICAgXCJvdXRGaWVsZHNcIixcbiAgICAgICAgXCJnZW9tZXRyeVwiLFxuICAgICAgICBcImdlb21ldHJ5VHlwZVwiLFxuICAgICAgICBcInNwYXRpYWxSZWxcIixcbiAgICAgICAgXCJyZXR1cm5HZW9tZXRyeVwiLFxuICAgICAgICBcIm1heEFsbG93YWJsZU9mZnNldFwiLFxuICAgICAgICBcImdlb21ldHJ5UHJlY2lzaW9uXCIsXG4gICAgICAgIFwiaW5TUlwiLFxuICAgICAgICBcIm91dFNSXCIsXG4gICAgICAgIFwiZ2RiVmVyc2lvblwiLFxuICAgICAgICBcInJldHVybkRpc3RpbmN0VmFsdWVzXCIsXG4gICAgICAgIFwicmV0dXJuSWRzT25seVwiLFxuICAgICAgICBcInJldHVybkNvdW50T25seVwiLFxuICAgICAgICBcInJldHVybkV4dGVudE9ubHlcIixcbiAgICAgICAgXCJvcmRlckJ5RmllbGRzXCIsXG4gICAgICAgIFwiZ3JvdXBCeUZpZWxkc0ZvclN0YXRpc3RpY3NcIixcbiAgICAgICAgXCJvdXRTdGF0aXN0aWNzXCIsXG4gICAgICAgIFwicmV0dXJuWlwiLFxuICAgICAgICBcInJldHVybk1cIixcbiAgICAgICAgXCJtdWx0aXBhdGNoT3B0aW9uXCIsXG4gICAgICAgIFwicmVzdWx0T2Zmc2V0XCIsXG4gICAgICAgIFwicmVzdWx0UmVjb3JkQ291bnRcIixcbiAgICAgICAgXCJxdWFudGl6YXRpb25QYXJhbWV0ZXJzXCIsXG4gICAgICAgIFwicmV0dXJuQ2VudHJvaWRcIixcbiAgICAgICAgXCJyZXN1bHRUeXBlXCIsXG4gICAgICAgIFwiaGlzdG9yaWNNb21lbnRcIixcbiAgICAgICAgXCJyZXR1cm5UcnVlQ3VydmVzXCIsXG4gICAgICAgIFwic3FsRm9ybWF0XCIsXG4gICAgICAgIFwicmV0dXJuRXhjZWVkZWRMaW1pdEZlYXR1cmVzXCIsXG4gICAgICAgIFwiZlwiXG4gICAgXSwge1xuICAgICAgICBodHRwTWV0aG9kOiBcIkdFVFwiLFxuICAgICAgICBwYXJhbXM6IF9fYXNzaWduKHsgXG4gICAgICAgICAgICAvLyBzZXQgZGVmYXVsdCBxdWVyeSBwYXJhbWV0ZXJzXG4gICAgICAgICAgICB3aGVyZTogXCIxPTFcIiwgb3V0RmllbGRzOiBcIipcIiB9LCByZXF1ZXN0T3B0aW9ucy5wYXJhbXMpXG4gICAgfSk7XG4gICAgcmV0dXJuIHJlcXVlc3QoY2xlYW5VcmwocmVxdWVzdE9wdGlvbnMudXJsKSArIFwiL3F1ZXJ5XCIsIHF1ZXJ5T3B0aW9ucyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1xdWVyeS5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIGNsZWFuVXJsLCBhcHBlbmRDdXN0b21QYXJhbXMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKlxuICogYGBganNcbiAqIGltcG9ydCB7IHF1ZXJ5UmVsYXRlZCB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXInXG4gKiAvL1xuICogcXVlcnlSZWxhdGVkKHtcbiAqICB1cmw6IFwiaHR0cDovL3NlcnZpY2VzLm15c2VydmVyL09yZ0lEL0FyY0dJUy9yZXN0L3NlcnZpY2VzL1BldHJvbGV1bS9LU1BldHJvL0ZlYXR1cmVTZXJ2ZXIvMFwiLFxuICogIHJlbGF0aW9uc2hpcElkOiAxLFxuICogIHBhcmFtczogeyByZXR1cm5Db3VudE9ubHk6IHRydWUgfVxuICogfSlcbiAqICAudGhlbihyZXNwb25zZSkgLy8gcmVzcG9uc2UucmVsYXRlZFJlY29yZHNcbiAqIGBgYFxuICogUXVlcnkgdGhlIHJlbGF0ZWQgcmVjb3JkcyBmb3IgYSBmZWF0dXJlIHNlcnZpY2UuIFNlZSB0aGUgW1JFU1QgRG9jdW1lbnRhdGlvbl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC9zZXJ2aWNlcy1yZWZlcmVuY2UvcXVlcnktcmVsYXRlZC1yZWNvcmRzLWZlYXR1cmUtc2VydmljZS0uaHRtKSBmb3IgbW9yZSBpbmZvcm1hdGlvbi5cbiAqXG4gKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnNcbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBxdWVyeSByZXNwb25zZVxuICovXG5leHBvcnQgZnVuY3Rpb24gcXVlcnlSZWxhdGVkKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIG9wdGlvbnMgPSBhcHBlbmRDdXN0b21QYXJhbXMocmVxdWVzdE9wdGlvbnMsIFtcIm9iamVjdElkc1wiLCBcInJlbGF0aW9uc2hpcElkXCIsIFwiZGVmaW5pdGlvbkV4cHJlc3Npb25cIiwgXCJvdXRGaWVsZHNcIl0sIHtcbiAgICAgICAgaHR0cE1ldGhvZDogXCJHRVRcIixcbiAgICAgICAgcGFyYW1zOiBfX2Fzc2lnbih7IFxuICAgICAgICAgICAgLy8gc2V0IGRlZmF1bHQgcXVlcnkgcGFyYW1ldGVyc1xuICAgICAgICAgICAgZGVmaW5pdGlvbkV4cHJlc3Npb246IFwiMT0xXCIsIG91dEZpZWxkczogXCIqXCIsIHJlbGF0aW9uc2hpcElkOiAwIH0sIHJlcXVlc3RPcHRpb25zLnBhcmFtcylcbiAgICB9KTtcbiAgICByZXR1cm4gcmVxdWVzdChjbGVhblVybChyZXF1ZXN0T3B0aW9ucy51cmwpICsgXCIvcXVlcnlSZWxhdGVkUmVjb3Jkc1wiLCBvcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXF1ZXJ5UmVsYXRlZC5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIGNsZWFuVXJsLCBhcHBlbmRDdXN0b21QYXJhbXMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKlxuICogYGBganNcbiAqIGltcG9ydCB7IHVwZGF0ZUZlYXR1cmVzIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcic7XG4gKiAvL1xuICogdXBkYXRlRmVhdHVyZXMoe1xuICogICB1cmw6IFwiaHR0cHM6Ly9zYW1wbGVzZXJ2ZXI2LmFyY2dpc29ubGluZS5jb20vYXJjZ2lzL3Jlc3Qvc2VydmljZXMvU2VydmljZVJlcXVlc3QvRmVhdHVyZVNlcnZlci8wXCIsXG4gKiAgIGZlYXR1cmVzOiBbe1xuICogICAgIGdlb21ldHJ5OiB7IHg6IC0xMjAsIHk6IDQ1LCBzcGF0aWFsUmVmZXJlbmNlOiB7IHdraWQ6IDQzMjYgfSB9LFxuICogICAgIGF0dHJpYnV0ZXM6IHsgc3RhdHVzOiBcImFsaXZlXCIgfVxuICogICB9XVxuICogfSk7XG4gKiBgYGBcbiAqIFVwZGF0ZSBmZWF0dXJlcyByZXF1ZXN0LiBTZWUgdGhlIFtSRVNUIERvY3VtZW50YXRpb25dKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3Qvc2VydmljZXMtcmVmZXJlbmNlL3VwZGF0ZS1mZWF0dXJlcy5odG0pIGZvciBtb3JlIGluZm9ybWF0aW9uLlxuICpcbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0LlxuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIHVwZGF0ZUZlYXR1cmVzIHJlc3BvbnNlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gdXBkYXRlRmVhdHVyZXMocmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgdXJsID0gY2xlYW5VcmwocmVxdWVzdE9wdGlvbnMudXJsKSArIFwiL3VwZGF0ZUZlYXR1cmVzXCI7XG4gICAgLy8gZWRpdCBvcGVyYXRpb25zIGFyZSBQT1NUIG9ubHlcbiAgICB2YXIgb3B0aW9ucyA9IGFwcGVuZEN1c3RvbVBhcmFtcyhyZXF1ZXN0T3B0aW9ucywgW1wiZmVhdHVyZXNcIiwgXCJnZGJWZXJzaW9uXCIsIFwicmV0dXJuRWRpdE1vbWVudFwiLCBcInJvbGxiYWNrT25GYWlsdXJlXCIsIFwidHJ1ZUN1cnZlQ2xpZW50XCJdLCB7IHBhcmFtczogX19hc3NpZ24oe30sIHJlcXVlc3RPcHRpb25zLnBhcmFtcykgfSk7XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXVwZGF0ZS5qcy5tYXAiLCIvKiEgKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcclxuQ29weXJpZ2h0IChjKSBNaWNyb3NvZnQgQ29ycG9yYXRpb24uXHJcblxyXG5QZXJtaXNzaW9uIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBhbmQvb3IgZGlzdHJpYnV0ZSB0aGlzIHNvZnR3YXJlIGZvciBhbnlcclxucHVycG9zZSB3aXRoIG9yIHdpdGhvdXQgZmVlIGlzIGhlcmVieSBncmFudGVkLlxyXG5cclxuVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiBBTkQgVEhFIEFVVEhPUiBESVNDTEFJTVMgQUxMIFdBUlJBTlRJRVMgV0lUSFxyXG5SRUdBUkQgVE8gVEhJUyBTT0ZUV0FSRSBJTkNMVURJTkcgQUxMIElNUExJRUQgV0FSUkFOVElFUyBPRiBNRVJDSEFOVEFCSUxJVFlcclxuQU5EIEZJVE5FU1MuIElOIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1IgQkUgTElBQkxFIEZPUiBBTlkgU1BFQ0lBTCwgRElSRUNULFxyXG5JTkRJUkVDVCwgT1IgQ09OU0VRVUVOVElBTCBEQU1BR0VTIE9SIEFOWSBEQU1BR0VTIFdIQVRTT0VWRVIgUkVTVUxUSU5HIEZST01cclxuTE9TUyBPRiBVU0UsIERBVEEgT1IgUFJPRklUUywgV0hFVEhFUiBJTiBBTiBBQ1RJT04gT0YgQ09OVFJBQ1QsIE5FR0xJR0VOQ0UgT1JcclxuT1RIRVIgVE9SVElPVVMgQUNUSU9OLCBBUklTSU5HIE9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFVTRSBPUlxyXG5QRVJGT1JNQU5DRSBPRiBUSElTIFNPRlRXQVJFLlxyXG4qKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiAqL1xyXG4vKiBnbG9iYWwgUmVmbGVjdCwgUHJvbWlzZSAqL1xyXG5cclxudmFyIGV4dGVuZFN0YXRpY3MgPSBmdW5jdGlvbihkLCBiKSB7XHJcbiAgICBleHRlbmRTdGF0aWNzID0gT2JqZWN0LnNldFByb3RvdHlwZU9mIHx8XHJcbiAgICAgICAgKHsgX19wcm90b19fOiBbXSB9IGluc3RhbmNlb2YgQXJyYXkgJiYgZnVuY3Rpb24gKGQsIGIpIHsgZC5fX3Byb3RvX18gPSBiOyB9KSB8fFxyXG4gICAgICAgIGZ1bmN0aW9uIChkLCBiKSB7IGZvciAodmFyIHAgaW4gYikgaWYgKGIuaGFzT3duUHJvcGVydHkocCkpIGRbcF0gPSBiW3BdOyB9O1xyXG4gICAgcmV0dXJuIGV4dGVuZFN0YXRpY3MoZCwgYik7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19leHRlbmRzKGQsIGIpIHtcclxuICAgIGV4dGVuZFN0YXRpY3MoZCwgYik7XHJcbiAgICBmdW5jdGlvbiBfXygpIHsgdGhpcy5jb25zdHJ1Y3RvciA9IGQ7IH1cclxuICAgIGQucHJvdG90eXBlID0gYiA9PT0gbnVsbCA/IE9iamVjdC5jcmVhdGUoYikgOiAoX18ucHJvdG90eXBlID0gYi5wcm90b3R5cGUsIG5ldyBfXygpKTtcclxufVxyXG5cclxuZXhwb3J0IHZhciBfX2Fzc2lnbiA9IGZ1bmN0aW9uKCkge1xyXG4gICAgX19hc3NpZ24gPSBPYmplY3QuYXNzaWduIHx8IGZ1bmN0aW9uIF9fYXNzaWduKHQpIHtcclxuICAgICAgICBmb3IgKHZhciBzLCBpID0gMSwgbiA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBuOyBpKyspIHtcclxuICAgICAgICAgICAgcyA9IGFyZ3VtZW50c1tpXTtcclxuICAgICAgICAgICAgZm9yICh2YXIgcCBpbiBzKSBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHMsIHApKSB0W3BdID0gc1twXTtcclxuICAgICAgICB9XHJcbiAgICAgICAgcmV0dXJuIHQ7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gX19hc3NpZ24uYXBwbHkodGhpcywgYXJndW1lbnRzKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcmVzdChzLCBlKSB7XHJcbiAgICB2YXIgdCA9IHt9O1xyXG4gICAgZm9yICh2YXIgcCBpbiBzKSBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHMsIHApICYmIGUuaW5kZXhPZihwKSA8IDApXHJcbiAgICAgICAgdFtwXSA9IHNbcF07XHJcbiAgICBpZiAocyAhPSBudWxsICYmIHR5cGVvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlTeW1ib2xzID09PSBcImZ1bmN0aW9uXCIpXHJcbiAgICAgICAgZm9yICh2YXIgaSA9IDAsIHAgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlTeW1ib2xzKHMpOyBpIDwgcC5sZW5ndGg7IGkrKykge1xyXG4gICAgICAgICAgICBpZiAoZS5pbmRleE9mKHBbaV0pIDwgMCAmJiBPYmplY3QucHJvdG90eXBlLnByb3BlcnR5SXNFbnVtZXJhYmxlLmNhbGwocywgcFtpXSkpXHJcbiAgICAgICAgICAgICAgICB0W3BbaV1dID0gc1twW2ldXTtcclxuICAgICAgICB9XHJcbiAgICByZXR1cm4gdDtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZGVjb3JhdGUoZGVjb3JhdG9ycywgdGFyZ2V0LCBrZXksIGRlc2MpIHtcclxuICAgIHZhciBjID0gYXJndW1lbnRzLmxlbmd0aCwgciA9IGMgPCAzID8gdGFyZ2V0IDogZGVzYyA9PT0gbnVsbCA/IGRlc2MgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKHRhcmdldCwga2V5KSA6IGRlc2MsIGQ7XHJcbiAgICBpZiAodHlwZW9mIFJlZmxlY3QgPT09IFwib2JqZWN0XCIgJiYgdHlwZW9mIFJlZmxlY3QuZGVjb3JhdGUgPT09IFwiZnVuY3Rpb25cIikgciA9IFJlZmxlY3QuZGVjb3JhdGUoZGVjb3JhdG9ycywgdGFyZ2V0LCBrZXksIGRlc2MpO1xyXG4gICAgZWxzZSBmb3IgKHZhciBpID0gZGVjb3JhdG9ycy5sZW5ndGggLSAxOyBpID49IDA7IGktLSkgaWYgKGQgPSBkZWNvcmF0b3JzW2ldKSByID0gKGMgPCAzID8gZChyKSA6IGMgPiAzID8gZCh0YXJnZXQsIGtleSwgcikgOiBkKHRhcmdldCwga2V5KSkgfHwgcjtcclxuICAgIHJldHVybiBjID4gMyAmJiByICYmIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0YXJnZXQsIGtleSwgciksIHI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3BhcmFtKHBhcmFtSW5kZXgsIGRlY29yYXRvcikge1xyXG4gICAgcmV0dXJuIGZ1bmN0aW9uICh0YXJnZXQsIGtleSkgeyBkZWNvcmF0b3IodGFyZ2V0LCBrZXksIHBhcmFtSW5kZXgpOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX21ldGFkYXRhKG1ldGFkYXRhS2V5LCBtZXRhZGF0YVZhbHVlKSB7XHJcbiAgICBpZiAodHlwZW9mIFJlZmxlY3QgPT09IFwib2JqZWN0XCIgJiYgdHlwZW9mIFJlZmxlY3QubWV0YWRhdGEgPT09IFwiZnVuY3Rpb25cIikgcmV0dXJuIFJlZmxlY3QubWV0YWRhdGEobWV0YWRhdGFLZXksIG1ldGFkYXRhVmFsdWUpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hd2FpdGVyKHRoaXNBcmcsIF9hcmd1bWVudHMsIFAsIGdlbmVyYXRvcikge1xyXG4gICAgZnVuY3Rpb24gYWRvcHQodmFsdWUpIHsgcmV0dXJuIHZhbHVlIGluc3RhbmNlb2YgUCA/IHZhbHVlIDogbmV3IFAoZnVuY3Rpb24gKHJlc29sdmUpIHsgcmVzb2x2ZSh2YWx1ZSk7IH0pOyB9XHJcbiAgICByZXR1cm4gbmV3IChQIHx8IChQID0gUHJvbWlzZSkpKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcclxuICAgICAgICBmdW5jdGlvbiBmdWxmaWxsZWQodmFsdWUpIHsgdHJ5IHsgc3RlcChnZW5lcmF0b3IubmV4dCh2YWx1ZSkpOyB9IGNhdGNoIChlKSB7IHJlamVjdChlKTsgfSB9XHJcbiAgICAgICAgZnVuY3Rpb24gcmVqZWN0ZWQodmFsdWUpIHsgdHJ5IHsgc3RlcChnZW5lcmF0b3JbXCJ0aHJvd1wiXSh2YWx1ZSkpOyB9IGNhdGNoIChlKSB7IHJlamVjdChlKTsgfSB9XHJcbiAgICAgICAgZnVuY3Rpb24gc3RlcChyZXN1bHQpIHsgcmVzdWx0LmRvbmUgPyByZXNvbHZlKHJlc3VsdC52YWx1ZSkgOiBhZG9wdChyZXN1bHQudmFsdWUpLnRoZW4oZnVsZmlsbGVkLCByZWplY3RlZCk7IH1cclxuICAgICAgICBzdGVwKChnZW5lcmF0b3IgPSBnZW5lcmF0b3IuYXBwbHkodGhpc0FyZywgX2FyZ3VtZW50cyB8fCBbXSkpLm5leHQoKSk7XHJcbiAgICB9KTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZ2VuZXJhdG9yKHRoaXNBcmcsIGJvZHkpIHtcclxuICAgIHZhciBfID0geyBsYWJlbDogMCwgc2VudDogZnVuY3Rpb24oKSB7IGlmICh0WzBdICYgMSkgdGhyb3cgdFsxXTsgcmV0dXJuIHRbMV07IH0sIHRyeXM6IFtdLCBvcHM6IFtdIH0sIGYsIHksIHQsIGc7XHJcbiAgICByZXR1cm4gZyA9IHsgbmV4dDogdmVyYigwKSwgXCJ0aHJvd1wiOiB2ZXJiKDEpLCBcInJldHVyblwiOiB2ZXJiKDIpIH0sIHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiAoZ1tTeW1ib2wuaXRlcmF0b3JdID0gZnVuY3Rpb24oKSB7IHJldHVybiB0aGlzOyB9KSwgZztcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyByZXR1cm4gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIHN0ZXAoW24sIHZdKTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gc3RlcChvcCkge1xyXG4gICAgICAgIGlmIChmKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiR2VuZXJhdG9yIGlzIGFscmVhZHkgZXhlY3V0aW5nLlwiKTtcclxuICAgICAgICB3aGlsZSAoXykgdHJ5IHtcclxuICAgICAgICAgICAgaWYgKGYgPSAxLCB5ICYmICh0ID0gb3BbMF0gJiAyID8geVtcInJldHVyblwiXSA6IG9wWzBdID8geVtcInRocm93XCJdIHx8ICgodCA9IHlbXCJyZXR1cm5cIl0pICYmIHQuY2FsbCh5KSwgMCkgOiB5Lm5leHQpICYmICEodCA9IHQuY2FsbCh5LCBvcFsxXSkpLmRvbmUpIHJldHVybiB0O1xyXG4gICAgICAgICAgICBpZiAoeSA9IDAsIHQpIG9wID0gW29wWzBdICYgMiwgdC52YWx1ZV07XHJcbiAgICAgICAgICAgIHN3aXRjaCAob3BbMF0pIHtcclxuICAgICAgICAgICAgICAgIGNhc2UgMDogY2FzZSAxOiB0ID0gb3A7IGJyZWFrO1xyXG4gICAgICAgICAgICAgICAgY2FzZSA0OiBfLmxhYmVsKys7IHJldHVybiB7IHZhbHVlOiBvcFsxXSwgZG9uZTogZmFsc2UgfTtcclxuICAgICAgICAgICAgICAgIGNhc2UgNTogXy5sYWJlbCsrOyB5ID0gb3BbMV07IG9wID0gWzBdOyBjb250aW51ZTtcclxuICAgICAgICAgICAgICAgIGNhc2UgNzogb3AgPSBfLm9wcy5wb3AoKTsgXy50cnlzLnBvcCgpOyBjb250aW51ZTtcclxuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKCEodCA9IF8udHJ5cywgdCA9IHQubGVuZ3RoID4gMCAmJiB0W3QubGVuZ3RoIC0gMV0pICYmIChvcFswXSA9PT0gNiB8fCBvcFswXSA9PT0gMikpIHsgXyA9IDA7IGNvbnRpbnVlOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG9wWzBdID09PSAzICYmICghdCB8fCAob3BbMV0gPiB0WzBdICYmIG9wWzFdIDwgdFszXSkpKSB7IF8ubGFiZWwgPSBvcFsxXTsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAob3BbMF0gPT09IDYgJiYgXy5sYWJlbCA8IHRbMV0pIHsgXy5sYWJlbCA9IHRbMV07IHQgPSBvcDsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAodCAmJiBfLmxhYmVsIDwgdFsyXSkgeyBfLmxhYmVsID0gdFsyXTsgXy5vcHMucHVzaChvcCk7IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHRbMl0pIF8ub3BzLnBvcCgpO1xyXG4gICAgICAgICAgICAgICAgICAgIF8udHJ5cy5wb3AoKTsgY29udGludWU7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgb3AgPSBib2R5LmNhbGwodGhpc0FyZywgXyk7XHJcbiAgICAgICAgfSBjYXRjaCAoZSkgeyBvcCA9IFs2LCBlXTsgeSA9IDA7IH0gZmluYWxseSB7IGYgPSB0ID0gMDsgfVxyXG4gICAgICAgIGlmIChvcFswXSAmIDUpIHRocm93IG9wWzFdOyByZXR1cm4geyB2YWx1ZTogb3BbMF0gPyBvcFsxXSA6IHZvaWQgMCwgZG9uZTogdHJ1ZSB9O1xyXG4gICAgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jcmVhdGVCaW5kaW5nKG8sIG0sIGssIGsyKSB7XHJcbiAgICBpZiAoazIgPT09IHVuZGVmaW5lZCkgazIgPSBrO1xyXG4gICAgb1trMl0gPSBtW2tdO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19leHBvcnRTdGFyKG0sIGV4cG9ydHMpIHtcclxuICAgIGZvciAodmFyIHAgaW4gbSkgaWYgKHAgIT09IFwiZGVmYXVsdFwiICYmICFleHBvcnRzLmhhc093blByb3BlcnR5KHApKSBleHBvcnRzW3BdID0gbVtwXTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fdmFsdWVzKG8pIHtcclxuICAgIHZhciBzID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIFN5bWJvbC5pdGVyYXRvciwgbSA9IHMgJiYgb1tzXSwgaSA9IDA7XHJcbiAgICBpZiAobSkgcmV0dXJuIG0uY2FsbChvKTtcclxuICAgIGlmIChvICYmIHR5cGVvZiBvLmxlbmd0aCA9PT0gXCJudW1iZXJcIikgcmV0dXJuIHtcclxuICAgICAgICBuZXh0OiBmdW5jdGlvbiAoKSB7XHJcbiAgICAgICAgICAgIGlmIChvICYmIGkgPj0gby5sZW5ndGgpIG8gPSB2b2lkIDA7XHJcbiAgICAgICAgICAgIHJldHVybiB7IHZhbHVlOiBvICYmIG9baSsrXSwgZG9uZTogIW8gfTtcclxuICAgICAgICB9XHJcbiAgICB9O1xyXG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihzID8gXCJPYmplY3QgaXMgbm90IGl0ZXJhYmxlLlwiIDogXCJTeW1ib2wuaXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19yZWFkKG8sIG4pIHtcclxuICAgIHZhciBtID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIG9bU3ltYm9sLml0ZXJhdG9yXTtcclxuICAgIGlmICghbSkgcmV0dXJuIG87XHJcbiAgICB2YXIgaSA9IG0uY2FsbChvKSwgciwgYXIgPSBbXSwgZTtcclxuICAgIHRyeSB7XHJcbiAgICAgICAgd2hpbGUgKChuID09PSB2b2lkIDAgfHwgbi0tID4gMCkgJiYgIShyID0gaS5uZXh0KCkpLmRvbmUpIGFyLnB1c2goci52YWx1ZSk7XHJcbiAgICB9XHJcbiAgICBjYXRjaCAoZXJyb3IpIHsgZSA9IHsgZXJyb3I6IGVycm9yIH07IH1cclxuICAgIGZpbmFsbHkge1xyXG4gICAgICAgIHRyeSB7XHJcbiAgICAgICAgICAgIGlmIChyICYmICFyLmRvbmUgJiYgKG0gPSBpW1wicmV0dXJuXCJdKSkgbS5jYWxsKGkpO1xyXG4gICAgICAgIH1cclxuICAgICAgICBmaW5hbGx5IHsgaWYgKGUpIHRocm93IGUuZXJyb3I7IH1cclxuICAgIH1cclxuICAgIHJldHVybiBhcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fc3ByZWFkKCkge1xyXG4gICAgZm9yICh2YXIgYXIgPSBbXSwgaSA9IDA7IGkgPCBhcmd1bWVudHMubGVuZ3RoOyBpKyspXHJcbiAgICAgICAgYXIgPSBhci5jb25jYXQoX19yZWFkKGFyZ3VtZW50c1tpXSkpO1xyXG4gICAgcmV0dXJuIGFyO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19zcHJlYWRBcnJheXMoKSB7XHJcbiAgICBmb3IgKHZhciBzID0gMCwgaSA9IDAsIGlsID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IGlsOyBpKyspIHMgKz0gYXJndW1lbnRzW2ldLmxlbmd0aDtcclxuICAgIGZvciAodmFyIHIgPSBBcnJheShzKSwgayA9IDAsIGkgPSAwOyBpIDwgaWw7IGkrKylcclxuICAgICAgICBmb3IgKHZhciBhID0gYXJndW1lbnRzW2ldLCBqID0gMCwgamwgPSBhLmxlbmd0aDsgaiA8IGpsOyBqKyssIGsrKylcclxuICAgICAgICAgICAgcltrXSA9IGFbal07XHJcbiAgICByZXR1cm4gcjtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2F3YWl0KHYpIHtcclxuICAgIHJldHVybiB0aGlzIGluc3RhbmNlb2YgX19hd2FpdCA/ICh0aGlzLnYgPSB2LCB0aGlzKSA6IG5ldyBfX2F3YWl0KHYpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY0dlbmVyYXRvcih0aGlzQXJnLCBfYXJndW1lbnRzLCBnZW5lcmF0b3IpIHtcclxuICAgIGlmICghU3ltYm9sLmFzeW5jSXRlcmF0b3IpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTeW1ib2wuYXN5bmNJdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbiAgICB2YXIgZyA9IGdlbmVyYXRvci5hcHBseSh0aGlzQXJnLCBfYXJndW1lbnRzIHx8IFtdKSwgaSwgcSA9IFtdO1xyXG4gICAgcmV0dXJuIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiKSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuYXN5bmNJdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IGlmIChnW25dKSBpW25dID0gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChhLCBiKSB7IHEucHVzaChbbiwgdiwgYSwgYl0pID4gMSB8fCByZXN1bWUobiwgdik7IH0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiByZXN1bWUobiwgdikgeyB0cnkgeyBzdGVwKGdbbl0odikpOyB9IGNhdGNoIChlKSB7IHNldHRsZShxWzBdWzNdLCBlKTsgfSB9XHJcbiAgICBmdW5jdGlvbiBzdGVwKHIpIHsgci52YWx1ZSBpbnN0YW5jZW9mIF9fYXdhaXQgPyBQcm9taXNlLnJlc29sdmUoci52YWx1ZS52KS50aGVuKGZ1bGZpbGwsIHJlamVjdCkgOiBzZXR0bGUocVswXVsyXSwgcik7IH1cclxuICAgIGZ1bmN0aW9uIGZ1bGZpbGwodmFsdWUpIHsgcmVzdW1lKFwibmV4dFwiLCB2YWx1ZSk7IH1cclxuICAgIGZ1bmN0aW9uIHJlamVjdCh2YWx1ZSkgeyByZXN1bWUoXCJ0aHJvd1wiLCB2YWx1ZSk7IH1cclxuICAgIGZ1bmN0aW9uIHNldHRsZShmLCB2KSB7IGlmIChmKHYpLCBxLnNoaWZ0KCksIHEubGVuZ3RoKSByZXN1bWUocVswXVswXSwgcVswXVsxXSk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNEZWxlZ2F0b3Iobykge1xyXG4gICAgdmFyIGksIHA7XHJcbiAgICByZXR1cm4gaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIsIGZ1bmN0aW9uIChlKSB7IHRocm93IGU7IH0pLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5pdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuLCBmKSB7IGlbbl0gPSBvW25dID8gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIChwID0gIXApID8geyB2YWx1ZTogX19hd2FpdChvW25dKHYpKSwgZG9uZTogbiA9PT0gXCJyZXR1cm5cIiB9IDogZiA/IGYodikgOiB2OyB9IDogZjsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY1ZhbHVlcyhvKSB7XHJcbiAgICBpZiAoIVN5bWJvbC5hc3luY0l0ZXJhdG9yKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU3ltYm9sLmFzeW5jSXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgdmFyIG0gPSBvW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSwgaTtcclxuICAgIHJldHVybiBtID8gbS5jYWxsKG8pIDogKG8gPSB0eXBlb2YgX192YWx1ZXMgPT09IFwiZnVuY3Rpb25cIiA/IF9fdmFsdWVzKG8pIDogb1tTeW1ib2wuaXRlcmF0b3JdKCksIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiKSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuYXN5bmNJdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpKTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyBpW25dID0gb1tuXSAmJiBmdW5jdGlvbiAodikgeyByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkgeyB2ID0gb1tuXSh2KSwgc2V0dGxlKHJlc29sdmUsIHJlamVjdCwgdi5kb25lLCB2LnZhbHVlKTsgfSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHNldHRsZShyZXNvbHZlLCByZWplY3QsIGQsIHYpIHsgUHJvbWlzZS5yZXNvbHZlKHYpLnRoZW4oZnVuY3Rpb24odikgeyByZXNvbHZlKHsgdmFsdWU6IHYsIGRvbmU6IGQgfSk7IH0sIHJlamVjdCk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fbWFrZVRlbXBsYXRlT2JqZWN0KGNvb2tlZCwgcmF3KSB7XHJcbiAgICBpZiAoT2JqZWN0LmRlZmluZVByb3BlcnR5KSB7IE9iamVjdC5kZWZpbmVQcm9wZXJ0eShjb29rZWQsIFwicmF3XCIsIHsgdmFsdWU6IHJhdyB9KTsgfSBlbHNlIHsgY29va2VkLnJhdyA9IHJhdzsgfVxyXG4gICAgcmV0dXJuIGNvb2tlZDtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2ltcG9ydFN0YXIobW9kKSB7XHJcbiAgICBpZiAobW9kICYmIG1vZC5fX2VzTW9kdWxlKSByZXR1cm4gbW9kO1xyXG4gICAgdmFyIHJlc3VsdCA9IHt9O1xyXG4gICAgaWYgKG1vZCAhPSBudWxsKSBmb3IgKHZhciBrIGluIG1vZCkgaWYgKE9iamVjdC5oYXNPd25Qcm9wZXJ0eS5jYWxsKG1vZCwgaykpIHJlc3VsdFtrXSA9IG1vZFtrXTtcclxuICAgIHJlc3VsdC5kZWZhdWx0ID0gbW9kO1xyXG4gICAgcmV0dXJuIHJlc3VsdDtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9faW1wb3J0RGVmYXVsdChtb2QpIHtcclxuICAgIHJldHVybiAobW9kICYmIG1vZC5fX2VzTW9kdWxlKSA/IG1vZCA6IHsgZGVmYXVsdDogbW9kIH07XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NsYXNzUHJpdmF0ZUZpZWxkR2V0KHJlY2VpdmVyLCBwcml2YXRlTWFwKSB7XHJcbiAgICBpZiAoIXByaXZhdGVNYXAuaGFzKHJlY2VpdmVyKSkge1xyXG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJhdHRlbXB0ZWQgdG8gZ2V0IHByaXZhdGUgZmllbGQgb24gbm9uLWluc3RhbmNlXCIpO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHByaXZhdGVNYXAuZ2V0KHJlY2VpdmVyKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY2xhc3NQcml2YXRlRmllbGRTZXQocmVjZWl2ZXIsIHByaXZhdGVNYXAsIHZhbHVlKSB7XHJcbiAgICBpZiAoIXByaXZhdGVNYXAuaGFzKHJlY2VpdmVyKSkge1xyXG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJhdHRlbXB0ZWQgdG8gc2V0IHByaXZhdGUgZmllbGQgb24gbm9uLWluc3RhbmNlXCIpO1xyXG4gICAgfVxyXG4gICAgcHJpdmF0ZU1hcC5zZXQocmVjZWl2ZXIsIHZhbHVlKTtcclxuICAgIHJldHVybiB2YWx1ZTtcclxufVxyXG4iLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiwgX19leHRlbmRzIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyBlbmNvZGVGb3JtRGF0YSB9IGZyb20gXCIuL3V0aWxzL2VuY29kZS1mb3JtLWRhdGFcIjtcbmltcG9ydCB7IGVuY29kZVF1ZXJ5U3RyaW5nIH0gZnJvbSBcIi4vdXRpbHMvZW5jb2RlLXF1ZXJ5LXN0cmluZ1wiO1xuaW1wb3J0IHsgcmVxdWlyZXNGb3JtRGF0YSB9IGZyb20gXCIuL3V0aWxzL3Byb2Nlc3MtcGFyYW1zXCI7XG5pbXBvcnQgeyBBcmNHSVNSZXF1ZXN0RXJyb3IgfSBmcm9tIFwiLi91dGlscy9BcmNHSVNSZXF1ZXN0RXJyb3JcIjtcbmltcG9ydCB7IHdhcm4gfSBmcm9tIFwiLi91dGlscy93YXJuXCI7XG5leHBvcnQgdmFyIE5PREVKU19ERUZBVUxUX1JFRkVSRVJfSEVBREVSID0gXCJAZXNyaS9hcmNnaXMtcmVzdC1qc1wiO1xudmFyIERFRkFVTFRfQVJDR0lTX1JFUVVFU1RfT1BUSU9OUyA9IHtcbiAgICBodHRwTWV0aG9kOiBcIlBPU1RcIixcbiAgICBwYXJhbXM6IHtcbiAgICAgICAgZjogXCJqc29uXCIsXG4gICAgfSxcbn07XG4vKipcbiAqIFNldHMgdGhlIGRlZmF1bHQgb3B0aW9ucyB0aGF0IHdpbGwgYmUgcGFzc2VkIGluICoqYWxsIHJlcXVlc3RzIGFjcm9zcyBhbGwgYEBlc3JpL2FyY2dpcy1yZXN0LWpzYCBtb2R1bGVzKiouXG4gKlxuICpcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBzZXREZWZhdWx0UmVxdWVzdE9wdGlvbnMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuICogc2V0RGVmYXVsdFJlcXVlc3RPcHRpb25zKHtcbiAqICAgYXV0aGVudGljYXRpb246IHVzZXJTZXNzaW9uIC8vIGFsbCByZXF1ZXN0cyB3aWxsIHVzZSB0aGlzIHNlc3Npb24gYnkgZGVmYXVsdFxuICogfSlcbiAqIGBgYFxuICogWW91IHNob3VsZCAqKm5ldmVyKiogc2V0IGEgZGVmYXVsdCBgYXV0aGVudGljYXRpb25gIHdoZW4geW91IGFyZSBpbiBhIHNlcnZlciBzaWRlIGVudmlyb25tZW50IHdoZXJlIHlvdSBtYXkgYmUgaGFuZGxpbmcgcmVxdWVzdHMgZm9yIG1hbnkgZGlmZmVyZW50IGF1dGhlbnRpY2F0ZWQgdXNlcnMuXG4gKlxuICogQHBhcmFtIG9wdGlvbnMgVGhlIGRlZmF1bHQgb3B0aW9ucyB0byBwYXNzIHdpdGggZXZlcnkgcmVxdWVzdC4gRXhpc3RpbmcgZGVmYXVsdCB3aWxsIGJlIG92ZXJ3cml0dGVuLlxuICogQHBhcmFtIGhpZGVXYXJuaW5ncyBTaWxlbmNlIHdhcm5pbmdzIGFib3V0IHNldHRpbmcgZGVmYXVsdCBgYXV0aGVudGljYXRpb25gIGluIHNoYXJlZCBlbnZpcm9ubWVudHMuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBzZXREZWZhdWx0UmVxdWVzdE9wdGlvbnMob3B0aW9ucywgaGlkZVdhcm5pbmdzKSB7XG4gICAgaWYgKG9wdGlvbnMuYXV0aGVudGljYXRpb24gJiYgIWhpZGVXYXJuaW5ncykge1xuICAgICAgICB3YXJuKFwiWW91IHNob3VsZCBub3Qgc2V0IGBhdXRoZW50aWNhdGlvbmAgYXMgYSBkZWZhdWx0IGluIGEgc2hhcmVkIGVudmlyb25tZW50IHN1Y2ggYXMgYSB3ZWIgc2VydmVyIHdoaWNoIHdpbGwgcHJvY2VzcyBtdWx0aXBsZSB1c2VycyByZXF1ZXN0cy4gWW91IGNhbiBjYWxsIGBzZXREZWZhdWx0UmVxdWVzdE9wdGlvbnNgIHdpdGggYHRydWVgIGFzIGEgc2Vjb25kIGFyZ3VtZW50IHRvIGRpc2FibGUgdGhpcyB3YXJuaW5nLlwiKTtcbiAgICB9XG4gICAgREVGQVVMVF9BUkNHSVNfUkVRVUVTVF9PUFRJT05TID0gb3B0aW9ucztcbn1cbnZhciBBcmNHSVNBdXRoRXJyb3IgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoX3N1cGVyKSB7XG4gICAgX19leHRlbmRzKEFyY0dJU0F1dGhFcnJvciwgX3N1cGVyKTtcbiAgICAvKipcbiAgICAgKiBDcmVhdGUgYSBuZXcgYEFyY0dJU0F1dGhFcnJvcmAgIG9iamVjdC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBtZXNzYWdlIC0gVGhlIGVycm9yIG1lc3NhZ2UgZnJvbSB0aGUgQVBJXG4gICAgICogQHBhcmFtIGNvZGUgLSBUaGUgZXJyb3IgY29kZSBmcm9tIHRoZSBBUElcbiAgICAgKiBAcGFyYW0gcmVzcG9uc2UgLSBUaGUgb3JpZ2luYWwgcmVzcG9uc2UgZnJvbSB0aGUgQVBJIHRoYXQgY2F1c2VkIHRoZSBlcnJvclxuICAgICAqIEBwYXJhbSB1cmwgLSBUaGUgb3JpZ2luYWwgdXJsIG9mIHRoZSByZXF1ZXN0XG4gICAgICogQHBhcmFtIG9wdGlvbnMgLSBUaGUgb3JpZ2luYWwgb3B0aW9ucyBvZiB0aGUgcmVxdWVzdFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIEFyY0dJU0F1dGhFcnJvcihtZXNzYWdlLCBjb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKSB7XG4gICAgICAgIGlmIChtZXNzYWdlID09PSB2b2lkIDApIHsgbWVzc2FnZSA9IFwiQVVUSEVOVElDQVRJT05fRVJST1JcIjsgfVxuICAgICAgICBpZiAoY29kZSA9PT0gdm9pZCAwKSB7IGNvZGUgPSBcIkFVVEhFTlRJQ0FUSU9OX0VSUk9SX0NPREVcIjsgfVxuICAgICAgICB2YXIgX3RoaXMgPSBfc3VwZXIuY2FsbCh0aGlzLCBtZXNzYWdlLCBjb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKSB8fCB0aGlzO1xuICAgICAgICBfdGhpcy5uYW1lID0gXCJBcmNHSVNBdXRoRXJyb3JcIjtcbiAgICAgICAgX3RoaXMubWVzc2FnZSA9XG4gICAgICAgICAgICBjb2RlID09PSBcIkFVVEhFTlRJQ0FUSU9OX0VSUk9SX0NPREVcIiA/IG1lc3NhZ2UgOiBjb2RlICsgXCI6IFwiICsgbWVzc2FnZTtcbiAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgIH1cbiAgICBBcmNHSVNBdXRoRXJyb3IucHJvdG90eXBlLnJldHJ5ID0gZnVuY3Rpb24gKGdldFNlc3Npb24sIHJldHJ5TGltaXQpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgaWYgKHJldHJ5TGltaXQgPT09IHZvaWQgMCkgeyByZXRyeUxpbWl0ID0gMzsgfVxuICAgICAgICB2YXIgdHJpZXMgPSAwO1xuICAgICAgICB2YXIgcmV0cnlSZXF1ZXN0ID0gZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xuICAgICAgICAgICAgZ2V0U2Vzc2lvbihfdGhpcy51cmwsIF90aGlzLm9wdGlvbnMpXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHNlc3Npb24pIHtcbiAgICAgICAgICAgICAgICB2YXIgbmV3T3B0aW9ucyA9IF9fYXNzaWduKF9fYXNzaWduKHt9LCBfdGhpcy5vcHRpb25zKSwgeyBhdXRoZW50aWNhdGlvbjogc2Vzc2lvbiB9KTtcbiAgICAgICAgICAgICAgICB0cmllcyA9IHRyaWVzICsgMTtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVxdWVzdChfdGhpcy51cmwsIG5ld09wdGlvbnMpO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICByZXNvbHZlKHJlc3BvbnNlKTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLmNhdGNoKGZ1bmN0aW9uIChlKSB7XG4gICAgICAgICAgICAgICAgaWYgKGUubmFtZSA9PT0gXCJBcmNHSVNBdXRoRXJyb3JcIiAmJiB0cmllcyA8IHJldHJ5TGltaXQpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0cnlSZXF1ZXN0KHJlc29sdmUsIHJlamVjdCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYgKGUubmFtZSA9PT0gXCJBcmNHSVNBdXRoRXJyb3JcIiAmJiB0cmllcyA+PSByZXRyeUxpbWl0KSB7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChfdGhpcyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICByZWplY3QoZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XG4gICAgICAgICAgICByZXRyeVJlcXVlc3QocmVzb2x2ZSwgcmVqZWN0KTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICByZXR1cm4gQXJjR0lTQXV0aEVycm9yO1xufShBcmNHSVNSZXF1ZXN0RXJyb3IpKTtcbmV4cG9ydCB7IEFyY0dJU0F1dGhFcnJvciB9O1xuLyoqXG4gKiBDaGVja3MgZm9yIGVycm9ycyBpbiBhIEpTT04gcmVzcG9uc2UgZnJvbSB0aGUgQXJjR0lTIFJFU1QgQVBJLiBJZiB0aGVyZSBhcmUgbm8gZXJyb3JzLCBpdCB3aWxsIHJldHVybiB0aGUgYGRhdGFgIHBhc3NlZCBpbi4gSWYgdGhlcmUgaXMgYW4gZXJyb3IsIGl0IHdpbGwgdGhyb3cgYW4gYEFyY0dJU1JlcXVlc3RFcnJvcmAgb3IgYEFyY0dJU0F1dGhFcnJvcmAuXG4gKlxuICogQHBhcmFtIGRhdGEgVGhlIHJlc3BvbnNlIEpTT04gdG8gY2hlY2sgZm9yIGVycm9ycy5cbiAqIEBwYXJhbSB1cmwgVGhlIHVybCBvZiB0aGUgb3JpZ2luYWwgcmVxdWVzdFxuICogQHBhcmFtIHBhcmFtcyBUaGUgcGFyYW1ldGVycyBvZiB0aGUgb3JpZ2luYWwgcmVxdWVzdFxuICogQHBhcmFtIG9wdGlvbnMgVGhlIG9wdGlvbnMgb2YgdGhlIG9yaWdpbmFsIHJlcXVlc3RcbiAqIEByZXR1cm5zIFRoZSBkYXRhIHRoYXQgd2FzIHBhc3NlZCBpbiB0aGUgYGRhdGFgIHBhcmFtZXRlclxuICovXG5leHBvcnQgZnVuY3Rpb24gY2hlY2tGb3JFcnJvcnMocmVzcG9uc2UsIHVybCwgcGFyYW1zLCBvcHRpb25zLCBvcmlnaW5hbEF1dGhFcnJvcikge1xuICAgIC8vIHRoaXMgaXMgYW4gZXJyb3IgbWVzc2FnZSBmcm9tIGJpbGxpbmcuYXJjZ2lzLmNvbSBiYWNrZW5kXG4gICAgaWYgKHJlc3BvbnNlLmNvZGUgPj0gNDAwKSB7XG4gICAgICAgIHZhciBtZXNzYWdlID0gcmVzcG9uc2UubWVzc2FnZSwgY29kZSA9IHJlc3BvbnNlLmNvZGU7XG4gICAgICAgIHRocm93IG5ldyBBcmNHSVNSZXF1ZXN0RXJyb3IobWVzc2FnZSwgY29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucyk7XG4gICAgfVxuICAgIC8vIGVycm9yIGZyb20gQXJjR0lTIE9ubGluZSBvciBhbiBBcmNHSVMgUG9ydGFsIG9yIHNlcnZlciBpbnN0YW5jZS5cbiAgICBpZiAocmVzcG9uc2UuZXJyb3IpIHtcbiAgICAgICAgdmFyIF9hID0gcmVzcG9uc2UuZXJyb3IsIG1lc3NhZ2UgPSBfYS5tZXNzYWdlLCBjb2RlID0gX2EuY29kZSwgbWVzc2FnZUNvZGUgPSBfYS5tZXNzYWdlQ29kZTtcbiAgICAgICAgdmFyIGVycm9yQ29kZSA9IG1lc3NhZ2VDb2RlIHx8IGNvZGUgfHwgXCJVTktOT1dOX0VSUk9SX0NPREVcIjtcbiAgICAgICAgaWYgKGNvZGUgPT09IDQ5OCB8fFxuICAgICAgICAgICAgY29kZSA9PT0gNDk5IHx8XG4gICAgICAgICAgICBtZXNzYWdlQ29kZSA9PT0gXCJHV01fMDAwM1wiIHx8XG4gICAgICAgICAgICAoY29kZSA9PT0gNDAwICYmIG1lc3NhZ2UgPT09IFwiVW5hYmxlIHRvIGdlbmVyYXRlIHRva2VuLlwiKSkge1xuICAgICAgICAgICAgaWYgKG9yaWdpbmFsQXV0aEVycm9yKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgb3JpZ2luYWxBdXRoRXJyb3I7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgQXJjR0lTQXV0aEVycm9yKG1lc3NhZ2UsIGVycm9yQ29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgdGhyb3cgbmV3IEFyY0dJU1JlcXVlc3RFcnJvcihtZXNzYWdlLCBlcnJvckNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpO1xuICAgIH1cbiAgICAvLyBlcnJvciBmcm9tIGEgc3RhdHVzIGNoZWNrXG4gICAgaWYgKHJlc3BvbnNlLnN0YXR1cyA9PT0gXCJmYWlsZWRcIiB8fCByZXNwb25zZS5zdGF0dXMgPT09IFwiZmFpbHVyZVwiKSB7XG4gICAgICAgIHZhciBtZXNzYWdlID0gdm9pZCAwO1xuICAgICAgICB2YXIgY29kZSA9IFwiVU5LTk9XTl9FUlJPUl9DT0RFXCI7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBtZXNzYWdlID0gSlNPTi5wYXJzZShyZXNwb25zZS5zdGF0dXNNZXNzYWdlKS5tZXNzYWdlO1xuICAgICAgICAgICAgY29kZSA9IEpTT04ucGFyc2UocmVzcG9uc2Uuc3RhdHVzTWVzc2FnZSkuY29kZTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZSkge1xuICAgICAgICAgICAgbWVzc2FnZSA9IHJlc3BvbnNlLnN0YXR1c01lc3NhZ2UgfHwgcmVzcG9uc2UubWVzc2FnZTtcbiAgICAgICAgfVxuICAgICAgICB0aHJvdyBuZXcgQXJjR0lTUmVxdWVzdEVycm9yKG1lc3NhZ2UsIGNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpO1xuICAgIH1cbiAgICByZXR1cm4gcmVzcG9uc2U7XG59XG4vKipcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyByZXF1ZXN0IH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdCc7XG4gKiAvL1xuICogcmVxdWVzdCgnaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3QnKVxuICogICAudGhlbihyZXNwb25zZSkgLy8gcmVzcG9uc2UuY3VycmVudFZlcnNpb24gPT09IDUuMlxuICogLy9cbiAqIHJlcXVlc3QoJ2h0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0Jywge1xuICogICBodHRwTWV0aG9kOiBcIkdFVFwiXG4gKiB9KVxuICogLy9cbiAqIHJlcXVlc3QoJ2h0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0L3NlYXJjaCcsIHtcbiAqICAgcGFyYW1zOiB7IHE6ICdwYXJrcycgfVxuICogfSlcbiAqICAgLnRoZW4ocmVzcG9uc2UpIC8vIHJlc3BvbnNlLnRvdGFsID0+IDc4Mzc5XG4gKiBgYGBcbiAqIEdlbmVyaWMgbWV0aG9kIGZvciBtYWtpbmcgSFRUUCByZXF1ZXN0cyB0byBBcmNHSVMgUkVTVCBBUEkgZW5kcG9pbnRzLlxuICpcbiAqIEBwYXJhbSB1cmwgLSBUaGUgVVJMIG9mIHRoZSBBcmNHSVMgUkVTVCBBUEkgZW5kcG9pbnQuXG4gKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdCwgaW5jbHVkaW5nIHBhcmFtZXRlcnMgcmVsZXZhbnQgdG8gdGhlIGVuZHBvaW50LlxuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIGRhdGEgZnJvbSB0aGUgcmVzcG9uc2UuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiByZXF1ZXN0KHVybCwgcmVxdWVzdE9wdGlvbnMpIHtcbiAgICBpZiAocmVxdWVzdE9wdGlvbnMgPT09IHZvaWQgMCkgeyByZXF1ZXN0T3B0aW9ucyA9IHsgcGFyYW1zOiB7IGY6IFwianNvblwiIH0gfTsgfVxuICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oX19hc3NpZ24oX19hc3NpZ24oeyBodHRwTWV0aG9kOiBcIlBPU1RcIiB9LCBERUZBVUxUX0FSQ0dJU19SRVFVRVNUX09QVElPTlMpLCByZXF1ZXN0T3B0aW9ucyksIHtcbiAgICAgICAgcGFyYW1zOiBfX2Fzc2lnbihfX2Fzc2lnbih7fSwgREVGQVVMVF9BUkNHSVNfUkVRVUVTVF9PUFRJT05TLnBhcmFtcyksIHJlcXVlc3RPcHRpb25zLnBhcmFtcyksXG4gICAgICAgIGhlYWRlcnM6IF9fYXNzaWduKF9fYXNzaWduKHt9LCBERUZBVUxUX0FSQ0dJU19SRVFVRVNUX09QVElPTlMuaGVhZGVycyksIHJlcXVlc3RPcHRpb25zLmhlYWRlcnMpLFxuICAgIH0pO1xuICAgIHZhciBtaXNzaW5nR2xvYmFscyA9IFtdO1xuICAgIHZhciByZWNvbW1lbmRlZFBhY2thZ2VzID0gW107XG4gICAgLy8gZG9uJ3QgY2hlY2sgZm9yIGEgZ2xvYmFsIGZldGNoIGlmIGEgY3VzdG9tIGltcGxlbWVudGF0aW9uIHdhcyBwYXNzZWQgdGhyb3VnaFxuICAgIGlmICghb3B0aW9ucy5mZXRjaCAmJiB0eXBlb2YgZmV0Y2ggIT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgb3B0aW9ucy5mZXRjaCA9IGZldGNoLmJpbmQoRnVuY3Rpb24oXCJyZXR1cm4gdGhpc1wiKSgpKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIG1pc3NpbmdHbG9iYWxzLnB1c2goXCJgZmV0Y2hgXCIpO1xuICAgICAgICByZWNvbW1lbmRlZFBhY2thZ2VzLnB1c2goXCJgbm9kZS1mZXRjaGBcIik7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgUHJvbWlzZSA9PT0gXCJ1bmRlZmluZWRcIikge1xuICAgICAgICBtaXNzaW5nR2xvYmFscy5wdXNoKFwiYFByb21pc2VgXCIpO1xuICAgICAgICByZWNvbW1lbmRlZFBhY2thZ2VzLnB1c2goXCJgZXM2LXByb21pc2VgXCIpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIEZvcm1EYXRhID09PSBcInVuZGVmaW5lZFwiKSB7XG4gICAgICAgIG1pc3NpbmdHbG9iYWxzLnB1c2goXCJgRm9ybURhdGFgXCIpO1xuICAgICAgICByZWNvbW1lbmRlZFBhY2thZ2VzLnB1c2goXCJgaXNvbW9ycGhpYy1mb3JtLWRhdGFgXCIpO1xuICAgIH1cbiAgICBpZiAoIW9wdGlvbnMuZmV0Y2ggfHxcbiAgICAgICAgdHlwZW9mIFByb21pc2UgPT09IFwidW5kZWZpbmVkXCIgfHxcbiAgICAgICAgdHlwZW9mIEZvcm1EYXRhID09PSBcInVuZGVmaW5lZFwiKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihcImBhcmNnaXMtcmVzdC1yZXF1ZXN0YCByZXF1aXJlcyBhIGBmZXRjaGAgaW1wbGVtZW50YXRpb24gYW5kIGdsb2JhbCB2YXJpYWJsZXMgZm9yIGBQcm9taXNlYCBhbmQgYEZvcm1EYXRhYCB0byBiZSBwcmVzZW50IGluIHRoZSBnbG9iYWwgc2NvcGUuIFlvdSBhcmUgbWlzc2luZyBcIiArIG1pc3NpbmdHbG9iYWxzLmpvaW4oXCIsIFwiKSArIFwiLiBXZSByZWNvbW1lbmQgaW5zdGFsbGluZyB0aGUgXCIgKyByZWNvbW1lbmRlZFBhY2thZ2VzLmpvaW4oXCIsIFwiKSArIFwiIG1vZHVsZXMgYXQgdGhlIHJvb3Qgb2YgeW91ciBhcHBsaWNhdGlvbiB0byBhZGQgdGhlc2UgdG8gdGhlIGdsb2JhbCBzY29wZS4gU2VlIGh0dHBzOi8vYml0Lmx5LzJLTndXYUogZm9yIG1vcmUgaW5mby5cIik7XG4gICAgfVxuICAgIHZhciBodHRwTWV0aG9kID0gb3B0aW9ucy5odHRwTWV0aG9kLCBhdXRoZW50aWNhdGlvbiA9IG9wdGlvbnMuYXV0aGVudGljYXRpb24sIHJhd1Jlc3BvbnNlID0gb3B0aW9ucy5yYXdSZXNwb25zZTtcbiAgICB2YXIgcGFyYW1zID0gX19hc3NpZ24oeyBmOiBcImpzb25cIiB9LCBvcHRpb25zLnBhcmFtcyk7XG4gICAgdmFyIG9yaWdpbmFsQXV0aEVycm9yID0gbnVsbDtcbiAgICB2YXIgZmV0Y2hPcHRpb25zID0ge1xuICAgICAgICBtZXRob2Q6IGh0dHBNZXRob2QsXG4gICAgICAgIC8qIGVuc3VyZXMgYmVoYXZpb3IgbWltaWNzIFhNTEh0dHBSZXF1ZXN0LlxuICAgICAgICBuZWVkZWQgdG8gc3VwcG9ydCBzZW5kaW5nIElXQSBjb29raWVzICovXG4gICAgICAgIGNyZWRlbnRpYWxzOiBvcHRpb25zLmNyZWRlbnRpYWxzIHx8IFwic2FtZS1vcmlnaW5cIixcbiAgICB9O1xuICAgIC8vIHRoZSAvb2F1dGgyL3BsYXRmb3JtU2VsZiByb3V0ZSB3aWxsIGFkZCBYLUVzcmktQXV0aC1DbGllbnQtSWQgaGVhZGVyXG4gICAgLy8gYW5kIHRoYXQgcmVxdWVzdCBuZWVkcyB0byBzZW5kIGNvb2tpZXMgY3Jvc3MgZG9tYWluXG4gICAgLy8gc28gd2UgbmVlZCB0byBzZXQgdGhlIGNyZWRlbnRpYWxzIHRvIFwiaW5jbHVkZVwiXG4gICAgaWYgKG9wdGlvbnMuaGVhZGVycyAmJlxuICAgICAgICBvcHRpb25zLmhlYWRlcnNbXCJYLUVzcmktQXV0aC1DbGllbnQtSWRcIl0gJiZcbiAgICAgICAgdXJsLmluZGV4T2YoXCIvb2F1dGgyL3BsYXRmb3JtU2VsZlwiKSA+IC0xKSB7XG4gICAgICAgIGZldGNoT3B0aW9ucy5jcmVkZW50aWFscyA9IFwiaW5jbHVkZVwiO1xuICAgIH1cbiAgICByZXR1cm4gKGF1dGhlbnRpY2F0aW9uXG4gICAgICAgID8gYXV0aGVudGljYXRpb24uZ2V0VG9rZW4odXJsLCB7IGZldGNoOiBvcHRpb25zLmZldGNoIH0pLmNhdGNoKGZ1bmN0aW9uIChlcnIpIHtcbiAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICogYXBwZW5kIG9yaWdpbmFsIHJlcXVlc3QgdXJsIGFuZCByZXF1ZXN0T3B0aW9uc1xuICAgICAgICAgICAgICogdG8gdGhlIGVycm9yIHRocm93biBieSBnZXRUb2tlbigpXG4gICAgICAgICAgICAgKiB0byBhc3Npc3Qgd2l0aCByZXRyeWluZ1xuICAgICAgICAgICAgICovXG4gICAgICAgICAgICBlcnIudXJsID0gdXJsO1xuICAgICAgICAgICAgZXJyLm9wdGlvbnMgPSBvcHRpb25zO1xuICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgKiBpZiBhbiBhdHRlbXB0IGlzIG1hZGUgdG8gdGFsayB0byBhbiB1bmZlZGVyYXRlZCBzZXJ2ZXJcbiAgICAgICAgICAgICAqIGZpcnN0IHRyeSB0aGUgcmVxdWVzdCBhbm9ueW1vdXNseS4gaWYgYSAndG9rZW4gcmVxdWlyZWQnXG4gICAgICAgICAgICAgKiBlcnJvciBpcyB0aHJvd24sIHRocm93IHRoZSBVTkZFREVSQVRFRCBlcnJvciB0aGVuLlxuICAgICAgICAgICAgICovXG4gICAgICAgICAgICBvcmlnaW5hbEF1dGhFcnJvciA9IGVycjtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoXCJcIik7XG4gICAgICAgIH0pXG4gICAgICAgIDogUHJvbWlzZS5yZXNvbHZlKFwiXCIpKVxuICAgICAgICAudGhlbihmdW5jdGlvbiAodG9rZW4pIHtcbiAgICAgICAgaWYgKHRva2VuLmxlbmd0aCkge1xuICAgICAgICAgICAgcGFyYW1zLnRva2VuID0gdG9rZW47XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGF1dGhlbnRpY2F0aW9uICYmIGF1dGhlbnRpY2F0aW9uLmdldERvbWFpbkNyZWRlbnRpYWxzKSB7XG4gICAgICAgICAgICBmZXRjaE9wdGlvbnMuY3JlZGVudGlhbHMgPSBhdXRoZW50aWNhdGlvbi5nZXREb21haW5DcmVkZW50aWFscyh1cmwpO1xuICAgICAgICB9XG4gICAgICAgIC8vIEN1c3RvbSBoZWFkZXJzIHRvIGFkZCB0byByZXF1ZXN0LiBJUmVxdWVzdE9wdGlvbnMuaGVhZGVycyB3aXRoIG1lcmdlIG92ZXIgcmVxdWVzdEhlYWRlcnMuXG4gICAgICAgIHZhciByZXF1ZXN0SGVhZGVycyA9IHt9O1xuICAgICAgICBpZiAoZmV0Y2hPcHRpb25zLm1ldGhvZCA9PT0gXCJHRVRcIikge1xuICAgICAgICAgICAgLy8gUHJldmVudHMgdG9rZW4gZnJvbSBiZWluZyBwYXNzZWQgaW4gcXVlcnkgcGFyYW1zIHdoZW4gaGlkZVRva2VuIG9wdGlvbiBpcyB1c2VkLlxuICAgICAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIGlmIC0gd2luZG93IGlzIGFsd2F5cyBkZWZpbmVkIGluIGEgYnJvd3Nlci4gVGVzdCBjYXNlIGlzIGNvdmVyZWQgYnkgSmFzbWluZSBpbiBub2RlIHRlc3QgKi9cbiAgICAgICAgICAgIGlmIChwYXJhbXMudG9rZW4gJiZcbiAgICAgICAgICAgICAgICBvcHRpb25zLmhpZGVUb2tlbiAmJlxuICAgICAgICAgICAgICAgIC8vIFNoYXJpbmcgQVBJIGRvZXMgbm90IHN1cHBvcnQgcHJlZmxpZ2h0IGNoZWNrIHJlcXVpcmVkIGJ5IG1vZGVybiBicm93c2VycyBodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL0dsb3NzYXJ5L1ByZWZsaWdodF9yZXF1ZXN0XG4gICAgICAgICAgICAgICAgdHlwZW9mIHdpbmRvdyA9PT0gXCJ1bmRlZmluZWRcIikge1xuICAgICAgICAgICAgICAgIHJlcXVlc3RIZWFkZXJzW1wiWC1Fc3JpLUF1dGhvcml6YXRpb25cIl0gPSBcIkJlYXJlciBcIiArIHBhcmFtcy50b2tlbjtcbiAgICAgICAgICAgICAgICBkZWxldGUgcGFyYW1zLnRva2VuO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgLy8gZW5jb2RlIHRoZSBwYXJhbWV0ZXJzIGludG8gdGhlIHF1ZXJ5IHN0cmluZ1xuICAgICAgICAgICAgdmFyIHF1ZXJ5UGFyYW1zID0gZW5jb2RlUXVlcnlTdHJpbmcocGFyYW1zKTtcbiAgICAgICAgICAgIC8vIGRvbnQgYXBwZW5kIGEgJz8nIHVubGVzcyBwYXJhbWV0ZXJzIGFyZSBhY3R1YWxseSBwcmVzZW50XG4gICAgICAgICAgICB2YXIgdXJsV2l0aFF1ZXJ5U3RyaW5nID0gcXVlcnlQYXJhbXMgPT09IFwiXCIgPyB1cmwgOiB1cmwgKyBcIj9cIiArIGVuY29kZVF1ZXJ5U3RyaW5nKHBhcmFtcyk7XG4gICAgICAgICAgICBpZiAoXG4gICAgICAgICAgICAvLyBUaGlzIHdvdWxkIGV4Y2VlZCB0aGUgbWF4aW11bSBsZW5ndGggZm9yIFVSTHMgc3BlY2lmaWVkIGJ5IHRoZSBjb25zdW1lciBhbmQgcmVxdWlyZXMgUE9TVFxuICAgICAgICAgICAgKG9wdGlvbnMubWF4VXJsTGVuZ3RoICYmXG4gICAgICAgICAgICAgICAgdXJsV2l0aFF1ZXJ5U3RyaW5nLmxlbmd0aCA+IG9wdGlvbnMubWF4VXJsTGVuZ3RoKSB8fFxuICAgICAgICAgICAgICAgIC8vIE9yIGlmIHRoZSBjdXN0b21lciByZXF1aXJlcyB0aGUgdG9rZW4gdG8gYmUgaGlkZGVuIGFuZCBpdCBoYXMgbm90IGFscmVhZHkgYmVlbiBoaWRkZW4gaW4gdGhlIGhlYWRlciAoZm9yIGJyb3dzZXJzKVxuICAgICAgICAgICAgICAgIChwYXJhbXMudG9rZW4gJiYgb3B0aW9ucy5oaWRlVG9rZW4pKSB7XG4gICAgICAgICAgICAgICAgLy8gdGhlIGNvbnN1bWVyIHNwZWNpZmllZCBhIG1heGltdW0gbGVuZ3RoIGZvciBVUkxzXG4gICAgICAgICAgICAgICAgLy8gYW5kIHRoaXMgd291bGQgZXhjZWVkIGl0LCBzbyB1c2UgcG9zdCBpbnN0ZWFkXG4gICAgICAgICAgICAgICAgZmV0Y2hPcHRpb25zLm1ldGhvZCA9IFwiUE9TVFwiO1xuICAgICAgICAgICAgICAgIC8vIElmIHRoZSB0b2tlbiB3YXMgYWxyZWFkeSBhZGRlZCBhcyBhIEF1dGggaGVhZGVyLCBhZGQgdGhlIHRva2VuIGJhY2sgdG8gYm9keSB3aXRoIG90aGVyIHBhcmFtcyBpbnN0ZWFkIG9mIGhlYWRlclxuICAgICAgICAgICAgICAgIGlmICh0b2tlbi5sZW5ndGggJiYgb3B0aW9ucy5oaWRlVG9rZW4pIHtcbiAgICAgICAgICAgICAgICAgICAgcGFyYW1zLnRva2VuID0gdG9rZW47XG4gICAgICAgICAgICAgICAgICAgIC8vIFJlbW92ZSBleGlzdGluZyBoZWFkZXIgdGhhdCB3YXMgYWRkZWQgYmVmb3JlIHVybCBxdWVyeSBsZW5ndGggd2FzIGNoZWNrZWRcbiAgICAgICAgICAgICAgICAgICAgZGVsZXRlIHJlcXVlc3RIZWFkZXJzW1wiWC1Fc3JpLUF1dGhvcml6YXRpb25cIl07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgLy8ganVzdCB1c2UgR0VUXG4gICAgICAgICAgICAgICAgdXJsID0gdXJsV2l0aFF1ZXJ5U3RyaW5nO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIC8qIHVwZGF0ZVJlc291cmNlcyBjdXJyZW50bHkgcmVxdWlyZXMgRm9ybURhdGEgZXZlbiB3aGVuIHRoZSBpbnB1dCBwYXJhbWV0ZXJzIGRvbnQgd2FycmFudCBpdC5cbiAgICBodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3VzZXJzLWdyb3Vwcy1hbmQtaXRlbXMvdXBkYXRlLXJlc291cmNlcy5odG1cbiAgICAgICAgc2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9Fc3JpL2FyY2dpcy1yZXN0LWpzL3B1bGwvNTAwIGZvciBtb3JlIGluZm8uICovXG4gICAgICAgIHZhciBmb3JjZUZvcm1EYXRhID0gbmV3IFJlZ0V4cChcIi9pdGVtcy8uKy91cGRhdGVSZXNvdXJjZXNcIikudGVzdCh1cmwpO1xuICAgICAgICBpZiAoZmV0Y2hPcHRpb25zLm1ldGhvZCA9PT0gXCJQT1NUXCIpIHtcbiAgICAgICAgICAgIGZldGNoT3B0aW9ucy5ib2R5ID0gZW5jb2RlRm9ybURhdGEocGFyYW1zLCBmb3JjZUZvcm1EYXRhKTtcbiAgICAgICAgfVxuICAgICAgICAvLyBNaXhpbiBoZWFkZXJzIGZyb20gcmVxdWVzdCBvcHRpb25zXG4gICAgICAgIGZldGNoT3B0aW9ucy5oZWFkZXJzID0gX19hc3NpZ24oX19hc3NpZ24oe30sIHJlcXVlc3RIZWFkZXJzKSwgb3B0aW9ucy5oZWFkZXJzKTtcbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgLSBrYXJtYSByZXBvcnRzIGNvdmVyYWdlIG9uIGJyb3dzZXIgdGVzdHMgb25seSAqL1xuICAgICAgICBpZiAodHlwZW9mIHdpbmRvdyA9PT0gXCJ1bmRlZmluZWRcIiAmJiAhZmV0Y2hPcHRpb25zLmhlYWRlcnMucmVmZXJlcikge1xuICAgICAgICAgICAgZmV0Y2hPcHRpb25zLmhlYWRlcnMucmVmZXJlciA9IE5PREVKU19ERUZBVUxUX1JFRkVSRVJfSEVBREVSO1xuICAgICAgICB9XG4gICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBlbHNlIGJsb2IgcmVzcG9uc2VzIGFyZSBkaWZmaWN1bHQgdG8gbWFrZSBjcm9zcyBwbGF0Zm9ybSB3ZSB3aWxsIGp1c3QgaGF2ZSB0byB0cnVzdCB0aGUgaXNvbW9ycGhpYyBmZXRjaCB3aWxsIGRvIGl0cyBqb2IgKi9cbiAgICAgICAgaWYgKCFyZXF1aXJlc0Zvcm1EYXRhKHBhcmFtcykgJiYgIWZvcmNlRm9ybURhdGEpIHtcbiAgICAgICAgICAgIGZldGNoT3B0aW9ucy5oZWFkZXJzW1wiQ29udGVudC1UeXBlXCJdID1cbiAgICAgICAgICAgICAgICBcImFwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZFwiO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBvcHRpb25zLmZldGNoKHVybCwgZmV0Y2hPcHRpb25zKTtcbiAgICB9KVxuICAgICAgICAudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKCFyZXNwb25zZS5vaykge1xuICAgICAgICAgICAgLy8gc2VydmVyIHJlc3BvbmRlZCB3LyBhbiBhY3R1YWwgZXJyb3IgKDQwNCwgNTAwLCBldGMpXG4gICAgICAgICAgICB2YXIgc3RhdHVzXzEgPSByZXNwb25zZS5zdGF0dXMsIHN0YXR1c1RleHQgPSByZXNwb25zZS5zdGF0dXNUZXh0O1xuICAgICAgICAgICAgdGhyb3cgbmV3IEFyY0dJU1JlcXVlc3RFcnJvcihzdGF0dXNUZXh0LCBcIkhUVFAgXCIgKyBzdGF0dXNfMSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHJhd1Jlc3BvbnNlKSB7XG4gICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH1cbiAgICAgICAgc3dpdGNoIChwYXJhbXMuZikge1xuICAgICAgICAgICAgY2FzZSBcImpzb25cIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuanNvbigpO1xuICAgICAgICAgICAgY2FzZSBcImdlb2pzb25cIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuanNvbigpO1xuICAgICAgICAgICAgY2FzZSBcImh0bWxcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UudGV4dCgpO1xuICAgICAgICAgICAgY2FzZSBcInRleHRcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UudGV4dCgpO1xuICAgICAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgYmxvYiByZXNwb25zZXMgYXJlIGRpZmZpY3VsdCB0byBtYWtlIGNyb3NzIHBsYXRmb3JtIHdlIHdpbGwganVzdCBoYXZlIHRvIHRydXN0IHRoYXQgaXNvbW9ycGhpYyBmZXRjaCB3aWxsIGRvIGl0cyBqb2IgKi9cbiAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmJsb2IoKTtcbiAgICAgICAgfVxuICAgIH0pXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIGlmICgocGFyYW1zLmYgPT09IFwianNvblwiIHx8IHBhcmFtcy5mID09PSBcImdlb2pzb25cIikgJiYgIXJhd1Jlc3BvbnNlKSB7XG4gICAgICAgICAgICB2YXIgcmVzcG9uc2UgPSBjaGVja0ZvckVycm9ycyhkYXRhLCB1cmwsIHBhcmFtcywgb3B0aW9ucywgb3JpZ2luYWxBdXRoRXJyb3IpO1xuICAgICAgICAgICAgaWYgKG9yaWdpbmFsQXV0aEVycm9yKSB7XG4gICAgICAgICAgICAgICAgLyogSWYgdGhlIHJlcXVlc3Qgd2FzIG1hZGUgdG8gYW4gdW5mZWRlcmF0ZWQgc2VydmljZSB0aGF0XG4gICAgICAgICAgICAgICAgZGlkbid0IHJlcXVpcmUgYXV0aGVudGljYXRpb24sIGFkZCB0aGUgYmFzZSB1cmwgYW5kIGEgZHVtbXkgdG9rZW5cbiAgICAgICAgICAgICAgICB0byB0aGUgbGlzdCBvZiB0cnVzdGVkIHNlcnZlcnMgdG8gYXZvaWQgYW5vdGhlciBmZWRlcmF0aW9uIGNoZWNrXG4gICAgICAgICAgICAgICAgaW4gdGhlIGV2ZW50IG9mIGEgcmVwZWF0IHJlcXVlc3QgKi9cbiAgICAgICAgICAgICAgICB2YXIgdHJ1bmNhdGVkVXJsID0gdXJsXG4gICAgICAgICAgICAgICAgICAgIC50b0xvd2VyQ2FzZSgpXG4gICAgICAgICAgICAgICAgICAgIC5zcGxpdCgvXFwvcmVzdChcXC9hZG1pbik/XFwvc2VydmljZXNcXC8vKVswXTtcbiAgICAgICAgICAgICAgICBvcHRpb25zLmF1dGhlbnRpY2F0aW9uLmZlZGVyYXRlZFNlcnZlcnNbdHJ1bmNhdGVkVXJsXSA9IHtcbiAgICAgICAgICAgICAgICAgICAgdG9rZW46IFtdLFxuICAgICAgICAgICAgICAgICAgICAvLyBkZWZhdWx0IHRvIDI0IGhvdXJzXG4gICAgICAgICAgICAgICAgICAgIGV4cGlyZXM6IG5ldyBEYXRlKERhdGUubm93KCkgKyA4NjQwMCAqIDEwMDApLFxuICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgICAgb3JpZ2luYWxBdXRoRXJyb3IgPSBudWxsO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIGRhdGE7XG4gICAgICAgIH1cbiAgICB9KTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXJlcXVlc3QuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbi8vIFR5cGVTY3JpcHQgMi4xIG5vIGxvbmdlciBhbGxvd3MgeW91IHRvIGV4dGVuZCBidWlsdCBpbiB0eXBlcy4gU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9NaWNyb3NvZnQvVHlwZVNjcmlwdC9pc3N1ZXMvMTI3OTAjaXNzdWVjb21tZW50LTI2NTk4MTQ0MlxuLy8gYW5kIGh0dHBzOi8vZ2l0aHViLmNvbS9NaWNyb3NvZnQvVHlwZVNjcmlwdC13aWtpL2Jsb2IvbWFzdGVyL0JyZWFraW5nLUNoYW5nZXMubWQjZXh0ZW5kaW5nLWJ1aWx0LWlucy1saWtlLWVycm9yLWFycmF5LWFuZC1tYXAtbWF5LW5vLWxvbmdlci13b3JrXG4vL1xuLy8gVGhpcyBjb2RlIGlzIGZyb20gTUROIGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0phdmFTY3JpcHQvUmVmZXJlbmNlL0dsb2JhbF9PYmplY3RzL0Vycm9yI0N1c3RvbV9FcnJvcl9UeXBlcy5cbnZhciBBcmNHSVNSZXF1ZXN0RXJyb3IgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgLyoqXG4gICAgICogQ3JlYXRlIGEgbmV3IGBBcmNHSVNSZXF1ZXN0RXJyb3JgICBvYmplY3QuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gbWVzc2FnZSAtIFRoZSBlcnJvciBtZXNzYWdlIGZyb20gdGhlIEFQSVxuICAgICAqIEBwYXJhbSBjb2RlIC0gVGhlIGVycm9yIGNvZGUgZnJvbSB0aGUgQVBJXG4gICAgICogQHBhcmFtIHJlc3BvbnNlIC0gVGhlIG9yaWdpbmFsIHJlc3BvbnNlIGZyb20gdGhlIEFQSSB0aGF0IGNhdXNlZCB0aGUgZXJyb3JcbiAgICAgKiBAcGFyYW0gdXJsIC0gVGhlIG9yaWdpbmFsIHVybCBvZiB0aGUgcmVxdWVzdFxuICAgICAqIEBwYXJhbSBvcHRpb25zIC0gVGhlIG9yaWdpbmFsIG9wdGlvbnMgYW5kIHBhcmFtZXRlcnMgb2YgdGhlIHJlcXVlc3RcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBBcmNHSVNSZXF1ZXN0RXJyb3IobWVzc2FnZSwgY29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucykge1xuICAgICAgICBtZXNzYWdlID0gbWVzc2FnZSB8fCBcIlVOS05PV05fRVJST1JcIjtcbiAgICAgICAgY29kZSA9IGNvZGUgfHwgXCJVTktOT1dOX0VSUk9SX0NPREVcIjtcbiAgICAgICAgdGhpcy5uYW1lID0gXCJBcmNHSVNSZXF1ZXN0RXJyb3JcIjtcbiAgICAgICAgdGhpcy5tZXNzYWdlID1cbiAgICAgICAgICAgIGNvZGUgPT09IFwiVU5LTk9XTl9FUlJPUl9DT0RFXCIgPyBtZXNzYWdlIDogY29kZSArIFwiOiBcIiArIG1lc3NhZ2U7XG4gICAgICAgIHRoaXMub3JpZ2luYWxNZXNzYWdlID0gbWVzc2FnZTtcbiAgICAgICAgdGhpcy5jb2RlID0gY29kZTtcbiAgICAgICAgdGhpcy5yZXNwb25zZSA9IHJlc3BvbnNlO1xuICAgICAgICB0aGlzLnVybCA9IHVybDtcbiAgICAgICAgdGhpcy5vcHRpb25zID0gb3B0aW9ucztcbiAgICB9XG4gICAgcmV0dXJuIEFyY0dJU1JlcXVlc3RFcnJvcjtcbn0oKSk7XG5leHBvcnQgeyBBcmNHSVNSZXF1ZXN0RXJyb3IgfTtcbkFyY0dJU1JlcXVlc3RFcnJvci5wcm90b3R5cGUgPSBPYmplY3QuY3JlYXRlKEVycm9yLnByb3RvdHlwZSk7XG5BcmNHSVNSZXF1ZXN0RXJyb3IucHJvdG90eXBlLmNvbnN0cnVjdG9yID0gQXJjR0lTUmVxdWVzdEVycm9yO1xuLy8jIHNvdXJjZU1hcHBpbmdVUkw9QXJjR0lTUmVxdWVzdEVycm9yLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG4vKipcbiAqIEhlbHBlciBmb3IgbWV0aG9kcyB3aXRoIGxvdHMgb2YgZmlyc3Qgb3JkZXIgcmVxdWVzdCBvcHRpb25zIHRvIHBhc3MgdGhyb3VnaCBhcyByZXF1ZXN0IHBhcmFtZXRlcnMuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBhcHBlbmRDdXN0b21QYXJhbXMoY3VzdG9tT3B0aW9ucywga2V5cywgYmFzZU9wdGlvbnMpIHtcbiAgICB2YXIgcmVxdWVzdE9wdGlvbnNLZXlzID0gW1xuICAgICAgICBcInBhcmFtc1wiLFxuICAgICAgICBcImh0dHBNZXRob2RcIixcbiAgICAgICAgXCJyYXdSZXNwb25zZVwiLFxuICAgICAgICBcImF1dGhlbnRpY2F0aW9uXCIsXG4gICAgICAgIFwicG9ydGFsXCIsXG4gICAgICAgIFwiZmV0Y2hcIixcbiAgICAgICAgXCJtYXhVcmxMZW5ndGhcIixcbiAgICAgICAgXCJoZWFkZXJzXCJcbiAgICBdO1xuICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oX19hc3NpZ24oeyBwYXJhbXM6IHt9IH0sIGJhc2VPcHRpb25zKSwgY3VzdG9tT3B0aW9ucyk7XG4gICAgLy8gbWVyZ2UgYWxsIGtleXMgaW4gY3VzdG9tT3B0aW9ucyBpbnRvIG9wdGlvbnMucGFyYW1zXG4gICAgb3B0aW9ucy5wYXJhbXMgPSBrZXlzLnJlZHVjZShmdW5jdGlvbiAodmFsdWUsIGtleSkge1xuICAgICAgICBpZiAoY3VzdG9tT3B0aW9uc1trZXldIHx8IHR5cGVvZiBjdXN0b21PcHRpb25zW2tleV0gPT09IFwiYm9vbGVhblwiKSB7XG4gICAgICAgICAgICB2YWx1ZVtrZXldID0gY3VzdG9tT3B0aW9uc1trZXldO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9LCBvcHRpb25zLnBhcmFtcyk7XG4gICAgLy8gbm93IHJlbW92ZSBhbGwgcHJvcGVydGllcyBpbiBvcHRpb25zIHRoYXQgZG9uJ3QgZXhpc3QgaW4gSVJlcXVlc3RPcHRpb25zXG4gICAgcmV0dXJuIHJlcXVlc3RPcHRpb25zS2V5cy5yZWR1Y2UoZnVuY3Rpb24gKHZhbHVlLCBrZXkpIHtcbiAgICAgICAgaWYgKG9wdGlvbnNba2V5XSkge1xuICAgICAgICAgICAgdmFsdWVba2V5XSA9IG9wdGlvbnNba2V5XTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdmFsdWU7XG4gICAgfSwge30pO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9YXBwZW5kLWN1c3RvbS1wYXJhbXMuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbi8qKlxuICogSGVscGVyIG1ldGhvZCB0byBlbnN1cmUgdGhhdCB1c2VyIHN1cHBsaWVkIHVybHMgZG9uJ3QgaW5jbHVkZSB3aGl0ZXNwYWNlIG9yIGEgdHJhaWxpbmcgc2xhc2guXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBjbGVhblVybCh1cmwpIHtcbiAgICAvLyBHdWFyZCBzbyB3ZSBkb24ndCB0cnkgdG8gdHJpbSBzb21ldGhpbmcgdGhhdCdzIG5vdCBhIHN0cmluZ1xuICAgIGlmICh0eXBlb2YgdXJsICE9PSBcInN0cmluZ1wiKSB7XG4gICAgICAgIHJldHVybiB1cmw7XG4gICAgfVxuICAgIC8vIHRyaW0gbGVhZGluZyBhbmQgdHJhaWxpbmcgc3BhY2VzLCBidXQgbm90IHNwYWNlcyBpbnNpZGUgdGhlIHVybFxuICAgIHVybCA9IHVybC50cmltKCk7XG4gICAgLy8gcmVtb3ZlIHRoZSB0cmFpbGluZyBzbGFzaCB0byB0aGUgdXJsIGlmIG9uZSB3YXMgaW5jbHVkZWRcbiAgICBpZiAodXJsW3VybC5sZW5ndGggLSAxXSA9PT0gXCIvXCIpIHtcbiAgICAgICAgdXJsID0gdXJsLnNsaWNlKDAsIC0xKTtcbiAgICB9XG4gICAgcmV0dXJuIHVybDtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWNsZWFuLXVybC5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAyMCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5leHBvcnQgZnVuY3Rpb24gZGVjb2RlUGFyYW0ocGFyYW0pIHtcbiAgICB2YXIgX2EgPSBwYXJhbS5zcGxpdChcIj1cIiksIGtleSA9IF9hWzBdLCB2YWx1ZSA9IF9hWzFdO1xuICAgIHJldHVybiB7IGtleTogZGVjb2RlVVJJQ29tcG9uZW50KGtleSksIHZhbHVlOiBkZWNvZGVVUklDb21wb25lbnQodmFsdWUpIH07XG59XG4vKipcbiAqIERlY29kZXMgdGhlIHBhc3NlZCBxdWVyeSBzdHJpbmcgYXMgYW4gb2JqZWN0LlxuICpcbiAqIEBwYXJhbSBxdWVyeSBBIHN0cmluZyB0byBiZSBkZWNvZGVkLlxuICogQHJldHVybnMgQSBkZWNvZGVkIHF1ZXJ5IHBhcmFtIG9iamVjdC5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGRlY29kZVF1ZXJ5U3RyaW5nKHF1ZXJ5KSB7XG4gICAgcmV0dXJuIHF1ZXJ5XG4gICAgICAgIC5yZXBsYWNlKC9eIy8sIFwiXCIpXG4gICAgICAgIC5zcGxpdChcIiZcIilcbiAgICAgICAgLnJlZHVjZShmdW5jdGlvbiAoYWNjLCBlbnRyeSkge1xuICAgICAgICB2YXIgX2EgPSBkZWNvZGVQYXJhbShlbnRyeSksIGtleSA9IF9hLmtleSwgdmFsdWUgPSBfYS52YWx1ZTtcbiAgICAgICAgYWNjW2tleV0gPSB2YWx1ZTtcbiAgICAgICAgcmV0dXJuIGFjYztcbiAgICB9LCB7fSk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1kZWNvZGUtcXVlcnktc3RyaW5nLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBwcm9jZXNzUGFyYW1zLCByZXF1aXJlc0Zvcm1EYXRhIH0gZnJvbSBcIi4vcHJvY2Vzcy1wYXJhbXNcIjtcbmltcG9ydCB7IGVuY29kZVF1ZXJ5U3RyaW5nIH0gZnJvbSBcIi4vZW5jb2RlLXF1ZXJ5LXN0cmluZ1wiO1xuLyoqXG4gKiBFbmNvZGVzIHBhcmFtZXRlcnMgaW4gYSBbRm9ybURhdGFdKGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0FQSS9Gb3JtRGF0YSkgb2JqZWN0IGluIGJyb3dzZXJzIG9yIGluIGEgW0Zvcm1EYXRhXShodHRwczovL2dpdGh1Yi5jb20vZm9ybS1kYXRhL2Zvcm0tZGF0YSkgaW4gTm9kZS5qc1xuICpcbiAqIEBwYXJhbSBwYXJhbXMgQW4gb2JqZWN0IHRvIGJlIGVuY29kZWQuXG4gKiBAcmV0dXJucyBUaGUgY29tcGxldGUgW0Zvcm1EYXRhXShodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL1dlYi9BUEkvRm9ybURhdGEpIG9iamVjdC5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGVuY29kZUZvcm1EYXRhKHBhcmFtcywgZm9yY2VGb3JtRGF0YSkge1xuICAgIC8vIHNlZSBodHRwczovL2dpdGh1Yi5jb20vRXNyaS9hcmNnaXMtcmVzdC1qcy9pc3N1ZXMvNDk5IGZvciBtb3JlIGluZm8uXG4gICAgdmFyIHVzZUZvcm1EYXRhID0gcmVxdWlyZXNGb3JtRGF0YShwYXJhbXMpIHx8IGZvcmNlRm9ybURhdGE7XG4gICAgdmFyIG5ld1BhcmFtcyA9IHByb2Nlc3NQYXJhbXMocGFyYW1zKTtcbiAgICBpZiAodXNlRm9ybURhdGEpIHtcbiAgICAgICAgdmFyIGZvcm1EYXRhXzEgPSBuZXcgRm9ybURhdGEoKTtcbiAgICAgICAgT2JqZWN0LmtleXMobmV3UGFyYW1zKS5mb3JFYWNoKGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgICAgIGlmICh0eXBlb2YgQmxvYiAhPT0gXCJ1bmRlZmluZWRcIiAmJiBuZXdQYXJhbXNba2V5XSBpbnN0YW5jZW9mIEJsb2IpIHtcbiAgICAgICAgICAgICAgICAvKiBUbyBuYW1lIHRoZSBCbG9iOlxuICAgICAgICAgICAgICAgICAxLiBsb29rIHRvIGFuIGFsdGVybmF0ZSByZXF1ZXN0IHBhcmFtZXRlciBjYWxsZWQgJ2ZpbGVOYW1lJ1xuICAgICAgICAgICAgICAgICAyLiBzZWUgaWYgJ25hbWUnIGhhcyBiZWVuIHRhY2tlZCBvbnRvIHRoZSBCbG9iIG1hbnVhbGx5XG4gICAgICAgICAgICAgICAgIDMuIGlmIGFsbCBlbHNlIGZhaWxzLCB1c2UgdGhlIHJlcXVlc3QgcGFyYW1ldGVyXG4gICAgICAgICAgICAgICAgKi9cbiAgICAgICAgICAgICAgICB2YXIgZmlsZW5hbWUgPSBuZXdQYXJhbXNbXCJmaWxlTmFtZVwiXSB8fCBuZXdQYXJhbXNba2V5XS5uYW1lIHx8IGtleTtcbiAgICAgICAgICAgICAgICBmb3JtRGF0YV8xLmFwcGVuZChrZXksIG5ld1BhcmFtc1trZXldLCBmaWxlbmFtZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICBmb3JtRGF0YV8xLmFwcGVuZChrZXksIG5ld1BhcmFtc1trZXldKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiBmb3JtRGF0YV8xO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgcmV0dXJuIGVuY29kZVF1ZXJ5U3RyaW5nKHBhcmFtcyk7XG4gICAgfVxufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZW5jb2RlLWZvcm0tZGF0YS5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgcHJvY2Vzc1BhcmFtcyB9IGZyb20gXCIuL3Byb2Nlc3MtcGFyYW1zXCI7XG4vKipcbiAqIEVuY29kZXMga2V5cyBhbmQgcGFyYW1ldGVycyBmb3IgdXNlIGluIGEgVVJMJ3MgcXVlcnkgc3RyaW5nLlxuICpcbiAqIEBwYXJhbSBrZXkgUGFyYW1ldGVyJ3Mga2V5XG4gKiBAcGFyYW0gdmFsdWUgUGFyYW1ldGVyJ3MgdmFsdWVcbiAqIEByZXR1cm5zIFF1ZXJ5IHN0cmluZyB3aXRoIGtleSBhbmQgdmFsdWUgcGFpcnMgc2VwYXJhdGVkIGJ5IFwiJlwiXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBlbmNvZGVQYXJhbShrZXksIHZhbHVlKSB7XG4gICAgLy8gRm9yIGFycmF5IG9mIGFycmF5cywgcmVwZWF0IGtleT12YWx1ZSBmb3IgZWFjaCBlbGVtZW50IG9mIGNvbnRhaW5pbmcgYXJyYXlcbiAgICBpZiAoQXJyYXkuaXNBcnJheSh2YWx1ZSkgJiYgdmFsdWVbMF0gJiYgQXJyYXkuaXNBcnJheSh2YWx1ZVswXSkpIHtcbiAgICAgICAgcmV0dXJuIHZhbHVlLm1hcChmdW5jdGlvbiAoYXJyYXlFbGVtKSB7IHJldHVybiBlbmNvZGVQYXJhbShrZXksIGFycmF5RWxlbSk7IH0pLmpvaW4oXCImXCIpO1xuICAgIH1cbiAgICByZXR1cm4gZW5jb2RlVVJJQ29tcG9uZW50KGtleSkgKyBcIj1cIiArIGVuY29kZVVSSUNvbXBvbmVudCh2YWx1ZSk7XG59XG4vKipcbiAqIEVuY29kZXMgdGhlIHBhc3NlZCBvYmplY3QgYXMgYSBxdWVyeSBzdHJpbmcuXG4gKlxuICogQHBhcmFtIHBhcmFtcyBBbiBvYmplY3QgdG8gYmUgZW5jb2RlZC5cbiAqIEByZXR1cm5zIEFuIGVuY29kZWQgcXVlcnkgc3RyaW5nLlxuICovXG5leHBvcnQgZnVuY3Rpb24gZW5jb2RlUXVlcnlTdHJpbmcocGFyYW1zKSB7XG4gICAgdmFyIG5ld1BhcmFtcyA9IHByb2Nlc3NQYXJhbXMocGFyYW1zKTtcbiAgICByZXR1cm4gT2JqZWN0LmtleXMobmV3UGFyYW1zKVxuICAgICAgICAubWFwKGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgcmV0dXJuIGVuY29kZVBhcmFtKGtleSwgbmV3UGFyYW1zW2tleV0pO1xuICAgIH0pXG4gICAgICAgIC5qb2luKFwiJlwiKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWVuY29kZS1xdWVyeS1zdHJpbmcuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbi8qKlxuICogQ2hlY2tzIHBhcmFtZXRlcnMgdG8gc2VlIGlmIHdlIHNob3VsZCB1c2UgRm9ybURhdGEgdG8gc2VuZCB0aGUgcmVxdWVzdFxuICogQHBhcmFtIHBhcmFtcyBUaGUgb2JqZWN0IHdob3NlIGtleXMgd2lsbCBiZSBlbmNvZGVkLlxuICogQHJldHVybiBBIGJvb2xlYW4gaW5kaWNhdGluZyBpZiBGb3JtRGF0YSB3aWxsIGJlIHJlcXVpcmVkLlxuICovXG5leHBvcnQgZnVuY3Rpb24gcmVxdWlyZXNGb3JtRGF0YShwYXJhbXMpIHtcbiAgICByZXR1cm4gT2JqZWN0LmtleXMocGFyYW1zKS5zb21lKGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgdmFyIHZhbHVlID0gcGFyYW1zW2tleV07XG4gICAgICAgIGlmICghdmFsdWUpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodmFsdWUgJiYgdmFsdWUudG9QYXJhbSkge1xuICAgICAgICAgICAgdmFsdWUgPSB2YWx1ZS50b1BhcmFtKCk7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIHR5cGUgPSB2YWx1ZS5jb25zdHJ1Y3Rvci5uYW1lO1xuICAgICAgICBzd2l0Y2ggKHR5cGUpIHtcbiAgICAgICAgICAgIGNhc2UgXCJBcnJheVwiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGNhc2UgXCJPYmplY3RcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBjYXNlIFwiRGF0ZVwiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGNhc2UgXCJGdW5jdGlvblwiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGNhc2UgXCJCb29sZWFuXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIlN0cmluZ1wiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGNhc2UgXCJOdW1iZXJcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG4gICAgfSk7XG59XG4vKipcbiAqIENvbnZlcnRzIHBhcmFtZXRlcnMgdG8gdGhlIHByb3BlciByZXByZXNlbnRhdGlvbiB0byBzZW5kIHRvIHRoZSBBcmNHSVMgUkVTVCBBUEkuXG4gKiBAcGFyYW0gcGFyYW1zIFRoZSBvYmplY3Qgd2hvc2Uga2V5cyB3aWxsIGJlIGVuY29kZWQuXG4gKiBAcmV0dXJuIEEgbmV3IG9iamVjdCB3aXRoIHByb3Blcmx5IGVuY29kZWQgdmFsdWVzLlxuICovXG5leHBvcnQgZnVuY3Rpb24gcHJvY2Vzc1BhcmFtcyhwYXJhbXMpIHtcbiAgICB2YXIgbmV3UGFyYW1zID0ge307XG4gICAgT2JqZWN0LmtleXMocGFyYW1zKS5mb3JFYWNoKGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgdmFyIF9hLCBfYjtcbiAgICAgICAgdmFyIHBhcmFtID0gcGFyYW1zW2tleV07XG4gICAgICAgIGlmIChwYXJhbSAmJiBwYXJhbS50b1BhcmFtKSB7XG4gICAgICAgICAgICBwYXJhbSA9IHBhcmFtLnRvUGFyYW0oKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXBhcmFtICYmXG4gICAgICAgICAgICBwYXJhbSAhPT0gMCAmJlxuICAgICAgICAgICAgdHlwZW9mIHBhcmFtICE9PSBcImJvb2xlYW5cIiAmJlxuICAgICAgICAgICAgdHlwZW9mIHBhcmFtICE9PSBcInN0cmluZ1wiKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cbiAgICAgICAgdmFyIHR5cGUgPSBwYXJhbS5jb25zdHJ1Y3Rvci5uYW1lO1xuICAgICAgICB2YXIgdmFsdWU7XG4gICAgICAgIC8vIHByb3Blcmx5IGVuY29kZXMgb2JqZWN0cywgYXJyYXlzIGFuZCBkYXRlcyBmb3IgYXJjZ2lzLmNvbSBhbmQgb3RoZXIgc2VydmljZXMuXG4gICAgICAgIC8vIHBvcnRlZCBmcm9tIGh0dHBzOi8vZ2l0aHViLmNvbS9Fc3JpL2VzcmktbGVhZmxldC9ibG9iL21hc3Rlci9zcmMvUmVxdWVzdC5qcyNMMjItTDMwXG4gICAgICAgIC8vIGFsc28gc2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9Fc3JpL2FyY2dpcy1yZXN0LWpzL2lzc3Vlcy8xODpcbiAgICAgICAgLy8gbnVsbCwgdW5kZWZpbmVkLCBmdW5jdGlvbiBhcmUgZXhjbHVkZWQuIElmIHlvdSB3YW50IHRvIHNlbmQgYW4gZW1wdHkga2V5IHlvdSBuZWVkIHRvIHNlbmQgYW4gZW1wdHkgc3RyaW5nIFwiXCIuXG4gICAgICAgIHN3aXRjaCAodHlwZSkge1xuICAgICAgICAgICAgY2FzZSBcIkFycmF5XCI6XG4gICAgICAgICAgICAgICAgLy8gQmFzZWQgb24gdGhlIGZpcnN0IGVsZW1lbnQgb2YgdGhlIGFycmF5LCBjbGFzc2lmeSBhcnJheSBhcyBhbiBhcnJheSBvZiBhcnJheXMsIGFuIGFycmF5IG9mIG9iamVjdHNcbiAgICAgICAgICAgICAgICAvLyB0byBiZSBzdHJpbmdpZmllZCwgb3IgYW4gYXJyYXkgb2Ygbm9uLW9iamVjdHMgdG8gYmUgY29tbWEtc2VwYXJhdGVkXG4gICAgICAgICAgICAgICAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5vLWNhc2UtZGVjbGFyYXRpb25zXG4gICAgICAgICAgICAgICAgdmFyIGZpcnN0RWxlbWVudFR5cGUgPSAoX2IgPSAoX2EgPSBwYXJhbVswXSkgPT09IG51bGwgfHwgX2EgPT09IHZvaWQgMCA/IHZvaWQgMCA6IF9hLmNvbnN0cnVjdG9yKSA9PT0gbnVsbCB8fCBfYiA9PT0gdm9pZCAwID8gdm9pZCAwIDogX2IubmFtZTtcbiAgICAgICAgICAgICAgICB2YWx1ZSA9XG4gICAgICAgICAgICAgICAgICAgIGZpcnN0RWxlbWVudFR5cGUgPT09IFwiQXJyYXlcIiA/IHBhcmFtIDogLy8gcGFzcyB0aHJ1IGFycmF5IG9mIGFycmF5c1xuICAgICAgICAgICAgICAgICAgICAgICAgZmlyc3RFbGVtZW50VHlwZSA9PT0gXCJPYmplY3RcIiA/IEpTT04uc3RyaW5naWZ5KHBhcmFtKSA6IC8vIHN0cmluZ2lmeSBhcnJheSBvZiBvYmplY3RzXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFyYW0uam9pbihcIixcIik7IC8vIGpvaW4gb3RoZXIgdHlwZXMgb2YgYXJyYXkgZWxlbWVudHNcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIGNhc2UgXCJPYmplY3RcIjpcbiAgICAgICAgICAgICAgICB2YWx1ZSA9IEpTT04uc3RyaW5naWZ5KHBhcmFtKTtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIGNhc2UgXCJEYXRlXCI6XG4gICAgICAgICAgICAgICAgdmFsdWUgPSBwYXJhbS52YWx1ZU9mKCk7XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICBjYXNlIFwiRnVuY3Rpb25cIjpcbiAgICAgICAgICAgICAgICB2YWx1ZSA9IG51bGw7XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICBjYXNlIFwiQm9vbGVhblwiOlxuICAgICAgICAgICAgICAgIHZhbHVlID0gcGFyYW0gKyBcIlwiO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICB2YWx1ZSA9IHBhcmFtO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGlmICh2YWx1ZSB8fCB2YWx1ZSA9PT0gMCB8fCB0eXBlb2YgdmFsdWUgPT09IFwic3RyaW5nXCIgfHwgQXJyYXkuaXNBcnJheSh2YWx1ZSkpIHtcbiAgICAgICAgICAgIG5ld1BhcmFtc1trZXldID0gdmFsdWU7XG4gICAgICAgIH1cbiAgICB9KTtcbiAgICByZXR1cm4gbmV3UGFyYW1zO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9cHJvY2Vzcy1wYXJhbXMuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuLyoqXG4gKiBNZXRob2QgdXNlZCBpbnRlcm5hbGx5IHRvIHN1cmZhY2UgbWVzc2FnZXMgdG8gZGV2ZWxvcGVycy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHdhcm4obWVzc2FnZSkge1xuICAgIGlmIChjb25zb2xlICYmIGNvbnNvbGUud2Fybikge1xuICAgICAgICBjb25zb2xlLndhcm4uYXBwbHkoY29uc29sZSwgW21lc3NhZ2VdKTtcbiAgICB9XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD13YXJuLmpzLm1hcCIsIi8qISAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxyXG5Db3B5cmlnaHQgKGMpIE1pY3Jvc29mdCBDb3Jwb3JhdGlvbi5cclxuXHJcblBlcm1pc3Npb24gdG8gdXNlLCBjb3B5LCBtb2RpZnksIGFuZC9vciBkaXN0cmlidXRlIHRoaXMgc29mdHdhcmUgZm9yIGFueVxyXG5wdXJwb3NlIHdpdGggb3Igd2l0aG91dCBmZWUgaXMgaGVyZWJ5IGdyYW50ZWQuXHJcblxyXG5USEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiIEFORCBUSEUgQVVUSE9SIERJU0NMQUlNUyBBTEwgV0FSUkFOVElFUyBXSVRIXHJcblJFR0FSRCBUTyBUSElTIFNPRlRXQVJFIElOQ0xVRElORyBBTEwgSU1QTElFRCBXQVJSQU5USUVTIE9GIE1FUkNIQU5UQUJJTElUWVxyXG5BTkQgRklUTkVTUy4gSU4gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUiBCRSBMSUFCTEUgRk9SIEFOWSBTUEVDSUFMLCBESVJFQ1QsXHJcbklORElSRUNULCBPUiBDT05TRVFVRU5USUFMIERBTUFHRVMgT1IgQU5ZIERBTUFHRVMgV0hBVFNPRVZFUiBSRVNVTFRJTkcgRlJPTVxyXG5MT1NTIE9GIFVTRSwgREFUQSBPUiBQUk9GSVRTLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgTkVHTElHRU5DRSBPUlxyXG5PVEhFUiBUT1JUSU9VUyBBQ1RJT04sIEFSSVNJTkcgT1VUIE9GIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgVVNFIE9SXHJcblBFUkZPUk1BTkNFIE9GIFRISVMgU09GVFdBUkUuXHJcbioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqICovXHJcbi8qIGdsb2JhbCBSZWZsZWN0LCBQcm9taXNlICovXHJcblxyXG52YXIgZXh0ZW5kU3RhdGljcyA9IGZ1bmN0aW9uKGQsIGIpIHtcclxuICAgIGV4dGVuZFN0YXRpY3MgPSBPYmplY3Quc2V0UHJvdG90eXBlT2YgfHxcclxuICAgICAgICAoeyBfX3Byb3RvX186IFtdIH0gaW5zdGFuY2VvZiBBcnJheSAmJiBmdW5jdGlvbiAoZCwgYikgeyBkLl9fcHJvdG9fXyA9IGI7IH0pIHx8XHJcbiAgICAgICAgZnVuY3Rpb24gKGQsIGIpIHsgZm9yICh2YXIgcCBpbiBiKSBpZiAoYi5oYXNPd25Qcm9wZXJ0eShwKSkgZFtwXSA9IGJbcF07IH07XHJcbiAgICByZXR1cm4gZXh0ZW5kU3RhdGljcyhkLCBiKTtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2V4dGVuZHMoZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyhkLCBiKTtcclxuICAgIGZ1bmN0aW9uIF9fKCkgeyB0aGlzLmNvbnN0cnVjdG9yID0gZDsgfVxyXG4gICAgZC5wcm90b3R5cGUgPSBiID09PSBudWxsID8gT2JqZWN0LmNyZWF0ZShiKSA6IChfXy5wcm90b3R5cGUgPSBiLnByb3RvdHlwZSwgbmV3IF9fKCkpO1xyXG59XHJcblxyXG5leHBvcnQgdmFyIF9fYXNzaWduID0gZnVuY3Rpb24oKSB7XHJcbiAgICBfX2Fzc2lnbiA9IE9iamVjdC5hc3NpZ24gfHwgZnVuY3Rpb24gX19hc3NpZ24odCkge1xyXG4gICAgICAgIGZvciAodmFyIHMsIGkgPSAxLCBuID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IG47IGkrKykge1xyXG4gICAgICAgICAgICBzID0gYXJndW1lbnRzW2ldO1xyXG4gICAgICAgICAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkpIHRbcF0gPSBzW3BdO1xyXG4gICAgICAgIH1cclxuICAgICAgICByZXR1cm4gdDtcclxuICAgIH1cclxuICAgIHJldHVybiBfX2Fzc2lnbi5hcHBseSh0aGlzLCBhcmd1bWVudHMpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19yZXN0KHMsIGUpIHtcclxuICAgIHZhciB0ID0ge307XHJcbiAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkgJiYgZS5pbmRleE9mKHApIDwgMClcclxuICAgICAgICB0W3BdID0gc1twXTtcclxuICAgIGlmIChzICE9IG51bGwgJiYgdHlwZW9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHMgPT09IFwiZnVuY3Rpb25cIilcclxuICAgICAgICBmb3IgKHZhciBpID0gMCwgcCA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHMocyk7IGkgPCBwLmxlbmd0aDsgaSsrKSB7XHJcbiAgICAgICAgICAgIGlmIChlLmluZGV4T2YocFtpXSkgPCAwICYmIE9iamVjdC5wcm90b3R5cGUucHJvcGVydHlJc0VudW1lcmFibGUuY2FsbChzLCBwW2ldKSlcclxuICAgICAgICAgICAgICAgIHRbcFtpXV0gPSBzW3BbaV1dO1xyXG4gICAgICAgIH1cclxuICAgIHJldHVybiB0O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19kZWNvcmF0ZShkZWNvcmF0b3JzLCB0YXJnZXQsIGtleSwgZGVzYykge1xyXG4gICAgdmFyIGMgPSBhcmd1bWVudHMubGVuZ3RoLCByID0gYyA8IDMgPyB0YXJnZXQgOiBkZXNjID09PSBudWxsID8gZGVzYyA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IodGFyZ2V0LCBrZXkpIDogZGVzYywgZDtcclxuICAgIGlmICh0eXBlb2YgUmVmbGVjdCA9PT0gXCJvYmplY3RcIiAmJiB0eXBlb2YgUmVmbGVjdC5kZWNvcmF0ZSA9PT0gXCJmdW5jdGlvblwiKSByID0gUmVmbGVjdC5kZWNvcmF0ZShkZWNvcmF0b3JzLCB0YXJnZXQsIGtleSwgZGVzYyk7XHJcbiAgICBlbHNlIGZvciAodmFyIGkgPSBkZWNvcmF0b3JzLmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSBpZiAoZCA9IGRlY29yYXRvcnNbaV0pIHIgPSAoYyA8IDMgPyBkKHIpIDogYyA+IDMgPyBkKHRhcmdldCwga2V5LCByKSA6IGQodGFyZ2V0LCBrZXkpKSB8fCByO1xyXG4gICAgcmV0dXJuIGMgPiAzICYmIHIgJiYgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRhcmdldCwga2V5LCByKSwgcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcGFyYW0ocGFyYW1JbmRleCwgZGVjb3JhdG9yKSB7XHJcbiAgICByZXR1cm4gZnVuY3Rpb24gKHRhcmdldCwga2V5KSB7IGRlY29yYXRvcih0YXJnZXQsIGtleSwgcGFyYW1JbmRleCk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fbWV0YWRhdGEobWV0YWRhdGFLZXksIG1ldGFkYXRhVmFsdWUpIHtcclxuICAgIGlmICh0eXBlb2YgUmVmbGVjdCA9PT0gXCJvYmplY3RcIiAmJiB0eXBlb2YgUmVmbGVjdC5tZXRhZGF0YSA9PT0gXCJmdW5jdGlvblwiKSByZXR1cm4gUmVmbGVjdC5tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2F3YWl0ZXIodGhpc0FyZywgX2FyZ3VtZW50cywgUCwgZ2VuZXJhdG9yKSB7XHJcbiAgICBmdW5jdGlvbiBhZG9wdCh2YWx1ZSkgeyByZXR1cm4gdmFsdWUgaW5zdGFuY2VvZiBQID8gdmFsdWUgOiBuZXcgUChmdW5jdGlvbiAocmVzb2x2ZSkgeyByZXNvbHZlKHZhbHVlKTsgfSk7IH1cclxuICAgIHJldHVybiBuZXcgKFAgfHwgKFAgPSBQcm9taXNlKSkoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xyXG4gICAgICAgIGZ1bmN0aW9uIGZ1bGZpbGxlZCh2YWx1ZSkgeyB0cnkgeyBzdGVwKGdlbmVyYXRvci5uZXh0KHZhbHVlKSk7IH0gY2F0Y2ggKGUpIHsgcmVqZWN0KGUpOyB9IH1cclxuICAgICAgICBmdW5jdGlvbiByZWplY3RlZCh2YWx1ZSkgeyB0cnkgeyBzdGVwKGdlbmVyYXRvcltcInRocm93XCJdKHZhbHVlKSk7IH0gY2F0Y2ggKGUpIHsgcmVqZWN0KGUpOyB9IH1cclxuICAgICAgICBmdW5jdGlvbiBzdGVwKHJlc3VsdCkgeyByZXN1bHQuZG9uZSA/IHJlc29sdmUocmVzdWx0LnZhbHVlKSA6IGFkb3B0KHJlc3VsdC52YWx1ZSkudGhlbihmdWxmaWxsZWQsIHJlamVjdGVkKTsgfVxyXG4gICAgICAgIHN0ZXAoKGdlbmVyYXRvciA9IGdlbmVyYXRvci5hcHBseSh0aGlzQXJnLCBfYXJndW1lbnRzIHx8IFtdKSkubmV4dCgpKTtcclxuICAgIH0pO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19nZW5lcmF0b3IodGhpc0FyZywgYm9keSkge1xyXG4gICAgdmFyIF8gPSB7IGxhYmVsOiAwLCBzZW50OiBmdW5jdGlvbigpIHsgaWYgKHRbMF0gJiAxKSB0aHJvdyB0WzFdOyByZXR1cm4gdFsxXTsgfSwgdHJ5czogW10sIG9wczogW10gfSwgZiwgeSwgdCwgZztcclxuICAgIHJldHVybiBnID0geyBuZXh0OiB2ZXJiKDApLCBcInRocm93XCI6IHZlcmIoMSksIFwicmV0dXJuXCI6IHZlcmIoMikgfSwgdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIChnW1N5bWJvbC5pdGVyYXRvcl0gPSBmdW5jdGlvbigpIHsgcmV0dXJuIHRoaXM7IH0pLCBnO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IHJldHVybiBmdW5jdGlvbiAodikgeyByZXR1cm4gc3RlcChbbiwgdl0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzdGVwKG9wKSB7XHJcbiAgICAgICAgaWYgKGYpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJHZW5lcmF0b3IgaXMgYWxyZWFkeSBleGVjdXRpbmcuXCIpO1xyXG4gICAgICAgIHdoaWxlIChfKSB0cnkge1xyXG4gICAgICAgICAgICBpZiAoZiA9IDEsIHkgJiYgKHQgPSBvcFswXSAmIDIgPyB5W1wicmV0dXJuXCJdIDogb3BbMF0gPyB5W1widGhyb3dcIl0gfHwgKCh0ID0geVtcInJldHVyblwiXSkgJiYgdC5jYWxsKHkpLCAwKSA6IHkubmV4dCkgJiYgISh0ID0gdC5jYWxsKHksIG9wWzFdKSkuZG9uZSkgcmV0dXJuIHQ7XHJcbiAgICAgICAgICAgIGlmICh5ID0gMCwgdCkgb3AgPSBbb3BbMF0gJiAyLCB0LnZhbHVlXTtcclxuICAgICAgICAgICAgc3dpdGNoIChvcFswXSkge1xyXG4gICAgICAgICAgICAgICAgY2FzZSAwOiBjYXNlIDE6IHQgPSBvcDsgYnJlYWs7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDQ6IF8ubGFiZWwrKzsgcmV0dXJuIHsgdmFsdWU6IG9wWzFdLCBkb25lOiBmYWxzZSB9O1xyXG4gICAgICAgICAgICAgICAgY2FzZSA1OiBfLmxhYmVsKys7IHkgPSBvcFsxXTsgb3AgPSBbMF07IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICAgICAgY2FzZSA3OiBvcCA9IF8ub3BzLnBvcCgpOyBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgICAgICAgICAgICBpZiAoISh0ID0gXy50cnlzLCB0ID0gdC5sZW5ndGggPiAwICYmIHRbdC5sZW5ndGggLSAxXSkgJiYgKG9wWzBdID09PSA2IHx8IG9wWzBdID09PSAyKSkgeyBfID0gMDsgY29udGludWU7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAob3BbMF0gPT09IDMgJiYgKCF0IHx8IChvcFsxXSA+IHRbMF0gJiYgb3BbMV0gPCB0WzNdKSkpIHsgXy5sYWJlbCA9IG9wWzFdOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gNiAmJiBfLmxhYmVsIDwgdFsxXSkgeyBfLmxhYmVsID0gdFsxXTsgdCA9IG9wOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0ICYmIF8ubGFiZWwgPCB0WzJdKSB7IF8ubGFiZWwgPSB0WzJdOyBfLm9wcy5wdXNoKG9wKTsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAodFsyXSkgXy5vcHMucG9wKCk7XHJcbiAgICAgICAgICAgICAgICAgICAgXy50cnlzLnBvcCgpOyBjb250aW51ZTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBvcCA9IGJvZHkuY2FsbCh0aGlzQXJnLCBfKTtcclxuICAgICAgICB9IGNhdGNoIChlKSB7IG9wID0gWzYsIGVdOyB5ID0gMDsgfSBmaW5hbGx5IHsgZiA9IHQgPSAwOyB9XHJcbiAgICAgICAgaWYgKG9wWzBdICYgNSkgdGhyb3cgb3BbMV07IHJldHVybiB7IHZhbHVlOiBvcFswXSA/IG9wWzFdIDogdm9pZCAwLCBkb25lOiB0cnVlIH07XHJcbiAgICB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NyZWF0ZUJpbmRpbmcobywgbSwgaywgazIpIHtcclxuICAgIGlmIChrMiA9PT0gdW5kZWZpbmVkKSBrMiA9IGs7XHJcbiAgICBvW2syXSA9IG1ba107XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2V4cG9ydFN0YXIobSwgZXhwb3J0cykge1xyXG4gICAgZm9yICh2YXIgcCBpbiBtKSBpZiAocCAhPT0gXCJkZWZhdWx0XCIgJiYgIWV4cG9ydHMuaGFzT3duUHJvcGVydHkocCkpIGV4cG9ydHNbcF0gPSBtW3BdO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX192YWx1ZXMobykge1xyXG4gICAgdmFyIHMgPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgU3ltYm9sLml0ZXJhdG9yLCBtID0gcyAmJiBvW3NdLCBpID0gMDtcclxuICAgIGlmIChtKSByZXR1cm4gbS5jYWxsKG8pO1xyXG4gICAgaWYgKG8gJiYgdHlwZW9mIG8ubGVuZ3RoID09PSBcIm51bWJlclwiKSByZXR1cm4ge1xyXG4gICAgICAgIG5leHQ6IGZ1bmN0aW9uICgpIHtcclxuICAgICAgICAgICAgaWYgKG8gJiYgaSA+PSBvLmxlbmd0aCkgbyA9IHZvaWQgMDtcclxuICAgICAgICAgICAgcmV0dXJuIHsgdmFsdWU6IG8gJiYgb1tpKytdLCBkb25lOiAhbyB9O1xyXG4gICAgICAgIH1cclxuICAgIH07XHJcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKHMgPyBcIk9iamVjdCBpcyBub3QgaXRlcmFibGUuXCIgOiBcIlN5bWJvbC5pdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3JlYWQobywgbikge1xyXG4gICAgdmFyIG0gPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgb1tTeW1ib2wuaXRlcmF0b3JdO1xyXG4gICAgaWYgKCFtKSByZXR1cm4gbztcclxuICAgIHZhciBpID0gbS5jYWxsKG8pLCByLCBhciA9IFtdLCBlO1xyXG4gICAgdHJ5IHtcclxuICAgICAgICB3aGlsZSAoKG4gPT09IHZvaWQgMCB8fCBuLS0gPiAwKSAmJiAhKHIgPSBpLm5leHQoKSkuZG9uZSkgYXIucHVzaChyLnZhbHVlKTtcclxuICAgIH1cclxuICAgIGNhdGNoIChlcnJvcikgeyBlID0geyBlcnJvcjogZXJyb3IgfTsgfVxyXG4gICAgZmluYWxseSB7XHJcbiAgICAgICAgdHJ5IHtcclxuICAgICAgICAgICAgaWYgKHIgJiYgIXIuZG9uZSAmJiAobSA9IGlbXCJyZXR1cm5cIl0pKSBtLmNhbGwoaSk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGZpbmFsbHkgeyBpZiAoZSkgdGhyb3cgZS5lcnJvcjsgfVxyXG4gICAgfVxyXG4gICAgcmV0dXJuIGFyO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19zcHJlYWQoKSB7XHJcbiAgICBmb3IgKHZhciBhciA9IFtdLCBpID0gMDsgaSA8IGFyZ3VtZW50cy5sZW5ndGg7IGkrKylcclxuICAgICAgICBhciA9IGFyLmNvbmNhdChfX3JlYWQoYXJndW1lbnRzW2ldKSk7XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZEFycmF5cygpIHtcclxuICAgIGZvciAodmFyIHMgPSAwLCBpID0gMCwgaWwgPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgaWw7IGkrKykgcyArPSBhcmd1bWVudHNbaV0ubGVuZ3RoO1xyXG4gICAgZm9yICh2YXIgciA9IEFycmF5KHMpLCBrID0gMCwgaSA9IDA7IGkgPCBpbDsgaSsrKVxyXG4gICAgICAgIGZvciAodmFyIGEgPSBhcmd1bWVudHNbaV0sIGogPSAwLCBqbCA9IGEubGVuZ3RoOyBqIDwgamw7IGorKywgaysrKVxyXG4gICAgICAgICAgICByW2tdID0gYVtqXTtcclxuICAgIHJldHVybiByO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXQodikge1xyXG4gICAgcmV0dXJuIHRoaXMgaW5zdGFuY2VvZiBfX2F3YWl0ID8gKHRoaXMudiA9IHYsIHRoaXMpIDogbmV3IF9fYXdhaXQodik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jR2VuZXJhdG9yKHRoaXNBcmcsIF9hcmd1bWVudHMsIGdlbmVyYXRvcikge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBnID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pLCBpLCBxID0gW107XHJcbiAgICByZXR1cm4gaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIpLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaWYgKGdbbl0pIGlbbl0gPSBmdW5jdGlvbiAodikgeyByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKGEsIGIpIHsgcS5wdXNoKFtuLCB2LCBhLCBiXSkgPiAxIHx8IHJlc3VtZShuLCB2KTsgfSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHJlc3VtZShuLCB2KSB7IHRyeSB7IHN0ZXAoZ1tuXSh2KSk7IH0gY2F0Y2ggKGUpIHsgc2V0dGxlKHFbMF1bM10sIGUpOyB9IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAocikgeyByLnZhbHVlIGluc3RhbmNlb2YgX19hd2FpdCA/IFByb21pc2UucmVzb2x2ZShyLnZhbHVlLnYpLnRoZW4oZnVsZmlsbCwgcmVqZWN0KSA6IHNldHRsZShxWzBdWzJdLCByKTsgfVxyXG4gICAgZnVuY3Rpb24gZnVsZmlsbCh2YWx1ZSkgeyByZXN1bWUoXCJuZXh0XCIsIHZhbHVlKTsgfVxyXG4gICAgZnVuY3Rpb24gcmVqZWN0KHZhbHVlKSB7IHJlc3VtZShcInRocm93XCIsIHZhbHVlKTsgfVxyXG4gICAgZnVuY3Rpb24gc2V0dGxlKGYsIHYpIHsgaWYgKGYodiksIHEuc2hpZnQoKSwgcS5sZW5ndGgpIHJlc3VtZShxWzBdWzBdLCBxWzBdWzFdKTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY0RlbGVnYXRvcihvKSB7XHJcbiAgICB2YXIgaSwgcDtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiwgZnVuY3Rpb24gKGUpIHsgdGhyb3cgZTsgfSksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4sIGYpIHsgaVtuXSA9IG9bbl0gPyBmdW5jdGlvbiAodikgeyByZXR1cm4gKHAgPSAhcCkgPyB7IHZhbHVlOiBfX2F3YWl0KG9bbl0odikpLCBkb25lOiBuID09PSBcInJldHVyblwiIH0gOiBmID8gZih2KSA6IHY7IH0gOiBmOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jVmFsdWVzKG8pIHtcclxuICAgIGlmICghU3ltYm9sLmFzeW5jSXRlcmF0b3IpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTeW1ib2wuYXN5bmNJdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbiAgICB2YXIgbSA9IG9bU3ltYm9sLmFzeW5jSXRlcmF0b3JdLCBpO1xyXG4gICAgcmV0dXJuIG0gPyBtLmNhbGwobykgOiAobyA9IHR5cGVvZiBfX3ZhbHVlcyA9PT0gXCJmdW5jdGlvblwiID8gX192YWx1ZXMobykgOiBvW1N5bWJvbC5pdGVyYXRvcl0oKSwgaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIpLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGkpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IGlbbl0gPSBvW25dICYmIGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7IHYgPSBvW25dKHYpLCBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCB2LmRvbmUsIHYudmFsdWUpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gc2V0dGxlKHJlc29sdmUsIHJlamVjdCwgZCwgdikgeyBQcm9taXNlLnJlc29sdmUodikudGhlbihmdW5jdGlvbih2KSB7IHJlc29sdmUoeyB2YWx1ZTogdiwgZG9uZTogZCB9KTsgfSwgcmVqZWN0KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tYWtlVGVtcGxhdGVPYmplY3QoY29va2VkLCByYXcpIHtcclxuICAgIGlmIChPYmplY3QuZGVmaW5lUHJvcGVydHkpIHsgT2JqZWN0LmRlZmluZVByb3BlcnR5KGNvb2tlZCwgXCJyYXdcIiwgeyB2YWx1ZTogcmF3IH0pOyB9IGVsc2UgeyBjb29rZWQucmF3ID0gcmF3OyB9XHJcbiAgICByZXR1cm4gY29va2VkO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9faW1wb3J0U3Rhcihtb2QpIHtcclxuICAgIGlmIChtb2QgJiYgbW9kLl9fZXNNb2R1bGUpIHJldHVybiBtb2Q7XHJcbiAgICB2YXIgcmVzdWx0ID0ge307XHJcbiAgICBpZiAobW9kICE9IG51bGwpIGZvciAodmFyIGsgaW4gbW9kKSBpZiAoT2JqZWN0Lmhhc093blByb3BlcnR5LmNhbGwobW9kLCBrKSkgcmVzdWx0W2tdID0gbW9kW2tdO1xyXG4gICAgcmVzdWx0LmRlZmF1bHQgPSBtb2Q7XHJcbiAgICByZXR1cm4gcmVzdWx0O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnREZWZhdWx0KG1vZCkge1xyXG4gICAgcmV0dXJuIChtb2QgJiYgbW9kLl9fZXNNb2R1bGUpID8gbW9kIDogeyBkZWZhdWx0OiBtb2QgfTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY2xhc3NQcml2YXRlRmllbGRHZXQocmVjZWl2ZXIsIHByaXZhdGVNYXApIHtcclxuICAgIGlmICghcHJpdmF0ZU1hcC5oYXMocmVjZWl2ZXIpKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcImF0dGVtcHRlZCB0byBnZXQgcHJpdmF0ZSBmaWVsZCBvbiBub24taW5zdGFuY2VcIik7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gcHJpdmF0ZU1hcC5nZXQocmVjZWl2ZXIpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZFNldChyZWNlaXZlciwgcHJpdmF0ZU1hcCwgdmFsdWUpIHtcclxuICAgIGlmICghcHJpdmF0ZU1hcC5oYXMocmVjZWl2ZXIpKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcImF0dGVtcHRlZCB0byBzZXQgcHJpdmF0ZSBmaWVsZCBvbiBub24taW5zdGFuY2VcIik7XHJcbiAgICB9XHJcbiAgICBwcml2YXRlTWFwLnNldChyZWNlaXZlciwgdmFsdWUpO1xyXG4gICAgcmV0dXJuIHZhbHVlO1xyXG59XHJcbiIsIm1vZHVsZS5leHBvcnRzID0gXCI8c3ZnIHZpZXdCb3g9XFxcIjAgMCAxNiAxNlxcXCIgZmlsbD1cXFwibm9uZVxcXCIgeG1sbnM9XFxcImh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnXFxcIj48cGF0aCBmaWxsLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGNsaXAtcnVsZT1cXFwiZXZlbm9kZFxcXCIgZD1cXFwiTTEuMzMzIDBoNGMuNzM3IDAgMS4zMzQuNTk3IDEuMzM0IDEuMzMzdjEuMzM0aDhDMTUuNDAzIDIuNjY3IDE2IDMuMjY0IDE2IDR2MTAuNjY3YzAgLjczNi0uNTk3IDEuMzMzLTEuMzMzIDEuMzMzSDEuMzMzQTEuMzMzIDEuMzMzIDAgMCAxIDAgMTQuNjY3VjEuMzMzQzAgLjU5Ny41OTcgMCAxLjMzMyAwWm0wIDcuMzMzdjcuMzM0aDEzLjMzNFY3LjMzM0gxLjMzNFptMC0xLjMzM2gxMy4zMzRWNEg1LjMzNFYxLjMzNWgtNFY2WlxcXCIgZmlsbD1cXFwiIzAwMFxcXCI+PC9wYXRoPjwvc3ZnPlwiIiwibW9kdWxlLmV4cG9ydHMgPSBcIjxzdmcgdmlld0JveD1cXFwiMCAwIDE2IDE2XFxcIiBmaWxsPVxcXCJub25lXFxcIiB4bWxucz1cXFwiaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmdcXFwiPjxwYXRoIGZpbGwtcnVsZT1cXFwiZXZlbm9kZFxcXCIgY2xpcC1ydWxlPVxcXCJldmVub2RkXFxcIiBkPVxcXCJNOS40MzguOTk0Yy4yMTMgMCAuMzk3LjE0Ni40NC4zNS4xNTEuNzIyLjI1NyAxLjM0LjMxNiAxLjg1Mi4zNzQuMTYuNzI1LjM2MiAxLjA0OC41OTlsMS43MjgtLjY3NmEuNDU1LjQ1NSAwIDAgMSAuNTU2LjE4OGwxLjQyIDIuMzk0YS40My40MyAwIDAgMS0uMDkxLjU0NyAyMS45OCAyMS45OCAwIDAgMS0xLjQ5IDEuMTk0IDUuMTcgNS4xNyAwIDAgMS0uMDA3IDEuMTgzbDEuNDY0IDEuMTE5YS40My40MyAwIDAgMSAuMTExLjU2M2wtMS40MiAyLjM5NGEuNDU0LjQ1NCAwIDAgMS0uNTMuMTk3IDIyLjQ0NSAyMi40NDUgMCAwIDEtMS44MDctLjY2Yy0uMzI1LjIzMy0uNjc5LjQzLTEuMDU1LjU4NmwtLjI2MyAxLjc5NGEuNDQ2LjQ0NiAwIDAgMS0uNDQ1LjM3Nkg2LjU3NGEuNDQ2LjQ0NiAwIDAgMS0uNDQtLjM1IDIxLjAxOSAyMS4wMTkgMCAwIDEtLjMxNy0xLjg1MyA1LjM0IDUuMzQgMCAwIDEtMS4wNDctLjU5OGwtMS43MjguNjc1YS40NTUuNDU1IDAgMCAxLS41NTYtLjE4N2wtMS40Mi0yLjM5NWEuNDMuNDMgMCAwIDEgLjA5MS0uNTQ2Yy41NjctLjQ5IDEuMDYzLS44ODggMS40OS0xLjE5NGE1LjE2NyA1LjE2NyAwIDAgMSAuMDA4LTEuMTgzTDEuMTkgNi4yNDNhLjQzLjQzIDAgMCAxLS4xMTItLjU2MmwxLjQyLTIuMzk1YS40NTUuNDU1IDAgMCAxIC41MzEtLjE5NmMuNzE5LjIzMyAxLjMyMS40NTMgMS44MDcuNjYuMzI0LS4yMzMuNjc5LS40MyAxLjA1Ni0uNTg3bC4yNjItMS43OTRBLjQ0Ni40NDYgMCAwIDEgNi42Ljk5NGgyLjgzOVptLS4zNjUgMUg2Ljk4NWwtLjI4IDEuODY2LS40NjcuMTljLS4yMzUuMDk1LS40Ni4yMS0uNjcyLjM0bC0uMjA3LjEzNi0uNDIuMjkzLS40NzYtLjE5N2MtLjMyOC0uMTM3LS43MTgtLjI4MS0xLjE2OS0uNDMzbC0uMjIxLS4wNzQtMS4wNDUgMS43MTlMMy41OSA2Ljk5OWwtLjA2LjQ3OWE0LjEyNyA0LjEyNyAwIDAgMC0uMDIxLjgxNmwuMDE0LjE0NC4wNTguNDkyLS40MTkuMjk0Yy0uMjg4LjIwMy0uNjE1LjQ1MS0uOTc5Ljc0NmwtLjE3Ny4xNDUgMS4wNDMgMS43MiAxLjg0NS0uNzAzLjQwNi4yOWMuMjA0LjE0Ni40Mi4yNzQuNjQ1LjM4NGwuMjI4LjEwMy40NzQuMTk5LjA1OS40OWMuMDQuMzM4LjEwMy43MzEuMTkgMS4xNzdsLjA0My4yMTloMi4wODhsLjI4Mi0xLjg2Ny40NjYtLjE5Yy4yMzYtLjA5NS40Ni0uMjEuNjcyLS4zNGwuMjA3LS4xMzYuNDE5LS4yOTMuNDc2LjE5OGMuMzMuMTM2LjcyLjI4IDEuMTcuNDMzbC4yMi4wNzIgMS4wNDQtMS43MTgtMS41Ni0xLjE2NS4wNi0uNDc5YTQuMTMxIDQuMTMxIDAgMCAwIC4wMi0uODE1bC0uMDEzLS4xNDQtLjA2LS40OTIuNDItLjI5NWExOC4xIDE4LjEgMCAwIDAgLjk4LS43NDZsLjE3Ni0uMTQ2LTEuMDQzLTEuNzItMS44NDQuNzA1LS40MDYtLjI5YTQuNDk2IDQuNDk2IDAgMCAwLS42NDYtLjM4NWwtLjIyOC0uMTAzLS40NzQtLjE5OS0uMDU4LS40OWMtLjAzMi0uMjctLjA4LS41NzYtLjE0LS45MTZsLS4wOTQtLjQ4Wm0tMS4wNjcgM2EzIDMgMCAxIDEgMCA2IDMgMyAwIDAgMSAwLTZabTAgMWEyIDIgMCAxIDAgMCA0IDIgMiAwIDAgMCAwLTRaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PC9zdmc+XCIiLCJtb2R1bGUuZXhwb3J0cyA9IFwiPHN2ZyB2aWV3Qm94PVxcXCIwIDAgMTYgMTZcXFwiIGZpbGw9XFxcIm5vbmVcXFwiIHhtbG5zPVxcXCJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2Z1xcXCI+PHBhdGggZmlsbC1ydWxlPVxcXCJldmVub2RkXFxcIiBjbGlwLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGQ9XFxcIk0xNCA4QTYgNiAwIDEgMSAyIDhhNiA2IDAgMCAxIDEyIDBabTEgMEE3IDcgMCAxIDEgMSA4YTcgNyAwIDAgMSAxNCAwWk03LjUgNC41YS41LjUgMCAwIDEgMSAwdjNoM2EuNS41IDAgMCAxIDAgMWgtM3YzYS41LjUgMCAwIDEtMSAwdi0zaC0zYS41LjUgMCAwIDEgMC0xaDN2LTNaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PC9zdmc+XCIiLCJtb2R1bGUuZXhwb3J0cyA9IFwiPHN2ZyB2aWV3Qm94PVxcXCIwIDAgMTYgMTZcXFwiIGZpbGw9XFxcIm5vbmVcXFwiIHhtbG5zPVxcXCJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2Z1xcXCI+PHBhdGggZD1cXFwiTTYgNi41YS41LjUgMCAwIDEgMSAwdjZhLjUuNSAwIDAgMS0xIDB2LTZaTTkuNSA2YS41LjUgMCAwIDAtLjUuNXY2YS41LjUgMCAwIDAgMSAwdi02YS41LjUgMCAwIDAtLjUtLjVaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PHBhdGggZmlsbC1ydWxlPVxcXCJldmVub2RkXFxcIiBjbGlwLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGQ9XFxcIk0xMSAwSDVhMSAxIDAgMCAwLTEgMXYySC41YS41LjUgMCAwIDAgMCAxaDEuNmwuODEgMTEuMWExIDEgMCAwIDAgLjk5NS45aDguMTlhMSAxIDAgMCAwIC45OTUtLjlMMTMuOSA0aDEuNmEuNS41IDAgMCAwIDAtMUgxMlYxYTEgMSAwIDAgMC0xLTFabTAgM1YxSDV2Mmg2Wm0xLjg5NSAxaC05Ljc5bC44IDExaDguMTlsLjgtMTFaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PC9zdmc+XCIiLCJtb2R1bGUuZXhwb3J0cyA9IFwiPHN2ZyB2aWV3Qm94PVxcXCIwIDAgMTYgMTZcXFwiIGZpbGw9XFxcIm5vbmVcXFwiIHhtbG5zPVxcXCJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2Z1xcXCI+PHBhdGggZD1cXFwibTcgMTEuNSA1LjM1NC01LjM1NC0uNzA4LS43MDdMNyAxMC4wODYgNC4zNTQgNy40MzlsLS43MDguNzA3TDcgMTEuNVpcXFwiIGZpbGw9XFxcIiMwMDBcXFwiPjwvcGF0aD48cGF0aCBmaWxsLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGNsaXAtcnVsZT1cXFwiZXZlbm9kZFxcXCIgZD1cXFwiTTAgOGE4IDggMCAxIDAgMTYgMEE4IDggMCAwIDAgMCA4Wm0xNSAwQTcgNyAwIDEgMSAxIDhhNyA3IDAgMCAxIDE0IDBaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PC9zdmc+XCIiLCJpbXBvcnQgeyBSZWFjdCwgY2xhc3NOYW1lcyB9IGZyb20gJ2ppbXUtY29yZSdcclxuaW1wb3J0IHsgdHlwZSBTVkdDb21wb25lbnRQcm9wcyB9IGZyb20gJ2ppbXUtdWknXHJcbmltcG9ydCBzcmMgZnJvbSAnLi4vLi4vc3ZnL291dGxpbmVkL2FwcGxpY2F0aW9uL2ZvbGRlci5zdmcnXHJcblxyXG5leHBvcnQgY29uc3QgRm9sZGVyT3V0bGluZWQgPSAocHJvcHM6IFNWR0NvbXBvbmVudFByb3BzKSA9PiB7XHJcbiAgY29uc3QgU1ZHID0gd2luZG93LlNWR1xyXG4gIGNvbnN0IHsgY2xhc3NOYW1lLCAuLi5vdGhlcnMgfSA9IHByb3BzXHJcblxyXG4gIGNvbnN0IGNsYXNzZXMgPSBjbGFzc05hbWVzKCdqaW11LWljb24gamltdS1pY29uLWNvbXBvbmVudCcsIGNsYXNzTmFtZSlcclxuICBpZiAoIVNWRykgcmV0dXJuIDxzdmcgY2xhc3NOYW1lPXtjbGFzc2VzfSB7Li4ub3RoZXJzIGFzIGFueX0gLz5cclxuICByZXR1cm4gPFNWRyBjbGFzc05hbWU9e2NsYXNzZXN9IHNyYz17c3JjfSB7Li4ub3RoZXJzfSAvPlxyXG59XHJcbiIsImltcG9ydCB7IFJlYWN0LCBjbGFzc05hbWVzIH0gZnJvbSAnamltdS1jb3JlJ1xyXG5pbXBvcnQgeyB0eXBlIFNWR0NvbXBvbmVudFByb3BzIH0gZnJvbSAnamltdS11aSdcclxuaW1wb3J0IHNyYyBmcm9tICcuLi8uLi9zdmcvb3V0bGluZWQvYXBwbGljYXRpb24vc2V0dGluZy5zdmcnXHJcblxyXG5leHBvcnQgY29uc3QgU2V0dGluZ091dGxpbmVkID0gKHByb3BzOiBTVkdDb21wb25lbnRQcm9wcykgPT4ge1xyXG4gIGNvbnN0IFNWRyA9IHdpbmRvdy5TVkdcclxuICBjb25zdCB7IGNsYXNzTmFtZSwgLi4ub3RoZXJzIH0gPSBwcm9wc1xyXG5cclxuICBjb25zdCBjbGFzc2VzID0gY2xhc3NOYW1lcygnamltdS1pY29uIGppbXUtaWNvbi1jb21wb25lbnQnLCBjbGFzc05hbWUpXHJcbiAgaWYgKCFTVkcpIHJldHVybiA8c3ZnIGNsYXNzTmFtZT17Y2xhc3Nlc30gey4uLm90aGVycyBhcyBhbnl9IC8+XHJcbiAgcmV0dXJuIDxTVkcgY2xhc3NOYW1lPXtjbGFzc2VzfSBzcmM9e3NyY30gey4uLm90aGVyc30gLz5cclxufVxyXG4iLCJpbXBvcnQgeyBSZWFjdCwgY2xhc3NOYW1lcyB9IGZyb20gJ2ppbXUtY29yZSdcclxuaW1wb3J0IHsgdHlwZSBTVkdDb21wb25lbnRQcm9wcyB9IGZyb20gJ2ppbXUtdWknXHJcbmltcG9ydCBzcmMgZnJvbSAnLi4vLi4vc3ZnL291dGxpbmVkL2VkaXRvci9wbHVzLWNpcmNsZS5zdmcnXHJcblxyXG5leHBvcnQgY29uc3QgUGx1c0NpcmNsZU91dGxpbmVkID0gKHByb3BzOiBTVkdDb21wb25lbnRQcm9wcykgPT4ge1xyXG4gIGNvbnN0IFNWRyA9IHdpbmRvdy5TVkdcclxuICBjb25zdCB7IGNsYXNzTmFtZSwgLi4ub3RoZXJzIH0gPSBwcm9wc1xyXG5cclxuICBjb25zdCBjbGFzc2VzID0gY2xhc3NOYW1lcygnamltdS1pY29uIGppbXUtaWNvbi1jb21wb25lbnQnLCBjbGFzc05hbWUpXHJcbiAgaWYgKCFTVkcpIHJldHVybiA8c3ZnIGNsYXNzTmFtZT17Y2xhc3Nlc30gey4uLm90aGVycyBhcyBhbnl9IC8+XHJcbiAgcmV0dXJuIDxTVkcgY2xhc3NOYW1lPXtjbGFzc2VzfSBzcmM9e3NyY30gey4uLm90aGVyc30gLz5cclxufVxyXG4iLCJpbXBvcnQgeyBSZWFjdCwgY2xhc3NOYW1lcyB9IGZyb20gJ2ppbXUtY29yZSdcclxuaW1wb3J0IHsgdHlwZSBTVkdDb21wb25lbnRQcm9wcyB9IGZyb20gJ2ppbXUtdWknXHJcbmltcG9ydCBzcmMgZnJvbSAnLi4vLi4vc3ZnL291dGxpbmVkL2VkaXRvci90cmFzaC5zdmcnXHJcblxyXG5leHBvcnQgY29uc3QgVHJhc2hPdXRsaW5lZCA9IChwcm9wczogU1ZHQ29tcG9uZW50UHJvcHMpID0+IHtcclxuICBjb25zdCBTVkcgPSB3aW5kb3cuU1ZHXHJcbiAgY29uc3QgeyBjbGFzc05hbWUsIC4uLm90aGVycyB9ID0gcHJvcHNcclxuXHJcbiAgY29uc3QgY2xhc3NlcyA9IGNsYXNzTmFtZXMoJ2ppbXUtaWNvbiBqaW11LWljb24tY29tcG9uZW50JywgY2xhc3NOYW1lKVxyXG4gIGlmICghU1ZHKSByZXR1cm4gPHN2ZyBjbGFzc05hbWU9e2NsYXNzZXN9IHsuLi5vdGhlcnMgYXMgYW55fSAvPlxyXG4gIHJldHVybiA8U1ZHIGNsYXNzTmFtZT17Y2xhc3Nlc30gc3JjPXtzcmN9IHsuLi5vdGhlcnN9IC8+XHJcbn1cclxuIiwiaW1wb3J0IHsgUmVhY3QsIGNsYXNzTmFtZXMgfSBmcm9tICdqaW11LWNvcmUnXHJcbmltcG9ydCB7IHR5cGUgU1ZHQ29tcG9uZW50UHJvcHMgfSBmcm9tICdqaW11LXVpJ1xyXG5pbXBvcnQgc3JjIGZyb20gJy4uLy4uL3N2Zy9vdXRsaW5lZC9zdWdnZXN0ZWQvc3VjY2Vzcy5zdmcnXHJcblxyXG5leHBvcnQgY29uc3QgU3VjY2Vzc091dGxpbmVkID0gKHByb3BzOiBTVkdDb21wb25lbnRQcm9wcykgPT4ge1xyXG4gIGNvbnN0IFNWRyA9IHdpbmRvdy5TVkdcclxuICBjb25zdCB7IGNsYXNzTmFtZSwgLi4ub3RoZXJzIH0gPSBwcm9wc1xyXG5cclxuICBjb25zdCBjbGFzc2VzID0gY2xhc3NOYW1lcygnamltdS1pY29uIGppbXUtaWNvbi1jb21wb25lbnQnLCBjbGFzc05hbWUpXHJcbiAgaWYgKCFTVkcpIHJldHVybiA8c3ZnIGNsYXNzTmFtZT17Y2xhc3Nlc30gey4uLm90aGVycyBhcyBhbnl9IC8+XHJcbiAgcmV0dXJuIDxTVkcgY2xhc3NOYW1lPXtjbGFzc2VzfSBzcmM9e3NyY30gey4uLm90aGVyc30gLz5cclxufVxyXG4iLCJpbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCI7XHJcbmltcG9ydCB7XHJcbiAgQXBwV2lkZ2V0Q29uZmlnLCBBc3Nlc3NtZW50LCBcclxuICBDbHNzUmVzcG9uc2UsXHJcbiAgQ0xTU1RlbXBsYXRlLCBcclxuICBDb21wb25lbnRUZW1wbGF0ZSwgXHJcbiAgSGF6YXJkLFxyXG4gIEluY2lkZW50LFxyXG4gIEluQ29tbWVudCxcclxuICBJbmRpY2F0b3JBc3Nlc3NtZW50LFxyXG4gIEluZGljYXRvclRlbXBsYXRlLCBJbmRpY2F0b3JXZWlnaHQsIExpZmVsaW5lU3RhdHVzLCBMaWZlTGluZVRlbXBsYXRlLFxyXG4gIE9yZ2FuaXphdGlvbiwgU2NhbGVGYWN0b3JcclxufSBmcm9tIFwiLi9kYXRhLWRlZmluaXRpb25zXCI7XHJcbmltcG9ydCB7XHJcbiAgQVNTRVNTTUVOVF9VUkxfRVJST1IsIFxyXG4gIEJBU0VMSU5FX1RFTVBMQVRFX05BTUUsIFxyXG4gIENPTVBPTkVOVF9VUkxfRVJST1IsIEVOVklST05NRU5UX1BSRVNFUlZBVElPTiwgSEFaQVJEX1VSTF9FUlJPUiwgSU5DSURFTlRfU1RBQklMSVpBVElPTiwgSU5DSURFTlRfVVJMX0VSUk9SLCBJTkRJQ0FUT1JfVVJMX0VSUk9SLFxyXG4gIExJRkVfU0FGRVRZLFxyXG4gIExJRkVfU0FGRVRZX1NDQUxFX0ZBQ1RPUixcclxuICBMSUZFTElORV9VUkxfRVJST1IsIE1BWElNVU1fV0VJR0hULCBPUkdBTklaQVRJT05fVVJMX0VSUk9SLCBPVEhFUl9XRUlHSFRTX1NDQUxFX0ZBQ1RPUiwgXHJcbiAgUE9SVEFMX1VSTCwgXHJcbiAgUFJPUEVSVFlfUFJPVEVDVElPTiwgXHJcbiAgUkFOSywgXHJcbiAgVEVNUExBVEVfVVJMX0VSUk9SfSBmcm9tIFwiLi9jb25zdGFudHNcIjtcclxuaW1wb3J0IHsgZ2V0QXBwU3RvcmUgfSBmcm9tIFwiamltdS1jb3JlXCI7XHJcbmltcG9ydCB7XHJcbiAgSUZlYXR1cmUsIElGZWF0dXJlU2V0LCBJRmllbGR9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyXCI7XHJcbmltcG9ydCB7IHF1ZXJ5VGFibGVGZWF0dXJlcywgXHJcbiAgIHVwZGF0ZVRhYmxlRmVhdHVyZSwgZGVsZXRlVGFibGVGZWF0dXJlcywgXHJcbiAgICBhZGRUYWJsZUZlYXR1cmVzLCB1cGRhdGVUYWJsZUZlYXR1cmVzLCBxdWVyeVRhYmxlRmVhdHVyZVNldCB9IGZyb20gXCIuL2VzcmktYXBpXCI7XHJcbmltcG9ydCB7IGxvZywgTG9nVHlwZSB9IGZyb20gXCIuL2xvZ2dlclwiO1xyXG5pbXBvcnQgeyBJQ29kZWRWYWx1ZSB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC10eXBlc1wiO1xyXG5pbXBvcnQgeyBjaGVja0N1cnJlbnRTdGF0dXMsIHNpZ25JbiB9IGZyb20gXCIuL2F1dGhcIjtcclxuaW1wb3J0IHsgQ0xTU0FjdGlvbktleXMgfSBmcm9tIFwiLi9jbHNzLXN0b3JlXCI7XHJcbmltcG9ydCB7IElDcmVkZW50aWFsIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LWF1dGhcIjtcclxuaW1wb3J0IHsgcGFyc2VEYXRlIH0gZnJvbSBcIi4vdXRpbHNcIjtcclxuXHJcblxyXG4vLz09PT09PT09PT09PT09PT09PT09PT09PVBVQkxJQz09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cclxuXHJcbmV4cG9ydCBjb25zdCBpbml0aWFsaXplQXV0aCA9IGFzeW5jKGFwcElkOiBzdHJpbmcpID0+eyAgIFxyXG4gIGNvbnNvbGUubG9nKCdpbml0aWFsaXplQXV0aCBjYWxsZWQnKVxyXG4gIGxldCBjcmVkID0gYXdhaXQgY2hlY2tDdXJyZW50U3RhdHVzKGFwcElkLCBQT1JUQUxfVVJMKTtcclxuXHJcbiAgaWYoIWNyZWQpe1xyXG4gICAgY3JlZCA9IGF3YWl0IHNpZ25JbihhcHBJZCwgUE9SVEFMX1VSTCk7ICAgIFxyXG4gIH1cclxuXHJcbiAgY29uc3QgY3JlZGVudGlhbCA9IHtcclxuICAgIGV4cGlyZXM6IGNyZWQuZXhwaXJlcyxcclxuICAgIHNlcnZlcjogY3JlZC5zZXJ2ZXIsXHJcbiAgICBzc2w6IGNyZWQuc3NsLFxyXG4gICAgdG9rZW46IGNyZWQudG9rZW4sXHJcbiAgICB1c2VySWQ6IGNyZWQudXNlcklkXHJcbiAgfSBhcyBJQ3JlZGVudGlhbFxyXG5cclxuICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5BVVRIRU5USUNBVEVfQUNUSU9OLCBjcmVkZW50aWFsKTsgXHJcbn1cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHVwZGF0ZUxpZmVsaW5lU3RhdHVzKGxpZmVsaW5lU3RhdHVzOiBMaWZlbGluZVN0YXR1cywgXHJcbiAgY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIGFzc2Vzc21lbnRPYmplY3RJZDogbnVtYmVyLCAgdXNlcjogc3RyaW5nKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gIFxyXG4gIGNvbnNvbGUubG9nKCdjYWxsZWQgdXBkYXRlTGlmZWxpbmVTdGF0dXMnKVxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmxpZmVsaW5lU3RhdHVzLCAnTGlmZWxpbmUgU3RhdHVzIFVSTCBub3QgcHJvdmlkZWQnKTtcclxuXHJcbiAgY29uc3QgYXR0cmlidXRlcyA9IHtcclxuICAgIE9CSkVDVElEOiBsaWZlbGluZVN0YXR1cy5vYmplY3RJZCxcclxuICAgIFNjb3JlOiBsaWZlbGluZVN0YXR1cy5zY29yZSwgXHJcbiAgICBDb2xvcjogbGlmZWxpbmVTdGF0dXMuY29sb3IsIFxyXG4gICAgSXNPdmVycmlkZW46IGxpZmVsaW5lU3RhdHVzLmlzT3ZlcnJpZGVuLCBcclxuICAgIE92ZXJyaWRlblNjb3JlOiBsaWZlbGluZVN0YXR1cy5vdmVycmlkZVNjb3JlLCAgXHJcbiAgICBPdmVycmlkZW5Db2xvcjogbGlmZWxpbmVTdGF0dXMub3ZlcnJpZGVuQ29sb3IsXHJcbiAgICBPdmVycmlkZW5CeTogbGlmZWxpbmVTdGF0dXMub3ZlcnJpZGVuQnksICBcclxuICAgIE92ZXJyaWRlQ29tbWVudDogbGlmZWxpbmVTdGF0dXMub3ZlcnJpZGVDb21tZW50IFxyXG4gIH1cclxuICBsZXQgcmVzcG9uc2UgID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy5saWZlbGluZVN0YXR1cywgYXR0cmlidXRlcywgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuXHJcbiAgICBjb25zdCBpYUZlYXR1cmVzID0gbGlmZWxpbmVTdGF0dXMuaW5kaWNhdG9yQXNzZXNzbWVudHMubWFwKGkgPT4ge1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgIE9CSkVDVElEOiBpLm9iamVjdElkLFxyXG4gICAgICAgICAgc3RhdHVzOiBpLnN0YXR1cyxcclxuICAgICAgICAgIENvbW1lbnRzOiBpLmNvbW1lbnRzICYmIGkuY29tbWVudHMubGVuZ3RoID4gMCA/IEpTT04uc3RyaW5naWZ5KGkuY29tbWVudHMpOiAnJ1xyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG4gICAgfSlcclxuXHJcbiAgICByZXNwb25zZSA9IGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBpYUZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcblxyXG4gICAgICBjb25zdCBhc3Nlc3NGZWF0dXJlID0ge1xyXG4gICAgICAgIE9CSkVDVElEOiBhc3Nlc3NtZW50T2JqZWN0SWQsXHJcbiAgICAgICAgRWRpdGVkRGF0ZTogbmV3IERhdGUoKS5nZXRUaW1lKCksXHJcbiAgICAgICAgRWRpdG9yOiB1c2VyXHJcbiAgICAgIH1cclxuICAgICAgcmVzcG9uc2UgPSBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmUoY29uZmlnLmFzc2Vzc21lbnRzLCBhc3Nlc3NGZWF0dXJlLCBjb25maWcpXHJcbiAgICAgIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcbiAgICB9ICAgIFxyXG4gIH1cclxuICBsb2coJ1VwZGF0aW5nIExpZmVsaW5lIHNjb3JlIGZhaWxlZCcsIExvZ1R5cGUuRVJST1IsICd1cGRhdGVMaWZlbGluZVN0YXR1cycpO1xyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdVcGRhdGluZyBMaWZlbGluZSBzY29yZSBmYWlsZWQnXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY29tcGxldGVBc3Nlc3NtZW50KGFzc2Vzc21lbnQ6IEFzc2Vzc21lbnQsIFxyXG4gIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCB1c2VyTmFtZTogc3RyaW5nKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gICBjaGVja1BhcmFtKGNvbmZpZy5hc3Nlc3NtZW50cywgJ05vIEFzc2Vzc21lbnQgVXJsIHByb3ZpZGVkJyk7XHJcblxyXG4gICBjb25zdCByZXNwb25zZSA9ICBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmUoY29uZmlnLmFzc2Vzc21lbnRzLCB7XHJcbiAgICAgIE9CSkVDVElEOiBhc3Nlc3NtZW50Lm9iamVjdElkLFxyXG4gICAgICBFZGl0b3I6IHVzZXJOYW1lLFxyXG4gICAgICBFZGl0ZWREYXRlOiBuZXcgRGF0ZSgpLmdldFRpbWUoKSxcclxuICAgICAgSXNDb21wbGV0ZWQ6IDFcclxuICAgfSwgY29uZmlnKTtcclxuICAgY29uc29sZS5sb2cocmVzcG9uc2UpO1xyXG4gICByZXR1cm57XHJcbiAgICAgZGF0YTogcmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKVxyXG4gICB9XHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBwYXNzRGF0YUludGVncml0eSA9IGFzeW5jIChzZXJ2aWNlVXJsOiBzdHJpbmcsIGZpZWxkczogSUZpZWxkW10sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKSA9PiB7XHJcblxyXG4gIGNoZWNrUGFyYW0oc2VydmljZVVybCwgJ1NlcnZpY2UgVVJMIG5vdCBwcm92aWRlZCcpO1xyXG5cclxuICAvLyBzZXJ2aWNlVXJsID0gYCR7c2VydmljZVVybH0/Zj1qc29uJnRva2VuPSR7dG9rZW59YDtcclxuICAvLyBjb25zdCByZXNwb25zZSA9IGF3YWl0IGZldGNoKHNlcnZpY2VVcmwsIHtcclxuICAvLyAgIG1ldGhvZDogXCJHRVRcIixcclxuICAvLyAgIGhlYWRlcnM6IHtcclxuICAvLyAgICAgJ2NvbnRlbnQtdHlwZSc6ICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbiAgLy8gICB9XHJcbiAgLy8gfVxyXG4gIC8vICk7XHJcbiAgLy8gY29uc3QganNvbiA9IGF3YWl0IHJlc3BvbnNlLmpzb24oKTtcclxuXHJcbiAgLy8gY29uc3QgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoc2VydmljZVVybCwgJzE9MScsIGNvbmZpZyk7XHJcblxyXG4gIC8vIGNvbnN0IGRhdGFGaWVsZHMgPSBmZWF0dXJlc1swXS4gYXMgSUZpZWxkW107XHJcblxyXG4gIC8vIGRlYnVnZ2VyO1xyXG4gIC8vIGlmIChmaWVsZHMubGVuZ3RoID4gZGF0YUZpZWxkcy5sZW5ndGgpIHtcclxuICAvLyAgIHRocm93IG5ldyBFcnJvcignTnVtYmVyIG9mIGZpZWxkcyBkbyBub3QgbWF0Y2ggZm9yICcgKyBzZXJ2aWNlVXJsKTtcclxuICAvLyB9XHJcblxyXG4gIC8vIGNvbnN0IGFsbEZpZWxkc0dvb2QgPSBmaWVsZHMuZXZlcnkoZiA9PiB7XHJcbiAgLy8gICBjb25zdCBmb3VuZCA9IGRhdGFGaWVsZHMuZmluZChmMSA9PiBmMS5uYW1lID09PSBmLm5hbWUgJiYgZjEudHlwZS50b1N0cmluZygpID09PSBmLnR5cGUudG9TdHJpbmcoKSAmJiBmMS5kb21haW4gPT0gZi5kb21haW4pO1xyXG4gIC8vICAgcmV0dXJuIGZvdW5kO1xyXG4gIC8vIH0pO1xyXG5cclxuICAvLyBpZiAoIWFsbEZpZWxkc0dvb2QpIHtcclxuICAvLyAgIHRocm93IG5ldyBFcnJvcignSW52YWxpZCBmaWVsZHMgaW4gdGhlIGZlYXR1cmUgc2VydmljZSAnICsgc2VydmljZVVybClcclxuICAvLyB9XHJcbiAgcmV0dXJuIHRydWU7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldEluZGljYXRvckZlYXR1cmVzKHF1ZXJ5OiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVtdPntcclxuICBjb25zb2xlLmxvZygnZ2V0IEluZGljYXRvcnMgY2FsbGVkJyk7XHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9ycywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldFdlaWdodHNGZWF0dXJlcyhxdWVyeTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVbXT57XHJcbiAgY29uc29sZS5sb2coJ2dldCBXZWlnaHRzIGNhbGxlZCcpO1xyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLndlaWdodHMsIHF1ZXJ5LCBjb25maWcpO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRMaWZlbGluZUZlYXR1cmVzKHF1ZXJ5OiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVtdPntcclxuICBjb25zb2xlLmxvZygnZ2V0IExpZmVsaW5lIGNhbGxlZCcpO1xyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lcywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldENvbXBvbmVudEZlYXR1cmVzKHF1ZXJ5OiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVtdPntcclxuICBjb25zb2xlLmxvZygnZ2V0IENvbXBvbmVudHMgY2FsbGVkJyk7XHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuY29tcG9uZW50cywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldFRlbXBsYXRlRmVhdHVyZVNldChxdWVyeTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVTZXQ+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgVGVtcGxhdGUgY2FsbGVkJyk7XHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlU2V0KGNvbmZpZy50ZW1wbGF0ZXMsIHF1ZXJ5LCBjb25maWcpO1xyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0VGVtcGxhdGVzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCB0ZW1wbGF0ZUlkPzogc3RyaW5nLCBxdWVyeVN0cmluZz86c3RyaW5nKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Q0xTU1RlbXBsYXRlW10+PiB7XHJcblxyXG4gIGNvbnN0IHRlbXBsYXRlVXJsID0gY29uZmlnLnRlbXBsYXRlcztcclxuICBjb25zdCBsaWZlbGluZVVybCA9IGNvbmZpZy5saWZlbGluZXM7XHJcbiAgY29uc3QgY29tcG9uZW50VXJsID0gY29uZmlnLmNvbXBvbmVudHM7XHJcblxyXG4gIHRyeXtcclxuICAgIGNoZWNrUGFyYW0odGVtcGxhdGVVcmwsIFRFTVBMQVRFX1VSTF9FUlJPUik7XHJcbiAgICBjaGVja1BhcmFtKGxpZmVsaW5lVXJsLCBMSUZFTElORV9VUkxfRVJST1IpO1xyXG4gICAgY2hlY2tQYXJhbShjb21wb25lbnRVcmwsIENPTVBPTkVOVF9VUkxfRVJST1IpO1xyXG5cclxuICAgIGNvbnN0IHRlbXBRdWVyeSA9IHRlbXBsYXRlSWQgPyBgR2xvYmFsSUQ9JyR7dGVtcGxhdGVJZH1gIDoocXVlcnlTdHJpbmcgPyBxdWVyeVN0cmluZyA6ICcxPTEnICk7XHJcblxyXG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBQcm9taXNlLmFsbChbXHJcbiAgICAgIGdldFRlbXBsYXRlRmVhdHVyZVNldCh0ZW1wUXVlcnksIGNvbmZpZyksXHJcbiAgICAgIGdldExpZmVsaW5lRmVhdHVyZXMoJzE9MScsIGNvbmZpZyksIFxyXG4gICAgICBnZXRDb21wb25lbnRGZWF0dXJlcygnMT0xJywgY29uZmlnKV0pO1xyXG4gICAgXHJcbiAgICBjb25zdCB0ZW1wbGF0ZUZlYXR1cmVTZXQgPSByZXNwb25zZVswXTtcclxuICAgIGNvbnN0IGxpZmVsaW5lRmVhdHVyZXMgPSByZXNwb25zZVsxXTtcclxuICAgIGNvbnN0IGNvbXBvbmVudEZlYXR1cmVzID0gcmVzcG9uc2VbMl07XHJcblxyXG4gICAgY29uc3QgaW5kaWNhdG9yRmVhdHVyZXMgPSBhd2FpdCBnZXRJbmRpY2F0b3JGZWF0dXJlcygnMT0xJywgY29uZmlnKTtcclxuICAgIGNvbnN0IHdlaWdodEZlYXR1cmVzID0gYXdhaXQgZ2V0V2VpZ2h0c0ZlYXR1cmVzKCcxPTEnLCBjb25maWcpO1xyXG5cclxuICAgIGNvbnN0IHRlbXBsYXRlcyA9IGF3YWl0IFByb21pc2UuYWxsKHRlbXBsYXRlRmVhdHVyZVNldC5mZWF0dXJlcy5tYXAoYXN5bmMgKHRlbXBsYXRlRmVhdHVyZTogSUZlYXR1cmUpID0+IHtcclxuICAgICAgY29uc3QgdGVtcGxhdGVJbmRpY2F0b3JGZWF0dXJlcyA9IGluZGljYXRvckZlYXR1cmVzLmZpbHRlcihpID0+aS5hdHRyaWJ1dGVzLlRlbXBsYXRlSUQgPT0gdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQpICAgICAgXHJcbiAgICAgIHJldHVybiBhd2FpdCBnZXRUZW1wbGF0ZSh0ZW1wbGF0ZUZlYXR1cmUsIGxpZmVsaW5lRmVhdHVyZXMsIGNvbXBvbmVudEZlYXR1cmVzLCBcclxuICAgICAgICB0ZW1wbGF0ZUluZGljYXRvckZlYXR1cmVzLCB3ZWlnaHRGZWF0dXJlcywgXHJcbiAgICAgICAgdGVtcGxhdGVGZWF0dXJlU2V0LmZpZWxkcy5maW5kKGYgPT4gZi5uYW1lID09PSAnU3RhdHVzJykuZG9tYWluLmNvZGVkVmFsdWVzKVxyXG4gICAgfSkpO1xyXG5cclxuICAgIGlmKHRlbXBsYXRlcy5maWx0ZXIodCA9PiB0LmlzU2VsZWN0ZWQpLmxlbmd0aCA+IDEgfHwgdGVtcGxhdGVzLmZpbHRlcih0ID0+IHQuaXNTZWxlY3RlZCkubGVuZ3RoID09IDApe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IHRlbXBsYXRlcy5tYXAodCA9PiB7XHJcbiAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAuLi50LFxyXG4gICAgICAgICAgICBpc1NlbGVjdGVkOiB0Lm5hbWUgPT09IEJBU0VMSU5FX1RFTVBMQVRFX05BTUVcclxuICAgICAgICAgIH1cclxuICAgICAgICB9KVxyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgaWYodGVtcGxhdGVzLmxlbmd0aCA9PT0gMSl7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogdGVtcGxhdGVzLm1hcCh0ID0+IHtcclxuICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgIC4uLnQsXHJcbiAgICAgICAgICAgIGlzU2VsZWN0ZWQ6IHRydWVcclxuICAgICAgICAgIH1cclxuICAgICAgICB9KVxyXG4gICAgICB9XHJcbiAgICB9XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB0ZW1wbGF0ZXNcclxuICAgIH1cclxuICB9XHJcbiAgY2F0Y2goZSl7IFxyXG4gICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdnZXRUZW1wbGF0ZXMnKTtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGVycm9yczogJ1RlbXBsYXRlcyByZXF1ZXN0IGZhaWxlZC4nXHJcbiAgICB9XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gdXNlRmV0Y2hEYXRhPFQ+KHVybDogc3RyaW5nLCBjYWxsYmFja0FkYXB0ZXI/OiBGdW5jdGlvbik6IFtULCBGdW5jdGlvbiwgYm9vbGVhbiwgc3RyaW5nXSB7XHJcbiAgY29uc3QgW2RhdGEsIHNldERhdGFdID0gUmVhY3QudXNlU3RhdGUobnVsbCk7XHJcbiAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gUmVhY3QudXNlU3RhdGUodHJ1ZSk7XHJcbiAgY29uc3QgW2Vycm9yLCBzZXRFcnJvcl0gPSBSZWFjdC51c2VTdGF0ZSgnJyk7XHJcblxyXG4gIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICBjb25zdCBjb250cm9sbGVyID0gbmV3IEFib3J0Q29udHJvbGxlcigpO1xyXG4gICAgcmVxdWVzdERhdGEodXJsLCBjb250cm9sbGVyKVxyXG4gICAgICAudGhlbigoZGF0YSkgPT4ge1xyXG4gICAgICAgIGlmIChjYWxsYmFja0FkYXB0ZXIpIHtcclxuICAgICAgICAgIHNldERhdGEoY2FsbGJhY2tBZGFwdGVyKGRhdGEpKTtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgc2V0RGF0YShkYXRhKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XHJcbiAgICAgIH0pXHJcbiAgICAgIC5jYXRjaCgoZXJyKSA9PiB7XHJcbiAgICAgICAgY29uc29sZS5sb2coZXJyKTtcclxuICAgICAgICBzZXRFcnJvcihlcnIpO1xyXG4gICAgICB9KVxyXG4gICAgcmV0dXJuICgpID0+IGNvbnRyb2xsZXIuYWJvcnQoKTtcclxuICB9LCBbdXJsXSlcclxuXHJcbiAgcmV0dXJuIFtkYXRhLCBzZXREYXRhLCBsb2FkaW5nLCBlcnJvcl1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIGRpc3BhdGNoQWN0aW9uKHR5cGU6IGFueSwgdmFsOiBhbnkpIHtcclxuICBnZXRBcHBTdG9yZSgpLmRpc3BhdGNoKHtcclxuICAgIHR5cGUsXHJcbiAgICB2YWxcclxuICB9KTtcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldEluY2lkZW50cyhjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SW5jaWRlbnRbXT4ge1xyXG4gICBcclxuICBjb25zb2xlLmxvZygnZ2V0IGluY2lkZW50cyBjYWxsZWQuJylcclxuICBjaGVja1BhcmFtKGNvbmZpZy5pbmNpZGVudHMsIElOQ0lERU5UX1VSTF9FUlJPUik7XHJcblxyXG4gIGNvbnN0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmNpZGVudHMsICcxPTEnLCBjb25maWcpO1xyXG5cclxuICBjb25zdCBxdWVyeSA9IGBHbG9iYWxJRCBJTiAoJHtmZWF0dXJlcy5tYXAoZiA9PiBmLmF0dHJpYnV0ZXMuSGF6YXJkSUQpLm1hcChpZCA9PiBgJyR7aWR9J2ApLmpvaW4oJywnKX0pYDtcclxuICBcclxuICBjb25zdCBoYXphcmRGZWF0dXJlc2V0ID0gYXdhaXQgZ2V0SGF6YXJkRmVhdHVyZXMoY29uZmlnLCBxdWVyeSwgJ2dldEluY2lkZW50cycpO1xyXG5cclxuICByZXR1cm4gZmVhdHVyZXMubWFwKChmOiBJRmVhdHVyZSkgPT57XHJcbiAgICAgIGNvbnN0IGhmID0gaGF6YXJkRmVhdHVyZXNldC5mZWF0dXJlcy5maW5kKGggPT4gaC5hdHRyaWJ1dGVzLkdsb2JhbElEID09IGYuYXR0cmlidXRlcy5IYXphcmRJRClcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBvYmplY3RJZDogZi5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICAgIGlkOiBmLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgICAgbmFtZTogZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgaGF6YXJkOiBoZiA/IHtcclxuICAgICAgICAgIG9iamVjdElkOiBoZi5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICAgICAgaWQ6IGhmLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgICAgICBuYW1lOiBoZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgICB0aXRsZTogaGYuYXR0cmlidXRlcy5EaXNwbGF5VGl0bGUgfHwgaGYuYXR0cmlidXRlcy5EaXNwbGF5TmFtZSB8fCBoZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgICB0eXBlOiBoZi5hdHRyaWJ1dGVzLlR5cGUsXHJcbiAgICAgICAgICBkZXNjcmlwdGlvbjogaGYuYXR0cmlidXRlcy5EZXNjcmlwdGlvbixcclxuICAgICAgICAgIGRvbWFpbnM6IGhhemFyZEZlYXR1cmVzZXQuZmllbGRzLmZpbmQoZiA9PiBmLm5hbWUgPT09ICdUeXBlJykuZG9tYWluLmNvZGVkVmFsdWVzXHJcbiAgICAgICAgfSA6IG51bGwsXHJcbiAgICAgICAgZGVzY3JpcHRpb246IGYuYXR0cmlidXRlcy5EZXNjcmlwdGlvbixcclxuICAgICAgICBzdGFydERhdGU6IE51bWJlcihmLmF0dHJpYnV0ZXMuU3RhcnREYXRlKSxcclxuICAgICAgICBlbmREYXRlOiBOdW1iZXIoZi5hdHRyaWJ1dGVzLkVuZERhdGUpXHJcbiAgICAgIH0gYXMgSW5jaWRlbnQ7XHJcbiAgfSk7XHJcbiAgcmV0dXJuIFtdO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRIYXphcmRGZWF0dXJlcyAoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHF1ZXJ5OiBzdHJpbmcsIGNhbGxlcjogc3RyaW5nKTogUHJvbWlzZTxJRmVhdHVyZVNldD4ge1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgSGF6YXJkcyBjYWxsZWQgYnkgJytjYWxsZXIpXHJcbiAgY2hlY2tQYXJhbShjb25maWcuaGF6YXJkcywgSEFaQVJEX1VSTF9FUlJPUik7ICBcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVTZXQoY29uZmlnLmhhemFyZHMsIHF1ZXJ5LCBjb25maWcpO1xyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0SGF6YXJkcyhjb25maWc6IEFwcFdpZGdldENvbmZpZywgcXVlcnlTdHJpbmc6IHN0cmluZywgY2FsbGVyOiBzdHJpbmcpOiBQcm9taXNlPEhhemFyZFtdPiB7XHJcbiAgXHJcbiAgY29uc3QgZmVhdHVyZVNldCA9IGF3YWl0IGdldEhhemFyZEZlYXR1cmVzKGNvbmZpZywgcXVlcnlTdHJpbmcsIGNhbGxlcik7XHJcbiAgaWYoIWZlYXR1cmVTZXQgfHwgZmVhdHVyZVNldC5mZWF0dXJlcy5sZW5ndGggPT0gMCl7XHJcbiAgICByZXR1cm4gW107XHJcbiAgfVxyXG4gIHJldHVybiBmZWF0dXJlU2V0LmZlYXR1cmVzLm1hcCgoZjogSUZlYXR1cmUpID0+IHtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIG9iamVjdElkOiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgIGlkOiBmLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgIG5hbWU6IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICB0aXRsZTogZi5hdHRyaWJ1dGVzLkRpc3BsYXlUaXRsZSB8fCBmLmF0dHJpYnV0ZXMuRGlzcGxheU5hbWUgfHwgZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgIHR5cGU6IGYuYXR0cmlidXRlcy5UeXBlLFxyXG4gICAgICBkZXNjcmlwdGlvbjogZi5hdHRyaWJ1dGVzLkRlc2NyaXB0aW9uLFxyXG4gICAgICBkb21haW5zOiBmZWF0dXJlU2V0LmZpZWxkcy5maW5kKGYgPT4gZi5uYW1lID09PSAnVHlwZScpLmRvbWFpbi5jb2RlZFZhbHVlc1xyXG4gICAgfSBhcyBIYXphcmRcclxuICB9KVxyXG4gIHJldHVybiBbXTtcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldE9yZ2FuaXphdGlvbnMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHF1ZXJ5U3RyaW5nOiBzdHJpbmcpOiBQcm9taXNlPE9yZ2FuaXphdGlvbltdPiB7XHJcbiAgY29uc29sZS5sb2coJ2dldCBPcmdhbml6YXRpb25zIGNhbGxlZCcpXHJcbiAgY2hlY2tQYXJhbShjb25maWcub3JnYW5pemF0aW9ucywgT1JHQU5JWkFUSU9OX1VSTF9FUlJPUik7XHJcblxyXG4gIGNvbnN0IGZlYXR1cmVTZXQgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZVNldChjb25maWcub3JnYW5pemF0aW9ucywgcXVlcnlTdHJpbmcsIGNvbmZpZyk7XHJcbiBcclxuICBpZihmZWF0dXJlU2V0ICYmIGZlYXR1cmVTZXQuZmVhdHVyZXMgJiYgZmVhdHVyZVNldC5mZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgIHJldHVybiBmZWF0dXJlU2V0LmZlYXR1cmVzLm1hcCgoZjogSUZlYXR1cmUpID0+IHtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBvYmplY3RJZDogZi5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICAgIGlkOiBmLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgICAgbmFtZTogZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgdGl0bGU6IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgIHR5cGU6IGYuYXR0cmlidXRlcy5UeXBlLFxyXG4gICAgICAgIHBhcmVudElkOiBmLmF0dHJpYnV0ZXMuUGFyZW50SUQsXHJcbiAgICAgICAgZGVzY3JpcHRpb246IGYuYXR0cmlidXRlcy5EZXNjcmlwdGlvbixcclxuICAgICAgICBkb21haW5zOiBmZWF0dXJlU2V0LmZpZWxkcy5maW5kKGYgPT4gZi5uYW1lID09PSAnVHlwZScpLmRvbWFpbi5jb2RlZFZhbHVlc1xyXG4gICAgICB9IGFzIE9yZ2FuaXphdGlvblxyXG4gICAgfSlcclxuICB9XHJcbiAgcmV0dXJuIFtdO1xyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY3JlYXRlTmV3VGVtcGxhdGUoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHRlbXBsYXRlOiBDTFNTVGVtcGxhdGUsIFxyXG4gdXNlck5hbWU6IHN0cmluZywgb3JnYW5pemF0aW9uOiBPcmdhbml6YXRpb24sIGhhemFyZDogSGF6YXJkKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+IHtcclxuIFxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLnRlbXBsYXRlcywgVEVNUExBVEVfVVJMX0VSUk9SKTtcclxuICBjaGVja1BhcmFtKHRlbXBsYXRlLCAnVGVtcGxhdGUgZGF0YSBub3QgcHJvdmlkZWQnKTtcclxuXHJcbiAgY29uc3QgY3JlYXRlRGF0ZSA9IG5ldyBEYXRlKCkuZ2V0VGltZSgpO1xyXG4gIGNvbnN0IHRlbXBsYXRlTmFtZSA9IHRlbXBsYXRlLm5hbWVbMF0udG9Mb2NhbGVVcHBlckNhc2UoKSt0ZW1wbGF0ZS5uYW1lLnN1YnN0cmluZygxKTtcclxuIFxyXG4gIGxldCBmZWF0dXJlID0ge1xyXG4gICAgYXR0cmlidXRlczoge1xyXG4gICAgICBPcmdhbml6YXRpb25JRDogb3JnYW5pemF0aW9uID8gb3JnYW5pemF0aW9uLmlkIDogIG51bGwsXHJcbiAgICAgIE9yZ2FuaXphdGlvbk5hbWU6IG9yZ2FuaXphdGlvbiA/IG9yZ2FuaXphdGlvbi5uYW1lOiBudWxsLFxyXG4gICAgICBPcmdhbml6YXRpb25UeXBlOiBvcmdhbml6YXRpb24gPyAob3JnYW5pemF0aW9uLnR5cGUuY29kZSA/IG9yZ2FuaXphdGlvbi50eXBlLmNvZGU6IG9yZ2FuaXphdGlvbi50eXBlICk6IG51bGwsXHJcbiAgICAgIEhhemFyZElEOiAgaGF6YXJkID8gaGF6YXJkLmlkIDogbnVsbCxcclxuICAgICAgSGF6YXJkTmFtZTogIGhhemFyZCA/IGhhemFyZC5uYW1lIDogbnVsbCxcclxuICAgICAgSGF6YXJkVHlwZTogIGhhemFyZCA/IChoYXphcmQudHlwZS5jb2RlID8gaGF6YXJkLnR5cGUuY29kZSA6IGhhemFyZC50eXBlKSA6IG51bGwsXHJcbiAgICAgIE5hbWU6IHRlbXBsYXRlTmFtZSAsXHJcbiAgICAgIENyZWF0b3I6IHVzZXJOYW1lLFxyXG4gICAgICBDcmVhdGVkRGF0ZTogY3JlYXRlRGF0ZSwgICAgICBcclxuICAgICAgU3RhdHVzOiAxLFxyXG4gICAgICBJc1NlbGVjdGVkOiAwLFxyXG4gICAgICBFZGl0b3I6IHVzZXJOYW1lLFxyXG4gICAgICBFZGl0ZWREYXRlOiBjcmVhdGVEYXRlICAgICBcclxuICAgIH1cclxuICB9XHJcbiAgbGV0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcudGVtcGxhdGVzLCBbZmVhdHVyZV0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcbiAgICBcclxuICAgIGNvbnN0IHRlbXBsYXRlSWQgPSByZXNwb25zZS5hZGRSZXN1bHRzWzBdLmdsb2JhbElkO1xyXG4gICAgLy9jcmVhdGUgbmV3IGluZGljYXRvcnMgICBcclxuICAgIGNvbnN0IGluZGljYXRvcnMgPSBnZXRUZW1wbGF0ZUluZGljYXRvcnModGVtcGxhdGUpO1xyXG4gICAgY29uc3QgaW5kaWNhdG9yRmVhdHVyZXMgPSBpbmRpY2F0b3JzLm1hcChpbmRpY2F0b3IgPT4ge1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgIFRlbXBsYXRlSUQ6IHRlbXBsYXRlSWQsICBcclxuICAgICAgICAgIENvbXBvbmVudElEOiBpbmRpY2F0b3IuY29tcG9uZW50SWQsXHJcbiAgICAgICAgICBDb21wb25lbnROYW1lOiBpbmRpY2F0b3IuY29tcG9uZW50TmFtZSwgIFxyXG4gICAgICAgICAgTmFtZTogaW5kaWNhdG9yLm5hbWUsICAgXHJcbiAgICAgICAgICBUZW1wbGF0ZU5hbWU6IHRlbXBsYXRlTmFtZSwgXHJcbiAgICAgICAgICBMaWZlbGluZU5hbWU6IGluZGljYXRvci5saWZlbGluZU5hbWUgICAgICBcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuICAgIH0pXHJcbiAgICByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvcnMsIGluZGljYXRvckZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcblxyXG4gICAgICBjb25zdCBnbG9iYWxJZHMgPSBgKCR7cmVzcG9uc2UuYWRkUmVzdWx0cy5tYXAociA9PiBgJyR7ci5nbG9iYWxJZH0nYCkuam9pbignLCcpfSlgO1xyXG4gICAgICBjb25zdCBxdWVyeSA9ICdHbG9iYWxJRCBJTiAnK2dsb2JhbElkczsgICAgIFxyXG4gICAgICBjb25zdCBhZGRlZEluZGljYXRvckZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLHF1ZXJ5ICwgY29uZmlnKTtcclxuXHJcbiAgICAgICBsZXQgd2VpZ2h0c0ZlYXR1cmVzID0gW107XHJcbiAgICAgICBmb3IobGV0IGZlYXR1cmUgb2YgYWRkZWRJbmRpY2F0b3JGZWF0dXJlcyl7ICAgXHJcbiAgICAgICAgIGNvbnN0IGluY29taW5nSW5kaWNhdG9yID0gaW5kaWNhdG9ycy5maW5kKGkgPT4gaS5uYW1lID09PSBmZWF0dXJlLmF0dHJpYnV0ZXMuTmFtZSk7XHJcbiAgICAgICAgIGlmKGluY29taW5nSW5kaWNhdG9yKXtcclxuICAgICAgICAgIGNvbnN0IHdlaWdodEZlYXR1cmVzID0gaW5jb21pbmdJbmRpY2F0b3Iud2VpZ2h0cy5tYXAodyA9PiB7ICAgICAgICBcclxuICAgICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICAgICAgICBJbmRpY2F0b3JJRDogZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELCAgXHJcbiAgICAgICAgICAgICAgICBOYW1lOiB3Lm5hbWUgLFxyXG4gICAgICAgICAgICAgICAgV2VpZ2h0OiB3LndlaWdodCwgXHJcbiAgICAgICAgICAgICAgICBTY2FsZUZhY3RvcjogMCwgIFxyXG4gICAgICAgICAgICAgICAgQWRqdXN0ZWRXZWlnaHQgOiAwLFxyXG4gICAgICAgICAgICAgICAgTWF4QWRqdXN0ZWRXZWlnaHQ6MFxyXG4gICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgfSk7XHJcbiAgICAgICAgICB3ZWlnaHRzRmVhdHVyZXMgPSB3ZWlnaHRzRmVhdHVyZXMuY29uY2F0KHdlaWdodEZlYXR1cmVzKVxyXG4gICAgICAgICB9ICAgICAgICAgICAgXHJcbiAgICAgICB9XHJcblxyXG4gICAgICAgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy53ZWlnaHRzLCB3ZWlnaHRzRmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICAgICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgICAgIH1cclxuICAgICAgIH1cclxuICAgIH1cclxuICAgIC8vIGNvbnN0IHByb21pc2VzID0gaW5kaWNhdG9ycy5tYXAoaW5kaWNhdG9yID0+IGNyZWF0ZU5ld0luZGljYXRvcihpbmRpY2F0b3IsIGNvbmZpZywgdGVtcGxhdGVJZCwgdGVtcGxhdGVOYW1lKSk7XHJcblxyXG4gICAgLy8gY29uc3QgcHJvbWlzZVJlc3BvbnNlID0gYXdhaXQgUHJvbWlzZS5hbGwocHJvbWlzZXMpO1xyXG4gICAgLy8gaWYocHJvbWlzZVJlc3BvbnNlLmV2ZXJ5KHAgPT4gcC5kYXRhKSl7XHJcbiAgICAvLyAgIHJldHVybiB7XHJcbiAgICAvLyAgICAgZGF0YTogdHJ1ZVxyXG4gICAgLy8gICB9XHJcbiAgICAvLyB9XHJcbiAgfSBcclxuXHJcbiAgbG9nKEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKSwgTG9nVHlwZS5FUlJPUiwgJ2NyZWF0ZU5ld1RlbXBsYXRlJylcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgY3JlYXRpbmcgdGhlIG5ldyB0ZW1wbGF0ZSdcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB1cGRhdGVUZW1wbGF0ZU9yZ2FuaXphdGlvbkFuZEhhemFyZChjb25maWc6IEFwcFdpZGdldENvbmZpZywgXHJcbiAgdGVtcGxhdGU6IENMU1NUZW1wbGF0ZSwgdXNlck5hbWU6IHN0cmluZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PiB7XHJcblxyXG4gIGNoZWNrUGFyYW0odGVtcGxhdGUsICdUZW1wbGF0ZSBub3QgcHJvdmlkZWQnKTtcclxuICBjaGVja1BhcmFtKGNvbmZpZy50ZW1wbGF0ZXMsIFRFTVBMQVRFX1VSTF9FUlJPUik7IFxyXG5cclxuICBjb25zdCBhdHRyaWJ1dGVzID0ge1xyXG4gICAgT0JKRUNUSUQ6IHRlbXBsYXRlLm9iamVjdElkLFxyXG4gICAgT3JnYW5pemF0aW9uSUQ6IHRlbXBsYXRlLm9yZ2FuaXphdGlvbklkLFxyXG4gICAgSGF6YXJkSUQ6IHRlbXBsYXRlLmhhemFyZElkLFxyXG4gICAgT3JnYW5pemF0aW9uTmFtZTogdGVtcGxhdGUub3JnYW5pemF0aW9uTmFtZSxcclxuICAgIE9yZ2FuaXphdGlvblR5cGU6IHRlbXBsYXRlLm9yZ2FuaXphdGlvblR5cGUsXHJcbiAgICBIYXphcmROYW1lOiB0ZW1wbGF0ZS5oYXphcmROYW1lLFxyXG4gICAgSGF6YXJkVHlwZTogdGVtcGxhdGUuaGF6YXJkVHlwZSxcclxuICAgIE5hbWU6IHRlbXBsYXRlLm5hbWUsXHJcbiAgICBFZGl0b3I6IHVzZXJOYW1lLFxyXG4gICAgRWRpdGVkRGF0ZTogbmV3IERhdGUoKS5nZXRUaW1lKCksXHJcbiAgICBTdGF0dXM6IHRlbXBsYXRlLnN0YXR1cy5jb2RlLFxyXG4gICAgSXNTZWxlY3RlZDogdGVtcGxhdGUuaXNTZWxlY3RlZCA/IDE6IDBcclxuICB9IFxyXG4gIGNvbnN0IHJlc3BvbnNlID0gIGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZShjb25maWcudGVtcGxhdGVzLCBhdHRyaWJ1dGVzLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgfVxyXG4gIH1cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAndXBkYXRlVGVtcGxhdGVPcmdhbml6YXRpb25BbmRIYXphcmQnKVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSB1cGRhdGluZyB0ZW1wbGF0ZS4nXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc2VsZWN0VGVtcGxhdGUob2JqZWN0SWQ6IG51bWJlciwgb2JqZWN0SWRzOiBudW1iZXJbXSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxTdHJpbmc+PiB7XHJcbiAgXHJcbiAgICBjb25zb2xlLmxvZygnc2VsZWN0IFRlbXBsYXRlIGNhbGxlZCcpXHJcbiAgICB0cnl7XHJcbiAgICAgIGNoZWNrUGFyYW0oY29uZmlnLnRlbXBsYXRlcywgVEVNUExBVEVfVVJMX0VSUk9SKTtcclxuXHJcbiAgICAgIC8vbGV0IGZlYXR1cmVzID0gYXdhaXQgZ2V0VGVtcGxhdGVGZWF0dXJlcygnMT0xJywgY29uZmlnKS8vIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcudGVtcGxhdGVzLCAnMT0xJywgY29uZmlnKVxyXG4gICAgXHJcbiAgICAgIGNvbnN0IGZlYXR1cmVzID0gIG9iamVjdElkcy5tYXAob2lkID0+IHtcclxuICAgICAgICByZXR1cm4geyAgICAgICAgICBcclxuICAgICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgICAgT0JKRUNUSUQ6IG9pZCxcclxuICAgICAgICAgICAgSXNTZWxlY3RlZDogb2lkID09PSBvYmplY3RJZCA/IDEgOiAwXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgICB9KVxyXG4gICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLnRlbXBsYXRlcywgZmVhdHVyZXMsIGNvbmZpZylcclxuICAgICAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcbiAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBkYXRhOiByZXNwb25zZS51cGRhdGVSZXN1bHRzWzBdLmdsb2JhbElkXHJcbiAgICAgICAgIH0gYXMgQ2xzc1Jlc3BvbnNlPFN0cmluZz47XHJcbiAgICAgIH1cclxuICAgIH1jYXRjaChlKSB7XHJcbiAgICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAnc2VsZWN0VGVtcGxhdGUnKTtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBlcnJvcnM6IGVcclxuICAgICAgfVxyXG4gICAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gbG9hZFNjYWxlRmFjdG9ycyhjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPFNjYWxlRmFjdG9yW10+PntcclxuXHJcbiAgY2hlY2tQYXJhbShjb25maWcuY29uc3RhbnRzLCAnUmF0aW5nIFNjYWxlcyB1cmwgbm90IHByb3ZpZGVkJyk7XHJcblxyXG4gIHRyeXtcclxuXHJcbiAgIGNvbnN0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5jb25zdGFudHMsICcxPTEnLCBjb25maWcpO1xyXG4gICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgICBjb25zdCBzY2FsZXMgPSAgZmVhdHVyZXMubWFwKGYgPT57XHJcbiAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICBuYW1lOiBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICAgdmFsdWU6IGYuYXR0cmlidXRlcy5WYWx1ZVxyXG4gICAgICAgfSBhcyBTY2FsZUZhY3RvcjsgICAgICAgXHJcbiAgICAgfSlcclxuXHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogc2NhbGVzXHJcbiAgICB9IGFzIENsc3NSZXNwb25zZTxTY2FsZUZhY3RvcltdPlxyXG4gICB9XHJcblxyXG4gICBsb2coJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHJlcXVlc3RpbmcgcmF0aW5nIHNjYWxlcycsIExvZ1R5cGUuRVJST1IsICdsb2FkUmF0aW5nU2NhbGVzJylcclxuICAgcmV0dXJuIHtcclxuICAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSByZXF1ZXN0aW5nIHJhdGluZyBzY2FsZXMnXHJcbiAgIH1cclxuICB9IGNhdGNoKGUpe1xyXG4gICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAnbG9hZFJhdGluZ1NjYWxlcycpOyAgICBcclxuICB9ICBcclxuICAgXHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjcmVhdGVOZXdJbmRpY2F0b3IoaW5kaWNhdG9yOiBJbmRpY2F0b3JUZW1wbGF0ZSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHRlbXBsYXRlSWQ6IHN0cmluZywgdGVtcGxhdGVOYW1lOiBzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj4ge1xyXG5cclxuICBjaGVja1BhcmFtKGNvbmZpZy5pbmRpY2F0b3JzLCBJTkRJQ0FUT1JfVVJMX0VSUk9SKTtcclxuXHJcbiAgY29uc3QgaW5kaWNhdG9yRmVhdHVyZSA9IHtcclxuICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgVGVtcGxhdGVJRDogdGVtcGxhdGVJZCwgIFxyXG4gICAgICBDb21wb25lbnRJRDogaW5kaWNhdG9yLmNvbXBvbmVudElkLFxyXG4gICAgICBDb21wb25lbnROYW1lOiBpbmRpY2F0b3IuY29tcG9uZW50TmFtZSwgIFxyXG4gICAgICBOYW1lOiBpbmRpY2F0b3IubmFtZSwgICBcclxuICAgICAgVGVtcGxhdGVOYW1lOiB0ZW1wbGF0ZU5hbWUsIFxyXG4gICAgICBMaWZlbGluZU5hbWU6IGluZGljYXRvci5saWZlbGluZU5hbWUgICAgICBcclxuICAgIH1cclxuICB9XHJcblxyXG4gIGxldCByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvcnMsIFtpbmRpY2F0b3JGZWF0dXJlXSwgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuXHJcbiAgICBjb25zdCB3ZWlnaHRGZWF0dXJlcyA9IGluZGljYXRvci53ZWlnaHRzLm1hcCh3ID0+IHtcclxuICAgICAgIFxyXG4gICAgICAgcmV0dXJuIHtcclxuICAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICBJbmRpY2F0b3JJRDogcmVzcG9uc2UuYWRkUmVzdWx0c1swXS5nbG9iYWxJZCwgIFxyXG4gICAgICAgICAgTmFtZTogdy5uYW1lICxcclxuICAgICAgICAgIFdlaWdodDogdy53ZWlnaHQsIFxyXG4gICAgICAgICAgU2NhbGVGYWN0b3I6IDAsICBcclxuICAgICAgICAgIEFkanVzdGVkV2VpZ2h0IDogMCxcclxuICAgICAgICAgIE1heEFkanVzdGVkV2VpZ2h0OjBcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuICAgIH0pO1xyXG5cclxuICAgIHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcud2VpZ2h0cywgd2VpZ2h0RmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgICAgfVxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgbG9nKEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKSwgTG9nVHlwZS5FUlJPUiwgJ2NyZWF0ZU5ld0luZGljYXRvcicpO1xyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSBzYXZpbmcgdGhlIGluZGljYXRvci4nXHJcbiAgfVxyXG5cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHVwZGF0ZUluZGljYXRvck5hbWUoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIGluZGljYXRvclRlbXA6SW5kaWNhdG9yVGVtcGxhdGUpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgIFxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmluZGljYXRvcnMsIElORElDQVRPUl9VUkxfRVJST1IpO1xyXG5cclxuICBjb25zdCBhdHRyaWJ1dGVzID0ge1xyXG4gICAgT0JKRUNUSUQ6IGluZGljYXRvclRlbXAub2JqZWN0SWQsXHJcbiAgICBOYW1lOiBpbmRpY2F0b3JUZW1wLm5hbWUsXHJcbiAgICBEaXNwbGF5VGl0bGU6IGluZGljYXRvclRlbXAubmFtZSxcclxuICAgIElzQWN0aXZlOiAxXHJcbiAgfVxyXG4gIGNvbnN0IHJlc3BvbnNlID0gIGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZShjb25maWcuaW5kaWNhdG9ycywgYXR0cmlidXRlcywgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB0cnVlXHJcbiAgICAgfVxyXG4gIH1cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAndXBkYXRlSW5kaWNhdG9yTmFtZScpXHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHVwZGF0aW5nIGluZGljYXRvcidcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB1cGRhdGVJbmRpY2F0b3IoaW5kaWNhdG9yOiBJbmRpY2F0b3JUZW1wbGF0ZSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgIFxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmluZGljYXRvcnMsIElOQ0lERU5UX1VSTF9FUlJPUik7XHJcblxyXG4gIGxldCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9ycywgYE5hbWU9JyR7aW5kaWNhdG9yLm5hbWV9JyBBTkQgVGVtcGxhdGVOYW1lPScke2luZGljYXRvci50ZW1wbGF0ZU5hbWV9J2AsIGNvbmZpZylcclxuIFxyXG4gIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDEpe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiAnQW4gaW5kaWNhdG9yIHdpdGggdGhlIHNhbWUgbmFtZSBhbHJlYWR5IGV4aXN0cydcclxuICAgIH1cclxuICB9XHJcbiAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCB1cGRhdGVJbmRpY2F0b3JOYW1lKGNvbmZpZywgaW5kaWNhdG9yKTtcclxuXHJcbiAgaWYocmVzcG9uc2UuZXJyb3JzKXtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGVycm9yczogcmVzcG9uc2UuZXJyb3JzXHJcbiAgICB9XHJcbiAgfVxyXG4gXHJcbiAgIGZlYXR1cmVzID0gaW5kaWNhdG9yLndlaWdodHMubWFwKHcgPT4ge1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICBPQkpFQ1RJRDogdy5vYmplY3RJZCxcclxuICAgICAgICAgIFdlaWdodDogTnVtYmVyKHcud2VpZ2h0KSwgXHJcbiAgICAgICAgICBBZGp1c3RlZFdlaWdodDogTnVtYmVyKHcud2VpZ2h0KSAqIHcuc2NhbGVGYWN0b3JcclxuICAgICAgIH1cclxuICAgICB9XHJcbiAgIH0pO1xyXG5cclxuICAgY29uc3QgdXBkYXRlUmVzcG9uc2UgPSBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmVzKGNvbmZpZy53ZWlnaHRzLCBmZWF0dXJlcywgY29uZmlnKTtcclxuICAgaWYodXBkYXRlUmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiB1cGRhdGVSZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgIH1cclxuICAgfVxyXG5cclxuICAgbG9nKEpTT04uc3RyaW5naWZ5KHVwZGF0ZVJlc3BvbnNlKSwgTG9nVHlwZS5FUlJPUiwgJ3VwZGF0ZUluZGljYXRvcicpO1xyXG4gICByZXR1cm4ge1xyXG4gICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHVwZGF0aW5nIGluZGljYXRvci4nXHJcbiAgIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZUluZGljYXRvcihpbmRpY2F0b3JUZW1wbGF0ZTogSW5kaWNhdG9yVGVtcGxhdGUsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+IHtcclxuXHJcbiAgY2hlY2tQYXJhbShjb25maWcuaW5kaWNhdG9ycywgSU5ESUNBVE9SX1VSTF9FUlJPUik7XHJcbiAgY2hlY2tQYXJhbShjb25maWcud2VpZ2h0cywgJ1dlaWdodHMgVVJMIG5vdCBwcm92aWRlZCcpO1xyXG4gIFxyXG4gIGxldCByZXNwID0gYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9ycywgW2luZGljYXRvclRlbXBsYXRlLm9iamVjdElkXSwgY29uZmlnKTtcclxuICBpZihyZXNwLmRlbGV0ZVJlc3VsdHMgJiYgcmVzcC5kZWxldGVSZXN1bHRzLmV2ZXJ5KGQgPT4gZC5zdWNjZXNzKSl7XHJcbiAgICAgY29uc3Qgd2VpZ2h0c09iamVjdElkcyA9IGluZGljYXRvclRlbXBsYXRlLndlaWdodHMubWFwKHcgPT4gdy5vYmplY3RJZCk7XHJcbiAgICAgcmVzcCA9IGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLndlaWdodHMsIHdlaWdodHNPYmplY3RJZHMsIGNvbmZpZyk7XHJcbiAgICAgaWYocmVzcC5kZWxldGVSZXN1bHRzICYmIHJlc3AuZGVsZXRlUmVzdWx0cy5ldmVyeShkID0+IGQuc3VjY2Vzcykpe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IHRydWVcclxuICAgICAgfVxyXG4gICAgIH1cclxuICB9XHJcblxyXG4gIGxvZyhKU09OLnN0cmluZ2lmeShyZXNwKSwgTG9nVHlwZS5FUlJPUiwgJ2RlbGV0ZUluZGljYXRvcicpXHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIGRlbGV0aW5nIHRoZSBpbmRpY2F0b3InXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gYXJjaGl2ZVRlbXBsYXRlKG9iamVjdElkOiBudW1iZXIsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+IHtcclxuIFxyXG4gIGNvbnN0IHJlc3BvbnNlICA9IGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZShjb25maWcudGVtcGxhdGVzLCB7XHJcbiAgICBPQkpFQ1RJRDogb2JqZWN0SWQsXHJcbiAgICBJc1NlbGVjdGVkOiAwLFxyXG4gICAgSXNBY3RpdmU6IDBcclxuICB9LCBjb25maWcpO1xyXG4gIGNvbnNvbGUubG9nKHJlc3BvbnNlKTtcclxuICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkoZSA9PiBlLnN1Y2Nlc3MpKXtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHRydWVcclxuICAgIH1cclxuICB9XHJcbiAgbG9nKEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKSwgTG9nVHlwZS5FUlJPUiwgJ2FyY2hpdmVUZW1wbGF0ZScpO1xyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdUaGUgdGVtcGxhdGUgY2Fubm90IGJlIGFyY2hpdmVkLidcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzYXZlT3JnYW5pemF0aW9uKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBvcmdhbml6YXRpb246IE9yZ2FuaXphdGlvbik6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPE9yZ2FuaXphdGlvbj4+IHtcclxuXHJcbiAgY2hlY2tQYXJhbShjb25maWcub3JnYW5pemF0aW9ucywgT1JHQU5JWkFUSU9OX1VSTF9FUlJPUik7XHJcbiAgY2hlY2tQYXJhbShvcmdhbml6YXRpb24sICdPcmdhbml6YXRpb24gb2JqZWN0IG5vdCBwcm92aWRlZCcpO1xyXG4gXHJcbiAgY29uc3QgZmVhdHVyZSA9IHtcclxuICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgTmFtZTogb3JnYW5pemF0aW9uLm5hbWUsXHJcbiAgICAgIFR5cGU6IG9yZ2FuaXphdGlvbi50eXBlPy5jb2RlLFxyXG4gICAgICBEaXNwbGF5VGl0bGU6IG9yZ2FuaXphdGlvbi5uYW1lLFxyXG4gICAgICBQYXJlbnRJRDogb3JnYW5pemF0aW9uPy5wYXJlbnRJZFxyXG4gICAgfVxyXG4gIH1cclxuICBjb25zdCByZXNwb25zZSA9ICBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5vcmdhbml6YXRpb25zLCBbZmVhdHVyZV0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7IFxyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZGF0YToge1xyXG4gICAgICAgIC4uLm9yZ2FuaXphdGlvblxyXG4gICAgICB9IGFzIE9yZ2FuaXphdGlvbiAvLyAoYXdhaXQgZ2V0T3JnYW5pemF0aW9ucyhjb25maWcsIGBHbG9iYWxJRD0nJHtyZXNwb25zZS5hZGRSZXN1bHRzWzBdLmdsb2JhbElkfSdgKSlbMF1cclxuICAgIH1cclxuICB9XHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc2F2ZUhhemFyZChjb25maWc6IEFwcFdpZGdldENvbmZpZywgaGF6YXJkOiBIYXphcmQpOiBQcm9taXNlPENsc3NSZXNwb25zZTxIYXphcmQ+PiB7XHJcbiAgXHJcbiAgY29uc3QgZmVhdHVyZSA9IHtcclxuICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgTmFtZTogaGF6YXJkLm5hbWUsXHJcbiAgICAgIERpc3BsYXlUaXRsZTogaGF6YXJkLm5hbWUsXHJcbiAgICAgIFR5cGU6IGhhemFyZC50eXBlLmNvZGUsXHJcbiAgICAgIERlc2NyaXB0aW9uOiBoYXphcmQuZGVzY3JpcHRpb25cclxuICAgIH1cclxuICB9XHJcblxyXG4gIGNvbnN0IHJlc3BvbnNlID0gIGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmhhemFyZHMsIFtmZWF0dXJlXSwgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXsgICBcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiB7XHJcbiAgICAgICAgICAuLi5oYXphcmQsXHJcbiAgICAgICAgICBvYmplY3RJZDogcmVzcG9uc2UuYWRkUmVzdWx0c1swXS5vYmplY3RJZCxcclxuICAgICAgICAgIGlkOiByZXNwb25zZS5hZGRSZXN1bHRzWzBdLmdsb2JhbElkXHJcbiAgICAgICAgfSBhcyBIYXphcmQgIFxyXG4gICAgICB9XHJcbiAgfVxyXG5cclxuICBsb2coYEVycm9yIG9jY3VycmVkIHdoaWxlIHNhdmluZyBoYXphcmQuIFJlc3RhcnRpbmcgdGhlIGFwcGxpY2F0aW9uIG1heSBmaXggdGhpcyBpc3N1ZS5gLCBMb2dUeXBlLkVSUk9SLCAnc2F2ZUhhemFyZCcpXHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHNhdmluZyBoYXphcmQuIFJlc3RhcnRpbmcgdGhlIGFwcGxpY2F0aW9uIG1heSBmaXggdGhpcyBpc3N1ZS4nXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVsZXRlSW5jaWRlbnQoaW5jaWRlbnQ6IEluY2lkZW50LCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmluY2lkZW50cywgW2luY2lkZW50Lm9iamVjdElkXSwgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS5kZWxldGVSZXN1bHRzICYmIHJlc3BvbnNlLmRlbGV0ZVJlc3VsdHMuZXZlcnkoZCA9PiBkLnN1Y2Nlc3MpKXtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgIH1cclxuICB9XHJcbiAgcmV0dXJuIHtcclxuICAgZXJyb3JzOiBKU09OLnN0cmluZ2lmeShyZXNwb25zZSlcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWxldGVIYXphcmQoaGF6YXJkOiBIYXphcmQsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmhhemFyZHMsIFtoYXphcmQub2JqZWN0SWRdLCBjb25maWcpO1xyXG4gICBpZihyZXNwb25zZS5kZWxldGVSZXN1bHRzICYmIHJlc3BvbnNlLmRlbGV0ZVJlc3VsdHMuZXZlcnkoZCA9PiBkLnN1Y2Nlc3MpKXtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgIH1cclxuICAgfVxyXG4gICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiBKU09OLnN0cmluZ2lmeShyZXNwb25zZSlcclxuICAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVsZXRlT3JnYW5pemF0aW9uKG9yZ2FuaXphdGlvbjogT3JnYW5pemF0aW9uLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLm9yZ2FuaXphdGlvbnMsIFtvcmdhbml6YXRpb24ub2JqZWN0SWRdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmRlbGV0ZVJlc3VsdHMgJiYgcmVzcG9uc2UuZGVsZXRlUmVzdWx0cy5ldmVyeShkID0+IGQuc3VjY2Vzcykpe1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgfVxyXG4gIH1cclxuICByZXR1cm4ge1xyXG4gICBlcnJvcnM6IEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKVxyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNoZWNrUGFyYW0ocGFyYW06IGFueSwgZXJyb3I6IHN0cmluZykge1xyXG4gIGlmICghcGFyYW0gfHwgcGFyYW0gPT0gbnVsbCB8fCBwYXJhbSA9PT0gJycgfHwgcGFyYW0gPT0gdW5kZWZpbmVkKSB7XHJcbiAgICB0aHJvdyBuZXcgRXJyb3IoZXJyb3IpXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdGVtcGxDbGVhblVwKGluZFVybDogc3RyaW5nLCBhbGlnVXJsOiBzdHJpbmcsIHRva2VuOiBzdHJpbmcpIHtcclxuXHJcblxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc2F2ZU5ld0Fzc2Vzc21lbnQobmV3QXNzZXNzbWVudDogQXNzZXNzbWVudCwgdGVtcGxhdGU6IENMU1NUZW1wbGF0ZSwgXHJcbiAgICAgICAgICAgICAgICAgIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBwcmV2QXNzZXNzbWVudD86IEFzc2Vzc21lbnQpOiBQcm9taXNlPENsc3NSZXNwb25zZTxzdHJpbmc+PnsgICAgXHJcbiAgICAgIFxyXG4gICAgICBjb25zdCByZXNwID0gYXdhaXQgc2F2ZUFzc2Vzc21lbnQobmV3QXNzZXNzbWVudCwgY29uZmlnKTtcclxuICAgICAgaWYocmVzcC5lcnJvcnMpe1xyXG4gICAgICAgIGxvZygnVW5hYmxlIHRvIGNyZWF0ZSB0aGUgYXNzZXNzbWVudC4nLCBMb2dUeXBlLkVSUk9SLCAnc2F2ZU5ld0Fzc2Vzc21lbnQnKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGVycm9yczogJ1VuYWJsZSB0byBjcmVhdGUgdGhlIGFzc2Vzc21lbnQuJ1xyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG4gICAgIFxyXG4gICAgICB0cnl7XHJcblxyXG4gICAgICAgIGNvbnN0IGluZGljYXRvcnMgPSBnZXRUZW1wbGF0ZUluZGljYXRvcnModGVtcGxhdGUpO1xyXG4gICAgICAgIGlmKCFpbmRpY2F0b3JzIHx8IGluZGljYXRvcnMubGVuZ3RoID09PSAwKXtcclxuICAgICAgICAgIGxvZygnVGVtcGxhdGUgaW5kaWNhdG9ycyBub3QgZm91bmQnLCBMb2dUeXBlLkVSUk9SLCAnc2F2ZU5ld0Fzc2Vzc21lbnQnKTsgIFxyXG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdUZW1wbGF0ZSBpbmRpY2F0b3JzIG5vdCBmb3VuZC4nKVxyXG4gICAgICAgIH0gICAgICBcclxuICBcclxuICAgICAgICBjb25zdCBsaWZlbGluZVN0YXR1c0ZlYXR1cmVzID0gdGVtcGxhdGUubGlmZWxpbmVUZW1wbGF0ZXMubWFwKGx0ID0+IHtcclxuICAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICBhdHRyaWJ1dGVzOiB7IFxyXG4gICAgICAgICAgICAgIEFzc2Vzc21lbnRJRCA6IHJlc3AuZGF0YSxcclxuICAgICAgICAgICAgICBTY29yZTogbnVsbCwgXHJcbiAgICAgICAgICAgICAgQ29sb3I6IG51bGwsIFxyXG4gICAgICAgICAgICAgIExpZmVsaW5lSUQ6IGx0LmlkLCBcclxuICAgICAgICAgICAgICBJc092ZXJyaWRlbjogMCwgXHJcbiAgICAgICAgICAgICAgT3ZlcnJpZGVuU2NvcmU6IG51bGwsIFxyXG4gICAgICAgICAgICAgIE92ZXJyaWRlbkJ5OiBudWxsLCBcclxuICAgICAgICAgICAgICBPdmVycmlkZUNvbW1lbnQ6IG51bGwsIFxyXG4gICAgICAgICAgICAgIExpZmVsaW5lTmFtZTogbHQudGl0bGUsIFxyXG4gICAgICAgICAgICAgIFRlbXBsYXRlTmFtZTogdGVtcGxhdGUubmFtZVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgfSlcclxuICAgICAgICBsZXQgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZVN0YXR1cywgbGlmZWxpbmVTdGF0dXNGZWF0dXJlcywgY29uZmlnKTtcclxuICAgICAgICBpZihyZXNwb25zZSAmJiByZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuICAgICAgICAgICBjb25zdCBxdWVyeSA9ICdHbG9iYWxJRCBJTiAoJysgcmVzcG9uc2UuYWRkUmVzdWx0cy5tYXAociA9PiBgJyR7ci5nbG9iYWxJZH0nYCkuam9pbignLCcpK1wiKVwiO1xyXG4gICAgICAgICAgIGNvbnN0IGxzRmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBxdWVyeSwgY29uZmlnKTtcclxuICAgICAgICAgICBcclxuICAgICAgICAgICBjb25zdCBpbmRpY2F0b3JBc3Nlc3NtZW50RmVhdHVyZXMgPSBpbmRpY2F0b3JzLm1hcChpID0+IHtcclxuICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIGNvbnN0IGxpZmVsaW5lU3RhdHVzRmVhdHVyZSA9IGxzRmVhdHVyZXMuZmluZChscyA9PiBcclxuICAgICAgICAgICAgICAgIGxzLmF0dHJpYnV0ZXMuTGlmZWxpbmVOYW1lLnNwbGl0KC9bJyAnJl8sXSsvKS5qb2luKCdfJykgID09PSBpLmxpZmVsaW5lTmFtZSk7XHJcbiAgICAgICAgICAgIGlmKCFsaWZlbGluZVN0YXR1c0ZlYXR1cmUpe1xyXG4gICAgICAgICAgICAgIGNvbnNvbGUubG9nKGAke2kubGlmZWxpbmVOYW1lfSBub3QgZm91bmRgKTtcclxuICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYCR7aS5saWZlbGluZU5hbWV9IG5vdCBmb3VuZGApO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgICAgICAgTGlmZWxpbmVTdGF0dXNJRCA6IGxpZmVsaW5lU3RhdHVzRmVhdHVyZT8gbGlmZWxpbmVTdGF0dXNGZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQgOiAnJyxcclxuICAgICAgICAgICAgICAgIEluZGljYXRvcklEOiBpLmlkLCAgXHJcbiAgICAgICAgICAgICAgICBUZW1wbGF0ZU5hbWU6IGkudGVtcGxhdGVOYW1lLCAgXHJcbiAgICAgICAgICAgICAgICBMaWZlbGluZU5hbWU6IGkubGlmZWxpbmVOYW1lLCAgXHJcbiAgICAgICAgICAgICAgICBDb21wb25lbnROYW1lOiBpLmNvbXBvbmVudE5hbWUsICBcclxuICAgICAgICAgICAgICAgIEluZGljYXRvck5hbWU6IGkubmFtZSxcclxuICAgICAgICAgICAgICAgIENvbW1lbnRzOiBcIlwiLFxyXG4gICAgICAgICAgICAgICAgUmFuazogaS53ZWlnaHRzLmZpbmQodyA9PiB3Lm5hbWUgPT09IFJBTkspPy53ZWlnaHQsXHJcbiAgICAgICAgICAgICAgICBMaWZlU2FmZXR5OiBpLndlaWdodHMuZmluZCh3ID0+IHcubmFtZSA9PT0gTElGRV9TQUZFVFkpPy53ZWlnaHQsXHJcbiAgICAgICAgICAgICAgICBQcm9wZXJ0eVByb3RlY3Rpb246IGkud2VpZ2h0cy5maW5kKHcgPT4gdy5uYW1lID09PSBQUk9QRVJUWV9QUk9URUNUSU9OKT8ud2VpZ2h0LFxyXG4gICAgICAgICAgICAgICAgSW5jaWRlbnRTdGFiaWxpemF0aW9uOiBpLndlaWdodHMuZmluZCh3ID0+IHcubmFtZSA9PT0gSU5DSURFTlRfU1RBQklMSVpBVElPTik/LndlaWdodCxcclxuICAgICAgICAgICAgICAgIEVudmlyb25tZW50UHJlc2VydmF0aW9uOiBpLndlaWdodHMuZmluZCh3ID0+IHcubmFtZSA9PT0gRU5WSVJPTk1FTlRfUFJFU0VSVkFUSU9OKT8ud2VpZ2h0LFxyXG4gICAgICAgICAgICAgICAgU3RhdHVzOiA0IC8vdW5rbm93blxyXG4gICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgIH0pXHJcbiAgXHJcbiAgICAgICAgICAgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JBc3Nlc3NtZW50cywgaW5kaWNhdG9yQXNzZXNzbWVudEZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgICAgICAgIGlmKHJlc3BvbnNlICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAgIGRhdGE6IHJlc3AuZGF0YVxyXG4gICAgICAgICAgICB9IFxyXG4gICAgICAgICAgIH1lbHNle1xyXG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ZhaWxlZCB0byBhZGQgaW5kaWNhdG9yIGFzc2Vzc21lbnQgZmVhdHVyZXMnKTtcclxuICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGVsc2V7XHJcbiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ZhaWxlZCB0byBhZGQgTGlmZWxpbmUgU3RhdHVzIEZlYXR1cmVzJyk7XHJcbiAgICAgICAgfSBcclxuXHJcbiAgICAgIH1jYXRjaChlKXtcclxuICAgICAgICBhd2FpdCBjbGVhblVwQXNzZXNzbWVudEZhaWxlZERhdGEocmVzcC5kYXRhLCBjb25maWcpO1xyXG4gICAgICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAnc2F2ZU5ld0Fzc2Vzc21lbnQnKVxyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBlcnJvcnM6J0Vycm9yIG9jY3VycmVkIHdoaWxlIGNyZWF0aW5nIEFzc2Vzc21lbnQuJ1xyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG5cclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gY2xlYW5VcEFzc2Vzc21lbnRGYWlsZWREYXRhKGFzc2Vzc21lbnRHbG9iYWxJZDogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyl7XHJcbiAgIFxyXG4gICBsZXQgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmFzc2Vzc21lbnRzLCBgR2xvYmFsSUQ9JyR7YXNzZXNzbWVudEdsb2JhbElkfSdgLCBjb25maWcpO1xyXG4gICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgICBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5hc3Nlc3NtZW50cywgZmVhdHVyZXMubWFwKGYgPT4gZi5hdHRyaWJ1dGVzLk9CSkVDVElEKSwgY29uZmlnKTtcclxuICAgfVxyXG5cclxuICAgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBgQXNzZXNzbWVudElEPScke2Fzc2Vzc21lbnRHbG9iYWxJZH0nYCwgY29uZmlnKTtcclxuICAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMCl7XHJcbiAgICBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZVN0YXR1cywgZmVhdHVyZXMubWFwKGYgPT4gZi5hdHRyaWJ1dGVzLk9CSkVDVElEKSwgY29uZmlnKTtcclxuXHJcbiAgICBjb25zdCBxdWVyeSA9IGBMaWZlbGluZVN0YXR1c0lEIElOICgke2ZlYXR1cmVzLm1hcChmID0+IGYuYXR0cmlidXRlcy5HbG9iYWxJRCkuam9pbignLCcpfSlgO1xyXG4gICAgY29uc29sZS5sb2coJ2RlbGV0ZSBxdWVyaWVzJywgcXVlcnkpXHJcbiAgICBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9yQXNzZXNzbWVudHMsIHF1ZXJ5LCBjb25maWcpO1xyXG4gICAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMCl7XHJcbiAgICAgIGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBmZWF0dXJlcy5tYXAoZiA9PiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQpLCBjb25maWcpO1xyXG4gICAgfVxyXG4gICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRBc3Nlc3NtZW50TmFtZXMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHRlbXBsYXRlTmFtZTogc3RyaW5nKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8e25hbWU6IHN0cmluZywgZGF0ZTogc3RyaW5nfVtdPj57XHJcbiAgXHJcbiAgY29uc3QgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmFzc2Vzc21lbnRzLCBgVGVtcGxhdGU9JyR7dGVtcGxhdGVOYW1lfSdgLCBjb25maWcpO1xyXG4gIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA9PT0gMCl7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiBbXVxyXG4gICAgfVxyXG4gIH1cclxuICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgXHJcbiAgICAgY29uc3QgYXNzZXNzID0gIGZlYXR1cmVzLm1hcChmID0+IHtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBuYW1lOiBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICBkYXRlOiBwYXJzZURhdGUoTnVtYmVyKGYuYXR0cmlidXRlcy5DcmVhdGVkRGF0ZSkpXHJcbiAgICAgIH1cclxuICAgICB9KTtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICAgZGF0YTogYXNzZXNzXHJcbiAgICAgfVxyXG4gIH1cclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnUmVxdWVzdCBmb3IgYXNzZXNzbWVudCBuYW1lcyBmYWlsZWQuJ1xyXG4gIH1cclxuXHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldEFzc2Vzc21lbnRGZWF0dXJlcyhjb25maWcpIHtcclxuICAgY29uc29sZS5sb2coJ2dldCBBc3Nlc3NtZW50IEZlYXR1cmVzIGNhbGxlZC4nKTtcclxuICAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuYXNzZXNzbWVudHMsIGAxPTFgLCBjb25maWcpO1xyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gbG9hZEFsbEFzc2Vzc21lbnRzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8QXNzZXNzbWVudFtdPj57XHJcblxyXG4gICB0cnl7XHJcbiAgICBjb25zdCBhc3Nlc3NtZW50RmVhdHVyZXMgPSBhd2FpdCBnZXRBc3Nlc3NtZW50RmVhdHVyZXMoY29uZmlnKTtcclxuICAgIGlmKCFhc3Nlc3NtZW50RmVhdHVyZXMgfHwgYXNzZXNzbWVudEZlYXR1cmVzLmxlbmd0aCA9PSAwKXtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiBbXVxyXG4gICAgICB9XHJcbiAgICB9XHJcbiAgICBcclxuICAgIGNvbnN0IGxzRmVhdHVyZXMgPSBhd2FpdCBnZXRMaWZlbGluZVN0YXR1c0ZlYXR1cmVzKGNvbmZpZywgYDE9MWApO1xyXG5cclxuICAgIGNvbnN0IHF1ZXJ5ID0gYExpZmVsaW5lU3RhdHVzSUQgSU4gKCR7bHNGZWF0dXJlcy5tYXAoZiA9PiBgJyR7Zi5hdHRyaWJ1dGVzLkdsb2JhbElEfSdgKS5qb2luKCcsJyl9KWBcclxuICAgIFxyXG4gICAgY29uc3QgaW5kaWNhdG9yQXNzZXNzbWVudHMgPSBhd2FpdCBnZXRJbmRpY2F0b3JBc3Nlc3NtZW50cyhxdWVyeSwgY29uZmlnKTtcclxuXHJcbiAgICBpZihhc3Nlc3NtZW50RmVhdHVyZXMgJiYgYXNzZXNzbWVudEZlYXR1cmVzLmxlbmd0aCA+IDApeyAgIFxyXG4gICAgICBjb25zdCBhc3Nlc3NtZW50cyA9IGFzc2Vzc21lbnRGZWF0dXJlcy5tYXAoKGZlYXR1cmU6IElGZWF0dXJlKSA9PiB7XHJcbiAgICAgICAgY29uc3QgYXNzZXNzbWVudExzRmVhdHVyZXMgPSBsc0ZlYXR1cmVzLmZpbHRlcihsID0+bC5hdHRyaWJ1dGVzLkFzc2Vzc21lbnRJRCA9PSBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQpICAgICAgICBcclxuICAgICAgICByZXR1cm4gbG9hZEFzc2Vzc21lbnQoZmVhdHVyZSwgYXNzZXNzbWVudExzRmVhdHVyZXMsIGluZGljYXRvckFzc2Vzc21lbnRzKTtcclxuICAgICAgfSk7XHJcblxyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IGFzc2Vzc21lbnRzXHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBpZihhc3Nlc3NtZW50RmVhdHVyZXMgJiYgYXNzZXNzbWVudEZlYXR1cmVzLmxlbmd0aCA9PSAwKXtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiBbXVxyXG4gICAgICB9ICBcclxuICAgIH1cclxuICAgfWNhdGNoKGUpe1xyXG4gICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdsb2FkQWxsQXNzZXNzbWVudHMnKTtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGVycm9yczogZVxyXG4gICAgfVxyXG4gICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjcmVhdGVJbmNpZGVudChjb25maWc6IEFwcFdpZGdldENvbmZpZywgaW5jaWRlbnQ6IEluY2lkZW50KTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8dm9pZD4+e1xyXG4gICBcclxuICAgIHRyeXtcclxuICAgICAgY2hlY2tQYXJhbShjb25maWcuaW5jaWRlbnRzLCBJTkNJREVOVF9VUkxfRVJST1IpO1xyXG4gICAgICBjaGVja1BhcmFtKGluY2lkZW50LCAnSW5jaWRlbnQgZGF0YSBub3QgcHJvdmlkZWQnKTtcclxuXHJcbiAgICAgIGNvbnN0IGZlYXR1cmVzID0gW3tcclxuICAgICAgICBhdHRyaWJ1dGVzIDoge1xyXG4gICAgICAgICAgSGF6YXJkSUQ6IGluY2lkZW50LmhhemFyZC5pZCxcclxuICAgICAgICAgIE5hbWUgOiBpbmNpZGVudC5uYW1lLFxyXG4gICAgICAgICAgRGVzY3JpcHRpb246IGluY2lkZW50LmRlc2NyaXB0aW9uLFxyXG4gICAgICAgICAgU3RhcnREYXRlIDogU3RyaW5nKGluY2lkZW50LnN0YXJ0RGF0ZSksXHJcbiAgICAgICAgICBFbmREYXRlIDogU3RyaW5nKGluY2lkZW50LmVuZERhdGUpXHJcbiAgICAgICAgfVxyXG4gICAgICB9XVxyXG5cclxuICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmNpZGVudHMsIGZlYXR1cmVzLCBjb25maWcpO1xyXG5cclxuICAgICAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmxlbmd0aCA+IDApe1xyXG4gICAgICAgIHJldHVybnt9IFxyXG4gICAgICB9XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZXJyb3JzOiAnSW5jaWRlbnQgY291bGQgbm90IGJlIHNhdmVkLidcclxuICAgICAgfVxyXG4gICAgfWNhdGNoKGUpIHtcclxuICAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdjcmVhdGVJbmNpZGVudCcpO1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGVycm9yczogJ0luY2lkZW50IGNvdWxkIG5vdCBiZSBzYXZlZC4nXHJcbiAgICAgIH1cclxuICAgIH1cclxufVxyXG5cclxuLy89PT09PT09PT09PT09PT09PT09PVBSSVZBVEU9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxyXG5cclxuY29uc3QgcmVxdWVzdERhdGEgPSBhc3luYyAodXJsOiBzdHJpbmcsIGNvbnRyb2xsZXI/OiBhbnkpOiBQcm9taXNlPElGZWF0dXJlU2V0PiA9PiB7XHJcbiAgaWYgKCFjb250cm9sbGVyKSB7XHJcbiAgICBjb250cm9sbGVyID0gbmV3IEFib3J0Q29udHJvbGxlcigpO1xyXG4gIH1cclxuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGZldGNoKHVybCwge1xyXG4gICAgbWV0aG9kOiBcIkdFVFwiLFxyXG4gICAgaGVhZGVyczoge1xyXG4gICAgICAnY29udGVudC10eXBlJzogJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcclxuICAgIH0sXHJcbiAgICBzaWduYWw6IGNvbnRyb2xsZXIuc2lnbmFsXHJcbiAgfVxyXG4gICk7XHJcbiAgcmV0dXJuIHJlc3BvbnNlLmpzb24oKTtcclxufVxyXG5cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldFRlbXBsYXRlKFxyXG4gIHRlbXBsYXRlRmVhdHVyZTogSUZlYXR1cmUsIFxyXG4gIGxpZmVsaW5lRmVhdHVyZXM6IElGZWF0dXJlW10sIFxyXG4gIGNvbXBvbmVudEZlYXR1cmVzOiBJRmVhdHVyZVtdLCBcclxuICBpbmRpY2F0b3JzRmVhdHVyZXM6IElGZWF0dXJlW10sIFxyXG4gIHdlaWdodHNGZWF0dXJlczogSUZlYXR1cmVbXSwgXHJcbiAgdGVtcGxhdGVEb21haW5zOiBJQ29kZWRWYWx1ZVtdKTogUHJvbWlzZTxDTFNTVGVtcGxhdGU+e1xyXG5cclxuICBjb25zdCBpbmRpY2F0b3JGZWF0dXJlcyA9IGluZGljYXRvcnNGZWF0dXJlcy5maWx0ZXIoaSA9PiBpLmF0dHJpYnV0ZXMuVGVtcGxhdGVJRCA9IGAnJHt0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRH0nYCkvLyAgYXdhaXQgZ2V0SW5kaWNhdG9yRmVhdHVyZXMoYFRlbXBsYXRlSUQ9JyR7dGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUR9J2AsIGNvbmZpZyk7XHJcbiAgXHJcbiAgLy9jb25zdCBxdWVyeSA9IGluZGljYXRvckZlYXR1cmVzLm1hcChpID0+IGBJbmRpY2F0b3JJRD0nJHtpLmF0dHJpYnV0ZXMuR2xvYmFsSUQudG9VcHBlckNhc2UoKX0nYCkuam9pbignIE9SICcpXHJcbiAgXHJcbiAgY29uc3QgaW5kaWNhdG9ySWRzID0gaW5kaWNhdG9yRmVhdHVyZXMubWFwKGkgPT4gaS5hdHRyaWJ1dGVzLkdsb2JhbElEKTtcclxuICBjb25zdCB3ZWlnaHRGZWF0dXJlcyA9IHdlaWdodHNGZWF0dXJlcy5maWx0ZXIodyA9PiBpbmRpY2F0b3JJZHMuaW5kZXhPZih3LmF0dHJpYnV0ZXMuSW5kaWNhdG9ySUQpKSAvL2F3YWl0IGdldFdlaWdodHNGZWF0dXJlcyhxdWVyeSwgY29uZmlnKTtcclxuICBcclxuICBjb25zdCBpbmRpY2F0b3JUZW1wbGF0ZXMgPSBpbmRpY2F0b3JGZWF0dXJlcy5tYXAoKGZlYXR1cmU6IElGZWF0dXJlKSA9PiB7XHJcblxyXG4gICAgIGNvbnN0IHdlaWdodHMgPSB3ZWlnaHRzRmVhdHVyZXNcclxuICAgICAgLmZpbHRlcih3ID0+IHcuYXR0cmlidXRlcy5JbmRpY2F0b3JJRD09PWZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRClcclxuICAgICAgLm1hcCh3ID0+IHtcclxuICAgICAgIHJldHVybiB7IFxyXG4gICAgICAgIG9iamVjdElkOiB3LmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgICAgbmFtZTogdy5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgd2VpZ2h0OiB3LmF0dHJpYnV0ZXMuV2VpZ2h0LFxyXG4gICAgICAgIHNjYWxlRmFjdG9yIDogdy5hdHRyaWJ1dGVzLlNjYWxlRmFjdG9yLCBcclxuICAgICAgICBhZGp1c3RlZFdlaWdodDogdy5hdHRyaWJ1dGVzLkFkanVzdGVkV2VpZ2h0LFxyXG4gICAgICAgIG1heEFkanVzdGVkV2VpZ2h0OiB3LmF0dHJpYnV0ZXMuTWF4QWRqdXN0ZWRXZWlnaHRcclxuICAgICAgIH0gYXMgSW5kaWNhdG9yV2VpZ2h0XHJcbiAgICAgfSlcclxuXHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgb2JqZWN0SWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgaWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCwgXHJcbiAgICAgIG5hbWU6IGZlYXR1cmUuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICB0ZW1wbGF0ZU5hbWU6IGZlYXR1cmUuYXR0cmlidXRlcy5UZW1wbGF0ZU5hbWUsXHJcbiAgICAgIHdlaWdodHMsXHJcbiAgICAgIGNvbXBvbmVudElkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuQ29tcG9uZW50SUQsXHJcbiAgICAgIHRlbXBsYXRlSWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5UZW1wbGF0ZUlELCAgXHJcbiAgICAgIGNvbXBvbmVudE5hbWU6IGZlYXR1cmUuYXR0cmlidXRlcy5Db21wb25lbnROYW1lLFxyXG4gICAgICBsaWZlbGluZU5hbWU6IGZlYXR1cmUuYXR0cmlidXRlcy5MaWZlbGluZU5hbWVcclxuICAgICB9IGFzIEluZGljYXRvclRlbXBsYXRlXHJcbiAgfSk7XHJcblxyXG4gIGNvbnN0IGNvbXBvbmVudFRlbXBsYXRlcyA9IGNvbXBvbmVudEZlYXR1cmVzLm1hcCgoZmVhdHVyZTogSUZlYXR1cmUpID0+IHtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICAgIGlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgICAgdGl0bGU6IGZlYXR1cmUuYXR0cmlidXRlcy5EaXNwbGF5TmFtZSB8fCBmZWF0dXJlLmF0dHJpYnV0ZXMuRGlzcGxheVRpdGxlLFxyXG4gICAgICAgIG5hbWU6IGZlYXR1cmUuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgIGxpZmVsaW5lSWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5MaWZlbGluZUlELFxyXG4gICAgICAgIGluZGljYXRvcnM6IChpbmRpY2F0b3JUZW1wbGF0ZXMuZmlsdGVyKGkgPT4gaS5jb21wb25lbnRJZCA9PT0gZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEKSBhcyBhbnkpLm9yZGVyQnkoJ25hbWUnKVxyXG4gICAgIH1cclxuICB9KTtcclxuXHJcbiAgY29uc3QgbGlmZWxpbmVUZW1wbGF0ZXMgPSBsaWZlbGluZUZlYXR1cmVzLm1hcCgoZmVhdHVyZTogSUZlYXR1cmUpID0+IHtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgIHRpdGxlOiBmZWF0dXJlLmF0dHJpYnV0ZXMuRGlzcGxheU5hbWUgfHwgZmVhdHVyZS5hdHRyaWJ1dGVzLkRpc3BsYXlUaXRsZSxcclxuICAgICAgbmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUsICAgICAgXHJcbiAgICAgIGNvbXBvbmVudFRlbXBsYXRlczogKGNvbXBvbmVudFRlbXBsYXRlcy5maWx0ZXIoYyA9PiBjLmxpZmVsaW5lSWQgPT09IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCkgYXMgYW55KS5vcmRlckJ5KCd0aXRsZScpXHJcbiAgICB9IGFzIExpZmVMaW5lVGVtcGxhdGU7XHJcbiAgfSk7XHJcblxyXG4gIGNvbnN0IHRlbXBsYXRlID0ge1xyXG4gICAgICBvYmplY3RJZDogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgIGlkOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgaXNTZWxlY3RlZDogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuSXNTZWxlY3RlZCA9PSAxLFxyXG4gICAgICBzdGF0dXM6IHtcclxuICAgICAgICBjb2RlOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5TdGF0dXMsXHJcbiAgICAgICAgbmFtZTogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuU3RhdHVzID09PSAxID8gXCJBY3RpdmVcIjogJ0FyY2hpdmVkJ1xyXG4gICAgICB9IGFzIElDb2RlZFZhbHVlLFxyXG4gICAgICBuYW1lOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICBoYXphcmROYW1lOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5IYXphcmROYW1lLFxyXG4gICAgICBoYXphcmRUeXBlOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5IYXphcmRUeXBlLFxyXG4gICAgICBvcmdhbml6YXRpb25OYW1lOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5Pcmdhbml6YXRpb25OYW1lLFxyXG4gICAgICBvcmdhbml6YXRpb25UeXBlOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5Pcmdhbml6YXRpb25UeXBlLCBcclxuICAgICAgY3JlYXRvcjogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuQ3JlYXRvcixcclxuICAgICAgY3JlYXRlZERhdGU6IE51bWJlcih0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5DcmVhdGVkRGF0ZSksXHJcbiAgICAgIGVkaXRvcjogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuRWRpdG9yLFxyXG4gICAgICBlZGl0ZWREYXRlOiBOdW1iZXIodGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuRWRpdGVkRGF0ZSksXHJcbiAgICAgIGxpZmVsaW5lVGVtcGxhdGVzOiAgKGxpZmVsaW5lVGVtcGxhdGVzIGFzIGFueSkub3JkZXJCeSgndGl0bGUnKSxcclxuICAgICAgZG9tYWluczogdGVtcGxhdGVEb21haW5zXHJcbiAgfSBhcyBDTFNTVGVtcGxhdGU7XHJcblxyXG4gIHJldHVybiB0ZW1wbGF0ZTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gc2F2ZUFzc2Vzc21lbnQoYXNzZXNzbWVudDogQXNzZXNzbWVudCwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxzdHJpbmc+PntcclxuXHJcbiAgdHJ5e1xyXG4gICAgY29uc3QgZmVhdHVyZSA9IHtcclxuICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgIE5hbWUgOmFzc2Vzc21lbnQubmFtZSxcclxuICAgICAgICBEZXNjcmlwdGlvbjogYXNzZXNzbWVudC5kZXNjcmlwdGlvbixcclxuICAgICAgICBBc3Nlc3NtZW50VHlwZTogYXNzZXNzbWVudC5hc3Nlc3NtZW50VHlwZSwgXHJcbiAgICAgICAgT3JnYW5pemF0aW9uOiBhc3Nlc3NtZW50Lm9yZ2FuaXphdGlvbiwgXHJcbiAgICAgICAgSW5jaWRlbnQ6IGFzc2Vzc21lbnQuaW5jaWRlbnQsIFxyXG4gICAgICAgIEhhemFyZDogYXNzZXNzbWVudC5oYXphcmQsIFxyXG4gICAgICAgIENyZWF0b3I6IGFzc2Vzc21lbnQuY3JlYXRvciwgXHJcbiAgICAgICAgQ3JlYXRlZERhdGU6IGFzc2Vzc21lbnQuY3JlYXRlZERhdGUsIFxyXG4gICAgICAgIEVkaXRvcjogYXNzZXNzbWVudC5lZGl0b3IsIFxyXG4gICAgICAgIEVkaXRlZERhdGU6IGFzc2Vzc21lbnQuZWRpdGVkRGF0ZSwgXHJcbiAgICAgICAgSXNDb21wbGV0ZWQ6IGFzc2Vzc21lbnQuaXNDb21wbGV0ZWQsIFxyXG4gICAgICAgIEhhemFyZFR5cGU6IGFzc2Vzc21lbnQuaGF6YXJkVHlwZSxcclxuICAgICAgICBPcmdhbml6YXRpb25UeXBlOmFzc2Vzc21lbnQub3JnYW5pemF0aW9uVHlwZSxcclxuICAgICAgICBUZW1wbGF0ZTogYXNzZXNzbWVudC50ZW1wbGF0ZVxyXG4gICAgICB9XHJcbiAgICB9XHJcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmFzc2Vzc21lbnRzLFtmZWF0dXJlXSwgY29uZmlnKTtcclxuICAgIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgICByZXR1cm57IGRhdGE6IHJlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWR9XHJcbiAgICB9XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBlcnJvcnM6ICBKU09OLnN0cmluZ2lmeShyZXNwb25zZSkgICAgXHJcbiAgICB9XHJcblxyXG4gIH1jYXRjaChlKXtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGVycm9yczogZVxyXG4gICAgfVxyXG4gIH1cclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0SW5kaWNhdG9yQXNzZXNzbWVudHMocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPEluZGljYXRvckFzc2Vzc21lbnRbXT57XHJcbiAgY29uc29sZS5sb2coJ2dldCBJbmRpY2F0b3IgQXNzZXNzbWVudHMgY2FsbGVkLicpXHJcblxyXG4gIGNvbnN0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JBc3Nlc3NtZW50cywgcXVlcnksIGNvbmZpZyk7XHJcbiAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMCl7XHJcbiAgICAgcmV0dXJuIGZlYXR1cmVzLm1hcChmZWF0dXJlID0+IHsgICAgICAgIFxyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBvYmplY3RJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICAgICAgaWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgICAgIGluZGljYXRvcklkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuSW5kaWNhdG9ySUQsXHJcbiAgICAgICAgICBpbmRpY2F0b3I6IGZlYXR1cmUuYXR0cmlidXRlcy5JbmRpY2F0b3JOYW1lLFxyXG4gICAgICAgICAgdGVtcGxhdGU6IGZlYXR1cmUuYXR0cmlidXRlcy5UZW1wbGF0ZU5hbWUsXHJcbiAgICAgICAgICBsaWZlbGluZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVsaW5lTmFtZSxcclxuICAgICAgICAgIGNvbXBvbmVudDogZmVhdHVyZS5hdHRyaWJ1dGVzLkNvbXBvbmVudE5hbWUsICAgICAgICAgIFxyXG4gICAgICAgICAgY29tbWVudHM6IHBhcnNlQ29tbWVudChmZWF0dXJlLmF0dHJpYnV0ZXMuQ29tbWVudHMpLCAgICAgICAgICBcclxuICAgICAgICAgIGxpZmVsaW5lU3RhdHVzSWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5MaWZlbGluZVN0YXR1c0lELFxyXG4gICAgICAgICAgZW52aXJvbm1lbnRQcmVzZXJ2YXRpb246IGZlYXR1cmUuYXR0cmlidXRlcy5FbnZpcm9ubWVudFByZXNlcnZhdGlvbixcclxuICAgICAgICAgIGluY2lkZW50U3RhYmlsaXphdGlvbjogZmVhdHVyZS5hdHRyaWJ1dGVzLkluY2lkZW50U3RhYmlsaXphdGlvbixcclxuICAgICAgICAgIHJhbms6IGZlYXR1cmUuYXR0cmlidXRlcy5SYW5rLFxyXG4gICAgICAgICAgbGlmZVNhZmV0eTogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVTYWZldHksXHJcbiAgICAgICAgICBwcm9wZXJ0eVByb3RlY3Rpb246IGZlYXR1cmUuYXR0cmlidXRlcy5Qcm9wZXJ0eVByb3RlY3Rpb24sXHJcbiAgICAgICAgICBzdGF0dXM6IGZlYXR1cmUuYXR0cmlidXRlcy5TdGF0dXNcclxuICAgICAgICB9IGFzIEluZGljYXRvckFzc2Vzc21lbnQ7XHJcbiAgICAgfSlcclxuICB9XHJcblxyXG59XHJcblxyXG5mdW5jdGlvbiBwYXJzZUNvbW1lbnQoY29tbWVudHM6IHN0cmluZyl7XHJcbiAgaWYoIWNvbW1lbnRzIHx8IGNvbW1lbnRzID09PSBcIlwiKXtcclxuICAgIHJldHVybiBbXTtcclxuICB9XHJcbiAgbGV0IHBhcnNlZENvbW1lbnRzID0gSlNPTi5wYXJzZShjb21tZW50cykgYXMgSW5Db21tZW50W107XHJcbiAgXHJcbiAgaWYocGFyc2VkQ29tbWVudHMgJiYgcGFyc2VkQ29tbWVudHMubGVuZ3RoID4gMCl7XHJcbiAgICBwYXJzZWRDb21tZW50cy5tYXAoKGNvbW1lbnREYXRhOiBJbkNvbW1lbnQpID0+IHtcclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAuLi5jb21tZW50RGF0YSxcclxuICAgICAgICAgICAgZGF0ZXRpbWU6IE51bWJlcihjb21tZW50RGF0YS5kYXRldGltZSlcclxuICAgICAgICB9IGFzIEluQ29tbWVudFxyXG4gICAgfSk7XHJcbiAgICBwYXJzZWRDb21tZW50cyA9IChwYXJzZWRDb21tZW50cyBhcyBhbnkpLm9yZGVyQnkoJ2RhdGV0aW1lJywgdHJ1ZSk7XHJcbiAgfWVsc2V7XHJcbiAgICBwYXJzZWRDb21tZW50cyA9IFtdO1xyXG4gIH1cclxuICBcclxuICByZXR1cm4gcGFyc2VkQ29tbWVudHM7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldExpZmVsaW5lU3RhdHVzRmVhdHVyZXMoY29uZmlnLCBxdWVyeSkge1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgTGlmZWxpbmUgU3RhdHVzIGNhbGxlZCcpXHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIHF1ZXJ5LCBjb25maWcpO1xyXG59XHJcblxyXG5mdW5jdGlvbiBsb2FkQXNzZXNzbWVudChhc3Nlc3NtZW50RmVhdHVyZTogSUZlYXR1cmUsIGxzRmVhdHVyZXM6IElGZWF0dXJlW10sIFxyXG4gIGluZGljYXRvckFzc2Vzc21lbnRzOiBJbmRpY2F0b3JBc3Nlc3NtZW50W10pOiBBc3Nlc3NtZW50eyAgIFxyXG5cclxuICBjb25zdCBsaWZlbGluZVN0YXR1c2VzID0gbHNGZWF0dXJlcy5tYXAoKGZlYXR1cmUpID0+IHsgXHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBvYmplY3RJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICBpZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICBhc3Nlc3NtZW50SWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5Bc3Nlc3NtZW50SUQsXHJcbiAgICAgIGxpZmVsaW5lTmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVsaW5lTmFtZSxcclxuICAgICAgaW5kaWNhdG9yQXNzZXNzbWVudHM6IGluZGljYXRvckFzc2Vzc21lbnRzLmZpbHRlcihpID0+IGkubGlmZWxpbmVTdGF0dXNJZCA9PT0gZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEKSwgICAgICBcclxuICAgICAgc2NvcmU6IGZlYXR1cmUuYXR0cmlidXRlcy5TY29yZSxcclxuICAgICAgY29sb3I6IGZlYXR1cmUuYXR0cmlidXRlcy5Db2xvcixcclxuICAgICAgaXNPdmVycmlkZW46IGZlYXR1cmUuYXR0cmlidXRlcy5Jc092ZXJyaWRlbixcclxuICAgICAgb3ZlcnJpZGVTY29yZTpmZWF0dXJlLmF0dHJpYnV0ZXMuT3ZlcnJpZGVuU2NvcmUsXHJcbiAgICAgIG92ZXJyaWRlbkJ5OiBmZWF0dXJlLmF0dHJpYnV0ZXMuT3ZlcnJpZGVuQnksXHJcbiAgICAgIG92ZXJyaWRlbkNvbG9yOiBmZWF0dXJlLmF0dHJpYnV0ZXMuT3ZlcnJpZGVuQ29sb3IsICAgICBcclxuICAgICAgb3ZlcnJpZGVDb21tZW50OiBmZWF0dXJlLmF0dHJpYnV0ZXMuT3ZlcnJpZGVDb21tZW50ICAgICAgXHJcbiAgICB9IGFzIExpZmVsaW5lU3RhdHVzO1xyXG4gIH0pO1xyXG5cclxuICBjb25zdCBhc3Nlc3NtZW50ID0ge1xyXG4gICAgb2JqZWN0SWQ6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICBpZDogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgIG5hbWU6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgIGFzc2Vzc21lbnRUeXBlOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkFzc2Vzc21lbnRUeXBlLFxyXG4gICAgbGlmZWxpbmVTdGF0dXNlczogbGlmZWxpbmVTdGF0dXNlcyxcclxuICAgIGRlc2NyaXB0aW9uOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkRlc2NyaXB0aW9uLFxyXG4gICAgdGVtcGxhdGU6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuVGVtcGxhdGUsXHJcbiAgICBvcmdhbml6YXRpb246IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuT3JnYW5pemF0aW9uLFxyXG4gICAgb3JnYW5pemF0aW9uVHlwZTogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5Pcmdhbml6YXRpb25UeXBlLFxyXG4gICAgaW5jaWRlbnQ6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuSW5jaWRlbnQsXHJcbiAgICBoYXphcmQ6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuSGF6YXJkLFxyXG4gICAgaGF6YXJkVHlwZTogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5IYXphcmRUeXBlLFxyXG4gICAgY3JlYXRvcjogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5DcmVhdG9yLFxyXG4gICAgY3JlYXRlZERhdGU6IE51bWJlcihhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkNyZWF0ZWREYXRlKSxcclxuICAgIGVkaXRvcjogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5FZGl0b3IsXHJcbiAgICBlZGl0ZWREYXRlOiBOdW1iZXIoYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5FZGl0ZWREYXRlKSxcclxuICAgIGlzU2VsZWN0ZWQ6IGZhbHNlLFxyXG4gICAgaXNDb21wbGV0ZWQ6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuSXNDb21wbGV0ZWQsXHJcbiAgfSBhcyBBc3Nlc3NtZW50XHJcblxyXG4gIHJldHVybiBhc3Nlc3NtZW50OyAgXHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIHNhdmVMaWZlbGluZVN0YXR1cyhsaWZlbGluZVN0YXR1c0ZlYXR1cmU6IElGZWF0dXJlLCBsc0luZEFzc2Vzc0ZlYXR1cmVzOiBJRmVhdHVyZVtdLCBjb25maWcpOiBQcm9taXNlPGJvb2xlYW4+e1xyXG4gIGxldCByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBbbGlmZWxpbmVTdGF0dXNGZWF0dXJlXSwgY29uZmlnKVxyXG4gIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShlID0+IGUuc3VjY2Vzcykpe1xyXG4gICAgIGNvbnN0IGdsb2JhbElkID0gcmVzcG9uc2UuYWRkUmVzdWx0c1swXS5nbG9iYWxJZDtcclxuXHJcbiAgICAgY29uc3QgaW5kaWNhdG9yQXNzZXNzbWVudEZlYXR1cmVzID0gbHNJbmRBc3Nlc3NGZWF0dXJlcy5tYXAoaW5kID0+IHtcclxuICAgICAgICBpbmQuYXR0cmlidXRlcy5MaWZlbGluZVN0YXR1c0lEID0gZ2xvYmFsSWRcclxuICAgICAgICByZXR1cm4gaW5kO1xyXG4gICAgIH0pXHJcbiAgICAgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JBc3Nlc3NtZW50cywgaW5kaWNhdG9yQXNzZXNzbWVudEZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShlID0+IGUuc3VjY2Vzcykpe1xyXG4gICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgfVxyXG4gIH1cclxufVxyXG5cclxuZnVuY3Rpb24gZ2V0VGVtcGxhdGVJbmRpY2F0b3JzKHRlbXBsYXRlOiBDTFNTVGVtcGxhdGUpOiBJbmRpY2F0b3JUZW1wbGF0ZVtdIHtcclxuICByZXR1cm4gW10uY29uY2F0LmFwcGx5KFtdLCAoW10uY29uY2F0LmFwcGx5KFtdLCBcclxuICAgdGVtcGxhdGUubGlmZWxpbmVUZW1wbGF0ZXMubWFwKGwgPT4gbC5jb21wb25lbnRUZW1wbGF0ZXMpKSlcclxuICAgLm1hcCgoYzogQ29tcG9uZW50VGVtcGxhdGUpID0+IGMuaW5kaWNhdG9ycykpO1xyXG59IiwiLy9BZGFwdGVkIGZyb20gLy9odHRwczovL2dpdGh1Yi5jb20vb2RvZS9tYXAtdnVlL2Jsb2IvbWFzdGVyL3NyYy9kYXRhL2F1dGgudHNcclxuXHJcbmltcG9ydCB7IGxvYWRBcmNHSVNKU0FQSU1vZHVsZXMgfSBmcm9tIFwiamltdS1hcmNnaXNcIjtcclxuXHJcbi8qKlxyXG4gKiBBdHRlbXB0IHRvIHNpZ24gaW4sXHJcbiAqIGZpcnN0IGNoZWNrIGN1cnJlbnQgc3RhdHVzXHJcbiAqIGlmIG5vdCBzaWduZWQgaW4sIHRoZW4gZ28gdGhyb3VnaFxyXG4gKiBzdGVwcyB0byBnZXQgY3JlZGVudGlhbHNcclxuICovXHJcbmV4cG9ydCBjb25zdCBzaWduSW4gPSBhc3luYyAoYXBwSWQ6IHN0cmluZywgcG9ydGFsVXJsOiBzdHJpbmcpID0+IHtcclxuICAgIHRyeSB7XHJcbiAgICAgICAgcmV0dXJuIGF3YWl0IGNoZWNrQ3VycmVudFN0YXR1cyhhcHBJZCwgcG9ydGFsVXJsKTtcclxuICAgIH0gY2F0Y2ggKGVycm9yKSB7XHJcbiAgICAgICAgY29uc29sZS5sb2coZXJyb3IpO1xyXG4gICAgICAgIHJldHVybiBhd2FpdCBmZXRjaENyZWRlbnRpYWxzKGFwcElkLCBwb3J0YWxVcmwpO1xyXG4gICAgfVxyXG59O1xyXG5cclxuLyoqXHJcbiAqIFNpZ24gdGhlIHVzZXIgb3V0LCBidXQgaWYgd2UgY2hlY2tlZCBjcmVkZW50aWFsc1xyXG4gKiBtYW51YWxseSwgbWFrZSBzdXJlIHRoZXkgYXJlIHJlZ2lzdGVyZWQgd2l0aFxyXG4gKiBJZGVudGl0eU1hbmFnZXIsIHNvIGl0IGNhbiBkZXN0cm95IHRoZW0gcHJvcGVybHlcclxuICovXHJcbmV4cG9ydCBjb25zdCBzaWduT3V0ID0gYXN5bmMgKGFwcElkOiBzdHJpbmcsIHBvcnRhbFVybDogc3RyaW5nKSA9PiB7XHJcbiAgICBjb25zdCBJZGVudGl0eU1hbmFnZXIgPSBhd2FpdCBsb2FkTW9kdWxlcyhhcHBJZCwgcG9ydGFsVXJsKTtcclxuICAgIGF3YWl0IHNpZ25JbihhcHBJZCwgcG9ydGFsVXJsKTtcclxuXHJcbiAgICBkZWxldGUgd2luZG93WydJZGVudGl0eU1hbmFnZXInXTtcclxuICAgIGRlbGV0ZSB3aW5kb3dbJ09BdXRoSW5mbyddO1xyXG4gICAgSWRlbnRpdHlNYW5hZ2VyLmRlc3Ryb3lDcmVkZW50aWFscygpO1xyXG4gICAgXHJcbn07XHJcblxyXG4vKipcclxuICogR2V0IHRoZSBjcmVkZW50aWFscyBmb3IgdGhlIHByb3ZpZGVkIHBvcnRhbFxyXG4gKi9cclxuYXN5bmMgZnVuY3Rpb24gZmV0Y2hDcmVkZW50aWFscyhhcHBJZDogc3RyaW5nLCBwb3J0YWxVcmw6IHN0cmluZyl7XHJcbiAgICBjb25zdCBJZGVudGl0eU1hbmFnZXIgPSBhd2FpdCBsb2FkTW9kdWxlcyhhcHBJZCwgcG9ydGFsVXJsKTtcclxuICAgIGNvbnN0IGNyZWRlbnRpYWwgPSBhd2FpdCBJZGVudGl0eU1hbmFnZXIuZ2V0Q3JlZGVudGlhbChgJHtwb3J0YWxVcmx9L3NoYXJpbmdgLCB7XHJcbiAgICAgICAgZXJyb3I6IG51bGwgYXMgYW55LFxyXG4gICAgICAgIG9BdXRoUG9wdXBDb25maXJtYXRpb246IGZhbHNlLFxyXG4gICAgICAgIHRva2VuOiBudWxsIGFzIGFueVxyXG4gICAgfSk7XHJcbiAgICByZXR1cm4gY3JlZGVudGlhbDtcclxufTtcclxuXHJcbi8qKlxyXG4gKiBJbXBvcnQgSWRlbnRpdHkgTWFuYWdlciwgYW5kIE9BdXRoSW5mb1xyXG4gKi9cclxuYXN5bmMgZnVuY3Rpb24gbG9hZE1vZHVsZXMoYXBwSWQ6IHN0cmluZywgcG9ydGFsVXJsOiBzdHJpbmcpIHtcclxuICAgIGxldCBJZGVudGl0eU1hbmFnZXIgPSB3aW5kb3dbJ0lkZW50aXR5TWFuYWdlciddXHJcbiAgICBpZighSWRlbnRpdHlNYW5hZ2VyKXtcclxuICAgICAgICBjb25zdCBtb2R1bGVzID0gYXdhaXQgbG9hZEFyY0dJU0pTQVBJTW9kdWxlcyhbXHJcbiAgICAgICAgICAgICdlc3JpL2lkZW50aXR5L0lkZW50aXR5TWFuYWdlcicsXHJcbiAgICAgICAgICAgICdlc3JpL2lkZW50aXR5L09BdXRoSW5mbyddKTtcclxuXHJcbiAgICAgICAgICAgIHdpbmRvd1snSWRlbnRpdHlNYW5hZ2VyJ10gPSBtb2R1bGVzWzBdO1xyXG4gICAgICAgICAgICB3aW5kb3dbJ09BdXRoSW5mbyddID0gbW9kdWxlc1sxXTtcclxuICAgICAgICAgICAgXHJcbiAgICAgICAgSWRlbnRpdHlNYW5hZ2VyID0gbW9kdWxlc1swXTtcclxuICAgICAgICBjb25zdCBPQXV0aEluZm8gPSBtb2R1bGVzWzFdO1xyXG5cclxuICAgICAgICBjb25zdCBvYXV0aEluZm8gPSBuZXcgT0F1dGhJbmZvKHtcclxuICAgICAgICAgICAgYXBwSWQsXHJcbiAgICAgICAgICAgIHBvcnRhbFVybCxcclxuICAgICAgICAgICAgcG9wdXA6IGZhbHNlXHJcbiAgICAgICAgfSk7XHJcbiAgICAgICAgSWRlbnRpdHlNYW5hZ2VyLnJlZ2lzdGVyT0F1dGhJbmZvcyhbb2F1dGhJbmZvXSk7ICAgICAgICBcclxuICAgIH1cclxuICAgIHJldHVybiBJZGVudGl0eU1hbmFnZXI7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBDaGVjayBjdXJyZW50IGxvZ2dlZCBpbiBzdGF0dXMgZm9yIGN1cnJlbnQgcG9ydGFsXHJcbiAqL1xyXG5leHBvcnQgY29uc3QgY2hlY2tDdXJyZW50U3RhdHVzID0gYXN5bmMgKGFwcElkOiBzdHJpbmcsIHBvcnRhbFVybDogc3RyaW5nKSA9PiB7XHJcbiAgICBjb25zdCBJZGVudGl0eU1hbmFnZXIgPSBhd2FpdCBsb2FkTW9kdWxlcyhhcHBJZCwgcG9ydGFsVXJsKTtcclxuICAgIHJldHVybiBJZGVudGl0eU1hbmFnZXIuY2hlY2tTaWduSW5TdGF0dXMoYCR7cG9ydGFsVXJsfS9zaGFyaW5nYCk7XHJcbn07IiwiaW1wb3J0IHsgZXh0ZW5zaW9uU3BlYywgSW1tdXRhYmxlT2JqZWN0LCBJTVN0YXRlIH0gZnJvbSAnamltdS1jb3JlJztcclxuaW1wb3J0IHsgQXNzZXNzbWVudCwgQ0xTU19TdGF0ZSwgXHJcbiAgQ0xTU1RlbXBsYXRlLCBDbHNzVXNlciwgSGF6YXJkLCBcclxuICBMaWZlbGluZVN0YXR1cywgT3JnYW5pemF0aW9uLCBcclxuICBSYXRpbmdTY2FsZSwgU2NhbGVGYWN0b3IgfSBmcm9tICcuL2RhdGEtZGVmaW5pdGlvbnMnO1xyXG5pbXBvcnQgeyBJQ29kZWRWYWx1ZSB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LXR5cGVzJztcclxuaW1wb3J0IHsgSUNyZWRlbnRpYWwgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1hdXRoJztcclxuXHJcblxyXG5leHBvcnQgZW51bSBDTFNTQWN0aW9uS2V5cyB7XHJcbiAgQVVUSEVOVElDQVRFX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gYXV0aGVuaWNhdGUgY3JlZGVudGlhbHMnLFxyXG4gIExPQURfSEFaQVJEU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGxvYWQgaGF6YXJkcycsXHJcbiAgTE9BRF9IQVpBUkRfVFlQRVNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBsb2FkIGhhemFyZCB0eXBlcycsXHJcbiAgTE9BRF9PUkdBTklaQVRJT05TX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCBvcmdhbml6YXRpb25zJyxcclxuICBMT0FEX09SR0FOSVpBVElPTl9UWVBFU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGxvYWQgb3JnYW5pemF0aW9uIHR5cGVzJyxcclxuICBMT0FEX1RFTVBMQVRFU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGxvYWQgdGVtcGxhdGVzJyxcclxuICBMT0FEX1BSSU9SSVRJRVNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBsb2FkIHByaW9yaXRpZXMnLFxyXG4gIFNFTEVDVF9URU1QTEFURV9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIHNlbGVjdCB0ZW1wbGF0ZScsXHJcbiAgU0VBUkNIX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gc2VhcmNoIGZvciB0ZW1wbGF0ZScsXHJcbiAgU0lHTl9JTl9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIFNpZ24gaW4nLFxyXG4gIFNJR05fT1VUX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2lnbiBvdXQnLFxyXG4gIFNFVF9VU0VSX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2V0IENMU1MgVXNlcicsXHJcbiAgU0VUX0lERU5USVRZX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2V0IElkZW50aXR5JyxcclxuICBTRVRfRVJST1JTID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTZXQgZ2xvYmFsIGVycm9ycycsXHJcbiAgVE9HR0xFX0lORElDQVRPUl9FRElUSU5HID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBUb2dnbGUgaW5kaWNhdG9yIGVkaXRpbmcnLCAgXHJcbiAgU0VMRUNUX0xJRkVMSU5FU1RBVFVTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2VsZWN0IGEgbGlmZWxpbmUgc3RhdHVzJyxcclxuICBMT0FEX0FTU0VTU01FTlRTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gTG9hZCBhc3Nlc3NtZW50cycsXHJcbiAgU0VMRUNUX0FTU0VTU01FTlRfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTZWxlY3QgYXNzZXNzbWVudCcsXHJcbiAgTE9BRF9SQVRJTkdTQ0FMRVNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBMb2FkIHJhdGluZyBzY2FsZXMnLFxyXG4gIExPQURfU0NBTEVGQUNUT1JTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gTG9hZCBjb25zdGFudHMnXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9TY2FsZUZhY3RvcnNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9TQ0FMRUZBQ1RPUlNfQUNUSU9OLFxyXG4gIHZhbDogU2NhbGVGYWN0b3JbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfUmF0aW5nX1NjYWxlc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX1JBVElOR1NDQUxFU19BQ1RJT04sXHJcbiAgdmFsOiBSYXRpbmdTY2FsZVtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2VsZWN0X0Fzc2Vzc21lbnRfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VMRUNUX0FTU0VTU01FTlRfQUNUSU9OLFxyXG4gIHZhbDogQXNzZXNzbWVudFxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfQXNzZXNzbWVudHNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9BU1NFU1NNRU5UU19BQ1RJT04sXHJcbiAgdmFsOiBBc3Nlc3NtZW50W11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX1ByaW9yaXRpZXNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9QUklPUklUSUVTX0FDVElPTixcclxuICB2YWw6IGFueVtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9IYXphcmRfVHlwZXNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9IQVpBUkRfVFlQRVNfQUNUSU9OLFxyXG4gIHZhbDogSUNvZGVkVmFsdWVbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfT3JnYW5pemF0aW9uX1R5cGVzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfT1JHQU5JWkFUSU9OX1RZUEVTX0FDVElPTixcclxuICB2YWw6IElDb2RlZFZhbHVlW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZWxlY3RfTGlmZWxpbmVTdGF0dXNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VMRUNUX0xJRkVMSU5FU1RBVFVTX0FDVElPTixcclxuICB2YWw6IExpZmVsaW5lU3RhdHVzXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2V0X1RvZ2dsZV9JbmRpY2F0b3JfRWRpdGluZ19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5UT0dHTEVfSU5ESUNBVE9SX0VESVRJTkcsXHJcbiAgdmFsOiBzdHJpbmdcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZXRfRXJyb3JzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlMsXHJcbiAgdmFsOiBzdHJpbmdcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX0hhemFyZHNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9IQVpBUkRTX0FDVElPTixcclxuICB2YWw6IEhhemFyZFtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9Pcmdhbml6YXRpb25zX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfT1JHQU5JWkFUSU9OU19BQ1RJT04sXHJcbiAgdmFsOiBPcmdhbml6YXRpb25bXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNldElkZW50aXR5X0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFVF9JREVOVElUWV9BQ1RJT04sXHJcbiAgdmFsOiBDbHNzVXNlclxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNldFVzZXJfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VUX1VTRVJfQUNUSU9OLFxyXG4gIHZhbDogQ2xzc1VzZXJcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTaWduaW5fQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0lHTl9JTl9BQ1RJT05cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTaWdub3V0X0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNJR05fT1VUX0FDVElPTlxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNlbGVjdF9UZW1wbGF0ZV9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfVEVNUExBVEVfQUNUSU9OLFxyXG4gIHZhbDogc3RyaW5nXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9UZW1wbGF0ZXNfQWN0aW9uX1R5cGUge1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfVEVNUExBVEVTX0FDVElPTixcclxuICB2YWw6IENMU1NUZW1wbGF0ZVtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2VhcmNoX1RlbXBsYXRlc19BY3Rpb25fVHlwZSB7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VBUkNIX0FDVElPTixcclxuICB2YWw6IHN0cmluZ1xyXG59ICBcclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgQXV0aGVudGljYXRlX0FjdGlvbl9UeXBlIHtcclxuICAgdHlwZTogQ0xTU0FjdGlvbktleXMuQVVUSEVOVElDQVRFX0FDVElPTixcclxuICAgdmFsOiBJQ3JlZGVudGlhbDtcclxufVxyXG5cclxuXHJcbnR5cGUgQWN0aW9uVHlwZXMgPSBcclxuIFNlbGVjdF9UZW1wbGF0ZV9BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX1RlbXBsYXRlc19BY3Rpb25fVHlwZSB8IFxyXG4gU2VhcmNoX1RlbXBsYXRlc19BY3Rpb25fVHlwZSB8IFxyXG4gU2lnbmluX0FjdGlvbl9UeXBlIHxcclxuIFNpZ25vdXRfQWN0aW9uX1R5cGUgfFxyXG4gU2V0VXNlcl9BY3Rpb25fVHlwZSB8IFxyXG4gU2V0SWRlbnRpdHlfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9IYXphcmRzX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfT3JnYW5pemF0aW9uc19BY3Rpb25fVHlwZSB8XHJcbiBTZXRfRXJyb3JzX0FjdGlvbl9UeXBlIHxcclxuIFNldF9Ub2dnbGVfSW5kaWNhdG9yX0VkaXRpbmdfQWN0aW9uX1R5cGUgfFxyXG4gU2VsZWN0X0xpZmVsaW5lU3RhdHVzX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfSGF6YXJkX1R5cGVzX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfT3JnYW5pemF0aW9uX1R5cGVzX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfUHJpb3JpdGllc19BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX0Fzc2Vzc21lbnRzX0FjdGlvbl9UeXBlIHxcclxuIFNlbGVjdF9Bc3Nlc3NtZW50X0FjdGlvbl9UeXBlfCBcclxuIExvYWRfUmF0aW5nX1NjYWxlc19BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX1NjYWxlRmFjdG9yc19BY3Rpb25fVHlwZSB8XHJcbiBBdXRoZW50aWNhdGVfQWN0aW9uX1R5cGUgO1xyXG5cclxudHlwZSBJTU15U3RhdGUgPSBJbW11dGFibGVPYmplY3Q8Q0xTU19TdGF0ZT47XHJcblxyXG5kZWNsYXJlIG1vZHVsZSAnamltdS1jb3JlL2xpYi90eXBlcy9zdGF0ZSd7XHJcbiAgaW50ZXJmYWNlIFN0YXRle1xyXG4gICAgY2xzc1N0YXRlPzogSU1NeVN0YXRlXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBNeVJlZHV4U3RvcmVFeHRlbnNpb24gaW1wbGVtZW50cyBleHRlbnNpb25TcGVjLlJlZHV4U3RvcmVFeHRlbnNpb24ge1xyXG4gIGlkID0gJ2Nsc3MtcmVkdXgtc3RvcmUtZXh0ZW5zaW9uJztcclxuIFxyXG4gIGdldEFjdGlvbnMoKSB7XHJcbiAgICByZXR1cm4gT2JqZWN0LmtleXMoQ0xTU0FjdGlvbktleXMpLm1hcChrID0+IENMU1NBY3Rpb25LZXlzW2tdKTtcclxuICB9XHJcblxyXG4gIGdldEluaXRMb2NhbFN0YXRlKCkge1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgIHNlbGVjdGVkVGVtcGxhdGU6IG51bGwsXHJcbiAgICAgICB0ZW1wbGF0ZXM6IFtdLFxyXG4gICAgICAgc2VhcmNoUmVzdWx0czogW10sXHJcbiAgICAgICB1c2VyOiBudWxsLFxyXG4gICAgICAgYXV0aDogbnVsbCxcclxuICAgICAgIGlkZW50aXR5OiBudWxsLCAgICAgICBcclxuICAgICAgIG5ld1RlbXBsYXRlTW9kYWxWaXNpYmxlOiBmYWxzZSxcclxuICAgICAgIGhhemFyZHM6IFtdLFxyXG4gICAgICAgb3JnYW5pemF0aW9uczogW10sXHJcbiAgICAgICBlcnJvcnM6ICcnLFxyXG4gICAgICAgaXNJbmRpY2F0b3JFZGl0aW5nOiBmYWxzZSxcclxuICAgICAgIHNlbGVjdGVkTGlmZWxpbmVTdGF0dXM6IG51bGwsXHJcbiAgICAgICBvcmdhbml6YXRpb25UeXBlczogW10sXHJcbiAgICAgICBoYXphcmRUeXBlczogW10sXHJcbiAgICAgICBwcmlvcml0aWVzOiBbXSxcclxuICAgICAgIGFzc2Vzc21lbnRzOiBbXSxcclxuICAgICAgIHJhdGluZ1NjYWxlczogW10sXHJcbiAgICAgICBzY2FsZUZhY3RvcnM6IFtdLFxyXG4gICAgICAgYXV0aGVudGljYXRlOiBudWxsXHJcbiAgICB9IGFzIENMU1NfU3RhdGU7XHJcbiAgfVxyXG5cclxuICBnZXRSZWR1Y2VyKCkge1xyXG4gICAgcmV0dXJuIChsb2NhbFN0YXRlOiBJTU15U3RhdGUsIGFjdGlvbjogQWN0aW9uVHlwZXMsIGFwcFN0YXRlOiBJTVN0YXRlKTogSU1NeVN0YXRlID0+IHsgICAgICBcclxuICAgICAgXHJcbiAgICAgIHN3aXRjaCAoYWN0aW9uLnR5cGUpIHtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5BVVRIRU5USUNBVEVfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdhdXRoZW50aWNhdGUnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX1NDQUxFRkFDVE9SU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3NjYWxlRmFjdG9ycycsIGFjdGlvbi52YWwpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9SQVRJTkdTQ0FMRVNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdyYXRpbmdTY2FsZXMnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfQVNTRVNTTUVOVF9BQ1RJT046XHJcbiAgICAgICAgICBjb25zdCBhc3Nlc3NtZW50cyA9IGxvY2FsU3RhdGUuYXNzZXNzbWVudHMubWFwKGFzc2VzcyA9PiB7XHJcbiAgICAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAgIC4uLmFzc2VzcyxcclxuICAgICAgICAgICAgICBpc1NlbGVjdGVkOiBhc3Nlc3MuaWQgPT09IGFjdGlvbi52YWwuaWQudG9Mb3dlckNhc2UoKVxyXG4gICAgICAgICAgICAgfVxyXG4gICAgICAgICAgfSlcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnYXNzZXNzbWVudHMnLCBhc3Nlc3NtZW50cyk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9BU1NFU1NNRU5UU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2Fzc2Vzc21lbnRzJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9QUklPUklUSUVTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgncHJpb3JpdGllcycsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFTEVDVF9MSUZFTElORVNUQVRVU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3NlbGVjdGVkTGlmZWxpbmVTdGF0dXMnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5UT0dHTEVfSU5ESUNBVE9SX0VESVRJTkc6XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2lzSW5kaWNhdG9yRWRpdGluZycsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlM6XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2Vycm9ycycsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfSEFaQVJEU19BQ1RJT046ICBcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnaGF6YXJkcycsIGFjdGlvbi52YWwpXHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9IQVpBUkRfVFlQRVNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdoYXphcmRUeXBlcycsIGFjdGlvbi52YWwpXHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9PUkdBTklaQVRJT05fVFlQRVNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdvcmdhbml6YXRpb25UeXBlcycsIGFjdGlvbi52YWwpXHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9PUkdBTklaQVRJT05TX0FDVElPTjpcclxuICAgICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdvcmdhbml6YXRpb25zJywgYWN0aW9uLnZhbClcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5TRVRfSURFTlRJVFlfQUNUSU9OOiAgXHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2lkZW50aXR5JywgYWN0aW9uLnZhbCk7XHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5TRVRfVVNFUl9BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3VzZXInLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX1RFTVBMQVRFU19BQ1RJT046ICAgICAgICAgIFxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCd0ZW1wbGF0ZXMnLCBhY3Rpb24udmFsKTtcclxuICAgICAgICBcclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFTEVDVF9URU1QTEFURV9BQ1RJT046XHJcbiAgICAgICAgICBsZXQgdGVtcGxhdGVzID0gWy4uLmxvY2FsU3RhdGUudGVtcGxhdGVzXS5tYXAodCA9PiB7XHJcbiAgICAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAgIC4uLnQsXHJcbiAgICAgICAgICAgICAgaXNTZWxlY3RlZDogdC5pZCA9PT0gYWN0aW9uLnZhbFxyXG4gICAgICAgICAgICAgfSBcclxuICAgICAgICAgIH0pXHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3RlbXBsYXRlcycsIHRlbXBsYXRlcykgICAgICAgICAgICBcclxuICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGU7XHJcbiAgICAgIH1cclxuICAgIH1cclxuICB9XHJcblxyXG4gIGdldFN0b3JlS2V5KCkge1xyXG4gICAgcmV0dXJuICdjbHNzU3RhdGUnO1xyXG4gIH1cclxufSIsImV4cG9ydCBjb25zdCBDTFNTX0FETUlOID0gJ0NMU1NfQWRtaW4nO1xyXG5leHBvcnQgY29uc3QgQ0xTU19FRElUT1IgPSAnQ0xTU19FZGl0b3InO1xyXG5leHBvcnQgY29uc3QgQ0xTU19BU1NFU1NPUiA9ICdDTFNTX0Fzc2Vzc29yJztcclxuZXhwb3J0IGNvbnN0IENMU1NfVklFV0VSID0gJ0NMU1NfVmlld2VyJztcclxuZXhwb3J0IGNvbnN0IENMU1NfRk9MTE9XRVJTID0gJ0NMU1MgRm9sbG93ZXJzJztcclxuXHJcbmV4cG9ydCBjb25zdCBCQVNFTElORV9URU1QTEFURV9OQU1FID0gJ0Jhc2VsaW5lJztcclxuZXhwb3J0IGNvbnN0IFRPS0VOX0VSUk9SID0gJ1Rva2VuIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBURU1QTEFURV9VUkxfRVJST1IgPSAnVGVtcGxhdGUgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgQVNTRVNTTUVOVF9VUkxfRVJST1IgPSAnQXNzZXNzbWVudCBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBPUkdBTklaQVRJT05fVVJMX0VSUk9SID0gJ09yZ2FuaXphdGlvbiBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBIQVpBUkRfVVJMX0VSUk9SID0gJ0hhemFyZCBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBJTkRJQ0FUT1JfVVJMX0VSUk9SID0gJ0luZGljYXRvciBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBBTElHTk1FTlRfVVJMX0VSUk9SID0gJ0FsaWdubWVudHMgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgTElGRUxJTkVfVVJMX0VSUk9SID0gJ0xpZmVsaW5lIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IENPTVBPTkVOVF9VUkxfRVJST1IgPSAnQ29tcG9uZW50IEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IFBSSU9SSVRZX1VSTF9FUlJPUiA9ICdQcmlvcml0eSBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBJTkNJREVOVF9VUkxfRVJST1IgPSAnSW5jaWRlbnQgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgU0FWSU5HX1NBTUVfQVNfQkFTRUxJTkVfRVJST1IgPSAnQmFzZWxpbmUgdGVtcGxhdGUgY2Fubm90IGJlIHVwZGF0ZWQuIENoYW5nZSB0aGUgdGVtcGxhdGUgbmFtZSB0byBjcmVhdGUgYSBuZXcgb25lLidcclxuXHJcbmV4cG9ydCBjb25zdCBTVEFCSUxJWklOR19TQ0FMRV9GQUNUT1IgPSAnU3RhYmlsaXppbmdfU2NhbGVfRmFjdG9yJztcclxuZXhwb3J0IGNvbnN0IERFU1RBQklMSVpJTkdfU0NBTEVfRkFDVE9SID0gJ0Rlc3RhYmlsaXppbmdfU2NhbGVfRmFjdG9yJztcclxuZXhwb3J0IGNvbnN0IFVOQ0hBTkdFRF9TQ0FMRV9GQUNUT1IgPSAnVW5jaGFuZ2VkX0luZGljYXRvcnMnO1xyXG5leHBvcnQgY29uc3QgREVGQVVMVF9QUklPUklUWV9MRVZFTFMgPSBcIkRlZmF1bHRfUHJpb3JpdHlfTGV2ZWxzXCI7XHJcbmV4cG9ydCBjb25zdCBSQU5LID0gJ0ltcG9ydGFuY2Ugb2YgSW5kaWNhdG9yJztcclxuZXhwb3J0IGNvbnN0IExJRkVfU0FGRVRZID0gJ0xpZmUgU2FmZXR5JztcclxuZXhwb3J0IGNvbnN0IElOQ0lERU5UX1NUQUJJTElaQVRJT04gPSAnSW5jaWRlbnQgU3RhYmlsaXphdGlvbic7XHJcbmV4cG9ydCBjb25zdCBQUk9QRVJUWV9QUk9URUNUSU9OID0gJ1Byb3BlcnR5IFByb3RlY3Rpb24nO1xyXG5leHBvcnQgY29uc3QgRU5WSVJPTk1FTlRfUFJFU0VSVkFUSU9OID0gJ0Vudmlyb25tZW50IFByZXNlcnZhdGlvbic7XHJcblxyXG5leHBvcnQgY29uc3QgTElGRV9TQUZFVFlfU0NBTEVfRkFDVE9SID0gMjAwO1xyXG5leHBvcnQgY29uc3QgT1RIRVJfV0VJR0hUU19TQ0FMRV9GQUNUT1IgPSAxMDA7XHJcbmV4cG9ydCBjb25zdCBNQVhJTVVNX1dFSUdIVCA9IDU7XHJcblxyXG5leHBvcnQgZW51bSBVcGRhdGVBY3Rpb24ge1xyXG4gICAgSEVBREVSID0gJ2hlYWRlcicsXHJcbiAgICBJTkRJQ0FUT1JfTkFNRSA9ICdJbmRpY2F0b3IgTmFtZScsXHJcbiAgICBQUklPUklUSUVTID0gJ0luZGljYXRvciBQcmlvcml0aWVzJyxcclxuICAgIE5FV19JTkRJQ0FUT1IgPSAnQ3JlYXRlIE5ldyBJbmRpY2F0b3InLFxyXG4gICAgREVMRVRFX0lORElDQVRPUiA9ICdEZWxldGUgSW5kaWNhdG9yJ1xyXG59XHJcblxyXG5leHBvcnQgY29uc3QgSU5DTFVERV9JTkRJQ0FUT1IgPSAnSW1wYWN0ZWQgLSBZZXMgb3IgTm8nO1xyXG5leHBvcnQgY29uc3QgSU5DTFVERV9JTkRJQ0FUT1JfSEVMUCA9ICdZZXM6IFRoZSBpbmRpY2F0b3Igd2lsbCBiZSBjb25zaWRlcmVkIGluIHRoZSBhc3Nlc3NtZW50Llxcbk5vOiBUaGUgaW5kaWNhdG9yIHdpbGwgbm90IGJlIGNvbnNpZGVyZWQuXFxuVW5rbm93bjogTm90IHN1cmUgdG8gaW5jbHVkZSB0aGUgaW5kaWNhdG9yIGluIGFzc2Vzc21lbnQuJztcclxuXHJcbmV4cG9ydCBjb25zdCBJTkRJQ0FUT1JfU1RBVFVTID0gJ0luZGljYXRvciBJbXBhY3QgU3RhdHVzJztcclxuZXhwb3J0IGNvbnN0IElORElDQVRPUl9TVEFUVVNfSEVMUCA9ICdTdGFiaWxpemluZzogSGFzIHRoZSBpbmRpY2F0b3IgYmVlbiBpbXByb3ZlZCBvciBpbXByb3ZpbmcuXFxuRGVzdGFiaWxpemluZzogSXMgdGhlIGluZGljYXRvciBkZWdyYWRpbmcuXFxuVW5jaGFuZ2VkOiBObyBzaWduaWZpY2FudCBpbXByb3ZlbWVudCBzaW5jZSB0aGUgbGFzdCBhc3Nlc3NtZW50Lic7XHJcblxyXG5leHBvcnQgY29uc3QgQ09NTUVOVCA9ICdDb21tZW50JztcclxuZXhwb3J0IGNvbnN0IENPTU1FTlRfSEVMUCA9ICdQcm92aWRlIGp1c3RpZmljYXRpb24gZm9yIHRoZSBzZWxlY3RlZCBpbmRpY2F0b3Igc3RhdHVzLic7XHJcblxyXG5leHBvcnQgY29uc3QgREVMRVRFX0lORElDQVRPUl9DT05GSVJNQVRJT04gPSAnQXJlIHlvdSBzdXJlIHlvdSB3YW50IHRvIGRlbGV0ZSBpbmRpY2F0b3I/JztcclxuXHJcbi8vQ2VsbCBXZWlnaHQgPSAgVHJlbmQgKiAoICgtMSpSYW5rKSArIDZcclxuZXhwb3J0IGNvbnN0IENSSVRJQ0FMID0gMjU7XHJcbmV4cG9ydCBjb25zdCBDUklUSUNBTF9MT1dFUl9CT1VOREFSWSA9IDEyLjU7XHJcbmV4cG9ydCBjb25zdCBNT0RFUkFURV9MT1dFUl9CT1VOREFSWSA9IDUuNTtcclxuZXhwb3J0IGNvbnN0IE5PREFUQV9DT0xPUiA9ICcjOTE5Mzk1JztcclxuZXhwb3J0IGNvbnN0IE5PREFUQV9WQUxVRSA9IDk5OTk5OTtcclxuZXhwb3J0IGNvbnN0IFJFRF9DT0xPUiA9ICcjQzUyMDM4JztcclxuZXhwb3J0IGNvbnN0IFlFTExPV19DT0xPUiA9ICcjRkJCQTE2JztcclxuZXhwb3J0IGNvbnN0IEdSRUVOX0NPTE9SID0gJyM1RTlDNDInO1xyXG5leHBvcnQgY29uc3QgU0FWSU5HX1RJTUVSID0gMTUwMDtcclxuZXhwb3J0IGNvbnN0IElORElDQVRPUl9DT01NRU5UX0xFTkdUSCA9IDMwMDtcclxuXHJcbmV4cG9ydCBjb25zdCBQT1JUQUxfVVJMID0gJ2h0dHBzOi8vd3d3LmFyY2dpcy5jb20nO1xyXG5cclxuZXhwb3J0IGNvbnN0IERFRkFVTFRfTElTVElURU0gPSB7aWQ6ICcwMDAnLCBuYW1lOiAnLU5vbmUtJywgdGl0bGU6ICctTm9uZS0nfSBhcyBhbnk7XHJcblxyXG5leHBvcnQgY29uc3QgUkFOS19NRVNTQUdFID0gJ0hvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byB5b3VyIGp1cmlzZGljdGlvbiBvciBoYXphcmQ/JztcclxuZXhwb3J0IGNvbnN0IExJRkVfU0FGRVRZX01FU1NBR0UgPSAnSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIExpZmUgU2FmZXR5Pyc7XHJcbmV4cG9ydCBjb25zdCBQUk9QRVJUWV9QUk9URUNUSU9OX01FU1NBR0UgPSAnSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIFByb3BlcnR5IFByb3RlY3Rpb24/JztcclxuZXhwb3J0IGNvbnN0IEVOVklST05NRU5UX1BSRVNFUlZBVElPTl9NRVNTQUdFID0gJ0hvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byBFbnZpcm9ubWVudCBQcmVzZXJ2YXRpb24/JztcclxuZXhwb3J0IGNvbnN0IElOQ0lERU5UX1NUQUJJTElaQVRJT05fTUVTU0FHRSA9ICdIb3cgaW1wb3J0YW50IGlzIHRoZSBpbmRpY2F0b3IgdG8gSW5jaWRlbnQgU3RhYmlsaXphdGlvbj8nO1xyXG5cclxuZXhwb3J0IGNvbnN0IE9WRVJXUklURV9TQ09SRV9NRVNTQUdFID0gJ0EgY29tcGxldGVkIGFzc2Vzc21lbnQgY2Fubm90IGJlIGVkaXRlZC4gQXJlIHlvdSBzdXJlIHlvdSB3YW50IHRvIGNvbXBsZXRlIHRoaXMgYXNzZXNzbWVudD8nOyIsImltcG9ydCB7IFVzZXJTZXNzaW9uIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LWF1dGhcIjtcclxuaW1wb3J0IHsgcXVlcnlGZWF0dXJlcywgSVF1ZXJ5RmVhdHVyZXNSZXNwb25zZSwgXHJcbiAgICBJUmVsYXRlZFJlY29yZEdyb3VwLCBxdWVyeVJlbGF0ZWQsIHVwZGF0ZUZlYXR1cmVzLCBcclxuICAgIGFkZEZlYXR1cmVzLCBkZWxldGVGZWF0dXJlcyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyXCI7XHJcbmltcG9ydCB7IElGZWF0dXJlU2V0LCBJRmVhdHVyZSB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC10eXBlc1wiO1xyXG5pbXBvcnQgeyBBcHBXaWRnZXRDb25maWcgfSBmcm9tIFwiLi9kYXRhLWRlZmluaXRpb25zXCI7XHJcbmltcG9ydCB7IGxvZywgTG9nVHlwZSB9IGZyb20gXCIuL2xvZ2dlclwiO1xyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0QXV0aGVudGljYXRpb24oY29uZmlnOiBBcHBXaWRnZXRDb25maWcpIHtcclxuICByZXR1cm4gVXNlclNlc3Npb24uZnJvbUNyZWRlbnRpYWwoY29uZmlnLmNyZWRlbnRpYWwpO1xyXG59XHJcbiAgXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBxdWVyeVRhYmxlRmVhdHVyZVNldCh1cmw6IHN0cmluZywgd2hlcmU6IHN0cmluZywgXHJcbiAgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlU2V0PiB7XHJcbiAgXHJcbiAgICB0cnl7XHJcblxyXG4gICAgICBjb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7XHJcbiAgICAgIHJldHVybiBxdWVyeUZlYXR1cmVzKHsgdXJsLCB3aGVyZSwgYXV0aGVudGljYXRpb24sIGhpZGVUb2tlbjogdHJ1ZSB9KVxyXG4gICAgICAudGhlbigocmVzcG9uc2U6IElRdWVyeUZlYXR1cmVzUmVzcG9uc2UpID0+IHtcclxuICAgICAgICByZXR1cm4gcmVzcG9uc2VcclxuICAgICAgfSlcclxuXHJcbiAgICB9Y2F0Y2goZSl7XHJcbiAgICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAncXVlcnlUYWJsZUZlYXR1cmVTZXQnKVxyXG4gICAgfSAgICBcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHF1ZXJ5VGFibGVGZWF0dXJlcyh1cmw6IHN0cmluZywgd2hlcmU6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlW10+IHtcclxuXHJcbiBjb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7XHJcblxyXG4gIHRyeXtcclxuICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBxdWVyeUZlYXR1cmVzKHsgdXJsLCB3aGVyZSwgYXV0aGVudGljYXRpb24sICBodHRwTWV0aG9kOidQT1NUJywgaGlkZVRva2VuOiB0cnVlIH0pXHJcbiAgICAgIHJldHVybiAocmVzcG9uc2UgYXMgSVF1ZXJ5RmVhdHVyZXNSZXNwb25zZSkuZmVhdHVyZXM7XHJcbiAgfWNhdGNoKGUpe1xyXG4gICAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ3F1ZXJ5VGFibGVGZWF0dXJlcycpXHJcbiAgICAgIGxvZyh1cmwsIExvZ1R5cGUuV1JOLCB3aGVyZSk7XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgIGFzeW5jIGZ1bmN0aW9uIHF1ZXJ5UmVsYXRlZFRhYmxlRmVhdHVyZXMob2JqZWN0SWRzOiBudW1iZXJbXSxcclxudXJsOiBzdHJpbmcsIHJlbGF0aW9uc2hpcElkOiBudW1iZXIsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJUmVsYXRlZFJlY29yZEdyb3VwW10+IHtcclxuXHJcbmNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTtcclxuXHJcbmNvbnN0IHJlc3BvbnNlID0gYXdhaXQgcXVlcnlSZWxhdGVkKHtcclxuICAgIG9iamVjdElkcyxcclxuICAgIHVybCwgcmVsYXRpb25zaGlwSWQsXHJcbiAgICBhdXRoZW50aWNhdGlvbixcclxuICAgIGhpZGVUb2tlbjogdHJ1ZVxyXG59KTtcclxucmV0dXJuIHJlc3BvbnNlLnJlbGF0ZWRSZWNvcmRHcm91cHM7XHJcbn1cclxuXHJcbmV4cG9ydCAgYXN5bmMgZnVuY3Rpb24gdXBkYXRlVGFibGVGZWF0dXJlKHVybDogc3RyaW5nLCBhdHRyaWJ1dGVzOiBhbnksIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKSB7XHJcbiAgY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG5cclxuICByZXR1cm4gdXBkYXRlRmVhdHVyZXMoe1xyXG4gICAgICB1cmwsXHJcbiAgICAgIGF1dGhlbnRpY2F0aW9uLFxyXG4gICAgICBmZWF0dXJlczogW3tcclxuICAgICAgYXR0cmlidXRlc1xyXG4gICAgICB9XSxcclxuICAgICAgcm9sbGJhY2tPbkZhaWx1cmU6IHRydWVcclxuICB9KVxyXG59XHJcblxyXG5leHBvcnQgIGFzeW5jIGZ1bmN0aW9uIHVwZGF0ZVRhYmxlRmVhdHVyZXModXJsOiBzdHJpbmcsIGZlYXR1cmVzOiBJRmVhdHVyZVtdLCBjb25maWc6IEFwcFdpZGdldENvbmZpZykge1xyXG4gIGNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTsgIFxyXG4gIHJldHVybiB1cGRhdGVGZWF0dXJlcyh7XHJcbiAgICAgIHVybCxcclxuICAgICAgYXV0aGVudGljYXRpb24sXHJcbiAgICAgIGZlYXR1cmVzXHJcbiAgfSlcclxufVxyXG5cclxuZXhwb3J0ICBhc3luYyBmdW5jdGlvbiBhZGRUYWJsZUZlYXR1cmVzKHVybDogc3RyaW5nLCBmZWF0dXJlczogYW55W10sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKSB7XHJcblxyXG4gIGNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTtcclxuXHJcbiAgdHJ5e1xyXG4gICAgcmV0dXJuIGFkZEZlYXR1cmVzKHsgdXJsLCBmZWF0dXJlcywgYXV0aGVudGljYXRpb24sIHJvbGxiYWNrT25GYWlsdXJlOiB0cnVlIH0pO1xyXG4gIH1jYXRjaChlKXtcclxuICAgIGNvbnNvbGUubG9nKGUpO1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0ICBhc3luYyBmdW5jdGlvbiBkZWxldGVUYWJsZUZlYXR1cmVzKHVybDogc3RyaW5nLCBvYmplY3RJZHM6IG51bWJlcltdLCBjb25maWc6IEFwcFdpZGdldENvbmZpZykge1xyXG5cclxuICAgIGNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTtcclxuICAgIHJldHVybiBkZWxldGVGZWF0dXJlcyh7IHVybCwgb2JqZWN0SWRzLCBhdXRoZW50aWNhdGlvbiwgcm9sbGJhY2tPbkZhaWx1cmU6IHRydWUgfSk7XHJcbn0iLCJleHBvcnQgZW51bSBMb2dUeXBlIHtcclxuICAgIElORk8gPSAnSW5mb3JtYXRpb24nLFxyXG4gICAgV1JOID0gJ1dhcm5pbmcnLFxyXG4gICAgRVJST1IgPSAnRXJyb3InXHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBsb2cobWVzc2FnZTogc3RyaW5nLCB0eXBlPzogTG9nVHlwZSwgZnVuYz86IHN0cmluZyl7XHJcbiAgICBpZighdHlwZSl7XHJcbiAgICAgICAgdHlwZSA9IExvZ1R5cGUuSU5GT1xyXG4gICAgfVxyXG5cclxuICAgIGlmKGZ1bmMpe1xyXG4gICAgICAgIGZ1bmMgPSBgKCR7ZnVuY30pYDtcclxuICAgIH1cclxuXHJcbiAgICBtZXNzYWdlID0gYFske25ldyBEYXRlKCkudG9Mb2NhbGVTdHJpbmcoKX1dOiAke21lc3NhZ2V9ICR7ZnVuY31gO1xyXG5cclxuICAgIHN3aXRjaCh0eXBlKXtcclxuICAgICAgICBjYXNlIExvZ1R5cGUuSU5GTzpcclxuICAgICAgICAgICAgY29uc29sZS5sb2cobWVzc2FnZSk7XHJcbiAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIGNhc2UgTG9nVHlwZS5XUk46XHJcbiAgICAgICAgICAgIGNvbnNvbGUud2FybihtZXNzYWdlKTtcclxuICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgY2FzZSBMb2dUeXBlLkVSUk9SOlxyXG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKG1lc3NhZ2UpO1xyXG4gICAgICAgICAgICBicmVhaztcclxuICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgICBjb25zb2xlLmxvZyhtZXNzYWdlKTtcclxuICAgIH1cclxufSIsIlxyXG5leHBvcnQgY29uc3Qgc29ydE9iamVjdCA9IDxUPihvYmo6IFRbXSwgcHJvcDogc3RyaW5nLCByZXZlcnNlPzpib29sZWFuKTogVFtdID0+IHtcclxuICAgcmV0dXJuIG9iai5zb3J0KChhOlQsIGI6VCkgPT4ge1xyXG4gICAgICBpZihhW3Byb3BdID4gYltwcm9wXSl7XHJcbiAgICAgICAgcmV0dXJuIHJldmVyc2UgPyAtMSA6IDFcclxuICAgICAgfVxyXG4gICAgICBpZihhW3Byb3BdIDwgYltwcm9wXSl7XHJcbiAgICAgICAgcmV0dXJuIHJldmVyc2UgPyAxIDogLTFcclxuICAgICAgfVxyXG4gICAgICByZXR1cm4gMDtcclxuICB9KTtcclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IGNyZWF0ZUd1aWQgPSAoKSA9PntcclxuICByZXR1cm4gJ3h4eHh4eHh4LXh4eHgtNHh4eC15eHh4LXh4eHh4eHh4eHh4eCcucmVwbGFjZSgvW3h5XS9nLCBmdW5jdGlvbihjKSB7XHJcbiAgICB2YXIgciA9IE1hdGgucmFuZG9tKCkgKiAxNiB8IDAsIHYgPSBjID09ICd4JyA/IHIgOiAociAmIDB4MyB8IDB4OCk7XHJcbiAgICByZXR1cm4gdi50b1N0cmluZygxNik7XHJcbiAgfSk7XHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBwYXJzZURhdGUgPSAobWlsbGlzZWNvbmRzOiBudW1iZXIpOiBzdHJpbmcgPT4ge1xyXG4gIGlmKCFtaWxsaXNlY29uZHMpe1xyXG4gICAgcmV0dXJuXHJcbiAgfVxyXG4gICByZXR1cm4gbmV3IERhdGUobWlsbGlzZWNvbmRzKS50b0xvY2FsZVN0cmluZygpO1xyXG59XHJcblxyXG5leHBvcnQgY29uc3Qgc2F2ZURhdGUgPSAoZGF0ZTogc3RyaW5nKTogbnVtYmVyID0+IHtcclxuICAgcmV0dXJuIG5ldyBEYXRlKGRhdGUpLmdldE1pbGxpc2Vjb25kcygpO1xyXG59XHJcblxyXG5cclxuLy9SZWZlcmVuY2U6IGh0dHBzOi8vc3RhY2tvdmVyZmxvdy5jb20vcXVlc3Rpb25zLzYxOTUzMzUvbGluZWFyLXJlZ3Jlc3Npb24taW4tamF2YXNjcmlwdFxyXG4vLyBleHBvcnQgY29uc3QgbGluZWFyUmVncmVzc2lvbiA9ICh5VmFsdWVzOiBudW1iZXJbXSwgeFZhbHVlczogbnVtYmVyW10pID0+e1xyXG4vLyAgIGRlYnVnZ2VyO1xyXG4vLyAgIGNvbnN0IHkgPSB5VmFsdWVzO1xyXG4vLyAgIGNvbnN0IHggPSB4VmFsdWVzO1xyXG5cclxuLy8gICB2YXIgbHIgPSB7c2xvcGU6IE5hTiwgaW50ZXJjZXB0OiBOYU4sIHIyOiBOYU59O1xyXG4vLyAgIHZhciBuID0geS5sZW5ndGg7XHJcbi8vICAgdmFyIHN1bV94ID0gMDtcclxuLy8gICB2YXIgc3VtX3kgPSAwO1xyXG4vLyAgIHZhciBzdW1feHkgPSAwO1xyXG4vLyAgIHZhciBzdW1feHggPSAwO1xyXG4vLyAgIHZhciBzdW1feXkgPSAwO1xyXG5cclxuLy8gICBmb3IgKHZhciBpID0gMDsgaSA8IHkubGVuZ3RoOyBpKyspIHtcclxuXHJcbi8vICAgICAgIHN1bV94ICs9IHhbaV07XHJcbi8vICAgICAgIHN1bV95ICs9IHlbaV07XHJcbi8vICAgICAgIHN1bV94eSArPSAoeFtpXSp5W2ldKTtcclxuLy8gICAgICAgc3VtX3h4ICs9ICh4W2ldKnhbaV0pO1xyXG4vLyAgICAgICBzdW1feXkgKz0gKHlbaV0qeVtpXSk7XHJcbi8vICAgfSBcclxuXHJcbi8vICAgbHIuc2xvcGUgPSAobiAqIHN1bV94eSAtIHN1bV94ICogc3VtX3kpIC8gKG4qc3VtX3h4IC0gc3VtX3ggKiBzdW1feCk7XHJcbi8vICAgbHIuaW50ZXJjZXB0ID0gKHN1bV95IC0gbHIuc2xvcGUgKiBzdW1feCkvbjtcclxuLy8gICBsci5yMiA9IE1hdGgucG93KChuKnN1bV94eSAtIHN1bV94KnN1bV95KS9NYXRoLnNxcnQoKG4qc3VtX3h4LXN1bV94KnN1bV94KSoobipzdW1feXktc3VtX3kqc3VtX3kpKSwyKTtcclxuLy8gICByZXR1cm4gbHI7XHJcbi8vIH1cclxuXHJcblN0cmluZy5wcm90b3R5cGUudG9UaXRsZUNhc2UgPSBmdW5jdGlvbiAoKSB7XHJcbiAgcmV0dXJuIHRoaXMucmVwbGFjZSgvXFx3XFxTKi9nLCBmdW5jdGlvbih0eHQpe3JldHVybiB0eHQuY2hhckF0KDApLnRvVXBwZXJDYXNlKCkgKyB0eHQuc3Vic3RyKDEpLnRvTG93ZXJDYXNlKCk7fSk7XHJcbn07XHJcblxyXG5BcnJheS5wcm90b3R5cGUub3JkZXJCeSA9IGZ1bmN0aW9uPFQ+KHByb3AsIHJldmVyc2UpIHtcclxuICByZXR1cm4gdGhpcy5zb3J0KChhOlQsIGI6VCkgPT4ge1xyXG4gICAgaWYoYVtwcm9wXSA+IGJbcHJvcF0pe1xyXG4gICAgICByZXR1cm4gcmV2ZXJzZSA/IC0xIDogMVxyXG4gICAgfVxyXG4gICAgaWYoYVtwcm9wXSA8IGJbcHJvcF0pe1xyXG4gICAgICByZXR1cm4gcmV2ZXJzZSA/IDEgOiAtMVxyXG4gICAgfVxyXG4gICAgcmV0dXJuIDA7XHJcbiAgfSk7XHJcbn1cclxuXHJcbkFycmF5LnByb3RvdHlwZS5ncm91cEJ5ID0gZnVuY3Rpb24oa2V5KSB7XHJcbiAgcmV0dXJuIHRoaXMucmVkdWNlKGZ1bmN0aW9uKHJ2LCB4KSB7XHJcbiAgICAocnZbeFtrZXldXSA9IHJ2W3hba2V5XV0gfHwgW10pLnB1c2goeCk7XHJcbiAgICByZXR1cm4gcnY7XHJcbiAgfSwge30pO1xyXG59O1xyXG4iLCJpbXBvcnQgeyBUZXh0SW5wdXQsIFRleHRBcmVhIH0gZnJvbSBcImppbXUtdWlcIlxyXG5pbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCJcclxuaW1wb3J0IHsgTGFiZWxcclxuICAgICAgfSBmcm9tIFwiamltdS11aVwiXHJcbmltcG9ydCB7IElDb2RlZFZhbHVlIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXR5cGVzXCJcclxuaW1wb3J0IHsgZGlzcGF0Y2hBY3Rpb24sICBzYXZlSGF6YXJkIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXBpXCJcclxuaW1wb3J0IHsgSGF6YXJkIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvZGF0YS1kZWZpbml0aW9uc1wiXHJcbmltcG9ydCB7IENMU1NBY3Rpb25LZXlzIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY2xzcy1zdG9yZVwiXHJcbmltcG9ydCB7IENsc3NEcm9wZG93biB9IGZyb20gXCIuL2Nsc3MtZHJvcGRvd25cIlxyXG5pbXBvcnQgeyBDbHNzTW9kYWwgfSBmcm9tIFwiLi9jbHNzLW1vZGFsXCI7XHJcbmltcG9ydCB7IFJlYWN0UmVkdXggfSBmcm9tIFwiamltdS1jb3JlXCJcclxuY29uc3QgeyB1c2VTZWxlY3RvciB9ID0gUmVhY3RSZWR1eDtcclxuXHJcbmV4cG9ydCBjb25zdCBBZGRIYXphcmRXaWRnZXQ9KHtwcm9wcywgdmlzaWJsZSwgdG9nZ2xlLCBzZXRIYXphcmR9OlxyXG4gICAge3Byb3BzOiBhbnksIHZpc2libGU6IGJvb2xlYW4sIHRvZ2dsZTogYW55LCBzZXRIYXphcmQ/OiBhbnl9KSA9PntcclxuXHJcbiAgICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSBSZWFjdC51c2VTdGF0ZShmYWxzZSk7ICAgIFxyXG4gICAgY29uc3QgW2lzVmlzaWJsZSwgc2V0VmlzaWJsZV0gPSBSZWFjdC51c2VTdGF0ZShmYWxzZSk7IFxyXG4gICAgY29uc3QgW25hbWUsIHNldE5hbWVdID0gUmVhY3QudXNlU3RhdGUoJycpOyAgIFxyXG4gICAgY29uc3QgW2Rlc2NyaXB0aW9uLCBzZXREZXNjcmlwdGlvbl0gPSBSZWFjdC51c2VTdGF0ZSgnJyk7IFxyXG4gICAgY29uc3QgW2hhemFyZFR5cGVzLCBzZXRIYXphcmRUeXBlc10gPSBSZWFjdC51c2VTdGF0ZTxJQ29kZWRWYWx1ZVtdPihbXSk7XHJcbiAgICBjb25zdCBbc2VsZWN0ZWRIYXphcmRUeXBlLCBzZXRTZWxlY3RlZEhhemFyZFR5cGVdID0gUmVhY3QudXNlU3RhdGU8SUNvZGVkVmFsdWU+KG51bGwpO1xyXG4gICAgY29uc3QgW2NvbmZpZywgc2V0Q29uZmlnXSA9IFJlYWN0LnVzZVN0YXRlKG51bGwpXHJcblxyXG4gICAgY29uc3QgY3JlZGVudGlhbCA9IHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KSA9PiB7XHJcbiAgICAgICAgcmV0dXJuIHN0YXRlLmNsc3NTdGF0ZT8uYXV0aGVudGljYXRlO1xyXG4gICAgfSlcclxuXHJcbiAgICBjb25zdCBoYXphcmRzID0gdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgICAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy5oYXphcmRzIGFzIEhhemFyZFtdO1xyXG4gICAgIH0pXHJcblxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpID0+IHtcclxuICAgICAgICBpZihjcmVkZW50aWFsKXtcclxuICAgICAgICAgICBzZXRDb25maWcoey4uLiBwcm9wcy5jb25maWcsIGNyZWRlbnRpYWw6Y3JlZGVudGlhbH0pOyAgICAgICAgICAgIFxyXG4gICAgICAgIH1cclxuICAgIH0sIFtjcmVkZW50aWFsXSlcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCkgPT4ge1xyXG4gICAgICAgIGlmKGhhemFyZHMgJiYgaGF6YXJkcy5sZW5ndGggPiAwKXtcclxuICAgICAgICAgICAgY29uc3QgdHlwZXMgPSBoYXphcmRzWzFdLmRvbWFpbnM7XHJcbiAgICAgICAgICAgICh0eXBlcyBhcyBhbnkpLm9yZGVyQnkoJ25hbWUnKTtcclxuICAgICAgICAgICAgIHNldEhhemFyZFR5cGVzKHR5cGVzKVxyXG47ICAgICAgICB9XHJcbiAgICB9LCBbaGF6YXJkc10pXHJcblxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpPT57XHJcbiAgICAgICAgc2V0VmlzaWJsZSh2aXNpYmxlKTtcclxuICAgICAgICBzZXROYW1lKCcnKTtcclxuICAgICAgICBzZXREZXNjcmlwdGlvbignJyk7XHJcbiAgICAgICAgc2V0U2VsZWN0ZWRIYXphcmRUeXBlKG51bGwpO1xyXG4gICAgfSwgW3Zpc2libGVdKSAgIFxyXG5cclxuICAgIGNvbnN0IHNhdmVOZXdIYXphcmQ9YXN5bmMgKCk9PntcclxuXHJcbiAgICAgICAgY29uc3QgZXhpc3QgPSBoYXphcmRzLmZpbmQoaCA9PiBoLm5hbWUudG9Mb3dlckNhc2UoKSA9PT0gbmFtZS50b0xvd2VyQ2FzZSgpLnRyaW0oKSk7XHJcbiAgICAgICAgaWYoZXhpc3Qpe1xyXG4gICAgICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCBgSGF6YXJkOiAke25hbWV9IGFscmVhZHkgZXhpc3RzYCk7XHJcbiAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHNldExvYWRpbmcodHJ1ZSk7XHJcblxyXG4gICAgICAgIHRyeXtcclxuICAgICAgICAgICAgbGV0IG5ld0hhemFyZCA9IHtcclxuICAgICAgICAgICAgICAgIG5hbWUsXHJcbiAgICAgICAgICAgICAgICB0aXRsZTogbmFtZSxcclxuICAgICAgICAgICAgICAgIHR5cGU6IHNlbGVjdGVkSGF6YXJkVHlwZSxcclxuICAgICAgICAgICAgICAgIGRlc2NyaXB0aW9uXHJcbiAgICAgICAgICAgIH0gYXMgSGF6YXJkO1xyXG4gICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IHNhdmVIYXphcmQoY29uZmlnLCBuZXdIYXphcmQpO1xyXG4gICAgICAgICAgICBjb25zb2xlLmxvZyhyZXNwb25zZSk7XHJcbiAgICAgICAgICAgIGlmKHJlc3BvbnNlLmVycm9ycyl7XHJcbiAgICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihTdHJpbmcocmVzcG9uc2UuZXJyb3JzKSk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIG5ld0hhemFyZCA9IHJlc3BvbnNlLmRhdGE7XHJcbiAgICAgICAgICAgIG5ld0hhemFyZC5kb21haW5zID0gaGF6YXJkc1sxXS5kb21haW5zO1xyXG5cclxuICAgICAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuTE9BRF9IQVpBUkRTX0FDVElPTixcclxuICAgICAgICAgICAgICAgWy4uLmhhemFyZHMsIG5ld0hhemFyZF0pXHJcblxyXG4gICAgICAgICAgICBzZXRIYXphcmQobmV3SGF6YXJkKTtcclxuICAgICAgICAgICAgdG9nZ2xlKGZhbHNlKTtcclxuICAgICAgICB9Y2F0Y2goZXJyKXtcclxuICAgICAgICAgICBjb25zb2xlLmxvZyhlcnIpO1xyXG4gICAgICAgICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlMsIGVyci5tZXNzYWdlKTtcclxuICAgICAgICB9ZmluYWxseXtcclxuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiAoXHJcbiAgICAgICAgPENsc3NNb2RhbCB0aXRsZT1cIkFkZCBOZXcgSGF6YXJkXCJcclxuICAgICAgICAgICAgZGlzYWJsZT17IShuYW1lICYmIHNlbGVjdGVkSGF6YXJkVHlwZSl9ICBzYXZlPXtzYXZlTmV3SGF6YXJkfSBcclxuICAgICAgICAgICAgdG9nZ2xlVmlzaWJpbGl0eT17dG9nZ2xlfSB2aXNpYmxlPXtpc1Zpc2libGV9XHJcbiAgICAgICAgICAgIGxvYWRpbmc9e2xvYWRpbmd9PlxyXG4gICAgICAgICAgICBcclxuICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJoYXphcmRzXCI+XHJcbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cIm1vZGFsLWl0ZW1cIj5cclxuICAgICAgICAgICAgICAgICAgICA8TGFiZWwgY2hlY2s+SGF6YXJkIE5hbWU8c3BhbiBzdHlsZT17e2NvbG9yOiAncmVkJ319Pio8L3NwYW4+PC9MYWJlbD5cclxuICAgICAgICAgICAgICAgICAgICA8VGV4dElucHV0IG9uQ2hhbmdlPXsoZSk9PiBzZXROYW1lKGUudGFyZ2V0LnZhbHVlKX0gXHJcbiAgICAgICAgICAgICAgICAgICAgdmFsdWU9e25hbWV9PjwvVGV4dElucHV0PlxyXG4gICAgICAgICAgICAgICAgPC9kaXY+XHJcblxyXG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJtb2RhbC1pdGVtXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgPExhYmVsIGNoZWNrPkhhemFyZCBUeXBlPHNwYW4gc3R5bGU9e3tjb2xvcjogJ3JlZCd9fT4qPC9zcGFuPjwvTGFiZWw+XHJcbiAgICAgICAgICAgICAgICAgICAgPENsc3NEcm9wZG93biBpdGVtcz17aGF6YXJkVHlwZXN9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpdGVtPXtzZWxlY3RlZEhhemFyZFR5cGV9IFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsZXRhYmxlPXtmYWxzZX1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNldEl0ZW09e3NldFNlbGVjdGVkSGF6YXJkVHlwZX0gLz4gXHJcbiAgICAgICAgICAgICAgICA8L2Rpdj4gICAgICAgXHJcblxyXG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJtb2RhbC1pdGVtXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgPExhYmVsIGNoZWNrPkRlc2NyaXB0aW9uIG9mIEhhemFyZCAoT3B0aW9uYWwpPC9MYWJlbD5cclxuICAgICAgICAgICAgICAgICAgICA8VGV4dEFyZWFcclxuICAgICAgICAgICAgICAgICAgICAgICAgdmFsdWU9e2Rlc2NyaXB0aW9ufVxyXG4gICAgICAgICAgICAgICAgICAgICAgICBvbkNoYW5nZT17KGUpID0+IHNldERlc2NyaXB0aW9uKGUudGFyZ2V0LnZhbHVlKX1cclxuICAgICAgICAgICAgICAgICAgICAvPlxyXG4gICAgICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgICAgIDwvZGl2PiAgXHJcbiAgICAgICAgPC9DbHNzTW9kYWw+XHJcbiAgICApXHJcbn0iLCJpbXBvcnQgeyBUZXh0SW5wdXQsIEJ1dHRvbiwgTW9kYWwsIE1vZGFsQm9keSwgTW9kYWxGb290ZXIsIE1vZGFsSGVhZGVyIH0gZnJvbSBcImppbXUtdWlcIlxyXG5pbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCJcclxuaW1wb3J0IHsgTGFiZWwgfSBmcm9tIFwiamltdS11aVwiXHJcbmltcG9ydCB7IE9yZ2FuaXphdGlvbiB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2RhdGEtZGVmaW5pdGlvbnNcIlxyXG5pbXBvcnQgeyBkaXNwYXRjaEFjdGlvbiwgc2F2ZU9yZ2FuaXphdGlvbiB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2FwaVwiXHJcbmltcG9ydCB7IENMU1NBY3Rpb25LZXlzIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY2xzcy1zdG9yZVwiXHJcbmltcG9ydCB7IElDb2RlZFZhbHVlIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXR5cGVzXCJcclxuaW1wb3J0IENsc3NMb2FkaW5nIGZyb20gXCIuL2Nsc3MtbG9hZGluZ1wiXHJcbmltcG9ydCB7IENsc3NEcm9wZG93biB9IGZyb20gXCIuL2Nsc3MtZHJvcGRvd25cIjtcclxuaW1wb3J0IHsgUmVhY3RSZWR1eCB9IGZyb20gXCJqaW11LWNvcmVcIlxyXG5pbXBvcnQgeyBDbHNzTW9kYWwgfSBmcm9tIFwiLi9jbHNzLW1vZGFsXCJcclxuaW1wb3J0IHsgT3JnYW5pemF0aW9uc0Ryb3Bkb3duIH0gZnJvbSBcIi4vY2xzcy1vcmdhbml6YXRpb25zLWRyb3Bkb3duXCJcclxuY29uc3QgeyB1c2VTZWxlY3RvciB9ID0gUmVhY3RSZWR1eDtcclxuXHJcbmV4cG9ydCBjb25zdCBBZGRPcmdhbml6YXRvbldpZGdldD0oe3Byb3BzQ29uZmlnLCB2aXNpYmxlLCB0b2dnbGUsIHNldE9yZ2FuaXphdGlvbn0pID0+e1xyXG5cclxuICAgIGNvbnN0IFtsb2FkaW5nLCBzZXRMb2FkaW5nXSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKTsgICAgXHJcbiAgICBjb25zdCBbaXNWaXNpYmxlLCBzZXRWaXNpYmxlXSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKTsgXHJcbiAgICBjb25zdCBbb3JnYW5pemF0aW9uTmFtZSwgc2V0T3JnYW5pemF0aW9uTmFtZV0gPSBSZWFjdC51c2VTdGF0ZSgnJyk7ICAgIFxyXG4gICAgY29uc3QgW29yZ2FuaXphdGlvblR5cGVzLCBzZXRPcmdhbml6YXRpb25UeXBlc10gPSBSZWFjdC51c2VTdGF0ZTxJQ29kZWRWYWx1ZVtdPihbXSk7XHJcbiAgICBjb25zdCBbc2VsZWN0ZWRPcmdhbml6YXRpb25UeXBlLCBzZXRTZWxlY3RlZE9yZ2FuaXphdGlvblR5cGVdID0gUmVhY3QudXNlU3RhdGU8SUNvZGVkVmFsdWU+KG51bGwpO1xyXG4gICAgY29uc3QgW3NlbGVjdGVkUGFyZW50T3JnYW5pemF0aW9uLCBzZXRTZWxlY3RlZFBhcmVudE9yZ2FuaXphdGlvbl0gPSBSZWFjdC51c2VTdGF0ZTxPcmdhbml6YXRpb24+KG51bGwpO1xyXG4gICAgY29uc3QgW2NvbmZpZywgc2V0Q29uZmlnXSA9IFJlYWN0LnVzZVN0YXRlKG51bGwpO1xyXG5cclxuICAgIGNvbnN0IG9yZ2FuaXphdGlvbnMgPSB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4ge1xyXG4gICAgICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGU/Lm9yZ2FuaXphdGlvbnMgYXMgT3JnYW5pemF0aW9uW107XHJcbiAgICAgfSlcclxuXHJcbiAgICAgY29uc3QgY3JlZGVudGlhbCA9IHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KSA9PiB7XHJcbiAgICAgICAgcmV0dXJuIHN0YXRlLmNsc3NTdGF0ZT8uYXV0aGVudGljYXRlO1xyXG4gICAgfSlcclxuICAgICBcclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKT0+eyBcclxuICAgICAgICBzZXRWaXNpYmxlKHZpc2libGUpO1xyXG4gICAgICAgIHNldE9yZ2FuaXphdGlvbk5hbWUoJycpO1xyXG4gICAgICAgIHNldFNlbGVjdGVkT3JnYW5pemF0aW9uVHlwZShudWxsKTtcclxuICAgIH0sIFt2aXNpYmxlXSkgICBcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCkgPT4ge1xyXG4gICAgICAgIGlmKGNyZWRlbnRpYWwpe1xyXG4gICAgICAgICAgIHNldENvbmZpZyh7Li4ucHJvcHNDb25maWcsIGNyZWRlbnRpYWx9KTsgICAgICAgICAgICBcclxuICAgICAgICB9XHJcbiAgICB9LCBbY3JlZGVudGlhbF0pXHJcblxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpID0+IHtcclxuICAgICAgaWYob3JnYW5pemF0aW9ucyAmJiBvcmdhbml6YXRpb25zLmxlbmd0aCA+IDApe1xyXG4gICAgICAgIGNvbnN0IHR5cGVzID0gb3JnYW5pemF0aW9uc1sxXS5kb21haW5zO1xyXG4gICAgICAgICh0eXBlcyBhcyBhbnkpPy5vcmRlckJ5KCduYW1lJyk7XHJcbiAgICAgICAgc2V0T3JnYW5pemF0aW9uVHlwZXModHlwZXMpO1xyXG4gICAgICB9XHJcbiAgICB9LCBbb3JnYW5pemF0aW9uc10pXHJcblxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpPT57XHJcbiAgICAgICAgc2V0U2VsZWN0ZWRQYXJlbnRPcmdhbml6YXRpb24ob3JnYW5pemF0aW9uc1swXSk7XHJcbiAgICB9LCBbb3JnYW5pemF0aW9uc10pXHJcblxyXG4gICAgY29uc3Qgc2F2ZSA9IGFzeW5jICgpID0+IHtcclxuICAgICAgICBjb25zdCBleGlzdHMgPSBvcmdhbml6YXRpb25zLmZpbmQobyA9PiBvLm5hbWUgPT09IG9yZ2FuaXphdGlvbk5hbWUpO1xyXG4gICAgICAgIGlmKGV4aXN0cyl7XHJcbiAgICAgICAgICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlMsIGBPcmdhbml6YXRpb246ICR7b3JnYW5pemF0aW9uTmFtZX0gYWxyZWFkeSBleGlzdHNgKTtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuICAgICAgICBzZXRMb2FkaW5nKHRydWUpO1xyXG4gICAgICAgIHRyeXtcclxuICAgICAgICAgICAgbGV0IG5ld09yZ2FuaXphdGlvbiA9IHtcclxuICAgICAgICAgICAgICAgIG5hbWU6IG9yZ2FuaXphdGlvbk5hbWUsXHJcbiAgICAgICAgICAgICAgICB0aXRsZTogb3JnYW5pemF0aW9uTmFtZSxcclxuICAgICAgICAgICAgICAgIHR5cGU6IHNlbGVjdGVkT3JnYW5pemF0aW9uVHlwZSxcclxuICAgICAgICAgICAgICAgIHBhcmVudElkOiBzZWxlY3RlZFBhcmVudE9yZ2FuaXphdGlvbi5pZCAhPT0gJzAwMCcgPyBzZWxlY3RlZFBhcmVudE9yZ2FuaXphdGlvbi5pZCA6IG51bGxcclxuICAgICAgICAgICAgfSBhcyBPcmdhbml6YXRpb25cclxuXHJcbiAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgc2F2ZU9yZ2FuaXphdGlvbihjb25maWcsIG5ld09yZ2FuaXphdGlvbik7ICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKHJlc3BvbnNlKTtcclxuICAgICAgICAgICAgaWYocmVzcG9uc2UuZXJyb3JzKXtcclxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihTdHJpbmcocmVzcG9uc2UuZXJyb3JzKSlcclxuICAgICAgICAgICAgfSAgICAgICAgICAgIFxyXG5cclxuICAgICAgICAgICAgbmV3T3JnYW5pemF0aW9uID0gcmVzcG9uc2UuZGF0YTtcclxuICAgICAgICAgICAgbmV3T3JnYW5pemF0aW9uLmRvbWFpbnMgPSBvcmdhbml6YXRpb25zWzFdLmRvbWFpbnM7XHJcblxyXG4gICAgICAgICAgICBkaXNwYXRjaEFjdGlvbihcclxuICAgICAgICAgICAgICAgIENMU1NBY3Rpb25LZXlzLkxPQURfT1JHQU5JWkFUSU9OU19BQ1RJT04sXHJcbiAgICAgICAgICAgICAgIFsuLi5vcmdhbml6YXRpb25zLCBuZXdPcmdhbml6YXRpb25dKTtcclxuICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIHNldE9yZ2FuaXphdGlvbihyZXNwb25zZS5kYXRhKVxyXG4gICAgICAgICAgICB0b2dnbGUoZmFsc2UpO1xyXG4gICAgICAgIH1jYXRjaChlcnIpe1xyXG4gICAgICAgICAgIGNvbnNvbGUubG9nKGVycik7XHJcbiAgICAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgZXJyLm1lc3NhZ2UpO1xyXG4gICAgICAgIH1maW5hbGx5e1xyXG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuKCAgICAgICAgICAgXHJcbiAgICAgIDxDbHNzTW9kYWwgdGl0bGU9XCJBZGQgTmV3IE9yZ2FuaXphdGlvblwiXHJcbiAgICAgICAgZGlzYWJsZT17IShvcmdhbml6YXRpb25OYW1lICYmIHNlbGVjdGVkT3JnYW5pemF0aW9uVHlwZSl9ICBcclxuICAgICAgICBzYXZlPXtzYXZlfSBcclxuICAgICAgICBsb2FkaW5nPXtsb2FkaW5nfVxyXG4gICAgICAgIHRvZ2dsZVZpc2liaWxpdHk9e3RvZ2dsZX0gdmlzaWJsZT17aXNWaXNpYmxlfT5cclxuICAgICAgICAgXHJcbiAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwiYWRkLW9yZ2FuaXphdGlvblwiPiBcclxuICAgICAgICAgICAgIDxzdHlsZT5cclxuICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmFkZC1vcmdhbml6YXRpb257XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW5cclxuICAgICAgICAgICAgICAgICAgICAgICAgIH0gICAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICA8L3N0eWxlPlxyXG4gICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJtb2RhbC1pdGVtXCI+ICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgIDxMYWJlbCBjaGVjaz5Pcmdhbml6YXRpb24gTmFtZTxzcGFuIHN0eWxlPXt7Y29sb3I6ICdyZWQnfX0+Kjwvc3Bhbj48L0xhYmVsPlxyXG4gICAgICAgICAgICAgICAgPFRleHRJbnB1dCBkYXRhLXRlc3RpZD1cInR4dE9yZ2FuaXphdGlvbk5hbWVcIiBzaXplPVwiZGVmYXVsdFwiXHJcbiAgICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhlKT0+IHNldE9yZ2FuaXphdGlvbk5hbWUoZS50YXJnZXQudmFsdWUpfSBcclxuICAgICAgICAgICAgICAgICAgICB2YWx1ZT17b3JnYW5pemF0aW9uTmFtZX0+XHJcbiAgICAgICAgICAgICAgICA8L1RleHRJbnB1dD5cclxuICAgICAgICAgICAgPC9kaXY+XHJcblxyXG4gICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cIm1vZGFsLWl0ZW1cIj5cclxuICAgICAgICAgICAgICAgIDxMYWJlbCBjaGVjaz5Pcmdhbml6YXRpb24gVHlwZTxzcGFuIHN0eWxlPXt7Y29sb3I6ICdyZWQnfX0+Kjwvc3Bhbj48L0xhYmVsPiAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgPENsc3NEcm9wZG93biBpdGVtcz17b3JnYW5pemF0aW9uVHlwZXN9IFxyXG4gICAgICAgICAgICAgICAgICAgIGl0ZW09e3NlbGVjdGVkT3JnYW5pemF0aW9uVHlwZX0gXHJcbiAgICAgICAgICAgICAgICAgICAgZGVsZXRhYmxlPXtmYWxzZX1cclxuICAgICAgICAgICAgICAgICAgICBzZXRJdGVtPXtzZXRTZWxlY3RlZE9yZ2FuaXphdGlvblR5cGV9Lz5cclxuICAgICAgICAgICAgPC9kaXY+XHJcblxyXG4gICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cIm1vZGFsLWl0ZW1cIj5cclxuICAgICAgICAgICAgICAgIDxMYWJlbCBjaGVjaz5Pcmdhbml6YXRpb24ncyBQYXJlbnQgKE9wdGlvbmFsKTwvTGFiZWw+XHJcbiAgICAgICAgICAgICAgICA8T3JnYW5pemF0aW9uc0Ryb3Bkb3duIFxyXG4gICAgICAgICAgICAgICAgICAgIGNvbmZpZz17Y29uZmlnfVxyXG4gICAgICAgICAgICAgICAgICAgIHRvZ2dsZU5ld09yZ2FuaXphdGlvbk1vZGFsPXtudWxsfSAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgb3JnYW5pemF0aW9ucz17b3JnYW5pemF0aW9uc30gXHJcbiAgICAgICAgICAgICAgICAgICAgc2VsZWN0ZWRPcmdhbml6YXRpb249e3NlbGVjdGVkUGFyZW50T3JnYW5pemF0aW9ufSBcclxuICAgICAgICAgICAgICAgICAgICBzZXRPcmdhbml6YXRpb249e3NldFNlbGVjdGVkUGFyZW50T3JnYW5pemF0aW9ufVxyXG4gICAgICAgICAgICAgICAgICAgIHZlcnRpY2FsPXtmYWxzZX0vPiAgXHJcbiAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgICA8L2Rpdj4gICAgICAgICAgICAgICAgXHJcbiAgICBcclxuICAgICAgPC9DbHNzTW9kYWw+XHJcbiAgICApXHJcbn0iLCJpbXBvcnQgeyBUZXh0SW5wdXQgfSBmcm9tIFwiamltdS11aVwiXHJcbmltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5pbXBvcnQgeyBMYWJlbFxyXG4gICAgIH0gZnJvbSBcImppbXUtdWlcIlxyXG5pbXBvcnQgeyBDTFNTVGVtcGxhdGUsIENsc3NVc2VyLCBIYXphcmQsIE9yZ2FuaXphdGlvbiB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2RhdGEtZGVmaW5pdGlvbnNcIlxyXG5pbXBvcnQgeyBSZWFjdFJlZHV4IH0gZnJvbSBcImppbXUtY29yZVwiXHJcbmltcG9ydCB7IGNyZWF0ZU5ld1RlbXBsYXRlLCBkaXNwYXRjaEFjdGlvbiB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2FwaVwiXHJcbmltcG9ydCB7IENMU1NBY3Rpb25LZXlzIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY2xzcy1zdG9yZVwiXHJcbmltcG9ydCB7IFRlbXBsYXRlc0Ryb3Bkb3duIH0gZnJvbSBcIi4vY2xzcy10ZW1wbGF0ZXMtZHJvcGRvd25cIlxyXG5pbXBvcnQgeyBIYXphcmRzRHJvcGRvd24gfSBmcm9tIFwiLi9jbHNzLWhhemFyZHMtZHJvcGRvd25cIlxyXG5pbXBvcnQgeyBPcmdhbml6YXRpb25zRHJvcGRvd24gfSBmcm9tIFwiLi9jbHNzLW9yZ2FuaXphdGlvbnMtZHJvcGRvd25cIlxyXG5pbXBvcnQgeyBDbHNzTW9kYWwgfSBmcm9tIFwiLi9jbHNzLW1vZGFsXCJcclxuY29uc3QgeyB1c2VTZWxlY3RvciB9ID0gUmVhY3RSZWR1eDtcclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgVGVtcGxhdGVBcmdzIHtcclxuICAgIGNvbmZpZzogYW55O1xyXG4gICAgdmlzaWJsZTogYm9vbGVhbjtcclxuICAgIHRvZ2dsZVZpc2liaWxpdHk6IEZ1bmN0aW9uO1xyXG4gICAgdG9nZ2xlTmV3T3JnYW5pemF0aW9uTW9kYWw6IEZ1bmN0aW9uO1xyXG4gICAgdG9nZ2xlTmV3SGF6YXJkTW9kYWw6IEZ1bmN0aW9uO1xyXG4gICAgc2F2ZVRlbXBsYXRlQ29tcGxldGVDYWxsYmFjazogRnVuY3Rpb247XHJcbiAgICBzZWxlY3RlZEhhemFyZDogSGF6YXJkO1xyXG4gICAgc2V0SGF6YXJkOiBGdW5jdGlvbjsgICBcclxuICAgIHNlbGVjdGVkT3JnYW5pemF0aW9uOiBPcmdhbml6YXRpb247XHJcbiAgICBzZXRPcmdhbml6YXRpb246IEZ1bmN0aW9uO1xyXG4gICAgaGF6YXJkczogSGF6YXJkW107XHJcbiAgICBvcmdhbml6YXRpb25zOiBPcmdhbml6YXRpb25bXTtcclxuICAgIHVzZXI6IENsc3NVc2VyO1xyXG4gICAgdGVtcGxhdGVzOiBDTFNTVGVtcGxhdGVbXTtcclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IEFkZFRlbXBsYXRlV2lkZ2V0PShwcm9wczogVGVtcGxhdGVBcmdzKSA9PntcclxuXHJcbiAgICBjb25zdCBbZXJyb3IsIHNldEVycm9yXSA9IFJlYWN0LnVzZVN0YXRlKCcnKTtcclxuICAgIGNvbnN0W2xvYWRpbmcsIHNldExvYWRpbmddID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpO1xyXG4gICAgY29uc3QgW2lzVmlzaWJsZSwgc2V0VmlzaWJpbGl0eV0gPSBSZWFjdC51c2VTdGF0ZShwcm9wcy52aXNpYmxlKTtcclxuICAgIGNvbnN0IFt0ZW1wbGF0ZU5hbWUsIHNldFRlbXBsYXRlTmFtZV0gPSBSZWFjdC51c2VTdGF0ZSgnJyk7ICAgICBcclxuICAgIGNvbnN0IFtzZWxlY3RlZEJhc2VkT25UZW1wbGF0ZSwgc2V0U2VsZWN0ZWRCYXNlZE9uVGVtcGxhdGVdID0gUmVhY3QudXNlU3RhdGU8Q0xTU1RlbXBsYXRlPihudWxsKTsgICAgXHJcbiAgICBcclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKT0+e1xyXG4gICAgICAgIHNldFZpc2liaWxpdHkocHJvcHMudmlzaWJsZSlcclxuICAgIH0sW3Byb3BzXSkgICBcclxuICAgXHJcblxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpPT4ge1xyXG4gICAgICAgIGlmKHByb3BzLnRlbXBsYXRlcyAmJiBwcm9wcy50ZW1wbGF0ZXMubGVuZ3RoID09PSAxKXtcclxuICAgICAgICAgICBzZXRTZWxlY3RlZEJhc2VkT25UZW1wbGF0ZShwcm9wcy50ZW1wbGF0ZXNbMF0pO1xyXG4gICAgICAgIH1cclxuICAgICB9LCBbcHJvcHNdKVxyXG4gICBcclxuICAgIGNvbnN0IHNhdmVOZXdUZW1wbGF0ZT1hc3luYyAoKT0+IHtcclxuICAgICAgICBjb25zdCBleGlzdCA9IHByb3BzLnRlbXBsYXRlcy5maW5kKHQgPT4gdC5uYW1lLnRvTG93ZXJDYXNlKCkudHJpbSgpID09PSB0ZW1wbGF0ZU5hbWUudG9Mb3dlckNhc2UoKS50cmltKCkpO1xyXG4gICAgICAgIGlmKGV4aXN0KXtcclxuICAgICAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgYFRlbXBsYXRlOiAke3RlbXBsYXRlTmFtZX0gYWxyZWFkeSBleGlzdHNgKTtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuICAgICAgICBzZXRMb2FkaW5nKHRydWUpO1xyXG5cclxuICAgICAgICBsZXQgbmV3VGVtcGxhdGUgPSB7XHJcbiAgICAgICAgICAgIC4uLnNlbGVjdGVkQmFzZWRPblRlbXBsYXRlLCAgICAgICAgICAgIFxyXG4gICAgICAgICAgICBuYW1lOiB0ZW1wbGF0ZU5hbWUsXHJcbiAgICAgICAgICAgIHRpdGxlOiB0ZW1wbGF0ZU5hbWUgICAgICBcclxuICAgICAgICB9IGFzIENMU1NUZW1wbGF0ZTtcclxuXHJcbiAgICAgICAgbGV0IG9yZ2FuaXphdGlvbiA9IG51bGw7XHJcbiAgICAgICAgaWYocHJvcHMuc2VsZWN0ZWRPcmdhbml6YXRpb24gJiYgXHJcbiAgICAgICAgICAgIHByb3BzLnNlbGVjdGVkT3JnYW5pemF0aW9uLnRpdGxlICE9PSAnLU5vbmUtJyl7XHJcbiAgICAgICAgICAgICAgICBvcmdhbml6YXRpb24gPSBwcm9wcy5zZWxlY3RlZE9yZ2FuaXphdGlvbjtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICBsZXQgaGF6YXJkID0gbnVsbDtcclxuICAgICAgICBpZihwcm9wcy5zZWxlY3RlZEhhemFyZCAmJiBwcm9wcy5zZWxlY3RlZEhhemFyZC50aXRsZSAhPT0gJy1Ob25lLScpe1xyXG4gICAgICAgICAgICBoYXphcmQgPSBwcm9wcy5zZWxlY3RlZEhhemFyZDtcclxuICAgICAgICB9XHJcbiAgICAgIFxyXG4gICAgICAgIGNvbnN0IHN0YXJ0ID0gbmV3IERhdGUoKS5nZXRUaW1lKCk7XHJcbiAgICAgICAgY29uc3QgcmVzcCA9IGF3YWl0IGNyZWF0ZU5ld1RlbXBsYXRlKHByb3BzLmNvbmZpZywgbmV3VGVtcGxhdGUsIHByb3BzLnVzZXI/LnVzZXJOYW1lLCBcclxuICAgICAgICAgICAgb3JnYW5pemF0aW9uLCBoYXphcmQpO1xyXG5cclxuICAgICAgICBjb25zb2xlLmxvZygnQ3JlYXRlIFRlbXBsYXRlIFRvb2snLCBuZXcgRGF0ZSgpLmdldFRpbWUoKSAtIHN0YXJ0KTtcclxuICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcclxuICAgICAgICBpZihyZXNwLmVycm9ycyl7XHJcbiAgICAgICAgICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlMsIHJlc3AuZXJyb3JzKTtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH0gICAgICAgXHJcbiAgICAgICAgcHJvcHMuc2F2ZVRlbXBsYXRlQ29tcGxldGVDYWxsYmFjaygpO1xyXG4gICAgICAgIHNldExvYWRpbmcoZmFsc2UpOyBcclxuICAgICAgICBwcm9wcy50b2dnbGVWaXNpYmlsaXR5KGZhbHNlKTtcclxuICAgIH1cclxuICAgIHJldHVybihcclxuICAgICAgICA8Q2xzc01vZGFsIHRpdGxlPVwiQWRkIE5ldyBUZW1wbGF0ZVwiXHJcbiAgICAgICAgICAgIGRpc2FibGU9eyEodGVtcGxhdGVOYW1lICYmIHNlbGVjdGVkQmFzZWRPblRlbXBsYXRlICYmICFlcnJvcil9ICBcclxuICAgICAgICAgICAgc2F2ZT17c2F2ZU5ld1RlbXBsYXRlfSBcclxuICAgICAgICAgICAgbG9hZGluZz17bG9hZGluZ31cclxuICAgICAgICAgICAgdG9nZ2xlVmlzaWJpbGl0eT17cHJvcHMudG9nZ2xlVmlzaWJpbGl0eX0gXHJcbiAgICAgICAgICAgIHZpc2libGU9e2lzVmlzaWJsZX0+XHJcbiAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibmV3LXRlbXBsYXRlXCI+XHJcbiAgICAgICAgICAgIDxzdHlsZT5cclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgIC5uZXctdGVtcGxhdGV7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47XHJcbiAgICAgICAgICAgICAgICAgICAgICB9ICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgLm5ldy10ZW1wbGF0ZSAuYWRkLWxpbmsge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogMjA3cHg7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIG1hcmdpbi1sZWZ0OiAtMTZweDtcclxuICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIDwvc3R5bGU+XHJcbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cIm1vZGFsLWl0ZW1cIj5cclxuICAgICAgICAgICAgICAgICAgICA8TGFiZWwgY2hlY2s+VGVtcGxhdGUgTmFtZTxzcGFuIHN0eWxlPXt7Y29sb3I6ICdyZWQnfX0+Kjwvc3Bhbj48L0xhYmVsPlxyXG4gICAgICAgICAgICAgICAgICAgIDxUZXh0SW5wdXQgZGF0YS10ZXN0aWQ9XCJ0eHRUZW1wbGF0ZU5hbWVcIiBcclxuICAgICAgICAgICAgICAgICAgICAgICAgY2xhc3NOYW1lPVwidGVtcGxhdGUtaW5wdXRcIiBzaXplPVwiZGVmYXVsdFwiXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsoZSk9PiBzZXRUZW1wbGF0ZU5hbWUoZS50YXJnZXQudmFsdWUpfSBcclxuICAgICAgICAgICAgICAgICAgICAgICAgdmFsdWU9e3RlbXBsYXRlTmFtZX0+PC9UZXh0SW5wdXQ+XHJcbiAgICAgICAgICAgICAgICA8L2Rpdj5cclxuXHJcbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cIm1vZGFsLWl0ZW1cIj5cclxuICAgICAgICAgICAgICAgICAgICA8TGFiZWwgY2hlY2s+QmFzZSBUZW1wbGF0ZSBPbjxzcGFuIHN0eWxlPXt7Y29sb3I6ICdyZWQnfX0+Kjwvc3Bhbj48L0xhYmVsPlxyXG4gICAgICAgICAgICAgICAgICAgIDxUZW1wbGF0ZXNEcm9wZG93biBcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGVtcGxhdGVzPXtwcm9wcy50ZW1wbGF0ZXN9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHNlbGVjdGVkVGVtcGxhdGU9e3NlbGVjdGVkQmFzZWRPblRlbXBsYXRlfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICBzZXRUZW1wbGF0ZT17c2V0U2VsZWN0ZWRCYXNlZE9uVGVtcGxhdGV9Lz4gICAgXHJcbiAgICAgICAgICAgICAgICA8L2Rpdj4gICAgICAgIFxyXG5cclxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibW9kYWwtaXRlbVwiPlxyXG4gICAgICAgICAgICAgICAgICAgIDxMYWJlbCBjaGVjaz5UZW1wbGF0ZSBIYXphcmQgKG9wdGlvbmFsKTwvTGFiZWw+XHJcbiAgICAgICAgICAgICAgICAgICAgPEhhemFyZHNEcm9wZG93blxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgY29uZmlnPXtwcm9wcy5jb25maWd9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGhhemFyZHM9e3Byb3BzLmhhemFyZHN9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHNlbGVjdGVkSGF6YXJkPXtwcm9wcy5zZWxlY3RlZEhhemFyZH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgc2V0SGF6YXJkPXtwcm9wcy5zZXRIYXphcmR9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHZlcnRpY2FsPXt0cnVlfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB0b2dnbGVOZXdIYXphcmRNb2RhbD17cHJvcHMudG9nZ2xlTmV3SGF6YXJkTW9kYWx9Lz4gICBcclxuICAgICAgICAgICAgICAgIDwvZGl2PiAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibW9kYWwtaXRlbVwiPlxyXG4gICAgICAgICAgICAgICAgICAgIDxMYWJlbCBjaGVjaz5UZW1wbGF0ZSBPcmdhbml6YXRpb24gKG9wdGlvbmFsKTwvTGFiZWw+XHJcbiAgICAgICAgICAgICAgICAgICAgPE9yZ2FuaXphdGlvbnNEcm9wZG93blxyXG4gICAgICAgICAgICAgICAgICAgICAgICBjb25maWc9e3Byb3BzLmNvbmZpZ31cclxuICAgICAgICAgICAgICAgICAgICAgICAgdmVydGljYWw9e3RydWV9ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIG9yZ2FuaXphdGlvbnM9e3Byb3BzLm9yZ2FuaXphdGlvbnN9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHNlbGVjdGVkT3JnYW5pemF0aW9uPXtwcm9wcy5zZWxlY3RlZE9yZ2FuaXphdGlvbn1cclxuICAgICAgICAgICAgICAgICAgICAgICAgc2V0T3JnYW5pemF0aW9uPXtwcm9wcy5zZXRPcmdhbml6YXRpb259XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRvZ2dsZU5ld09yZ2FuaXphdGlvbk1vZGFsPXtwcm9wcy50b2dnbGVOZXdPcmdhbml6YXRpb25Nb2RhbH0vPlxyXG4gICAgICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgICAgIDwvZGl2PiBcclxuICAgICAgICA8L0Nsc3NNb2RhbD4gICAgICAgXHJcbiAgICApXHJcbn0iLCJpbXBvcnQgeyBEcm9wZG93biwgRHJvcGRvd25CdXR0b24sIERyb3Bkb3duTWVudSwgTGFiZWwgfSBmcm9tIFwiamltdS11aVwiO1xyXG5pbXBvcnQgeyBUcmFzaE91dGxpbmVkIH0gZnJvbSAnamltdS1pY29ucy9vdXRsaW5lZC9lZGl0b3IvdHJhc2gnO1xyXG5pbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCJcclxuXHJcbmV4cG9ydCBjb25zdCBDbHNzRHJvcGRvd24gPSAoe2l0ZW1zLCBpdGVtLCBkZWxldGFibGUsIHNldEl0ZW0sIGRlbGV0ZUl0ZW0sIG1lbnVXaWR0aH06XHJcbiAgICB7aXRlbXM6IGFueVtdLCBpdGVtOiBhbnksIGRlbGV0YWJsZTogYm9vbGVhbiwgc2V0SXRlbTogRnVuY3Rpb24sIFxyXG4gICAgICBkZWxldGVJdGVtPzogRnVuY3Rpb24sIG1lbnVXaWR0aD86IHN0cmluZ30pPT4ge1xyXG5cclxuICAgIGNvbnN0IGJ1dHRvbkVsZW1lbnQgPSBSZWFjdC51c2VSZWY8SFRNTEVsZW1lbnQ+KCk7XHJcbiAgICBcclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKSA9PntcclxuICAgICAgIGlmKGl0ZW1zICYmIGl0ZW1zLmxlbmd0aCA+IDApe1xyXG4gICAgICAgICAgaWYoIWl0ZW0pe1xyXG4gICAgICAgICAgICBzZXRJdGVtKGl0ZW1zWzBdKSBcclxuICAgICAgICAgIH1lbHNle1xyXG4gICAgICAgICAgICBzZXRJdGVtKGl0ZW0pO1xyXG4gICAgICAgICAgfSAgICAgIFxyXG4gICAgICAgfVxyXG4gICAgfSwgW2l0ZW1zXSlcclxuXHJcbiAgICBjb25zdCBpdGVtQ2xpY2sgPSAoaXRlbSk9PnsgICAgIFxyXG4gICAgICAgIHNldEl0ZW0oaXRlbSk7ICAgICAgICBcclxuICAgICAgICBpZihidXR0b25FbGVtZW50ICYmIGJ1dHRvbkVsZW1lbnQuY3VycmVudCl7XHJcbiAgICAgICAgICAgIGJ1dHRvbkVsZW1lbnQuY3VycmVudC5jbGljaygpO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBjb25zdCByZW1vdmVJdGVtID0oaXRlbSkgPT57XHJcbiAgICAgICAgaWYoY29uZmlybSgnUmVtb3ZlICcrKGl0ZW0udGl0bGUgfHwgaXRlbS5uYW1lKSkpe1xyXG4gICAgICAgICAgICBkZWxldGVJdGVtKGl0ZW0pO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gKFxyXG4gICAgICAgIDxkaXYgY2xhc3NOYW1lPVwiY2xzcy1kcm9wZG93bi1jb250YWluZXJcIiBzdHlsZT17e3dpZHRoOiAnMTAwJSd9fT5cclxuICAgICAgICAgICAgPHN0eWxlPlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgICAgLmRyb3Bkb3duLWl0ZW0tY29udGFpbmVye1xyXG4gICAgICAgICAgICAgICAgICAgIGhlaWdodDogNDVweDtcclxuICAgICAgICAgICAgICAgICAgICBib3JkZXItYm90dG9tOiAxcHggc29saWQgcmdiKDIyNywgMjI3LCAyMjcpO1xyXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICAgICAgICAgIGN1cnNvcjogcG9pbnRlcjtcclxuICAgICAgICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmRyb3Bkb3duLWl0ZW0tY29udGFpbmVyOmhvdmVye1xyXG4gICAgICAgICAgICAgICAgICAgIGJhY2tncm91bmQtY29sb3I6IHJnYigyMjcsIDIyNywgMjI3KTtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuamltdS1kcm9wZG93bi1tZW51e1xyXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiAzNSU7XHJcbiAgICAgICAgICAgICAgICAgICAgbWF4LWhlaWdodDogNTAwcHg7XHJcbiAgICAgICAgICAgICAgICAgICAgb3ZlcmZsb3c6IGF1dG87XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmppbXUtZHJvcGRvd24tbWVudSAuZHJvcGRvd24taXRlbS1jb250YWluZXI6bGFzdC1jaGlsZHtcclxuICAgICAgICAgICAgICAgICAgICBib3JkZXItYm90dG9tOiBub25lO1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5tb2RhbC1jb250ZW50IC5jbHNzLWRyb3Bkb3duLWNvbnRhaW5lciBidXR0b257XHJcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmNsc3MtZHJvcGRvd24tY29udGFpbmVyIC5qaW11LWRyb3Bkb3due1xyXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5jbG9zZS1idXR0b257XHJcbiAgICAgICAgICAgICAgICAgICAgbWFyZ2luOiAxMHB4O1xyXG4gICAgICAgICAgICAgICAgICAgIGNvbG9yOiBncmF5O1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgIC5kcm9wZG93bi1pdGVtLWNvbnRhaW5lciBsYWJlbHtcclxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDEwMCU7XHJcbiAgICAgICAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICAgICAgICBhbGlnbi1pdGVtczogY2VudGVyO1xyXG4gICAgICAgICAgICAgICAgICAgIGZvbnQtc2l6ZTogMS4yZW07XHJcbiAgICAgICAgICAgICAgICAgICAgbWFyZ2luLWxlZnQ6IDFlbTtcclxuICAgICAgICAgICAgICAgICAgICBjdXJzb3I6IHBvaW50ZXI7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIDwvc3R5bGU+XHJcbiAgICAgICAgICAgIDxEcm9wZG93biAgYWN0aXZlSWNvbj1cInRydWVcIiBzaXplPVwibGdcIj5cclxuICAgICAgICAgICAgICAgICAgICA8RHJvcGRvd25CdXR0b24gcmVmPXtidXR0b25FbGVtZW50fSAgc2l6ZT1cImxnXCIgc3R5bGU9e3t0ZXh0QWxpZ246ICdsZWZ0J319PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7aXRlbT8udGl0bGUgfHwgaXRlbT8ubmFtZX1cclxuICAgICAgICAgICAgICAgICAgICA8L0Ryb3Bkb3duQnV0dG9uPlxyXG4gICAgICAgICAgICAgICAgICAgIDxEcm9wZG93bk1lbnUgc3R5bGU9e3t3aWR0aDogbWVudVdpZHRoIHx8IFwiMzAlXCJ9fT5cclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGl0ZW1zPy5tYXAoKGl0ZW0sIGlkeCkgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGlkPXtpdGVtPy5uYW1lIHx8IGl0ZW0/LnRpdGxlfSBjbGFzc05hbWU9XCJkcm9wZG93bi1pdGVtLWNvbnRhaW5lclwiPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8TGFiZWwgY2hlY2sgb25DbGljaz17KCkgPT4gaXRlbUNsaWNrKGl0ZW0pfT57aXRlbT8udGl0bGUgfHwgaXRlbT8ubmFtZX08L0xhYmVsPiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKChpdGVtPy50aXRsZSB8fCBpdGVtPy5uYW1lKSAhPT0gJy1Ob25lLScpICYmIGRlbGV0YWJsZSA/IFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKDxUcmFzaE91dGxpbmVkIHRpdGxlPSdSZW1vdmUnIGNsYXNzTmFtZT1cImNsb3NlLWJ1dHRvblwiIHNpemU9ezIwfSBvbkNsaWNrPXsoKSA9PiByZW1vdmVJdGVtKGl0ZW0pfS8+KVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgOiBudWxsXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4gIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB9KVxyXG4gICAgICAgICAgICAgICAgICAgIH0gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgPC9Ecm9wZG93bk1lbnU+XHJcbiAgICAgICAgICAgIDwvRHJvcGRvd24+XHJcbiAgICAgICAgPC9kaXY+XHJcbiAgICApXHJcbn0iLCJpbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCJcclxuaW1wb3J0IHsgQ2xzc0Ryb3Bkb3duIH0gZnJvbSBcIi4vY2xzcy1kcm9wZG93blwiXHJcbmltcG9ydCB7IEhhemFyZCB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2RhdGEtZGVmaW5pdGlvbnNcIlxyXG5pbXBvcnQgeyBCdXR0b24gfSBmcm9tIFwiamltdS11aVwiO1xyXG5pbXBvcnQgeyBQbHVzQ2lyY2xlT3V0bGluZWQgfSBmcm9tIFwiamltdS1pY29ucy9vdXRsaW5lZC9lZGl0b3IvcGx1cy1jaXJjbGVcIjtcclxuaW1wb3J0IHsgZGVsZXRlSGF6YXJkLCBkaXNwYXRjaEFjdGlvbiB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2FwaVwiO1xyXG5pbXBvcnQgeyBDTFNTQWN0aW9uS2V5cyB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2Nsc3Mtc3RvcmVcIjtcclxuXHJcblxyXG5leHBvcnQgY29uc3QgSGF6YXJkc0Ryb3Bkb3duID0oe2NvbmZpZywgaGF6YXJkcywgc2VsZWN0ZWRIYXphcmQsIHNldEhhemFyZCwgdmVydGljYWwsIHRvZ2dsZU5ld0hhemFyZE1vZGFsfSk9PntcclxuXHJcbiAgICBjb25zdCBbbG9jYWxIYXphcmRzLCBzZXRMb2NhbEhhemFyZHNdID0gUmVhY3QudXNlU3RhdGU8SGF6YXJkW10+KFtdKTtcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgICAgICBpZihoYXphcmRzKXsgICAgICAgICAgICBcclxuICAgICAgICAgICAgc2V0TG9jYWxIYXphcmRzKFsuLi5oYXphcmRzXSBhcyBIYXphcmRbXSlcclxuICAgICAgICB9XHJcbiAgICB9LCBbaGF6YXJkc10pXHJcblxyXG4gICAgY29uc3QgcmVtb3ZlSGF6YXJkID1hc3luYyAoaGF6YXJkOiBIYXphcmQpPT57ICAgICAgIFxyXG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZGVsZXRlSGF6YXJkKGhhemFyZCwgY29uZmlnKTtcclxuICAgICAgIGlmKHJlc3BvbnNlLmVycm9ycyl7XHJcbiAgICAgICAgY29uc29sZS5sb2cocmVzcG9uc2UuZXJyb3JzKTtcclxuICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCByZXNwb25zZS5lcnJvcnMpO1xyXG4gICAgICAgIHJldHVybjtcclxuICAgICAgIH1cclxuICAgICAgIGNvbnNvbGUubG9nKGAke2hhemFyZC50aXRsZX0gZGVsZXRlZGApO1xyXG4gICAgICAgc2V0TG9jYWxIYXphcmRzKFsuLi5sb2NhbEhhemFyZHMuZmlsdGVyKGggPT4gaC5pZCAhPT0gaGF6YXJkLmlkKV0pO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICByZXR1cm4gKFxyXG4gICAgICAgIDxkaXYgc3R5bGU9e3tkaXNwbGF5OiB2ZXJ0aWNhbCA/ICdibG9jayc6ICdmbGV4JyxcclxuICAgICAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcid9fT5cclxuICAgICAgICAgICAgPHN0eWxlPlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgICAgICAgLmFjdGlvbi1pY29uIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IGdyYXk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGN1cnNvcjogcG9pbnRlcjtcclxuICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIDwvc3R5bGU+XHJcbiAgICAgICAgICAgIDxDbHNzRHJvcGRvd24gaXRlbXM9e2xvY2FsSGF6YXJkc31cclxuICAgICAgICAgICAgICAgIGl0ZW09e3NlbGVjdGVkSGF6YXJkfSBcclxuICAgICAgICAgICAgICAgIGRlbGV0YWJsZT17dHJ1ZX1cclxuICAgICAgICAgICAgICAgIHNldEl0ZW09e3NldEhhemFyZH0gXHJcbiAgICAgICAgICAgICAgICBkZWxldGVJdGVtPXtyZW1vdmVIYXphcmR9Lz4gXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgdmVydGljYWw/IChcclxuICAgICAgICAgICAgICAgIDxCdXR0b24gZGF0YS10ZXN0aWQ9XCJidG5TaG93QWRkT3JnYW5pemF0aW9uXCIgIGNsYXNzTmFtZT1cIiBhZGQtbGlua1wiXHJcbiAgICAgICAgICAgICAgICAgICAgIHR5cGU9XCJsaW5rXCIgc3R5bGU9e3t0ZXh0QWxpZ246ICdsZWZ0J319XHJcbiAgICAgICAgICAgICAgICAgICAgb25DbGljaz17KCk9PiB0b2dnbGVOZXdIYXphcmRNb2RhbCh0cnVlKX0+XHJcbiAgICAgICAgICAgICAgICAgICAgQWRkIE5ldyBIYXphcmRcclxuICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxyXG4gICAgICAgICAgICAgICApOihcclxuICAgICAgICAgICAgICAgIDxQbHVzQ2lyY2xlT3V0bGluZWQgY2xhc3NOYW1lPVwiYWN0aW9uLWljb25cIiBcclxuICAgICAgICAgICAgICAgICAgICBkYXRhLXRlc3RpZD1cImJ0bkFkZE5ld0hhemFyZFwiIFxyXG4gICAgICAgICAgICAgICAgICAgIHRpdGxlPVwiQWRkIE5ldyBIYXphcmRcIiBzaXplPXszMH0gY29sb3I9eydncmF5J31cclxuICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKT0+IHRvZ2dsZU5ld0hhemFyZE1vZGFsKHRydWUpfS8+IFxyXG4gICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICB9ICAgXHJcbiAgICAgICAgICAgIHsvKiA8cD57c2VsZWN0ZWRIYXphcmQ/LmRlc2NyaXB0aW9ufTwvcD4gKi99XHJcbiAgICAgICAgPC9kaXY+XHJcbiAgICApXHJcbn0iLCJpbXBvcnQgeyBMb2FkaW5nIH0gZnJvbSBcImppbXUtdWlcIlxyXG5pbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCJcclxuXHJcbmNvbnN0IENsc3NMb2FkaW5nID0oe21lc3NhZ2V9OnttZXNzYWdlPzpzdHJpbmd9KSA9PntcclxuICAgIHJldHVybiggICAgICAgIFxyXG4gICAgICAgIDxkaXZcclxuICAgICAgICAgICAgc3R5bGU9e3tcclxuICAgICAgICAgICAgICAgIGhlaWdodDogJzEwMCUnLFxyXG4gICAgICAgICAgICAgICAgd2lkdGg6ICcxMDAlJyxcclxuICAgICAgICAgICAgICAgIHBvc2l0aW9uOiAnYWJzb2x1dGUnLFxyXG4gICAgICAgICAgICAgICAgYmFja2dyb3VuZDogJ3JnYigwIDAgMCAvIDEzJSknLFxyXG4gICAgICAgICAgICAgICAgdG9wOiAwLCAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICBsZWZ0OiAwLFxyXG4gICAgICAgICAgICAgICAgekluZGV4OiA5OTk5OTksXHJcbiAgICAgICAgICAgICAgICBkaXNwbGF5OiAnZmxleCcsXHJcbiAgICAgICAgICAgICAgICBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicsXHJcbiAgICAgICAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJ1xyXG4gICAgICAgICAgICB9fVxyXG4gICAgICAgICAgICA+XHJcbiAgICAgICAgICAgIDxMb2FkaW5nXHJcbiAgICAgICAgICAgICAgICBjbGFzc05hbWU9XCJcIlxyXG4gICAgICAgICAgICAgICAgdHlwZT1cIlNFQ09OREFSWVwiXHJcbiAgICAgICAgICAgIC8+XHJcbiAgICAgICAgICAgIDxoMz57bWVzc2FnZX08L2gzPlxyXG4gICAgICAgIDwvZGl2PlxyXG4gICAgKVxyXG59XHJcbmV4cG9ydCBkZWZhdWx0IENsc3NMb2FkaW5nOyIsIlxyXG5pbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCJcclxuaW1wb3J0IHsgTW9kYWwsIE1vZGFsSGVhZGVyLCBNb2RhbEJvZHksIE1vZGFsRm9vdGVyLCBCdXR0b24gfSBmcm9tIFwiamltdS11aVwiXHJcbmltcG9ydCBDbHNzTG9hZGluZyBmcm9tIFwiLi9jbHNzLWxvYWRpbmdcIlxyXG5cclxuLy8gZXhwb3J0IGludGVyZmFjZSBNb2RhbFByb3BzIHtcclxuLy8gICAgIHRpdGxlOiBzdHJpbmc7XHJcbi8vICAgICB2aXNpYmxlOiBib29sZWFuO1xyXG4vLyAgICAgZGlzYWJsZTogYm9vbGVhbjtcclxuLy8gICAgIGNoaWxkcmVuOiBhbnk7XHJcbi8vICAgICB0b2dnbGVWaXNpYmlsaXR5OiBGdW5jdGlvbjtcclxuLy8gICAgIHNhdmU6IEZ1bmN0aW9uO1xyXG4vLyAgICAgY2FuY2VsOiBGdW5jdGlvbjtcclxuLy8gfVxyXG5cclxuZXhwb3J0IGNvbnN0IENsc3NNb2RhbCA9KHByb3BzKT0+e1xyXG4gICAgcmV0dXJuIChcclxuICAgICAgICA8TW9kYWwgaXNPcGVuPXtwcm9wcy52aXNpYmxlfSBjZW50ZXJlZD17dHJ1ZX0gY2xhc3NOYW1lPVwiY2xzcy1tb2RhbFwiPlxyXG4gICAgICAgICAgICA8c3R5bGU+XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAuY2xzcy1tb2RhbCAubW9kYWwtY29udGVudHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LXNpemU6IDEuM3JlbTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW5cclxuICAgICAgICAgICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jbHNzLW1vZGFsIC5tb2RhbC10aXRsZXtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQtc2l6ZTogMS4xZW07XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH0gICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgaW5wdXR7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYWRkaW5nLWxlZnQ6IDBweDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgLmppbXUtaW5wdXQgc3BhbntcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogNDBweDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQtc2l6ZTogLjllbTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgbGFiZWx7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogZ3JheTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfSAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgLmppbXUtZHJvcGRvd24tYnV0dG9ue1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC1zaXplOiAxZW07XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH0gICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jbHNzLW1vZGFsIC5tb2RhbC1pdGVte1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbWFyZ2luOiAxMHB4IDA7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH0gICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgdGV4dGFyZWF7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LXNpemU6IDAuOGVtO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9ICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgLnNwYWNlcntcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiAxZW07XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIDwvc3R5bGU+XHJcbiAgICAgICAgICAgIDxNb2RhbEhlYWRlciB0b2dnbGU9eygpPT5wcm9wcy50b2dnbGVWaXNpYmlsaXR5KGZhbHNlKX0+XHJcbiAgICAgICAgICAgICAgICB7cHJvcHMudGl0bGV9XHJcbiAgICAgICAgICAgIDwvTW9kYWxIZWFkZXI+XHJcbiAgICAgICAgICAgIDxNb2RhbEJvZHk+XHJcbiAgICAgICAgICAgICAgICB7cHJvcHMuY2hpbGRyZW59ICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgPC9Nb2RhbEJvZHk+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHByb3BzLmhpZGVGb290ZXIgJiYgcHJvcHMuaGlkZUZvb3RlciA9PSB0cnVlID8gbnVsbCA6XHJcbiAgICAgICAgICAgICAgICAoXHJcbiAgICAgICAgICAgICAgICAgICAgPE1vZGFsRm9vdGVyID5cclxuICAgICAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiBvbkNsaWNrPXsoKSA9PiAocHJvcHMuY2FuY2VsID8gcHJvcHMuY2FuY2VsKCkgOiBwcm9wcy50b2dnbGVWaXNpYmlsaXR5KGZhbHNlKSl9PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge3Byb3BzLm5vQnV0dG9uVGl0bGUgfHwgJ0NhbmNlbCd9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cInNwYWNlclwiLz5cclxuICAgICAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiBkYXRhLXRlc3RpZD1cImJ0blNhdmVcIiBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRpc2FibGVkPXtwcm9wcy5kaXNhYmxlfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgb25DbGljaz17KCkgPT4gcHJvcHMuc2F2ZSgpfT5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtwcm9wcy55ZXNCdXR0b25UaXRsZSB8fCAnU2F2ZSd9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxyXG4gICAgICAgICAgICAgICAgICAgIDwvTW9kYWxGb290ZXI+XHJcbiAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgIH0gICAgICAgICAgICBcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgKHByb3BzLmxvYWRpbmcpID8gPENsc3NMb2FkaW5nLz4gOiBudWxsICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgPC9Nb2RhbD4gXHJcbiAgICApXHJcbn0iLCJpbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCJcclxuaW1wb3J0IHsgQ2xzc0Ryb3Bkb3duIH0gZnJvbSBcIi4vY2xzcy1kcm9wZG93blwiXHJcbmltcG9ydCB7IEJ1dHRvbiB9IGZyb20gXCJqaW11LXVpXCJcclxuaW1wb3J0IHsgUGx1c0NpcmNsZU91dGxpbmVkIH0gZnJvbSBcImppbXUtaWNvbnMvb3V0bGluZWQvZWRpdG9yL3BsdXMtY2lyY2xlXCJcclxuaW1wb3J0IHsgZGVsZXRlT3JnYW5pemF0aW9uLCBkaXNwYXRjaEFjdGlvbiB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2FwaVwiXHJcbmltcG9ydCB7IE9yZ2FuaXphdGlvbiB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2RhdGEtZGVmaW5pdGlvbnNcIlxyXG5pbXBvcnQgeyBDTFNTQWN0aW9uS2V5cyB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2Nsc3Mtc3RvcmVcIlxyXG5cclxuXHJcbmV4cG9ydCBjb25zdCBPcmdhbml6YXRpb25zRHJvcGRvd24gPSh7Y29uZmlnLCBvcmdhbml6YXRpb25zLCBzZWxlY3RlZE9yZ2FuaXphdGlvbiwgXHJcbiAgICBzZXRPcmdhbml6YXRpb24sIHZlcnRpY2FsLCB0b2dnbGVOZXdPcmdhbml6YXRpb25Nb2RhbH0pPT57XHJcblxyXG4gICAgY29uc3QgW2xvY2FsT3JnYW5pemF0aW9ucywgc2V0TG9jYWxPcmdhbml6YXRpb25zXSA9IFJlYWN0LnVzZVN0YXRlPE9yZ2FuaXphdGlvbltdPihbXSk7XHJcblxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpPT57XHJcbiAgICAgICAgaWYob3JnYW5pemF0aW9ucyl7IFxyXG4gICAgICAgICAgICBzZXRMb2NhbE9yZ2FuaXphdGlvbnMoWy4uLm9yZ2FuaXphdGlvbnNdIGFzIE9yZ2FuaXphdGlvbltdKVxyXG4gICAgICAgIH1cclxuICAgIH0sIFtvcmdhbml6YXRpb25zXSlcclxuICAgIFxyXG4gICAgY29uc3QgcmVtb3ZlT3JnYW5pemF0aW9uID1hc3luYyAob3JnYW5pemF0aW9uOiBPcmdhbml6YXRpb24pPT57XHJcbiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZGVsZXRlT3JnYW5pemF0aW9uKG9yZ2FuaXphdGlvbiwgY29uZmlnKTtcclxuICAgICAgaWYocmVzcG9uc2UuZXJyb3JzKXtcclxuICAgICAgIGNvbnNvbGUubG9nKHJlc3BvbnNlLmVycm9ycyk7XHJcbiAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCByZXNwb25zZS5lcnJvcnMpO1xyXG4gICAgICAgcmV0dXJuO1xyXG4gICAgICB9XHJcbiAgICAgIGNvbnNvbGUubG9nKGAke29yZ2FuaXphdGlvbi50aXRsZX0gZGVsZXRlZGApXHJcbiAgICAgIHNldExvY2FsT3JnYW5pemF0aW9ucyhbLi4ubG9jYWxPcmdhbml6YXRpb25zLmZpbHRlcihvID0+IG8uaWQgIT09IG9yZ2FuaXphdGlvbi5pZCldKTtcclxuICAgIH1cclxuICAgIHJldHVybiAoXHJcbiAgICAgICAgPGRpdiBzdHlsZT17e2Rpc3BsYXk6IHZlcnRpY2FsID8gJ2Jsb2NrJzogJ2ZsZXgnLFxyXG4gICAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJ319PlxyXG4gICAgICAgICAgICAgPENsc3NEcm9wZG93biBpdGVtcz17bG9jYWxPcmdhbml6YXRpb25zfVxyXG4gICAgICAgICAgICAgICAgaXRlbT17c2VsZWN0ZWRPcmdhbml6YXRpb259IFxyXG4gICAgICAgICAgICAgICAgZGVsZXRhYmxlPXt0cnVlfVxyXG4gICAgICAgICAgICAgICAgc2V0SXRlbT17c2V0T3JnYW5pemF0aW9ufSBcclxuICAgICAgICAgICAgICAgIGRlbGV0ZUl0ZW09e3JlbW92ZU9yZ2FuaXphdGlvbn0vPlxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgIHRvZ2dsZU5ld09yZ2FuaXphdGlvbk1vZGFsID8gKFxyXG4gICAgICAgICAgICAgICAgdmVydGljYWw/IChcclxuICAgICAgICAgICAgICAgICAgICA8QnV0dG9uIGRhdGEtdGVzdGlkPVwiYnRuU2hvd0FkZE9yZ2FuaXphdGlvblwiICBjbGFzc05hbWU9XCIgYWRkLWxpbmtcIlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgdHlwZT1cImxpbmtcIiBzdHlsZT17e3RleHRBbGlnbjogJ2xlZnQnfX1cclxuICAgICAgICAgICAgICAgICAgICAgICAgb25DbGljaz17KCk9PiB0b2dnbGVOZXdPcmdhbml6YXRpb25Nb2RhbCh0cnVlKX0+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIEFkZCBOZXcgT3JnYW5pemF0aW9uXHJcbiAgICAgICAgICAgICAgICAgICAgPC9CdXR0b24+XHJcbiAgICAgICAgICAgICAgICAgICApOihcclxuICAgICAgICAgICAgICAgICAgICA8UGx1c0NpcmNsZU91dGxpbmVkIGNsYXNzTmFtZT1cImFjdGlvbi1pY29uXCIgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGRhdGEtdGVzdGlkPVwiYnRuQWRkTmV3T3JnYW5pemF0aW9uXCIgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRpdGxlPVwiQWRkIE5ldyBPcmdhbml6YXRpb25cIiBzaXplPXszMH0gY29sb3I9eydncmF5J31cclxuICAgICAgICAgICAgICAgICAgICAgICAgb25DbGljaz17KCk9PiB0b2dnbGVOZXdPcmdhbml6YXRpb25Nb2RhbCh0cnVlKX0vPiAgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgIClcclxuICAgICAgICAgICAgICAgKTogbnVsbFxyXG4gICAgICAgICAgICB9ICAgXHJcbiAgICAgICAgPC9kaXY+XHJcbiAgICApXHJcbn0iLCJpbXBvcnQgeyBUZXh0SW5wdXQgfSBmcm9tIFwiamltdS11aVwiXHJcbmltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5cclxuZXhwb3J0IGNvbnN0IENMU1NTZWFyY2hJbnB1dCA9ICh7dGl0bGUsIG9uQ2hhbmdlLCBkZWZhdWx0VmFsdWUsIHByb3BzfTpcclxuICAgIHt0aXRsZTogc3RyaW5nLCBvbkNoYW5nZTogRnVuY3Rpb24sIGRlZmF1bHRWYWx1ZT86IHN0cmluZywgcHJvcHM6IGFueX0pID0+IHsgICBcclxuICAgIHJldHVybiAoXHJcbiAgICAgICAgPGg0IHN0eWxlPXt7XHJcbiAgICAgICAgICAgIHdpZHRoOiAnMTAwJScgICAgXHJcbiAgICAgICAgICB9fT5cclxuICAgICAgICB7dGl0bGV9OlxyXG4gICAgICAgIDxUZXh0SW5wdXQgc3R5bGU9e3tmb250U2l6ZTogcHJvcHMudGhlbWUudHlwb2dyYXBoeS5zaXplcy5kaXNwbGF5NH19ICBcclxuICAgICAgICAgICAgZGF0YS10ZXN0aWQ9J3RlbXBsYXRlU2VhcmNoSW5wdXQnICAgICAgICAgXHJcbiAgICAgICAgICAgIHBsYWNlaG9sZGVyPSdTZWFyY2guLi4nXHJcbiAgICAgICAgICAgIHNpemU9J2xnJ1xyXG4gICAgICAgICAgICBhbGxvd0NsZWFyXHJcbiAgICAgICAgICAgIHR5cGU9XCJ0ZXh0XCJcclxuICAgICAgICAgICAgdmFsdWU9e2RlZmF1bHRWYWx1ZX1cclxuICAgICAgICAgICAgb25DaGFuZ2U9eyhlKSA9PiBvbkNoYW5nZShlLnRhcmdldC52YWx1ZSl9ICAgICAgICAgIFxyXG4gICAgICAgICAgICB7Li4ucHJvcHN9Lz5cclxuICAgICAgICA8L2g0PlxyXG4gICAgKVxyXG59IiwiaW1wb3J0IHsgU2V0dGluZ091dGxpbmVkIH0gZnJvbSAnamltdS1pY29ucy9vdXRsaW5lZC9hcHBsaWNhdGlvbi9zZXR0aW5nJztcclxuaW1wb3J0IHsgU3VjY2Vzc091dGxpbmVkIH0gZnJvbSAnamltdS1pY29ucy9vdXRsaW5lZC9zdWdnZXN0ZWQvc3VjY2Vzcyc7XHJcbmltcG9ydCB7IExhYmVsIH0gZnJvbSAnamltdS11aSc7XHJcbmltcG9ydCBSZWFjdCBmcm9tICdyZWFjdCc7XHJcbmltcG9ydCB7IEJBU0VMSU5FX1RFTVBMQVRFX05BTUUsIENMU1NfQURNSU4gfSBmcm9tICcuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2NvbnN0YW50cyc7XHJcbmltcG9ydCB7IENMU1NUZW1wbGF0ZSB9IGZyb20gJy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvZGF0YS1kZWZpbml0aW9ucyc7XHJcbmltcG9ydCB7IEZvbGRlck91dGxpbmVkIH0gZnJvbSAnamltdS1pY29ucy9vdXRsaW5lZC9hcHBsaWNhdGlvbi9mb2xkZXInXHJcblxyXG5leHBvcnQgY29uc3QgVGVtcGxhdGVCdXR0b24gPSh7dGVtcGxhdGUsIG9uQ2xpY2ssIG9uRGJsQ2xpY2ssIHByb3BzfTpcclxuICAgIHt0ZW1wbGF0ZTogQ0xTU1RlbXBsYXRlLCBvbkNsaWNrOiBhbnksIG9uRGJsQ2xpY2s6IGFueSwgcHJvcHM6IGFueX0pPT4geyAgXHJcblxyXG4gICAgY29uc3Qgb25Eb3VibGVDbGljaz0oKT0+e1xyXG4gICAgICAgIC8vIGlmKHByb3BzLnVzZXIuZ3JvdXBzLmZpbmQoZyA9PiBnLnRpdGxlID09PSBDTFNTX0FETUlOKSAmJlxyXG4gICAgICAgIC8vIHRlbXBsYXRlLm5hbWUgIT09IEJBU0VMSU5FX1RFTVBMQVRFX05BTUUpe1xyXG5cclxuICAgICAgICAvLyAgICAgaWYoY29uZmlybSgnQXJjaGl2ZSB0aGUgdGVtcGxhdGU/JykgPT0gdHJ1ZSl7XHJcbiAgICAgICAgLy8gICAgICAgICBvbkRibENsaWNrKHRlbXBsYXRlLm9iamVjdElkKTtcclxuICAgICAgICAvLyAgICAgfVxyXG4gICAgICAgIC8vIH1cclxuICAgIH1cclxuICAgIHJldHVybiAoXHJcbiAgICAgICAgPGRpdiBkYXRhLXRlc3RpZD1cInRlbXBsYXRlQnV0dG9uXCIgY2xhc3NOYW1lPVwiYnV0dG9uLXdyYXBwZXJcIiBcclxuICAgICAgICBvbkRvdWJsZUNsaWNrPXtvbkRvdWJsZUNsaWNrfSBvbkNsaWNrPXsoKSA9PiBvbkNsaWNrKHRlbXBsYXRlLm9iamVjdElkKX1cclxuICAgICAgICAgICAgc3R5bGU9e3tcclxuICAgICAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6KHRlbXBsYXRlLmlzU2VsZWN0ZWQgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgID8gcHJvcHMuY29uZmlnLnNlbGVjdGVkQnV0dG9uQmFja2dyb3VuZENvbG9yXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDogcHJvcHMuY29uZmlnLmRlZmF1bHRCdXR0b25CYWNrZ3JvdW5kQ29sb3IpXHJcbiAgICAgICAgICAgICAgICAgICB9fT5cclxuICAgICAgICAgICAgICAgIDxzdHlsZT5cclxuICAgICAgICAgICAgICAgICAge2BcclxuICAgICAgICAgICAgICAgICAgICAuYnV0dG9uLXdyYXBwZXJ7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBhbGlnbi1pdGVtczogY2VudGVyO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBmb250LXNpemU6IDE1cHg7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHBhZGRpbmc6IDEwcHg7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGN1cnNvcjogcG9pbnRlcjtcclxuICAgICAgICAgICAgICAgICAgICAgICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBtYXJnaW46IDVweCAwO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAuYnV0dG9uLXdyYXBwZXI6aG92ZXJ7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIG9wYWNpdHk6IDAuNTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgLmJ1dHRvbi1jb250ZW50e1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjtcclxuICAgICAgICAgICAgICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgLmJ1dHRvbi1sYWJlbHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgY3Vyc29yOiBwb2ludGVyOyAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogMTgwcHg7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIG92ZXJmbG93OiBoaWRkZW47XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRleHQtb3ZlcmZsb3c6IGVsbGlwc2lzO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBtYXJnaW4tYm90dG9tOiAwICFpbXBvcnRhbnQ7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIC5wcmUtaWNvbntcclxuICAgICAgICAgICAgICAgICAgICAgICAgbWFyZ2luLXJpZ2h0OiAxMHB4O1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGB9XHJcbiAgICAgICAgICAgICAgICA8L3N0eWxlPlxyXG4gICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cImJ1dHRvbi1jb250ZW50XCI+XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgdGVtcGxhdGU/LnN0YXR1cz8uY29kZSA9PT0gMSA/IChcclxuICAgICAgICAgICAgICAgICAgICAgICAgPFNldHRpbmdPdXRsaW5lZCBjbGFzc05hbWU9J3ByZS1pY29uJyBzaXplPXsyMH0gY29sb3I9e1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGVtcGxhdGUuaXNTZWxlY3RlZCBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgID8gcHJvcHMuY29uZmlnLnNlbGVjdGVkQnV0dG9uQ29sb3JcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogJ2dyYXknfSAvPlxyXG4gICAgICAgICAgICAgICAgICAgICk6IFxyXG4gICAgICAgICAgICAgICAgICAgIChcclxuICAgICAgICAgICAgICAgICAgICAgICAgPEZvbGRlck91dGxpbmVkIGNsYXNzTmFtZT0ncHJlLWljb24nIHNpemU9ezE1fSBjb2xvcj17XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZW1wbGF0ZS5pc1NlbGVjdGVkIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPyBwcm9wcy5jb25maWcuc2VsZWN0ZWRCdXR0b25Db2xvclxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgOiAnZ3JheSd9IC8+XHJcbiAgICAgICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICA8TGFiZWwgc3R5bGU9e3tcclxuICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHRlbXBsYXRlLmlzU2VsZWN0ZWQgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgID8gcHJvcHMuY29uZmlnLnNlbGVjdGVkQnV0dG9uQ29sb3IgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDogcHJvcHMuY29uZmlnLmRlZmF1bHRUZW1wbGF0ZUJ1dHRvbkNvbG9yXHJcbiAgICAgICAgICAgICAgICAgICAgfX0gY2xhc3NOYW1lPSdidXR0b24tbGFiZWwnPnt0ZW1wbGF0ZS5uYW1lfTwvTGFiZWw+XHJcbiAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB0ZW1wbGF0ZS5pc1NlbGVjdGVkID8gIDxTdWNjZXNzT3V0bGluZWQgY2xhc3NOYW1lPSdwb3N0LWljb24nIHNpemU9ezIwfSBjb2xvcj17cHJvcHMuY29uZmlnLnNlbGVjdGVkQnV0dG9uQ29sb3J9Lz4gOiBudWxsXHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICA8L2Rpdj5cclxuICAgIClcclxufSIsImltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5pbXBvcnQgeyBDbHNzRHJvcGRvd24gfSBmcm9tIFwiLi9jbHNzLWRyb3Bkb3duXCJcclxuXHJcblxyXG5leHBvcnQgY29uc3QgVGVtcGxhdGVzRHJvcGRvd24gPSh7dGVtcGxhdGVzLCBzZWxlY3RlZFRlbXBsYXRlLCBzZXRUZW1wbGF0ZX0pPT57XHJcbiAgICBcclxuICAgIGNvbnN0IGRlbGV0ZVRlbXBsYXRlID0oKT0+e1xyXG4gICAgICAgIFxyXG4gICAgfVxyXG4gICAgcmV0dXJuIChcclxuICAgICAgICA8Q2xzc0Ryb3Bkb3duIGl0ZW1zPXt0ZW1wbGF0ZXN9XHJcbiAgICAgICAgICAgIGl0ZW09e3NlbGVjdGVkVGVtcGxhdGV9IFxyXG4gICAgICAgICAgICBkZWxldGFibGU9e3RydWV9XHJcbiAgICAgICAgICAgIHNldEl0ZW09e3NldFRlbXBsYXRlfSBcclxuICAgICAgICAgICAgZGVsZXRlSXRlbT17ZGVsZXRlVGVtcGxhdGV9Lz5cclxuICAgIClcclxufSIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X2FyY2dpc19fOyIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X2NvcmVfXzsiLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfcmVhY3RfXzsiLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfamltdV91aV9fOyIsIi8vIFRoZSBtb2R1bGUgY2FjaGVcbnZhciBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX18gPSB7fTtcblxuLy8gVGhlIHJlcXVpcmUgZnVuY3Rpb25cbmZ1bmN0aW9uIF9fd2VicGFja19yZXF1aXJlX18obW9kdWxlSWQpIHtcblx0Ly8gQ2hlY2sgaWYgbW9kdWxlIGlzIGluIGNhY2hlXG5cdHZhciBjYWNoZWRNb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdO1xuXHRpZiAoY2FjaGVkTW9kdWxlICE9PSB1bmRlZmluZWQpIHtcblx0XHRyZXR1cm4gY2FjaGVkTW9kdWxlLmV4cG9ydHM7XG5cdH1cblx0Ly8gQ3JlYXRlIGEgbmV3IG1vZHVsZSAoYW5kIHB1dCBpdCBpbnRvIHRoZSBjYWNoZSlcblx0dmFyIG1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF0gPSB7XG5cdFx0Ly8gbm8gbW9kdWxlLmlkIG5lZWRlZFxuXHRcdC8vIG5vIG1vZHVsZS5sb2FkZWQgbmVlZGVkXG5cdFx0ZXhwb3J0czoge31cblx0fTtcblxuXHQvLyBFeGVjdXRlIHRoZSBtb2R1bGUgZnVuY3Rpb25cblx0X193ZWJwYWNrX21vZHVsZXNfX1ttb2R1bGVJZF0obW9kdWxlLCBtb2R1bGUuZXhwb3J0cywgX193ZWJwYWNrX3JlcXVpcmVfXyk7XG5cblx0Ly8gUmV0dXJuIHRoZSBleHBvcnRzIG9mIHRoZSBtb2R1bGVcblx0cmV0dXJuIG1vZHVsZS5leHBvcnRzO1xufVxuXG4iLCIvLyBnZXREZWZhdWx0RXhwb3J0IGZ1bmN0aW9uIGZvciBjb21wYXRpYmlsaXR5IHdpdGggbm9uLWhhcm1vbnkgbW9kdWxlc1xuX193ZWJwYWNrX3JlcXVpcmVfXy5uID0gKG1vZHVsZSkgPT4ge1xuXHR2YXIgZ2V0dGVyID0gbW9kdWxlICYmIG1vZHVsZS5fX2VzTW9kdWxlID9cblx0XHQoKSA9PiAobW9kdWxlWydkZWZhdWx0J10pIDpcblx0XHQoKSA9PiAobW9kdWxlKTtcblx0X193ZWJwYWNrX3JlcXVpcmVfXy5kKGdldHRlciwgeyBhOiBnZXR0ZXIgfSk7XG5cdHJldHVybiBnZXR0ZXI7XG59OyIsIi8vIGRlZmluZSBnZXR0ZXIgZnVuY3Rpb25zIGZvciBoYXJtb255IGV4cG9ydHNcbl9fd2VicGFja19yZXF1aXJlX18uZCA9IChleHBvcnRzLCBkZWZpbml0aW9uKSA9PiB7XG5cdGZvcih2YXIga2V5IGluIGRlZmluaXRpb24pIHtcblx0XHRpZihfX3dlYnBhY2tfcmVxdWlyZV9fLm8oZGVmaW5pdGlvbiwga2V5KSAmJiAhX193ZWJwYWNrX3JlcXVpcmVfXy5vKGV4cG9ydHMsIGtleSkpIHtcblx0XHRcdE9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBrZXksIHsgZW51bWVyYWJsZTogdHJ1ZSwgZ2V0OiBkZWZpbml0aW9uW2tleV0gfSk7XG5cdFx0fVxuXHR9XG59OyIsIl9fd2VicGFja19yZXF1aXJlX18ubyA9IChvYmosIHByb3ApID0+IChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwob2JqLCBwcm9wKSkiLCIvLyBkZWZpbmUgX19lc01vZHVsZSBvbiBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLnIgPSAoZXhwb3J0cykgPT4ge1xuXHRpZih0eXBlb2YgU3ltYm9sICE9PSAndW5kZWZpbmVkJyAmJiBTeW1ib2wudG9TdHJpbmdUYWcpIHtcblx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgU3ltYm9sLnRvU3RyaW5nVGFnLCB7IHZhbHVlOiAnTW9kdWxlJyB9KTtcblx0fVxuXHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgJ19fZXNNb2R1bGUnLCB7IHZhbHVlOiB0cnVlIH0pO1xufTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLnAgPSBcIlwiOyIsIi8qKlxyXG4gKiBXZWJwYWNrIHdpbGwgcmVwbGFjZSBfX3dlYnBhY2tfcHVibGljX3BhdGhfXyB3aXRoIF9fd2VicGFja19yZXF1aXJlX18ucCB0byBzZXQgdGhlIHB1YmxpYyBwYXRoIGR5bmFtaWNhbGx5LlxyXG4gKiBUaGUgcmVhc29uIHdoeSB3ZSBjYW4ndCBzZXQgdGhlIHB1YmxpY1BhdGggaW4gd2VicGFjayBjb25maWcgaXM6IHdlIGNoYW5nZSB0aGUgcHVibGljUGF0aCB3aGVuIGRvd25sb2FkLlxyXG4gKiAqL1xyXG4vLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmVcclxuLy8gQHRzLWlnbm9yZVxyXG5fX3dlYnBhY2tfcHVibGljX3BhdGhfXyA9IHdpbmRvdy5qaW11Q29uZmlnLmJhc2VVcmxcclxuIiwiXHJcbmltcG9ydCB7IFJlYWN0LCBBbGxXaWRnZXRQcm9wcywgUmVhY3RSZWR1eCAgfSBmcm9tICdqaW11LWNvcmUnO1xyXG5pbXBvcnQgeyBCdXR0b24sIFxyXG4gIENoZWNrYm94LCBcclxuICBMYWJlbCB9IGZyb20gJ2ppbXUtdWknO1xyXG5pbXBvcnQge0NMU1NTZWFyY2hJbnB1dH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLXNlYXJjaC10ZW1wbGF0ZSc7XHJcbmltcG9ydCB7IFRlbXBsYXRlQnV0dG9uIH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLXRlbXBsYXRlLWJ1dHRvbic7XHJcbmltcG9ydCBDbHNzTG9hZGluZyBmcm9tICcuLi8uLi8uLi9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtbG9hZGluZyc7XHJcbmltcG9ydCB7IENMU1NBY3Rpb25LZXlzIH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jbHNzLXN0b3JlJztcclxuaW1wb3J0IHsgZGlzcGF0Y2hBY3Rpb24sIFxyXG4gIGdldEhhemFyZHMsIFxyXG4gIGdldE9yZ2FuaXphdGlvbnMsIFxyXG4gIGdldFRlbXBsYXRlcywgXHJcbiAgaW5pdGlhbGl6ZUF1dGh9IGZyb20gJy4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXBpJztcclxuaW1wb3J0IHsgQ0xTU1RlbXBsYXRlLCBDTFNTX1N0YXRlLCBDbHNzVXNlciwgSGF6YXJkLCBPcmdhbml6YXRpb24gfSBmcm9tICcuLi8uLi8uLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2RhdGEtZGVmaW5pdGlvbnMnO1xyXG5pbXBvcnQgeyBDTFNTX0FETUlOLCBDTFNTX0VESVRPUiwgQ0xTU19GT0xMT1dFUlMsIERFRkFVTFRfTElTVElURU0gfSBmcm9tICcuLi8uLi8uLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2NvbnN0YW50cyc7XHJcbmltcG9ydCB7IEFkZFRlbXBsYXRlV2lkZ2V0IH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWFkZC10ZW1wbGF0ZSc7XHJcbmltcG9ydCB7IEFkZE9yZ2FuaXphdG9uV2lkZ2V0IH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWFkZC1vcmdhbml6YXRpb24nO1xyXG5pbXBvcnQgeyBBZGRIYXphcmRXaWRnZXQgfSBmcm9tICcuLi8uLi8uLi9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtYWRkLWhhemFyZCc7XHJcbmltcG9ydCB7IElNQ29uZmlnIH0gZnJvbSAnLi4vY29uZmlnJztcclxuaW1wb3J0IHsgcGFyc2VEYXRlLCBzb3J0T2JqZWN0IH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy91dGlscyc7XHJcbmNvbnN0IHsgdXNlU2VsZWN0b3IgfSA9IFJlYWN0UmVkdXg7XHJcblxyXG5jb25zdCBXaWRnZXQgPSAocHJvcHM6IEFsbFdpZGdldFByb3BzPElNQ29uZmlnPikgPT4ge1xyXG4gIFxyXG4gIGNvbnN0IFtsb2FkaW5nLCBzZXRMb2FkaW5nXSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKTtcclxuICBjb25zdCBbaXNBZGRUZW1wbGF0ZU1vZGFsVmlzaWJsZSwgc2V0QWRkVGVtcGxhdGVNb2RhbFZpc2liaWxpdHldID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpO1xyXG4gIGNvbnN0IFtpc0FkZE9yZ2FuaXphdGlvbk1vZGFsVmlzaWJsZSwgc2V0QWRkT3JnYW5pemF0aW9uTW9kYWxWaXNpYmlsaXR5XSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKTtcclxuICBjb25zdCBbaXNBZGRIYXphcmRNb2RhbFZpc2libGUsIHNldEFkZEhhemFyZE1vZGFsVmlzaWJpbGl0eV0gPSBSZWFjdC51c2VTdGF0ZShmYWxzZSk7XHJcbiAgY29uc3QgW3NlbGVjdGVkSGF6YXJkLCBzZXRTZWxlY3RlZEhhemFyZF09UmVhY3QudXNlU3RhdGU8SGF6YXJkPihudWxsKTtcclxuICBjb25zdCBbc2VsZWN0ZWRPcmdhbml6YXRpb24sIHNldFNlbGVjdGVkT3JnYW5pemF0aW9uXT1SZWFjdC51c2VTdGF0ZTxPcmdhbml6YXRpb24+KG51bGwpO1xyXG4gIGNvbnN0IFtzZWFyY2hSZXN1bHQsIHNldFNlYXJjaFJlc3VsdHNdID0gUmVhY3QudXNlU3RhdGU8Q0xTU1RlbXBsYXRlW10+KFtdKVxyXG4gIGNvbnN0IFtjb25maWcsIHNldENvbmZpZ10gPSBSZWFjdC51c2VTdGF0ZShudWxsKVxyXG4gIGNvbnN0W3NlbGVjdGVkRmlsdGVyLCBzZXRTZWxlY3RlZEZpbHRlcl0gPSBSZWFjdC51c2VTdGF0ZSgnQWxsJylcclxuICBjb25zdFtzZWFyY2hUZXh0LCBzZXRTZWFyY2hUZXh0XSA9IFJlYWN0LnVzZVN0YXRlKCcnKVxyXG5cclxuICBjb25zdCBzdGF0ZSA9ICB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4ge1xyXG4gICAgcmV0dXJuIHN0YXRlLmNsc3NTdGF0ZSBhcyBDTFNTX1N0YXRlO1xyXG4gIH0pXHJcblxyXG4gIGNvbnN0IHVzZXIgPSB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4ge1xyXG4gICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGU/LnVzZXIgYXMgQ2xzc1VzZXI7XHJcbiAgfSlcclxuXHJcbiAgY29uc3QgY3JlZGVudGlhbCA9IHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KSA9PiB7XHJcbiAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy5hdXRoZW50aWNhdGU7XHJcbiAgfSlcclxuXHJcbiAgY29uc3QgZXJyb3JzID0gdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGU/LmVycm9ycztcclxuICB9KVxyXG4gIFxyXG4gIGNvbnN0IHRlbXBsYXRlcyA9ICB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4ge1xyXG4gICAgcmV0dXJuIHN0YXRlLmNsc3NTdGF0ZT8udGVtcGxhdGVzIGFzIENMU1NUZW1wbGF0ZVtdO1xyXG4gIH0pXHJcblxyXG4gIGNvbnN0IGhhemFyZHMgPSAgdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGU/LmhhemFyZHMgYXMgSGF6YXJkW107XHJcbiAgfSlcclxuXHJcbiAgY29uc3Qgb3JnYW5pemF0aW9ucyA9ICB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4ge1xyXG4gICAgcmV0dXJuIHN0YXRlLmNsc3NTdGF0ZT8ub3JnYW5pemF0aW9ucyBhcyBPcmdhbml6YXRpb25bXTtcclxuICB9KVxyXG5cclxuICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgIGluaXRpYWxpemVBdXRoKHByb3BzLmNvbmZpZy5hcHBJZCk7XHJcbiAgfSwgW10pO1xyXG5cclxuICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgIGlmKGNvbmZpZyl7ICAgICAgXHJcbiAgICAgIGlmKCFoYXphcmRzIHx8IGhhemFyZHMubGVuZ3RoID09PSAwKXtcclxuICAgICAgICBjb25zdCBzdGFydCA9IG5ldyBEYXRlKCkuZ2V0VGltZSgpOyAgICAgIFxyXG4gICAgICAgIGdldEhhemFyZHMoY29uZmlnLCAnMT0xJywgJ2Nsc3MtdGVtcGxhdGVzJylcclxuICAgICAgICAudGhlbigoaGF6YXJkczogSGF6YXJkW10pID0+IHsgIFxyXG4gICAgICAgICAgICBpZihoYXphcmRzICYmIGhhemFyZHMubGVuZ3RoID4gMCl7XHJcbiAgICAgICAgICAgICAgKGhhemFyZHMgYXMgYW55KS5vcmRlckJ5KCduYW1lJylcclxuICAgICAgICAgICAgICBoYXphcmRzLnVuc2hpZnQoREVGQVVMVF9MSVNUSVRFTSlcclxuICAgICAgICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5MT0FEX0hBWkFSRFNfQUNUSU9OLCBoYXphcmRzKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBjb25zb2xlLmxvZygnSGF6YXJkcyB0b29rOiAnICsgKG5ldyBEYXRlKCkuZ2V0VGltZSgpIC0gc3RhcnQpICtcIiBtc1wiKVxyXG4gICAgICAgIH0pO1xyXG4gICAgICB9XHJcbiAgICB9XHJcbiAgfSwgW2NvbmZpZ10pXHJcblxyXG4gIFJlYWN0LnVzZUVmZmVjdCgoKT0+e1xyXG4gICAgaWYoY29uZmlnKXsgICAgXHJcbiAgICAgIGlmKCFvcmdhbml6YXRpb25zIHx8IG9yZ2FuaXphdGlvbnMubGVuZ3RoID09PSAwKSB7ICBcclxuICAgICAgICBjb25zdCBzdGFydCA9IG5ldyBEYXRlKCkuZ2V0VGltZSgpO1xyXG4gICAgICAgICBnZXRPcmdhbml6YXRpb25zKGNvbmZpZywgJzE9MScpXHJcbiAgICAgICAgICAudGhlbigob3JnYW5pemF0aW9uczogT3JnYW5pemF0aW9uW10pID0+IHtcclxuICAgICAgICAgICAgaWYob3JnYW5pemF0aW9ucyAmJiBvcmdhbml6YXRpb25zLmxlbmd0aCA+IDApe1xyXG4gICAgICAgICAgICAgIChvcmdhbml6YXRpb25zIGFzIGFueSkub3JkZXJCeSgnbmFtZScpO1xyXG4gICAgICAgICAgICAgIG9yZ2FuaXphdGlvbnMudW5zaGlmdChERUZBVUxUX0xJU1RJVEVNKTtcclxuICAgICAgICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5MT0FEX09SR0FOSVpBVElPTlNfQUNUSU9OLCBvcmdhbml6YXRpb25zKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBjb25zb2xlLmxvZygnT3JnYW5pemF0aW9ucyB0b29rOiAnKyhuZXcgRGF0ZSgpLmdldFRpbWUoKSAtIHN0YXJ0KStcIiBtc1wiKVxyXG4gICAgICAgICAgfSlcclxuICAgICAgfVxyXG4gICAgfVxyXG4gIH0sIFtjb25maWddKVxyXG5cclxuICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgIGlmKGNyZWRlbnRpYWwpeyBcclxuICAgICAgIHNldENvbmZpZyh7Li4uIHByb3BzLmNvbmZpZywgY3JlZGVudGlhbDpjcmVkZW50aWFsfSkgICAgICAgXHJcbiAgICB9XHJcbiAgfSwgW2NyZWRlbnRpYWxdKSBcclxuICBcclxuICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgaWYoY29uZmlnKXsgICAgIFxyXG4gICAgICBsb2FkVGVtcGxhdGVzKCk7XHJcbiAgIH1cclxuICB9LCBbY29uZmlnXSkgXHJcblxyXG4gIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICBpZihlcnJvcnMpe1xyXG4gICAgICBhbGVydChlcnJvcnMpO1xyXG4gICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCAnJylcclxuICAgIH1cclxuICB9LCBbZXJyb3JzXSlcclxuXHJcbiAgUmVhY3QudXNlRWZmZWN0KCgpPT4ge1xyXG4gICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX1VTRVJfQUNUSU9OLFxyXG4gICAgICB7XHJcbiAgICAgICAgdXNlck5hbWU6IHByb3BzLnVzZXI/LnVzZXJuYW1lLFxyXG4gICAgICAgIGZpcnN0TmFtZTogcHJvcHMudXNlcj8uZmlyc3ROYW1lLFxyXG4gICAgICAgIGxhc3ROYW1lOnByb3BzLnVzZXI/Lmxhc3ROYW1lLFxyXG4gICAgICAgIGdyb3VwczogcHJvcHMudXNlcj8uZ3JvdXBzPy5tYXAoZyA9PiBnLnRpdGxlKVxyXG4gICAgICB9IFxyXG4gICAgKVxyXG4gIH0sIFtwcm9wcy51c2VyXSk7XHJcbiAgXHJcbiAgUmVhY3QudXNlRWZmZWN0KCgpID0+e1xyXG4gICAgaWYodGVtcGxhdGVzICYmIHRlbXBsYXRlcy5sZW5ndGggPiAwKXtcclxuICAgICAgZmlsdGVyU2VsZWN0aW9uQ2hhbmdlKHNlbGVjdGVkRmlsdGVyLCB0ZW1wbGF0ZXMpO1xyXG4gICAgfSAgICAgICBcclxuICB9LFt0ZW1wbGF0ZXNdKVxyXG4gXHJcbiAgY29uc3QgbG9hZFRlbXBsYXRlcz1hc3luYyAoKT0+eyAgICAgXHJcbiAgICBzZXRMb2FkaW5nKHRydWUpOyAgIFxyXG4gICAgXHJcbiAgICBjb25zdCBzdGFydCA9IG5ldyBEYXRlKCkuZ2V0VGltZSgpO1xyXG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBnZXRUZW1wbGF0ZXMoY29uZmlnLCBudWxsLCBudWxsKTsgICAgIFxyXG4gICAgY29uc29sZS5sb2coJ1RlbXBsYXRlcyBUb29rJywgbmV3IERhdGUoKS5nZXRUaW1lKCkgLSBzdGFydCk7XHJcbiAgICBzZXRMb2FkaW5nKGZhbHNlKVxyXG5cclxuICAgIGlmKHJlc3BvbnNlLmVycm9ycyl7XHJcbiAgICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlMsIHJlc3BvbnNlLmVycm9ycyk7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH0gICAgICBcclxuICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLkxPQURfVEVNUExBVEVTX0FDVElPTiwgcmVzcG9uc2UuZGF0YSk7XHJcbiAgICBhd2FpdCBmaWx0ZXJTZWxlY3Rpb25DaGFuZ2Uoc2VsZWN0ZWRGaWx0ZXIsIHJlc3BvbnNlLmRhdGEpO1xyXG4gIH1cclxuXHJcbiAgY29uc3QgcGVyZm9ybVNlYXJjaCA9KHRleHQ6IHN0cmluZyk9PntcclxuXHJcbiAgICBzZXRTZWFyY2hUZXh0KHRleHQpO1xyXG5cclxuICAgIGxldCBjb3BpZWRUZW1wbGF0ZXMgPSBbLi4udGVtcGxhdGVzXTtcclxuXHJcbiAgICBpZighdGV4dCB8fCB0ZXh0ID09PSAnJyB8fCB0ZXh0ID09PSBudWxsKXtcclxuICAgICAgcmV0dXJuIHNvcnRPYmplY3QoY29waWVkVGVtcGxhdGVzLCAnY3JlYXRlZERhdGUnKTtcclxuICAgIH0gICAgXHJcbiAgICBsZXQgc2VhcmNoUmVzdWx0cyA9IGNvcGllZFRlbXBsYXRlcy5maWx0ZXIodCA9PiBcclxuICAgICAgdC5uYW1lPy50b0xvY2FsZUxvd2VyQ2FzZSgpLmluY2x1ZGVzKHRleHQudG9Mb2NhbGVMb3dlckNhc2UoKSkgfHxcclxuICAgICAgdC5vcmdhbml6YXRpb25OYW1lPy50b0xvY2FsZUxvd2VyQ2FzZSgpLmluY2x1ZGVzKHRleHQudG9Mb2NhbGVMb3dlckNhc2UoKSkgfHxcclxuICAgICAgdC5oYXphcmROYW1lPy50b0xvY2FsZUxvd2VyQ2FzZSgpLmluY2x1ZGVzKHRleHQudG9Mb2NhbGVMb3dlckNhc2UoKSkgfHxcclxuICAgICAgdC5oYXphcmRUeXBlPy50b0xvY2FsZUxvd2VyQ2FzZSgpLmluY2x1ZGVzKHRleHQudG9Mb2NhbGVMb3dlckNhc2UoKSkgfHxcclxuICAgICAgcGFyc2VEYXRlKHQuY3JlYXRlZERhdGUpPy5zcGxpdCgnLCcpWzBdLnRyaW0oKSA9PSB0ZXh0IHx8XHJcbiAgICAgIHBhcnNlRGF0ZSh0LmNyZWF0ZWREYXRlKT8uaW5jbHVkZXModGV4dCkgfHwgXHJcbiAgICAgIHBhcnNlRGF0ZSh0LmVkaXRlZERhdGUpPy5pbmNsdWRlcyh0ZXh0KSB8fFxyXG4gICAgICBwYXJzZURhdGUodC5lZGl0ZWREYXRlKT8uc3BsaXQoJywnKVswXS50cmltKCkgPT0gdGV4dCk7XHJcblxyXG4gICAgICByZXR1cm4gc29ydE9iamVjdChzZWFyY2hSZXN1bHRzLCAnY3JlYXRlZERhdGUnKTtcclxuICB9XHJcblxyXG4gIGNvbnN0IG9uU2VhcmNoVGVtcGxhdGVzPSh0ZXh0OiBzdHJpbmcpPT57ICAgICBcclxuICAgIGZpbHRlclNlbGVjdGlvbkNoYW5nZShzZWxlY3RlZEZpbHRlciwgcGVyZm9ybVNlYXJjaCh0ZXh0KSk7XHJcbiAgfVxyXG5cclxuICBjb25zdCBvblNlbGVjdFRlbXBsYXRlPWFzeW5jIChvYmplY3RJZDogbnVtYmVyKT0+eyBcclxuICAgIFxyXG4gICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuTE9BRF9URU1QTEFURVNfQUNUSU9OLCB0ZW1wbGF0ZXMubWFwKHQgPT4ge1xyXG4gICAgICByZXR1cm57XHJcbiAgICAgICAgLi4udCwgXHJcbiAgICAgICAgaXNTZWxlY3RlZDogdC5vYmplY3RJZCA9PT0gb2JqZWN0SWRcclxuICAgICAgfVxyXG4gICAgfSkpICAgIFxyXG5cclxuICAgIGlmKHRlbXBsYXRlcy5maW5kKHQgPT4gdC5vYmplY3RJZCA9PT0gb2JqZWN0SWQpLnN0YXR1cy5jb2RlICE9PSAxKXtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG4gICAgLy9hd2FpdCBzZWxlY3RUZW1wbGF0ZShvYmplY3RJZCwgdGVtcGxhdGVzLm1hcCh0ID0+IHQub2JqZWN0SWQpLCBjb25maWcpOyBcclxuICB9IFxyXG5cclxuICBjb25zdCBvbkFyY2hpdmVUZW1wbGF0ZT1hc3luYyAob2JqZWN0SWQ6IG51bWJlcik9PntcclxuICAgIC8vIHNldExvYWRpbmcodHJ1ZSk7XHJcblxyXG4gICAgLy8gY29uc3QgcmVzID0gYXdhaXQgYXJjaGl2ZVRlbXBsYXRlKG9iamVjdElkLCBwcm9wcy5jb25maWcpO1xyXG4gICAgLy8gaWYoIXJlcy5lcnJvcnMgJiYgcmVzLmRhdGEpe1xyXG4gICAgLy8gICBhd2FpdCBsb2FkVGVtcGxhdGVzKCk7XHJcbiAgICAvLyB9ICBcclxuICAgIC8vIHNldExvYWRpbmcoZmFsc2UpO1xyXG4gIH1cclxuXHJcbiAgY29uc3Qgc2F2ZVRlbXBsYXRlID1hc3luYyAoKT0+e1xyXG4gICAgYXdhaXQgbG9hZFRlbXBsYXRlcygpO1xyXG4gICAgc2V0QWRkVGVtcGxhdGVNb2RhbFZpc2liaWxpdHkoZmFsc2UpO1xyXG4gIH1cclxuXHJcbiAgY29uc3Qgc2VsZWN0RmlsdGVyID0oaWQ6IHN0cmluZyk9PiB7ICAgIFxyXG4gICAgZmlsdGVyU2VsZWN0aW9uQ2hhbmdlKGlkLCAgcGVyZm9ybVNlYXJjaChzZWFyY2hUZXh0KSk7XHJcbiAgfVxyXG5cclxuICBjb25zdCBmaWx0ZXJTZWxlY3Rpb25DaGFuZ2UgPWFzeW5jIChpZCwgX3RlbXBsYXRlcyk9PntcclxuICAgICBpZihfdGVtcGxhdGVzID09IG51bGwpe1xyXG4gICAgICByZXR1cm47XHJcbiAgICAgfSAgICAgXHJcblxyXG4gICAgIHNldFNlbGVjdGVkRmlsdGVyKGlkKTtcclxuXHJcbiAgICAgc3dpdGNoKGlkKXtcclxuICAgICAgY2FzZSAnQWxsJzpcclxuICAgICAgICBzZXRTZWFyY2hSZXN1bHRzKFsuLi5fdGVtcGxhdGVzXSlcclxuICAgICAgICBicmVhaztcclxuICAgICAgY2FzZSAnU2VsZWN0ZWQnOlxyXG4gICAgICAgIHNldFNlYXJjaFJlc3VsdHMoX3RlbXBsYXRlcy5maWx0ZXIodCA9PiB0LmlzU2VsZWN0ZWQpKVxyXG4gICAgICAgIGJyZWFrO1xyXG4gICAgICBjYXNlICdBY3RpdmUnOiAgICAgXHJcbiAgICAgIHNldFNlYXJjaFJlc3VsdHMoX3RlbXBsYXRlcy5maWx0ZXIodCA9PiB0LnN0YXR1cy5jb2RlID09PSAxKSlcclxuICAgICAgICBicmVhaztcclxuICAgICAgY2FzZSAnQXJjaGl2ZWQnOlxyXG4gICAgICAgIHNldFNlYXJjaFJlc3VsdHMoX3RlbXBsYXRlcy5maWx0ZXIodCA9PiB0LnN0YXR1cy5jb2RlID09PSAwKSlcclxuICAgICAgICBicmVhaztcclxuICAgICB9XHJcbiAgfVxyXG4gXHJcbiAgcmV0dXJuIChcclxuICAgIDxkaXYgY2xhc3NOYW1lPVwid2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciBqaW11LXdpZGdldFwiXHJcbiAgICAgIHN0eWxlPXt7XHJcbiAgICAgICAgYmFja2dyb3VuZENvbG9yOiBwcm9wcy50aGVtZS5zdXJmYWNlc1syXS5iZ1xyXG4gICAgICB9fT5cclxuICAgICAgPHN0eWxlPlxyXG4gICAgICAgIHtgXHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lcnsgICAgICAgXHJcbiAgICAgICAgICAgIG92ZXJmbG93OiBoaWRkZW47IFxyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLnNlYXJjaC10ZW1wbGF0ZXN7XHJcbiAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgZmxleDogMTtcclxuICAgICAgICAgICAgICBwYWRkaW5nLWJvdHRvbTogMTBweDtcclxuICAgICAgICAgICAgICBvdmVyZmxvdy15OiBhdXRvO1xyXG4gICAgICAgICAgICAgIG92ZXJmbG93LXg6IGhpZGRlbjtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC5jbHNzLXRlbXBsYXRlcy1oZWFkZXJ7XHJcbiAgICAgICAgICAgIGhlaWdodDogNTBweDtcclxuICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7XHJcbiAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7ICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAudGVtcGxhdGUtYnV0dG9ucy1jb250ZW50e1xyXG4gICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uO1xyXG4gICAgICAgICAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47XHJcbiAgICAgICAgICAgIHBhZGRpbmc6IDIwcHggMTBweDtcclxuICAgICAgICAgICAgaGVpZ2h0OiBjYWxjKDEwMCUgLSA1MHB4KTtcclxuICAgICAgICAgICAgXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAuY3JlYXRlLWFzc2Vzc21lbnQtYnV0dG9ueyAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICBoZWlnaHQ6IDY1cHg7XHJcbiAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICBmb250LXdlaWdodDogYm9sZDtcclxuICAgICAgICAgICAgZm9udC1zaXplOiAxLjVlbTtcclxuICAgICAgICAgICAgYm9yZGVyLXJhZGl1czogNXB4O1xyXG4gICAgICAgICAgICBsaW5lLWhlaWdodDogMS41ZW07XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAuY3JlYXRlLWFzc2Vzc21lbnQtYnV0dG9uOmhvdmVye1xyXG4gICAgICAgICAgICAgIG9wYWNpdHk6IDAuOFxyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLmNyZWF0ZS1uZXctdGVtcGxhdGV7XHJcbiAgICAgICAgICAgIGhlaWdodDogNTBweDtcclxuICAgICAgICAgICAgZm9udC13ZWlnaHQ6IGJvbGQ7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAuY3JlYXRlLW5ldy10ZW1wbGF0ZTpob3ZlcntcclxuICAgICAgICAgICAgb3BhY2l0eTogLjhcclxuICAgICAgICAgIH0gICAgICAgICAgXHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciAuZWRpdG9yLWljb257ICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgY29sb3I6ICM1MzRjNGM7XHJcbiAgICAgICAgICAgIGN1cnNvcjogcG9pbnRlcjtcclxuICAgICAgICAgICAgbWFyZ2luOiAxMHB4O1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLndpZGdldC1jbHNzLXRlbXBsYXRlcy1jb250YWluZXIgLmVkaXRvci1pY29uOmhvdmVye1xyXG4gICAgICAgICAgICBvcGFjaXR5OiAuOFxyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLndpZGdldC1jbHNzLXRlbXBsYXRlcy1jb250YWluZXIgLnNhdmUtY2FuY2VsLCBcclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIC5zYXZlLWljb257XHJcbiAgICAgICAgICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTtcclxuICAgICAgICAgICAgcmlnaHQ6IDEwcHg7XHJcbiAgICAgICAgICAgIHRvcDogMTBweDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIC5kYXRhLWRyb3Bkb3duLCBcclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIC5kYXRhLWlucHV0e1xyXG4gICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIC5kYXRhLWRyb3Bkb3duIFxyXG4gICAgICAgICAgLndpZGdldC1jbHNzLXRlbXBsYXRlcy1jb250YWluZXIgLmppbXUtZHJvcGRvd257XHJcbiAgICAgICAgICAgIHdpZHRoOiAzMDBweDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIC5kYXRhLWRyb3Bkb3duLW1lbnV7XHJcbiAgICAgICAgICAgIHdpZHRoOiAzMDBweDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIC5lcnJvcntcclxuICAgICAgICAgICAgY29sb3I6IHJlZDtcclxuICAgICAgICAgICAgZm9udC1zaXplOiAxNXB4O1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLndpZGdldC1jbHNzLXRlbXBsYXRlcy1jb250YWluZXIgLmRyb3Bkb3duLWl0ZW17XHJcbiAgICAgICAgICAgICAgZm9udC1zaXplOiAxLjNlbTtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIC5vcmdhbml6YXRpb257XHJcbiAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciAuZW5kLXdpZGdldHtcclxuICAgICAgICAgICAgbWFyZ2luLWJvdHRvbTogMTVweDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIC5kYXRhLWlucHV0e1xyXG4gICAgICAgICAgICB3aWR0aDogMzAuNyVcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIC50aXRsZS50ZW1wbGF0ZXtcclxuICAgICAgICAgICAgd2lkdGg6IDE0MnB4O1xyXG4gICAgICAgICAgfVxyXG5cclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIHRkIGxhYmVsLCBcclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIHRkIGlucHV0eyBcclxuICAgICAgICAgICAgZm9udC1zaXplOiAxLjVlbTtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIHRkIGxhYmVse1xyXG4gICAgICAgICAgICB3aWR0aDogMTI4cHg7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciB0ZCBsYWJlbC52YWx1ZXtcclxuICAgICAgICAgICAgZm9udC13ZWlnaHQ6IGJvbGQ7XHJcbiAgICAgICAgICAgIHdpZHRoOiBhdXRvO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLndpZGdldC1jbHNzLXRlbXBsYXRlcy1jb250YWluZXIgdHIudGQtdW5kZXI+dGR7XHJcbiAgICAgICAgICAgIHBhZGRpbmctYm90dG9tOiAxZW07XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciAgLnRlbXBsYXRlLWlucHV0IGlucHV0e1xyXG4gICAgICAgICAgICBwYWRkaW5nLWxlZnQ6IDIwcHg7XHJcbiAgICAgICAgICAgIGhlaWdodDogNDBweDtcclxuICAgICAgICAgICAgZm9udC1zaXplOiAxNnB4O1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLndpZGdldC1jbHNzLXRlbXBsYXRlcy1jb250YWluZXIgIC50ZW1wbGF0ZS1pbnB1dCBzcGFue1xyXG4gICAgICAgICAgICBoZWlnaHQ6IDQwcHggIWltcG9ydGFudDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC50ZW1wbGF0ZS1maWx0ZXItYWN0aW9ucyAuYWN0aW9uc3tcclxuICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1hcm91bmQ7XHJcbiAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAudGVtcGxhdGUtZmlsdGVyLWFjdGlvbnMgLmppbXUtY2hlY2tib3h7XHJcbiAgICAgICAgICAgIG1hcmdpbi1yaWdodDogMTBweDtcclxuICAgICAgICAgIH1cclxuICAgICAgICBgfVxyXG4gICAgICA8L3N0eWxlPiAgICAgICBcclxuICAgICAgPGRpdiBjbGFzc05hbWU9XCJjbHNzLXRlbXBsYXRlcy1oZWFkZXJcIiBzdHlsZT17e1xyXG4gICAgICAgICAgYmFja2dyb3VuZENvbG9yOiBwcm9wcy5jb25maWcuaGVhZGVyQmFja2dyb3VuZENvbG9yIHx8IHByb3BzLnRoZW1lLmNvbG9ycy5zZWNvbmRhcnksXHJcbiAgICAgICAgICBjb2xvcjogcHJvcHMuY29uZmlnLmhlYWRlclRleHRDb2xvciB8fCBwcm9wcy50aGVtZS5jb2xvcnMucGFsZXR0ZS5wcmltYXJ5WzkwMF0sXHJcbiAgICAgICAgICBib3hTaGFkb3c6IHByb3BzLnRoZW1lLmJveFNoYWRvd3MuZGVmYXVsdCxcclxuICAgICAgICAgIGZvbnRTaXplOiBwcm9wcy50aGVtZS50eXBvZ3JhcGh5LnNpemVzLmRpc3BsYXkzLFxyXG4gICAgICAgICAgZm9udFdlaWdodDogcHJvcHMudGhlbWUudHlwb2dyYXBoeS53ZWlnaHRzLmJvbGRcclxuICAgICAgICB9fT5cclxuICAgICAgICA8TGFiZWwgY2hlY2s+XHJcbiAgICAgICAgICAgIFRlbXBsYXRlc1xyXG4gICAgICAgIDwvTGFiZWw+XHJcbiAgICAgIDwvZGl2PlxyXG4gICAgICA8ZGl2IGNsYXNzTmFtZT0ndGVtcGxhdGUtYnV0dG9ucy1jb250ZW50Jz4gXHJcbiAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJ0ZW1wbGF0ZS1maWx0ZXItYWN0aW9uc1wiPlxyXG4gICAgICAgICAgICA8aDQ+XHJcbiAgICAgICAgICAgICAgRmlsdGVyIHRlbXBsYXRlcyBieTpcclxuICAgICAgICAgICAgPC9oND5cclxuICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJhY3Rpb25zXCIgYXJpYS1sYWJlbD1cIkZpbHRlciB0ZW1wbGF0ZXMgYnlcIiAgcm9sZT1cImdyb3VwXCI+XHJcbiAgICAgICAgICAgICAgey8qIDxMYWJlbCBjZW50cmljID5cclxuICAgICAgICAgICAgICAgIDxDaGVja2JveFxyXG4gICAgICAgICAgICAgICAgICBpZD0gJ1NlbGVjdGVkJ1xyXG4gICAgICAgICAgICAgICAgICBhcmlhLWxhYmVsPVwiQ2hlY2tib3hcIlxyXG4gICAgICAgICAgICAgICAgICBjaGVja2VkPXtzZWxlY3RlZEZpbHRlciA9PT0gJ1NlbGVjdGVkJ31cclxuICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhlKT0+IGZpbHRlclNlbGVjdGlvbkNoYW5nZShlLnRhcmdldC5pZCwgdGVtcGxhdGVzKX1cclxuICAgICAgICAgICAgICAgIC8+XHJcbiAgICAgICAgICAgICAgICBTZWxlY3RlZFxyXG4gICAgICAgICAgICAgIDwvTGFiZWw+ICovfVxyXG5cclxuICAgICAgICAgICAgICA8TGFiZWwgY2VudHJpYyA+XHJcbiAgICAgICAgICAgICAgICA8Q2hlY2tib3hcclxuICAgICAgICAgICAgICAgICAgaWQ9ICdBbGwnXHJcbiAgICAgICAgICAgICAgICAgIGFyaWEtbGFiZWw9XCJDaGVja2JveFwiXHJcbiAgICAgICAgICAgICAgICAgIGNoZWNrZWQ9e3NlbGVjdGVkRmlsdGVyID09PSAnQWxsJ31cclxuICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhlKT0+IHNlbGVjdEZpbHRlcihlLnRhcmdldC5pZCl9XHJcbiAgICAgICAgICAgICAgICAvPlxyXG4gICAgICAgICAgICAgICAgQWxsXHJcbiAgICAgICAgICAgICAgPC9MYWJlbD5cclxuXHJcbiAgICAgICAgICAgICAgPExhYmVsIGNlbnRyaWM+XHJcbiAgICAgICAgICAgICAgICA8Q2hlY2tib3hcclxuICAgICAgICAgICAgICAgICAgaWQ9J0FjdGl2ZSdcclxuICAgICAgICAgICAgICAgICAgYXJpYS1sYWJlbD1cIkNoZWNrYm94XCJcclxuICAgICAgICAgICAgICAgICAgY2hlY2tlZD17c2VsZWN0ZWRGaWx0ZXIgPT09ICdBY3RpdmUnfVxyXG4gICAgICAgICAgICAgICAgICBvbkNoYW5nZT17KGUpPT4gc2VsZWN0RmlsdGVyKGUudGFyZ2V0LmlkKX1cclxuICAgICAgICAgICAgICAgIC8+XHJcbiAgICAgICAgICAgICAgICBBY3RpdmVcclxuICAgICAgICAgICAgICA8L0xhYmVsPlxyXG4gICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgIDxMYWJlbCBjZW50cmljIGNoZWNrPlxyXG4gICAgICAgICAgICAgICAgPENoZWNrYm94XHJcbiAgICAgICAgICAgICAgICAgIGlkPSdBcmNoaXZlZCdcclxuICAgICAgICAgICAgICAgICAgYXJpYS1sYWJlbD1cIkNoZWNrYm94XCJcclxuICAgICAgICAgICAgICAgICAgY2hlY2tlZD17c2VsZWN0ZWRGaWx0ZXIgPT09ICdBcmNoaXZlZCd9XHJcbiAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsoZSk9PiBzZWxlY3RGaWx0ZXIoZS50YXJnZXQuaWQpfVxyXG4gICAgICAgICAgICAgICAgLz5cclxuICAgICAgICAgICAgICAgIEFyY2hpdmVkXHJcbiAgICAgICAgICAgICAgPC9MYWJlbD5cclxuICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgPC9kaXY+ICAgXHJcbiAgICAgICAgPGRpdiBjbGFzc05hbWU9J3NlYXJjaC10ZW1wbGF0ZXMnPlxyXG4gICAgICAgICAgPENMU1NTZWFyY2hJbnB1dCB0aXRsZT17J1NlYXJjaCBUZW1wbGF0ZXMnfSBcclxuICAgICAgICAgICAgb25DaGFuZ2U9e29uU2VhcmNoVGVtcGxhdGVzfSBwcm9wcz17cHJvcHN9Lz4gICAgXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICBzZWFyY2hSZXN1bHQ/Lm1hcCgodGVtcDogQ0xTU1RlbXBsYXRlKSA9PiB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gKFxyXG4gICAgICAgICAgICAgICAgICA8VGVtcGxhdGVCdXR0b24ga2V5PXt0ZW1wLmlkfSBwcm9wcz17cHJvcHN9XHJcbiAgICAgICAgICAgICAgICAgICAgdGVtcGxhdGU9e3RlbXB9IFxyXG4gICAgICAgICAgICAgICAgICAgIG9uQ2xpY2s9eygpID0+IG9uU2VsZWN0VGVtcGxhdGUodGVtcC5vYmplY3RJZCl9IFxyXG4gICAgICAgICAgICAgICAgICAgIG9uRGJsQ2xpY2s9e29uQXJjaGl2ZVRlbXBsYXRlfS8+XHJcbiAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgICAgfSlcclxuICAgICAgICAgICAgfSAgXHJcbiAgICAgICAgPC9kaXY+ICAgICAgICAgICBcclxuICAgICAgICB7XHJcbiAgICAgICAgICAodXNlciAmJiB1c2VyLmdyb3Vwcz8uaW5jbHVkZXMoQ0xTU19BRE1JTikgfHxcclxuICAgICAgICAgICAgdXNlciAmJiB1c2VyLmdyb3Vwcz8uaW5jbHVkZXMoQ0xTU19FRElUT1IpIHx8XHJcbiAgICAgICAgICAgIHVzZXIgJiYgdXNlci5ncm91cHM/LmluY2x1ZGVzKENMU1NfRk9MTE9XRVJTKSkgP1xyXG4gICAgICAgICAgKCA8QnV0dG9uIGRhdGEtdGVzdGlkPVwiYnRuQ3JlYXRlTmV3VGVtcGxhdGVcIiBcclxuICAgICAgICAgIGNsYXNzTmFtZT0nY3JlYXRlLW5ldy10ZW1wbGF0ZScgXHJcbiAgICAgICAgICBzdHlsZT17e2JhY2tncm91bmQ6IHByb3BzLmNvbmZpZy5oZWFkZXJCYWNrZ3JvdW5kQ29sb3J9fSBcclxuICAgICAgICAgIHNpemU9J2xnJyBvbkNsaWNrPXsoKSA9PiBzZXRBZGRUZW1wbGF0ZU1vZGFsVmlzaWJpbGl0eSh0cnVlKX0+Q3JlYXRlIFRlbXBsYXRlPC9CdXR0b24+XHJcbiAgICAgICAgICApOiBudWxsXHJcbiAgICAgICAgfSAgXHJcbiAgICAgICAgPEFkZFRlbXBsYXRlV2lkZ2V0ICAgICAgICAgIFxyXG4gICAgICAgICAgY29uZmlnPXtjb25maWd9XHJcbiAgICAgICAgICBoYXphcmRzPXtoYXphcmRzfVxyXG4gICAgICAgICAgc2VsZWN0ZWRIYXphcmQ9e3NlbGVjdGVkSGF6YXJkfVxyXG4gICAgICAgICAgc2V0SGF6YXJkPXtzZXRTZWxlY3RlZEhhemFyZH1cclxuICAgICAgICAgIHNlbGVjdGVkT3JnYW5pemF0aW9uPXtzZWxlY3RlZE9yZ2FuaXphdGlvbn1cclxuICAgICAgICAgIG9yZ2FuaXphdGlvbnM9e29yZ2FuaXphdGlvbnN9XHJcbiAgICAgICAgICBzZXRPcmdhbml6YXRpb249e3NldFNlbGVjdGVkT3JnYW5pemF0aW9ufVxyXG4gICAgICAgICAgdGVtcGxhdGVzPXt0ZW1wbGF0ZXN9XHJcbiAgICAgICAgICB1c2VyPXt1c2VyfSAgICAgICAgICBcclxuICAgICAgICAgIHZpc2libGU9e2lzQWRkVGVtcGxhdGVNb2RhbFZpc2libGV9XHJcbiAgICAgICAgICB0b2dnbGVWaXNpYmlsaXR5PXtzZXRBZGRUZW1wbGF0ZU1vZGFsVmlzaWJpbGl0eX1cclxuICAgICAgICAgIHNhdmVUZW1wbGF0ZUNvbXBsZXRlQ2FsbGJhY2s9e3NhdmVUZW1wbGF0ZX1cclxuICAgICAgICAgIHRvZ2dsZU5ld0hhemFyZE1vZGFsPXtzZXRBZGRIYXphcmRNb2RhbFZpc2liaWxpdHl9XHJcbiAgICAgICAgICB0b2dnbGVOZXdPcmdhbml6YXRpb25Nb2RhbD17c2V0QWRkT3JnYW5pemF0aW9uTW9kYWxWaXNpYmlsaXR5fS8+IFxyXG5cclxuICAgICAgICA8QWRkT3JnYW5pemF0b25XaWRnZXQgXHJcbiAgICAgICAgICBwcm9wc0NvbmZpZz17cHJvcHM/LmNvbmZpZ31cclxuICAgICAgICAgIHZpc2libGU9e2lzQWRkT3JnYW5pemF0aW9uTW9kYWxWaXNpYmxlfVxyXG4gICAgICAgICAgc2V0T3JnYW5pemF0aW9uPXtzZXRTZWxlY3RlZE9yZ2FuaXphdGlvbn1cclxuICAgICAgICAgIHRvZ2dsZT17c2V0QWRkT3JnYW5pemF0aW9uTW9kYWxWaXNpYmlsaXR5fS8+IFxyXG5cclxuICAgICAgICA8QWRkSGF6YXJkV2lkZ2V0IFxyXG4gICAgICAgICAgcHJvcHM9e3Byb3BzfVxyXG4gICAgICAgICAgdmlzaWJsZT17aXNBZGRIYXphcmRNb2RhbFZpc2libGV9XHJcbiAgICAgICAgICBzZXRIYXphcmQ9e3NldFNlbGVjdGVkSGF6YXJkfVxyXG4gICAgICAgICAgdG9nZ2xlPXtzZXRBZGRIYXphcmRNb2RhbFZpc2liaWxpdHl9Lz5cclxuICAgICAgPC9kaXY+IFxyXG4gICAgICB7XHJcbiAgICAgICAgbG9hZGluZyA/IDxDbHNzTG9hZGluZy8+OiBudWxsXHJcbiAgICAgIH0gICAgXHJcbiAgICA8L2Rpdj5cclxuICApXHJcbn1cclxuZXhwb3J0IGRlZmF1bHQgV2lkZ2V0XHJcblxyXG5cclxuIl0sIm5hbWVzIjpbXSwic291cmNlUm9vdCI6IiJ9