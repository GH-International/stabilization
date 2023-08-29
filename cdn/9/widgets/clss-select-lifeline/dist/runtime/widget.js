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
/* harmony export */   "ANALYSIS_REPORTING_URL": () => (/* binding */ ANALYSIS_REPORTING_URL),
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
/* harmony export */   "DATA_LIBRARY_URL": () => (/* binding */ DATA_LIBRARY_URL),
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
const DATA_LIBRARY_URL = 'https://experience.arcgis.com/experience/f961191cd2514abf8e43486c6ffbf18b';
const ANALYSIS_REPORTING_URL = 'https://experience.arcgis.com/experience/8a760a7391254530b2cc9c9952e7aadd';


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
function useWindowSize() {
    const [size, setSize] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState([0, 0]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useLayoutEffect(() => {
        function updateSize() {
            setSize([window.innerWidth, window.innerHeight]);
        }
        window.addEventListener('resize', updateSize);
        updateSize();
        return () => window.removeEventListener('resize', updateSize);
    }, []);
    return size;
}
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
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { check: true, className: 'lifelines-header', style: { backgroundColor: props.config.backgroundColor,
                    color: props.config.fontColor, borderTop: '1px solid white' } }, "Lifelines"), lifelineStatuses === null || lifelineStatuses === void 0 ? void 0 :
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2lkZ2V0cy9jbHNzLXNlbGVjdC1saWZlbGluZS9kaXN0L3J1bnRpbWUvd2lkZ2V0LmpzIiwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQ0E7QUFDaUM7QUFDcUY7QUFDckU7QUFDTjtBQUN5QjtBQUNWO0FBQzFEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFlBQVksY0FBYztBQUMxQjtBQUNBO0FBQ0E7QUFDQTtBQUNBLElBQUk7QUFDSjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsSUFBSTtBQUNKO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGNBQWMsbUVBQVE7QUFDdEI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBLGtCQUFrQixlQUFlO0FBQ2pDO0FBQ0E7QUFDQTtB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QUssU0FBUyxFQUFDLFVBQVUsRUFBQyxHQUFHLEVBQUUsY0FBYyxDQUFDLEVBQUUsRUFBRSxLQUFLLEVBQUU7d0JBQ3pELGVBQWUsRUFBRSx1QkFBc0IsYUFBdEIsc0JBQXNCLHVCQUF0QixzQkFBc0IsQ0FBRSxFQUFFLE1BQUssY0FBYyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyx1QkFBdUIsQ0FBQyxDQUFDLENBQUMsYUFBYTtxQkFDdkgsRUFBRSxPQUFPLEVBQUUsR0FBRyxFQUFFLENBQUMsb0JBQW9CLENBQUMsY0FBYyxDQUFDO29CQUNsRCwyREFBQywwQ0FBSyxJQUFDLElBQUksRUFBQyxJQUFJLEVBQUMsS0FBSyxFQUFFLEVBQUMsS0FBSyxFQUFFLEtBQUssQ0FBQyxNQUFNLENBQUMsU0FBUyxFQUFDLElBQ3BELGNBQWMsQ0FBQyxZQUFZLENBQ3RCLENBQ04sQ0FDVDtZQUNILENBQUMsQ0FBQyxDQUVBLENBQ0YsQ0FDUDtBQUNILENBQUM7QUFDRCxpRUFBZSxNQUFNIiwic291cmNlcyI6WyJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL2Rpc3QvZXNtL1VzZXJTZXNzaW9uLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aC9kaXN0L2VzbS9mZWRlcmF0aW9uLXV0aWxzLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aC9kaXN0L2VzbS9mZXRjaC10b2tlbi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgvZGlzdC9lc20vZ2VuZXJhdGUtdG9rZW4uanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL2Rpc3QvZXNtL3ZhbGlkYXRlLWFwcC1hY2Nlc3MuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL25vZGVfbW9kdWxlcy90c2xpYi90c2xpYi5lczYuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyL2Rpc3QvZXNtL2FkZC5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXIvZGlzdC9lc20vZGVsZXRlLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllci9kaXN0L2VzbS9xdWVyeS5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXIvZGlzdC9lc20vcXVlcnlSZWxhdGVkLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllci9kaXN0L2VzbS91cGRhdGUuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyL25vZGVfbW9kdWxlcy90c2xpYi90c2xpYi5lczYuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3JlcXVlc3QuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL0FyY0dJU1JlcXVlc3RFcnJvci5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvYXBwZW5kLWN1c3RvbS1wYXJhbXMuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL2NsZWFuLXVybC5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvZGVjb2RlLXF1ZXJ5LXN0cmluZy5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvZW5jb2RlLWZvcm0tZGF0YS5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvZW5jb2RlLXF1ZXJ5LXN0cmluZy5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvcHJvY2Vzcy1wYXJhbXMuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL3dhcm4uanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L25vZGVfbW9kdWxlcy90c2xpYi90c2xpYi5lczYuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXBpLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2F1dGgudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY2xzcy1zdG9yZS50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jb25zdGFudHMudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvZXNyaS1hcGkudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvbG9nZ2VyLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL3V0aWxzLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS1hcmNnaXNcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtY29yZVwiIiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS1jb3JlL3JlYWN0XCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC9leHRlcm5hbCBzeXN0ZW0gXCJqaW11LXVpXCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL2Jvb3RzdHJhcCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9kZWZpbmUgcHJvcGVydHkgZ2V0dGVycyIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9oYXNPd25Qcm9wZXJ0eSBzaG9ydGhhbmQiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvbWFrZSBuYW1lc3BhY2Ugb2JqZWN0Iiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL3B1YmxpY1BhdGgiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtY29yZS9saWIvc2V0LXB1YmxpYy1wYXRoLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLXNlbGVjdC1saWZlbGluZS9zcmMvcnVudGltZS93aWRnZXQudHN4Il0sInNvdXJjZXNDb250ZW50IjpbIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDE5IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyByZXF1ZXN0LCBBcmNHSVNBdXRoRXJyb3IsIGNsZWFuVXJsLCBlbmNvZGVRdWVyeVN0cmluZywgZGVjb2RlUXVlcnlTdHJpbmcsIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbmltcG9ydCB7IGdlbmVyYXRlVG9rZW4gfSBmcm9tIFwiLi9nZW5lcmF0ZS10b2tlblwiO1xuaW1wb3J0IHsgZmV0Y2hUb2tlbiB9IGZyb20gXCIuL2ZldGNoLXRva2VuXCI7XG5pbXBvcnQgeyBjYW5Vc2VPbmxpbmVUb2tlbiwgaXNGZWRlcmF0ZWQgfSBmcm9tIFwiLi9mZWRlcmF0aW9uLXV0aWxzXCI7XG5pbXBvcnQgeyB2YWxpZGF0ZUFwcEFjY2VzcyB9IGZyb20gXCIuL3ZhbGlkYXRlLWFwcC1hY2Nlc3NcIjtcbmZ1bmN0aW9uIGRlZmVyKCkge1xuICAgIHZhciBkZWZlcnJlZCA9IHtcbiAgICAgICAgcHJvbWlzZTogbnVsbCxcbiAgICAgICAgcmVzb2x2ZTogbnVsbCxcbiAgICAgICAgcmVqZWN0OiBudWxsLFxuICAgIH07XG4gICAgZGVmZXJyZWQucHJvbWlzZSA9IG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSA9IHJlc29sdmU7XG4gICAgICAgIGRlZmVycmVkLnJlamVjdCA9IHJlamVjdDtcbiAgICB9KTtcbiAgICByZXR1cm4gZGVmZXJyZWQ7XG59XG4vKipcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBVc2VyU2Vzc2lvbiB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgnO1xuICogVXNlclNlc3Npb24uYmVnaW5PQXV0aDIoe1xuICogICAvLyByZWdpc3RlciBhbiBhcHAgb2YgeW91ciBvd24gdG8gY3JlYXRlIGEgdW5pcXVlIGNsaWVudElkXG4gKiAgIGNsaWVudElkOiBcImFiYzEyM1wiLFxuICogICByZWRpcmVjdFVyaTogJ2h0dHBzOi8veW91cmFwcC5jb20vYXV0aGVudGljYXRlLmh0bWwnXG4gKiB9KVxuICogICAudGhlbihzZXNzaW9uKVxuICogLy8gb3JcbiAqIG5ldyBVc2VyU2Vzc2lvbih7XG4gKiAgIHVzZXJuYW1lOiBcImpzbWl0aFwiLFxuICogICBwYXNzd29yZDogXCIxMjM0NTZcIlxuICogfSlcbiAqIC8vIG9yXG4gKiBVc2VyU2Vzc2lvbi5kZXNlcmlhbGl6ZShjYWNoZSlcbiAqIGBgYFxuICogVXNlZCB0byBhdXRoZW50aWNhdGUgYm90aCBBcmNHSVMgT25saW5lIGFuZCBBcmNHSVMgRW50ZXJwcmlzZSB1c2Vycy4gYFVzZXJTZXNzaW9uYCBpbmNsdWRlcyBoZWxwZXIgbWV0aG9kcyBmb3IgW09BdXRoIDIuMF0oL2FyY2dpcy1yZXN0LWpzL2d1aWRlcy9icm93c2VyLWF1dGhlbnRpY2F0aW9uLykgaW4gYm90aCBicm93c2VyIGFuZCBzZXJ2ZXIgYXBwbGljYXRpb25zLlxuICovXG52YXIgVXNlclNlc3Npb24gPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgZnVuY3Rpb24gVXNlclNlc3Npb24ob3B0aW9ucykge1xuICAgICAgICB0aGlzLmNsaWVudElkID0gb3B0aW9ucy5jbGllbnRJZDtcbiAgICAgICAgdGhpcy5fcmVmcmVzaFRva2VuID0gb3B0aW9ucy5yZWZyZXNoVG9rZW47XG4gICAgICAgIHRoaXMuX3JlZnJlc2hUb2tlbkV4cGlyZXMgPSBvcHRpb25zLnJlZnJlc2hUb2tlbkV4cGlyZXM7XG4gICAgICAgIHRoaXMudXNlcm5hbWUgPSBvcHRpb25zLnVzZXJuYW1lO1xuICAgICAgICB0aGlzLnBhc3N3b3JkID0gb3B0aW9ucy5wYXNzd29yZDtcbiAgICAgICAgdGhpcy5fdG9rZW4gPSBvcHRpb25zLnRva2VuO1xuICAgICAgICB0aGlzLl90b2tlbkV4cGlyZXMgPSBvcHRpb25zLnRva2VuRXhwaXJlcztcbiAgICAgICAgdGhpcy5wb3J0YWwgPSBvcHRpb25zLnBvcnRhbFxuICAgICAgICAgICAgPyBjbGVhblVybChvcHRpb25zLnBvcnRhbClcbiAgICAgICAgICAgIDogXCJodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiO1xuICAgICAgICB0aGlzLnNzbCA9IG9wdGlvbnMuc3NsO1xuICAgICAgICB0aGlzLnByb3ZpZGVyID0gb3B0aW9ucy5wcm92aWRlciB8fCBcImFyY2dpc1wiO1xuICAgICAgICB0aGlzLnRva2VuRHVyYXRpb24gPSBvcHRpb25zLnRva2VuRHVyYXRpb24gfHwgMjAxNjA7XG4gICAgICAgIHRoaXMucmVkaXJlY3RVcmkgPSBvcHRpb25zLnJlZGlyZWN0VXJpO1xuICAgICAgICB0aGlzLnJlZnJlc2hUb2tlblRUTCA9IG9wdGlvbnMucmVmcmVzaFRva2VuVFRMIHx8IDIwMTYwO1xuICAgICAgICB0aGlzLnNlcnZlciA9IG9wdGlvbnMuc2VydmVyO1xuICAgICAgICB0aGlzLmZlZGVyYXRlZFNlcnZlcnMgPSB7fTtcbiAgICAgICAgdGhpcy50cnVzdGVkRG9tYWlucyA9IFtdO1xuICAgICAgICAvLyBpZiBhIG5vbi1mZWRlcmF0ZWQgc2VydmVyIHdhcyBwYXNzZWQgZXhwbGljaXRseSwgaXQgc2hvdWxkIGJlIHRydXN0ZWQuXG4gICAgICAgIGlmIChvcHRpb25zLnNlcnZlcikge1xuICAgICAgICAgICAgLy8gaWYgdGhlIHVybCBpbmNsdWRlcyBtb3JlIHRoYW4gJy9hcmNnaXMvJywgdHJpbSB0aGUgcmVzdFxuICAgICAgICAgICAgdmFyIHJvb3QgPSB0aGlzLmdldFNlcnZlclJvb3RVcmwob3B0aW9ucy5zZXJ2ZXIpO1xuICAgICAgICAgICAgdGhpcy5mZWRlcmF0ZWRTZXJ2ZXJzW3Jvb3RdID0ge1xuICAgICAgICAgICAgICAgIHRva2VuOiBvcHRpb25zLnRva2VuLFxuICAgICAgICAgICAgICAgIGV4cGlyZXM6IG9wdGlvbnMudG9rZW5FeHBpcmVzLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0cyA9IHt9O1xuICAgIH1cbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoVXNlclNlc3Npb24ucHJvdG90eXBlLCBcInRva2VuXCIsIHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFRoZSBjdXJyZW50IEFyY0dJUyBPbmxpbmUgb3IgQXJjR0lTIEVudGVycHJpc2UgYHRva2VuYC5cbiAgICAgICAgICovXG4gICAgICAgIGdldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3Rva2VuO1xuICAgICAgICB9LFxuICAgICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSk7XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KFVzZXJTZXNzaW9uLnByb3RvdHlwZSwgXCJ0b2tlbkV4cGlyZXNcIiwge1xuICAgICAgICAvKipcbiAgICAgICAgICogVGhlIGV4cGlyYXRpb24gdGltZSBvZiB0aGUgY3VycmVudCBgdG9rZW5gLlxuICAgICAgICAgKi9cbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fdG9rZW5FeHBpcmVzO1xuICAgICAgICB9LFxuICAgICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSk7XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KFVzZXJTZXNzaW9uLnByb3RvdHlwZSwgXCJyZWZyZXNoVG9rZW5cIiwge1xuICAgICAgICAvKipcbiAgICAgICAgICogVGhlIGN1cnJlbnQgdG9rZW4gdG8gQXJjR0lTIE9ubGluZSBvciBBcmNHSVMgRW50ZXJwcmlzZS5cbiAgICAgICAgICovXG4gICAgICAgIGdldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3JlZnJlc2hUb2tlbjtcbiAgICAgICAgfSxcbiAgICAgICAgZW51bWVyYWJsZTogZmFsc2UsXG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZVxuICAgIH0pO1xuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShVc2VyU2Vzc2lvbi5wcm90b3R5cGUsIFwicmVmcmVzaFRva2VuRXhwaXJlc1wiLCB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBUaGUgZXhwaXJhdGlvbiB0aW1lIG9mIHRoZSBjdXJyZW50IGByZWZyZXNoVG9rZW5gLlxuICAgICAgICAgKi9cbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcmVmcmVzaFRva2VuRXhwaXJlcztcbiAgICAgICAgfSxcbiAgICAgICAgZW51bWVyYWJsZTogZmFsc2UsXG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZVxuICAgIH0pO1xuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShVc2VyU2Vzc2lvbi5wcm90b3R5cGUsIFwidHJ1c3RlZFNlcnZlcnNcIiwge1xuICAgICAgICAvKipcbiAgICAgICAgICogRGVwcmVjYXRlZCwgdXNlIGBmZWRlcmF0ZWRTZXJ2ZXJzYCBpbnN0ZWFkLlxuICAgICAgICAgKlxuICAgICAgICAgKiBAZGVwcmVjYXRlZFxuICAgICAgICAgKi9cbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkRFUFJFQ0FURUQ6IHVzZSBmZWRlcmF0ZWRTZXJ2ZXJzIGluc3RlYWRcIik7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5mZWRlcmF0ZWRTZXJ2ZXJzO1xuICAgICAgICB9LFxuICAgICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSk7XG4gICAgLyoqXG4gICAgICogQmVnaW5zIGEgbmV3IGJyb3dzZXItYmFzZWQgT0F1dGggMi4wIHNpZ24gaW4uIElmIGBvcHRpb25zLnBvcHVwYCBpcyBgdHJ1ZWAgdGhlXG4gICAgICogYXV0aGVudGljYXRpb24gd2luZG93IHdpbGwgb3BlbiBpbiBhIG5ldyB0YWIvd2luZG93IGFuZCB0aGUgZnVuY3Rpb24gd2lsbCByZXR1cm5cbiAgICAgKiBQcm9taXNlJmx0O1VzZXJTZXNzaW9uJmd0Oy4gT3RoZXJ3aXNlLCB0aGUgdXNlciB3aWxsIGJlIHJlZGlyZWN0ZWQgdG8gdGhlXG4gICAgICogYXV0aG9yaXphdGlvbiBwYWdlIGluIHRoZWlyIGN1cnJlbnQgdGFiL3dpbmRvdyBhbmQgdGhlIGZ1bmN0aW9uIHdpbGwgcmV0dXJuIGB1bmRlZmluZWRgLlxuICAgICAqXG4gICAgICogQGJyb3dzZXJPbmx5XG4gICAgICovXG4gICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgICBVc2VyU2Vzc2lvbi5iZWdpbk9BdXRoMiA9IGZ1bmN0aW9uIChvcHRpb25zLCB3aW4pIHtcbiAgICAgICAgaWYgKHdpbiA9PT0gdm9pZCAwKSB7IHdpbiA9IHdpbmRvdzsgfVxuICAgICAgICBpZiAob3B0aW9ucy5kdXJhdGlvbikge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJERVBSRUNBVEVEOiAnZHVyYXRpb24nIGlzIGRlcHJlY2F0ZWQgLSB1c2UgJ2V4cGlyYXRpb24nIGluc3RlYWRcIik7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIF9hID0gX19hc3NpZ24oe1xuICAgICAgICAgICAgcG9ydGFsOiBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCIsXG4gICAgICAgICAgICBwcm92aWRlcjogXCJhcmNnaXNcIixcbiAgICAgICAgICAgIGV4cGlyYXRpb246IDIwMTYwLFxuICAgICAgICAgICAgcG9wdXA6IHRydWUsXG4gICAgICAgICAgICBwb3B1cFdpbmRvd0ZlYXR1cmVzOiBcImhlaWdodD00MDAsd2lkdGg9NjAwLG1lbnViYXI9bm8sbG9jYXRpb249eWVzLHJlc2l6YWJsZT15ZXMsc2Nyb2xsYmFycz15ZXMsc3RhdHVzPXllc1wiLFxuICAgICAgICAgICAgc3RhdGU6IG9wdGlvbnMuY2xpZW50SWQsXG4gICAgICAgICAgICBsb2NhbGU6IFwiXCIsXG4gICAgICAgIH0sIG9wdGlvbnMpLCBwb3J0YWwgPSBfYS5wb3J0YWwsIHByb3ZpZGVyID0gX2EucHJvdmlkZXIsIGNsaWVudElkID0gX2EuY2xpZW50SWQsIGV4cGlyYXRpb24gPSBfYS5leHBpcmF0aW9uLCByZWRpcmVjdFVyaSA9IF9hLnJlZGlyZWN0VXJpLCBwb3B1cCA9IF9hLnBvcHVwLCBwb3B1cFdpbmRvd0ZlYXR1cmVzID0gX2EucG9wdXBXaW5kb3dGZWF0dXJlcywgc3RhdGUgPSBfYS5zdGF0ZSwgbG9jYWxlID0gX2EubG9jYWxlLCBwYXJhbXMgPSBfYS5wYXJhbXM7XG4gICAgICAgIHZhciB1cmw7XG4gICAgICAgIGlmIChwcm92aWRlciA9PT0gXCJhcmNnaXNcIikge1xuICAgICAgICAgICAgdXJsID0gcG9ydGFsICsgXCIvb2F1dGgyL2F1dGhvcml6ZT9jbGllbnRfaWQ9XCIgKyBjbGllbnRJZCArIFwiJnJlc3BvbnNlX3R5cGU9dG9rZW4mZXhwaXJhdGlvbj1cIiArIChvcHRpb25zLmR1cmF0aW9uIHx8IGV4cGlyYXRpb24pICsgXCImcmVkaXJlY3RfdXJpPVwiICsgZW5jb2RlVVJJQ29tcG9uZW50KHJlZGlyZWN0VXJpKSArIFwiJnN0YXRlPVwiICsgc3RhdGUgKyBcIiZsb2NhbGU9XCIgKyBsb2NhbGU7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICB1cmwgPSBwb3J0YWwgKyBcIi9vYXV0aDIvc29jaWFsL2F1dGhvcml6ZT9jbGllbnRfaWQ9XCIgKyBjbGllbnRJZCArIFwiJnNvY2lhbExvZ2luUHJvdmlkZXJOYW1lPVwiICsgcHJvdmlkZXIgKyBcIiZhdXRvQWNjb3VudENyZWF0ZUZvclNvY2lhbD10cnVlJnJlc3BvbnNlX3R5cGU9dG9rZW4mZXhwaXJhdGlvbj1cIiArIChvcHRpb25zLmR1cmF0aW9uIHx8IGV4cGlyYXRpb24pICsgXCImcmVkaXJlY3RfdXJpPVwiICsgZW5jb2RlVVJJQ29tcG9uZW50KHJlZGlyZWN0VXJpKSArIFwiJnN0YXRlPVwiICsgc3RhdGUgKyBcIiZsb2NhbGU9XCIgKyBsb2NhbGU7XG4gICAgICAgIH1cbiAgICAgICAgLy8gYXBwZW5kIGFkZGl0aW9uYWwgcGFyYW1zXG4gICAgICAgIGlmIChwYXJhbXMpIHtcbiAgICAgICAgICAgIHVybCA9IHVybCArIFwiJlwiICsgZW5jb2RlUXVlcnlTdHJpbmcocGFyYW1zKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXBvcHVwKSB7XG4gICAgICAgICAgICB3aW4ubG9jYXRpb24uaHJlZiA9IHVybDtcbiAgICAgICAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIHNlc3Npb24gPSBkZWZlcigpO1xuICAgICAgICB3aW5bXCJfX0VTUklfUkVTVF9BVVRIX0hBTkRMRVJfXCIgKyBjbGllbnRJZF0gPSBmdW5jdGlvbiAoZXJyb3JTdHJpbmcsIG9hdXRoSW5mb1N0cmluZykge1xuICAgICAgICAgICAgaWYgKGVycm9yU3RyaW5nKSB7XG4gICAgICAgICAgICAgICAgdmFyIGVycm9yID0gSlNPTi5wYXJzZShlcnJvclN0cmluZyk7XG4gICAgICAgICAgICAgICAgc2Vzc2lvbi5yZWplY3QobmV3IEFyY0dJU0F1dGhFcnJvcihlcnJvci5lcnJvck1lc3NhZ2UsIGVycm9yLmVycm9yKSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKG9hdXRoSW5mb1N0cmluZykge1xuICAgICAgICAgICAgICAgIHZhciBvYXV0aEluZm8gPSBKU09OLnBhcnNlKG9hdXRoSW5mb1N0cmluZyk7XG4gICAgICAgICAgICAgICAgc2Vzc2lvbi5yZXNvbHZlKG5ldyBVc2VyU2Vzc2lvbih7XG4gICAgICAgICAgICAgICAgICAgIGNsaWVudElkOiBjbGllbnRJZCxcbiAgICAgICAgICAgICAgICAgICAgcG9ydGFsOiBwb3J0YWwsXG4gICAgICAgICAgICAgICAgICAgIHNzbDogb2F1dGhJbmZvLnNzbCxcbiAgICAgICAgICAgICAgICAgICAgdG9rZW46IG9hdXRoSW5mby50b2tlbixcbiAgICAgICAgICAgICAgICAgICAgdG9rZW5FeHBpcmVzOiBuZXcgRGF0ZShvYXV0aEluZm8uZXhwaXJlcyksXG4gICAgICAgICAgICAgICAgICAgIHVzZXJuYW1lOiBvYXV0aEluZm8udXNlcm5hbWUsXG4gICAgICAgICAgICAgICAgfSkpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuICAgICAgICB3aW4ub3Blbih1cmwsIFwib2F1dGgtd2luZG93XCIsIHBvcHVwV2luZG93RmVhdHVyZXMpO1xuICAgICAgICByZXR1cm4gc2Vzc2lvbi5wcm9taXNlO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogQ29tcGxldGVzIGEgYnJvd3Nlci1iYXNlZCBPQXV0aCAyLjAgc2lnbiBpbi4gSWYgYG9wdGlvbnMucG9wdXBgIGlzIGB0cnVlYCB0aGUgdXNlclxuICAgICAqIHdpbGwgYmUgcmV0dXJuZWQgdG8gdGhlIHByZXZpb3VzIHdpbmRvdy4gT3RoZXJ3aXNlIGEgbmV3IGBVc2VyU2Vzc2lvbmBcbiAgICAgKiB3aWxsIGJlIHJldHVybmVkLiBZb3UgbXVzdCBwYXNzIHRoZSBzYW1lIHZhbHVlcyBmb3IgYG9wdGlvbnMucG9wdXBgIGFuZFxuICAgICAqIGBvcHRpb25zLnBvcnRhbGAgYXMgeW91IHVzZWQgaW4gYGJlZ2luT0F1dGgyKClgLlxuICAgICAqXG4gICAgICogQGJyb3dzZXJPbmx5XG4gICAgICovXG4gICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgICBVc2VyU2Vzc2lvbi5jb21wbGV0ZU9BdXRoMiA9IGZ1bmN0aW9uIChvcHRpb25zLCB3aW4pIHtcbiAgICAgICAgaWYgKHdpbiA9PT0gdm9pZCAwKSB7IHdpbiA9IHdpbmRvdzsgfVxuICAgICAgICB2YXIgX2EgPSBfX2Fzc2lnbih7IHBvcnRhbDogXCJodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiLCBwb3B1cDogdHJ1ZSB9LCBvcHRpb25zKSwgcG9ydGFsID0gX2EucG9ydGFsLCBjbGllbnRJZCA9IF9hLmNsaWVudElkLCBwb3B1cCA9IF9hLnBvcHVwO1xuICAgICAgICBmdW5jdGlvbiBjb21wbGV0ZVNpZ25JbihlcnJvciwgb2F1dGhJbmZvKSB7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIHZhciBoYW5kbGVyRm4gPSB2b2lkIDA7XG4gICAgICAgICAgICAgICAgdmFyIGhhbmRsZXJGbk5hbWUgPSBcIl9fRVNSSV9SRVNUX0FVVEhfSEFORExFUl9cIiArIGNsaWVudElkO1xuICAgICAgICAgICAgICAgIGlmIChwb3B1cCkge1xuICAgICAgICAgICAgICAgICAgICAvLyBHdWFyZCBiL2MgSUUgZG9lcyBub3Qgc3VwcG9ydCB3aW5kb3cub3BlbmVyXG4gICAgICAgICAgICAgICAgICAgIGlmICh3aW4ub3BlbmVyKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAod2luLm9wZW5lci5wYXJlbnQgJiYgd2luLm9wZW5lci5wYXJlbnRbaGFuZGxlckZuTmFtZV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVyRm4gPSB3aW4ub3BlbmVyLnBhcmVudFtoYW5kbGVyRm5OYW1lXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgaWYgKHdpbi5vcGVuZXIgJiYgd2luLm9wZW5lcltoYW5kbGVyRm5OYW1lXSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIHN1cHBvcnQgcG9wLW91dCBvYXV0aCBmcm9tIHdpdGhpbiBhbiBpZnJhbWVcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVyRm4gPSB3aW4ub3BlbmVyW2hhbmRsZXJGbk5hbWVdO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gSUVcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICh3aW4gIT09IHdpbi5wYXJlbnQgJiYgd2luLnBhcmVudCAmJiB3aW4ucGFyZW50W2hhbmRsZXJGbk5hbWVdKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaGFuZGxlckZuID0gd2luLnBhcmVudFtoYW5kbGVyRm5OYW1lXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAvLyBpZiB3ZSBoYXZlIGEgaGFuZGxlciBmbiwgY2FsbCBpdCBhbmQgY2xvc2UgdGhlIHdpbmRvd1xuICAgICAgICAgICAgICAgICAgICBpZiAoaGFuZGxlckZuKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVyRm4oZXJyb3IgPyBKU09OLnN0cmluZ2lmeShlcnJvcikgOiB1bmRlZmluZWQsIEpTT04uc3RyaW5naWZ5KG9hdXRoSW5mbykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgd2luLmNsb3NlKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gdW5kZWZpbmVkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgQXJjR0lTQXV0aEVycm9yKFwiVW5hYmxlIHRvIGNvbXBsZXRlIGF1dGhlbnRpY2F0aW9uLiBJdCdzIHBvc3NpYmxlIHlvdSBzcGVjaWZpZWQgcG9wdXAgYmFzZWQgb0F1dGgyIGJ1dCBubyBoYW5kbGVyIGZyb20gXFxcImJlZ2luT0F1dGgyKClcXFwiIHByZXNlbnQuIFRoaXMgZ2VuZXJhbGx5IGhhcHBlbnMgYmVjYXVzZSB0aGUgXFxcInBvcHVwXFxcIiBvcHRpb24gZGlmZmVycyBiZXR3ZWVuIFxcXCJiZWdpbk9BdXRoMigpXFxcIiBhbmQgXFxcImNvbXBsZXRlT0F1dGgyKClcXFwiLlwiKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmIChlcnJvcikge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNBdXRoRXJyb3IoZXJyb3IuZXJyb3JNZXNzYWdlLCBlcnJvci5lcnJvcik7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gbmV3IFVzZXJTZXNzaW9uKHtcbiAgICAgICAgICAgICAgICBjbGllbnRJZDogY2xpZW50SWQsXG4gICAgICAgICAgICAgICAgcG9ydGFsOiBwb3J0YWwsXG4gICAgICAgICAgICAgICAgc3NsOiBvYXV0aEluZm8uc3NsLFxuICAgICAgICAgICAgICAgIHRva2VuOiBvYXV0aEluZm8udG9rZW4sXG4gICAgICAgICAgICAgICAgdG9rZW5FeHBpcmVzOiBvYXV0aEluZm8uZXhwaXJlcyxcbiAgICAgICAgICAgICAgICB1c2VybmFtZTogb2F1dGhJbmZvLnVzZXJuYW1lLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIHBhcmFtcyA9IGRlY29kZVF1ZXJ5U3RyaW5nKHdpbi5sb2NhdGlvbi5oYXNoKTtcbiAgICAgICAgaWYgKCFwYXJhbXMuYWNjZXNzX3Rva2VuKSB7XG4gICAgICAgICAgICB2YXIgZXJyb3IgPSB2b2lkIDA7XG4gICAgICAgICAgICB2YXIgZXJyb3JNZXNzYWdlID0gXCJVbmtub3duIGVycm9yXCI7XG4gICAgICAgICAgICBpZiAocGFyYW1zLmVycm9yKSB7XG4gICAgICAgICAgICAgICAgZXJyb3IgPSBwYXJhbXMuZXJyb3I7XG4gICAgICAgICAgICAgICAgZXJyb3JNZXNzYWdlID0gcGFyYW1zLmVycm9yX2Rlc2NyaXB0aW9uO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIGNvbXBsZXRlU2lnbkluKHsgZXJyb3I6IGVycm9yLCBlcnJvck1lc3NhZ2U6IGVycm9yTWVzc2FnZSB9KTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgdG9rZW4gPSBwYXJhbXMuYWNjZXNzX3Rva2VuO1xuICAgICAgICB2YXIgZXhwaXJlcyA9IG5ldyBEYXRlKERhdGUubm93KCkgKyBwYXJzZUludChwYXJhbXMuZXhwaXJlc19pbiwgMTApICogMTAwMCAtIDYwICogMTAwMCk7XG4gICAgICAgIHZhciB1c2VybmFtZSA9IHBhcmFtcy51c2VybmFtZTtcbiAgICAgICAgdmFyIHNzbCA9IHBhcmFtcy5zc2wgPT09IFwidHJ1ZVwiO1xuICAgICAgICByZXR1cm4gY29tcGxldGVTaWduSW4odW5kZWZpbmVkLCB7XG4gICAgICAgICAgICB0b2tlbjogdG9rZW4sXG4gICAgICAgICAgICBleHBpcmVzOiBleHBpcmVzLFxuICAgICAgICAgICAgc3NsOiBzc2wsXG4gICAgICAgICAgICB1c2VybmFtZTogdXNlcm5hbWUsXG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogUmVxdWVzdCBzZXNzaW9uIGluZm9ybWF0aW9uIGZyb20gdGhlIHBhcmVudCBhcHBsaWNhdGlvblxuICAgICAqXG4gICAgICogV2hlbiBhbiBhcHBsaWNhdGlvbiBpcyBlbWJlZGRlZCBpbnRvIGFub3RoZXIgYXBwbGljYXRpb24gdmlhIGFuIElGcmFtZSwgdGhlIGVtYmVkZGVkIGFwcCBjYW5cbiAgICAgKiB1c2UgYHdpbmRvdy5wb3N0TWVzc2FnZWAgdG8gcmVxdWVzdCBjcmVkZW50aWFscyBmcm9tIHRoZSBob3N0IGFwcGxpY2F0aW9uLiBUaGlzIGZ1bmN0aW9uIHdyYXBzXG4gICAgICogdGhhdCBiZWhhdmlvci5cbiAgICAgKlxuICAgICAqIFRoZSBBcmNHSVMgQVBJIGZvciBKYXZhc2NyaXB0IGhhcyB0aGlzIGJ1aWx0IGludG8gdGhlIElkZW50aXR5IE1hbmFnZXIgYXMgb2YgdGhlIDQuMTkgcmVsZWFzZS5cbiAgICAgKlxuICAgICAqIE5vdGU6IFRoZSBwYXJlbnQgYXBwbGljYXRpb24gd2lsbCBub3QgcmVzcG9uZCBpZiB0aGUgZW1iZWRkZWQgYXBwJ3Mgb3JpZ2luIGlzIG5vdDpcbiAgICAgKiAtIHRoZSBzYW1lIG9yaWdpbiBhcyB0aGUgcGFyZW50IG9yICouYXJjZ2lzLmNvbSAoSlNBUEkpXG4gICAgICogLSBpbiB0aGUgbGlzdCBvZiB2YWxpZCBjaGlsZCBvcmlnaW5zIChSRVNULUpTKVxuICAgICAqXG4gICAgICpcbiAgICAgKiBAcGFyYW0gcGFyZW50T3JpZ2luIG9yaWdpbiBvZiB0aGUgcGFyZW50IGZyYW1lLiBQYXNzZWQgaW50byB0aGUgZW1iZWRkZWQgYXBwbGljYXRpb24gYXMgYHBhcmVudE9yaWdpbmAgcXVlcnkgcGFyYW1cbiAgICAgKiBAYnJvd3Nlck9ubHlcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5mcm9tUGFyZW50ID0gZnVuY3Rpb24gKHBhcmVudE9yaWdpbiwgd2luKSB7XG4gICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0OiBtdXN0IHBhc3MgaW4gYSBtb2Nrd2luZG93IGZvciB0ZXN0cyBzbyB3ZSBjYW4ndCBjb3ZlciB0aGUgb3RoZXIgYnJhbmNoICovXG4gICAgICAgIGlmICghd2luICYmIHdpbmRvdykge1xuICAgICAgICAgICAgd2luID0gd2luZG93O1xuICAgICAgICB9XG4gICAgICAgIC8vIERlY2xhcmUgaGFuZGxlciBvdXRzaWRlIG9mIHByb21pc2Ugc2NvcGUgc28gd2UgY2FuIGRldGFjaCBpdFxuICAgICAgICB2YXIgaGFuZGxlcjtcbiAgICAgICAgLy8gcmV0dXJuIGEgcHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aGVuIHRoZSBoYW5kbGVyIHJlY2VpdmVzXG4gICAgICAgIC8vIHNlc3Npb24gaW5mb3JtYXRpb24gZnJvbSB0aGUgY29ycmVjdCBvcmlnaW5cbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcbiAgICAgICAgICAgIC8vIGNyZWF0ZSBhbiBldmVudCBoYW5kbGVyIHRoYXQganVzdCB3cmFwcyB0aGUgcGFyZW50TWVzc2FnZUhhbmRsZXJcbiAgICAgICAgICAgIGhhbmRsZXIgPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgICAgICAgICAvLyBlbnN1cmUgd2Ugb25seSBsaXN0ZW4gdG8gZXZlbnRzIGZyb20gdGhlIHBhcmVudFxuICAgICAgICAgICAgICAgIGlmIChldmVudC5zb3VyY2UgPT09IHdpbi5wYXJlbnQgJiYgZXZlbnQuZGF0YSkge1xuICAgICAgICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJlc29sdmUoVXNlclNlc3Npb24ucGFyZW50TWVzc2FnZUhhbmRsZXIoZXZlbnQpKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgLy8gYWRkIGxpc3RlbmVyXG4gICAgICAgICAgICB3aW4uYWRkRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgaGFuZGxlciwgZmFsc2UpO1xuICAgICAgICAgICAgd2luLnBhcmVudC5wb3N0TWVzc2FnZSh7IHR5cGU6IFwiYXJjZ2lzOmF1dGg6cmVxdWVzdENyZWRlbnRpYWxcIiB9LCBwYXJlbnRPcmlnaW4pO1xuICAgICAgICB9KS50aGVuKGZ1bmN0aW9uIChzZXNzaW9uKSB7XG4gICAgICAgICAgICB3aW4ucmVtb3ZlRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgaGFuZGxlciwgZmFsc2UpO1xuICAgICAgICAgICAgcmV0dXJuIHNlc3Npb247XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogQmVnaW5zIGEgbmV3IHNlcnZlci1iYXNlZCBPQXV0aCAyLjAgc2lnbiBpbi4gVGhpcyB3aWxsIHJlZGlyZWN0IHRoZSB1c2VyIHRvXG4gICAgICogdGhlIEFyY0dJUyBPbmxpbmUgb3IgQXJjR0lTIEVudGVycHJpc2UgYXV0aG9yaXphdGlvbiBwYWdlLlxuICAgICAqXG4gICAgICogQG5vZGVPbmx5XG4gICAgICovXG4gICAgVXNlclNlc3Npb24uYXV0aG9yaXplID0gZnVuY3Rpb24gKG9wdGlvbnMsIHJlc3BvbnNlKSB7XG4gICAgICAgIGlmIChvcHRpb25zLmR1cmF0aW9uKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkRFUFJFQ0FURUQ6ICdkdXJhdGlvbicgaXMgZGVwcmVjYXRlZCAtIHVzZSAnZXhwaXJhdGlvbicgaW5zdGVhZFwiKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgX2EgPSBfX2Fzc2lnbih7IHBvcnRhbDogXCJodHRwczovL2FyY2dpcy5jb20vc2hhcmluZy9yZXN0XCIsIGV4cGlyYXRpb246IDIwMTYwIH0sIG9wdGlvbnMpLCBwb3J0YWwgPSBfYS5wb3J0YWwsIGNsaWVudElkID0gX2EuY2xpZW50SWQsIGV4cGlyYXRpb24gPSBfYS5leHBpcmF0aW9uLCByZWRpcmVjdFVyaSA9IF9hLnJlZGlyZWN0VXJpO1xuICAgICAgICByZXNwb25zZS53cml0ZUhlYWQoMzAxLCB7XG4gICAgICAgICAgICBMb2NhdGlvbjogcG9ydGFsICsgXCIvb2F1dGgyL2F1dGhvcml6ZT9jbGllbnRfaWQ9XCIgKyBjbGllbnRJZCArIFwiJmV4cGlyYXRpb249XCIgKyAob3B0aW9ucy5kdXJhdGlvbiB8fCBleHBpcmF0aW9uKSArIFwiJnJlc3BvbnNlX3R5cGU9Y29kZSZyZWRpcmVjdF91cmk9XCIgKyBlbmNvZGVVUklDb21wb25lbnQocmVkaXJlY3RVcmkpLFxuICAgICAgICB9KTtcbiAgICAgICAgcmVzcG9uc2UuZW5kKCk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBDb21wbGV0ZXMgdGhlIHNlcnZlci1iYXNlZCBPQXV0aCAyLjAgc2lnbiBpbiBwcm9jZXNzIGJ5IGV4Y2hhbmdpbmcgdGhlIGBhdXRob3JpemF0aW9uQ29kZWBcbiAgICAgKiBmb3IgYSBgYWNjZXNzX3Rva2VuYC5cbiAgICAgKlxuICAgICAqIEBub2RlT25seVxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLmV4Y2hhbmdlQXV0aG9yaXphdGlvbkNvZGUgPSBmdW5jdGlvbiAob3B0aW9ucywgYXV0aG9yaXphdGlvbkNvZGUpIHtcbiAgICAgICAgdmFyIF9hID0gX19hc3NpZ24oe1xuICAgICAgICAgICAgcG9ydGFsOiBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCIsXG4gICAgICAgICAgICByZWZyZXNoVG9rZW5UVEw6IDIwMTYwLFxuICAgICAgICB9LCBvcHRpb25zKSwgcG9ydGFsID0gX2EucG9ydGFsLCBjbGllbnRJZCA9IF9hLmNsaWVudElkLCByZWRpcmVjdFVyaSA9IF9hLnJlZGlyZWN0VXJpLCByZWZyZXNoVG9rZW5UVEwgPSBfYS5yZWZyZXNoVG9rZW5UVEw7XG4gICAgICAgIHJldHVybiBmZXRjaFRva2VuKHBvcnRhbCArIFwiL29hdXRoMi90b2tlblwiLCB7XG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICBncmFudF90eXBlOiBcImF1dGhvcml6YXRpb25fY29kZVwiLFxuICAgICAgICAgICAgICAgIGNsaWVudF9pZDogY2xpZW50SWQsXG4gICAgICAgICAgICAgICAgcmVkaXJlY3RfdXJpOiByZWRpcmVjdFVyaSxcbiAgICAgICAgICAgICAgICBjb2RlOiBhdXRob3JpemF0aW9uQ29kZSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICByZXR1cm4gbmV3IFVzZXJTZXNzaW9uKHtcbiAgICAgICAgICAgICAgICBjbGllbnRJZDogY2xpZW50SWQsXG4gICAgICAgICAgICAgICAgcG9ydGFsOiBwb3J0YWwsXG4gICAgICAgICAgICAgICAgc3NsOiByZXNwb25zZS5zc2wsXG4gICAgICAgICAgICAgICAgcmVkaXJlY3RVcmk6IHJlZGlyZWN0VXJpLFxuICAgICAgICAgICAgICAgIHJlZnJlc2hUb2tlbjogcmVzcG9uc2UucmVmcmVzaFRva2VuLFxuICAgICAgICAgICAgICAgIHJlZnJlc2hUb2tlblRUTDogcmVmcmVzaFRva2VuVFRMLFxuICAgICAgICAgICAgICAgIHJlZnJlc2hUb2tlbkV4cGlyZXM6IG5ldyBEYXRlKERhdGUubm93KCkgKyAocmVmcmVzaFRva2VuVFRMIC0gMSkgKiA2MCAqIDEwMDApLFxuICAgICAgICAgICAgICAgIHRva2VuOiByZXNwb25zZS50b2tlbixcbiAgICAgICAgICAgICAgICB0b2tlbkV4cGlyZXM6IHJlc3BvbnNlLmV4cGlyZXMsXG4gICAgICAgICAgICAgICAgdXNlcm5hbWU6IHJlc3BvbnNlLnVzZXJuYW1lLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgVXNlclNlc3Npb24uZGVzZXJpYWxpemUgPSBmdW5jdGlvbiAoc3RyKSB7XG4gICAgICAgIHZhciBvcHRpb25zID0gSlNPTi5wYXJzZShzdHIpO1xuICAgICAgICByZXR1cm4gbmV3IFVzZXJTZXNzaW9uKHtcbiAgICAgICAgICAgIGNsaWVudElkOiBvcHRpb25zLmNsaWVudElkLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuOiBvcHRpb25zLnJlZnJlc2hUb2tlbixcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlbkV4cGlyZXM6IG5ldyBEYXRlKG9wdGlvbnMucmVmcmVzaFRva2VuRXhwaXJlcyksXG4gICAgICAgICAgICB1c2VybmFtZTogb3B0aW9ucy51c2VybmFtZSxcbiAgICAgICAgICAgIHBhc3N3b3JkOiBvcHRpb25zLnBhc3N3b3JkLFxuICAgICAgICAgICAgdG9rZW46IG9wdGlvbnMudG9rZW4sXG4gICAgICAgICAgICB0b2tlbkV4cGlyZXM6IG5ldyBEYXRlKG9wdGlvbnMudG9rZW5FeHBpcmVzKSxcbiAgICAgICAgICAgIHBvcnRhbDogb3B0aW9ucy5wb3J0YWwsXG4gICAgICAgICAgICBzc2w6IG9wdGlvbnMuc3NsLFxuICAgICAgICAgICAgdG9rZW5EdXJhdGlvbjogb3B0aW9ucy50b2tlbkR1cmF0aW9uLFxuICAgICAgICAgICAgcmVkaXJlY3RVcmk6IG9wdGlvbnMucmVkaXJlY3RVcmksXG4gICAgICAgICAgICByZWZyZXNoVG9rZW5UVEw6IG9wdGlvbnMucmVmcmVzaFRva2VuVFRMLFxuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFRyYW5zbGF0ZXMgYXV0aGVudGljYXRpb24gZnJvbSB0aGUgZm9ybWF0IHVzZWQgaW4gdGhlIFtBcmNHSVMgQVBJIGZvciBKYXZhU2NyaXB0XShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9qYXZhc2NyaXB0LykuXG4gICAgICpcbiAgICAgKiBgYGBqc1xuICAgICAqIFVzZXJTZXNzaW9uLmZyb21DcmVkZW50aWFsKHtcbiAgICAgKiAgIHVzZXJJZDogXCJqc21pdGhcIixcbiAgICAgKiAgIHRva2VuOiBcInNlY3JldFwiXG4gICAgICogfSk7XG4gICAgICogYGBgXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyBVc2VyU2Vzc2lvblxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLmZyb21DcmVkZW50aWFsID0gZnVuY3Rpb24gKGNyZWRlbnRpYWwpIHtcbiAgICAgICAgLy8gQXQgQXJjR0lTIE9ubGluZSA5LjEsIGNyZWRlbnRpYWxzIG5vIGxvbmdlciBpbmNsdWRlIHRoZSBzc2wgYW5kIGV4cGlyZXMgcHJvcGVydGllc1xuICAgICAgICAvLyBIZXJlLCB3ZSBwcm92aWRlIGRlZmF1bHQgdmFsdWVzIGZvciB0aGVtIHRvIGNvdmVyIHRoaXMgY29uZGl0aW9uXG4gICAgICAgIHZhciBzc2wgPSB0eXBlb2YgY3JlZGVudGlhbC5zc2wgIT09IFwidW5kZWZpbmVkXCIgPyBjcmVkZW50aWFsLnNzbCA6IHRydWU7XG4gICAgICAgIHZhciBleHBpcmVzID0gY3JlZGVudGlhbC5leHBpcmVzIHx8IERhdGUubm93KCkgKyA3MjAwMDAwOyAvKiAyIGhvdXJzICovXG4gICAgICAgIHJldHVybiBuZXcgVXNlclNlc3Npb24oe1xuICAgICAgICAgICAgcG9ydGFsOiBjcmVkZW50aWFsLnNlcnZlci5pbmNsdWRlcyhcInNoYXJpbmcvcmVzdFwiKVxuICAgICAgICAgICAgICAgID8gY3JlZGVudGlhbC5zZXJ2ZXJcbiAgICAgICAgICAgICAgICA6IGNyZWRlbnRpYWwuc2VydmVyICsgXCIvc2hhcmluZy9yZXN0XCIsXG4gICAgICAgICAgICBzc2w6IHNzbCxcbiAgICAgICAgICAgIHRva2VuOiBjcmVkZW50aWFsLnRva2VuLFxuICAgICAgICAgICAgdXNlcm5hbWU6IGNyZWRlbnRpYWwudXNlcklkLFxuICAgICAgICAgICAgdG9rZW5FeHBpcmVzOiBuZXcgRGF0ZShleHBpcmVzKSxcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBIYW5kbGUgdGhlIHJlc3BvbnNlIGZyb20gdGhlIHBhcmVudFxuICAgICAqIEBwYXJhbSBldmVudCBET00gRXZlbnRcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wYXJlbnRNZXNzYWdlSGFuZGxlciA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICBpZiAoZXZlbnQuZGF0YS50eXBlID09PSBcImFyY2dpczphdXRoOmNyZWRlbnRpYWxcIikge1xuICAgICAgICAgICAgcmV0dXJuIFVzZXJTZXNzaW9uLmZyb21DcmVkZW50aWFsKGV2ZW50LmRhdGEuY3JlZGVudGlhbCk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGV2ZW50LmRhdGEudHlwZSA9PT0gXCJhcmNnaXM6YXV0aDplcnJvclwiKSB7XG4gICAgICAgICAgICB2YXIgZXJyID0gbmV3IEVycm9yKGV2ZW50LmRhdGEuZXJyb3IubWVzc2FnZSk7XG4gICAgICAgICAgICBlcnIubmFtZSA9IGV2ZW50LmRhdGEuZXJyb3IubmFtZTtcbiAgICAgICAgICAgIHRocm93IGVycjtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcIlVua25vd24gbWVzc2FnZSB0eXBlLlwiKTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgLyoqXG4gICAgICogUmV0dXJucyBhdXRoZW50aWNhdGlvbiBpbiBhIGZvcm1hdCB1c2VhYmxlIGluIHRoZSBbQXJjR0lTIEFQSSBmb3IgSmF2YVNjcmlwdF0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vamF2YXNjcmlwdC8pLlxuICAgICAqXG4gICAgICogYGBganNcbiAgICAgKiBlc3JpSWQucmVnaXN0ZXJUb2tlbihzZXNzaW9uLnRvQ3JlZGVudGlhbCgpKTtcbiAgICAgKiBgYGBcbiAgICAgKlxuICAgICAqIEByZXR1cm5zIElDcmVkZW50aWFsXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnRvQ3JlZGVudGlhbCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIGV4cGlyZXM6IHRoaXMudG9rZW5FeHBpcmVzLmdldFRpbWUoKSxcbiAgICAgICAgICAgIHNlcnZlcjogdGhpcy5wb3J0YWwsXG4gICAgICAgICAgICBzc2w6IHRoaXMuc3NsLFxuICAgICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgICB1c2VySWQ6IHRoaXMudXNlcm5hbWUsXG4gICAgICAgIH07XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIGluZm9ybWF0aW9uIGFib3V0IHRoZSBjdXJyZW50bHkgbG9nZ2VkIGluIFt1c2VyXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3VzZXJzLWdyb3Vwcy1hbmQtaXRlbXMvdXNlci5odG0pLiBTdWJzZXF1ZW50IGNhbGxzIHdpbGwgKm5vdCogcmVzdWx0IGluIGFkZGl0aW9uYWwgd2ViIHRyYWZmaWMuXG4gICAgICpcbiAgICAgKiBgYGBqc1xuICAgICAqIHNlc3Npb24uZ2V0VXNlcigpXG4gICAgICogICAudGhlbihyZXNwb25zZSA9PiB7XG4gICAgICogICAgIGNvbnNvbGUubG9nKHJlc3BvbnNlLnJvbGUpOyAvLyBcIm9yZ19hZG1pblwiXG4gICAgICogICB9KVxuICAgICAqIGBgYFxuICAgICAqXG4gICAgICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3QuIE5PVEU6IGByYXdSZXNwb25zZWAgaXMgbm90IHN1cHBvcnRlZCBieSB0aGlzIG9wZXJhdGlvbi5cbiAgICAgKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgZGF0YSBmcm9tIHRoZSByZXNwb25zZS5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0VXNlciA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBpZiAodGhpcy5fcGVuZGluZ1VzZXJSZXF1ZXN0KSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1VzZXJSZXF1ZXN0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKHRoaXMuX3VzZXIpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy5fdXNlcik7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICB2YXIgdXJsID0gdGhpcy5wb3J0YWwgKyBcIi9jb21tdW5pdHkvc2VsZlwiO1xuICAgICAgICAgICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbihfX2Fzc2lnbih7IGh0dHBNZXRob2Q6IFwiR0VUXCIsIGF1dGhlbnRpY2F0aW9uOiB0aGlzIH0sIHJlcXVlc3RPcHRpb25zKSwgeyByYXdSZXNwb25zZTogZmFsc2UgfSk7XG4gICAgICAgICAgICB0aGlzLl9wZW5kaW5nVXNlclJlcXVlc3QgPSByZXF1ZXN0KHVybCwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICBfdGhpcy5fdXNlciA9IHJlc3BvbnNlO1xuICAgICAgICAgICAgICAgIF90aGlzLl9wZW5kaW5nVXNlclJlcXVlc3QgPSBudWxsO1xuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdVc2VyUmVxdWVzdDtcbiAgICAgICAgfVxuICAgIH07XG4gICAgLyoqXG4gICAgICogUmV0dXJucyBpbmZvcm1hdGlvbiBhYm91dCB0aGUgY3VycmVudGx5IGxvZ2dlZCBpbiB1c2VyJ3MgW3BvcnRhbF0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC91c2Vycy1ncm91cHMtYW5kLWl0ZW1zL3BvcnRhbC1zZWxmLmh0bSkuIFN1YnNlcXVlbnQgY2FsbHMgd2lsbCAqbm90KiByZXN1bHQgaW4gYWRkaXRpb25hbCB3ZWIgdHJhZmZpYy5cbiAgICAgKlxuICAgICAqIGBgYGpzXG4gICAgICogc2Vzc2lvbi5nZXRQb3J0YWwoKVxuICAgICAqICAgLnRoZW4ocmVzcG9uc2UgPT4ge1xuICAgICAqICAgICBjb25zb2xlLmxvZyhwb3J0YWwubmFtZSk7IC8vIFwiQ2l0eSBvZiAuLi5cIlxuICAgICAqICAgfSlcbiAgICAgKiBgYGBcbiAgICAgKlxuICAgICAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0LiBOT1RFOiBgcmF3UmVzcG9uc2VgIGlzIG5vdCBzdXBwb3J0ZWQgYnkgdGhpcyBvcGVyYXRpb24uXG4gICAgICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIGRhdGEgZnJvbSB0aGUgcmVzcG9uc2UuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFBvcnRhbCA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBpZiAodGhpcy5fcGVuZGluZ1BvcnRhbFJlcXVlc3QpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nUG9ydGFsUmVxdWVzdDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICh0aGlzLl9wb3J0YWxJbmZvKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMuX3BvcnRhbEluZm8pO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgdmFyIHVybCA9IHRoaXMucG9ydGFsICsgXCIvcG9ydGFscy9zZWxmXCI7XG4gICAgICAgICAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKF9fYXNzaWduKHsgaHR0cE1ldGhvZDogXCJHRVRcIiwgYXV0aGVudGljYXRpb246IHRoaXMgfSwgcmVxdWVzdE9wdGlvbnMpLCB7IHJhd1Jlc3BvbnNlOiBmYWxzZSB9KTtcbiAgICAgICAgICAgIHRoaXMuX3BlbmRpbmdQb3J0YWxSZXF1ZXN0ID0gcmVxdWVzdCh1cmwsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMuX3BvcnRhbEluZm8gPSByZXNwb25zZTtcbiAgICAgICAgICAgICAgICBfdGhpcy5fcGVuZGluZ1BvcnRhbFJlcXVlc3QgPSBudWxsO1xuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdQb3J0YWxSZXF1ZXN0O1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSB1c2VybmFtZSBmb3IgdGhlIGN1cnJlbnRseSBsb2dnZWQgaW4gW3VzZXJdKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3QvdXNlcnMtZ3JvdXBzLWFuZC1pdGVtcy91c2VyLmh0bSkuIFN1YnNlcXVlbnQgY2FsbHMgd2lsbCAqbm90KiByZXN1bHQgaW4gYWRkaXRpb25hbCB3ZWIgdHJhZmZpYy4gVGhpcyBpcyBhbHNvIHVzZWQgaW50ZXJuYWxseSB3aGVuIGEgdXNlcm5hbWUgaXMgcmVxdWlyZWQgZm9yIHNvbWUgcmVxdWVzdHMgYnV0IGlzIG5vdCBwcmVzZW50IGluIHRoZSBvcHRpb25zLlxuICAgICAqXG4gICAgICogICAgKiBgYGBqc1xuICAgICAqIHNlc3Npb24uZ2V0VXNlcm5hbWUoKVxuICAgICAqICAgLnRoZW4ocmVzcG9uc2UgPT4ge1xuICAgICAqICAgICBjb25zb2xlLmxvZyhyZXNwb25zZSk7IC8vIFwiY2FzZXlfam9uZXNcIlxuICAgICAqICAgfSlcbiAgICAgKiBgYGBcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0VXNlcm5hbWUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmICh0aGlzLnVzZXJuYW1lKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMudXNlcm5hbWUpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKHRoaXMuX3VzZXIpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy5fdXNlci51c2VybmFtZSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5nZXRVc2VyKCkudGhlbihmdW5jdGlvbiAodXNlcikge1xuICAgICAgICAgICAgICAgIHJldHVybiB1c2VyLnVzZXJuYW1lO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEdldHMgYW4gYXBwcm9wcmlhdGUgdG9rZW4gZm9yIHRoZSBnaXZlbiBVUkwuIElmIGBwb3J0YWxgIGlzIEFyY0dJUyBPbmxpbmUgYW5kXG4gICAgICogdGhlIHJlcXVlc3QgaXMgdG8gYW4gQXJjR0lTIE9ubGluZSBkb21haW4gYHRva2VuYCB3aWxsIGJlIHVzZWQuIElmIHRoZSByZXF1ZXN0XG4gICAgICogaXMgdG8gdGhlIGN1cnJlbnQgYHBvcnRhbGAgdGhlIGN1cnJlbnQgYHRva2VuYCB3aWxsIGFsc28gYmUgdXNlZC4gSG93ZXZlciBpZlxuICAgICAqIHRoZSByZXF1ZXN0IGlzIHRvIGFuIHVua25vd24gc2VydmVyIHdlIHdpbGwgdmFsaWRhdGUgdGhlIHNlcnZlciB3aXRoIGEgcmVxdWVzdFxuICAgICAqIHRvIG91ciBjdXJyZW50IGBwb3J0YWxgLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRUb2tlbiA9IGZ1bmN0aW9uICh1cmwsIHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIGlmIChjYW5Vc2VPbmxpbmVUb2tlbih0aGlzLnBvcnRhbCwgdXJsKSkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuZ2V0RnJlc2hUb2tlbihyZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAobmV3IFJlZ0V4cCh0aGlzLnBvcnRhbCwgXCJpXCIpLnRlc3QodXJsKSkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuZ2V0RnJlc2hUb2tlbihyZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5nZXRUb2tlbkZvclNlcnZlcih1cmwsIHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgLyoqXG4gICAgICogR2V0IGFwcGxpY2F0aW9uIGFjY2VzcyBpbmZvcm1hdGlvbiBmb3IgdGhlIGN1cnJlbnQgdXNlclxuICAgICAqIHNlZSBgdmFsaWRhdGVBcHBBY2Nlc3NgIGZ1bmN0aW9uIGZvciBkZXRhaWxzXG4gICAgICpcbiAgICAgKiBAcGFyYW0gY2xpZW50SWQgYXBwbGljYXRpb24gY2xpZW50IGlkXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnZhbGlkYXRlQXBwQWNjZXNzID0gZnVuY3Rpb24gKGNsaWVudElkKSB7XG4gICAgICAgIHJldHVybiB0aGlzLmdldFRva2VuKHRoaXMucG9ydGFsKS50aGVuKGZ1bmN0aW9uICh0b2tlbikge1xuICAgICAgICAgICAgcmV0dXJuIHZhbGlkYXRlQXBwQWNjZXNzKHRva2VuLCBjbGllbnRJZCk7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnRvSlNPTiA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIGNsaWVudElkOiB0aGlzLmNsaWVudElkLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuOiB0aGlzLnJlZnJlc2hUb2tlbixcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlbkV4cGlyZXM6IHRoaXMucmVmcmVzaFRva2VuRXhwaXJlcyxcbiAgICAgICAgICAgIHVzZXJuYW1lOiB0aGlzLnVzZXJuYW1lLFxuICAgICAgICAgICAgcGFzc3dvcmQ6IHRoaXMucGFzc3dvcmQsXG4gICAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICAgIHRva2VuRXhwaXJlczogdGhpcy50b2tlbkV4cGlyZXMsXG4gICAgICAgICAgICBwb3J0YWw6IHRoaXMucG9ydGFsLFxuICAgICAgICAgICAgc3NsOiB0aGlzLnNzbCxcbiAgICAgICAgICAgIHRva2VuRHVyYXRpb246IHRoaXMudG9rZW5EdXJhdGlvbixcbiAgICAgICAgICAgIHJlZGlyZWN0VXJpOiB0aGlzLnJlZGlyZWN0VXJpLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuVFRMOiB0aGlzLnJlZnJlc2hUb2tlblRUTCxcbiAgICAgICAgfTtcbiAgICB9O1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5zZXJpYWxpemUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeSh0aGlzKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEZvciBhIFwiSG9zdFwiIGFwcCB0aGF0IGVtYmVkcyBvdGhlciBwbGF0Zm9ybSBhcHBzIHZpYSBpZnJhbWVzLCBhZnRlciBhdXRoZW50aWNhdGluZyB0aGUgdXNlclxuICAgICAqIGFuZCBjcmVhdGluZyBhIFVzZXJTZXNzaW9uLCB0aGUgYXBwIGNhbiB0aGVuIGVuYWJsZSBcInBvc3QgbWVzc2FnZVwiIHN0eWxlIGF1dGhlbnRpY2F0aW9uIGJ5IGNhbGxpbmdcbiAgICAgKiB0aGlzIG1ldGhvZC5cbiAgICAgKlxuICAgICAqIEludGVybmFsbHkgdGhpcyBhZGRzIGFuIGV2ZW50IGxpc3RlbmVyIG9uIHdpbmRvdyBmb3IgdGhlIGBtZXNzYWdlYCBldmVudFxuICAgICAqXG4gICAgICogQHBhcmFtIHZhbGlkQ2hpbGRPcmlnaW5zIEFycmF5IG9mIG9yaWdpbnMgdGhhdCBhcmUgYWxsb3dlZCB0byByZXF1ZXN0IGF1dGhlbnRpY2F0aW9uIGZyb20gdGhlIGhvc3QgYXBwXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmVuYWJsZVBvc3RNZXNzYWdlQXV0aCA9IGZ1bmN0aW9uICh2YWxpZENoaWxkT3JpZ2lucywgd2luKSB7XG4gICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0OiBtdXN0IHBhc3MgaW4gYSBtb2Nrd2luZG93IGZvciB0ZXN0cyBzbyB3ZSBjYW4ndCBjb3ZlciB0aGUgb3RoZXIgYnJhbmNoICovXG4gICAgICAgIGlmICghd2luICYmIHdpbmRvdykge1xuICAgICAgICAgICAgd2luID0gd2luZG93O1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX2hvc3RIYW5kbGVyID0gdGhpcy5jcmVhdGVQb3N0TWVzc2FnZUhhbmRsZXIodmFsaWRDaGlsZE9yaWdpbnMpO1xuICAgICAgICB3aW4uYWRkRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgdGhpcy5faG9zdEhhbmRsZXIsIGZhbHNlKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEZvciBhIFwiSG9zdFwiIGFwcCB0aGF0IGhhcyBlbWJlZGRlZCBvdGhlciBwbGF0Zm9ybSBhcHBzIHZpYSBpZnJhbWVzLCB3aGVuIHRoZSBob3N0IG5lZWRzXG4gICAgICogdG8gdHJhbnNpdGlvbiByb3V0ZXMsIGl0IHNob3VsZCBjYWxsIGBVc2VyU2Vzc2lvbi5kaXNhYmxlUG9zdE1lc3NhZ2VBdXRoKClgIHRvIHJlbW92ZVxuICAgICAqIHRoZSBldmVudCBsaXN0ZW5lciBhbmQgcHJldmVudCBtZW1vcnkgbGVha3NcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZGlzYWJsZVBvc3RNZXNzYWdlQXV0aCA9IGZ1bmN0aW9uICh3aW4pIHtcbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQ6IG11c3QgcGFzcyBpbiBhIG1vY2t3aW5kb3cgZm9yIHRlc3RzIHNvIHdlIGNhbid0IGNvdmVyIHRoZSBvdGhlciBicmFuY2ggKi9cbiAgICAgICAgaWYgKCF3aW4gJiYgd2luZG93KSB7XG4gICAgICAgICAgICB3aW4gPSB3aW5kb3c7XG4gICAgICAgIH1cbiAgICAgICAgd2luLnJlbW92ZUV2ZW50TGlzdGVuZXIoXCJtZXNzYWdlXCIsIHRoaXMuX2hvc3RIYW5kbGVyLCBmYWxzZSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBNYW51YWxseSByZWZyZXNoZXMgdGhlIGN1cnJlbnQgYHRva2VuYCBhbmQgYHRva2VuRXhwaXJlc2AuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnJlZnJlc2hTZXNzaW9uID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIC8vIG1ha2Ugc3VyZSBzdWJzZXF1ZW50IGNhbGxzIHRvIGdldFVzZXIoKSBkb24ndCByZXR1cm5lZCBjYWNoZWQgbWV0YWRhdGFcbiAgICAgICAgdGhpcy5fdXNlciA9IG51bGw7XG4gICAgICAgIGlmICh0aGlzLnVzZXJuYW1lICYmIHRoaXMucGFzc3dvcmQpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnJlZnJlc2hXaXRoVXNlcm5hbWVBbmRQYXNzd29yZChyZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuY2xpZW50SWQgJiYgdGhpcy5yZWZyZXNoVG9rZW4pIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnJlZnJlc2hXaXRoUmVmcmVzaFRva2VuKCk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBBcmNHSVNBdXRoRXJyb3IoXCJVbmFibGUgdG8gcmVmcmVzaCB0b2tlbi5cIikpO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogRGV0ZXJtaW5lcyB0aGUgcm9vdCBvZiB0aGUgQXJjR0lTIFNlcnZlciBvciBQb3J0YWwgZm9yIGEgZ2l2ZW4gVVJMLlxuICAgICAqXG4gICAgICogQHBhcmFtIHVybCB0aGUgVVJsIHRvIGRldGVybWluZSB0aGUgcm9vdCB1cmwgZm9yLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRTZXJ2ZXJSb290VXJsID0gZnVuY3Rpb24gKHVybCkge1xuICAgICAgICB2YXIgcm9vdCA9IGNsZWFuVXJsKHVybCkuc3BsaXQoL1xcL3Jlc3QoXFwvYWRtaW4pP1xcL3NlcnZpY2VzKD86XFwvfCN8XFw/fCQpLylbMF07XG4gICAgICAgIHZhciBfYSA9IHJvb3QubWF0Y2goLyhodHRwcz86XFwvXFwvKSguKykvKSwgbWF0Y2ggPSBfYVswXSwgcHJvdG9jb2wgPSBfYVsxXSwgZG9tYWluQW5kUGF0aCA9IF9hWzJdO1xuICAgICAgICB2YXIgX2IgPSBkb21haW5BbmRQYXRoLnNwbGl0KFwiL1wiKSwgZG9tYWluID0gX2JbMF0sIHBhdGggPSBfYi5zbGljZSgxKTtcbiAgICAgICAgLy8gb25seSB0aGUgZG9tYWluIGlzIGxvd2VyY2FzZWQgYmVjYXVzZSBpbiBzb21lIGNhc2VzIGFuIG9yZyBpZCBtaWdodCBiZVxuICAgICAgICAvLyBpbiB0aGUgcGF0aCB3aGljaCBjYW5ub3QgYmUgbG93ZXJjYXNlZC5cbiAgICAgICAgcmV0dXJuIFwiXCIgKyBwcm90b2NvbCArIGRvbWFpbi50b0xvd2VyQ2FzZSgpICsgXCIvXCIgKyBwYXRoLmpvaW4oXCIvXCIpO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgcHJvcGVyIFtgY3JlZGVudGlhbHNgXSBvcHRpb24gZm9yIGBmZXRjaGAgZm9yIGEgZ2l2ZW4gZG9tYWluLlxuICAgICAqIFNlZSBbdHJ1c3RlZCBzZXJ2ZXJdKGh0dHBzOi8vZW50ZXJwcmlzZS5hcmNnaXMuY29tL2VuL3BvcnRhbC9sYXRlc3QvYWRtaW5pc3Rlci93aW5kb3dzL2NvbmZpZ3VyZS1zZWN1cml0eS5odG0jRVNSSV9TRUNUSU9OMV83MENDMTU5QjM1NDA0NDBBQjMyNUJFNUQ4OURCRTk0QSkuXG4gICAgICogVXNlZCBpbnRlcm5hbGx5IGJ5IHVuZGVybHlpbmcgcmVxdWVzdCBtZXRob2RzIHRvIGFkZCBzdXBwb3J0IGZvciBzcGVjaWZpYyBzZWN1cml0eSBjb25zaWRlcmF0aW9ucy5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB1cmwgVGhlIHVybCBvZiB0aGUgcmVxdWVzdFxuICAgICAqIEByZXR1cm5zIFwiaW5jbHVkZVwiIG9yIFwic2FtZS1vcmlnaW5cIlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXREb21haW5DcmVkZW50aWFscyA9IGZ1bmN0aW9uICh1cmwpIHtcbiAgICAgICAgaWYgKCF0aGlzLnRydXN0ZWREb21haW5zIHx8ICF0aGlzLnRydXN0ZWREb21haW5zLmxlbmd0aCkge1xuICAgICAgICAgICAgcmV0dXJuIFwic2FtZS1vcmlnaW5cIjtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdGhpcy50cnVzdGVkRG9tYWlucy5zb21lKGZ1bmN0aW9uIChkb21haW5XaXRoUHJvdG9jb2wpIHtcbiAgICAgICAgICAgIHJldHVybiB1cmwuc3RhcnRzV2l0aChkb21haW5XaXRoUHJvdG9jb2wpO1xuICAgICAgICB9KVxuICAgICAgICAgICAgPyBcImluY2x1ZGVcIlxuICAgICAgICAgICAgOiBcInNhbWUtb3JpZ2luXCI7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm4gYSBmdW5jdGlvbiB0aGF0IGNsb3NlcyBvdmVyIHRoZSB2YWxpZE9yaWdpbnMgYXJyYXkgYW5kXG4gICAgICogY2FuIGJlIHVzZWQgYXMgYW4gZXZlbnQgaGFuZGxlciBmb3IgdGhlIGBtZXNzYWdlYCBldmVudFxuICAgICAqXG4gICAgICogQHBhcmFtIHZhbGlkT3JpZ2lucyBBcnJheSBvZiB2YWxpZCBvcmlnaW5zXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmNyZWF0ZVBvc3RNZXNzYWdlSGFuZGxlciA9IGZ1bmN0aW9uICh2YWxpZE9yaWdpbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgLy8gcmV0dXJuIGEgZnVuY3Rpb24gdGhhdCBjbG9zZXMgb3ZlciB0aGUgdmFsaWRPcmlnaW5zIGFuZFxuICAgICAgICAvLyBoYXMgYWNjZXNzIHRvIHRoZSBjcmVkZW50aWFsXG4gICAgICAgIHJldHVybiBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgICAgIC8vIFZlcmlmeSB0aGF0IHRoZSBvcmlnaW4gaXMgdmFsaWRcbiAgICAgICAgICAgIC8vIE5vdGU6IGRvIG5vdCB1c2UgcmVnZXgncyBoZXJlLiB2YWxpZE9yaWdpbnMgaXMgYW4gYXJyYXkgc28gd2UncmUgY2hlY2tpbmcgdGhhdCB0aGUgZXZlbnQncyBvcmlnaW5cbiAgICAgICAgICAgIC8vIGlzIGluIHRoZSBhcnJheSB2aWEgZXhhY3QgbWF0Y2guIE1vcmUgaW5mbyBhYm91dCBhdm9pZGluZyBwb3N0TWVzc2FnZSB4c3MgaXNzdWVzIGhlcmVcbiAgICAgICAgICAgIC8vIGh0dHBzOi8vamxhamFyYS5naXRsYWIuaW8vd2ViLzIwMjAvMDcvMTcvRG9tX1hTU19Qb3N0TWVzc2FnZV8yLmh0bWwjdGlwc2J5cGFzc2VzLWluLXBvc3RtZXNzYWdlLXZ1bG5lcmFiaWxpdGllc1xuICAgICAgICAgICAgdmFyIGlzVmFsaWRPcmlnaW4gPSB2YWxpZE9yaWdpbnMuaW5kZXhPZihldmVudC5vcmlnaW4pID4gLTE7XG4gICAgICAgICAgICAvLyBKU0FQSSBoYW5kbGVzIHRoaXMgc2xpZ2h0bHkgZGlmZmVyZW50bHkgLSBpbnN0ZWFkIG9mIGNoZWNraW5nIGEgbGlzdCwgaXQgd2lsbCByZXNwb25kIGlmXG4gICAgICAgICAgICAvLyBldmVudC5vcmlnaW4gPT09IHdpbmRvdy5sb2NhdGlvbi5vcmlnaW4gfHwgZXZlbnQub3JpZ2luLmVuZHNXaXRoKCcuYXJjZ2lzLmNvbScpXG4gICAgICAgICAgICAvLyBGb3IgSHViLCBhbmQgdG8gZW5hYmxlIGNyb3NzIGRvbWFpbiBkZWJ1Z2dpbmcgd2l0aCBwb3J0J3MgaW4gdXJscywgd2UgYXJlIG9wdGluZyB0b1xuICAgICAgICAgICAgLy8gdXNlIGEgbGlzdCBvZiB2YWxpZCBvcmlnaW5zXG4gICAgICAgICAgICAvLyBFbnN1cmUgdGhlIG1lc3NhZ2UgdHlwZSBpcyBzb21ldGhpbmcgd2Ugd2FudCB0byBoYW5kbGVcbiAgICAgICAgICAgIHZhciBpc1ZhbGlkVHlwZSA9IGV2ZW50LmRhdGEudHlwZSA9PT0gXCJhcmNnaXM6YXV0aDpyZXF1ZXN0Q3JlZGVudGlhbFwiO1xuICAgICAgICAgICAgdmFyIGlzVG9rZW5WYWxpZCA9IF90aGlzLnRva2VuRXhwaXJlcy5nZXRUaW1lKCkgPiBEYXRlLm5vdygpO1xuICAgICAgICAgICAgaWYgKGlzVmFsaWRPcmlnaW4gJiYgaXNWYWxpZFR5cGUpIHtcbiAgICAgICAgICAgICAgICB2YXIgbXNnID0ge307XG4gICAgICAgICAgICAgICAgaWYgKGlzVG9rZW5WYWxpZCkge1xuICAgICAgICAgICAgICAgICAgICB2YXIgY3JlZGVudGlhbCA9IF90aGlzLnRvQ3JlZGVudGlhbCgpO1xuICAgICAgICAgICAgICAgICAgICAvLyBhcmNnaXM6YXV0aDplcnJvciB3aXRoIHtuYW1lOiBcIlwiLCBtZXNzYWdlOiBcIlwifVxuICAgICAgICAgICAgICAgICAgICAvLyB0aGUgZm9sbG93aW5nIGxpbmUgYWxsb3dzIHVzIHRvIGNvbmZvcm0gdG8gb3VyIHNwZWMgd2l0aG91dCBjaGFuZ2luZyBvdGhlciBkZXBlbmRlZC1vbiBmdW5jdGlvbmFsaXR5XG4gICAgICAgICAgICAgICAgICAgIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9Fc3JpL2FyY2dpcy1yZXN0LWpzL2Jsb2IvbWFzdGVyL3BhY2thZ2VzL2FyY2dpcy1yZXN0LWF1dGgvcG9zdC1tZXNzYWdlLWF1dGgtc3BlYy5tZCNhcmNnaXNhdXRoY3JlZGVudGlhbFxuICAgICAgICAgICAgICAgICAgICBjcmVkZW50aWFsLnNlcnZlciA9IGNyZWRlbnRpYWwuc2VydmVyLnJlcGxhY2UoXCIvc2hhcmluZy9yZXN0XCIsIFwiXCIpO1xuICAgICAgICAgICAgICAgICAgICBtc2cgPSB7IHR5cGU6IFwiYXJjZ2lzOmF1dGg6Y3JlZGVudGlhbFwiLCBjcmVkZW50aWFsOiBjcmVkZW50aWFsIH07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAvLyBSZXR1cm4gYW4gZXJyb3JcbiAgICAgICAgICAgICAgICAgICAgbXNnID0ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdHlwZTogXCJhcmNnaXM6YXV0aDplcnJvclwiLFxuICAgICAgICAgICAgICAgICAgICAgICAgZXJyb3I6IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBuYW1lOiBcInRva2VuRXhwaXJlZEVycm9yXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbWVzc2FnZTogXCJTZXNzaW9uIHRva2VuIHdhcyBleHBpcmVkLCBhbmQgbm90IHJldHVybmVkIHRvIHRoZSBjaGlsZCBhcHBsaWNhdGlvblwiLFxuICAgICAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZXZlbnQuc291cmNlLnBvc3RNZXNzYWdlKG1zZywgZXZlbnQub3JpZ2luKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFZhbGlkYXRlcyB0aGF0IGEgZ2l2ZW4gVVJMIGlzIHByb3Blcmx5IGZlZGVyYXRlZCB3aXRoIG91ciBjdXJyZW50IGBwb3J0YWxgLlxuICAgICAqIEF0dGVtcHRzIHRvIHVzZSB0aGUgaW50ZXJuYWwgYGZlZGVyYXRlZFNlcnZlcnNgIGNhY2hlIGZpcnN0LlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRUb2tlbkZvclNlcnZlciA9IGZ1bmN0aW9uICh1cmwsIHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIC8vIHJlcXVlc3RzIHRvIC9yZXN0L3NlcnZpY2VzLyBhbmQgL3Jlc3QvYWRtaW4vc2VydmljZXMvIGFyZSBib3RoIHZhbGlkXG4gICAgICAgIC8vIEZlZGVyYXRlZCBzZXJ2ZXJzIG1heSBoYXZlIGluY29uc2lzdGVudCBjYXNpbmcsIHNvIGxvd2VyQ2FzZSBpdFxuICAgICAgICB2YXIgcm9vdCA9IHRoaXMuZ2V0U2VydmVyUm9vdFVybCh1cmwpO1xuICAgICAgICB2YXIgZXhpc3RpbmdUb2tlbiA9IHRoaXMuZmVkZXJhdGVkU2VydmVyc1tyb290XTtcbiAgICAgICAgaWYgKGV4aXN0aW5nVG9rZW4gJiZcbiAgICAgICAgICAgIGV4aXN0aW5nVG9rZW4uZXhwaXJlcyAmJlxuICAgICAgICAgICAgZXhpc3RpbmdUb2tlbi5leHBpcmVzLmdldFRpbWUoKSA+IERhdGUubm93KCkpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoZXhpc3RpbmdUb2tlbi50b2tlbik7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3Jvb3RdKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbcm9vdF07XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbcm9vdF0gPSB0aGlzLmZldGNoQXV0aG9yaXplZERvbWFpbnMoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiByZXF1ZXN0KHJvb3QgKyBcIi9yZXN0L2luZm9cIiwge1xuICAgICAgICAgICAgICAgIGNyZWRlbnRpYWxzOiBfdGhpcy5nZXREb21haW5DcmVkZW50aWFscyh1cmwpLFxuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2Uub3duaW5nU3lzdGVtVXJsKSB7XG4gICAgICAgICAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICAgICAgICAgKiBpZiB0aGlzIHNlcnZlciBpcyBub3Qgb3duZWQgYnkgdGhpcyBwb3J0YWxcbiAgICAgICAgICAgICAgICAgICAgICogYmFpbCBvdXQgd2l0aCBhbiBlcnJvciBzaW5jZSB3ZSBrbm93IHdlIHdvbnRcbiAgICAgICAgICAgICAgICAgICAgICogYmUgYWJsZSB0byBnZW5lcmF0ZSBhIHRva2VuXG4gICAgICAgICAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgICAgICAgICBpZiAoIWlzRmVkZXJhdGVkKHJlc3BvbnNlLm93bmluZ1N5c3RlbVVybCwgX3RoaXMucG9ydGFsKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEFyY0dJU0F1dGhFcnJvcih1cmwgKyBcIiBpcyBub3QgZmVkZXJhdGVkIHdpdGggXCIgKyBfdGhpcy5wb3J0YWwgKyBcIi5cIiwgXCJOT1RfRkVERVJBVEVEXCIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgICAgICAgICAgICAgKiBpZiB0aGUgc2VydmVyIGlzIGZlZGVyYXRlZCwgdXNlIHRoZSByZWxldmFudCB0b2tlbiBlbmRwb2ludC5cbiAgICAgICAgICAgICAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJlcXVlc3QocmVzcG9uc2Uub3duaW5nU3lzdGVtVXJsICsgXCIvc2hhcmluZy9yZXN0L2luZm9cIiwgcmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYgKHJlc3BvbnNlLmF1dGhJbmZvICYmXG4gICAgICAgICAgICAgICAgICAgIF90aGlzLmZlZGVyYXRlZFNlcnZlcnNbcm9vdF0gIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAgICAgICAgICogaWYgaXRzIGEgc3RhbmQtYWxvbmUgaW5zdGFuY2Ugb2YgQXJjR0lTIFNlcnZlciB0aGF0IGRvZXNuJ3QgYWR2ZXJ0aXNlXG4gICAgICAgICAgICAgICAgICAgICAqIGZlZGVyYXRpb24sIGJ1dCB0aGUgcm9vdCBzZXJ2ZXIgdXJsIGlzIHJlY29nbml6ZWQsIHVzZSBpdHMgYnVpbHQgaW4gdG9rZW4gZW5kcG9pbnQuXG4gICAgICAgICAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGF1dGhJbmZvOiByZXNwb25zZS5hdXRoSW5mbyxcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgQXJjR0lTQXV0aEVycm9yKHVybCArIFwiIGlzIG5vdCBmZWRlcmF0ZWQgd2l0aCBhbnkgcG9ydGFsIGFuZCBpcyBub3QgZXhwbGljaXRseSB0cnVzdGVkLlwiLCBcIk5PVF9GRURFUkFURURcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuYXV0aEluZm8udG9rZW5TZXJ2aWNlc1VybDtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHRva2VuU2VydmljZXNVcmwpIHtcbiAgICAgICAgICAgICAgICAvLyBhbiBleHBpcmVkIHRva2VuIGNhbnQgYmUgdXNlZCB0byBnZW5lcmF0ZSBhIG5ldyB0b2tlblxuICAgICAgICAgICAgICAgIGlmIChfdGhpcy50b2tlbiAmJiBfdGhpcy50b2tlbkV4cGlyZXMuZ2V0VGltZSgpID4gRGF0ZS5ub3coKSkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZ2VuZXJhdGVUb2tlbih0b2tlblNlcnZpY2VzVXJsLCB7XG4gICAgICAgICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlbjogX3RoaXMudG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc2VydmVyVXJsOiB1cmwsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhwaXJhdGlvbjogX3RoaXMudG9rZW5EdXJhdGlvbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjbGllbnQ6IFwicmVmZXJlclwiLFxuICAgICAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIC8vIGdlbmVyYXRlIGFuIGVudGlyZWx5IGZyZXNoIHRva2VuIGlmIG5lY2Vzc2FyeVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGdlbmVyYXRlVG9rZW4odG9rZW5TZXJ2aWNlc1VybCwge1xuICAgICAgICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdXNlcm5hbWU6IF90aGlzLnVzZXJuYW1lLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhc3N3b3JkOiBfdGhpcy5wYXNzd29yZCxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBleHBpcmF0aW9uOiBfdGhpcy50b2tlbkR1cmF0aW9uLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNsaWVudDogXCJyZWZlcmVyXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICB9KS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuX3Rva2VuID0gcmVzcG9uc2UudG9rZW47XG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5fdG9rZW5FeHBpcmVzID0gbmV3IERhdGUocmVzcG9uc2UuZXhwaXJlcyk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMuZmVkZXJhdGVkU2VydmVyc1tyb290XSA9IHtcbiAgICAgICAgICAgICAgICAgICAgZXhwaXJlczogbmV3IERhdGUocmVzcG9uc2UuZXhwaXJlcyksXG4gICAgICAgICAgICAgICAgICAgIHRva2VuOiByZXNwb25zZS50b2tlbixcbiAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICAgIGRlbGV0ZSBfdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbcm9vdF07XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLnRva2VuO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbcm9vdF07XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIGFuIHVuZXhwaXJlZCB0b2tlbiBmb3IgdGhlIGN1cnJlbnQgYHBvcnRhbGAuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldEZyZXNoVG9rZW4gPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgaWYgKHRoaXMudG9rZW4gJiYgIXRoaXMudG9rZW5FeHBpcmVzKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMudG9rZW4pO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLnRva2VuICYmXG4gICAgICAgICAgICB0aGlzLnRva2VuRXhwaXJlcyAmJlxuICAgICAgICAgICAgdGhpcy50b2tlbkV4cGlyZXMuZ2V0VGltZSgpID4gRGF0ZS5ub3coKSkge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzLnRva2VuKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3RoaXMucG9ydGFsXSkge1xuICAgICAgICAgICAgdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbdGhpcy5wb3J0YWxdID0gdGhpcy5yZWZyZXNoU2Vzc2lvbihyZXF1ZXN0T3B0aW9ucykudGhlbihmdW5jdGlvbiAoc2Vzc2lvbikge1xuICAgICAgICAgICAgICAgIF90aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tfdGhpcy5wb3J0YWxdID0gbnVsbDtcbiAgICAgICAgICAgICAgICByZXR1cm4gc2Vzc2lvbi50b2tlbjtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1t0aGlzLnBvcnRhbF07XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZWZyZXNoZXMgdGhlIGN1cnJlbnQgYHRva2VuYCBhbmQgYHRva2VuRXhwaXJlc2Agd2l0aCBgdXNlcm5hbWVgIGFuZFxuICAgICAqIGBwYXNzd29yZGAuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnJlZnJlc2hXaXRoVXNlcm5hbWVBbmRQYXNzd29yZCA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKHsgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgdXNlcm5hbWU6IHRoaXMudXNlcm5hbWUsXG4gICAgICAgICAgICAgICAgcGFzc3dvcmQ6IHRoaXMucGFzc3dvcmQsXG4gICAgICAgICAgICAgICAgZXhwaXJhdGlvbjogdGhpcy50b2tlbkR1cmF0aW9uLFxuICAgICAgICAgICAgfSB9LCByZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIHJldHVybiBnZW5lcmF0ZVRva2VuKHRoaXMucG9ydGFsICsgXCIvZ2VuZXJhdGVUb2tlblwiLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgX3RoaXMuX3Rva2VuID0gcmVzcG9uc2UudG9rZW47XG4gICAgICAgICAgICBfdGhpcy5fdG9rZW5FeHBpcmVzID0gbmV3IERhdGUocmVzcG9uc2UuZXhwaXJlcyk7XG4gICAgICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogUmVmcmVzaGVzIHRoZSBjdXJyZW50IGB0b2tlbmAgYW5kIGB0b2tlbkV4cGlyZXNgIHdpdGggYHJlZnJlc2hUb2tlbmAuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnJlZnJlc2hXaXRoUmVmcmVzaFRva2VuID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIGlmICh0aGlzLnJlZnJlc2hUb2tlbiAmJlxuICAgICAgICAgICAgdGhpcy5yZWZyZXNoVG9rZW5FeHBpcmVzICYmXG4gICAgICAgICAgICB0aGlzLnJlZnJlc2hUb2tlbkV4cGlyZXMuZ2V0VGltZSgpIDwgRGF0ZS5ub3coKSkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMucmVmcmVzaFJlZnJlc2hUb2tlbihyZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbih7IHBhcmFtczoge1xuICAgICAgICAgICAgICAgIGNsaWVudF9pZDogdGhpcy5jbGllbnRJZCxcbiAgICAgICAgICAgICAgICByZWZyZXNoX3Rva2VuOiB0aGlzLnJlZnJlc2hUb2tlbixcbiAgICAgICAgICAgICAgICBncmFudF90eXBlOiBcInJlZnJlc2hfdG9rZW5cIixcbiAgICAgICAgICAgIH0gfSwgcmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICByZXR1cm4gZmV0Y2hUb2tlbih0aGlzLnBvcnRhbCArIFwiL29hdXRoMi90b2tlblwiLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgX3RoaXMuX3Rva2VuID0gcmVzcG9uc2UudG9rZW47XG4gICAgICAgICAgICBfdGhpcy5fdG9rZW5FeHBpcmVzID0gcmVzcG9uc2UuZXhwaXJlcztcbiAgICAgICAgICAgIHJldHVybiBfdGhpcztcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBFeGNoYW5nZXMgYW4gdW5leHBpcmVkIGByZWZyZXNoVG9rZW5gIGZvciBhIG5ldyBvbmUsIGFsc28gdXBkYXRlcyBgdG9rZW5gIGFuZFxuICAgICAqIGB0b2tlbkV4cGlyZXNgLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5yZWZyZXNoUmVmcmVzaFRva2VuID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oeyBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICBjbGllbnRfaWQ6IHRoaXMuY2xpZW50SWQsXG4gICAgICAgICAgICAgICAgcmVmcmVzaF90b2tlbjogdGhpcy5yZWZyZXNoVG9rZW4sXG4gICAgICAgICAgICAgICAgcmVkaXJlY3RfdXJpOiB0aGlzLnJlZGlyZWN0VXJpLFxuICAgICAgICAgICAgICAgIGdyYW50X3R5cGU6IFwiZXhjaGFuZ2VfcmVmcmVzaF90b2tlblwiLFxuICAgICAgICAgICAgfSB9LCByZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIHJldHVybiBmZXRjaFRva2VuKHRoaXMucG9ydGFsICsgXCIvb2F1dGgyL3Rva2VuXCIsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICBfdGhpcy5fdG9rZW4gPSByZXNwb25zZS50b2tlbjtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbkV4cGlyZXMgPSByZXNwb25zZS5leHBpcmVzO1xuICAgICAgICAgICAgX3RoaXMuX3JlZnJlc2hUb2tlbiA9IHJlc3BvbnNlLnJlZnJlc2hUb2tlbjtcbiAgICAgICAgICAgIF90aGlzLl9yZWZyZXNoVG9rZW5FeHBpcmVzID0gbmV3IERhdGUoRGF0ZS5ub3coKSArIChfdGhpcy5yZWZyZXNoVG9rZW5UVEwgLSAxKSAqIDYwICogMTAwMCk7XG4gICAgICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogZW5zdXJlcyB0aGF0IHRoZSBhdXRob3JpemVkQ3Jvc3NPcmlnaW5Eb21haW5zIGFyZSBvYnRhaW5lZCBmcm9tIHRoZSBwb3J0YWwgYW5kIGNhY2hlZFxuICAgICAqIHNvIHdlIGNhbiBjaGVjayB0aGVtIGxhdGVyLlxuICAgICAqXG4gICAgICogQHJldHVybnMgdGhpc1xuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5mZXRjaEF1dGhvcml6ZWREb21haW5zID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICAvLyBpZiB0aGlzIHRva2VuIGlzIGZvciBhIHNwZWNpZmljIHNlcnZlciBvciB3ZSBkb24ndCBoYXZlIGEgcG9ydGFsXG4gICAgICAgIC8vIGRvbid0IGdldCB0aGUgcG9ydGFsIGluZm8gYmVjYXVzZSB3ZSBjYW50IGdldCB0aGUgYXV0aG9yaXplZENyb3NzT3JpZ2luRG9tYWluc1xuICAgICAgICBpZiAodGhpcy5zZXJ2ZXIgfHwgIXRoaXMucG9ydGFsKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0aGlzLmdldFBvcnRhbCgpLnRoZW4oZnVuY3Rpb24gKHBvcnRhbEluZm8pIHtcbiAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICogU3BlY2lmaWMgZG9tYWlucyBjYW4gYmUgY29uZmlndXJlZCBhcyBzZWN1cmUuZXNyaS5jb20gb3IgaHR0cHM6Ly9zZWN1cmUuZXNyaS5jb20gdGhpc1xuICAgICAgICAgICAgICogbm9ybWFsaXplcyB0byBodHRwczovL3NlY3VyZS5lc3JpLmNvbSBzbyB3ZSBjYW4gdXNlIHN0YXJ0c1dpdGggbGF0ZXIuXG4gICAgICAgICAgICAgKi9cbiAgICAgICAgICAgIGlmIChwb3J0YWxJbmZvLmF1dGhvcml6ZWRDcm9zc09yaWdpbkRvbWFpbnMgJiZcbiAgICAgICAgICAgICAgICBwb3J0YWxJbmZvLmF1dGhvcml6ZWRDcm9zc09yaWdpbkRvbWFpbnMubGVuZ3RoKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMudHJ1c3RlZERvbWFpbnMgPSBwb3J0YWxJbmZvLmF1dGhvcml6ZWRDcm9zc09yaWdpbkRvbWFpbnNcbiAgICAgICAgICAgICAgICAgICAgLmZpbHRlcihmdW5jdGlvbiAoZCkgeyByZXR1cm4gIWQuc3RhcnRzV2l0aChcImh0dHA6Ly9cIik7IH0pXG4gICAgICAgICAgICAgICAgICAgIC5tYXAoZnVuY3Rpb24gKGQpIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGQuc3RhcnRzV2l0aChcImh0dHBzOi8vXCIpKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImh0dHBzOi8vXCIgKyBkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgcmV0dXJuIFVzZXJTZXNzaW9uO1xufSgpKTtcbmV4cG9ydCB7IFVzZXJTZXNzaW9uIH07XG4vLyMgc291cmNlTWFwcGluZ1VSTD1Vc2VyU2Vzc2lvbi5qcy5tYXAiLCJpbXBvcnQgeyBjbGVhblVybCB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqIFVzZWQgdG8gdGVzdCBpZiBhIFVSTCBpcyBhbiBBcmNHSVMgT25saW5lIFVSTFxuICovXG52YXIgYXJjZ2lzT25saW5lVXJsUmVnZXggPSAvXmh0dHBzPzpcXC9cXC8oXFxTKylcXC5hcmNnaXNcXC5jb20uKy87XG4vKipcbiAqIFVzZWQgdG8gdGVzdCBpZiBhIFVSTCBpcyBwcm9kdWN0aW9uIEFyY0dJUyBPbmxpbmUgUG9ydGFsXG4gKi9cbnZhciBhcmNnaXNPbmxpbmVQb3J0YWxSZWdleCA9IC9eaHR0cHM/OlxcL1xcLyhkZXZ8ZGV2ZXh0fHFhfHFhZXh0fHd3dylcXC5hcmNnaXNcXC5jb21cXC9zaGFyaW5nXFwvcmVzdCsvO1xuLyoqXG4gKiBVc2VkIHRvIHRlc3QgaWYgYSBVUkwgaXMgYW4gQXJjR0lTIE9ubGluZSBPcmdhbml6YXRpb24gUG9ydGFsXG4gKi9cbnZhciBhcmNnaXNPbmxpbmVPcmdQb3J0YWxSZWdleCA9IC9eaHR0cHM/OlxcL1xcLyg/OlthLXowLTktXStcXC5tYXBzKGRldnxkZXZleHR8cWF8cWFleHQpPyk/LmFyY2dpc1xcLmNvbVxcL3NoYXJpbmdcXC9yZXN0LztcbmV4cG9ydCBmdW5jdGlvbiBpc09ubGluZSh1cmwpIHtcbiAgICByZXR1cm4gYXJjZ2lzT25saW5lVXJsUmVnZXgudGVzdCh1cmwpO1xufVxuZXhwb3J0IGZ1bmN0aW9uIG5vcm1hbGl6ZU9ubGluZVBvcnRhbFVybChwb3J0YWxVcmwpIHtcbiAgICBpZiAoIWFyY2dpc09ubGluZVVybFJlZ2V4LnRlc3QocG9ydGFsVXJsKSkge1xuICAgICAgICByZXR1cm4gcG9ydGFsVXJsO1xuICAgIH1cbiAgICBzd2l0Y2ggKGdldE9ubGluZUVudmlyb25tZW50KHBvcnRhbFVybCkpIHtcbiAgICAgICAgY2FzZSBcImRldlwiOlxuICAgICAgICAgICAgcmV0dXJuIFwiaHR0cHM6Ly9kZXZleHQuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIjtcbiAgICAgICAgY2FzZSBcInFhXCI6XG4gICAgICAgICAgICByZXR1cm4gXCJodHRwczovL3FhZXh0LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCI7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICByZXR1cm4gXCJodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiO1xuICAgIH1cbn1cbmV4cG9ydCBmdW5jdGlvbiBnZXRPbmxpbmVFbnZpcm9ubWVudCh1cmwpIHtcbiAgICBpZiAoIWFyY2dpc09ubGluZVVybFJlZ2V4LnRlc3QodXJsKSkge1xuICAgICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG4gICAgdmFyIG1hdGNoID0gdXJsLm1hdGNoKGFyY2dpc09ubGluZVVybFJlZ2V4KTtcbiAgICB2YXIgc3ViZG9tYWluID0gbWF0Y2hbMV0uc3BsaXQoXCIuXCIpLnBvcCgpO1xuICAgIGlmIChzdWJkb21haW4uaW5jbHVkZXMoXCJkZXZcIikpIHtcbiAgICAgICAgcmV0dXJuIFwiZGV2XCI7XG4gICAgfVxuICAgIGlmIChzdWJkb21haW4uaW5jbHVkZXMoXCJxYVwiKSkge1xuICAgICAgICByZXR1cm4gXCJxYVwiO1xuICAgIH1cbiAgICByZXR1cm4gXCJwcm9kdWN0aW9uXCI7XG59XG5leHBvcnQgZnVuY3Rpb24gaXNGZWRlcmF0ZWQob3duaW5nU3lzdGVtVXJsLCBwb3J0YWxVcmwpIHtcbiAgICB2YXIgbm9ybWFsaXplZFBvcnRhbFVybCA9IGNsZWFuVXJsKG5vcm1hbGl6ZU9ubGluZVBvcnRhbFVybChwb3J0YWxVcmwpKS5yZXBsYWNlKC9odHRwcz86XFwvXFwvLywgXCJcIik7XG4gICAgdmFyIG5vcm1hbGl6ZWRPd25pbmdTeXN0ZW1VcmwgPSBjbGVhblVybChvd25pbmdTeXN0ZW1VcmwpLnJlcGxhY2UoL2h0dHBzPzpcXC9cXC8vLCBcIlwiKTtcbiAgICByZXR1cm4gbmV3IFJlZ0V4cChub3JtYWxpemVkT3duaW5nU3lzdGVtVXJsLCBcImlcIikudGVzdChub3JtYWxpemVkUG9ydGFsVXJsKTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBjYW5Vc2VPbmxpbmVUb2tlbihwb3J0YWxVcmwsIHJlcXVlc3RVcmwpIHtcbiAgICB2YXIgcG9ydGFsSXNPbmxpbmUgPSBpc09ubGluZShwb3J0YWxVcmwpO1xuICAgIHZhciByZXF1ZXN0SXNPbmxpbmUgPSBpc09ubGluZShyZXF1ZXN0VXJsKTtcbiAgICB2YXIgcG9ydGFsRW52ID0gZ2V0T25saW5lRW52aXJvbm1lbnQocG9ydGFsVXJsKTtcbiAgICB2YXIgcmVxdWVzdEVudiA9IGdldE9ubGluZUVudmlyb25tZW50KHJlcXVlc3RVcmwpO1xuICAgIGlmIChwb3J0YWxJc09ubGluZSAmJiByZXF1ZXN0SXNPbmxpbmUgJiYgcG9ydGFsRW52ID09PSByZXF1ZXN0RW52KSB7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cbiAgICByZXR1cm4gZmFsc2U7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1mZWRlcmF0aW9uLXV0aWxzLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyByZXF1ZXN0IH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbmV4cG9ydCBmdW5jdGlvbiBmZXRjaFRva2VuKHVybCwgcmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgb3B0aW9ucyA9IHJlcXVlc3RPcHRpb25zO1xuICAgIC8vIHdlIGdlbmVyYXRlIGEgcmVzcG9uc2UsIHNvIHdlIGNhbid0IHJldHVybiB0aGUgcmF3IHJlc3BvbnNlXG4gICAgb3B0aW9ucy5yYXdSZXNwb25zZSA9IGZhbHNlO1xuICAgIHJldHVybiByZXF1ZXN0KHVybCwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdmFyIHIgPSB7XG4gICAgICAgICAgICB0b2tlbjogcmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxuICAgICAgICAgICAgdXNlcm5hbWU6IHJlc3BvbnNlLnVzZXJuYW1lLFxuICAgICAgICAgICAgZXhwaXJlczogbmV3IERhdGUoXG4gICAgICAgICAgICAvLyBjb252ZXJ0IHNlY29uZHMgaW4gcmVzcG9uc2UgdG8gbWlsbGlzZWNvbmRzIGFuZCBhZGQgdGhlIHZhbHVlIHRvIHRoZSBjdXJyZW50IHRpbWUgdG8gY2FsY3VsYXRlIGEgc3RhdGljIGV4cGlyYXRpb24gdGltZXN0YW1wXG4gICAgICAgICAgICBEYXRlLm5vdygpICsgKHJlc3BvbnNlLmV4cGlyZXNfaW4gKiAxMDAwIC0gMTAwMCkpLFxuICAgICAgICAgICAgc3NsOiByZXNwb25zZS5zc2wgPT09IHRydWVcbiAgICAgICAgfTtcbiAgICAgICAgaWYgKHJlc3BvbnNlLnJlZnJlc2hfdG9rZW4pIHtcbiAgICAgICAgICAgIHIucmVmcmVzaFRva2VuID0gcmVzcG9uc2UucmVmcmVzaF90b2tlbjtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcjtcbiAgICB9KTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWZldGNoLXRva2VuLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IHJlcXVlc3QsIE5PREVKU19ERUZBVUxUX1JFRkVSRVJfSEVBREVSLCB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG5leHBvcnQgZnVuY3Rpb24gZ2VuZXJhdGVUb2tlbih1cmwsIHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIG9wdGlvbnMgPSByZXF1ZXN0T3B0aW9ucztcbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgZWxzZSAqL1xuICAgIGlmICh0eXBlb2Ygd2luZG93ICE9PSBcInVuZGVmaW5lZFwiICYmXG4gICAgICAgIHdpbmRvdy5sb2NhdGlvbiAmJlxuICAgICAgICB3aW5kb3cubG9jYXRpb24uaG9zdCkge1xuICAgICAgICBvcHRpb25zLnBhcmFtcy5yZWZlcmVyID0gd2luZG93LmxvY2F0aW9uLmhvc3Q7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBvcHRpb25zLnBhcmFtcy5yZWZlcmVyID0gTk9ERUpTX0RFRkFVTFRfUkVGRVJFUl9IRUFERVI7XG4gICAgfVxuICAgIHJldHVybiByZXF1ZXN0KHVybCwgb3B0aW9ucyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1nZW5lcmF0ZS10b2tlbi5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTgtMjAyMCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyByZXF1ZXN0IH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICogVmFsaWRhdGVzIHRoYXQgdGhlIHVzZXIgaGFzIGFjY2VzcyB0byB0aGUgYXBwbGljYXRpb25cbiAqIGFuZCBpZiB0aGV5IHVzZXIgc2hvdWxkIGJlIHByZXNlbnRlZCBhIFwiVmlldyBPbmx5XCIgbW9kZVxuICpcbiAqIFRoaXMgaXMgb25seSBuZWVkZWQvdmFsaWQgZm9yIEVzcmkgYXBwbGljYXRpb25zIHRoYXQgYXJlIFwibGljZW5zZWRcIlxuICogYW5kIHNoaXBwZWQgaW4gQXJjR0lTIE9ubGluZSBvciBBcmNHSVMgRW50ZXJwcmlzZS4gTW9zdCBjdXN0b20gYXBwbGljYXRpb25zXG4gKiBzaG91bGQgbm90IG5lZWQgb3IgdXNlIHRoaXMuXG4gKlxuICogYGBganNcbiAqIGltcG9ydCB7IHZhbGlkYXRlQXBwQWNjZXNzIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aCc7XG4gKlxuICogcmV0dXJuIHZhbGlkYXRlQXBwQWNjZXNzKCd5b3VyLXRva2VuJywgJ3RoZUNsaWVudElkJylcbiAqIC50aGVuKChyZXN1bHQpID0+IHtcbiAqICAgIGlmICghcmVzdWx0LnZhbHVlKSB7XG4gKiAgICAgIC8vIHJlZGlyZWN0IG9yIHNob3cgc29tZSBvdGhlciB1aVxuICogICAgfSBlbHNlIHtcbiAqICAgICAgaWYgKHJlc3VsdC52aWV3T25seVVzZXJUeXBlQXBwKSB7XG4gKiAgICAgICAgLy8gdXNlIHRoaXMgdG8gaW5mb3JtIHlvdXIgYXBwIHRvIHNob3cgYSBcIlZpZXcgT25seVwiIG1vZGVcbiAqICAgICAgfVxuICogICAgfVxuICogfSlcbiAqIC5jYXRjaCgoZXJyKSA9PiB7XG4gKiAgLy8gdHdvIHBvc3NpYmxlIGVycm9yc1xuICogIC8vIGludmFsaWQgY2xpZW50SWQ6IHtcImVycm9yXCI6e1wiY29kZVwiOjQwMCxcIm1lc3NhZ2VDb2RlXCI6XCJHV01fMDAwN1wiLFwibWVzc2FnZVwiOlwiSW52YWxpZCByZXF1ZXN0XCIsXCJkZXRhaWxzXCI6W119fVxuICogIC8vIGludmFsaWQgdG9rZW46IHtcImVycm9yXCI6e1wiY29kZVwiOjQ5OCxcIm1lc3NhZ2VcIjpcIkludmFsaWQgdG9rZW4uXCIsXCJkZXRhaWxzXCI6W119fVxuICogfSlcbiAqIGBgYFxuICpcbiAqIE5vdGU6IFRoaXMgaXMgb25seSB1c2FibGUgYnkgRXNyaSBhcHBsaWNhdGlvbnMgaG9zdGVkIG9uICphcmNnaXMuY29tLCAqZXNyaS5jb20gb3Igd2l0aGluXG4gKiBhbiBBcmNHSVMgRW50ZXJwcmlzZSBpbnN0YWxsYXRpb24uIEN1c3RvbSBhcHBsaWNhdGlvbnMgY2FuIG5vdCB1c2UgdGhpcy5cbiAqXG4gKiBAcGFyYW0gdG9rZW4gcGxhdGZvcm0gdG9rZW5cbiAqIEBwYXJhbSBjbGllbnRJZCBhcHBsaWNhdGlvbiBjbGllbnQgaWRcbiAqIEBwYXJhbSBwb3J0YWwgT3B0aW9uYWxcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHZhbGlkYXRlQXBwQWNjZXNzKHRva2VuLCBjbGllbnRJZCwgcG9ydGFsKSB7XG4gICAgaWYgKHBvcnRhbCA9PT0gdm9pZCAwKSB7IHBvcnRhbCA9IFwiaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIjsgfVxuICAgIHZhciB1cmwgPSBwb3J0YWwgKyBcIi9vYXV0aDIvdmFsaWRhdGVBcHBBY2Nlc3NcIjtcbiAgICB2YXIgcm8gPSB7XG4gICAgICAgIG1ldGhvZDogXCJQT1NUXCIsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgZjogXCJqc29uXCIsXG4gICAgICAgICAgICBjbGllbnRfaWQ6IGNsaWVudElkLFxuICAgICAgICAgICAgdG9rZW46IHRva2VuLFxuICAgICAgICB9LFxuICAgIH07XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBybyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD12YWxpZGF0ZS1hcHAtYWNjZXNzLmpzLm1hcCIsIi8qISAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxyXG5Db3B5cmlnaHQgKGMpIE1pY3Jvc29mdCBDb3Jwb3JhdGlvbi5cclxuXHJcblBlcm1pc3Npb24gdG8gdXNlLCBjb3B5LCBtb2RpZnksIGFuZC9vciBkaXN0cmlidXRlIHRoaXMgc29mdHdhcmUgZm9yIGFueVxyXG5wdXJwb3NlIHdpdGggb3Igd2l0aG91dCBmZWUgaXMgaGVyZWJ5IGdyYW50ZWQuXHJcblxyXG5USEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiIEFORCBUSEUgQVVUSE9SIERJU0NMQUlNUyBBTEwgV0FSUkFOVElFUyBXSVRIXHJcblJFR0FSRCBUTyBUSElTIFNPRlRXQVJFIElOQ0xVRElORyBBTEwgSU1QTElFRCBXQVJSQU5USUVTIE9GIE1FUkNIQU5UQUJJTElUWVxyXG5BTkQgRklUTkVTUy4gSU4gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUiBCRSBMSUFCTEUgRk9SIEFOWSBTUEVDSUFMLCBESVJFQ1QsXHJcbklORElSRUNULCBPUiBDT05TRVFVRU5USUFMIERBTUFHRVMgT1IgQU5ZIERBTUFHRVMgV0hBVFNPRVZFUiBSRVNVTFRJTkcgRlJPTVxyXG5MT1NTIE9GIFVTRSwgREFUQSBPUiBQUk9GSVRTLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgTkVHTElHRU5DRSBPUlxyXG5PVEhFUiBUT1JUSU9VUyBBQ1RJT04sIEFSSVNJTkcgT1VUIE9GIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgVVNFIE9SXHJcblBFUkZPUk1BTkNFIE9GIFRISVMgU09GVFdBUkUuXHJcbioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqICovXHJcbi8qIGdsb2JhbCBSZWZsZWN0LCBQcm9taXNlICovXHJcblxyXG52YXIgZXh0ZW5kU3RhdGljcyA9IGZ1bmN0aW9uKGQsIGIpIHtcclxuICAgIGV4dGVuZFN0YXRpY3MgPSBPYmplY3Quc2V0UHJvdG90eXBlT2YgfHxcclxuICAgICAgICAoeyBfX3Byb3RvX186IFtdIH0gaW5zdGFuY2VvZiBBcnJheSAmJiBmdW5jdGlvbiAoZCwgYikgeyBkLl9fcHJvdG9fXyA9IGI7IH0pIHx8XHJcbiAgICAgICAgZnVuY3Rpb24gKGQsIGIpIHsgZm9yICh2YXIgcCBpbiBiKSBpZiAoYi5oYXNPd25Qcm9wZXJ0eShwKSkgZFtwXSA9IGJbcF07IH07XHJcbiAgICByZXR1cm4gZXh0ZW5kU3RhdGljcyhkLCBiKTtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2V4dGVuZHMoZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyhkLCBiKTtcclxuICAgIGZ1bmN0aW9uIF9fKCkgeyB0aGlzLmNvbnN0cnVjdG9yID0gZDsgfVxyXG4gICAgZC5wcm90b3R5cGUgPSBiID09PSBudWxsID8gT2JqZWN0LmNyZWF0ZShiKSA6IChfXy5wcm90b3R5cGUgPSBiLnByb3RvdHlwZSwgbmV3IF9fKCkpO1xyXG59XHJcblxyXG5leHBvcnQgdmFyIF9fYXNzaWduID0gZnVuY3Rpb24oKSB7XHJcbiAgICBfX2Fzc2lnbiA9IE9iamVjdC5hc3NpZ24gfHwgZnVuY3Rpb24gX19hc3NpZ24odCkge1xyXG4gICAgICAgIGZvciAodmFyIHMsIGkgPSAxLCBuID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IG47IGkrKykge1xyXG4gICAgICAgICAgICBzID0gYXJndW1lbnRzW2ldO1xyXG4gICAgICAgICAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkpIHRbcF0gPSBzW3BdO1xyXG4gICAgICAgIH1cclxuICAgICAgICByZXR1cm4gdDtcclxuICAgIH1cclxuICAgIHJldHVybiBfX2Fzc2lnbi5hcHBseSh0aGlzLCBhcmd1bWVudHMpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19yZXN0KHMsIGUpIHtcclxuICAgIHZhciB0ID0ge307XHJcbiAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkgJiYgZS5pbmRleE9mKHApIDwgMClcclxuICAgICAgICB0W3BdID0gc1twXTtcclxuICAgIGlmIChzICE9IG51bGwgJiYgdHlwZW9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHMgPT09IFwiZnVuY3Rpb25cIilcclxuICAgICAgICBmb3IgKHZhciBpID0gMCwgcCA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHMocyk7IGkgPCBwLmxlbmd0aDsgaSsrKSB7XHJcbiAgICAgICAgICAgIGlmIChlLmluZGV4T2YocFtpXSkgPCAwICYmIE9iamVjdC5wcm90b3R5cGUucHJvcGVydHlJc0VudW1lcmFibGUuY2FsbChzLCBwW2ldKSlcclxuICAgICAgICAgICAgICAgIHRbcFtpXV0gPSBzW3BbaV1dO1xyXG4gICAgICAgIH1cclxuICAgIHJldHVybiB0O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19kZWNvcmF0ZShkZWNvcmF0b3JzLCB0YXJnZXQsIGtleSwgZGVzYykge1xyXG4gICAgdmFyIGMgPSBhcmd1bWVudHMubGVuZ3RoLCByID0gYyA8IDMgPyB0YXJnZXQgOiBkZXNjID09PSBudWxsID8gZGVzYyA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IodGFyZ2V0LCBrZXkpIDogZGVzYywgZDtcclxuICAgIGlmICh0eXBlb2YgUmVmbGVjdCA9PT0gXCJvYmplY3RcIiAmJiB0eXBlb2YgUmVmbGVjdC5kZWNvcmF0ZSA9PT0gXCJmdW5jdGlvblwiKSByID0gUmVmbGVjdC5kZWNvcmF0ZShkZWNvcmF0b3JzLCB0YXJnZXQsIGtleSwgZGVzYyk7XHJcbiAgICBlbHNlIGZvciAodmFyIGkgPSBkZWNvcmF0b3JzLmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSBpZiAoZCA9IGRlY29yYXRvcnNbaV0pIHIgPSAoYyA8IDMgPyBkKHIpIDogYyA+IDMgPyBkKHRhcmdldCwga2V5LCByKSA6IGQodGFyZ2V0LCBrZXkpKSB8fCByO1xyXG4gICAgcmV0dXJuIGMgPiAzICYmIHIgJiYgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRhcmdldCwga2V5LCByKSwgcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcGFyYW0ocGFyYW1JbmRleCwgZGVjb3JhdG9yKSB7XHJcbiAgICByZXR1cm4gZnVuY3Rpb24gKHRhcmdldCwga2V5KSB7IGRlY29yYXRvcih0YXJnZXQsIGtleSwgcGFyYW1JbmRleCk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fbWV0YWRhdGEobWV0YWRhdGFLZXksIG1ldGFkYXRhVmFsdWUpIHtcclxuICAgIGlmICh0eXBlb2YgUmVmbGVjdCA9PT0gXCJvYmplY3RcIiAmJiB0eXBlb2YgUmVmbGVjdC5tZXRhZGF0YSA9PT0gXCJmdW5jdGlvblwiKSByZXR1cm4gUmVmbGVjdC5tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2F3YWl0ZXIodGhpc0FyZywgX2FyZ3VtZW50cywgUCwgZ2VuZXJhdG9yKSB7XHJcbiAgICBmdW5jdGlvbiBhZG9wdCh2YWx1ZSkgeyByZXR1cm4gdmFsdWUgaW5zdGFuY2VvZiBQID8gdmFsdWUgOiBuZXcgUChmdW5jdGlvbiAocmVzb2x2ZSkgeyByZXNvbHZlKHZhbHVlKTsgfSk7IH1cclxuICAgIHJldHVybiBuZXcgKFAgfHwgKFAgPSBQcm9taXNlKSkoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xyXG4gICAgICAgIGZ1bmN0aW9uIGZ1bGZpbGxlZCh2YWx1ZSkgeyB0cnkgeyBzdGVwKGdlbmVyYXRvci5uZXh0KHZhbHVlKSk7IH0gY2F0Y2ggKGUpIHsgcmVqZWN0KGUpOyB9IH1cclxuICAgICAgICBmdW5jdGlvbiByZWplY3RlZCh2YWx1ZSkgeyB0cnkgeyBzdGVwKGdlbmVyYXRvcltcInRocm93XCJdKHZhbHVlKSk7IH0gY2F0Y2ggKGUpIHsgcmVqZWN0KGUpOyB9IH1cclxuICAgICAgICBmdW5jdGlvbiBzdGVwKHJlc3VsdCkgeyByZXN1bHQuZG9uZSA/IHJlc29sdmUocmVzdWx0LnZhbHVlKSA6IGFkb3B0KHJlc3VsdC52YWx1ZSkudGhlbihmdWxmaWxsZWQsIHJlamVjdGVkKTsgfVxyXG4gICAgICAgIHN0ZXAoKGdlbmVyYXRvciA9IGdlbmVyYXRvci5hcHBseSh0aGlzQXJnLCBfYXJndW1lbnRzIHx8IFtdKSkubmV4dCgpKTtcclxuICAgIH0pO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19nZW5lcmF0b3IodGhpc0FyZywgYm9keSkge1xyXG4gICAgdmFyIF8gPSB7IGxhYmVsOiAwLCBzZW50OiBmdW5jdGlvbigpIHsgaWYgKHRbMF0gJiAxKSB0aHJvdyB0WzFdOyByZXR1cm4gdFsxXTsgfSwgdHJ5czogW10sIG9wczogW10gfSwgZiwgeSwgdCwgZztcclxuICAgIHJldHVybiBnID0geyBuZXh0OiB2ZXJiKDApLCBcInRocm93XCI6IHZlcmIoMSksIFwicmV0dXJuXCI6IHZlcmIoMikgfSwgdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIChnW1N5bWJvbC5pdGVyYXRvcl0gPSBmdW5jdGlvbigpIHsgcmV0dXJuIHRoaXM7IH0pLCBnO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IHJldHVybiBmdW5jdGlvbiAodikgeyByZXR1cm4gc3RlcChbbiwgdl0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzdGVwKG9wKSB7XHJcbiAgICAgICAgaWYgKGYpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJHZW5lcmF0b3IgaXMgYWxyZWFkeSBleGVjdXRpbmcuXCIpO1xyXG4gICAgICAgIHdoaWxlIChfKSB0cnkge1xyXG4gICAgICAgICAgICBpZiAoZiA9IDEsIHkgJiYgKHQgPSBvcFswXSAmIDIgPyB5W1wicmV0dXJuXCJdIDogb3BbMF0gPyB5W1widGhyb3dcIl0gfHwgKCh0ID0geVtcInJldHVyblwiXSkgJiYgdC5jYWxsKHkpLCAwKSA6IHkubmV4dCkgJiYgISh0ID0gdC5jYWxsKHksIG9wWzFdKSkuZG9uZSkgcmV0dXJuIHQ7XHJcbiAgICAgICAgICAgIGlmICh5ID0gMCwgdCkgb3AgPSBbb3BbMF0gJiAyLCB0LnZhbHVlXTtcclxuICAgICAgICAgICAgc3dpdGNoIChvcFswXSkge1xyXG4gICAgICAgICAgICAgICAgY2FzZSAwOiBjYXNlIDE6IHQgPSBvcDsgYnJlYWs7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDQ6IF8ubGFiZWwrKzsgcmV0dXJuIHsgdmFsdWU6IG9wWzFdLCBkb25lOiBmYWxzZSB9O1xyXG4gICAgICAgICAgICAgICAgY2FzZSA1OiBfLmxhYmVsKys7IHkgPSBvcFsxXTsgb3AgPSBbMF07IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICAgICAgY2FzZSA3OiBvcCA9IF8ub3BzLnBvcCgpOyBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgICAgICAgICAgICBpZiAoISh0ID0gXy50cnlzLCB0ID0gdC5sZW5ndGggPiAwICYmIHRbdC5sZW5ndGggLSAxXSkgJiYgKG9wWzBdID09PSA2IHx8IG9wWzBdID09PSAyKSkgeyBfID0gMDsgY29udGludWU7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAob3BbMF0gPT09IDMgJiYgKCF0IHx8IChvcFsxXSA+IHRbMF0gJiYgb3BbMV0gPCB0WzNdKSkpIHsgXy5sYWJlbCA9IG9wWzFdOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gNiAmJiBfLmxhYmVsIDwgdFsxXSkgeyBfLmxhYmVsID0gdFsxXTsgdCA9IG9wOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0ICYmIF8ubGFiZWwgPCB0WzJdKSB7IF8ubGFiZWwgPSB0WzJdOyBfLm9wcy5wdXNoKG9wKTsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAodFsyXSkgXy5vcHMucG9wKCk7XHJcbiAgICAgICAgICAgICAgICAgICAgXy50cnlzLnBvcCgpOyBjb250aW51ZTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBvcCA9IGJvZHkuY2FsbCh0aGlzQXJnLCBfKTtcclxuICAgICAgICB9IGNhdGNoIChlKSB7IG9wID0gWzYsIGVdOyB5ID0gMDsgfSBmaW5hbGx5IHsgZiA9IHQgPSAwOyB9XHJcbiAgICAgICAgaWYgKG9wWzBdICYgNSkgdGhyb3cgb3BbMV07IHJldHVybiB7IHZhbHVlOiBvcFswXSA/IG9wWzFdIDogdm9pZCAwLCBkb25lOiB0cnVlIH07XHJcbiAgICB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NyZWF0ZUJpbmRpbmcobywgbSwgaywgazIpIHtcclxuICAgIGlmIChrMiA9PT0gdW5kZWZpbmVkKSBrMiA9IGs7XHJcbiAgICBvW2syXSA9IG1ba107XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2V4cG9ydFN0YXIobSwgZXhwb3J0cykge1xyXG4gICAgZm9yICh2YXIgcCBpbiBtKSBpZiAocCAhPT0gXCJkZWZhdWx0XCIgJiYgIWV4cG9ydHMuaGFzT3duUHJvcGVydHkocCkpIGV4cG9ydHNbcF0gPSBtW3BdO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX192YWx1ZXMobykge1xyXG4gICAgdmFyIHMgPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgU3ltYm9sLml0ZXJhdG9yLCBtID0gcyAmJiBvW3NdLCBpID0gMDtcclxuICAgIGlmIChtKSByZXR1cm4gbS5jYWxsKG8pO1xyXG4gICAgaWYgKG8gJiYgdHlwZW9mIG8ubGVuZ3RoID09PSBcIm51bWJlclwiKSByZXR1cm4ge1xyXG4gICAgICAgIG5leHQ6IGZ1bmN0aW9uICgpIHtcclxuICAgICAgICAgICAgaWYgKG8gJiYgaSA+PSBvLmxlbmd0aCkgbyA9IHZvaWQgMDtcclxuICAgICAgICAgICAgcmV0dXJuIHsgdmFsdWU6IG8gJiYgb1tpKytdLCBkb25lOiAhbyB9O1xyXG4gICAgICAgIH1cclxuICAgIH07XHJcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKHMgPyBcIk9iamVjdCBpcyBub3QgaXRlcmFibGUuXCIgOiBcIlN5bWJvbC5pdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3JlYWQobywgbikge1xyXG4gICAgdmFyIG0gPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgb1tTeW1ib2wuaXRlcmF0b3JdO1xyXG4gICAgaWYgKCFtKSByZXR1cm4gbztcclxuICAgIHZhciBpID0gbS5jYWxsKG8pLCByLCBhciA9IFtdLCBlO1xyXG4gICAgdHJ5IHtcclxuICAgICAgICB3aGlsZSAoKG4gPT09IHZvaWQgMCB8fCBuLS0gPiAwKSAmJiAhKHIgPSBpLm5leHQoKSkuZG9uZSkgYXIucHVzaChyLnZhbHVlKTtcclxuICAgIH1cclxuICAgIGNhdGNoIChlcnJvcikgeyBlID0geyBlcnJvcjogZXJyb3IgfTsgfVxyXG4gICAgZmluYWxseSB7XHJcbiAgICAgICAgdHJ5IHtcclxuICAgICAgICAgICAgaWYgKHIgJiYgIXIuZG9uZSAmJiAobSA9IGlbXCJyZXR1cm5cIl0pKSBtLmNhbGwoaSk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGZpbmFsbHkgeyBpZiAoZSkgdGhyb3cgZS5lcnJvcjsgfVxyXG4gICAgfVxyXG4gICAgcmV0dXJuIGFyO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19zcHJlYWQoKSB7XHJcbiAgICBmb3IgKHZhciBhciA9IFtdLCBpID0gMDsgaSA8IGFyZ3VtZW50cy5sZW5ndGg7IGkrKylcclxuICAgICAgICBhciA9IGFyLmNvbmNhdChfX3JlYWQoYXJndW1lbnRzW2ldKSk7XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZEFycmF5cygpIHtcclxuICAgIGZvciAodmFyIHMgPSAwLCBpID0gMCwgaWwgPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgaWw7IGkrKykgcyArPSBhcmd1bWVudHNbaV0ubGVuZ3RoO1xyXG4gICAgZm9yICh2YXIgciA9IEFycmF5KHMpLCBrID0gMCwgaSA9IDA7IGkgPCBpbDsgaSsrKVxyXG4gICAgICAgIGZvciAodmFyIGEgPSBhcmd1bWVudHNbaV0sIGogPSAwLCBqbCA9IGEubGVuZ3RoOyBqIDwgamw7IGorKywgaysrKVxyXG4gICAgICAgICAgICByW2tdID0gYVtqXTtcclxuICAgIHJldHVybiByO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXQodikge1xyXG4gICAgcmV0dXJuIHRoaXMgaW5zdGFuY2VvZiBfX2F3YWl0ID8gKHRoaXMudiA9IHYsIHRoaXMpIDogbmV3IF9fYXdhaXQodik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jR2VuZXJhdG9yKHRoaXNBcmcsIF9hcmd1bWVudHMsIGdlbmVyYXRvcikge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBnID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pLCBpLCBxID0gW107XHJcbiAgICByZXR1cm4gaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIpLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaWYgKGdbbl0pIGlbbl0gPSBmdW5jdGlvbiAodikgeyByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKGEsIGIpIHsgcS5wdXNoKFtuLCB2LCBhLCBiXSkgPiAxIHx8IHJlc3VtZShuLCB2KTsgfSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHJlc3VtZShuLCB2KSB7IHRyeSB7IHN0ZXAoZ1tuXSh2KSk7IH0gY2F0Y2ggKGUpIHsgc2V0dGxlKHFbMF1bM10sIGUpOyB9IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAocikgeyByLnZhbHVlIGluc3RhbmNlb2YgX19hd2FpdCA/IFByb21pc2UucmVzb2x2ZShyLnZhbHVlLnYpLnRoZW4oZnVsZmlsbCwgcmVqZWN0KSA6IHNldHRsZShxWzBdWzJdLCByKTsgfVxyXG4gICAgZnVuY3Rpb24gZnVsZmlsbCh2YWx1ZSkgeyByZXN1bWUoXCJuZXh0XCIsIHZhbHVlKTsgfVxyXG4gICAgZnVuY3Rpb24gcmVqZWN0KHZhbHVlKSB7IHJlc3VtZShcInRocm93XCIsIHZhbHVlKTsgfVxyXG4gICAgZnVuY3Rpb24gc2V0dGxlKGYsIHYpIHsgaWYgKGYodiksIHEuc2hpZnQoKSwgcS5sZW5ndGgpIHJlc3VtZShxWzBdWzBdLCBxWzBdWzFdKTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY0RlbGVnYXRvcihvKSB7XHJcbiAgICB2YXIgaSwgcDtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiwgZnVuY3Rpb24gKGUpIHsgdGhyb3cgZTsgfSksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4sIGYpIHsgaVtuXSA9IG9bbl0gPyBmdW5jdGlvbiAodikgeyByZXR1cm4gKHAgPSAhcCkgPyB7IHZhbHVlOiBfX2F3YWl0KG9bbl0odikpLCBkb25lOiBuID09PSBcInJldHVyblwiIH0gOiBmID8gZih2KSA6IHY7IH0gOiBmOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jVmFsdWVzKG8pIHtcclxuICAgIGlmICghU3ltYm9sLmFzeW5jSXRlcmF0b3IpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTeW1ib2wuYXN5bmNJdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbiAgICB2YXIgbSA9IG9bU3ltYm9sLmFzeW5jSXRlcmF0b3JdLCBpO1xyXG4gICAgcmV0dXJuIG0gPyBtLmNhbGwobykgOiAobyA9IHR5cGVvZiBfX3ZhbHVlcyA9PT0gXCJmdW5jdGlvblwiID8gX192YWx1ZXMobykgOiBvW1N5bWJvbC5pdGVyYXRvcl0oKSwgaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIpLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGkpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IGlbbl0gPSBvW25dICYmIGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7IHYgPSBvW25dKHYpLCBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCB2LmRvbmUsIHYudmFsdWUpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gc2V0dGxlKHJlc29sdmUsIHJlamVjdCwgZCwgdikgeyBQcm9taXNlLnJlc29sdmUodikudGhlbihmdW5jdGlvbih2KSB7IHJlc29sdmUoeyB2YWx1ZTogdiwgZG9uZTogZCB9KTsgfSwgcmVqZWN0KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tYWtlVGVtcGxhdGVPYmplY3QoY29va2VkLCByYXcpIHtcclxuICAgIGlmIChPYmplY3QuZGVmaW5lUHJvcGVydHkpIHsgT2JqZWN0LmRlZmluZVByb3BlcnR5KGNvb2tlZCwgXCJyYXdcIiwgeyB2YWx1ZTogcmF3IH0pOyB9IGVsc2UgeyBjb29rZWQucmF3ID0gcmF3OyB9XHJcbiAgICByZXR1cm4gY29va2VkO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9faW1wb3J0U3Rhcihtb2QpIHtcclxuICAgIGlmIChtb2QgJiYgbW9kLl9fZXNNb2R1bGUpIHJldHVybiBtb2Q7XHJcbiAgICB2YXIgcmVzdWx0ID0ge307XHJcbiAgICBpZiAobW9kICE9IG51bGwpIGZvciAodmFyIGsgaW4gbW9kKSBpZiAoT2JqZWN0Lmhhc093blByb3BlcnR5LmNhbGwobW9kLCBrKSkgcmVzdWx0W2tdID0gbW9kW2tdO1xyXG4gICAgcmVzdWx0LmRlZmF1bHQgPSBtb2Q7XHJcbiAgICByZXR1cm4gcmVzdWx0O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnREZWZhdWx0KG1vZCkge1xyXG4gICAgcmV0dXJuIChtb2QgJiYgbW9kLl9fZXNNb2R1bGUpID8gbW9kIDogeyBkZWZhdWx0OiBtb2QgfTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY2xhc3NQcml2YXRlRmllbGRHZXQocmVjZWl2ZXIsIHByaXZhdGVNYXApIHtcclxuICAgIGlmICghcHJpdmF0ZU1hcC5oYXMocmVjZWl2ZXIpKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcImF0dGVtcHRlZCB0byBnZXQgcHJpdmF0ZSBmaWVsZCBvbiBub24taW5zdGFuY2VcIik7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gcHJpdmF0ZU1hcC5nZXQocmVjZWl2ZXIpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZFNldChyZWNlaXZlciwgcHJpdmF0ZU1hcCwgdmFsdWUpIHtcclxuICAgIGlmICghcHJpdmF0ZU1hcC5oYXMocmVjZWl2ZXIpKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcImF0dGVtcHRlZCB0byBzZXQgcHJpdmF0ZSBmaWVsZCBvbiBub24taW5zdGFuY2VcIik7XHJcbiAgICB9XHJcbiAgICBwcml2YXRlTWFwLnNldChyZWNlaXZlciwgdmFsdWUpO1xyXG4gICAgcmV0dXJuIHZhbHVlO1xyXG59XHJcbiIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgcmVxdWVzdCwgY2xlYW5VcmwsIGFwcGVuZEN1c3RvbVBhcmFtcyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBhZGRGZWF0dXJlcyB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXInO1xuICogLy9cbiAqIGFkZEZlYXR1cmVzKHtcbiAqICAgdXJsOiBcImh0dHBzOi8vc2FtcGxlc2VydmVyNi5hcmNnaXNvbmxpbmUuY29tL2FyY2dpcy9yZXN0L3NlcnZpY2VzL1NlcnZpY2VSZXF1ZXN0L0ZlYXR1cmVTZXJ2ZXIvMFwiLFxuICogICBmZWF0dXJlczogW3tcbiAqICAgICBnZW9tZXRyeTogeyB4OiAtMTIwLCB5OiA0NSwgc3BhdGlhbFJlZmVyZW5jZTogeyB3a2lkOiA0MzI2IH0gfSxcbiAqICAgICBhdHRyaWJ1dGVzOiB7IHN0YXR1czogXCJhbGl2ZVwiIH1cbiAqICAgfV1cbiAqIH0pXG4gKiAgIC50aGVuKHJlc3BvbnNlKVxuICogYGBgXG4gKiBBZGQgZmVhdHVyZXMgcmVxdWVzdC4gU2VlIHRoZSBbUkVTVCBEb2N1bWVudGF0aW9uXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3NlcnZpY2VzLXJlZmVyZW5jZS9hZGQtZmVhdHVyZXMuaHRtKSBmb3IgbW9yZSBpbmZvcm1hdGlvbi5cbiAqXG4gKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdC5cbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBhZGRGZWF0dXJlcyByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGFkZEZlYXR1cmVzKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIHVybCA9IGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi9hZGRGZWF0dXJlc1wiO1xuICAgIC8vIGVkaXQgb3BlcmF0aW9ucyBhcmUgUE9TVCBvbmx5XG4gICAgdmFyIG9wdGlvbnMgPSBhcHBlbmRDdXN0b21QYXJhbXMocmVxdWVzdE9wdGlvbnMsIFtcImZlYXR1cmVzXCIsIFwiZ2RiVmVyc2lvblwiLCBcInJldHVybkVkaXRNb21lbnRcIiwgXCJyb2xsYmFja09uRmFpbHVyZVwiXSwgeyBwYXJhbXM6IF9fYXNzaWduKHt9LCByZXF1ZXN0T3B0aW9ucy5wYXJhbXMpIH0pO1xuICAgIHJldHVybiByZXF1ZXN0KHVybCwgb3B0aW9ucyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1hZGQuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyByZXF1ZXN0LCBjbGVhblVybCwgYXBwZW5kQ3VzdG9tUGFyYW1zIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IGRlbGV0ZUZlYXR1cmVzIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcic7XG4gKiAvL1xuICogZGVsZXRlRmVhdHVyZXMoe1xuICogICB1cmw6IFwiaHR0cHM6Ly9zYW1wbGVzZXJ2ZXI2LmFyY2dpc29ubGluZS5jb20vYXJjZ2lzL3Jlc3Qvc2VydmljZXMvU2VydmljZVJlcXVlc3QvRmVhdHVyZVNlcnZlci8wXCIsXG4gKiAgIG9iamVjdElkczogWzEsMiwzXVxuICogfSk7XG4gKiBgYGBcbiAqIERlbGV0ZSBmZWF0dXJlcyByZXF1ZXN0LiBTZWUgdGhlIFtSRVNUIERvY3VtZW50YXRpb25dKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3Qvc2VydmljZXMtcmVmZXJlbmNlL2RlbGV0ZS1mZWF0dXJlcy5odG0pIGZvciBtb3JlIGluZm9ybWF0aW9uLlxuICpcbiAqIEBwYXJhbSBkZWxldGVGZWF0dXJlc1JlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3QuXG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgZGVsZXRlRmVhdHVyZXMgcmVzcG9uc2UuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBkZWxldGVGZWF0dXJlcyhyZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciB1cmwgPSBjbGVhblVybChyZXF1ZXN0T3B0aW9ucy51cmwpICsgXCIvZGVsZXRlRmVhdHVyZXNcIjtcbiAgICAvLyBlZGl0IG9wZXJhdGlvbnMgUE9TVCBvbmx5XG4gICAgdmFyIG9wdGlvbnMgPSBhcHBlbmRDdXN0b21QYXJhbXMocmVxdWVzdE9wdGlvbnMsIFtcbiAgICAgICAgXCJ3aGVyZVwiLFxuICAgICAgICBcIm9iamVjdElkc1wiLFxuICAgICAgICBcImdkYlZlcnNpb25cIixcbiAgICAgICAgXCJyZXR1cm5FZGl0TW9tZW50XCIsXG4gICAgICAgIFwicm9sbGJhY2tPbkZhaWx1cmVcIlxuICAgIF0sIHsgcGFyYW1zOiBfX2Fzc2lnbih7fSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKSB9KTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIG9wdGlvbnMpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGVsZXRlLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyByZXF1ZXN0LCBjbGVhblVybCwgYXBwZW5kQ3VzdG9tUGFyYW1zIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IGdldEZlYXR1cmUgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyJztcbiAqIC8vXG4gKiBjb25zdCB1cmwgPSBcImh0dHBzOi8vc2VydmljZXMuYXJjZ2lzLmNvbS9WNlpIRnI2emRnTlp1VkcwL2FyY2dpcy9yZXN0L3NlcnZpY2VzL0xhbmRzY2FwZV9UcmVlcy9GZWF0dXJlU2VydmVyLzBcIjtcbiAqIC8vXG4gKiBnZXRGZWF0dXJlKHtcbiAqICAgdXJsLFxuICogICBpZDogNDJcbiAqIH0pLnRoZW4oZmVhdHVyZSA9PiB7XG4gKiAgY29uc29sZS5sb2coZmVhdHVyZS5hdHRyaWJ1dGVzLkZJRCk7IC8vIDQyXG4gKiB9KTtcbiAqIGBgYFxuICogR2V0IGEgZmVhdHVyZSBieSBpZC5cbiAqXG4gKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdFxuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIGZlYXR1cmUgb3IgdGhlIFtyZXNwb25zZV0oaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvQVBJL1Jlc3BvbnNlKSBpdHNlbGYgaWYgYHJhd1Jlc3BvbnNlOiB0cnVlYCB3YXMgcGFzc2VkIGluLlxuICovXG5leHBvcnQgZnVuY3Rpb24gZ2V0RmVhdHVyZShyZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciB1cmwgPSBjbGVhblVybChyZXF1ZXN0T3B0aW9ucy51cmwpICsgXCIvXCIgKyByZXF1ZXN0T3B0aW9ucy5pZDtcbiAgICAvLyBkZWZhdWx0IHRvIGEgR0VUIHJlcXVlc3RcbiAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKHsgaHR0cE1ldGhvZDogXCJHRVRcIiB9LCByZXF1ZXN0T3B0aW9ucyk7XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICBpZiAob3B0aW9ucy5yYXdSZXNwb25zZSkge1xuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiByZXNwb25zZS5mZWF0dXJlO1xuICAgIH0pO1xufVxuLyoqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgcXVlcnlGZWF0dXJlcyB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXInO1xuICogLy9cbiAqIHF1ZXJ5RmVhdHVyZXMoe1xuICogICB1cmw6IFwiaHR0cDovL3NhbXBsZXNlcnZlcjYuYXJjZ2lzb25saW5lLmNvbS9hcmNnaXMvcmVzdC9zZXJ2aWNlcy9DZW5zdXMvTWFwU2VydmVyLzNcIixcbiAqICAgd2hlcmU6IFwiU1RBVEVfTkFNRSA9ICdBbGFza2EnXCJcbiAqIH0pXG4gKiAgIC50aGVuKHJlc3VsdClcbiAqIGBgYFxuICogUXVlcnkgYSBmZWF0dXJlIHNlcnZpY2UuIFNlZSBbUkVTVCBEb2N1bWVudGF0aW9uXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3NlcnZpY2VzLXJlZmVyZW5jZS9xdWVyeS1mZWF0dXJlLXNlcnZpY2UtbGF5ZXItLmh0bSkgZm9yIG1vcmUgaW5mb3JtYXRpb24uXG4gKlxuICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3RcbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBxdWVyeSByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHF1ZXJ5RmVhdHVyZXMocmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgcXVlcnlPcHRpb25zID0gYXBwZW5kQ3VzdG9tUGFyYW1zKHJlcXVlc3RPcHRpb25zLCBbXG4gICAgICAgIFwid2hlcmVcIixcbiAgICAgICAgXCJvYmplY3RJZHNcIixcbiAgICAgICAgXCJyZWxhdGlvblBhcmFtXCIsXG4gICAgICAgIFwidGltZVwiLFxuICAgICAgICBcImRpc3RhbmNlXCIsXG4gICAgICAgIFwidW5pdHNcIixcbiAgICAgICAgXCJvdXRGaWVsZHNcIixcbiAgICAgICAgXCJnZW9tZXRyeVwiLFxuICAgICAgICBcImdlb21ldHJ5VHlwZVwiLFxuICAgICAgICBcInNwYXRpYWxSZWxcIixcbiAgICAgICAgXCJyZXR1cm5HZW9tZXRyeVwiLFxuICAgICAgICBcIm1heEFsbG93YWJsZU9mZnNldFwiLFxuICAgICAgICBcImdlb21ldHJ5UHJlY2lzaW9uXCIsXG4gICAgICAgIFwiaW5TUlwiLFxuICAgICAgICBcIm91dFNSXCIsXG4gICAgICAgIFwiZ2RiVmVyc2lvblwiLFxuICAgICAgICBcInJldHVybkRpc3RpbmN0VmFsdWVzXCIsXG4gICAgICAgIFwicmV0dXJuSWRzT25seVwiLFxuICAgICAgICBcInJldHVybkNvdW50T25seVwiLFxuICAgICAgICBcInJldHVybkV4dGVudE9ubHlcIixcbiAgICAgICAgXCJvcmRlckJ5RmllbGRzXCIsXG4gICAgICAgIFwiZ3JvdXBCeUZpZWxkc0ZvclN0YXRpc3RpY3NcIixcbiAgICAgICAgXCJvdXRTdGF0aXN0aWNzXCIsXG4gICAgICAgIFwicmV0dXJuWlwiLFxuICAgICAgICBcInJldHVybk1cIixcbiAgICAgICAgXCJtdWx0aXBhdGNoT3B0aW9uXCIsXG4gICAgICAgIFwicmVzdWx0T2Zmc2V0XCIsXG4gICAgICAgIFwicmVzdWx0UmVjb3JkQ291bnRcIixcbiAgICAgICAgXCJxdWFudGl6YXRpb25QYXJhbWV0ZXJzXCIsXG4gICAgICAgIFwicmV0dXJuQ2VudHJvaWRcIixcbiAgICAgICAgXCJyZXN1bHRUeXBlXCIsXG4gICAgICAgIFwiaGlzdG9yaWNNb21lbnRcIixcbiAgICAgICAgXCJyZXR1cm5UcnVlQ3VydmVzXCIsXG4gICAgICAgIFwic3FsRm9ybWF0XCIsXG4gICAgICAgIFwicmV0dXJuRXhjZWVkZWRMaW1pdEZlYXR1cmVzXCIsXG4gICAgICAgIFwiZlwiXG4gICAgXSwge1xuICAgICAgICBodHRwTWV0aG9kOiBcIkdFVFwiLFxuICAgICAgICBwYXJhbXM6IF9fYXNzaWduKHsgXG4gICAgICAgICAgICAvLyBzZXQgZGVmYXVsdCBxdWVyeSBwYXJhbWV0ZXJzXG4gICAgICAgICAgICB3aGVyZTogXCIxPTFcIiwgb3V0RmllbGRzOiBcIipcIiB9LCByZXF1ZXN0T3B0aW9ucy5wYXJhbXMpXG4gICAgfSk7XG4gICAgcmV0dXJuIHJlcXVlc3QoY2xlYW5VcmwocmVxdWVzdE9wdGlvbnMudXJsKSArIFwiL3F1ZXJ5XCIsIHF1ZXJ5T3B0aW9ucyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1xdWVyeS5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIGNsZWFuVXJsLCBhcHBlbmRDdXN0b21QYXJhbXMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKlxuICogYGBganNcbiAqIGltcG9ydCB7IHF1ZXJ5UmVsYXRlZCB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXInXG4gKiAvL1xuICogcXVlcnlSZWxhdGVkKHtcbiAqICB1cmw6IFwiaHR0cDovL3NlcnZpY2VzLm15c2VydmVyL09yZ0lEL0FyY0dJUy9yZXN0L3NlcnZpY2VzL1BldHJvbGV1bS9LU1BldHJvL0ZlYXR1cmVTZXJ2ZXIvMFwiLFxuICogIHJlbGF0aW9uc2hpcElkOiAxLFxuICogIHBhcmFtczogeyByZXR1cm5Db3VudE9ubHk6IHRydWUgfVxuICogfSlcbiAqICAudGhlbihyZXNwb25zZSkgLy8gcmVzcG9uc2UucmVsYXRlZFJlY29yZHNcbiAqIGBgYFxuICogUXVlcnkgdGhlIHJlbGF0ZWQgcmVjb3JkcyBmb3IgYSBmZWF0dXJlIHNlcnZpY2UuIFNlZSB0aGUgW1JFU1QgRG9jdW1lbnRhdGlvbl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC9zZXJ2aWNlcy1yZWZlcmVuY2UvcXVlcnktcmVsYXRlZC1yZWNvcmRzLWZlYXR1cmUtc2VydmljZS0uaHRtKSBmb3IgbW9yZSBpbmZvcm1hdGlvbi5cbiAqXG4gKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnNcbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBxdWVyeSByZXNwb25zZVxuICovXG5leHBvcnQgZnVuY3Rpb24gcXVlcnlSZWxhdGVkKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIG9wdGlvbnMgPSBhcHBlbmRDdXN0b21QYXJhbXMocmVxdWVzdE9wdGlvbnMsIFtcIm9iamVjdElkc1wiLCBcInJlbGF0aW9uc2hpcElkXCIsIFwiZGVmaW5pdGlvbkV4cHJlc3Npb25cIiwgXCJvdXRGaWVsZHNcIl0sIHtcbiAgICAgICAgaHR0cE1ldGhvZDogXCJHRVRcIixcbiAgICAgICAgcGFyYW1zOiBfX2Fzc2lnbih7IFxuICAgICAgICAgICAgLy8gc2V0IGRlZmF1bHQgcXVlcnkgcGFyYW1ldGVyc1xuICAgICAgICAgICAgZGVmaW5pdGlvbkV4cHJlc3Npb246IFwiMT0xXCIsIG91dEZpZWxkczogXCIqXCIsIHJlbGF0aW9uc2hpcElkOiAwIH0sIHJlcXVlc3RPcHRpb25zLnBhcmFtcylcbiAgICB9KTtcbiAgICByZXR1cm4gcmVxdWVzdChjbGVhblVybChyZXF1ZXN0T3B0aW9ucy51cmwpICsgXCIvcXVlcnlSZWxhdGVkUmVjb3Jkc1wiLCBvcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXF1ZXJ5UmVsYXRlZC5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIGNsZWFuVXJsLCBhcHBlbmRDdXN0b21QYXJhbXMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKlxuICogYGBganNcbiAqIGltcG9ydCB7IHVwZGF0ZUZlYXR1cmVzIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcic7XG4gKiAvL1xuICogdXBkYXRlRmVhdHVyZXMoe1xuICogICB1cmw6IFwiaHR0cHM6Ly9zYW1wbGVzZXJ2ZXI2LmFyY2dpc29ubGluZS5jb20vYXJjZ2lzL3Jlc3Qvc2VydmljZXMvU2VydmljZVJlcXVlc3QvRmVhdHVyZVNlcnZlci8wXCIsXG4gKiAgIGZlYXR1cmVzOiBbe1xuICogICAgIGdlb21ldHJ5OiB7IHg6IC0xMjAsIHk6IDQ1LCBzcGF0aWFsUmVmZXJlbmNlOiB7IHdraWQ6IDQzMjYgfSB9LFxuICogICAgIGF0dHJpYnV0ZXM6IHsgc3RhdHVzOiBcImFsaXZlXCIgfVxuICogICB9XVxuICogfSk7XG4gKiBgYGBcbiAqIFVwZGF0ZSBmZWF0dXJlcyByZXF1ZXN0LiBTZWUgdGhlIFtSRVNUIERvY3VtZW50YXRpb25dKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3Qvc2VydmljZXMtcmVmZXJlbmNlL3VwZGF0ZS1mZWF0dXJlcy5odG0pIGZvciBtb3JlIGluZm9ybWF0aW9uLlxuICpcbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0LlxuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIHVwZGF0ZUZlYXR1cmVzIHJlc3BvbnNlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gdXBkYXRlRmVhdHVyZXMocmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgdXJsID0gY2xlYW5VcmwocmVxdWVzdE9wdGlvbnMudXJsKSArIFwiL3VwZGF0ZUZlYXR1cmVzXCI7XG4gICAgLy8gZWRpdCBvcGVyYXRpb25zIGFyZSBQT1NUIG9ubHlcbiAgICB2YXIgb3B0aW9ucyA9IGFwcGVuZEN1c3RvbVBhcmFtcyhyZXF1ZXN0T3B0aW9ucywgW1wiZmVhdHVyZXNcIiwgXCJnZGJWZXJzaW9uXCIsIFwicmV0dXJuRWRpdE1vbWVudFwiLCBcInJvbGxiYWNrT25GYWlsdXJlXCIsIFwidHJ1ZUN1cnZlQ2xpZW50XCJdLCB7IHBhcmFtczogX19hc3NpZ24oe30sIHJlcXVlc3RPcHRpb25zLnBhcmFtcykgfSk7XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXVwZGF0ZS5qcy5tYXAiLCIvKiEgKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcclxuQ29weXJpZ2h0IChjKSBNaWNyb3NvZnQgQ29ycG9yYXRpb24uXHJcblxyXG5QZXJtaXNzaW9uIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBhbmQvb3IgZGlzdHJpYnV0ZSB0aGlzIHNvZnR3YXJlIGZvciBhbnlcclxucHVycG9zZSB3aXRoIG9yIHdpdGhvdXQgZmVlIGlzIGhlcmVieSBncmFudGVkLlxyXG5cclxuVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiBBTkQgVEhFIEFVVEhPUiBESVNDTEFJTVMgQUxMIFdBUlJBTlRJRVMgV0lUSFxyXG5SRUdBUkQgVE8gVEhJUyBTT0ZUV0FSRSBJTkNMVURJTkcgQUxMIElNUExJRUQgV0FSUkFOVElFUyBPRiBNRVJDSEFOVEFCSUxJVFlcclxuQU5EIEZJVE5FU1MuIElOIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1IgQkUgTElBQkxFIEZPUiBBTlkgU1BFQ0lBTCwgRElSRUNULFxyXG5JTkRJUkVDVCwgT1IgQ09OU0VRVUVOVElBTCBEQU1BR0VTIE9SIEFOWSBEQU1BR0VTIFdIQVRTT0VWRVIgUkVTVUxUSU5HIEZST01cclxuTE9TUyBPRiBVU0UsIERBVEEgT1IgUFJPRklUUywgV0hFVEhFUiBJTiBBTiBBQ1RJT04gT0YgQ09OVFJBQ1QsIE5FR0xJR0VOQ0UgT1JcclxuT1RIRVIgVE9SVElPVVMgQUNUSU9OLCBBUklTSU5HIE9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFVTRSBPUlxyXG5QRVJGT1JNQU5DRSBPRiBUSElTIFNPRlRXQVJFLlxyXG4qKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiAqL1xyXG4vKiBnbG9iYWwgUmVmbGVjdCwgUHJvbWlzZSAqL1xyXG5cclxudmFyIGV4dGVuZFN0YXRpY3MgPSBmdW5jdGlvbihkLCBiKSB7XHJcbiAgICBleHRlbmRTdGF0aWNzID0gT2JqZWN0LnNldFByb3RvdHlwZU9mIHx8XHJcbiAgICAgICAgKHsgX19wcm90b19fOiBbXSB9IGluc3RhbmNlb2YgQXJyYXkgJiYgZnVuY3Rpb24gKGQsIGIpIHsgZC5fX3Byb3RvX18gPSBiOyB9KSB8fFxyXG4gICAgICAgIGZ1bmN0aW9uIChkLCBiKSB7IGZvciAodmFyIHAgaW4gYikgaWYgKGIuaGFzT3duUHJvcGVydHkocCkpIGRbcF0gPSBiW3BdOyB9O1xyXG4gICAgcmV0dXJuIGV4dGVuZFN0YXRpY3MoZCwgYik7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19leHRlbmRzKGQsIGIpIHtcclxuICAgIGV4dGVuZFN0YXRpY3MoZCwgYik7XHJcbiAgICBmdW5jdGlvbiBfXygpIHsgdGhpcy5jb25zdHJ1Y3RvciA9IGQ7IH1cclxuICAgIGQucHJvdG90eXBlID0gYiA9PT0gbnVsbCA/IE9iamVjdC5jcmVhdGUoYikgOiAoX18ucHJvdG90eXBlID0gYi5wcm90b3R5cGUsIG5ldyBfXygpKTtcclxufVxyXG5cclxuZXhwb3J0IHZhciBfX2Fzc2lnbiA9IGZ1bmN0aW9uKCkge1xyXG4gICAgX19hc3NpZ24gPSBPYmplY3QuYXNzaWduIHx8IGZ1bmN0aW9uIF9fYXNzaWduKHQpIHtcclxuICAgICAgICBmb3IgKHZhciBzLCBpID0gMSwgbiA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBuOyBpKyspIHtcclxuICAgICAgICAgICAgcyA9IGFyZ3VtZW50c1tpXTtcclxuICAgICAgICAgICAgZm9yICh2YXIgcCBpbiBzKSBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHMsIHApKSB0W3BdID0gc1twXTtcclxuICAgICAgICB9XHJcbiAgICAgICAgcmV0dXJuIHQ7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gX19hc3NpZ24uYXBwbHkodGhpcywgYXJndW1lbnRzKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcmVzdChzLCBlKSB7XHJcbiAgICB2YXIgdCA9IHt9O1xyXG4gICAgZm9yICh2YXIgcCBpbiBzKSBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHMsIHApICYmIGUuaW5kZXhPZihwKSA8IDApXHJcbiAgICAgICAgdFtwXSA9IHNbcF07XHJcbiAgICBpZiAocyAhPSBudWxsICYmIHR5cGVvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlTeW1ib2xzID09PSBcImZ1bmN0aW9uXCIpXHJcbiAgICAgICAgZm9yICh2YXIgaSA9IDAsIHAgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlTeW1ib2xzKHMpOyBpIDwgcC5sZW5ndGg7IGkrKykge1xyXG4gICAgICAgICAgICBpZiAoZS5pbmRleE9mKHBbaV0pIDwgMCAmJiBPYmplY3QucHJvdG90eXBlLnByb3BlcnR5SXNFbnVtZXJhYmxlLmNhbGwocywgcFtpXSkpXHJcbiAgICAgICAgICAgICAgICB0W3BbaV1dID0gc1twW2ldXTtcclxuICAgICAgICB9XHJcbiAgICByZXR1cm4gdDtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZGVjb3JhdGUoZGVjb3JhdG9ycywgdGFyZ2V0LCBrZXksIGRlc2MpIHtcclxuICAgIHZhciBjID0gYXJndW1lbnRzLmxlbmd0aCwgciA9IGMgPCAzID8gdGFyZ2V0IDogZGVzYyA9PT0gbnVsbCA/IGRlc2MgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKHRhcmdldCwga2V5KSA6IGRlc2MsIGQ7XHJcbiAgICBpZiAodHlwZW9mIFJlZmxlY3QgPT09IFwib2JqZWN0XCIgJiYgdHlwZW9mIFJlZmxlY3QuZGVjb3JhdGUgPT09IFwiZnVuY3Rpb25cIikgciA9IFJlZmxlY3QuZGVjb3JhdGUoZGVjb3JhdG9ycywgdGFyZ2V0LCBrZXksIGRlc2MpO1xyXG4gICAgZWxzZSBmb3IgKHZhciBpID0gZGVjb3JhdG9ycy5sZW5ndGggLSAxOyBpID49IDA7IGktLSkgaWYgKGQgPSBkZWNvcmF0b3JzW2ldKSByID0gKGMgPCAzID8gZChyKSA6IGMgPiAzID8gZCh0YXJnZXQsIGtleSwgcikgOiBkKHRhcmdldCwga2V5KSkgfHwgcjtcclxuICAgIHJldHVybiBjID4gMyAmJiByICYmIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0YXJnZXQsIGtleSwgciksIHI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3BhcmFtKHBhcmFtSW5kZXgsIGRlY29yYXRvcikge1xyXG4gICAgcmV0dXJuIGZ1bmN0aW9uICh0YXJnZXQsIGtleSkgeyBkZWNvcmF0b3IodGFyZ2V0LCBrZXksIHBhcmFtSW5kZXgpOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX21ldGFkYXRhKG1ldGFkYXRhS2V5LCBtZXRhZGF0YVZhbHVlKSB7XHJcbiAgICBpZiAodHlwZW9mIFJlZmxlY3QgPT09IFwib2JqZWN0XCIgJiYgdHlwZW9mIFJlZmxlY3QubWV0YWRhdGEgPT09IFwiZnVuY3Rpb25cIikgcmV0dXJuIFJlZmxlY3QubWV0YWRhdGEobWV0YWRhdGFLZXksIG1ldGFkYXRhVmFsdWUpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hd2FpdGVyKHRoaXNBcmcsIF9hcmd1bWVudHMsIFAsIGdlbmVyYXRvcikge1xyXG4gICAgZnVuY3Rpb24gYWRvcHQodmFsdWUpIHsgcmV0dXJuIHZhbHVlIGluc3RhbmNlb2YgUCA/IHZhbHVlIDogbmV3IFAoZnVuY3Rpb24gKHJlc29sdmUpIHsgcmVzb2x2ZSh2YWx1ZSk7IH0pOyB9XHJcbiAgICByZXR1cm4gbmV3IChQIHx8IChQID0gUHJvbWlzZSkpKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcclxuICAgICAgICBmdW5jdGlvbiBmdWxmaWxsZWQodmFsdWUpIHsgdHJ5IHsgc3RlcChnZW5lcmF0b3IubmV4dCh2YWx1ZSkpOyB9IGNhdGNoIChlKSB7IHJlamVjdChlKTsgfSB9XHJcbiAgICAgICAgZnVuY3Rpb24gcmVqZWN0ZWQodmFsdWUpIHsgdHJ5IHsgc3RlcChnZW5lcmF0b3JbXCJ0aHJvd1wiXSh2YWx1ZSkpOyB9IGNhdGNoIChlKSB7IHJlamVjdChlKTsgfSB9XHJcbiAgICAgICAgZnVuY3Rpb24gc3RlcChyZXN1bHQpIHsgcmVzdWx0LmRvbmUgPyByZXNvbHZlKHJlc3VsdC52YWx1ZSkgOiBhZG9wdChyZXN1bHQudmFsdWUpLnRoZW4oZnVsZmlsbGVkLCByZWplY3RlZCk7IH1cclxuICAgICAgICBzdGVwKChnZW5lcmF0b3IgPSBnZW5lcmF0b3IuYXBwbHkodGhpc0FyZywgX2FyZ3VtZW50cyB8fCBbXSkpLm5leHQoKSk7XHJcbiAgICB9KTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZ2VuZXJhdG9yKHRoaXNBcmcsIGJvZHkpIHtcclxuICAgIHZhciBfID0geyBsYWJlbDogMCwgc2VudDogZnVuY3Rpb24oKSB7IGlmICh0WzBdICYgMSkgdGhyb3cgdFsxXTsgcmV0dXJuIHRbMV07IH0sIHRyeXM6IFtdLCBvcHM6IFtdIH0sIGYsIHksIHQsIGc7XHJcbiAgICByZXR1cm4gZyA9IHsgbmV4dDogdmVyYigwKSwgXCJ0aHJvd1wiOiB2ZXJiKDEpLCBcInJldHVyblwiOiB2ZXJiKDIpIH0sIHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiAoZ1tTeW1ib2wuaXRlcmF0b3JdID0gZnVuY3Rpb24oKSB7IHJldHVybiB0aGlzOyB9KSwgZztcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyByZXR1cm4gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIHN0ZXAoW24sIHZdKTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gc3RlcChvcCkge1xyXG4gICAgICAgIGlmIChmKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiR2VuZXJhdG9yIGlzIGFscmVhZHkgZXhlY3V0aW5nLlwiKTtcclxuICAgICAgICB3aGlsZSAoXykgdHJ5IHtcclxuICAgICAgICAgICAgaWYgKGYgPSAxLCB5ICYmICh0ID0gb3BbMF0gJiAyID8geVtcInJldHVyblwiXSA6IG9wWzBdID8geVtcInRocm93XCJdIHx8ICgodCA9IHlbXCJyZXR1cm5cIl0pICYmIHQuY2FsbCh5KSwgMCkgOiB5Lm5leHQpICYmICEodCA9IHQuY2FsbCh5LCBvcFsxXSkpLmRvbmUpIHJldHVybiB0O1xyXG4gICAgICAgICAgICBpZiAoeSA9IDAsIHQpIG9wID0gW29wWzBdICYgMiwgdC52YWx1ZV07XHJcbiAgICAgICAgICAgIHN3aXRjaCAob3BbMF0pIHtcclxuICAgICAgICAgICAgICAgIGNhc2UgMDogY2FzZSAxOiB0ID0gb3A7IGJyZWFrO1xyXG4gICAgICAgICAgICAgICAgY2FzZSA0OiBfLmxhYmVsKys7IHJldHVybiB7IHZhbHVlOiBvcFsxXSwgZG9uZTogZmFsc2UgfTtcclxuICAgICAgICAgICAgICAgIGNhc2UgNTogXy5sYWJlbCsrOyB5ID0gb3BbMV07IG9wID0gWzBdOyBjb250aW51ZTtcclxuICAgICAgICAgICAgICAgIGNhc2UgNzogb3AgPSBfLm9wcy5wb3AoKTsgXy50cnlzLnBvcCgpOyBjb250aW51ZTtcclxuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKCEodCA9IF8udHJ5cywgdCA9IHQubGVuZ3RoID4gMCAmJiB0W3QubGVuZ3RoIC0gMV0pICYmIChvcFswXSA9PT0gNiB8fCBvcFswXSA9PT0gMikpIHsgXyA9IDA7IGNvbnRpbnVlOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG9wWzBdID09PSAzICYmICghdCB8fCAob3BbMV0gPiB0WzBdICYmIG9wWzFdIDwgdFszXSkpKSB7IF8ubGFiZWwgPSBvcFsxXTsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAob3BbMF0gPT09IDYgJiYgXy5sYWJlbCA8IHRbMV0pIHsgXy5sYWJlbCA9IHRbMV07IHQgPSBvcDsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAodCAmJiBfLmxhYmVsIDwgdFsyXSkgeyBfLmxhYmVsID0gdFsyXTsgXy5vcHMucHVzaChvcCk7IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHRbMl0pIF8ub3BzLnBvcCgpO1xyXG4gICAgICAgICAgICAgICAgICAgIF8udHJ5cy5wb3AoKTsgY29udGludWU7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgb3AgPSBib2R5LmNhbGwodGhpc0FyZywgXyk7XHJcbiAgICAgICAgfSBjYXRjaCAoZSkgeyBvcCA9IFs2LCBlXTsgeSA9IDA7IH0gZmluYWxseSB7IGYgPSB0ID0gMDsgfVxyXG4gICAgICAgIGlmIChvcFswXSAmIDUpIHRocm93IG9wWzFdOyByZXR1cm4geyB2YWx1ZTogb3BbMF0gPyBvcFsxXSA6IHZvaWQgMCwgZG9uZTogdHJ1ZSB9O1xyXG4gICAgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jcmVhdGVCaW5kaW5nKG8sIG0sIGssIGsyKSB7XHJcbiAgICBpZiAoazIgPT09IHVuZGVmaW5lZCkgazIgPSBrO1xyXG4gICAgb1trMl0gPSBtW2tdO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19leHBvcnRTdGFyKG0sIGV4cG9ydHMpIHtcclxuICAgIGZvciAodmFyIHAgaW4gbSkgaWYgKHAgIT09IFwiZGVmYXVsdFwiICYmICFleHBvcnRzLmhhc093blByb3BlcnR5KHApKSBleHBvcnRzW3BdID0gbVtwXTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fdmFsdWVzKG8pIHtcclxuICAgIHZhciBzID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIFN5bWJvbC5pdGVyYXRvciwgbSA9IHMgJiYgb1tzXSwgaSA9IDA7XHJcbiAgICBpZiAobSkgcmV0dXJuIG0uY2FsbChvKTtcclxuICAgIGlmIChvICYmIHR5cGVvZiBvLmxlbmd0aCA9PT0gXCJudW1iZXJcIikgcmV0dXJuIHtcclxuICAgICAgICBuZXh0OiBmdW5jdGlvbiAoKSB7XHJcbiAgICAgICAgICAgIGlmIChvICYmIGkgPj0gby5sZW5ndGgpIG8gPSB2b2lkIDA7XHJcbiAgICAgICAgICAgIHJldHVybiB7IHZhbHVlOiBvICYmIG9baSsrXSwgZG9uZTogIW8gfTtcclxuICAgICAgICB9XHJcbiAgICB9O1xyXG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihzID8gXCJPYmplY3QgaXMgbm90IGl0ZXJhYmxlLlwiIDogXCJTeW1ib2wuaXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19yZWFkKG8sIG4pIHtcclxuICAgIHZhciBtID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIG9bU3ltYm9sLml0ZXJhdG9yXTtcclxuICAgIGlmICghbSkgcmV0dXJuIG87XHJcbiAgICB2YXIgaSA9IG0uY2FsbChvKSwgciwgYXIgPSBbXSwgZTtcclxuICAgIHRyeSB7XHJcbiAgICAgICAgd2hpbGUgKChuID09PSB2b2lkIDAgfHwgbi0tID4gMCkgJiYgIShyID0gaS5uZXh0KCkpLmRvbmUpIGFyLnB1c2goci52YWx1ZSk7XHJcbiAgICB9XHJcbiAgICBjYXRjaCAoZXJyb3IpIHsgZSA9IHsgZXJyb3I6IGVycm9yIH07IH1cclxuICAgIGZpbmFsbHkge1xyXG4gICAgICAgIHRyeSB7XHJcbiAgICAgICAgICAgIGlmIChyICYmICFyLmRvbmUgJiYgKG0gPSBpW1wicmV0dXJuXCJdKSkgbS5jYWxsKGkpO1xyXG4gICAgICAgIH1cclxuICAgICAgICBmaW5hbGx5IHsgaWYgKGUpIHRocm93IGUuZXJyb3I7IH1cclxuICAgIH1cclxuICAgIHJldHVybiBhcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fc3ByZWFkKCkge1xyXG4gICAgZm9yICh2YXIgYXIgPSBbXSwgaSA9IDA7IGkgPCBhcmd1bWVudHMubGVuZ3RoOyBpKyspXHJcbiAgICAgICAgYXIgPSBhci5jb25jYXQoX19yZWFkKGFyZ3VtZW50c1tpXSkpO1xyXG4gICAgcmV0dXJuIGFyO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19zcHJlYWRBcnJheXMoKSB7XHJcbiAgICBmb3IgKHZhciBzID0gMCwgaSA9IDAsIGlsID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IGlsOyBpKyspIHMgKz0gYXJndW1lbnRzW2ldLmxlbmd0aDtcclxuICAgIGZvciAodmFyIHIgPSBBcnJheShzKSwgayA9IDAsIGkgPSAwOyBpIDwgaWw7IGkrKylcclxuICAgICAgICBmb3IgKHZhciBhID0gYXJndW1lbnRzW2ldLCBqID0gMCwgamwgPSBhLmxlbmd0aDsgaiA8IGpsOyBqKyssIGsrKylcclxuICAgICAgICAgICAgcltrXSA9IGFbal07XHJcbiAgICByZXR1cm4gcjtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2F3YWl0KHYpIHtcclxuICAgIHJldHVybiB0aGlzIGluc3RhbmNlb2YgX19hd2FpdCA/ICh0aGlzLnYgPSB2LCB0aGlzKSA6IG5ldyBfX2F3YWl0KHYpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY0dlbmVyYXRvcih0aGlzQXJnLCBfYXJndW1lbnRzLCBnZW5lcmF0b3IpIHtcclxuICAgIGlmICghU3ltYm9sLmFzeW5jSXRlcmF0b3IpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTeW1ib2wuYXN5bmNJdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbiAgICB2YXIgZyA9IGdlbmVyYXRvci5hcHBseSh0aGlzQXJnLCBfYXJndW1lbnRzIHx8IFtdKSwgaSwgcSA9IFtdO1xyXG4gICAgcmV0dXJuIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiKSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuYXN5bmNJdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IGlmIChnW25dKSBpW25dID0gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChhLCBiKSB7IHEucHVzaChbbiwgdiwgYSwgYl0pID4gMSB8fCByZXN1bWUobiwgdik7IH0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiByZXN1bWUobiwgdikgeyB0cnkgeyBzdGVwKGdbbl0odikpOyB9IGNhdGNoIChlKSB7IHNldHRsZShxWzBdWzNdLCBlKTsgfSB9XHJcbiAgICBmdW5jdGlvbiBzdGVwKHIpIHsgci52YWx1ZSBpbnN0YW5jZW9mIF9fYXdhaXQgPyBQcm9taXNlLnJlc29sdmUoci52YWx1ZS52KS50aGVuKGZ1bGZpbGwsIHJlamVjdCkgOiBzZXR0bGUocVswXVsyXSwgcik7IH1cclxuICAgIGZ1bmN0aW9uIGZ1bGZpbGwodmFsdWUpIHsgcmVzdW1lKFwibmV4dFwiLCB2YWx1ZSk7IH1cclxuICAgIGZ1bmN0aW9uIHJlamVjdCh2YWx1ZSkgeyByZXN1bWUoXCJ0aHJvd1wiLCB2YWx1ZSk7IH1cclxuICAgIGZ1bmN0aW9uIHNldHRsZShmLCB2KSB7IGlmIChmKHYpLCBxLnNoaWZ0KCksIHEubGVuZ3RoKSByZXN1bWUocVswXVswXSwgcVswXVsxXSk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNEZWxlZ2F0b3Iobykge1xyXG4gICAgdmFyIGksIHA7XHJcbiAgICByZXR1cm4gaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIsIGZ1bmN0aW9uIChlKSB7IHRocm93IGU7IH0pLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5pdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuLCBmKSB7IGlbbl0gPSBvW25dID8gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIChwID0gIXApID8geyB2YWx1ZTogX19hd2FpdChvW25dKHYpKSwgZG9uZTogbiA9PT0gXCJyZXR1cm5cIiB9IDogZiA/IGYodikgOiB2OyB9IDogZjsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY1ZhbHVlcyhvKSB7XHJcbiAgICBpZiAoIVN5bWJvbC5hc3luY0l0ZXJhdG9yKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU3ltYm9sLmFzeW5jSXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgdmFyIG0gPSBvW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSwgaTtcclxuICAgIHJldHVybiBtID8gbS5jYWxsKG8pIDogKG8gPSB0eXBlb2YgX192YWx1ZXMgPT09IFwiZnVuY3Rpb25cIiA/IF9fdmFsdWVzKG8pIDogb1tTeW1ib2wuaXRlcmF0b3JdKCksIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiKSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuYXN5bmNJdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpKTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyBpW25dID0gb1tuXSAmJiBmdW5jdGlvbiAodikgeyByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkgeyB2ID0gb1tuXSh2KSwgc2V0dGxlKHJlc29sdmUsIHJlamVjdCwgdi5kb25lLCB2LnZhbHVlKTsgfSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHNldHRsZShyZXNvbHZlLCByZWplY3QsIGQsIHYpIHsgUHJvbWlzZS5yZXNvbHZlKHYpLnRoZW4oZnVuY3Rpb24odikgeyByZXNvbHZlKHsgdmFsdWU6IHYsIGRvbmU6IGQgfSk7IH0sIHJlamVjdCk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fbWFrZVRlbXBsYXRlT2JqZWN0KGNvb2tlZCwgcmF3KSB7XHJcbiAgICBpZiAoT2JqZWN0LmRlZmluZVByb3BlcnR5KSB7IE9iamVjdC5kZWZpbmVQcm9wZXJ0eShjb29rZWQsIFwicmF3XCIsIHsgdmFsdWU6IHJhdyB9KTsgfSBlbHNlIHsgY29va2VkLnJhdyA9IHJhdzsgfVxyXG4gICAgcmV0dXJuIGNvb2tlZDtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2ltcG9ydFN0YXIobW9kKSB7XHJcbiAgICBpZiAobW9kICYmIG1vZC5fX2VzTW9kdWxlKSByZXR1cm4gbW9kO1xyXG4gICAgdmFyIHJlc3VsdCA9IHt9O1xyXG4gICAgaWYgKG1vZCAhPSBudWxsKSBmb3IgKHZhciBrIGluIG1vZCkgaWYgKE9iamVjdC5oYXNPd25Qcm9wZXJ0eS5jYWxsKG1vZCwgaykpIHJlc3VsdFtrXSA9IG1vZFtrXTtcclxuICAgIHJlc3VsdC5kZWZhdWx0ID0gbW9kO1xyXG4gICAgcmV0dXJuIHJlc3VsdDtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9faW1wb3J0RGVmYXVsdChtb2QpIHtcclxuICAgIHJldHVybiAobW9kICYmIG1vZC5fX2VzTW9kdWxlKSA/IG1vZCA6IHsgZGVmYXVsdDogbW9kIH07XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NsYXNzUHJpdmF0ZUZpZWxkR2V0KHJlY2VpdmVyLCBwcml2YXRlTWFwKSB7XHJcbiAgICBpZiAoIXByaXZhdGVNYXAuaGFzKHJlY2VpdmVyKSkge1xyXG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJhdHRlbXB0ZWQgdG8gZ2V0IHByaXZhdGUgZmllbGQgb24gbm9uLWluc3RhbmNlXCIpO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHByaXZhdGVNYXAuZ2V0KHJlY2VpdmVyKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY2xhc3NQcml2YXRlRmllbGRTZXQocmVjZWl2ZXIsIHByaXZhdGVNYXAsIHZhbHVlKSB7XHJcbiAgICBpZiAoIXByaXZhdGVNYXAuaGFzKHJlY2VpdmVyKSkge1xyXG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJhdHRlbXB0ZWQgdG8gc2V0IHByaXZhdGUgZmllbGQgb24gbm9uLWluc3RhbmNlXCIpO1xyXG4gICAgfVxyXG4gICAgcHJpdmF0ZU1hcC5zZXQocmVjZWl2ZXIsIHZhbHVlKTtcclxuICAgIHJldHVybiB2YWx1ZTtcclxufVxyXG4iLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiwgX19leHRlbmRzIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyBlbmNvZGVGb3JtRGF0YSB9IGZyb20gXCIuL3V0aWxzL2VuY29kZS1mb3JtLWRhdGFcIjtcbmltcG9ydCB7IGVuY29kZVF1ZXJ5U3RyaW5nIH0gZnJvbSBcIi4vdXRpbHMvZW5jb2RlLXF1ZXJ5LXN0cmluZ1wiO1xuaW1wb3J0IHsgcmVxdWlyZXNGb3JtRGF0YSB9IGZyb20gXCIuL3V0aWxzL3Byb2Nlc3MtcGFyYW1zXCI7XG5pbXBvcnQgeyBBcmNHSVNSZXF1ZXN0RXJyb3IgfSBmcm9tIFwiLi91dGlscy9BcmNHSVNSZXF1ZXN0RXJyb3JcIjtcbmltcG9ydCB7IHdhcm4gfSBmcm9tIFwiLi91dGlscy93YXJuXCI7XG5leHBvcnQgdmFyIE5PREVKU19ERUZBVUxUX1JFRkVSRVJfSEVBREVSID0gXCJAZXNyaS9hcmNnaXMtcmVzdC1qc1wiO1xudmFyIERFRkFVTFRfQVJDR0lTX1JFUVVFU1RfT1BUSU9OUyA9IHtcbiAgICBodHRwTWV0aG9kOiBcIlBPU1RcIixcbiAgICBwYXJhbXM6IHtcbiAgICAgICAgZjogXCJqc29uXCIsXG4gICAgfSxcbn07XG4vKipcbiAqIFNldHMgdGhlIGRlZmF1bHQgb3B0aW9ucyB0aGF0IHdpbGwgYmUgcGFzc2VkIGluICoqYWxsIHJlcXVlc3RzIGFjcm9zcyBhbGwgYEBlc3JpL2FyY2dpcy1yZXN0LWpzYCBtb2R1bGVzKiouXG4gKlxuICpcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBzZXREZWZhdWx0UmVxdWVzdE9wdGlvbnMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuICogc2V0RGVmYXVsdFJlcXVlc3RPcHRpb25zKHtcbiAqICAgYXV0aGVudGljYXRpb246IHVzZXJTZXNzaW9uIC8vIGFsbCByZXF1ZXN0cyB3aWxsIHVzZSB0aGlzIHNlc3Npb24gYnkgZGVmYXVsdFxuICogfSlcbiAqIGBgYFxuICogWW91IHNob3VsZCAqKm5ldmVyKiogc2V0IGEgZGVmYXVsdCBgYXV0aGVudGljYXRpb25gIHdoZW4geW91IGFyZSBpbiBhIHNlcnZlciBzaWRlIGVudmlyb25tZW50IHdoZXJlIHlvdSBtYXkgYmUgaGFuZGxpbmcgcmVxdWVzdHMgZm9yIG1hbnkgZGlmZmVyZW50IGF1dGhlbnRpY2F0ZWQgdXNlcnMuXG4gKlxuICogQHBhcmFtIG9wdGlvbnMgVGhlIGRlZmF1bHQgb3B0aW9ucyB0byBwYXNzIHdpdGggZXZlcnkgcmVxdWVzdC4gRXhpc3RpbmcgZGVmYXVsdCB3aWxsIGJlIG92ZXJ3cml0dGVuLlxuICogQHBhcmFtIGhpZGVXYXJuaW5ncyBTaWxlbmNlIHdhcm5pbmdzIGFib3V0IHNldHRpbmcgZGVmYXVsdCBgYXV0aGVudGljYXRpb25gIGluIHNoYXJlZCBlbnZpcm9ubWVudHMuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBzZXREZWZhdWx0UmVxdWVzdE9wdGlvbnMob3B0aW9ucywgaGlkZVdhcm5pbmdzKSB7XG4gICAgaWYgKG9wdGlvbnMuYXV0aGVudGljYXRpb24gJiYgIWhpZGVXYXJuaW5ncykge1xuICAgICAgICB3YXJuKFwiWW91IHNob3VsZCBub3Qgc2V0IGBhdXRoZW50aWNhdGlvbmAgYXMgYSBkZWZhdWx0IGluIGEgc2hhcmVkIGVudmlyb25tZW50IHN1Y2ggYXMgYSB3ZWIgc2VydmVyIHdoaWNoIHdpbGwgcHJvY2VzcyBtdWx0aXBsZSB1c2VycyByZXF1ZXN0cy4gWW91IGNhbiBjYWxsIGBzZXREZWZhdWx0UmVxdWVzdE9wdGlvbnNgIHdpdGggYHRydWVgIGFzIGEgc2Vjb25kIGFyZ3VtZW50IHRvIGRpc2FibGUgdGhpcyB3YXJuaW5nLlwiKTtcbiAgICB9XG4gICAgREVGQVVMVF9BUkNHSVNfUkVRVUVTVF9PUFRJT05TID0gb3B0aW9ucztcbn1cbnZhciBBcmNHSVNBdXRoRXJyb3IgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoX3N1cGVyKSB7XG4gICAgX19leHRlbmRzKEFyY0dJU0F1dGhFcnJvciwgX3N1cGVyKTtcbiAgICAvKipcbiAgICAgKiBDcmVhdGUgYSBuZXcgYEFyY0dJU0F1dGhFcnJvcmAgIG9iamVjdC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBtZXNzYWdlIC0gVGhlIGVycm9yIG1lc3NhZ2UgZnJvbSB0aGUgQVBJXG4gICAgICogQHBhcmFtIGNvZGUgLSBUaGUgZXJyb3IgY29kZSBmcm9tIHRoZSBBUElcbiAgICAgKiBAcGFyYW0gcmVzcG9uc2UgLSBUaGUgb3JpZ2luYWwgcmVzcG9uc2UgZnJvbSB0aGUgQVBJIHRoYXQgY2F1c2VkIHRoZSBlcnJvclxuICAgICAqIEBwYXJhbSB1cmwgLSBUaGUgb3JpZ2luYWwgdXJsIG9mIHRoZSByZXF1ZXN0XG4gICAgICogQHBhcmFtIG9wdGlvbnMgLSBUaGUgb3JpZ2luYWwgb3B0aW9ucyBvZiB0aGUgcmVxdWVzdFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIEFyY0dJU0F1dGhFcnJvcihtZXNzYWdlLCBjb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKSB7XG4gICAgICAgIGlmIChtZXNzYWdlID09PSB2b2lkIDApIHsgbWVzc2FnZSA9IFwiQVVUSEVOVElDQVRJT05fRVJST1JcIjsgfVxuICAgICAgICBpZiAoY29kZSA9PT0gdm9pZCAwKSB7IGNvZGUgPSBcIkFVVEhFTlRJQ0FUSU9OX0VSUk9SX0NPREVcIjsgfVxuICAgICAgICB2YXIgX3RoaXMgPSBfc3VwZXIuY2FsbCh0aGlzLCBtZXNzYWdlLCBjb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKSB8fCB0aGlzO1xuICAgICAgICBfdGhpcy5uYW1lID0gXCJBcmNHSVNBdXRoRXJyb3JcIjtcbiAgICAgICAgX3RoaXMubWVzc2FnZSA9XG4gICAgICAgICAgICBjb2RlID09PSBcIkFVVEhFTlRJQ0FUSU9OX0VSUk9SX0NPREVcIiA/IG1lc3NhZ2UgOiBjb2RlICsgXCI6IFwiICsgbWVzc2FnZTtcbiAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgIH1cbiAgICBBcmNHSVNBdXRoRXJyb3IucHJvdG90eXBlLnJldHJ5ID0gZnVuY3Rpb24gKGdldFNlc3Npb24sIHJldHJ5TGltaXQpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgaWYgKHJldHJ5TGltaXQgPT09IHZvaWQgMCkgeyByZXRyeUxpbWl0ID0gMzsgfVxuICAgICAgICB2YXIgdHJpZXMgPSAwO1xuICAgICAgICB2YXIgcmV0cnlSZXF1ZXN0ID0gZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xuICAgICAgICAgICAgZ2V0U2Vzc2lvbihfdGhpcy51cmwsIF90aGlzLm9wdGlvbnMpXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHNlc3Npb24pIHtcbiAgICAgICAgICAgICAgICB2YXIgbmV3T3B0aW9ucyA9IF9fYXNzaWduKF9fYXNzaWduKHt9LCBfdGhpcy5vcHRpb25zKSwgeyBhdXRoZW50aWNhdGlvbjogc2Vzc2lvbiB9KTtcbiAgICAgICAgICAgICAgICB0cmllcyA9IHRyaWVzICsgMTtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVxdWVzdChfdGhpcy51cmwsIG5ld09wdGlvbnMpO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICByZXNvbHZlKHJlc3BvbnNlKTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLmNhdGNoKGZ1bmN0aW9uIChlKSB7XG4gICAgICAgICAgICAgICAgaWYgKGUubmFtZSA9PT0gXCJBcmNHSVNBdXRoRXJyb3JcIiAmJiB0cmllcyA8IHJldHJ5TGltaXQpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0cnlSZXF1ZXN0KHJlc29sdmUsIHJlamVjdCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYgKGUubmFtZSA9PT0gXCJBcmNHSVNBdXRoRXJyb3JcIiAmJiB0cmllcyA+PSByZXRyeUxpbWl0KSB7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChfdGhpcyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICByZWplY3QoZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XG4gICAgICAgICAgICByZXRyeVJlcXVlc3QocmVzb2x2ZSwgcmVqZWN0KTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICByZXR1cm4gQXJjR0lTQXV0aEVycm9yO1xufShBcmNHSVNSZXF1ZXN0RXJyb3IpKTtcbmV4cG9ydCB7IEFyY0dJU0F1dGhFcnJvciB9O1xuLyoqXG4gKiBDaGVja3MgZm9yIGVycm9ycyBpbiBhIEpTT04gcmVzcG9uc2UgZnJvbSB0aGUgQXJjR0lTIFJFU1QgQVBJLiBJZiB0aGVyZSBhcmUgbm8gZXJyb3JzLCBpdCB3aWxsIHJldHVybiB0aGUgYGRhdGFgIHBhc3NlZCBpbi4gSWYgdGhlcmUgaXMgYW4gZXJyb3IsIGl0IHdpbGwgdGhyb3cgYW4gYEFyY0dJU1JlcXVlc3RFcnJvcmAgb3IgYEFyY0dJU0F1dGhFcnJvcmAuXG4gKlxuICogQHBhcmFtIGRhdGEgVGhlIHJlc3BvbnNlIEpTT04gdG8gY2hlY2sgZm9yIGVycm9ycy5cbiAqIEBwYXJhbSB1cmwgVGhlIHVybCBvZiB0aGUgb3JpZ2luYWwgcmVxdWVzdFxuICogQHBhcmFtIHBhcmFtcyBUaGUgcGFyYW1ldGVycyBvZiB0aGUgb3JpZ2luYWwgcmVxdWVzdFxuICogQHBhcmFtIG9wdGlvbnMgVGhlIG9wdGlvbnMgb2YgdGhlIG9yaWdpbmFsIHJlcXVlc3RcbiAqIEByZXR1cm5zIFRoZSBkYXRhIHRoYXQgd2FzIHBhc3NlZCBpbiB0aGUgYGRhdGFgIHBhcmFtZXRlclxuICovXG5leHBvcnQgZnVuY3Rpb24gY2hlY2tGb3JFcnJvcnMocmVzcG9uc2UsIHVybCwgcGFyYW1zLCBvcHRpb25zLCBvcmlnaW5hbEF1dGhFcnJvcikge1xuICAgIC8vIHRoaXMgaXMgYW4gZXJyb3IgbWVzc2FnZSBmcm9tIGJpbGxpbmcuYXJjZ2lzLmNvbSBiYWNrZW5kXG4gICAgaWYgKHJlc3BvbnNlLmNvZGUgPj0gNDAwKSB7XG4gICAgICAgIHZhciBtZXNzYWdlID0gcmVzcG9uc2UubWVzc2FnZSwgY29kZSA9IHJlc3BvbnNlLmNvZGU7XG4gICAgICAgIHRocm93IG5ldyBBcmNHSVNSZXF1ZXN0RXJyb3IobWVzc2FnZSwgY29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucyk7XG4gICAgfVxuICAgIC8vIGVycm9yIGZyb20gQXJjR0lTIE9ubGluZSBvciBhbiBBcmNHSVMgUG9ydGFsIG9yIHNlcnZlciBpbnN0YW5jZS5cbiAgICBpZiAocmVzcG9uc2UuZXJyb3IpIHtcbiAgICAgICAgdmFyIF9hID0gcmVzcG9uc2UuZXJyb3IsIG1lc3NhZ2UgPSBfYS5tZXNzYWdlLCBjb2RlID0gX2EuY29kZSwgbWVzc2FnZUNvZGUgPSBfYS5tZXNzYWdlQ29kZTtcbiAgICAgICAgdmFyIGVycm9yQ29kZSA9IG1lc3NhZ2VDb2RlIHx8IGNvZGUgfHwgXCJVTktOT1dOX0VSUk9SX0NPREVcIjtcbiAgICAgICAgaWYgKGNvZGUgPT09IDQ5OCB8fFxuICAgICAgICAgICAgY29kZSA9PT0gNDk5IHx8XG4gICAgICAgICAgICBtZXNzYWdlQ29kZSA9PT0gXCJHV01fMDAwM1wiIHx8XG4gICAgICAgICAgICAoY29kZSA9PT0gNDAwICYmIG1lc3NhZ2UgPT09IFwiVW5hYmxlIHRvIGdlbmVyYXRlIHRva2VuLlwiKSkge1xuICAgICAgICAgICAgaWYgKG9yaWdpbmFsQXV0aEVycm9yKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgb3JpZ2luYWxBdXRoRXJyb3I7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgQXJjR0lTQXV0aEVycm9yKG1lc3NhZ2UsIGVycm9yQ29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgdGhyb3cgbmV3IEFyY0dJU1JlcXVlc3RFcnJvcihtZXNzYWdlLCBlcnJvckNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpO1xuICAgIH1cbiAgICAvLyBlcnJvciBmcm9tIGEgc3RhdHVzIGNoZWNrXG4gICAgaWYgKHJlc3BvbnNlLnN0YXR1cyA9PT0gXCJmYWlsZWRcIiB8fCByZXNwb25zZS5zdGF0dXMgPT09IFwiZmFpbHVyZVwiKSB7XG4gICAgICAgIHZhciBtZXNzYWdlID0gdm9pZCAwO1xuICAgICAgICB2YXIgY29kZSA9IFwiVU5LTk9XTl9FUlJPUl9DT0RFXCI7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBtZXNzYWdlID0gSlNPTi5wYXJzZShyZXNwb25zZS5zdGF0dXNNZXNzYWdlKS5tZXNzYWdlO1xuICAgICAgICAgICAgY29kZSA9IEpTT04ucGFyc2UocmVzcG9uc2Uuc3RhdHVzTWVzc2FnZSkuY29kZTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZSkge1xuICAgICAgICAgICAgbWVzc2FnZSA9IHJlc3BvbnNlLnN0YXR1c01lc3NhZ2UgfHwgcmVzcG9uc2UubWVzc2FnZTtcbiAgICAgICAgfVxuICAgICAgICB0aHJvdyBuZXcgQXJjR0lTUmVxdWVzdEVycm9yKG1lc3NhZ2UsIGNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpO1xuICAgIH1cbiAgICByZXR1cm4gcmVzcG9uc2U7XG59XG4vKipcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyByZXF1ZXN0IH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdCc7XG4gKiAvL1xuICogcmVxdWVzdCgnaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3QnKVxuICogICAudGhlbihyZXNwb25zZSkgLy8gcmVzcG9uc2UuY3VycmVudFZlcnNpb24gPT09IDUuMlxuICogLy9cbiAqIHJlcXVlc3QoJ2h0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0Jywge1xuICogICBodHRwTWV0aG9kOiBcIkdFVFwiXG4gKiB9KVxuICogLy9cbiAqIHJlcXVlc3QoJ2h0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0L3NlYXJjaCcsIHtcbiAqICAgcGFyYW1zOiB7IHE6ICdwYXJrcycgfVxuICogfSlcbiAqICAgLnRoZW4ocmVzcG9uc2UpIC8vIHJlc3BvbnNlLnRvdGFsID0+IDc4Mzc5XG4gKiBgYGBcbiAqIEdlbmVyaWMgbWV0aG9kIGZvciBtYWtpbmcgSFRUUCByZXF1ZXN0cyB0byBBcmNHSVMgUkVTVCBBUEkgZW5kcG9pbnRzLlxuICpcbiAqIEBwYXJhbSB1cmwgLSBUaGUgVVJMIG9mIHRoZSBBcmNHSVMgUkVTVCBBUEkgZW5kcG9pbnQuXG4gKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdCwgaW5jbHVkaW5nIHBhcmFtZXRlcnMgcmVsZXZhbnQgdG8gdGhlIGVuZHBvaW50LlxuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIGRhdGEgZnJvbSB0aGUgcmVzcG9uc2UuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiByZXF1ZXN0KHVybCwgcmVxdWVzdE9wdGlvbnMpIHtcbiAgICBpZiAocmVxdWVzdE9wdGlvbnMgPT09IHZvaWQgMCkgeyByZXF1ZXN0T3B0aW9ucyA9IHsgcGFyYW1zOiB7IGY6IFwianNvblwiIH0gfTsgfVxuICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oX19hc3NpZ24oX19hc3NpZ24oeyBodHRwTWV0aG9kOiBcIlBPU1RcIiB9LCBERUZBVUxUX0FSQ0dJU19SRVFVRVNUX09QVElPTlMpLCByZXF1ZXN0T3B0aW9ucyksIHtcbiAgICAgICAgcGFyYW1zOiBfX2Fzc2lnbihfX2Fzc2lnbih7fSwgREVGQVVMVF9BUkNHSVNfUkVRVUVTVF9PUFRJT05TLnBhcmFtcyksIHJlcXVlc3RPcHRpb25zLnBhcmFtcyksXG4gICAgICAgIGhlYWRlcnM6IF9fYXNzaWduKF9fYXNzaWduKHt9LCBERUZBVUxUX0FSQ0dJU19SRVFVRVNUX09QVElPTlMuaGVhZGVycyksIHJlcXVlc3RPcHRpb25zLmhlYWRlcnMpLFxuICAgIH0pO1xuICAgIHZhciBtaXNzaW5nR2xvYmFscyA9IFtdO1xuICAgIHZhciByZWNvbW1lbmRlZFBhY2thZ2VzID0gW107XG4gICAgLy8gZG9uJ3QgY2hlY2sgZm9yIGEgZ2xvYmFsIGZldGNoIGlmIGEgY3VzdG9tIGltcGxlbWVudGF0aW9uIHdhcyBwYXNzZWQgdGhyb3VnaFxuICAgIGlmICghb3B0aW9ucy5mZXRjaCAmJiB0eXBlb2YgZmV0Y2ggIT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgb3B0aW9ucy5mZXRjaCA9IGZldGNoLmJpbmQoRnVuY3Rpb24oXCJyZXR1cm4gdGhpc1wiKSgpKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIG1pc3NpbmdHbG9iYWxzLnB1c2goXCJgZmV0Y2hgXCIpO1xuICAgICAgICByZWNvbW1lbmRlZFBhY2thZ2VzLnB1c2goXCJgbm9kZS1mZXRjaGBcIik7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgUHJvbWlzZSA9PT0gXCJ1bmRlZmluZWRcIikge1xuICAgICAgICBtaXNzaW5nR2xvYmFscy5wdXNoKFwiYFByb21pc2VgXCIpO1xuICAgICAgICByZWNvbW1lbmRlZFBhY2thZ2VzLnB1c2goXCJgZXM2LXByb21pc2VgXCIpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIEZvcm1EYXRhID09PSBcInVuZGVmaW5lZFwiKSB7XG4gICAgICAgIG1pc3NpbmdHbG9iYWxzLnB1c2goXCJgRm9ybURhdGFgXCIpO1xuICAgICAgICByZWNvbW1lbmRlZFBhY2thZ2VzLnB1c2goXCJgaXNvbW9ycGhpYy1mb3JtLWRhdGFgXCIpO1xuICAgIH1cbiAgICBpZiAoIW9wdGlvbnMuZmV0Y2ggfHxcbiAgICAgICAgdHlwZW9mIFByb21pc2UgPT09IFwidW5kZWZpbmVkXCIgfHxcbiAgICAgICAgdHlwZW9mIEZvcm1EYXRhID09PSBcInVuZGVmaW5lZFwiKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihcImBhcmNnaXMtcmVzdC1yZXF1ZXN0YCByZXF1aXJlcyBhIGBmZXRjaGAgaW1wbGVtZW50YXRpb24gYW5kIGdsb2JhbCB2YXJpYWJsZXMgZm9yIGBQcm9taXNlYCBhbmQgYEZvcm1EYXRhYCB0byBiZSBwcmVzZW50IGluIHRoZSBnbG9iYWwgc2NvcGUuIFlvdSBhcmUgbWlzc2luZyBcIiArIG1pc3NpbmdHbG9iYWxzLmpvaW4oXCIsIFwiKSArIFwiLiBXZSByZWNvbW1lbmQgaW5zdGFsbGluZyB0aGUgXCIgKyByZWNvbW1lbmRlZFBhY2thZ2VzLmpvaW4oXCIsIFwiKSArIFwiIG1vZHVsZXMgYXQgdGhlIHJvb3Qgb2YgeW91ciBhcHBsaWNhdGlvbiB0byBhZGQgdGhlc2UgdG8gdGhlIGdsb2JhbCBzY29wZS4gU2VlIGh0dHBzOi8vYml0Lmx5LzJLTndXYUogZm9yIG1vcmUgaW5mby5cIik7XG4gICAgfVxuICAgIHZhciBodHRwTWV0aG9kID0gb3B0aW9ucy5odHRwTWV0aG9kLCBhdXRoZW50aWNhdGlvbiA9IG9wdGlvbnMuYXV0aGVudGljYXRpb24sIHJhd1Jlc3BvbnNlID0gb3B0aW9ucy5yYXdSZXNwb25zZTtcbiAgICB2YXIgcGFyYW1zID0gX19hc3NpZ24oeyBmOiBcImpzb25cIiB9LCBvcHRpb25zLnBhcmFtcyk7XG4gICAgdmFyIG9yaWdpbmFsQXV0aEVycm9yID0gbnVsbDtcbiAgICB2YXIgZmV0Y2hPcHRpb25zID0ge1xuICAgICAgICBtZXRob2Q6IGh0dHBNZXRob2QsXG4gICAgICAgIC8qIGVuc3VyZXMgYmVoYXZpb3IgbWltaWNzIFhNTEh0dHBSZXF1ZXN0LlxuICAgICAgICBuZWVkZWQgdG8gc3VwcG9ydCBzZW5kaW5nIElXQSBjb29raWVzICovXG4gICAgICAgIGNyZWRlbnRpYWxzOiBvcHRpb25zLmNyZWRlbnRpYWxzIHx8IFwic2FtZS1vcmlnaW5cIixcbiAgICB9O1xuICAgIC8vIHRoZSAvb2F1dGgyL3BsYXRmb3JtU2VsZiByb3V0ZSB3aWxsIGFkZCBYLUVzcmktQXV0aC1DbGllbnQtSWQgaGVhZGVyXG4gICAgLy8gYW5kIHRoYXQgcmVxdWVzdCBuZWVkcyB0byBzZW5kIGNvb2tpZXMgY3Jvc3MgZG9tYWluXG4gICAgLy8gc28gd2UgbmVlZCB0byBzZXQgdGhlIGNyZWRlbnRpYWxzIHRvIFwiaW5jbHVkZVwiXG4gICAgaWYgKG9wdGlvbnMuaGVhZGVycyAmJlxuICAgICAgICBvcHRpb25zLmhlYWRlcnNbXCJYLUVzcmktQXV0aC1DbGllbnQtSWRcIl0gJiZcbiAgICAgICAgdXJsLmluZGV4T2YoXCIvb2F1dGgyL3BsYXRmb3JtU2VsZlwiKSA+IC0xKSB7XG4gICAgICAgIGZldGNoT3B0aW9ucy5jcmVkZW50aWFscyA9IFwiaW5jbHVkZVwiO1xuICAgIH1cbiAgICByZXR1cm4gKGF1dGhlbnRpY2F0aW9uXG4gICAgICAgID8gYXV0aGVudGljYXRpb24uZ2V0VG9rZW4odXJsLCB7IGZldGNoOiBvcHRpb25zLmZldGNoIH0pLmNhdGNoKGZ1bmN0aW9uIChlcnIpIHtcbiAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICogYXBwZW5kIG9yaWdpbmFsIHJlcXVlc3QgdXJsIGFuZCByZXF1ZXN0T3B0aW9uc1xuICAgICAgICAgICAgICogdG8gdGhlIGVycm9yIHRocm93biBieSBnZXRUb2tlbigpXG4gICAgICAgICAgICAgKiB0byBhc3Npc3Qgd2l0aCByZXRyeWluZ1xuICAgICAgICAgICAgICovXG4gICAgICAgICAgICBlcnIudXJsID0gdXJsO1xuICAgICAgICAgICAgZXJyLm9wdGlvbnMgPSBvcHRpb25zO1xuICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgKiBpZiBhbiBhdHRlbXB0IGlzIG1hZGUgdG8gdGFsayB0byBhbiB1bmZlZGVyYXRlZCBzZXJ2ZXJcbiAgICAgICAgICAgICAqIGZpcnN0IHRyeSB0aGUgcmVxdWVzdCBhbm9ueW1vdXNseS4gaWYgYSAndG9rZW4gcmVxdWlyZWQnXG4gICAgICAgICAgICAgKiBlcnJvciBpcyB0aHJvd24sIHRocm93IHRoZSBVTkZFREVSQVRFRCBlcnJvciB0aGVuLlxuICAgICAgICAgICAgICovXG4gICAgICAgICAgICBvcmlnaW5hbEF1dGhFcnJvciA9IGVycjtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoXCJcIik7XG4gICAgICAgIH0pXG4gICAgICAgIDogUHJvbWlzZS5yZXNvbHZlKFwiXCIpKVxuICAgICAgICAudGhlbihmdW5jdGlvbiAodG9rZW4pIHtcbiAgICAgICAgaWYgKHRva2VuLmxlbmd0aCkge1xuICAgICAgICAgICAgcGFyYW1zLnRva2VuID0gdG9rZW47XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGF1dGhlbnRpY2F0aW9uICYmIGF1dGhlbnRpY2F0aW9uLmdldERvbWFpbkNyZWRlbnRpYWxzKSB7XG4gICAgICAgICAgICBmZXRjaE9wdGlvbnMuY3JlZGVudGlhbHMgPSBhdXRoZW50aWNhdGlvbi5nZXREb21haW5DcmVkZW50aWFscyh1cmwpO1xuICAgICAgICB9XG4gICAgICAgIC8vIEN1c3RvbSBoZWFkZXJzIHRvIGFkZCB0byByZXF1ZXN0LiBJUmVxdWVzdE9wdGlvbnMuaGVhZGVycyB3aXRoIG1lcmdlIG92ZXIgcmVxdWVzdEhlYWRlcnMuXG4gICAgICAgIHZhciByZXF1ZXN0SGVhZGVycyA9IHt9O1xuICAgICAgICBpZiAoZmV0Y2hPcHRpb25zLm1ldGhvZCA9PT0gXCJHRVRcIikge1xuICAgICAgICAgICAgLy8gUHJldmVudHMgdG9rZW4gZnJvbSBiZWluZyBwYXNzZWQgaW4gcXVlcnkgcGFyYW1zIHdoZW4gaGlkZVRva2VuIG9wdGlvbiBpcyB1c2VkLlxuICAgICAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIGlmIC0gd2luZG93IGlzIGFsd2F5cyBkZWZpbmVkIGluIGEgYnJvd3Nlci4gVGVzdCBjYXNlIGlzIGNvdmVyZWQgYnkgSmFzbWluZSBpbiBub2RlIHRlc3QgKi9cbiAgICAgICAgICAgIGlmIChwYXJhbXMudG9rZW4gJiZcbiAgICAgICAgICAgICAgICBvcHRpb25zLmhpZGVUb2tlbiAmJlxuICAgICAgICAgICAgICAgIC8vIFNoYXJpbmcgQVBJIGRvZXMgbm90IHN1cHBvcnQgcHJlZmxpZ2h0IGNoZWNrIHJlcXVpcmVkIGJ5IG1vZGVybiBicm93c2VycyBodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL0dsb3NzYXJ5L1ByZWZsaWdodF9yZXF1ZXN0XG4gICAgICAgICAgICAgICAgdHlwZW9mIHdpbmRvdyA9PT0gXCJ1bmRlZmluZWRcIikge1xuICAgICAgICAgICAgICAgIHJlcXVlc3RIZWFkZXJzW1wiWC1Fc3JpLUF1dGhvcml6YXRpb25cIl0gPSBcIkJlYXJlciBcIiArIHBhcmFtcy50b2tlbjtcbiAgICAgICAgICAgICAgICBkZWxldGUgcGFyYW1zLnRva2VuO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgLy8gZW5jb2RlIHRoZSBwYXJhbWV0ZXJzIGludG8gdGhlIHF1ZXJ5IHN0cmluZ1xuICAgICAgICAgICAgdmFyIHF1ZXJ5UGFyYW1zID0gZW5jb2RlUXVlcnlTdHJpbmcocGFyYW1zKTtcbiAgICAgICAgICAgIC8vIGRvbnQgYXBwZW5kIGEgJz8nIHVubGVzcyBwYXJhbWV0ZXJzIGFyZSBhY3R1YWxseSBwcmVzZW50XG4gICAgICAgICAgICB2YXIgdXJsV2l0aFF1ZXJ5U3RyaW5nID0gcXVlcnlQYXJhbXMgPT09IFwiXCIgPyB1cmwgOiB1cmwgKyBcIj9cIiArIGVuY29kZVF1ZXJ5U3RyaW5nKHBhcmFtcyk7XG4gICAgICAgICAgICBpZiAoXG4gICAgICAgICAgICAvLyBUaGlzIHdvdWxkIGV4Y2VlZCB0aGUgbWF4aW11bSBsZW5ndGggZm9yIFVSTHMgc3BlY2lmaWVkIGJ5IHRoZSBjb25zdW1lciBhbmQgcmVxdWlyZXMgUE9TVFxuICAgICAgICAgICAgKG9wdGlvbnMubWF4VXJsTGVuZ3RoICYmXG4gICAgICAgICAgICAgICAgdXJsV2l0aFF1ZXJ5U3RyaW5nLmxlbmd0aCA+IG9wdGlvbnMubWF4VXJsTGVuZ3RoKSB8fFxuICAgICAgICAgICAgICAgIC8vIE9yIGlmIHRoZSBjdXN0b21lciByZXF1aXJlcyB0aGUgdG9rZW4gdG8gYmUgaGlkZGVuIGFuZCBpdCBoYXMgbm90IGFscmVhZHkgYmVlbiBoaWRkZW4gaW4gdGhlIGhlYWRlciAoZm9yIGJyb3dzZXJzKVxuICAgICAgICAgICAgICAgIChwYXJhbXMudG9rZW4gJiYgb3B0aW9ucy5oaWRlVG9rZW4pKSB7XG4gICAgICAgICAgICAgICAgLy8gdGhlIGNvbnN1bWVyIHNwZWNpZmllZCBhIG1heGltdW0gbGVuZ3RoIGZvciBVUkxzXG4gICAgICAgICAgICAgICAgLy8gYW5kIHRoaXMgd291bGQgZXhjZWVkIGl0LCBzbyB1c2UgcG9zdCBpbnN0ZWFkXG4gICAgICAgICAgICAgICAgZmV0Y2hPcHRpb25zLm1ldGhvZCA9IFwiUE9TVFwiO1xuICAgICAgICAgICAgICAgIC8vIElmIHRoZSB0b2tlbiB3YXMgYWxyZWFkeSBhZGRlZCBhcyBhIEF1dGggaGVhZGVyLCBhZGQgdGhlIHRva2VuIGJhY2sgdG8gYm9keSB3aXRoIG90aGVyIHBhcmFtcyBpbnN0ZWFkIG9mIGhlYWRlclxuICAgICAgICAgICAgICAgIGlmICh0b2tlbi5sZW5ndGggJiYgb3B0aW9ucy5oaWRlVG9rZW4pIHtcbiAgICAgICAgICAgICAgICAgICAgcGFyYW1zLnRva2VuID0gdG9rZW47XG4gICAgICAgICAgICAgICAgICAgIC8vIFJlbW92ZSBleGlzdGluZyBoZWFkZXIgdGhhdCB3YXMgYWRkZWQgYmVmb3JlIHVybCBxdWVyeSBsZW5ndGggd2FzIGNoZWNrZWRcbiAgICAgICAgICAgICAgICAgICAgZGVsZXRlIHJlcXVlc3RIZWFkZXJzW1wiWC1Fc3JpLUF1dGhvcml6YXRpb25cIl07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgLy8ganVzdCB1c2UgR0VUXG4gICAgICAgICAgICAgICAgdXJsID0gdXJsV2l0aFF1ZXJ5U3RyaW5nO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIC8qIHVwZGF0ZVJlc291cmNlcyBjdXJyZW50bHkgcmVxdWlyZXMgRm9ybURhdGEgZXZlbiB3aGVuIHRoZSBpbnB1dCBwYXJhbWV0ZXJzIGRvbnQgd2FycmFudCBpdC5cbiAgICBodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3VzZXJzLWdyb3Vwcy1hbmQtaXRlbXMvdXBkYXRlLXJlc291cmNlcy5odG1cbiAgICAgICAgc2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9Fc3JpL2FyY2dpcy1yZXN0LWpzL3B1bGwvNTAwIGZvciBtb3JlIGluZm8uICovXG4gICAgICAgIHZhciBmb3JjZUZvcm1EYXRhID0gbmV3IFJlZ0V4cChcIi9pdGVtcy8uKy91cGRhdGVSZXNvdXJjZXNcIikudGVzdCh1cmwpO1xuICAgICAgICBpZiAoZmV0Y2hPcHRpb25zLm1ldGhvZCA9PT0gXCJQT1NUXCIpIHtcbiAgICAgICAgICAgIGZldGNoT3B0aW9ucy5ib2R5ID0gZW5jb2RlRm9ybURhdGEocGFyYW1zLCBmb3JjZUZvcm1EYXRhKTtcbiAgICAgICAgfVxuICAgICAgICAvLyBNaXhpbiBoZWFkZXJzIGZyb20gcmVxdWVzdCBvcHRpb25zXG4gICAgICAgIGZldGNoT3B0aW9ucy5oZWFkZXJzID0gX19hc3NpZ24oX19hc3NpZ24oe30sIHJlcXVlc3RIZWFkZXJzKSwgb3B0aW9ucy5oZWFkZXJzKTtcbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgLSBrYXJtYSByZXBvcnRzIGNvdmVyYWdlIG9uIGJyb3dzZXIgdGVzdHMgb25seSAqL1xuICAgICAgICBpZiAodHlwZW9mIHdpbmRvdyA9PT0gXCJ1bmRlZmluZWRcIiAmJiAhZmV0Y2hPcHRpb25zLmhlYWRlcnMucmVmZXJlcikge1xuICAgICAgICAgICAgZmV0Y2hPcHRpb25zLmhlYWRlcnMucmVmZXJlciA9IE5PREVKU19ERUZBVUxUX1JFRkVSRVJfSEVBREVSO1xuICAgICAgICB9XG4gICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBlbHNlIGJsb2IgcmVzcG9uc2VzIGFyZSBkaWZmaWN1bHQgdG8gbWFrZSBjcm9zcyBwbGF0Zm9ybSB3ZSB3aWxsIGp1c3QgaGF2ZSB0byB0cnVzdCB0aGUgaXNvbW9ycGhpYyBmZXRjaCB3aWxsIGRvIGl0cyBqb2IgKi9cbiAgICAgICAgaWYgKCFyZXF1aXJlc0Zvcm1EYXRhKHBhcmFtcykgJiYgIWZvcmNlRm9ybURhdGEpIHtcbiAgICAgICAgICAgIGZldGNoT3B0aW9ucy5oZWFkZXJzW1wiQ29udGVudC1UeXBlXCJdID1cbiAgICAgICAgICAgICAgICBcImFwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZFwiO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBvcHRpb25zLmZldGNoKHVybCwgZmV0Y2hPcHRpb25zKTtcbiAgICB9KVxuICAgICAgICAudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKCFyZXNwb25zZS5vaykge1xuICAgICAgICAgICAgLy8gc2VydmVyIHJlc3BvbmRlZCB3LyBhbiBhY3R1YWwgZXJyb3IgKDQwNCwgNTAwLCBldGMpXG4gICAgICAgICAgICB2YXIgc3RhdHVzXzEgPSByZXNwb25zZS5zdGF0dXMsIHN0YXR1c1RleHQgPSByZXNwb25zZS5zdGF0dXNUZXh0O1xuICAgICAgICAgICAgdGhyb3cgbmV3IEFyY0dJU1JlcXVlc3RFcnJvcihzdGF0dXNUZXh0LCBcIkhUVFAgXCIgKyBzdGF0dXNfMSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHJhd1Jlc3BvbnNlKSB7XG4gICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH1cbiAgICAgICAgc3dpdGNoIChwYXJhbXMuZikge1xuICAgICAgICAgICAgY2FzZSBcImpzb25cIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuanNvbigpO1xuICAgICAgICAgICAgY2FzZSBcImdlb2pzb25cIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuanNvbigpO1xuICAgICAgICAgICAgY2FzZSBcImh0bWxcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UudGV4dCgpO1xuICAgICAgICAgICAgY2FzZSBcInRleHRcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UudGV4dCgpO1xuICAgICAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgYmxvYiByZXNwb25zZXMgYXJlIGRpZmZpY3VsdCB0byBtYWtlIGNyb3NzIHBsYXRmb3JtIHdlIHdpbGwganVzdCBoYXZlIHRvIHRydXN0IHRoYXQgaXNvbW9ycGhpYyBmZXRjaCB3aWxsIGRvIGl0cyBqb2IgKi9cbiAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmJsb2IoKTtcbiAgICAgICAgfVxuICAgIH0pXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIGlmICgocGFyYW1zLmYgPT09IFwianNvblwiIHx8IHBhcmFtcy5mID09PSBcImdlb2pzb25cIikgJiYgIXJhd1Jlc3BvbnNlKSB7XG4gICAgICAgICAgICB2YXIgcmVzcG9uc2UgPSBjaGVja0ZvckVycm9ycyhkYXRhLCB1cmwsIHBhcmFtcywgb3B0aW9ucywgb3JpZ2luYWxBdXRoRXJyb3IpO1xuICAgICAgICAgICAgaWYgKG9yaWdpbmFsQXV0aEVycm9yKSB7XG4gICAgICAgICAgICAgICAgLyogSWYgdGhlIHJlcXVlc3Qgd2FzIG1hZGUgdG8gYW4gdW5mZWRlcmF0ZWQgc2VydmljZSB0aGF0XG4gICAgICAgICAgICAgICAgZGlkbid0IHJlcXVpcmUgYXV0aGVudGljYXRpb24sIGFkZCB0aGUgYmFzZSB1cmwgYW5kIGEgZHVtbXkgdG9rZW5cbiAgICAgICAgICAgICAgICB0byB0aGUgbGlzdCBvZiB0cnVzdGVkIHNlcnZlcnMgdG8gYXZvaWQgYW5vdGhlciBmZWRlcmF0aW9uIGNoZWNrXG4gICAgICAgICAgICAgICAgaW4gdGhlIGV2ZW50IG9mIGEgcmVwZWF0IHJlcXVlc3QgKi9cbiAgICAgICAgICAgICAgICB2YXIgdHJ1bmNhdGVkVXJsID0gdXJsXG4gICAgICAgICAgICAgICAgICAgIC50b0xvd2VyQ2FzZSgpXG4gICAgICAgICAgICAgICAgICAgIC5zcGxpdCgvXFwvcmVzdChcXC9hZG1pbik/XFwvc2VydmljZXNcXC8vKVswXTtcbiAgICAgICAgICAgICAgICBvcHRpb25zLmF1dGhlbnRpY2F0aW9uLmZlZGVyYXRlZFNlcnZlcnNbdHJ1bmNhdGVkVXJsXSA9IHtcbiAgICAgICAgICAgICAgICAgICAgdG9rZW46IFtdLFxuICAgICAgICAgICAgICAgICAgICAvLyBkZWZhdWx0IHRvIDI0IGhvdXJzXG4gICAgICAgICAgICAgICAgICAgIGV4cGlyZXM6IG5ldyBEYXRlKERhdGUubm93KCkgKyA4NjQwMCAqIDEwMDApLFxuICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgICAgb3JpZ2luYWxBdXRoRXJyb3IgPSBudWxsO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIGRhdGE7XG4gICAgICAgIH1cbiAgICB9KTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXJlcXVlc3QuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbi8vIFR5cGVTY3JpcHQgMi4xIG5vIGxvbmdlciBhbGxvd3MgeW91IHRvIGV4dGVuZCBidWlsdCBpbiB0eXBlcy4gU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9NaWNyb3NvZnQvVHlwZVNjcmlwdC9pc3N1ZXMvMTI3OTAjaXNzdWVjb21tZW50LTI2NTk4MTQ0MlxuLy8gYW5kIGh0dHBzOi8vZ2l0aHViLmNvbS9NaWNyb3NvZnQvVHlwZVNjcmlwdC13aWtpL2Jsb2IvbWFzdGVyL0JyZWFraW5nLUNoYW5nZXMubWQjZXh0ZW5kaW5nLWJ1aWx0LWlucy1saWtlLWVycm9yLWFycmF5LWFuZC1tYXAtbWF5LW5vLWxvbmdlci13b3JrXG4vL1xuLy8gVGhpcyBjb2RlIGlzIGZyb20gTUROIGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0phdmFTY3JpcHQvUmVmZXJlbmNlL0dsb2JhbF9PYmplY3RzL0Vycm9yI0N1c3RvbV9FcnJvcl9UeXBlcy5cbnZhciBBcmNHSVNSZXF1ZXN0RXJyb3IgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgLyoqXG4gICAgICogQ3JlYXRlIGEgbmV3IGBBcmNHSVNSZXF1ZXN0RXJyb3JgICBvYmplY3QuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gbWVzc2FnZSAtIFRoZSBlcnJvciBtZXNzYWdlIGZyb20gdGhlIEFQSVxuICAgICAqIEBwYXJhbSBjb2RlIC0gVGhlIGVycm9yIGNvZGUgZnJvbSB0aGUgQVBJXG4gICAgICogQHBhcmFtIHJlc3BvbnNlIC0gVGhlIG9yaWdpbmFsIHJlc3BvbnNlIGZyb20gdGhlIEFQSSB0aGF0IGNhdXNlZCB0aGUgZXJyb3JcbiAgICAgKiBAcGFyYW0gdXJsIC0gVGhlIG9yaWdpbmFsIHVybCBvZiB0aGUgcmVxdWVzdFxuICAgICAqIEBwYXJhbSBvcHRpb25zIC0gVGhlIG9yaWdpbmFsIG9wdGlvbnMgYW5kIHBhcmFtZXRlcnMgb2YgdGhlIHJlcXVlc3RcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBBcmNHSVNSZXF1ZXN0RXJyb3IobWVzc2FnZSwgY29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucykge1xuICAgICAgICBtZXNzYWdlID0gbWVzc2FnZSB8fCBcIlVOS05PV05fRVJST1JcIjtcbiAgICAgICAgY29kZSA9IGNvZGUgfHwgXCJVTktOT1dOX0VSUk9SX0NPREVcIjtcbiAgICAgICAgdGhpcy5uYW1lID0gXCJBcmNHSVNSZXF1ZXN0RXJyb3JcIjtcbiAgICAgICAgdGhpcy5tZXNzYWdlID1cbiAgICAgICAgICAgIGNvZGUgPT09IFwiVU5LTk9XTl9FUlJPUl9DT0RFXCIgPyBtZXNzYWdlIDogY29kZSArIFwiOiBcIiArIG1lc3NhZ2U7XG4gICAgICAgIHRoaXMub3JpZ2luYWxNZXNzYWdlID0gbWVzc2FnZTtcbiAgICAgICAgdGhpcy5jb2RlID0gY29kZTtcbiAgICAgICAgdGhpcy5yZXNwb25zZSA9IHJlc3BvbnNlO1xuICAgICAgICB0aGlzLnVybCA9IHVybDtcbiAgICAgICAgdGhpcy5vcHRpb25zID0gb3B0aW9ucztcbiAgICB9XG4gICAgcmV0dXJuIEFyY0dJU1JlcXVlc3RFcnJvcjtcbn0oKSk7XG5leHBvcnQgeyBBcmNHSVNSZXF1ZXN0RXJyb3IgfTtcbkFyY0dJU1JlcXVlc3RFcnJvci5wcm90b3R5cGUgPSBPYmplY3QuY3JlYXRlKEVycm9yLnByb3RvdHlwZSk7XG5BcmNHSVNSZXF1ZXN0RXJyb3IucHJvdG90eXBlLmNvbnN0cnVjdG9yID0gQXJjR0lTUmVxdWVzdEVycm9yO1xuLy8jIHNvdXJjZU1hcHBpbmdVUkw9QXJjR0lTUmVxdWVzdEVycm9yLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG4vKipcbiAqIEhlbHBlciBmb3IgbWV0aG9kcyB3aXRoIGxvdHMgb2YgZmlyc3Qgb3JkZXIgcmVxdWVzdCBvcHRpb25zIHRvIHBhc3MgdGhyb3VnaCBhcyByZXF1ZXN0IHBhcmFtZXRlcnMuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBhcHBlbmRDdXN0b21QYXJhbXMoY3VzdG9tT3B0aW9ucywga2V5cywgYmFzZU9wdGlvbnMpIHtcbiAgICB2YXIgcmVxdWVzdE9wdGlvbnNLZXlzID0gW1xuICAgICAgICBcInBhcmFtc1wiLFxuICAgICAgICBcImh0dHBNZXRob2RcIixcbiAgICAgICAgXCJyYXdSZXNwb25zZVwiLFxuICAgICAgICBcImF1dGhlbnRpY2F0aW9uXCIsXG4gICAgICAgIFwicG9ydGFsXCIsXG4gICAgICAgIFwiZmV0Y2hcIixcbiAgICAgICAgXCJtYXhVcmxMZW5ndGhcIixcbiAgICAgICAgXCJoZWFkZXJzXCJcbiAgICBdO1xuICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oX19hc3NpZ24oeyBwYXJhbXM6IHt9IH0sIGJhc2VPcHRpb25zKSwgY3VzdG9tT3B0aW9ucyk7XG4gICAgLy8gbWVyZ2UgYWxsIGtleXMgaW4gY3VzdG9tT3B0aW9ucyBpbnRvIG9wdGlvbnMucGFyYW1zXG4gICAgb3B0aW9ucy5wYXJhbXMgPSBrZXlzLnJlZHVjZShmdW5jdGlvbiAodmFsdWUsIGtleSkge1xuICAgICAgICBpZiAoY3VzdG9tT3B0aW9uc1trZXldIHx8IHR5cGVvZiBjdXN0b21PcHRpb25zW2tleV0gPT09IFwiYm9vbGVhblwiKSB7XG4gICAgICAgICAgICB2YWx1ZVtrZXldID0gY3VzdG9tT3B0aW9uc1trZXldO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9LCBvcHRpb25zLnBhcmFtcyk7XG4gICAgLy8gbm93IHJlbW92ZSBhbGwgcHJvcGVydGllcyBpbiBvcHRpb25zIHRoYXQgZG9uJ3QgZXhpc3QgaW4gSVJlcXVlc3RPcHRpb25zXG4gICAgcmV0dXJuIHJlcXVlc3RPcHRpb25zS2V5cy5yZWR1Y2UoZnVuY3Rpb24gKHZhbHVlLCBrZXkpIHtcbiAgICAgICAgaWYgKG9wdGlvbnNba2V5XSkge1xuICAgICAgICAgICAgdmFsdWVba2V5XSA9IG9wdGlvbnNba2V5XTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdmFsdWU7XG4gICAgfSwge30pO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9YXBwZW5kLWN1c3RvbS1wYXJhbXMuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbi8qKlxuICogSGVscGVyIG1ldGhvZCB0byBlbnN1cmUgdGhhdCB1c2VyIHN1cHBsaWVkIHVybHMgZG9uJ3QgaW5jbHVkZSB3aGl0ZXNwYWNlIG9yIGEgdHJhaWxpbmcgc2xhc2guXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBjbGVhblVybCh1cmwpIHtcbiAgICAvLyBHdWFyZCBzbyB3ZSBkb24ndCB0cnkgdG8gdHJpbSBzb21ldGhpbmcgdGhhdCdzIG5vdCBhIHN0cmluZ1xuICAgIGlmICh0eXBlb2YgdXJsICE9PSBcInN0cmluZ1wiKSB7XG4gICAgICAgIHJldHVybiB1cmw7XG4gICAgfVxuICAgIC8vIHRyaW0gbGVhZGluZyBhbmQgdHJhaWxpbmcgc3BhY2VzLCBidXQgbm90IHNwYWNlcyBpbnNpZGUgdGhlIHVybFxuICAgIHVybCA9IHVybC50cmltKCk7XG4gICAgLy8gcmVtb3ZlIHRoZSB0cmFpbGluZyBzbGFzaCB0byB0aGUgdXJsIGlmIG9uZSB3YXMgaW5jbHVkZWRcbiAgICBpZiAodXJsW3VybC5sZW5ndGggLSAxXSA9PT0gXCIvXCIpIHtcbiAgICAgICAgdXJsID0gdXJsLnNsaWNlKDAsIC0xKTtcbiAgICB9XG4gICAgcmV0dXJuIHVybDtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWNsZWFuLXVybC5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAyMCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5leHBvcnQgZnVuY3Rpb24gZGVjb2RlUGFyYW0ocGFyYW0pIHtcbiAgICB2YXIgX2EgPSBwYXJhbS5zcGxpdChcIj1cIiksIGtleSA9IF9hWzBdLCB2YWx1ZSA9IF9hWzFdO1xuICAgIHJldHVybiB7IGtleTogZGVjb2RlVVJJQ29tcG9uZW50KGtleSksIHZhbHVlOiBkZWNvZGVVUklDb21wb25lbnQodmFsdWUpIH07XG59XG4vKipcbiAqIERlY29kZXMgdGhlIHBhc3NlZCBxdWVyeSBzdHJpbmcgYXMgYW4gb2JqZWN0LlxuICpcbiAqIEBwYXJhbSBxdWVyeSBBIHN0cmluZyB0byBiZSBkZWNvZGVkLlxuICogQHJldHVybnMgQSBkZWNvZGVkIHF1ZXJ5IHBhcmFtIG9iamVjdC5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGRlY29kZVF1ZXJ5U3RyaW5nKHF1ZXJ5KSB7XG4gICAgcmV0dXJuIHF1ZXJ5XG4gICAgICAgIC5yZXBsYWNlKC9eIy8sIFwiXCIpXG4gICAgICAgIC5zcGxpdChcIiZcIilcbiAgICAgICAgLnJlZHVjZShmdW5jdGlvbiAoYWNjLCBlbnRyeSkge1xuICAgICAgICB2YXIgX2EgPSBkZWNvZGVQYXJhbShlbnRyeSksIGtleSA9IF9hLmtleSwgdmFsdWUgPSBfYS52YWx1ZTtcbiAgICAgICAgYWNjW2tleV0gPSB2YWx1ZTtcbiAgICAgICAgcmV0dXJuIGFjYztcbiAgICB9LCB7fSk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1kZWNvZGUtcXVlcnktc3RyaW5nLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBwcm9jZXNzUGFyYW1zLCByZXF1aXJlc0Zvcm1EYXRhIH0gZnJvbSBcIi4vcHJvY2Vzcy1wYXJhbXNcIjtcbmltcG9ydCB7IGVuY29kZVF1ZXJ5U3RyaW5nIH0gZnJvbSBcIi4vZW5jb2RlLXF1ZXJ5LXN0cmluZ1wiO1xuLyoqXG4gKiBFbmNvZGVzIHBhcmFtZXRlcnMgaW4gYSBbRm9ybURhdGFdKGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0FQSS9Gb3JtRGF0YSkgb2JqZWN0IGluIGJyb3dzZXJzIG9yIGluIGEgW0Zvcm1EYXRhXShodHRwczovL2dpdGh1Yi5jb20vZm9ybS1kYXRhL2Zvcm0tZGF0YSkgaW4gTm9kZS5qc1xuICpcbiAqIEBwYXJhbSBwYXJhbXMgQW4gb2JqZWN0IHRvIGJlIGVuY29kZWQuXG4gKiBAcmV0dXJucyBUaGUgY29tcGxldGUgW0Zvcm1EYXRhXShodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL1dlYi9BUEkvRm9ybURhdGEpIG9iamVjdC5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGVuY29kZUZvcm1EYXRhKHBhcmFtcywgZm9yY2VGb3JtRGF0YSkge1xuICAgIC8vIHNlZSBodHRwczovL2dpdGh1Yi5jb20vRXNyaS9hcmNnaXMtcmVzdC1qcy9pc3N1ZXMvNDk5IGZvciBtb3JlIGluZm8uXG4gICAgdmFyIHVzZUZvcm1EYXRhID0gcmVxdWlyZXNGb3JtRGF0YShwYXJhbXMpIHx8IGZvcmNlRm9ybURhdGE7XG4gICAgdmFyIG5ld1BhcmFtcyA9IHByb2Nlc3NQYXJhbXMocGFyYW1zKTtcbiAgICBpZiAodXNlRm9ybURhdGEpIHtcbiAgICAgICAgdmFyIGZvcm1EYXRhXzEgPSBuZXcgRm9ybURhdGEoKTtcbiAgICAgICAgT2JqZWN0LmtleXMobmV3UGFyYW1zKS5mb3JFYWNoKGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgICAgIGlmICh0eXBlb2YgQmxvYiAhPT0gXCJ1bmRlZmluZWRcIiAmJiBuZXdQYXJhbXNba2V5XSBpbnN0YW5jZW9mIEJsb2IpIHtcbiAgICAgICAgICAgICAgICAvKiBUbyBuYW1lIHRoZSBCbG9iOlxuICAgICAgICAgICAgICAgICAxLiBsb29rIHRvIGFuIGFsdGVybmF0ZSByZXF1ZXN0IHBhcmFtZXRlciBjYWxsZWQgJ2ZpbGVOYW1lJ1xuICAgICAgICAgICAgICAgICAyLiBzZWUgaWYgJ25hbWUnIGhhcyBiZWVuIHRhY2tlZCBvbnRvIHRoZSBCbG9iIG1hbnVhbGx5XG4gICAgICAgICAgICAgICAgIDMuIGlmIGFsbCBlbHNlIGZhaWxzLCB1c2UgdGhlIHJlcXVlc3QgcGFyYW1ldGVyXG4gICAgICAgICAgICAgICAgKi9cbiAgICAgICAgICAgICAgICB2YXIgZmlsZW5hbWUgPSBuZXdQYXJhbXNbXCJmaWxlTmFtZVwiXSB8fCBuZXdQYXJhbXNba2V5XS5uYW1lIHx8IGtleTtcbiAgICAgICAgICAgICAgICBmb3JtRGF0YV8xLmFwcGVuZChrZXksIG5ld1BhcmFtc1trZXldLCBmaWxlbmFtZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICBmb3JtRGF0YV8xLmFwcGVuZChrZXksIG5ld1BhcmFtc1trZXldKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiBmb3JtRGF0YV8xO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgcmV0dXJuIGVuY29kZVF1ZXJ5U3RyaW5nKHBhcmFtcyk7XG4gICAgfVxufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZW5jb2RlLWZvcm0tZGF0YS5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgcHJvY2Vzc1BhcmFtcyB9IGZyb20gXCIuL3Byb2Nlc3MtcGFyYW1zXCI7XG4vKipcbiAqIEVuY29kZXMga2V5cyBhbmQgcGFyYW1ldGVycyBmb3IgdXNlIGluIGEgVVJMJ3MgcXVlcnkgc3RyaW5nLlxuICpcbiAqIEBwYXJhbSBrZXkgUGFyYW1ldGVyJ3Mga2V5XG4gKiBAcGFyYW0gdmFsdWUgUGFyYW1ldGVyJ3MgdmFsdWVcbiAqIEByZXR1cm5zIFF1ZXJ5IHN0cmluZyB3aXRoIGtleSBhbmQgdmFsdWUgcGFpcnMgc2VwYXJhdGVkIGJ5IFwiJlwiXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBlbmNvZGVQYXJhbShrZXksIHZhbHVlKSB7XG4gICAgLy8gRm9yIGFycmF5IG9mIGFycmF5cywgcmVwZWF0IGtleT12YWx1ZSBmb3IgZWFjaCBlbGVtZW50IG9mIGNvbnRhaW5pbmcgYXJyYXlcbiAgICBpZiAoQXJyYXkuaXNBcnJheSh2YWx1ZSkgJiYgdmFsdWVbMF0gJiYgQXJyYXkuaXNBcnJheSh2YWx1ZVswXSkpIHtcbiAgICAgICAgcmV0dXJuIHZhbHVlLm1hcChmdW5jdGlvbiAoYXJyYXlFbGVtKSB7IHJldHVybiBlbmNvZGVQYXJhbShrZXksIGFycmF5RWxlbSk7IH0pLmpvaW4oXCImXCIpO1xuICAgIH1cbiAgICByZXR1cm4gZW5jb2RlVVJJQ29tcG9uZW50KGtleSkgKyBcIj1cIiArIGVuY29kZVVSSUNvbXBvbmVudCh2YWx1ZSk7XG59XG4vKipcbiAqIEVuY29kZXMgdGhlIHBhc3NlZCBvYmplY3QgYXMgYSBxdWVyeSBzdHJpbmcuXG4gKlxuICogQHBhcmFtIHBhcmFtcyBBbiBvYmplY3QgdG8gYmUgZW5jb2RlZC5cbiAqIEByZXR1cm5zIEFuIGVuY29kZWQgcXVlcnkgc3RyaW5nLlxuICovXG5leHBvcnQgZnVuY3Rpb24gZW5jb2RlUXVlcnlTdHJpbmcocGFyYW1zKSB7XG4gICAgdmFyIG5ld1BhcmFtcyA9IHByb2Nlc3NQYXJhbXMocGFyYW1zKTtcbiAgICByZXR1cm4gT2JqZWN0LmtleXMobmV3UGFyYW1zKVxuICAgICAgICAubWFwKGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgcmV0dXJuIGVuY29kZVBhcmFtKGtleSwgbmV3UGFyYW1zW2tleV0pO1xuICAgIH0pXG4gICAgICAgIC5qb2luKFwiJlwiKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWVuY29kZS1xdWVyeS1zdHJpbmcuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbi8qKlxuICogQ2hlY2tzIHBhcmFtZXRlcnMgdG8gc2VlIGlmIHdlIHNob3VsZCB1c2UgRm9ybURhdGEgdG8gc2VuZCB0aGUgcmVxdWVzdFxuICogQHBhcmFtIHBhcmFtcyBUaGUgb2JqZWN0IHdob3NlIGtleXMgd2lsbCBiZSBlbmNvZGVkLlxuICogQHJldHVybiBBIGJvb2xlYW4gaW5kaWNhdGluZyBpZiBGb3JtRGF0YSB3aWxsIGJlIHJlcXVpcmVkLlxuICovXG5leHBvcnQgZnVuY3Rpb24gcmVxdWlyZXNGb3JtRGF0YShwYXJhbXMpIHtcbiAgICByZXR1cm4gT2JqZWN0LmtleXMocGFyYW1zKS5zb21lKGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgdmFyIHZhbHVlID0gcGFyYW1zW2tleV07XG4gICAgICAgIGlmICghdmFsdWUpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodmFsdWUgJiYgdmFsdWUudG9QYXJhbSkge1xuICAgICAgICAgICAgdmFsdWUgPSB2YWx1ZS50b1BhcmFtKCk7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIHR5cGUgPSB2YWx1ZS5jb25zdHJ1Y3Rvci5uYW1lO1xuICAgICAgICBzd2l0Y2ggKHR5cGUpIHtcbiAgICAgICAgICAgIGNhc2UgXCJBcnJheVwiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGNhc2UgXCJPYmplY3RcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBjYXNlIFwiRGF0ZVwiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGNhc2UgXCJGdW5jdGlvblwiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGNhc2UgXCJCb29sZWFuXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIlN0cmluZ1wiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGNhc2UgXCJOdW1iZXJcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG4gICAgfSk7XG59XG4vKipcbiAqIENvbnZlcnRzIHBhcmFtZXRlcnMgdG8gdGhlIHByb3BlciByZXByZXNlbnRhdGlvbiB0byBzZW5kIHRvIHRoZSBBcmNHSVMgUkVTVCBBUEkuXG4gKiBAcGFyYW0gcGFyYW1zIFRoZSBvYmplY3Qgd2hvc2Uga2V5cyB3aWxsIGJlIGVuY29kZWQuXG4gKiBAcmV0dXJuIEEgbmV3IG9iamVjdCB3aXRoIHByb3Blcmx5IGVuY29kZWQgdmFsdWVzLlxuICovXG5leHBvcnQgZnVuY3Rpb24gcHJvY2Vzc1BhcmFtcyhwYXJhbXMpIHtcbiAgICB2YXIgbmV3UGFyYW1zID0ge307XG4gICAgT2JqZWN0LmtleXMocGFyYW1zKS5mb3JFYWNoKGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgdmFyIF9hLCBfYjtcbiAgICAgICAgdmFyIHBhcmFtID0gcGFyYW1zW2tleV07XG4gICAgICAgIGlmIChwYXJhbSAmJiBwYXJhbS50b1BhcmFtKSB7XG4gICAgICAgICAgICBwYXJhbSA9IHBhcmFtLnRvUGFyYW0oKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXBhcmFtICYmXG4gICAgICAgICAgICBwYXJhbSAhPT0gMCAmJlxuICAgICAgICAgICAgdHlwZW9mIHBhcmFtICE9PSBcImJvb2xlYW5cIiAmJlxuICAgICAgICAgICAgdHlwZW9mIHBhcmFtICE9PSBcInN0cmluZ1wiKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cbiAgICAgICAgdmFyIHR5cGUgPSBwYXJhbS5jb25zdHJ1Y3Rvci5uYW1lO1xuICAgICAgICB2YXIgdmFsdWU7XG4gICAgICAgIC8vIHByb3Blcmx5IGVuY29kZXMgb2JqZWN0cywgYXJyYXlzIGFuZCBkYXRlcyBmb3IgYXJjZ2lzLmNvbSBhbmQgb3RoZXIgc2VydmljZXMuXG4gICAgICAgIC8vIHBvcnRlZCBmcm9tIGh0dHBzOi8vZ2l0aHViLmNvbS9Fc3JpL2VzcmktbGVhZmxldC9ibG9iL21hc3Rlci9zcmMvUmVxdWVzdC5qcyNMMjItTDMwXG4gICAgICAgIC8vIGFsc28gc2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9Fc3JpL2FyY2dpcy1yZXN0LWpzL2lzc3Vlcy8xODpcbiAgICAgICAgLy8gbnVsbCwgdW5kZWZpbmVkLCBmdW5jdGlvbiBhcmUgZXhjbHVkZWQuIElmIHlvdSB3YW50IHRvIHNlbmQgYW4gZW1wdHkga2V5IHlvdSBuZWVkIHRvIHNlbmQgYW4gZW1wdHkgc3RyaW5nIFwiXCIuXG4gICAgICAgIHN3aXRjaCAodHlwZSkge1xuICAgICAgICAgICAgY2FzZSBcIkFycmF5XCI6XG4gICAgICAgICAgICAgICAgLy8gQmFzZWQgb24gdGhlIGZpcnN0IGVsZW1lbnQgb2YgdGhlIGFycmF5LCBjbGFzc2lmeSBhcnJheSBhcyBhbiBhcnJheSBvZiBhcnJheXMsIGFuIGFycmF5IG9mIG9iamVjdHNcbiAgICAgICAgICAgICAgICAvLyB0byBiZSBzdHJpbmdpZmllZCwgb3IgYW4gYXJyYXkgb2Ygbm9uLW9iamVjdHMgdG8gYmUgY29tbWEtc2VwYXJhdGVkXG4gICAgICAgICAgICAgICAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5vLWNhc2UtZGVjbGFyYXRpb25zXG4gICAgICAgICAgICAgICAgdmFyIGZpcnN0RWxlbWVudFR5cGUgPSAoX2IgPSAoX2EgPSBwYXJhbVswXSkgPT09IG51bGwgfHwgX2EgPT09IHZvaWQgMCA/IHZvaWQgMCA6IF9hLmNvbnN0cnVjdG9yKSA9PT0gbnVsbCB8fCBfYiA9PT0gdm9pZCAwID8gdm9pZCAwIDogX2IubmFtZTtcbiAgICAgICAgICAgICAgICB2YWx1ZSA9XG4gICAgICAgICAgICAgICAgICAgIGZpcnN0RWxlbWVudFR5cGUgPT09IFwiQXJyYXlcIiA/IHBhcmFtIDogLy8gcGFzcyB0aHJ1IGFycmF5IG9mIGFycmF5c1xuICAgICAgICAgICAgICAgICAgICAgICAgZmlyc3RFbGVtZW50VHlwZSA9PT0gXCJPYmplY3RcIiA/IEpTT04uc3RyaW5naWZ5KHBhcmFtKSA6IC8vIHN0cmluZ2lmeSBhcnJheSBvZiBvYmplY3RzXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFyYW0uam9pbihcIixcIik7IC8vIGpvaW4gb3RoZXIgdHlwZXMgb2YgYXJyYXkgZWxlbWVudHNcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIGNhc2UgXCJPYmplY3RcIjpcbiAgICAgICAgICAgICAgICB2YWx1ZSA9IEpTT04uc3RyaW5naWZ5KHBhcmFtKTtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIGNhc2UgXCJEYXRlXCI6XG4gICAgICAgICAgICAgICAgdmFsdWUgPSBwYXJhbS52YWx1ZU9mKCk7XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICBjYXNlIFwiRnVuY3Rpb25cIjpcbiAgICAgICAgICAgICAgICB2YWx1ZSA9IG51bGw7XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICBjYXNlIFwiQm9vbGVhblwiOlxuICAgICAgICAgICAgICAgIHZhbHVlID0gcGFyYW0gKyBcIlwiO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICB2YWx1ZSA9IHBhcmFtO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGlmICh2YWx1ZSB8fCB2YWx1ZSA9PT0gMCB8fCB0eXBlb2YgdmFsdWUgPT09IFwic3RyaW5nXCIgfHwgQXJyYXkuaXNBcnJheSh2YWx1ZSkpIHtcbiAgICAgICAgICAgIG5ld1BhcmFtc1trZXldID0gdmFsdWU7XG4gICAgICAgIH1cbiAgICB9KTtcbiAgICByZXR1cm4gbmV3UGFyYW1zO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9cHJvY2Vzcy1wYXJhbXMuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuLyoqXG4gKiBNZXRob2QgdXNlZCBpbnRlcm5hbGx5IHRvIHN1cmZhY2UgbWVzc2FnZXMgdG8gZGV2ZWxvcGVycy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHdhcm4obWVzc2FnZSkge1xuICAgIGlmIChjb25zb2xlICYmIGNvbnNvbGUud2Fybikge1xuICAgICAgICBjb25zb2xlLndhcm4uYXBwbHkoY29uc29sZSwgW21lc3NhZ2VdKTtcbiAgICB9XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD13YXJuLmpzLm1hcCIsIi8qISAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxyXG5Db3B5cmlnaHQgKGMpIE1pY3Jvc29mdCBDb3Jwb3JhdGlvbi5cclxuXHJcblBlcm1pc3Npb24gdG8gdXNlLCBjb3B5LCBtb2RpZnksIGFuZC9vciBkaXN0cmlidXRlIHRoaXMgc29mdHdhcmUgZm9yIGFueVxyXG5wdXJwb3NlIHdpdGggb3Igd2l0aG91dCBmZWUgaXMgaGVyZWJ5IGdyYW50ZWQuXHJcblxyXG5USEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiIEFORCBUSEUgQVVUSE9SIERJU0NMQUlNUyBBTEwgV0FSUkFOVElFUyBXSVRIXHJcblJFR0FSRCBUTyBUSElTIFNPRlRXQVJFIElOQ0xVRElORyBBTEwgSU1QTElFRCBXQVJSQU5USUVTIE9GIE1FUkNIQU5UQUJJTElUWVxyXG5BTkQgRklUTkVTUy4gSU4gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUiBCRSBMSUFCTEUgRk9SIEFOWSBTUEVDSUFMLCBESVJFQ1QsXHJcbklORElSRUNULCBPUiBDT05TRVFVRU5USUFMIERBTUFHRVMgT1IgQU5ZIERBTUFHRVMgV0hBVFNPRVZFUiBSRVNVTFRJTkcgRlJPTVxyXG5MT1NTIE9GIFVTRSwgREFUQSBPUiBQUk9GSVRTLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgTkVHTElHRU5DRSBPUlxyXG5PVEhFUiBUT1JUSU9VUyBBQ1RJT04sIEFSSVNJTkcgT1VUIE9GIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgVVNFIE9SXHJcblBFUkZPUk1BTkNFIE9GIFRISVMgU09GVFdBUkUuXHJcbioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqICovXHJcbi8qIGdsb2JhbCBSZWZsZWN0LCBQcm9taXNlICovXHJcblxyXG52YXIgZXh0ZW5kU3RhdGljcyA9IGZ1bmN0aW9uKGQsIGIpIHtcclxuICAgIGV4dGVuZFN0YXRpY3MgPSBPYmplY3Quc2V0UHJvdG90eXBlT2YgfHxcclxuICAgICAgICAoeyBfX3Byb3RvX186IFtdIH0gaW5zdGFuY2VvZiBBcnJheSAmJiBmdW5jdGlvbiAoZCwgYikgeyBkLl9fcHJvdG9fXyA9IGI7IH0pIHx8XHJcbiAgICAgICAgZnVuY3Rpb24gKGQsIGIpIHsgZm9yICh2YXIgcCBpbiBiKSBpZiAoYi5oYXNPd25Qcm9wZXJ0eShwKSkgZFtwXSA9IGJbcF07IH07XHJcbiAgICByZXR1cm4gZXh0ZW5kU3RhdGljcyhkLCBiKTtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2V4dGVuZHMoZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyhkLCBiKTtcclxuICAgIGZ1bmN0aW9uIF9fKCkgeyB0aGlzLmNvbnN0cnVjdG9yID0gZDsgfVxyXG4gICAgZC5wcm90b3R5cGUgPSBiID09PSBudWxsID8gT2JqZWN0LmNyZWF0ZShiKSA6IChfXy5wcm90b3R5cGUgPSBiLnByb3RvdHlwZSwgbmV3IF9fKCkpO1xyXG59XHJcblxyXG5leHBvcnQgdmFyIF9fYXNzaWduID0gZnVuY3Rpb24oKSB7XHJcbiAgICBfX2Fzc2lnbiA9IE9iamVjdC5hc3NpZ24gfHwgZnVuY3Rpb24gX19hc3NpZ24odCkge1xyXG4gICAgICAgIGZvciAodmFyIHMsIGkgPSAxLCBuID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IG47IGkrKykge1xyXG4gICAgICAgICAgICBzID0gYXJndW1lbnRzW2ldO1xyXG4gICAgICAgICAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkpIHRbcF0gPSBzW3BdO1xyXG4gICAgICAgIH1cclxuICAgICAgICByZXR1cm4gdDtcclxuICAgIH1cclxuICAgIHJldHVybiBfX2Fzc2lnbi5hcHBseSh0aGlzLCBhcmd1bWVudHMpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19yZXN0KHMsIGUpIHtcclxuICAgIHZhciB0ID0ge307XHJcbiAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkgJiYgZS5pbmRleE9mKHApIDwgMClcclxuICAgICAgICB0W3BdID0gc1twXTtcclxuICAgIGlmIChzICE9IG51bGwgJiYgdHlwZW9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHMgPT09IFwiZnVuY3Rpb25cIilcclxuICAgICAgICBmb3IgKHZhciBpID0gMCwgcCA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHMocyk7IGkgPCBwLmxlbmd0aDsgaSsrKSB7XHJcbiAgICAgICAgICAgIGlmIChlLmluZGV4T2YocFtpXSkgPCAwICYmIE9iamVjdC5wcm90b3R5cGUucHJvcGVydHlJc0VudW1lcmFibGUuY2FsbChzLCBwW2ldKSlcclxuICAgICAgICAgICAgICAgIHRbcFtpXV0gPSBzW3BbaV1dO1xyXG4gICAgICAgIH1cclxuICAgIHJldHVybiB0O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19kZWNvcmF0ZShkZWNvcmF0b3JzLCB0YXJnZXQsIGtleSwgZGVzYykge1xyXG4gICAgdmFyIGMgPSBhcmd1bWVudHMubGVuZ3RoLCByID0gYyA8IDMgPyB0YXJnZXQgOiBkZXNjID09PSBudWxsID8gZGVzYyA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IodGFyZ2V0LCBrZXkpIDogZGVzYywgZDtcclxuICAgIGlmICh0eXBlb2YgUmVmbGVjdCA9PT0gXCJvYmplY3RcIiAmJiB0eXBlb2YgUmVmbGVjdC5kZWNvcmF0ZSA9PT0gXCJmdW5jdGlvblwiKSByID0gUmVmbGVjdC5kZWNvcmF0ZShkZWNvcmF0b3JzLCB0YXJnZXQsIGtleSwgZGVzYyk7XHJcbiAgICBlbHNlIGZvciAodmFyIGkgPSBkZWNvcmF0b3JzLmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSBpZiAoZCA9IGRlY29yYXRvcnNbaV0pIHIgPSAoYyA8IDMgPyBkKHIpIDogYyA+IDMgPyBkKHRhcmdldCwga2V5LCByKSA6IGQodGFyZ2V0LCBrZXkpKSB8fCByO1xyXG4gICAgcmV0dXJuIGMgPiAzICYmIHIgJiYgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRhcmdldCwga2V5LCByKSwgcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcGFyYW0ocGFyYW1JbmRleCwgZGVjb3JhdG9yKSB7XHJcbiAgICByZXR1cm4gZnVuY3Rpb24gKHRhcmdldCwga2V5KSB7IGRlY29yYXRvcih0YXJnZXQsIGtleSwgcGFyYW1JbmRleCk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fbWV0YWRhdGEobWV0YWRhdGFLZXksIG1ldGFkYXRhVmFsdWUpIHtcclxuICAgIGlmICh0eXBlb2YgUmVmbGVjdCA9PT0gXCJvYmplY3RcIiAmJiB0eXBlb2YgUmVmbGVjdC5tZXRhZGF0YSA9PT0gXCJmdW5jdGlvblwiKSByZXR1cm4gUmVmbGVjdC5tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2F3YWl0ZXIodGhpc0FyZywgX2FyZ3VtZW50cywgUCwgZ2VuZXJhdG9yKSB7XHJcbiAgICBmdW5jdGlvbiBhZG9wdCh2YWx1ZSkgeyByZXR1cm4gdmFsdWUgaW5zdGFuY2VvZiBQID8gdmFsdWUgOiBuZXcgUChmdW5jdGlvbiAocmVzb2x2ZSkgeyByZXNvbHZlKHZhbHVlKTsgfSk7IH1cclxuICAgIHJldHVybiBuZXcgKFAgfHwgKFAgPSBQcm9taXNlKSkoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xyXG4gICAgICAgIGZ1bmN0aW9uIGZ1bGZpbGxlZCh2YWx1ZSkgeyB0cnkgeyBzdGVwKGdlbmVyYXRvci5uZXh0KHZhbHVlKSk7IH0gY2F0Y2ggKGUpIHsgcmVqZWN0KGUpOyB9IH1cclxuICAgICAgICBmdW5jdGlvbiByZWplY3RlZCh2YWx1ZSkgeyB0cnkgeyBzdGVwKGdlbmVyYXRvcltcInRocm93XCJdKHZhbHVlKSk7IH0gY2F0Y2ggKGUpIHsgcmVqZWN0KGUpOyB9IH1cclxuICAgICAgICBmdW5jdGlvbiBzdGVwKHJlc3VsdCkgeyByZXN1bHQuZG9uZSA/IHJlc29sdmUocmVzdWx0LnZhbHVlKSA6IGFkb3B0KHJlc3VsdC52YWx1ZSkudGhlbihmdWxmaWxsZWQsIHJlamVjdGVkKTsgfVxyXG4gICAgICAgIHN0ZXAoKGdlbmVyYXRvciA9IGdlbmVyYXRvci5hcHBseSh0aGlzQXJnLCBfYXJndW1lbnRzIHx8IFtdKSkubmV4dCgpKTtcclxuICAgIH0pO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19nZW5lcmF0b3IodGhpc0FyZywgYm9keSkge1xyXG4gICAgdmFyIF8gPSB7IGxhYmVsOiAwLCBzZW50OiBmdW5jdGlvbigpIHsgaWYgKHRbMF0gJiAxKSB0aHJvdyB0WzFdOyByZXR1cm4gdFsxXTsgfSwgdHJ5czogW10sIG9wczogW10gfSwgZiwgeSwgdCwgZztcclxuICAgIHJldHVybiBnID0geyBuZXh0OiB2ZXJiKDApLCBcInRocm93XCI6IHZlcmIoMSksIFwicmV0dXJuXCI6IHZlcmIoMikgfSwgdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIChnW1N5bWJvbC5pdGVyYXRvcl0gPSBmdW5jdGlvbigpIHsgcmV0dXJuIHRoaXM7IH0pLCBnO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IHJldHVybiBmdW5jdGlvbiAodikgeyByZXR1cm4gc3RlcChbbiwgdl0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzdGVwKG9wKSB7XHJcbiAgICAgICAgaWYgKGYpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJHZW5lcmF0b3IgaXMgYWxyZWFkeSBleGVjdXRpbmcuXCIpO1xyXG4gICAgICAgIHdoaWxlIChfKSB0cnkge1xyXG4gICAgICAgICAgICBpZiAoZiA9IDEsIHkgJiYgKHQgPSBvcFswXSAmIDIgPyB5W1wicmV0dXJuXCJdIDogb3BbMF0gPyB5W1widGhyb3dcIl0gfHwgKCh0ID0geVtcInJldHVyblwiXSkgJiYgdC5jYWxsKHkpLCAwKSA6IHkubmV4dCkgJiYgISh0ID0gdC5jYWxsKHksIG9wWzFdKSkuZG9uZSkgcmV0dXJuIHQ7XHJcbiAgICAgICAgICAgIGlmICh5ID0gMCwgdCkgb3AgPSBbb3BbMF0gJiAyLCB0LnZhbHVlXTtcclxuICAgICAgICAgICAgc3dpdGNoIChvcFswXSkge1xyXG4gICAgICAgICAgICAgICAgY2FzZSAwOiBjYXNlIDE6IHQgPSBvcDsgYnJlYWs7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDQ6IF8ubGFiZWwrKzsgcmV0dXJuIHsgdmFsdWU6IG9wWzFdLCBkb25lOiBmYWxzZSB9O1xyXG4gICAgICAgICAgICAgICAgY2FzZSA1OiBfLmxhYmVsKys7IHkgPSBvcFsxXTsgb3AgPSBbMF07IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICAgICAgY2FzZSA3OiBvcCA9IF8ub3BzLnBvcCgpOyBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgICAgICAgICAgICBpZiAoISh0ID0gXy50cnlzLCB0ID0gdC5sZW5ndGggPiAwICYmIHRbdC5sZW5ndGggLSAxXSkgJiYgKG9wWzBdID09PSA2IHx8IG9wWzBdID09PSAyKSkgeyBfID0gMDsgY29udGludWU7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAob3BbMF0gPT09IDMgJiYgKCF0IHx8IChvcFsxXSA+IHRbMF0gJiYgb3BbMV0gPCB0WzNdKSkpIHsgXy5sYWJlbCA9IG9wWzFdOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gNiAmJiBfLmxhYmVsIDwgdFsxXSkgeyBfLmxhYmVsID0gdFsxXTsgdCA9IG9wOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0ICYmIF8ubGFiZWwgPCB0WzJdKSB7IF8ubGFiZWwgPSB0WzJdOyBfLm9wcy5wdXNoKG9wKTsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAodFsyXSkgXy5vcHMucG9wKCk7XHJcbiAgICAgICAgICAgICAgICAgICAgXy50cnlzLnBvcCgpOyBjb250aW51ZTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBvcCA9IGJvZHkuY2FsbCh0aGlzQXJnLCBfKTtcclxuICAgICAgICB9IGNhdGNoIChlKSB7IG9wID0gWzYsIGVdOyB5ID0gMDsgfSBmaW5hbGx5IHsgZiA9IHQgPSAwOyB9XHJcbiAgICAgICAgaWYgKG9wWzBdICYgNSkgdGhyb3cgb3BbMV07IHJldHVybiB7IHZhbHVlOiBvcFswXSA/IG9wWzFdIDogdm9pZCAwLCBkb25lOiB0cnVlIH07XHJcbiAgICB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NyZWF0ZUJpbmRpbmcobywgbSwgaywgazIpIHtcclxuICAgIGlmIChrMiA9PT0gdW5kZWZpbmVkKSBrMiA9IGs7XHJcbiAgICBvW2syXSA9IG1ba107XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2V4cG9ydFN0YXIobSwgZXhwb3J0cykge1xyXG4gICAgZm9yICh2YXIgcCBpbiBtKSBpZiAocCAhPT0gXCJkZWZhdWx0XCIgJiYgIWV4cG9ydHMuaGFzT3duUHJvcGVydHkocCkpIGV4cG9ydHNbcF0gPSBtW3BdO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX192YWx1ZXMobykge1xyXG4gICAgdmFyIHMgPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgU3ltYm9sLml0ZXJhdG9yLCBtID0gcyAmJiBvW3NdLCBpID0gMDtcclxuICAgIGlmIChtKSByZXR1cm4gbS5jYWxsKG8pO1xyXG4gICAgaWYgKG8gJiYgdHlwZW9mIG8ubGVuZ3RoID09PSBcIm51bWJlclwiKSByZXR1cm4ge1xyXG4gICAgICAgIG5leHQ6IGZ1bmN0aW9uICgpIHtcclxuICAgICAgICAgICAgaWYgKG8gJiYgaSA+PSBvLmxlbmd0aCkgbyA9IHZvaWQgMDtcclxuICAgICAgICAgICAgcmV0dXJuIHsgdmFsdWU6IG8gJiYgb1tpKytdLCBkb25lOiAhbyB9O1xyXG4gICAgICAgIH1cclxuICAgIH07XHJcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKHMgPyBcIk9iamVjdCBpcyBub3QgaXRlcmFibGUuXCIgOiBcIlN5bWJvbC5pdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3JlYWQobywgbikge1xyXG4gICAgdmFyIG0gPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgb1tTeW1ib2wuaXRlcmF0b3JdO1xyXG4gICAgaWYgKCFtKSByZXR1cm4gbztcclxuICAgIHZhciBpID0gbS5jYWxsKG8pLCByLCBhciA9IFtdLCBlO1xyXG4gICAgdHJ5IHtcclxuICAgICAgICB3aGlsZSAoKG4gPT09IHZvaWQgMCB8fCBuLS0gPiAwKSAmJiAhKHIgPSBpLm5leHQoKSkuZG9uZSkgYXIucHVzaChyLnZhbHVlKTtcclxuICAgIH1cclxuICAgIGNhdGNoIChlcnJvcikgeyBlID0geyBlcnJvcjogZXJyb3IgfTsgfVxyXG4gICAgZmluYWxseSB7XHJcbiAgICAgICAgdHJ5IHtcclxuICAgICAgICAgICAgaWYgKHIgJiYgIXIuZG9uZSAmJiAobSA9IGlbXCJyZXR1cm5cIl0pKSBtLmNhbGwoaSk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGZpbmFsbHkgeyBpZiAoZSkgdGhyb3cgZS5lcnJvcjsgfVxyXG4gICAgfVxyXG4gICAgcmV0dXJuIGFyO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19zcHJlYWQoKSB7XHJcbiAgICBmb3IgKHZhciBhciA9IFtdLCBpID0gMDsgaSA8IGFyZ3VtZW50cy5sZW5ndGg7IGkrKylcclxuICAgICAgICBhciA9IGFyLmNvbmNhdChfX3JlYWQoYXJndW1lbnRzW2ldKSk7XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZEFycmF5cygpIHtcclxuICAgIGZvciAodmFyIHMgPSAwLCBpID0gMCwgaWwgPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgaWw7IGkrKykgcyArPSBhcmd1bWVudHNbaV0ubGVuZ3RoO1xyXG4gICAgZm9yICh2YXIgciA9IEFycmF5KHMpLCBrID0gMCwgaSA9IDA7IGkgPCBpbDsgaSsrKVxyXG4gICAgICAgIGZvciAodmFyIGEgPSBhcmd1bWVudHNbaV0sIGogPSAwLCBqbCA9IGEubGVuZ3RoOyBqIDwgamw7IGorKywgaysrKVxyXG4gICAgICAgICAgICByW2tdID0gYVtqXTtcclxuICAgIHJldHVybiByO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXQodikge1xyXG4gICAgcmV0dXJuIHRoaXMgaW5zdGFuY2VvZiBfX2F3YWl0ID8gKHRoaXMudiA9IHYsIHRoaXMpIDogbmV3IF9fYXdhaXQodik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jR2VuZXJhdG9yKHRoaXNBcmcsIF9hcmd1bWVudHMsIGdlbmVyYXRvcikge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBnID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pLCBpLCBxID0gW107XHJcbiAgICByZXR1cm4gaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIpLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaWYgKGdbbl0pIGlbbl0gPSBmdW5jdGlvbiAodikgeyByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKGEsIGIpIHsgcS5wdXNoKFtuLCB2LCBhLCBiXSkgPiAxIHx8IHJlc3VtZShuLCB2KTsgfSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHJlc3VtZShuLCB2KSB7IHRyeSB7IHN0ZXAoZ1tuXSh2KSk7IH0gY2F0Y2ggKGUpIHsgc2V0dGxlKHFbMF1bM10sIGUpOyB9IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAocikgeyByLnZhbHVlIGluc3RhbmNlb2YgX19hd2FpdCA/IFByb21pc2UucmVzb2x2ZShyLnZhbHVlLnYpLnRoZW4oZnVsZmlsbCwgcmVqZWN0KSA6IHNldHRsZShxWzBdWzJdLCByKTsgfVxyXG4gICAgZnVuY3Rpb24gZnVsZmlsbCh2YWx1ZSkgeyByZXN1bWUoXCJuZXh0XCIsIHZhbHVlKTsgfVxyXG4gICAgZnVuY3Rpb24gcmVqZWN0KHZhbHVlKSB7IHJlc3VtZShcInRocm93XCIsIHZhbHVlKTsgfVxyXG4gICAgZnVuY3Rpb24gc2V0dGxlKGYsIHYpIHsgaWYgKGYodiksIHEuc2hpZnQoKSwgcS5sZW5ndGgpIHJlc3VtZShxWzBdWzBdLCBxWzBdWzFdKTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY0RlbGVnYXRvcihvKSB7XHJcbiAgICB2YXIgaSwgcDtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiwgZnVuY3Rpb24gKGUpIHsgdGhyb3cgZTsgfSksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4sIGYpIHsgaVtuXSA9IG9bbl0gPyBmdW5jdGlvbiAodikgeyByZXR1cm4gKHAgPSAhcCkgPyB7IHZhbHVlOiBfX2F3YWl0KG9bbl0odikpLCBkb25lOiBuID09PSBcInJldHVyblwiIH0gOiBmID8gZih2KSA6IHY7IH0gOiBmOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jVmFsdWVzKG8pIHtcclxuICAgIGlmICghU3ltYm9sLmFzeW5jSXRlcmF0b3IpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTeW1ib2wuYXN5bmNJdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbiAgICB2YXIgbSA9IG9bU3ltYm9sLmFzeW5jSXRlcmF0b3JdLCBpO1xyXG4gICAgcmV0dXJuIG0gPyBtLmNhbGwobykgOiAobyA9IHR5cGVvZiBfX3ZhbHVlcyA9PT0gXCJmdW5jdGlvblwiID8gX192YWx1ZXMobykgOiBvW1N5bWJvbC5pdGVyYXRvcl0oKSwgaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIpLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGkpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IGlbbl0gPSBvW25dICYmIGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7IHYgPSBvW25dKHYpLCBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCB2LmRvbmUsIHYudmFsdWUpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gc2V0dGxlKHJlc29sdmUsIHJlamVjdCwgZCwgdikgeyBQcm9taXNlLnJlc29sdmUodikudGhlbihmdW5jdGlvbih2KSB7IHJlc29sdmUoeyB2YWx1ZTogdiwgZG9uZTogZCB9KTsgfSwgcmVqZWN0KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tYWtlVGVtcGxhdGVPYmplY3QoY29va2VkLCByYXcpIHtcclxuICAgIGlmIChPYmplY3QuZGVmaW5lUHJvcGVydHkpIHsgT2JqZWN0LmRlZmluZVByb3BlcnR5KGNvb2tlZCwgXCJyYXdcIiwgeyB2YWx1ZTogcmF3IH0pOyB9IGVsc2UgeyBjb29rZWQucmF3ID0gcmF3OyB9XHJcbiAgICByZXR1cm4gY29va2VkO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9faW1wb3J0U3Rhcihtb2QpIHtcclxuICAgIGlmIChtb2QgJiYgbW9kLl9fZXNNb2R1bGUpIHJldHVybiBtb2Q7XHJcbiAgICB2YXIgcmVzdWx0ID0ge307XHJcbiAgICBpZiAobW9kICE9IG51bGwpIGZvciAodmFyIGsgaW4gbW9kKSBpZiAoT2JqZWN0Lmhhc093blByb3BlcnR5LmNhbGwobW9kLCBrKSkgcmVzdWx0W2tdID0gbW9kW2tdO1xyXG4gICAgcmVzdWx0LmRlZmF1bHQgPSBtb2Q7XHJcbiAgICByZXR1cm4gcmVzdWx0O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnREZWZhdWx0KG1vZCkge1xyXG4gICAgcmV0dXJuIChtb2QgJiYgbW9kLl9fZXNNb2R1bGUpID8gbW9kIDogeyBkZWZhdWx0OiBtb2QgfTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY2xhc3NQcml2YXRlRmllbGRHZXQocmVjZWl2ZXIsIHByaXZhdGVNYXApIHtcclxuICAgIGlmICghcHJpdmF0ZU1hcC5oYXMocmVjZWl2ZXIpKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcImF0dGVtcHRlZCB0byBnZXQgcHJpdmF0ZSBmaWVsZCBvbiBub24taW5zdGFuY2VcIik7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gcHJpdmF0ZU1hcC5nZXQocmVjZWl2ZXIpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZFNldChyZWNlaXZlciwgcHJpdmF0ZU1hcCwgdmFsdWUpIHtcclxuICAgIGlmICghcHJpdmF0ZU1hcC5oYXMocmVjZWl2ZXIpKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcImF0dGVtcHRlZCB0byBzZXQgcHJpdmF0ZSBmaWVsZCBvbiBub24taW5zdGFuY2VcIik7XHJcbiAgICB9XHJcbiAgICBwcml2YXRlTWFwLnNldChyZWNlaXZlciwgdmFsdWUpO1xyXG4gICAgcmV0dXJuIHZhbHVlO1xyXG59XHJcbiIsImltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIjtcclxuaW1wb3J0IHtcclxuICBBcHBXaWRnZXRDb25maWcsIEFzc2Vzc21lbnQsIFxyXG4gIENsc3NSZXNwb25zZSxcclxuICBDTFNTVGVtcGxhdGUsIFxyXG4gIENvbXBvbmVudFRlbXBsYXRlLCBcclxuICBIYXphcmQsXHJcbiAgSW5jaWRlbnQsXHJcbiAgSW5Db21tZW50LFxyXG4gIEluZGljYXRvckFzc2Vzc21lbnQsXHJcbiAgSW5kaWNhdG9yVGVtcGxhdGUsIEluZGljYXRvcldlaWdodCwgTGlmZWxpbmVTdGF0dXMsIExpZmVMaW5lVGVtcGxhdGUsXHJcbiAgT3JnYW5pemF0aW9uLCBTY2FsZUZhY3RvclxyXG59IGZyb20gXCIuL2RhdGEtZGVmaW5pdGlvbnNcIjtcclxuaW1wb3J0IHtcclxuICBBU1NFU1NNRU5UX1VSTF9FUlJPUiwgXHJcbiAgQkFTRUxJTkVfVEVNUExBVEVfTkFNRSwgXHJcbiAgQ09NUE9ORU5UX1VSTF9FUlJPUiwgRU5WSVJPTk1FTlRfUFJFU0VSVkFUSU9OLCBIQVpBUkRfVVJMX0VSUk9SLCBJTkNJREVOVF9TVEFCSUxJWkFUSU9OLCBJTkNJREVOVF9VUkxfRVJST1IsIElORElDQVRPUl9VUkxfRVJST1IsXHJcbiAgTElGRV9TQUZFVFksXHJcbiAgTElGRV9TQUZFVFlfU0NBTEVfRkFDVE9SLFxyXG4gIExJRkVMSU5FX1VSTF9FUlJPUiwgTUFYSU1VTV9XRUlHSFQsIE9SR0FOSVpBVElPTl9VUkxfRVJST1IsIE9USEVSX1dFSUdIVFNfU0NBTEVfRkFDVE9SLCBcclxuICBQT1JUQUxfVVJMLCBcclxuICBQUk9QRVJUWV9QUk9URUNUSU9OLCBcclxuICBSQU5LLCBcclxuICBURU1QTEFURV9VUkxfRVJST1J9IGZyb20gXCIuL2NvbnN0YW50c1wiO1xyXG5pbXBvcnQgeyBnZXRBcHBTdG9yZSB9IGZyb20gXCJqaW11LWNvcmVcIjtcclxuaW1wb3J0IHtcclxuICBJRmVhdHVyZSwgSUZlYXR1cmVTZXQsIElGaWVsZH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXJcIjtcclxuaW1wb3J0IHsgcXVlcnlUYWJsZUZlYXR1cmVzLCBcclxuICAgdXBkYXRlVGFibGVGZWF0dXJlLCBkZWxldGVUYWJsZUZlYXR1cmVzLCBcclxuICAgIGFkZFRhYmxlRmVhdHVyZXMsIHVwZGF0ZVRhYmxlRmVhdHVyZXMsIHF1ZXJ5VGFibGVGZWF0dXJlU2V0IH0gZnJvbSBcIi4vZXNyaS1hcGlcIjtcclxuaW1wb3J0IHsgbG9nLCBMb2dUeXBlIH0gZnJvbSBcIi4vbG9nZ2VyXCI7XHJcbmltcG9ydCB7IElDb2RlZFZhbHVlIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXR5cGVzXCI7XHJcbmltcG9ydCB7IGNoZWNrQ3VycmVudFN0YXR1cywgc2lnbkluIH0gZnJvbSBcIi4vYXV0aFwiO1xyXG5pbXBvcnQgeyBDTFNTQWN0aW9uS2V5cyB9IGZyb20gXCIuL2Nsc3Mtc3RvcmVcIjtcclxuaW1wb3J0IHsgSUNyZWRlbnRpYWwgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aFwiO1xyXG5pbXBvcnQgeyBwYXJzZURhdGUgfSBmcm9tIFwiLi91dGlsc1wiO1xyXG5cclxuXHJcbi8vPT09PT09PT09PT09PT09PT09PT09PT09UFVCTElDPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxyXG5cclxuZXhwb3J0IGNvbnN0IGluaXRpYWxpemVBdXRoID0gYXN5bmMoYXBwSWQ6IHN0cmluZykgPT57ICAgXHJcbiAgY29uc29sZS5sb2coJ2luaXRpYWxpemVBdXRoIGNhbGxlZCcpXHJcbiAgbGV0IGNyZWQgPSBhd2FpdCBjaGVja0N1cnJlbnRTdGF0dXMoYXBwSWQsIFBPUlRBTF9VUkwpO1xyXG5cclxuICBpZighY3JlZCl7XHJcbiAgICBjcmVkID0gYXdhaXQgc2lnbkluKGFwcElkLCBQT1JUQUxfVVJMKTsgICAgXHJcbiAgfVxyXG5cclxuICBjb25zdCBjcmVkZW50aWFsID0ge1xyXG4gICAgZXhwaXJlczogY3JlZC5leHBpcmVzLFxyXG4gICAgc2VydmVyOiBjcmVkLnNlcnZlcixcclxuICAgIHNzbDogY3JlZC5zc2wsXHJcbiAgICB0b2tlbjogY3JlZC50b2tlbixcclxuICAgIHVzZXJJZDogY3JlZC51c2VySWRcclxuICB9IGFzIElDcmVkZW50aWFsXHJcblxyXG4gIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLkFVVEhFTlRJQ0FURV9BQ1RJT04sIGNyZWRlbnRpYWwpOyBcclxufVxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdXBkYXRlTGlmZWxpbmVTdGF0dXMobGlmZWxpbmVTdGF0dXM6IExpZmVsaW5lU3RhdHVzLCBcclxuICBjb25maWc6IEFwcFdpZGdldENvbmZpZywgYXNzZXNzbWVudE9iamVjdElkOiBudW1iZXIsICB1c2VyOiBzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgXHJcbiAgY29uc29sZS5sb2coJ2NhbGxlZCB1cGRhdGVMaWZlbGluZVN0YXR1cycpXHJcbiAgY2hlY2tQYXJhbShjb25maWcubGlmZWxpbmVTdGF0dXMsICdMaWZlbGluZSBTdGF0dXMgVVJMIG5vdCBwcm92aWRlZCcpO1xyXG5cclxuICBjb25zdCBhdHRyaWJ1dGVzID0ge1xyXG4gICAgT0JKRUNUSUQ6IGxpZmVsaW5lU3RhdHVzLm9iamVjdElkLFxyXG4gICAgU2NvcmU6IGxpZmVsaW5lU3RhdHVzLnNjb3JlLCBcclxuICAgIENvbG9yOiBsaWZlbGluZVN0YXR1cy5jb2xvciwgXHJcbiAgICBJc092ZXJyaWRlbjogbGlmZWxpbmVTdGF0dXMuaXNPdmVycmlkZW4sIFxyXG4gICAgT3ZlcnJpZGVuU2NvcmU6IGxpZmVsaW5lU3RhdHVzLm92ZXJyaWRlU2NvcmUsICBcclxuICAgIE92ZXJyaWRlbkNvbG9yOiBsaWZlbGluZVN0YXR1cy5vdmVycmlkZW5Db2xvcixcclxuICAgIE92ZXJyaWRlbkJ5OiBsaWZlbGluZVN0YXR1cy5vdmVycmlkZW5CeSwgIFxyXG4gICAgT3ZlcnJpZGVDb21tZW50OiBsaWZlbGluZVN0YXR1cy5vdmVycmlkZUNvbW1lbnQgXHJcbiAgfVxyXG4gIGxldCByZXNwb25zZSAgPSBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmUoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBhdHRyaWJ1dGVzLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG5cclxuICAgIGNvbnN0IGlhRmVhdHVyZXMgPSBsaWZlbGluZVN0YXR1cy5pbmRpY2F0b3JBc3Nlc3NtZW50cy5tYXAoaSA9PiB7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgT0JKRUNUSUQ6IGkub2JqZWN0SWQsXHJcbiAgICAgICAgICBzdGF0dXM6IGkuc3RhdHVzLFxyXG4gICAgICAgICAgQ29tbWVudHM6IGkuY29tbWVudHMgJiYgaS5jb21tZW50cy5sZW5ndGggPiAwID8gSlNPTi5zdHJpbmdpZnkoaS5jb21tZW50cyk6ICcnXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcbiAgICB9KVxyXG5cclxuICAgIHJlc3BvbnNlID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9yQXNzZXNzbWVudHMsIGlhRmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuXHJcbiAgICAgIGNvbnN0IGFzc2Vzc0ZlYXR1cmUgPSB7XHJcbiAgICAgICAgT0JKRUNUSUQ6IGFzc2Vzc21lbnRPYmplY3RJZCxcclxuICAgICAgICBFZGl0ZWREYXRlOiBuZXcgRGF0ZSgpLmdldFRpbWUoKSxcclxuICAgICAgICBFZGl0b3I6IHVzZXJcclxuICAgICAgfVxyXG4gICAgICByZXNwb25zZSA9IGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZShjb25maWcuYXNzZXNzbWVudHMsIGFzc2Vzc0ZlYXR1cmUsIGNvbmZpZylcclxuICAgICAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGRhdGE6IHRydWVcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuICAgIH0gICAgXHJcbiAgfVxyXG4gIGxvZygnVXBkYXRpbmcgTGlmZWxpbmUgc2NvcmUgZmFpbGVkJywgTG9nVHlwZS5FUlJPUiwgJ3VwZGF0ZUxpZmVsaW5lU3RhdHVzJyk7XHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ1VwZGF0aW5nIExpZmVsaW5lIHNjb3JlIGZhaWxlZCdcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjb21wbGV0ZUFzc2Vzc21lbnQoYXNzZXNzbWVudDogQXNzZXNzbWVudCwgXHJcbiAgY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHVzZXJOYW1lOiBzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgIGNoZWNrUGFyYW0oY29uZmlnLmFzc2Vzc21lbnRzLCAnTm8gQXNzZXNzbWVudCBVcmwgcHJvdmlkZWQnKTtcclxuXHJcbiAgIGNvbnN0IHJlc3BvbnNlID0gIGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZShjb25maWcuYXNzZXNzbWVudHMsIHtcclxuICAgICAgT0JKRUNUSUQ6IGFzc2Vzc21lbnQub2JqZWN0SWQsXHJcbiAgICAgIEVkaXRvcjogdXNlck5hbWUsXHJcbiAgICAgIEVkaXRlZERhdGU6IG5ldyBEYXRlKCkuZ2V0VGltZSgpLFxyXG4gICAgICBJc0NvbXBsZXRlZDogMVxyXG4gICB9LCBjb25maWcpO1xyXG4gICBjb25zb2xlLmxvZyhyZXNwb25zZSk7XHJcbiAgIHJldHVybntcclxuICAgICBkYXRhOiByZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpXHJcbiAgIH1cclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IHBhc3NEYXRhSW50ZWdyaXR5ID0gYXN5bmMgKHNlcnZpY2VVcmw6IHN0cmluZywgZmllbGRzOiBJRmllbGRbXSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpID0+IHtcclxuXHJcbiAgY2hlY2tQYXJhbShzZXJ2aWNlVXJsLCAnU2VydmljZSBVUkwgbm90IHByb3ZpZGVkJyk7XHJcblxyXG4gIC8vIHNlcnZpY2VVcmwgPSBgJHtzZXJ2aWNlVXJsfT9mPWpzb24mdG9rZW49JHt0b2tlbn1gO1xyXG4gIC8vIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2goc2VydmljZVVybCwge1xyXG4gIC8vICAgbWV0aG9kOiBcIkdFVFwiLFxyXG4gIC8vICAgaGVhZGVyczoge1xyXG4gIC8vICAgICAnY29udGVudC10eXBlJzogJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcclxuICAvLyAgIH1cclxuICAvLyB9XHJcbiAgLy8gKTtcclxuICAvLyBjb25zdCBqc29uID0gYXdhaXQgcmVzcG9uc2UuanNvbigpO1xyXG5cclxuICAvLyBjb25zdCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhzZXJ2aWNlVXJsLCAnMT0xJywgY29uZmlnKTtcclxuXHJcbiAgLy8gY29uc3QgZGF0YUZpZWxkcyA9IGZlYXR1cmVzWzBdLiBhcyBJRmllbGRbXTtcclxuXHJcbiAgLy8gZGVidWdnZXI7XHJcbiAgLy8gaWYgKGZpZWxkcy5sZW5ndGggPiBkYXRhRmllbGRzLmxlbmd0aCkge1xyXG4gIC8vICAgdGhyb3cgbmV3IEVycm9yKCdOdW1iZXIgb2YgZmllbGRzIGRvIG5vdCBtYXRjaCBmb3IgJyArIHNlcnZpY2VVcmwpO1xyXG4gIC8vIH1cclxuXHJcbiAgLy8gY29uc3QgYWxsRmllbGRzR29vZCA9IGZpZWxkcy5ldmVyeShmID0+IHtcclxuICAvLyAgIGNvbnN0IGZvdW5kID0gZGF0YUZpZWxkcy5maW5kKGYxID0+IGYxLm5hbWUgPT09IGYubmFtZSAmJiBmMS50eXBlLnRvU3RyaW5nKCkgPT09IGYudHlwZS50b1N0cmluZygpICYmIGYxLmRvbWFpbiA9PSBmLmRvbWFpbik7XHJcbiAgLy8gICByZXR1cm4gZm91bmQ7XHJcbiAgLy8gfSk7XHJcblxyXG4gIC8vIGlmICghYWxsRmllbGRzR29vZCkge1xyXG4gIC8vICAgdGhyb3cgbmV3IEVycm9yKCdJbnZhbGlkIGZpZWxkcyBpbiB0aGUgZmVhdHVyZSBzZXJ2aWNlICcgKyBzZXJ2aWNlVXJsKVxyXG4gIC8vIH1cclxuICByZXR1cm4gdHJ1ZTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0SW5kaWNhdG9yRmVhdHVyZXMocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlW10+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgSW5kaWNhdG9ycyBjYWxsZWQnKTtcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0V2VpZ2h0c0ZlYXR1cmVzKHF1ZXJ5OiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVtdPntcclxuICBjb25zb2xlLmxvZygnZ2V0IFdlaWdodHMgY2FsbGVkJyk7XHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcud2VpZ2h0cywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldExpZmVsaW5lRmVhdHVyZXMocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlW10+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgTGlmZWxpbmUgY2FsbGVkJyk7XHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0Q29tcG9uZW50RmVhdHVyZXMocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlW10+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgQ29tcG9uZW50cyBjYWxsZWQnKTtcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5jb21wb25lbnRzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0VGVtcGxhdGVGZWF0dXJlU2V0KHF1ZXJ5OiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVNldD57XHJcbiAgY29uc29sZS5sb2coJ2dldCBUZW1wbGF0ZSBjYWxsZWQnKTtcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVTZXQoY29uZmlnLnRlbXBsYXRlcywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRUZW1wbGF0ZXMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHRlbXBsYXRlSWQ/OiBzdHJpbmcsIHF1ZXJ5U3RyaW5nPzpzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxDTFNTVGVtcGxhdGVbXT4+IHtcclxuXHJcbiAgY29uc3QgdGVtcGxhdGVVcmwgPSBjb25maWcudGVtcGxhdGVzO1xyXG4gIGNvbnN0IGxpZmVsaW5lVXJsID0gY29uZmlnLmxpZmVsaW5lcztcclxuICBjb25zdCBjb21wb25lbnRVcmwgPSBjb25maWcuY29tcG9uZW50cztcclxuXHJcbiAgdHJ5e1xyXG4gICAgY2hlY2tQYXJhbSh0ZW1wbGF0ZVVybCwgVEVNUExBVEVfVVJMX0VSUk9SKTtcclxuICAgIGNoZWNrUGFyYW0obGlmZWxpbmVVcmwsIExJRkVMSU5FX1VSTF9FUlJPUik7XHJcbiAgICBjaGVja1BhcmFtKGNvbXBvbmVudFVybCwgQ09NUE9ORU5UX1VSTF9FUlJPUik7XHJcblxyXG4gICAgY29uc3QgdGVtcFF1ZXJ5ID0gdGVtcGxhdGVJZCA/IGBHbG9iYWxJRD0nJHt0ZW1wbGF0ZUlkfWAgOihxdWVyeVN0cmluZyA/IHF1ZXJ5U3RyaW5nIDogJzE9MScgKTtcclxuXHJcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IFByb21pc2UuYWxsKFtcclxuICAgICAgZ2V0VGVtcGxhdGVGZWF0dXJlU2V0KHRlbXBRdWVyeSwgY29uZmlnKSxcclxuICAgICAgZ2V0TGlmZWxpbmVGZWF0dXJlcygnMT0xJywgY29uZmlnKSwgXHJcbiAgICAgIGdldENvbXBvbmVudEZlYXR1cmVzKCcxPTEnLCBjb25maWcpXSk7XHJcbiAgICBcclxuICAgIGNvbnN0IHRlbXBsYXRlRmVhdHVyZVNldCA9IHJlc3BvbnNlWzBdO1xyXG4gICAgY29uc3QgbGlmZWxpbmVGZWF0dXJlcyA9IHJlc3BvbnNlWzFdO1xyXG4gICAgY29uc3QgY29tcG9uZW50RmVhdHVyZXMgPSByZXNwb25zZVsyXTtcclxuXHJcbiAgICBjb25zdCBpbmRpY2F0b3JGZWF0dXJlcyA9IGF3YWl0IGdldEluZGljYXRvckZlYXR1cmVzKCcxPTEnLCBjb25maWcpO1xyXG4gICAgY29uc3Qgd2VpZ2h0RmVhdHVyZXMgPSBhd2FpdCBnZXRXZWlnaHRzRmVhdHVyZXMoJzE9MScsIGNvbmZpZyk7XHJcblxyXG4gICAgY29uc3QgdGVtcGxhdGVzID0gYXdhaXQgUHJvbWlzZS5hbGwodGVtcGxhdGVGZWF0dXJlU2V0LmZlYXR1cmVzLm1hcChhc3luYyAodGVtcGxhdGVGZWF0dXJlOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgICBjb25zdCB0ZW1wbGF0ZUluZGljYXRvckZlYXR1cmVzID0gaW5kaWNhdG9yRmVhdHVyZXMuZmlsdGVyKGkgPT5pLmF0dHJpYnV0ZXMuVGVtcGxhdGVJRCA9PSB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCkgICAgICBcclxuICAgICAgcmV0dXJuIGF3YWl0IGdldFRlbXBsYXRlKHRlbXBsYXRlRmVhdHVyZSwgbGlmZWxpbmVGZWF0dXJlcywgY29tcG9uZW50RmVhdHVyZXMsIFxyXG4gICAgICAgIHRlbXBsYXRlSW5kaWNhdG9yRmVhdHVyZXMsIHdlaWdodEZlYXR1cmVzLCBcclxuICAgICAgICB0ZW1wbGF0ZUZlYXR1cmVTZXQuZmllbGRzLmZpbmQoZiA9PiBmLm5hbWUgPT09ICdTdGF0dXMnKS5kb21haW4uY29kZWRWYWx1ZXMpXHJcbiAgICB9KSk7XHJcblxyXG4gICAgaWYodGVtcGxhdGVzLmZpbHRlcih0ID0+IHQuaXNTZWxlY3RlZCkubGVuZ3RoID4gMSB8fCB0ZW1wbGF0ZXMuZmlsdGVyKHQgPT4gdC5pc1NlbGVjdGVkKS5sZW5ndGggPT0gMCl7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogdGVtcGxhdGVzLm1hcCh0ID0+IHtcclxuICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgIC4uLnQsXHJcbiAgICAgICAgICAgIGlzU2VsZWN0ZWQ6IHQubmFtZSA9PT0gQkFTRUxJTkVfVEVNUExBVEVfTkFNRVxyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH0pXHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBpZih0ZW1wbGF0ZXMubGVuZ3RoID09PSAxKXtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiB0ZW1wbGF0ZXMubWFwKHQgPT4ge1xyXG4gICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgLi4udCxcclxuICAgICAgICAgICAgaXNTZWxlY3RlZDogdHJ1ZVxyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH0pXHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHRlbXBsYXRlc1xyXG4gICAgfVxyXG4gIH1cclxuICBjYXRjaChlKXsgXHJcbiAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ2dldFRlbXBsYXRlcycpO1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiAnVGVtcGxhdGVzIHJlcXVlc3QgZmFpbGVkLidcclxuICAgIH1cclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiB1c2VGZXRjaERhdGE8VD4odXJsOiBzdHJpbmcsIGNhbGxiYWNrQWRhcHRlcj86IEZ1bmN0aW9uKTogW1QsIEZ1bmN0aW9uLCBib29sZWFuLCBzdHJpbmddIHtcclxuICBjb25zdCBbZGF0YSwgc2V0RGF0YV0gPSBSZWFjdC51c2VTdGF0ZShudWxsKTtcclxuICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSBSZWFjdC51c2VTdGF0ZSh0cnVlKTtcclxuICBjb25zdCBbZXJyb3IsIHNldEVycm9yXSA9IFJlYWN0LnVzZVN0YXRlKCcnKTtcclxuXHJcbiAgUmVhY3QudXNlRWZmZWN0KCgpID0+IHtcclxuICAgIGNvbnN0IGNvbnRyb2xsZXIgPSBuZXcgQWJvcnRDb250cm9sbGVyKCk7XHJcbiAgICByZXF1ZXN0RGF0YSh1cmwsIGNvbnRyb2xsZXIpXHJcbiAgICAgIC50aGVuKChkYXRhKSA9PiB7XHJcbiAgICAgICAgaWYgKGNhbGxiYWNrQWRhcHRlcikge1xyXG4gICAgICAgICAgc2V0RGF0YShjYWxsYmFja0FkYXB0ZXIoZGF0YSkpO1xyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICBzZXREYXRhKGRhdGEpO1xyXG4gICAgICAgIH1cclxuICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcclxuICAgICAgfSlcclxuICAgICAgLmNhdGNoKChlcnIpID0+IHtcclxuICAgICAgICBjb25zb2xlLmxvZyhlcnIpO1xyXG4gICAgICAgIHNldEVycm9yKGVycik7XHJcbiAgICAgIH0pXHJcbiAgICByZXR1cm4gKCkgPT4gY29udHJvbGxlci5hYm9ydCgpO1xyXG4gIH0sIFt1cmxdKVxyXG5cclxuICByZXR1cm4gW2RhdGEsIHNldERhdGEsIGxvYWRpbmcsIGVycm9yXVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gZGlzcGF0Y2hBY3Rpb24odHlwZTogYW55LCB2YWw6IGFueSkge1xyXG4gIGdldEFwcFN0b3JlKCkuZGlzcGF0Y2goe1xyXG4gICAgdHlwZSxcclxuICAgIHZhbFxyXG4gIH0pO1xyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0SW5jaWRlbnRzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJbmNpZGVudFtdPiB7XHJcbiAgIFxyXG4gIGNvbnNvbGUubG9nKCdnZXQgaW5jaWRlbnRzIGNhbGxlZC4nKVxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmluY2lkZW50cywgSU5DSURFTlRfVVJMX0VSUk9SKTtcclxuXHJcbiAgY29uc3QgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluY2lkZW50cywgJzE9MScsIGNvbmZpZyk7XHJcblxyXG4gIGNvbnN0IHF1ZXJ5ID0gYEdsb2JhbElEIElOICgke2ZlYXR1cmVzLm1hcChmID0+IGYuYXR0cmlidXRlcy5IYXphcmRJRCkubWFwKGlkID0+IGAnJHtpZH0nYCkuam9pbignLCcpfSlgO1xyXG4gIFxyXG4gIGNvbnN0IGhhemFyZEZlYXR1cmVzZXQgPSBhd2FpdCBnZXRIYXphcmRGZWF0dXJlcyhjb25maWcsIHF1ZXJ5LCAnZ2V0SW5jaWRlbnRzJyk7XHJcblxyXG4gIHJldHVybiBmZWF0dXJlcy5tYXAoKGY6IElGZWF0dXJlKSA9PntcclxuICAgICAgY29uc3QgaGYgPSBoYXphcmRGZWF0dXJlc2V0LmZlYXR1cmVzLmZpbmQoaCA9PiBoLmF0dHJpYnV0ZXMuR2xvYmFsSUQgPT0gZi5hdHRyaWJ1dGVzLkhhemFyZElEKVxyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIG9iamVjdElkOiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgICAgaWQ6IGYuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgICBuYW1lOiBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICBoYXphcmQ6IGhmID8ge1xyXG4gICAgICAgICAgb2JqZWN0SWQ6IGhmLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgICAgICBpZDogaGYuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgICAgIG5hbWU6IGhmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICAgIHRpdGxlOiBoZi5hdHRyaWJ1dGVzLkRpc3BsYXlUaXRsZSB8fCBoZi5hdHRyaWJ1dGVzLkRpc3BsYXlOYW1lIHx8IGhmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICAgIHR5cGU6IGhmLmF0dHJpYnV0ZXMuVHlwZSxcclxuICAgICAgICAgIGRlc2NyaXB0aW9uOiBoZi5hdHRyaWJ1dGVzLkRlc2NyaXB0aW9uLFxyXG4gICAgICAgICAgZG9tYWluczogaGF6YXJkRmVhdHVyZXNldC5maWVsZHMuZmluZChmID0+IGYubmFtZSA9PT0gJ1R5cGUnKS5kb21haW4uY29kZWRWYWx1ZXNcclxuICAgICAgICB9IDogbnVsbCxcclxuICAgICAgICBkZXNjcmlwdGlvbjogZi5hdHRyaWJ1dGVzLkRlc2NyaXB0aW9uLFxyXG4gICAgICAgIHN0YXJ0RGF0ZTogTnVtYmVyKGYuYXR0cmlidXRlcy5TdGFydERhdGUpLFxyXG4gICAgICAgIGVuZERhdGU6IE51bWJlcihmLmF0dHJpYnV0ZXMuRW5kRGF0ZSlcclxuICAgICAgfSBhcyBJbmNpZGVudDtcclxuICB9KTtcclxuICByZXR1cm4gW107XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldEhhemFyZEZlYXR1cmVzIChjb25maWc6IEFwcFdpZGdldENvbmZpZywgcXVlcnk6IHN0cmluZywgY2FsbGVyOiBzdHJpbmcpOiBQcm9taXNlPElGZWF0dXJlU2V0PiB7XHJcbiAgY29uc29sZS5sb2coJ2dldCBIYXphcmRzIGNhbGxlZCBieSAnK2NhbGxlcilcclxuICBjaGVja1BhcmFtKGNvbmZpZy5oYXphcmRzLCBIQVpBUkRfVVJMX0VSUk9SKTsgIFxyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZVNldChjb25maWcuaGF6YXJkcywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRIYXphcmRzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBxdWVyeVN0cmluZzogc3RyaW5nLCBjYWxsZXI6IHN0cmluZyk6IFByb21pc2U8SGF6YXJkW10+IHtcclxuICBcclxuICBjb25zdCBmZWF0dXJlU2V0ID0gYXdhaXQgZ2V0SGF6YXJkRmVhdHVyZXMoY29uZmlnLCBxdWVyeVN0cmluZywgY2FsbGVyKTtcclxuICBpZighZmVhdHVyZVNldCB8fCBmZWF0dXJlU2V0LmZlYXR1cmVzLmxlbmd0aCA9PSAwKXtcclxuICAgIHJldHVybiBbXTtcclxuICB9XHJcbiAgcmV0dXJuIGZlYXR1cmVTZXQuZmVhdHVyZXMubWFwKChmOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgb2JqZWN0SWQ6IGYuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgaWQ6IGYuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgbmFtZTogZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgIHRpdGxlOiBmLmF0dHJpYnV0ZXMuRGlzcGxheVRpdGxlIHx8IGYuYXR0cmlidXRlcy5EaXNwbGF5TmFtZSB8fCBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgdHlwZTogZi5hdHRyaWJ1dGVzLlR5cGUsXHJcbiAgICAgIGRlc2NyaXB0aW9uOiBmLmF0dHJpYnV0ZXMuRGVzY3JpcHRpb24sXHJcbiAgICAgIGRvbWFpbnM6IGZlYXR1cmVTZXQuZmllbGRzLmZpbmQoZiA9PiBmLm5hbWUgPT09ICdUeXBlJykuZG9tYWluLmNvZGVkVmFsdWVzXHJcbiAgICB9IGFzIEhhemFyZFxyXG4gIH0pXHJcbiAgcmV0dXJuIFtdO1xyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0T3JnYW5pemF0aW9ucyhjb25maWc6IEFwcFdpZGdldENvbmZpZywgcXVlcnlTdHJpbmc6IHN0cmluZyk6IFByb21pc2U8T3JnYW5pemF0aW9uW10+IHtcclxuICBjb25zb2xlLmxvZygnZ2V0IE9yZ2FuaXphdGlvbnMgY2FsbGVkJylcclxuICBjaGVja1BhcmFtKGNvbmZpZy5vcmdhbml6YXRpb25zLCBPUkdBTklaQVRJT05fVVJMX0VSUk9SKTtcclxuXHJcbiAgY29uc3QgZmVhdHVyZVNldCA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlU2V0KGNvbmZpZy5vcmdhbml6YXRpb25zLCBxdWVyeVN0cmluZywgY29uZmlnKTtcclxuIFxyXG4gIGlmKGZlYXR1cmVTZXQgJiYgZmVhdHVyZVNldC5mZWF0dXJlcyAmJiBmZWF0dXJlU2V0LmZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgcmV0dXJuIGZlYXR1cmVTZXQuZmVhdHVyZXMubWFwKChmOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIG9iamVjdElkOiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgICAgaWQ6IGYuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgICBuYW1lOiBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICB0aXRsZTogZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgdHlwZTogZi5hdHRyaWJ1dGVzLlR5cGUsXHJcbiAgICAgICAgcGFyZW50SWQ6IGYuYXR0cmlidXRlcy5QYXJlbnRJRCxcclxuICAgICAgICBkZXNjcmlwdGlvbjogZi5hdHRyaWJ1dGVzLkRlc2NyaXB0aW9uLFxyXG4gICAgICAgIGRvbWFpbnM6IGZlYXR1cmVTZXQuZmllbGRzLmZpbmQoZiA9PiBmLm5hbWUgPT09ICdUeXBlJykuZG9tYWluLmNvZGVkVmFsdWVzXHJcbiAgICAgIH0gYXMgT3JnYW5pemF0aW9uXHJcbiAgICB9KVxyXG4gIH1cclxuICByZXR1cm4gW107XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjcmVhdGVOZXdUZW1wbGF0ZShjb25maWc6IEFwcFdpZGdldENvbmZpZywgdGVtcGxhdGU6IENMU1NUZW1wbGF0ZSwgXHJcbiB1c2VyTmFtZTogc3RyaW5nLCBvcmdhbml6YXRpb246IE9yZ2FuaXphdGlvbiwgaGF6YXJkOiBIYXphcmQpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj4ge1xyXG4gXHJcbiAgY2hlY2tQYXJhbShjb25maWcudGVtcGxhdGVzLCBURU1QTEFURV9VUkxfRVJST1IpO1xyXG4gIGNoZWNrUGFyYW0odGVtcGxhdGUsICdUZW1wbGF0ZSBkYXRhIG5vdCBwcm92aWRlZCcpO1xyXG5cclxuICBjb25zdCBjcmVhdGVEYXRlID0gbmV3IERhdGUoKS5nZXRUaW1lKCk7XHJcbiAgY29uc3QgdGVtcGxhdGVOYW1lID0gdGVtcGxhdGUubmFtZVswXS50b0xvY2FsZVVwcGVyQ2FzZSgpK3RlbXBsYXRlLm5hbWUuc3Vic3RyaW5nKDEpO1xyXG4gXHJcbiAgbGV0IGZlYXR1cmUgPSB7XHJcbiAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgIE9yZ2FuaXphdGlvbklEOiBvcmdhbml6YXRpb24gPyBvcmdhbml6YXRpb24uaWQgOiAgbnVsbCxcclxuICAgICAgT3JnYW5pemF0aW9uTmFtZTogb3JnYW5pemF0aW9uID8gb3JnYW5pemF0aW9uLm5hbWU6IG51bGwsXHJcbiAgICAgIE9yZ2FuaXphdGlvblR5cGU6IG9yZ2FuaXphdGlvbiA/IChvcmdhbml6YXRpb24udHlwZS5jb2RlID8gb3JnYW5pemF0aW9uLnR5cGUuY29kZTogb3JnYW5pemF0aW9uLnR5cGUgKTogbnVsbCxcclxuICAgICAgSGF6YXJkSUQ6ICBoYXphcmQgPyBoYXphcmQuaWQgOiBudWxsLFxyXG4gICAgICBIYXphcmROYW1lOiAgaGF6YXJkID8gaGF6YXJkLm5hbWUgOiBudWxsLFxyXG4gICAgICBIYXphcmRUeXBlOiAgaGF6YXJkID8gKGhhemFyZC50eXBlLmNvZGUgPyBoYXphcmQudHlwZS5jb2RlIDogaGF6YXJkLnR5cGUpIDogbnVsbCxcclxuICAgICAgTmFtZTogdGVtcGxhdGVOYW1lICxcclxuICAgICAgQ3JlYXRvcjogdXNlck5hbWUsXHJcbiAgICAgIENyZWF0ZWREYXRlOiBjcmVhdGVEYXRlLCAgICAgIFxyXG4gICAgICBTdGF0dXM6IDEsXHJcbiAgICAgIElzU2VsZWN0ZWQ6IDAsXHJcbiAgICAgIEVkaXRvcjogdXNlck5hbWUsXHJcbiAgICAgIEVkaXRlZERhdGU6IGNyZWF0ZURhdGUgICAgIFxyXG4gICAgfVxyXG4gIH1cclxuICBsZXQgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy50ZW1wbGF0ZXMsIFtmZWF0dXJlXSwgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuICAgIFxyXG4gICAgY29uc3QgdGVtcGxhdGVJZCA9IHJlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWQ7XHJcbiAgICAvL2NyZWF0ZSBuZXcgaW5kaWNhdG9ycyAgIFxyXG4gICAgY29uc3QgaW5kaWNhdG9ycyA9IGdldFRlbXBsYXRlSW5kaWNhdG9ycyh0ZW1wbGF0ZSk7XHJcbiAgICBjb25zdCBpbmRpY2F0b3JGZWF0dXJlcyA9IGluZGljYXRvcnMubWFwKGluZGljYXRvciA9PiB7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgVGVtcGxhdGVJRDogdGVtcGxhdGVJZCwgIFxyXG4gICAgICAgICAgQ29tcG9uZW50SUQ6IGluZGljYXRvci5jb21wb25lbnRJZCxcclxuICAgICAgICAgIENvbXBvbmVudE5hbWU6IGluZGljYXRvci5jb21wb25lbnROYW1lLCAgXHJcbiAgICAgICAgICBOYW1lOiBpbmRpY2F0b3IubmFtZSwgICBcclxuICAgICAgICAgIFRlbXBsYXRlTmFtZTogdGVtcGxhdGVOYW1lLCBcclxuICAgICAgICAgIExpZmVsaW5lTmFtZTogaW5kaWNhdG9yLmxpZmVsaW5lTmFtZSAgICAgIFxyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG4gICAgfSlcclxuICAgIHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9ycywgaW5kaWNhdG9yRmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuXHJcbiAgICAgIGNvbnN0IGdsb2JhbElkcyA9IGAoJHtyZXNwb25zZS5hZGRSZXN1bHRzLm1hcChyID0+IGAnJHtyLmdsb2JhbElkfSdgKS5qb2luKCcsJyl9KWA7XHJcbiAgICAgIGNvbnN0IHF1ZXJ5ID0gJ0dsb2JhbElEIElOICcrZ2xvYmFsSWRzOyAgICAgXHJcbiAgICAgIGNvbnN0IGFkZGVkSW5kaWNhdG9yRmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvcnMscXVlcnkgLCBjb25maWcpO1xyXG5cclxuICAgICAgIGxldCB3ZWlnaHRzRmVhdHVyZXMgPSBbXTtcclxuICAgICAgIGZvcihsZXQgZmVhdHVyZSBvZiBhZGRlZEluZGljYXRvckZlYXR1cmVzKXsgICBcclxuICAgICAgICAgY29uc3QgaW5jb21pbmdJbmRpY2F0b3IgPSBpbmRpY2F0b3JzLmZpbmQoaSA9PiBpLm5hbWUgPT09IGZlYXR1cmUuYXR0cmlidXRlcy5OYW1lKTtcclxuICAgICAgICAgaWYoaW5jb21pbmdJbmRpY2F0b3Ipe1xyXG4gICAgICAgICAgY29uc3Qgd2VpZ2h0RmVhdHVyZXMgPSBpbmNvbWluZ0luZGljYXRvci53ZWlnaHRzLm1hcCh3ID0+IHsgICAgICAgIFxyXG4gICAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgICAgICAgIEluZGljYXRvcklEOiBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsICBcclxuICAgICAgICAgICAgICAgIE5hbWU6IHcubmFtZSAsXHJcbiAgICAgICAgICAgICAgICBXZWlnaHQ6IHcud2VpZ2h0LCBcclxuICAgICAgICAgICAgICAgIFNjYWxlRmFjdG9yOiAwLCAgXHJcbiAgICAgICAgICAgICAgICBBZGp1c3RlZFdlaWdodCA6IDAsXHJcbiAgICAgICAgICAgICAgICBNYXhBZGp1c3RlZFdlaWdodDowXHJcbiAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICB9KTtcclxuICAgICAgICAgIHdlaWdodHNGZWF0dXJlcyA9IHdlaWdodHNGZWF0dXJlcy5jb25jYXQod2VpZ2h0RmVhdHVyZXMpXHJcbiAgICAgICAgIH0gICAgICAgICAgICBcclxuICAgICAgIH1cclxuXHJcbiAgICAgICByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLndlaWdodHMsIHdlaWdodHNGZWF0dXJlcywgY29uZmlnKTtcclxuICAgICAgIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgICAgfVxyXG4gICAgICAgfVxyXG4gICAgfVxyXG4gICAgLy8gY29uc3QgcHJvbWlzZXMgPSBpbmRpY2F0b3JzLm1hcChpbmRpY2F0b3IgPT4gY3JlYXRlTmV3SW5kaWNhdG9yKGluZGljYXRvciwgY29uZmlnLCB0ZW1wbGF0ZUlkLCB0ZW1wbGF0ZU5hbWUpKTtcclxuXHJcbiAgICAvLyBjb25zdCBwcm9taXNlUmVzcG9uc2UgPSBhd2FpdCBQcm9taXNlLmFsbChwcm9taXNlcyk7XHJcbiAgICAvLyBpZihwcm9taXNlUmVzcG9uc2UuZXZlcnkocCA9PiBwLmRhdGEpKXtcclxuICAgIC8vICAgcmV0dXJuIHtcclxuICAgIC8vICAgICBkYXRhOiB0cnVlXHJcbiAgICAvLyAgIH1cclxuICAgIC8vIH1cclxuICB9IFxyXG5cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAnY3JlYXRlTmV3VGVtcGxhdGUnKVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSBjcmVhdGluZyB0aGUgbmV3IHRlbXBsYXRlJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHVwZGF0ZVRlbXBsYXRlT3JnYW5pemF0aW9uQW5kSGF6YXJkKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBcclxuICB0ZW1wbGF0ZTogQ0xTU1RlbXBsYXRlLCB1c2VyTmFtZTogc3RyaW5nKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+IHtcclxuXHJcbiAgY2hlY2tQYXJhbSh0ZW1wbGF0ZSwgJ1RlbXBsYXRlIG5vdCBwcm92aWRlZCcpO1xyXG4gIGNoZWNrUGFyYW0oY29uZmlnLnRlbXBsYXRlcywgVEVNUExBVEVfVVJMX0VSUk9SKTsgXHJcblxyXG4gIGNvbnN0IGF0dHJpYnV0ZXMgPSB7XHJcbiAgICBPQkpFQ1RJRDogdGVtcGxhdGUub2JqZWN0SWQsXHJcbiAgICBPcmdhbml6YXRpb25JRDogdGVtcGxhdGUub3JnYW5pemF0aW9uSWQsXHJcbiAgICBIYXphcmRJRDogdGVtcGxhdGUuaGF6YXJkSWQsXHJcbiAgICBPcmdhbml6YXRpb25OYW1lOiB0ZW1wbGF0ZS5vcmdhbml6YXRpb25OYW1lLFxyXG4gICAgT3JnYW5pemF0aW9uVHlwZTogdGVtcGxhdGUub3JnYW5pemF0aW9uVHlwZSxcclxuICAgIEhhemFyZE5hbWU6IHRlbXBsYXRlLmhhemFyZE5hbWUsXHJcbiAgICBIYXphcmRUeXBlOiB0ZW1wbGF0ZS5oYXphcmRUeXBlLFxyXG4gICAgTmFtZTogdGVtcGxhdGUubmFtZSxcclxuICAgIEVkaXRvcjogdXNlck5hbWUsXHJcbiAgICBFZGl0ZWREYXRlOiBuZXcgRGF0ZSgpLmdldFRpbWUoKSxcclxuICAgIFN0YXR1czogdGVtcGxhdGUuc3RhdHVzLmNvZGUsXHJcbiAgICBJc1NlbGVjdGVkOiB0ZW1wbGF0ZS5pc1NlbGVjdGVkID8gMTogMFxyXG4gIH0gXHJcbiAgY29uc3QgcmVzcG9uc2UgPSAgYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy50ZW1wbGF0ZXMsIGF0dHJpYnV0ZXMsIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB0cnVlXHJcbiAgICB9XHJcbiAgfVxyXG4gIGxvZyhKU09OLnN0cmluZ2lmeShyZXNwb25zZSksIExvZ1R5cGUuRVJST1IsICd1cGRhdGVUZW1wbGF0ZU9yZ2FuaXphdGlvbkFuZEhhemFyZCcpXHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHVwZGF0aW5nIHRlbXBsYXRlLidcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzZWxlY3RUZW1wbGF0ZShvYmplY3RJZDogbnVtYmVyLCBvYmplY3RJZHM6IG51bWJlcltdLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPFN0cmluZz4+IHtcclxuICBcclxuICAgIGNvbnNvbGUubG9nKCdzZWxlY3QgVGVtcGxhdGUgY2FsbGVkJylcclxuICAgIHRyeXtcclxuICAgICAgY2hlY2tQYXJhbShjb25maWcudGVtcGxhdGVzLCBURU1QTEFURV9VUkxfRVJST1IpO1xyXG5cclxuICAgICAgLy9sZXQgZmVhdHVyZXMgPSBhd2FpdCBnZXRUZW1wbGF0ZUZlYXR1cmVzKCcxPTEnLCBjb25maWcpLy8gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy50ZW1wbGF0ZXMsICcxPTEnLCBjb25maWcpXHJcbiAgICBcclxuICAgICAgY29uc3QgZmVhdHVyZXMgPSAgb2JqZWN0SWRzLm1hcChvaWQgPT4ge1xyXG4gICAgICAgIHJldHVybiB7ICAgICAgICAgIFxyXG4gICAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgICBPQkpFQ1RJRDogb2lkLFxyXG4gICAgICAgICAgICBJc1NlbGVjdGVkOiBvaWQgPT09IG9iamVjdElkID8gMSA6IDBcclxuICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICAgIH0pXHJcbiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlcyhjb25maWcudGVtcGxhdGVzLCBmZWF0dXJlcywgY29uZmlnKVxyXG4gICAgICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGRhdGE6IHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHNbMF0uZ2xvYmFsSWRcclxuICAgICAgICAgfSBhcyBDbHNzUmVzcG9uc2U8U3RyaW5nPjtcclxuICAgICAgfVxyXG4gICAgfWNhdGNoKGUpIHtcclxuICAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdzZWxlY3RUZW1wbGF0ZScpO1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGVycm9yczogZVxyXG4gICAgICB9XHJcbiAgICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBsb2FkU2NhbGVGYWN0b3JzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8U2NhbGVGYWN0b3JbXT4+e1xyXG5cclxuICBjaGVja1BhcmFtKGNvbmZpZy5jb25zdGFudHMsICdSYXRpbmcgU2NhbGVzIHVybCBub3QgcHJvdmlkZWQnKTtcclxuXHJcbiAgdHJ5e1xyXG5cclxuICAgY29uc3QgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmNvbnN0YW50cywgJzE9MScsIGNvbmZpZyk7XHJcbiAgIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgIGNvbnN0IHNjYWxlcyA9ICBmZWF0dXJlcy5tYXAoZiA9PntcclxuICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgIG5hbWU6IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgICB2YWx1ZTogZi5hdHRyaWJ1dGVzLlZhbHVlXHJcbiAgICAgICB9IGFzIFNjYWxlRmFjdG9yOyAgICAgICBcclxuICAgICB9KVxyXG5cclxuICAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiBzY2FsZXNcclxuICAgIH0gYXMgQ2xzc1Jlc3BvbnNlPFNjYWxlRmFjdG9yW10+XHJcbiAgIH1cclxuXHJcbiAgIGxvZygnRXJyb3Igb2NjdXJyZWQgd2hpbGUgcmVxdWVzdGluZyByYXRpbmcgc2NhbGVzJywgTG9nVHlwZS5FUlJPUiwgJ2xvYWRSYXRpbmdTY2FsZXMnKVxyXG4gICByZXR1cm4ge1xyXG4gICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHJlcXVlc3RpbmcgcmF0aW5nIHNjYWxlcydcclxuICAgfVxyXG4gIH0gY2F0Y2goZSl7XHJcbiAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdsb2FkUmF0aW5nU2NhbGVzJyk7ICAgIFxyXG4gIH0gIFxyXG4gICBcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNyZWF0ZU5ld0luZGljYXRvcihpbmRpY2F0b3I6IEluZGljYXRvclRlbXBsYXRlLCBjb25maWc6IEFwcFdpZGdldENvbmZpZywgdGVtcGxhdGVJZDogc3RyaW5nLCB0ZW1wbGF0ZU5hbWU6IHN0cmluZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PiB7XHJcblxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmluZGljYXRvcnMsIElORElDQVRPUl9VUkxfRVJST1IpO1xyXG5cclxuICBjb25zdCBpbmRpY2F0b3JGZWF0dXJlID0ge1xyXG4gICAgYXR0cmlidXRlczoge1xyXG4gICAgICBUZW1wbGF0ZUlEOiB0ZW1wbGF0ZUlkLCAgXHJcbiAgICAgIENvbXBvbmVudElEOiBpbmRpY2F0b3IuY29tcG9uZW50SWQsXHJcbiAgICAgIENvbXBvbmVudE5hbWU6IGluZGljYXRvci5jb21wb25lbnROYW1lLCAgXHJcbiAgICAgIE5hbWU6IGluZGljYXRvci5uYW1lLCAgIFxyXG4gICAgICBUZW1wbGF0ZU5hbWU6IHRlbXBsYXRlTmFtZSwgXHJcbiAgICAgIExpZmVsaW5lTmFtZTogaW5kaWNhdG9yLmxpZmVsaW5lTmFtZSAgICAgIFxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgbGV0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9ycywgW2luZGljYXRvckZlYXR1cmVdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG5cclxuICAgIGNvbnN0IHdlaWdodEZlYXR1cmVzID0gaW5kaWNhdG9yLndlaWdodHMubWFwKHcgPT4ge1xyXG4gICAgICAgXHJcbiAgICAgICByZXR1cm4ge1xyXG4gICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgIEluZGljYXRvcklEOiByZXNwb25zZS5hZGRSZXN1bHRzWzBdLmdsb2JhbElkLCAgXHJcbiAgICAgICAgICBOYW1lOiB3Lm5hbWUgLFxyXG4gICAgICAgICAgV2VpZ2h0OiB3LndlaWdodCwgXHJcbiAgICAgICAgICBTY2FsZUZhY3RvcjogMCwgIFxyXG4gICAgICAgICAgQWRqdXN0ZWRXZWlnaHQgOiAwLFxyXG4gICAgICAgICAgTWF4QWRqdXN0ZWRXZWlnaHQ6MFxyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG4gICAgfSk7XHJcblxyXG4gICAgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy53ZWlnaHRzLCB3ZWlnaHRGZWF0dXJlcywgY29uZmlnKTtcclxuICAgIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgICB9XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAnY3JlYXRlTmV3SW5kaWNhdG9yJyk7XHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHNhdmluZyB0aGUgaW5kaWNhdG9yLidcclxuICB9XHJcblxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdXBkYXRlSW5kaWNhdG9yTmFtZShjb25maWc6IEFwcFdpZGdldENvbmZpZywgaW5kaWNhdG9yVGVtcDpJbmRpY2F0b3JUZW1wbGF0ZSk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICAgXHJcbiAgY2hlY2tQYXJhbShjb25maWcuaW5kaWNhdG9ycywgSU5ESUNBVE9SX1VSTF9FUlJPUik7XHJcblxyXG4gIGNvbnN0IGF0dHJpYnV0ZXMgPSB7XHJcbiAgICBPQkpFQ1RJRDogaW5kaWNhdG9yVGVtcC5vYmplY3RJZCxcclxuICAgIE5hbWU6IGluZGljYXRvclRlbXAubmFtZSxcclxuICAgIERpc3BsYXlUaXRsZTogaW5kaWNhdG9yVGVtcC5uYW1lLFxyXG4gICAgSXNBY3RpdmU6IDFcclxuICB9XHJcbiAgY29uc3QgcmVzcG9uc2UgPSAgYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy5pbmRpY2F0b3JzLCBhdHRyaWJ1dGVzLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHRydWVcclxuICAgICB9XHJcbiAgfVxyXG4gIGxvZyhKU09OLnN0cmluZ2lmeShyZXNwb25zZSksIExvZ1R5cGUuRVJST1IsICd1cGRhdGVJbmRpY2F0b3JOYW1lJylcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgdXBkYXRpbmcgaW5kaWNhdG9yJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHVwZGF0ZUluZGljYXRvcihpbmRpY2F0b3I6IEluZGljYXRvclRlbXBsYXRlLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICAgXHJcbiAgY2hlY2tQYXJhbShjb25maWcuaW5kaWNhdG9ycywgSU5DSURFTlRfVVJMX0VSUk9SKTtcclxuXHJcbiAgbGV0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLCBgTmFtZT0nJHtpbmRpY2F0b3IubmFtZX0nIEFORCBUZW1wbGF0ZU5hbWU9JyR7aW5kaWNhdG9yLnRlbXBsYXRlTmFtZX0nYCwgY29uZmlnKVxyXG4gXHJcbiAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMSl7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBlcnJvcnM6ICdBbiBpbmRpY2F0b3Igd2l0aCB0aGUgc2FtZSBuYW1lIGFscmVhZHkgZXhpc3RzJ1xyXG4gICAgfVxyXG4gIH1cclxuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IHVwZGF0ZUluZGljYXRvck5hbWUoY29uZmlnLCBpbmRpY2F0b3IpO1xyXG5cclxuICBpZihyZXNwb25zZS5lcnJvcnMpe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiByZXNwb25zZS5lcnJvcnNcclxuICAgIH1cclxuICB9XHJcbiBcclxuICAgZmVhdHVyZXMgPSBpbmRpY2F0b3Iud2VpZ2h0cy5tYXAodyA9PiB7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgIE9CSkVDVElEOiB3Lm9iamVjdElkLFxyXG4gICAgICAgICAgV2VpZ2h0OiBOdW1iZXIody53ZWlnaHQpLCBcclxuICAgICAgICAgIEFkanVzdGVkV2VpZ2h0OiBOdW1iZXIody53ZWlnaHQpICogdy5zY2FsZUZhY3RvclxyXG4gICAgICAgfVxyXG4gICAgIH1cclxuICAgfSk7XHJcblxyXG4gICBjb25zdCB1cGRhdGVSZXNwb25zZSA9IGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLndlaWdodHMsIGZlYXR1cmVzLCBjb25maWcpO1xyXG4gICBpZih1cGRhdGVSZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHVwZGF0ZVJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB0cnVlXHJcbiAgICAgfVxyXG4gICB9XHJcblxyXG4gICBsb2coSlNPTi5zdHJpbmdpZnkodXBkYXRlUmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAndXBkYXRlSW5kaWNhdG9yJyk7XHJcbiAgIHJldHVybiB7XHJcbiAgICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgdXBkYXRpbmcgaW5kaWNhdG9yLidcclxuICAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVsZXRlSW5kaWNhdG9yKGluZGljYXRvclRlbXBsYXRlOiBJbmRpY2F0b3JUZW1wbGF0ZSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj4ge1xyXG5cclxuICBjaGVja1BhcmFtKGNvbmZpZy5pbmRpY2F0b3JzLCBJTkRJQ0FUT1JfVVJMX0VSUk9SKTtcclxuICBjaGVja1BhcmFtKGNvbmZpZy53ZWlnaHRzLCAnV2VpZ2h0cyBVUkwgbm90IHByb3ZpZGVkJyk7XHJcbiAgXHJcbiAgbGV0IHJlc3AgPSBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLCBbaW5kaWNhdG9yVGVtcGxhdGUub2JqZWN0SWRdLCBjb25maWcpO1xyXG4gIGlmKHJlc3AuZGVsZXRlUmVzdWx0cyAmJiByZXNwLmRlbGV0ZVJlc3VsdHMuZXZlcnkoZCA9PiBkLnN1Y2Nlc3MpKXtcclxuICAgICBjb25zdCB3ZWlnaHRzT2JqZWN0SWRzID0gaW5kaWNhdG9yVGVtcGxhdGUud2VpZ2h0cy5tYXAodyA9PiB3Lm9iamVjdElkKTtcclxuICAgICByZXNwID0gYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcud2VpZ2h0cywgd2VpZ2h0c09iamVjdElkcywgY29uZmlnKTtcclxuICAgICBpZihyZXNwLmRlbGV0ZVJlc3VsdHMgJiYgcmVzcC5kZWxldGVSZXN1bHRzLmV2ZXJ5KGQgPT4gZC5zdWNjZXNzKSl7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgICB9XHJcbiAgICAgfVxyXG4gIH1cclxuXHJcbiAgbG9nKEpTT04uc3RyaW5naWZ5KHJlc3ApLCBMb2dUeXBlLkVSUk9SLCAnZGVsZXRlSW5kaWNhdG9yJylcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgZGVsZXRpbmcgdGhlIGluZGljYXRvcidcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBhcmNoaXZlVGVtcGxhdGUob2JqZWN0SWQ6IG51bWJlciwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj4ge1xyXG4gXHJcbiAgY29uc3QgcmVzcG9uc2UgID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy50ZW1wbGF0ZXMsIHtcclxuICAgIE9CSkVDVElEOiBvYmplY3RJZCxcclxuICAgIElzU2VsZWN0ZWQ6IDAsXHJcbiAgICBJc0FjdGl2ZTogMFxyXG4gIH0sIGNvbmZpZyk7XHJcbiAgY29uc29sZS5sb2cocmVzcG9uc2UpO1xyXG4gIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeShlID0+IGUuc3VjY2Vzcykpe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgfVxyXG4gIH1cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAnYXJjaGl2ZVRlbXBsYXRlJyk7XHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ1RoZSB0ZW1wbGF0ZSBjYW5ub3QgYmUgYXJjaGl2ZWQuJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHNhdmVPcmdhbml6YXRpb24oY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIG9yZ2FuaXphdGlvbjogT3JnYW5pemF0aW9uKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8T3JnYW5pemF0aW9uPj4ge1xyXG5cclxuICBjaGVja1BhcmFtKGNvbmZpZy5vcmdhbml6YXRpb25zLCBPUkdBTklaQVRJT05fVVJMX0VSUk9SKTtcclxuICBjaGVja1BhcmFtKG9yZ2FuaXphdGlvbiwgJ09yZ2FuaXphdGlvbiBvYmplY3Qgbm90IHByb3ZpZGVkJyk7XHJcbiBcclxuICBjb25zdCBmZWF0dXJlID0ge1xyXG4gICAgYXR0cmlidXRlczoge1xyXG4gICAgICBOYW1lOiBvcmdhbml6YXRpb24ubmFtZSxcclxuICAgICAgVHlwZTogb3JnYW5pemF0aW9uLnR5cGU/LmNvZGUsXHJcbiAgICAgIERpc3BsYXlUaXRsZTogb3JnYW5pemF0aW9uLm5hbWUsXHJcbiAgICAgIFBhcmVudElEOiBvcmdhbml6YXRpb24/LnBhcmVudElkXHJcbiAgICB9XHJcbiAgfVxyXG4gIGNvbnN0IHJlc3BvbnNlID0gIGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLm9yZ2FuaXphdGlvbnMsIFtmZWF0dXJlXSwgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXsgXHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB7XHJcbiAgICAgICAgLi4ub3JnYW5pemF0aW9uXHJcbiAgICAgIH0gYXMgT3JnYW5pemF0aW9uIC8vIChhd2FpdCBnZXRPcmdhbml6YXRpb25zKGNvbmZpZywgYEdsb2JhbElEPScke3Jlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWR9J2ApKVswXVxyXG4gICAgfVxyXG4gIH1cclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiBKU09OLnN0cmluZ2lmeShyZXNwb25zZSlcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzYXZlSGF6YXJkKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBoYXphcmQ6IEhhemFyZCk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPEhhemFyZD4+IHtcclxuICBcclxuICBjb25zdCBmZWF0dXJlID0ge1xyXG4gICAgYXR0cmlidXRlczoge1xyXG4gICAgICBOYW1lOiBoYXphcmQubmFtZSxcclxuICAgICAgRGlzcGxheVRpdGxlOiBoYXphcmQubmFtZSxcclxuICAgICAgVHlwZTogaGF6YXJkLnR5cGUuY29kZSxcclxuICAgICAgRGVzY3JpcHRpb246IGhhemFyZC5kZXNjcmlwdGlvblxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgY29uc3QgcmVzcG9uc2UgPSAgYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaGF6YXJkcywgW2ZlYXR1cmVdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2VzcykpeyAgIFxyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IHtcclxuICAgICAgICAgIC4uLmhhemFyZCxcclxuICAgICAgICAgIG9iamVjdElkOiByZXNwb25zZS5hZGRSZXN1bHRzWzBdLm9iamVjdElkLFxyXG4gICAgICAgICAgaWQ6IHJlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWRcclxuICAgICAgICB9IGFzIEhhemFyZCAgXHJcbiAgICAgIH1cclxuICB9XHJcblxyXG4gIGxvZyhgRXJyb3Igb2NjdXJyZWQgd2hpbGUgc2F2aW5nIGhhemFyZC4gUmVzdGFydGluZyB0aGUgYXBwbGljYXRpb24gbWF5IGZpeCB0aGlzIGlzc3VlLmAsIExvZ1R5cGUuRVJST1IsICdzYXZlSGF6YXJkJylcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgc2F2aW5nIGhhemFyZC4gUmVzdGFydGluZyB0aGUgYXBwbGljYXRpb24gbWF5IGZpeCB0aGlzIGlzc3VlLidcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWxldGVJbmNpZGVudChpbmNpZGVudDogSW5jaWRlbnQsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcuaW5jaWRlbnRzLCBbaW5jaWRlbnQub2JqZWN0SWRdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmRlbGV0ZVJlc3VsdHMgJiYgcmVzcG9uc2UuZGVsZXRlUmVzdWx0cy5ldmVyeShkID0+IGQuc3VjY2Vzcykpe1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgfVxyXG4gIH1cclxuICByZXR1cm4ge1xyXG4gICBlcnJvcnM6IEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKVxyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZUhhemFyZChoYXphcmQ6IEhhemFyZCwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcuaGF6YXJkcywgW2hhemFyZC5vYmplY3RJZF0sIGNvbmZpZyk7XHJcbiAgIGlmKHJlc3BvbnNlLmRlbGV0ZVJlc3VsdHMgJiYgcmVzcG9uc2UuZGVsZXRlUmVzdWx0cy5ldmVyeShkID0+IGQuc3VjY2Vzcykpe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IHRydWVcclxuICAgICAgfVxyXG4gICB9XHJcbiAgIHJldHVybiB7XHJcbiAgICBlcnJvcnM6IEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKVxyXG4gICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWxldGVPcmdhbml6YXRpb24ob3JnYW5pemF0aW9uOiBPcmdhbml6YXRpb24sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcub3JnYW5pemF0aW9ucywgW29yZ2FuaXphdGlvbi5vYmplY3RJZF0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UuZGVsZXRlUmVzdWx0cyAmJiByZXNwb25zZS5kZWxldGVSZXN1bHRzLmV2ZXJ5KGQgPT4gZC5zdWNjZXNzKSl7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgIGRhdGE6IHRydWVcclxuICAgICB9XHJcbiAgfVxyXG4gIHJldHVybiB7XHJcbiAgIGVycm9yczogSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY2hlY2tQYXJhbShwYXJhbTogYW55LCBlcnJvcjogc3RyaW5nKSB7XHJcbiAgaWYgKCFwYXJhbSB8fCBwYXJhbSA9PSBudWxsIHx8IHBhcmFtID09PSAnJyB8fCBwYXJhbSA9PSB1bmRlZmluZWQpIHtcclxuICAgIHRocm93IG5ldyBFcnJvcihlcnJvcilcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB0ZW1wbENsZWFuVXAoaW5kVXJsOiBzdHJpbmcsIGFsaWdVcmw6IHN0cmluZywgdG9rZW46IHN0cmluZykge1xyXG5cclxuXHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzYXZlTmV3QXNzZXNzbWVudChuZXdBc3Nlc3NtZW50OiBBc3Nlc3NtZW50LCB0ZW1wbGF0ZTogQ0xTU1RlbXBsYXRlLCBcclxuICAgICAgICAgICAgICAgICAgY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHByZXZBc3Nlc3NtZW50PzogQXNzZXNzbWVudCk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPHN0cmluZz4+eyAgICBcclxuICAgICAgXHJcbiAgICAgIGNvbnN0IHJlc3AgPSBhd2FpdCBzYXZlQXNzZXNzbWVudChuZXdBc3Nlc3NtZW50LCBjb25maWcpO1xyXG4gICAgICBpZihyZXNwLmVycm9ycyl7XHJcbiAgICAgICAgbG9nKCdVbmFibGUgdG8gY3JlYXRlIHRoZSBhc3Nlc3NtZW50LicsIExvZ1R5cGUuRVJST1IsICdzYXZlTmV3QXNzZXNzbWVudCcpO1xyXG5cclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgZXJyb3JzOiAnVW5hYmxlIHRvIGNyZWF0ZSB0aGUgYXNzZXNzbWVudC4nXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcbiAgICAgXHJcbiAgICAgIHRyeXtcclxuXHJcbiAgICAgICAgY29uc3QgaW5kaWNhdG9ycyA9IGdldFRlbXBsYXRlSW5kaWNhdG9ycyh0ZW1wbGF0ZSk7XHJcbiAgICAgICAgaWYoIWluZGljYXRvcnMgfHwgaW5kaWNhdG9ycy5sZW5ndGggPT09IDApe1xyXG4gICAgICAgICAgbG9nKCdUZW1wbGF0ZSBpbmRpY2F0b3JzIG5vdCBmb3VuZCcsIExvZ1R5cGUuRVJST1IsICdzYXZlTmV3QXNzZXNzbWVudCcpOyAgXHJcbiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1RlbXBsYXRlIGluZGljYXRvcnMgbm90IGZvdW5kLicpXHJcbiAgICAgICAgfSAgICAgIFxyXG4gIFxyXG4gICAgICAgIGNvbnN0IGxpZmVsaW5lU3RhdHVzRmVhdHVyZXMgPSB0ZW1wbGF0ZS5saWZlbGluZVRlbXBsYXRlcy5tYXAobHQgPT4ge1xyXG4gICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgIGF0dHJpYnV0ZXM6IHsgXHJcbiAgICAgICAgICAgICAgQXNzZXNzbWVudElEIDogcmVzcC5kYXRhLFxyXG4gICAgICAgICAgICAgIFNjb3JlOiBudWxsLCBcclxuICAgICAgICAgICAgICBDb2xvcjogbnVsbCwgXHJcbiAgICAgICAgICAgICAgTGlmZWxpbmVJRDogbHQuaWQsIFxyXG4gICAgICAgICAgICAgIElzT3ZlcnJpZGVuOiAwLCBcclxuICAgICAgICAgICAgICBPdmVycmlkZW5TY29yZTogbnVsbCwgXHJcbiAgICAgICAgICAgICAgT3ZlcnJpZGVuQnk6IG51bGwsIFxyXG4gICAgICAgICAgICAgIE92ZXJyaWRlQ29tbWVudDogbnVsbCwgXHJcbiAgICAgICAgICAgICAgTGlmZWxpbmVOYW1lOiBsdC50aXRsZSwgXHJcbiAgICAgICAgICAgICAgVGVtcGxhdGVOYW1lOiB0ZW1wbGF0ZS5uYW1lXHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgIH1cclxuICAgICAgICB9KVxyXG4gICAgICAgIGxldCByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBsaWZlbGluZVN0YXR1c0ZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgICAgIGlmKHJlc3BvbnNlICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgICAgICAgIGNvbnN0IHF1ZXJ5ID0gJ0dsb2JhbElEIElOICgnKyByZXNwb25zZS5hZGRSZXN1bHRzLm1hcChyID0+IGAnJHtyLmdsb2JhbElkfSdgKS5qb2luKCcsJykrXCIpXCI7XHJcbiAgICAgICAgICAgY29uc3QgbHNGZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIHF1ZXJ5LCBjb25maWcpO1xyXG4gICAgICAgICAgIFxyXG4gICAgICAgICAgIGNvbnN0IGluZGljYXRvckFzc2Vzc21lbnRGZWF0dXJlcyA9IGluZGljYXRvcnMubWFwKGkgPT4ge1xyXG4gICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgY29uc3QgbGlmZWxpbmVTdGF0dXNGZWF0dXJlID0gbHNGZWF0dXJlcy5maW5kKGxzID0+IFxyXG4gICAgICAgICAgICAgICAgbHMuYXR0cmlidXRlcy5MaWZlbGluZU5hbWUuc3BsaXQoL1snICcmXyxdKy8pLmpvaW4oJ18nKSAgPT09IGkubGlmZWxpbmVOYW1lKTtcclxuICAgICAgICAgICAgaWYoIWxpZmVsaW5lU3RhdHVzRmVhdHVyZSl7XHJcbiAgICAgICAgICAgICAgY29uc29sZS5sb2coYCR7aS5saWZlbGluZU5hbWV9IG5vdCBmb3VuZGApO1xyXG4gICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgJHtpLmxpZmVsaW5lTmFtZX0gbm90IGZvdW5kYCk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICAgICAgICBMaWZlbGluZVN0YXR1c0lEIDogbGlmZWxpbmVTdGF0dXNGZWF0dXJlPyBsaWZlbGluZVN0YXR1c0ZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCA6ICcnLFxyXG4gICAgICAgICAgICAgICAgSW5kaWNhdG9ySUQ6IGkuaWQsICBcclxuICAgICAgICAgICAgICAgIFRlbXBsYXRlTmFtZTogaS50ZW1wbGF0ZU5hbWUsICBcclxuICAgICAgICAgICAgICAgIExpZmVsaW5lTmFtZTogaS5saWZlbGluZU5hbWUsICBcclxuICAgICAgICAgICAgICAgIENvbXBvbmVudE5hbWU6IGkuY29tcG9uZW50TmFtZSwgIFxyXG4gICAgICAgICAgICAgICAgSW5kaWNhdG9yTmFtZTogaS5uYW1lLFxyXG4gICAgICAgICAgICAgICAgQ29tbWVudHM6IFwiXCIsXHJcbiAgICAgICAgICAgICAgICBSYW5rOiBpLndlaWdodHMuZmluZCh3ID0+IHcubmFtZSA9PT0gUkFOSyk/LndlaWdodCxcclxuICAgICAgICAgICAgICAgIExpZmVTYWZldHk6IGkud2VpZ2h0cy5maW5kKHcgPT4gdy5uYW1lID09PSBMSUZFX1NBRkVUWSk/LndlaWdodCxcclxuICAgICAgICAgICAgICAgIFByb3BlcnR5UHJvdGVjdGlvbjogaS53ZWlnaHRzLmZpbmQodyA9PiB3Lm5hbWUgPT09IFBST1BFUlRZX1BST1RFQ1RJT04pPy53ZWlnaHQsXHJcbiAgICAgICAgICAgICAgICBJbmNpZGVudFN0YWJpbGl6YXRpb246IGkud2VpZ2h0cy5maW5kKHcgPT4gdy5uYW1lID09PSBJTkNJREVOVF9TVEFCSUxJWkFUSU9OKT8ud2VpZ2h0LFxyXG4gICAgICAgICAgICAgICAgRW52aXJvbm1lbnRQcmVzZXJ2YXRpb246IGkud2VpZ2h0cy5maW5kKHcgPT4gdy5uYW1lID09PSBFTlZJUk9OTUVOVF9QUkVTRVJWQVRJT04pPy53ZWlnaHQsXHJcbiAgICAgICAgICAgICAgICBTdGF0dXM6IDQgLy91bmtub3duXHJcbiAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgfSlcclxuICBcclxuICAgICAgICAgICByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBpbmRpY2F0b3JBc3Nlc3NtZW50RmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICAgICAgICAgaWYocmVzcG9uc2UgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcbiAgICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgICAgZGF0YTogcmVzcC5kYXRhXHJcbiAgICAgICAgICAgIH0gXHJcbiAgICAgICAgICAgfWVsc2V7XHJcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcignRmFpbGVkIHRvIGFkZCBpbmRpY2F0b3IgYXNzZXNzbWVudCBmZWF0dXJlcycpO1xyXG4gICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICAgICAgZWxzZXtcclxuICAgICAgICAgIHRocm93IG5ldyBFcnJvcignRmFpbGVkIHRvIGFkZCBMaWZlbGluZSBTdGF0dXMgRmVhdHVyZXMnKTtcclxuICAgICAgICB9IFxyXG5cclxuICAgICAgfWNhdGNoKGUpe1xyXG4gICAgICAgIGF3YWl0IGNsZWFuVXBBc3Nlc3NtZW50RmFpbGVkRGF0YShyZXNwLmRhdGEsIGNvbmZpZyk7XHJcbiAgICAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdzYXZlTmV3QXNzZXNzbWVudCcpXHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGVycm9yczonRXJyb3Igb2NjdXJyZWQgd2hpbGUgY3JlYXRpbmcgQXNzZXNzbWVudC4nXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcblxyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBjbGVhblVwQXNzZXNzbWVudEZhaWxlZERhdGEoYXNzZXNzbWVudEdsb2JhbElkOiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKXtcclxuICAgXHJcbiAgIGxldCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuYXNzZXNzbWVudHMsIGBHbG9iYWxJRD0nJHthc3Nlc3NtZW50R2xvYmFsSWR9J2AsIGNvbmZpZyk7XHJcbiAgIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgIGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmFzc2Vzc21lbnRzLCBmZWF0dXJlcy5tYXAoZiA9PiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQpLCBjb25maWcpO1xyXG4gICB9XHJcblxyXG4gICBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIGBBc3Nlc3NtZW50SUQ9JyR7YXNzZXNzbWVudEdsb2JhbElkfSdgLCBjb25maWcpO1xyXG4gICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgIGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBmZWF0dXJlcy5tYXAoZiA9PiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQpLCBjb25maWcpO1xyXG5cclxuICAgIGNvbnN0IHF1ZXJ5ID0gYExpZmVsaW5lU3RhdHVzSUQgSU4gKCR7ZmVhdHVyZXMubWFwKGYgPT4gZi5hdHRyaWJ1dGVzLkdsb2JhbElEKS5qb2luKCcsJyl9KWA7XHJcbiAgICBjb25zb2xlLmxvZygnZGVsZXRlIHF1ZXJpZXMnLCBxdWVyeSlcclxuICAgIGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JBc3Nlc3NtZW50cywgcXVlcnksIGNvbmZpZyk7XHJcbiAgICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgICAgYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9yQXNzZXNzbWVudHMsIGZlYXR1cmVzLm1hcChmID0+IGYuYXR0cmlidXRlcy5PQkpFQ1RJRCksIGNvbmZpZyk7XHJcbiAgICB9XHJcbiAgIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldEFzc2Vzc21lbnROYW1lcyhjb25maWc6IEFwcFdpZGdldENvbmZpZywgdGVtcGxhdGVOYW1lOiBzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTx7bmFtZTogc3RyaW5nLCBkYXRlOiBzdHJpbmd9W10+PntcclxuICBcclxuICBjb25zdCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuYXNzZXNzbWVudHMsIGBUZW1wbGF0ZT0nJHt0ZW1wbGF0ZU5hbWV9J2AsIGNvbmZpZyk7XHJcbiAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID09PSAwKXtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IFtdXHJcbiAgICB9XHJcbiAgfVxyXG4gIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICBcclxuICAgICBjb25zdCBhc3Nlc3MgPSAgZmVhdHVyZXMubWFwKGYgPT4ge1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIG5hbWU6IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgIGRhdGU6IHBhcnNlRGF0ZShOdW1iZXIoZi5hdHRyaWJ1dGVzLkNyZWF0ZWREYXRlKSlcclxuICAgICAgfVxyXG4gICAgIH0pO1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgICBkYXRhOiBhc3Nlc3NcclxuICAgICB9XHJcbiAgfVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdSZXF1ZXN0IGZvciBhc3Nlc3NtZW50IG5hbWVzIGZhaWxlZC4nXHJcbiAgfVxyXG5cclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0QXNzZXNzbWVudEZlYXR1cmVzKGNvbmZpZykge1xyXG4gICBjb25zb2xlLmxvZygnZ2V0IEFzc2Vzc21lbnQgRmVhdHVyZXMgY2FsbGVkLicpO1xyXG4gICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5hc3Nlc3NtZW50cywgYDE9MWAsIGNvbmZpZyk7XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBsb2FkQWxsQXNzZXNzbWVudHMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxBc3Nlc3NtZW50W10+PntcclxuXHJcbiAgIHRyeXtcclxuICAgIGNvbnN0IGFzc2Vzc21lbnRGZWF0dXJlcyA9IGF3YWl0IGdldEFzc2Vzc21lbnRGZWF0dXJlcyhjb25maWcpO1xyXG4gICAgaWYoIWFzc2Vzc21lbnRGZWF0dXJlcyB8fCBhc3Nlc3NtZW50RmVhdHVyZXMubGVuZ3RoID09IDApe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IFtdXHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIFxyXG4gICAgY29uc3QgbHNGZWF0dXJlcyA9IGF3YWl0IGdldExpZmVsaW5lU3RhdHVzRmVhdHVyZXMoY29uZmlnLCBgMT0xYCk7XHJcblxyXG4gICAgY29uc3QgcXVlcnkgPSBgTGlmZWxpbmVTdGF0dXNJRCBJTiAoJHtsc0ZlYXR1cmVzLm1hcChmID0+IGAnJHtmLmF0dHJpYnV0ZXMuR2xvYmFsSUR9J2ApLmpvaW4oJywnKX0pYFxyXG4gICAgXHJcbiAgICBjb25zdCBpbmRpY2F0b3JBc3Nlc3NtZW50cyA9IGF3YWl0IGdldEluZGljYXRvckFzc2Vzc21lbnRzKHF1ZXJ5LCBjb25maWcpO1xyXG5cclxuICAgIGlmKGFzc2Vzc21lbnRGZWF0dXJlcyAmJiBhc3Nlc3NtZW50RmVhdHVyZXMubGVuZ3RoID4gMCl7ICAgXHJcbiAgICAgIGNvbnN0IGFzc2Vzc21lbnRzID0gYXNzZXNzbWVudEZlYXR1cmVzLm1hcCgoZmVhdHVyZTogSUZlYXR1cmUpID0+IHtcclxuICAgICAgICBjb25zdCBhc3Nlc3NtZW50THNGZWF0dXJlcyA9IGxzRmVhdHVyZXMuZmlsdGVyKGwgPT5sLmF0dHJpYnV0ZXMuQXNzZXNzbWVudElEID09IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCkgICAgICAgIFxyXG4gICAgICAgIHJldHVybiBsb2FkQXNzZXNzbWVudChmZWF0dXJlLCBhc3Nlc3NtZW50THNGZWF0dXJlcywgaW5kaWNhdG9yQXNzZXNzbWVudHMpO1xyXG4gICAgICB9KTtcclxuXHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogYXNzZXNzbWVudHNcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGlmKGFzc2Vzc21lbnRGZWF0dXJlcyAmJiBhc3Nlc3NtZW50RmVhdHVyZXMubGVuZ3RoID09IDApe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IFtdXHJcbiAgICAgIH0gIFxyXG4gICAgfVxyXG4gICB9Y2F0Y2goZSl7XHJcbiAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ2xvYWRBbGxBc3Nlc3NtZW50cycpO1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiBlXHJcbiAgICB9XHJcbiAgIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNyZWF0ZUluY2lkZW50KGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBpbmNpZGVudDogSW5jaWRlbnQpOiBQcm9taXNlPENsc3NSZXNwb25zZTx2b2lkPj57XHJcbiAgIFxyXG4gICAgdHJ5e1xyXG4gICAgICBjaGVja1BhcmFtKGNvbmZpZy5pbmNpZGVudHMsIElOQ0lERU5UX1VSTF9FUlJPUik7XHJcbiAgICAgIGNoZWNrUGFyYW0oaW5jaWRlbnQsICdJbmNpZGVudCBkYXRhIG5vdCBwcm92aWRlZCcpO1xyXG5cclxuICAgICAgY29uc3QgZmVhdHVyZXMgPSBbe1xyXG4gICAgICAgIGF0dHJpYnV0ZXMgOiB7XHJcbiAgICAgICAgICBIYXphcmRJRDogaW5jaWRlbnQuaGF6YXJkLmlkLFxyXG4gICAgICAgICAgTmFtZSA6IGluY2lkZW50Lm5hbWUsXHJcbiAgICAgICAgICBEZXNjcmlwdGlvbjogaW5jaWRlbnQuZGVzY3JpcHRpb24sXHJcbiAgICAgICAgICBTdGFydERhdGUgOiBTdHJpbmcoaW5jaWRlbnQuc3RhcnREYXRlKSxcclxuICAgICAgICAgIEVuZERhdGUgOiBTdHJpbmcoaW5jaWRlbnQuZW5kRGF0ZSlcclxuICAgICAgICB9XHJcbiAgICAgIH1dXHJcblxyXG4gICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmluY2lkZW50cywgZmVhdHVyZXMsIGNvbmZpZyk7XHJcblxyXG4gICAgICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMubGVuZ3RoID4gMCl7XHJcbiAgICAgICAgcmV0dXJue30gXHJcbiAgICAgIH1cclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBlcnJvcnM6ICdJbmNpZGVudCBjb3VsZCBub3QgYmUgc2F2ZWQuJ1xyXG4gICAgICB9XHJcbiAgICB9Y2F0Y2goZSkge1xyXG4gICAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ2NyZWF0ZUluY2lkZW50Jyk7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZXJyb3JzOiAnSW5jaWRlbnQgY291bGQgbm90IGJlIHNhdmVkLidcclxuICAgICAgfVxyXG4gICAgfVxyXG59XHJcblxyXG4vLz09PT09PT09PT09PT09PT09PT09UFJJVkFURT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XHJcblxyXG5jb25zdCByZXF1ZXN0RGF0YSA9IGFzeW5jICh1cmw6IHN0cmluZywgY29udHJvbGxlcj86IGFueSk6IFByb21pc2U8SUZlYXR1cmVTZXQ+ID0+IHtcclxuICBpZiAoIWNvbnRyb2xsZXIpIHtcclxuICAgIGNvbnRyb2xsZXIgPSBuZXcgQWJvcnRDb250cm9sbGVyKCk7XHJcbiAgfVxyXG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2godXJsLCB7XHJcbiAgICBtZXRob2Q6IFwiR0VUXCIsXHJcbiAgICBoZWFkZXJzOiB7XHJcbiAgICAgICdjb250ZW50LXR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xyXG4gICAgfSxcclxuICAgIHNpZ25hbDogY29udHJvbGxlci5zaWduYWxcclxuICB9XHJcbiAgKTtcclxuICByZXR1cm4gcmVzcG9uc2UuanNvbigpO1xyXG59XHJcblxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0VGVtcGxhdGUoXHJcbiAgdGVtcGxhdGVGZWF0dXJlOiBJRmVhdHVyZSwgXHJcbiAgbGlmZWxpbmVGZWF0dXJlczogSUZlYXR1cmVbXSwgXHJcbiAgY29tcG9uZW50RmVhdHVyZXM6IElGZWF0dXJlW10sIFxyXG4gIGluZGljYXRvcnNGZWF0dXJlczogSUZlYXR1cmVbXSwgXHJcbiAgd2VpZ2h0c0ZlYXR1cmVzOiBJRmVhdHVyZVtdLCBcclxuICB0ZW1wbGF0ZURvbWFpbnM6IElDb2RlZFZhbHVlW10pOiBQcm9taXNlPENMU1NUZW1wbGF0ZT57XHJcblxyXG4gIGNvbnN0IGluZGljYXRvckZlYXR1cmVzID0gaW5kaWNhdG9yc0ZlYXR1cmVzLmZpbHRlcihpID0+IGkuYXR0cmlidXRlcy5UZW1wbGF0ZUlEID0gYCcke3RlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEfSdgKS8vICBhd2FpdCBnZXRJbmRpY2F0b3JGZWF0dXJlcyhgVGVtcGxhdGVJRD0nJHt0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRH0nYCwgY29uZmlnKTtcclxuICBcclxuICAvL2NvbnN0IHF1ZXJ5ID0gaW5kaWNhdG9yRmVhdHVyZXMubWFwKGkgPT4gYEluZGljYXRvcklEPScke2kuYXR0cmlidXRlcy5HbG9iYWxJRC50b1VwcGVyQ2FzZSgpfSdgKS5qb2luKCcgT1IgJylcclxuICBcclxuICBjb25zdCBpbmRpY2F0b3JJZHMgPSBpbmRpY2F0b3JGZWF0dXJlcy5tYXAoaSA9PiBpLmF0dHJpYnV0ZXMuR2xvYmFsSUQpO1xyXG4gIGNvbnN0IHdlaWdodEZlYXR1cmVzID0gd2VpZ2h0c0ZlYXR1cmVzLmZpbHRlcih3ID0+IGluZGljYXRvcklkcy5pbmRleE9mKHcuYXR0cmlidXRlcy5JbmRpY2F0b3JJRCkpIC8vYXdhaXQgZ2V0V2VpZ2h0c0ZlYXR1cmVzKHF1ZXJ5LCBjb25maWcpO1xyXG4gIFxyXG4gIGNvbnN0IGluZGljYXRvclRlbXBsYXRlcyA9IGluZGljYXRvckZlYXR1cmVzLm1hcCgoZmVhdHVyZTogSUZlYXR1cmUpID0+IHtcclxuXHJcbiAgICAgY29uc3Qgd2VpZ2h0cyA9IHdlaWdodHNGZWF0dXJlc1xyXG4gICAgICAuZmlsdGVyKHcgPT4gdy5hdHRyaWJ1dGVzLkluZGljYXRvcklEPT09ZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEKVxyXG4gICAgICAubWFwKHcgPT4ge1xyXG4gICAgICAgcmV0dXJuIHsgXHJcbiAgICAgICAgb2JqZWN0SWQ6IHcuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgICBuYW1lOiB3LmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICB3ZWlnaHQ6IHcuYXR0cmlidXRlcy5XZWlnaHQsXHJcbiAgICAgICAgc2NhbGVGYWN0b3IgOiB3LmF0dHJpYnV0ZXMuU2NhbGVGYWN0b3IsIFxyXG4gICAgICAgIGFkanVzdGVkV2VpZ2h0OiB3LmF0dHJpYnV0ZXMuQWRqdXN0ZWRXZWlnaHQsXHJcbiAgICAgICAgbWF4QWRqdXN0ZWRXZWlnaHQ6IHcuYXR0cmlidXRlcy5NYXhBZGp1c3RlZFdlaWdodFxyXG4gICAgICAgfSBhcyBJbmRpY2F0b3JXZWlnaHRcclxuICAgICB9KVxyXG5cclxuICAgICByZXR1cm4ge1xyXG4gICAgICBvYmplY3RJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICBpZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELCBcclxuICAgICAgbmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgIHRlbXBsYXRlTmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLlRlbXBsYXRlTmFtZSxcclxuICAgICAgd2VpZ2h0cyxcclxuICAgICAgY29tcG9uZW50SWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5Db21wb25lbnRJRCxcclxuICAgICAgdGVtcGxhdGVJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLlRlbXBsYXRlSUQsICBcclxuICAgICAgY29tcG9uZW50TmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkNvbXBvbmVudE5hbWUsXHJcbiAgICAgIGxpZmVsaW5lTmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVsaW5lTmFtZVxyXG4gICAgIH0gYXMgSW5kaWNhdG9yVGVtcGxhdGVcclxuICB9KTtcclxuXHJcbiAgY29uc3QgY29tcG9uZW50VGVtcGxhdGVzID0gY29tcG9uZW50RmVhdHVyZXMubWFwKChmZWF0dXJlOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgICAgaWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgICB0aXRsZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkRpc3BsYXlOYW1lIHx8IGZlYXR1cmUuYXR0cmlidXRlcy5EaXNwbGF5VGl0bGUsXHJcbiAgICAgICAgbmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgbGlmZWxpbmVJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVsaW5lSUQsXHJcbiAgICAgICAgaW5kaWNhdG9yczogKGluZGljYXRvclRlbXBsYXRlcy5maWx0ZXIoaSA9PiBpLmNvbXBvbmVudElkID09PSBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQpIGFzIGFueSkub3JkZXJCeSgnbmFtZScpXHJcbiAgICAgfVxyXG4gIH0pO1xyXG5cclxuICBjb25zdCBsaWZlbGluZVRlbXBsYXRlcyA9IGxpZmVsaW5lRmVhdHVyZXMubWFwKChmZWF0dXJlOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgaWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgdGl0bGU6IGZlYXR1cmUuYXR0cmlidXRlcy5EaXNwbGF5TmFtZSB8fCBmZWF0dXJlLmF0dHJpYnV0ZXMuRGlzcGxheVRpdGxlLFxyXG4gICAgICBuYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTmFtZSwgICAgICBcclxuICAgICAgY29tcG9uZW50VGVtcGxhdGVzOiAoY29tcG9uZW50VGVtcGxhdGVzLmZpbHRlcihjID0+IGMubGlmZWxpbmVJZCA9PT0gZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEKSBhcyBhbnkpLm9yZGVyQnkoJ3RpdGxlJylcclxuICAgIH0gYXMgTGlmZUxpbmVUZW1wbGF0ZTtcclxuICB9KTtcclxuXHJcbiAgY29uc3QgdGVtcGxhdGUgPSB7XHJcbiAgICAgIG9iamVjdElkOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgaWQ6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICBpc1NlbGVjdGVkOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5Jc1NlbGVjdGVkID09IDEsXHJcbiAgICAgIHN0YXR1czoge1xyXG4gICAgICAgIGNvZGU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLlN0YXR1cyxcclxuICAgICAgICBuYW1lOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5TdGF0dXMgPT09IDEgPyBcIkFjdGl2ZVwiOiAnQXJjaGl2ZWQnXHJcbiAgICAgIH0gYXMgSUNvZGVkVmFsdWUsXHJcbiAgICAgIG5hbWU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgIGhhemFyZE5hbWU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkhhemFyZE5hbWUsXHJcbiAgICAgIGhhemFyZFR5cGU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkhhemFyZFR5cGUsXHJcbiAgICAgIG9yZ2FuaXphdGlvbk5hbWU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLk9yZ2FuaXphdGlvbk5hbWUsXHJcbiAgICAgIG9yZ2FuaXphdGlvblR5cGU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLk9yZ2FuaXphdGlvblR5cGUsIFxyXG4gICAgICBjcmVhdG9yOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5DcmVhdG9yLFxyXG4gICAgICBjcmVhdGVkRGF0ZTogTnVtYmVyKHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkNyZWF0ZWREYXRlKSxcclxuICAgICAgZWRpdG9yOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5FZGl0b3IsXHJcbiAgICAgIGVkaXRlZERhdGU6IE51bWJlcih0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5FZGl0ZWREYXRlKSxcclxuICAgICAgbGlmZWxpbmVUZW1wbGF0ZXM6ICAobGlmZWxpbmVUZW1wbGF0ZXMgYXMgYW55KS5vcmRlckJ5KCd0aXRsZScpLFxyXG4gICAgICBkb21haW5zOiB0ZW1wbGF0ZURvbWFpbnNcclxuICB9IGFzIENMU1NUZW1wbGF0ZTtcclxuXHJcbiAgcmV0dXJuIHRlbXBsYXRlO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBzYXZlQXNzZXNzbWVudChhc3Nlc3NtZW50OiBBc3Nlc3NtZW50LCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPHN0cmluZz4+e1xyXG5cclxuICB0cnl7XHJcbiAgICBjb25zdCBmZWF0dXJlID0ge1xyXG4gICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgTmFtZSA6YXNzZXNzbWVudC5uYW1lLFxyXG4gICAgICAgIERlc2NyaXB0aW9uOiBhc3Nlc3NtZW50LmRlc2NyaXB0aW9uLFxyXG4gICAgICAgIEFzc2Vzc21lbnRUeXBlOiBhc3Nlc3NtZW50LmFzc2Vzc21lbnRUeXBlLCBcclxuICAgICAgICBPcmdhbml6YXRpb246IGFzc2Vzc21lbnQub3JnYW5pemF0aW9uLCBcclxuICAgICAgICBJbmNpZGVudDogYXNzZXNzbWVudC5pbmNpZGVudCwgXHJcbiAgICAgICAgSGF6YXJkOiBhc3Nlc3NtZW50LmhhemFyZCwgXHJcbiAgICAgICAgQ3JlYXRvcjogYXNzZXNzbWVudC5jcmVhdG9yLCBcclxuICAgICAgICBDcmVhdGVkRGF0ZTogYXNzZXNzbWVudC5jcmVhdGVkRGF0ZSwgXHJcbiAgICAgICAgRWRpdG9yOiBhc3Nlc3NtZW50LmVkaXRvciwgXHJcbiAgICAgICAgRWRpdGVkRGF0ZTogYXNzZXNzbWVudC5lZGl0ZWREYXRlLCBcclxuICAgICAgICBJc0NvbXBsZXRlZDogYXNzZXNzbWVudC5pc0NvbXBsZXRlZCwgXHJcbiAgICAgICAgSGF6YXJkVHlwZTogYXNzZXNzbWVudC5oYXphcmRUeXBlLFxyXG4gICAgICAgIE9yZ2FuaXphdGlvblR5cGU6YXNzZXNzbWVudC5vcmdhbml6YXRpb25UeXBlLFxyXG4gICAgICAgIFRlbXBsYXRlOiBhc3Nlc3NtZW50LnRlbXBsYXRlXHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuYXNzZXNzbWVudHMsW2ZlYXR1cmVdLCBjb25maWcpO1xyXG4gICAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcbiAgICAgIHJldHVybnsgZGF0YTogcmVzcG9uc2UuYWRkUmVzdWx0c1swXS5nbG9iYWxJZH1cclxuICAgIH1cclxuICAgIHJldHVybiB7XHJcbiAgICAgIGVycm9yczogIEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKSAgICBcclxuICAgIH1cclxuXHJcbiAgfWNhdGNoKGUpe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiBlXHJcbiAgICB9XHJcbiAgfVxyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRJbmRpY2F0b3JBc3Nlc3NtZW50cyhxdWVyeTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SW5kaWNhdG9yQXNzZXNzbWVudFtdPntcclxuICBjb25zb2xlLmxvZygnZ2V0IEluZGljYXRvciBBc3Nlc3NtZW50cyBjYWxsZWQuJylcclxuXHJcbiAgY29uc3QgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBxdWVyeSwgY29uZmlnKTtcclxuICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgICByZXR1cm4gZmVhdHVyZXMubWFwKGZlYXR1cmUgPT4geyAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIG9iamVjdElkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgICAgICBpZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICAgICAgaW5kaWNhdG9ySWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5JbmRpY2F0b3JJRCxcclxuICAgICAgICAgIGluZGljYXRvcjogZmVhdHVyZS5hdHRyaWJ1dGVzLkluZGljYXRvck5hbWUsXHJcbiAgICAgICAgICB0ZW1wbGF0ZTogZmVhdHVyZS5hdHRyaWJ1dGVzLlRlbXBsYXRlTmFtZSxcclxuICAgICAgICAgIGxpZmVsaW5lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZWxpbmVOYW1lLFxyXG4gICAgICAgICAgY29tcG9uZW50OiBmZWF0dXJlLmF0dHJpYnV0ZXMuQ29tcG9uZW50TmFtZSwgICAgICAgICAgXHJcbiAgICAgICAgICBjb21tZW50czogcGFyc2VDb21tZW50KGZlYXR1cmUuYXR0cmlidXRlcy5Db21tZW50cyksICAgICAgICAgIFxyXG4gICAgICAgICAgbGlmZWxpbmVTdGF0dXNJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVsaW5lU3RhdHVzSUQsXHJcbiAgICAgICAgICBlbnZpcm9ubWVudFByZXNlcnZhdGlvbjogZmVhdHVyZS5hdHRyaWJ1dGVzLkVudmlyb25tZW50UHJlc2VydmF0aW9uLFxyXG4gICAgICAgICAgaW5jaWRlbnRTdGFiaWxpemF0aW9uOiBmZWF0dXJlLmF0dHJpYnV0ZXMuSW5jaWRlbnRTdGFiaWxpemF0aW9uLFxyXG4gICAgICAgICAgcmFuazogZmVhdHVyZS5hdHRyaWJ1dGVzLlJhbmssXHJcbiAgICAgICAgICBsaWZlU2FmZXR5OiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZVNhZmV0eSxcclxuICAgICAgICAgIHByb3BlcnR5UHJvdGVjdGlvbjogZmVhdHVyZS5hdHRyaWJ1dGVzLlByb3BlcnR5UHJvdGVjdGlvbixcclxuICAgICAgICAgIHN0YXR1czogZmVhdHVyZS5hdHRyaWJ1dGVzLlN0YXR1c1xyXG4gICAgICAgIH0gYXMgSW5kaWNhdG9yQXNzZXNzbWVudDtcclxuICAgICB9KVxyXG4gIH1cclxuXHJcbn1cclxuXHJcbmZ1bmN0aW9uIHBhcnNlQ29tbWVudChjb21tZW50czogc3RyaW5nKXtcclxuICBpZighY29tbWVudHMgfHwgY29tbWVudHMgPT09IFwiXCIpe1xyXG4gICAgcmV0dXJuIFtdO1xyXG4gIH1cclxuICBsZXQgcGFyc2VkQ29tbWVudHMgPSBKU09OLnBhcnNlKGNvbW1lbnRzKSBhcyBJbkNvbW1lbnRbXTtcclxuICBcclxuICBpZihwYXJzZWRDb21tZW50cyAmJiBwYXJzZWRDb21tZW50cy5sZW5ndGggPiAwKXtcclxuICAgIHBhcnNlZENvbW1lbnRzLm1hcCgoY29tbWVudERhdGE6IEluQ29tbWVudCkgPT4ge1xyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgIC4uLmNvbW1lbnREYXRhLFxyXG4gICAgICAgICAgICBkYXRldGltZTogTnVtYmVyKGNvbW1lbnREYXRhLmRhdGV0aW1lKVxyXG4gICAgICAgIH0gYXMgSW5Db21tZW50XHJcbiAgICB9KTtcclxuICAgIHBhcnNlZENvbW1lbnRzID0gKHBhcnNlZENvbW1lbnRzIGFzIGFueSkub3JkZXJCeSgnZGF0ZXRpbWUnLCB0cnVlKTtcclxuICB9ZWxzZXtcclxuICAgIHBhcnNlZENvbW1lbnRzID0gW107XHJcbiAgfVxyXG4gIFxyXG4gIHJldHVybiBwYXJzZWRDb21tZW50cztcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0TGlmZWxpbmVTdGF0dXNGZWF0dXJlcyhjb25maWcsIHF1ZXJ5KSB7XHJcbiAgY29uc29sZS5sb2coJ2dldCBMaWZlbGluZSBTdGF0dXMgY2FsbGVkJylcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZVN0YXR1cywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGxvYWRBc3Nlc3NtZW50KGFzc2Vzc21lbnRGZWF0dXJlOiBJRmVhdHVyZSwgbHNGZWF0dXJlczogSUZlYXR1cmVbXSwgXHJcbiAgaW5kaWNhdG9yQXNzZXNzbWVudHM6IEluZGljYXRvckFzc2Vzc21lbnRbXSk6IEFzc2Vzc21lbnR7ICAgXHJcblxyXG4gIGNvbnN0IGxpZmVsaW5lU3RhdHVzZXMgPSBsc0ZlYXR1cmVzLm1hcCgoZmVhdHVyZSkgPT4geyBcclxuICAgIHJldHVybiB7XHJcbiAgICAgIG9iamVjdElkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgIGlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgIGFzc2Vzc21lbnRJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkFzc2Vzc21lbnRJRCxcclxuICAgICAgbGlmZWxpbmVOYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZWxpbmVOYW1lLFxyXG4gICAgICBpbmRpY2F0b3JBc3Nlc3NtZW50czogaW5kaWNhdG9yQXNzZXNzbWVudHMuZmlsdGVyKGkgPT4gaS5saWZlbGluZVN0YXR1c0lkID09PSBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQpLCAgICAgIFxyXG4gICAgICBzY29yZTogZmVhdHVyZS5hdHRyaWJ1dGVzLlNjb3JlLFxyXG4gICAgICBjb2xvcjogZmVhdHVyZS5hdHRyaWJ1dGVzLkNvbG9yLFxyXG4gICAgICBpc092ZXJyaWRlbjogZmVhdHVyZS5hdHRyaWJ1dGVzLklzT3ZlcnJpZGVuLFxyXG4gICAgICBvdmVycmlkZVNjb3JlOmZlYXR1cmUuYXR0cmlidXRlcy5PdmVycmlkZW5TY29yZSxcclxuICAgICAgb3ZlcnJpZGVuQnk6IGZlYXR1cmUuYXR0cmlidXRlcy5PdmVycmlkZW5CeSxcclxuICAgICAgb3ZlcnJpZGVuQ29sb3I6IGZlYXR1cmUuYXR0cmlidXRlcy5PdmVycmlkZW5Db2xvciwgICAgIFxyXG4gICAgICBvdmVycmlkZUNvbW1lbnQ6IGZlYXR1cmUuYXR0cmlidXRlcy5PdmVycmlkZUNvbW1lbnQgICAgICBcclxuICAgIH0gYXMgTGlmZWxpbmVTdGF0dXM7XHJcbiAgfSk7XHJcblxyXG4gIGNvbnN0IGFzc2Vzc21lbnQgPSB7XHJcbiAgICBvYmplY3RJZDogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgIGlkOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgbmFtZTogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgYXNzZXNzbWVudFR5cGU6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuQXNzZXNzbWVudFR5cGUsXHJcbiAgICBsaWZlbGluZVN0YXR1c2VzOiBsaWZlbGluZVN0YXR1c2VzLFxyXG4gICAgZGVzY3JpcHRpb246IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuRGVzY3JpcHRpb24sXHJcbiAgICB0ZW1wbGF0ZTogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5UZW1wbGF0ZSxcclxuICAgIG9yZ2FuaXphdGlvbjogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5Pcmdhbml6YXRpb24sXHJcbiAgICBvcmdhbml6YXRpb25UeXBlOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLk9yZ2FuaXphdGlvblR5cGUsXHJcbiAgICBpbmNpZGVudDogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5JbmNpZGVudCxcclxuICAgIGhhemFyZDogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5IYXphcmQsXHJcbiAgICBoYXphcmRUeXBlOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkhhemFyZFR5cGUsXHJcbiAgICBjcmVhdG9yOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkNyZWF0b3IsXHJcbiAgICBjcmVhdGVkRGF0ZTogTnVtYmVyKGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuQ3JlYXRlZERhdGUpLFxyXG4gICAgZWRpdG9yOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkVkaXRvcixcclxuICAgIGVkaXRlZERhdGU6IE51bWJlcihhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkVkaXRlZERhdGUpLFxyXG4gICAgaXNTZWxlY3RlZDogZmFsc2UsXHJcbiAgICBpc0NvbXBsZXRlZDogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5Jc0NvbXBsZXRlZCxcclxuICB9IGFzIEFzc2Vzc21lbnRcclxuXHJcbiAgcmV0dXJuIGFzc2Vzc21lbnQ7ICBcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gc2F2ZUxpZmVsaW5lU3RhdHVzKGxpZmVsaW5lU3RhdHVzRmVhdHVyZTogSUZlYXR1cmUsIGxzSW5kQXNzZXNzRmVhdHVyZXM6IElGZWF0dXJlW10sIGNvbmZpZyk6IFByb21pc2U8Ym9vbGVhbj57XHJcbiAgbGV0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIFtsaWZlbGluZVN0YXR1c0ZlYXR1cmVdLCBjb25maWcpXHJcbiAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KGUgPT4gZS5zdWNjZXNzKSl7XHJcbiAgICAgY29uc3QgZ2xvYmFsSWQgPSByZXNwb25zZS5hZGRSZXN1bHRzWzBdLmdsb2JhbElkO1xyXG5cclxuICAgICBjb25zdCBpbmRpY2F0b3JBc3Nlc3NtZW50RmVhdHVyZXMgPSBsc0luZEFzc2Vzc0ZlYXR1cmVzLm1hcChpbmQgPT4ge1xyXG4gICAgICAgIGluZC5hdHRyaWJ1dGVzLkxpZmVsaW5lU3RhdHVzSUQgPSBnbG9iYWxJZFxyXG4gICAgICAgIHJldHVybiBpbmQ7XHJcbiAgICAgfSlcclxuICAgICByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBpbmRpY2F0b3JBc3Nlc3NtZW50RmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KGUgPT4gZS5zdWNjZXNzKSl7XHJcbiAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICB9XHJcbiAgfVxyXG59XHJcblxyXG5mdW5jdGlvbiBnZXRUZW1wbGF0ZUluZGljYXRvcnModGVtcGxhdGU6IENMU1NUZW1wbGF0ZSk6IEluZGljYXRvclRlbXBsYXRlW10ge1xyXG4gIHJldHVybiBbXS5jb25jYXQuYXBwbHkoW10sIChbXS5jb25jYXQuYXBwbHkoW10sIFxyXG4gICB0ZW1wbGF0ZS5saWZlbGluZVRlbXBsYXRlcy5tYXAobCA9PiBsLmNvbXBvbmVudFRlbXBsYXRlcykpKVxyXG4gICAubWFwKChjOiBDb21wb25lbnRUZW1wbGF0ZSkgPT4gYy5pbmRpY2F0b3JzKSk7XHJcbn0iLCIvL0FkYXB0ZWQgZnJvbSAvL2h0dHBzOi8vZ2l0aHViLmNvbS9vZG9lL21hcC12dWUvYmxvYi9tYXN0ZXIvc3JjL2RhdGEvYXV0aC50c1xyXG5cclxuaW1wb3J0IHsgbG9hZEFyY0dJU0pTQVBJTW9kdWxlcyB9IGZyb20gXCJqaW11LWFyY2dpc1wiO1xyXG5cclxuLyoqXHJcbiAqIEF0dGVtcHQgdG8gc2lnbiBpbixcclxuICogZmlyc3QgY2hlY2sgY3VycmVudCBzdGF0dXNcclxuICogaWYgbm90IHNpZ25lZCBpbiwgdGhlbiBnbyB0aHJvdWdoXHJcbiAqIHN0ZXBzIHRvIGdldCBjcmVkZW50aWFsc1xyXG4gKi9cclxuZXhwb3J0IGNvbnN0IHNpZ25JbiA9IGFzeW5jIChhcHBJZDogc3RyaW5nLCBwb3J0YWxVcmw6IHN0cmluZykgPT4ge1xyXG4gICAgdHJ5IHtcclxuICAgICAgICByZXR1cm4gYXdhaXQgY2hlY2tDdXJyZW50U3RhdHVzKGFwcElkLCBwb3J0YWxVcmwpO1xyXG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcclxuICAgICAgICBjb25zb2xlLmxvZyhlcnJvcik7XHJcbiAgICAgICAgcmV0dXJuIGF3YWl0IGZldGNoQ3JlZGVudGlhbHMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICB9XHJcbn07XHJcblxyXG4vKipcclxuICogU2lnbiB0aGUgdXNlciBvdXQsIGJ1dCBpZiB3ZSBjaGVja2VkIGNyZWRlbnRpYWxzXHJcbiAqIG1hbnVhbGx5LCBtYWtlIHN1cmUgdGhleSBhcmUgcmVnaXN0ZXJlZCB3aXRoXHJcbiAqIElkZW50aXR5TWFuYWdlciwgc28gaXQgY2FuIGRlc3Ryb3kgdGhlbSBwcm9wZXJseVxyXG4gKi9cclxuZXhwb3J0IGNvbnN0IHNpZ25PdXQgPSBhc3luYyAoYXBwSWQ6IHN0cmluZywgcG9ydGFsVXJsOiBzdHJpbmcpID0+IHtcclxuICAgIGNvbnN0IElkZW50aXR5TWFuYWdlciA9IGF3YWl0IGxvYWRNb2R1bGVzKGFwcElkLCBwb3J0YWxVcmwpO1xyXG4gICAgYXdhaXQgc2lnbkluKGFwcElkLCBwb3J0YWxVcmwpO1xyXG5cclxuICAgIGRlbGV0ZSB3aW5kb3dbJ0lkZW50aXR5TWFuYWdlciddO1xyXG4gICAgZGVsZXRlIHdpbmRvd1snT0F1dGhJbmZvJ107XHJcbiAgICBJZGVudGl0eU1hbmFnZXIuZGVzdHJveUNyZWRlbnRpYWxzKCk7XHJcbiAgICBcclxufTtcclxuXHJcbi8qKlxyXG4gKiBHZXQgdGhlIGNyZWRlbnRpYWxzIGZvciB0aGUgcHJvdmlkZWQgcG9ydGFsXHJcbiAqL1xyXG5hc3luYyBmdW5jdGlvbiBmZXRjaENyZWRlbnRpYWxzKGFwcElkOiBzdHJpbmcsIHBvcnRhbFVybDogc3RyaW5nKXtcclxuICAgIGNvbnN0IElkZW50aXR5TWFuYWdlciA9IGF3YWl0IGxvYWRNb2R1bGVzKGFwcElkLCBwb3J0YWxVcmwpO1xyXG4gICAgY29uc3QgY3JlZGVudGlhbCA9IGF3YWl0IElkZW50aXR5TWFuYWdlci5nZXRDcmVkZW50aWFsKGAke3BvcnRhbFVybH0vc2hhcmluZ2AsIHtcclxuICAgICAgICBlcnJvcjogbnVsbCBhcyBhbnksXHJcbiAgICAgICAgb0F1dGhQb3B1cENvbmZpcm1hdGlvbjogZmFsc2UsXHJcbiAgICAgICAgdG9rZW46IG51bGwgYXMgYW55XHJcbiAgICB9KTtcclxuICAgIHJldHVybiBjcmVkZW50aWFsO1xyXG59O1xyXG5cclxuLyoqXHJcbiAqIEltcG9ydCBJZGVudGl0eSBNYW5hZ2VyLCBhbmQgT0F1dGhJbmZvXHJcbiAqL1xyXG5hc3luYyBmdW5jdGlvbiBsb2FkTW9kdWxlcyhhcHBJZDogc3RyaW5nLCBwb3J0YWxVcmw6IHN0cmluZykge1xyXG4gICAgbGV0IElkZW50aXR5TWFuYWdlciA9IHdpbmRvd1snSWRlbnRpdHlNYW5hZ2VyJ11cclxuICAgIGlmKCFJZGVudGl0eU1hbmFnZXIpe1xyXG4gICAgICAgIGNvbnN0IG1vZHVsZXMgPSBhd2FpdCBsb2FkQXJjR0lTSlNBUElNb2R1bGVzKFtcclxuICAgICAgICAgICAgJ2VzcmkvaWRlbnRpdHkvSWRlbnRpdHlNYW5hZ2VyJyxcclxuICAgICAgICAgICAgJ2VzcmkvaWRlbnRpdHkvT0F1dGhJbmZvJ10pO1xyXG5cclxuICAgICAgICAgICAgd2luZG93WydJZGVudGl0eU1hbmFnZXInXSA9IG1vZHVsZXNbMF07XHJcbiAgICAgICAgICAgIHdpbmRvd1snT0F1dGhJbmZvJ10gPSBtb2R1bGVzWzFdO1xyXG4gICAgICAgICAgICBcclxuICAgICAgICBJZGVudGl0eU1hbmFnZXIgPSBtb2R1bGVzWzBdO1xyXG4gICAgICAgIGNvbnN0IE9BdXRoSW5mbyA9IG1vZHVsZXNbMV07XHJcblxyXG4gICAgICAgIGNvbnN0IG9hdXRoSW5mbyA9IG5ldyBPQXV0aEluZm8oe1xyXG4gICAgICAgICAgICBhcHBJZCxcclxuICAgICAgICAgICAgcG9ydGFsVXJsLFxyXG4gICAgICAgICAgICBwb3B1cDogZmFsc2VcclxuICAgICAgICB9KTtcclxuICAgICAgICBJZGVudGl0eU1hbmFnZXIucmVnaXN0ZXJPQXV0aEluZm9zKFtvYXV0aEluZm9dKTsgICAgICAgIFxyXG4gICAgfVxyXG4gICAgcmV0dXJuIElkZW50aXR5TWFuYWdlcjtcclxufVxyXG5cclxuLyoqXHJcbiAqIENoZWNrIGN1cnJlbnQgbG9nZ2VkIGluIHN0YXR1cyBmb3IgY3VycmVudCBwb3J0YWxcclxuICovXHJcbmV4cG9ydCBjb25zdCBjaGVja0N1cnJlbnRTdGF0dXMgPSBhc3luYyAoYXBwSWQ6IHN0cmluZywgcG9ydGFsVXJsOiBzdHJpbmcpID0+IHtcclxuICAgIGNvbnN0IElkZW50aXR5TWFuYWdlciA9IGF3YWl0IGxvYWRNb2R1bGVzKGFwcElkLCBwb3J0YWxVcmwpO1xyXG4gICAgcmV0dXJuIElkZW50aXR5TWFuYWdlci5jaGVja1NpZ25JblN0YXR1cyhgJHtwb3J0YWxVcmx9L3NoYXJpbmdgKTtcclxufTsiLCJpbXBvcnQgeyBleHRlbnNpb25TcGVjLCBJbW11dGFibGVPYmplY3QsIElNU3RhdGUgfSBmcm9tICdqaW11LWNvcmUnO1xyXG5pbXBvcnQgeyBBc3Nlc3NtZW50LCBDTFNTX1N0YXRlLCBcclxuICBDTFNTVGVtcGxhdGUsIENsc3NVc2VyLCBIYXphcmQsIFxyXG4gIExpZmVsaW5lU3RhdHVzLCBPcmdhbml6YXRpb24sIFxyXG4gIFJhdGluZ1NjYWxlLCBTY2FsZUZhY3RvciB9IGZyb20gJy4vZGF0YS1kZWZpbml0aW9ucyc7XHJcbmltcG9ydCB7IElDb2RlZFZhbHVlIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtdHlwZXMnO1xyXG5pbXBvcnQgeyBJQ3JlZGVudGlhbCB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgnO1xyXG5cclxuXHJcbmV4cG9ydCBlbnVtIENMU1NBY3Rpb25LZXlzIHtcclxuICBBVVRIRU5USUNBVEVfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBhdXRoZW5pY2F0ZSBjcmVkZW50aWFscycsXHJcbiAgTE9BRF9IQVpBUkRTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCBoYXphcmRzJyxcclxuICBMT0FEX0hBWkFSRF9UWVBFU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGxvYWQgaGF6YXJkIHR5cGVzJyxcclxuICBMT0FEX09SR0FOSVpBVElPTlNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBsb2FkIG9yZ2FuaXphdGlvbnMnLFxyXG4gIExPQURfT1JHQU5JWkFUSU9OX1RZUEVTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCBvcmdhbml6YXRpb24gdHlwZXMnLFxyXG4gIExPQURfVEVNUExBVEVTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCB0ZW1wbGF0ZXMnLFxyXG4gIExPQURfUFJJT1JJVElFU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGxvYWQgcHJpb3JpdGllcycsXHJcbiAgU0VMRUNUX1RFTVBMQVRFX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gc2VsZWN0IHRlbXBsYXRlJyxcclxuICBTRUFSQ0hfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBzZWFyY2ggZm9yIHRlbXBsYXRlJyxcclxuICBTSUdOX0lOX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2lnbiBpbicsXHJcbiAgU0lHTl9PVVRfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTaWduIG91dCcsXHJcbiAgU0VUX1VTRVJfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTZXQgQ0xTUyBVc2VyJyxcclxuICBTRVRfSURFTlRJVFlfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTZXQgSWRlbnRpdHknLFxyXG4gIFNFVF9FUlJPUlMgPSAnW0NMU1MtQVBQTElDQVRJT05dIFNldCBnbG9iYWwgZXJyb3JzJyxcclxuICBUT0dHTEVfSU5ESUNBVE9SX0VESVRJTkcgPSAnW0NMU1MtQVBQTElDQVRJT05dIFRvZ2dsZSBpbmRpY2F0b3IgZWRpdGluZycsICBcclxuICBTRUxFQ1RfTElGRUxJTkVTVEFUVVNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTZWxlY3QgYSBsaWZlbGluZSBzdGF0dXMnLFxyXG4gIExPQURfQVNTRVNTTUVOVFNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBMb2FkIGFzc2Vzc21lbnRzJyxcclxuICBTRUxFQ1RfQVNTRVNTTUVOVF9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIFNlbGVjdCBhc3Nlc3NtZW50JyxcclxuICBMT0FEX1JBVElOR1NDQUxFU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIExvYWQgcmF0aW5nIHNjYWxlcycsXHJcbiAgTE9BRF9TQ0FMRUZBQ1RPUlNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBMb2FkIGNvbnN0YW50cydcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX1NjYWxlRmFjdG9yc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX1NDQUxFRkFDVE9SU19BQ1RJT04sXHJcbiAgdmFsOiBTY2FsZUZhY3RvcltdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9SYXRpbmdfU2NhbGVzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfUkFUSU5HU0NBTEVTX0FDVElPTixcclxuICB2YWw6IFJhdGluZ1NjYWxlW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZWxlY3RfQXNzZXNzbWVudF9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfQVNTRVNTTUVOVF9BQ1RJT04sXHJcbiAgdmFsOiBBc3Nlc3NtZW50XHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9Bc3Nlc3NtZW50c19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX0FTU0VTU01FTlRTX0FDVElPTixcclxuICB2YWw6IEFzc2Vzc21lbnRbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfUHJpb3JpdGllc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX1BSSU9SSVRJRVNfQUNUSU9OLFxyXG4gIHZhbDogYW55W11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX0hhemFyZF9UeXBlc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX0hBWkFSRF9UWVBFU19BQ1RJT04sXHJcbiAgdmFsOiBJQ29kZWRWYWx1ZVtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9Pcmdhbml6YXRpb25fVHlwZXNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9PUkdBTklaQVRJT05fVFlQRVNfQUNUSU9OLFxyXG4gIHZhbDogSUNvZGVkVmFsdWVbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNlbGVjdF9MaWZlbGluZVN0YXR1c19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfTElGRUxJTkVTVEFUVVNfQUNUSU9OLFxyXG4gIHZhbDogTGlmZWxpbmVTdGF0dXNcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZXRfVG9nZ2xlX0luZGljYXRvcl9FZGl0aW5nX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlRPR0dMRV9JTkRJQ0FUT1JfRURJVElORyxcclxuICB2YWw6IHN0cmluZ1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNldF9FcnJvcnNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUyxcclxuICB2YWw6IHN0cmluZ1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfSGF6YXJkc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX0hBWkFSRFNfQUNUSU9OLFxyXG4gIHZhbDogSGF6YXJkW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX09yZ2FuaXphdGlvbnNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9PUkdBTklaQVRJT05TX0FDVElPTixcclxuICB2YWw6IE9yZ2FuaXphdGlvbltdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2V0SWRlbnRpdHlfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VUX0lERU5USVRZX0FDVElPTixcclxuICB2YWw6IENsc3NVc2VyXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2V0VXNlcl9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRVRfVVNFUl9BQ1RJT04sXHJcbiAgdmFsOiBDbHNzVXNlclxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNpZ25pbl9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TSUdOX0lOX0FDVElPTlxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNpZ25vdXRfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0lHTl9PVVRfQUNUSU9OXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2VsZWN0X1RlbXBsYXRlX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFTEVDVF9URU1QTEFURV9BQ1RJT04sXHJcbiAgdmFsOiBzdHJpbmdcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX1RlbXBsYXRlc19BY3Rpb25fVHlwZSB7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9URU1QTEFURVNfQUNUSU9OLFxyXG4gIHZhbDogQ0xTU1RlbXBsYXRlW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZWFyY2hfVGVtcGxhdGVzX0FjdGlvbl9UeXBlIHtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRUFSQ0hfQUNUSU9OLFxyXG4gIHZhbDogc3RyaW5nXHJcbn0gIFxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBBdXRoZW50aWNhdGVfQWN0aW9uX1R5cGUge1xyXG4gICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5BVVRIRU5USUNBVEVfQUNUSU9OLFxyXG4gICB2YWw6IElDcmVkZW50aWFsO1xyXG59XHJcblxyXG5cclxudHlwZSBBY3Rpb25UeXBlcyA9IFxyXG4gU2VsZWN0X1RlbXBsYXRlX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfVGVtcGxhdGVzX0FjdGlvbl9UeXBlIHwgXHJcbiBTZWFyY2hfVGVtcGxhdGVzX0FjdGlvbl9UeXBlIHwgXHJcbiBTaWduaW5fQWN0aW9uX1R5cGUgfFxyXG4gU2lnbm91dF9BY3Rpb25fVHlwZSB8XHJcbiBTZXRVc2VyX0FjdGlvbl9UeXBlIHwgXHJcbiBTZXRJZGVudGl0eV9BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX0hhemFyZHNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9Pcmdhbml6YXRpb25zX0FjdGlvbl9UeXBlIHxcclxuIFNldF9FcnJvcnNfQWN0aW9uX1R5cGUgfFxyXG4gU2V0X1RvZ2dsZV9JbmRpY2F0b3JfRWRpdGluZ19BY3Rpb25fVHlwZSB8XHJcbiBTZWxlY3RfTGlmZWxpbmVTdGF0dXNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9IYXphcmRfVHlwZXNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9Pcmdhbml6YXRpb25fVHlwZXNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9Qcmlvcml0aWVzX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfQXNzZXNzbWVudHNfQWN0aW9uX1R5cGUgfFxyXG4gU2VsZWN0X0Fzc2Vzc21lbnRfQWN0aW9uX1R5cGV8IFxyXG4gTG9hZF9SYXRpbmdfU2NhbGVzX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfU2NhbGVGYWN0b3JzX0FjdGlvbl9UeXBlIHxcclxuIEF1dGhlbnRpY2F0ZV9BY3Rpb25fVHlwZSA7XHJcblxyXG50eXBlIElNTXlTdGF0ZSA9IEltbXV0YWJsZU9iamVjdDxDTFNTX1N0YXRlPjtcclxuXHJcbmRlY2xhcmUgbW9kdWxlICdqaW11LWNvcmUvbGliL3R5cGVzL3N0YXRlJ3tcclxuICBpbnRlcmZhY2UgU3RhdGV7XHJcbiAgICBjbHNzU3RhdGU/OiBJTU15U3RhdGVcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBkZWZhdWx0IGNsYXNzIE15UmVkdXhTdG9yZUV4dGVuc2lvbiBpbXBsZW1lbnRzIGV4dGVuc2lvblNwZWMuUmVkdXhTdG9yZUV4dGVuc2lvbiB7XHJcbiAgaWQgPSAnY2xzcy1yZWR1eC1zdG9yZS1leHRlbnNpb24nO1xyXG4gXHJcbiAgZ2V0QWN0aW9ucygpIHtcclxuICAgIHJldHVybiBPYmplY3Qua2V5cyhDTFNTQWN0aW9uS2V5cykubWFwKGsgPT4gQ0xTU0FjdGlvbktleXNba10pO1xyXG4gIH1cclxuXHJcbiAgZ2V0SW5pdExvY2FsU3RhdGUoKSB7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICAgc2VsZWN0ZWRUZW1wbGF0ZTogbnVsbCxcclxuICAgICAgIHRlbXBsYXRlczogW10sXHJcbiAgICAgICBzZWFyY2hSZXN1bHRzOiBbXSxcclxuICAgICAgIHVzZXI6IG51bGwsXHJcbiAgICAgICBhdXRoOiBudWxsLFxyXG4gICAgICAgaWRlbnRpdHk6IG51bGwsICAgICAgIFxyXG4gICAgICAgbmV3VGVtcGxhdGVNb2RhbFZpc2libGU6IGZhbHNlLFxyXG4gICAgICAgaGF6YXJkczogW10sXHJcbiAgICAgICBvcmdhbml6YXRpb25zOiBbXSxcclxuICAgICAgIGVycm9yczogJycsXHJcbiAgICAgICBpc0luZGljYXRvckVkaXRpbmc6IGZhbHNlLFxyXG4gICAgICAgc2VsZWN0ZWRMaWZlbGluZVN0YXR1czogbnVsbCxcclxuICAgICAgIG9yZ2FuaXphdGlvblR5cGVzOiBbXSxcclxuICAgICAgIGhhemFyZFR5cGVzOiBbXSxcclxuICAgICAgIHByaW9yaXRpZXM6IFtdLFxyXG4gICAgICAgYXNzZXNzbWVudHM6IFtdLFxyXG4gICAgICAgcmF0aW5nU2NhbGVzOiBbXSxcclxuICAgICAgIHNjYWxlRmFjdG9yczogW10sXHJcbiAgICAgICBhdXRoZW50aWNhdGU6IG51bGxcclxuICAgIH0gYXMgQ0xTU19TdGF0ZTtcclxuICB9XHJcblxyXG4gIGdldFJlZHVjZXIoKSB7XHJcbiAgICByZXR1cm4gKGxvY2FsU3RhdGU6IElNTXlTdGF0ZSwgYWN0aW9uOiBBY3Rpb25UeXBlcywgYXBwU3RhdGU6IElNU3RhdGUpOiBJTU15U3RhdGUgPT4geyAgICAgIFxyXG4gICAgICBcclxuICAgICAgc3dpdGNoIChhY3Rpb24udHlwZSkge1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkFVVEhFTlRJQ0FURV9BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2F1dGhlbnRpY2F0ZScsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfU0NBTEVGQUNUT1JTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnc2NhbGVGYWN0b3JzJywgYWN0aW9uLnZhbCk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX1JBVElOR1NDQUxFU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3JhdGluZ1NjYWxlcycsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFTEVDVF9BU1NFU1NNRU5UX0FDVElPTjpcclxuICAgICAgICAgIGNvbnN0IGFzc2Vzc21lbnRzID0gbG9jYWxTdGF0ZS5hc3Nlc3NtZW50cy5tYXAoYXNzZXNzID0+IHtcclxuICAgICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgICAgLi4uYXNzZXNzLFxyXG4gICAgICAgICAgICAgIGlzU2VsZWN0ZWQ6IGFzc2Vzcy5pZCA9PT0gYWN0aW9uLnZhbC5pZC50b0xvd2VyQ2FzZSgpXHJcbiAgICAgICAgICAgICB9XHJcbiAgICAgICAgICB9KVxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdhc3Nlc3NtZW50cycsIGFzc2Vzc21lbnRzKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX0FTU0VTU01FTlRTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnYXNzZXNzbWVudHMnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX1BSSU9SSVRJRVNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdwcmlvcml0aWVzJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VMRUNUX0xJRkVMSU5FU1RBVFVTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnc2VsZWN0ZWRMaWZlbGluZVN0YXR1cycsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlRPR0dMRV9JTkRJQ0FUT1JfRURJVElORzpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnaXNJbmRpY2F0b3JFZGl0aW5nJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUzpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnZXJyb3JzJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9IQVpBUkRTX0FDVElPTjogIFxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdoYXphcmRzJywgYWN0aW9uLnZhbClcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX0hBWkFSRF9UWVBFU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2hhemFyZFR5cGVzJywgYWN0aW9uLnZhbClcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX09SR0FOSVpBVElPTl9UWVBFU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ29yZ2FuaXphdGlvblR5cGVzJywgYWN0aW9uLnZhbClcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX09SR0FOSVpBVElPTlNfQUNUSU9OOlxyXG4gICAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ29yZ2FuaXphdGlvbnMnLCBhY3Rpb24udmFsKVxyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFVF9JREVOVElUWV9BQ1RJT046ICBcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnaWRlbnRpdHknLCBhY3Rpb24udmFsKTtcclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFVF9VU0VSX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgndXNlcicsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfVEVNUExBVEVTX0FDVElPTjogICAgICAgICAgXHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3RlbXBsYXRlcycsIGFjdGlvbi52YWwpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VMRUNUX1RFTVBMQVRFX0FDVElPTjpcclxuICAgICAgICAgIGxldCB0ZW1wbGF0ZXMgPSBbLi4ubG9jYWxTdGF0ZS50ZW1wbGF0ZXNdLm1hcCh0ID0+IHtcclxuICAgICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgICAgLi4udCxcclxuICAgICAgICAgICAgICBpc1NlbGVjdGVkOiB0LmlkID09PSBhY3Rpb24udmFsXHJcbiAgICAgICAgICAgICB9IFxyXG4gICAgICAgICAgfSlcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgndGVtcGxhdGVzJywgdGVtcGxhdGVzKSAgICAgICAgICAgIFxyXG4gICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZTtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgZ2V0U3RvcmVLZXkoKSB7XHJcbiAgICByZXR1cm4gJ2Nsc3NTdGF0ZSc7XHJcbiAgfVxyXG59IiwiZXhwb3J0IGNvbnN0IENMU1NfQURNSU4gPSAnQ0xTU19BZG1pbic7XHJcbmV4cG9ydCBjb25zdCBDTFNTX0VESVRPUiA9ICdDTFNTX0VkaXRvcic7XHJcbmV4cG9ydCBjb25zdCBDTFNTX0FTU0VTU09SID0gJ0NMU1NfQXNzZXNzb3InO1xyXG5leHBvcnQgY29uc3QgQ0xTU19WSUVXRVIgPSAnQ0xTU19WaWV3ZXInO1xyXG5leHBvcnQgY29uc3QgQ0xTU19GT0xMT1dFUlMgPSAnQ0xTUyBGb2xsb3dlcnMnO1xyXG5cclxuZXhwb3J0IGNvbnN0IEJBU0VMSU5FX1RFTVBMQVRFX05BTUUgPSAnQmFzZWxpbmUnO1xyXG5leHBvcnQgY29uc3QgVE9LRU5fRVJST1IgPSAnVG9rZW4gbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IFRFTVBMQVRFX1VSTF9FUlJPUiA9ICdUZW1wbGF0ZSBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBBU1NFU1NNRU5UX1VSTF9FUlJPUiA9ICdBc3Nlc3NtZW50IEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IE9SR0FOSVpBVElPTl9VUkxfRVJST1IgPSAnT3JnYW5pemF0aW9uIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IEhBWkFSRF9VUkxfRVJST1IgPSAnSGF6YXJkIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IElORElDQVRPUl9VUkxfRVJST1IgPSAnSW5kaWNhdG9yIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IEFMSUdOTUVOVF9VUkxfRVJST1IgPSAnQWxpZ25tZW50cyBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBMSUZFTElORV9VUkxfRVJST1IgPSAnTGlmZWxpbmUgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgQ09NUE9ORU5UX1VSTF9FUlJPUiA9ICdDb21wb25lbnQgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgUFJJT1JJVFlfVVJMX0VSUk9SID0gJ1ByaW9yaXR5IEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IElOQ0lERU5UX1VSTF9FUlJPUiA9ICdJbmNpZGVudCBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBTQVZJTkdfU0FNRV9BU19CQVNFTElORV9FUlJPUiA9ICdCYXNlbGluZSB0ZW1wbGF0ZSBjYW5ub3QgYmUgdXBkYXRlZC4gQ2hhbmdlIHRoZSB0ZW1wbGF0ZSBuYW1lIHRvIGNyZWF0ZSBhIG5ldyBvbmUuJ1xyXG5cclxuZXhwb3J0IGNvbnN0IFNUQUJJTElaSU5HX1NDQUxFX0ZBQ1RPUiA9ICdTdGFiaWxpemluZ19TY2FsZV9GYWN0b3InO1xyXG5leHBvcnQgY29uc3QgREVTVEFCSUxJWklOR19TQ0FMRV9GQUNUT1IgPSAnRGVzdGFiaWxpemluZ19TY2FsZV9GYWN0b3InO1xyXG5leHBvcnQgY29uc3QgVU5DSEFOR0VEX1NDQUxFX0ZBQ1RPUiA9ICdVbmNoYW5nZWRfSW5kaWNhdG9ycyc7XHJcbmV4cG9ydCBjb25zdCBERUZBVUxUX1BSSU9SSVRZX0xFVkVMUyA9IFwiRGVmYXVsdF9Qcmlvcml0eV9MZXZlbHNcIjtcclxuZXhwb3J0IGNvbnN0IFJBTksgPSAnSW1wb3J0YW5jZSBvZiBJbmRpY2F0b3InO1xyXG5leHBvcnQgY29uc3QgTElGRV9TQUZFVFkgPSAnTGlmZSBTYWZldHknO1xyXG5leHBvcnQgY29uc3QgSU5DSURFTlRfU1RBQklMSVpBVElPTiA9ICdJbmNpZGVudCBTdGFiaWxpemF0aW9uJztcclxuZXhwb3J0IGNvbnN0IFBST1BFUlRZX1BST1RFQ1RJT04gPSAnUHJvcGVydHkgUHJvdGVjdGlvbic7XHJcbmV4cG9ydCBjb25zdCBFTlZJUk9OTUVOVF9QUkVTRVJWQVRJT04gPSAnRW52aXJvbm1lbnQgUHJlc2VydmF0aW9uJztcclxuXHJcbmV4cG9ydCBjb25zdCBMSUZFX1NBRkVUWV9TQ0FMRV9GQUNUT1IgPSAyMDA7XHJcbmV4cG9ydCBjb25zdCBPVEhFUl9XRUlHSFRTX1NDQUxFX0ZBQ1RPUiA9IDEwMDtcclxuZXhwb3J0IGNvbnN0IE1BWElNVU1fV0VJR0hUID0gNTtcclxuXHJcbmV4cG9ydCBlbnVtIFVwZGF0ZUFjdGlvbiB7XHJcbiAgICBIRUFERVIgPSAnaGVhZGVyJyxcclxuICAgIElORElDQVRPUl9OQU1FID0gJ0luZGljYXRvciBOYW1lJyxcclxuICAgIFBSSU9SSVRJRVMgPSAnSW5kaWNhdG9yIFByaW9yaXRpZXMnLFxyXG4gICAgTkVXX0lORElDQVRPUiA9ICdDcmVhdGUgTmV3IEluZGljYXRvcicsXHJcbiAgICBERUxFVEVfSU5ESUNBVE9SID0gJ0RlbGV0ZSBJbmRpY2F0b3InXHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBJTkNMVURFX0lORElDQVRPUiA9ICdJbXBhY3RlZCAtIFllcyBvciBObyc7XHJcbmV4cG9ydCBjb25zdCBJTkNMVURFX0lORElDQVRPUl9IRUxQID0gJ1llczogVGhlIGluZGljYXRvciB3aWxsIGJlIGNvbnNpZGVyZWQgaW4gdGhlIGFzc2Vzc21lbnQuXFxuTm86IFRoZSBpbmRpY2F0b3Igd2lsbCBub3QgYmUgY29uc2lkZXJlZC5cXG5Vbmtub3duOiBOb3Qgc3VyZSB0byBpbmNsdWRlIHRoZSBpbmRpY2F0b3IgaW4gYXNzZXNzbWVudC4nO1xyXG5cclxuZXhwb3J0IGNvbnN0IElORElDQVRPUl9TVEFUVVMgPSAnSW5kaWNhdG9yIEltcGFjdCBTdGF0dXMnO1xyXG5leHBvcnQgY29uc3QgSU5ESUNBVE9SX1NUQVRVU19IRUxQID0gJ1N0YWJpbGl6aW5nOiBIYXMgdGhlIGluZGljYXRvciBiZWVuIGltcHJvdmVkIG9yIGltcHJvdmluZy5cXG5EZXN0YWJpbGl6aW5nOiBJcyB0aGUgaW5kaWNhdG9yIGRlZ3JhZGluZy5cXG5VbmNoYW5nZWQ6IE5vIHNpZ25pZmljYW50IGltcHJvdmVtZW50IHNpbmNlIHRoZSBsYXN0IGFzc2Vzc21lbnQuJztcclxuXHJcbmV4cG9ydCBjb25zdCBDT01NRU5UID0gJ0NvbW1lbnQnO1xyXG5leHBvcnQgY29uc3QgQ09NTUVOVF9IRUxQID0gJ1Byb3ZpZGUganVzdGlmaWNhdGlvbiBmb3IgdGhlIHNlbGVjdGVkIGluZGljYXRvciBzdGF0dXMuJztcclxuXHJcbmV4cG9ydCBjb25zdCBERUxFVEVfSU5ESUNBVE9SX0NPTkZJUk1BVElPTiA9ICdBcmUgeW91IHN1cmUgeW91IHdhbnQgdG8gZGVsZXRlIGluZGljYXRvcj8nO1xyXG5cclxuLy9DZWxsIFdlaWdodCA9ICBUcmVuZCAqICggKC0xKlJhbmspICsgNlxyXG5leHBvcnQgY29uc3QgQ1JJVElDQUwgPSAyNTtcclxuZXhwb3J0IGNvbnN0IENSSVRJQ0FMX0xPV0VSX0JPVU5EQVJZID0gMTIuNTtcclxuZXhwb3J0IGNvbnN0IE1PREVSQVRFX0xPV0VSX0JPVU5EQVJZID0gNS41O1xyXG5leHBvcnQgY29uc3QgTk9EQVRBX0NPTE9SID0gJyM5MTkzOTUnO1xyXG5leHBvcnQgY29uc3QgTk9EQVRBX1ZBTFVFID0gOTk5OTk5O1xyXG5leHBvcnQgY29uc3QgUkVEX0NPTE9SID0gJyNDNTIwMzgnO1xyXG5leHBvcnQgY29uc3QgWUVMTE9XX0NPTE9SID0gJyNGQkJBMTYnO1xyXG5leHBvcnQgY29uc3QgR1JFRU5fQ09MT1IgPSAnIzVFOUM0Mic7XHJcbmV4cG9ydCBjb25zdCBTQVZJTkdfVElNRVIgPSAxNTAwO1xyXG5leHBvcnQgY29uc3QgSU5ESUNBVE9SX0NPTU1FTlRfTEVOR1RIID0gMzAwO1xyXG5cclxuZXhwb3J0IGNvbnN0IFBPUlRBTF9VUkwgPSAnaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbSc7XHJcblxyXG5leHBvcnQgY29uc3QgREVGQVVMVF9MSVNUSVRFTSA9IHtpZDogJzAwMCcsIG5hbWU6ICctTm9uZS0nLCB0aXRsZTogJy1Ob25lLSd9IGFzIGFueTtcclxuXHJcbmV4cG9ydCBjb25zdCBSQU5LX01FU1NBR0UgPSAnSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIHlvdXIganVyaXNkaWN0aW9uIG9yIGhhemFyZD8nO1xyXG5leHBvcnQgY29uc3QgTElGRV9TQUZFVFlfTUVTU0FHRSA9ICdIb3cgaW1wb3J0YW50IGlzIHRoZSBpbmRpY2F0b3IgdG8gTGlmZSBTYWZldHk/JztcclxuZXhwb3J0IGNvbnN0IFBST1BFUlRZX1BST1RFQ1RJT05fTUVTU0FHRSA9ICdIb3cgaW1wb3J0YW50IGlzIHRoZSBpbmRpY2F0b3IgdG8gUHJvcGVydHkgUHJvdGVjdGlvbj8nO1xyXG5leHBvcnQgY29uc3QgRU5WSVJPTk1FTlRfUFJFU0VSVkFUSU9OX01FU1NBR0UgPSAnSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIEVudmlyb25tZW50IFByZXNlcnZhdGlvbj8nO1xyXG5leHBvcnQgY29uc3QgSU5DSURFTlRfU1RBQklMSVpBVElPTl9NRVNTQUdFID0gJ0hvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byBJbmNpZGVudCBTdGFiaWxpemF0aW9uPyc7XHJcblxyXG5leHBvcnQgY29uc3QgT1ZFUldSSVRFX1NDT1JFX01FU1NBR0UgPSAnQSBjb21wbGV0ZWQgYXNzZXNzbWVudCBjYW5ub3QgYmUgZWRpdGVkLiBBcmUgeW91IHN1cmUgeW91IHdhbnQgdG8gY29tcGxldGUgdGhpcyBhc3Nlc3NtZW50Pyc7XHJcblxyXG5leHBvcnQgY29uc3QgVVNFUl9CT1hfRUxFTUVOVF9JRCA9ICd1c2VyQm94RWxlbWVudCc7XHJcblxyXG5leHBvcnQgY29uc3QgREFUQV9MSUJSQVJZX1RJVExFID0gJ0RhdGEgTGlicmFyeSc7XHJcbmV4cG9ydCBjb25zdCBBTkFMWVNJU19SRVBPUlRJTkdfVElUTEUgPSAnQW5hbHlzaXMgJiBSZXBvcnRpbmcnO1xyXG5leHBvcnQgY29uc3QgREFUQV9MSUJSQVJZX1VSTCA9ICdodHRwczovL2V4cGVyaWVuY2UuYXJjZ2lzLmNvbS9leHBlcmllbmNlL2Y5NjExOTFjZDI1MTRhYmY4ZTQzNDg2YzZmZmJmMThiJztcclxuZXhwb3J0IGNvbnN0IEFOQUxZU0lTX1JFUE9SVElOR19VUkwgPSAnaHR0cHM6Ly9leHBlcmllbmNlLmFyY2dpcy5jb20vZXhwZXJpZW5jZS84YTc2MGE3MzkxMjU0NTMwYjJjYzljOTk1MmU3YWFkZCc7IiwiaW1wb3J0IHsgVXNlclNlc3Npb24gfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aFwiO1xyXG5pbXBvcnQgeyBxdWVyeUZlYXR1cmVzLCBJUXVlcnlGZWF0dXJlc1Jlc3BvbnNlLCBcclxuICAgIElSZWxhdGVkUmVjb3JkR3JvdXAsIHF1ZXJ5UmVsYXRlZCwgdXBkYXRlRmVhdHVyZXMsIFxyXG4gICAgYWRkRmVhdHVyZXMsIGRlbGV0ZUZlYXR1cmVzIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXJcIjtcclxuaW1wb3J0IHsgSUZlYXR1cmVTZXQsIElGZWF0dXJlIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXR5cGVzXCI7XHJcbmltcG9ydCB7IEFwcFdpZGdldENvbmZpZyB9IGZyb20gXCIuL2RhdGEtZGVmaW5pdGlvbnNcIjtcclxuaW1wb3J0IHsgbG9nLCBMb2dUeXBlIH0gZnJvbSBcIi4vbG9nZ2VyXCI7XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRBdXRoZW50aWNhdGlvbihjb25maWc6IEFwcFdpZGdldENvbmZpZykge1xyXG4gIHJldHVybiBVc2VyU2Vzc2lvbi5mcm9tQ3JlZGVudGlhbChjb25maWcuY3JlZGVudGlhbCk7XHJcbn1cclxuICBcclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHF1ZXJ5VGFibGVGZWF0dXJlU2V0KHVybDogc3RyaW5nLCB3aGVyZTogc3RyaW5nLCBcclxuICBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVTZXQ+IHtcclxuICBcclxuICAgIHRyeXtcclxuXHJcbiAgICAgIGNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTtcclxuICAgICAgcmV0dXJuIHF1ZXJ5RmVhdHVyZXMoeyB1cmwsIHdoZXJlLCBhdXRoZW50aWNhdGlvbiwgaGlkZVRva2VuOiB0cnVlIH0pXHJcbiAgICAgIC50aGVuKChyZXNwb25zZTogSVF1ZXJ5RmVhdHVyZXNSZXNwb25zZSkgPT4ge1xyXG4gICAgICAgIHJldHVybiByZXNwb25zZVxyXG4gICAgICB9KVxyXG5cclxuICAgIH1jYXRjaChlKXtcclxuICAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdxdWVyeVRhYmxlRmVhdHVyZVNldCcpXHJcbiAgICB9ICAgIFxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcXVlcnlUYWJsZUZlYXR1cmVzKHVybDogc3RyaW5nLCB3aGVyZTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVbXT4ge1xyXG5cclxuIGNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTtcclxuXHJcbiAgdHJ5e1xyXG4gICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IHF1ZXJ5RmVhdHVyZXMoeyB1cmwsIHdoZXJlLCBhdXRoZW50aWNhdGlvbiwgIGh0dHBNZXRob2Q6J1BPU1QnLCBoaWRlVG9rZW46IHRydWUgfSlcclxuICAgICAgcmV0dXJuIChyZXNwb25zZSBhcyBJUXVlcnlGZWF0dXJlc1Jlc3BvbnNlKS5mZWF0dXJlcztcclxuICB9Y2F0Y2goZSl7XHJcbiAgICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAncXVlcnlUYWJsZUZlYXR1cmVzJylcclxuICAgICAgbG9nKHVybCwgTG9nVHlwZS5XUk4sIHdoZXJlKTtcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCAgYXN5bmMgZnVuY3Rpb24gcXVlcnlSZWxhdGVkVGFibGVGZWF0dXJlcyhvYmplY3RJZHM6IG51bWJlcltdLFxyXG51cmw6IHN0cmluZywgcmVsYXRpb25zaGlwSWQ6IG51bWJlciwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElSZWxhdGVkUmVjb3JkR3JvdXBbXT4ge1xyXG5cclxuY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG5cclxuY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBxdWVyeVJlbGF0ZWQoe1xyXG4gICAgb2JqZWN0SWRzLFxyXG4gICAgdXJsLCByZWxhdGlvbnNoaXBJZCxcclxuICAgIGF1dGhlbnRpY2F0aW9uLFxyXG4gICAgaGlkZVRva2VuOiB0cnVlXHJcbn0pO1xyXG5yZXR1cm4gcmVzcG9uc2UucmVsYXRlZFJlY29yZEdyb3VwcztcclxufVxyXG5cclxuZXhwb3J0ICBhc3luYyBmdW5jdGlvbiB1cGRhdGVUYWJsZUZlYXR1cmUodXJsOiBzdHJpbmcsIGF0dHJpYnV0ZXM6IGFueSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpIHtcclxuICBjb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7XHJcblxyXG4gIHJldHVybiB1cGRhdGVGZWF0dXJlcyh7XHJcbiAgICAgIHVybCxcclxuICAgICAgYXV0aGVudGljYXRpb24sXHJcbiAgICAgIGZlYXR1cmVzOiBbe1xyXG4gICAgICBhdHRyaWJ1dGVzXHJcbiAgICAgIH1dLFxyXG4gICAgICByb2xsYmFja09uRmFpbHVyZTogdHJ1ZVxyXG4gIH0pXHJcbn1cclxuXHJcbmV4cG9ydCAgYXN5bmMgZnVuY3Rpb24gdXBkYXRlVGFibGVGZWF0dXJlcyh1cmw6IHN0cmluZywgZmVhdHVyZXM6IElGZWF0dXJlW10sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKSB7XHJcbiAgY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpOyAgXHJcbiAgcmV0dXJuIHVwZGF0ZUZlYXR1cmVzKHtcclxuICAgICAgdXJsLFxyXG4gICAgICBhdXRoZW50aWNhdGlvbixcclxuICAgICAgZmVhdHVyZXNcclxuICB9KVxyXG59XHJcblxyXG5leHBvcnQgIGFzeW5jIGZ1bmN0aW9uIGFkZFRhYmxlRmVhdHVyZXModXJsOiBzdHJpbmcsIGZlYXR1cmVzOiBhbnlbXSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpIHtcclxuXHJcbiAgY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG5cclxuICB0cnl7XHJcbiAgICByZXR1cm4gYWRkRmVhdHVyZXMoeyB1cmwsIGZlYXR1cmVzLCBhdXRoZW50aWNhdGlvbiwgcm9sbGJhY2tPbkZhaWx1cmU6IHRydWUgfSk7XHJcbiAgfWNhdGNoKGUpe1xyXG4gICAgY29uc29sZS5sb2coZSk7XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgIGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZVRhYmxlRmVhdHVyZXModXJsOiBzdHJpbmcsIG9iamVjdElkczogbnVtYmVyW10sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKSB7XHJcblxyXG4gICAgY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG4gICAgcmV0dXJuIGRlbGV0ZUZlYXR1cmVzKHsgdXJsLCBvYmplY3RJZHMsIGF1dGhlbnRpY2F0aW9uLCByb2xsYmFja09uRmFpbHVyZTogdHJ1ZSB9KTtcclxufSIsImV4cG9ydCBlbnVtIExvZ1R5cGUge1xyXG4gICAgSU5GTyA9ICdJbmZvcm1hdGlvbicsXHJcbiAgICBXUk4gPSAnV2FybmluZycsXHJcbiAgICBFUlJPUiA9ICdFcnJvcidcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIGxvZyhtZXNzYWdlOiBzdHJpbmcsIHR5cGU/OiBMb2dUeXBlLCBmdW5jPzogc3RyaW5nKXtcclxuICAgIGlmKCF0eXBlKXtcclxuICAgICAgICB0eXBlID0gTG9nVHlwZS5JTkZPXHJcbiAgICB9XHJcblxyXG4gICAgaWYoZnVuYyl7XHJcbiAgICAgICAgZnVuYyA9IGAoJHtmdW5jfSlgO1xyXG4gICAgfVxyXG5cclxuICAgIG1lc3NhZ2UgPSBgWyR7bmV3IERhdGUoKS50b0xvY2FsZVN0cmluZygpfV06ICR7bWVzc2FnZX0gJHtmdW5jfWA7XHJcblxyXG4gICAgc3dpdGNoKHR5cGUpe1xyXG4gICAgICAgIGNhc2UgTG9nVHlwZS5JTkZPOlxyXG4gICAgICAgICAgICBjb25zb2xlLmxvZyhtZXNzYWdlKTtcclxuICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgY2FzZSBMb2dUeXBlLldSTjpcclxuICAgICAgICAgICAgY29uc29sZS53YXJuKG1lc3NhZ2UpO1xyXG4gICAgICAgICAgICBicmVhaztcclxuICAgICAgICBjYXNlIExvZ1R5cGUuRVJST1I6XHJcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IobWVzc2FnZSk7XHJcbiAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKG1lc3NhZ2UpO1xyXG4gICAgfVxyXG59IiwiXHJcbmV4cG9ydCBjb25zdCBzb3J0T2JqZWN0ID0gPFQ+KG9iajogVFtdLCBwcm9wOiBzdHJpbmcsIHJldmVyc2U/OmJvb2xlYW4pOiBUW10gPT4ge1xyXG4gICByZXR1cm4gb2JqLnNvcnQoKGE6VCwgYjpUKSA9PiB7XHJcbiAgICAgIGlmKGFbcHJvcF0gPiBiW3Byb3BdKXtcclxuICAgICAgICByZXR1cm4gcmV2ZXJzZSA/IC0xIDogMVxyXG4gICAgICB9XHJcbiAgICAgIGlmKGFbcHJvcF0gPCBiW3Byb3BdKXtcclxuICAgICAgICByZXR1cm4gcmV2ZXJzZSA/IDEgOiAtMVxyXG4gICAgICB9XHJcbiAgICAgIHJldHVybiAwO1xyXG4gIH0pO1xyXG59XHJcblxyXG5leHBvcnQgY29uc3QgY3JlYXRlR3VpZCA9ICgpID0+e1xyXG4gIHJldHVybiAneHh4eHh4eHgteHh4eC00eHh4LXl4eHgteHh4eHh4eHh4eHh4Jy5yZXBsYWNlKC9beHldL2csIGZ1bmN0aW9uKGMpIHtcclxuICAgIHZhciByID0gTWF0aC5yYW5kb20oKSAqIDE2IHwgMCwgdiA9IGMgPT0gJ3gnID8gciA6IChyICYgMHgzIHwgMHg4KTtcclxuICAgIHJldHVybiB2LnRvU3RyaW5nKDE2KTtcclxuICB9KTtcclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IHBhcnNlRGF0ZSA9IChtaWxsaXNlY29uZHM6IG51bWJlcik6IHN0cmluZyA9PiB7XHJcbiAgaWYoIW1pbGxpc2Vjb25kcyl7XHJcbiAgICByZXR1cm5cclxuICB9XHJcbiAgIHJldHVybiBuZXcgRGF0ZShtaWxsaXNlY29uZHMpLnRvTG9jYWxlU3RyaW5nKCk7XHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBzYXZlRGF0ZSA9IChkYXRlOiBzdHJpbmcpOiBudW1iZXIgPT4ge1xyXG4gICByZXR1cm4gbmV3IERhdGUoZGF0ZSkuZ2V0TWlsbGlzZWNvbmRzKCk7XHJcbn1cclxuXHJcblxyXG4vL1JlZmVyZW5jZTogaHR0cHM6Ly9zdGFja292ZXJmbG93LmNvbS9xdWVzdGlvbnMvNjE5NTMzNS9saW5lYXItcmVncmVzc2lvbi1pbi1qYXZhc2NyaXB0XHJcbi8vIGV4cG9ydCBjb25zdCBsaW5lYXJSZWdyZXNzaW9uID0gKHlWYWx1ZXM6IG51bWJlcltdLCB4VmFsdWVzOiBudW1iZXJbXSkgPT57XHJcbi8vICAgZGVidWdnZXI7XHJcbi8vICAgY29uc3QgeSA9IHlWYWx1ZXM7XHJcbi8vICAgY29uc3QgeCA9IHhWYWx1ZXM7XHJcblxyXG4vLyAgIHZhciBsciA9IHtzbG9wZTogTmFOLCBpbnRlcmNlcHQ6IE5hTiwgcjI6IE5hTn07XHJcbi8vICAgdmFyIG4gPSB5Lmxlbmd0aDtcclxuLy8gICB2YXIgc3VtX3ggPSAwO1xyXG4vLyAgIHZhciBzdW1feSA9IDA7XHJcbi8vICAgdmFyIHN1bV94eSA9IDA7XHJcbi8vICAgdmFyIHN1bV94eCA9IDA7XHJcbi8vICAgdmFyIHN1bV95eSA9IDA7XHJcblxyXG4vLyAgIGZvciAodmFyIGkgPSAwOyBpIDwgeS5sZW5ndGg7IGkrKykge1xyXG5cclxuLy8gICAgICAgc3VtX3ggKz0geFtpXTtcclxuLy8gICAgICAgc3VtX3kgKz0geVtpXTtcclxuLy8gICAgICAgc3VtX3h5ICs9ICh4W2ldKnlbaV0pO1xyXG4vLyAgICAgICBzdW1feHggKz0gKHhbaV0qeFtpXSk7XHJcbi8vICAgICAgIHN1bV95eSArPSAoeVtpXSp5W2ldKTtcclxuLy8gICB9IFxyXG5cclxuLy8gICBsci5zbG9wZSA9IChuICogc3VtX3h5IC0gc3VtX3ggKiBzdW1feSkgLyAobipzdW1feHggLSBzdW1feCAqIHN1bV94KTtcclxuLy8gICBsci5pbnRlcmNlcHQgPSAoc3VtX3kgLSBsci5zbG9wZSAqIHN1bV94KS9uO1xyXG4vLyAgIGxyLnIyID0gTWF0aC5wb3coKG4qc3VtX3h5IC0gc3VtX3gqc3VtX3kpL01hdGguc3FydCgobipzdW1feHgtc3VtX3gqc3VtX3gpKihuKnN1bV95eS1zdW1feSpzdW1feSkpLDIpO1xyXG4vLyAgIHJldHVybiBscjtcclxuLy8gfVxyXG5cclxuU3RyaW5nLnByb3RvdHlwZS50b1RpdGxlQ2FzZSA9IGZ1bmN0aW9uICgpIHtcclxuICByZXR1cm4gdGhpcy5yZXBsYWNlKC9cXHdcXFMqL2csIGZ1bmN0aW9uKHR4dCl7cmV0dXJuIHR4dC5jaGFyQXQoMCkudG9VcHBlckNhc2UoKSArIHR4dC5zdWJzdHIoMSkudG9Mb3dlckNhc2UoKTt9KTtcclxufTtcclxuXHJcbkFycmF5LnByb3RvdHlwZS5vcmRlckJ5ID0gZnVuY3Rpb248VD4ocHJvcCwgcmV2ZXJzZSkge1xyXG4gIHJldHVybiB0aGlzLnNvcnQoKGE6VCwgYjpUKSA9PiB7XHJcbiAgICBpZihhW3Byb3BdID4gYltwcm9wXSl7XHJcbiAgICAgIHJldHVybiByZXZlcnNlID8gLTEgOiAxXHJcbiAgICB9XHJcbiAgICBpZihhW3Byb3BdIDwgYltwcm9wXSl7XHJcbiAgICAgIHJldHVybiByZXZlcnNlID8gMSA6IC0xXHJcbiAgICB9XHJcbiAgICByZXR1cm4gMDtcclxuICB9KTtcclxufVxyXG5cclxuQXJyYXkucHJvdG90eXBlLmdyb3VwQnkgPSBmdW5jdGlvbihrZXkpIHtcclxuICByZXR1cm4gdGhpcy5yZWR1Y2UoZnVuY3Rpb24ocnYsIHgpIHtcclxuICAgIChydlt4W2tleV1dID0gcnZbeFtrZXldXSB8fCBbXSkucHVzaCh4KTtcclxuICAgIHJldHVybiBydjtcclxuICB9LCB7fSk7XHJcbn07XHJcbiIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X2FyY2dpc19fOyIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X2NvcmVfXzsiLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfcmVhY3RfXzsiLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfamltdV91aV9fOyIsIi8vIFRoZSBtb2R1bGUgY2FjaGVcbnZhciBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX18gPSB7fTtcblxuLy8gVGhlIHJlcXVpcmUgZnVuY3Rpb25cbmZ1bmN0aW9uIF9fd2VicGFja19yZXF1aXJlX18obW9kdWxlSWQpIHtcblx0Ly8gQ2hlY2sgaWYgbW9kdWxlIGlzIGluIGNhY2hlXG5cdHZhciBjYWNoZWRNb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdO1xuXHRpZiAoY2FjaGVkTW9kdWxlICE9PSB1bmRlZmluZWQpIHtcblx0XHRyZXR1cm4gY2FjaGVkTW9kdWxlLmV4cG9ydHM7XG5cdH1cblx0Ly8gQ3JlYXRlIGEgbmV3IG1vZHVsZSAoYW5kIHB1dCBpdCBpbnRvIHRoZSBjYWNoZSlcblx0dmFyIG1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF0gPSB7XG5cdFx0Ly8gbm8gbW9kdWxlLmlkIG5lZWRlZFxuXHRcdC8vIG5vIG1vZHVsZS5sb2FkZWQgbmVlZGVkXG5cdFx0ZXhwb3J0czoge31cblx0fTtcblxuXHQvLyBFeGVjdXRlIHRoZSBtb2R1bGUgZnVuY3Rpb25cblx0X193ZWJwYWNrX21vZHVsZXNfX1ttb2R1bGVJZF0obW9kdWxlLCBtb2R1bGUuZXhwb3J0cywgX193ZWJwYWNrX3JlcXVpcmVfXyk7XG5cblx0Ly8gUmV0dXJuIHRoZSBleHBvcnRzIG9mIHRoZSBtb2R1bGVcblx0cmV0dXJuIG1vZHVsZS5leHBvcnRzO1xufVxuXG4iLCIvLyBkZWZpbmUgZ2V0dGVyIGZ1bmN0aW9ucyBmb3IgaGFybW9ueSBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLmQgPSAoZXhwb3J0cywgZGVmaW5pdGlvbikgPT4ge1xuXHRmb3IodmFyIGtleSBpbiBkZWZpbml0aW9uKSB7XG5cdFx0aWYoX193ZWJwYWNrX3JlcXVpcmVfXy5vKGRlZmluaXRpb24sIGtleSkgJiYgIV9fd2VicGFja19yZXF1aXJlX18ubyhleHBvcnRzLCBrZXkpKSB7XG5cdFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywga2V5LCB7IGVudW1lcmFibGU6IHRydWUsIGdldDogZGVmaW5pdGlvbltrZXldIH0pO1xuXHRcdH1cblx0fVxufTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLm8gPSAob2JqLCBwcm9wKSA9PiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCkpIiwiLy8gZGVmaW5lIF9fZXNNb2R1bGUgb24gZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5yID0gKGV4cG9ydHMpID0+IHtcblx0aWYodHlwZW9mIFN5bWJvbCAhPT0gJ3VuZGVmaW5lZCcgJiYgU3ltYm9sLnRvU3RyaW5nVGFnKSB7XG5cdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFN5bWJvbC50b1N0cmluZ1RhZywgeyB2YWx1ZTogJ01vZHVsZScgfSk7XG5cdH1cblx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsICdfX2VzTW9kdWxlJywgeyB2YWx1ZTogdHJ1ZSB9KTtcbn07IiwiX193ZWJwYWNrX3JlcXVpcmVfXy5wID0gXCJcIjsiLCIvKipcclxuICogV2VicGFjayB3aWxsIHJlcGxhY2UgX193ZWJwYWNrX3B1YmxpY19wYXRoX18gd2l0aCBfX3dlYnBhY2tfcmVxdWlyZV9fLnAgdG8gc2V0IHRoZSBwdWJsaWMgcGF0aCBkeW5hbWljYWxseS5cclxuICogVGhlIHJlYXNvbiB3aHkgd2UgY2FuJ3Qgc2V0IHRoZSBwdWJsaWNQYXRoIGluIHdlYnBhY2sgY29uZmlnIGlzOiB3ZSBjaGFuZ2UgdGhlIHB1YmxpY1BhdGggd2hlbiBkb3dubG9hZC5cclxuICogKi9cclxuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lXHJcbi8vIEB0cy1pZ25vcmVcclxuX193ZWJwYWNrX3B1YmxpY19wYXRoX18gPSB3aW5kb3cuamltdUNvbmZpZy5iYXNlVXJsXHJcbiIsImltcG9ydCB7IFJlYWN0LCBBbGxXaWRnZXRQcm9wcywgUmVhY3RSZWR1eCB9IGZyb20gJ2ppbXUtY29yZSdcclxuaW1wb3J0IHsgSU1Db25maWcgfSBmcm9tICcuLi9jb25maWcnXHJcbmltcG9ydCB7IExhYmVsIH0gZnJvbSAnamltdS11aSc7XHJcbmltcG9ydCB7IEFzc2Vzc21lbnQsIExpZmVsaW5lU3RhdHVzIH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9kYXRhLWRlZmluaXRpb25zJztcclxuaW1wb3J0IHsgQ0xTU0FjdGlvbktleXMgfSBmcm9tICcuLi8uLi8uLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2Nsc3Mtc3RvcmUnO1xyXG5pbXBvcnQgeyBkaXNwYXRjaEFjdGlvbiB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXBpJztcclxuY29uc3QgeyB1c2VTZWxlY3RvciB9ID0gUmVhY3RSZWR1eDtcclxuXHJcbmZ1bmN0aW9uIHVzZVdpbmRvd1NpemUoKSB7XHJcbiAgY29uc3QgW3NpemUsIHNldFNpemVdID0gUmVhY3QudXNlU3RhdGUoWzAsIDBdKTtcclxuICBSZWFjdC51c2VMYXlvdXRFZmZlY3QoKCkgPT4ge1xyXG4gICAgZnVuY3Rpb24gdXBkYXRlU2l6ZSgpIHtcclxuICAgICAgc2V0U2l6ZShbd2luZG93LmlubmVyV2lkdGgsIHdpbmRvdy5pbm5lckhlaWdodF0pO1xyXG4gICAgfVxyXG4gICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ3Jlc2l6ZScsIHVwZGF0ZVNpemUpO1xyXG4gICAgdXBkYXRlU2l6ZSgpO1xyXG4gICAgcmV0dXJuICgpID0+IHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKCdyZXNpemUnLCB1cGRhdGVTaXplKTtcclxuICB9LCBbXSk7XHJcbiAgcmV0dXJuIHNpemU7XHJcbn1cclxuXHJcbmNvbnN0IFdpZGdldCA9IChwcm9wczogQWxsV2lkZ2V0UHJvcHM8SU1Db25maWc+KSA9PiB7XHJcbiAgLy8gY29uc3QgW3dpZHRoLCBoZWlnaHRdID0gdXNlV2luZG93U2l6ZSgpO1xyXG4gIGNvbnN0IFtsaWZlbGluZVN0YXR1c2VzLCBzZXRMaWZlbGluZVN0YXR1c2VzXSA9IFJlYWN0LnVzZVN0YXRlPExpZmVsaW5lU3RhdHVzW10+KFtdKTtcclxuICBjb25zdCBbc2VsZWN0ZWRMaWZlbGluZVN0YXR1cywgc2V0U2VsZWN0ZWRMaWZlbGluZVN0YXR1c10gPSBSZWFjdC51c2VTdGF0ZTxMaWZlbGluZVN0YXR1cz4obnVsbClcclxuXHJcbiAgY29uc3Qgc2VsZWN0ZWRBc3Nlc3NtZW50ID0gdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpPT4ge1xyXG4gICAgaWYoc3RhdGUuY2xzc1N0YXRlPy5hc3Nlc3NtZW50cyAmJiBzdGF0ZS5jbHNzU3RhdGU/LmFzc2Vzc21lbnRzLmxlbmd0aCA+IDApeyAgICAgXHJcbiAgICAgIHJldHVybiAoc3RhdGUuY2xzc1N0YXRlPy5hc3Nlc3NtZW50cyBhcyBBc3Nlc3NtZW50W10pPy5maW5kKGEgPT4gYS5pc1NlbGVjdGVkKVxyXG4gICAgfVxyXG4gIH0pXHJcblxyXG4gIFJlYWN0LnVzZUVmZmVjdCgoKT0+e1xyXG4gICAgaWYoc2VsZWN0ZWRBc3Nlc3NtZW50KXsgICAgIFxyXG4gICAgICBzZXRMaWZlbGluZVN0YXR1c2VzKChzZWxlY3RlZEFzc2Vzc21lbnQ/LmxpZmVsaW5lU3RhdHVzZXMgYXMgYW55KS5vcmRlckJ5KCdsaWZlbGluZU5hbWUnKSk7XHJcbiAgICB9XHJcbiAgfSwgW3NlbGVjdGVkQXNzZXNzbWVudF0pXHJcblxyXG4gIFJlYWN0LnVzZUVmZmVjdCgoKT0+e1xyXG4gICAgaWYobGlmZWxpbmVTdGF0dXNlcyl7XHJcbiAgICAgIHNlbGVjdExpZmVsaW5lU3RhdHVzKGxpZmVsaW5lU3RhdHVzZXNbMF0pO1xyXG4gICAgfVxyXG4gIH0sIFtsaWZlbGluZVN0YXR1c2VzXSlcclxuXHJcbiAgY29uc3Qgc2VsZWN0TGlmZWxpbmVTdGF0dXMgPSAobGlmZWxpbmVTdGF0dXM6IExpZmVsaW5lU3RhdHVzKSA9PntcclxuICAgIHNldFNlbGVjdGVkTGlmZWxpbmVTdGF0dXMobGlmZWxpbmVTdGF0dXMpO1xyXG4gICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VMRUNUX0xJRkVMSU5FU1RBVFVTX0FDVElPTiwgbGlmZWxpbmVTdGF0dXMpO1xyXG4gIH1cclxuXHJcbiAgaWYoIWxpZmVsaW5lU3RhdHVzZXMgfHwgbGlmZWxpbmVTdGF0dXNlcy5sZW5ndGggPT0gMCl7ICAgXHJcbiAgICByZXR1cm4gPGg1IHN0eWxlPXt7cG9zaXRpb246ICdhYnNvbHV0ZScsIGxlZnQ6ICc0MCUnLCB0b3A6ICc1MCUnfX0+Tm8gRGF0YTwvaDU+XHJcbiAgfVxyXG4gIHJldHVybiAoXHJcbiAgICA8ZGl2IGNsYXNzTmFtZT1cIndpZGdldC1zZWxlY3QtbGlmZWxpbmVzIGppbXUtd2lkZ2V0XCI+XHJcbiAgICAgIDxzdHlsZT5cclxuICAgICAgICB7XHJcbiAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAud2lkZ2V0LXNlbGVjdC1saWZlbGluZXN7XHJcbiAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgaGVpZ2h0OiAxMDAlO1xyXG4gICAgICAgICAgICAgIHBhZGRpbmc6IDEwcHg7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgLnNlbGVjdC1saWZlbGluZS1jb250YWluZXJ7XHJcbiAgICAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICAgICBoZWlnaHQ6IDEwMCU7XHJcbiAgICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47XHJcbiAgICAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7XHJcbiAgICAgICAgICAgICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7XHJcbiAgICAgICAgICAgICAgIG92ZXJmbG93LXk6IGF1dG87XHJcbiAgICAgICAgICAgICAgIG92ZXJmbG93LXg6IGhpZGRlbjtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAubGlmZWxpbmVzLWhlYWRlcntcclxuICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICAgIGp1c3RpZnktY29udGVudDogY2VudGVyO1xyXG4gICAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7XHJcbiAgICAgICAgICAgICAgcGFkZGluZzogMTBweCAwO1xyXG4gICAgICAgICAgICAgIGZvbnQtc2l6ZTogMS4ycmVtO1xyXG4gICAgICAgICAgICAgIGZvbnQtd2VpZ2h0OiBib2xkOyAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgYm9yZGVyLXJhZGl1czogMTBweCAxMHB4IDAgMDtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAubGlmZWxpbmV7XHJcbiAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgY3Vyc29yOiBwb2ludGVyOyAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgIHRleHQtYWxpZ246IGNlbnRlcjtcclxuICAgICAgICAgICAgICBmb250LXNpemU6IDIuNWVtO1xyXG4gICAgICAgICAgICAgIHBhZGRpbmc6IDAuMmVtIDBcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAubGlmZWxpbmU6aG92ZXJ7XHJcbiAgICAgICAgICAgICAgb3BhY2l0eTogMC41O1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIC5saWZlbGluZSBsYWJlbHtcclxuICAgICAgICAgICAgICBjdXJzb3I6IHBvaW50ZXI7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgLmJhY2stdGVtcGxhdGVzLWJ1dHRvbnsgICAgXHJcbiAgICAgICAgICAgICAgcG9zaXRpb246IGFic29sdXRlO1xyXG4gICAgICAgICAgICAgIGJvdHRvbTogMTBweDtcclxuICAgICAgICAgICAgICBsZWZ0OiAwOyAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgaGVpZ2h0OiA2NXB4O1xyXG4gICAgICAgICAgICAgIHdpZHRoOiA4NSU7XHJcbiAgICAgICAgICAgICAgZm9udC13ZWlnaHQ6IGJvbGQ7XHJcbiAgICAgICAgICAgICAgZm9udC1zaXplOiAxLjVlbTtcclxuICAgICAgICAgICAgICBib3JkZXItcmFkaXVzOiA1cHg7XHJcbiAgICAgICAgICAgICAgbGluZS1oZWlnaHQ6IDEuNWVtO1xyXG4gICAgICAgICAgICAgIG1hcmdpbjogMTBweCAxOHB4IDEwcHggMThweDtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAuYmFjay10ZW1wbGF0ZXMtYnV0dG9uOmhvdmVye1xyXG4gICAgICAgICAgICAgICBvcGFjaXR5OiAwLjhcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAuc2VsZWN0ZWQtYXNzZXNzbWVudHtcclxuICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47XHJcbiAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjtcclxuICAgICAgICAgICAgICBtYXJnaW4tdG9wOiA1ZW07XHJcbiAgICAgICAgICAgICAgY29sb3I6ICM5YTlhOWE7XHJcbiAgICAgICAgICAgICAgYm9yZGVyLXRvcDogMXB4IHNvbGlkO1xyXG4gICAgICAgICAgICAgIHBhZGRpbmctdG9wOiAyMHB4O1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIC5zZWxlY3RlZC1hc3Nlc3NtZW50IGgyLFxyXG4gICAgICAgICAgICAuc2VsZWN0ZWQtYXNzZXNzbWVudCBoMyxcclxuICAgICAgICAgICAgLnNlbGVjdGVkLWFzc2Vzc21lbnQtdG9wIGgyLFxyXG4gICAgICAgICAgICAuc2VsZWN0ZWQtYXNzZXNzbWVudC10b3AgaDMge1xyXG4gICAgICAgICAgICAgIGNvbG9yOiAjOWE5YTlhO1xyXG4gICAgICAgICAgICAgIG1hcmdpbjogMDtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAuc2VsZWN0ZWQtYXNzZXNzbWVudC10b3B7XHJcbiAgICAgICAgICAgICAgY29sb3I6ICM5YTlhOWE7XHJcbiAgICAgICAgICAgICAgbWFyZ2luOiAwO1xyXG4gICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjtcclxuICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgICBhbGlnbi1pdGVtczogY2VudGVyOyAgIFxyXG4gICAgICAgICAgICAgIGJvcmRlci1ib3R0b206IDFweCBzb2xpZDtcclxuICAgICAgICAgICAgICBwYWRkaW5nLXRvcDogMjBweDtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgIGBcclxuICAgICAgICB9XHJcbiAgICAgIDwvc3R5bGU+XHJcbiAgICAgIDxkaXYgY2xhc3NOYW1lPVwic2VsZWN0LWxpZmVsaW5lLWNvbnRhaW5lclwiIHN0eWxlPXt7XHJcbiAgICAgICAgYmFja2dyb3VuZENvbG9yOiAgcHJvcHMuY29uZmlnLmJhY2tncm91bmRDb2xvcn19PlxyXG4gICAgICAgIFxyXG4gICAgICAgIDxMYWJlbCBjaGVjayBjbGFzc05hbWU9J2xpZmVsaW5lcy1oZWFkZXInXHJcbiAgICAgICAgICBzdHlsZT17e2JhY2tncm91bmRDb2xvcjogcHJvcHMuY29uZmlnLmJhY2tncm91bmRDb2xvcixcclxuICAgICAgICAgIGNvbG9yOiBwcm9wcy5jb25maWcuZm9udENvbG9yfX0+XHJcbiAgICAgICAgICAgQXNzZXNzbWVudFxyXG4gICAgICAgIDwvTGFiZWw+XHJcbiAgICAgICAgPGgyIHN0eWxlPXt7XHJcbiAgICAgICAgICBjb2xvcjogJyNiNmI2YjYnLFxyXG4gICAgICAgICAgbWFyZ2luVG9wOiAnLTE1cHgnLFxyXG4gICAgICAgICAgZm9udFNpemU6ICcyMXB4J1xyXG4gICAgICAgICAgfX0+e3NlbGVjdGVkQXNzZXNzbWVudD8ubmFtZX08L2gyPlxyXG5cclxuICAgICAgICB7LyogPExhYmVsIGNoZWNrIGNsYXNzTmFtZT0nbGlmZWxpbmVzLWhlYWRlcidcclxuICAgICAgICAgIHN0eWxlPXt7YmFja2dyb3VuZENvbG9yOiBwcm9wcy5jb25maWcuYmFja2dyb3VuZENvbG9yLFxyXG4gICAgICAgICAgY29sb3I6IHByb3BzLmNvbmZpZy5mb250Q29sb3IsXHJcbiAgICAgICAgICBtYXJnaW5Ub3A6ICctMTVweCd9fT5cclxuICAgICAgICAgICBBc3Nlc3NtZW50IFN0YXR1c1xyXG4gICAgICAgIDwvTGFiZWw+XHJcbiAgICAgICAgPGgyIHN0eWxlPXt7XHJcbiAgICAgICAgICBjb2xvcjogJ3JnYigxMzksIDEzOSwgMTM5KScsXHJcbiAgICAgICAgICBtYXJnaW5Ub3A6ICctMTVweCcsXHJcbiAgICAgICAgICBmb250U2l6ZTogJzIxcHgnLCAgICAgICAgICAgXHJcbiAgICAgICAgICB9fT57c2VsZWN0ZWRBc3Nlc3NtZW50Py5pc0NvbXBsZXRlZCA/ICdDb21wbGV0ZWQnOiAnSW4gUHJvZ3Jlc3MnfTwvaDI+ICovfVxyXG5cclxuICAgICAgICA8TGFiZWwgY2hlY2sgY2xhc3NOYW1lPSdsaWZlbGluZXMtaGVhZGVyJ1xyXG4gICAgICAgICAgc3R5bGU9e3tiYWNrZ3JvdW5kQ29sb3I6IHByb3BzLmNvbmZpZy5iYWNrZ3JvdW5kQ29sb3IsXHJcbiAgICAgICAgICBjb2xvcjogcHJvcHMuY29uZmlnLmZvbnRDb2xvciwgYm9yZGVyVG9wOiAnMXB4IHNvbGlkIHdoaXRlJ319PlxyXG4gICAgICAgICAgIExpZmVsaW5lc1xyXG4gICAgICAgIDwvTGFiZWw+XHJcbiAgICAgICAge1xyXG4gICAgICAgICAgbGlmZWxpbmVTdGF0dXNlcz8ubWFwKChsaWZlbGluZVN0YXR1czogTGlmZWxpbmVTdGF0dXMpID0+IHtcclxuICAgICAgICAgICAgcmV0dXJuIChcclxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPSdsaWZlbGluZScga2V5PXtsaWZlbGluZVN0YXR1cy5pZH0gc3R5bGU9e3tcclxuICAgICAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogc2VsZWN0ZWRMaWZlbGluZVN0YXR1cz8uaWQgPT09IGxpZmVsaW5lU3RhdHVzLmlkID8gcHJvcHMuY29uZmlnLnNlbGVjdGVkQmFja2dyb3VuZENvbG9yIDogJ3RyYW5zcGFyZW50J1xyXG4gICAgICAgICAgICAgICAgfX0gb25DbGljaz17KCkgPT4gc2VsZWN0TGlmZWxpbmVTdGF0dXMobGlmZWxpbmVTdGF0dXMpfT5cclxuICAgICAgICAgICAgICAgICAgICA8TGFiZWwgc2l6ZT0nbGcnIHN0eWxlPXt7Y29sb3I6IHByb3BzLmNvbmZpZy5mb250Q29sb3J9fT5cclxuICAgICAgICAgICAgICAgICAgICAgIHtsaWZlbGluZVN0YXR1cy5saWZlbGluZU5hbWV9XHJcbiAgICAgICAgICAgICAgICAgICAgPC9MYWJlbD5cclxuICAgICAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgICAgICApXHJcbiAgICAgICAgICB9KVxyXG4gICAgICAgIH0gICAgICAgICAgICAgIFxyXG4gICAgICA8L2Rpdj4gICAgIFxyXG4gICAgPC9kaXY+XHJcbiAgKVxyXG59XHJcbmV4cG9ydCBkZWZhdWx0IFdpZGdldFxyXG4iXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=