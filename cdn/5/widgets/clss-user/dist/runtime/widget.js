System.register(["jimu-core","jimu-ui","jimu-core/react-dom","jimu-arcgis"], function(__WEBPACK_DYNAMIC_EXPORT__, __system_context__) {
	var __WEBPACK_EXTERNAL_MODULE_jimu_core__ = {};
	var __WEBPACK_EXTERNAL_MODULE_jimu_ui__ = {};
	var __WEBPACK_EXTERNAL_MODULE_react_dom__ = {};
	var __WEBPACK_EXTERNAL_MODULE_jimu_arcgis__ = {};
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_jimu_core__, "__esModule", { value: true });
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_jimu_ui__, "__esModule", { value: true });
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_react_dom__, "__esModule", { value: true });
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
					__WEBPACK_EXTERNAL_MODULE_react_dom__[key] = module[key];
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

/***/ "./jimu-icons/svg/filled/application/person.svg":
/*!******************************************************!*\
  !*** ./jimu-icons/svg/filled/application/person.svg ***!
  \******************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M13.374 12.465A6.994 6.994 0 1 0 1 8a6.95 6.95 0 0 0 1.626 4.465l-.01.008c.034.042.075.078.11.12.046.051.094.1.14.15.14.152.284.298.435.435.046.042.094.08.14.12.16.139.325.27.496.392.022.015.042.034.063.05v-.006a6.95 6.95 0 0 0 8 0v.006c.023-.016.042-.035.065-.05.17-.123.335-.253.495-.391l.14-.121a7 7 0 0 0 .434-.435c.047-.05.095-.099.14-.15.036-.042.077-.078.112-.12l-.011-.008ZM8 4a2.25 2.25 0 1 1 0 4.5A2.25 2.25 0 0 1 8 4Zm-3.997 8.465A2.498 2.498 0 0 1 6.5 10h3a2.498 2.498 0 0 1 2.496 2.465 5.97 5.97 0 0 1-7.993 0Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/outlined/editor/close.svg":
/*!**************************************************!*\
  !*** ./jimu-icons/svg/outlined/editor/close.svg ***!
  \**************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"m8.745 8 6.1 6.1a.527.527 0 1 1-.745.746L8 8.746l-6.1 6.1a.527.527 0 1 1-.746-.746l6.1-6.1-6.1-6.1a.527.527 0 0 1 .746-.746l6.1 6.1 6.1-6.1a.527.527 0 0 1 .746.746L8.746 8Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/filled/application/person.tsx":
/*!**************************************************!*\
  !*** ./jimu-icons/filled/application/person.tsx ***!
  \**************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "PersonFilled": () => (/* binding */ PersonFilled)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_filled_application_person_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/filled/application/person.svg */ "./jimu-icons/svg/filled/application/person.svg");
/* harmony import */ var _svg_filled_application_person_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_filled_application_person_svg__WEBPACK_IMPORTED_MODULE_1__);
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


const PersonFilled = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_filled_application_person_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
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

/***/ "react-dom":
/*!**************************************!*\
  !*** external "jimu-core/react-dom" ***!
  \**************************************/
/***/ ((module) => {

"use strict";
module.exports = __WEBPACK_EXTERNAL_MODULE_react_dom__;

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
/*!******************************************************************!*\
  !*** ./your-extensions/widgets/clss-user/src/runtime/widget.tsx ***!
  \******************************************************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "UserBox": () => (/* binding */ UserBox),
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var jimu_icons_filled_application_person__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-icons/filled/application/person */ "./jimu-icons/filled/application/person.tsx");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var jimu_icons_outlined_editor_close__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! jimu-icons/outlined/editor/close */ "./jimu-icons/outlined/editor/close.tsx");
/* harmony import */ var react_dom__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! react-dom */ "react-dom");
/* harmony import */ var _clss_application_src_extensions_auth__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../clss-application/src/extensions/auth */ "./your-extensions/widgets/clss-application/src/extensions/auth.ts");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};






const UserBox = ({ username, fullName, closeMe, authenticate, theme }) => {
    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { id: "userPopup", style: { backgroundColor: '#004d8a',
            boxShadow: theme.boxShadows.lg }, className: 'popup-container' },
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("style", null, `
            .popup-container{
              display: block;
              position: absolute;
              color: white;
              padding: 20px;
              width: 300px;            
              z-index: 100;
              right: 10px;
              top: 60px;
            }
            .close-icon{
               position: absolute;
               right: 5px;
               top: 5px;
               cursor: pointer;
            }
            .user{
              display: flex;
              width: 100%;
              align-items: center;
              border-bottom: 1px solid white;
              padding: 10px 0;
            }
            .user-name{
              color: white;
              font-size: 18px;
            }
            .actions {
              padding: 20px;
              width: 100%;
            }
            .sign-in-out{
              color: white;
              font-size: 18px;
              cursor: pointer;
            }
            .sign-in-out:hover{
              text-decoration-line: underline;
            }`),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_icons_outlined_editor_close__WEBPACK_IMPORTED_MODULE_3__.CloseOutlined, { onClick: closeMe, size: 20, className: "close-icon", color: '#d7d8d8' }),
        username ?
            (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: 'user' },
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_icons_filled_application_person__WEBPACK_IMPORTED_MODULE_1__.PersonFilled, { style: { flex: 1 }, size: 60 }),
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_2__.Label, { className: 'user-name', check: true, style: { flex: 2 } },
                    fullName,
                    `\n${username}`))) : null,
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "actions" },
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_2__.Label, { className: 'sign-in-out', check: true, onClick: authenticate }, username ? 'Sign Out' : 'Sign In'))));
};
const Widget = (props) => {
    const [isUserBoxVisible, showUserBox] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        (0,_clss_application_src_extensions_auth__WEBPACK_IMPORTED_MODULE_5__.signIn)(props.config.appId, 'https://www.arcgis.com');
    }, []);
    const closeUserBox = () => {
        const el = document.getElementById('userBoxElement');
        if (el) {
            el.remove();
            document.removeEventListener('click', function (e) { });
            showUserBox(false);
        }
    };
    const logout = () => __awaiter(void 0, void 0, void 0, function* () {
        yield (0,_clss_application_src_extensions_auth__WEBPACK_IMPORTED_MODULE_5__.signOut)(props.config.appId, 'https://www.arcgis.com');
        location.replace('https://www.arcgis.com');
        //location.reload(); 
    });
    const showPopup = () => {
        var _a, _b;
        if (isUserBoxVisible) {
            closeUserBox();
            return;
        }
        var userBoxElement = document.createElement("DIV");
        userBoxElement.setAttribute('id', 'userBoxElement');
        react_dom__WEBPACK_IMPORTED_MODULE_4__["default"].render(jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(UserBox, { fullName: (_a = props === null || props === void 0 ? void 0 : props.user) === null || _a === void 0 ? void 0 : _a.fullName, username: (_b = props === null || props === void 0 ? void 0 : props.user) === null || _b === void 0 ? void 0 : _b.username, theme: props.theme, closeMe: () => closeUserBox(), authenticate: () => logout() }), document.body.appendChild(userBoxElement));
        showUserBox(true);
    };
    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: 'jimu-widget widget-container', style: { background: props.config.backgroundColor } },
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("style", null, `
          .widget-container{
            display: flex;
            justify-content: center;
            align-items: center;
          }
          .greeting-icon{
            width: 80px;
            cursor: pointer;
          }
          
        `),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_icons_filled_application_person__WEBPACK_IMPORTED_MODULE_1__.PersonFilled, { className: 'greeting-icon', onClick: () => showPopup(), size: props.config.iconSize, color: "white" })));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (Widget);

})();

/******/ 	return __webpack_exports__;
/******/ })()

			);
		}
	};
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2lkZ2V0cy9jbHNzLXVzZXIvZGlzdC9ydW50aW1lL3dpZGdldC5qcyIsIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNBNkM7QUFFWTtBQUVsRCxNQUFNLFlBQVksR0FBRyxDQUFDLEtBQXdCLEVBQUUsRUFBRTtJQUN2RCxNQUFNLEdBQUcsR0FBRyxNQUFNLENBQUMsR0FBRztJQUN0QixNQUFNLEVBQUUsU0FBUyxLQUFnQixLQUFLLEVBQWhCLE1BQU0sVUFBSyxLQUFLLEVBQWhDLGFBQXdCLENBQVE7SUFFdEMsTUFBTSxPQUFPLEdBQUcscURBQVUsQ0FBQywrQkFBK0IsRUFBRSxTQUFTLENBQUM7SUFDdEUsSUFBSSxDQUFDLEdBQUc7UUFBRSxPQUFPLGtGQUFLLFNBQVMsRUFBRSxPQUFPLElBQU0sTUFBYSxFQUFJO0lBQy9ELE9BQU8sMkRBQUMsR0FBRyxrQkFBQyxTQUFTLEVBQUUsT0FBTyxFQUFFLEdBQUcsRUFBRSwyRUFBRyxJQUFNLE1BQU0sRUFBSTtBQUMxRCxDQUFDOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNYNEM7QUFFUTtBQUU5QyxNQUFNLGFBQWEsR0FBRyxDQUFDLEtBQXdCLEVBQUUsRUFBRTtJQUN4RCxNQUFNLEdBQUcsR0FBRyxNQUFNLENBQUMsR0FBRztJQUN0QixNQUFNLEVBQUUsU0FBUyxLQUFnQixLQUFLLEVBQWhCLE1BQU0sVUFBSyxLQUFLLEVBQWhDLGFBQXdCLENBQVE7SUFFdEMsTUFBTSxPQUFPLEdBQUcscURBQVUsQ0FBQywrQkFBK0IsRUFBRSxTQUFTLENBQUM7SUFDdEUsSUFBSSxDQUFDLEdBQUc7UUFBRSxPQUFPLGtGQUFLLFNBQVMsRUFBRSxPQUFPLElBQU0sTUFBYSxFQUFJO0lBQy9ELE9BQU8sMkRBQUMsR0FBRyxrQkFBQyxTQUFTLEVBQUUsT0FBTyxFQUFFLEdBQUcsRUFBRSx1RUFBRyxJQUFNLE1BQU0sRUFBSTtBQUMxRCxDQUFDOzs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDWEQsNkVBQTZFOzs7Ozs7Ozs7O0FBRXhCO0FBRXJEOzs7OztHQUtHO0FBQ0ksTUFBTSxNQUFNLEdBQUcsQ0FBTyxLQUFhLEVBQUUsU0FBaUIsRUFBRSxFQUFFO0lBQzdELElBQUk7UUFDQSxPQUFPLE1BQU0sa0JBQWtCLENBQUMsS0FBSyxFQUFFLFNBQVMsQ0FBQyxDQUFDO0tBQ3JEO0lBQUMsT0FBTyxLQUFLLEVBQUU7UUFDWixPQUFPLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQ25CLE9BQU8sTUFBTSxnQkFBZ0IsQ0FBQyxLQUFLLEVBQUUsU0FBUyxDQUFDLENBQUM7S0FDbkQ7QUFDTCxDQUFDLEVBQUM7QUFFRjs7OztHQUlHO0FBQ0ksTUFBTSxPQUFPLEdBQUcsQ0FBTyxLQUFhLEVBQUUsU0FBaUIsRUFBRSxFQUFFO0lBQzlELE1BQU0sZUFBZSxHQUFHLE1BQU0sV0FBVyxDQUFDLEtBQUssRUFBRSxTQUFTLENBQUMsQ0FBQztJQUM1RCxNQUFNLE1BQU0sQ0FBQyxLQUFLLEVBQUUsU0FBUyxDQUFDLENBQUM7SUFFL0IsT0FBTyxNQUFNLENBQUMsaUJBQWlCLENBQUMsQ0FBQztJQUNqQyxPQUFPLE1BQU0sQ0FBQyxXQUFXLENBQUMsQ0FBQztJQUMzQixlQUFlLENBQUMsa0JBQWtCLEVBQUUsQ0FBQztBQUV6QyxDQUFDLEVBQUM7QUFFRjs7R0FFRztBQUNILFNBQWUsZ0JBQWdCLENBQUMsS0FBYSxFQUFFLFNBQWlCOztRQUM1RCxNQUFNLGVBQWUsR0FBRyxNQUFNLFdBQVcsQ0FBQyxLQUFLLEVBQUUsU0FBUyxDQUFDLENBQUM7UUFDNUQsTUFBTSxVQUFVLEdBQUcsTUFBTSxlQUFlLENBQUMsYUFBYSxDQUFDLEdBQUcsU0FBUyxVQUFVLEVBQUU7WUFDM0UsS0FBSyxFQUFFLElBQVc7WUFDbEIsc0JBQXNCLEVBQUUsS0FBSztZQUM3QixLQUFLLEVBQUUsSUFBVztTQUNyQixDQUFDLENBQUM7UUFDSCxPQUFPLFVBQVUsQ0FBQztJQUN0QixDQUFDO0NBQUE7QUFBQSxDQUFDO0FBRUY7O0dBRUc7QUFDSCxTQUFlLFdBQVcsQ0FBQyxLQUFhLEVBQUUsU0FBaUI7O1FBQ3ZELElBQUksZUFBZSxHQUFHLE1BQU0sQ0FBQyxpQkFBaUIsQ0FBQztRQUMvQyxJQUFHLENBQUMsZUFBZSxFQUFDO1lBQ2hCLE1BQU0sT0FBTyxHQUFHLE1BQU0sbUVBQXNCLENBQUM7Z0JBQ3pDLCtCQUErQjtnQkFDL0IseUJBQXlCO2FBQUMsQ0FBQyxDQUFDO1lBRTVCLE1BQU0sQ0FBQyxpQkFBaUIsQ0FBQyxHQUFHLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUN2QyxNQUFNLENBQUMsV0FBVyxDQUFDLEdBQUcsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBRXJDLGVBQWUsR0FBRyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUM7WUFDN0IsTUFBTSxTQUFTLEdBQUcsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBRTdCLE1BQU0sU0FBUyxHQUFHLElBQUksU0FBUyxDQUFDO2dCQUM1QixLQUFLO2dCQUNMLFNBQVM7Z0JBQ1QsS0FBSyxFQUFFLEtBQUs7YUFDZixDQUFDLENBQUM7WUFDSCxlQUFlLENBQUMsa0JBQWtCLENBQUMsQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDO1NBQ25EO1FBQ0QsT0FBTyxlQUFlLENBQUM7SUFDM0IsQ0FBQztDQUFBO0FBRUQ7O0dBRUc7QUFDSSxNQUFNLGtCQUFrQixHQUFHLENBQU8sS0FBYSxFQUFFLFNBQWlCLEVBQUUsRUFBRTtJQUN6RSxNQUFNLGVBQWUsR0FBRyxNQUFNLFdBQVcsQ0FBQyxLQUFLLEVBQUUsU0FBUyxDQUFDLENBQUM7SUFDNUQsT0FBTyxlQUFlLENBQUMsaUJBQWlCLENBQUMsR0FBRyxTQUFTLFVBQVUsQ0FBQyxDQUFDO0FBQ3JFLENBQUMsRUFBQzs7Ozs7Ozs7Ozs7O0FDL0VGOzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7VUNBQTtVQUNBOztVQUVBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBOztVQUVBO1VBQ0E7O1VBRUE7VUFDQTtVQUNBOzs7OztXQ3RCQTtXQUNBO1dBQ0E7V0FDQTtXQUNBO1dBQ0EsaUNBQWlDLFdBQVc7V0FDNUM7V0FDQTs7Ozs7V0NQQTtXQUNBO1dBQ0E7V0FDQTtXQUNBLHlDQUF5Qyx3Q0FBd0M7V0FDakY7V0FDQTtXQUNBOzs7OztXQ1BBOzs7OztXQ0FBO1dBQ0E7V0FDQTtXQUNBLHVEQUF1RCxpQkFBaUI7V0FDeEU7V0FDQSxnREFBZ0QsYUFBYTtXQUM3RDs7Ozs7V0NOQTs7Ozs7Ozs7OztBQ0FBOzs7S0FHSztBQUNMLDJCQUEyQjtBQUMzQixhQUFhO0FBQ2IscUJBQXVCLEdBQUcsTUFBTSxDQUFDLFVBQVUsQ0FBQyxPQUFPOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNORjtBQUVtQjtBQUN0QztBQUNtQztBQUNoQztBQUMrQztBQUV6RSxNQUFNLE9BQU8sR0FBRyxDQUFDLEVBQUMsUUFBUSxFQUFFLFFBQVEsRUFBRSxPQUFPLEVBQUUsWUFBWSxFQUFFLEtBQUssRUFBQyxFQUFFLEVBQUU7SUFFMUUsT0FBTyxDQUNMLG9FQUFLLEVBQUUsRUFBQyxXQUFXLEVBQUMsS0FBSyxFQUFFLEVBQUMsZUFBZSxFQUFFLFNBQVM7WUFDdEQsU0FBUyxFQUFFLEtBQUssQ0FBQyxVQUFVLENBQUMsRUFBRSxFQUFDLEVBQUcsU0FBUyxFQUFDLGlCQUFpQjtRQUMzRCwwRUFFSTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O2NBdUNFLENBRUU7UUFDWCwyREFBQywyRUFBYSxJQUFDLE9BQU8sRUFBRSxPQUFPLEVBQUUsSUFBSSxFQUFFLEVBQUUsRUFBRSxTQUFTLEVBQUMsWUFBWSxFQUFDLEtBQUssRUFBRSxTQUFTLEdBQUc7UUFFbEYsUUFBUSxDQUFDLENBQUM7WUFDWCxDQUFDLG9FQUFLLFNBQVMsRUFBQyxNQUFNO2dCQUNuQiwyREFBQyw4RUFBWSxJQUFDLEtBQUssRUFBRSxFQUFDLElBQUksRUFBRSxDQUFDLEVBQUMsRUFBRSxJQUFJLEVBQUUsRUFBRSxHQUFHO2dCQUMzQywyREFBQywwQ0FBSyxJQUFDLFNBQVMsRUFBQyxXQUFXLEVBQUMsS0FBSyxRQUFDLEtBQUssRUFBRSxFQUFDLElBQUksRUFBRSxDQUFDLEVBQUM7b0JBQzlDLFFBQVE7b0JBQ1IsS0FBSyxRQUFRLEVBQUUsQ0FDWixDQUNKLENBQUMsRUFBQyxDQUFDLElBQUk7UUFFYixvRUFBSyxTQUFTLEVBQUMsU0FBUztZQUNwQiwyREFBQywwQ0FBSyxJQUFDLFNBQVMsRUFBQyxhQUFhLEVBQUMsS0FBSyxRQUFDLE9BQU8sRUFBRSxZQUFZLElBRXRELFFBQVEsQ0FBQyxDQUFDLENBQUUsVUFBVSxDQUFDLENBQUMsQ0FBRSxTQUFTLENBRS9CLENBQ04sQ0FDTixDQUNIO0FBRUwsQ0FBQztBQUVELE1BQU0sTUFBTSxHQUFHLENBQUMsS0FBK0IsRUFBRSxFQUFFO0lBRWpELE1BQU0sQ0FBQyxnQkFBZ0IsRUFBRSxXQUFXLENBQUMsR0FBRyxxREFBYyxDQUFDLEtBQUssQ0FBQyxDQUFDO0lBRTlELHNEQUFlLENBQUMsR0FBRSxFQUFFO1FBQ2xCLDZFQUFNLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxLQUFLLEVBQUUsd0JBQXdCLENBQUMsQ0FBQztJQUN2RCxDQUFDLEVBQUUsRUFBRSxDQUFDO0lBRU4sTUFBTSxZQUFZLEdBQUUsR0FBRyxFQUFFO1FBQ3ZCLE1BQU0sRUFBRSxHQUFHLFFBQVEsQ0FBQyxjQUFjLENBQUMsZ0JBQWdCLENBQUMsQ0FBQztRQUNyRCxJQUFHLEVBQUUsRUFBQztZQUNKLEVBQUUsQ0FBQyxNQUFNLEVBQUUsQ0FBQztZQUNaLFFBQVEsQ0FBQyxtQkFBbUIsQ0FBQyxPQUFPLEVBQUUsVUFBUyxDQUFDLElBQUUsQ0FBQyxDQUFDLENBQUM7WUFDckQsV0FBVyxDQUFDLEtBQUssQ0FBQyxDQUFDO1NBQ3BCO0lBQ0gsQ0FBQztJQUVELE1BQU0sTUFBTSxHQUFHLEdBQVMsRUFBRTtRQUN4QixNQUFNLDhFQUFPLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxLQUFLLEVBQUUsd0JBQXdCLENBQUMsQ0FBQztRQUM1RCxRQUFRLENBQUMsT0FBTyxDQUFDLHdCQUF3QixDQUFDLENBQUM7UUFDM0MscUJBQXFCO0lBQ3ZCLENBQUM7SUFFRCxNQUFNLFNBQVMsR0FBRyxHQUFHLEVBQUU7O1FBRXJCLElBQUcsZ0JBQWdCLEVBQUM7WUFDbEIsWUFBWSxFQUFFLENBQUM7WUFDZixPQUFPO1NBQ1I7UUFFQSxJQUFJLGNBQWMsR0FBRyxRQUFRLENBQUMsYUFBYSxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQ25ELGNBQWMsQ0FBQyxZQUFZLENBQUMsSUFBSSxFQUFFLGdCQUFnQixDQUFDLENBQUM7UUFFcEQsd0RBQWUsQ0FDWiwyREFBQyxPQUFPLElBQ1IsUUFBUSxFQUFFLFdBQUssYUFBTCxLQUFLLHVCQUFMLEtBQUssQ0FBRSxJQUFJLDBDQUFFLFFBQVEsRUFDL0IsUUFBUSxFQUFFLFdBQUssYUFBTCxLQUFLLHVCQUFMLEtBQUssQ0FBRSxJQUFJLDBDQUFFLFFBQVEsRUFDL0IsS0FBSyxFQUFFLEtBQUssQ0FBQyxLQUFLLEVBQ2xCLE9BQU8sRUFBRSxHQUFHLEVBQUUsQ0FBQyxZQUFZLEVBQUUsRUFDN0IsWUFBWSxFQUFFLEdBQUcsRUFBRSxDQUFDLE1BQU0sRUFBRSxHQUFHLEVBQy9CLFFBQVEsQ0FBQyxJQUFJLENBQUMsV0FBVyxDQUFDLGNBQWMsQ0FBQyxDQUMxQztRQUNGLFdBQVcsQ0FBQyxJQUFJLENBQUMsQ0FBQztJQUNyQixDQUFDO0lBRUQsT0FBTyxDQUNMLG9FQUFLLFNBQVMsRUFBQyw4QkFBOEIsRUFDM0MsS0FBSyxFQUFFLEVBQUMsVUFBVSxFQUFFLEtBQUssQ0FBQyxNQUFNLENBQUMsZUFBZSxFQUFDO1FBQ2hELDBFQUNFOzs7Ozs7Ozs7OztTQVdBLENBQ0s7UUFDTiwyREFBQyw4RUFBWSxJQUFDLFNBQVMsRUFBQyxlQUFlLEVBQ3JDLE9BQU8sRUFBRSxHQUFFLEVBQUUsQ0FBQyxTQUFTLEVBQUUsRUFDekIsSUFBSSxFQUFFLEtBQUssQ0FBQyxNQUFNLENBQUMsUUFBUSxFQUMzQixLQUFLLEVBQUUsT0FBTyxHQUNkLENBQ0MsQ0FDUjtBQUNILENBQUM7QUFFRCxpRUFBZSxNQUFNIiwic291cmNlcyI6WyJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvc3ZnL2ZpbGxlZC9hcHBsaWNhdGlvbi9wZXJzb24uc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL3N2Zy9vdXRsaW5lZC9lZGl0b3IvY2xvc2Uuc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL2ZpbGxlZC9hcHBsaWNhdGlvbi9wZXJzb24udHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL291dGxpbmVkL2VkaXRvci9jbG9zZS50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXV0aC50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtYXJjZ2lzXCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC9leHRlcm5hbCBzeXN0ZW0gXCJqaW11LWNvcmVcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtY29yZS9yZWFjdC1kb21cIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtdWlcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svYm9vdHN0cmFwIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL2NvbXBhdCBnZXQgZGVmYXVsdCBleHBvcnQiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvZGVmaW5lIHByb3BlcnR5IGdldHRlcnMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvaGFzT3duUHJvcGVydHkgc2hvcnRoYW5kIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL21ha2UgbmFtZXNwYWNlIG9iamVjdCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9wdWJsaWNQYXRoIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWNvcmUvbGliL3NldC1wdWJsaWMtcGF0aC50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy11c2VyL3NyYy9ydW50aW1lL3dpZGdldC50c3giXSwic291cmNlc0NvbnRlbnQiOlsibW9kdWxlLmV4cG9ydHMgPSBcIjxzdmcgdmlld0JveD1cXFwiMCAwIDE2IDE2XFxcIiBmaWxsPVxcXCJub25lXFxcIiB4bWxucz1cXFwiaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmdcXFwiPjxwYXRoIGQ9XFxcIk0xMy4zNzQgMTIuNDY1QTYuOTk0IDYuOTk0IDAgMSAwIDEgOGE2Ljk1IDYuOTUgMCAwIDAgMS42MjYgNC40NjVsLS4wMS4wMDhjLjAzNC4wNDIuMDc1LjA3OC4xMS4xMi4wNDYuMDUxLjA5NC4xLjE0LjE1LjE0LjE1Mi4yODQuMjk4LjQzNS40MzUuMDQ2LjA0Mi4wOTQuMDguMTQuMTIuMTYuMTM5LjMyNS4yNy40OTYuMzkyLjAyMi4wMTUuMDQyLjAzNC4wNjMuMDV2LS4wMDZhNi45NSA2Ljk1IDAgMCAwIDggMHYuMDA2Yy4wMjMtLjAxNi4wNDItLjAzNS4wNjUtLjA1LjE3LS4xMjMuMzM1LS4yNTMuNDk1LS4zOTFsLjE0LS4xMjFhNyA3IDAgMCAwIC40MzQtLjQzNWMuMDQ3LS4wNS4wOTUtLjA5OS4xNC0uMTUuMDM2LS4wNDIuMDc3LS4wNzguMTEyLS4xMmwtLjAxMS0uMDA4Wk04IDRhMi4yNSAyLjI1IDAgMSAxIDAgNC41QTIuMjUgMi4yNSAwIDAgMSA4IDRabS0zLjk5NyA4LjQ2NUEyLjQ5OCAyLjQ5OCAwIDAgMSA2LjUgMTBoM2EyLjQ5OCAyLjQ5OCAwIDAgMSAyLjQ5NiAyLjQ2NSA1Ljk3IDUuOTcgMCAwIDEtNy45OTMgMFpcXFwiIGZpbGw9XFxcIiMwMDBcXFwiPjwvcGF0aD48L3N2Zz5cIiIsIm1vZHVsZS5leHBvcnRzID0gXCI8c3ZnIHZpZXdCb3g9XFxcIjAgMCAxNiAxNlxcXCIgZmlsbD1cXFwibm9uZVxcXCIgeG1sbnM9XFxcImh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnXFxcIj48cGF0aCBkPVxcXCJtOC43NDUgOCA2LjEgNi4xYS41MjcuNTI3IDAgMSAxLS43NDUuNzQ2TDggOC43NDZsLTYuMSA2LjFhLjUyNy41MjcgMCAxIDEtLjc0Ni0uNzQ2bDYuMS02LjEtNi4xLTYuMWEuNTI3LjUyNyAwIDAgMSAuNzQ2LS43NDZsNi4xIDYuMSA2LjEtNi4xYS41MjcuNTI3IDAgMCAxIC43NDYuNzQ2TDguNzQ2IDhaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PC9zdmc+XCIiLCJpbXBvcnQgeyBSZWFjdCwgY2xhc3NOYW1lcyB9IGZyb20gJ2ppbXUtY29yZSdcclxuaW1wb3J0IHsgdHlwZSBTVkdDb21wb25lbnRQcm9wcyB9IGZyb20gJ2ppbXUtdWknXHJcbmltcG9ydCBzcmMgZnJvbSAnLi4vLi4vc3ZnL2ZpbGxlZC9hcHBsaWNhdGlvbi9wZXJzb24uc3ZnJ1xyXG5cclxuZXhwb3J0IGNvbnN0IFBlcnNvbkZpbGxlZCA9IChwcm9wczogU1ZHQ29tcG9uZW50UHJvcHMpID0+IHtcclxuICBjb25zdCBTVkcgPSB3aW5kb3cuU1ZHXHJcbiAgY29uc3QgeyBjbGFzc05hbWUsIC4uLm90aGVycyB9ID0gcHJvcHNcclxuXHJcbiAgY29uc3QgY2xhc3NlcyA9IGNsYXNzTmFtZXMoJ2ppbXUtaWNvbiBqaW11LWljb24tY29tcG9uZW50JywgY2xhc3NOYW1lKVxyXG4gIGlmICghU1ZHKSByZXR1cm4gPHN2ZyBjbGFzc05hbWU9e2NsYXNzZXN9IHsuLi5vdGhlcnMgYXMgYW55fSAvPlxyXG4gIHJldHVybiA8U1ZHIGNsYXNzTmFtZT17Y2xhc3Nlc30gc3JjPXtzcmN9IHsuLi5vdGhlcnN9IC8+XHJcbn1cclxuIiwiaW1wb3J0IHsgUmVhY3QsIGNsYXNzTmFtZXMgfSBmcm9tICdqaW11LWNvcmUnXHJcbmltcG9ydCB7IHR5cGUgU1ZHQ29tcG9uZW50UHJvcHMgfSBmcm9tICdqaW11LXVpJ1xyXG5pbXBvcnQgc3JjIGZyb20gJy4uLy4uL3N2Zy9vdXRsaW5lZC9lZGl0b3IvY2xvc2Uuc3ZnJ1xyXG5cclxuZXhwb3J0IGNvbnN0IENsb3NlT3V0bGluZWQgPSAocHJvcHM6IFNWR0NvbXBvbmVudFByb3BzKSA9PiB7XHJcbiAgY29uc3QgU1ZHID0gd2luZG93LlNWR1xyXG4gIGNvbnN0IHsgY2xhc3NOYW1lLCAuLi5vdGhlcnMgfSA9IHByb3BzXHJcblxyXG4gIGNvbnN0IGNsYXNzZXMgPSBjbGFzc05hbWVzKCdqaW11LWljb24gamltdS1pY29uLWNvbXBvbmVudCcsIGNsYXNzTmFtZSlcclxuICBpZiAoIVNWRykgcmV0dXJuIDxzdmcgY2xhc3NOYW1lPXtjbGFzc2VzfSB7Li4ub3RoZXJzIGFzIGFueX0gLz5cclxuICByZXR1cm4gPFNWRyBjbGFzc05hbWU9e2NsYXNzZXN9IHNyYz17c3JjfSB7Li4ub3RoZXJzfSAvPlxyXG59XHJcbiIsIi8vQWRhcHRlZCBmcm9tIC8vaHR0cHM6Ly9naXRodWIuY29tL29kb2UvbWFwLXZ1ZS9ibG9iL21hc3Rlci9zcmMvZGF0YS9hdXRoLnRzXHJcblxyXG5pbXBvcnQgeyBsb2FkQXJjR0lTSlNBUElNb2R1bGVzIH0gZnJvbSBcImppbXUtYXJjZ2lzXCI7XHJcblxyXG4vKipcclxuICogQXR0ZW1wdCB0byBzaWduIGluLFxyXG4gKiBmaXJzdCBjaGVjayBjdXJyZW50IHN0YXR1c1xyXG4gKiBpZiBub3Qgc2lnbmVkIGluLCB0aGVuIGdvIHRocm91Z2hcclxuICogc3RlcHMgdG8gZ2V0IGNyZWRlbnRpYWxzXHJcbiAqL1xyXG5leHBvcnQgY29uc3Qgc2lnbkluID0gYXN5bmMgKGFwcElkOiBzdHJpbmcsIHBvcnRhbFVybDogc3RyaW5nKSA9PiB7XHJcbiAgICB0cnkge1xyXG4gICAgICAgIHJldHVybiBhd2FpdCBjaGVja0N1cnJlbnRTdGF0dXMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICB9IGNhdGNoIChlcnJvcikge1xyXG4gICAgICAgIGNvbnNvbGUubG9nKGVycm9yKTtcclxuICAgICAgICByZXR1cm4gYXdhaXQgZmV0Y2hDcmVkZW50aWFscyhhcHBJZCwgcG9ydGFsVXJsKTtcclxuICAgIH1cclxufTtcclxuXHJcbi8qKlxyXG4gKiBTaWduIHRoZSB1c2VyIG91dCwgYnV0IGlmIHdlIGNoZWNrZWQgY3JlZGVudGlhbHNcclxuICogbWFudWFsbHksIG1ha2Ugc3VyZSB0aGV5IGFyZSByZWdpc3RlcmVkIHdpdGhcclxuICogSWRlbnRpdHlNYW5hZ2VyLCBzbyBpdCBjYW4gZGVzdHJveSB0aGVtIHByb3Blcmx5XHJcbiAqL1xyXG5leHBvcnQgY29uc3Qgc2lnbk91dCA9IGFzeW5jIChhcHBJZDogc3RyaW5nLCBwb3J0YWxVcmw6IHN0cmluZykgPT4ge1xyXG4gICAgY29uc3QgSWRlbnRpdHlNYW5hZ2VyID0gYXdhaXQgbG9hZE1vZHVsZXMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICBhd2FpdCBzaWduSW4oYXBwSWQsIHBvcnRhbFVybCk7XHJcblxyXG4gICAgZGVsZXRlIHdpbmRvd1snSWRlbnRpdHlNYW5hZ2VyJ107XHJcbiAgICBkZWxldGUgd2luZG93WydPQXV0aEluZm8nXTtcclxuICAgIElkZW50aXR5TWFuYWdlci5kZXN0cm95Q3JlZGVudGlhbHMoKTtcclxuICAgIFxyXG59O1xyXG5cclxuLyoqXHJcbiAqIEdldCB0aGUgY3JlZGVudGlhbHMgZm9yIHRoZSBwcm92aWRlZCBwb3J0YWxcclxuICovXHJcbmFzeW5jIGZ1bmN0aW9uIGZldGNoQ3JlZGVudGlhbHMoYXBwSWQ6IHN0cmluZywgcG9ydGFsVXJsOiBzdHJpbmcpe1xyXG4gICAgY29uc3QgSWRlbnRpdHlNYW5hZ2VyID0gYXdhaXQgbG9hZE1vZHVsZXMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICBjb25zdCBjcmVkZW50aWFsID0gYXdhaXQgSWRlbnRpdHlNYW5hZ2VyLmdldENyZWRlbnRpYWwoYCR7cG9ydGFsVXJsfS9zaGFyaW5nYCwge1xyXG4gICAgICAgIGVycm9yOiBudWxsIGFzIGFueSxcclxuICAgICAgICBvQXV0aFBvcHVwQ29uZmlybWF0aW9uOiBmYWxzZSxcclxuICAgICAgICB0b2tlbjogbnVsbCBhcyBhbnlcclxuICAgIH0pO1xyXG4gICAgcmV0dXJuIGNyZWRlbnRpYWw7XHJcbn07XHJcblxyXG4vKipcclxuICogSW1wb3J0IElkZW50aXR5IE1hbmFnZXIsIGFuZCBPQXV0aEluZm9cclxuICovXHJcbmFzeW5jIGZ1bmN0aW9uIGxvYWRNb2R1bGVzKGFwcElkOiBzdHJpbmcsIHBvcnRhbFVybDogc3RyaW5nKSB7XHJcbiAgICBsZXQgSWRlbnRpdHlNYW5hZ2VyID0gd2luZG93WydJZGVudGl0eU1hbmFnZXInXVxyXG4gICAgaWYoIUlkZW50aXR5TWFuYWdlcil7XHJcbiAgICAgICAgY29uc3QgbW9kdWxlcyA9IGF3YWl0IGxvYWRBcmNHSVNKU0FQSU1vZHVsZXMoW1xyXG4gICAgICAgICAgICAnZXNyaS9pZGVudGl0eS9JZGVudGl0eU1hbmFnZXInLFxyXG4gICAgICAgICAgICAnZXNyaS9pZGVudGl0eS9PQXV0aEluZm8nXSk7XHJcblxyXG4gICAgICAgICAgICB3aW5kb3dbJ0lkZW50aXR5TWFuYWdlciddID0gbW9kdWxlc1swXTtcclxuICAgICAgICAgICAgd2luZG93WydPQXV0aEluZm8nXSA9IG1vZHVsZXNbMV07XHJcbiAgICAgICAgICAgIFxyXG4gICAgICAgIElkZW50aXR5TWFuYWdlciA9IG1vZHVsZXNbMF07XHJcbiAgICAgICAgY29uc3QgT0F1dGhJbmZvID0gbW9kdWxlc1sxXTtcclxuXHJcbiAgICAgICAgY29uc3Qgb2F1dGhJbmZvID0gbmV3IE9BdXRoSW5mbyh7XHJcbiAgICAgICAgICAgIGFwcElkLFxyXG4gICAgICAgICAgICBwb3J0YWxVcmwsXHJcbiAgICAgICAgICAgIHBvcHVwOiBmYWxzZVxyXG4gICAgICAgIH0pO1xyXG4gICAgICAgIElkZW50aXR5TWFuYWdlci5yZWdpc3Rlck9BdXRoSW5mb3MoW29hdXRoSW5mb10pOyAgICAgICAgXHJcbiAgICB9XHJcbiAgICByZXR1cm4gSWRlbnRpdHlNYW5hZ2VyO1xyXG59XHJcblxyXG4vKipcclxuICogQ2hlY2sgY3VycmVudCBsb2dnZWQgaW4gc3RhdHVzIGZvciBjdXJyZW50IHBvcnRhbFxyXG4gKi9cclxuZXhwb3J0IGNvbnN0IGNoZWNrQ3VycmVudFN0YXR1cyA9IGFzeW5jIChhcHBJZDogc3RyaW5nLCBwb3J0YWxVcmw6IHN0cmluZykgPT4ge1xyXG4gICAgY29uc3QgSWRlbnRpdHlNYW5hZ2VyID0gYXdhaXQgbG9hZE1vZHVsZXMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICByZXR1cm4gSWRlbnRpdHlNYW5hZ2VyLmNoZWNrU2lnbkluU3RhdHVzKGAke3BvcnRhbFVybH0vc2hhcmluZ2ApO1xyXG59OyIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X2FyY2dpc19fOyIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X2NvcmVfXzsiLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfcmVhY3RfZG9tX187IiwibW9kdWxlLmV4cG9ydHMgPSBfX1dFQlBBQ0tfRVhURVJOQUxfTU9EVUxFX2ppbXVfdWlfXzsiLCIvLyBUaGUgbW9kdWxlIGNhY2hlXG52YXIgX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fID0ge307XG5cbi8vIFRoZSByZXF1aXJlIGZ1bmN0aW9uXG5mdW5jdGlvbiBfX3dlYnBhY2tfcmVxdWlyZV9fKG1vZHVsZUlkKSB7XG5cdC8vIENoZWNrIGlmIG1vZHVsZSBpcyBpbiBjYWNoZVxuXHR2YXIgY2FjaGVkTW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXTtcblx0aWYgKGNhY2hlZE1vZHVsZSAhPT0gdW5kZWZpbmVkKSB7XG5cdFx0cmV0dXJuIGNhY2hlZE1vZHVsZS5leHBvcnRzO1xuXHR9XG5cdC8vIENyZWF0ZSBhIG5ldyBtb2R1bGUgKGFuZCBwdXQgaXQgaW50byB0aGUgY2FjaGUpXG5cdHZhciBtb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdID0ge1xuXHRcdC8vIG5vIG1vZHVsZS5pZCBuZWVkZWRcblx0XHQvLyBubyBtb2R1bGUubG9hZGVkIG5lZWRlZFxuXHRcdGV4cG9ydHM6IHt9XG5cdH07XG5cblx0Ly8gRXhlY3V0ZSB0aGUgbW9kdWxlIGZ1bmN0aW9uXG5cdF9fd2VicGFja19tb2R1bGVzX19bbW9kdWxlSWRdKG1vZHVsZSwgbW9kdWxlLmV4cG9ydHMsIF9fd2VicGFja19yZXF1aXJlX18pO1xuXG5cdC8vIFJldHVybiB0aGUgZXhwb3J0cyBvZiB0aGUgbW9kdWxlXG5cdHJldHVybiBtb2R1bGUuZXhwb3J0cztcbn1cblxuIiwiLy8gZ2V0RGVmYXVsdEV4cG9ydCBmdW5jdGlvbiBmb3IgY29tcGF0aWJpbGl0eSB3aXRoIG5vbi1oYXJtb255IG1vZHVsZXNcbl9fd2VicGFja19yZXF1aXJlX18ubiA9IChtb2R1bGUpID0+IHtcblx0dmFyIGdldHRlciA9IG1vZHVsZSAmJiBtb2R1bGUuX19lc01vZHVsZSA/XG5cdFx0KCkgPT4gKG1vZHVsZVsnZGVmYXVsdCddKSA6XG5cdFx0KCkgPT4gKG1vZHVsZSk7XG5cdF9fd2VicGFja19yZXF1aXJlX18uZChnZXR0ZXIsIHsgYTogZ2V0dGVyIH0pO1xuXHRyZXR1cm4gZ2V0dGVyO1xufTsiLCIvLyBkZWZpbmUgZ2V0dGVyIGZ1bmN0aW9ucyBmb3IgaGFybW9ueSBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLmQgPSAoZXhwb3J0cywgZGVmaW5pdGlvbikgPT4ge1xuXHRmb3IodmFyIGtleSBpbiBkZWZpbml0aW9uKSB7XG5cdFx0aWYoX193ZWJwYWNrX3JlcXVpcmVfXy5vKGRlZmluaXRpb24sIGtleSkgJiYgIV9fd2VicGFja19yZXF1aXJlX18ubyhleHBvcnRzLCBrZXkpKSB7XG5cdFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywga2V5LCB7IGVudW1lcmFibGU6IHRydWUsIGdldDogZGVmaW5pdGlvbltrZXldIH0pO1xuXHRcdH1cblx0fVxufTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLm8gPSAob2JqLCBwcm9wKSA9PiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCkpIiwiLy8gZGVmaW5lIF9fZXNNb2R1bGUgb24gZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5yID0gKGV4cG9ydHMpID0+IHtcblx0aWYodHlwZW9mIFN5bWJvbCAhPT0gJ3VuZGVmaW5lZCcgJiYgU3ltYm9sLnRvU3RyaW5nVGFnKSB7XG5cdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFN5bWJvbC50b1N0cmluZ1RhZywgeyB2YWx1ZTogJ01vZHVsZScgfSk7XG5cdH1cblx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsICdfX2VzTW9kdWxlJywgeyB2YWx1ZTogdHJ1ZSB9KTtcbn07IiwiX193ZWJwYWNrX3JlcXVpcmVfXy5wID0gXCJcIjsiLCIvKipcclxuICogV2VicGFjayB3aWxsIHJlcGxhY2UgX193ZWJwYWNrX3B1YmxpY19wYXRoX18gd2l0aCBfX3dlYnBhY2tfcmVxdWlyZV9fLnAgdG8gc2V0IHRoZSBwdWJsaWMgcGF0aCBkeW5hbWljYWxseS5cclxuICogVGhlIHJlYXNvbiB3aHkgd2UgY2FuJ3Qgc2V0IHRoZSBwdWJsaWNQYXRoIGluIHdlYnBhY2sgY29uZmlnIGlzOiB3ZSBjaGFuZ2UgdGhlIHB1YmxpY1BhdGggd2hlbiBkb3dubG9hZC5cclxuICogKi9cclxuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lXHJcbi8vIEB0cy1pZ25vcmVcclxuX193ZWJwYWNrX3B1YmxpY19wYXRoX18gPSB3aW5kb3cuamltdUNvbmZpZy5iYXNlVXJsXHJcbiIsImltcG9ydCB7IFJlYWN0LCBBbGxXaWRnZXRQcm9wcyB9IGZyb20gJ2ppbXUtY29yZSdcclxuaW1wb3J0IHsgSU1Db25maWcgfSBmcm9tICcuLi9jb25maWcnO1xyXG5pbXBvcnQgeyBQZXJzb25GaWxsZWQgfSBmcm9tICdqaW11LWljb25zL2ZpbGxlZC9hcHBsaWNhdGlvbi9wZXJzb24nO1xyXG5pbXBvcnQge0xhYmVsfSBmcm9tICdqaW11LXVpJztcclxuaW1wb3J0IHsgQ2xvc2VPdXRsaW5lZCB9IGZyb20gJ2ppbXUtaWNvbnMvb3V0bGluZWQvZWRpdG9yL2Nsb3NlJztcclxuaW1wb3J0IFJlYWN0RE9NIGZyb20gJ3JlYWN0LWRvbSc7XHJcbmltcG9ydCB7IHNpZ25PdXQsIHNpZ25JbiB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXV0aCc7XHJcblxyXG5leHBvcnQgY29uc3QgVXNlckJveCA9ICh7dXNlcm5hbWUsIGZ1bGxOYW1lLCBjbG9zZU1lLCBhdXRoZW50aWNhdGUsIHRoZW1lfSkgPT4ge1xyXG5cclxuICAgIHJldHVybiAoXHJcbiAgICAgIDxkaXYgaWQ9XCJ1c2VyUG9wdXBcIiBzdHlsZT17e2JhY2tncm91bmRDb2xvcjogJyMwMDRkOGEnLFxyXG4gICAgICBib3hTaGFkb3c6IHRoZW1lLmJveFNoYWRvd3MubGd9fSAgY2xhc3NOYW1lPSdwb3B1cC1jb250YWluZXInPlxyXG4gICAgICAgIDxzdHlsZT5cclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAucG9wdXAtY29udGFpbmVye1xyXG4gICAgICAgICAgICAgIGRpc3BsYXk6IGJsb2NrO1xyXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTtcclxuICAgICAgICAgICAgICBjb2xvcjogd2hpdGU7XHJcbiAgICAgICAgICAgICAgcGFkZGluZzogMjBweDtcclxuICAgICAgICAgICAgICB3aWR0aDogMzAwcHg7ICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgei1pbmRleDogMTAwO1xyXG4gICAgICAgICAgICAgIHJpZ2h0OiAxMHB4O1xyXG4gICAgICAgICAgICAgIHRvcDogNjBweDtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAuY2xvc2UtaWNvbntcclxuICAgICAgICAgICAgICAgcG9zaXRpb246IGFic29sdXRlO1xyXG4gICAgICAgICAgICAgICByaWdodDogNXB4O1xyXG4gICAgICAgICAgICAgICB0b3A6IDVweDtcclxuICAgICAgICAgICAgICAgY3Vyc29yOiBwb2ludGVyO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIC51c2Vye1xyXG4gICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjtcclxuICAgICAgICAgICAgICBib3JkZXItYm90dG9tOiAxcHggc29saWQgd2hpdGU7XHJcbiAgICAgICAgICAgICAgcGFkZGluZzogMTBweCAwO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIC51c2VyLW5hbWV7XHJcbiAgICAgICAgICAgICAgY29sb3I6IHdoaXRlO1xyXG4gICAgICAgICAgICAgIGZvbnQtc2l6ZTogMThweDtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAuYWN0aW9ucyB7XHJcbiAgICAgICAgICAgICAgcGFkZGluZzogMjBweDtcclxuICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAuc2lnbi1pbi1vdXR7XHJcbiAgICAgICAgICAgICAgY29sb3I6IHdoaXRlO1xyXG4gICAgICAgICAgICAgIGZvbnQtc2l6ZTogMThweDtcclxuICAgICAgICAgICAgICBjdXJzb3I6IHBvaW50ZXI7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgLnNpZ24taW4tb3V0OmhvdmVye1xyXG4gICAgICAgICAgICAgIHRleHQtZGVjb3JhdGlvbi1saW5lOiB1bmRlcmxpbmU7XHJcbiAgICAgICAgICAgIH1gXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgPC9zdHlsZT5cclxuICAgICA8Q2xvc2VPdXRsaW5lZCBvbkNsaWNrPXtjbG9zZU1lfSBzaXplPXsyMH0gY2xhc3NOYW1lPVwiY2xvc2UtaWNvblwiIGNvbG9yPXsnI2Q3ZDhkOCd9Lz5cclxuICAgICAge1xyXG4gICAgICAgIHVzZXJuYW1lID9cclxuICAgICAgICg8ZGl2IGNsYXNzTmFtZT0ndXNlcic+XHJcbiAgICAgICAgICA8UGVyc29uRmlsbGVkIHN0eWxlPXt7ZmxleDogMX19IHNpemU9ezYwfS8+XHJcbiAgICAgICAgICA8TGFiZWwgY2xhc3NOYW1lPSd1c2VyLW5hbWUnIGNoZWNrIHN0eWxlPXt7ZmxleDogMn19PlxyXG4gICAgICAgICAgICAgIHtmdWxsTmFtZX1cclxuICAgICAgICAgICAgICB7YFxcbiR7dXNlcm5hbWV9YH1cclxuICAgICAgICAgIDwvTGFiZWw+XHJcbiAgICAgICAgPC9kaXY+KTogbnVsbFxyXG4gICAgICAgIH1cclxuICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cImFjdGlvbnNcIj5cclxuICAgICAgICAgICAgPExhYmVsIGNsYXNzTmFtZT0nc2lnbi1pbi1vdXQnIGNoZWNrIG9uQ2xpY2s9e2F1dGhlbnRpY2F0ZX0+XHJcbiAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdXNlcm5hbWUgPyAgJ1NpZ24gT3V0JyA6ICAnU2lnbiBJbidcclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIDwvTGFiZWw+XHJcbiAgICAgICAgPC9kaXY+XHJcbiAgPC9kaXY+XHJcbiAgICApXHJcbiAgXHJcbn1cclxuXHJcbmNvbnN0IFdpZGdldCA9IChwcm9wczogQWxsV2lkZ2V0UHJvcHM8SU1Db25maWc+KSA9PiB7XHJcblxyXG4gIGNvbnN0IFtpc1VzZXJCb3hWaXNpYmxlLCBzaG93VXNlckJveF0gPSBSZWFjdC51c2VTdGF0ZShmYWxzZSk7XHJcblxyXG4gIFJlYWN0LnVzZUVmZmVjdCgoKT0+e1xyXG4gICAgc2lnbkluKHByb3BzLmNvbmZpZy5hcHBJZCwgJ2h0dHBzOi8vd3d3LmFyY2dpcy5jb20nKTtcclxuICB9LCBbXSlcclxuXHJcbiAgY29uc3QgY2xvc2VVc2VyQm94ID0oKSA9PiB7XHJcbiAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd1c2VyQm94RWxlbWVudCcpO1xyXG4gICAgaWYoZWwpe1xyXG4gICAgICBlbC5yZW1vdmUoKTtcclxuICAgICAgZG9jdW1lbnQucmVtb3ZlRXZlbnRMaXN0ZW5lcignY2xpY2snLCBmdW5jdGlvbihlKXt9KTtcclxuICAgICAgc2hvd1VzZXJCb3goZmFsc2UpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgY29uc3QgbG9nb3V0ID0gYXN5bmMgKCkgPT4ge1xyXG4gICAgYXdhaXQgc2lnbk91dChwcm9wcy5jb25maWcuYXBwSWQsICdodHRwczovL3d3dy5hcmNnaXMuY29tJyk7XHJcbiAgICBsb2NhdGlvbi5yZXBsYWNlKCdodHRwczovL3d3dy5hcmNnaXMuY29tJyk7XHJcbiAgICAvL2xvY2F0aW9uLnJlbG9hZCgpOyBcclxuICB9XHJcblxyXG4gIGNvbnN0IHNob3dQb3B1cCA9ICgpID0+eyAgIFxyXG5cclxuICAgIGlmKGlzVXNlckJveFZpc2libGUpe1xyXG4gICAgICBjbG9zZVVzZXJCb3goKTtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG4gICAgIFxyXG4gICAgIHZhciB1c2VyQm94RWxlbWVudCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJESVZcIik7XHJcbiAgICAgdXNlckJveEVsZW1lbnQuc2V0QXR0cmlidXRlKCdpZCcsICd1c2VyQm94RWxlbWVudCcpO1xyXG5cclxuICAgICBSZWFjdERPTS5yZW5kZXIoXHJcbiAgICAgICAgPFVzZXJCb3ggXHJcbiAgICAgICAgZnVsbE5hbWU9e3Byb3BzPy51c2VyPy5mdWxsTmFtZX0gXHJcbiAgICAgICAgdXNlcm5hbWU9e3Byb3BzPy51c2VyPy51c2VybmFtZX0gXHJcbiAgICAgICAgdGhlbWU9e3Byb3BzLnRoZW1lfVxyXG4gICAgICAgIGNsb3NlTWU9eygpID0+IGNsb3NlVXNlckJveCgpfVxyXG4gICAgICAgIGF1dGhlbnRpY2F0ZT17KCkgPT4gbG9nb3V0KCl9Lz4sXHJcbiAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh1c2VyQm94RWxlbWVudClcclxuICAgICAgKSAgIFxyXG4gICAgIHNob3dVc2VyQm94KHRydWUpO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuICggXHJcbiAgICA8ZGl2IGNsYXNzTmFtZT0namltdS13aWRnZXQgd2lkZ2V0LWNvbnRhaW5lcicgXHJcbiAgICAgIHN0eWxlPXt7YmFja2dyb3VuZDogcHJvcHMuY29uZmlnLmJhY2tncm91bmRDb2xvcn19PlxyXG4gICAgICAgPHN0eWxlPlxyXG4gICAgICAgIHtgXHJcbiAgICAgICAgICAud2lkZ2V0LWNvbnRhaW5lcntcclxuICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7XHJcbiAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAuZ3JlZXRpbmctaWNvbntcclxuICAgICAgICAgICAgd2lkdGg6IDgwcHg7XHJcbiAgICAgICAgICAgIGN1cnNvcjogcG9pbnRlcjtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIFxyXG4gICAgICAgIGB9XHJcbiAgICAgIDwvc3R5bGU+XHJcbiAgICAgICAgPFBlcnNvbkZpbGxlZCBjbGFzc05hbWU9J2dyZWV0aW5nLWljb24nIFxyXG4gICAgICAgICAgb25DbGljaz17KCk9PiBzaG93UG9wdXAoKX0gXHJcbiAgICAgICAgICBzaXplPXtwcm9wcy5jb25maWcuaWNvblNpemV9XHJcbiAgICAgICAgICBjb2xvcj0gXCJ3aGl0ZVwiXHJcbiAgICAgICAgLz5cclxuICAgICA8L2Rpdj5cclxuICApXHJcbn1cclxuXHJcbmV4cG9ydCBkZWZhdWx0IFdpZGdldFxyXG4iXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=