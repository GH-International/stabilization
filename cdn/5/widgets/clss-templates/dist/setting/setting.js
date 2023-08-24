System.register(["jimu-core","jimu-ui/advanced/setting-components","jimu-ui/basic/color-picker"], function(__WEBPACK_DYNAMIC_EXPORT__, __system_context__) {
	var __WEBPACK_EXTERNAL_MODULE_jimu_core__ = {};
	var __WEBPACK_EXTERNAL_MODULE_jimu_ui_advanced_setting_components__ = {};
	var __WEBPACK_EXTERNAL_MODULE_jimu_ui_basic_color_picker__ = {};
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_jimu_core__, "__esModule", { value: true });
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_jimu_ui_advanced_setting_components__, "__esModule", { value: true });
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_jimu_ui_basic_color_picker__, "__esModule", { value: true });
	return {
		setters: [
			function(module) {
				Object.keys(module).forEach(function(key) {
					__WEBPACK_EXTERNAL_MODULE_jimu_core__[key] = module[key];
				});
			},
			function(module) {
				Object.keys(module).forEach(function(key) {
					__WEBPACK_EXTERNAL_MODULE_jimu_ui_advanced_setting_components__[key] = module[key];
				});
			},
			function(module) {
				Object.keys(module).forEach(function(key) {
					__WEBPACK_EXTERNAL_MODULE_jimu_ui_basic_color_picker__[key] = module[key];
				});
			}
		],
		execute: function() {
			__WEBPACK_DYNAMIC_EXPORT__(
/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ "./your-extensions/widgets/clss-templates/src/setting/translations/default.ts":
/*!************************************************************************************!*\
  !*** ./your-extensions/widgets/clss-templates/src/setting/translations/default.ts ***!
  \************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = ({
    settings: "Settings",
    iconSizeInstr: "Set Icon size",
    setInnerIconSizeInstr: 'Set Inner Icon Size'
});


/***/ }),

/***/ "jimu-core":
/*!****************************!*\
  !*** external "jimu-core" ***!
  \****************************/
/***/ ((module) => {

"use strict";
module.exports = __WEBPACK_EXTERNAL_MODULE_jimu_core__;

/***/ }),

/***/ "jimu-ui/advanced/setting-components":
/*!******************************************************!*\
  !*** external "jimu-ui/advanced/setting-components" ***!
  \******************************************************/
/***/ ((module) => {

"use strict";
module.exports = __WEBPACK_EXTERNAL_MODULE_jimu_ui_advanced_setting_components__;

/***/ }),

/***/ "jimu-ui/basic/color-picker":
/*!*********************************************!*\
  !*** external "jimu-ui/basic/color-picker" ***!
  \*********************************************/
/***/ ((module) => {

"use strict";
module.exports = __WEBPACK_EXTERNAL_MODULE_jimu_ui_basic_color_picker__;

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
/*!************************************************************************!*\
  !*** ./your-extensions/widgets/clss-templates/src/setting/setting.tsx ***!
  \************************************************************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ Setting)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-ui/advanced/setting-components */ "jimu-ui/advanced/setting-components");
/* harmony import */ var _translations_default__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./translations/default */ "./your-extensions/widgets/clss-templates/src/setting/translations/default.ts");
/* harmony import */ var jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! jimu-ui/basic/color-picker */ "jimu-ui/basic/color-picker");




function Setting(props) {
    const [headerBackgroundColor, setHeaderBackgroundColor] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.headerBackgroundColor);
    const [headerTextColor, setHeaderTextColor] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.headerTextColor);
    const [defaultButtonBackgroundColor, setDefaultButtonBackgroundColor] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.defaultButtonBackgroundColor);
    const [defaultButtonTextColor, setDefaultButtonTextColor] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.defaultButtonColor);
    const [selectedButtonBackgroundColor, setSelectedButtonBackgroundColor] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.selectedButtonBackgroundColor);
    const [selectedButtonTextColor, setSelectedButtonTextColor] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.selectedButtonColor);
    const onHeaderBackgroundColor = (color) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('headerBackgroundColor', color)
        });
        setHeaderBackgroundColor(color);
    };
    const onHeaderTextColor = (color) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('headerTextColor', color)
        });
        setHeaderTextColor(color);
    };
    const onDefaultButtonBackgroundColorChange = (color) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('defaultButtonBackgroundColor', color)
        });
        setDefaultButtonBackgroundColor(color);
    };
    const onDefaultButtonTextColorChange = (color) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('defaultButtonColor', color)
        });
        setDefaultButtonTextColor(color);
    };
    const onSelectedButtonBackgroundColorChange = (color) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('selectedButtonBackgroundColor', color)
        });
        setSelectedButtonBackgroundColor(color);
    };
    const onSelectedButtonTextColorChange = (color) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('selectedButtonColor', color)
        });
        setSelectedButtonTextColor(color);
    };
    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "widget-setting" },
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingSection, { title: props.intl.formatMessage({
                id: "settingsLabel",
                defaultMessage: _translations_default__WEBPACK_IMPORTED_MODULE_2__["default"].settings
            }) },
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { style: { display: 'flex', justifyContent: 'space-between', width: '100%' } },
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("h4", { style: { flex: '1' } }, "Header Background"),
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_3__.ThemeColorPicker, { color: headerBackgroundColor, height: 26, icon: "none", value: headerBackgroundColor, onChange: (c) => onHeaderBackgroundColor(c), placement: "auto", type: "default", width: 30 }))),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { style: { display: 'flex', justifyContent: 'space-between', width: '100%' } },
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("h4", { style: { flex: '1' } }, "Header Text Color"),
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_3__.ThemeColorPicker, { color: headerTextColor, height: 26, icon: "none", value: headerTextColor, onChange: (c) => onHeaderTextColor(c), placement: "auto", type: "default", width: 30 }))),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { style: { display: 'flex', justifyContent: 'space-between', width: '100%' } },
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("h4", { style: { flex: '1' } }, "Default Button Background Color"),
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_3__.ThemeColorPicker, { color: defaultButtonBackgroundColor, height: 26, icon: "none", value: defaultButtonBackgroundColor, onChange: (c) => onDefaultButtonBackgroundColorChange(c), placement: "auto", type: "default", width: 30 }))),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { style: { display: 'flex', justifyContent: 'space-between', width: '100%' } },
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("h4", { style: { flex: '1' } }, "Default Button Text Color"),
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_3__.ThemeColorPicker, { color: defaultButtonTextColor, height: 26, icon: "none", value: defaultButtonTextColor, onChange: (c) => onDefaultButtonTextColorChange(c), placement: "auto", type: "default", width: 30 }))),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { style: { display: 'flex', justifyContent: 'space-between', width: '100%' } },
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("h4", { style: { flex: '1' } }, "Selected Button Background Color"),
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_3__.ThemeColorPicker, { color: selectedButtonBackgroundColor, height: 26, icon: "none", value: selectedButtonBackgroundColor, onChange: (c) => onSelectedButtonBackgroundColorChange(c), placement: "auto", type: "default", width: 30 }))),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { style: { display: 'flex', justifyContent: 'space-between', width: '100%' } },
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("h4", { style: { flex: '1' } }, "Selected Button Text Color"),
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_3__.ThemeColorPicker, { color: selectedButtonTextColor, height: 26, icon: "none", value: selectedButtonTextColor, onChange: (c) => onSelectedButtonTextColorChange(c), placement: "auto", type: "default", width: 30 }))))));
}
;

})();

/******/ 	return __webpack_exports__;
/******/ })()

			);
		}
	};
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2lkZ2V0cy9jbHNzLXRlbXBsYXRlcy9kaXN0L3NldHRpbmcvc2V0dGluZy5qcyIsIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLGlFQUFlO0lBQ2IsUUFBUSxFQUFFLFVBQVU7SUFDcEIsYUFBYSxFQUFFLGVBQWU7SUFDOUIscUJBQXFCLEVBQUUscUJBQXFCO0NBQzdDLEVBQUM7Ozs7Ozs7Ozs7OztBQ0pGOzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7VUNBQTtVQUNBOztVQUVBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBOztVQUVBO1VBQ0E7O1VBRUE7VUFDQTtVQUNBOzs7OztXQ3RCQTtXQUNBO1dBQ0E7V0FDQTtXQUNBLHlDQUF5Qyx3Q0FBd0M7V0FDakY7V0FDQTtXQUNBOzs7OztXQ1BBOzs7OztXQ0FBO1dBQ0E7V0FDQTtXQUNBLHVEQUF1RCxpQkFBaUI7V0FDeEU7V0FDQSxnREFBZ0QsYUFBYTtXQUM3RDs7Ozs7V0NOQTs7Ozs7Ozs7OztBQ0FBOzs7S0FHSztBQUNMLDJCQUEyQjtBQUMzQixhQUFhO0FBQ2IscUJBQXVCLEdBQUcsTUFBTSxDQUFDLFVBQVUsQ0FBQyxPQUFPOzs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNMakI7QUFLVztBQUVZO0FBQ0s7QUFFL0MsU0FBUyxPQUFPLENBQUUsS0FBc0M7SUFFckUsTUFBTSxDQUFDLHFCQUFxQixFQUFFLHdCQUF3QixDQUFDLEdBQUcscURBQWMsQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLHFCQUFxQixDQUFDLENBQUM7SUFDN0csTUFBTSxDQUFDLGVBQWUsRUFBRSxrQkFBa0IsQ0FBQyxHQUFHLHFEQUFjLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxlQUFlLENBQUMsQ0FBQztJQUUzRixNQUFNLENBQUMsNEJBQTRCLEVBQUUsK0JBQStCLENBQUMsR0FBRyxxREFBYyxDQUFDLEtB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LDJEQUFDLHdFQUFnQixJQUNmLEtBQUssRUFBRSw2QkFBNkIsRUFDcEMsTUFBTSxFQUFFLEVBQUUsRUFDVixJQUFJLEVBQUMsTUFBTSxFQUNYLEtBQUssRUFBRSw2QkFBNkIsRUFDcEMsUUFBUSxFQUFFLENBQUMsQ0FBQyxFQUFDLEVBQUUsQ0FBQyxxQ0FBcUMsQ0FBQyxDQUFDLENBQUMsRUFDeEQsU0FBUyxFQUFDLE1BQU0sRUFDaEIsSUFBSSxFQUFDLFNBQVMsRUFDZCxLQUFLLEVBQUUsRUFBRSxHQUNULENBQ0EsQ0FDSztZQUViLDJEQUFDLDJFQUFVO2dCQUNULG9FQUFLLEtBQUssRUFBRSxFQUFFLE9BQU8sRUFBRSxNQUFNLEVBQUUsY0FBYyxFQUFFLGVBQWUsRUFBRSxLQUFLLEVBQUUsTUFBTSxFQUFDO29CQUMxRSxtRUFBSSxLQUFLLEVBQUUsRUFBQyxJQUFJLEVBQUUsR0FBRyxFQUFDLGlDQUFpQztvQkFDdkQsMkRBQUMsd0VBQWdCLElBQ2YsS0FBSyxFQUFFLHVCQUF1QixFQUM5QixNQUFNLEVBQUUsRUFBRSxFQUNWLElBQUksRUFBQyxNQUFNLEVBQ1gsS0FBSyxFQUFFLHVCQUF1QixFQUM5QixRQUFRLEVBQUUsQ0FBQyxDQUFDLEVBQUMsRUFBRSxDQUFDLCtCQUErQixDQUFDLENBQUMsQ0FBQyxFQUNsRCxTQUFTLEVBQUMsTUFBTSxFQUNoQixJQUFJLEVBQUMsU0FBUyxFQUNkLEtBQUssRUFBRSxFQUFFLEdBQ1QsQ0FDQSxDQUNLLENBQ0UsQ0FDYixDQUNULENBQUM7QUFDSixDQUFDO0FBQUEsQ0FBQyIsInNvdXJjZXMiOlsid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLXRlbXBsYXRlcy9zcmMvc2V0dGluZy90cmFuc2xhdGlvbnMvZGVmYXVsdC50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtY29yZVwiIiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS11aS9hZHZhbmNlZC9zZXR0aW5nLWNvbXBvbmVudHNcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtdWkvYmFzaWMvY29sb3ItcGlja2VyXCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL2Jvb3RzdHJhcCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9kZWZpbmUgcHJvcGVydHkgZ2V0dGVycyIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9oYXNPd25Qcm9wZXJ0eSBzaG9ydGhhbmQiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvbWFrZSBuYW1lc3BhY2Ugb2JqZWN0Iiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL3B1YmxpY1BhdGgiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtY29yZS9saWIvc2V0LXB1YmxpYy1wYXRoLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLXRlbXBsYXRlcy9zcmMvc2V0dGluZy9zZXR0aW5nLnRzeCJdLCJzb3VyY2VzQ29udGVudCI6WyJleHBvcnQgZGVmYXVsdCB7IFxyXG4gIHNldHRpbmdzOiBcIlNldHRpbmdzXCIsXHJcbiAgaWNvblNpemVJbnN0cjogXCJTZXQgSWNvbiBzaXplXCIsXHJcbiAgc2V0SW5uZXJJY29uU2l6ZUluc3RyOiAnU2V0IElubmVyIEljb24gU2l6ZSdcclxufTtcclxuIiwibW9kdWxlLmV4cG9ydHMgPSBfX1dFQlBBQ0tfRVhURVJOQUxfTU9EVUxFX2ppbXVfY29yZV9fOyIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X3VpX2FkdmFuY2VkX3NldHRpbmdfY29tcG9uZW50c19fOyIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X3VpX2Jhc2ljX2NvbG9yX3BpY2tlcl9fOyIsIi8vIFRoZSBtb2R1bGUgY2FjaGVcbnZhciBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX18gPSB7fTtcblxuLy8gVGhlIHJlcXVpcmUgZnVuY3Rpb25cbmZ1bmN0aW9uIF9fd2VicGFja19yZXF1aXJlX18obW9kdWxlSWQpIHtcblx0Ly8gQ2hlY2sgaWYgbW9kdWxlIGlzIGluIGNhY2hlXG5cdHZhciBjYWNoZWRNb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdO1xuXHRpZiAoY2FjaGVkTW9kdWxlICE9PSB1bmRlZmluZWQpIHtcblx0XHRyZXR1cm4gY2FjaGVkTW9kdWxlLmV4cG9ydHM7XG5cdH1cblx0Ly8gQ3JlYXRlIGEgbmV3IG1vZHVsZSAoYW5kIHB1dCBpdCBpbnRvIHRoZSBjYWNoZSlcblx0dmFyIG1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF0gPSB7XG5cdFx0Ly8gbm8gbW9kdWxlLmlkIG5lZWRlZFxuXHRcdC8vIG5vIG1vZHVsZS5sb2FkZWQgbmVlZGVkXG5cdFx0ZXhwb3J0czoge31cblx0fTtcblxuXHQvLyBFeGVjdXRlIHRoZSBtb2R1bGUgZnVuY3Rpb25cblx0X193ZWJwYWNrX21vZHVsZXNfX1ttb2R1bGVJZF0obW9kdWxlLCBtb2R1bGUuZXhwb3J0cywgX193ZWJwYWNrX3JlcXVpcmVfXyk7XG5cblx0Ly8gUmV0dXJuIHRoZSBleHBvcnRzIG9mIHRoZSBtb2R1bGVcblx0cmV0dXJuIG1vZHVsZS5leHBvcnRzO1xufVxuXG4iLCIvLyBkZWZpbmUgZ2V0dGVyIGZ1bmN0aW9ucyBmb3IgaGFybW9ueSBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLmQgPSAoZXhwb3J0cywgZGVmaW5pdGlvbikgPT4ge1xuXHRmb3IodmFyIGtleSBpbiBkZWZpbml0aW9uKSB7XG5cdFx0aWYoX193ZWJwYWNrX3JlcXVpcmVfXy5vKGRlZmluaXRpb24sIGtleSkgJiYgIV9fd2VicGFja19yZXF1aXJlX18ubyhleHBvcnRzLCBrZXkpKSB7XG5cdFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywga2V5LCB7IGVudW1lcmFibGU6IHRydWUsIGdldDogZGVmaW5pdGlvbltrZXldIH0pO1xuXHRcdH1cblx0fVxufTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLm8gPSAob2JqLCBwcm9wKSA9PiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCkpIiwiLy8gZGVmaW5lIF9fZXNNb2R1bGUgb24gZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5yID0gKGV4cG9ydHMpID0+IHtcblx0aWYodHlwZW9mIFN5bWJvbCAhPT0gJ3VuZGVmaW5lZCcgJiYgU3ltYm9sLnRvU3RyaW5nVGFnKSB7XG5cdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFN5bWJvbC50b1N0cmluZ1RhZywgeyB2YWx1ZTogJ01vZHVsZScgfSk7XG5cdH1cblx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsICdfX2VzTW9kdWxlJywgeyB2YWx1ZTogdHJ1ZSB9KTtcbn07IiwiX193ZWJwYWNrX3JlcXVpcmVfXy5wID0gXCJcIjsiLCIvKipcclxuICogV2VicGFjayB3aWxsIHJlcGxhY2UgX193ZWJwYWNrX3B1YmxpY19wYXRoX18gd2l0aCBfX3dlYnBhY2tfcmVxdWlyZV9fLnAgdG8gc2V0IHRoZSBwdWJsaWMgcGF0aCBkeW5hbWljYWxseS5cclxuICogVGhlIHJlYXNvbiB3aHkgd2UgY2FuJ3Qgc2V0IHRoZSBwdWJsaWNQYXRoIGluIHdlYnBhY2sgY29uZmlnIGlzOiB3ZSBjaGFuZ2UgdGhlIHB1YmxpY1BhdGggd2hlbiBkb3dubG9hZC5cclxuICogKi9cclxuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lXHJcbi8vIEB0cy1pZ25vcmVcclxuX193ZWJwYWNrX3B1YmxpY19wYXRoX18gPSB3aW5kb3cuamltdUNvbmZpZy5iYXNlVXJsXHJcbiIsIlxyXG5pbXBvcnQgeyBSZWFjdCB9IGZyb20gXCJqaW11LWNvcmVcIjtcclxuaW1wb3J0IHsgQWxsV2lkZ2V0U2V0dGluZ1Byb3BzIH0gZnJvbSBcImppbXUtZm9yLWJ1aWxkZXJcIjtcclxuaW1wb3J0IHtcclxuICBTZXR0aW5nU2VjdGlvbixcclxuICBTZXR0aW5nUm93XHJcbn0gZnJvbSBcImppbXUtdWkvYWR2YW5jZWQvc2V0dGluZy1jb21wb25lbnRzXCI7XHJcbmltcG9ydCB7IElNQ29uZmlnIH0gZnJvbSBcIi4uL2NvbmZpZ1wiO1xyXG5pbXBvcnQgZGVmYXVsdEkxOG5NZXNzYWdlcyBmcm9tIFwiLi90cmFuc2xhdGlvbnMvZGVmYXVsdFwiO1xyXG5pbXBvcnQgeyBUaGVtZUNvbG9yUGlja2VyIH0gZnJvbSBcImppbXUtdWkvYmFzaWMvY29sb3ItcGlja2VyXCI7XHJcblxyXG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBTZXR0aW5nIChwcm9wczogQWxsV2lkZ2V0U2V0dGluZ1Byb3BzPElNQ29uZmlnPikgeyBcclxuXHJcbiAgY29uc3QgW2hlYWRlckJhY2tncm91bmRDb2xvciwgc2V0SGVhZGVyQmFja2dyb3VuZENvbG9yXSA9IFJlYWN0LnVzZVN0YXRlKHByb3BzLmNvbmZpZy5oZWFkZXJCYWNrZ3JvdW5kQ29sb3IpO1xyXG4gIGNvbnN0IFtoZWFkZXJUZXh0Q29sb3IsIHNldEhlYWRlclRleHRDb2xvcl0gPSBSZWFjdC51c2VTdGF0ZShwcm9wcy5jb25maWcuaGVhZGVyVGV4dENvbG9yKTtcclxuICBcclxuICBjb25zdCBbZGVmYXVsdEJ1dHRvbkJhY2tncm91bmRDb2xvciwgc2V0RGVmYXVsdEJ1dHRvbkJhY2tncm91bmRDb2xvcl0gPSBSZWFjdC51c2VTdGF0ZShwcm9wcy5jb25maWcuZGVmYXVsdEJ1dHRvbkJhY2tncm91bmRDb2xvcik7XHJcbiAgY29uc3QgW2RlZmF1bHRCdXR0b25UZXh0Q29sb3IsIHNldERlZmF1bHRCdXR0b25UZXh0Q29sb3JdID0gUmVhY3QudXNlU3RhdGUocHJvcHMuY29uZmlnLmRlZmF1bHRCdXR0b25Db2xvcik7XHJcbiAgXHJcbiAgY29uc3QgW3NlbGVjdGVkQnV0dG9uQmFja2dyb3VuZENvbG9yLCBzZXRTZWxlY3RlZEJ1dHRvbkJhY2tncm91bmRDb2xvcl0gPSBSZWFjdC51c2VTdGF0ZShwcm9wcy5jb25maWcuc2VsZWN0ZWRCdXR0b25CYWNrZ3JvdW5kQ29sb3IpO1xyXG4gIGNvbnN0IFtzZWxlY3RlZEJ1dHRvblRleHRDb2xvciwgc2V0U2VsZWN0ZWRCdXR0b25UZXh0Q29sb3JdID0gUmVhY3QudXNlU3RhdGUocHJvcHMuY29uZmlnLnNlbGVjdGVkQnV0dG9uQ29sb3IpO1xyXG4gICAgXHJcbiAgY29uc3Qgb25IZWFkZXJCYWNrZ3JvdW5kQ29sb3IgPSAoY29sb3I6IHN0cmluZyk9PnsgICAgXHJcbiAgICAgIFxyXG4gICAgcHJvcHMub25TZXR0aW5nQ2hhbmdlKHtcclxuICAgICAgaWQ6IHByb3BzLmlkLFxyXG4gICAgICBjb25maWc6IHByb3BzLmNvbmZpZy5zZXQoJ2hlYWRlckJhY2tncm91bmRDb2xvcicsIGNvbG9yKVxyXG4gICAgfSk7XHJcbiAgICBzZXRIZWFkZXJCYWNrZ3JvdW5kQ29sb3IoY29sb3IpO1xyXG4gIH1cclxuXHJcbiAgY29uc3Qgb25IZWFkZXJUZXh0Q29sb3IgPSAoY29sb3I6IHN0cmluZyk9PnsgICAgICAgIFxyXG4gICAgcHJvcHMub25TZXR0aW5nQ2hhbmdlKHtcclxuICAgICAgaWQ6IHByb3BzLmlkLFxyXG4gICAgICBjb25maWc6IHByb3BzLmNvbmZpZy5zZXQoJ2hlYWRlclRleHRDb2xvcicsIGNvbG9yKVxyXG4gICAgfSk7XHJcbiAgICBzZXRIZWFkZXJUZXh0Q29sb3IoY29sb3IpO1xyXG4gIH1cclxuXHJcbiAgY29uc3Qgb25EZWZhdWx0QnV0dG9uQmFja2dyb3VuZENvbG9yQ2hhbmdlID0gKGNvbG9yOiBzdHJpbmcpPT57ICAgICAgICBcclxuICAgIHByb3BzLm9uU2V0dGluZ0NoYW5nZSh7XHJcbiAgICAgIGlkOiBwcm9wcy5pZCxcclxuICAgICAgY29uZmlnOiBwcm9wcy5jb25maWcuc2V0KCdkZWZhdWx0QnV0dG9uQmFja2dyb3VuZENvbG9yJywgY29sb3IpXHJcbiAgICB9KTtcclxuICAgIHNldERlZmF1bHRCdXR0b25CYWNrZ3JvdW5kQ29sb3IoY29sb3IpO1xyXG4gIH1cclxuXHJcbiAgY29uc3Qgb25EZWZhdWx0QnV0dG9uVGV4dENvbG9yQ2hhbmdlID0gKGNvbG9yOiBzdHJpbmcpPT57ICAgICAgICBcclxuICAgIHByb3BzLm9uU2V0dGluZ0NoYW5nZSh7XHJcbiAgICAgIGlkOiBwcm9wcy5pZCxcclxuICAgICAgY29uZmlnOiBwcm9wcy5jb25maWcuc2V0KCdkZWZhdWx0QnV0dG9uQ29sb3InLCBjb2xvcilcclxuICAgIH0pO1xyXG4gICAgc2V0RGVmYXVsdEJ1dHRvblRleHRDb2xvcihjb2xvcik7XHJcbiAgfVxyXG5cclxuICBjb25zdCBvblNlbGVjdGVkQnV0dG9uQmFja2dyb3VuZENvbG9yQ2hhbmdlID0gKGNvbG9yOiBzdHJpbmcpPT57IFxyXG4gICAgcHJvcHMub25TZXR0aW5nQ2hhbmdlKHtcclxuICAgICAgaWQ6IHByb3BzLmlkLFxyXG4gICAgICBjb25maWc6IHByb3BzLmNvbmZpZy5zZXQoJ3NlbGVjdGVkQnV0dG9uQmFja2dyb3VuZENvbG9yJywgY29sb3IpXHJcbiAgICB9KTtcclxuICAgIHNldFNlbGVjdGVkQnV0dG9uQmFja2dyb3VuZENvbG9yKGNvbG9yKTtcclxuICB9XHJcblxyXG4gIGNvbnN0IG9uU2VsZWN0ZWRCdXR0b25UZXh0Q29sb3JDaGFuZ2UgPSAoY29sb3I6IHN0cmluZyk9PnsgICAgICAgIFxyXG4gICAgcHJvcHMub25TZXR0aW5nQ2hhbmdlKHtcclxuICAgICAgaWQ6IHByb3BzLmlkLFxyXG4gICAgICBjb25maWc6IHByb3BzLmNvbmZpZy5zZXQoJ3NlbGVjdGVkQnV0dG9uQ29sb3InLCBjb2xvcilcclxuICAgIH0pO1xyXG4gICAgc2V0U2VsZWN0ZWRCdXR0b25UZXh0Q29sb3IoY29sb3IpO1xyXG4gIH1cclxuICByZXR1cm4gKFxyXG4gICAgPGRpdiBjbGFzc05hbWU9XCJ3aWRnZXQtc2V0dGluZ1wiPiAgXHJcblxyXG4gICAgICAgIDxTZXR0aW5nU2VjdGlvblxyXG4gICAgICAgICAgdGl0bGU9e3Byb3BzLmludGwuZm9ybWF0TWVzc2FnZSh7XHJcbiAgICAgICAgICAgIGlkOiBcInNldHRpbmdzTGFiZWxcIixcclxuICAgICAgICAgICAgZGVmYXVsdE1lc3NhZ2U6IGRlZmF1bHRJMThuTWVzc2FnZXMuc2V0dGluZ3NcclxuICAgICAgICAgIH0pfT5cclxuXHJcbiAgICAgICAgICA8U2V0dGluZ1Jvdz5cclxuICAgICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGp1c3RpZnlDb250ZW50OiAnc3BhY2UtYmV0d2VlbicsIHdpZHRoOiAnMTAwJSd9fT5cclxuICAgICAgICAgICAgICAgIDxoNCBzdHlsZT17e2ZsZXg6ICcxJ319PkhlYWRlciBCYWNrZ3JvdW5kPC9oND5cclxuICAgICAgICAgICAgICAgIDxUaGVtZUNvbG9yUGlja2VyXHJcbiAgICAgICAgICAgICAgICAgIGNvbG9yPXtoZWFkZXJCYWNrZ3JvdW5kQ29sb3J9XHJcbiAgICAgICAgICAgICAgICAgIGhlaWdodD17MjZ9XHJcbiAgICAgICAgICAgICAgICAgIGljb249XCJub25lXCJcclxuICAgICAgICAgICAgICAgICAgdmFsdWU9e2hlYWRlckJhY2tncm91bmRDb2xvcn1cclxuICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhjKT0+IG9uSGVhZGVyQmFja2dyb3VuZENvbG9yKGMpfVxyXG4gICAgICAgICAgICAgICAgICBwbGFjZW1lbnQ9XCJhdXRvXCJcclxuICAgICAgICAgICAgICAgICAgdHlwZT1cImRlZmF1bHRcIlxyXG4gICAgICAgICAgICAgICAgICB3aWR0aD17MzB9XHJcbiAgICAgICAgICAgICAgICAvPlxyXG4gICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICAgIDwvU2V0dGluZ1Jvdz5cclxuXHJcbiAgICAgICAgICA8U2V0dGluZ1Jvdz5cclxuICAgICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGp1c3RpZnlDb250ZW50OiAnc3BhY2UtYmV0d2VlbicsIHdpZHRoOiAnMTAwJSd9fT5cclxuICAgICAgICAgICAgICAgIDxoNCBzdHlsZT17e2ZsZXg6ICcxJ319PkhlYWRlciBUZXh0IENvbG9yPC9oND5cclxuICAgICAgICAgICAgICAgIDxUaGVtZUNvbG9yUGlja2VyXHJcbiAgICAgICAgICAgICAgICAgIGNvbG9yPXtoZWFkZXJUZXh0Q29sb3J9XHJcbiAgICAgICAgICAgICAgICAgIGhlaWdodD17MjZ9XHJcbiAgICAgICAgICAgICAgICAgIGljb249XCJub25lXCJcclxuICAgICAgICAgICAgICAgICAgdmFsdWU9e2hlYWRlclRleHRDb2xvcn1cclxuICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhjKT0+IG9uSGVhZGVyVGV4dENvbG9yKGMpfVxyXG4gICAgICAgICAgICAgICAgICBwbGFjZW1lbnQ9XCJhdXRvXCJcclxuICAgICAgICAgICAgICAgICAgdHlwZT1cImRlZmF1bHRcIlxyXG4gICAgICAgICAgICAgICAgICB3aWR0aD17MzB9XHJcbiAgICAgICAgICAgICAgICAvPlxyXG4gICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICAgIDwvU2V0dGluZ1Jvdz5cclxuXHJcbiAgICAgICAgICA8U2V0dGluZ1Jvdz5cclxuICAgICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGp1c3RpZnlDb250ZW50OiAnc3BhY2UtYmV0d2VlbicsIHdpZHRoOiAnMTAwJSd9fT5cclxuICAgICAgICAgICAgICAgIDxoNCBzdHlsZT17e2ZsZXg6ICcxJ319PkRlZmF1bHQgQnV0dG9uIEJhY2tncm91bmQgQ29sb3I8L2g0PlxyXG4gICAgICAgICAgICAgICAgPFRoZW1lQ29sb3JQaWNrZXJcclxuICAgICAgICAgICAgICAgICAgY29sb3I9e2RlZmF1bHRCdXR0b25CYWNrZ3JvdW5kQ29sb3J9XHJcbiAgICAgICAgICAgICAgICAgIGhlaWdodD17MjZ9XHJcbiAgICAgICAgICAgICAgICAgIGljb249XCJub25lXCJcclxuICAgICAgICAgICAgICAgICAgdmFsdWU9e2RlZmF1bHRCdXR0b25CYWNrZ3JvdW5kQ29sb3J9XHJcbiAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsoYyk9PiBvbkRlZmF1bHRCdXR0b25CYWNrZ3JvdW5kQ29sb3JDaGFuZ2UoYyl9XHJcbiAgICAgICAgICAgICAgICAgIHBsYWNlbWVudD1cImF1dG9cIlxyXG4gICAgICAgICAgICAgICAgICB0eXBlPVwiZGVmYXVsdFwiXHJcbiAgICAgICAgICAgICAgICAgIHdpZHRoPXszMH1cclxuICAgICAgICAgICAgICAgIC8+XHJcbiAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgICAgPC9TZXR0aW5nUm93PlxyXG5cclxuICAgICAgICAgIDxTZXR0aW5nUm93PlxyXG4gICAgICAgICAgICA8ZGl2IHN0eWxlPXt7IGRpc3BsYXk6ICdmbGV4JywganVzdGlmeUNvbnRlbnQ6ICdzcGFjZS1iZXR3ZWVuJywgd2lkdGg6ICcxMDAlJ319PlxyXG4gICAgICAgICAgICAgICAgPGg0IHN0eWxlPXt7ZmxleDogJzEnfX0+RGVmYXVsdCBCdXR0b24gVGV4dCBDb2xvcjwvaDQ+XHJcbiAgICAgICAgICAgICAgICA8VGhlbWVDb2xvclBpY2tlclxyXG4gICAgICAgICAgICAgICAgICBjb2xvcj17ZGVmYXVsdEJ1dHRvblRleHRDb2xvcn1cclxuICAgICAgICAgICAgICAgICAgaGVpZ2h0PXsyNn1cclxuICAgICAgICAgICAgICAgICAgaWNvbj1cIm5vbmVcIlxyXG4gICAgICAgICAgICAgICAgICB2YWx1ZT17ZGVmYXVsdEJ1dHRvblRleHRDb2xvcn1cclxuICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhjKT0+IG9uRGVmYXVsdEJ1dHRvblRleHRDb2xvckNoYW5nZShjKX1cclxuICAgICAgICAgICAgICAgICAgcGxhY2VtZW50PVwiYXV0b1wiXHJcbiAgICAgICAgICAgICAgICAgIHR5cGU9XCJkZWZhdWx0XCJcclxuICAgICAgICAgICAgICAgICAgd2lkdGg9ezMwfVxyXG4gICAgICAgICAgICAgICAgLz5cclxuICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgICA8L1NldHRpbmdSb3c+XHJcblxyXG4gICAgICAgICAgPFNldHRpbmdSb3c+XHJcbiAgICAgICAgICAgIDxkaXYgc3R5bGU9e3sgZGlzcGxheTogJ2ZsZXgnLCBqdXN0aWZ5Q29udGVudDogJ3NwYWNlLWJldHdlZW4nLCB3aWR0aDogJzEwMCUnfX0+XHJcbiAgICAgICAgICAgICAgICA8aDQgc3R5bGU9e3tmbGV4OiAnMSd9fT5TZWxlY3RlZCBCdXR0b24gQmFja2dyb3VuZCBDb2xvcjwvaDQ+XHJcbiAgICAgICAgICAgICAgICA8VGhlbWVDb2xvclBpY2tlclxyXG4gICAgICAgICAgICAgICAgICBjb2xvcj17c2VsZWN0ZWRCdXR0b25CYWNrZ3JvdW5kQ29sb3J9XHJcbiAgICAgICAgICAgICAgICAgIGhlaWdodD17MjZ9XHJcbiAgICAgICAgICAgICAgICAgIGljb249XCJub25lXCJcclxuICAgICAgICAgICAgICAgICAgdmFsdWU9e3NlbGVjdGVkQnV0dG9uQmFja2dyb3VuZENvbG9yfVxyXG4gICAgICAgICAgICAgICAgICBvbkNoYW5nZT17KGMpPT4gb25TZWxlY3RlZEJ1dHRvbkJhY2tncm91bmRDb2xvckNoYW5nZShjKX1cclxuICAgICAgICAgICAgICAgICAgcGxhY2VtZW50PVwiYXV0b1wiXHJcbiAgICAgICAgICAgICAgICAgIHR5cGU9XCJkZWZhdWx0XCJcclxuICAgICAgICAgICAgICAgICAgd2lkdGg9ezMwfVxyXG4gICAgICAgICAgICAgICAgLz5cclxuICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgICA8L1NldHRpbmdSb3c+XHJcbiAgICAgICAgXHJcbiAgICAgICAgICA8U2V0dGluZ1Jvdz5cclxuICAgICAgICAgICAgPGRpdiBzdHlsZT17eyBkaXNwbGF5OiAnZmxleCcsIGp1c3RpZnlDb250ZW50OiAnc3BhY2UtYmV0d2VlbicsIHdpZHRoOiAnMTAwJSd9fT5cclxuICAgICAgICAgICAgICAgIDxoNCBzdHlsZT17e2ZsZXg6ICcxJ319PlNlbGVjdGVkIEJ1dHRvbiBUZXh0IENvbG9yPC9oND5cclxuICAgICAgICAgICAgICAgIDxUaGVtZUNvbG9yUGlja2VyXHJcbiAgICAgICAgICAgICAgICAgIGNvbG9yPXtzZWxlY3RlZEJ1dHRvblRleHRDb2xvcn1cclxuICAgICAgICAgICAgICAgICAgaGVpZ2h0PXsyNn1cclxuICAgICAgICAgICAgICAgICAgaWNvbj1cIm5vbmVcIlxyXG4gICAgICAgICAgICAgICAgICB2YWx1ZT17c2VsZWN0ZWRCdXR0b25UZXh0Q29sb3J9XHJcbiAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsoYyk9PiBvblNlbGVjdGVkQnV0dG9uVGV4dENvbG9yQ2hhbmdlKGMpfVxyXG4gICAgICAgICAgICAgICAgICBwbGFjZW1lbnQ9XCJhdXRvXCJcclxuICAgICAgICAgICAgICAgICAgdHlwZT1cImRlZmF1bHRcIlxyXG4gICAgICAgICAgICAgICAgICB3aWR0aD17MzB9XHJcbiAgICAgICAgICAgICAgICAvPlxyXG4gICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICAgIDwvU2V0dGluZ1Jvdz5cclxuICAgICAgICA8L1NldHRpbmdTZWN0aW9uPlxyXG4gICAgICA8L2Rpdj5cclxuICApO1xyXG59OyJdLCJuYW1lcyI6W10sInNvdXJjZVJvb3QiOiIifQ==