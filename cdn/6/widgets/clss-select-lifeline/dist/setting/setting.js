System.register(["jimu-core","jimu-ui/advanced/setting-components","jimu-ui","jimu-ui/basic/color-picker"], function(__WEBPACK_DYNAMIC_EXPORT__, __system_context__) {
	var __WEBPACK_EXTERNAL_MODULE_jimu_core__ = {};
	var __WEBPACK_EXTERNAL_MODULE_jimu_ui_advanced_setting_components__ = {};
	var __WEBPACK_EXTERNAL_MODULE_jimu_ui__ = {};
	var __WEBPACK_EXTERNAL_MODULE_jimu_ui_basic_color_picker__ = {};
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_jimu_core__, "__esModule", { value: true });
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_jimu_ui_advanced_setting_components__, "__esModule", { value: true });
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_jimu_ui__, "__esModule", { value: true });
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
					__WEBPACK_EXTERNAL_MODULE_jimu_ui__[key] = module[key];
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

/***/ "./your-extensions/widgets/clss-select-lifeline/src/setting/translations/default.ts":
/*!******************************************************************************************!*\
  !*** ./your-extensions/widgets/clss-select-lifeline/src/setting/translations/default.ts ***!
  \******************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = ({
    settings: "Settings"
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

/***/ "jimu-ui":
/*!**************************!*\
  !*** external "jimu-ui" ***!
  \**************************/
/***/ ((module) => {

"use strict";
module.exports = __WEBPACK_EXTERNAL_MODULE_jimu_ui__;

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
/*!******************************************************************************!*\
  !*** ./your-extensions/widgets/clss-select-lifeline/src/setting/setting.tsx ***!
  \******************************************************************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ Setting)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-ui/advanced/setting-components */ "jimu-ui/advanced/setting-components");
/* harmony import */ var _translations_default__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./translations/default */ "./your-extensions/widgets/clss-select-lifeline/src/setting/translations/default.ts");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! jimu-ui/basic/color-picker */ "jimu-ui/basic/color-picker");





function Setting(props) {
    const [fontColor, setFontColor] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.fontColor);
    const [backgroundColor, setBackgroundColor] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.backgroundColor);
    const [selectedBackgroundColor, setSelectedBackgroundColor] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.selectedBackgroundColor);
    const onFontColorChange = (color) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('fontColor', color)
        });
        setFontColor(color);
    };
    const onBackgroundColorChange = (color) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('backgroundColor', color)
        });
        setBackgroundColor(color);
    };
    const onSelectedBackgroundColorChange = (color) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('selectedBackgroundColor', color)
        });
        setSelectedBackgroundColor(color);
    };
    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "widget-setting-template-container" },
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingSection, { title: props.intl.formatMessage({
                id: "settingsLabel",
                defaultMessage: _translations_default__WEBPACK_IMPORTED_MODULE_2__["default"].settings
            }) },
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_3__.Label, { check: true, size: "lg" }, "Font Color"),
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_4__.ThemeColorPicker, { color: fontColor, height: 26, icon: "none", value: fontColor, onChange: (c) => onFontColorChange(c), placement: "auto", type: "default", width: 30 })),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_3__.Label, { check: true, size: "lg" }, "Background Color"),
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_4__.ThemeColorPicker, { color: backgroundColor, height: 26, icon: "none", value: backgroundColor, onChange: (c) => onBackgroundColorChange(c), placement: "auto", type: "default", width: 30 })),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_3__.Label, { check: true, size: "lg" }, "Selected BackgroundColor"),
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_4__.ThemeColorPicker, { color: selectedBackgroundColor, height: 26, icon: "none", value: selectedBackgroundColor, onChange: (c) => onSelectedBackgroundColorChange(c), placement: "auto", type: "default", width: 30 })))));
}
;

})();

/******/ 	return __webpack_exports__;
/******/ })()

			);
		}
	};
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2lkZ2V0cy9jbHNzLXNlbGVjdC1saWZlbGluZS9kaXN0L3NldHRpbmcvc2V0dGluZy5qcyIsIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFBQSxpRUFBZTtJQUNiLFFBQVEsRUFBRSxVQUFVO0NBQ3JCLEVBQUM7Ozs7Ozs7Ozs7OztBQ0ZGOzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7VUNBQTtVQUNBOztVQUVBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBOztVQUVBO1VBQ0E7O1VBRUE7VUFDQTtVQUNBOzs7OztXQ3RCQTtXQUNBO1dBQ0E7V0FDQTtXQUNBLHlDQUF5Qyx3Q0FBd0M7V0FDakY7V0FDQTtXQUNBOzs7OztXQ1BBOzs7OztXQ0FBO1dBQ0E7V0FDQTtXQUNBLHVEQUF1RCxpQkFBaUI7V0FDeEU7V0FDQSxnREFBZ0QsYUFBYTtXQUM3RDs7Ozs7V0NOQTs7Ozs7Ozs7OztBQ0FBOzs7S0FHSztBQUNMLDJCQUEyQjtBQUMzQixhQUFhO0FBQ2IscUJBQXVCLEdBQUcsTUFBTSxDQUFDLFVBQVUsQ0FBQyxPQUFPOzs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDTGpCO0FBSTJCO0FBRUo7QUFDekI7QUFDOEI7QUFFL0MsU0FBUyxPQUFPLENBQUUsS0FBc0M7SUFFckUsTUFBTSxDQUFDLFNBQVMsRUFBRSxZQUFZLENBQUMsR0FBRyxxREFBYyxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLENBQUM7SUFDekUsTUFBTSxDQUFDLGVBQWUsRUFBRSxrQkFBa0IsQ0FBQyxHQUFHLHFEQUFjLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxlQUFlLENBQUMsQ0FBQztJQUMzRixNQUFNLENBQUMsdUJBQXVCLEVBQUUsMEJBQTBCLENBQUMsR0FBRyxxREFBYyxDQUFDLEtBQUssQ0FBQyxNQUFNLENB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QztBQUFBLENBQUMiLCJzb3VyY2VzIjpbIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1zZWxlY3QtbGlmZWxpbmUvc3JjL3NldHRpbmcvdHJhbnNsYXRpb25zL2RlZmF1bHQudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC9leHRlcm5hbCBzeXN0ZW0gXCJqaW11LWNvcmVcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtdWlcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtdWkvYWR2YW5jZWQvc2V0dGluZy1jb21wb25lbnRzXCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC9leHRlcm5hbCBzeXN0ZW0gXCJqaW11LXVpL2Jhc2ljL2NvbG9yLXBpY2tlclwiIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ib290c3RyYXAiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvZGVmaW5lIHByb3BlcnR5IGdldHRlcnMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvaGFzT3duUHJvcGVydHkgc2hvcnRoYW5kIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL21ha2UgbmFtZXNwYWNlIG9iamVjdCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9wdWJsaWNQYXRoIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWNvcmUvbGliL3NldC1wdWJsaWMtcGF0aC50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1zZWxlY3QtbGlmZWxpbmUvc3JjL3NldHRpbmcvc2V0dGluZy50c3giXSwic291cmNlc0NvbnRlbnQiOlsiZXhwb3J0IGRlZmF1bHQgeyBcclxuICBzZXR0aW5nczogXCJTZXR0aW5nc1wiXHJcbn07XHJcbiIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X2NvcmVfXzsiLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfamltdV91aV9fOyIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X3VpX2FkdmFuY2VkX3NldHRpbmdfY29tcG9uZW50c19fOyIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X3VpX2Jhc2ljX2NvbG9yX3BpY2tlcl9fOyIsIi8vIFRoZSBtb2R1bGUgY2FjaGVcbnZhciBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX18gPSB7fTtcblxuLy8gVGhlIHJlcXVpcmUgZnVuY3Rpb25cbmZ1bmN0aW9uIF9fd2VicGFja19yZXF1aXJlX18obW9kdWxlSWQpIHtcblx0Ly8gQ2hlY2sgaWYgbW9kdWxlIGlzIGluIGNhY2hlXG5cdHZhciBjYWNoZWRNb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdO1xuXHRpZiAoY2FjaGVkTW9kdWxlICE9PSB1bmRlZmluZWQpIHtcblx0XHRyZXR1cm4gY2FjaGVkTW9kdWxlLmV4cG9ydHM7XG5cdH1cblx0Ly8gQ3JlYXRlIGEgbmV3IG1vZHVsZSAoYW5kIHB1dCBpdCBpbnRvIHRoZSBjYWNoZSlcblx0dmFyIG1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF0gPSB7XG5cdFx0Ly8gbm8gbW9kdWxlLmlkIG5lZWRlZFxuXHRcdC8vIG5vIG1vZHVsZS5sb2FkZWQgbmVlZGVkXG5cdFx0ZXhwb3J0czoge31cblx0fTtcblxuXHQvLyBFeGVjdXRlIHRoZSBtb2R1bGUgZnVuY3Rpb25cblx0X193ZWJwYWNrX21vZHVsZXNfX1ttb2R1bGVJZF0obW9kdWxlLCBtb2R1bGUuZXhwb3J0cywgX193ZWJwYWNrX3JlcXVpcmVfXyk7XG5cblx0Ly8gUmV0dXJuIHRoZSBleHBvcnRzIG9mIHRoZSBtb2R1bGVcblx0cmV0dXJuIG1vZHVsZS5leHBvcnRzO1xufVxuXG4iLCIvLyBkZWZpbmUgZ2V0dGVyIGZ1bmN0aW9ucyBmb3IgaGFybW9ueSBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLmQgPSAoZXhwb3J0cywgZGVmaW5pdGlvbikgPT4ge1xuXHRmb3IodmFyIGtleSBpbiBkZWZpbml0aW9uKSB7XG5cdFx0aWYoX193ZWJwYWNrX3JlcXVpcmVfXy5vKGRlZmluaXRpb24sIGtleSkgJiYgIV9fd2VicGFja19yZXF1aXJlX18ubyhleHBvcnRzLCBrZXkpKSB7XG5cdFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywga2V5LCB7IGVudW1lcmFibGU6IHRydWUsIGdldDogZGVmaW5pdGlvbltrZXldIH0pO1xuXHRcdH1cblx0fVxufTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLm8gPSAob2JqLCBwcm9wKSA9PiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCkpIiwiLy8gZGVmaW5lIF9fZXNNb2R1bGUgb24gZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5yID0gKGV4cG9ydHMpID0+IHtcblx0aWYodHlwZW9mIFN5bWJvbCAhPT0gJ3VuZGVmaW5lZCcgJiYgU3ltYm9sLnRvU3RyaW5nVGFnKSB7XG5cdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFN5bWJvbC50b1N0cmluZ1RhZywgeyB2YWx1ZTogJ01vZHVsZScgfSk7XG5cdH1cblx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsICdfX2VzTW9kdWxlJywgeyB2YWx1ZTogdHJ1ZSB9KTtcbn07IiwiX193ZWJwYWNrX3JlcXVpcmVfXy5wID0gXCJcIjsiLCIvKipcclxuICogV2VicGFjayB3aWxsIHJlcGxhY2UgX193ZWJwYWNrX3B1YmxpY19wYXRoX18gd2l0aCBfX3dlYnBhY2tfcmVxdWlyZV9fLnAgdG8gc2V0IHRoZSBwdWJsaWMgcGF0aCBkeW5hbWljYWxseS5cclxuICogVGhlIHJlYXNvbiB3aHkgd2UgY2FuJ3Qgc2V0IHRoZSBwdWJsaWNQYXRoIGluIHdlYnBhY2sgY29uZmlnIGlzOiB3ZSBjaGFuZ2UgdGhlIHB1YmxpY1BhdGggd2hlbiBkb3dubG9hZC5cclxuICogKi9cclxuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lXHJcbi8vIEB0cy1pZ25vcmVcclxuX193ZWJwYWNrX3B1YmxpY19wYXRoX18gPSB3aW5kb3cuamltdUNvbmZpZy5iYXNlVXJsXHJcbiIsIlxyXG5pbXBvcnQgeyBSZWFjdCB9IGZyb20gXCJqaW11LWNvcmVcIjtcclxuaW1wb3J0IHsgQWxsV2lkZ2V0U2V0dGluZ1Byb3BzIH0gZnJvbSBcImppbXUtZm9yLWJ1aWxkZXJcIjtcclxuaW1wb3J0IHtcclxuICBTZXR0aW5nUm93LFxyXG4gIFNldHRpbmdTZWN0aW9ufSBmcm9tIFwiamltdS11aS9hZHZhbmNlZC9zZXR0aW5nLWNvbXBvbmVudHNcIjtcclxuaW1wb3J0IHsgSU1Db25maWcgfSBmcm9tIFwiLi4vY29uZmlnXCI7XHJcbmltcG9ydCBkZWZhdWx0STE4bk1lc3NhZ2VzIGZyb20gXCIuL3RyYW5zbGF0aW9ucy9kZWZhdWx0XCI7XHJcbmltcG9ydCB7IExhYmVsIH0gZnJvbSBcImppbXUtdWlcIjtcclxuaW1wb3J0IHsgVGhlbWVDb2xvclBpY2tlciB9IGZyb20gXCJqaW11LXVpL2Jhc2ljL2NvbG9yLXBpY2tlclwiO1xyXG5cclxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gU2V0dGluZyAocHJvcHM6IEFsbFdpZGdldFNldHRpbmdQcm9wczxJTUNvbmZpZz4pIHsgXHJcblxyXG4gIGNvbnN0IFtmb250Q29sb3IsIHNldEZvbnRDb2xvcl0gPSBSZWFjdC51c2VTdGF0ZShwcm9wcy5jb25maWcuZm9udENvbG9yKTtcclxuICBjb25zdCBbYmFja2dyb3VuZENvbG9yLCBzZXRCYWNrZ3JvdW5kQ29sb3JdID0gUmVhY3QudXNlU3RhdGUocHJvcHMuY29uZmlnLmJhY2tncm91bmRDb2xvcik7XHJcbiAgY29uc3QgW3NlbGVjdGVkQmFja2dyb3VuZENvbG9yLCBzZXRTZWxlY3RlZEJhY2tncm91bmRDb2xvcl0gPSBSZWFjdC51c2VTdGF0ZShwcm9wcy5jb25maWcuc2VsZWN0ZWRCYWNrZ3JvdW5kQ29sb3IpO1xyXG5cclxuICBjb25zdCBvbkZvbnRDb2xvckNoYW5nZSA9KGNvbG9yOiBzdHJpbmcpID0+e1xyXG4gICAgcHJvcHMub25TZXR0aW5nQ2hhbmdlKHtcclxuICAgICAgaWQ6IHByb3BzLmlkLFxyXG4gICAgICBjb25maWc6IHByb3BzLmNvbmZpZy5zZXQoJ2ZvbnRDb2xvcicsIGNvbG9yKVxyXG4gICAgfSk7XHJcbiAgICBzZXRGb250Q29sb3IoY29sb3IpO1xyXG4gIH1cclxuXHJcbiAgY29uc3Qgb25CYWNrZ3JvdW5kQ29sb3JDaGFuZ2UgPShjb2xvcjogc3RyaW5nKSA9PntcclxuICAgIHByb3BzLm9uU2V0dGluZ0NoYW5nZSh7XHJcbiAgICAgIGlkOiBwcm9wcy5pZCxcclxuICAgICAgY29uZmlnOiBwcm9wcy5jb25maWcuc2V0KCdiYWNrZ3JvdW5kQ29sb3InLCBjb2xvcilcclxuICAgIH0pO1xyXG4gICAgc2V0QmFja2dyb3VuZENvbG9yKGNvbG9yKTtcclxuICB9XHJcblxyXG4gIGNvbnN0IG9uU2VsZWN0ZWRCYWNrZ3JvdW5kQ29sb3JDaGFuZ2UgPShjb2xvcjogc3RyaW5nKSA9PntcclxuICAgIHByb3BzLm9uU2V0dGluZ0NoYW5nZSh7XHJcbiAgICAgIGlkOiBwcm9wcy5pZCxcclxuICAgICAgY29uZmlnOiBwcm9wcy5jb25maWcuc2V0KCdzZWxlY3RlZEJhY2tncm91bmRDb2xvcicsIGNvbG9yKVxyXG4gICAgfSk7XHJcbiAgICBzZXRTZWxlY3RlZEJhY2tncm91bmRDb2xvcihjb2xvcik7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gKFxyXG4gICAgPGRpdiBjbGFzc05hbWU9XCJ3aWRnZXQtc2V0dGluZy10ZW1wbGF0ZS1jb250YWluZXJcIj4gICAgICAgIFxyXG5cclxuICAgICAgICA8U2V0dGluZ1NlY3Rpb25cclxuICAgICAgICAgIHRpdGxlPXtwcm9wcy5pbnRsLmZvcm1hdE1lc3NhZ2Uoe1xyXG4gICAgICAgICAgICBpZDogXCJzZXR0aW5nc0xhYmVsXCIsXHJcbiAgICAgICAgICAgIGRlZmF1bHRNZXNzYWdlOiBkZWZhdWx0STE4bk1lc3NhZ2VzLnNldHRpbmdzXHJcbiAgICAgICAgICB9KX1cclxuICAgICAgICA+XHJcbiAgICAgICAgICA8U2V0dGluZ1Jvdz5cclxuXHJcbiAgICAgICAgICAgIDxMYWJlbCBjaGVjayBzaXplPVwibGdcIj5cclxuICAgICAgICAgICAgICBGb250IENvbG9yXHJcbiAgICAgICAgICAgIDwvTGFiZWw+XHJcblxyXG4gICAgICAgICAgICA8VGhlbWVDb2xvclBpY2tlclxyXG4gICAgICAgICAgICAgICAgICBjb2xvcj17Zm9udENvbG9yfVxyXG4gICAgICAgICAgICAgICAgICBoZWlnaHQ9ezI2fVxyXG4gICAgICAgICAgICAgICAgICBpY29uPVwibm9uZVwiXHJcbiAgICAgICAgICAgICAgICAgIHZhbHVlPXtmb250Q29sb3J9XHJcbiAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsoYyk9PiBvbkZvbnRDb2xvckNoYW5nZShjKX1cclxuICAgICAgICAgICAgICAgICAgcGxhY2VtZW50PVwiYXV0b1wiXHJcbiAgICAgICAgICAgICAgICAgIHR5cGU9XCJkZWZhdWx0XCJcclxuICAgICAgICAgICAgICAgICAgd2lkdGg9ezMwfVxyXG4gICAgICAgICAgICAgICAgLz5cclxuICAgICAgICAgIDwvU2V0dGluZ1Jvdz4gICAgICAgXHJcblxyXG4gICAgICAgICAgPFNldHRpbmdSb3c+XHJcblxyXG4gICAgICAgICAgICA8TGFiZWwgY2hlY2sgc2l6ZT1cImxnXCI+XHJcbiAgICAgICAgICAgICAgQmFja2dyb3VuZCBDb2xvclxyXG4gICAgICAgICAgICA8L0xhYmVsPlxyXG5cclxuICAgICAgICAgICAgPFRoZW1lQ29sb3JQaWNrZXJcclxuICAgICAgICAgICAgICAgICAgY29sb3I9e2JhY2tncm91bmRDb2xvcn1cclxuICAgICAgICAgICAgICAgICAgaGVpZ2h0PXsyNn1cclxuICAgICAgICAgICAgICAgICAgaWNvbj1cIm5vbmVcIlxyXG4gICAgICAgICAgICAgICAgICB2YWx1ZT17YmFja2dyb3VuZENvbG9yfVxyXG4gICAgICAgICAgICAgICAgICBvbkNoYW5nZT17KGMpPT4gb25CYWNrZ3JvdW5kQ29sb3JDaGFuZ2UoYyl9XHJcbiAgICAgICAgICAgICAgICAgIHBsYWNlbWVudD1cImF1dG9cIlxyXG4gICAgICAgICAgICAgICAgICB0eXBlPVwiZGVmYXVsdFwiXHJcbiAgICAgICAgICAgICAgICAgIHdpZHRoPXszMH1cclxuICAgICAgICAgICAgICAgIC8+XHJcbiAgICAgICAgICA8L1NldHRpbmdSb3c+ICAgXHJcblxyXG4gICAgICAgICAgPFNldHRpbmdSb3c+XHJcblxyXG4gICAgICAgICAgICA8TGFiZWwgY2hlY2sgc2l6ZT1cImxnXCI+XHJcbiAgICAgICAgICAgICAgU2VsZWN0ZWQgQmFja2dyb3VuZENvbG9yXHJcbiAgICAgICAgICAgIDwvTGFiZWw+XHJcblxyXG4gICAgICAgICAgICA8VGhlbWVDb2xvclBpY2tlclxyXG4gICAgICAgICAgICAgICAgICBjb2xvcj17c2VsZWN0ZWRCYWNrZ3JvdW5kQ29sb3J9XHJcbiAgICAgICAgICAgICAgICAgIGhlaWdodD17MjZ9XHJcbiAgICAgICAgICAgICAgICAgIGljb249XCJub25lXCJcclxuICAgICAgICAgICAgICAgICAgdmFsdWU9e3NlbGVjdGVkQmFja2dyb3VuZENvbG9yfVxyXG4gICAgICAgICAgICAgICAgICBvbkNoYW5nZT17KGMpPT4gb25TZWxlY3RlZEJhY2tncm91bmRDb2xvckNoYW5nZShjKX1cclxuICAgICAgICAgICAgICAgICAgcGxhY2VtZW50PVwiYXV0b1wiXHJcbiAgICAgICAgICAgICAgICAgIHR5cGU9XCJkZWZhdWx0XCJcclxuICAgICAgICAgICAgICAgICAgd2lkdGg9ezMwfVxyXG4gICAgICAgICAgICAgICAgLz5cclxuICAgICAgICAgIDwvU2V0dGluZ1Jvdz4gICAgICAgXHJcbiAgICAgICAgPC9TZXR0aW5nU2VjdGlvbj5cclxuICAgICAgPC9kaXY+XHJcbiAgKTtcclxufTsiXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=