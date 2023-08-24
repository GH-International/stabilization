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

/***/ "./your-extensions/widgets/clss-template-detail/src/setting/translations/default.ts":
/*!******************************************************************************************!*\
  !*** ./your-extensions/widgets/clss-template-detail/src/setting/translations/default.ts ***!
  \******************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = ({
    settings: "Settings",
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
  !*** ./your-extensions/widgets/clss-template-detail/src/setting/setting.tsx ***!
  \******************************************************************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ Setting)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-ui/advanced/setting-components */ "jimu-ui/advanced/setting-components");
/* harmony import */ var _translations_default__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./translations/default */ "./your-extensions/widgets/clss-template-detail/src/setting/translations/default.ts");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! jimu-ui/basic/color-picker */ "jimu-ui/basic/color-picker");





function Setting(props) {
    const [backgroundColor2, setBackgroundColor] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.backgoundColor);
    const [headerBackground, setHeaderBackground] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.headerBackgroundColor);
    const onBackgroundColorChange = (color) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('backgroundColor', color)
        });
        setBackgroundColor(color);
    };
    const onHeaderBackgroundColorChange = (color) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('headerBackgroundColor', color)
        });
        setBackgroundColor(color);
    };
    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "widget-setting-clss-user" },
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingSection, { title: props.intl.formatMessage({
                id: "settingsLabel",
                defaultMessage: _translations_default__WEBPACK_IMPORTED_MODULE_2__["default"].settings
            }) },
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_3__.Label, { style: { marginRight: '2em' }, check: true }, "Background Color"),
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_4__.ThemeColorPicker, { color: backgroundColor2, height: 26, icon: "none", value: backgroundColor2, onChange: (c) => onBackgroundColorChange(c), placement: "auto", type: "default", width: 30 })),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_3__.Label, { style: { marginRight: '2em' }, check: true }, "Header Background"),
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_4__.ThemeColorPicker, { color: headerBackground, height: 26, icon: "none", value: headerBackground, onChange: (c) => onHeaderBackgroundColorChange(c), placement: "auto", type: "default", width: 30 })))));
}
;

})();

/******/ 	return __webpack_exports__;
/******/ })()

			);
		}
	};
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2lkZ2V0cy9jbHNzLXRlbXBsYXRlLWRldGFpbC9kaXN0L3NldHRpbmcvc2V0dGluZy5qcyIsIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFBQSxpRUFBZTtJQUNiLFFBQVEsRUFBRSxVQUFVO0NBQ3JCLEVBQUM7Ozs7Ozs7Ozs7OztBQ0ZGOzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7VUNBQTtVQUNBOztVQUVBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBOztVQUVBO1VBQ0E7O1VBRUE7VUFDQTtVQUNBOzs7OztXQ3RCQTtXQUNBO1dBQ0E7V0FDQTtXQUNBLHlDQUF5Qyx3Q0FBd0M7V0FDakY7V0FDQTtXQUNBOzs7OztXQ1BBOzs7OztXQ0FBO1dBQ0E7V0FDQTtXQUNBLHVEQUF1RCxpQkFBaUI7V0FDeEU7V0FDQSxnREFBZ0QsYUFBYTtXQUM3RDs7Ozs7V0NOQTs7Ozs7Ozs7OztBQ0FBOzs7S0FHSztBQUNMLDJCQUEyQjtBQUMzQixhQUFhO0FBQ2IscUJBQXVCLEdBQUcsTUFBTSxDQUFDLFVBQVUsQ0FBQyxPQUFPOzs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDTGpCO0FBS1c7QUFFWTtBQUMxQjtBQUMrQjtBQUUvQyxTQUFTLE9BQU8sQ0FBRSxLQUFzQztJQUVyRSxNQUFNLENBQUMsZ0JBQWdCLEVBQUUsa0JBQWtCLENBQUMsR0FBRyxxREFBYyxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsY0FBYyxDQUFDLENBQUM7SUFDM0YsTUFBTSxDQUFDLGdCQUFnQixFQUFFLG1CQUFtQixDQUFDLEdBQUcscURBQWMsQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLHFCQUFxQixDQUFDLENBQUM7SUFFbkcsTUFBTSx1QkFBdUIsR0FBRyxDQUFDLEtBQWEsRUFBQyxFQUFFO1FBQy9DLEtBQUssQ0FBQyxlQUFlLENBQUM7WUFDcEIsRUFBRSxFQUFFLEtBQUssQ0FBQyxFQUFFO1lBQ1osTUFBTSxFQUFFLEtBQUssQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLGlCQUFpQixFQUFFLEtBQUssQ0FBQztTQUNuRCxDQUFDLENBQUM7UUFDSCxrQkFBa0IsQ0FBQyxLQUFLLENBQUMsQ0FBQztJQUM1QixDQUFDO0lBRUQsTUFBTSw2QkFBNkIsR0FBRyxDQUFDLEtBQWEsRUFBQyxFQUFFO1FBQ3JELEtBQUssQ0FBQyxlQUFlLENBQUM7WUFDcEIsRUFBRSxFQUFFLEtBQUssQ0FBQyxFQUFFO1lBQ1osTUFBTSxFQUFFLEtBQUssQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLHVCQUF1QixFQUFFLEtBQUssQ0FBQztTQUN6RCxDQUFDLENBQUM7UUFDSCxrQkFBa0IsQ0FBQyxLQUFLLENBQUMsQ0FBQztJQUM1QixDQUFDO0lBR0QsT0FBTyxDQUNMLG9FQUFLLFNBQVMsRUFBQywwQkFBMEI7UUFFckMsMkRBQUMsK0VBQWMsSUFDYixLQUFLLEVBQUUsS0FBSyxDQUFDLElBQUksQ0FBQyxhQUFhLENBQUM7Z0JBQzlCLEVBQUUsRUFBRSxlQUFlO2dCQUNuQixjQUFjLEVBQUUsc0VBQTRCO2FBQzdDLENBQUM7WUFFQSwyREFBQywyRUFBVTtnQkFDVCwyREFBQywwQ0FBSyxJQUFDLEtBQUssRUFBRSxFQUFDLFdBQVcsRUFBRSxLQUFLLEVBQUMsRUFBRSxLQUFLLDZCQUF5QjtnQkFDbEUsMkRBQUMsd0VBQWdCLElBQ2IsS0FBSyxFQUFFLGdCQUFnQixFQUN2QixNQUFNLEVBQUUsRUFBRSxFQUNWLElBQUksRUFBQyxNQUFNLEVBQ1gsS0FBSyxFQUFFLGdCQUFnQixFQUN2QixRQUFRLEVBQUUsQ0FBQyxDQUFDLEVBQUMsRUFBRSxDQUFDLHVCQUF1QixDQUFDLENBQUMsQ0FBQyxFQUMxQyxTQUFTLEVBQUMsTUFBTSxFQUNoQixJQUFJLEVBQUMsU0FBUyxFQUNkLEtBQUssRUFBRSxFQUFFLEdBQ1QsQ0FDTztZQUViLDJEQUFDLDJFQUFVO2dCQUNULDJEQUFDLDBDQUFLLElBQUMsS0FBSyxFQUFFLEVBQUMsV0FBVyxFQUFFLEtBQUssRUFBQyxFQUFFLEtBQUssOEJBQTBCO2dCQUNuRSwyREFBQyx3RUFBZ0IsSUFDYixLQUFLLEVBQUUsZ0JBQWdCLEVBQ3ZCLE1BQU0sRUFBRSxFQUFFLEVBQ1YsSUFBSSxFQUFDLE1BQU0sRUFDWCxLQUFLLEVBQUUsZ0JBQWdCLEVBQ3ZCLFFBQVEsRUFBRSxDQUFDLENBQUMsRUFBQyxFQUFFLENBQUMsNkJBQTZCLENBQUMsQ0FBQyxDQUFDLEVBQ2hELFNBQVMsRUFBQyxNQUFNLEVBQ2hCLElBQUksRUFBQyxTQUFTLEVBQ2QsS0FBSyxFQUFFLEVBQUUsR0FDVCxDQUNPLENBQ0EsQ0FDYixDQUNULENBQUM7QUFDSixDQUFDO0FBQUEsQ0FBQyIsInNvdXJjZXMiOlsid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLXRlbXBsYXRlLWRldGFpbC9zcmMvc2V0dGluZy90cmFuc2xhdGlvbnMvZGVmYXVsdC50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtY29yZVwiIiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS11aVwiIiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS11aS9hZHZhbmNlZC9zZXR0aW5nLWNvbXBvbmVudHNcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtdWkvYmFzaWMvY29sb3ItcGlja2VyXCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL2Jvb3RzdHJhcCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9kZWZpbmUgcHJvcGVydHkgZ2V0dGVycyIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9oYXNPd25Qcm9wZXJ0eSBzaG9ydGhhbmQiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvbWFrZSBuYW1lc3BhY2Ugb2JqZWN0Iiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL3B1YmxpY1BhdGgiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtY29yZS9saWIvc2V0LXB1YmxpYy1wYXRoLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLXRlbXBsYXRlLWRldGFpbC9zcmMvc2V0dGluZy9zZXR0aW5nLnRzeCJdLCJzb3VyY2VzQ29udGVudCI6WyJleHBvcnQgZGVmYXVsdCB7IFxyXG4gIHNldHRpbmdzOiBcIlNldHRpbmdzXCIsXHJcbn07XHJcbiIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X2NvcmVfXzsiLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfamltdV91aV9fOyIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X3VpX2FkdmFuY2VkX3NldHRpbmdfY29tcG9uZW50c19fOyIsIm1vZHVsZS5leHBvcnRzID0gX19XRUJQQUNLX0VYVEVSTkFMX01PRFVMRV9qaW11X3VpX2Jhc2ljX2NvbG9yX3BpY2tlcl9fOyIsIi8vIFRoZSBtb2R1bGUgY2FjaGVcbnZhciBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX18gPSB7fTtcblxuLy8gVGhlIHJlcXVpcmUgZnVuY3Rpb25cbmZ1bmN0aW9uIF9fd2VicGFja19yZXF1aXJlX18obW9kdWxlSWQpIHtcblx0Ly8gQ2hlY2sgaWYgbW9kdWxlIGlzIGluIGNhY2hlXG5cdHZhciBjYWNoZWRNb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdO1xuXHRpZiAoY2FjaGVkTW9kdWxlICE9PSB1bmRlZmluZWQpIHtcblx0XHRyZXR1cm4gY2FjaGVkTW9kdWxlLmV4cG9ydHM7XG5cdH1cblx0Ly8gQ3JlYXRlIGEgbmV3IG1vZHVsZSAoYW5kIHB1dCBpdCBpbnRvIHRoZSBjYWNoZSlcblx0dmFyIG1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF0gPSB7XG5cdFx0Ly8gbm8gbW9kdWxlLmlkIG5lZWRlZFxuXHRcdC8vIG5vIG1vZHVsZS5sb2FkZWQgbmVlZGVkXG5cdFx0ZXhwb3J0czoge31cblx0fTtcblxuXHQvLyBFeGVjdXRlIHRoZSBtb2R1bGUgZnVuY3Rpb25cblx0X193ZWJwYWNrX21vZHVsZXNfX1ttb2R1bGVJZF0obW9kdWxlLCBtb2R1bGUuZXhwb3J0cywgX193ZWJwYWNrX3JlcXVpcmVfXyk7XG5cblx0Ly8gUmV0dXJuIHRoZSBleHBvcnRzIG9mIHRoZSBtb2R1bGVcblx0cmV0dXJuIG1vZHVsZS5leHBvcnRzO1xufVxuXG4iLCIvLyBkZWZpbmUgZ2V0dGVyIGZ1bmN0aW9ucyBmb3IgaGFybW9ueSBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLmQgPSAoZXhwb3J0cywgZGVmaW5pdGlvbikgPT4ge1xuXHRmb3IodmFyIGtleSBpbiBkZWZpbml0aW9uKSB7XG5cdFx0aWYoX193ZWJwYWNrX3JlcXVpcmVfXy5vKGRlZmluaXRpb24sIGtleSkgJiYgIV9fd2VicGFja19yZXF1aXJlX18ubyhleHBvcnRzLCBrZXkpKSB7XG5cdFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywga2V5LCB7IGVudW1lcmFibGU6IHRydWUsIGdldDogZGVmaW5pdGlvbltrZXldIH0pO1xuXHRcdH1cblx0fVxufTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLm8gPSAob2JqLCBwcm9wKSA9PiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCkpIiwiLy8gZGVmaW5lIF9fZXNNb2R1bGUgb24gZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5yID0gKGV4cG9ydHMpID0+IHtcblx0aWYodHlwZW9mIFN5bWJvbCAhPT0gJ3VuZGVmaW5lZCcgJiYgU3ltYm9sLnRvU3RyaW5nVGFnKSB7XG5cdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFN5bWJvbC50b1N0cmluZ1RhZywgeyB2YWx1ZTogJ01vZHVsZScgfSk7XG5cdH1cblx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsICdfX2VzTW9kdWxlJywgeyB2YWx1ZTogdHJ1ZSB9KTtcbn07IiwiX193ZWJwYWNrX3JlcXVpcmVfXy5wID0gXCJcIjsiLCIvKipcclxuICogV2VicGFjayB3aWxsIHJlcGxhY2UgX193ZWJwYWNrX3B1YmxpY19wYXRoX18gd2l0aCBfX3dlYnBhY2tfcmVxdWlyZV9fLnAgdG8gc2V0IHRoZSBwdWJsaWMgcGF0aCBkeW5hbWljYWxseS5cclxuICogVGhlIHJlYXNvbiB3aHkgd2UgY2FuJ3Qgc2V0IHRoZSBwdWJsaWNQYXRoIGluIHdlYnBhY2sgY29uZmlnIGlzOiB3ZSBjaGFuZ2UgdGhlIHB1YmxpY1BhdGggd2hlbiBkb3dubG9hZC5cclxuICogKi9cclxuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lXHJcbi8vIEB0cy1pZ25vcmVcclxuX193ZWJwYWNrX3B1YmxpY19wYXRoX18gPSB3aW5kb3cuamltdUNvbmZpZy5iYXNlVXJsXHJcbiIsIlxyXG5pbXBvcnQgeyBSZWFjdCB9IGZyb20gXCJqaW11LWNvcmVcIjtcclxuaW1wb3J0IHsgQWxsV2lkZ2V0U2V0dGluZ1Byb3BzIH0gZnJvbSBcImppbXUtZm9yLWJ1aWxkZXJcIjtcclxuaW1wb3J0IHtcclxuICBTZXR0aW5nU2VjdGlvbixcclxuICBTZXR0aW5nUm93XHJcbn0gZnJvbSBcImppbXUtdWkvYWR2YW5jZWQvc2V0dGluZy1jb21wb25lbnRzXCI7XHJcbmltcG9ydCB7IElNQ29uZmlnIH0gZnJvbSBcIi4uL2NvbmZpZ1wiO1xyXG5pbXBvcnQgZGVmYXVsdEkxOG5NZXNzYWdlcyBmcm9tIFwiLi90cmFuc2xhdGlvbnMvZGVmYXVsdFwiO1xyXG5pbXBvcnQgeyBMYWJlbCB9IGZyb20gJ2ppbXUtdWknXHJcbmltcG9ydCB7IFRoZW1lQ29sb3JQaWNrZXIgfSBmcm9tIFwiamltdS11aS9iYXNpYy9jb2xvci1waWNrZXJcIjtcclxuXHJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIFNldHRpbmcgKHByb3BzOiBBbGxXaWRnZXRTZXR0aW5nUHJvcHM8SU1Db25maWc+KSB7IFxyXG5cclxuICBjb25zdCBbYmFja2dyb3VuZENvbG9yMiwgc2V0QmFja2dyb3VuZENvbG9yXSA9IFJlYWN0LnVzZVN0YXRlKHByb3BzLmNvbmZpZy5iYWNrZ291bmRDb2xvcik7XHJcbiAgY29uc3QgW2hlYWRlckJhY2tncm91bmQsIHNldEhlYWRlckJhY2tncm91bmRdID0gUmVhY3QudXNlU3RhdGUocHJvcHMuY29uZmlnLmhlYWRlckJhY2tncm91bmRDb2xvcik7XHJcblxyXG4gIGNvbnN0IG9uQmFja2dyb3VuZENvbG9yQ2hhbmdlID0gKGNvbG9yOiBzdHJpbmcpPT57ICBcclxuICAgIHByb3BzLm9uU2V0dGluZ0NoYW5nZSh7XHJcbiAgICAgIGlkOiBwcm9wcy5pZCxcclxuICAgICAgY29uZmlnOiBwcm9wcy5jb25maWcuc2V0KCdiYWNrZ3JvdW5kQ29sb3InLCBjb2xvcilcclxuICAgIH0pO1xyXG4gICAgc2V0QmFja2dyb3VuZENvbG9yKGNvbG9yKTtcclxuICB9XHJcblxyXG4gIGNvbnN0IG9uSGVhZGVyQmFja2dyb3VuZENvbG9yQ2hhbmdlID0gKGNvbG9yOiBzdHJpbmcpPT57ICBcclxuICAgIHByb3BzLm9uU2V0dGluZ0NoYW5nZSh7XHJcbiAgICAgIGlkOiBwcm9wcy5pZCxcclxuICAgICAgY29uZmlnOiBwcm9wcy5jb25maWcuc2V0KCdoZWFkZXJCYWNrZ3JvdW5kQ29sb3InLCBjb2xvcilcclxuICAgIH0pO1xyXG4gICAgc2V0QmFja2dyb3VuZENvbG9yKGNvbG9yKTtcclxuICB9XHJcbiAgXHJcblxyXG4gIHJldHVybiAoXHJcbiAgICA8ZGl2IGNsYXNzTmFtZT1cIndpZGdldC1zZXR0aW5nLWNsc3MtdXNlclwiPiAgICAgICAgXHJcblxyXG4gICAgICAgIDxTZXR0aW5nU2VjdGlvblxyXG4gICAgICAgICAgdGl0bGU9e3Byb3BzLmludGwuZm9ybWF0TWVzc2FnZSh7XHJcbiAgICAgICAgICAgIGlkOiBcInNldHRpbmdzTGFiZWxcIixcclxuICAgICAgICAgICAgZGVmYXVsdE1lc3NhZ2U6IGRlZmF1bHRJMThuTWVzc2FnZXMuc2V0dGluZ3NcclxuICAgICAgICAgIH0pfT5cclxuXHJcbiAgICAgICAgICAgIDxTZXR0aW5nUm93PlxyXG4gICAgICAgICAgICAgIDxMYWJlbCBzdHlsZT17e21hcmdpblJpZ2h0OiAnMmVtJ319IGNoZWNrPkJhY2tncm91bmQgQ29sb3I8L0xhYmVsPlxyXG4gICAgICAgICAgICAgIDxUaGVtZUNvbG9yUGlja2VyXHJcbiAgICAgICAgICAgICAgICAgIGNvbG9yPXtiYWNrZ3JvdW5kQ29sb3IyfVxyXG4gICAgICAgICAgICAgICAgICBoZWlnaHQ9ezI2fVxyXG4gICAgICAgICAgICAgICAgICBpY29uPVwibm9uZVwiXHJcbiAgICAgICAgICAgICAgICAgIHZhbHVlPXtiYWNrZ3JvdW5kQ29sb3IyfVxyXG4gICAgICAgICAgICAgICAgICBvbkNoYW5nZT17KGMpPT4gb25CYWNrZ3JvdW5kQ29sb3JDaGFuZ2UoYyl9XHJcbiAgICAgICAgICAgICAgICAgIHBsYWNlbWVudD1cImF1dG9cIlxyXG4gICAgICAgICAgICAgICAgICB0eXBlPVwiZGVmYXVsdFwiXHJcbiAgICAgICAgICAgICAgICAgIHdpZHRoPXszMH1cclxuICAgICAgICAgICAgICAgIC8+XHJcbiAgICAgICAgICAgIDwvU2V0dGluZ1Jvdz5cclxuXHJcbiAgICAgICAgICAgIDxTZXR0aW5nUm93PlxyXG4gICAgICAgICAgICAgIDxMYWJlbCBzdHlsZT17e21hcmdpblJpZ2h0OiAnMmVtJ319IGNoZWNrPkhlYWRlciBCYWNrZ3JvdW5kPC9MYWJlbD5cclxuICAgICAgICAgICAgICA8VGhlbWVDb2xvclBpY2tlclxyXG4gICAgICAgICAgICAgICAgICBjb2xvcj17aGVhZGVyQmFja2dyb3VuZH1cclxuICAgICAgICAgICAgICAgICAgaGVpZ2h0PXsyNn1cclxuICAgICAgICAgICAgICAgICAgaWNvbj1cIm5vbmVcIlxyXG4gICAgICAgICAgICAgICAgICB2YWx1ZT17aGVhZGVyQmFja2dyb3VuZH1cclxuICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhjKT0+IG9uSGVhZGVyQmFja2dyb3VuZENvbG9yQ2hhbmdlKGMpfVxyXG4gICAgICAgICAgICAgICAgICBwbGFjZW1lbnQ9XCJhdXRvXCJcclxuICAgICAgICAgICAgICAgICAgdHlwZT1cImRlZmF1bHRcIlxyXG4gICAgICAgICAgICAgICAgICB3aWR0aD17MzB9XHJcbiAgICAgICAgICAgICAgICAvPlxyXG4gICAgICAgICAgICA8L1NldHRpbmdSb3c+XHJcbiAgICAgICAgPC9TZXR0aW5nU2VjdGlvbj5cclxuICAgICAgPC9kaXY+XHJcbiAgKTtcclxufTsiXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=