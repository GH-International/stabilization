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

/***/ "./your-extensions/widgets/clss-banner/src/setting/translations/default.ts":
/*!*********************************************************************************!*\
  !*** ./your-extensions/widgets/clss-banner/src/setting/translations/default.ts ***!
  \*********************************************************************************/
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
/*!*********************************************************************!*\
  !*** ./your-extensions/widgets/clss-banner/src/setting/setting.tsx ***!
  \*********************************************************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ Setting)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-ui/advanced/setting-components */ "jimu-ui/advanced/setting-components");
/* harmony import */ var _translations_default__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./translations/default */ "./your-extensions/widgets/clss-banner/src/setting/translations/default.ts");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! jimu-ui/basic/color-picker */ "jimu-ui/basic/color-picker");





function Setting(props) {
    const [backgroundColor, setBackgroundColor] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.backgroundColor);
    const [title, setTitle] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.title);
    const [size, setSize] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.size);
    const [fontSize, setFontSize] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.fontSize);
    const [color, setColor] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(props.config.color);
    const onBackgroundColor = (color) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('backgroundColor', color)
        });
        setBackgroundColor(color);
    };
    const onTitleChange = (title) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('title', title)
        });
        setTitle(color);
    };
    const onSizeChange = (size) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('size', size)
        });
        setSize(size);
    };
    const onFontSizeChange = (fsize) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('fontSize', fsize)
        });
        setFontSize(fsize);
    };
    const onColorChange = (color) => {
        props.onSettingChange({
            id: props.id,
            config: props.config.set('color', fontSize)
        });
        setColor(color);
    };
    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "widget-setting-template-container" },
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingSection, { title: props.intl.formatMessage({
                id: "settingsLabel",
                defaultMessage: _translations_default__WEBPACK_IMPORTED_MODULE_2__["default"].settings
            }) },
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_3__.Label, { size: "lg" }, "Background"),
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_4__.ThemeColorPicker, { color: backgroundColor, height: 26, icon: "none", value: backgroundColor, onChange: (c) => onBackgroundColor(c), placement: "bottom", type: "default", width: 30 })),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_3__.Label, { size: "lg" }, "Logo Size"),
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_3__.TextInput, { value: size, onChange: (e) => onSizeChange(e.target.value), size: "lg", style: { width: '100%' } })),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_3__.Label, { size: "lg" }, "Title"),
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_3__.TextInput, { value: title, onChange: (e) => onTitleChange(e.target.value), size: "lg", style: { width: '100%' } })),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_3__.Label, { size: "lg" }, "Font Size"),
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_3__.TextInput, { value: fontSize, onChange: (e) => onFontSizeChange(e.target.value), size: "lg", style: { width: '100%' } })),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_advanced_setting_components__WEBPACK_IMPORTED_MODULE_1__.SettingRow, null,
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_3__.Label, { size: "lg" }, "Color"),
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui_basic_color_picker__WEBPACK_IMPORTED_MODULE_4__.ThemeColorPicker, { color: color, height: 26, icon: "none", value: color, onChange: (c) => onColorChange(c), placement: "bottom", type: "default", width: 30 })))));
}
;

})();

/******/ 	return __webpack_exports__;
/******/ })()

			);
		}
	};
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2lkZ2V0cy9jbHNzLWJhbm5lci9kaXN0L3NldHRpbmcvc2V0dGluZy5qcyIsIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFBQSxpRUFBZTtJQUNiLFFBQVEsRUFBRSxVQUFVO0NBQ3JCLEVBQUM7Ozs7Ozs7Ozs7OztBQ0ZGOzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7VUNBQTtVQUNBOztVQUVBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBOztVQUVBO1VBQ0E7O1VBRUE7VUFDQTtVQUNBOzs7OztXQ3RCQTtXQUNBO1dBQ0E7V0FDQTtXQUNBLHlDQUF5Qyx3Q0FBd0M7V0FDakY7V0FDQTtXQUNBOzs7OztXQ1BBOzs7OztXQ0FBO1dBQ0E7V0FDQTtXQUNBLHVEQUF1RCxpQkFBaUI7V0FDeEU7V0FDQSxnREFBZ0QsYUFBYTtXQUM3RDs7Ozs7V0NOQTs7Ozs7Ozs7OztBQ0FBOzs7S0FHSztBQUNMLDJCQUEyQjtBQUMzQixhQUFhO0FBQ2IscUJBQXVCLEdBQUcsTUFBTSxDQUFDLFVBQVUsQ0FBQyxPQUFPOzs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDTGpCO0FBSTJCO0FBRUo7QUFDZDtBQUNtQjtBQUcvQyxTQUFTLE9BQU8sQ0FBRSxLQUFzQztJQUVyRSxNQUFNLENBQUMsZUFBZSxFQUFFLGtCQUFrQixDQUFDLEdBQUcscURBQWMsQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLGVBQWUsQ0FBQyxDQUFDO0lBQzNGLE1BQU0sQ0FBQyxLQUFLLEVBQUUsUUFBUSxDQUFDLEdBQUcscURBQWMsQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQzdELE1BQU0sQ0FBQyxJQUFJLEVBQUUsT0FBTyxDQUFDLEdBQUcscURBQWMsQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxD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QyxDQUFDLENBQUMsRUFDaEMsU0FBUyxFQUFDLFFBQVEsRUFDbEIsSUFBSSxFQUFDLFNBQVMsRUFDZCxLQUFLLEVBQUUsRUFBRSxHQUNULENBQ0ssQ0FFRSxDQUNiLENBQ1QsQ0FBQztBQUNKLENBQUM7QUFBQSxDQUFDIiwic291cmNlcyI6WyJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYmFubmVyL3NyYy9zZXR0aW5nL3RyYW5zbGF0aW9ucy9kZWZhdWx0LnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS1jb3JlXCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC9leHRlcm5hbCBzeXN0ZW0gXCJqaW11LXVpXCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC9leHRlcm5hbCBzeXN0ZW0gXCJqaW11LXVpL2FkdmFuY2VkL3NldHRpbmctY29tcG9uZW50c1wiIiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS11aS9iYXNpYy9jb2xvci1waWNrZXJcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svYm9vdHN0cmFwIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL2RlZmluZSBwcm9wZXJ0eSBnZXR0ZXJzIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL2hhc093blByb3BlcnR5IHNob3J0aGFuZCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9tYWtlIG5hbWVzcGFjZSBvYmplY3QiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvcHVibGljUGF0aCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1jb3JlL2xpYi9zZXQtcHVibGljLXBhdGgudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYmFubmVyL3NyYy9zZXR0aW5nL3NldHRpbmcudHN4Il0sInNvdXJjZXNDb250ZW50IjpbImV4cG9ydCBkZWZhdWx0IHsgXHJcbiAgc2V0dGluZ3M6IFwiU2V0dGluZ3NcIlxyXG59O1xyXG4iLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfamltdV9jb3JlX187IiwibW9kdWxlLmV4cG9ydHMgPSBfX1dFQlBBQ0tfRVhURVJOQUxfTU9EVUxFX2ppbXVfdWlfXzsiLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfamltdV91aV9hZHZhbmNlZF9zZXR0aW5nX2NvbXBvbmVudHNfXzsiLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfamltdV91aV9iYXNpY19jb2xvcl9waWNrZXJfXzsiLCIvLyBUaGUgbW9kdWxlIGNhY2hlXG52YXIgX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fID0ge307XG5cbi8vIFRoZSByZXF1aXJlIGZ1bmN0aW9uXG5mdW5jdGlvbiBfX3dlYnBhY2tfcmVxdWlyZV9fKG1vZHVsZUlkKSB7XG5cdC8vIENoZWNrIGlmIG1vZHVsZSBpcyBpbiBjYWNoZVxuXHR2YXIgY2FjaGVkTW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXTtcblx0aWYgKGNhY2hlZE1vZHVsZSAhPT0gdW5kZWZpbmVkKSB7XG5cdFx0cmV0dXJuIGNhY2hlZE1vZHVsZS5leHBvcnRzO1xuXHR9XG5cdC8vIENyZWF0ZSBhIG5ldyBtb2R1bGUgKGFuZCBwdXQgaXQgaW50byB0aGUgY2FjaGUpXG5cdHZhciBtb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdID0ge1xuXHRcdC8vIG5vIG1vZHVsZS5pZCBuZWVkZWRcblx0XHQvLyBubyBtb2R1bGUubG9hZGVkIG5lZWRlZFxuXHRcdGV4cG9ydHM6IHt9XG5cdH07XG5cblx0Ly8gRXhlY3V0ZSB0aGUgbW9kdWxlIGZ1bmN0aW9uXG5cdF9fd2VicGFja19tb2R1bGVzX19bbW9kdWxlSWRdKG1vZHVsZSwgbW9kdWxlLmV4cG9ydHMsIF9fd2VicGFja19yZXF1aXJlX18pO1xuXG5cdC8vIFJldHVybiB0aGUgZXhwb3J0cyBvZiB0aGUgbW9kdWxlXG5cdHJldHVybiBtb2R1bGUuZXhwb3J0cztcbn1cblxuIiwiLy8gZGVmaW5lIGdldHRlciBmdW5jdGlvbnMgZm9yIGhhcm1vbnkgZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5kID0gKGV4cG9ydHMsIGRlZmluaXRpb24pID0+IHtcblx0Zm9yKHZhciBrZXkgaW4gZGVmaW5pdGlvbikge1xuXHRcdGlmKF9fd2VicGFja19yZXF1aXJlX18ubyhkZWZpbml0aW9uLCBrZXkpICYmICFfX3dlYnBhY2tfcmVxdWlyZV9fLm8oZXhwb3J0cywga2V5KSkge1xuXHRcdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIGtleSwgeyBlbnVtZXJhYmxlOiB0cnVlLCBnZXQ6IGRlZmluaXRpb25ba2V5XSB9KTtcblx0XHR9XG5cdH1cbn07IiwiX193ZWJwYWNrX3JlcXVpcmVfXy5vID0gKG9iaiwgcHJvcCkgPT4gKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChvYmosIHByb3ApKSIsIi8vIGRlZmluZSBfX2VzTW9kdWxlIG9uIGV4cG9ydHNcbl9fd2VicGFja19yZXF1aXJlX18uciA9IChleHBvcnRzKSA9PiB7XG5cdGlmKHR5cGVvZiBTeW1ib2wgIT09ICd1bmRlZmluZWQnICYmIFN5bWJvbC50b1N0cmluZ1RhZykge1xuXHRcdE9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBTeW1ib2wudG9TdHJpbmdUYWcsIHsgdmFsdWU6ICdNb2R1bGUnIH0pO1xuXHR9XG5cdE9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCAnX19lc01vZHVsZScsIHsgdmFsdWU6IHRydWUgfSk7XG59OyIsIl9fd2VicGFja19yZXF1aXJlX18ucCA9IFwiXCI7IiwiLyoqXHJcbiAqIFdlYnBhY2sgd2lsbCByZXBsYWNlIF9fd2VicGFja19wdWJsaWNfcGF0aF9fIHdpdGggX193ZWJwYWNrX3JlcXVpcmVfXy5wIHRvIHNldCB0aGUgcHVibGljIHBhdGggZHluYW1pY2FsbHkuXHJcbiAqIFRoZSByZWFzb24gd2h5IHdlIGNhbid0IHNldCB0aGUgcHVibGljUGF0aCBpbiB3ZWJwYWNrIGNvbmZpZyBpczogd2UgY2hhbmdlIHRoZSBwdWJsaWNQYXRoIHdoZW4gZG93bmxvYWQuXHJcbiAqICovXHJcbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZVxyXG4vLyBAdHMtaWdub3JlXHJcbl9fd2VicGFja19wdWJsaWNfcGF0aF9fID0gd2luZG93LmppbXVDb25maWcuYmFzZVVybFxyXG4iLCJcclxuaW1wb3J0IHsgUmVhY3QgfSBmcm9tIFwiamltdS1jb3JlXCI7XHJcbmltcG9ydCB7IEFsbFdpZGdldFNldHRpbmdQcm9wcyB9IGZyb20gXCJqaW11LWZvci1idWlsZGVyXCI7XHJcbmltcG9ydCB7XHJcbiAgU2V0dGluZ1JvdyxcclxuICBTZXR0aW5nU2VjdGlvbn0gZnJvbSBcImppbXUtdWkvYWR2YW5jZWQvc2V0dGluZy1jb21wb25lbnRzXCI7XHJcbmltcG9ydCB7IElNQ29uZmlnIH0gZnJvbSBcIi4uL2NvbmZpZ1wiO1xyXG5pbXBvcnQgZGVmYXVsdEkxOG5NZXNzYWdlcyBmcm9tIFwiLi90cmFuc2xhdGlvbnMvZGVmYXVsdFwiO1xyXG5pbXBvcnQgeyBMYWJlbCwgVGV4dElucHV0IH0gZnJvbSBcImppbXUtdWlcIjtcclxuaW1wb3J0IHsgVGhlbWVDb2xvclBpY2tlciB9IGZyb20gXCJqaW11LXVpL2Jhc2ljL2NvbG9yLXBpY2tlclwiO1xyXG5cclxuXHJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIFNldHRpbmcgKHByb3BzOiBBbGxXaWRnZXRTZXR0aW5nUHJvcHM8SU1Db25maWc+KSB7XHJcbiAgXHJcbiAgY29uc3QgW2JhY2tncm91bmRDb2xvciwgc2V0QmFja2dyb3VuZENvbG9yXSA9IFJlYWN0LnVzZVN0YXRlKHByb3BzLmNvbmZpZy5iYWNrZ3JvdW5kQ29sb3IpO1xyXG4gIGNvbnN0IFt0aXRsZSwgc2V0VGl0bGVdID0gUmVhY3QudXNlU3RhdGUocHJvcHMuY29uZmlnLnRpdGxlKTtcclxuICBjb25zdCBbc2l6ZSwgc2V0U2l6ZV0gPSBSZWFjdC51c2VTdGF0ZShwcm9wcy5jb25maWcuc2l6ZSk7XHJcbiAgY29uc3QgW2ZvbnRTaXplLCBzZXRGb250U2l6ZV0gPSBSZWFjdC51c2VTdGF0ZShwcm9wcy5jb25maWcuZm9udFNpemUpO1xyXG4gIGNvbnN0IFtjb2xvciwgc2V0Q29sb3JdID0gUmVhY3QudXNlU3RhdGUocHJvcHMuY29uZmlnLmNvbG9yKVxyXG4gIFxyXG4gIGNvbnN0IG9uQmFja2dyb3VuZENvbG9yID0gKGNvbG9yOiBzdHJpbmcpPT57ICAgIFxyXG4gICAgcHJvcHMub25TZXR0aW5nQ2hhbmdlKHtcclxuICAgICAgaWQ6IHByb3BzLmlkLFxyXG4gICAgICBjb25maWc6IHByb3BzLmNvbmZpZy5zZXQoJ2JhY2tncm91bmRDb2xvcicsIGNvbG9yKVxyXG4gICAgfSk7XHJcbiAgICBzZXRCYWNrZ3JvdW5kQ29sb3IoY29sb3IpO1xyXG4gIH1cclxuXHJcbiAgY29uc3Qgb25UaXRsZUNoYW5nZSA9ICh0aXRsZTogc3RyaW5nKT0+eyAgICBcclxuICAgIHByb3BzLm9uU2V0dGluZ0NoYW5nZSh7XHJcbiAgICAgIGlkOiBwcm9wcy5pZCxcclxuICAgICAgY29uZmlnOiBwcm9wcy5jb25maWcuc2V0KCd0aXRsZScsIHRpdGxlKVxyXG4gICAgfSk7XHJcbiAgICBzZXRUaXRsZShjb2xvcik7XHJcbiAgfVxyXG5cclxuICBjb25zdCBvblNpemVDaGFuZ2UgPSAoc2l6ZTogc3RyaW5nKT0+eyAgICBcclxuICAgIHByb3BzLm9uU2V0dGluZ0NoYW5nZSh7XHJcbiAgICAgIGlkOiBwcm9wcy5pZCxcclxuICAgICAgY29uZmlnOiBwcm9wcy5jb25maWcuc2V0KCdzaXplJywgc2l6ZSlcclxuICAgIH0pO1xyXG4gICAgc2V0U2l6ZShzaXplKTtcclxuICB9XHJcblxyXG4gIGNvbnN0IG9uRm9udFNpemVDaGFuZ2UgPSAoZnNpemU6IHN0cmluZyk9PnsgICAgXHJcbiAgICBwcm9wcy5vblNldHRpbmdDaGFuZ2Uoe1xyXG4gICAgICBpZDogcHJvcHMuaWQsXHJcbiAgICAgIGNvbmZpZzogcHJvcHMuY29uZmlnLnNldCgnZm9udFNpemUnLCBmc2l6ZSlcclxuICAgIH0pO1xyXG4gICAgc2V0Rm9udFNpemUoZnNpemUpO1xyXG4gIH1cclxuXHJcbiAgY29uc3Qgb25Db2xvckNoYW5nZSA9IChjb2xvcjogc3RyaW5nKT0+eyAgICBcclxuICAgIHByb3BzLm9uU2V0dGluZ0NoYW5nZSh7XHJcbiAgICAgIGlkOiBwcm9wcy5pZCxcclxuICAgICAgY29uZmlnOiBwcm9wcy5jb25maWcuc2V0KCdjb2xvcicsIGZvbnRTaXplKVxyXG4gICAgfSk7XHJcbiAgICBzZXRDb2xvcihjb2xvcik7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gKFxyXG4gICAgPGRpdiBjbGFzc05hbWU9XCJ3aWRnZXQtc2V0dGluZy10ZW1wbGF0ZS1jb250YWluZXJcIj4gICAgICAgIFxyXG5cclxuICAgICAgICA8U2V0dGluZ1NlY3Rpb25cclxuICAgICAgICAgIHRpdGxlPXtwcm9wcy5pbnRsLmZvcm1hdE1lc3NhZ2Uoe1xyXG4gICAgICAgICAgICBpZDogXCJzZXR0aW5nc0xhYmVsXCIsXHJcbiAgICAgICAgICAgIGRlZmF1bHRNZXNzYWdlOiBkZWZhdWx0STE4bk1lc3NhZ2VzLnNldHRpbmdzXHJcbiAgICAgICAgICB9KX0+XHJcbiAgICAgICAgICBcclxuICAgICAgICAgIDxTZXR0aW5nUm93PlxyXG4gICAgICAgICAgICA8TGFiZWwgc2l6ZT1cImxnXCI+QmFja2dyb3VuZDwvTGFiZWw+XHJcbiAgICAgICAgICAgIDxUaGVtZUNvbG9yUGlja2VyXHJcbiAgICAgICAgICAgICAgICAgIGNvbG9yPXtiYWNrZ3JvdW5kQ29sb3J9XHJcbiAgICAgICAgICAgICAgICAgIGhlaWdodD17MjZ9XHJcbiAgICAgICAgICAgICAgICAgIGljb249XCJub25lXCJcclxuICAgICAgICAgICAgICAgICAgdmFsdWU9e2JhY2tncm91bmRDb2xvcn1cclxuICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhjKT0+IG9uQmFja2dyb3VuZENvbG9yKGMpfVxyXG4gICAgICAgICAgICAgICAgICBwbGFjZW1lbnQ9XCJib3R0b21cIlxyXG4gICAgICAgICAgICAgICAgICB0eXBlPVwiZGVmYXVsdFwiXHJcbiAgICAgICAgICAgICAgICAgIHdpZHRoPXszMH1cclxuICAgICAgICAgICAgICAgIC8+XHJcbiAgICAgICAgICA8L1NldHRpbmdSb3c+XHJcblxyXG4gICAgICAgICAgPFNldHRpbmdSb3c+XHJcbiAgICAgICAgICAgIDxMYWJlbCBzaXplPVwibGdcIj5Mb2dvIFNpemU8L0xhYmVsPlxyXG4gICAgICAgICAgICA8VGV4dElucHV0IHZhbHVlPXtzaXplfSBvbkNoYW5nZT17KGUpPT4gb25TaXplQ2hhbmdlKGUudGFyZ2V0LnZhbHVlKX0gc2l6ZT1cImxnXCIgXHJcbiAgICAgICAgICAgICAgc3R5bGU9e3t3aWR0aDogJzEwMCUnfX0vPlxyXG4gICAgICAgICAgPC9TZXR0aW5nUm93PlxyXG5cclxuICAgICAgICAgIDxTZXR0aW5nUm93PlxyXG4gICAgICAgICAgICA8TGFiZWwgc2l6ZT1cImxnXCI+VGl0bGU8L0xhYmVsPlxyXG4gICAgICAgICAgICA8VGV4dElucHV0IHZhbHVlPXt0aXRsZX0gb25DaGFuZ2U9eyhlKT0+IG9uVGl0bGVDaGFuZ2UoZS50YXJnZXQudmFsdWUpfSBzaXplPVwibGdcIiBcclxuICAgICAgICAgICAgICBzdHlsZT17e3dpZHRoOiAnMTAwJSd9fS8+XHJcbiAgICAgICAgICA8L1NldHRpbmdSb3c+XHJcblxyXG4gICAgICAgICAgPFNldHRpbmdSb3c+XHJcbiAgICAgICAgICAgIDxMYWJlbCBzaXplPVwibGdcIj5Gb250IFNpemU8L0xhYmVsPlxyXG4gICAgICAgICAgICA8VGV4dElucHV0IHZhbHVlPXtmb250U2l6ZX0gb25DaGFuZ2U9eyhlKT0+IG9uRm9udFNpemVDaGFuZ2UoZS50YXJnZXQudmFsdWUpfSBzaXplPVwibGdcIiBcclxuICAgICAgICAgICAgICBzdHlsZT17e3dpZHRoOiAnMTAwJSd9fS8+XHJcbiAgICAgICAgICA8L1NldHRpbmdSb3c+XHJcblxyXG4gICAgICAgICAgPFNldHRpbmdSb3c+XHJcbiAgICAgICAgICAgIDxMYWJlbCBzaXplPVwibGdcIj5Db2xvcjwvTGFiZWw+XHJcbiAgICAgICAgICAgIDxUaGVtZUNvbG9yUGlja2VyXHJcbiAgICAgICAgICAgICAgICAgIGNvbG9yPXtjb2xvcn1cclxuICAgICAgICAgICAgICAgICAgaGVpZ2h0PXsyNn1cclxuICAgICAgICAgICAgICAgICAgaWNvbj1cIm5vbmVcIlxyXG4gICAgICAgICAgICAgICAgICB2YWx1ZT17Y29sb3J9XHJcbiAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsoYyk9PiBvbkNvbG9yQ2hhbmdlKGMpfVxyXG4gICAgICAgICAgICAgICAgICBwbGFjZW1lbnQ9XCJib3R0b21cIlxyXG4gICAgICAgICAgICAgICAgICB0eXBlPVwiZGVmYXVsdFwiXHJcbiAgICAgICAgICAgICAgICAgIHdpZHRoPXszMH1cclxuICAgICAgICAgICAgICAgIC8+XHJcbiAgICAgICAgICA8L1NldHRpbmdSb3c+XHJcbiAgICAgICAgIFxyXG4gICAgICAgIDwvU2V0dGluZ1NlY3Rpb24+XHJcbiAgICAgIDwvZGl2PlxyXG4gICk7XHJcbn07Il0sIm5hbWVzIjpbXSwic291cmNlUm9vdCI6IiJ9