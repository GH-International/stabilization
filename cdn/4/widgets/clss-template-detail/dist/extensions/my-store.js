System.register([], function(__WEBPACK_DYNAMIC_EXPORT__, __system_context__) {


	return {

		execute: function() {
			__WEBPACK_DYNAMIC_EXPORT__(
/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	// The require scope
/******/ 	var __webpack_require__ = {};
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
/************************************************************************/
var __webpack_exports__ = {};
/*!*********************************************************************************!*\
  !*** ./your-extensions/widgets/clss-template-detail/src/extensions/my-store.ts ***!
  \*********************************************************************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "CLSSTempDetailActionKeys": () => (/* binding */ CLSSTempDetailActionKeys),
/* harmony export */   "default": () => (/* binding */ MyReduxStoreExtension)
/* harmony export */ });
var CLSSTempDetailActionKeys;
(function (CLSSTempDetailActionKeys) {
    CLSSTempDetailActionKeys["TOGGLE_TEMPLATE_EDITING_ACTION"] = "[CLSS-TEMPLATE-DETAILS] set is header editing";
    CLSSTempDetailActionKeys["HAZARD_MODAL_VISIBILITY_ACTION"] = "[CLSS-TEMPLATE-DETAILS] set hazard modal visibility";
    CLSSTempDetailActionKeys["ORGANIZATION_MODAL_VISIBILITY_ACTION"] = "[CLSS-TEMPLATE-DETAILS] set organization modal visibility";
})(CLSSTempDetailActionKeys || (CLSSTempDetailActionKeys = {}));
class MyReduxStoreExtension {
    constructor() {
        this.id = 'clss-template-details-redux-store-extension';
    }
    getActions() {
        return Object.keys(CLSSTempDetailActionKeys).map(k => CLSSTempDetailActionKeys[k]);
    }
    getInitLocalState() {
        return {
            isHeaderEditing: false,
            isHazardModalVisible: false,
            isOrganizationModalVisible: false
        };
    }
    getReducer() {
        return (localState, action, appState) => {
            switch (action.type) {
                case CLSSTempDetailActionKeys.TOGGLE_TEMPLATE_EDITING_ACTION:
                    return localState.set('isHeaderEditing', action.val);
                case CLSSTempDetailActionKeys.HAZARD_MODAL_VISIBILITY_ACTION:
                    return localState.set('isHazardModalVisible', action.val);
                case CLSSTempDetailActionKeys.ORGANIZATION_MODAL_VISIBILITY_ACTION:
                    return localState.set('isOrganizationModalVisible', action.val);
                default:
                    return localState;
            }
        };
    }
    getStoreKey() {
        return 'templateDetailState';
    }
}

/******/ 	return __webpack_exports__;
/******/ })()

			);
		}
	};
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2lkZ2V0cy9jbHNzLXRlbXBsYXRlLWRldGFpbC9kaXN0L2V4dGVuc2lvbnMvbXktc3RvcmUuanMiLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7O1VBQUE7VUFDQTs7Ozs7V0NEQTtXQUNBO1dBQ0E7V0FDQTtXQUNBLHlDQUF5Qyx3Q0FBd0M7V0FDakY7V0FDQTtXQUNBOzs7OztXQ1BBOzs7OztXQ0FBO1dBQ0E7V0FDQTtXQUNBLHVEQUF1RCxpQkFBaUI7V0FDeEU7V0FDQSxnREFBZ0QsYUFBYTtXQUM3RDs7Ozs7Ozs7Ozs7OztBQ0hBLElBQVksd0JBSVg7QUFKRCxXQUFZLHdCQUF3QjtJQUNsQyw0R0FBZ0Y7SUFDaEYsa0hBQXNGO0lBQ3RGLDhIQUFrRztBQUNwRyxDQUFDLEVBSlcsd0JBQXdCLEtBQXhCLHdCQUF3QixRQUluQztBQTRCYyxNQUFNLHFCQUFxQjtJQUExQztRQUNFLE9BQUUsR0FBRyw2Q0FBNkMsQ0FBQztJQW9DckQsQ0FBQztJQWxDQyxVQUFVO1FBQ1IsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLHdCQUF3QixDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsd0JBQXdCLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUNyRixDQUFDO0lBRUQsaUJBQWlCO1FBQ2YsT0FBTztZQUNMLGVBQWUsRUFBRSxLQUFLO1lBQ3RCLG9CQUFvQixFQUFFLEtBQUs7WUFDM0IsMEJBQTBCLEVBQUUsS0FBSztTQUNYLENBQUM7SUFDM0IsQ0FBQztJQUVELFVBQVU7UUFDUixPQUFPLENBQUMsVUFBcUIsRUFBRSxNQUFtQixFQUFFLFFBQWlCLEVBQWEsRUFBRTtZQUNsRixRQUFRLE1BQU0sQ0FBQyxJQUFJLEVBQUU7Z0JBRW5CLEtBQUssd0JBQXdCLENBQUMsOEJBQThCO29CQUMxRCxPQUFPLFVBQVUsQ0FBQyxHQUFHLENBQUMsaUJBQWlCLEVBQUUsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO2dCQUV2RCxLQUFLLHdCQUF3QixDQUFDLDhCQUE4QjtvQkFDMUQsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLHNCQUFzQixFQUFFLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztnQkFFNUQsS0FBSyx3QkFBd0IsQ0FBQyxvQ0FBb0M7b0JBQ2hFLE9BQU8sVUFBVSxDQUFDLEdBQUcsQ0FBQyw0QkFBNEIsRUFBRSxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7Z0JBRWxFO29CQUNFLE9BQU8sVUFBVSxDQUFDO2FBQ3JCO1FBQ0gsQ0FBQztJQUNILENBQUM7SUFFRCxXQUFXO1FBQ1QsT0FBTyxxQkFBcUIsQ0FBQztJQUMvQixDQUFDO0NBQ0YiLCJzb3VyY2VzIjpbIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svYm9vdHN0cmFwIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL2RlZmluZSBwcm9wZXJ0eSBnZXR0ZXJzIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL2hhc093blByb3BlcnR5IHNob3J0aGFuZCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9tYWtlIG5hbWVzcGFjZSBvYmplY3QiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtdGVtcGxhdGUtZGV0YWlsL3NyYy9leHRlbnNpb25zL215LXN0b3JlLnRzIl0sInNvdXJjZXNDb250ZW50IjpbIi8vIFRoZSByZXF1aXJlIHNjb3BlXG52YXIgX193ZWJwYWNrX3JlcXVpcmVfXyA9IHt9O1xuXG4iLCIvLyBkZWZpbmUgZ2V0dGVyIGZ1bmN0aW9ucyBmb3IgaGFybW9ueSBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLmQgPSAoZXhwb3J0cywgZGVmaW5pdGlvbikgPT4ge1xuXHRmb3IodmFyIGtleSBpbiBkZWZpbml0aW9uKSB7XG5cdFx0aWYoX193ZWJwYWNrX3JlcXVpcmVfXy5vKGRlZmluaXRpb24sIGtleSkgJiYgIV9fd2VicGFja19yZXF1aXJlX18ubyhleHBvcnRzLCBrZXkpKSB7XG5cdFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywga2V5LCB7IGVudW1lcmFibGU6IHRydWUsIGdldDogZGVmaW5pdGlvbltrZXldIH0pO1xuXHRcdH1cblx0fVxufTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLm8gPSAob2JqLCBwcm9wKSA9PiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCkpIiwiLy8gZGVmaW5lIF9fZXNNb2R1bGUgb24gZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5yID0gKGV4cG9ydHMpID0+IHtcblx0aWYodHlwZW9mIFN5bWJvbCAhPT0gJ3VuZGVmaW5lZCcgJiYgU3ltYm9sLnRvU3RyaW5nVGFnKSB7XG5cdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFN5bWJvbC50b1N0cmluZ1RhZywgeyB2YWx1ZTogJ01vZHVsZScgfSk7XG5cdH1cblx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsICdfX2VzTW9kdWxlJywgeyB2YWx1ZTogdHJ1ZSB9KTtcbn07IiwiaW1wb3J0IHsgZXh0ZW5zaW9uU3BlYywgSW1tdXRhYmxlT2JqZWN0LCBJTVN0YXRlIH0gZnJvbSAnamltdS1jb3JlJztcclxuaW1wb3J0IHsgVGVtcGxhdGVEZXRhaWxTdGF0ZSB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvZGF0YS1kZWZpbml0aW9ucyc7XHJcblxyXG5leHBvcnQgZW51bSBDTFNTVGVtcERldGFpbEFjdGlvbktleXMge1xyXG4gIFRPR0dMRV9URU1QTEFURV9FRElUSU5HX0FDVElPTiA9ICdbQ0xTUy1URU1QTEFURS1ERVRBSUxTXSBzZXQgaXMgaGVhZGVyIGVkaXRpbmcnLFxyXG4gIEhBWkFSRF9NT0RBTF9WSVNJQklMSVRZX0FDVElPTiA9ICdbQ0xTUy1URU1QTEFURS1ERVRBSUxTXSBzZXQgaGF6YXJkIG1vZGFsIHZpc2liaWxpdHknLFxyXG4gIE9SR0FOSVpBVElPTl9NT0RBTF9WSVNJQklMSVRZX0FDVElPTiA9ICdbQ0xTUy1URU1QTEFURS1ERVRBSUxTXSBzZXQgb3JnYW5pemF0aW9uIG1vZGFsIHZpc2liaWxpdHknLFxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNldF9UZW1wbGF0ZV9FZGl0aW5nX0FjdGlvbl9UeXBle1xyXG4gICB0eXBlOiBDTFNTVGVtcERldGFpbEFjdGlvbktleXMuVE9HR0xFX1RFTVBMQVRFX0VESVRJTkdfQUNUSU9OLFxyXG4gICB2YWw6IGJvb2xlYW5cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZXRfSGF6YXJkX01vZGFsX1Zpc2liaWxpdHlfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU1RlbXBEZXRhaWxBY3Rpb25LZXlzLkhBWkFSRF9NT0RBTF9WSVNJQklMSVRZX0FDVElPTixcclxuICB2YWw6IGJvb2xlYW5cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZXRfT3JnYW5pemF0aW9uX01vZGFsX1Zpc2liaWxpdHlfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU1RlbXBEZXRhaWxBY3Rpb25LZXlzLk9SR0FOSVpBVElPTl9NT0RBTF9WSVNJQklMSVRZX0FDVElPTixcclxuICB2YWw6IGJvb2xlYW5cclxufVxyXG5cclxudHlwZSBBY3Rpb25UeXBlcyA9IFNldF9UZW1wbGF0ZV9FZGl0aW5nX0FjdGlvbl9UeXBlIHxcclxuU2V0X0hhemFyZF9Nb2RhbF9WaXNpYmlsaXR5X0FjdGlvbl9UeXBlIHwgU2V0X09yZ2FuaXphdGlvbl9Nb2RhbF9WaXNpYmlsaXR5X0FjdGlvbl9UeXBlO1xyXG5cclxudHlwZSBJTU15U3RhdGUgPSBJbW11dGFibGVPYmplY3Q8VGVtcGxhdGVEZXRhaWxTdGF0ZT47XHJcblxyXG5kZWNsYXJlIG1vZHVsZSAnamltdS1jb3JlL2xpYi90eXBlcy9zdGF0ZSd7XHJcbiAgaW50ZXJmYWNlIFN0YXRle1xyXG4gICAgdGVtcGxhdGVEZXRhaWxTdGF0ZT86IElNTXlTdGF0ZVxyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgTXlSZWR1eFN0b3JlRXh0ZW5zaW9uIGltcGxlbWVudHMgZXh0ZW5zaW9uU3BlYy5SZWR1eFN0b3JlRXh0ZW5zaW9uIHtcclxuICBpZCA9ICdjbHNzLXRlbXBsYXRlLWRldGFpbHMtcmVkdXgtc3RvcmUtZXh0ZW5zaW9uJztcclxuXHJcbiAgZ2V0QWN0aW9ucygpIHtcclxuICAgIHJldHVybiBPYmplY3Qua2V5cyhDTFNTVGVtcERldGFpbEFjdGlvbktleXMpLm1hcChrID0+IENMU1NUZW1wRGV0YWlsQWN0aW9uS2V5c1trXSk7XHJcbiAgfVxyXG5cclxuICBnZXRJbml0TG9jYWxTdGF0ZSgpIHtcclxuICAgIHJldHVybiB7IFxyXG4gICAgICBpc0hlYWRlckVkaXRpbmc6IGZhbHNlLFxyXG4gICAgICBpc0hhemFyZE1vZGFsVmlzaWJsZTogZmFsc2UsXHJcbiAgICAgIGlzT3JnYW5pemF0aW9uTW9kYWxWaXNpYmxlOiBmYWxzZVxyXG4gICAgfSBhcyBUZW1wbGF0ZURldGFpbFN0YXRlO1xyXG4gIH1cclxuXHJcbiAgZ2V0UmVkdWNlcigpIHtcclxuICAgIHJldHVybiAobG9jYWxTdGF0ZTogSU1NeVN0YXRlLCBhY3Rpb246IEFjdGlvblR5cGVzLCBhcHBTdGF0ZTogSU1TdGF0ZSk6IElNTXlTdGF0ZSA9PiB7XHJcbiAgICAgIHN3aXRjaCAoYWN0aW9uLnR5cGUpIHtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTVGVtcERldGFpbEFjdGlvbktleXMuVE9HR0xFX1RFTVBMQVRFX0VESVRJTkdfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdpc0hlYWRlckVkaXRpbmcnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTVGVtcERldGFpbEFjdGlvbktleXMuSEFaQVJEX01PREFMX1ZJU0lCSUxJVFlfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdpc0hhemFyZE1vZGFsVmlzaWJsZScsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NUZW1wRGV0YWlsQWN0aW9uS2V5cy5PUkdBTklaQVRJT05fTU9EQUxfVklTSUJJTElUWV9BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2lzT3JnYW5pemF0aW9uTW9kYWxWaXNpYmxlJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZTtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgZ2V0U3RvcmVLZXkoKSB7XHJcbiAgICByZXR1cm4gJ3RlbXBsYXRlRGV0YWlsU3RhdGUnO1xyXG4gIH1cclxufSJdLCJuYW1lcyI6W10sInNvdXJjZVJvb3QiOiIifQ==