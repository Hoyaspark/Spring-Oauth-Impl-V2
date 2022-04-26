import * as types from './types';
import axios from 'axios';

export function mainChoose(title) {
  return {
    type: types.MAIN_CATEGORY_CHOOSE,
    title,
  };
}
export function subChoose() {
  return {
    type: types.SUB_CATEGORY_CHOOSE,
  };
}
export function resetCategory() {
  return {
    type: types.CATEGORY_RESET,
  };
}
export function resetMainCategory() {
  return {
    type: types.MAIN_CATEGORY_RESET,
  };
}
export function resetSubCategory(main) {
  return {
    type: types.SUB_CATEGORY_RESET,
    main,
  };
}
export function getSearchResult(body, headers) {
  return (dispatch) => {
    dispatch(getSearchRequest());
    return axios
      .get('http://localhost:8080/getSearch', {
        params: body,
        headers: headers,
      })
      .then((response) => {
        dispatch(getSearchRequestSuccess(response.data));
        console.log(response.data);
      })
      .catch((error) => {
        dispatch(getSearchRequestFailure());
        console.log(error);
      });
  };
}

export function getSearchRequest() {
  return {
    type: types.GET_SEARCH_RESULT,
  };
}

export function getSearchRequestSuccess(searchResult) {
  return {
    type: types.GET_SEARCH_RESULT_SUCCESS,
    searchResult,
  };
}

export function getSearchRequestFailure() {
  return {
    type: types.GET_SEARCH_RESULT_FAILURE,
  };
}

export function clicklike() {
  return {
    types: types.LIKE_CLICK,
  };
}
