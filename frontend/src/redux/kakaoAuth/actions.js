import axios from 'axios';
import {
  KAKAO_AUTHORIZE,
  KAKAO_AUTHORIZE_SUCCESS,
  KAKAO_AUTHORIZE_FAILURE,
  KAKAO_LOGOUT,
  KAKAO_VERIFICATION,
  KAKAO_VERIFICATION_SUCCESS,
  KAKAO_VERIFICATION_FAILURE,
} from './types';

export function kakaoAuthRequest(code) {
  return (dispatch) => {
    // Inform Login API is starting
    dispatch(kakaoAuth());

    // API REQUEST
    return axios
      .get('http://localhost:8080/auth/kakao/login', {
        params: {
          code: code,
        },
      })
      .then((response) => {
        // SUCCEED
        dispatch(kakaoAuthSuccess(response.data));
        // 성공하면 사용자ID 받아오기
        console.log(response.data);
        const ACCESS_TOKEN = response.data.accessToken;

        localStorage.setItem('token', ACCESS_TOKEN); //예시로 로컬에 저장함
      })
      .catch((error) => {
        // FAILED
        dispatch(kakaoAuthFailure());
        console.log('소셜로그인 에러', error);
        window.alert('로그인에 실패하였습니다.');
      });
  };
}

export function kakaoAuth() {
  return {
    type: KAKAO_AUTHORIZE,
  };
}

export function kakaoAuthSuccess(userInfo) {
  return {
    type: KAKAO_AUTHORIZE_SUCCESS,
    userInfo,
  };
}

export function kakaoAuthFailure() {
  return {
    type: KAKAO_AUTHORIZE_FAILURE,
  };
}

/* Check Session KAKAO User */
export function checkSessionRequest(headers) {
  return (dispatch) => {
    // inform Get Status API is starting
    dispatch(checkSession());

    return axios
      .post('http://localhost:8080/auth/kakao/authorize', headers)
      .then((response) => {
        dispatch(checkSessionSuccess(response.data)); //HTTP 틍신을 통해 userId을 빋이옴
      })
      .catch((error) => {
        dispatch(checkSessionFailure());
      });
  };
}

export function checkSession() {
  return {
    type: KAKAO_VERIFICATION,
  };
}

export function checkSessionSuccess() {
  return {
    type: KAKAO_VERIFICATION_SUCCESS,
  };
}

export function checkSessionFailure() {
  return {
    type: KAKAO_VERIFICATION_FAILURE,
  };
}

/* KAKAO Logout */
export function kakaoLogoutRequest() {
  return (dispatch) => {
    return axios.post('http://localhost:8080/kakaoLogout').then((response) => {
      dispatch(kakaoLogout());
    });
  };
}

export function kakaoLogout() {
  return {
    type: KAKAO_LOGOUT,
  };
}
