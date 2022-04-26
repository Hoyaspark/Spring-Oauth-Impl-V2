import React from 'react';
import styled from 'styled-components';

const Button = styled.a`
  display: flex;
  justify-content: center;
  align-items: center;
  border-radius: 18px;
  marign-top: 58px;
  width: 371px;
  height: 71px;
  line-height: 71px;
  font-size: 22px;
  text-align: center;
  color: #f0ffff;
  cursor: pointer;
  background: linear-gradient(90deg, #ffdc3c, #fff064);
  text-decoration: none;
  box-shadow: 0 15px 14px rgb(0 42 177 / 12 %);
`;

function KakaoAuth() {
  const CLIENT_ID = 'f3e8be6cc15cdffba2d5f2b675130366';
  const REDIRECT_URI = 'http://localhost:3000/auth/kakao/login';
  const KAKAO_AUTH_URL = `https://kauth.kakao.com/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code`;

  return (
    <div>
      <Button id="kakaoLoginButton" href={KAKAO_AUTH_URL}>
        카카오로 로그인하기
      </Button>
    </div>
  );
}

export default KakaoAuth;
