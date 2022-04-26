import React from 'react';
import styled, { keyframes } from 'styled-components';
import KakaoAuth from './user/KakaoAuth';
import { useNavigate } from 'react-router-dom';
import { connect } from 'react-redux';
import { checkSessionRequest } from '../redux';

const smoothAppear = keyframes`
  from {
    opacity: 0;
    transform: translateX(-5%);
  }
  to {
    opacity: 1;
    transform: translateX(0);
}
`;
const Section = styled.section`
  background: black;
  height: 100vh;
  display: block;
  border: None;
`;
const Content = styled.div`
  width: 100%;
  height: 100px;

  animation: ${smoothAppear} 1s;
`;
const Left = styled.div`
  padding-left: 220px;
  padding-top: 143px;
`;
const Title = styled.p`
  width: 800px;
  font-size: 55px;
  color: white;
  font-weight: 400;
`;
const Desc = styled.p`
  width: 800px;
  font-size: 20px;
  color: white;
  line-height: 30px;
  margin-top: 58px;
  margin-bottom: 40px;
`;
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
  background: linear-gradient(90deg, #0546d6, #3f89fc);
  text-decoration: none;
  box-shadow: 0 15px 14px rgb(0 42 177 / 12 %);
`;

function Main({ isLoggedIn }) {
  const navigate = useNavigate();

  const onClick = () => {
    const headers = {
      Authorization: localStorage.getItem('token'),
    };
    checkSessionRequest(headers);
    navigate('/Search');
  };
  return (
    <Section>
      <Content>
        <Left>
          <Title>
            쇼핑몰 리뷰 Text Mining <br /> 상품 추천 서비스
          </Title>
          <Desc>
            사용자들이 직접적으로 사용하고 느낀 리뷰를 Ai 모델을 통해 분석하여
            <br />좀 더 쉽게 원하는 타입의 상품을 검색하고 구입하게 한 사이트
          </Desc>
          {/* {isLoggedIn ? (
            <KakaoAuth />
          ) : (
            <Button onClick={onClick}>검색하러 가기</Button>
          )} */}
          {isLoggedIn ? (
            <Button onClick={onClick}>검색하러 가기</Button>
          ) : (
            <KakaoAuth />
          )}
        </Left>
      </Content>
    </Section>
  );
}
const mapStateToProps = (state) => {
  return {
    isLoggedIn: state.kakaoAuth.status.isLoggedIn,
  };
};

const mapDispatchToProps = (dispatch) => {
  return {
    checkSessionRequest: (headers) => {
      return dispatch(checkSessionRequest(headers));
    },
  };
};

export default connect(mapStateToProps, mapDispatchToProps)(Main);
