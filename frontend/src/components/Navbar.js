import React, { useEffect } from 'react';
import styled from 'styled-components';
import { connect, useDispatch } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import { kakaoLogoutRequest, checkSessionRequest } from '../redux';
// import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { resetCategory } from '../redux/category/actions';

const NavbarContainer = styled.div`
  width: 100%;
  height: 80px;
  background: black;
  color: #fff;
`;
const NavbarWrap = styled.div`
  width: 1200px;
  height: 100%;
  margin: 0 auto;
  display: flex;
  position: relative;
  align-items: center;
  justify-content: space-between;
`;
const Title = styled.div`
  width: 128px;
  height: 22px;
  font-size: 25px;
  position: fixed;
  left: 200px;
  top: 24px;
  background-size: 100% 100%;
  cursor: pointer;
`;
const ButtonContainer = styled.div`
  display: flex;
  align-items: center;
  font-size: 25px;
  justify-content: flex-end;
  position: fixed;
  right: 100px;
`;
const Button = styled.div`
  width: 100px;
  cursor: pointer;
  height: 36px;
  text-align: center;
`;
const AdminButton = styled.div`
  width: 100px;
  font-size: 20px;
  cursor: pointer;
  height: 36px;
  text-align: center;
`;

function Navbar(isLoggedIn) {
  useEffect(() => {}, []);
  const navigate = useNavigate();
  const dispatch = useDispatch();
  // const toastOnLogout = () => toast('로그아웃 되었습니다.');

  // const onLogout = (e) => {
  //   kakaoLogoutRequest().then(() => {
  //     toastOnLogout();
  //     window.location.replace('/');
  //   });
  // };
  const onClick = () => {
    navigate('/');
    dispatch(resetCategory());
  };

  const onClickAdmin = () => {
    navigate('/adminProduct');
  };
  return (
    <NavbarContainer>
      <NavbarWrap>
        <Title onClick={onClick}>유종의 ME</Title>
        {isLoggedIn ? (
          <ButtonContainer>
            <AdminButton onClick={onClickAdmin}>Add Products</AdminButton>
          </ButtonContainer>
        ) : (
          <ButtonContainer>
            <Button>로그아웃</Button>
            &nbsp; | &nbsp;
            <Button href="/MyPage"> My Page </Button>
          </ButtonContainer>
        )}
      </NavbarWrap>
    </NavbarContainer>
  );
}

const mapStateToProps = (state) => {
  return {
    isLoggedIn: state.kakaoAuth.status.isLoggedIn,
  };
};

const mapDispatchToProps = (dispatch) => {
  return {
    kakaoLogoutRequest: () => {
      return dispatch(kakaoLogoutRequest());
    },
    checkSessionRequest: () => {
      return dispatch(checkSessionRequest());
    },
  };
};
export default connect(mapStateToProps, mapDispatchToProps)(Navbar);
