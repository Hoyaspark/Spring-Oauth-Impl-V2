import React from 'react';
import { connect, useDispatch } from 'react-redux';
import styled, { keyframes } from 'styled-components';
import { clicklike } from '../../redux/category/actions';

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
  border: None;
`;
const Header = styled.h1`
  font-weight: 500;
  margin-left: 60px;
  margin-top: 50px;
`;
const ResultContainer = styled.div`
  justfy-contnet: center;
  width: 90%;
  height: 90vh;

  position: relative;
  background: white;
  border-radius: 16px;
  box-shadow: 0 0 8px rgba(0, 0, 0, 0.04);

  margin: 0 auto;

  display: flex;
  flex-direction: column;
  animation: ${smoothAppear} 1s;
`;
const VerticleLine = styled.div`
  border-left: 2px solid black;
  height: 50vh;
`;
const FirstProduct = styled.div`
  padding: 35px 50px;
  display: flex;
`;
const ImageContainer = styled.div`
  flex: 1;
`;
const Image = styled.img`
  width: 80%;
  height: 50vh;
  object-fit: cover;
`;
const InfoContainter = styled.div`
  flex: 1;
  padding: 0 50px;
`;

const Title = styled.h1`
  font-weight: 200;
`;
const Desc = styled.p`
  margin: 20px 0px;
`;
const Price = styled.span`
  font-weight: 100;
  font-size: 30px;
`;
const ButtonContainer = styled.div`
  width: 100%;
  margin-top: 20px;
  display: flex;
  align-items: center;
  justify-content: flex-end;
`;
const LikeButton = styled.img`
  width: 40px;
  cursor: pointer;
  padding: 30px 0px;
  maring: 20px 0px;
`;
const ProductButton = styled.button`
  padding: 15px;
  margin: 30px; 0px;
  border: 2px solid teal;
  background-color: white;
  cursor: pointer;
  font-weight: 500;
  &:hover {
    background-color: #f8f4f4;
  }
`;
function SearchResult({ like }) {
  const dispatch = useDispatch();

  const CilckLikeButton = () => {
    dispatch(clicklike());
    console.log(like.liked);
  };
  return (
    <Section>
      <ResultContainer>
        <Header>검색결과</Header>
        <FirstProduct>
          <ImageContainer>
            <Image src="https://image.msscdn.net/data/curating/23723/23723_1_250.jpg"></Image>
          </ImageContainer>
          <VerticleLine />
          <InfoContainter>
            <Title>Longsleeve 무지 긴팔티</Title>
            <Desc>배송</Desc>
            <Desc>사이즈</Desc>
            <Desc>품질</Desc>
            <Price>200,000 Won</Price>
            <ButtonContainer>
              <LikeButton
                src={like.liked ? like.likeSrc : like.NonLikeSrc}
                onClick={CilckLikeButton}
              ></LikeButton>
              <ProductButton>상품 보러가기</ProductButton>
            </ButtonContainer>
          </InfoContainter>
        </FirstProduct>
      </ResultContainer>
    </Section>
  );
}
const mapStateToProps = (state) => {
  return {
    like: state.category.status.like,
  };
};

const mapDispatchToProps = () => {
  return {};
};
export default connect(mapStateToProps, mapDispatchToProps)(SearchResult);
