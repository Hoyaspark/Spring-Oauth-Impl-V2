import React from 'react';
import styled from 'styled-components';

const Section = styled.section`
  background: black;
  height: 100vh;
  display: flex;
  border: None;
`;
const Content = styled.div`
  display: block;
  width: 100%;
  height: 100px;
  justify-content: center;
  align-items: center;
`;
const Title = styled.p`
  margin-top: 100px;
  width: 1000px;
  font-size: 55px;
  color: white;
  font-weight: 300;
`;
const Input = styled.input``;

function AdminProducts() {
  return (
    <Section>
      <Content>
        <Title>추가하고 싶은 상품의 URL을 적으세요</Title>
        <Input></Input>
      </Content>
    </Section>
  );
}

export default AdminProducts;
