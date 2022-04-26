import { combineReducers } from 'redux';
import kakaoAuth from './kakaoAuth/reducer';
import category from './category/reducer';

const rootReducer = combineReducers({
  kakaoAuth: kakaoAuth,
  category: category,
});

export default rootReducer;
