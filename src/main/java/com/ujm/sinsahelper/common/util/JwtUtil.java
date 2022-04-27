package com.ujm.sinsahelper.common.util;

import com.ujm.sinsahelper.domain.AuthRole;
import com.ujm.sinsahelper.domain.Member;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.DefaultClaims;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;

public class JwtUtil {

    private static final String TOKEN_TYPE = "Bearer";
    private static final String ROLE_KEY = "Role";

    @Value("${jwt.key}")
    private String jwtKey;

    public Authentication getAuthentication(String token) {

        Claims claims = Jwts.parser()
                .setSigningKey(jwtKey)
                .parseClaimsJws(token)
                .getBody();

        String userEmail = claims.getSubject();
        AuthRole authRole = claims.get(ROLE_KEY, AuthRole.class);

        return new UsernamePasswordAuthenticationToken(userEmail, "", Collections.singleton(new SimpleGrantedAuthority(authRole.name())));
    }

    public JwtTokenDTO generateToken(Member member) {

        return JwtTokenDTO.builder()
                .tokenType(TOKEN_TYPE)
                .accessToken(Jwts.builder()
                        .signWith(SignatureAlgorithm.HS256, jwtKey)
                        .setSubject(member.getEmail())
                        .claim(ROLE_KEY, member.getAuthRole())
                        .compact())
                .refreshToken(null)
                .build();
    }

    public boolean validateJwtToken(String token) {
        try {
            Jwts.parser().setSigningKey(jwtKey).parseClaimsJws(token);
            return true;
        } catch (MalformedJwtException e) {
            throw new MalformedJwtException("MalformedJwtException!!");
        } catch (ExpiredJwtException e) {
            throw new RuntimeException();
        } catch (UnsupportedJwtException e) {
            throw new UnsupportedJwtException("UnsupportedJwtException!!");
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException();
        }
    }
}
