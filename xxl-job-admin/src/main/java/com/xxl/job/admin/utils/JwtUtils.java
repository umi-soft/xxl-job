package com.xxl.job.admin.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;

import javax.servlet.http.HttpServletRequest;

/**
 * @Description: JWT工具类
 * @Author: hujie@mail.taiji.com.cn
 * @Date: 2019/2/18 12:42 PM
 */
public class JwtUtils {
    public final static String JWT_PREFIX = "Bearer ";
    public final static String HEAD_TOKEN_KEY = "Authorization";
    public final static String PARAMETER_TOKEN_KEY = "token";

    /**
     * @description: <p>验证token</p>
     * @author: hujie@mail.taiji.com.cn
     * @date: 2019/2/19 3:01 PM
     * @param request 从request中获取token
     * @param secret 秘钥
     * @return jwtId 或 userId
     */
    public static void verify(HttpServletRequest request, String secret) {
        String token = request.getHeader(HEAD_TOKEN_KEY);
        if (token == null) {
            token = request.getParameter(PARAMETER_TOKEN_KEY);
        }
        if (token == null) {
            throw new JWTVerificationException("缺失Token信息");
        }
        token = token.replaceFirst(JWT_PREFIX,"");
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret)).build();
        verifier.verify(token);
    }
}