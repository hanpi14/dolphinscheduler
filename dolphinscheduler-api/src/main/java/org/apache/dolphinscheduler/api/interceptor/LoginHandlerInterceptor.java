/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.dolphinscheduler.api.interceptor;

import org.apache.dolphinscheduler.api.enums.Status;
import org.apache.dolphinscheduler.api.security.Authenticator;
import org.apache.dolphinscheduler.api.utils.HttpUtils;
import org.apache.dolphinscheduler.common.constants.Constants;
import org.apache.dolphinscheduler.common.enums.Flag;
import org.apache.dolphinscheduler.common.thread.ThreadLocalContext;
import org.apache.dolphinscheduler.dao.entity.User;
import org.apache.dolphinscheduler.dao.mapper.UserMapper;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;

import java.io.IOException;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import com.para.esc.sdk.oauth.IOAuth20Service;
import com.para.esc.sdk.oauth.builder.OAuthServiceBuilder;
import com.para.esc.sdk.oauth.model.OAuth20Config;
import com.para.esc.sdk.oauth.utils.OAuthConfigUtil;

/**
 * login interceptor, must log in first
 */
public class LoginHandlerInterceptor implements HandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(LoginHandlerInterceptor.class);

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private Authenticator authenticator;

    @Autowired
    private HttpUtils httpUtils;

    // 容器测试
    // public static final String DS_URL = "http://10.11.114.31:9040/dolphinscheduler/ui/home";
    // 本地测试
    // public static final String DS_URL = "http://10.11.114.31:9040/dolphinscheduler/ui/home";
    // DAM用户查询
    public static final String DAM_URL = "http://10.11.116.206:31006/getUserInfoByToken";

    /**
     * Intercept the execution of a handler. Called after HandlerMapping determined
     *
     * @param request current HTTP request
     * @param response current HTTP response
     * @param handler chosen handler to execute, for type and/or instance evaluation
     * @return boolean true or false
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {

        // get token
        String token = request.getHeader("token");
        // get accesstoken
        // String accesstoken = request.getHeader("accesstoken");
        logger.info("request请求：{}", request.toString());
        logger.info("login拦截器请求的路径:{}", request.getRequestURI());
        // String accesstoken = request.getParameter("accesstoken");
        // logger.info("获取到的accesstoken:{}", accesstoken);
        User user = null;

        String requestURI = request.getRequestURI();

        if (StringUtils.isEmpty(token)) {

            user = authenticator.getAuthUser(request);
            logger.info("进入LoginHandlerInterceptor拦截器,此时user:{}", user);
            // if user is null
            if (user == null) {
                // response.setStatus(HttpStatus.SC_UNAUTHORIZED);
                // logger.info("user does not exist");

                // // // TODO: 2024/1/10 重定向
                logger.info("开始进入LoginHandlerInterceptor拦截器,并重定向sso");
                OAuthConfigUtil configUtil = new OAuthConfigUtil("appIDP");
                OAuth20Config configInfo =
                        new OAuth20Config(configUtil.getClientId(), configUtil.getClientSecret(),
                                configUtil.getRedirectUri(), configUtil.getAuthorizeUrl(),
                                configUtil.getAccessTokenUrl());
                IOAuth20Service service = new OAuthServiceBuilder(configInfo).build20Service();
                String redUrl = service.getAuthorizationUrl();
                try {
                    response.sendRedirect(redUrl);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                // response.setStatus(HttpStatus.SC_UNAUTHORIZED);
                // logger.info("user does not exist");
                return false;
            }
        }

        // else if (StringUtils.isEmpty(token) && StringUtils.isNotEmpty(accesstoken)) {
        //
        // // user = authenticator.getAuthUser(request);
        //
        // // logger.info("accesstoken不为空,通过cookie获取认证过后的User:{}", user);
        // // if user is null
        // // if (user == null) {
        //
        // logger.info("accesstoken不为空,cookie为空,请求后坠为/list开始执行http请求");
        // String damData = httpUtils.doGetHttp(DAM_URL, accesstoken);
        // JSONObject damDataJsonObject = JSON.parseObject(damData);
        // String userName = damDataJsonObject.getJSONObject("data").getString("username");
        // logger.info("获取dam的用户名称,{}", userName);
        // String ip = getClientIpAddress(request);
        // Result<Map<String, Object>> mapResult = authenticator.authenticateDAM(userName, ip);
        // user = (User) mapResult.getData().get("user");
        //
        // if (mapResult.getCode() != Status.SUCCESS.getCode()) {
        // logger.info("sso 回调 返回值异常 ：{} ", mapResult.toString());
        // return false;
        // }
        //
        // if (user == null) {
        // response.setStatus(HttpStatus.SC_UNAUTHORIZED);
        // logger.info("user does not exist");
        // return false;
        // }
        // // Cookie[] cookies = request.getCookies();
        //
        // response.setStatus(HttpStatus.SC_OK);
        // Map<String, Object> cookieMap = mapResult.getData();
        // String sessionId = null;
        // for (Map.Entry<String, Object> cookieEntry : cookieMap.entrySet()) {
        // if (cookieEntry.getKey().equals(Constants.SESSION_ID)) {
        // logger.info("开始设置cookie");
        // Cookie cookie = new Cookie(cookieEntry.getKey(), String.valueOf(cookieEntry.getValue()));
        // cookie.setHttpOnly(true);
        // response.addCookie(cookie);
        // if (cookieEntry.getKey().equals("sessionId")) {
        // sessionId = String.valueOf(cookieEntry.getValue());
        // }
        // }
        // }
        //
        // request.setAttribute(Constants.SESSION_USER, userName);
        //
        // try {
        // logger.info("开始进入重定向 http://172.30.245.67:12345/dolphinscheduler/ui/projects/list");
        // String jumpUrl = "http://172.30.245.67:12345/dolphinscheduler/ui/#/home";
        // response.sendRedirect(jumpUrl);
        // } catch (IOException e) {
        // throw new RuntimeException(e);
        // }
        //
        // return false;
        //
        // }

        else {
            user = userMapper.queryUserByToken(token, new Date());
            if (user == null) {
                response.setStatus(HttpStatus.SC_UNAUTHORIZED);
                logger.info("user token has expired");
                return false;
            }
        }

        // check user state
        if (user.getState() == Flag.NO.ordinal()) {
            response.setStatus(HttpStatus.SC_UNAUTHORIZED);
            logger.info(Status.USER_DISABLED.getMsg());
            return false;
        }
        request.setAttribute(Constants.SESSION_USER, user);

        ThreadLocalContext.getTimezoneThreadLocal().set(user.getTimeZone());

        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
                           ModelAndView modelAndView) throws Exception {
        ThreadLocalContext.getTimezoneThreadLocal().remove();
    }
}
