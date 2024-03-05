package org.apache.dolphinscheduler.api.interceptor;

import static org.apache.dolphinscheduler.api.controller.BaseController.getClientIpAddress;

import org.apache.dolphinscheduler.api.enums.Status;
import org.apache.dolphinscheduler.api.security.Authenticator;
import org.apache.dolphinscheduler.api.utils.HttpUtils;
import org.apache.dolphinscheduler.api.utils.Result;
import org.apache.dolphinscheduler.common.constants.Constants;
import org.apache.dolphinscheduler.dao.entity.User;
import org.apache.dolphinscheduler.dao.mapper.UserMapper;

import org.apache.http.HttpStatus;

import java.io.IOException;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

@Component
public class DamHandlerInterceptor implements HandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(DamHandlerInterceptor.class);

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private Authenticator authenticator;

    @Autowired
    private HttpUtils httpUtils;

    public static final String DAM_URL = "http://10.11.116.206:31006/getUserInfoByToken";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) throws Exception {

        String uri = request.getRequestURI();
        logger.info("DamHandlerInterceptor拦截到的请求的URI={}", uri);
        String accesstoken = request.getParameter("accesstoken");

        try {
            oauthCallback(accesstoken, request, response);
        } catch (ServletException e) {
            e.printStackTrace();
        }
        return true;

    }

    private void oauthCallback(String accesstoken, HttpServletRequest request,
                               HttpServletResponse response) throws ServletException {

        // user = authenticator.getAuthUser(request);

        // logger.info("accesstoken不为空,通过cookie获取认证过后的User:{}", user);
        // if user is null
        // if (user == null) {

        logger.info("accesstoken不为空,cookie为空,请求后坠为/list开始执行http请求");
        String damData = httpUtils.doGetHttp(DAM_URL, accesstoken);
        JSONObject damDataJsonObject = JSON.parseObject(damData);
        String userName = damDataJsonObject.getJSONObject("data").getString("username");
        logger.info("获取dam的用户名称,{}", userName);
        String ip = getClientIpAddress(request);
        Result<Map<String, Object>> mapResult = authenticator.authenticateDAM(userName, ip);
        User user = (User) mapResult.getData().get("user");

        if (mapResult.getCode() != Status.SUCCESS.getCode()) {
            logger.info("sso 回调 返回值异常 ：{} ", mapResult.toString());
            return;
        }

        if (user == null) {
            response.setStatus(HttpStatus.SC_UNAUTHORIZED);
            logger.info("user does not exist");
            return;
        }
        // Cookie[] cookies = request.getCookies();

        response.setStatus(HttpStatus.SC_OK);
        Map<String, Object> cookieMap = mapResult.getData();
        String sessionId = null;
        for (Map.Entry<String, Object> cookieEntry : cookieMap.entrySet()) {
            if (cookieEntry.getKey().equals(Constants.SESSION_ID)) {
                logger.info("开始设置cookie");
                // String sameSiteRestriction = "None";
                Cookie cookie = new Cookie(cookieEntry.getKey(), String.valueOf(cookieEntry.getValue()));
                // cookie.setHttpOnly(true);
                // cookie.setSecure(true);
                // String cookieHeader = String.format("%s=%s; SameSite=%s ;Secure=true", cookieEntry.getKey(),
                // cookieEntry.getValue(), sameSiteRestriction);

                // logger.info("cookieHeader的值是:{}", cookieHeader);
                response.addCookie(cookie);
                // logger.info("设置Header的信息key:{},value,{}", cookieEntry.getKey(),
                // String.valueOf(cookieEntry.getValue()));
                // response.addHeader(cookieEntry.getKey(), String.valueOf(cookieEntry.getValue()));
                if (cookieEntry.getKey().equals("sessionId")) {
                    sessionId = String.valueOf(cookieEntry.getValue());
                }
            }
        }

        request.setAttribute(Constants.SESSION_USER, userName);

        try {
            logger.info("http://172.30.245.67:12345/dolphinscheduler/ui/projects/list");
            String jumpUrl = "http://172.30.245.67:12345/dolphinscheduler/ui/projects/list";
            response.sendRedirect(jumpUrl);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

}
