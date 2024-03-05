package org.apache.dolphinscheduler.api.interceptor;

import static org.apache.dolphinscheduler.api.controller.BaseController.getClientIpAddress;

import org.apache.dolphinscheduler.api.enums.Status;
import org.apache.dolphinscheduler.api.security.Authenticator;
import org.apache.dolphinscheduler.api.service.SessionService;
import org.apache.dolphinscheduler.api.utils.Result;
import org.apache.dolphinscheduler.common.constants.Constants;

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

import com.para.esc.sdk.oauth.IOAuth20Service;
import com.para.esc.sdk.oauth.builder.OAuthServiceBuilder;
import com.para.esc.sdk.oauth.client.model.UserInfo;
import com.para.esc.sdk.oauth.exceptions.OAuthApiException;
import com.para.esc.sdk.oauth.model.OAuth20Config;
import com.para.esc.sdk.oauth.model.Token;
import com.para.esc.sdk.oauth.utils.OAuthConfigUtil;

@Component
public class SsoLoginHandlerInterceptor implements HandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(SsoLoginHandlerInterceptor.class);
    @Autowired
    private Authenticator authenticator;
    @Autowired
    private SessionService sessionService;
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String uri = request.getRequestURI();
        // logger.info("preHandle拦截到的请求的URI={}", uri);
        String code = request.getParameter("code");
        try {
            oauthCallback(code, request, response);
        } catch (ServletException e) {
            e.printStackTrace();
        }
        return true;
    }
    private void oauthCallback(String code, HttpServletRequest request,
                               HttpServletResponse response) throws ServletException {
        // logger.info("================ 从sso平台页面 进入 =======================");
        // logger.info("preHandle拦截到的请求的 code = {}", code);
        OAuthConfigUtil configUtil = new OAuthConfigUtil("appIDP");
        OAuth20Config configInfo =
                new OAuth20Config(configUtil.getClientId(), configUtil.getClientSecret(),
                        configUtil.getRedirectUri(), configUtil.getAuthorizeUrl(),
                        configUtil.getAccessTokenUrl());
        IOAuth20Service service = new OAuthServiceBuilder(configInfo).build20Service();
        // 生成认证跳转地址，认证请求第一步请求回调地址不会传递code信息，要应用系统请求认证地址，认证中心第二次调用回调地址会将认code信息带回来。
        if (null == code) {
            String redUrl = service.getAuthorizationUrl();
            // 跳转到认证中心,进行认证，获取code信息
            try {
                logger.info("preHandle拦截到的请求回调的 code = {}", code);
                response.sendRedirect(redUrl);
            } catch (IOException e) {
                e.printStackTrace();
            }
            return;
        }
        // 应用已经发起过认证请求，code信息已经传递过来
        // 根据code信息使用sdk中的方法获取token信息
        Token accessToken = service.getAccessToken(code);
        // 根据token信息使用SDK中的方法获取用户登录信息
        UserInfo oauthUser = new UserInfo(accessToken);
        // logger.info("UserInfo oauthUser:{}", oauthUser);

        try {
            UserInfo loginUser = oauthUser.requestUserInfo(configUtil.getUserInfoUrl());

            // logger.info("userinfo的具体信息:{}", loginUser);
            // 认证过程完成，得到用户信息，下来为应用自身的访问逻辑
            String ip = getClientIpAddress(request);
            Result<Map<String, String>> result = authenticator.authenticateSSO(loginUser.getId(), ip);
            if (result.getCode() != Status.SUCCESS.getCode()) {
                logger.info("sso 回调 返回值异常 ：{} ", result.toString());
                return;
            }

            response.setStatus(HttpStatus.SC_OK);
            Map<String, String> cookieMap = result.getData();
            String sessionId = null;
            for (Map.Entry<String, String> cookieEntry : cookieMap.entrySet()) {
                Cookie cookie = new Cookie(cookieEntry.getKey(), cookieEntry.getValue());
                cookie.setHttpOnly(true);
                response.addCookie(cookie);
                if (cookieEntry.getKey().equals("sessionId")) {
                    sessionId = cookieEntry.getValue();
                }
            }

            request.setAttribute(Constants.SESSION_USER, loginUser.getId());
            // 本地测试
            // String jumpUrl = "http://172.30.245.67:12345/dolphinscheduler/ui/#/home?sessionId=" + sessionId;
            String jumpUrl = "http://172.30.245.67:12345/dolphinscheduler/ui/#/home";
            // 容器测试环境
            // String jumpUrl = "http://10.11.114.31:9040/dolphinscheduler/ui/#/home";
            // 容器生产环境
            // String jumpUrl = "http://10.20.235.1:9001/dolphinscheduler/ui/#/home";
            // logger.info("重定向的url:{}", jumpUrl);
            // 测试环境
            // String jumpUrl="http://10.11.114.31:12345/dolphinscheduler/ui/#/home?sessionId="+sessionId;
            response.sendRedirect(jumpUrl);

            return;
        } catch (OAuthApiException | IOException e) {
            e.printStackTrace();
        }

    }
}
