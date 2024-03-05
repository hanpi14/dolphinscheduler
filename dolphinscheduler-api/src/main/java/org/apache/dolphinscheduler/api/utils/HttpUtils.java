package org.apache.dolphinscheduler.api.utils;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.alibaba.fastjson.JSONObject;

@Component
public class HttpUtils {

    @Autowired
    private CloseableHttpClient httpClient;

    public String doGetHttp(String url, String token) {

        String sendUrl = url;
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("token", token);

        if (Objects.nonNull(jsonObject) && jsonObject.size() > 0) {
            sendUrl = connectParams(url, jsonObject);
        }

        // 创建Get请求
        HttpGet httpGet = new HttpGet(sendUrl);

        CloseableHttpResponse response = null;
        try {
            response = httpClient.execute(httpGet);
            HttpEntity httpEntity = response.getEntity();
            if (HttpStatus.SC_OK == response.getStatusLine().getStatusCode() && null != httpEntity) {
                return EntityUtils.toString(httpEntity);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                close(response);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    private String connectParams(String url, JSONObject params) {
        StringBuffer buffer = new StringBuffer();
        buffer.append(url).append("?");
        params.forEach((x, y) -> buffer.append(x).append("=").append(y).append("&"));
        buffer.deleteCharAt(buffer.length() - 1);
        return buffer.toString();
    }

    public void close(CloseableHttpResponse httpResponse) throws IOException {
        // if (null != httpClient) {
        // httpClient.close();
        // }
        if (null != httpResponse) {
            httpResponse.close();
        }
    }

}
