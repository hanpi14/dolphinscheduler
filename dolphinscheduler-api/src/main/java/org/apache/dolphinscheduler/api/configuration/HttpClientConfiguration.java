package org.apache.dolphinscheduler.api.configuration;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

import lombok.extern.slf4j.Slf4j;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@Slf4j
public class HttpClientConfiguration {

    @Bean
    @ConditionalOnMissingBean // 保证整个容器只有一个工具类对象
    public CloseableHttpClient aliOssUtil() {
        log.info("创建Http请求对象");

        return HttpClientBuilder.create().build();

    }
}
