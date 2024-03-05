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

import axios, { AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios'
import { useUserStore } from '@/store/user/user'

import qs from 'qs'
import _ from 'lodash'
import cookies from 'js-cookie'
import router from '@/router'
import utils from '@/utils'
import {UserInfoRes} from "@/service/modules/users/types";
import {getUserInfo} from "@/service/modules/users";

import { useTimezoneStore } from '@/store/timezone/timezone'


const userStore = useUserStore()
const userInfo = userStore.getUserInfo as UserInfoRes
const timezoneStore = useTimezoneStore()

/**
 * @description Log and display errors
 * @param {Error} error Error object
 */
const handleError = (res: AxiosResponse<any, any>) => {
  // Print to console
  if (import.meta.env.MODE === 'development') {
    utils.log.capsule('DolphinScheduler', 'UI')
    utils.log.error(res)
  }
  window.$message.error(res.data.msg)
}

const baseRequestConfig: AxiosRequestConfig = {
  baseURL:
      import.meta.env.MODE === 'development'
          ? '/dolphinscheduler'
          : import.meta.env.VITE_APP_PROD_WEB_URL + '/dolphinscheduler',
  timeout: 15000,
  transformRequest: (params) => {
    if (_.isPlainObject(params)) {
      return qs.stringify(params, { arrayFormat: 'repeat' })
    } else {
      return params
    }
  },
  paramsSerializer: (params) => {
    return qs.stringify(params, { arrayFormat: 'repeat' })
  }
}

const service = axios.create(baseRequestConfig)

const err = (err: AxiosError): Promise<AxiosError> => {
  if (err.response?.status === 401 || err.response?.status === 504) {
    userStore.setSessionId('')
    userStore.setSecurityConfigType('')
    userStore.setUserInfo({})
    router.push({ path: '/login' })
  }

  return Promise.reject(err)
}






service.interceptors.request.use((config: AxiosRequestConfig<any>) => {
  config.headers && (config.headers.sessionId = userStore.getSessionId)
  const language = cookies.get('language')
  config.headers = config.headers || {}
  if (language) config.headers.language = language

  return config
}, err)


// service.interceptors.response.use(async (response) => {
//
//   let sessionId;
//   response.data.path.data
//
//   console.log('获取到的sessionId是:', sessionId);
//   if (sessionId) {
//
//     cookies.set('sessionId', sessionId, {path: '/'})
//
//     const userInfoRes: UserInfoRes = await getUserInfo()
//     await userStore.setUserInfo(userInfoRes)
//     await userStore.setSessionId(sessionId);
//
//   }
//
//   return response;
// },(error)=>{
//   console.error('自定义前端响应拦截器An error occurred:', error);
//   return Promise.reject(error);
// })

// The response to intercept
service.interceptors.response.use( (res: AxiosResponse) => {


  // No code will be processed
  if (res.data.code === undefined) {
    return res.data
  }

  if (!userInfo) {
    console.log("此时的userInfo为空,设置用户")
    const userInfoRes: UserInfoRes =  getUserInfo()
     userStore.setUserInfo(userInfoRes)

    const timezone = userInfoRes.timeZone ? userInfoRes.timeZone : 'UTC'
    timezoneStore.setTimezone(timezone)

  }else {
    console.log("此时的userInfo不为空:"+userInfo)
  }

  if (userStore.getUserInfo)

    switch (res.data.code) {
      case 0:
        return res.data.data
      default:
        handleError(res)
        throw new Error()
    }


}, err)



export { service as axios }