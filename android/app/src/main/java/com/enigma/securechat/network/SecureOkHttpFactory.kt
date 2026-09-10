package com.enigma.securechat.network

import com.enigma.securechat.BuildConfig
import java.util.concurrent.TimeUnit
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient

class SecureOkHttpFactory(
    private val defaultTokenProvider: suspend () -> String?,
) {
    fun create(
        config: NetworkConfig,
        tokenProvider: suspend () -> String? = defaultTokenProvider,
    ): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .addInterceptor(AuthInterceptor(tokenProvider))
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)

        if (BuildConfig.DEBUG) {
            builder.addInterceptor { chain ->
                val request = chain.request()
                val path = request.url.encodedPath
                SafeLog.info("HTTP", "${request.method} $path")
                val response = chain.proceed(request)
                SafeLog.info("HTTP", "${response.code} $path")
                response
            }
        }

        if (config.pinningEnabled) {
            builder.certificatePinner(
                CertificatePinner.Builder()
                    .add(config.pinnedHost, config.pinnedSha256)
                    .build(),
            )
        }

        return builder.build()
    }
}
