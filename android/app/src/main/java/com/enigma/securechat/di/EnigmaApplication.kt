package com.enigma.securechat.di

import android.app.Application

class EnigmaApplication : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
    }

    fun reloadContainer() {
        val previous = container
        container = AppContainer(this)
        previous.dispose()
    }
}
