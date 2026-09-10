package com.enigma.securechat.network

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Response
import com.enigma.securechat.domain.model.displayMessage

class ApiErrorMapperTest {
    @Test
    fun mapsStructuredHandleReservedError() {
        val error = httpError(
            """{"error_code":"HANDLE_RESERVED","message":"HANDLE_RESERVED","request_id":"req-1"}""",
        ).toUserVisibleError("fallback")

        assertEquals("fallback", error.message)
        assertEquals("HANDLE_RESERVED", error.errorCode)
        assertEquals("req-1", error.requestId)
        assertFalse(error.recoverable)
        assertEquals("Ce handle est reserve\nReference support: req-1", error.displayMessage(fr = true))
        assertEquals("This handle is reserved\nSupport reference: req-1", error.displayMessage(fr = false))
    }

    @Test
    fun preservesUnknownStableCode() {
        val error = httpError(
            """{"error_code":"FUTURE_CODE","message":"future","request_id":"req-2"}""",
        ).toUserVisibleError("fallback")

        assertEquals("future", error.message)
        assertEquals("FUTURE_CODE", error.errorCode)
        assertEquals("req-2", error.requestId)
        assertTrue(error.recoverable)
        assertEquals("Server error: FUTURE_CODE\nSupport reference: req-2", error.displayMessage(fr = false))
    }

    @Test
    fun fallsBackWhenBodyIsNotStructured() {
        val error = httpError("not-json").toUserVisibleError("fallback")

        assertEquals("fallback", error.message)
        assertEquals(null, error.errorCode)
        assertEquals(null, error.requestId)
    }

    private fun httpError(body: String): Throwable =
        HttpException(
            Response.error<Unit>(
                409,
                body.toResponseBody("application/json".toMediaType()),
            ),
        )
}
