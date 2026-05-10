package so.prelude.android.session

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `metadata` rides on `POST /stepup/request` only when the caller
 * passes a non-null map. Default-null callers must keep the prior
 * wire shape: no key on the body, no `metadata: null`.
 */
class RequestStepUpMetadataTest {

    @Test
    fun metadata_omittedByDefault() = runBlocking {
        val fixture = Fixture.make()
        fixture.prePopulateStepUp()
        fixture.http.install(
            "/v1/session/stepup/request",
            StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
        )

        fixture.client.requestStepUp(scope = "prld:pwd:write")

        val body = fixture.http.requestsFor("/v1/session/stepup/request")
            .single().bodyAsJson()
        assertEquals("prld:pwd:write", body["scope"]!!.jsonPrimitive.content)
        assertFalse(
            "default-null metadata must not appear on the wire",
            body.containsKey("metadata"),
        )
    }

    @Test
    fun metadata_passedThroughVerbatim() = runBlocking {
        val fixture = Fixture.make()
        fixture.prePopulateStepUp()
        fixture.http.install(
            "/v1/session/stepup/request",
            StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
        )

        fixture.client.requestStepUp(
            scope = "prld:pwd:write",
            metadata = mapOf("reason" to "settings", "channel" to "android"),
        )

        val body = fixture.http.requestsFor("/v1/session/stepup/request")
            .single().bodyAsJson()
        val md = body["metadata"]!!.jsonObject
        assertEquals(2, md.size)
        assertEquals("settings", md["reason"]!!.jsonPrimitive.content)
        assertEquals("android", md["channel"]!!.jsonPrimitive.content)
        assertTrue(md is JsonObject)
    }
}
