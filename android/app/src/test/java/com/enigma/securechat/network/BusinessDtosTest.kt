package com.enigma.securechat.network
import com.enigma.securechat.network.dto.SupportConfigDto
import org.junit.Assert.assertEquals
import org.junit.Test
class BusinessDtosTest { @Test fun `support URL uses localized then default fallback`() { val c=SupportConfigDto(true,true,"https://fr",null,"https://default",true,null,null,"https://premium");assertEquals("https://fr",c.donationUrl("fr"));assertEquals("https://default",c.donationUrl("en"));assertEquals("https://premium",c.premiumUrl("de")) } }
