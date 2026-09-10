package com.enigma.securechat.ui.components

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.enigma.securechat.R

@Composable
fun EnigmaBrandLogo(
    modifier: Modifier = Modifier,
    size: Dp = 56.dp,
) {
    Box(
        modifier = modifier
            .size(size)
            .clip(CircleShape)
            .background(Color.Transparent),
        contentAlignment = Alignment.Center,
    ) {
        Image(
            painter = painterResource(R.drawable.enigma_logo),
            contentDescription = "Enigma",
            modifier = Modifier.size(size),
            contentScale = ContentScale.Crop,
        )
    }
}
