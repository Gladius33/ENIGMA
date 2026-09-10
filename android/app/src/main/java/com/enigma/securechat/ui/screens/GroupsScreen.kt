package com.enigma.securechat.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.enigma.securechat.data.db.GroupEntity
import com.enigma.securechat.ui.viewmodel.GroupsViewModel

@Composable
fun GroupsScreen(
    viewModel: GroupsViewModel,
    onOpen: (GroupEntity) -> Unit,
    onBack: () -> Unit,
) {
    val groups by viewModel.groups.collectAsState()
    val state by viewModel.state.collectAsState()
    var title by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { viewModel.refresh() }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Row(Modifier.fillMaxWidth()) {
            Text("Groupes", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
            OutlinedButton(onClick = onBack) { Text("Retour") }
        }
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth()) {
            OutlinedTextField(title, { title = it }, Modifier.weight(1f), label = { Text("Titre") })
            Button(onClick = { viewModel.create(title); title = "" }, Modifier.padding(start = 8.dp)) {
                Text("Créer")
            }
        }
        state.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        LazyColumn {
            items(groups, key = { it.id }) { group ->
                Column(Modifier.fillMaxWidth().clickable { onOpen(group) }.padding(vertical = 12.dp)) {
                    Text(group.title, fontWeight = FontWeight.SemiBold)
                    Text(group.id, style = MaterialTheme.typography.bodySmall)
                }
                HorizontalDivider()
            }
        }
    }
}
